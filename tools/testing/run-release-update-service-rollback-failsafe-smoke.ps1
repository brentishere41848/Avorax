param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$UpdateServicePath = "",
  [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"

function Get-BoundedText {
  param([AllowNull()][object]$Value, [int]$MaxChars = 4096)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  $text = $text -replace "[`0-\x1F\x7F]+", " "
  if ($text.Length -le $MaxChars) { return $text }
  return $text.Substring(0, [Math]::Max(0, $MaxChars - 3)) + "..."
}

function Restore-EnvVar {
  param(
    [string]$Name,
    [AllowNull()][object]$Value
  )
  if ($null -eq $Value) {
    if (Test-Path -Path "Env:\$Name") {
      Remove-Item -Path "Env:\$Name" -ErrorAction Stop
    }
  } else {
    Set-Item -Path "Env:\$Name" -Value $Value -ErrorAction Stop
  }
}

function Resolve-ReleaseBinary {
  param(
    [string]$Repo,
    [string]$ConfiguredPath,
    [string]$FileName
  )
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\$FileName"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release update-service binary is missing: $candidate. Run cargo build --release --manifest-path core\avorax_update_service\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne $FileName) {
    throw "Release update-service rollback fail-safe smoke expects $FileName, got: $resolved"
  }
  return $resolved
}

function ConvertTo-ProcessArgument {
  param([string]$Value)
  return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-ReleaseCommand {
  param(
    [string]$Binary,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [int]$Timeout
  )

  $process = $null
  try {
    $argumentText = ($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join " "

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Binary
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.Arguments = $argumentText
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "release update-service rollback fail-safe command timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release update-service rollback fail-safe command timed out after ${Timeout}s."
    }

    return [pscustomobject]@{
      ExitCode = $process.ExitCode
      Stdout = $stdoutTask.Result
      Stderr = $stderrTask.Result
    }
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Write-Utf8NoBomFile {
  param([string]$Path, [string]$Text)
  [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Read-JsonFile {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "expected JSON file was not written: $Path"
  }
  return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
}

function Assert-FileText {
  param([string]$Path, [string]$Expected)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "expected file is missing: $Path"
  }
  $actual = Get-Content -LiteralPath $Path -Raw
  if ($actual -ne $Expected) {
    throw "file content mismatch for $Path"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$updateService = Resolve-ReleaseBinary $repo $UpdateServicePath "avorax_update_service.exe"
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-update-service-rollback-failsafe-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$installRoot = Join-Path $tempRoot "install"
$rollbackRoot = Join-Path $dataRoot "updates\rollback"

$oldDataDir = [System.Environment]::GetEnvironmentVariable("AVORAX_DATA_DIR")

try {
  New-Item -ItemType Directory -Path (Join-Path $installRoot "engine\signatures") -Force | Out-Null

  $currentApp = "current Avorax app fixture without rollback snapshot`n"
  $currentCore = "current Avorax core service fixture without rollback snapshot`n"
  $currentGuard = "current Avorax guard service fixture without rollback snapshot`n"
  $currentSignature = "current Avorax signature fixture without rollback snapshot`n"
  Write-Utf8NoBomFile (Join-Path $installRoot "Avorax.exe") $currentApp
  Write-Utf8NoBomFile (Join-Path $installRoot "avorax_core_service.exe") $currentCore
  Write-Utf8NoBomFile (Join-Path $installRoot "avorax_guard_service.exe") $currentGuard
  Write-Utf8NoBomFile (Join-Path $installRoot "engine\signatures\current.asig") $currentSignature

  Set-Item -Path Env:\AVORAX_DATA_DIR -Value $dataRoot -ErrorAction Stop

  $rollbackResult = Invoke-ReleaseCommand $updateService @("--rollback", $installRoot) $repo $TimeoutSeconds
  if ($rollbackResult.ExitCode -eq 0) {
    throw "release update-service rollback succeeded even though no rollback snapshot exists"
  }
  if (-not $rollbackResult.Stderr.Contains("No Avorax rollback snapshot is available.")) {
    throw "release update-service rollback fail-safe diagnostic mismatch: $(Get-BoundedText $rollbackResult.Stderr)"
  }

  Assert-FileText (Join-Path $installRoot "Avorax.exe") $currentApp
  Assert-FileText (Join-Path $installRoot "avorax_core_service.exe") $currentCore
  Assert-FileText (Join-Path $installRoot "avorax_guard_service.exe") $currentGuard
  Assert-FileText (Join-Path $installRoot "engine\signatures\current.asig") $currentSignature
  if (Test-Path -LiteralPath $rollbackRoot) {
    throw "rollback fail-safe smoke unexpectedly created a rollback root"
  }
  if (Test-Path -LiteralPath (Join-Path $dataRoot "updates\logs\update_report.json")) {
    throw "rollback fail-safe smoke unexpectedly wrote update_report.json"
  }

  $status = Read-JsonFile (Join-Path $dataRoot "updates\logs\update_cli_status.json")
  if ([bool]$status.ok -ne $false -or $status.command -ne "--rollback") {
    throw "rollback fail-safe CLI status mismatch"
  }
  if ($null -eq $status.error -or -not ([string]$status.error).Contains("No Avorax rollback snapshot is available.")) {
    throw "rollback fail-safe CLI status missing no-snapshot diagnostic"
  }

  Write-Host "Avorax release update-service rollback missing-snapshot fail-safe smoke test passed."
  Write-Host "Rollback fail-safe diagnostic: $(Get-BoundedText $rollbackResult.Stderr)"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $oldDataDir
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
