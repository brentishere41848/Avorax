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
    throw "Release update-service rollback destination-kind smoke expects $FileName, got: $resolved"
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
        throw "release update-service rollback destination-kind command timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release update-service rollback destination-kind command timed out after ${Timeout}s."
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

function Assert-Directory {
  param([string]$Path, [string]$Description)
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "$Description is not a directory: $Path"
  }
}

function Assert-MissingPath {
  param([string]$Path, [string]$Description)
  if (Test-Path -LiteralPath $Path) {
    throw "$Description unexpectedly exists: $Path"
  }
}

function Write-CompleteSnapshot {
  param([string]$SnapshotRoot)
  New-Item -ItemType Directory -Path (Join-Path $SnapshotRoot "engine\signatures") -Force | Out-Null
  Write-Utf8NoBomFile (Join-Path $SnapshotRoot "Avorax.exe") "rollback Avorax app fixture`n"
  Write-Utf8NoBomFile (Join-Path $SnapshotRoot "avorax_core_service.exe") "rollback Avorax core service fixture`n"
  Write-Utf8NoBomFile (Join-Path $SnapshotRoot "avorax_guard_service.exe") "rollback Avorax guard service fixture`n"
  Write-Utf8NoBomFile (Join-Path $SnapshotRoot "engine\signatures\rollback.asig") "rollback Avorax signature fixture`n"
}

function Write-CurrentInstallFiles {
  param([string]$InstallRoot)
  Write-Utf8NoBomFile (Join-Path $InstallRoot "Avorax.exe") "current Avorax app fixture before destination-kind rollback`n"
  Write-Utf8NoBomFile (Join-Path $InstallRoot "avorax_guard_service.exe") "current Avorax guard service fixture before destination-kind rollback`n"
}

function Assert-CommonFailureEvidence {
  param(
    [string]$DataRoot,
    [string]$ExpectedDiagnostic
  )
  if (Test-Path -LiteralPath (Join-Path $DataRoot "updates\logs\update_report.json")) {
    throw "rollback destination-kind smoke unexpectedly wrote update_report.json"
  }
  $status = Read-JsonFile (Join-Path $DataRoot "updates\logs\update_cli_status.json")
  if ([bool]$status.ok -ne $false -or $status.command -ne "--rollback") {
    throw "rollback destination-kind CLI status mismatch"
  }
  if ($null -eq $status.error -or -not ([string]$status.error).Contains($ExpectedDiagnostic)) {
    throw "rollback destination-kind CLI status missing diagnostic: $ExpectedDiagnostic"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$updateService = Resolve-ReleaseBinary $repo $UpdateServicePath "avorax_update_service.exe"
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-update-service-rollback-destination-kind-" + [System.Guid]::NewGuid().ToString("N"))
$oldDataDir = [System.Environment]::GetEnvironmentVariable("AVORAX_DATA_DIR")

try {
  $coreScenario = Join-Path $tempRoot "core-service-directory"
  $coreDataRoot = Join-Path $coreScenario "data"
  $coreInstallRoot = Join-Path $coreScenario "install"
  $coreSnapshotRoot = Join-Path $coreDataRoot "updates\rollback\0.5.0"
  Write-CompleteSnapshot $coreSnapshotRoot
  New-Item -ItemType Directory -Path (Join-Path $coreInstallRoot "engine\signatures") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $coreInstallRoot "avorax_core_service.exe") -Force | Out-Null
  Write-CurrentInstallFiles $coreInstallRoot
  Write-Utf8NoBomFile (Join-Path $coreInstallRoot "engine\signatures\current.asig") "current Avorax signature fixture before destination-kind rollback`n"
  Set-Item -Path Env:\AVORAX_DATA_DIR -Value $coreDataRoot -ErrorAction Stop

  $coreResult = Invoke-ReleaseCommand $updateService @("--rollback", $coreInstallRoot) $repo $TimeoutSeconds
  $coreDiagnostic = "rollback destination target is not a regular file"
  if ($coreResult.ExitCode -eq 0 -or -not $coreResult.Stderr.Contains($coreDiagnostic)) {
    throw "core-service destination-kind diagnostic mismatch: $(Get-BoundedText $coreResult.Stderr)"
  }
  Assert-FileText (Join-Path $coreInstallRoot "Avorax.exe") "current Avorax app fixture before destination-kind rollback`n"
  Assert-Directory (Join-Path $coreInstallRoot "avorax_core_service.exe") "core-service destination"
  Assert-FileText (Join-Path $coreInstallRoot "avorax_guard_service.exe") "current Avorax guard service fixture before destination-kind rollback`n"
  Assert-FileText (Join-Path $coreInstallRoot "engine\signatures\current.asig") "current Avorax signature fixture before destination-kind rollback`n"
  Assert-MissingPath (Join-Path $coreInstallRoot "engine\signatures\rollback.asig") "rollback signature in core-service scenario"
  Assert-CommonFailureEvidence $coreDataRoot $coreDiagnostic

  $engineScenario = Join-Path $tempRoot "engine-file"
  $engineDataRoot = Join-Path $engineScenario "data"
  $engineInstallRoot = Join-Path $engineScenario "install"
  $engineSnapshotRoot = Join-Path $engineDataRoot "updates\rollback\0.5.0"
  Write-CompleteSnapshot $engineSnapshotRoot
  New-Item -ItemType Directory -Path $engineInstallRoot -Force | Out-Null
  Write-CurrentInstallFiles $engineInstallRoot
  Write-Utf8NoBomFile (Join-Path $engineInstallRoot "avorax_core_service.exe") "current Avorax core service fixture before destination-kind rollback`n"
  Write-Utf8NoBomFile (Join-Path $engineInstallRoot "engine") "current Avorax engine file fixture before destination-kind rollback`n"
  Set-Item -Path Env:\AVORAX_DATA_DIR -Value $engineDataRoot -ErrorAction Stop

  $engineResult = Invoke-ReleaseCommand $updateService @("--rollback", $engineInstallRoot) $repo $TimeoutSeconds
  $engineDiagnostic = "rollback destination target is not a directory"
  if ($engineResult.ExitCode -eq 0 -or -not $engineResult.Stderr.Contains($engineDiagnostic)) {
    throw "engine destination-kind diagnostic mismatch: $(Get-BoundedText $engineResult.Stderr)"
  }
  Assert-FileText (Join-Path $engineInstallRoot "Avorax.exe") "current Avorax app fixture before destination-kind rollback`n"
  Assert-FileText (Join-Path $engineInstallRoot "avorax_core_service.exe") "current Avorax core service fixture before destination-kind rollback`n"
  Assert-FileText (Join-Path $engineInstallRoot "avorax_guard_service.exe") "current Avorax guard service fixture before destination-kind rollback`n"
  Assert-FileText (Join-Path $engineInstallRoot "engine") "current Avorax engine file fixture before destination-kind rollback`n"
  Assert-CommonFailureEvidence $engineDataRoot $engineDiagnostic

  Write-Host "Avorax release update-service rollback destination-kind fail-safe smoke test passed."
  Write-Host "Core-service diagnostic: $(Get-BoundedText $coreResult.Stderr)"
  Write-Host "Engine diagnostic: $(Get-BoundedText $engineResult.Stderr)"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $oldDataDir
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
