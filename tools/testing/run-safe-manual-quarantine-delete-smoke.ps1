param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$CargoPath = "",
  [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"

function Resolve-ToolPath {
  param(
    [string]$ConfiguredPath,
    [string]$PreferredPath,
    [string]$FallbackName,
    [string]$Description
  )
  if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
    if (-not (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf)) {
      throw "$Description was configured but is not a file: $ConfiguredPath"
    }
    return (Resolve-Path -LiteralPath $ConfiguredPath).Path
  }
  if (-not [string]::IsNullOrWhiteSpace($PreferredPath) -and (Test-Path -LiteralPath $PreferredPath -PathType Leaf)) {
    return (Resolve-Path -LiteralPath $PreferredPath).Path
  }
  return $FallbackName
}

function Get-BoundedText {
  param([AllowNull()][object]$Value, [int]$MaxChars = 4096)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  $text = $text -replace "[`0-\x1F\x7F]+", " "
  if ($text.Length -le $MaxChars) { return $text }
  return $text.Substring(0, [Math]::Max(0, $MaxChars - 3)) + "..."
}

function Invoke-LocalCoreJson {
  param(
    [hashtable]$Command,
    [string]$InputJsonPath,
    [string]$Repo,
    [string]$Cargo,
    [string]$Manifest,
    [int]$Timeout
  )

  $json = $Command | ConvertTo-Json -Compress
  [System.IO.File]::WriteAllText(
    $InputJsonPath,
    $json + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $process = $null
  try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "cmd.exe"
    $startInfo.WorkingDirectory = $Repo
    $startInfo.Arguments = "/d /c `"type `"$InputJsonPath`" | `"$Cargo`" run --quiet --manifest-path `"$Manifest`"`""
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
      } catch {
        throw "local-core timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "local-core timed out after ${Timeout}s."
    }

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    if ($process.ExitCode -ne 0) {
      throw "local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
    }

    $jsonResponses = @()
    foreach ($line in ($stdout -split "`r?`n")) {
      $trimmed = $line.Trim()
      if ($trimmed.Length -eq 0) { continue }
      if ($trimmed.StartsWith("{`"type`":`"scan_progress`"")) { continue }
      try {
        $jsonResponses += $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "local-core emitted non-JSON stdout during manual quarantine delete smoke test: $(Get-BoundedText $trimmed)"
      }
    }
    if ($jsonResponses.Count -eq 0) {
      throw "local-core produced no JSON response. stderr: $(Get-BoundedText $stderr)"
    }
    return $jsonResponses[-1]
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$cargo = Resolve-ToolPath $CargoPath "C:\Users\Brent\.cargo\bin\cargo.exe" "cargo" "Cargo"
$manifest = Join-Path $repo "core\zentor_local_core\Cargo.toml"
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
  throw "Local-core manifest is missing: $manifest"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-safe-manual-quarantine-delete-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$fixture = Join-Path $tempRoot "manual-quarantine-delete-benign.txt"
$inputJson = Join-Path $tempRoot "local-core-command.json"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$previousPath = $env:PATH
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  Set-Content -LiteralPath $fixture -Value "AVORAX-SAFE-MANUAL-QUARANTINE-DELETE-FIXTURE" -NoNewline -Encoding ASCII

  $pathAdditions = @(
    "C:\Program Files\Git\cmd",
    "C:\Users\Brent\.cargo\bin"
  ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
  if ($pathAdditions.Count -gt 0) {
    $env:PATH = (($pathAdditions + @($env:PATH)) -join [System.IO.Path]::PathSeparator)
  }
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot

  $quarantine = Invoke-LocalCoreJson @{
    command = "quarantine_file"
    path = $fixture
    threat_name = "Manual safe quarantine delete smoke"
    engine = "zentor-manual-delete-smoke"
  } $inputJson $repo $cargo $manifest $TimeoutSeconds
  if ($quarantine.ok -ne $true -or $quarantine.record.status -ne "quarantined" -or $quarantine.record.action_taken -ne "quarantined") {
    throw "manual quarantine delete smoke did not quarantine the benign fixture: $(Get-BoundedText ($quarantine | ConvertTo-Json -Compress))"
  }
  if (Test-Path -LiteralPath $fixture) {
    throw "manual quarantine delete smoke left the source fixture in place after quarantine"
  }
  if (-not (Test-Path -LiteralPath $quarantine.record.quarantine_path -PathType Leaf)) {
    throw "manual quarantine delete smoke record payload is missing: $($quarantine.record.quarantine_path)"
  }

  $delete = Invoke-LocalCoreJson @{
    command = "delete_quarantine_item"
    quarantine_id = $quarantine.record.quarantine_id
    confirmed = $true
  } $inputJson $repo $cargo $manifest $TimeoutSeconds
  if ($delete.ok -ne $true -or $delete.record.status -ne "deleted" -or $delete.record.action_taken -ne "deleted") {
    throw "manual quarantine delete smoke delete failed: $(Get-BoundedText ($delete | ConvertTo-Json -Compress))"
  }
  if (Test-Path -LiteralPath $quarantine.record.quarantine_path) {
    throw "manual quarantine delete smoke left the quarantined payload after delete"
  }
  if (Test-Path -LiteralPath $fixture) {
    throw "manual quarantine delete smoke restored the source fixture during delete"
  }

  Write-Host "Avorax safe manual quarantine/delete smoke test passed."
  Write-Host "Fixture: $fixture"
  Write-Host "Quarantine id: $($quarantine.record.quarantine_id)"
  Write-Host "Quarantine status: $($quarantine.record.status)"
  Write-Host "Delete status: $($delete.record.status)"
} finally {
  $env:PATH = $previousPath
  if ($null -eq $previousQuarantineDir) {
    if (Test-Path Env:\AVORAX_QUARANTINE_DIR) {
      Remove-Item Env:\AVORAX_QUARANTINE_DIR -ErrorAction Stop
    }
  } else {
    $env:AVORAX_QUARANTINE_DIR = $previousQuarantineDir
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
