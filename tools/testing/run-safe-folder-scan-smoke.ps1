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
        throw "local-core emitted non-JSON stdout during safe folder scan smoke test: $(Get-BoundedText $trimmed)"
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

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-safe-folder-scan-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$scanRoot = Join-Path $tempRoot "scan-root"
$benign = Join-Path $scanRoot "benign-note.txt"
$simulator = Join-Path $scanRoot "safe-eicar-folder.com"
$inputJson = Join-Path $tempRoot "local-core-command.json"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$previousPath = $env:PATH
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR

try {
  New-Item -ItemType Directory -Path $scanRoot -Force | Out-Null
  Set-Content -LiteralPath $benign -Value "AVORAX-SAFE-BENIGN-FOLDER-SCAN-FIXTURE" -NoNewline -Encoding ASCII
  Set-Content -LiteralPath $simulator -Value "ZENTOR-SAFE-EICAR-SIMULATOR-FILE" -NoNewline -Encoding ASCII

  $pathAdditions = @(
    "C:\Program Files\Git\cmd",
    "C:\Users\Brent\.cargo\bin"
  ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
  if ($pathAdditions.Count -gt 0) {
    $env:PATH = (($pathAdditions + @($env:PATH)) -join [System.IO.Path]::PathSeparator)
  }
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot

  $scan = Invoke-LocalCoreJson @{
    command = "scan_folder"
    path = $scanRoot
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "custom"
  } $inputJson $repo $cargo $manifest $TimeoutSeconds

  $threats = @($scan.threats)
  $quarantinedThreat = $threats | Where-Object {
    $_.status -eq "quarantined" -and
    $_.path -eq $simulator -and
    ($_.confidence -eq "confirmed" -or $_.reason_summary -like "*safe simulator*" -or $_.reason_summary -like "*ZENTOR-SAFE*")
  } | Select-Object -First 1
  if ($scan.status -ne "threatsFound") {
    throw "safe folder scan smoke did not return a threat status: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($scan.files_scanned -lt 2) {
    throw "safe folder scan smoke did not scan both safe fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($null -eq $quarantinedThreat) {
    throw "safe folder scan smoke did not quarantine the simulator from the folder scan: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($scan.quarantined_files -lt 1) {
    throw "safe folder scan smoke did not report quarantined files: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $benign -PathType Leaf)) {
    throw "safe folder scan smoke moved or removed the benign fixture"
  }
  if (Test-Path -LiteralPath $simulator) {
    throw "safe folder scan smoke left the simulator source in place after auto-quarantine"
  }
  if ([string]::IsNullOrWhiteSpace([string]$quarantinedThreat.quarantine_id)) {
    throw "safe folder scan smoke did not include quarantine_id evidence: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ([string]::IsNullOrWhiteSpace([string]$quarantinedThreat.quarantine_path) -or -not ([string]$quarantinedThreat.quarantine_path).EndsWith(".avoraxq")) {
    throw "safe folder scan smoke did not include .avoraxq quarantine_path evidence: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $quarantinedThreat.quarantine_path -PathType Leaf)) {
    throw "safe folder scan smoke quarantine payload is missing: $($quarantinedThreat.quarantine_path)"
  }

  Write-Host "Avorax safe folder scan smoke test passed."
  Write-Host "Scan root: $scanRoot"
  Write-Host "Status: $($scan.status)"
  Write-Host "Files scanned: $($scan.files_scanned)"
  Write-Host "Threats: $($threats.Count)"
  Write-Host "Quarantined files: $($scan.quarantined_files)"
  Write-Host "Quarantine id: $($quarantinedThreat.quarantine_id)"
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
