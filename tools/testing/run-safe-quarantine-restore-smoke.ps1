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
        throw "local-core emitted non-JSON stdout during quarantine smoke test: $(Get-BoundedText $trimmed)"
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

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-safe-quarantine-restore-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$fixture = Join-Path $tempRoot "safe-eicar-quarantine.com"
$inputJson = Join-Path $tempRoot "local-core-command.json"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$previousPath = $env:PATH
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  Set-Content -LiteralPath $fixture -Value "ZENTOR-SAFE-EICAR-SIMULATOR-FILE" -NoNewline -Encoding ASCII
  $expectedContent = [System.IO.File]::ReadAllText($fixture, [System.Text.Encoding]::ASCII)

  $pathAdditions = @(
    "C:\Program Files\Git\cmd",
    "C:\Users\Brent\.cargo\bin"
  ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
  if ($pathAdditions.Count -gt 0) {
    $env:PATH = (($pathAdditions + @($env:PATH)) -join [System.IO.Path]::PathSeparator)
  }
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot

  $scan = Invoke-LocalCoreJson @{
    command = "scan_file"
    path = $fixture
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "custom"
  } $inputJson $repo $cargo $manifest $TimeoutSeconds

  $threats = @($scan.threats)
  $quarantinedThreat = $threats | Where-Object {
    $_.status -eq "quarantined" -and
    ($_.confidence -eq "confirmed" -or $_.reason_summary -like "*safe simulator*" -or $_.reason_summary -like "*ZENTOR-SAFE*")
  } | Select-Object -First 1
  if ($scan.status -ne "threatsFound") {
    throw "safe quarantine smoke scan did not return a threat status: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($null -eq $quarantinedThreat) {
    throw "safe quarantine smoke scan did not quarantine a confirmed simulator threat: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ([string]::IsNullOrWhiteSpace([string]$quarantinedThreat.quarantine_id)) {
    throw "safe quarantine smoke scan did not include quarantine_id on the quarantined threat row: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ([string]::IsNullOrWhiteSpace([string]$quarantinedThreat.quarantine_path) -or -not ([string]$quarantinedThreat.quarantine_path).EndsWith(".avoraxq")) {
    throw "safe quarantine smoke scan did not include a safe quarantine_path on the quarantined threat row: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($quarantinedThreat.quarantine_action_taken -ne "quarantined") {
    throw "safe quarantine smoke scan did not include quarantined action evidence on the threat row: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if (Test-Path -LiteralPath $fixture) {
    throw "safe quarantine smoke left the source fixture in place after auto-quarantine"
  }

  $list = Invoke-LocalCoreJson @{ command = "list_quarantine" } $inputJson $repo $cargo $manifest $TimeoutSeconds
  if ($list.ok -ne $true) {
    throw "list_quarantine failed after safe quarantine smoke scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress))"
  }
  $record = @($list.records) | Where-Object {
    $_.quarantine_id -eq $quarantinedThreat.quarantine_id -and
    $_.original_path -eq $fixture -and
    $_.status -eq "quarantined" -and
    $_.action_taken -eq "quarantined" -and
    $_.quarantine_path -like "*.avoraxq"
  } | Select-Object -First 1
  if ($null -eq $record) {
    throw "safe quarantine smoke did not list the quarantined simulator record: $(Get-BoundedText ($list | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $record.quarantine_path -PathType Leaf)) {
    throw "safe quarantine smoke record payload is missing: $($record.quarantine_path)"
  }

  $restore = Invoke-LocalCoreJson @{
    command = "restore_quarantine_item"
    quarantine_id = $record.quarantine_id
    confirmed = $true
  } $inputJson $repo $cargo $manifest $TimeoutSeconds
  if ($restore.ok -ne $true -or $restore.record.status -ne "restored" -or $restore.record.action_taken -ne "restored") {
    throw "safe quarantine smoke restore failed: $(Get-BoundedText ($restore | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw "safe quarantine smoke did not restore the original fixture path"
  }
  $restoredContent = [System.IO.File]::ReadAllText($fixture, [System.Text.Encoding]::ASCII)
  if ($restoredContent -ne $expectedContent) {
    throw "safe quarantine smoke restored content does not match the original simulator"
  }
  if (Test-Path -LiteralPath $record.quarantine_path) {
    throw "safe quarantine smoke left the quarantined payload after restore"
  }

  Write-Host "Avorax safe quarantine/restore smoke test passed."
  Write-Host "Fixture: $fixture"
  Write-Host "Status: $($scan.status)"
  Write-Host "Threats: $($threats.Count)"
  Write-Host "Action mode: autoQuarantineConfirmedOnly"
  Write-Host "Quarantine id: $($record.quarantine_id)"
  Write-Host "Restore status: $($restore.record.status)"
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
