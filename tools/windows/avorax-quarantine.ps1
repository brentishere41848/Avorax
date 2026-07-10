param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [ValidateSet("List", "Quarantine", "Restore", "Delete", "Rescan")]
  [string]$Action = "List",
  [string]$QuarantineId = "",
  [string]$TargetPath = "",
  [string]$ThreatName = "Manual quarantine",
  [string]$Engine = "avorax-manual-quarantine-wrapper",
  [switch]$ConfirmAction,
  [string]$LocalCorePath = "",
  [string]$ReportPath = "",
  [string]$DataRoot = "",
  [string]$QuarantineRoot = "",
  [string]$EngineRoot = "",
  [int]$TimeoutSeconds = 120
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

function Assert-NotReparsePath {
  param([string]$PathValue, [string]$Description)
  $item = Get-Item -LiteralPath $PathValue -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $PathValue"
  }
}

function Resolve-RepoChildPath {
  param([string]$Repo, [string]$PathValue, [string]$Description)
  $rootFull = [System.IO.Path]::GetFullPath($Repo).TrimEnd('\', '/')
  $candidate = $PathValue
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $rootFull $candidate
  }
  $pathFull = [System.IO.Path]::GetFullPath($candidate)
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be inside the repository: $pathFull"
  }
  if ($pathFull.TrimEnd('\', '/').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be a child file, not the repository root."
  }
  return $pathFull
}

function Resolve-LocalCoreBinary {
  param([string]$Repo, [string]$ConfiguredPath)
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\zentor_local_core.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release local-core binary is missing: $candidate. Run cargo build --release --manifest-path core\zentor_local_core\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne "zentor_local_core.exe") {
    throw "Avorax quarantine expects zentor_local_core.exe, got: $resolved"
  }
  Assert-NotReparsePath $resolved "local-core binary"
  return $resolved
}

function Resolve-OptionalRoot {
  param([string]$PathValue, [string]$Description)
  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    return ""
  }
  if ($PathValue.Contains([char]0)) {
    throw "$Description contains a NUL byte."
  }
  if ($PathValue.Length -gt 4096) {
    throw "$Description exceeds 4096 characters."
  }
  New-Item -ItemType Directory -Path $PathValue -Force | Out-Null
  $resolved = (Resolve-Path -LiteralPath $PathValue).Path
  Assert-NotReparsePath $resolved $Description
  return $resolved
}

function Resolve-OptionalExistingRoot {
  param([string]$PathValue, [string]$Description)
  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    return ""
  }
  if ($PathValue.Contains([char]0)) {
    throw "$Description contains a NUL byte."
  }
  if ($PathValue.Length -gt 4096) {
    throw "$Description exceeds 4096 characters."
  }
  if ($PathValue -replace '/', '\' -match '(^|\\)\.\.(\\|$)') {
    throw "$Description must not contain parent traversal."
  }
  if (-not (Test-Path -LiteralPath $PathValue -PathType Container)) {
    throw "$Description does not exist: $PathValue"
  }
  $resolved = (Resolve-Path -LiteralPath $PathValue).Path
  Assert-NotReparsePath $resolved $Description
  return $resolved
}

function Resolve-ManualQuarantineTarget {
  param([string]$PathValue)
  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    throw "Quarantine action requires -TargetPath."
  }
  if ($PathValue.Contains([char]0)) {
    throw "TargetPath contains a NUL byte."
  }
  if ($PathValue.Length -gt 4096) {
    throw "TargetPath exceeds 4096 characters."
  }
  if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
    throw "TargetPath must be an existing file: $PathValue"
  }
  $resolved = (Resolve-Path -LiteralPath $PathValue).Path
  Assert-NotReparsePath $resolved "manual quarantine target"
  return $resolved
}

function Get-BoundedIpcText {
  param([string]$Value, [string]$Description, [int]$MaxChars)
  if ([string]::IsNullOrWhiteSpace($Value)) {
    throw "$Description must not be empty."
  }
  if ($Value.Contains([char]0)) {
    throw "$Description contains a NUL byte."
  }
  $trimmed = $Value.Trim()
  if ($trimmed.Length -gt $MaxChars) {
    throw "$Description exceeds $MaxChars characters."
  }
  return $trimmed
}

function Assert-QuarantineId {
  param([string]$Id)
  if ([string]::IsNullOrWhiteSpace($Id)) {
    throw "Restore/Delete requires -QuarantineId."
  }
  if ($Id.Trim() -ne $Id) {
    throw "QuarantineId must not contain leading or trailing whitespace."
  }
  if ($Id.Contains([char]0)) {
    throw "QuarantineId contains a NUL byte."
  }
  if ($Id.Length -gt 128) {
    throw "QuarantineId exceeds maximum length."
  }
  if ($Id -notmatch '^[A-Za-z0-9_-]+$') {
    throw "QuarantineId may contain only ASCII letters, digits, hyphen, and underscore."
  }
}

function Get-JsonArrayItems {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) {
    return @()
  }
  if ($Value -is [System.Array]) {
    return @($Value)
  }
  return @($Value)
}

function Resolve-QuarantinePayloadForRescan {
  param([object]$Record, [string]$ResolvedQuarantineRoot)
  $payload = [string]$Record.quarantine_path
  if ([string]::IsNullOrWhiteSpace($payload)) {
    throw "Quarantine record is missing quarantine_path."
  }
  if ($payload.Contains([char]0)) {
    throw "Quarantine payload path contains a NUL byte."
  }
  if ($payload.Length -gt 4096) {
    throw "Quarantine payload path exceeds 4096 characters."
  }
  if (-not [System.IO.Path]::IsPathRooted($payload)) {
    throw "Quarantine payload path must be absolute for rescan: $payload"
  }
  if ([System.IO.Path]::GetExtension($payload) -ne ".avoraxq") {
    throw "Quarantine payload rescan requires a .avoraxq payload: $payload"
  }
  if (-not (Test-Path -LiteralPath $payload -PathType Leaf)) {
    throw "Quarantine payload is missing for rescan: $payload"
  }
  $resolved = (Resolve-Path -LiteralPath $payload).Path
  Assert-NotReparsePath $resolved "quarantine payload"

  if (-not [string]::IsNullOrWhiteSpace($ResolvedQuarantineRoot)) {
    $rootFull = [System.IO.Path]::GetFullPath($ResolvedQuarantineRoot).TrimEnd('\', '/')
    $payloadFull = [System.IO.Path]::GetFullPath($resolved)
    $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $payloadFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Quarantine payload rescan must stay inside QuarantineRoot: $payloadFull"
    }
  }

  return $resolved
}

function Invoke-LocalCoreJson {
  param(
    [object]$Command,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout
  )

  $json = $Command | ConvertTo-Json -Compress
  $process = $null
  try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Binary
    $startInfo.WorkingDirectory = $Repo
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.WriteLine($json)
    $process.StandardInput.Close()

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "Avorax quarantine command timed out after ${Timeout}s and failed to stop local-core: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "Avorax quarantine command timed out after ${Timeout}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
      throw "local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
    }

    $responses = @()
    foreach ($line in ($stdout -split "`r?`n")) {
      $trimmed = $line.Trim()
      if ($trimmed.Length -eq 0) { continue }
      try {
        $body = $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "local-core emitted non-JSON stdout during Avorax quarantine command: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
        continue
      }
      $responses += $body
    }
    if ($responses.Count -eq 0) {
      throw "local-core produced no JSON quarantine response. stderr: $(Get-BoundedText $stderr)"
    }
    $response = $responses[-1]
    if (($response.PSObject.Properties.Name -contains "ok") -and $response.ok -eq $false) {
      throw "local-core rejected Avorax quarantine command: $(Get-BoundedText $response.error)"
    }
    return [ordered]@{
      response = $response
      stderr = Get-BoundedText $stderr
    }
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Write-JsonReportAtomic {
  param([string]$PathValue, [object]$Body)
  $directory = Split-Path -Parent $PathValue
  if (-not [string]::IsNullOrWhiteSpace($directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }
  $tempPath = Join-Path $directory (".tmp-" + [System.Guid]::NewGuid().ToString("N") + ".json")
  $backupPath = Join-Path $directory (".bak-" + [System.Guid]::NewGuid().ToString("N") + ".json")
  $json = $Body | ConvertTo-Json -Depth 100
  [System.IO.File]::WriteAllText($tempPath, $json + "`r`n", [System.Text.UTF8Encoding]::new($false))
  if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
    [System.IO.File]::Replace($tempPath, $PathValue, $backupPath, $true)
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
      Remove-Item -LiteralPath $backupPath -Force
    }
  } else {
    [System.IO.File]::Move($tempPath, $PathValue)
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

if ($Action -eq "List") {
  if (-not [string]::IsNullOrWhiteSpace($QuarantineId)) {
    throw "List action does not accept -QuarantineId."
  }
  if (-not [string]::IsNullOrWhiteSpace($TargetPath)) {
    throw "List action does not accept -TargetPath."
  }
  if ($ConfirmAction) {
    throw "List action does not accept -ConfirmAction."
  }
} elseif ($Action -eq "Quarantine") {
  if (-not [string]::IsNullOrWhiteSpace($QuarantineId)) {
    throw "Quarantine action does not accept -QuarantineId."
  }
  if (-not $ConfirmAction) {
    throw "Quarantine requires -ConfirmAction. Avorax will not manually quarantine files without explicit confirmation."
  }
} elseif ($Action -eq "Rescan") {
  Assert-QuarantineId $QuarantineId
  if (-not [string]::IsNullOrWhiteSpace($TargetPath)) {
    throw "Rescan action does not accept -TargetPath."
  }
  if ($ConfirmAction) {
    throw "Rescan does not accept -ConfirmAction because it is detect-only and does not restore or delete quarantine items."
  }
} else {
  Assert-QuarantineId $QuarantineId
  if (-not [string]::IsNullOrWhiteSpace($TargetPath)) {
    throw "$Action action does not accept -TargetPath."
  }
  if (-not $ConfirmAction) {
    throw "$Action requires -ConfirmAction. Avorax will not restore or delete quarantine items without explicit confirmation."
  }
}

$command = [ordered]@{ command = "list_quarantine" }
$manualTargetFull = ""
$manualThreatName = ""
$manualEngine = ""
if ($Action -eq "Quarantine") {
  $manualTargetFull = Resolve-ManualQuarantineTarget $TargetPath
  $manualThreatName = Get-BoundedIpcText $ThreatName "ThreatName" 256
  $manualEngine = Get-BoundedIpcText $Engine "Engine" 128
  $command = [ordered]@{
    command = "quarantine_file"
    path = $manualTargetFull
    threat_name = $manualThreatName
    engine = $manualEngine
  }
} elseif ($Action -eq "Restore") {
  $command = [ordered]@{
    command = "restore_quarantine_item"
    quarantine_id = $QuarantineId
    confirmed = $true
  }
} elseif ($Action -eq "Delete") {
  $command = [ordered]@{
    command = "delete_quarantine_item"
    quarantine_id = $QuarantineId
    confirmed = $true
  }
}

$reportFull = ""
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
  $reportFull = Resolve-RepoChildPath $repo $ReportPath "Avorax quarantine report"
}

$previousDataDir = $env:AVORAX_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  $resolvedDataRoot = Resolve-OptionalRoot $DataRoot "DataRoot"
  if (-not [string]::IsNullOrWhiteSpace($resolvedDataRoot)) {
    $env:AVORAX_DATA_DIR = $resolvedDataRoot
  }
  $resolvedQuarantineRoot = Resolve-OptionalRoot $QuarantineRoot "QuarantineRoot"
  if (-not [string]::IsNullOrWhiteSpace($resolvedQuarantineRoot)) {
    $env:AVORAX_QUARANTINE_DIR = $resolvedQuarantineRoot
  }
  $resolvedEngineRoot = Resolve-OptionalExistingRoot $EngineRoot "EngineRoot"
  if (-not [string]::IsNullOrWhiteSpace($resolvedEngineRoot)) {
    $env:AVORAX_ENGINE_DIR = $resolvedEngineRoot
  }

  $result = Invoke-LocalCoreJson $command $repo $binary $TimeoutSeconds
  $response = $result.response
  $records = if ($Action -eq "List" -or $Action -eq "Rescan") {
    @(Get-JsonArrayItems $response.records)
  } else {
    @(Get-JsonArrayItems $response.record)
  }
  $selectedRecord = $null
  $rescan = $null
  if ($Action -eq "Rescan") {
    $selectedRecord = @($records | Where-Object { $_.quarantine_id -eq $QuarantineId }) | Select-Object -First 1
    if ($null -eq $selectedRecord) {
      throw "Quarantine item not found for rescan: $QuarantineId"
    }
    if ([string]$selectedRecord.status -ne "quarantined") {
      throw "Quarantine item must be in quarantined status before rescan: $QuarantineId"
    }
    $payloadFull = Resolve-QuarantinePayloadForRescan $selectedRecord $resolvedQuarantineRoot
    $rescanCommand = [ordered]@{
      command = "scan_file"
      path = $payloadFull
      scan_kind = "custom"
      action_mode = "detectOnly"
    }
    $rescanResult = Invoke-LocalCoreJson $rescanCommand $repo $binary $TimeoutSeconds
    $rescan = $rescanResult.response
  }

  $summary = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    tool = "avorax-quarantine"
    repository = $repo
    local_core_path = $binary
    action = $Action
    quarantine_id = if ($Action -eq "List") { "" } elseif ($Action -eq "Quarantine" -and $null -ne $response.record) { [string]$response.record.quarantine_id } else { $QuarantineId }
    target_path = if ($Action -eq "Quarantine") { $manualTargetFull } else { "" }
    threat_name = if ($Action -eq "Quarantine") { $manualThreatName } else { "" }
    engine = if ($Action -eq "Quarantine") { $manualEngine } else { "" }
    explicit_confirmation = [bool]$ConfirmAction
    records_count = [int]@($records).Count
    rescan_status = if ($Action -eq "Rescan") { [string]$rescan.status } else { "" }
    rescan_files_scanned = if ($Action -eq "Rescan" -and $null -ne $rescan.files_scanned) { [int64]$rescan.files_scanned } else { 0 }
    rescan_threats_found = if ($Action -eq "Rescan" -and $null -ne $rescan.threats_found) { [int64]$rescan.threats_found } else { 0 }
    rescan_quarantined_files = if ($Action -eq "Rescan" -and $null -ne $rescan.quarantined_files) { [int64]$rescan.quarantined_files } else { 0 }
    rescan_payload_path = if ($Action -eq "Rescan") { $payloadFull } else { "" }
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      pre_execution_blocking_claimed = $false
      secure_erase_claimed = $false
      manual_quarantine_requires_confirmation = $true
      restore_during_rescan = $false
      delete_during_rescan = $false
    }
    selected_record = $selectedRecord
    raw_response = $response
    raw_rescan_report = $rescan
  }

  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-JsonReportAtomic $reportFull $summary
  }

  Write-Host "Avorax quarantine command completed."
  Write-Host "Action: $Action"
  Write-Host "Records: $($summary.records_count)"
  if ($Action -ne "List" -and $Action -ne "Quarantine") {
    Write-Host "Quarantine id: $QuarantineId"
  }
  if ($Action -eq "Quarantine") {
    Write-Host "Quarantine id: $($summary.quarantine_id)"
    Write-Host "Target: $manualTargetFull"
    Write-Host "Manual quarantine status: $($response.record.status)"
  }
  if ($Action -eq "Rescan") {
    Write-Host "Rescan status: $($summary.rescan_status)"
    Write-Host "Rescan files scanned: $($summary.rescan_files_scanned)"
    Write-Host "Rescan threats found: $($summary.rescan_threats_found)"
  }
  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-Host "Report: $reportFull"
  }
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "AVORAX_QUARANTINE_DIR" $previousQuarantineDir
  Restore-EnvVar "AVORAX_ENGINE_DIR" $previousEngineDir
}
