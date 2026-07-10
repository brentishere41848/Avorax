param(
  [Parameter(Mandatory = $true)]
  [string]$LocalCorePath,
  [Parameter(Mandatory = $true)]
  [string]$EvidenceRoot,
  [string]$ReportPath = "",
  [ValidateRange(5, 600)]
  [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

$script:LifecycleReportByteLimit = 1048576
$script:LifecycleTempPrefix = "avorax-installed-core-lifecycle-"

function Resolve-AvoraxLifecycleEvidencePath {
  param(
    [string]$Root,
    [string]$ConfiguredPath
  )

  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Root "reports\installed_core_lifecycle_report.json"
  } elseif (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $Root $candidate
  }
  if ($candidate.Contains([char]0) -or $candidate.Length -gt 4096) {
    throw "Installed core lifecycle report path is invalid."
  }

  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($candidate)
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if ($pathFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
      -not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Installed core lifecycle report must be a child of EvidenceRoot: $pathFull"
  }
  if ([System.IO.Path]::GetExtension($pathFull) -ne ".json") {
    throw "Installed core lifecycle report must use a .json extension: $pathFull"
  }
  Assert-AvoraxNoReparsePath $pathFull "installed core lifecycle report"
  return $pathFull
}

function Get-AvoraxLifecycleSha256Bytes {
  param([byte[]]$Bytes)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

function Get-AvoraxLifecycleSha256File {
  param(
    [string]$Path,
    [string]$Description
  )
  $file = Get-AvoraxGateFile $Path $Description
  return (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Write-AvoraxLifecycleSignaturePack {
  param(
    [string]$EngineRoot,
    [string]$FixtureSha256
  )

  $signaturesDir = New-AvoraxGateDirectory (Join-Path $EngineRoot "signatures") "lifecycle signature directory"
  New-AvoraxGateDirectory (Join-Path $EngineRoot "rules") "lifecycle rule directory" | Out-Null
  New-AvoraxGateDirectory (Join-Path $EngineRoot "ml") "lifecycle model directory" | Out-Null
  New-AvoraxGateDirectory (Join-Path $EngineRoot "trust") "lifecycle trust directory" | Out-Null
  New-AvoraxGateDirectory (Join-Path $EngineRoot "config") "lifecycle config directory" | Out-Null

  $signature = [ordered]@{
    id = "ZNE-SAFE-INSTALLED-LIFECYCLE-001"
    name = "Installed lifecycle harmless exact-hash fixture"
    version = "1"
    category = "testThreat"
    confidence = "confirmed"
    severity = "test"
    signature_type = "exact_hash"
    pattern = $FixtureSha256
    mask = $null
    offset = $null
    file_types = @("*")
    min_file_size = $null
    max_file_size = $null
    required_context = @()
    false_positive_notes = "Safe fixture hash only; no malware binary is included or generated."
    action_policy = "quarantine_if_policy_allows"
    created_at = "2026-07-10T00:00:00Z"
    updated_at = "2026-07-10T00:00:00Z"
  }
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-10T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-INSTALLED-LIFECYCLE-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Installed lifecycle harmless exact-hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-10T00:00:00Z","version":"1"}],"version":"1.0.0"}'
  $pack = [ordered]@{
    format = "zentor-signature-pack-v1"
    version = "1.0.0"
    compiler_version = $null
    created_at = $null
    pack_sha256 = Get-AvoraxLifecycleSha256Bytes ([System.Text.UTF8Encoding]::new($false).GetBytes($canonicalJson))
    signatures = @($signature)
  }
  Write-AvoraxGateJsonFileAtomic (Join-Path $signaturesDir "avorax_core.asig") $pack 8 "lifecycle exact-hash signature pack"
}

function Read-AvoraxLifecycleReport {
  param(
    [string]$Path,
    [string]$Description
  )
  $json = Read-AvoraxGateTextFileBounded $Path $script:LifecycleReportByteLimit $Description
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "$Description is empty: $Path"
  }
  try {
    $report = ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    throw "$Description is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array] -or -not ($report -is [pscustomobject])) {
    throw "$Description must be one JSON object."
  }
  return $report
}

function Assert-AvoraxLifecycleWrapperSafety {
  param(
    [object]$Report,
    [string]$Description
  )
  foreach ($field in @(
    "live_malware_used",
    "standard_eicar_string_written",
    "defender_exclusion_required",
    "machine_wide_changes",
    "service_installation_attempted",
    "pre_execution_blocking_claimed"
  )) {
    if ($null -eq $Report.safety -or $Report.safety.PSObject.Properties.Name -notcontains $field -or
        $Report.safety.PSObject.Properties[$field].Value -ne $false) {
      throw "$Description safety.$field must be present and false."
    }
  }
}

function Invoke-AvoraxLifecycleWrapper {
  param(
    [string]$ScriptPath,
    [hashtable]$Parameters,
    [string]$Description
  )
  try {
    $null = & $ScriptPath @Parameters
  } catch {
    throw "$Description failed: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
}

function Get-AvoraxLifecycleQuarantinePayload {
  param(
    [AllowNull()][object]$Value,
    [string]$QuarantineRoot,
    [string]$Description
  )
  if (-not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace($Value)) {
    throw "$Description did not provide a quarantine payload path."
  }
  $rootFull = [System.IO.Path]::GetFullPath($QuarantineRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Value)
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if ($pathFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
      -not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description payload escaped the isolated quarantine root: $pathFull"
  }
  if ([System.IO.Path]::GetExtension($pathFull) -ne ".avoraxq") {
    throw "$Description payload must use the non-executable .avoraxq extension: $pathFull"
  }
  return Get-AvoraxGateFile $pathFull "$Description payload"
}

function Remove-AvoraxLifecycleTempRoot {
  param(
    [AllowNull()][string]$Path,
    [string]$TempBase
  )
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
  $baseFull = [System.IO.Path]::GetFullPath($TempBase).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $parent = [System.IO.Directory]::GetParent($pathFull)
  $leaf = [System.IO.Path]::GetFileName($pathFull)
  if ($null -eq $parent -or -not $parent.FullName.TrimEnd('\', '/').Equals($baseFull, [StringComparison]::OrdinalIgnoreCase) -or
      $leaf -notmatch '^avorax-installed-core-lifecycle-[0-9a-f]{32}$') {
    throw "Refusing to remove an unverified lifecycle temp directory: $pathFull"
  }
  Get-AvoraxGateDirectory $pathFull "isolated lifecycle temp directory" | Out-Null
  Remove-Item -LiteralPath $pathFull -Recurse -Force -ErrorAction Stop
  if (Test-Path -LiteralPath $pathFull) {
    throw "Isolated lifecycle temp directory still exists after cleanup: $pathFull"
  }
}

$startedAt = Get-Date
$binary = Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($LocalCorePath)) "installed core lifecycle executable"
if ([System.IO.Path]::GetFileName($binary) -ine "zentor_local_core.exe") {
  throw "Installed core lifecycle probe expects zentor_local_core.exe, got: $binary"
}
$evidence = Get-AvoraxGateDirectory ([System.IO.Path]::GetFullPath($EvidenceRoot)) "installed core lifecycle evidence root"
$reportFull = Resolve-AvoraxLifecycleEvidencePath $evidence $ReportPath
$localScanWrapper = Get-AvoraxGateFile (Join-Path $PSScriptRoot "avorax-local-scan.ps1") "installed lifecycle local scan wrapper"
$quarantineWrapper = Get-AvoraxGateFile (Join-Path $PSScriptRoot "avorax-quarantine.ps1") "installed lifecycle quarantine wrapper"
$binarySha256 = Get-AvoraxLifecycleSha256File $binary "installed core lifecycle executable"
Remove-AvoraxGateRegularFileIfPresent $reportFull "previous installed core lifecycle report"

$tempBase = Get-AvoraxGateDirectory ([System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())) "Windows temporary directory"
$tempRoot = Join-Path $tempBase ($script:LifecycleTempPrefix + [System.Guid]::NewGuid().ToString("N"))
$operations = [ordered]@{}
$failureMessage = $null
$cleanupVerified = $false

try {
  New-AvoraxGateDirectory $tempRoot "isolated lifecycle temp directory" | Out-Null
  $dataRoot = New-AvoraxGateDirectory (Join-Path $tempRoot "data") "isolated lifecycle data directory"
  $quarantineRoot = New-AvoraxGateDirectory (Join-Path $tempRoot "quarantine") "isolated lifecycle quarantine directory"
  $engineRoot = New-AvoraxGateDirectory (Join-Path $tempRoot "engine") "isolated lifecycle engine directory"
  $workReports = New-AvoraxGateDirectory (Join-Path $tempRoot "reports") "isolated lifecycle report directory"
  $allowlistFile = Join-Path $tempRoot "allowlist.json"
  $restoreFixture = Join-Path $tempRoot "harmless-lifecycle-restore.bin"
  $deleteFixture = Join-Path $tempRoot "harmless-lifecycle-delete.bin"
  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-installed-core-lifecycle-fixture-v1")
  $fixtureSha256 = Get-AvoraxLifecycleSha256Bytes $fixtureBytes
  [System.IO.File]::WriteAllBytes($restoreFixture, $fixtureBytes)
  [System.IO.File]::WriteAllBytes($deleteFixture, $fixtureBytes)
  [System.IO.File]::WriteAllText($allowlistFile, "[]", [System.Text.UTF8Encoding]::new($false))
  Get-AvoraxGateFile $restoreFixture "restore lifecycle fixture" | Out-Null
  Get-AvoraxGateFile $deleteFixture "delete lifecycle fixture" | Out-Null
  Get-AvoraxGateFile $allowlistFile "empty lifecycle allowlist" | Out-Null
  Write-AvoraxLifecycleSignaturePack $engineRoot $fixtureSha256

  $restoreScanPath = Join-Path $workReports "scan-restore.json"
  Invoke-AvoraxLifecycleWrapper $localScanWrapper @{
    RepoRoot = $tempRoot
    ScanType = "File"
    Path = @($restoreFixture)
    AutoQuarantineConfirmed = $true
    LocalCorePath = $binary
    ReportPath = $restoreScanPath
    DataRoot = $dataRoot
    QuarantineRoot = $quarantineRoot
    AllowlistFile = $allowlistFile
    EngineRoot = $engineRoot
    TimeoutSeconds = $TimeoutSeconds
  } "installed core restore-fixture scan"
  $restoreScan = Read-AvoraxLifecycleReport $restoreScanPath "installed core restore-fixture scan report"
  Assert-AvoraxLifecycleWrapperSafety $restoreScan "installed core restore-fixture scan report"
  $restoreThreat = @($restoreScan.raw_scan_report.threats) | Where-Object {
    $_.status -eq "quarantined" -and -not [string]::IsNullOrWhiteSpace([string]$_.quarantine_id)
  } | Select-Object -First 1
  if ($restoreScan.tool -ne "avorax-local-scan" -or $restoreScan.status -ne "threatsFound" -or
      $restoreScan.action_mode -ne "autoQuarantineConfirmedOnly" -or [int64]$restoreScan.files_scanned -ne 1 -or
      [int64]$restoreScan.threats_found -lt 1 -or [int64]$restoreScan.quarantined_files -lt 1 -or
      [int64]$restoreScan.scan_error_count -ne 0 -or $null -eq $restoreThreat) {
    $scanErrors = Get-AvoraxGateBoundedDiagnostic ($restoreScan.raw_scan_report.scan_errors | ConvertTo-Json -Compress -Depth 6)
    throw "Installed core restore-fixture scan did not produce one clean confirmed quarantine lifecycle result. Scan errors: $scanErrors"
  }
  if (Test-Path -LiteralPath $restoreFixture) {
    throw "Installed core restore-fixture scan left the source fixture in place."
  }
  $restoreId = [string]$restoreThreat.quarantine_id
  $restorePayload = Get-AvoraxLifecycleQuarantinePayload $restoreThreat.quarantine_path $quarantineRoot "restore-fixture scan"
  $operations.scan_restore = [ordered]@{
    wrapper = "avorax-local-scan"
    status = "threatsFound"
    action_mode = "autoQuarantineConfirmedOnly"
    files_scanned = 1
    threats_found = [int64]$restoreScan.threats_found
    quarantined_files = [int64]$restoreScan.quarantined_files
    quarantine_id = $restoreId
    source_removed = $true
    payload_extension = ".avoraxq"
    payload_created = $true
  }

  $listPath = Join-Path $workReports "list.json"
  Invoke-AvoraxLifecycleWrapper $quarantineWrapper @{
    RepoRoot = $tempRoot
    Action = "List"
    LocalCorePath = $binary
    ReportPath = $listPath
    DataRoot = $dataRoot
    QuarantineRoot = $quarantineRoot
    EngineRoot = $engineRoot
    TimeoutSeconds = $TimeoutSeconds
  } "installed core quarantine list"
  $list = Read-AvoraxLifecycleReport $listPath "installed core quarantine list report"
  Assert-AvoraxLifecycleWrapperSafety $list "installed core quarantine list report"
  $listedRecord = @($list.raw_response.records) | Where-Object { $_.quarantine_id -eq $restoreId } | Select-Object -First 1
  if ($list.tool -ne "avorax-quarantine" -or $list.action -ne "List" -or
      [int64]$list.records_count -lt 1 -or $null -eq $listedRecord -or $listedRecord.status -ne "quarantined") {
    throw "Installed core quarantine list did not return the quarantined restore fixture."
  }
  $listedPayload = Get-AvoraxLifecycleQuarantinePayload $listedRecord.quarantine_path $quarantineRoot "listed restore fixture"
  if (-not $listedPayload.Equals($restorePayload, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Installed core quarantine list changed the restore fixture payload path."
  }
  $operations.list = [ordered]@{
    wrapper = "avorax-quarantine"
    action = "List"
    records_count = [int64]$list.records_count
    quarantine_id = $restoreId
    record_found = $true
    record_status = "quarantined"
    payload_verified = $true
  }

  $restorePath = Join-Path $workReports "restore.json"
  Invoke-AvoraxLifecycleWrapper $quarantineWrapper @{
    RepoRoot = $tempRoot
    Action = "Restore"
    QuarantineId = $restoreId
    ConfirmAction = $true
    LocalCorePath = $binary
    ReportPath = $restorePath
    DataRoot = $dataRoot
    QuarantineRoot = $quarantineRoot
    EngineRoot = $engineRoot
    TimeoutSeconds = $TimeoutSeconds
  } "installed core quarantine restore"
  $restore = Read-AvoraxLifecycleReport $restorePath "installed core quarantine restore report"
  Assert-AvoraxLifecycleWrapperSafety $restore "installed core quarantine restore report"
  if ($restore.tool -ne "avorax-quarantine" -or $restore.action -ne "Restore" -or
      $restore.explicit_confirmation -ne $true -or $restore.raw_response.record.status -ne "restored" -or
      $restore.raw_response.record.action_taken -ne "restored") {
    throw "Installed core quarantine restore did not record a confirmed restored state."
  }
  Get-AvoraxGateFile $restoreFixture "restored lifecycle fixture" | Out-Null
  if ((Get-AvoraxLifecycleSha256File $restoreFixture "restored lifecycle fixture") -ne $fixtureSha256) {
    throw "Installed core quarantine restore did not reproduce the original harmless fixture hash."
  }
  if (Test-Path -LiteralPath $restorePayload) {
    throw "Installed core quarantine restore left its quarantine payload in place."
  }
  $operations.restore = [ordered]@{
    wrapper = "avorax-quarantine"
    action = "Restore"
    quarantine_id = $restoreId
    explicit_confirmation = $true
    record_status = "restored"
    action_taken = "restored"
    source_restored = $true
    fixture_sha256_verified = $true
    payload_removed = $true
  }

  $deleteScanPath = Join-Path $workReports "scan-delete.json"
  Invoke-AvoraxLifecycleWrapper $localScanWrapper @{
    RepoRoot = $tempRoot
    ScanType = "File"
    Path = @($deleteFixture)
    AutoQuarantineConfirmed = $true
    LocalCorePath = $binary
    ReportPath = $deleteScanPath
    DataRoot = $dataRoot
    QuarantineRoot = $quarantineRoot
    AllowlistFile = $allowlistFile
    EngineRoot = $engineRoot
    TimeoutSeconds = $TimeoutSeconds
  } "installed core delete-fixture scan"
  $deleteScan = Read-AvoraxLifecycleReport $deleteScanPath "installed core delete-fixture scan report"
  Assert-AvoraxLifecycleWrapperSafety $deleteScan "installed core delete-fixture scan report"
  $deleteThreat = @($deleteScan.raw_scan_report.threats) | Where-Object {
    $_.status -eq "quarantined" -and -not [string]::IsNullOrWhiteSpace([string]$_.quarantine_id)
  } | Select-Object -First 1
  if ($deleteScan.tool -ne "avorax-local-scan" -or $deleteScan.status -ne "threatsFound" -or
      $deleteScan.action_mode -ne "autoQuarantineConfirmedOnly" -or [int64]$deleteScan.files_scanned -ne 1 -or
      [int64]$deleteScan.threats_found -lt 1 -or [int64]$deleteScan.quarantined_files -lt 1 -or
      [int64]$deleteScan.scan_error_count -ne 0 -or $null -eq $deleteThreat) {
    $scanErrors = Get-AvoraxGateBoundedDiagnostic ($deleteScan.raw_scan_report.scan_errors | ConvertTo-Json -Compress -Depth 6)
    throw "Installed core delete-fixture scan did not produce one clean confirmed quarantine lifecycle result. Scan errors: $scanErrors"
  }
  if (Test-Path -LiteralPath $deleteFixture) {
    throw "Installed core delete-fixture scan left the source fixture in place."
  }
  $deleteId = [string]$deleteThreat.quarantine_id
  if ($deleteId -eq $restoreId) {
    throw "Installed core lifecycle reused a quarantine id across separate fixtures."
  }
  $deletePayload = Get-AvoraxLifecycleQuarantinePayload $deleteThreat.quarantine_path $quarantineRoot "delete-fixture scan"
  $operations.scan_delete = [ordered]@{
    wrapper = "avorax-local-scan"
    status = "threatsFound"
    action_mode = "autoQuarantineConfirmedOnly"
    files_scanned = 1
    threats_found = [int64]$deleteScan.threats_found
    quarantined_files = [int64]$deleteScan.quarantined_files
    quarantine_id = $deleteId
    source_removed = $true
    payload_extension = ".avoraxq"
    payload_created = $true
  }

  $deletePath = Join-Path $workReports "delete.json"
  Invoke-AvoraxLifecycleWrapper $quarantineWrapper @{
    RepoRoot = $tempRoot
    Action = "Delete"
    QuarantineId = $deleteId
    ConfirmAction = $true
    LocalCorePath = $binary
    ReportPath = $deletePath
    DataRoot = $dataRoot
    QuarantineRoot = $quarantineRoot
    EngineRoot = $engineRoot
    TimeoutSeconds = $TimeoutSeconds
  } "installed core quarantine delete"
  $delete = Read-AvoraxLifecycleReport $deletePath "installed core quarantine delete report"
  Assert-AvoraxLifecycleWrapperSafety $delete "installed core quarantine delete report"
  if ($delete.tool -ne "avorax-quarantine" -or $delete.action -ne "Delete" -or
      $delete.explicit_confirmation -ne $true -or $delete.raw_response.record.status -ne "deleted" -or
      $delete.raw_response.record.action_taken -ne "deleted") {
    throw "Installed core quarantine delete did not record a confirmed deleted state."
  }
  if (Test-Path -LiteralPath $deleteFixture) {
    throw "Installed core quarantine delete recreated the original fixture."
  }
  if (Test-Path -LiteralPath $deletePayload) {
    throw "Installed core quarantine delete left its quarantine payload in place."
  }
  $operations.delete = [ordered]@{
    wrapper = "avorax-quarantine"
    action = "Delete"
    quarantine_id = $deleteId
    explicit_confirmation = $true
    record_status = "deleted"
    action_taken = "deleted"
    source_absent = $true
    payload_removed = $true
    secure_erase_claimed = $false
  }
} catch {
  $failureMessage = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
}

try {
  Remove-AvoraxLifecycleTempRoot $tempRoot $tempBase
  $cleanupVerified = -not (Test-Path -LiteralPath $tempRoot)
} catch {
  $cleanupError = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
  if ([string]::IsNullOrWhiteSpace($failureMessage)) {
    $failureMessage = $cleanupError
  } else {
    $failureMessage = Get-AvoraxGateBoundedDiagnostic ($failureMessage + " Cleanup also failed: " + $cleanupError)
  }
}

$status = "passed"
if (-not [string]::IsNullOrWhiteSpace($failureMessage) -or -not $cleanupVerified) {
  $status = "failed"
  if ([string]::IsNullOrWhiteSpace($failureMessage)) {
    $failureMessage = "Isolated lifecycle cleanup was not verified."
  }
}
$report = [ordered]@{
  schema_version = 1
  status = $status
  tool = "avorax-installed-core-lifecycle-probe"
  started_at_utc = $startedAt.ToUniversalTime().ToString("o")
  completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  elapsed_seconds = [Math]::Round(((Get-Date) - $startedAt).TotalSeconds, 3)
  local_core_path = $binary
  local_core_sha256 = $binarySha256
  canonical_binary_name_verified = $true
  evidence_root = $evidence
  wrappers = @("avorax-local-scan.ps1", "avorax-quarantine.ps1")
  fixture_policy = [ordered]@{
    live_malware_used = $false
    standard_eicar_file_created = $false
    standard_eicar_string_written = $false
    harmless_exact_hash_fixture_only = $true
    network_access_required = $false
    description = "Harmless ASCII exact-hash fixtures only; no standard EICAR content."
  }
  operations = $operations
  cleanup = [ordered]@{
    isolated_temp_removed = [bool]$cleanupVerified
    isolated_temp_path_retained = [bool](-not $cleanupVerified)
  }
  safety = [ordered]@{
    defender_exclusion_required = $false
    machine_wide_changes = $false
    service_installation_attempted = $false
    driver_installation_attempted = $false
    installed_layout_claimed = $false
    installed_service_mediation_claimed = $false
    pre_execution_blocking_claimed = $false
    secure_erase_claimed = $false
  }
  limits = @(
    "canonical local-core executable and wrapper stdio lifecycle only",
    "no installed Windows service IPC claim",
    "no installed UI click-through evidence",
    "no pre-execution blocking claim"
  )
  error = if ($status -eq "passed") { $null } else { $failureMessage }
}

try {
  Write-AvoraxGateJsonFileAtomic $reportFull $report 12 "installed core lifecycle report"
} catch {
  $writeError = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
  if ($status -eq "passed") {
    throw "Installed core lifecycle succeeded but its evidence report could not be written: $writeError"
  }
  throw "Installed core lifecycle failed and its failure report could not be written: $failureMessage Report error: $writeError"
}

if ($status -ne "passed") {
  throw "Avorax installed core lifecycle probe failed: $failureMessage"
}

Write-Host "Avorax installed core lifecycle probe passed."
Write-Host "Report: $reportFull"
