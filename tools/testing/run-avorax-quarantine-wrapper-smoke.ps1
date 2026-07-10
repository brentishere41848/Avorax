param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [int]$TimeoutSeconds = 180
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
    throw "Avorax quarantine wrapper smoke expects zentor_local_core.exe, got: $resolved"
  }
  return $resolved
}

function Get-Sha256Hex {
  param([byte[]]$Bytes)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

function Write-QuarantineWrapperSignaturePack {
  param([string]$EngineRoot, [string]$FixtureSha256)
  $signaturesDir = Join-Path $EngineRoot "signatures"
  $rulesDir = Join-Path $EngineRoot "rules"
  $mlDir = Join-Path $EngineRoot "ml"
  $trustDir = Join-Path $EngineRoot "trust"
  $configDir = Join-Path $EngineRoot "config"
  New-Item -ItemType Directory -Path $signaturesDir -Force | Out-Null
  New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
  New-Item -ItemType Directory -Path $mlDir -Force | Out-Null
  New-Item -ItemType Directory -Path $trustDir -Force | Out-Null
  New-Item -ItemType Directory -Path $configDir -Force | Out-Null

  $signature = [ordered]@{
    id = "ZNE-SAFE-QUARANTINE-WRAPPER-001"
    name = "Quarantine wrapper harmless known-bad hash fixture"
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
    created_at = "2026-07-08T00:00:00Z"
    updated_at = "2026-07-08T00:00:00Z"
  }
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-08T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-QUARANTINE-WRAPPER-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Quarantine wrapper harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-08T00:00:00Z","version":"1"}],"version":"1.0.0"}'
  $canonicalBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonicalJson)
  $packSha256 = Get-Sha256Hex $canonicalBytes
  $pack = [ordered]@{
    format = "zentor-signature-pack-v1"
    version = "1.0.0"
    compiler_version = $null
    created_at = $null
    pack_sha256 = $packSha256
    signatures = @($signature)
  }
  [System.IO.File]::WriteAllText(
    (Join-Path $signaturesDir "avorax_core.asig"),
    ($pack | ConvertTo-Json -Depth 8) + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )
}

function Read-JsonFile {
  param([string]$PathValue, [string]$Description)
  if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
    throw "$Description was not written: $PathValue"
  }
  return Get-Content -LiteralPath $PathValue -Raw | ConvertFrom-Json -ErrorAction Stop
}

function Write-JsonFileAtomic {
  param([string]$PathValue, [object]$Body)
  $directory = Split-Path -Parent $PathValue
  if (-not [string]::IsNullOrWhiteSpace($directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }
  $tempPath = Join-Path $directory (".tmp-" + [System.Guid]::NewGuid().ToString("N") + ".json")
  $backupPath = Join-Path $directory (".bak-" + [System.Guid]::NewGuid().ToString("N") + ".json")
  $json = $Body | ConvertTo-Json -Depth 20
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

function Invoke-Wrapper {
  param([string[]]$Arguments, [bool]$ExpectSuccess = $true)
  $previousErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $output = & powershell.exe @Arguments 2>&1
    $exit = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  if ($ExpectSuccess -and $exit -ne 0) {
    throw "wrapper command failed with exit ${exit}: $(Get-BoundedText ($output -join ' '))"
  }
  if (-not $ExpectSuccess -and $exit -eq 0) {
    throw "wrapper command unexpectedly succeeded: $(Get-BoundedText ($output -join ' '))"
  }
  return [ordered]@{
    exit = $exit
    output = ($output -join "`n")
  }
}

function Assert-SafetyReport {
  param([object]$Report, [string]$Description)
  if ($Report.tool -ne "avorax-quarantine") {
    throw "$Description tool mismatch: $($Report.tool)"
  }
  foreach ($field in @(
    "live_malware_used",
    "standard_eicar_string_written",
    "defender_exclusion_required",
    "machine_wide_changes",
    "service_installation_attempted",
    "pre_execution_blocking_claimed",
    "secure_erase_claimed",
    "restore_during_rescan",
    "delete_during_rescan"
  )) {
    if ($Report.safety.$field -ne $false) {
      throw "$Description safety.$field must be false."
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$localScanWrapper = Join-Path $repo "tools\windows\avorax-local-scan.ps1"
$quarantineWrapper = Join-Path $repo "tools\windows\avorax-quarantine.ps1"
if (-not (Test-Path -LiteralPath $localScanWrapper -PathType Leaf)) {
  throw "Avorax local scan wrapper is missing: $localScanWrapper"
}
if (-not (Test-Path -LiteralPath $quarantineWrapper -PathType Leaf)) {
  throw "Avorax quarantine wrapper is missing: $quarantineWrapper"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-quarantine-wrapper-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$manualFixture = Join-Path $tempRoot "safe-quarantine-wrapper-manual.bin"
$restoreFixture = Join-Path $tempRoot "safe-quarantine-wrapper-restore.bin"
$deleteFixture = Join-Path $tempRoot "safe-quarantine-wrapper-delete.bin"
$missingManualFixture = Join-Path $tempRoot "missing-quarantine-wrapper-target.bin"
$wrongKindManualDir = Join-Path $tempRoot "wrong-kind-manual-quarantine-target"
$outsideReport = Join-Path $tempRoot "outside-quarantine-wrapper-report.json"
$manualReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-manual.json"
$restoreScanReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-restore-setup-scan.json"
$deleteScanReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-delete-setup-scan.json"
$listReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-list.json"
$rescanReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-rescan.json"
$restoreReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-restore.json"
$deleteReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-delete.json"
$missingTargetReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-missing-target-should-not-exist.json"
$wrongKindReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-wrong-kind-should-not-exist.json"
$invalidIdReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-invalid-id-should-not-exist.json"
$pathGuardReportRelative = ".workflow\ultracode\avorax-hardening\results\quarantine-wrapper-path-guards.json"
$manualReport = Join-Path $repo $manualReportRelative
$restoreScanReport = Join-Path $repo $restoreScanReportRelative
$deleteScanReport = Join-Path $repo $deleteScanReportRelative
$listReport = Join-Path $repo $listReportRelative
$rescanReport = Join-Path $repo $rescanReportRelative
$restoreReport = Join-Path $repo $restoreReportRelative
$deleteReport = Join-Path $repo $deleteReportRelative
$missingTargetReport = Join-Path $repo $missingTargetReportRelative
$wrongKindReport = Join-Path $repo $wrongKindReportRelative
$invalidIdReport = Join-Path $repo $invalidIdReportRelative
$pathGuardReport = Join-Path $repo $pathGuardReportRelative

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $quarantineRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $wrongKindManualDir -Force | Out-Null
  foreach ($negativeReport in @($missingTargetReport, $wrongKindReport, $invalidIdReport)) {
    if (Test-Path -LiteralPath $negativeReport -PathType Leaf) {
      Remove-Item -LiteralPath $negativeReport -Force
    }
  }

  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-quarantine-wrapper-fixture")
  [System.IO.File]::WriteAllBytes($manualFixture, $fixtureBytes)
  [System.IO.File]::WriteAllBytes($restoreFixture, $fixtureBytes)
  [System.IO.File]::WriteAllBytes($deleteFixture, $fixtureBytes)
  Write-QuarantineWrapperSignaturePack $engineRoot (Get-Sha256Hex $fixtureBytes)
  $expectedContent = [System.Text.Encoding]::ASCII.GetString($fixtureBytes)

  $negativeManual = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Quarantine",
    "-TargetPath", $manualFixture,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectSuccess $false
  if ($negativeManual.output.IndexOf("Quarantine requires -ConfirmAction", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "manual quarantine without confirmation did not fail with the expected diagnostic."
  }
  if (-not (Test-Path -LiteralPath $manualFixture -PathType Leaf)) {
    throw "manual quarantine negative guard removed the source fixture."
  }

  $missingTargetGuard = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Quarantine",
    "-TargetPath", $missingManualFixture,
    "-ConfirmAction",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-ReportPath", $missingTargetReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectSuccess $false
  if ($missingTargetGuard.output.IndexOf("TargetPath must be an existing file", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "missing manual quarantine target guard did not explain the target validation failure: $(Get-BoundedText $missingTargetGuard.output)"
  }
  if (Test-Path -LiteralPath $missingTargetReport -PathType Leaf) {
    throw "missing manual quarantine target guard wrote a report despite rejecting input: $missingTargetReport"
  }

  $wrongKindGuard = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Quarantine",
    "-TargetPath", $wrongKindManualDir,
    "-ConfirmAction",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-ReportPath", $wrongKindReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectSuccess $false
  if ($wrongKindGuard.output.IndexOf("TargetPath must be an existing file", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "wrong-kind manual quarantine target guard did not explain the target validation failure: $(Get-BoundedText $wrongKindGuard.output)"
  }
  if (Test-Path -LiteralPath $wrongKindReport -PathType Leaf) {
    throw "wrong-kind manual quarantine target guard wrote a report despite rejecting input: $wrongKindReport"
  }

  $invalidIdGuard = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Restore",
    "-QuarantineId", "bad/id",
    "-ConfirmAction",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-ReportPath", $invalidIdReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectSuccess $false
  if ($invalidIdGuard.output.IndexOf("QuarantineId may contain only ASCII letters", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "invalid quarantine-id guard did not explain the ID validation failure: $(Get-BoundedText $invalidIdGuard.output)"
  }
  if (Test-Path -LiteralPath $invalidIdReport -PathType Leaf) {
    throw "invalid quarantine-id guard wrote a report despite rejecting input: $invalidIdReport"
  }

  $reportEscapeGuard = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "List",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-ReportPath", $outsideReport,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectSuccess $false
  if ($reportEscapeGuard.output.IndexOf("Avorax quarantine report must be inside the repository", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "quarantine report-escape guard did not explain the repo-contained report requirement: $(Get-BoundedText $reportEscapeGuard.output)"
  }
  if (Test-Path -LiteralPath $outsideReport -PathType Leaf) {
    throw "quarantine report-escape guard wrote a report outside the repository: $outsideReport"
  }

  $pathGuardEvidence = [ordered]@{
    schema_version = 1
    tool = "avorax-quarantine-wrapper-path-guards"
    status = "passed"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    checked_cases = @(
      [ordered]@{
        name = "missing-manual-target"
        blocked = $true
        diagnostic_contains = "TargetPath must be an existing file"
        report_written = $false
      },
      [ordered]@{
        name = "wrong-manual-target-kind"
        blocked = $true
        diagnostic_contains = "TargetPath must be an existing file"
        report_written = $false
      },
      [ordered]@{
        name = "invalid-quarantine-id"
        blocked = $true
        diagnostic_contains = "QuarantineId may contain only ASCII letters"
        report_written = $false
      },
      [ordered]@{
        name = "report-path-outside-repo"
        blocked = $true
        diagnostic_contains = "Avorax quarantine report must be inside the repository"
        outside_report_written = $false
      }
    )
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      pre_execution_blocking_claimed = $false
      secure_erase_claimed = $false
    }
  }
  Write-JsonFileAtomic $pathGuardReport $pathGuardEvidence

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Quarantine",
    "-TargetPath", $manualFixture,
    "-ThreatName", "Manual quarantine wrapper harmless fixture",
    "-Engine", "avorax-manual-quarantine-wrapper-smoke",
    "-ConfirmAction",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-ReportPath", $manualReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $manual = Read-JsonFile $manualReport "manual quarantine wrapper report"
  Assert-SafetyReport $manual "manual quarantine wrapper report"
  if ($manual.action -ne "Quarantine" -or $manual.explicit_confirmation -ne $true) {
    throw "manual quarantine wrapper report did not record confirmed Quarantine action."
  }
  if ([string]::IsNullOrWhiteSpace([string]$manual.quarantine_id)) {
    throw "manual quarantine wrapper report did not record a quarantine id."
  }
  if ($manual.raw_response.record.status -ne "quarantined" -or $manual.raw_response.record.action_taken -ne "quarantined") {
    throw "manual quarantine wrapper report did not record quarantined state."
  }
  if ([string]$manual.raw_response.record.detection_name -ne "Manual quarantine wrapper harmless fixture") {
    throw "manual quarantine wrapper did not preserve threat-name evidence."
  }
  if ([string]$manual.raw_response.record.engine -ne "avorax-manual-quarantine-wrapper-smoke") {
    throw "manual quarantine wrapper did not preserve engine evidence."
  }
  if ($manual.safety.manual_quarantine_requires_confirmation -ne $true) {
    throw "manual quarantine wrapper report must record manual_quarantine_requires_confirmation=true."
  }
  if (Test-Path -LiteralPath $manualFixture -PathType Leaf) {
    throw "manual quarantine wrapper left the source fixture in place."
  }
  if (-not (Test-Path -LiteralPath ([string]$manual.raw_response.record.quarantine_path) -PathType Leaf)) {
    throw "manual quarantine wrapper did not create a quarantined payload."
  }

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $localScanWrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $restoreFixture,
    "-AutoQuarantineConfirmed",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $restoreScanReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $restoreSetup = Read-JsonFile $restoreScanReport "restore setup scan report"
  $restoreThreat = @($restoreSetup.raw_scan_report.threats) | Where-Object { $_.status -eq "quarantined" } | Select-Object -First 1
  if ($null -eq $restoreThreat -or [string]::IsNullOrWhiteSpace([string]$restoreThreat.quarantine_id)) {
    throw "restore setup scan did not create a quarantined record."
  }
  if (Test-Path -LiteralPath $restoreFixture -PathType Leaf) {
    throw "restore setup fixture still exists after quarantine."
  }

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "List",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-ReportPath", $listReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $list = Read-JsonFile $listReport "quarantine list wrapper report"
  Assert-SafetyReport $list "quarantine list wrapper report"
  if ([int]$list.records_count -lt 1) {
    throw "quarantine wrapper list records_count did not report the quarantined record."
  }
  $listedRecord = @($list.raw_response.records) | Where-Object { $_.quarantine_id -eq $restoreThreat.quarantine_id } | Select-Object -First 1
  if ($null -eq $listedRecord -or $listedRecord.status -ne "quarantined") {
    throw "quarantine wrapper list did not report the restore fixture record."
  }

  $negativeRescan = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Rescan",
    "-QuarantineId", $restoreThreat.quarantine_id,
    "-ConfirmAction",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-EngineRoot", $engineRoot,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectSuccess $false
  if ($negativeRescan.output.IndexOf("Rescan does not accept -ConfirmAction", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "rescan with confirmation did not fail with the expected diagnostic."
  }

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Rescan",
    "-QuarantineId", $restoreThreat.quarantine_id,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $rescanReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $rescan = Read-JsonFile $rescanReport "quarantine rescan wrapper report"
  Assert-SafetyReport $rescan "quarantine rescan wrapper report"
  if ($rescan.raw_rescan_report.status -ne "threatsFound" -or [int64]$rescan.rescan_files_scanned -ne 1) {
    throw "quarantine rescan wrapper did not scan the quarantined payload: $(Get-BoundedText ($rescan.raw_rescan_report | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([int64]$rescan.rescan_threats_found -lt 1 -or [int64]$rescan.rescan_quarantined_files -ne 0) {
    throw "quarantine rescan wrapper did not detect without re-quarantining: $(Get-BoundedText ($rescan.raw_rescan_report | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($rescan.safety.restore_during_rescan -ne $false -or $rescan.safety.delete_during_rescan -ne $false) {
    throw "quarantine rescan wrapper reported restore/delete side effects."
  }
  if (-not (Test-Path -LiteralPath ([string]$listedRecord.quarantine_path) -PathType Leaf)) {
    throw "quarantine rescan removed the quarantine payload."
  }
  if (Test-Path -LiteralPath $restoreFixture -PathType Leaf) {
    throw "quarantine rescan restored the original fixture."
  }

  $negative = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Restore",
    "-QuarantineId", $restoreThreat.quarantine_id,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectSuccess $false
  if ($negative.output.IndexOf("requires -ConfirmAction", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "restore without confirmation did not fail with the expected diagnostic."
  }

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Restore",
    "-QuarantineId", $restoreThreat.quarantine_id,
    "-ConfirmAction",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-ReportPath", $restoreReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $restore = Read-JsonFile $restoreReport "quarantine restore wrapper report"
  Assert-SafetyReport $restore "quarantine restore wrapper report"
  if ($restore.raw_response.record.status -ne "restored" -or $restore.raw_response.record.action_taken -ne "restored") {
    throw "quarantine wrapper restore report did not record restored state."
  }
  if (-not (Test-Path -LiteralPath $restoreFixture -PathType Leaf)) {
    throw "quarantine wrapper restore did not restore the original fixture."
  }
  $restoredContent = [System.IO.File]::ReadAllText($restoreFixture, [System.Text.Encoding]::ASCII)
  if ($restoredContent -ne $expectedContent) {
    throw "quarantine wrapper restore content mismatch."
  }

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $localScanWrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $deleteFixture,
    "-AutoQuarantineConfirmed",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $deleteScanReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $deleteSetup = Read-JsonFile $deleteScanReport "delete setup scan report"
  $deleteThreat = @($deleteSetup.raw_scan_report.threats) | Where-Object { $_.status -eq "quarantined" } | Select-Object -First 1
  if ($null -eq $deleteThreat -or [string]::IsNullOrWhiteSpace([string]$deleteThreat.quarantine_id)) {
    throw "delete setup scan did not create a quarantined record."
  }

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $quarantineWrapper,
    "-RepoRoot", $repo,
    "-Action", "Delete",
    "-QuarantineId", $deleteThreat.quarantine_id,
    "-ConfirmAction",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-ReportPath", $deleteReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $delete = Read-JsonFile $deleteReport "quarantine delete wrapper report"
  Assert-SafetyReport $delete "quarantine delete wrapper report"
  if ($delete.raw_response.record.status -ne "deleted" -or $delete.raw_response.record.action_taken -ne "deleted") {
    throw "quarantine wrapper delete report did not record deleted state."
  }
  if (Test-Path -LiteralPath $deleteFixture -PathType Leaf) {
    throw "quarantine wrapper delete restored the original fixture."
  }

  Write-Host "Avorax quarantine wrapper smoke passed."
  Write-Host "Manual report: $manualReport"
  Write-Host "List report: $listReport"
  Write-Host "Rescan report: $rescanReport"
  Write-Host "Restore report: $restoreReport"
  Write-Host "Delete report: $deleteReport"
  Write-Host "Path guard report: $pathGuardReport"
} finally {
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
