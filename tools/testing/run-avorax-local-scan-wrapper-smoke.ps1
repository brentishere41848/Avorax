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
  param(
    [string]$Repo,
    [string]$ConfiguredPath
  )
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\zentor_local_core.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release local-core binary is missing: $candidate. Run cargo build --release --manifest-path core\zentor_local_core\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne "zentor_local_core.exe") {
    throw "Avorax local scan wrapper smoke expects zentor_local_core.exe, got: $resolved"
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

function Write-LocalScanWrapperSignaturePack {
  param(
    [string]$EngineRoot,
    [string]$FixtureSha256
  )

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
    id = "ZNE-SAFE-LOCAL-SCAN-WRAPPER-001"
    name = "Local scan wrapper harmless known-bad hash fixture"
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
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-08T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-LOCAL-SCAN-WRAPPER-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Local scan wrapper harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-08T00:00:00Z","version":"1"}],"version":"1.0.0"}'
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
  $packJson = $pack | ConvertTo-Json -Depth 8
  [System.IO.File]::WriteAllText(
    (Join-Path $signaturesDir "avorax_core.asig"),
    $packJson + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )
}

function Invoke-Wrapper {
  param(
    [string]$PowerShellPath,
    [string[]]$Arguments,
    [bool]$ExpectSuccess
  )

  $previousErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $output = & $PowerShellPath @Arguments 2>&1
    $exitCode = if ($null -ne $global:LASTEXITCODE) { [int]$global:LASTEXITCODE } else { 0 }
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
  if ($ExpectSuccess -and $exitCode -ne 0) {
    throw "Avorax local scan wrapper command failed with exit code ${exitCode}: $(Get-BoundedText $text)"
  }
  if (-not $ExpectSuccess -and $exitCode -eq 0) {
    throw "Avorax local scan wrapper command unexpectedly succeeded: $(Get-BoundedText $text)"
  }
  return [ordered]@{
    exit_code = $exitCode
    output = $text
  }
}

function Read-JsonFile {
  param([string]$PathValue, [string]$Description)
  if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
    throw "$Description was not written: $PathValue"
  }
  try {
    return Get-Content -LiteralPath $PathValue -Raw | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "$Description is not valid JSON: $(Get-BoundedText $_.Exception.Message)"
  }
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

function Assert-FalseProperty {
  param([object]$Object, [string]$Name, [string]$Description)
  if (-not ($Object.PSObject.Properties.Name -contains $Name)) {
    throw "$Description is missing safety.$Name"
  }
  if ([bool]$Object.$Name) {
    throw "$Description safety.$Name must be false."
  }
}

function Assert-SafeReport {
  param([object]$Report, [string]$Description)
  if ($Report.tool -ne "avorax-local-scan") {
    throw "$Description tool mismatch: $($Report.tool)"
  }
  foreach ($name in @(
    "live_malware_used",
    "standard_eicar_string_written",
    "defender_exclusion_required",
    "machine_wide_changes",
    "service_installation_attempted",
    "pre_execution_blocking_claimed",
    "default_root_auto_quarantine_allowed"
  )) {
    Assert-FalseProperty $Report.safety $name $Description
  }
}

function Remove-SmokeTempRoot {
  param([string]$PathValue)
  if ([string]::IsNullOrWhiteSpace($PathValue) -or -not (Test-Path -LiteralPath $PathValue)) {
    return
  }
  $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  $full = [System.IO.Path]::GetFullPath($PathValue)
  if (-not $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove smoke temp root outside temp directory: $full"
  }
  if ([System.IO.Path]::GetFileName($full) -notlike "avorax-local-scan-wrapper-smoke-*") {
    throw "Refusing to remove unexpected smoke temp root: $full"
  }
  Remove-Item -LiteralPath $full -Recurse -Force
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$wrapper = Join-Path $repo "tools\windows\avorax-local-scan.ps1"
if (-not (Test-Path -LiteralPath $wrapper -PathType Leaf)) {
  throw "Avorax local scan wrapper is missing: $wrapper"
}

$powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-local-scan-wrapper-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$detectFixture = Join-Path $tempRoot "safe-local-scan-detect.bin"
$quarantineFixture = Join-Path $tempRoot "safe-local-scan-quarantine.bin"
$progressDir = Join-Path $tempRoot "progress-scan"
$progressFixture = Join-Path $progressDir "safe-local-scan-progress.bin"
$folderDir = Join-Path $tempRoot "folder-scan"
$folderThreatFixture = Join-Path $folderDir "safe-local-scan-folder-threat.bin"
$folderBenignFixture = Join-Path $folderDir "safe-local-scan-folder-benign.txt"
$failOnThreatFixture = Join-Path $tempRoot "safe-local-scan-fail-on-threat.bin"
$wrongKindDir = Join-Path $tempRoot "wrong-kind-folder"
$missingTargetFixture = Join-Path $tempRoot "missing-local-scan-target.bin"
$outsideReport = Join-Path $tempRoot "outside-local-scan-report.json"
$detectReportRelative = ".workflow\ultracode\avorax-hardening\results\local-scan-wrapper-detect.json"
$progressReportRelative = ".workflow\ultracode\avorax-hardening\results\local-scan-wrapper-progress.json"
$quarantineReportRelative = ".workflow\ultracode\avorax-hardening\results\local-scan-wrapper-quarantine.json"
$folderReportRelative = ".workflow\ultracode\avorax-hardening\results\local-scan-wrapper-folder-quarantine.json"
$failOnThreatReportRelative = ".workflow\ultracode\avorax-hardening\results\local-scan-wrapper-fail-on-threat.json"
$missingTargetReportRelative = ".workflow\ultracode\avorax-hardening\results\local-scan-wrapper-missing-target-should-not-exist.json"
$wrongKindReportRelative = ".workflow\ultracode\avorax-hardening\results\local-scan-wrapper-wrong-kind-should-not-exist.json"
$pathGuardReportRelative = ".workflow\ultracode\avorax-hardening\results\local-scan-wrapper-path-guards.json"
$detectReport = Join-Path $repo $detectReportRelative
$progressReport = Join-Path $repo $progressReportRelative
$quarantineReport = Join-Path $repo $quarantineReportRelative
$folderReport = Join-Path $repo $folderReportRelative
$failOnThreatReport = Join-Path $repo $failOnThreatReportRelative
$missingTargetReport = Join-Path $repo $missingTargetReportRelative
$wrongKindReport = Join-Path $repo $wrongKindReportRelative
$pathGuardReport = Join-Path $repo $pathGuardReportRelative

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $quarantineRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $progressDir -Force | Out-Null
  New-Item -ItemType Directory -Path $folderDir -Force | Out-Null
  New-Item -ItemType Directory -Path $wrongKindDir -Force | Out-Null
  foreach ($negativeReport in @($missingTargetReport, $wrongKindReport)) {
    if (Test-Path -LiteralPath $negativeReport -PathType Leaf) {
      Remove-Item -LiteralPath $negativeReport -Force
    }
  }
  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-local-scan-wrapper-fixture")
  $benignBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-local-scan-wrapper-benign-folder-file")
  [System.IO.File]::WriteAllBytes($detectFixture, $fixtureBytes)
  [System.IO.File]::WriteAllBytes($quarantineFixture, $fixtureBytes)
  [System.IO.File]::WriteAllBytes($progressFixture, $fixtureBytes)
  [System.IO.File]::WriteAllBytes($folderThreatFixture, $fixtureBytes)
  [System.IO.File]::WriteAllBytes($folderBenignFixture, $benignBytes)
  [System.IO.File]::WriteAllBytes($failOnThreatFixture, $fixtureBytes)
  Write-LocalScanWrapperSignaturePack $engineRoot (Get-Sha256Hex $fixtureBytes)

  Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $detectFixture,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $detectReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $true | Out-Null

  $detectReportJson = Read-JsonFile $detectReport "detect-only local scan wrapper report"
  Assert-SafeReport $detectReportJson "detect-only local scan wrapper report"
  if ($detectReportJson.status -ne "threatsFound") {
    throw "detect-only wrapper report status mismatch: $($detectReportJson.status)"
  }
  if ($detectReportJson.action_mode -ne "detectOnly") {
    throw "detect-only wrapper report action_mode mismatch: $($detectReportJson.action_mode)"
  }
  if ([int64]$detectReportJson.threats_found -lt 1) {
    throw "detect-only wrapper report did not record a threat."
  }
  if ([int64]$detectReportJson.quarantined_files -ne 0) {
    throw "detect-only wrapper report quarantined files."
  }
  if (-not (Test-Path -LiteralPath $detectFixture -PathType Leaf)) {
    throw "detect-only wrapper scan removed the harmless fixture."
  }

  Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "Quick",
    "-Path", $progressFixture,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $progressReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $true | Out-Null

  $progressReportJson = Read-JsonFile $progressReport "progress local scan wrapper report"
  Assert-SafeReport $progressReportJson "progress local scan wrapper report"
  if ($progressReportJson.command -ne "quick_scan_selected_paths") {
    throw "progress wrapper report command mismatch: $($progressReportJson.command)"
  }
  if ($progressReportJson.scan_kind -ne "quick") {
    throw "progress wrapper report scan_kind mismatch: $($progressReportJson.scan_kind)"
  }
  if ($progressReportJson.action_mode -ne "detectOnly") {
    throw "progress wrapper report action_mode mismatch: $($progressReportJson.action_mode)"
  }
  if ([int64]$progressReportJson.files_scanned -lt 1) {
    throw "progress wrapper report did not scan the harmless progress fixture."
  }
  if ([int64]$progressReportJson.progress_events -lt 2) {
    throw "progress wrapper report did not record multiple release-binary progress events."
  }
  if ([int64]$progressReportJson.threats_found -lt 1) {
    throw "progress wrapper report did not record the harmless known-bad hash fixture."
  }
  if ([int64]$progressReportJson.quarantined_files -ne 0) {
    throw "progress wrapper detect-only scan quarantined files."
  }
  if (-not (Test-Path -LiteralPath $progressFixture -PathType Leaf)) {
    throw "progress wrapper detect-only scan removed the harmless fixture."
  }

  Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $quarantineFixture,
    "-AutoQuarantineConfirmed",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $quarantineReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $true | Out-Null

  $quarantineReportJson = Read-JsonFile $quarantineReport "auto-quarantine local scan wrapper report"
  Assert-SafeReport $quarantineReportJson "auto-quarantine local scan wrapper report"
  if ($quarantineReportJson.status -ne "threatsFound") {
    throw "auto-quarantine wrapper report status mismatch: $($quarantineReportJson.status)"
  }
  if ($quarantineReportJson.action_mode -ne "autoQuarantineConfirmedOnly") {
    throw "auto-quarantine wrapper report action_mode mismatch: $($quarantineReportJson.action_mode)"
  }
  if ([int64]$quarantineReportJson.threats_found -lt 1) {
    throw "auto-quarantine wrapper report did not record a threat."
  }
  if ([int64]$quarantineReportJson.quarantined_files -lt 1) {
    throw "auto-quarantine wrapper report did not quarantine a confirmed harmless fixture."
  }
  if (Test-Path -LiteralPath $quarantineFixture -PathType Leaf) {
    throw "auto-quarantine wrapper scan left the source fixture in place."
  }

  Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "Folder",
    "-Path", $folderDir,
    "-AutoQuarantineConfirmed",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $folderReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $true | Out-Null

  $folderReportJson = Read-JsonFile $folderReport "folder auto-quarantine local scan wrapper report"
  Assert-SafeReport $folderReportJson "folder auto-quarantine local scan wrapper report"
  if ($folderReportJson.command -ne "scan_folder") {
    throw "folder wrapper report command mismatch: $($folderReportJson.command)"
  }
  if ($folderReportJson.scan_kind -ne "custom") {
    throw "folder wrapper report scan_kind mismatch: $($folderReportJson.scan_kind)"
  }
  if ($folderReportJson.action_mode -ne "autoQuarantineConfirmedOnly") {
    throw "folder wrapper report action_mode mismatch: $($folderReportJson.action_mode)"
  }
  if ([int64]$folderReportJson.files_scanned -lt 2) {
    throw "folder wrapper report did not scan both harmless folder fixtures."
  }
  if ([int64]$folderReportJson.threats_found -lt 1) {
    throw "folder wrapper report did not record the harmless known-bad folder fixture."
  }
  if ([int64]$folderReportJson.quarantined_files -lt 1) {
    throw "folder wrapper report did not quarantine the harmless known-bad folder fixture."
  }
  if (Test-Path -LiteralPath $folderThreatFixture -PathType Leaf) {
    throw "folder wrapper scan left the known-bad harmless fixture in place."
  }
  if (-not (Test-Path -LiteralPath $folderBenignFixture -PathType Leaf)) {
    throw "folder wrapper scan removed the benign folder fixture."
  }

  $failOnThreat = Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $failOnThreatFixture,
    "-FailOnThreat",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $failOnThreatReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $false
  if ($failOnThreat.output.IndexOf("Avorax local scan found", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "FailOnThreat wrapper guard did not explain the threat failure: $(Get-BoundedText $failOnThreat.output)"
  }
  $failOnThreatReportJson = Read-JsonFile $failOnThreatReport "fail-on-threat local scan wrapper report"
  Assert-SafeReport $failOnThreatReportJson "fail-on-threat local scan wrapper report"
  if ($failOnThreatReportJson.status -ne "threatsFound") {
    throw "fail-on-threat wrapper report status mismatch: $($failOnThreatReportJson.status)"
  }
  if ($failOnThreatReportJson.action_mode -ne "detectOnly") {
    throw "fail-on-threat wrapper report action_mode mismatch: $($failOnThreatReportJson.action_mode)"
  }
  if ([int64]$failOnThreatReportJson.threats_found -lt 1) {
    throw "fail-on-threat wrapper report did not record the harmless known-bad fixture."
  }
  if ([int64]$failOnThreatReportJson.quarantined_files -ne 0) {
    throw "fail-on-threat detect-only wrapper scan quarantined files."
  }
  if (-not (Test-Path -LiteralPath $failOnThreatFixture -PathType Leaf)) {
    throw "fail-on-threat detect-only wrapper scan removed the harmless fixture."
  }

  $negative = Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "Quick",
    "-AutoQuarantineConfirmed",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $false
  if ($negative.output.IndexOf("Auto-quarantine from this wrapper requires explicit -Path targets", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "negative wrapper guard did not explain the explicit -Path requirement: $(Get-BoundedText $negative.output)"
  }

  $missingTargetGuard = Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $missingTargetFixture,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $missingTargetReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $false
  if ($missingTargetGuard.output.IndexOf("Scan target does not exist", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "missing-target guard did not explain the target validation failure: $(Get-BoundedText $missingTargetGuard.output)"
  }
  if (Test-Path -LiteralPath $missingTargetReport -PathType Leaf) {
    throw "missing-target guard wrote a scan report despite rejecting input: $missingTargetReport"
  }

  $wrongKindGuard = Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $wrongKindDir,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $wrongKindReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $false
  if ($wrongKindGuard.output.IndexOf("File scan target is not a file", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "wrong-kind guard did not explain the file target validation failure: $(Get-BoundedText $wrongKindGuard.output)"
  }
  if (Test-Path -LiteralPath $wrongKindReport -PathType Leaf) {
    throw "wrong-kind guard wrote a scan report despite rejecting input: $wrongKindReport"
  }

  $reportEscapeGuard = Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $detectFixture,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $outsideReport,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $false
  if ($reportEscapeGuard.output.IndexOf("Avorax local scan report must be inside the repository", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "report-escape guard did not explain the repo-contained report requirement: $(Get-BoundedText $reportEscapeGuard.output)"
  }
  if (Test-Path -LiteralPath $outsideReport -PathType Leaf) {
    throw "report-escape guard wrote a report outside the repository: $outsideReport"
  }

  $pathGuardEvidence = [ordered]@{
    schema_version = 1
    tool = "avorax-local-scan-wrapper-path-guards"
    status = "passed"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    checked_cases = @(
      [ordered]@{
        name = "missing-target"
        blocked = $true
        diagnostic_contains = "Scan target does not exist"
        report_written = $false
      },
      [ordered]@{
        name = "wrong-target-kind"
        blocked = $true
        diagnostic_contains = "File scan target is not a file"
        report_written = $false
      },
      [ordered]@{
        name = "report-path-outside-repo"
        blocked = $true
        diagnostic_contains = "Avorax local scan report must be inside the repository"
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
    }
  }
  Write-JsonFileAtomic $pathGuardReport $pathGuardEvidence

  Write-Host "Avorax local scan wrapper smoke passed."
  Write-Host "Detect report: $detectReport"
  Write-Host "Progress report: $progressReport"
  Write-Host "Quarantine report: $quarantineReport"
  Write-Host "Folder quarantine report: $folderReport"
  Write-Host "Fail-on-threat report: $failOnThreatReport"
  Write-Host "Path guard report: $pathGuardReport"
  Write-Host "Negative guard: explicit target required for broad auto-quarantine."
  Write-Host "Negative guards: missing target, wrong target kind, and report path outside repository."
} finally {
  Remove-SmokeTempRoot $tempRoot
}
