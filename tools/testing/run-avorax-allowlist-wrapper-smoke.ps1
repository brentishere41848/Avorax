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
    throw "Avorax allowlist wrapper smoke expects zentor_local_core.exe, got: $resolved"
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

function Write-AllowlistWrapperSignaturePack {
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
    id = "ZNE-SAFE-ALLOWLIST-WRAPPER-001"
    name = "Allowlist wrapper harmless known-bad hash fixture"
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
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-08T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-ALLOWLIST-WRAPPER-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Allowlist wrapper harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-08T00:00:00Z","version":"1"}],"version":"1.0.0"}'
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
  $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
  if ($ExpectSuccess -and $exit -ne 0) {
    throw "wrapper command failed with exit ${exit}: $(Get-BoundedText $text)"
  }
  if (-not $ExpectSuccess -and $exit -eq 0) {
    throw "wrapper command unexpectedly succeeded: $(Get-BoundedText $text)"
  }
  return [ordered]@{
    exit = $exit
    output = $text
  }
}

function Assert-ReportNotWritten {
  param([string]$PathValue, [string]$Description)
  if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
    throw "$Description wrote a report unexpectedly: $PathValue"
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

function Invoke-NegativeAllowlistWrapperCase {
  param(
    [string]$Name,
    [string[]]$Arguments,
    [string]$ExpectedDiagnostic,
    [string]$UnexpectedReportPath
  )
  $negative = Invoke-Wrapper -Arguments $Arguments -ExpectSuccess $false
  if ($negative.output.IndexOf($ExpectedDiagnostic, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "$Name guard did not explain the expected failure '$ExpectedDiagnostic': $(Get-BoundedText $negative.output)"
  }
  Assert-ReportNotWritten $UnexpectedReportPath "$Name guard"
  return [ordered]@{
    name = $Name
    expected_diagnostic = $ExpectedDiagnostic
    exit_code = $negative.exit
    report_written = Test-Path -LiteralPath $UnexpectedReportPath -PathType Leaf
  }
}

function Assert-SafetyReport {
  param([object]$Report, [string]$Description)
  if ($Report.tool -ne "avorax-allowlist") {
    throw "$Description tool mismatch: $($Report.tool)"
  }
  foreach ($field in @(
    "live_malware_used",
    "standard_eicar_string_written",
    "defender_exclusion_required",
    "machine_wide_changes",
    "service_installation_attempted",
    "pre_execution_blocking_claimed",
    "broad_root_allowlist_allowed",
    "folder_allowlist_supported_by_wrapper",
    "hash_allowlist_supported_by_wrapper"
  )) {
    if ($Report.safety.$field -ne $false) {
      throw "$Description safety.$field must be false."
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$allowlistWrapper = Join-Path $repo "tools\windows\avorax-allowlist.ps1"
$localScanWrapper = Join-Path $repo "tools\windows\avorax-local-scan.ps1"
if (-not (Test-Path -LiteralPath $allowlistWrapper -PathType Leaf)) {
  throw "Avorax allowlist wrapper is missing: $allowlistWrapper"
}
if (-not (Test-Path -LiteralPath $localScanWrapper -PathType Leaf)) {
  throw "Avorax local scan wrapper is missing: $localScanWrapper"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-allowlist-wrapper-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$fixture = Join-Path $tempRoot "safe-allowlist-wrapper.bin"
$addReportRelative = ".workflow\ultracode\avorax-hardening\results\allowlist-wrapper-add.json"
$listReportRelative = ".workflow\ultracode\avorax-hardening\results\allowlist-wrapper-list.json"
$allowlistedScanReportRelative = ".workflow\ultracode\avorax-hardening\results\allowlist-wrapper-allowlisted-scan.json"
$removeReportRelative = ".workflow\ultracode\avorax-hardening\results\allowlist-wrapper-remove.json"
$postRemoveScanReportRelative = ".workflow\ultracode\avorax-hardening\results\allowlist-wrapper-post-remove-scan.json"
$guardReportRelative = ".workflow\ultracode\avorax-hardening\results\allowlist-wrapper-path-guards.json"
$addUnconfirmedReportRelative = ".workflow\ultracode\avorax-hardening\results\allowlist-wrapper-add-unconfirmed-should-not-exist.json"
$removeUnconfirmedReportRelative = ".workflow\ultracode\avorax-hardening\results\allowlist-wrapper-remove-unconfirmed-should-not-exist.json"
$addReport = Join-Path $repo $addReportRelative
$listReport = Join-Path $repo $listReportRelative
$allowlistedScanReport = Join-Path $repo $allowlistedScanReportRelative
$removeReport = Join-Path $repo $removeReportRelative
$postRemoveScanReport = Join-Path $repo $postRemoveScanReportRelative
$guardReport = Join-Path $repo $guardReportRelative
$addUnconfirmedReport = Join-Path $repo $addUnconfirmedReportRelative
$removeUnconfirmedReport = Join-Path $repo $removeUnconfirmedReportRelative
$outsideReport = Join-Path $tempRoot "allowlist-wrapper-outside-repo-should-not-exist.json"

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $quarantineRoot -Force | Out-Null
  foreach ($staleReport in @($guardReport, $addUnconfirmedReport, $removeUnconfirmedReport, $outsideReport)) {
    if (Test-Path -LiteralPath $staleReport -PathType Leaf) {
      Remove-Item -LiteralPath $staleReport -Force
    }
  }
  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-allowlist-wrapper-fixture")
  [System.IO.File]::WriteAllBytes($fixture, $fixtureBytes)
  $fixtureSha256 = Get-Sha256Hex $fixtureBytes
  $expectedStoredSha256 = "sha256:$fixtureSha256"
  Write-AllowlistWrapperSignaturePack $engineRoot $fixtureSha256

  $guardCases = @()
  $guardCases += Invoke-NegativeAllowlistWrapperCase -Name "add-without-confirmation" -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $allowlistWrapper,
    "-RepoRoot", $repo,
    "-Action", "Add",
    "-TargetPath", $fixture,
    "-AllowlistFile", $allowlistFile,
    "-LocalCorePath", $binary,
    "-ReportPath", $addUnconfirmedReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectedDiagnostic "Add requires -ConfirmAction" -UnexpectedReportPath $addUnconfirmedReport
  $guardCases += Invoke-NegativeAllowlistWrapperCase -Name "report-path-outside-repo" -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $allowlistWrapper,
    "-RepoRoot", $repo,
    "-Action", "List",
    "-AllowlistFile", $allowlistFile,
    "-LocalCorePath", $binary,
    "-ReportPath", $outsideReport,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectedDiagnostic "Avorax allowlist report must be inside the repository" -UnexpectedReportPath $outsideReport

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $allowlistWrapper,
    "-RepoRoot", $repo,
    "-Action", "Add",
    "-TargetPath", $fixture,
    "-ConfirmAction",
    "-AllowlistFile", $allowlistFile,
    "-LocalCorePath", $binary,
    "-ReportPath", $addReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $add = Read-JsonFile $addReport "allowlist add wrapper report"
  Assert-SafetyReport $add "allowlist add wrapper report"
  if ($add.raw_response.entry.active -ne $true -or [string]::IsNullOrWhiteSpace([string]$add.raw_response.entry.id)) {
    throw "allowlist add wrapper report did not include an active entry."
  }
  if ([string]$add.raw_response.entry.sha256 -ne $expectedStoredSha256) {
    throw "allowlist add wrapper report hash mismatch: $(Get-BoundedText ($add.raw_response.entry | ConvertTo-Json -Compress -Depth 8))"
  }
  $entryId = [string]$add.raw_response.entry.id

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $allowlistWrapper,
    "-RepoRoot", $repo,
    "-Action", "List",
    "-AllowlistFile", $allowlistFile,
    "-LocalCorePath", $binary,
    "-ReportPath", $listReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $list = Read-JsonFile $listReport "allowlist list wrapper report"
  Assert-SafetyReport $list "allowlist list wrapper report"
  $listedEntry = @($list.raw_response.entries) | Where-Object {
    $_.id -eq $entryId -and $_.active -eq $true -and $_.sha256 -eq $expectedStoredSha256
  } | Select-Object -First 1
  if ($null -eq $listedEntry) {
    throw "allowlist list wrapper did not return the active fixture entry."
  }

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $localScanWrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $fixture,
    "-AutoQuarantineConfirmed",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $allowlistedScanReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $allowlistedScan = Read-JsonFile $allowlistedScanReport "allowlisted scan report"
  $allowlistedThreat = @($allowlistedScan.raw_scan_report.threats) | Where-Object {
    $_.status -eq "allowlisted" -and $_.recommended_action -eq "allowlist"
  } | Select-Object -First 1
  if ($null -eq $allowlistedThreat -or [int64]$allowlistedScan.quarantined_files -ne 0) {
    throw "allowlisted scan did not preserve the confirmed fixture: $(Get-BoundedText ($allowlistedScan.raw_scan_report | ConvertTo-Json -Compress -Depth 8))"
  }
  if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw "allowlisted scan removed the fixture."
  }

  $guardCases += Invoke-NegativeAllowlistWrapperCase -Name "remove-without-confirmation" -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $allowlistWrapper,
    "-RepoRoot", $repo,
    "-Action", "Remove",
    "-AllowlistId", $entryId,
    "-AllowlistFile", $allowlistFile,
    "-LocalCorePath", $binary,
    "-ReportPath", $removeUnconfirmedReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectedDiagnostic "Remove requires -ConfirmAction" -UnexpectedReportPath $removeUnconfirmedReport

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $allowlistWrapper,
    "-RepoRoot", $repo,
    "-Action", "Remove",
    "-AllowlistId", $entryId,
    "-ConfirmAction",
    "-AllowlistFile", $allowlistFile,
    "-LocalCorePath", $binary,
    "-ReportPath", $removeReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $remove = Read-JsonFile $removeReport "allowlist remove wrapper report"
  Assert-SafetyReport $remove "allowlist remove wrapper report"
  if ($remove.raw_response.entry.id -ne $entryId -or $remove.raw_response.entry.active -ne $false) {
    throw "allowlist remove wrapper did not deactivate the selected entry."
  }

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $localScanWrapper,
    "-RepoRoot", $repo,
    "-ScanType", "File",
    "-Path", $fixture,
    "-AutoQuarantineConfirmed",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $postRemoveScanReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $postRemoveScan = Read-JsonFile $postRemoveScanReport "post-remove scan report"
  $quarantinedThreat = @($postRemoveScan.raw_scan_report.threats) | Where-Object {
    $_.status -eq "quarantined"
  } | Select-Object -First 1
  if ($null -eq $quarantinedThreat -or [int64]$postRemoveScan.quarantined_files -lt 1) {
    throw "post-remove scan did not restore confirmed quarantine behavior: $(Get-BoundedText ($postRemoveScan.raw_scan_report | ConvertTo-Json -Compress -Depth 8))"
  }
  if (Test-Path -LiteralPath $fixture -PathType Leaf) {
    throw "post-remove scan left the fixture in place after confirmed quarantine."
  }

  Write-JsonFileAtomic $guardReport ([ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    status = "passed"
    tool = "avorax-allowlist-wrapper-path-guards"
    checked_cases = $guardCases
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      pre_execution_blocking_claimed = $false
      broad_root_allowlist_allowed = $false
    }
  })

  Write-Host "Avorax allowlist wrapper smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Allowlist id: $entryId"
  Write-Host "Fixture SHA-256: $fixtureSha256"
  Write-Host "Initial scan threat status: $($allowlistedThreat.status)"
  Write-Host "Post-remove threat status: $($quarantinedThreat.status)"
  Write-Host "Guard report: $guardReport"
} finally {
  if (Test-Path -LiteralPath $tempRoot) {
    $tempPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $full = [System.IO.Path]::GetFullPath($tempRoot)
    if (-not $full.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to remove allowlist wrapper smoke temp root outside temp: $full"
    }
    if ([System.IO.Path]::GetFileName($full) -notlike "avorax-allowlist-wrapper-smoke-*") {
      throw "Refusing to remove unexpected allowlist wrapper smoke temp root: $full"
    }
    Remove-Item -LiteralPath $full -Recurse -Force
  }
}
