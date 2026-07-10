param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
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
    throw "Avorax status wrapper smoke expects zentor_local_core.exe, got: $resolved"
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

function Write-StatusWrapperSignaturePack {
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
    id = "ZNE-SAFE-STATUS-WRAPPER-001"
    name = "Status wrapper harmless known-bad hash fixture"
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
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-08T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-STATUS-WRAPPER-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Status wrapper harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-08T00:00:00Z","version":"1"}],"version":"1.0.0"}'
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

function Invoke-NegativeStatusWrapperCase {
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
  if ($Report.tool -ne "avorax-status") {
    throw "$Description tool mismatch: $($Report.tool)"
  }
  foreach ($field in @(
    "live_malware_used",
    "standard_eicar_string_written",
    "defender_exclusion_required",
    "machine_wide_changes",
    "service_installation_attempted",
    "pre_execution_blocking_claimed",
    "persistent_monitoring_claimed",
    "kernel_driver_claimed",
    "network_content_trusted"
  )) {
    if ($Report.safety.$field -ne $false) {
      throw "$Description safety.$field must be false."
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$statusWrapper = Join-Path $repo "tools\windows\avorax-status.ps1"
if (-not (Test-Path -LiteralPath $statusWrapper -PathType Leaf)) {
  throw "Avorax status wrapper is missing: $statusWrapper"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-status-wrapper-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$engineRoot = Join-Path $tempRoot "engine"
$reportRelative = ".workflow\ultracode\avorax-hardening\results\status-wrapper-health.json"
$guardReportRelative = ".workflow\ultracode\avorax-hardening\results\status-wrapper-path-guards.json"
$missingEngineReportRelative = ".workflow\ultracode\avorax-hardening\results\status-wrapper-missing-engine-should-not-exist.json"
$report = Join-Path $repo $reportRelative
$guardReport = Join-Path $repo $guardReportRelative
$missingEngineReport = Join-Path $repo $missingEngineReportRelative
$outsideReport = Join-Path $tempRoot "status-wrapper-outside-repo-should-not-exist.json"
$missingEngineRoot = Join-Path $tempRoot "missing-engine"

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $engineRoot -Force | Out-Null
  foreach ($staleReport in @($guardReport, $missingEngineReport, $outsideReport)) {
    if (Test-Path -LiteralPath $staleReport -PathType Leaf) {
      Remove-Item -LiteralPath $staleReport -Force
    }
  }
  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-status-wrapper-fixture")
  $fixtureSha256 = Get-Sha256Hex $fixtureBytes
  Write-StatusWrapperSignaturePack $engineRoot $fixtureSha256

  $null = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $statusWrapper,
    "-RepoRoot", $repo,
    "-EngineRoot", $engineRoot,
    "-LocalCorePath", $binary,
    "-ReportPath", $reportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  )
  $status = Read-JsonFile $report "status wrapper report"
  Assert-SafetyReport $status "status wrapper report"
  if ($status.health_state -ne "degraded" -and $status.health_state -ne "ready") {
    throw "status wrapper report health_state must be degraded or ready, got: $($status.health_state)"
  }
  if ($status.engine_status -ne "available" -or $status.native_engine_status -ne "ready") {
    throw "status wrapper did not report the temp engine as available: $(Get-BoundedText ($status | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([int64]$status.native_signature_count -lt 1) {
    throw "status wrapper did not load the harmless signature pack."
  }
  if ($status.network_exposed -ne $false -or $status.ipc -ne "stdio") {
    throw "status wrapper reported an unexpected IPC/network boundary."
  }
  if ([string]$status.driver_status -ne "missing") {
    throw "status wrapper must not claim a driver is active in this user-mode smoke: $($status.driver_status)"
  }
  if (@($status.limitations).Count -lt 1 -or ($status.limitations -join " ").IndexOf("Pre-execution blocking is not claimed", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "status wrapper did not report the expected user-mode limitation."
  }

  $requireReady = Invoke-Wrapper -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $statusWrapper,
    "-RepoRoot", $repo,
    "-EngineRoot", $engineRoot,
    "-LocalCorePath", $binary,
    "-RequireReady",
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectSuccess $false
  if ($requireReady.output.IndexOf("Avorax status is not ready", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "status wrapper -RequireReady did not fail with the expected readiness diagnostic."
  }

  $guardCases = @()
  $guardCases += Invoke-NegativeStatusWrapperCase -Name "missing-engine-root" -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $statusWrapper,
    "-RepoRoot", $repo,
    "-EngineRoot", $missingEngineRoot,
    "-LocalCorePath", $binary,
    "-ReportPath", $missingEngineReportRelative,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectedDiagnostic "EngineRoot does not exist" -UnexpectedReportPath $missingEngineReport
  $guardCases += Invoke-NegativeStatusWrapperCase -Name "report-path-outside-repo" -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $statusWrapper,
    "-RepoRoot", $repo,
    "-EngineRoot", $engineRoot,
    "-LocalCorePath", $binary,
    "-ReportPath", $outsideReport,
    "-TimeoutSeconds", "$TimeoutSeconds"
  ) -ExpectedDiagnostic "Avorax status report must be inside the repository" -UnexpectedReportPath $outsideReport

  Write-JsonFileAtomic $guardReport ([ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    status = "passed"
    tool = "avorax-status-wrapper-path-guards"
    checked_cases = $guardCases
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      pre_execution_blocking_claimed = $false
      persistent_monitoring_claimed = $false
      kernel_driver_claimed = $false
    }
  })

  Write-Host "Avorax status wrapper smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Health state: $($status.health_state)"
  Write-Host "Native signatures: $($status.native_signature_count)"
  Write-Host "Native self-test: $($status.native_self_test)"
  Write-Host "Guard report: $guardReport"
} finally {
  if (Test-Path -LiteralPath $tempRoot) {
    $tempPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $full = [System.IO.Path]::GetFullPath($tempRoot)
    if (-not $full.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to remove status wrapper smoke temp root outside temp: $full"
    }
    if ([System.IO.Path]::GetFileName($full) -notlike "avorax-status-wrapper-smoke-*") {
      throw "Refusing to remove unexpected status wrapper smoke temp root: $full"
    }
    Remove-Item -LiteralPath $full -Recurse -Force
  }
}
