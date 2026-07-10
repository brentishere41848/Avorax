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
    throw "Avorax cancel scan wrapper smoke expects zentor_local_core.exe, got: $resolved"
  }
  return $resolved
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
    throw "Avorax cancel scan wrapper command failed with exit code ${exitCode}: $(Get-BoundedText $text)"
  }
  if (-not $ExpectSuccess -and $exitCode -eq 0) {
    throw "Avorax cancel scan wrapper command unexpectedly succeeded: $(Get-BoundedText $text)"
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

function Invoke-NegativeCancelWrapperCase {
  param(
    [string]$Name,
    [string[]]$Arguments,
    [string]$ExpectedDiagnostic,
    [string]$UnexpectedReportPath,
    [string]$UnexpectedTokenPath = ""
  )
  $negative = Invoke-Wrapper -PowerShellPath $powershell -Arguments $Arguments -ExpectSuccess $false
  if ($negative.output.IndexOf($ExpectedDiagnostic, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "$Name guard did not explain the expected failure '$ExpectedDiagnostic': $(Get-BoundedText $negative.output)"
  }
  Assert-ReportNotWritten $UnexpectedReportPath "$Name guard"
  if (-not [string]::IsNullOrWhiteSpace($UnexpectedTokenPath) -and (Test-Path -LiteralPath $UnexpectedTokenPath -PathType Leaf)) {
    throw "$Name guard wrote a cancel token unexpectedly: $UnexpectedTokenPath"
  }
  return [ordered]@{
    name = $Name
    expected_diagnostic = $ExpectedDiagnostic
    exit_code = $negative.exit_code
    report_written = Test-Path -LiteralPath $UnexpectedReportPath -PathType Leaf
    cancel_token_written = if ([string]::IsNullOrWhiteSpace($UnexpectedTokenPath)) { $false } else { Test-Path -LiteralPath $UnexpectedTokenPath -PathType Leaf }
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

function Assert-CancelReport {
  param([object]$Report, [string]$DataRoot)
  if ($Report.tool -ne "avorax-cancel-scan") {
    throw "cancel wrapper report tool mismatch: $($Report.tool)"
  }
  if ($Report.command -ne "cancel_scan") {
    throw "cancel wrapper report command mismatch: $($Report.command)"
  }
  if ($Report.cancel_requested -ne $true) {
    throw "cancel wrapper report did not mark cancel_requested=true."
  }
  if ($Report.cancel_token_exists -ne $true) {
    throw "cancel wrapper report did not observe the cancel token."
  }
  if ($Report.token_under_data_root -ne $true) {
    throw "cancel wrapper report did not keep the token under DataRoot."
  }
  if ($Report.use_installed_data_root -ne $false) {
    throw "cancel wrapper report unexpectedly used installed data root."
  }
  if ($Report.network_exposed -ne $false -or $Report.ipc -ne "stdio") {
    throw "cancel wrapper report reported an unexpected IPC/network boundary."
  }
  foreach ($name in @(
    "live_malware_used",
    "standard_eicar_string_written",
    "defender_exclusion_required",
    "machine_wide_component_installation",
    "service_installation_attempted",
    "process_kill_attempted",
    "external_process_kill_attempted",
    "pre_execution_blocking_claimed",
    "persistent_monitoring_claimed",
    "installed_data_root_requested"
  )) {
    Assert-FalseProperty $Report.safety $name "cancel wrapper report"
  }
  if ($Report.safety.child_process_timeout_cleanup_enabled -ne $true) {
    throw "cancel wrapper report must disclose child_process_timeout_cleanup_enabled=true."
  }
  $limitations = @($Report.limitations) -join " "
  foreach ($expected in @(
    "cooperative-cancel-token-request-only",
    "running-scan-observation-covered-by-local-core-regressions",
    "no-installed-service-e2e-claim",
    "no-kernel-pre-execution-blocking"
  )) {
    if ($limitations.IndexOf($expected, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
      throw "cancel wrapper report limitations missing: $expected"
    }
  }
  $expectedToken = Join-Path (Join-Path $DataRoot "runtime") "cancel-active-scan"
  if (-not ([System.IO.Path]::GetFullPath([string]$Report.cancel_token_path).Equals([System.IO.Path]::GetFullPath($expectedToken), [StringComparison]::OrdinalIgnoreCase))) {
    throw "cancel wrapper report token path mismatch: $($Report.cancel_token_path)"
  }
  if (-not (Test-Path -LiteralPath $expectedToken -PathType Leaf)) {
    throw "cancel wrapper did not write the expected token: $expectedToken"
  }
  $tokenItem = Get-Item -LiteralPath $expectedToken -Force -ErrorAction Stop
  if (($tokenItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "cancel wrapper token must not be a reparse point."
  }
  $tokenText = Get-Content -LiteralPath $expectedToken -Raw
  if ([string]::IsNullOrWhiteSpace($tokenText)) {
    throw "cancel wrapper token must not be empty."
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
  if ([System.IO.Path]::GetFileName($full) -notlike "avorax-cancel-scan-wrapper-smoke-*") {
    throw "Refusing to remove unexpected smoke temp root: $full"
  }
  Remove-Item -LiteralPath $full -Recurse -Force
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$wrapper = Join-Path $repo "tools\windows\avorax-cancel-scan.ps1"
if (-not (Test-Path -LiteralPath $wrapper -PathType Leaf)) {
  throw "Avorax cancel scan wrapper is missing: $wrapper"
}

$powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-cancel-scan-wrapper-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$reportRelative = ".workflow\ultracode\avorax-hardening\results\cancel-scan-wrapper-request.json"
$guardReportRelative = ".workflow\ultracode\avorax-hardening\results\cancel-scan-wrapper-path-guards.json"
$missingRootReportRelative = ".workflow\ultracode\avorax-hardening\results\cancel-scan-wrapper-missing-root-should-not-exist.json"
$dualRootReportRelative = ".workflow\ultracode\avorax-hardening\results\cancel-scan-wrapper-dual-root-should-not-exist.json"
$report = Join-Path $repo $reportRelative
$guardReport = Join-Path $repo $guardReportRelative
$missingRootReport = Join-Path $repo $missingRootReportRelative
$dualRootReport = Join-Path $repo $dualRootReportRelative
$outsideReport = Join-Path $tempRoot "cancel-scan-wrapper-outside-repo-should-not-exist.json"
$outsideDataRoot = Join-Path $tempRoot "outside-report-data"
$outsideToken = Join-Path (Join-Path $outsideDataRoot "runtime") "cancel-active-scan"

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  foreach ($staleReport in @($guardReport, $missingRootReport, $dualRootReport, $outsideReport)) {
    if (Test-Path -LiteralPath $staleReport -PathType Leaf) {
      Remove-Item -LiteralPath $staleReport -Force
    }
  }

  Invoke-Wrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-DataRoot", $dataRoot,
    "-LocalCorePath", $binary,
    "-ReportPath", $reportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectSuccess $true | Out-Null

  $reportJson = Read-JsonFile $report "cancel scan wrapper report"
  Assert-CancelReport $reportJson $dataRoot

  $guardCases = @()
  $guardCases += Invoke-NegativeCancelWrapperCase -Name "missing-data-root" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-LocalCorePath", $binary,
    "-ReportPath", $missingRootReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectedDiagnostic "Avorax cancel scan requires -DataRoot" -UnexpectedReportPath $missingRootReport

  $guardCases += Invoke-NegativeCancelWrapperCase -Name "dual-data-root-selection" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-DataRoot", $dataRoot,
    "-UseInstalledDataRoot",
    "-LocalCorePath", $binary,
    "-ReportPath", $dualRootReportRelative,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectedDiagnostic "either -DataRoot or -UseInstalledDataRoot" -UnexpectedReportPath $dualRootReport
  $guardCases += Invoke-NegativeCancelWrapperCase -Name "report-path-outside-repo" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-DataRoot", $outsideDataRoot,
    "-LocalCorePath", $binary,
    "-ReportPath", $outsideReport,
    "-TimeoutSeconds", ([string]$TimeoutSeconds)
  ) -ExpectedDiagnostic "Avorax cancel scan report must be inside the repository" -UnexpectedReportPath $outsideReport -UnexpectedTokenPath $outsideToken

  Write-JsonFileAtomic $guardReport ([ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    status = "passed"
    tool = "avorax-cancel-scan-wrapper-path-guards"
    checked_cases = $guardCases
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      process_kill_attempted = $false
      pre_execution_blocking_claimed = $false
      persistent_monitoring_claimed = $false
    }
  })

  Write-Host "Avorax cancel scan wrapper smoke passed."
  Write-Host "Report: $report"
  Write-Host "Token: $($reportJson.cancel_token_path)"
  Write-Host "Guard report: $guardReport"
} finally {
  Remove-SmokeTempRoot $tempRoot
}
