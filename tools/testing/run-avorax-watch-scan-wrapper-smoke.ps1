param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [int]$TimeoutSeconds = 90
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
    throw "Avorax watch scan wrapper smoke expects zentor_local_core.exe, got: $resolved"
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

function Write-WatchScanWrapperSignaturePack {
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
    id = "ZNE-SAFE-WATCH-SCAN-WRAPPER-001"
    name = "Watch scan wrapper harmless known-bad hash fixture"
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
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-08T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-WATCH-SCAN-WRAPPER-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Watch scan wrapper harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-08T00:00:00Z","version":"1"}],"version":"1.0.0"}'
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

function Invoke-WatchWrapper {
  param(
    [string]$PowerShellPath,
    [string[]]$Arguments,
    [AllowNull()][scriptblock]$DuringRun = $null,
    [bool]$ExpectSuccess = $true,
    [int]$TimeoutSeconds = 90
  )

  $process = $null
  try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PowerShellPath
    $startInfo.Arguments = Join-ProcessArguments $Arguments
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if ($null -ne $DuringRun) {
      & $DuringRun $process
    }

    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "Avorax watch scan wrapper smoke timed out after ${TimeoutSeconds}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "Avorax watch scan wrapper smoke timed out after ${TimeoutSeconds}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($ExpectSuccess -and $process.ExitCode -ne 0) {
      throw "Avorax watch scan wrapper command failed with exit code $($process.ExitCode): $(Get-BoundedText ($stdout + $stderr))"
    }
    if (-not $ExpectSuccess -and $process.ExitCode -eq 0) {
      throw "Avorax watch scan wrapper command unexpectedly succeeded: $(Get-BoundedText ($stdout + $stderr))"
    }
    return [ordered]@{
      exit_code = $process.ExitCode
      stdout = $stdout
      stderr = $stderr
    }
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Join-ProcessArguments {
  param([string[]]$Arguments)
  $quoted = @()
  foreach ($argument in $Arguments) {
    if ($null -eq $argument) {
      $quoted += '""'
    } elseif ($argument -notmatch '[\s"]') {
      $quoted += $argument
    } else {
      $quoted += '"' + ($argument -replace '"', '\"') + '"'
    }
  }
  return ($quoted -join " ")
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

function Assert-FalseProperty {
  param([object]$Object, [string]$Name, [string]$Description)
  if (-not ($Object.PSObject.Properties.Name -contains $Name)) {
    throw "$Description is missing safety.$Name"
  }
  if ([bool]$Object.$Name) {
    throw "$Description safety.$Name must be false."
  }
}

function Assert-SafeWatchReport {
  param([object]$Report, [string]$Description)
  if ($Report.tool -ne "avorax-watch-scan") {
    throw "$Description tool mismatch: $($Report.tool)"
  }
  foreach ($name in @(
    "live_malware_used",
    "standard_eicar_string_written",
    "defender_exclusion_required",
    "machine_wide_changes",
    "service_installation_attempted",
    "persistent_monitoring_claimed",
    "pre_execution_blocking_claimed",
    "kernel_driver_required",
    "broad_default_watch_roots_allowed"
  )) {
    Assert-FalseProperty $Report.safety $name $Description
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

function Invoke-NegativeWatchWrapperCase {
  param(
    [string]$Name,
    [string[]]$Arguments,
    [string]$ExpectedDiagnostic,
    [string]$UnexpectedReportPath,
    [int]$TimeoutSeconds = 90
  )

  $negative = Invoke-WatchWrapper `
    -PowerShellPath $powershell `
    -Arguments $Arguments `
    -ExpectSuccess $false `
    -TimeoutSeconds $TimeoutSeconds
  $negativeText = $negative.stdout + $negative.stderr
  if ($negativeText.IndexOf($ExpectedDiagnostic, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "$Name guard did not explain the expected failure '$ExpectedDiagnostic': $(Get-BoundedText $negativeText)"
  }
  if (-not [string]::IsNullOrWhiteSpace($UnexpectedReportPath)) {
    Assert-ReportNotWritten $UnexpectedReportPath "$Name guard"
  }
  return [ordered]@{
    name = $Name
    expected_diagnostic = $ExpectedDiagnostic
    exit_code = $negative.exit_code
    report_written = if ([string]::IsNullOrWhiteSpace($UnexpectedReportPath)) { $false } else { Test-Path -LiteralPath $UnexpectedReportPath -PathType Leaf }
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
  if ([System.IO.Path]::GetFileName($full) -notlike "avorax-watch-scan-wrapper-smoke-*") {
    throw "Refusing to remove unexpected smoke temp root: $full"
  }
  Remove-Item -LiteralPath $full -Recurse -Force
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$wrapper = Join-Path $repo "tools\windows\avorax-watch-scan.ps1"
if (-not (Test-Path -LiteralPath $wrapper -PathType Leaf)) {
  throw "Avorax watch scan wrapper is missing: $wrapper"
}

$powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-watch-scan-wrapper-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$detectRoot = Join-Path $tempRoot "detect-watch"
$quarantineRootWatch = Join-Path $tempRoot "quarantine-watch"
$detectFixture = Join-Path $detectRoot "created-detect.bin"
$quarantineFixture = Join-Path $quarantineRootWatch "created-quarantine.bin"
$detectReportRelative = ".workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-detect.json"
$quarantineReportRelative = ".workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-quarantine.json"
$guardReportRelative = ".workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-path-guards.json"
$missingPathReportRelative = ".workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-missing-path-should-not-exist.json"
$missingRootReportRelative = ".workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-missing-root-should-not-exist.json"
$wrongKindReportRelative = ".workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-wrong-kind-should-not-exist.json"
$broadRootReportRelative = ".workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-broad-root-should-not-exist.json"
$detectReport = Join-Path $repo $detectReportRelative
$quarantineReport = Join-Path $repo $quarantineReportRelative
$guardReport = Join-Path $repo $guardReportRelative
$missingPathReport = Join-Path $repo $missingPathReportRelative
$missingRootReport = Join-Path $repo $missingRootReportRelative
$wrongKindReport = Join-Path $repo $wrongKindReportRelative
$broadRootReport = Join-Path $repo $broadRootReportRelative
$outsideReport = Join-Path $tempRoot "watch-scan-wrapper-outside-repo-should-not-exist.json"
$missingRoot = Join-Path $tempRoot "missing-watch-root"
$wrongKindRoot = Join-Path $tempRoot "not-a-directory.txt"
$broadRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($tempRoot))

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $quarantineRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $detectRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $quarantineRootWatch -Force | Out-Null
  foreach ($staleReport in @(
    $guardReport,
    $missingPathReport,
    $missingRootReport,
    $wrongKindReport,
    $broadRootReport,
    $outsideReport
  )) {
    if (Test-Path -LiteralPath $staleReport -PathType Leaf) {
      Remove-Item -LiteralPath $staleReport -Force
    }
  }

  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-watch-scan-wrapper-fixture")
  Write-WatchScanWrapperSignaturePack $engineRoot (Get-Sha256Hex $fixtureBytes)
  [System.IO.File]::WriteAllText($wrongKindRoot, "not a directory`r`n", [System.Text.UTF8Encoding]::new($false))

  Invoke-WatchWrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-Path", $detectRoot,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $detectReportRelative,
    "-DurationSeconds", "8",
    "-PollIntervalMilliseconds", "200",
    "-MaxEvents", "4",
    "-TimeoutSeconds", "30"
  ) -DuringRun {
    param($Process)
    Start-Sleep -Milliseconds 2500
    if ($Process.HasExited) {
      throw "detect-only watch wrapper exited before fixture creation."
    }
    [System.IO.File]::WriteAllBytes($detectFixture, $fixtureBytes)
  } -ExpectSuccess $true -TimeoutSeconds $TimeoutSeconds | Out-Null

  $detectReportJson = Read-JsonFile $detectReport "detect-only watch scan wrapper report"
  Assert-SafeWatchReport $detectReportJson "detect-only watch scan wrapper report"
  if ($detectReportJson.action_mode -ne "detectOnly") {
    throw "detect-only watch report action_mode mismatch: $($detectReportJson.action_mode)"
  }
  if ($detectReportJson.mode -ne "finiteUserModePolling") {
    throw "detect-only watch report mode mismatch: $($detectReportJson.mode)"
  }
  if ([int64]$detectReportJson.events_observed -lt 1 -or [int64]$detectReportJson.files_scanned -lt 1) {
    throw "detect-only watch report did not observe and scan the fixture."
  }
  if ([int64]$detectReportJson.threats_found -lt 1) {
    throw "detect-only watch report did not record a threat."
  }
  if ([int64]$detectReportJson.quarantined_files -ne 0) {
    throw "detect-only watch report quarantined files."
  }
  if (-not (Test-Path -LiteralPath $detectFixture -PathType Leaf)) {
    throw "detect-only watch scan removed the harmless fixture."
  }

  Invoke-WatchWrapper -PowerShellPath $powershell -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-Path", $quarantineRootWatch,
    "-AutoQuarantineConfirmed",
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $quarantineReportRelative,
    "-DurationSeconds", "8",
    "-PollIntervalMilliseconds", "200",
    "-MaxEvents", "4",
    "-TimeoutSeconds", "30"
  ) -DuringRun {
    param($Process)
    Start-Sleep -Milliseconds 2500
    if ($Process.HasExited) {
      throw "auto-quarantine watch wrapper exited before fixture creation."
    }
    [System.IO.File]::WriteAllBytes($quarantineFixture, $fixtureBytes)
  } -ExpectSuccess $true -TimeoutSeconds $TimeoutSeconds | Out-Null

  $quarantineReportJson = Read-JsonFile $quarantineReport "auto-quarantine watch scan wrapper report"
  Assert-SafeWatchReport $quarantineReportJson "auto-quarantine watch scan wrapper report"
  if ($quarantineReportJson.action_mode -ne "autoQuarantineConfirmedOnly") {
    throw "auto-quarantine watch report action_mode mismatch: $($quarantineReportJson.action_mode)"
  }
  if ($quarantineReportJson.mode -ne "finiteUserModePolling") {
    throw "auto-quarantine watch report mode mismatch: $($quarantineReportJson.mode)"
  }
  if ([int64]$quarantineReportJson.events_observed -lt 1 -or [int64]$quarantineReportJson.files_scanned -lt 1) {
    throw "auto-quarantine watch report did not observe and scan the fixture."
  }
  if ([int64]$quarantineReportJson.threats_found -lt 1 -or [int64]$quarantineReportJson.quarantined_files -lt 1) {
    throw "auto-quarantine watch report did not quarantine a confirmed harmless fixture."
  }
  if (Test-Path -LiteralPath $quarantineFixture -PathType Leaf) {
    throw "auto-quarantine watch scan left the source fixture in place."
  }

  $guardCases = @()
  $guardCases += Invoke-NegativeWatchWrapperCase -Name "missing-watch-path" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $missingPathReportRelative,
    "-DurationSeconds", "1",
    "-TimeoutSeconds", "15"
  ) -ExpectedDiagnostic "requires at least one explicit -Path directory" -UnexpectedReportPath $missingPathReport -TimeoutSeconds $TimeoutSeconds
  $guardCases += Invoke-NegativeWatchWrapperCase -Name "missing-watch-root" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-Path", $missingRoot,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $missingRootReportRelative,
    "-DurationSeconds", "1",
    "-TimeoutSeconds", "15"
  ) -ExpectedDiagnostic "Watch root is not an existing directory" -UnexpectedReportPath $missingRootReport -TimeoutSeconds $TimeoutSeconds
  $guardCases += Invoke-NegativeWatchWrapperCase -Name "watch-root-wrong-kind" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-Path", $wrongKindRoot,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $wrongKindReportRelative,
    "-DurationSeconds", "1",
    "-TimeoutSeconds", "15"
  ) -ExpectedDiagnostic "Watch root is not an existing directory" -UnexpectedReportPath $wrongKindReport -TimeoutSeconds $TimeoutSeconds
  $guardCases += Invoke-NegativeWatchWrapperCase -Name "broad-watch-root" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-Path", $broadRoot,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $broadRootReportRelative,
    "-DurationSeconds", "1",
    "-TimeoutSeconds", "15"
  ) -ExpectedDiagnostic "Watch root is too broad for this finite user-mode wrapper" -UnexpectedReportPath $broadRootReport -TimeoutSeconds $TimeoutSeconds
  $guardCases += Invoke-NegativeWatchWrapperCase -Name "report-path-outside-repo" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-RepoRoot", $repo,
    "-Path", $detectRoot,
    "-LocalCorePath", $binary,
    "-DataRoot", $dataRoot,
    "-QuarantineRoot", $quarantineRoot,
    "-AllowlistFile", $allowlistFile,
    "-EngineRoot", $engineRoot,
    "-ReportPath", $outsideReport,
    "-DurationSeconds", "1",
    "-TimeoutSeconds", "15"
  ) -ExpectedDiagnostic "Avorax watch scan report must be inside the repository" -UnexpectedReportPath $outsideReport -TimeoutSeconds $TimeoutSeconds

  $guardReportBody = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    status = "passed"
    checked_cases = $guardCases
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      persistent_monitoring_claimed = $false
      pre_execution_blocking_claimed = $false
      kernel_driver_required = $false
      broad_default_watch_roots_allowed = $false
    }
  }
  Write-JsonFileAtomic $guardReport $guardReportBody

  Write-Host "Avorax watch scan wrapper smoke passed."
  Write-Host "Detect report: $detectReport"
  Write-Host "Quarantine report: $quarantineReport"
  Write-Host "Guard report: $guardReport"
} finally {
  Remove-SmokeTempRoot $tempRoot
}
