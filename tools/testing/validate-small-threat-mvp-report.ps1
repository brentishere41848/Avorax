param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$ReportPath = "",
  [switch]$RequireFullSuite
)

$ErrorActionPreference = "Stop"
$maxReportBytes = 2097152

$expectedBundledSignaturePacks = @(
  "zentor_core.zsig",
  "zentor_github_known_bad.zsig",
  "zentor_infostealer_indicators.zsig",
  "zentor_lab_known_bad.zsig",
  "zentor_miner_pup_indicators.zsig",
  "zentor_ransomware_indicators.zsig",
  "zentor_realworld_hashes.zsig",
  "zentor_script_threats.zsig"
)

$expectedBundledRulePacks = @(
  "zentor_infostealers.zrule",
  "zentor_miners_pup.zrule",
  "zentor_persistence.zrule",
  "zentor_ransomware.zrule",
  "zentor_rules.zrule",
  "zentor_script_threats.zrule"
)

$expectedPythonDirectRequirements = @(
  "onnx==1.22.0",
  "numpy==2.2.6",
  "jsonschema==4.26.0"
)

$expectedPythonVerificationLock = @(
  "attrs==26.1.0",
  "jsonschema==4.26.0",
  "jsonschema-specifications==2025.9.1",
  "ml_dtypes==0.5.4",
  "numpy==2.2.6",
  "onnx==1.22.0",
  "protobuf==7.35.1",
  "referencing==0.37.0",
  "rpds-py==2026.5.1",
  "typing_extensions==4.15.0"
)

$expectedDependencyLockfiles = @(
  [ordered]@{ component = "Root Rust workspace"; manifest = "Cargo.toml"; lockfile = "Cargo.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "Native engine"; manifest = "core\zentor_native_engine\Cargo.toml"; lockfile = "core\zentor_native_engine\Cargo.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "Local core"; manifest = "core\zentor_local_core\Cargo.toml"; lockfile = "core\zentor_local_core\Cargo.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "Guard service"; manifest = "core\zentor_guard_service\Cargo.toml"; lockfile = "core\zentor_guard_service\Cargo.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "Update service (workspace member)"; manifest = "core\avorax_update_service\Cargo.toml"; lockfile = "Cargo.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "API service"; manifest = "services\api\Cargo.toml"; lockfile = "services\api\Cargo.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "Flutter client"; manifest = "apps\zentor_client\pubspec.yaml"; lockfile = "apps\zentor_client\pubspec.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "Zentor protocol package"; manifest = "packages\zentor_protocol\pubspec.yaml"; lockfile = "packages\zentor_protocol\pubspec.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "Avorax protocol package"; manifest = "packages\avorax_protocol\pubspec.yaml"; lockfile = "packages\avorax_protocol\pubspec.lock"; required_for_release = $true; lockfile_present = $true },
  [ordered]@{ component = "Android Gradle dependencies (non-Windows release path)"; manifest = "apps\zentor_client\android\settings.gradle.kts"; lockfile = "apps\zentor_client\android\gradle.lockfile"; required_for_release = $false; lockfile_present = $false },
  [ordered]@{ component = "Archived legacy website"; manifest = "archive\*_website_old\package.json"; lockfile = "archive\*_website_old\package-lock.json"; required_for_release = $false; lockfile_present = $true }
)

$expectedDependencyLockfileSummaries = @(
  [ordered]@{ ecosystem = "cargo"; lockfile = "Cargo.lock"; package_pattern = '^\[\[package\]\]'; integrity_pattern = '^\s*checksum\s*='; integrity_evidence = "Cargo registry checksum entries" },
  [ordered]@{ ecosystem = "cargo"; lockfile = "core\zentor_native_engine\Cargo.lock"; package_pattern = '^\[\[package\]\]'; integrity_pattern = '^\s*checksum\s*='; integrity_evidence = "Cargo registry checksum entries" },
  [ordered]@{ ecosystem = "cargo"; lockfile = "core\zentor_local_core\Cargo.lock"; package_pattern = '^\[\[package\]\]'; integrity_pattern = '^\s*checksum\s*='; integrity_evidence = "Cargo registry checksum entries" },
  [ordered]@{ ecosystem = "cargo"; lockfile = "core\zentor_guard_service\Cargo.lock"; package_pattern = '^\[\[package\]\]'; integrity_pattern = '^\s*checksum\s*='; integrity_evidence = "Cargo registry checksum entries" },
  [ordered]@{ ecosystem = "cargo"; lockfile = "services\api\Cargo.lock"; package_pattern = '^\[\[package\]\]'; integrity_pattern = '^\s*checksum\s*='; integrity_evidence = "Cargo registry checksum entries" },
  [ordered]@{ ecosystem = "pub"; lockfile = "apps\zentor_client\pubspec.lock"; package_pattern = '^\s{2}[A-Za-z0-9_][A-Za-z0-9_-]*:\s*$'; integrity_pattern = '^\s+sha256:\s*'; integrity_evidence = "pub.dev SHA-256 entries" },
  [ordered]@{ ecosystem = "pub"; lockfile = "packages\zentor_protocol\pubspec.lock"; package_pattern = '^\s{2}[A-Za-z0-9_][A-Za-z0-9_-]*:\s*$'; integrity_pattern = '^\s+sha256:\s*'; integrity_evidence = "pub.dev SHA-256 entries" },
  [ordered]@{ ecosystem = "pub"; lockfile = "packages\avorax_protocol\pubspec.lock"; package_pattern = '^\s{2}[A-Za-z0-9_][A-Za-z0-9_-]*:\s*$'; integrity_pattern = '^\s+sha256:\s*'; integrity_evidence = "pub.dev SHA-256 entries" },
  [ordered]@{ ecosystem = "python"; lockfile = "ml\requirements.lock.txt"; package_pattern = '^[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+_-]+$'; integrity_pattern = '^[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+_-]+$'; integrity_evidence = "exact version pins" }
)

$expectedGradleWrapperSha256 = "b84e04fa845fecba48551f425957641074fcc00a88a84d2aae5808743b35fc85"

. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

function Assert-SmallThreatMvpRepoChildPath {
  param(
    [string]$Path,
    [string]$RepositoryRoot,
    [string]$Description
  )

  $rootFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  Assert-AvoraxNoReparsePath $pathFull $Description
  if ($pathFull.TrimEnd('\', '/').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be a child path inside the repository root, not the repository root itself."
  }
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must stay under $RepositoryRoot`: $pathFull"
  }
  $pathFull
}

function Resolve-SmallThreatMvpReportPath {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Join-Path $RepositoryRoot ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-verification-report.json"
  } elseif (-not [System.IO.Path]::IsPathRooted($Path)) {
    $Path = Join-Path $RepositoryRoot $Path
  }

  Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($Path)) $RepositoryRoot "small-threat MVP verification report"
}

function Get-RequiredProperty {
  param(
    [object]$Object,
    [string]$Name,
    [string]$Description
  )

  if ($null -eq $Object -or $Object -isnot [System.Management.Automation.PSCustomObject]) {
    throw "$Description must be a JSON object."
  }
  if (-not ($Object.PSObject.Properties.Name -contains $Name)) {
    throw "$Description is missing required property '$Name'."
  }
  $Object.$Name
}

function Assert-JsonObject {
  param(
    [object]$Value,
    [string]$Description
  )

  if ($null -eq $Value -or $Value -isnot [System.Management.Automation.PSCustomObject]) {
    throw "$Description must be a JSON object."
  }
}

function Assert-JsonString {
  param(
    [object]$Value,
    [string]$Description
  )

  if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) {
    throw "$Description must be a non-empty string."
  }
  [string]$Value
}

function Assert-JsonStringEquals {
  param(
    [object]$Value,
    [string]$Expected,
    [string]$Description
  )

  $actual = Assert-JsonString $Value $Description
  if ($actual -ne $Expected) {
    throw "$Description mismatch: expected $Expected, found $actual"
  }
  $actual
}

function Assert-JsonBoolean {
  param(
    [object]$Value,
    [string]$Description
  )

  if ($Value -isnot [bool]) {
    throw "$Description must be a JSON boolean."
  }
  [bool]$Value
}

function Assert-JsonBooleanEquals {
  param(
    [object]$Value,
    [bool]$Expected,
    [string]$Description
  )

  $actual = Assert-JsonBoolean $Value $Description
  if ($actual -ne $Expected) {
    throw "$Description must be JSON boolean $Expected."
  }
}

function Assert-JsonNumber {
  param(
    [object]$Value,
    [string]$Description
  )

  if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string]) {
    throw "$Description must be a JSON number."
  }
  try {
    $number = [double]$Value
  } catch {
    throw "$Description must be a JSON number."
  }
  if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
    throw "$Description must be finite."
  }
  if ($number -lt 0) {
    throw "$Description must be non-negative."
  }
  $number
}

function Assert-JsonInteger {
  param(
    [object]$Value,
    [string]$Description
  )

  if (-not ($Value -is [int] -or $Value -is [long])) {
    throw "$Description must be a JSON integer."
  }
  $number = [int64]$Value
  if ($number -lt 0) {
    throw "$Description must be non-negative."
  }
  $number
}

function Assert-JsonIntegerEquals {
  param(
    [object]$Value,
    [int64]$Expected,
    [string]$Description
  )

  $actual = Assert-JsonInteger $Value $Description
  if ($actual -ne $Expected) {
    throw "$Description mismatch: expected $Expected, found $actual"
  }
  $actual
}

function Assert-JsonArray {
  param(
    [object]$Value,
    [string]$Description
  )

  if ($null -eq $Value -or $Value -isnot [array]) {
    throw "$Description must be a JSON array."
  }
  @($Value)
}

function Assert-JsonArrayEmpty {
  param(
    [object]$Value,
    [string]$Description
  )

  if ($null -eq $Value) {
    return
  }
  $items = @(Assert-JsonArray $Value $Description)
  if ($items.Count -ne 0) {
    throw "$Description must be an empty JSON array, found $($items.Count) entries."
  }
}

function Assert-JsonObjectPropertiesExactly {
  param(
    [object]$Object,
    [string[]]$Expected,
    [string]$Description
  )

  Assert-JsonObject $Object $Description
  $actualNames = @($Object.PSObject.Properties.Name | Sort-Object)
  $expectedNames = @($Expected | Sort-Object)
  if ($actualNames.Count -ne $expectedNames.Count) {
    throw "$Description must contain exactly $($expectedNames.Count) properties, found $($actualNames.Count)."
  }
  for ($i = 0; $i -lt $expectedNames.Count; $i++) {
    if ($actualNames[$i] -ne $expectedNames[$i]) {
      throw "$Description property mismatch: expected $($expectedNames[$i]), found $($actualNames[$i])."
    }
  }
}

function Assert-JsonStringArrayEquals {
  param(
    [object]$Value,
    [string[]]$Expected,
    [string]$Description
  )

  $items = @(Assert-JsonArray $Value $Description)
  if ($items.Count -ne $Expected.Count) {
    throw "$Description must contain exactly $($Expected.Count) entries, found $($items.Count)."
  }
  for ($i = 0; $i -lt $Expected.Count; $i++) {
    $actual = Assert-JsonString $items[$i] "$Description entry $($i + 1)"
    if ($actual -ne $Expected[$i]) {
      throw "$Description entry $($i + 1) mismatch: expected $($Expected[$i]), found $actual"
    }
  }
}

function Assert-StringArrayEquals {
  param(
    [string[]]$Actual,
    [string[]]$Expected,
    [string]$Description
  )

  if ($Actual.Count -ne $Expected.Count) {
    throw "$Description must contain exactly $($Expected.Count) entries, found $($Actual.Count)."
  }
  for ($i = 0; $i -lt $Expected.Count; $i++) {
    if ($Actual[$i] -ne $Expected[$i]) {
      throw "$Description entry $($i + 1) mismatch: expected $($Expected[$i]), found $($Actual[$i])"
    }
  }
}

function Assert-JsonTimestamp {
  param(
    [object]$Value,
    [string]$Description
  )

  $text = Assert-JsonString $Value $Description
  try {
    [datetime]::Parse(
      $text,
      [System.Globalization.CultureInfo]::InvariantCulture,
      [System.Globalization.DateTimeStyles]::RoundtripKind
    )
  } catch {
    throw "$Description must be an ISO-8601 timestamp."
  }
}

function Read-SmallThreatMvpReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "small-threat MVP verification report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "small-threat MVP verification report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "small-threat MVP verification report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "small-threat MVP verification report must be a single JSON object."
  }
  Assert-JsonObject $report "small-threat MVP verification report"
  $report
}

function Read-ProtectionSelfTestReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "protection self-test generated report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "protection self-test generated report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "protection self-test generated report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "protection self-test generated report must be a single JSON object."
  }
  Assert-JsonObject $report "protection self-test generated report"
  $report
}

function Read-DependencyEvidenceReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "dependency evidence generated report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "dependency evidence generated report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "dependency evidence generated report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "dependency evidence generated report must be a single JSON object."
  }
  Assert-JsonObject $report "dependency evidence generated report"
  $report
}

function Read-PerformanceGateReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "performance gate generated report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "performance gate generated report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "performance gate generated report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "performance gate generated report must be a single JSON object."
  }
  Assert-JsonObject $report "performance gate generated report"
  $report
}

function Read-PerformanceBenchmarkReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "performance benchmark generated report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "performance benchmark generated report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "performance benchmark generated report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "performance benchmark generated report must be a single JSON object."
  }
  Assert-JsonObject $report "performance benchmark generated report"
  $report
}

function Read-BundledPackInventoryReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "bundled pack inventory report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "bundled pack inventory report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "bundled pack inventory report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "bundled pack inventory report must be a single JSON object."
  }
  Assert-JsonObject $report "bundled pack inventory report"
  $report
}

function Read-NoEicarHarmlessThreatReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "no-EICAR harmless-threat generated report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "no-EICAR harmless-threat generated report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "no-EICAR harmless-threat generated report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "no-EICAR harmless-threat generated report must be a single JSON object."
  }
  Assert-JsonObject $report "no-EICAR harmless-threat generated report"
  $report
}

function Resolve-GeneratedReportPath {
  param(
    [AllowNull()][object]$Value,
    [string]$RepositoryRoot,
    [string]$Description,
    [bool]$RequireExistingFile
  )

  if ($null -eq $Value -or ([string]$Value).Length -eq 0) {
    if ($RequireExistingFile) {
      throw "$Description must be present for a passed report."
    }
    return $null
  }
  $text = Assert-JsonString $Value $Description
  $candidate = $text
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $RepositoryRoot $candidate
  }
  $fullPath = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($candidate)) $RepositoryRoot $Description
  if ($RequireExistingFile) {
    Get-AvoraxGateFile $fullPath $Description | Out-Null
  }
  $fullPath
}

function Assert-GeneratedReportPath {
  param(
    [AllowNull()][object]$Value,
    [string]$RepositoryRoot,
    [string]$Description,
    [bool]$RequireExistingFile
  )

  [void](Resolve-GeneratedReportPath $Value $RepositoryRoot $Description $RequireExistingFile)
}

function Assert-RequiredToolPath {
  param(
    [object]$Value,
    [string]$Description,
    [bool]$RequireExistingFile
  )

  $text = Assert-JsonString $Value $Description
  if ($RequireExistingFile) {
    Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($text)) $Description | Out-Null
  }
}

function Assert-Step {
  param(
    [object]$Step,
    [int]$Index
  )

  Assert-JsonObject $Step "step $Index"
  [void](Assert-JsonString (Get-RequiredProperty $Step "name" "step $Index") "step $Index name")
  [void](Assert-JsonString (Get-RequiredProperty $Step "command" "step $Index") "step $Index command")
  [void](Assert-JsonNumber (Get-RequiredProperty $Step "seconds" "step $Index") "step $Index seconds")
  $stepStatus = Assert-JsonString (Get-RequiredProperty $Step "status" "step $Index") "step $Index status"
  if ($stepStatus -ne "passed") {
    throw "step $Index status must be 'passed': $stepStatus"
  }
}

function Assert-ReportContainsStep {
  param(
    [object[]]$Steps,
    [string]$Name
  )

  foreach ($step in $Steps) {
    if ($step.name -eq $Name) { return }
  }
  throw "passed full-suite report is missing required step: $Name"
}

function Assert-ReportScopeContains {
  param(
    [string]$Text,
    [string]$Expected,
    [string]$Description
  )

  if ($Text.IndexOf($Expected, [StringComparison]::Ordinal) -lt 0) {
    throw "$Description must include required evidence scope: $Expected"
  }
}

function Assert-DependencyRelativePathSafe {
  param(
    [string]$RelativePath,
    [string]$RepositoryRoot,
    [string]$Description
  )

  if ([System.IO.Path]::IsPathRooted($RelativePath)) {
    throw "$Description must be repository-relative: $RelativePath"
  }
  if ($RelativePath -match '(^|[\\/])\.\.([\\/]|$)') {
    throw "$Description must not contain parent traversal: $RelativePath"
  }
  $candidate = Join-Path $RepositoryRoot $RelativePath
  $wildcardIndex = $RelativePath.IndexOfAny([char[]]@('*', '?'))
  if ($wildcardIndex -ge 0) {
    $fixedPrefix = $RelativePath.Substring(0, $wildcardIndex)
    $separatorIndex = $fixedPrefix.LastIndexOfAny([char[]]@('\', '/'))
    $wildcardAnchorRelative = if ($separatorIndex -ge 0) {
      $fixedPrefix.Substring(0, $separatorIndex)
    } else {
      ""
    }
    $wildcardAnchor = if ([string]::IsNullOrWhiteSpace($wildcardAnchorRelative)) {
      $RepositoryRoot
    } else {
      Join-Path $RepositoryRoot $wildcardAnchorRelative
    }
    $checkedWildcardAnchor = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($wildcardAnchor)) $RepositoryRoot "$Description wildcard anchor"
    if (-not (Test-Path -LiteralPath $checkedWildcardAnchor -PathType Container)) {
      return $false
    }
    $matches = @(Get-ChildItem -Path $candidate -File -ErrorAction Stop)
    foreach ($match in $matches) {
      [void](Assert-SmallThreatMvpRepoChildPath $match.FullName $RepositoryRoot $Description)
      Get-AvoraxGateFile $match.FullName $Description | Out-Null
    }
    return ($matches.Count -gt 0)
  }
  $fullPath = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($candidate)) $RepositoryRoot $Description
  if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
    Get-AvoraxGateFile $fullPath $Description | Out-Null
    return $true
  }
  return $false
}

function Get-DependencyRequirementLines {
  param(
    [string]$Path,
    [string]$Description
  )

  $text = Read-AvoraxGateTextFileBounded $Path $maxReportBytes $Description
  @(
    $text -split '\r?\n' |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ -match '\S' } |
      Where-Object { -not $_.StartsWith("#") }
  )
}

function Assert-DependencyRequirementCheck {
  param(
    [object]$Check,
    [string]$ExpectedName,
    [string]$ExpectedRelativePath,
    [string[]]$ExpectedLines,
    [string]$RepositoryRoot
  )

  $description = "dependency evidence generated report requirement check $ExpectedName"
  Assert-JsonObjectPropertiesExactly $Check @(
    "name",
    "path",
    "ok",
    "line_count",
    "missing",
    "extra",
    "unexpected"
  ) $description

  $name = Assert-JsonString (Get-RequiredProperty $Check "name" $description) "$description name"
  if ($name -ne $ExpectedName) {
    throw "$description name mismatch: $name"
  }
  Assert-JsonBooleanEquals (Get-RequiredProperty $Check "ok" $description) $true "$description ok"
  $lineCount = Assert-JsonInteger (Get-RequiredProperty $Check "line_count" $description) "$description line_count"
  if ($lineCount -ne $ExpectedLines.Count) {
    throw "$description line_count mismatch: $lineCount"
  }
  Assert-JsonArrayEmpty (Get-RequiredProperty $Check "missing" $description) "$description missing"
  Assert-JsonArrayEmpty (Get-RequiredProperty $Check "extra" $description) "$description extra"
  Assert-JsonArrayEmpty (Get-RequiredProperty $Check "unexpected" $description) "$description unexpected"

  $expectedPath = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot $ExpectedRelativePath))
  $path = Assert-JsonString (Get-RequiredProperty $Check "path" $description) "$description path"
  $pathFull = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($path)) $RepositoryRoot $description
  if (-not $pathFull.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$description path mismatch: $path"
  }
  Get-AvoraxGateFile $pathFull $description | Out-Null
  $actualLines = @(Get-DependencyRequirementLines $pathFull $description)
  Assert-StringArrayEquals $actualLines $ExpectedLines "$description current file lines"
}

function Assert-DependencyLockfileCheck {
  param(
    [object]$Check,
    [object]$Expected,
    [string]$RepositoryRoot,
    [int]$Index
  )

  $description = "dependency evidence generated report lockfile check $Index"
  Assert-JsonObjectPropertiesExactly $Check @(
    "component",
    "manifest",
    "manifest_present",
    "lockfile",
    "lockfile_present",
    "required_for_release"
  ) $description

  $component = Assert-JsonString (Get-RequiredProperty $Check "component" $description) "$description component"
  if ($component -ne $Expected.component) {
    throw "$description component mismatch: $component"
  }
  $manifest = Assert-JsonString (Get-RequiredProperty $Check "manifest" $description) "$description manifest"
  if ($manifest -ne $Expected.manifest) {
    throw "$description manifest mismatch: $manifest"
  }
  $lockfile = Assert-JsonString (Get-RequiredProperty $Check "lockfile" $description) "$description lockfile"
  if ($lockfile -ne $Expected.lockfile) {
    throw "$description lockfile mismatch: $lockfile"
  }
  Assert-JsonBooleanEquals (Get-RequiredProperty $Check "required_for_release" $description) ([bool]$Expected.required_for_release) "$description required_for_release"
  Assert-JsonBooleanEquals (Get-RequiredProperty $Check "manifest_present" $description) $true "$description manifest_present"
  Assert-JsonBooleanEquals (Get-RequiredProperty $Check "lockfile_present" $description) ([bool]$Expected.lockfile_present) "$description lockfile_present"

  $manifestPresent = Assert-DependencyRelativePathSafe $manifest $RepositoryRoot "$description manifest"
  if (-not $manifestPresent) {
    throw "$description manifest must exist in the current repository: $manifest"
  }
  $lockfilePresent = Assert-DependencyRelativePathSafe $lockfile $RepositoryRoot "$description lockfile"
  if ($lockfilePresent -ne [bool]$Expected.lockfile_present) {
    throw "$description lockfile presence mismatch in current repository: $lockfile"
  }
}

function Count-RegexMatches {
  param(
    [string]$Text,
    [string]$Pattern
  )

  [System.Text.RegularExpressions.Regex]::Matches(
    $Text,
    $Pattern,
    [System.Text.RegularExpressions.RegexOptions]::Multiline
  ).Count
}

function Assert-DependencyLockfileSummary {
  param(
    [object]$Summary,
    [object]$Expected,
    [string]$RepositoryRoot,
    [int]$Index
  )

  $description = "dependency evidence generated report lockfile summary $Index"
  Assert-JsonObjectPropertiesExactly $Summary @(
    "ecosystem",
    "lockfile",
    "present",
    "package_count",
    "integrity_evidence",
    "integrity_entry_count"
  ) $description

  [void](Assert-JsonStringEquals (Get-RequiredProperty $Summary "ecosystem" $description) $Expected.ecosystem "$description ecosystem")
  $lockfile = Assert-JsonString (Get-RequiredProperty $Summary "lockfile" $description) "$description lockfile"
  if ($lockfile -ne $Expected.lockfile) {
    throw "$description lockfile mismatch: $lockfile"
  }
  Assert-JsonBooleanEquals (Get-RequiredProperty $Summary "present" $description) $true "$description present"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $Summary "integrity_evidence" $description) $Expected.integrity_evidence "$description integrity_evidence")

  $lockfileFull = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot $lockfile))) $RepositoryRoot "$description lockfile"
  Get-AvoraxGateFile $lockfileFull "$description lockfile" | Out-Null
  $text = Read-AvoraxGateTextFileBounded $lockfileFull $maxReportBytes "$description lockfile"
  $expectedPackageCount = Count-RegexMatches $text $Expected.package_pattern
  $expectedIntegrityCount = Count-RegexMatches $text $Expected.integrity_pattern
  if ($expectedPackageCount -le 0) {
    throw "$description current lockfile package count must be positive: $lockfile"
  }
  if ($expectedIntegrityCount -le 0) {
    throw "$description current lockfile integrity count must be positive: $lockfile"
  }

  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $Summary "package_count" $description) $expectedPackageCount "$description package_count")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $Summary "integrity_entry_count" $description) $expectedIntegrityCount "$description integrity_entry_count")
}

function Assert-DependencyLicenseInventory {
  param(
    [object]$Inventory,
    [string]$RepositoryRoot
  )

  Assert-JsonObjectPropertiesExactly $Inventory @(
    "status",
    "evidence_basis",
    "full_release_sbom_required",
    "machine_wide_dependency_installation",
    "network_access_required",
    "documentation",
    "documented_license_notes"
  ) "dependency evidence generated report license_inventory"

  [void](Assert-JsonStringEquals (Get-RequiredProperty $Inventory "status" "dependency evidence generated report license_inventory") "source_level_partial" "dependency evidence generated report license_inventory status")
  $basis = Assert-JsonString (Get-RequiredProperty $Inventory "evidence_basis" "dependency evidence generated report license_inventory") "dependency evidence generated report license_inventory evidence_basis"
  if ($basis.IndexOf("lockfiles", [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
      $basis.IndexOf("documented license notes", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "dependency evidence generated report license_inventory evidence_basis must name lockfiles and documented license notes."
  }
  Assert-JsonBooleanEquals (Get-RequiredProperty $Inventory "full_release_sbom_required" "dependency evidence generated report license_inventory") $true "dependency evidence generated report license_inventory full_release_sbom_required"
  Assert-JsonBooleanEquals (Get-RequiredProperty $Inventory "machine_wide_dependency_installation" "dependency evidence generated report license_inventory") $false "dependency evidence generated report license_inventory machine_wide_dependency_installation"
  Assert-JsonBooleanEquals (Get-RequiredProperty $Inventory "network_access_required" "dependency evidence generated report license_inventory") $false "dependency evidence generated report license_inventory network_access_required"

  $doc = Assert-JsonString (Get-RequiredProperty $Inventory "documentation" "dependency evidence generated report license_inventory") "dependency evidence generated report license_inventory documentation"
  if ($doc -ne "docs\dependency-license-inventory.md") {
    throw "dependency evidence generated report license_inventory documentation mismatch: $doc"
  }
  $docFull = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot $doc))) $RepositoryRoot "dependency evidence generated report license_inventory documentation"
  Get-AvoraxGateFile $docFull "dependency evidence generated report license_inventory documentation" | Out-Null
  $docText = Read-AvoraxGateTextFileBounded $docFull $maxReportBytes "dependency evidence generated report license_inventory documentation"
  foreach ($marker in @("onnx", "numpy", "jsonschema", "flate2", "MIT OR Apache-2.0", "full SBOM")) {
    if ($docText.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
      throw "dependency license inventory documentation is missing marker: $marker"
    }
  }

  $notes = @(Assert-JsonArray (Get-RequiredProperty $Inventory "documented_license_notes" "dependency evidence generated report license_inventory") "dependency evidence generated report license_inventory documented_license_notes")
  if ($notes.Count -ne 2) {
    throw "dependency evidence generated report license_inventory documented_license_notes must contain exactly 2 entries, found $($notes.Count)."
  }
  foreach ($note in $notes) {
    Assert-JsonObjectPropertiesExactly $note @("component", "packages", "licenses", "status") "dependency evidence generated report license_inventory note"
    [void](Assert-JsonString (Get-RequiredProperty $note "component" "dependency evidence generated report license_inventory note") "dependency evidence generated report license_inventory note component")
    $packages = @(Assert-JsonArray (Get-RequiredProperty $note "packages" "dependency evidence generated report license_inventory note") "dependency evidence generated report license_inventory note packages")
    $licenses = @(Assert-JsonArray (Get-RequiredProperty $note "licenses" "dependency evidence generated report license_inventory note") "dependency evidence generated report license_inventory note licenses")
    if ($packages.Count -lt 3 -or $licenses.Count -lt 2) {
      throw "dependency evidence generated report license_inventory note must include multiple packages and licenses."
    }
    [void](Assert-JsonString (Get-RequiredProperty $note "status" "dependency evidence generated report license_inventory note") "dependency evidence generated report license_inventory note status")
  }
}

function Assert-PerformanceMetricBase {
  param(
    [object]$Metric,
    [string]$ExpectedName,
    [string]$ExpectedMeasuredBy,
    [string]$Description
  )

  Assert-JsonObject $Metric $Description
  [void](Assert-JsonStringEquals (Get-RequiredProperty $Metric "name" $Description) $ExpectedName "$Description name")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $Metric "status" $Description) "pass" "$Description status")
  $elapsedMs = Assert-JsonNumber (Get-RequiredProperty $Metric "elapsed_ms" $Description) "$Description elapsed_ms"
  if ($elapsedMs -le 0) {
    throw "$Description elapsed_ms must be greater than zero."
  }
  $errorValue = Get-RequiredProperty $Metric "error" $Description
  if ($null -ne $errorValue) {
    throw "$Description error must be null for a passing metric."
  }
  [void](Assert-JsonStringEquals (Get-RequiredProperty $Metric "measured_by" $Description) $ExpectedMeasuredBy "$Description measured_by")
}

function Get-RequiredMetricByName {
  param(
    [object[]]$Metrics,
    [string]$Name
  )

  $matches = @($Metrics | Where-Object {
      (Get-RequiredProperty $_ "name" "performance benchmark generated report metric") -eq $Name
    })
  if ($matches.Count -ne 1) {
    throw "performance benchmark generated report must contain exactly one metric named $Name, found $($matches.Count)."
  }
  $matches[0]
}

function Assert-PerformanceCommandMetric {
  param(
    [object]$Metric,
    [string]$ExpectedName,
    [string]$ExpectedManifest,
    [string]$ExpectedTest
  )

  $description = "performance benchmark generated report metric $ExpectedName"
  Assert-JsonObjectPropertiesExactly $Metric @(
    "name",
    "status",
    "elapsed_ms",
    "error",
    "measured_by",
    "command",
    "exit_code",
    "output_truncated",
    "output_tail"
  ) $description

  Assert-PerformanceMetricBase $Metric $ExpectedName "subprocess wall-clock timing" $description
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $Metric "exit_code" $description) 0 "$description exit_code")
  Assert-JsonBooleanEquals (Get-RequiredProperty $Metric "output_truncated" $description) $false "$description output_truncated"

  $command = @(Assert-JsonArray (Get-RequiredProperty $Metric "command" $description) "$description command")
  if ($command.Count -ne 5) {
    throw "$description command must contain exactly 5 entries, found $($command.Count)."
  }
  $cargoPath = Assert-JsonString $command[0] "$description command cargo path"
  if ([System.IO.Path]::GetFileName($cargoPath) -ne "cargo.exe") {
    throw "$description command must launch cargo.exe, found $cargoPath"
  }
  Get-AvoraxGateFile $cargoPath "$description command cargo path" | Out-Null
  [void](Assert-JsonStringEquals $command[1] "test" "$description command verb")
  [void](Assert-JsonStringEquals $command[2] "--manifest-path" "$description command manifest flag")
  [void](Assert-JsonStringEquals $command[3] $ExpectedManifest "$description command manifest path")
  [void](Assert-JsonStringEquals $command[4] $ExpectedTest "$description command test name")

  $outputTail = Assert-JsonString (Get-RequiredProperty $Metric "output_tail" $description) "$description output_tail"
  if ($outputTail.IndexOf("1 passed", [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
      $outputTail.IndexOf($ExpectedTest, [StringComparison]::Ordinal) -lt 0) {
    throw "$description output_tail must show the expected single passing test."
  }
}

function Assert-NoEicarHarmlessThreatReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "no-EICAR harmless-threat generated report path is required."
  }
  [void](Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($Path)) $RepositoryRoot "no-EICAR harmless-threat generated report")
  $report = Read-NoEicarHarmlessThreatReport $Path

  Assert-JsonObjectPropertiesExactly $report @(
    "schema_version",
    "status",
    "repository",
    "started_at_utc",
    "completed_at_utc",
    "elapsed_seconds",
    "local_core_path",
    "underlying_script",
    "fixture_policy",
    "verified_flow",
    "limits",
    "error"
  ) "no-EICAR harmless-threat generated report"

  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $report "schema_version" "no-EICAR harmless-threat generated report") 1 "no-EICAR harmless-threat generated report schema_version")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $report "status" "no-EICAR harmless-threat generated report") "passed" "no-EICAR harmless-threat generated report status")

  $repository = Assert-JsonString (Get-RequiredProperty $report "repository" "no-EICAR harmless-threat generated report") "no-EICAR harmless-threat generated report repository"
  $reportRepo = (Resolve-Path -LiteralPath $repository).Path
  if (-not $reportRepo.Equals($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "no-EICAR harmless-threat generated report repository does not match RepoRoot: $repository"
  }

  $startedAt = Assert-JsonTimestamp (Get-RequiredProperty $report "started_at_utc" "no-EICAR harmless-threat generated report") "no-EICAR harmless-threat generated report started_at_utc"
  $completedAt = Assert-JsonTimestamp (Get-RequiredProperty $report "completed_at_utc" "no-EICAR harmless-threat generated report") "no-EICAR harmless-threat generated report completed_at_utc"
  if ($completedAt -lt $startedAt) {
    throw "no-EICAR harmless-threat generated report completed_at_utc is before started_at_utc."
  }
  [void](Assert-JsonNumber (Get-RequiredProperty $report "elapsed_seconds" "no-EICAR harmless-threat generated report") "no-EICAR harmless-threat generated report elapsed_seconds")

  $localCorePath = Assert-JsonString (Get-RequiredProperty $report "local_core_path" "no-EICAR harmless-threat generated report") "no-EICAR harmless-threat generated report local_core_path"
  [void](Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($localCorePath)) $RepositoryRoot "no-EICAR harmless-threat generated report local_core_path")
  Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($localCorePath)) "no-EICAR harmless-threat generated report local_core_path" | Out-Null

  $underlyingScript = Assert-JsonString (Get-RequiredProperty $report "underlying_script" "no-EICAR harmless-threat generated report") "no-EICAR harmless-threat generated report underlying_script"
  $underlyingScriptFull = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($underlyingScript)) $RepositoryRoot "no-EICAR harmless-threat generated report underlying_script"
  $expectedUnderlyingScript = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot "tools\testing\run-release-local-core-smoke.ps1"))
  if (-not $underlyingScriptFull.Equals($expectedUnderlyingScript, [StringComparison]::OrdinalIgnoreCase)) {
    throw "no-EICAR harmless-threat generated report underlying_script mismatch: $underlyingScript"
  }
  Get-AvoraxGateFile $underlyingScriptFull "no-EICAR harmless-threat generated report underlying_script" | Out-Null

  $fixturePolicy = Get-RequiredProperty $report "fixture_policy" "no-EICAR harmless-threat generated report"
  Assert-JsonObjectPropertiesExactly $fixturePolicy @(
    "live_malware_used",
    "standard_eicar_file_created",
    "standard_eicar_string_written",
    "defender_exclusion_required",
    "machine_wide_changes",
    "network_access_required",
    "fixture_description"
  ) "no-EICAR harmless-threat generated report fixture_policy"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "live_malware_used" "no-EICAR harmless-threat generated report fixture_policy") $false "no-EICAR harmless-threat generated report fixture_policy.live_malware_used"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "standard_eicar_file_created" "no-EICAR harmless-threat generated report fixture_policy") $false "no-EICAR harmless-threat generated report fixture_policy.standard_eicar_file_created"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "standard_eicar_string_written" "no-EICAR harmless-threat generated report fixture_policy") $false "no-EICAR harmless-threat generated report fixture_policy.standard_eicar_string_written"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "defender_exclusion_required" "no-EICAR harmless-threat generated report fixture_policy") $false "no-EICAR harmless-threat generated report fixture_policy.defender_exclusion_required"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "machine_wide_changes" "no-EICAR harmless-threat generated report fixture_policy") $false "no-EICAR harmless-threat generated report fixture_policy.machine_wide_changes"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "network_access_required" "no-EICAR harmless-threat generated report fixture_policy") $false "no-EICAR harmless-threat generated report fixture_policy.network_access_required"
  $fixtureDescription = Assert-JsonString (Get-RequiredProperty $fixturePolicy "fixture_description" "no-EICAR harmless-threat generated report fixture_policy") "no-EICAR harmless-threat generated report fixture_policy.fixture_description"
  if ($fixtureDescription.IndexOf("Harmless exact-hash", [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
      $fixtureDescription.IndexOf("no standard EICAR content", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "no-EICAR harmless-threat generated report fixture_description must preserve harmless exact-hash and no-standard-EICAR wording."
  }

  Assert-JsonStringArrayEquals (Get-RequiredProperty $report "verified_flow" "no-EICAR harmless-threat generated report") @(
    "detect-only scan reports threatsFound without quarantine",
    "confirmed-only mode quarantines the harmless exact-hash fixture",
    "quarantine payload uses a safe .avoraxq extension",
    "list_quarantine returns the quarantined record",
    "restore_quarantine_item restores the original fixture bytes"
  ) "no-EICAR harmless-threat generated report verified_flow"

  Assert-JsonStringArrayEquals (Get-RequiredProperty $report "limits" "no-EICAR harmless-threat generated report") @(
    "release local-core binary proof only",
    "no installed UI click-through evidence",
    "no installed service or driver evidence",
    "no pre-execution blocking claim"
  ) "no-EICAR harmless-threat generated report limits"

  $errorValue = Get-RequiredProperty $report "error" "no-EICAR harmless-threat generated report"
  if ($null -ne $errorValue -and -not [string]::IsNullOrWhiteSpace([string]$errorValue)) {
    throw "passed no-EICAR harmless-threat generated report must not contain an error message."
  }
}

function Read-InstalledCoreLifecycleReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "installed core lifecycle generated report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "installed core lifecycle generated report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "installed core lifecycle generated report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "installed core lifecycle generated report must be a single JSON object."
  }
  Assert-JsonObject $report "installed core lifecycle generated report"
  $report
}

function Assert-InstalledCoreLifecycleReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "installed core lifecycle generated report path is required."
  }
  [void](Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($Path)) $RepositoryRoot "installed core lifecycle generated report")
  $report = Read-InstalledCoreLifecycleReport $Path
  Assert-JsonObjectPropertiesExactly $report @(
    "schema_version",
    "status",
    "tool",
    "started_at_utc",
    "completed_at_utc",
    "elapsed_seconds",
    "local_core_path",
    "local_core_sha256",
    "canonical_binary_name_verified",
    "evidence_root",
    "wrappers",
    "fixture_policy",
    "operations",
    "cleanup",
    "safety",
    "limits",
    "error"
  ) "installed core lifecycle generated report"

  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $report "schema_version" "installed core lifecycle generated report") 1 "installed core lifecycle generated report schema_version")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $report "status" "installed core lifecycle generated report") "passed" "installed core lifecycle generated report status")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $report "tool" "installed core lifecycle generated report") "avorax-installed-core-lifecycle-probe" "installed core lifecycle generated report tool")
  $startedAt = Assert-JsonTimestamp (Get-RequiredProperty $report "started_at_utc" "installed core lifecycle generated report") "installed core lifecycle generated report started_at_utc"
  $completedAt = Assert-JsonTimestamp (Get-RequiredProperty $report "completed_at_utc" "installed core lifecycle generated report") "installed core lifecycle generated report completed_at_utc"
  if ($completedAt -lt $startedAt) {
    throw "installed core lifecycle generated report completed_at_utc is before started_at_utc."
  }
  [void](Assert-JsonNumber (Get-RequiredProperty $report "elapsed_seconds" "installed core lifecycle generated report") "installed core lifecycle generated report elapsed_seconds")

  $localCorePath = Assert-JsonString (Get-RequiredProperty $report "local_core_path" "installed core lifecycle generated report") "installed core lifecycle generated report local_core_path"
  $localCoreFull = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($localCorePath)) $RepositoryRoot "installed core lifecycle generated report local_core_path"
  Get-AvoraxGateFile $localCoreFull "installed core lifecycle generated report local_core_path" | Out-Null
  if ([System.IO.Path]::GetFileName($localCoreFull) -ine "zentor_local_core.exe") {
    throw "installed core lifecycle generated report must identify zentor_local_core.exe."
  }
  $reportedHash = Assert-JsonString (Get-RequiredProperty $report "local_core_sha256" "installed core lifecycle generated report") "installed core lifecycle generated report local_core_sha256"
  if ($reportedHash -cnotmatch '^[a-f0-9]{64}$') {
    throw "installed core lifecycle generated report local_core_sha256 must be lowercase SHA-256 hex."
  }
  $actualHash = (Get-FileHash -LiteralPath $localCoreFull -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($reportedHash -cne $actualHash) {
    throw "installed core lifecycle generated report local_core_sha256 does not match the verified executable."
  }
  Assert-JsonBooleanEquals (Get-RequiredProperty $report "canonical_binary_name_verified" "installed core lifecycle generated report") $true "installed core lifecycle generated report canonical_binary_name_verified"
  $evidenceRoot = Assert-JsonString (Get-RequiredProperty $report "evidence_root" "installed core lifecycle generated report") "installed core lifecycle generated report evidence_root"
  $resolvedEvidenceRoot = (Resolve-Path -LiteralPath $evidenceRoot).Path
  if (-not $resolvedEvidenceRoot.Equals($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "installed core lifecycle generated report evidence_root does not match RepoRoot: $evidenceRoot"
  }
  Assert-JsonStringArrayEquals (Get-RequiredProperty $report "wrappers" "installed core lifecycle generated report") @(
    "avorax-local-scan.ps1",
    "avorax-quarantine.ps1"
  ) "installed core lifecycle generated report wrappers"

  $fixturePolicy = Get-RequiredProperty $report "fixture_policy" "installed core lifecycle generated report"
  Assert-JsonObjectPropertiesExactly $fixturePolicy @(
    "live_malware_used",
    "standard_eicar_file_created",
    "standard_eicar_string_written",
    "harmless_exact_hash_fixture_only",
    "network_access_required",
    "description"
  ) "installed core lifecycle generated report fixture_policy"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "live_malware_used" "installed core lifecycle generated report fixture_policy") $false "installed core lifecycle generated report fixture_policy.live_malware_used"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "standard_eicar_file_created" "installed core lifecycle generated report fixture_policy") $false "installed core lifecycle generated report fixture_policy.standard_eicar_file_created"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "standard_eicar_string_written" "installed core lifecycle generated report fixture_policy") $false "installed core lifecycle generated report fixture_policy.standard_eicar_string_written"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "harmless_exact_hash_fixture_only" "installed core lifecycle generated report fixture_policy") $true "installed core lifecycle generated report fixture_policy.harmless_exact_hash_fixture_only"
  Assert-JsonBooleanEquals (Get-RequiredProperty $fixturePolicy "network_access_required" "installed core lifecycle generated report fixture_policy") $false "installed core lifecycle generated report fixture_policy.network_access_required"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $fixturePolicy "description" "installed core lifecycle generated report fixture_policy") "Harmless ASCII exact-hash fixtures only; no standard EICAR content." "installed core lifecycle generated report fixture_policy.description")

  $operations = Get-RequiredProperty $report "operations" "installed core lifecycle generated report"
  Assert-JsonObjectPropertiesExactly $operations @("scan_restore", "list", "restore", "scan_delete", "delete") "installed core lifecycle generated report operations"

  $scanRestore = Get-RequiredProperty $operations "scan_restore" "installed core lifecycle generated report operations"
  Assert-JsonObjectPropertiesExactly $scanRestore @(
    "wrapper", "status", "action_mode", "files_scanned", "threats_found", "quarantined_files",
    "quarantine_id", "source_removed", "payload_extension", "payload_created"
  ) "installed core lifecycle generated report operations.scan_restore"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $scanRestore "wrapper" "installed core lifecycle generated report operations.scan_restore") "avorax-local-scan" "installed core lifecycle generated report operations.scan_restore.wrapper")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $scanRestore "status" "installed core lifecycle generated report operations.scan_restore") "threatsFound" "installed core lifecycle generated report operations.scan_restore.status")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $scanRestore "action_mode" "installed core lifecycle generated report operations.scan_restore") "autoQuarantineConfirmedOnly" "installed core lifecycle generated report operations.scan_restore.action_mode")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $scanRestore "files_scanned" "installed core lifecycle generated report operations.scan_restore") 1 "installed core lifecycle generated report operations.scan_restore.files_scanned")
  $restoreThreatCount = Assert-JsonInteger (Get-RequiredProperty $scanRestore "threats_found" "installed core lifecycle generated report operations.scan_restore") "installed core lifecycle generated report operations.scan_restore.threats_found"
  $restoreQuarantineCount = Assert-JsonInteger (Get-RequiredProperty $scanRestore "quarantined_files" "installed core lifecycle generated report operations.scan_restore") "installed core lifecycle generated report operations.scan_restore.quarantined_files"
  if ($restoreThreatCount -lt 1 -or $restoreQuarantineCount -lt 1) {
    throw "installed core lifecycle generated report restore scan must record at least one threat and quarantine."
  }
  $restoreId = Assert-JsonString (Get-RequiredProperty $scanRestore "quarantine_id" "installed core lifecycle generated report operations.scan_restore") "installed core lifecycle generated report operations.scan_restore.quarantine_id"
  Assert-JsonBooleanEquals (Get-RequiredProperty $scanRestore "source_removed" "installed core lifecycle generated report operations.scan_restore") $true "installed core lifecycle generated report operations.scan_restore.source_removed"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $scanRestore "payload_extension" "installed core lifecycle generated report operations.scan_restore") ".avoraxq" "installed core lifecycle generated report operations.scan_restore.payload_extension")
  Assert-JsonBooleanEquals (Get-RequiredProperty $scanRestore "payload_created" "installed core lifecycle generated report operations.scan_restore") $true "installed core lifecycle generated report operations.scan_restore.payload_created"

  $list = Get-RequiredProperty $operations "list" "installed core lifecycle generated report operations"
  Assert-JsonObjectPropertiesExactly $list @("wrapper", "action", "records_count", "quarantine_id", "record_found", "record_status", "payload_verified") "installed core lifecycle generated report operations.list"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $list "wrapper" "installed core lifecycle generated report operations.list") "avorax-quarantine" "installed core lifecycle generated report operations.list.wrapper")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $list "action" "installed core lifecycle generated report operations.list") "List" "installed core lifecycle generated report operations.list.action")
  $recordsCount = Assert-JsonInteger (Get-RequiredProperty $list "records_count" "installed core lifecycle generated report operations.list") "installed core lifecycle generated report operations.list.records_count"
  if ($recordsCount -lt 1) { throw "installed core lifecycle generated report list must record at least one item." }
  [void](Assert-JsonStringEquals (Get-RequiredProperty $list "quarantine_id" "installed core lifecycle generated report operations.list") $restoreId "installed core lifecycle generated report operations.list.quarantine_id")
  Assert-JsonBooleanEquals (Get-RequiredProperty $list "record_found" "installed core lifecycle generated report operations.list") $true "installed core lifecycle generated report operations.list.record_found"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $list "record_status" "installed core lifecycle generated report operations.list") "quarantined" "installed core lifecycle generated report operations.list.record_status")
  Assert-JsonBooleanEquals (Get-RequiredProperty $list "payload_verified" "installed core lifecycle generated report operations.list") $true "installed core lifecycle generated report operations.list.payload_verified"

  $restore = Get-RequiredProperty $operations "restore" "installed core lifecycle generated report operations"
  Assert-JsonObjectPropertiesExactly $restore @(
    "wrapper", "action", "quarantine_id", "explicit_confirmation", "record_status", "action_taken",
    "source_restored", "fixture_sha256_verified", "payload_removed"
  ) "installed core lifecycle generated report operations.restore"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $restore "wrapper" "installed core lifecycle generated report operations.restore") "avorax-quarantine" "installed core lifecycle generated report operations.restore.wrapper")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $restore "action" "installed core lifecycle generated report operations.restore") "Restore" "installed core lifecycle generated report operations.restore.action")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $restore "quarantine_id" "installed core lifecycle generated report operations.restore") $restoreId "installed core lifecycle generated report operations.restore.quarantine_id")
  Assert-JsonBooleanEquals (Get-RequiredProperty $restore "explicit_confirmation" "installed core lifecycle generated report operations.restore") $true "installed core lifecycle generated report operations.restore.explicit_confirmation"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $restore "record_status" "installed core lifecycle generated report operations.restore") "restored" "installed core lifecycle generated report operations.restore.record_status")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $restore "action_taken" "installed core lifecycle generated report operations.restore") "restored" "installed core lifecycle generated report operations.restore.action_taken")
  Assert-JsonBooleanEquals (Get-RequiredProperty $restore "source_restored" "installed core lifecycle generated report operations.restore") $true "installed core lifecycle generated report operations.restore.source_restored"
  Assert-JsonBooleanEquals (Get-RequiredProperty $restore "fixture_sha256_verified" "installed core lifecycle generated report operations.restore") $true "installed core lifecycle generated report operations.restore.fixture_sha256_verified"
  Assert-JsonBooleanEquals (Get-RequiredProperty $restore "payload_removed" "installed core lifecycle generated report operations.restore") $true "installed core lifecycle generated report operations.restore.payload_removed"

  $scanDelete = Get-RequiredProperty $operations "scan_delete" "installed core lifecycle generated report operations"
  Assert-JsonObjectPropertiesExactly $scanDelete @(
    "wrapper", "status", "action_mode", "files_scanned", "threats_found", "quarantined_files",
    "quarantine_id", "source_removed", "payload_extension", "payload_created"
  ) "installed core lifecycle generated report operations.scan_delete"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $scanDelete "wrapper" "installed core lifecycle generated report operations.scan_delete") "avorax-local-scan" "installed core lifecycle generated report operations.scan_delete.wrapper")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $scanDelete "status" "installed core lifecycle generated report operations.scan_delete") "threatsFound" "installed core lifecycle generated report operations.scan_delete.status")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $scanDelete "action_mode" "installed core lifecycle generated report operations.scan_delete") "autoQuarantineConfirmedOnly" "installed core lifecycle generated report operations.scan_delete.action_mode")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $scanDelete "files_scanned" "installed core lifecycle generated report operations.scan_delete") 1 "installed core lifecycle generated report operations.scan_delete.files_scanned")
  $deleteThreatCount = Assert-JsonInteger (Get-RequiredProperty $scanDelete "threats_found" "installed core lifecycle generated report operations.scan_delete") "installed core lifecycle generated report operations.scan_delete.threats_found"
  $deleteQuarantineCount = Assert-JsonInteger (Get-RequiredProperty $scanDelete "quarantined_files" "installed core lifecycle generated report operations.scan_delete") "installed core lifecycle generated report operations.scan_delete.quarantined_files"
  if ($deleteThreatCount -lt 1 -or $deleteQuarantineCount -lt 1) {
    throw "installed core lifecycle generated report delete scan must record at least one threat and quarantine."
  }
  $deleteId = Assert-JsonString (Get-RequiredProperty $scanDelete "quarantine_id" "installed core lifecycle generated report operations.scan_delete") "installed core lifecycle generated report operations.scan_delete.quarantine_id"
  if ($deleteId -eq $restoreId) {
    throw "installed core lifecycle generated report must use distinct quarantine ids."
  }
  Assert-JsonBooleanEquals (Get-RequiredProperty $scanDelete "source_removed" "installed core lifecycle generated report operations.scan_delete") $true "installed core lifecycle generated report operations.scan_delete.source_removed"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $scanDelete "payload_extension" "installed core lifecycle generated report operations.scan_delete") ".avoraxq" "installed core lifecycle generated report operations.scan_delete.payload_extension")
  Assert-JsonBooleanEquals (Get-RequiredProperty $scanDelete "payload_created" "installed core lifecycle generated report operations.scan_delete") $true "installed core lifecycle generated report operations.scan_delete.payload_created"

  $delete = Get-RequiredProperty $operations "delete" "installed core lifecycle generated report operations"
  Assert-JsonObjectPropertiesExactly $delete @(
    "wrapper", "action", "quarantine_id", "explicit_confirmation", "record_status", "action_taken",
    "source_absent", "payload_removed", "secure_erase_claimed"
  ) "installed core lifecycle generated report operations.delete"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $delete "wrapper" "installed core lifecycle generated report operations.delete") "avorax-quarantine" "installed core lifecycle generated report operations.delete.wrapper")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $delete "action" "installed core lifecycle generated report operations.delete") "Delete" "installed core lifecycle generated report operations.delete.action")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $delete "quarantine_id" "installed core lifecycle generated report operations.delete") $deleteId "installed core lifecycle generated report operations.delete.quarantine_id")
  Assert-JsonBooleanEquals (Get-RequiredProperty $delete "explicit_confirmation" "installed core lifecycle generated report operations.delete") $true "installed core lifecycle generated report operations.delete.explicit_confirmation"
  [void](Assert-JsonStringEquals (Get-RequiredProperty $delete "record_status" "installed core lifecycle generated report operations.delete") "deleted" "installed core lifecycle generated report operations.delete.record_status")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $delete "action_taken" "installed core lifecycle generated report operations.delete") "deleted" "installed core lifecycle generated report operations.delete.action_taken")
  Assert-JsonBooleanEquals (Get-RequiredProperty $delete "source_absent" "installed core lifecycle generated report operations.delete") $true "installed core lifecycle generated report operations.delete.source_absent"
  Assert-JsonBooleanEquals (Get-RequiredProperty $delete "payload_removed" "installed core lifecycle generated report operations.delete") $true "installed core lifecycle generated report operations.delete.payload_removed"
  Assert-JsonBooleanEquals (Get-RequiredProperty $delete "secure_erase_claimed" "installed core lifecycle generated report operations.delete") $false "installed core lifecycle generated report operations.delete.secure_erase_claimed"

  $cleanup = Get-RequiredProperty $report "cleanup" "installed core lifecycle generated report"
  Assert-JsonObjectPropertiesExactly $cleanup @("isolated_temp_removed", "isolated_temp_path_retained") "installed core lifecycle generated report cleanup"
  Assert-JsonBooleanEquals (Get-RequiredProperty $cleanup "isolated_temp_removed" "installed core lifecycle generated report cleanup") $true "installed core lifecycle generated report cleanup.isolated_temp_removed"
  Assert-JsonBooleanEquals (Get-RequiredProperty $cleanup "isolated_temp_path_retained" "installed core lifecycle generated report cleanup") $false "installed core lifecycle generated report cleanup.isolated_temp_path_retained"

  $safety = Get-RequiredProperty $report "safety" "installed core lifecycle generated report"
  Assert-JsonObjectPropertiesExactly $safety @(
    "defender_exclusion_required", "machine_wide_changes", "service_installation_attempted",
    "driver_installation_attempted", "installed_layout_claimed", "installed_service_mediation_claimed",
    "pre_execution_blocking_claimed", "secure_erase_claimed"
  ) "installed core lifecycle generated report safety"
  foreach ($field in @(
    "defender_exclusion_required", "machine_wide_changes", "service_installation_attempted",
    "driver_installation_attempted", "installed_layout_claimed", "installed_service_mediation_claimed",
    "pre_execution_blocking_claimed", "secure_erase_claimed"
  )) {
    Assert-JsonBooleanEquals (Get-RequiredProperty $safety $field "installed core lifecycle generated report safety") $false "installed core lifecycle generated report safety.$field"
  }
  Assert-JsonStringArrayEquals (Get-RequiredProperty $report "limits" "installed core lifecycle generated report") @(
    "canonical local-core executable and wrapper stdio lifecycle only",
    "no installed Windows service IPC claim",
    "no installed UI click-through evidence",
    "no pre-execution blocking claim"
  ) "installed core lifecycle generated report limits"
  $errorValue = Get-RequiredProperty $report "error" "installed core lifecycle generated report"
  if ($null -ne $errorValue -and -not [string]::IsNullOrWhiteSpace([string]$errorValue)) {
    throw "passed installed core lifecycle generated report must not contain an error message."
  }
}

function Read-ReleasePrereqHostReport {
  param([string]$Path)

  $json = Read-AvoraxGateTextFileBounded $Path $maxReportBytes "release prerequisite host generated report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "release prerequisite host generated report is empty: $Path"
  }
  try {
    $report = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "release prerequisite host generated report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array]) {
    throw "release prerequisite host generated report must be a single JSON object."
  }
  Assert-JsonObject $report "release prerequisite host generated report"
  $report
}

function Get-ReleasePrereqCheckByName {
  param(
    [object[]]$Checks,
    [string]$Name
  )

  foreach ($check in $Checks) {
    if ($check.name -eq $Name) { return $check }
  }
  throw "release prerequisite host generated report is missing required check: $Name"
}

function Assert-ReleasePrereqCheckStatus {
  param(
    [object[]]$Checks,
    [string]$Name,
    [string[]]$AllowedStatuses
  )

  $check = Get-ReleasePrereqCheckByName $Checks $Name
  Assert-JsonObject $check "release prerequisite host generated report check $Name"
  [void](Assert-JsonString (Get-RequiredProperty $check "detail" "release prerequisite host generated report check $Name") "release prerequisite host generated report check $Name detail")
  $status = Assert-JsonString (Get-RequiredProperty $check "status" "release prerequisite host generated report check $Name") "release prerequisite host generated report check $Name status"
  if ($AllowedStatuses -notcontains $status) {
    throw "release prerequisite host generated report check $Name has unexpected status '$status'."
  }
  $check
}

function Assert-ReleasePrereqHostReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "release prerequisite host generated report path is required."
  }
  [void](Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($Path)) $RepositoryRoot "release prerequisite host generated report")
  $report = Read-ReleasePrereqHostReport $Path

  Assert-JsonObjectPropertiesExactly $report @(
    "ok",
    "timestamp_utc",
    "repo_root",
    "mode",
    "tool_paths",
    "checks",
    "errors",
    "warnings"
  ) "release prerequisite host generated report"

  $ok = Assert-JsonBoolean (Get-RequiredProperty $report "ok" "release prerequisite host generated report") "release prerequisite host generated report ok"
  [void](Assert-JsonTimestamp (Get-RequiredProperty $report "timestamp_utc" "release prerequisite host generated report") "release prerequisite host generated report timestamp_utc")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $report "mode" "release prerequisite host generated report") "host_only" "release prerequisite host generated report mode")

  $repo = Assert-JsonString (Get-RequiredProperty $report "repo_root" "release prerequisite host generated report") "release prerequisite host generated report repo_root"
  $reportRepo = (Resolve-Path -LiteralPath $repo).Path
  if (-not $reportRepo.Equals($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "release prerequisite host generated report repo_root does not match RepoRoot: $repo"
  }

  $toolPaths = Get-RequiredProperty $report "tool_paths" "release prerequisite host generated report"
  Assert-JsonObjectPropertiesExactly $toolPaths @("dotnet", "cargo", "flutter") "release prerequisite host generated report tool_paths"
  $dotnetPathValue = Get-RequiredProperty $toolPaths "dotnet" "release prerequisite host generated report tool_paths"
  if ($dotnetPathValue -isnot [string]) {
    throw "release prerequisite host generated report tool_paths.dotnet must be a string."
  }
  $dotnetPath = [string]$dotnetPathValue
  $cargoPath = Assert-JsonString (Get-RequiredProperty $toolPaths "cargo" "release prerequisite host generated report tool_paths") "release prerequisite host generated report tool_paths.cargo"
  $flutterPath = Assert-JsonString (Get-RequiredProperty $toolPaths "flutter" "release prerequisite host generated report tool_paths") "release prerequisite host generated report tool_paths.flutter"
  Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($cargoPath)) "release prerequisite host generated report cargo path" | Out-Null
  Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($flutterPath)) "release prerequisite host generated report flutter path" | Out-Null
  if (-not [string]::IsNullOrWhiteSpace($dotnetPath)) {
    Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($dotnetPath)) "release prerequisite host generated report dotnet path" | Out-Null
  }

  $checks = @(Assert-JsonArray (Get-RequiredProperty $report "checks" "release prerequisite host generated report") "release prerequisite host generated report checks")
  if ($checks.Count -lt 15) {
    throw "release prerequisite host generated report must include detailed host checks, found $($checks.Count)."
  }
  [void](Assert-ReleasePrereqCheckStatus $checks "repository root" @("pass"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Cargo executable" @("pass"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Flutter executable" @("pass"))
  [void](Assert-ReleasePrereqCheckStatus $checks ".NET SDK dotnet executable" @("pass", "fail"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Windows symlink support" @("pass", "fail"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Flutter doctor command" @("pass", "fail"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Visual Studio Desktop C++ components" @("pass", "fail"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Android SDK" @("pass", "skipped"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Flutter Windows release Avorax.exe" @("skipped"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Windows installer stage" @("skipped"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Rust release service target\release\zentor_local_core.exe" @("skipped"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Rust release service target\release\zentor_guard_service.exe" @("skipped"))
  [void](Assert-ReleasePrereqCheckStatus $checks "Rust release service target\release\avorax_update_service.exe" @("skipped"))

  $errorsValue = Get-RequiredProperty $report "errors" "release prerequisite host generated report"
  $errors = if ($null -eq $errorsValue) {
    @()
  } else {
    @(Assert-JsonArray $errorsValue "release prerequisite host generated report errors")
  }
  $warningsValue = Get-RequiredProperty $report "warnings" "release prerequisite host generated report"
  if ($null -ne $warningsValue) {
    [void](Assert-JsonArray $warningsValue "release prerequisite host generated report warnings")
  }
  if ($ok) {
    if ($errors.Count -ne 0) {
      throw "release prerequisite host generated report ok=true must not list errors."
    }
    $failed = @($checks | Where-Object { $_.status -eq "fail" })
    if ($failed.Count -ne 0) {
      throw "release prerequisite host generated report ok=true must not contain failing checks."
    }
  } else {
    if ($errors.Count -eq 0) {
      throw "release prerequisite host generated report ok=false must list blockers."
    }
    $joinedErrors = ($errors | ForEach-Object { Assert-JsonString $_ "release prerequisite host generated report error" }) -join "`n"
    if ($joinedErrors -notmatch "\.NET SDK" -and
        $joinedErrors -notmatch "Windows symlink support" -and
        $joinedErrors -notmatch "Visual Studio Desktop C\+\+") {
      throw "release prerequisite host generated report blockers must name an actionable release-host prerequisite."
    }
  }
}

function Assert-PerformanceGateReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "performance gate generated report path is required."
  }
  [void](Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($Path)) $RepositoryRoot "performance gate generated report")
  $report = Read-PerformanceGateReport $Path

  Assert-JsonObjectPropertiesExactly $report @(
    "known_good_cache_target_ms",
    "known_bad_cache_target_ms",
    "unknown_lockdown_target_ms",
    "measured_by",
    "status"
  ) "performance gate generated report"

  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $report "known_good_cache_target_ms" "performance gate generated report") 50 "performance gate generated report known_good_cache_target_ms")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $report "known_bad_cache_target_ms" "performance gate generated report") 100 "performance gate generated report known_bad_cache_target_ms")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $report "unknown_lockdown_target_ms" "performance gate generated report") 750 "performance gate generated report unknown_lockdown_target_ms")
  $measuredBy = Assert-JsonString (Get-RequiredProperty $report "measured_by" "performance gate generated report") "performance gate generated report measured_by"
  if ($measuredBy.IndexOf("unit decision path", [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
      $measuredBy.IndexOf("WDK VM should run driver latency tests", [StringComparison]::Ordinal) -lt 0) {
    throw "performance gate generated report measured_by must preserve the unit-path and WDK VM latency-test limitation."
  }
  [void](Assert-JsonStringEquals (Get-RequiredProperty $report "status" "performance gate generated report") "pass" "performance gate generated report status")
}

function Assert-PerformanceBenchmarkReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "performance benchmark generated report path is required."
  }
  [void](Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($Path)) $RepositoryRoot "performance benchmark generated report")
  $benchmark = Read-PerformanceBenchmarkReport $Path

  Assert-JsonObjectPropertiesExactly $benchmark @(
    "schema_version",
    "generated_at_unix_ms",
    "repo_root",
    "host",
    "safe_fixture_policy",
    "metrics"
  ) "performance benchmark generated report"

  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $benchmark "schema_version" "performance benchmark generated report") 1 "performance benchmark generated report schema_version")
  $generatedAt = Assert-JsonInteger (Get-RequiredProperty $benchmark "generated_at_unix_ms" "performance benchmark generated report") "performance benchmark generated report generated_at_unix_ms"
  if ($generatedAt -le 0) {
    throw "performance benchmark generated report generated_at_unix_ms must be greater than zero."
  }

  $repoRoot = Assert-JsonString (Get-RequiredProperty $benchmark "repo_root" "performance benchmark generated report") "performance benchmark generated report repo_root"
  $repoRootFull = (Resolve-Path -LiteralPath $repoRoot).Path
  if (-not $repoRootFull.Equals($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "performance benchmark generated report repo_root does not match RepoRoot: $repoRoot"
  }

  $hostInfo = Get-RequiredProperty $benchmark "host" "performance benchmark generated report"
  Assert-JsonObjectPropertiesExactly $hostInfo @("platform", "python") "performance benchmark generated report host"
  [void](Assert-JsonString (Get-RequiredProperty $hostInfo "platform" "performance benchmark generated report host") "performance benchmark generated report host platform")
  [void](Assert-JsonString (Get-RequiredProperty $hostInfo "python" "performance benchmark generated report host") "performance benchmark generated report host python")
  [void](Assert-JsonStringEquals (Get-RequiredProperty $benchmark "safe_fixture_policy" "performance benchmark generated report") "synthetic harmless files only; no malware samples; no destructive update apply" "performance benchmark generated report safe_fixture_policy")

  $metrics = @(Assert-JsonArray (Get-RequiredProperty $benchmark "metrics" "performance benchmark generated report") "performance benchmark generated report metrics")
  if ($metrics.Count -ne 4) {
    throw "performance benchmark generated report metrics must contain exactly 4 entries, found $($metrics.Count)."
  }

  $traversal = Get-RequiredMetricByName $metrics "synthetic_traversal_and_hashing"
  $traversalDescription = "performance benchmark generated report metric synthetic_traversal_and_hashing"
  Assert-JsonObjectPropertiesExactly $traversal @(
    "name",
    "status",
    "elapsed_ms",
    "error",
    "measured_by",
    "file_count",
    "file_size_bytes",
    "total_bytes",
    "traversal_ms",
    "hashing_ms",
    "hash_per_file_p50_ms",
    "hash_per_file_p95_ms",
    "combined_digest_prefix"
  ) $traversalDescription
  Assert-PerformanceMetricBase $traversal "synthetic_traversal_and_hashing" "Python synthetic harmless corpus traversal and SHA-256 streaming" $traversalDescription
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $traversal "file_count" $traversalDescription) 64 "$traversalDescription file_count")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $traversal "file_size_bytes" $traversalDescription) 4096 "$traversalDescription file_size_bytes")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $traversal "total_bytes" $traversalDescription) 262144 "$traversalDescription total_bytes")
  [void](Assert-JsonNumber (Get-RequiredProperty $traversal "traversal_ms" $traversalDescription) "$traversalDescription traversal_ms")
  [void](Assert-JsonNumber (Get-RequiredProperty $traversal "hashing_ms" $traversalDescription) "$traversalDescription hashing_ms")
  [void](Assert-JsonNumber (Get-RequiredProperty $traversal "hash_per_file_p50_ms" $traversalDescription) "$traversalDescription hash_per_file_p50_ms")
  [void](Assert-JsonNumber (Get-RequiredProperty $traversal "hash_per_file_p95_ms" $traversalDescription) "$traversalDescription hash_per_file_p95_ms")
  $digestPrefix = Assert-JsonString (Get-RequiredProperty $traversal "combined_digest_prefix" $traversalDescription) "$traversalDescription combined_digest_prefix"
  if ($digestPrefix -notmatch '^[0-9a-f]{16}$') {
    throw "$traversalDescription combined_digest_prefix must be a 16-character lowercase hex prefix."
  }

  Assert-PerformanceCommandMetric (Get-RequiredMetricByName $metrics "native_signature_matching_test_wall_clock") "native_signature_matching_test_wall_clock" "core/zentor_native_engine/Cargo.toml" "normal_exe_in_downloads_is_not_malware"
  Assert-PerformanceCommandMetric (Get-RequiredMetricByName $metrics "guard_pre_execution_known_good_wall_clock") "guard_pre_execution_known_good_wall_clock" "core/zentor_guard_service/Cargo.toml" "driver_request_known_good_allows_in_lockdown"

  $updateCopy = Get-RequiredMetricByName $metrics "synthetic_update_copy_simulation"
  $updateDescription = "performance benchmark generated report metric synthetic_update_copy_simulation"
  Assert-JsonObjectPropertiesExactly $updateCopy @(
    "name",
    "status",
    "elapsed_ms",
    "error",
    "measured_by",
    "file_count",
    "file_size_bytes",
    "total_bytes",
    "copy_ms",
    "copy_per_file_p50_ms",
    "copy_per_file_p95_ms"
  ) $updateDescription
  Assert-PerformanceMetricBase $updateCopy "synthetic_update_copy_simulation" "non-elevated synthetic copy simulation; not real Avorax Update Service apply" $updateDescription
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $updateCopy "file_count" $updateDescription) 64 "$updateDescription file_count")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $updateCopy "file_size_bytes" $updateDescription) 4096 "$updateDescription file_size_bytes")
  [void](Assert-JsonIntegerEquals (Get-RequiredProperty $updateCopy "total_bytes" $updateDescription) 262144 "$updateDescription total_bytes")
  [void](Assert-JsonNumber (Get-RequiredProperty $updateCopy "copy_ms" $updateDescription) "$updateDescription copy_ms")
  [void](Assert-JsonNumber (Get-RequiredProperty $updateCopy "copy_per_file_p50_ms" $updateDescription) "$updateDescription copy_per_file_p50_ms")
  [void](Assert-JsonNumber (Get-RequiredProperty $updateCopy "copy_per_file_p95_ms" $updateDescription) "$updateDescription copy_per_file_p95_ms")
}

function Assert-ProtectionSelfTestReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "protection self-test generated report path is required."
  }
  [void](Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($Path)) $RepositoryRoot "protection self-test generated report")
  $report = Read-ProtectionSelfTestReport $Path

  Assert-JsonObjectPropertiesExactly $report @(
    "fixture",
    "fixture_scope",
    "overall_result",
    "driver",
    "tests"
  ) "protection self-test generated report"

  $fixture = Assert-JsonString (Get-RequiredProperty $report "fixture" "protection self-test generated report") "protection self-test generated report fixture"
  if ($fixture -ne "small-threat-mvp-synthetic-non-driver") {
    throw "protection self-test generated report fixture mismatch: $fixture"
  }
  $fixtureScope = Assert-JsonString (Get-RequiredProperty $report "fixture_scope" "protection self-test generated report") "protection self-test generated report fixture_scope"
  if ($fixtureScope.IndexOf("no signed-driver or pre-execution claim", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "protection self-test generated report fixture_scope must disclaim signed-driver/pre-execution coverage."
  }
  $overallResult = Assert-JsonString (Get-RequiredProperty $report "overall_result" "protection self-test generated report") "protection self-test generated report overall_result"
  if ($overallResult -ne "pass") {
    throw "protection self-test generated report overall_result must be 'pass': $overallResult"
  }

  $driver = Get-RequiredProperty $report "driver" "protection self-test generated report"
  Assert-JsonObjectPropertiesExactly $driver @(
    "communication_port_ok",
    "installed",
    "running",
    "pre_execution_blocking_available"
  ) "protection self-test generated report driver"
  Assert-JsonBooleanEquals (Get-RequiredProperty $driver "communication_port_ok" "protection self-test generated report driver") $false "protection self-test generated report driver.communication_port_ok"
  Assert-JsonBooleanEquals (Get-RequiredProperty $driver "installed" "protection self-test generated report driver") $false "protection self-test generated report driver.installed"
  Assert-JsonBooleanEquals (Get-RequiredProperty $driver "running" "protection self-test generated report driver") $false "protection self-test generated report driver.running"
  Assert-JsonBooleanEquals (Get-RequiredProperty $driver "pre_execution_blocking_available" "protection self-test generated report driver") $false "protection self-test generated report driver.pre_execution_blocking_available"

  $tests = Get-RequiredProperty $report "tests" "protection self-test generated report"
  Assert-JsonObjectPropertiesExactly $tests @(
    "eicar_scan_blocked",
    "unknown_unsigned_lockdown_policy_blocked",
    "unknown_unsigned_allowed_after_hash_approval",
    "known_good_executable_allowed",
    "normal_exe_blocked_only_as_unknown",
    "unknown_unsigned_lockdown_blocked_before_launch"
  ) "protection self-test generated report tests"
  Assert-JsonBooleanEquals (Get-RequiredProperty $tests "eicar_scan_blocked" "protection self-test generated report tests") $true "protection self-test generated report tests.eicar_scan_blocked"
  Assert-JsonBooleanEquals (Get-RequiredProperty $tests "unknown_unsigned_lockdown_policy_blocked" "protection self-test generated report tests") $true "protection self-test generated report tests.unknown_unsigned_lockdown_policy_blocked"
  Assert-JsonBooleanEquals (Get-RequiredProperty $tests "unknown_unsigned_allowed_after_hash_approval" "protection self-test generated report tests") $true "protection self-test generated report tests.unknown_unsigned_allowed_after_hash_approval"
  Assert-JsonBooleanEquals (Get-RequiredProperty $tests "known_good_executable_allowed" "protection self-test generated report tests") $true "protection self-test generated report tests.known_good_executable_allowed"
  Assert-JsonBooleanEquals (Get-RequiredProperty $tests "normal_exe_blocked_only_as_unknown" "protection self-test generated report tests") $true "protection self-test generated report tests.normal_exe_blocked_only_as_unknown"
  Assert-JsonBooleanEquals (Get-RequiredProperty $tests "unknown_unsigned_lockdown_blocked_before_launch" "protection self-test generated report tests") $false "protection self-test generated report tests.unknown_unsigned_lockdown_blocked_before_launch"
}

function Assert-DependencyEvidenceReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "dependency evidence generated report path is required."
  }
  [void](Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($Path)) $RepositoryRoot "dependency evidence generated report")
  $dependency = Read-DependencyEvidenceReport $Path

  Assert-JsonObjectPropertiesExactly $dependency @(
    "generated_utc",
    "repo_root",
    "allow_known_blockers",
    "ok",
    "partial",
    "requirement_checks",
    "lockfile_checks",
    "gradle_wrapper",
    "lockfile_summaries",
    "license_inventory",
    "release_blockers"
  ) "dependency evidence generated report"

  [void](Assert-JsonTimestamp (Get-RequiredProperty $dependency "generated_utc" "dependency evidence generated report") "dependency evidence generated report generated_utc")
  $repoRoot = Assert-JsonString (Get-RequiredProperty $dependency "repo_root" "dependency evidence generated report") "dependency evidence generated report repo_root"
  $repoRootFull = (Resolve-Path -LiteralPath $repoRoot).Path
  if (-not $repoRootFull.Equals($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "dependency evidence generated report repo_root does not match RepoRoot: $repoRoot"
  }
  Assert-JsonBooleanEquals (Get-RequiredProperty $dependency "allow_known_blockers" "dependency evidence generated report") $false "dependency evidence generated report allow_known_blockers"
  Assert-JsonBooleanEquals (Get-RequiredProperty $dependency "ok" "dependency evidence generated report") $true "dependency evidence generated report ok"
  Assert-JsonBooleanEquals (Get-RequiredProperty $dependency "partial" "dependency evidence generated report") $false "dependency evidence generated report partial"
  Assert-JsonArrayEmpty (Get-RequiredProperty $dependency "release_blockers" "dependency evidence generated report") "dependency evidence generated report release_blockers"

  $requirementChecks = @(Assert-JsonArray (Get-RequiredProperty $dependency "requirement_checks" "dependency evidence generated report") "dependency evidence generated report requirement_checks")
  if ($requirementChecks.Count -ne 2) {
    throw "dependency evidence generated report requirement_checks must contain exactly 2 entries, found $($requirementChecks.Count)."
  }
  Assert-DependencyRequirementCheck $requirementChecks[0] "python_direct_requirements" "ml\requirements.txt" $expectedPythonDirectRequirements $RepositoryRoot
  Assert-DependencyRequirementCheck $requirementChecks[1] "python_verification_lock" "ml\requirements.lock.txt" $expectedPythonVerificationLock $RepositoryRoot

  $lockfileChecks = @(Assert-JsonArray (Get-RequiredProperty $dependency "lockfile_checks" "dependency evidence generated report") "dependency evidence generated report lockfile_checks")
  if ($lockfileChecks.Count -ne $expectedDependencyLockfiles.Count) {
    throw "dependency evidence generated report lockfile_checks must contain exactly $($expectedDependencyLockfiles.Count) entries, found $($lockfileChecks.Count)."
  }
  for ($i = 0; $i -lt $expectedDependencyLockfiles.Count; $i++) {
    Assert-DependencyLockfileCheck $lockfileChecks[$i] $expectedDependencyLockfiles[$i] $RepositoryRoot ($i + 1)
  }

  $gradleWrapper = Get-RequiredProperty $dependency "gradle_wrapper" "dependency evidence generated report"
  Assert-JsonObjectPropertiesExactly $gradleWrapper @(
    "name",
    "path",
    "url_pinned",
    "sha256_pinned",
    "expected_sha256"
  ) "dependency evidence generated report gradle_wrapper"
  $gradleName = Assert-JsonString (Get-RequiredProperty $gradleWrapper "name" "dependency evidence generated report gradle_wrapper") "dependency evidence generated report gradle_wrapper name"
  if ($gradleName -ne "android_gradle_wrapper") {
    throw "dependency evidence generated report gradle_wrapper name mismatch: $gradleName"
  }
  $gradlePath = Assert-JsonString (Get-RequiredProperty $gradleWrapper "path" "dependency evidence generated report gradle_wrapper") "dependency evidence generated report gradle_wrapper path"
  if ($gradlePath -ne "apps\zentor_client\android\gradle\wrapper\gradle-wrapper.properties") {
    throw "dependency evidence generated report gradle_wrapper path mismatch: $gradlePath"
  }
  Assert-JsonBooleanEquals (Get-RequiredProperty $gradleWrapper "url_pinned" "dependency evidence generated report gradle_wrapper") $true "dependency evidence generated report gradle_wrapper url_pinned"
  Assert-JsonBooleanEquals (Get-RequiredProperty $gradleWrapper "sha256_pinned" "dependency evidence generated report gradle_wrapper") $true "dependency evidence generated report gradle_wrapper sha256_pinned"
  $expectedSha = Assert-JsonString (Get-RequiredProperty $gradleWrapper "expected_sha256" "dependency evidence generated report gradle_wrapper") "dependency evidence generated report gradle_wrapper expected_sha256"
  if ($expectedSha -ne $expectedGradleWrapperSha256) {
    throw "dependency evidence generated report gradle_wrapper expected_sha256 mismatch: $expectedSha"
  }
  $gradleFullPath = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot $gradlePath))
  [void](Assert-SmallThreatMvpRepoChildPath $gradleFullPath $RepositoryRoot "dependency evidence generated report gradle_wrapper file")
  Get-AvoraxGateFile $gradleFullPath "dependency evidence generated report gradle_wrapper file" | Out-Null
  $gradleText = Read-AvoraxGateTextFileBounded $gradleFullPath $maxReportBytes "dependency evidence generated report gradle_wrapper file"
  if (-not $gradleText.Contains("distributionUrl=https\://services.gradle.org/distributions/gradle-9.1.0-all.zip")) {
    throw "dependency evidence generated report gradle_wrapper current file is missing the pinned Gradle URL."
  }
  if (-not $gradleText.Contains("distributionSha256Sum=$expectedGradleWrapperSha256")) {
    throw "dependency evidence generated report gradle_wrapper current file is missing the pinned Gradle SHA-256."
  }

  $summaries = @(Assert-JsonArray (Get-RequiredProperty $dependency "lockfile_summaries" "dependency evidence generated report") "dependency evidence generated report lockfile_summaries")
  if ($summaries.Count -ne $expectedDependencyLockfileSummaries.Count) {
    throw "dependency evidence generated report lockfile_summaries must contain exactly $($expectedDependencyLockfileSummaries.Count) entries, found $($summaries.Count)."
  }
  for ($i = 0; $i -lt $expectedDependencyLockfileSummaries.Count; $i++) {
    Assert-DependencyLockfileSummary $summaries[$i] $expectedDependencyLockfileSummaries[$i] $RepositoryRoot ($i + 1)
  }

  Assert-DependencyLicenseInventory (Get-RequiredProperty $dependency "license_inventory" "dependency evidence generated report") $RepositoryRoot
}

function Assert-BundledPackInventoryReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "bundled pack inventory generated report path is required."
  }
  $inventory = Read-BundledPackInventoryReport $Path

  $schemaVersion = Get-RequiredProperty $inventory "schema_version" "bundled pack inventory report"
  if (-not ($schemaVersion -is [int] -or $schemaVersion -is [long]) -or [int64]$schemaVersion -ne 1) {
    throw "bundled pack inventory report schema_version must be integer 1."
  }

  $status = Assert-JsonString (Get-RequiredProperty $inventory "status" "bundled pack inventory report") "bundled pack inventory report status"
  if ($status -ne "passed") {
    throw "bundled pack inventory report status must be 'passed': $status"
  }

  $repository = Assert-JsonString (Get-RequiredProperty $inventory "repository" "bundled pack inventory report") "bundled pack inventory report repository"
  $inventoryRepo = (Resolve-Path -LiteralPath $repository).Path
  if (-not $inventoryRepo.Equals($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "bundled pack inventory report repository does not match RepoRoot: $repository"
  }

  [void](Assert-JsonTimestamp (Get-RequiredProperty $inventory "generated_at_utc" "bundled pack inventory report") "bundled pack inventory report generated_at_utc")
  $validator = Assert-JsonString (Get-RequiredProperty $inventory "validator" "bundled pack inventory report") "bundled pack inventory report validator"
  $validatorFull = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath($validator)) $RepositoryRoot "bundled pack inventory report validator"
  $expectedValidator = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot "tools\zentor_intel\validate_indicator_pack.py"))
  if (-not $validatorFull.Equals($expectedValidator, [StringComparison]::OrdinalIgnoreCase)) {
    throw "bundled pack inventory report validator mismatch: $validator"
  }
  Get-AvoraxGateFile $validatorFull "bundled pack inventory report validator" | Out-Null

  Assert-JsonStringArrayEquals (Get-RequiredProperty $inventory "expected_signature_packs" "bundled pack inventory report") $expectedBundledSignaturePacks "bundled pack inventory report expected_signature_packs"
  Assert-JsonStringArrayEquals (Get-RequiredProperty $inventory "expected_rule_packs" "bundled pack inventory report") $expectedBundledRulePacks "bundled pack inventory report expected_rule_packs"

  $signatureCount = Assert-JsonInteger (Get-RequiredProperty $inventory "signature_pack_count" "bundled pack inventory report") "bundled pack inventory report signature_pack_count"
  $ruleCount = Assert-JsonInteger (Get-RequiredProperty $inventory "rule_pack_count" "bundled pack inventory report") "bundled pack inventory report rule_pack_count"
  $totalCount = Assert-JsonInteger (Get-RequiredProperty $inventory "total_pack_count" "bundled pack inventory report") "bundled pack inventory report total_pack_count"
  if ($signatureCount -ne $expectedBundledSignaturePacks.Count) {
    throw "bundled pack inventory report signature_pack_count mismatch: $signatureCount"
  }
  if ($ruleCount -ne $expectedBundledRulePacks.Count) {
    throw "bundled pack inventory report rule_pack_count mismatch: $ruleCount"
  }
  if ($totalCount -ne ($expectedBundledSignaturePacks.Count + $expectedBundledRulePacks.Count)) {
    throw "bundled pack inventory report total_pack_count mismatch: $totalCount"
  }

  $packRows = @(Assert-JsonArray (Get-RequiredProperty $inventory "packs" "bundled pack inventory report") "bundled pack inventory report packs")
  if ($packRows.Count -ne $totalCount) {
    throw "bundled pack inventory report packs count must match total_pack_count: $($packRows.Count) vs $totalCount"
  }

  $seenNames = @{}
  $seenPaths = @{}
  $seenSignatures = @{}
  $seenRules = @{}
  $signatureRoot = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot "assets\zentor_native\signatures")).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  $ruleRoot = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot "assets\zentor_native\rules")).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar

  for ($i = 0; $i -lt $packRows.Count; $i++) {
    $description = "bundled pack inventory report pack row $($i + 1)"
    $row = $packRows[$i]
    Assert-JsonObject $row $description
    $kind = Assert-JsonString (Get-RequiredProperty $row "kind" $description) "$description kind"
    $name = Assert-JsonString (Get-RequiredProperty $row "name" $description) "$description name"
    $relativePath = Assert-JsonString (Get-RequiredProperty $row "path" $description) "$description path"
    $bytes = Assert-JsonInteger (Get-RequiredProperty $row "bytes" $description) "$description bytes"
    $validatorOutput = Assert-JsonString (Get-RequiredProperty $row "validator_output" $description) "$description validator_output"

    if ($seenNames.ContainsKey($name.ToLowerInvariant())) {
      throw "$description duplicates pack name: $name"
    }
    if ($seenPaths.ContainsKey($relativePath.ToLowerInvariant())) {
      throw "$description duplicates pack path: $relativePath"
    }
    $seenNames[$name.ToLowerInvariant()] = $true
    $seenPaths[$relativePath.ToLowerInvariant()] = $true

    if ([System.IO.Path]::IsPathRooted($relativePath)) {
      throw "$description path must be repository-relative: $relativePath"
    }
    $packFull = Assert-SmallThreatMvpRepoChildPath ([System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot $relativePath))) $RepositoryRoot $description
    $packFile = Get-AvoraxGateFile $packFull $description
    $actualFile = Get-Item -LiteralPath $packFile -Force -ErrorAction Stop
    if ($actualFile.Name -ne $name) {
      throw "$description name must match path leaf: $name vs $($actualFile.Name)"
    }
    if ([int64]$actualFile.Length -ne $bytes) {
      throw "$description bytes must match current pack file length: $bytes vs $($actualFile.Length)"
    }

    if ($kind -eq "signature") {
      if (-not $packFull.StartsWith($signatureRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$description signature path must stay under assets\zentor_native\signatures: $relativePath"
      }
      if (-not ($expectedBundledSignaturePacks -contains $name)) {
        throw "$description unexpected signature pack: $name"
      }
      if (-not $name.EndsWith(".zsig", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$description signature pack must have .zsig extension: $name"
      }
      if ($validatorOutput.IndexOf("validated ", [StringComparison]::Ordinal) -lt 0 -or
          $validatorOutput.IndexOf("zentor-signature-pack-v1", [StringComparison]::Ordinal) -lt 0) {
        throw "$description validator_output must include signature-pack validation evidence."
      }
      $seenSignatures[$name.ToLowerInvariant()] = $true
    } elseif ($kind -eq "rule") {
      if (-not $packFull.StartsWith($ruleRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$description rule path must stay under assets\zentor_native\rules: $relativePath"
      }
      if (-not ($expectedBundledRulePacks -contains $name)) {
        throw "$description unexpected rule pack: $name"
      }
      if (-not $name.EndsWith(".zrule", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$description rule pack must have .zrule extension: $name"
      }
      if ($validatorOutput.IndexOf("validated ", [StringComparison]::Ordinal) -lt 0 -or
          $validatorOutput.IndexOf("zentor-rule-pack-v1", [StringComparison]::Ordinal) -lt 0) {
        throw "$description validator_output must include rule-pack validation evidence."
      }
      $seenRules[$name.ToLowerInvariant()] = $true
    } else {
      throw "$description kind must be 'signature' or 'rule': $kind"
    }
  }

  foreach ($expected in $expectedBundledSignaturePacks) {
    if (-not $seenSignatures.ContainsKey($expected.ToLowerInvariant())) {
      throw "bundled pack inventory report is missing expected signature pack row: $expected"
    }
  }
  foreach ($expected in $expectedBundledRulePacks) {
    if (-not $seenRules.ContainsKey($expected.ToLowerInvariant())) {
      throw "bundled pack inventory report is missing expected rule pack row: $expected"
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$reportPathFull = Resolve-SmallThreatMvpReportPath $ReportPath $repo
$report = Read-SmallThreatMvpReport $reportPathFull

$schemaVersion = Get-RequiredProperty $report "schema_version" "small-threat MVP verification report"
if (-not ($schemaVersion -is [int] -or $schemaVersion -is [long]) -or [int64]$schemaVersion -ne 1) {
  throw "small-threat MVP verification report schema_version must be integer 1."
}

$status = Assert-JsonString (Get-RequiredProperty $report "status" "small-threat MVP verification report") "small-threat MVP verification report status"
if ($status -ne "passed" -and $status -ne "failed") {
  throw "small-threat MVP verification report status must be 'passed' or 'failed': $status"
}

$repository = Assert-JsonString (Get-RequiredProperty $report "repository" "small-threat MVP verification report") "small-threat MVP verification report repository"
$reportRepo = (Resolve-Path -LiteralPath $repository).Path
if (-not $reportRepo.Equals($repo, [StringComparison]::OrdinalIgnoreCase)) {
  throw "small-threat MVP verification report repository does not match RepoRoot: $repository"
}

$startedAt = Assert-JsonTimestamp (Get-RequiredProperty $report "started_at_utc" "small-threat MVP verification report") "small-threat MVP verification report started_at_utc"
$completedAt = Assert-JsonTimestamp (Get-RequiredProperty $report "completed_at_utc" "small-threat MVP verification report") "small-threat MVP verification report completed_at_utc"
if ($completedAt -lt $startedAt) {
  throw "small-threat MVP verification report completed_at_utc is before started_at_utc."
}
[void](Assert-JsonNumber (Get-RequiredProperty $report "elapsed_seconds" "small-threat MVP verification report") "small-threat MVP verification report elapsed_seconds")

$options = Get-RequiredProperty $report "options" "small-threat MVP verification report"
Assert-JsonObject $options "small-threat MVP verification report options"
$includeDefenderEicar = Assert-JsonBoolean (Get-RequiredProperty $options "include_defender_eicar" "small-threat MVP verification report options") "include_defender_eicar"
$skipFlutter = Assert-JsonBoolean (Get-RequiredProperty $options "skip_flutter" "small-threat MVP verification report options") "skip_flutter"
$skipRust = Assert-JsonBoolean (Get-RequiredProperty $options "skip_rust" "small-threat MVP verification report options") "skip_rust"

$tools = Get-RequiredProperty $report "tools" "small-threat MVP verification report"
Assert-JsonObject $tools "small-threat MVP verification report tools"
$requireToolFiles = [bool]$RequireFullSuite
Assert-RequiredToolPath (Get-RequiredProperty $tools "python" "small-threat MVP verification report tools") "Python tool path" $requireToolFiles
Assert-RequiredToolPath (Get-RequiredProperty $tools "cargo" "small-threat MVP verification report tools") "Cargo tool path" $requireToolFiles
Assert-RequiredToolPath (Get-RequiredProperty $tools "flutter" "small-threat MVP verification report tools") "Flutter tool path" $requireToolFiles
Assert-RequiredToolPath (Get-RequiredProperty $tools "dart" "small-threat MVP verification report tools") "Dart tool path" $requireToolFiles
Assert-RequiredToolPath (Get-RequiredProperty $tools "powershell" "small-threat MVP verification report tools") "PowerShell tool path" $requireToolFiles

$generatedReports = Get-RequiredProperty $report "generated_reports" "small-threat MVP verification report"
Assert-JsonObject $generatedReports "small-threat MVP verification report generated_reports"
$requireGeneratedReports = $status -eq "passed"
$protectionSelfTestReport = Resolve-GeneratedReportPath (Get-RequiredProperty $generatedReports "protection_self_test" "small-threat MVP verification report generated_reports") $repo "protection self-test generated report" $requireGeneratedReports
$dependencyEvidenceReport = Resolve-GeneratedReportPath (Get-RequiredProperty $generatedReports "dependency_evidence" "small-threat MVP verification report generated_reports") $repo "dependency evidence generated report" $requireGeneratedReports
$performanceGateReport = Resolve-GeneratedReportPath (Get-RequiredProperty $generatedReports "performance_gate" "small-threat MVP verification report generated_reports") $repo "performance gate generated report" $requireGeneratedReports
$performanceBenchmarkReport = Resolve-GeneratedReportPath (Get-RequiredProperty $generatedReports "performance_benchmark" "small-threat MVP verification report generated_reports") $repo "performance benchmark generated report" $requireGeneratedReports
$bundledPackInventoryReport = Resolve-GeneratedReportPath (Get-RequiredProperty $generatedReports "bundled_pack_inventory" "small-threat MVP verification report generated_reports") $repo "bundled pack inventory generated report" $requireGeneratedReports
$requireNoEicarHarmlessThreatReport = $status -eq "passed" -and -not $skipRust
$noEicarHarmlessThreatReport = Resolve-GeneratedReportPath (Get-RequiredProperty $generatedReports "no_eicar_harmless_threat" "small-threat MVP verification report generated_reports") $repo "no-EICAR harmless-threat generated report" $requireNoEicarHarmlessThreatReport
$requireInstalledCoreLifecycleReport = $status -eq "passed" -and -not $skipRust
$installedCoreLifecycleReport = Resolve-GeneratedReportPath (Get-RequiredProperty $generatedReports "installed_core_lifecycle" "small-threat MVP verification report generated_reports") $repo "installed core lifecycle generated report" $requireInstalledCoreLifecycleReport
$releasePrereqHostReport = Resolve-GeneratedReportPath (Get-RequiredProperty $generatedReports "release_prereq_host" "small-threat MVP verification report generated_reports") $repo "release prerequisite host generated report" $requireGeneratedReports
if ($status -eq "passed") {
  Assert-ProtectionSelfTestReport $protectionSelfTestReport $repo
  Assert-DependencyEvidenceReport $dependencyEvidenceReport $repo
  Assert-PerformanceGateReport $performanceGateReport $repo
  Assert-PerformanceBenchmarkReport $performanceBenchmarkReport $repo
  Assert-BundledPackInventoryReport $bundledPackInventoryReport $repo
  Assert-ReleasePrereqHostReport $releasePrereqHostReport $repo
  if (-not $skipRust) {
    Assert-NoEicarHarmlessThreatReport $noEicarHarmlessThreatReport $repo
    Assert-InstalledCoreLifecycleReport $installedCoreLifecycleReport $repo
  }
}

$stepsValue = Get-RequiredProperty $report "steps" "small-threat MVP verification report"
$steps = @()
if ($null -ne $stepsValue) {
  $steps = @($stepsValue)
}
if ($status -eq "passed" -and $steps.Count -eq 0) {
  throw "passed small-threat MVP verification report must include at least one passed step."
}
for ($i = 0; $i -lt $steps.Count; $i++) {
  Assert-Step $steps[$i] ($i + 1)
}

$verificationScope = Get-RequiredProperty $report "verification_scope" "small-threat MVP verification report"
Assert-JsonObject $verificationScope "small-threat MVP verification report verification_scope"
$verifiedScopeText = Assert-JsonString (Get-RequiredProperty $verificationScope "verified" "small-threat MVP verification report verification_scope") "verification_scope.verified"
[void](Assert-JsonString (Get-RequiredProperty $verificationScope "optional" "small-threat MVP verification report verification_scope") "verification_scope.optional")
[void](Assert-JsonString (Get-RequiredProperty $verificationScope "partial" "small-threat MVP verification report verification_scope") "verification_scope.partial")
[void](Assert-JsonString (Get-RequiredProperty $verificationScope "technically_limited" "small-threat MVP verification report verification_scope") "verification_scope.technically_limited")

$errorValue = Get-RequiredProperty $report "error" "small-threat MVP verification report"
if ($status -eq "passed") {
  if ($null -ne $errorValue -and -not [string]::IsNullOrWhiteSpace([string]$errorValue)) {
    throw "passed small-threat MVP verification report must not contain an error message."
  }
} else {
  [void](Assert-JsonString $errorValue "failed small-threat MVP verification report error")
}

if ($status -eq "passed" -and -not $skipFlutter) {
  Assert-ReportContainsStep $steps "Flutter shell notification priority tests"
  Assert-ReportContainsStep $steps "Flutter support-bundle export tests"
  Assert-ReportContainsStep $steps "Flutter shareable export credential-redaction tests"
  Assert-ReportScopeContains $verifiedScopeText "security-prioritized shell notification summaries" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "support-bundle export confirmation/busy/privacy guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "shareable log/support-bundle credential-redaction guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Basic-auth/cookie/session/URL-userinfo shareable export redaction guards" "verification_scope.verified"
}

if ($RequireFullSuite) {
  if ($status -ne "passed") {
    throw "-RequireFullSuite requires a passed small-threat MVP verification report."
  }
  if ($includeDefenderEicar) {
    throw "-RequireFullSuite expects include_defender_eicar=false; Defender/EICAR integration is opt-in host evidence."
  }
  if ($skipFlutter -or $skipRust) {
    throw "-RequireFullSuite requires skip_flutter=false and skip_rust=false."
  }
  if ($steps.Count -lt 80) {
    throw "-RequireFullSuite expected at least 80 verifier steps, found $($steps.Count)."
  }
  if ($steps[0].name -ne "local-core safe simulator scan reporting") {
    throw "-RequireFullSuite first step mismatch: $($steps[0].name)"
  }
  if ($steps[$steps.Count - 1].name -ne "Dependency evidence gate") {
    throw "-RequireFullSuite last step mismatch: $($steps[$steps.Count - 1].name)"
  }
  Assert-ReportContainsStep $steps "Branding gate"
  Assert-ReportContainsStep $steps "False-positive gate"
  Assert-ReportContainsStep $steps "Protection gate without driver feature claim"
  Assert-ReportContainsStep $steps "Safe synthetic performance/resource gate"
  Assert-ReportContainsStep $steps "Dependency evidence gate"
  Assert-ReportContainsStep $steps "Client UI inventory source gate"
  Assert-ReportContainsStep $steps "native-engine file-type classifier regressions"
  Assert-ReportContainsStep $steps "native-engine archive content sampling regressions"
  Assert-ReportContainsStep $steps "native-engine archive embedded signature detection"
  Assert-ReportContainsStep $steps "native-engine JAR archive embedded signature detection"
  Assert-ReportContainsStep $steps "native-engine APK archive embedded signature detection"
  Assert-ReportContainsStep $steps "native-engine XPI archive embedded signature detection"
  Assert-ReportContainsStep $steps "native-engine VSIX archive embedded signature detection"
  Assert-ReportContainsStep $steps "native-engine NUPKG archive embedded signature detection"
  Assert-ReportContainsStep $steps "native-engine APPX/MSIX archive embedded signature detection"
  Assert-ReportContainsStep $steps "native-engine APPXBUNDLE/MSIXBUNDLE nested package signature detection"
  Assert-ReportContainsStep $steps "native-engine nested archive embedded signature detection"
  Assert-ReportContainsStep $steps "native-engine archive embedded rule and heuristic detection"
  Assert-ReportContainsStep $steps "native-engine Authenticode unsigned-file probe regression"
  Assert-ReportContainsStep $steps "native-engine Authenticode Microsoft-signed probe regression"
  Assert-ReportContainsStep $steps "native-engine ClickOnce carrier heuristic detection"
  Assert-ReportContainsStep $steps "native-engine Java Web Start carrier heuristic detection"
  Assert-ReportContainsStep $steps "native-engine Windows scriptlet carrier heuristic detection"
  Assert-ReportContainsStep $steps "native-engine Windows Installer carrier heuristic detection"
  Assert-ReportContainsStep $steps "native-engine Windows App Installer carrier heuristic detection"
  Assert-ReportContainsStep $steps "local-core CPL/MSU quick-scan simulator quarantine"
  Assert-ReportContainsStep $steps "local-core full-scan PE carrier simulator quarantine"
  Assert-ReportContainsStep $steps "local-core archive-entry simulator scan reporting"
  Assert-ReportContainsStep $steps "local-core JAR archive-entry simulator scan reporting"
  Assert-ReportContainsStep $steps "local-core APK quick-scan archive-entry simulator reporting"
  Assert-ReportContainsStep $steps "local-core XPI quick-scan archive-entry simulator reporting"
  Assert-ReportContainsStep $steps "local-core VSIX quick-scan archive-entry simulator reporting"
  Assert-ReportContainsStep $steps "local-core NUPKG quick-scan archive-entry simulator reporting"
  Assert-ReportContainsStep $steps "local-core APPX/MSIX quick-scan archive-entry simulator reporting"
  Assert-ReportContainsStep $steps "local-core APPXBUNDLE/MSIXBUNDLE nested package simulator reporting"
  Assert-ReportContainsStep $steps "local-core nested archive-entry simulator scan reporting"
  Assert-ReportContainsStep $steps "local-core archive-entry script rule and heuristic reporting"
  Assert-ReportContainsStep $steps "local-core ClickOnce carrier review reporting"
  Assert-ReportContainsStep $steps "local-core Java Web Start carrier review reporting"
  Assert-ReportContainsStep $steps "local-core Windows scriptlet carrier review reporting"
  Assert-ReportContainsStep $steps "local-core Windows Installer carrier review reporting"
  Assert-ReportContainsStep $steps "local-core Windows App Installer carrier review reporting"
  Assert-ReportContainsStep $steps "update-service release binary build"
  Assert-ReportContainsStep $steps "release update-service signed package verify/tamper smoke"
  Assert-ReportContainsStep $steps "release update-service apply tamper fail-before-activation smoke"
  Assert-ReportContainsStep $steps "release update-service apply snapshot-failure fail-safe smoke"
  Assert-ReportContainsStep $steps "release update-service apply success fake-service smoke"
  Assert-ReportContainsStep $steps "release update-service apply stop-failure rollback/staging smoke"
  Assert-ReportContainsStep $steps "release update-service rollback restore smoke"
  Assert-ReportContainsStep $steps "release update-service rollback missing-snapshot fail-safe smoke"
  Assert-ReportContainsStep $steps "release update-service rollback partial-snapshot fail-safe smoke"
  Assert-ReportContainsStep $steps "release update-service rollback destination-kind fail-safe smoke"
  Assert-ReportContainsStep $steps "release update-service rollback staged-engine restore smoke"
  Assert-ReportContainsStep $steps "release update-package builder signed verify smoke"
  Assert-ReportContainsStep $steps "release signed hash-intelligence definitions package smoke"
  Assert-ReportContainsStep $steps "release update-package builder restricted-payload fail-safe smoke"
  Assert-ReportContainsStep $steps "local-core release binary build"
  Assert-ReportContainsStep $steps "release local-core binary safe hash fixture smoke"
  Assert-ReportContainsStep $steps "release local-core binary no-EICAR harmless threat validation smoke"
  Assert-ReportContainsStep $steps "release local-core binary full-scan PE carrier safe hash fixture smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan CPL/MSU safe hash fixture smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan script carrier review smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan family script review smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan persistence/shortcut carrier review smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan AppInstaller carrier review smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan launch/installer carrier review smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan document/web carrier review smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan ZIP carrier review smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan nested ZIP archive-entry safe hash fixture smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan package archive-entry safe hash fixture smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan unsafe archive path review smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan archive limit fail-visible smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan archive count/total fail-visible smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan archive truncation fail-visible smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan archive encryption/unsupported fail-visible smoke"
  Assert-ReportContainsStep $steps "release local-core binary quick-scan archive depth fail-visible smoke"
  Assert-ReportContainsStep $steps "release local-core binary invalid signature-pack fail-safe smoke"
  Assert-ReportContainsStep $steps "release local-core binary invalid rule-pack fail-safe smoke"
  Assert-ReportContainsStep $steps "release local-core binary invalid native-model fail-safe smoke"
  Assert-ReportContainsStep $steps "release local-core binary invalid native trust-store fail-safe smoke"
  Assert-ReportContainsStep $steps "release local-core binary allowlist confirmed-fixture no-quarantine smoke"
  Assert-ReportContainsStep $steps "release local-core binary corrupt allowlist fail-closed smoke"
  Assert-ReportContainsStep $steps "release local-core binary quarantine metadata/payload tamper fail-safe smoke"
  Assert-ReportContainsStep $steps "release local-core binary ransomware guard config/activity smoke"
  Assert-ReportContainsStep $steps "release local-core binary watcher honesty smoke"
  Assert-ReportContainsStep $steps "release local-core binary process snapshot observation smoke"
  Assert-ReportContainsStep $steps "release local-core binary finite watch-poll scan/quarantine smoke"
  Assert-ReportContainsStep $steps "Local scan wrapper release-binary smoke"
  Assert-ReportContainsStep $steps "Cancel scan wrapper release-binary smoke"
  Assert-ReportContainsStep $steps "Allowlist wrapper release-binary smoke"
  Assert-ReportContainsStep $steps "Status wrapper release-binary smoke"
  Assert-ReportContainsStep $steps "Installed smoke structured core-health probe tests"
  Assert-ReportContainsStep $steps "Installed core lifecycle probe release-binary smoke"
  Assert-ReportContainsStep $steps "Quarantine wrapper release-binary smoke"
  Assert-ReportContainsStep $steps "Watch scan wrapper finite release-binary smoke"
  Assert-ReportContainsStep $steps "Release host prerequisite ready-or-blocked evidence"
  Assert-ReportContainsStep $steps "Flutter shell notification priority tests"
  Assert-ReportContainsStep $steps "Flutter manual quarantine IPC tests"
  Assert-ReportContainsStep $steps "Flutter update controller/UI tests"
  Assert-ReportContainsStep $steps "Flutter watch-poll IPC diagnostics tests"
  Assert-ReportContainsStep $steps "Flutter watch-poll loop controller tests"
  Assert-ReportContainsStep $steps "Flutter service recovery update-mutation controller/UI tests"
  Assert-ReportContainsStep $steps "Flutter developer override update-mutation controller/UI tests"
  Assert-ReportContainsStep $steps "Flutter update expanded active-work controller tests"
  Assert-ReportContainsStep $steps "Flutter update expanded active-work UI tests"
  Assert-ReportContainsStep $steps "Flutter custom picker adapter tests"
  Assert-ReportContainsStep $steps "Flutter Protected Apps picker adapter tests"
  Assert-ReportContainsStep $steps "Flutter scan concurrency controller tests"
  Assert-ReportContainsStep $steps "Flutter scan update-mutation controller tests"
  Assert-ReportContainsStep $steps "Flutter configuration update-mutation controller/UI tests"
  Assert-ReportContainsStep $steps "Flutter manual trust update-mutation controller tests"
  Assert-ReportContainsStep $steps "Flutter scan manual trust update-mutation UI tests"
  Assert-ReportContainsStep $steps "Flutter quarantine manual trust update-mutation UI tests"
  Assert-ReportContainsStep $steps "Flutter allowlist manual trust update-mutation UI tests"
  Assert-ReportContainsStep $steps "Flutter protected-app update-mutation controller tests"
  Assert-ReportContainsStep $steps "Flutter protected-app update-mutation UI tests"
  Assert-ReportContainsStep $steps "Flutter configuration scan-busy controller tests"
  Assert-ReportContainsStep $steps "Flutter threat-ignore controller tests"
  Assert-ReportContainsStep $steps "Flutter settings busy-state UI tests"
  Assert-ReportContainsStep $steps "Flutter support-bundle export tests"
  Assert-ReportContainsStep $steps "Flutter shareable export credential-redaction tests"
  Assert-ReportContainsStep $steps "Threat-intel pack metadata smoke"
  Assert-ReportContainsStep $steps "Bundled signature/rule pack validation"
  Assert-ReportScopeContains $verifiedScopeText "client UI tab/button/setting source inventory gate" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Flutter timeout process-tree cleanup guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Protected Apps process-evidence newest ordering plus UTC timestamp visibility" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service signed package verify/tamper smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service apply tamper fail-before-activation smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service apply snapshot-failure fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service apply success fake-service smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service apply stop-failure rollback/staging smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service rollback restore smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service rollback missing-snapshot fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service rollback partial-snapshot fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service rollback destination-kind fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-service rollback staged-engine restore smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-package builder signed verify smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release signed hash-intelligence definitions package smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release update-package builder restricted-payload fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary safe hash fixture scan/quarantine smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary no-EICAR harmless threat validation smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary full-scan PE carrier safe hash fixture smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan CPL/MSU safe hash fixture smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan script carrier review smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan family script review smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan persistence/shortcut carrier review smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan AppInstaller carrier review smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan launch/installer carrier review smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan document/web carrier review smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan ZIP carrier review smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan nested ZIP archive-entry safe hash fixture smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan package archive-entry safe hash fixture smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan unsafe archive path review smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan archive limit fail-visible smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan archive count/total fail-visible smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan archive truncation fail-visible smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan archive encryption/unsupported fail-visible smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quick-scan archive depth fail-visible smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "full-scan PE carrier simulator quarantine" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "CPL/MSU quick-scan simulator quarantine" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "native-engine file-type classifier regressions" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "bounded ZIP/JAR/APK/XPI/VSIX/NUPKG/APPX/MSIX/APPXBUNDLE/MSIXBUNDLE archive-entry and nested archive-entry signature/rule/heuristic detection/quarantine" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "ClickOnce application/reference carrier review" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Java Web Start/JNLP carrier review" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Windows scriptlet/SCT/WSC carrier review" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Windows Installer custom-action carrier review" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Windows App Installer/AppInstaller carrier review" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "ZIP nested executable/autorun/shortcut carrier review" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "registry/shortcut/disk-image carrier review" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "autorun INF/email/Office/RTF/PDF/web/help/OneNote/add-in carrier review" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary invalid signature-pack fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary invalid rule-pack fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary invalid native-model fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary invalid native trust-store fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Windows Authenticode unsigned-file and Microsoft-signed probe regressions" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary allowlist confirmed-fixture no-quarantine smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary corrupt allowlist fail-closed smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary quarantine metadata/payload tamper fail-safe smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary ransomware guard config/activity smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary watcher honesty smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary process snapshot observation smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release local-core binary finite watch-poll scan/quarantine smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "local scan wrapper release-binary progress/quarantine smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "local scan wrapper release-binary folder/fail-on-threat smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "local scan wrapper release-binary path/report guard smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "cancel scan wrapper release-binary request smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "cancel scan wrapper release-binary path/report guard smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "allowlist wrapper release-binary smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "allowlist wrapper release-binary path/report guard smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "status wrapper release-binary health smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "installed smoke structured core-health parser/probe guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "installed core scan/quarantine/restore/delete lifecycle probe" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "status wrapper release-binary path/report guard smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "quarantine management wrapper release-binary manual/rescan/restore/delete smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "quarantine management wrapper release-binary path/report guard smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "manual quarantine file-picker UI/controller/IPC guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "watch scan wrapper finite release-binary smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "watch scan wrapper finite release-binary path/report guard smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "release-host prerequisite ready-or-blocked evidence gate" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "app-lifetime finite watch-poll scan loop controller evidence" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "security-prioritized shell notification summaries" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "support-bundle export confirmation/busy/privacy guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "shareable log/support-bundle credential-redaction guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Basic-auth/cookie/session/URL-userinfo shareable export redaction guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "threat-intel pack metadata smoke" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "bundled signature/rule pack validation" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "app-lifetime scheduled quick scans including target-selection skip and scan-mode busy guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "scan concurrency target-selection controller guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "custom-picker scan-busy controller guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "custom picker adapter success/cancel/failure tests" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "Protected Apps picker adapter success/failure tests" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "scan start configuration-busy controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "protection action public busy-state guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "protection start-stop self-test-busy UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "protection self-test public busy-state guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "security settings protection-busy controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "configuration reset protection-busy controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "manual trust actions configuration-busy controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "threat ignore configuration-busy controller guard" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "configuration mutation scan-busy controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "update install/rollback active-work controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "update install/rollback expanded active-work controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "service recovery actions update-mutation controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "developer override update-mutation controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "protection actions update-mutation controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "scan starts update-mutation controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "configuration mutation update-mutation controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "manual trust actions update-mutation controller/UI guards" "verification_scope.verified"
  Assert-ReportScopeContains $verifiedScopeText "protected app actions update-mutation controller/UI guards" "verification_scope.verified"
}

Write-Host "Avorax small-threat MVP report validation passed."
Write-Host "Report: $reportPathFull"
Write-Host "Status: $status; steps: $($steps.Count); require_full_suite: $([bool]$RequireFullSuite)"
