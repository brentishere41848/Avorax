param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$PythonPath = "",
  [string]$CargoPath = "",
  [string]$FlutterPath = "",
  [string]$DartPath = "",
  [string]$ReportPath = "",
  [switch]$IncludeDefenderEicar,
  [switch]$SkipFlutter,
  [switch]$SkipRust
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

. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

function New-SmallThreatProtectionSelfTestReport {
  param([string]$Path)

  $report = [ordered]@{
    fixture = "small-threat-mvp-synthetic-non-driver"
    fixture_scope = "Policy/verdict coverage only; no signed-driver or pre-execution claim."
    overall_result = "pass"
    driver = [ordered]@{
      communication_port_ok = $false
      installed = $false
      running = $false
      pre_execution_blocking_available = $false
    }
    tests = [ordered]@{
      eicar_scan_blocked = $true
      unknown_unsigned_lockdown_policy_blocked = $true
      unknown_unsigned_allowed_after_hash_approval = $true
      known_good_executable_allowed = $true
      normal_exe_blocked_only_as_unknown = $true
      unknown_unsigned_lockdown_blocked_before_launch = $false
    }
  }

  Write-AvoraxGateJsonFileAtomic $Path $report 6 "small-threat protection self-test fixture"
  (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-SmallThreatMvpReportPath {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Join-Path $RepositoryRoot ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-verification-report.json"
  }

  $rootFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  Assert-AvoraxNoReparsePath $pathFull "small-threat MVP verification report"
  if ($pathFull.TrimEnd('\', '/').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "small-threat MVP verification report must be a child path inside the repository root, not the repository root itself."
  }
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "small-threat MVP verification report must stay under $RepositoryRoot`: $pathFull"
  }
  $pathFull
}

function Invoke-Step {
  param(
    [string]$Name,
    [string]$WorkingDirectory,
    [string]$Executable,
    [string[]]$Arguments
  )
  $commandLine = "$Executable $($Arguments -join ' ')"
  Write-Host ""
  Write-Host "== $Name =="
  Write-Host $commandLine
  $started = Get-Date
  Push-Location -LiteralPath $WorkingDirectory
  try {
    & $Executable @Arguments
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
  } finally {
    Pop-Location
  }
  $elapsed = ((Get-Date) - $started).TotalSeconds
  if ($exitCode -ne 0) {
    throw "$Name failed with exit code $exitCode after $([Math]::Round($elapsed, 1))s"
  }
  Write-Host "PASS $Name ($([Math]::Round($elapsed, 1))s)"
  [pscustomobject]@{
    Name = $Name
    Command = $commandLine
    Seconds = [Math]::Round($elapsed, 1)
  }
}

function New-SmallThreatMvpVerificationReport {
  param(
    [string]$Status,
    [string]$Repo,
    [datetime]$StartedAt,
    [double]$ElapsedSeconds,
    [System.Collections.Generic.List[object]]$Results,
    [string]$Python,
    [string]$Cargo,
    [string]$Flutter,
    [string]$Dart,
    [string]$PowerShell,
    [bool]$IncludeDefenderEicarValue,
    [bool]$SkipFlutterValue,
    [bool]$SkipRustValue,
    [AllowNull()][string]$ProtectionSelfTestReport,
    [AllowNull()][string]$DependencyEvidenceReport,
    [AllowNull()][string]$PerformanceGateReport,
    [AllowNull()][string]$PerformanceBenchmarkReport,
    [AllowNull()][string]$BundledPackInventoryReport,
    [AllowNull()][string]$NoEicarHarmlessThreatReport,
    [AllowNull()][string]$InstalledCoreLifecycleReport,
    [AllowNull()][string]$ReleasePrereqHostReport,
    [string]$VerifiedScope,
    [string]$OptionalDefenderScope,
    [string]$PartialScope,
    [string]$TechnicalLimits,
    [AllowNull()][string]$ErrorMessage
  )

  $steps = @($Results | ForEach-Object {
    [ordered]@{
      name = $_.Name
      command = $_.Command
      seconds = $_.Seconds
      status = "passed"
    }
  })

  [ordered]@{
    schema_version = 1
    status = $Status
    repository = $Repo
    started_at_utc = $StartedAt.ToUniversalTime().ToString("o")
    completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    elapsed_seconds = [Math]::Round($ElapsedSeconds, 1)
    options = [ordered]@{
      include_defender_eicar = $IncludeDefenderEicarValue
      skip_flutter = $SkipFlutterValue
      skip_rust = $SkipRustValue
    }
    tools = [ordered]@{
      python = $Python
      cargo = $Cargo
      flutter = $Flutter
      dart = $Dart
      powershell = $PowerShell
    }
    generated_reports = [ordered]@{
      protection_self_test = $ProtectionSelfTestReport
      dependency_evidence = $DependencyEvidenceReport
      performance_gate = $PerformanceGateReport
      performance_benchmark = $PerformanceBenchmarkReport
      bundled_pack_inventory = $BundledPackInventoryReport
      no_eicar_harmless_threat = $NoEicarHarmlessThreatReport
      installed_core_lifecycle = $InstalledCoreLifecycleReport
      release_prereq_host = $ReleasePrereqHostReport
    }
    steps = $steps
    verification_scope = [ordered]@{
      verified = $VerifiedScope
      optional = $OptionalDefenderScope
      partial = $PartialScope
      technically_limited = $TechnicalLimits
    }
    error = $ErrorMessage
  }
}

function Write-SmallThreatMvpVerificationReport {
  param(
    [string]$Path,
    [object]$Report
  )

  Write-AvoraxGateJsonFileAtomic $Path $Report 8 "small-threat MVP verification report"
  Write-Host "Verification report: $Path"
}

function Invoke-SmallThreatMvpReportValidator {
  param(
    [string]$RepositoryRoot,
    [string]$Path,
    [string]$PowerShellPath,
    [bool]$RequireFullSuite
  )

  $validator = Join-Path $PSScriptRoot "validate-small-threat-mvp-report.ps1"
  if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
    throw "small-threat MVP report validator is missing: $validator"
  }

  $validatorArguments = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $validator,
    "-RepoRoot",
    $RepositoryRoot,
    "-ReportPath",
    $Path
  )
  if ($RequireFullSuite) {
    $validatorArguments += "-RequireFullSuite"
  }

  [void](Invoke-Step "Small-threat MVP report validator" $RepositoryRoot $PowerShellPath $validatorArguments)
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$python = Resolve-ToolPath $PythonPath "C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" "python" "Python"
$cargo = Resolve-ToolPath $CargoPath "C:\Users\Brent\.cargo\bin\cargo.exe" "cargo" "Cargo"
$flutter = Resolve-ToolPath $FlutterPath "C:\Users\Brent\develop\flutter\bin\flutter.bat" "flutter" "Flutter"
$dart = Resolve-ToolPath $DartPath "C:\Users\Brent\develop\flutter\bin\dart.bat" "dart" "Dart"
$powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
$verificationReportPath = Resolve-SmallThreatMvpReportPath $ReportPath $repo
$verifiedScope = "Verified: safe simulator detection, full-scan PE carrier simulator quarantine, CPL/MSU quick-scan simulator quarantine, bounded ZIP/JAR/APK/XPI/VSIX/NUPKG/APPX/MSIX/APPXBUNDLE/MSIXBUNDLE archive-entry and nested archive-entry signature/rule/heuristic detection/quarantine, ClickOnce application/reference carrier review, Java Web Start/JNLP carrier review, Windows scriptlet/SCT/WSC carrier review, Windows Installer custom-action carrier review, Windows App Installer/AppInstaller carrier review, release update-service signed package verify/tamper smoke, release update-service apply tamper fail-before-activation smoke, release update-service apply snapshot-failure fail-safe smoke, release update-service apply success fake-service smoke, release update-service apply stop-failure rollback/staging smoke, release update-service rollback restore smoke, release update-service rollback missing-snapshot fail-safe smoke, release update-service rollback partial-snapshot fail-safe smoke, release update-service rollback destination-kind fail-safe smoke, release update-service rollback staged-engine restore smoke, release update-package builder signed verify smoke, release update-package builder restricted-payload fail-safe smoke, release local-core binary safe hash fixture scan/quarantine smoke, release local-core binary full-scan PE carrier safe hash fixture smoke, release local-core binary quick-scan CPL/MSU safe hash fixture smoke, release local-core binary quick-scan script carrier review smoke, release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke, release local-core binary quick-scan nested ZIP archive-entry safe hash fixture smoke, release local-core binary quick-scan package archive-entry safe hash fixture smoke, release local-core binary quick-scan unsafe archive path review smoke, release local-core binary quick-scan archive limit fail-visible smoke, release local-core binary quick-scan archive count/total fail-visible smoke, release local-core binary quick-scan archive truncation fail-visible smoke, release local-core binary quick-scan archive encryption/unsupported fail-visible smoke, release local-core binary quick-scan archive depth fail-visible smoke, release local-core binary invalid signature-pack fail-safe smoke, release local-core binary invalid rule-pack fail-safe smoke, release local-core binary invalid native-model fail-safe smoke, release local-core binary invalid native trust-store fail-safe smoke, release local-core binary corrupt allowlist fail-closed smoke, release local-core binary quarantine metadata/payload tamper fail-safe smoke, detect-only scans, custom-folder scan, Windows anti-malware OS-block mapping, Windows Authenticode unsigned-file and Microsoft-signed probe regressions, conservative quick/full scan target planning, native scan-root env/planner regressions, local/native file-walker skip/error-bound regressions, local heuristic/static-feature signal regressions, local app-control/trust-store policy regressions, local/native allowlist and training-label feedback regressions, local/native quarantine metadata and trust regressions, Guard service fixture regressions without pre-execution claims, update-service signed manifest/package and rollback fixture regressions, cancellation regressions, local health/self-test readiness reporting, native-engine self-test fixtures, native-engine file-type classifier regressions, native-engine signature/rule/static/archive/script/family/risk-fusion regressions, native-engine exact-hash trust-store regressions, local YARA/ClamAV compatibility regressions, best-effort user-mode realtime watcher planning/status/IPC/controller paths, local ransomware guard runtime policy/config regressions, suspicious-process snapshot observation, app-lifetime process snapshot loop controller evidence, fail-closed process snapshot response handling, app-lifetime finite watch-poll scan loop controller evidence, state/UI visibility, event evidence, and Protected Apps process-evidence newest ordering plus UTC timestamp visibility, false-positive gate for benign installer/tool and unknown-app label guards, non-driver protection gate for synthetic self-test verdict fixtures, protection start-stop confirmation/failure-honesty guards, protection action public busy-state guards, protection start-stop self-test-busy UI guards, protection self-test public busy-state guards, security settings protection-busy controller/UI guards, configuration reset protection-busy controller/UI guards, manual trust actions configuration-busy controller/UI guards, threat ignore configuration-busy controller guard, configuration mutation scan-busy controller/UI guards, update install/rollback active-work controller/UI guards, update install/rollback expanded active-work controller/UI guards, service recovery actions update-mutation controller/UI guards, developer override update-mutation controller/UI guards, protection actions update-mutation controller/UI guards, scan starts update-mutation controller/UI guards, configuration mutation update-mutation controller/UI guards, manual trust actions update-mutation controller/UI guards, protected app actions update-mutation controller/UI guards, ransomware guard settings confirmation/config/failure guards, route/navigation matrix, startup/onboarding/privacy/native-status, visible Allowlist/Device/Protected Apps surfaces, local helper/cloud-boundary guards, and product-policy/no-fake-control guards, repair-installation development-checkout boundary, in-app update-service development-checkout boundary, update controller/UI confirmation and busy-state guards, quarantine restore/delete, manual quarantine restore/delete, allowlist add/remove lifecycle, local event history/log export, support-bundle export confirmation/busy/privacy guards, shareable log/support-bundle credential-redaction guards, Basic-auth/cookie/session/URL-userinfo shareable export redaction guards, app-lifetime scheduled quick scans including target-selection skip and scan-mode busy guards, scan concurrency target-selection controller guards, custom-picker scan-busy controller guards, custom picker adapter success/cancel/failure tests, Protected Apps picker adapter success/failure tests, scan start configuration-busy controller/UI guards, Flutter scan/quarantine/health/self-test UI/controller paths, analyzer, threat-intel pack metadata smoke, bundled signature/rule pack validation, source contracts, branding gate for active product/copy boundary, product-copy gate, no-malware-binaries gate, false-positive gate, protection gate with synthetic non-driver self-test fixture, safe synthetic performance/resource gate, and source-level dependency/lockfile evidence gate."
$verifiedScope = $verifiedScope.Replace(
  "release local-core binary quick-scan script carrier review smoke, release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke",
  "release local-core binary quick-scan script carrier review smoke, release local-core binary quick-scan family script review smoke, release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "release local-core binary quick-scan family script review smoke, release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke",
  "release local-core binary quick-scan family script review smoke, release local-core binary quick-scan persistence/shortcut carrier review smoke, release local-core binary quick-scan AppInstaller carrier review smoke, release local-core binary quick-scan launch/installer carrier review smoke, release local-core binary quick-scan document/web carrier review smoke, release local-core binary quick-scan ZIP carrier review smoke, release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "Windows App Installer/AppInstaller carrier review, release update-service signed package verify/tamper smoke",
  "Windows App Installer/AppInstaller carrier review, ZIP nested executable/autorun/shortcut carrier review, registry/shortcut/disk-image carrier review, autorun INF/email/Office/RTF/PDF/web/help/OneNote/add-in carrier review, release update-service signed package verify/tamper smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "release update-package builder signed verify smoke, release update-package builder restricted-payload fail-safe smoke",
  "release update-package builder signed verify smoke, release signed hash-intelligence definitions package smoke, release update-package builder restricted-payload fail-safe smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "release local-core binary corrupt allowlist fail-closed smoke, release local-core binary quarantine metadata/payload tamper fail-safe smoke",
  "release local-core binary allowlist confirmed-fixture no-quarantine smoke, release local-core binary corrupt allowlist fail-closed smoke, release local-core binary quarantine metadata/payload tamper fail-safe smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "release local-core binary quarantine metadata/payload tamper fail-safe smoke, detect-only scans",
  "release local-core binary quarantine metadata/payload tamper fail-safe smoke, release local-core binary ransomware guard config/activity smoke, detect-only scans"
)
$verifiedScope = $verifiedScope.Replace(
  "best-effort user-mode realtime watcher planning/status/IPC/controller paths",
  "release local-core binary watcher honesty smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths"
)
$verifiedScope = $verifiedScope.Replace(
  "release local-core binary watcher honesty smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths",
  "release local-core binary watcher honesty smoke, release local-core binary finite watch-poll scan/quarantine smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths"
)
$verifiedScope = $verifiedScope.Replace(
  "release local-core binary finite watch-poll scan/quarantine smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths",
  "release local-core binary process snapshot observation smoke, release local-core binary finite watch-poll scan/quarantine smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths"
)
$verifiedScope = $verifiedScope.Replace(
  "release local-core binary safe hash fixture scan/quarantine smoke",
  "release local-core binary safe hash fixture scan/quarantine smoke, release local-core binary no-EICAR harmless threat validation smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "route/navigation matrix, startup/onboarding/privacy/native-status",
  "route/navigation matrix, client UI tab/button/setting source inventory gate, startup/onboarding/privacy/native-status"
)
$verifiedScope = $verifiedScope.Replace(
  "visible Allowlist/Device/Protected Apps surfaces, local helper/cloud-boundary guards, and product-policy/no-fake-control guards",
  "visible Allowlist/Device/Protected Apps surfaces, local helper/cloud-boundary guards, Flutter timeout process-tree cleanup guards, and product-policy/no-fake-control guards"
)
$verifiedScope = $verifiedScope.Replace(
  "release local-core binary finite watch-poll scan/quarantine smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths",
  "release local-core binary finite watch-poll scan/quarantine smoke, local scan wrapper release-binary progress/quarantine smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths"
)
$verifiedScope = $verifiedScope.Replace(
  "local scan wrapper release-binary progress/quarantine smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths",
  "local scan wrapper release-binary progress/quarantine smoke, allowlist wrapper release-binary smoke, status wrapper release-binary health smoke, watch scan wrapper finite release-binary smoke, best-effort user-mode realtime watcher planning/status/IPC/controller paths"
)
$verifiedScope = $verifiedScope.Replace(
  "status wrapper release-binary health smoke, watch scan wrapper finite release-binary smoke",
  "status wrapper release-binary health smoke, status wrapper release-binary path/report guard smoke, watch scan wrapper finite release-binary smoke, watch scan wrapper finite release-binary path/report guard smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "status wrapper release-binary health smoke, status wrapper release-binary path/report guard smoke",
  "status wrapper release-binary health smoke, installed smoke structured core-health parser/probe guards, status wrapper release-binary path/report guard smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "installed smoke structured core-health parser/probe guards",
  "installed smoke structured core-health parser/probe guards, installed core scan/quarantine/restore/delete lifecycle probe release-binary evidence and installed-smoke wiring"
)
$verifiedScope = $verifiedScope.Replace(
  "local scan wrapper release-binary progress/quarantine smoke, allowlist wrapper release-binary smoke",
  "local scan wrapper release-binary progress/quarantine smoke, local scan wrapper release-binary folder/fail-on-threat smoke, local scan wrapper release-binary path/report guard smoke, cancel scan wrapper release-binary request smoke, cancel scan wrapper release-binary path/report guard smoke, allowlist wrapper release-binary smoke, allowlist wrapper release-binary path/report guard smoke"
)
$verifiedScope = $verifiedScope.Replace(
  "quarantine restore/delete, manual quarantine restore/delete",
  "quarantine restore/delete, quarantine management wrapper release-binary manual/rescan/restore/delete smoke, manual quarantine restore/delete, manual quarantine file-picker UI/controller/IPC guards"
)
$verifiedScope = $verifiedScope.Replace(
  "quarantine management wrapper release-binary manual/rescan/restore/delete smoke, manual quarantine restore/delete",
  "quarantine management wrapper release-binary manual/rescan/restore/delete smoke, quarantine management wrapper release-binary path/report guard smoke, manual quarantine restore/delete"
)
$verifiedScope = $verifiedScope.Replace(
  "local event history/log export, support-bundle export confirmation/busy/privacy guards",
  "local event history/log export, security-prioritized shell notification summaries, support-bundle export confirmation/busy/privacy guards"
)
$verifiedScope = $verifiedScope.Replace(
  "source-level dependency/lockfile evidence gate",
  "release-host prerequisite ready-or-blocked evidence gate, source-level dependency/lockfile evidence gate"
)
$optionalDefenderScope = "Optional: standard EICAR file/Defender integration is skipped by default to avoid repeated Microsoft Defender DOS/EICAR_Test_File alerts; rerun with -IncludeDefenderEicar for that host integration proof."
$partialScope = "Partial: packaged desktop click-through E2E, installed local-core/service E2E, installed service repair E2E, installed update/rollback E2E, installed UI filesystem picker flows, installed log export filesystem E2E, installed realtime watcher smoke/E2E, installed process observation service/driver loop/E2E, full release-host SBOM/license output, release-host performance baselines, and production false-positive-rate evidence."
$technicalLimits = "Technically limited: no live malware, no pre-execution blocking claim without a signed installed driver, no kernel realtime blocking claim, no installed service or OS-level polling-loop claim from app-lifetime snapshot observation, no driver-latency claim from synthetic user-mode performance evidence, no Windows Scheduled Task/background-service scheduling claim, no secure-erase claim, no machine-wide dependency installation, and no enterprise update/deployment approval claim."

$pathAdditions = @(
  "C:\Program Files\Git\cmd",
  "C:\Users\Brent\develop\flutter\bin",
  "C:\Users\Brent\.cargo\bin"
) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
$previousPath = $env:PATH
$previousDontWriteBytecode = $env:PYTHONDONTWRITEBYTECODE
$results = New-Object System.Collections.Generic.List[object]
$startedAll = Get-Date
$protectionSelfTestReport = $null
$dependencyEvidenceReport = $null
$performanceGateReport = $null
$performanceBenchmarkReport = $null
$bundledPackInventoryReport = $null
$noEicarHarmlessThreatReport = $null
$installedCoreLifecycleReport = $null
$releasePrereqHostReport = $null

try {
  if ($pathAdditions.Count -gt 0) {
    $env:PATH = (($pathAdditions + @($env:PATH)) -join [System.IO.Path]::PathSeparator)
  }
  $env:PYTHONDONTWRITEBYTECODE = "1"

  Write-Host "Avorax/Zentor small-threat MVP verification"
  Write-Host "Repository: $repo"
  Write-Host "Safety: no live malware, no admin install, no machine-wide changes."
  Write-Host "Defender/EICAR: standard EICAR file creation is opt-in via -IncludeDefenderEicar; default uses safe simulator fixtures."

  if (-not $SkipRust) {
    $results.Add((Invoke-Step "local-core safe simulator scan reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "safe_eicar_simulator_is_detected_and_auto_quarantined_by_confirmed_mode", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core full-scan PE carrier simulator quarantine" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "full_scan_reports_pe_carrier_safe_simulators_and_quarantines_files", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core CPL/MSU quick-scan simulator quarantine" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_cpl_msu_safe_simulators_and_quarantines_files", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core archive-entry simulator scan reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "zip_entry_safe_simulator_is_detected_and_outer_archive_quarantined", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core JAR archive-entry simulator scan reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "jar_entry_safe_simulator_is_detected_and_outer_archive_quarantined", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core APK quick-scan archive-entry simulator reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_apk_entry_safe_simulator_and_quarantines_outer_package", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core XPI quick-scan archive-entry simulator reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_xpi_entry_safe_simulator_and_quarantines_outer_package", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core VSIX quick-scan archive-entry simulator reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_vsix_entry_safe_simulator_and_quarantines_outer_package", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core NUPKG quick-scan archive-entry simulator reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_nupkg_entry_safe_simulator_and_quarantines_outer_package", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core APPX/MSIX quick-scan archive-entry simulator reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_appx_msix_entry_safe_simulator_and_quarantines_outer_packages", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core APPXBUNDLE/MSIXBUNDLE nested package simulator reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_appxbundle_msixbundle_nested_package_safe_simulator", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core nested archive-entry simulator scan reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "nested_zip_entry_safe_simulator_is_detected_and_outer_archive_quarantined", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core archive-entry script rule and heuristic reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "zip_entry_script_rule_and_heuristics_are_reported_without_confirmed_quarantine", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core ClickOnce carrier review reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_clickonce_carriers_for_review", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core Java Web Start carrier review reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_java_web_start_carrier_for_review", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core Windows scriptlet carrier review reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_windows_scriptlet_carriers_for_review", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core Windows Installer carrier review reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_windows_installer_custom_action_carriers_for_review", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core Windows App Installer carrier review reporting" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports_windows_appinstaller_carrier_for_review", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core Windows anti-malware OS-block mapping" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "windows_antimalware_blocked_read_errors_are_confirmed_detections", "--", "--test-threads=1")))
    if ($IncludeDefenderEicar) {
      $results.Add((Invoke-Step "local-core standard EICAR Defender integration" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "standard_eicar_is_detected_or_reported_when_os_blocks_read", "--", "--test-threads=1")))
    }
    $results.Add((Invoke-Step "local-core quick-scan small-threat reports" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quick_scan_reports", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core full-scan boundedness regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "full_scan", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core file-walker error regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "file_walker", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core heuristic signal regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "heuristic", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core static-feature extraction regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "static_feature", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core app-control policy regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "app_control", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core trust-store boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "trust_store", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core allowlist persistence regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "allowlist", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core training-label feedback regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "training_label", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core quarantine metadata regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quarantine", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core scan cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "scan_cancellation", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core realtime watcher regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "watch", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core ransomware guard runtime regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "ransomware_guard", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core YARA rule compatibility regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "yara", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core ClamAV compatibility regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "clamav", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core process monitor snapshot regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "process_monitor", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core process snapshot IPC regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "process_snapshot", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core health self-test regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "self_test", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine indicator regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "indicator", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine self-test regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "self_test", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine file-type classifier regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "file_type", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine ClickOnce carrier heuristic detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "clickonce", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Java Web Start carrier heuristic detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "java_web_start", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Windows scriptlet carrier heuristic detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "windows_scriptlet", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Windows Installer carrier heuristic detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "windows_installer", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Windows App Installer carrier heuristic detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "windows_appinstaller", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine file-walker error regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_file_walker", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine scan-root env validation" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_scan_env_roots", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine quick-scan root planning" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "quick_scan_plan", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine full-scan root planning" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "full_scan_planner", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine EICAR signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_detected_by_native_signature", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine archive content sampling regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "bounded_zip_entry_samples", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine archive embedded signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_zip_entry_is_detected_without_extracting_archive", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine JAR archive embedded signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_jar_entry_is_detected_without_extracting_archive", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine APK archive embedded signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_apk_entry_is_detected_without_extracting_archive", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine XPI archive embedded signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_xpi_entry_is_detected_without_extracting_archive", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine VSIX archive embedded signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_vsix_entry_is_detected_without_extracting_archive", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine NUPKG archive embedded signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_nupkg_entry_is_detected_without_extracting_archive", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine APPX/MSIX archive embedded signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_appx_and_msix_entries_is_detected_without_extracting_package", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine APPXBUNDLE/MSIXBUNDLE nested package signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_appxbundle_and_msixbundle_nested_packages_is_detected", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine nested archive embedded signature detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "eicar_inside_nested_zip_entry_is_detected_without_extracting_archive", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine archive embedded rule and heuristic detection" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "script_rule_and_heuristics_inside_zip_entry_are_reported_without_extracting_archive", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine packaged signature coverage" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "repo_native_packs_detect_more_than_eicar", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine trust-store boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "trust_store", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode unsigned-file probe regression" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "authenticode_probe_accepts_unsigned_file_without_encoded_command_argument_error", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode Microsoft-signed probe regression" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "authenticode_probe_accepts_microsoft_signed_windows_powershell_binary", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine known-good hash regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "known_good", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine known-bad hash regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "known_bad", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine allowlist boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "allowlist", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine quarantine trust regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "quarantine_trust", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine rule pack coverage" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "rule_pack_loads", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine archive traversal analyzer" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "archive_zip_slip", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine large-file sample bounds" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "large_file_scan_reports_full_hash_and_sample_limit", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine script rule verdict" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "encoded_powershell_rule_returns_probable", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine family indicator fusion" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "indicator_combination_is_probable", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine downloader verdict fusion" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "script_downloader_indicator_becomes_probable", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine normal executable false-positive guard" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "normal_exe_in_downloads_is_not_malware", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine risk fusion regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "risk_fusion", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service guard-mode config regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "guard_mode", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service known-bad cache regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "known_bad", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service quarantine metadata regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "quarantine", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service driver IPC boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "driver_ipc", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service driver-health probe regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "driver_health", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service self-test regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "self_test", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service process observation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "process_watch", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service process skip regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "process_skip", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service signed package/update regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service release binary build" $repo $cargo @("build", "--release", "--manifest-path", "core\avorax_update_service\Cargo.toml")))
    $releaseUpdateServicePath = Join-Path $repo "target\release\avorax_update_service.exe"
    $releaseUpdateSignerPath = Join-Path $repo "target\release\avorax_sign_manifest.exe"
    $releaseUpdateKeygenPath = Join-Path $repo "target\release\avorax_generate_update_key.exe"
    $results.Add((Invoke-Step "release update-service signed package verify/tamper smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-verify-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath, "-SignerPath", $releaseUpdateSignerPath, "-KeygenPath", $releaseUpdateKeygenPath)))
    $results.Add((Invoke-Step "release update-service apply tamper fail-before-activation smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-apply-tamper-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath, "-SignerPath", $releaseUpdateSignerPath, "-KeygenPath", $releaseUpdateKeygenPath)))
    $results.Add((Invoke-Step "release update-service apply snapshot-failure fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-apply-snapshot-failure-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath, "-SignerPath", $releaseUpdateSignerPath, "-KeygenPath", $releaseUpdateKeygenPath)))
    $results.Add((Invoke-Step "release update-service apply success fake-service smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-apply-success-fake-service-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath, "-SignerPath", $releaseUpdateSignerPath, "-KeygenPath", $releaseUpdateKeygenPath)))
    $results.Add((Invoke-Step "release update-service apply stop-failure rollback/staging smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-apply-stop-failure-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath, "-SignerPath", $releaseUpdateSignerPath, "-KeygenPath", $releaseUpdateKeygenPath)))
    $results.Add((Invoke-Step "release update-service rollback restore smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-rollback-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath)))
    $results.Add((Invoke-Step "release update-service rollback missing-snapshot fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-rollback-failsafe-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath)))
    $results.Add((Invoke-Step "release update-service rollback partial-snapshot fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-rollback-partial-snapshot-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath)))
    $results.Add((Invoke-Step "release update-service rollback destination-kind fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-rollback-destination-kind-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath)))
    $results.Add((Invoke-Step "release update-service rollback staged-engine restore smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-service-rollback-staged-engine-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath)))
    $results.Add((Invoke-Step "release update-package builder signed verify smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-package-builder-smoke.ps1", "-UpdateServicePath", $releaseUpdateServicePath, "-SignerPath", $releaseUpdateSignerPath, "-KeygenPath", $releaseUpdateKeygenPath)))
    $results.Add((Invoke-Step "release signed hash-intelligence definitions package smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-hash-intel-update-package-smoke.ps1", "-PythonPath", $python, "-UpdateServicePath", $releaseUpdateServicePath, "-SignerPath", $releaseUpdateSignerPath, "-KeygenPath", $releaseUpdateKeygenPath)))
    $results.Add((Invoke-Step "release update-package builder restricted-payload fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-update-package-builder-failsafe-smoke.ps1", "-SignerPath", $releaseUpdateSignerPath)))
    $results.Add((Invoke-Step "safe EICAR detect-only smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-safe-eicar-smoke.ps1", "-CargoPath", $cargo)))
    $results.Add((Invoke-Step "safe custom-folder scan smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-safe-folder-scan-smoke.ps1", "-CargoPath", $cargo)))
    $results.Add((Invoke-Step "safe EICAR quarantine restore smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-safe-quarantine-restore-smoke.ps1", "-CargoPath", $cargo)))
    $results.Add((Invoke-Step "safe EICAR quarantine delete smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-safe-quarantine-delete-smoke.ps1", "-CargoPath", $cargo)))
    $results.Add((Invoke-Step "safe manual quarantine restore smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-safe-manual-quarantine-smoke.ps1", "-CargoPath", $cargo)))
    $results.Add((Invoke-Step "safe manual quarantine delete smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-safe-manual-quarantine-delete-smoke.ps1", "-CargoPath", $cargo)))
    $results.Add((Invoke-Step "safe EICAR allowlist smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-safe-allowlist-smoke.ps1", "-CargoPath", $cargo)))
    $results.Add((Invoke-Step "safe EICAR allowlist removal smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-safe-allowlist-removal-smoke.ps1", "-CargoPath", $cargo)))
    $results.Add((Invoke-Step "local-core release binary build" $repo $cargo @("build", "--release", "--manifest-path", "core\zentor_local_core\Cargo.toml")))
    $releaseLocalCorePath = Join-Path $repo "target\release\zentor_local_core.exe"
    $results.Add((Invoke-Step "release local-core binary safe hash fixture smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $noEicarHarmlessThreatReport = Join-Path $repo ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-no-eicar-harmless-threat.json"
    $results.Add((Invoke-Step "release local-core binary no-EICAR harmless threat validation smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-no-eicar-local-core-harmless-threat-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath, "-ReportPath", $noEicarHarmlessThreatReport)))
    $results.Add((Invoke-Step "release local-core binary full-scan PE carrier safe hash fixture smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-full-scan-pe-carrier-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan CPL/MSU safe hash fixture smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-cpl-msu-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan script carrier review smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-script-carrier-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan family script review smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-family-script-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan persistence/shortcut carrier review smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-persistence-shortcut-carrier-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan AppInstaller carrier review smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-appinstaller-carrier-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan launch/installer carrier review smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-launch-installer-carrier-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan document/web carrier review smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-document-web-carrier-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan ZIP carrier review smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-zip-carrier-review-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-zip-entry-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan nested ZIP archive-entry safe hash fixture smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-nested-zip-entry-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan package archive-entry safe hash fixture smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-package-archive-entry-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan unsafe archive path review smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-unsafe-archive-path-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan archive limit fail-visible smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-archive-limit-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan archive count/total fail-visible smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-archive-count-total-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan archive truncation fail-visible smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-archive-truncation-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan archive encryption/unsupported fail-visible smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-archive-encryption-unsupported-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quick-scan archive depth fail-visible smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quick-scan-archive-depth-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary invalid signature-pack fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-definition-failsafe-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary invalid rule-pack fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-rule-failsafe-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary invalid native-model fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-model-failsafe-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary invalid native trust-store fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-trust-failsafe-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary allowlist confirmed-fixture no-quarantine smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-allowlist-honored-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary corrupt allowlist fail-closed smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-allowlist-failsafe-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary quarantine metadata/payload tamper fail-safe smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-quarantine-tamper-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary ransomware guard config/activity smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-ransomware-guard-config-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary watcher honesty smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-watcher-honesty-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary process snapshot observation smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-process-snapshot-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "release local-core binary finite watch-poll scan/quarantine smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-watch-poll-scan-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "Local scan wrapper release-binary smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-avorax-local-scan-wrapper-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "Cancel scan wrapper release-binary smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-avorax-cancel-scan-wrapper-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "Allowlist wrapper release-binary smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-avorax-allowlist-wrapper-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "Status wrapper release-binary smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-avorax-status-wrapper-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "Installed smoke structured core-health probe tests" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-avorax-installed-core-health-probe-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $installedCoreLifecycleReport = Join-Path $repo ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-installed-core-lifecycle.json"
    $results.Add((Invoke-Step "Installed core lifecycle probe release-binary smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\windows\avorax-installed-core-lifecycle-probe.ps1", "-LocalCorePath", $releaseLocalCorePath, "-EvidenceRoot", $repo, "-ReportPath", $installedCoreLifecycleReport)))
    $results.Add((Invoke-Step "Quarantine wrapper release-binary smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-avorax-quarantine-wrapper-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
    $results.Add((Invoke-Step "Watch scan wrapper finite release-binary smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-avorax-watch-scan-wrapper-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
  }

  if (-not $SkipFlutter) {
    $protocolRoot = Join-Path $repo "packages\zentor_protocol"
    $clientRoot = Join-Path $repo "apps\zentor_client"
    $results.Add((Invoke-Step "Client UI inventory source gate" $repo $python @("-B", "tools\testing\validate-client-ui-inventory.py")))
    $results.Add((Invoke-Step "Dart protocol tests" $protocolRoot $dart @("test", "test\zentor_protocol_test.dart")))
    $results.Add((Invoke-Step "Flutter route/navigation matrix tests" $clientRoot $flutter @("test", "test\route_matrix_test.dart", "test\navigation_accessibility_test.dart")))
    $results.Add((Invoke-Step "Flutter shell notification priority tests" $clientRoot $flutter @("test", "test\navigation_accessibility_test.dart", "--plain-name", "shell notification")))
    $results.Add((Invoke-Step "Flutter product-policy no-fake-control tests" $clientRoot $flutter @("test", "test\app_visual_policy_test.dart")))
    $results.Add((Invoke-Step "Flutter startup/onboarding/native-status tests" $clientRoot $flutter @("test", "test\home_startup_test.dart", "test\home_navigation_test.dart", "test\onboarding_screen_test.dart", "test\privacy_screen_test.dart", "test\settings_native_status_test.dart")))
    $results.Add((Invoke-Step "Flutter visible surface guard tests" $clientRoot $flutter @("test", "test\allowlist_screen_test.dart", "test\device_screen_test.dart", "test\protected_apps_screen_test.dart", "test\protection_status_test.dart")))
    $results.Add((Invoke-Step "Flutter local helper/cloud-boundary tests" $clientRoot $flutter @("test", "test\hash_service_test.dart", "test\app_detector_test.dart", "test\platform_info_service_test.dart", "test\api_client_test.dart")))
    $results.Add((Invoke-Step "Flutter timeout process-tree cleanup tests" $clientRoot $flutter @("test", "test\app_detector_test.dart", "test\platform_info_service_test.dart", "test\local_core_ipc_diagnostics_test.dart", "--plain-name", "timeout")))
    $results.Add((Invoke-Step "Flutter scan screen tests" $clientRoot $flutter @("test", "test\scan_screen_test.dart", "--plain-name", "scan")))
    $results.Add((Invoke-Step "Flutter custom picker adapter tests" $clientRoot $flutter @("test", "test\scan_screen_test.dart", "test\offline_scan_test.dart", "--plain-name", "custom")))
    $results.Add((Invoke-Step "Flutter Protected Apps picker adapter tests" $clientRoot $flutter @("test", "test\protected_apps_screen_test.dart", "--plain-name", "protected apps add")))
    $results.Add((Invoke-Step "Flutter scan-report IPC tests" $clientRoot $flutter @("test", "test\local_core_ipc_diagnostics_test.dart", "--plain-name", "scan report")))
    $results.Add((Invoke-Step "Flutter manual quarantine IPC tests" $clientRoot $flutter @("test", "test\local_core_ipc_diagnostics_test.dart", "--plain-name", "manual quarantine IPC")))
    $results.Add((Invoke-Step "Flutter health IPC diagnostics tests" $clientRoot $flutter @("test", "test\local_core_ipc_diagnostics_test.dart", "--plain-name", "health")))
    $results.Add((Invoke-Step "Flutter repair-installation boundary tests" $clientRoot $flutter @("test", "test\local_core_ipc_diagnostics_test.dart", "--plain-name", "repair installation")))
    $results.Add((Invoke-Step "Flutter update-service boundary tests" $clientRoot $flutter @("test", "test\update_service_test.dart", "--plain-name", "development checkout")))
    $results.Add((Invoke-Step "Flutter service recovery update-mutation controller/UI tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "test\scan_screen_test.dart", "--plain-name", "service recovery")))
    $results.Add((Invoke-Step "Flutter developer override update-mutation controller/UI tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "test\settings_accessibility_test.dart", "--plain-name", "developer cloud override")))
    $results.Add((Invoke-Step "Flutter update controller/UI tests" $clientRoot $flutter @("test", "test\update_controller_test.dart", "test\update_ui_test.dart")))
    $results.Add((Invoke-Step "Flutter update expanded active-work controller tests" $clientRoot $flutter @("test", "test\update_controller_test.dart", "--plain-name", "trust work is active")))
    $results.Add((Invoke-Step "Flutter update expanded active-work UI tests" $clientRoot $flutter @("test", "test\update_ui_test.dart", "test\settings_accessibility_test.dart", "--plain-name", "active security work is busy")))
    $results.Add((Invoke-Step "Flutter scan-target planning tests" $clientRoot $flutter @("test", "test\scan_target_service_test.dart")))
    $results.Add((Invoke-Step "Flutter watcher IPC diagnostics tests" $clientRoot $flutter @("test", "test\local_core_ipc_diagnostics_test.dart", "--plain-name", "watcher")))
    $results.Add((Invoke-Step "Flutter process snapshot IPC tests" $clientRoot $flutter @("test", "test\local_core_ipc_diagnostics_test.dart", "--plain-name", "process")))
    $results.Add((Invoke-Step "Flutter watch-poll IPC diagnostics tests" $clientRoot $flutter @("test", "test\local_core_ipc_diagnostics_test.dart", "--plain-name", "watch-poll")))
    $results.Add((Invoke-Step "Flutter watcher controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "watcher")))
    $results.Add((Invoke-Step "Flutter watch-poll loop controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "watch-poll")))
    $results.Add((Invoke-Step "Flutter protection start-stop controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "protection")))
    $results.Add((Invoke-Step "Flutter ransomware settings controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "ransomware")))
    $results.Add((Invoke-Step "Flutter quarantine controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "quarantine")))
    $results.Add((Invoke-Step "Flutter false-positive feedback controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "false-positive feedback")))
    $results.Add((Invoke-Step "Flutter review-only feedback controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "malicious feedback")))
    $results.Add((Invoke-Step "Flutter quarantine screen tests" $clientRoot $flutter @("test", "test\quarantine_screen_test.dart")))
    $results.Add((Invoke-Step "Flutter local-event audit tests" $clientRoot $flutter @("test", "test\local_event_test.dart")))
    $results.Add((Invoke-Step "Flutter process snapshot event tests" $clientRoot $flutter @("test", "test\local_event_test.dart", "--plain-name", "process snapshot")))
    $results.Add((Invoke-Step "Flutter logs screen export tests" $clientRoot $flutter @("test", "test\logs_screen_test.dart")))
    $results.Add((Invoke-Step "Flutter support-bundle export tests" $clientRoot $flutter @("test", "test\logs_screen_test.dart", "test\local_event_test.dart", "test\settings_accessibility_test.dart", "--plain-name", "support bundle")))
    $results.Add((Invoke-Step "Flutter shareable export credential-redaction tests" $clientRoot $flutter @("test", "test\local_event_test.dart", "--plain-name", "redacts credentials")))
    $results.Add((Invoke-Step "Flutter scheduled quick-scan tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "scheduled quick scan")))
    $results.Add((Invoke-Step "Flutter scan concurrency controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "scan concurrency")))
    $results.Add((Invoke-Step "Flutter scan update-mutation controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "scan starts block while update package work is busy")))
    $results.Add((Invoke-Step "Flutter configuration update-mutation controller/UI tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "test\settings_accessibility_test.dart", "--plain-name", "update package work is busy")))
    $results.Add((Invoke-Step "Flutter manual trust update-mutation controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "manual trust actions block while update package work is busy")))
    $results.Add((Invoke-Step "Flutter scan manual trust update-mutation UI tests" $clientRoot $flutter @("test", "test\scan_screen_test.dart", "--plain-name", "manual trust actions disable during update package work")))
    $results.Add((Invoke-Step "Flutter quarantine manual trust update-mutation UI tests" $clientRoot $flutter @("test", "test\quarantine_screen_test.dart", "--plain-name", "manual trust actions disable during update package work")))
    $results.Add((Invoke-Step "Flutter allowlist manual trust update-mutation UI tests" $clientRoot $flutter @("test", "test\allowlist_screen_test.dart", "--plain-name", "manual trust actions disable during update package work")))
    $results.Add((Invoke-Step "Flutter protected-app update-mutation controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "protected app actions block while update package work is busy")))
    $results.Add((Invoke-Step "Flutter protected-app update-mutation UI tests" $clientRoot $flutter @("test", "test\protected_apps_screen_test.dart", "--plain-name", "protected apps mutation controls disable during update package work")))
    $results.Add((Invoke-Step "Flutter configuration scan-busy controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "scan work is busy")))
    $results.Add((Invoke-Step "Flutter threat-ignore controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "ignore")))
    $results.Add((Invoke-Step "Flutter protection self-test controller tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "self-test")))
    $results.Add((Invoke-Step "Flutter scheduled quick-scan settings tests" $clientRoot $flutter @("test", "test\settings_accessibility_test.dart", "--plain-name", "scheduled quick scan")))
    $results.Add((Invoke-Step "Flutter ransomware settings UI tests" $clientRoot $flutter @("test", "test\settings_accessibility_test.dart", "--plain-name", "ransomware guard")))
    $results.Add((Invoke-Step "Flutter settings busy-state UI tests" $clientRoot $flutter @("test", "test\settings_accessibility_test.dart", "--plain-name", "busy")))
    $results.Add((Invoke-Step "Flutter scheduled quick-scan config tests" $clientRoot $flutter @("test", "test\config_validation_test.dart", "--plain-name", "scheduled quick scan")))
    $results.Add((Invoke-Step "Flutter ransomware config validation tests" $clientRoot $flutter @("test", "test\config_validation_test.dart", "--plain-name", "ransomware")))
    $results.Add((Invoke-Step "Flutter analyzer" $clientRoot $flutter @("analyze")))
  }

  $results.Add((Invoke-Step "Threat-intel pack metadata smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-threat-intel-category-smoke.ps1", "-PythonPath", $python)))
  $bundledPackInventoryReport = Join-Path $repo ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-bundled-pack-inventory.json"
  $results.Add((Invoke-Step "Bundled signature/rule pack validation" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-bundled-pack-validation.ps1", "-PythonPath", $python, "-ReportPath", $bundledPackInventoryReport)))
  $results.Add((Invoke-Step "Python source contracts" $repo $python @("-B", "tools\testing\run-python-source-contracts.py")))
  $results.Add((Invoke-Step "Branding gate" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\branding\branding-check.ps1", "-Root", $repo)))
  $results.Add((Invoke-Step "Product-copy gate" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\security\zentor-product-copy-gate.ps1")))
  $results.Add((Invoke-Step "No-malware-binaries gate" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\security\zentor-no-malware-binaries-gate.ps1", "-PythonPath", $python)))
  $results.Add((Invoke-Step "False-positive gate" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\security\zentor-false-positive-gate.ps1", "-RepoRoot", $repo, "-CargoPath", $cargo)))
  $protectionSelfTestReport = Join-Path $repo ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-protection-selftest.json"
  $protectionSelfTestReport = New-SmallThreatProtectionSelfTestReport $protectionSelfTestReport
  $results.Add((Invoke-Step "Protection gate without driver feature claim" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\security\zentor-protection-gate.ps1", "-RepoRoot", $repo, "-SelfTestReport", $protectionSelfTestReport, "-CargoPath", $cargo)))
  $performanceGateReport = Join-Path $repo "dist\performance\performance_gate_report.json"
  $performanceBenchmarkReport = Join-Path $repo "dist\performance\benchmark_report.json"
  $results.Add((Invoke-Step "Safe synthetic performance/resource gate" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\perf\zentor-performance-gate.ps1", "-RepoRoot", $repo, "-CargoPath", $cargo, "-PythonPath", $python)))
  $releasePrereqHostReport = Join-Path $repo ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-release-prereq-host.json"
  $results.Add((Invoke-Step "Release host prerequisite ready-or-blocked evidence" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-prereq-host-evidence.ps1", "-RepoRoot", $repo, "-CargoPath", $cargo, "-FlutterPath", $flutter, "-ReportPath", $releasePrereqHostReport)))
  $dependencyEvidenceReport = Join-Path $repo ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-dependency-evidence.json"
  $results.Add((Invoke-Step "Dependency evidence gate" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\security\avorax-dependency-evidence.ps1", "-RepoRoot", $repo, "-ReportPath", $dependencyEvidenceReport)))

  Write-Host ""
  Write-Host "== Summary =="
  foreach ($result in $results) {
    Write-Host "PASS $($result.Name) [$($result.Seconds)s]"
  }
  $elapsedAll = ((Get-Date) - $startedAll).TotalSeconds
  Write-Host "All small-threat MVP checks passed in $([Math]::Round($elapsedAll, 1))s."
  Write-Host ""
  Write-Host "== Verification scope =="
  Write-Host $verifiedScope
  if (-not $IncludeDefenderEicar) {
    Write-Host $optionalDefenderScope
  }
  Write-Host $partialScope
  Write-Host $technicalLimits
  $successReport = New-SmallThreatMvpVerificationReport "passed" $repo $startedAll $elapsedAll $results $python $cargo $flutter $dart $powershell ([bool]$IncludeDefenderEicar) ([bool]$SkipFlutter) ([bool]$SkipRust) $protectionSelfTestReport $dependencyEvidenceReport $performanceGateReport $performanceBenchmarkReport $bundledPackInventoryReport $noEicarHarmlessThreatReport $installedCoreLifecycleReport $releasePrereqHostReport $verifiedScope $optionalDefenderScope $partialScope $technicalLimits $null
  Write-SmallThreatMvpVerificationReport $verificationReportPath $successReport
  $requireFullReportValidation = (-not $IncludeDefenderEicar) -and (-not $SkipFlutter) -and (-not $SkipRust)
  Invoke-SmallThreatMvpReportValidator $repo $verificationReportPath $powershell $requireFullReportValidation
} catch {
  $elapsedAll = ((Get-Date) - $startedAll).TotalSeconds
  $errorMessage = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
  try {
    $failureReport = New-SmallThreatMvpVerificationReport "failed" $repo $startedAll $elapsedAll $results $python $cargo $flutter $dart $powershell ([bool]$IncludeDefenderEicar) ([bool]$SkipFlutter) ([bool]$SkipRust) $protectionSelfTestReport $dependencyEvidenceReport $performanceGateReport $performanceBenchmarkReport $bundledPackInventoryReport $noEicarHarmlessThreatReport $installedCoreLifecycleReport $releasePrereqHostReport $verifiedScope $optionalDefenderScope $partialScope $technicalLimits $errorMessage
    Write-SmallThreatMvpVerificationReport $verificationReportPath $failureReport
  } catch {
    Write-Warning "Could not write small-threat MVP failure report: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  throw
} finally {
  $env:PATH = $previousPath
  if ($null -eq $previousDontWriteBytecode) {
    if (Test-Path Env:\PYTHONDONTWRITEBYTECODE) {
      Remove-Item Env:\PYTHONDONTWRITEBYTECODE -ErrorAction Stop
    }
  } else {
    $env:PYTHONDONTWRITEBYTECODE = $previousDontWriteBytecode
  }
}
