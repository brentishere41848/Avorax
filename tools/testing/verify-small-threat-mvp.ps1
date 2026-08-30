param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$PythonPath = "",
  [string]$CargoPath = "",
  [string]$FlutterPath = "",
  [string]$DartPath = "",
  [string]$PowerShell7Path = "",
  [string]$ReportPath = "",
  [switch]$IncludeDefenderEicar,
  [switch]$SkipFlutter,
  [switch]$SkipRust
)

$ErrorActionPreference = "Stop"
$script:SmallThreatMvpFailedStepResult = $null

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
  $script:SmallThreatMvpFailedStepResult = $null
  $timer = [System.Diagnostics.Stopwatch]::StartNew()
  $locationPushed = $false
  try {
    try {
      Push-Location -LiteralPath $WorkingDirectory
      $locationPushed = $true
      & $Executable @Arguments
      $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
      if ($exitCode -ne 0) {
        throw "$Name failed with exit code $exitCode"
      }
    } finally {
      if ($locationPushed) {
        Pop-Location
      }
      if ($timer.IsRunning) {
        $timer.Stop()
      }
    }
  } catch {
    if ($timer.IsRunning) {
      $timer.Stop()
    }
    $elapsed = $timer.Elapsed.TotalSeconds
    $diagnostic = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
    if ([string]::IsNullOrWhiteSpace($diagnostic)) {
      $diagnostic = "$Name failed without a diagnostic."
    }
    $script:SmallThreatMvpFailedStepResult = [pscustomobject]@{
      Name = $Name
      Command = $commandLine
      Seconds = [Math]::Round($elapsed, 1)
      Status = "failed"
      Error = $diagnostic
    }
    throw
  }
  $elapsed = $timer.Elapsed.TotalSeconds
  Write-Host "PASS $Name ($([Math]::Round($elapsed, 1))s)"
  [pscustomobject]@{
    Name = $Name
    Command = $commandLine
    Seconds = [Math]::Round($elapsed, 1)
    Status = "passed"
    Error = $null
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
      status = $_.Status
      error = $_.Error
    }
  })

  $failureKind = $null
  if ($Status -eq "failed") {
    $failureKind = if ($steps.Count -gt 0 -and $steps[$steps.Count - 1].status -eq "failed") {
      "step"
    } else {
      "orchestration"
    }
  }

  [ordered]@{
    schema_version = 2
    status = $Status
    failure_kind = $failureKind
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
    [string]$WindowsPowerShellPath,
    [string]$PowerShell7Path,
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

  [void](Invoke-Step "Small-threat MVP report validator (Windows PowerShell 5.1)" $RepositoryRoot $WindowsPowerShellPath $validatorArguments)
  [void](Invoke-Step "Small-threat MVP report validator (PowerShell 7)" $RepositoryRoot $PowerShell7Path $validatorArguments)
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$python = Resolve-ToolPath $PythonPath "C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" "python" "Python"
$cargo = Resolve-ToolPath $CargoPath "C:\Users\Brent\.cargo\bin\cargo.exe" "cargo" "Cargo"
$flutter = Resolve-ToolPath $FlutterPath "C:\Users\Brent\develop\flutter\bin\flutter.bat" "flutter" "Flutter"
$dart = Resolve-ToolPath $DartPath "C:\Users\Brent\develop\flutter\bin\dart.bat" "dart" "Dart"
$powershell = Get-AvoraxRequiredTool (Get-Command powershell.exe -ErrorAction Stop).Source "Windows PowerShell 5.1 validator host"
$powerShell7 = Resolve-ToolPath $PowerShell7Path "C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe" "pwsh.exe" "PowerShell 7"
if (-not [System.IO.Path]::IsPathRooted($powerShell7)) {
  $powerShell7 = (Get-Command $powerShell7 -CommandType Application -ErrorAction Stop).Source
}
$powerShell7 = Get-AvoraxRequiredTool $powerShell7 "PowerShell 7 validator host"
if ($powerShell7.Equals($powershell, [StringComparison]::OrdinalIgnoreCase)) {
  throw "PowerShell 7 and Windows PowerShell 5.1 validator hosts must be distinct executables."
}
$verificationReportPath = Resolve-SmallThreatMvpReportPath $ReportPath $repo
$verifiedScope = "Verified: safe simulator detection, full-scan PE carrier simulator quarantine, CPL/MSU quick-scan simulator quarantine, bounded ZIP/JAR/APK/XPI/VSIX/NUPKG/APPX/MSIX/APPXBUNDLE/MSIXBUNDLE archive-entry and nested archive-entry signature/rule/heuristic detection/quarantine, ClickOnce application/reference carrier review, Java Web Start/JNLP carrier review, Windows scriptlet/SCT/WSC carrier review, Windows Installer custom-action carrier review, Windows App Installer/AppInstaller carrier review, release update-service signed package verify/tamper smoke, release update-service apply tamper fail-before-activation smoke, release update-service apply snapshot-failure fail-safe smoke, release update-service apply success fake-service smoke, release update-service apply stop-failure rollback/staging smoke, release update-service rollback restore smoke, release update-service rollback missing-snapshot fail-safe smoke, release update-service rollback partial-snapshot fail-safe smoke, release update-service rollback destination-kind fail-safe smoke, release update-service rollback staged-engine restore smoke, release update-package builder signed verify smoke, release update-package builder restricted-payload fail-safe smoke, release local-core binary safe hash fixture scan/quarantine smoke, release local-core binary full-scan PE carrier safe hash fixture smoke, release local-core binary quick-scan CPL/MSU safe hash fixture smoke, release local-core binary quick-scan script carrier review smoke, release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke, release local-core binary quick-scan nested ZIP archive-entry safe hash fixture smoke, release local-core binary quick-scan package archive-entry safe hash fixture smoke, release local-core binary quick-scan unsafe archive path review smoke, release local-core binary quick-scan archive limit fail-visible smoke, release local-core binary quick-scan archive count/total fail-visible smoke, release local-core binary quick-scan archive truncation fail-visible smoke, release local-core binary quick-scan archive encryption/unsupported fail-visible smoke, release local-core binary quick-scan archive depth fail-visible smoke, release local-core binary invalid signature-pack fail-safe smoke, release local-core binary invalid rule-pack fail-safe smoke, release local-core binary invalid native-model fail-safe smoke, release local-core binary invalid native trust-store fail-safe smoke, release local-core binary corrupt allowlist fail-closed smoke, release local-core binary quarantine metadata/payload tamper fail-safe smoke, detect-only scans, custom-folder scan, Windows anti-malware OS-block mapping, Windows direct Authenticode boundary, unsigned/malformed, Microsoft-signed, and scanned-content hash-binding regressions, conservative quick/full scan target planning, native scan-root env/planner regressions, local/native file-walker skip/error-bound regressions, local heuristic/static-feature signal regressions, local app-control/trust-store policy regressions, local/native allowlist and training-label feedback regressions, local/native quarantine metadata and trust regressions, Guard service fixture regressions without pre-execution claims, update-service signed manifest/package and rollback fixture regressions, cancellation regressions, local health/self-test readiness reporting, native-engine self-test fixtures, native-engine file-type classifier regressions, native-engine signature/rule/static/archive/script/family/risk-fusion regressions, native-engine exact-hash trust-store regressions, local YARA/ClamAV compatibility regressions, best-effort user-mode realtime watcher planning/status/IPC/controller paths, local ransomware guard runtime policy/config regressions, suspicious-process snapshot observation, app-lifetime process snapshot loop controller evidence, fail-closed process snapshot response handling, app-lifetime finite watch-poll scan loop controller evidence, state/UI visibility, event evidence, and Protected Apps process-evidence newest ordering plus UTC timestamp visibility, false-positive gate for benign installer/tool and unknown-app label guards, non-driver protection gate for synthetic self-test verdict fixtures, protection start-stop confirmation/failure-honesty guards, protection action public busy-state guards, protection start-stop self-test-busy UI guards, protection self-test public busy-state guards, security settings protection-busy controller/UI guards, configuration reset protection-busy controller/UI guards, manual trust actions configuration-busy controller/UI guards, threat ignore configuration-busy controller guard, configuration mutation scan-busy controller/UI guards, update install/rollback active-work controller/UI guards, update install/rollback expanded active-work controller/UI guards, service recovery actions update-mutation controller/UI guards, developer override update-mutation controller/UI guards, protection actions update-mutation controller/UI guards, scan starts update-mutation controller/UI guards, configuration mutation update-mutation controller/UI guards, manual trust actions update-mutation controller/UI guards, protected app actions update-mutation controller/UI guards, ransomware guard settings confirmation/config/failure guards, route/navigation matrix, startup/onboarding/privacy/native-status, visible Allowlist/Device/Protected Apps surfaces, local helper/cloud-boundary guards, and product-policy/no-fake-control guards, repair-installation installer-owned fail-closed boundary, in-app update-service development-checkout boundary, update controller/UI confirmation and busy-state guards, quarantine restore/delete, manual quarantine restore/delete, allowlist add/remove lifecycle, local event history/log export, support-bundle export confirmation/busy/privacy guards, shareable log/support-bundle credential-redaction guards, Basic-auth/cookie/session/URL-userinfo shareable export redaction guards, app-lifetime scheduled quick scans including target-selection skip and scan-mode busy guards, scan concurrency target-selection controller guards, custom-picker scan-busy controller guards, custom picker adapter success/cancel/failure tests, Protected Apps picker adapter success/failure tests, scan start configuration-busy controller/UI guards, Flutter scan/quarantine/health/self-test UI/controller paths, analyzer, threat-intel pack metadata smoke, bundled signature/rule pack validation, source contracts, branding gate for active product/copy boundary, product-copy gate, no-malware-binaries gate, false-positive gate, protection gate with synthetic non-driver self-test fixture, safe synthetic performance/resource gate, and source-level dependency/lockfile evidence gate."
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
  "local/native quarantine metadata and trust regressions",
  "local/native quarantine metadata and trust regressions, shared Local Core/Guard HMAC-SHA-256 quarantine metadata authentication and interoperability"
)
$verifiedScope += " Additional verified boundary: native-engine detection-only mutation boundary."
$verifiedScope += " Additional verified boundary: shared cross-platform quarantine permission hardening with process-token SID and exact protected Windows DACL verification plus exact Unix 0700/0600 verification."
$verifiedScope += " Additional verified boundary: Guard native Windows process enumeration and Linux procfs coverage gaps are bounded, fail-visible, and cannot become a clean finite-watch result."
$verifiedScope += " Additional verified boundary: Guard process skips, taskkill discovery, driver-health System32 tools, and driver IPC fail-open roots use the bounded native system Windows directory and reject environment or other-drive lookalikes."
$verifiedScope += " Additional verified boundary: Native Engine uses direct handle-based WinVerifyTrust with no script, shell, or network retrieval; it accepts publisher trust only for a valid primary or bounded secondary embedded Authenticode signature, or a bounded SHA-256 system-catalog membership, whose verified leaf has the exact Microsoft identity and, on the scan path, a second bounded SHA-256 read matching the bytes already scanned. Embedded and catalog verification request primary index zero, require primary output to be zero or provider-untouched, check each returned secondary index exactly, cap each candidate at 16 total signatures, close every WinTrust state before the next signature, and fail visibly on count drift, API, policy, limit, or cleanup errors. An invalid primary signature is not rescued by a secondary; invalid embedded signatures retain catalog fallback and invalid catalog candidates advance only to the next bounded catalog. Catalog lookup is capped at 16 candidates and rejects non-local catalog paths. The installed WindowsPowerShell catalog proves the primary catalog path and exact scan-hash binding; bounded secondary-catalog aggregation is unit-verified, but positive acceptance of an actual secondary catalog signature remains partial because no controlled benign multi-signed catalog fixture is available. Release Local Core and Guard isolate native WinTrust work in an exact-current-executable child using strict nonce-bound one-request JSON, bounded stdin/stdout/stderr, a 15-second deadline, kill-on-close Windows Job containment, and bounded kill/reap diagnostics; helper errors and timeouts cannot become trust. Debug test builds retain a direct backend for deterministic unit fixtures and do not prove release isolation. Memory-mapped and post-verdict mutation, same-token helper least privilege, and pre-execution blocking are not claimed. Native Engine's disabled test-only legacy quarantine store uses token-derived native DACL application and verification without an external helper, while production quarantine remains owned by Local Core."
$verifiedScope += " Additional verified boundary: every Microsoft publisher-trust request requires the scanner's lowercase or uppercase 64-hex SHA-256, including strict helper IPC; no path-only publisher verdict API remains. The open candidate is snapshotted before and after trust using Windows volume/file identity, legacy file index, creation/write/change times, attributes, allocation/end size, link count, delete-pending, and directory state. Any query failure or drift is diagnostic and cannot become trust. Last-access time is intentionally excluded because reads may update it. Existing writable mappings and mutation after the verdict remain user-mode limitations."
$verifiedScope += " Additional verified boundary: the release Authenticode helper Windows Job enforces and reads back an exact 12-second per-process user-CPU limit, one-process active limit, and 1 GiB per-process and whole-Job commit ceilings before untrusted candidate processing begins. Unhandled-exception dialogs are suppressed and kill-on-close remains mandatory. Any SetInformationJobObject, QueryInformationJobObject, or exact-limit mismatch is diagnostic and prevents trust work."
$verifiedScope += " Additional verified boundary: before the suspended Authenticode helper is assigned and resumed, its Windows Job enables and exactly reads back the returned JOBOBJECT_BASIC_UI_RESTRICTIONS byte count plus all eight JOB_OBJECT_UILIMIT controls for foreign USER handles, clipboard reads and writes, system parameters, display settings, global atoms, desktop creation/switching, and ExitWindows. Any UI-limit configuration, query, returned-size, exact-flag, Job assignment, or resume failure is diagnostic and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: After assignment and before ResumeThread, the parent requires nonzero matching PROCESS_INFORMATION and GetProcessId identities, successful exact-Job IsProcessInJob, the exact JOBOBJECT_BASIC_PROCESS_ID_LIST returned byte count, exactly one assigned/listed process, and that one PID equal to the helper. Before standard-handle, private-desktop, token, mitigation, stdin, request, or candidate processing, the child requires GetCurrentProcessId to be nonzero and IsProcessInJob against any current Job to return true. Parent process-ID, exact-Job membership, process-list query, returned-size, count, or PID failure terminates and reaps the still-suspended helper; child membership failure is diagnostic before trust work, and neither can become publisher trust."
$verifiedScope += " Additional verified boundary: before process creation, release Local Core and Guard create a unique bounded private Authenticode desktop in the current process window station while the parent thread temporarily uses a read-back-verified low-integrity SecurityImpersonation token derived from the exact child primary token, require successful RevertToSelf plus exact name and byte-count read-back plus non-inheritable zero hook flags, pass that exact name through STARTUPINFOEXW.lpDesktop, and retain the desktop handle until child exit. Before token validation or stdin parsing, the child requires its exact startup desktop name to match its queried current-thread desktop. Desktop token duplication/application/read-back/revert, creation, encoding, name/flag/size read-back, process attachment, or child binding failure is diagnostic and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: release Local Core and Guard require each Authenticode CreatePipe parent/child endpoint to be FILE_TYPE_PIPE with exact parent-zero/child-HANDLE_FLAG_INHERIT flags before process creation; GetNamedPipeInfo verifies each server/read endpoint, while exact CreatePipe read/write return-role assignment binds stdin to the child read handle and stdout/stderr to child write handles. Before private-desktop, token, mitigation, or stdin processing, the child requires exact STARTF_USESTDHANDLES startup state, exact GetStdHandle-to-startup identity, three valid distinct pipe handles, queried stdin server/read mode, stdout/stderr identities bound to the parent-created write handles, and exact initial inheritance flags, then clears HANDLE_FLAG_INHERIT on all three handles and reads back exact zero. Handle query, type, direction binding, identity, duplicate, initial-flag, mutation, or read-back failure is diagnostic and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: after standard-handle type, direction, identity, and inheritance validation and before private-desktop, token, mitigation, stdin, request, or candidate processing, the child reads a canonical nonzero parent PID from its exact sanitized launch environment. It requires GetNamedPipeClientProcessId on the inherited stdin server/read handle and GetNamedPipeServerProcessId on both inherited stdout/stderr client/write handles to return that exact parent PID, distinct from the child PID. Missing, malformed, zero, self, API-failed, or mismatched peer evidence is diagnostic and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: before helper trust work, a dedicated random local-only one-instance named-pipe handshake requires the child to verify the exact parent server PID and the parent to verify the exact suspended-launch child client PID. A distinct canonical random launch token must cross that pipe exactly; the pipe rejects remote clients, has a protected current-user/SYSTEM DACL plus low-integrity mandatory label, is non-inheritable, and uses bounded overlapped connect/read with explicit cancellation settlement. Any missing environment, malformed UUID, ACL/pipe/API failure, wrong PID, wrong token, child exit, timeout, or unsettled cancellation fails visibly and terminates/reaps the helper without a weaker retry."
$verifiedScope += " Additional verified boundary: immediately after creating and validating the Authenticode handshake server endpoint and before event creation, connection, or helper launch, the parent uses GetSecurityInfo with SE_KERNEL_OBJECT plus OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, and LABEL_SECURITY_INFORMATION to read back exactly the applied descriptor under existing READ_CONTROL access. Bounded structured ACL reads require a protected nondefault DACL containing exactly ordered zero-flag access-allowed ACEs for SYSTEM with normalized full control and the current user with normalized generic read plus generic write, plus one nondefault zero-flag low-integrity no-write-up mandatory-label ACE; generic pipe/file rights are normalized with MapGenericMask before exact evidence comparison. A current-user full-control, read-only, write-only, execute, delete, write-owner, or otherwise mismatched ACE fails both endpoint read-backs before token exchange or publisher trust. Query, control-flag, ACL size/count/bound, ACE type/size/flag/mask/SID, principal, order, policy, or label mismatch fails visibly without enabling SeSecurityPrivilege, requesting ACCESS_SYSTEM_SECURITY, reading the full SACL, or retrying with weaker security."
$verifiedScope += " Additional verified boundary: after the Authenticode helper opens the dedicated duplex handshake client with exactly GENERIC_READ plus GENERIC_WRITE plus READ_CONTROL, validates its client endpoint, and binds the server PID to the exact parent, but before reading the parent-delivered launch key, the child resolves its current process-token SID and performs the same GetSecurityInfo DACL and mandatory-label read-back on the actually opened client handle. Client access, SID, query, descriptor, ACL, ACE, policy, or label failure is diagnostic and cannot reach key delivery or publisher trust; there is no weaker retry."
$verifiedScope += " Additional verified boundary: the handshake descriptor sets and reads back the exact current process-token user SID as owner and contains a third ordered zero-flag Owner Rights S-1-3-4 allow ACE granting only READ_CONTROL. Windows owner-rights semantics suppress the owner's otherwise implicit READ_CONTROL and WRITE_DAC; a benign same-user CreateFileW reopen requesting only WRITE_DAC must fail with ERROR_ACCESS_DENIED while exact parent/client protocol access and both read-backs remain functional. Missing, reordered, wrong-owner, wrong-SID, zero, WRITE_DAC-augmented, flagged, or extra ACE evidence fails visibly before token exchange or publisher trust."
$verifiedScope += " Additional verified boundary: the Authenticode helper opens the handshake client with explicit SECURITY_SQOS_PRESENT plus SECURITY_IMPERSONATION. Before delivering the bounded launch key, the parent calls ImpersonateNamedPipeClient on the verified server endpoint and requires an exact SecurityImpersonation thread token with the launch user SID, low-integrity label, no-write-up mandatory policy, privilege stripping, zero restricting SIDs, canonical virtualization state, and UIAccess disabled before the key can be disclosed. Impersonation failure, bounded token query/size/pointer/type/level/SID/privilege/restricting-SID/integrity/policy/safety mismatch, or inability to prove RevertToSelf and an empty parent thread token is diagnostic and cannot reach key delivery or publisher trust."
$verifiedScope += " Additional verified boundary: before handshake pipe creation, the parent queries exact TokenStatistics.AuthenticationId and TokenSessionId from the low-integrity privilege-stripped launch primary token. After named-pipe client impersonation, it requires the connected token to match both values before the launch key can be disclosed. Empty expected authentication IDs, fixed-size query failures, authentication-ID drift, or session-ID drift are diagnostic and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: after named-pipe client impersonation, the parent snapshots the exact TokenStatistics.TokenId and ModifiedId before all client-token property checks and queries both again after every successful check. An empty initial token ID, fixed-size query failure, token-instance drift, or token-modification drift is diagnostic and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: before handshake pipe creation, the parent snapshots the exact launch primary TokenStatistics.TokenId and ModifiedId from the same parent-held token handle later passed to CreateProcessAsUserW. It queries that same handle after successful process creation while the helper remains suspended, immediately before authenticated launch-key delivery, and again after exact child-process, connected-client-token, and key-confirmation HMAC authentication. An empty initial launch token ID, fixed-size query failure, token-instance drift, or modified-context drift fails visibly; post-creation failure terminates and reaps the helper and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: the Authenticode handshake is duplex. Before disclosing the random launch key, the parent binds the connected pipe client PID to the exact retained child process, authenticates its same-user logon-session token, and revalidates the parent-held launch token plus the exact child primary-token profile and object stability. Before delivery, the parent opens the token currently attached to the exact child process with TOKEN_QUERY, requires exact primary type, launch user SID, AuthenticationId and session, privilege stripping, zero restricting SIDs, low integrity, mandatory no-write-up, canonical virtualization state, disabled UIAccess, and a nonempty child TokenId, then captures its TokenId and ModifiedId. The parent then sends the canonical 36-byte key only over that retained pipe; the child first verifies the exact server PID and applied pipe security, reads and validates the key, derives the response MAC key, and returns an exact 32-byte key-confirmation HMAC. The key is absent from the child environment. After the key-confirmation HMAC, the parent repeats the complete child-token profile validation and requires exact equality with the captured child TokenId and ModifiedId before allowing the handshake to complete. Invalid process/token handles, open/query/profile failure, empty IDs, child token-instance or modified-context drift, malformed key or confirmation, incomplete I/O, timeout, or unsettled cancellation fails visibly, terminates and reaps the child, and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: the child computes the handshake key confirmation as domain-separated HMAC-SHA-256 under the exact canonical 36-byte per-launch key over the exact unsigned 64-bit little-endian canonical pipe-name byte length, every canonical pipe-name byte, and the unsigned 32-bit little-endian parent and child PIDs. The parent requires exactly 32 bytes and verifies that HMAC in constant time against its retained pipe name, launch key, own PID, and exact retained child PID before accepting key possession. Empty, truncated, extended, mutated, wrong-key, wrong-pipe, wrong-parent-PID, wrong-child-PID, zero-PID, or equal-PID evidence fails visibly; the real restricted benign child succeeds and a real restricted wrong-key child is terminated and reaped."
$verifiedScope += " Additional verified boundary: the parent handshake, authenticated response evidence, pending child handshake, and completed child handshake each own the same fixed AuthenticodeLaunchKey shape, Zeroizing<[u8; 37]>, containing exactly 36 canonical lowercase random-UUID bytes plus one zero overflow guard. The parent generates directly into that guarded buffer and writes only the first 36 bytes; the child reads at most 37 bytes, requires an exact 36-byte transfer and unchanged zero guard, and moves that same buffer through pending and completed state without creating an owned String copy. HMAC operations borrow only the canonical 36-byte prefix after guard, UTF-8, UUID-variant, and UUID-version validation, and key-bearing structs do not derive Debug. Drop and every early-return path zeroize these Avorax-owned fixed buffers; explicit scrub and guard-mutation regressions prove all-zero storage, canonical-key rejection after scrub, overflow-guard rejection, and prior handshake-HMAC and response-MAC evidence failure after scrub."
$verifiedScope += " Additional verified boundary: the same duplex handshake remains open through candidate trust work and bounded response production. After the helper writes and flushes stdout, it sends an exact fixed response-binding frame beginning with the response-ready marker and blocks for a distinct final ACK. Before that ACK, the parent revalidates the same parent-held launch TokenId and ModifiedId, reopens the exact live child process token with TOKEN_QUERY, repeats its complete launch identity and restricted security profile, and requires the child token's captured TokenId and ModifiedId to remain exact. Missing, malformed, duplicate-length, incomplete, timed-out, early-exit, query, profile, token-drift, cancellation, or final-ACK failure terminates and reaps the helper and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: after accepting the exact response-binding frame marker, length, and MAC and before launch-token or child-process-token read-back and final ACK, the parent queries the client PID from the still-connected named-pipe instance, binds it to GetProcessId on the exact retained child process handle, then freshly impersonates that same pipe connection. The second client-token validation repeats exact SecurityImpersonation type and level, launch user SID, AuthenticationId and session, privilege stripping, zero restricting SIDs, low integrity, no-write-up policy, canonical virtualization state, disabled UIAccess, and within-validation TokenId and ModifiedId stability, then proves RevertToSelf and an empty parent thread token. Process-handle/PID/peer query, process binding, impersonation, token profile/stability, or revert failure is diagnostic, terminates and reaps the helper, and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: After flushing exact bounded stdout, the child computes domain-separated HMAC-SHA-256 under the exact canonical 36-byte random launch-token key over the exact unsigned 64-bit little-endian byte length and every response byte, including the JSON newline. It sends one fixed 41-byte marker, length, and MAC frame over the retained duplex pipe, then waits for final ACK. The parent validates the exact frame and canonical 1..16384-byte length before fresh connected-client reauthentication, launch-token and child-token read-back, and final ACK. After the helper exits, the parent uses its retained per-launch key and constant-time MAC verification to require the collected bounded stdout length and HMAC-SHA-256 to match that authenticated frame before strict JSON parsing or publisher trust. Empty, oversized, truncated, extended, malformed-marker, noncanonical-length, length-mismatch, MAC-mismatch, or wrong-launch-key evidence fails visibly and cannot become publisher trust."
$verifiedScope += " Additional verified boundary: the sanitized child environment contains only the canonical handshake pipe name, canonical parent PID, and checked native SystemRoot/WINDIR values; it contains no launch token or response MAC key. Exact connected-client process/token validation and launch/child token stability precede parent-to-child key delivery on the retained pipe, and the child validates and cryptographically confirms possession of the key before request processing."
$verifiedScope += " Additional verified boundary: Native Engine PUP category inference requires a bounded ASCII-alphanumeric token, so incidental path fragments such as .tmpuPoV59 cannot override stronger downloader/script evidence while an explicit PUP token remains classified as potentially unwanted."
$verifiedScope += " Additional verified boundary: the exact generated verification report and every nested generated JSON report are parsed without PowerShell 7 timestamp coercion and pass the same strict schema, type, path, scope, step-count, and status validation under distinct checked Windows PowerShell 5.1 and PowerShell 7 executables."
$verifiedScope = $verifiedScope.Replace(
  "Memory-mapped and post-verdict mutation, same-token helper least privilege, and pre-execution blocking are not claimed.",
  "Release Local Core and Guard create the helper suspended with a read-back-verified DISABLE_MAX_PRIVILEGE primary token, restrict inheritance to exactly stdin/stdout/stderr through PROC_THREAD_ATTRIBUTE_HANDLE_LIST, assign the configured Job before ResumeThread, and require child-side primary-token validation before request parsing. The parent supplies a bounded Unicode environment containing exactly a canonical parent PID and canonical parent-child handshake pipe plus SystemRoot and WINDIR derived from the checked native Windows directory; no launch token or response MAC key is inherited. It sets CREATE_UNICODE_ENVIRONMENT and an explicit checked non-reparse System32 current directory, never falling back to inherited environment or current-directory state. Before CreateProcessAsUserW, the parent supplies an immutable DWORD64 process-creation mitigation policy enabling strict handle checks, extension-point disable, dynamic-code prohibition, Microsoft-signed-only binary loading, no remote images, no low-label images, and System32 image preference; the child requires both invalid-handle exception and permanent-enforcement read-back flags plus every other required policy before stdin or request parsing, and attribute construction, application, or read-back failure cannot become trust. Before stdin or request parsing, release helper code applies a read-back-verified write-restricted SecurityImpersonation token created with DISABLE_MAX_PRIVILEGE plus WRITE_RESTRICTED and exactly one WinRestrictedCodeSid; strict request parsing and read-only candidate open/snapshot remain under that token. The token is fail-visibly reverted before WinTrust/catalog compatibility work under the privilege-stripped primary token, and a fresh write-restricted token protects response serialization/output. Only SeChangeNotifyPrivilege may remain enabled; ordinary user-owned file mutation is denied while read access and embedded/catalog Microsoft verification remain functional. Environment construction, current-directory validation, mitigation-policy construction/application/read-back, token/SID creation, process launch, handle-list construction, Job assignment, resume, bounded TokenPrivileges or TokenRestrictedSids inspection, verification, or normal revert failure cannot become trust. The primary process token is privilege-stripped but not write-restricted because a write-restricted primary token fails Windows child loader initialization with 0xC0000142 on the verified host; same-process code can technically call RevertToSelf. WinTrust/catalog execute under that primary token because the Windows trust stack failed under write restriction with error 127 on the verified host. The helper retains the parent SID, integrity level, desktop, and ordinary read access, so this is not an AppContainer, a separate desktop, or authenticated cross-identity IPC. Memory-mapped and post-verdict mutation plus pre-execution blocking are not claimed."
)
$verifiedScope = $verifiedScope.Replace(
  "Release Local Core and Guard create the helper suspended with a read-back-verified DISABLE_MAX_PRIVILEGE primary token, restrict inheritance to exactly stdin/stdout/stderr through PROC_THREAD_ATTRIBUTE_HANDLE_LIST, assign the configured Job before ResumeThread, and require child-side primary-token validation before request parsing.",
  "Release Local Core and Guard create the helper suspended with a read-back-verified DISABLE_MAX_PRIVILEGE primary token, set its mandatory label to the exact WinLowLabelSid through SetTokenInformation(TokenIntegrityLevel), require the LSA-created mandatory policy inherited through CreateRestrictedToken to contain TOKEN_MANDATORY_POLICY_NO_WRITE_UP, allow only the documented optional TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN read-back bit, require TokenVirtualizationAllowed to be a canonical Boolean and TokenVirtualizationEnabled and TokenUIAccess to be zero, read back the label, enforced no-write-up policy, canonical legacy virtualization capability evidence, inactive legacy virtualization state, and disabled UIAccess in the parent before CreateProcessAsUserW and in the child before stdin or request parsing, restrict inheritance to exactly stdin/stdout/stderr through PROC_THREAD_ATTRIBUTE_HANDLE_LIST, assign the configured Job before ResumeThread, and require child-side primary-token validation before request parsing."
)
$verifiedScope = $verifiedScope.Replace(
  "Only SeChangeNotifyPrivilege may remain enabled; ordinary user-owned file mutation is denied while read access and embedded/catalog Microsoft verification remain functional.",
  "Only SeChangeNotifyPrivilege may remain enabled; low-integrity MIC/no-write-up denies ordinary medium-integrity file mutation even after RevertToSelf while read access and embedded/catalog Microsoft verification remain functional."
)
$verifiedScope = $verifiedScope.Replace(
  "bounded TokenPrivileges or TokenRestrictedSids inspection",
  "bounded TokenPrivileges, TokenRestrictedSids, TokenIntegrityLevel, fixed-size TokenMandatoryPolicy, or fixed-size token virtualization/UIAccess inspection"
)
$verifiedScope = $verifiedScope.Replace(
  "The primary process token is privilege-stripped but not write-restricted because a write-restricted primary token fails Windows child loader initialization with 0xC0000142 on the verified host; same-process code can technically call RevertToSelf.",
  "The primary process token is low-integrity and privilege-stripped but not WRITE_RESTRICTED because a write-restricted primary token fails Windows child loader initialization with 0xC0000142 on the verified host; same-process RevertToSelf returns only to that low-integrity primary token."
)
$verifiedScope = $verifiedScope.Replace(
  "WinTrust/catalog execute under that primary token because the Windows trust stack failed under write restriction with error 127 on the verified host.",
  "WinTrust/catalog execute under that low-integrity primary token because the Windows trust stack failed under write restriction with error 127 on the verified host."
)
$verifiedScope = $verifiedScope.Replace(
  "The helper retains the parent SID, integrity level, desktop, and ordinary read access, so this is not an AppContainer, a separate desktop, or authenticated cross-identity IPC.",
  "The helper retains the parent SID, profile/registry namespace, current process window station, and ordinary read access, so low integrity is not an AppContainer or authenticated cross-identity IPC."
)
$verifiedScope = $verifiedScope.Replace(
  "Windows direct Authenticode boundary, unsigned/malformed, Microsoft-signed, and scanned-content hash-binding regressions",
  "Windows direct Authenticode file/catalog boundary, unsigned/malformed, Microsoft-signed, and scanned-content hash-binding regressions"
)
$verifiedScope += " Additional verified boundary: Native Engine and Local Core runtime-decode the standard EICAR test marker from non-signature bytes and regression-scan their own test executables to prevent a static EICAR marker from making benign verifier binaries Defender targets. The late Native false-positive gate runs a dedicated benign integration-test target against the public production API instead of relaunching the malware-fixture-bearing unit-test harness."
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
$verifiedScope += " Additional verified boundary: app-lifetime process-snapshot and finite watch-poll completions are generation-bound; stopping or replacing a protection loop invalidates late success and error state/event publication without claiming hard cancellation of already-started operating-system or Local Core work."
$verifiedScope += " Additional verified boundary: scan cancellation is generation-bound to the exact active scan; replacement manual, scheduled, picker, and visible scan starts remain blocked until cancellation resolves; a delayed cancellation failure preserves the completed scan report; and Local Core fallback termination captures an exact active-process lease that unrelated IPC completion cannot clear or retarget."
$verifiedScope += " Additional verified boundary: every client scan receives a canonical random UUID before process start; scan IPC, progress, exact subprocess lease, cancel IPC response, and a bounded per-job runtime token remain bound to that UUID. Missing, malformed, noncanonical, mismatched, oversized, and unsafe token evidence fails visibly, while an old or wrong job token cannot cancel another scan."
$verifiedScope += " Additional verified boundary: job-bound cancellation is checked around at-most-1-MiB content-hash reads, between Native Engine detection stages, around bounded archive sample collection, before each sampled archive entry, and immediately before verdict publication. An interrupted file publishes no partial verdict and is counted with the remaining queue as unscanned; cancellation-probe corruption fails the command visibly rather than becoming cancelled, clean, or an ordinary skipped-file result."
$verifiedScope += " Additional verified boundary: bounded ZIP sampling checks cancellation before each local or central-directory entry, around stored-body copies, and before each at-most-64-KiB inflate output read. Cancellation and probe failure abort collection without publishing partial archive evidence or becoming an archive limit."
$verifiedScope += " Additional verified boundary: Native static ZIP analysis checks cancellation before parser traversal, before every local or central-directory metadata entry, around stored OOXML relationship and autorun copies, and before each at-most-64-KiB relationship or autorun inflate output read. Cancellation and checkpoint-probe failure propagate as errors, so no partial StaticAnalysis or file verdict is published and neither failure is mislabeled as an archive limit."
$verifiedScope += " Additional verified boundary: non-archive entropy 4096-byte traversal and PE section entropy use fallible checkpoints; string references stream counts without URL/path vectors while term groups, IP candidates, and UTF16 traversal checkpoint; PE section/import/debug and script term passes checkpoint. Arbitrary callback errors propagate; no partial StaticAnalysis/verdict is published, and compatibility wrappers preserve behavior."
$verifiedScope += " Additional verified boundary: Native signature, rule, and ML providers propagate the exact job-bound cancellation callback before publishing evidence; exact, masked, ASCII, UTF16, EICAR, required-context, and rule term searches checkpoint every at-most-64-KiB candidate chunk; one lowercase sample is prepared per signature or rule provider instead of per item; ML scoring checkpoints each of at most 128 weights and contributions; and bounded archive-entry static/signature/rule work uses the same fail-visible path. Local signature and rule pack discovery rejects more than 32 provider files, 256 inspected directory entries, 16 MiB aggregate pack bytes, 4,096 loaded signatures, or 4,096 loaded rules without partial activation. Compatibility wrappers preserve verdict behavior, arbitrary callback failures remain errors, and no partial provider evidence or file verdict is published."
$verifiedScope += " Additional verified boundary: signature and rule provider text normalization preserves lossy UTF-8 replacement and ASCII case-fold semantics while checking cancellation before every at-most-64-KiB input chunk and after the final chunk. Incomplete valid or malformed UTF-8 split across chunks retains one-shot compatibility; arbitrary callback failures abort before provider evidence or a file verdict is published."
$verifiedScope += " Additional verified boundary: non-archive string-indicator, script, and PE-import text normalization uses the same lossy UTF-8 and ASCII case-fold helper, checking the exact scan-job callback before every at-most-64-KiB input chunk and after the final chunk. Bounded OOXML relationship and autorun bodies propagate that callback through normalization and indicator extraction, and archive evidence fields mutate only after complete success. Arbitrary callback failures remain errors before StaticAnalysis or file-verdict publication."
$verifiedScope += " Additional verified boundary: static String Indicator groups, script terms, PE-import terms, and UTF-16 marker probes reuse one non-overlapping exact byte search that checkpoints every at-most-64-KiB candidate chunk. Cross-chunk matches and existing non-overlapping count semantics are preserved; arbitrary callback errors return before analyzer evidence or verdict publication."
$verifiedScope += " Additional verified boundary: static URL and remote network-path reference marker searches use the shared exact finder, and reference-body terminator traversal checkpoints before every at-most-64-KiB UTF-8-safe byte chunk. Existing first-match, Unicode whitespace/delimiter, count, classification, and ordering semantics are preserved; arbitrary callback errors return before StringIndicators or verdict publication."
$verifiedScope += " Additional verified boundary: structured String Indicator carrier markers, IPv4 candidates, URL query/fragment paths, remote host/share parsing, autorun lines and command tokens, optical-image markers, and email lines/fields checkpoint every at-most-64-KiB byte or UTF-8-safe character chunk. Existing CRLF, comment, token, suffix, per-line count, and conservative classification semantics are preserved; arbitrary callback errors return before StringIndicators or verdict publication."
$verifiedScope += " Additional verified boundary: Authenticode stdout and stderr drainers start before the initial authenticated handshake, four concurrent helpers complete independently without product-wide serialization, and an early child exit preserves bounded exit-status, stdout, stderr, cleanup, and reader diagnostics without retrying or accepting a trust result."
$verifiedScope += " Additional verified boundary: every successful overlapped Authenticode key delivery, key-confirmation read, response-ready read, and response ACK write obtains its authoritative byte count through GetOverlappedResult whether ReadFile or WriteFile completed pending or synchronously."
$verifiedScope += " Additional verified boundary: the Authenticode handshake transport uses local message-type/message-read-mode named-pipe framing, preserving each key-confirmation and response-binding write boundary while retaining exact overlength rejection."
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
  "desktop package builder source contracts including bounded macOS DMG transient verification retries, release-host prerequisite ready-or-blocked evidence gate, source-level dependency/lockfile evidence gate"
)
$verifiedScope += " Additional verified boundary: Native and Local Core risk fusion use overflow-safe bounded score accumulation; only positive Local Core reasons count toward evidence quality and source independence; reported Native evidence is stably prioritized by absolute decision weight, retains decisive late evidence, includes synthetic TrustStore provenance, and bounds identifiers, titles, details, and explanations at valid UTF-8 byte boundaries."
$verifiedScope += " Additional verified boundary: Native process-start behavior validates nonzero event identity before file I/O, rejects embedded-NUL command lines, preserves caller-reported bounded command omission, uses bounded UTF-8-safe head/tail command-line sampling, exact executable-name context, and distinct capped security-tamper indicators. Script-host identity alone has zero weight, command indicators remain post-start review evidence, high-risk process-start verdicts return recommendations rather than fake block success, and the behavior provider inventory explicitly disables engines missing correlated telemetry. Browser-data, credential/network, persistence-write, and parent-image lineage engines remain disabled with exact blockers. Local Core connects relevant caller-supplied app-lifetime process observations to file-plus-behavior Native review with an exact 16-review limit, a hard 16 MiB per-process executable total-read limit, exact allowlist bypass before file I/O, positive observed behavior remains review-visible despite trusted-file offsets, bounded fail-visible diagnostics, per-batch completion counters, and no process stop or quarantine action."
$verifiedScope += " Additional verified boundary: ZIP local-header sampling/static analysis and central-directory entry/local-name consistency normalize header-bounded entry names through the exact callback-aware lossy UTF-8 and ASCII case-fold helper. Arbitrary callback errors remain errors instead of malformed, limited, no-match, or clean fallback and abort before sample collection, archive evidence, or trusted entry-body use."
$verifiedScope += " Additional verified boundary: ZIP central-directory sampling and static analysis share one fallible end-of-central-directory search that checkpoints before the first candidate and every next at-most-4,096 backward candidate offsets. Existing bounded comment lookup and valid commented-archive semantics are preserved; arbitrary callback errors abort before central-directory metadata, samples, archive evidence, local-header fallback, or verdict publication."
$verifiedScope += " Additional verified boundary: PE resource-directory RVA mapping propagates the exact static-analysis callback before directory handling, before every at-most-4,096 section entries, and after an exhausted mapping search. Existing resource count, truncation, and unmapped-RVA failures are preserved; arbitrary callback errors abort before resource evidence, later PE/string evidence, StaticAnalysis, or file verdict publication."
$verifiedScope += " Additional verified boundary: Local Core path discovery checks the exact job-bound cancellation token before each root, before every at-most-128 WalkDir entries, after each root, before every at-most-128-path priority bucket, and after completed bucketing. Cancellation during discovery returns a cancelled report without scanning discovered files; malformed or mismatched token evidence aborts visibly rather than becoming cancelled, clean, or completed. Quick scans retain a 5,000-file and 8 MiB encoded-path-payload discovery cap; full/custom scans retain a 250,000-file cap and add a 128 MiB encoded-path-payload cap; reaching any cap records an incomplete discovery error and undiscovered entries are not counted or reported clean. Stable three-bucket priority classification evaluates each discovered path once, preserves within-priority order, retains all discovered paths on cancellation, and propagates arbitrary callback errors before Native Engine initialization or scan-result publication."
$verifiedScope += " Additional verified boundary: Quick discovery consumes at most 100,000 application work items within a 600-second monotonic discovery budget; full/custom discovery consumes at most 1,000,000 work items within a 3,600-second budget. One work item gates every explicit root inspection and every WalkDir iterator advance, including directories, non-candidate files, non-regular entries, errors, and the exhaustion probe. Cancellation is evaluated before the deadline at each cooperative checkpoint, including before and after retained target work and after successful zero-file Native Engine initialization, so an observed user cancellation remains Cancelled rather than a time-limit error. Quick total scan elapsed time is capped at 1,800 seconds and full/custom elapsed time at 10,800 seconds from before discovery; every discovery or total-time limit is fail-visible, counts retained unscanned files as skipped where known, cannot report clean, and keeps incomplete progress indeterminate rather than 100 percent. Native Engine unavailability skips each retained file once, bypasses target inspection, and leaves final progress indeterminate rather than publishing 100 percent. Running scans with retained zero-byte files use bounded file-count progress instead of publishing 100 percent before inspection; a running zero-file scan remains indeterminate until its terminal result."
$verifiedScope += " Additional verified boundary: Local Core propagates cancellation-first total scan elapsed classification through the exact Native Engine callback at full-file hashing, static-analysis, post-Authenticode, signature, archive, rule, heuristic, ML, and verdict checkpoints. A reached elapsed limit stops before any partial file verdict, counts the interrupted file and queued files as skipped, reports them not clean, and keeps the result incomplete. Standard Native file scans reject initial metadata or streaming growth beyond 1,073,741,824 bytes before a verdict; the existing 64 MiB analyzer sample remains unchanged."
$verifiedScope += " Additional verified boundary: Local Core and Guard automatic quarantine carry the exact originating scan SHA-256 into their quarantine boundary. Local Core requires an infected result and matching selected path; both paths require a valid expected SHA-256, matching bytes from the already-opened single-link source, and matching open-handle/path identity before mutation. A changed, replaced, malformed, or mismatched source remains in place with a visible rescan-required error and no finalized quarantine record. Manual Local Core quarantine takes a fresh bounded hash snapshot and crosses the same store boundary. Copied payloads are hash-verified before source removal and path identity is rechecked immediately before removal."
$verifiedScope += " Additional verified boundary: confirmed quarantine from a visible scan-result threat row sends that row's exact SHA-256 through bounded Local Core IPC. Local Core rejects empty, oversized, NUL-bearing, malformed, changed, or mismatched evidence before vault mutation, while the Flutter client rejects success records whose original path or SHA-256 does not match the request. The separate confirmed Quarantine file picker intentionally omits prior-verdict SHA-256 and takes a fresh bounded current-file snapshot."
$verifiedScope += " Additional verified boundary: confirmed allowlist and detection-feedback actions from a visible scan-result row send that row's exact SHA-256 through bounded Local Core IPC. Local Core independently requires explicit confirmation, validates bounded SHA-256 syntax before store or file access, rejects bytes changed since the scan verdict, and persists only matching hash-bound state. Detection feedback hashes before and after bounded feature extraction, rejects unsupported labels, and returns compact persisted label evidence. The Flutter client accepts success only when allowlist type/path/hash/active state or feedback identifier/hash/label/previous-verdict/store path exactly matches the request and response contract."
$verifiedScope += " Additional verified boundary: quarantine restore staging activates with an operating-system atomic no-replace primitive on Windows, Linux, and Apple platforms. A destination created after preflight is preserved byte-for-byte, the staged payload remains available for fail-visible cleanup, and unsupported platforms fail instead of falling back to replacement-capable rename."
$verifiedScope += " Additional verified boundary: Local Core, Guard, and the disabled Native compatibility quarantine path attempt payload ingestion with the shared operating-system atomic no-replace primitive before their existing exclusive verified copy fallback. Harmless competing-destination fixtures prove all three paths preserve both source bytes and destination bytes while retaining the atomic rename error and exclusive copy fallback error."
$verifiedScope += " Additional verified boundary: Local Core and Guard activate new quarantine finalization journals, metadata records, and authentication sidecars with the shared operating-system atomic no-replace primitive; the disabled Native compatibility metadata path uses the same boundary. Local Core status and authenticated-recovery record and sidecar updates independently use shared atomic existing-file replacement without first removing either destination name. Harmless competing-metadata fixtures prove all three owners preserve both staged bytes and competing destination bytes and fail visibly instead of overwriting the destination. Harmless existing-file fixtures prove ordinary JSON and HMAC sidecar replacement, authenticated pairing after success, missing-destination rejection, and zero temporary or backup residue."
$verifiedScope += " Additional verified boundary: small-threat MVP report schema 2 distinguishes terminal invoked-step failure from orchestration failure, records bounded command, elapsed time, status, and exact error for the failed step before rethrow, and requires dual-host rejection of missing, non-terminal, or errorless failed-step evidence."
$optionalDefenderScope = "Optional: standard EICAR file/Defender integration is skipped by default to avoid repeated Microsoft Defender DOS/EICAR_Test_File alerts; rerun with -IncludeDefenderEicar for that host integration proof."
$partialScope = "Partial: packaged desktop click-through E2E, installed local-core/service E2E, installer-owned service repair/install E2E, installed update/rollback E2E, installed UI filesystem picker flows, installed log export filesystem E2E, installed realtime watcher smoke/E2E, installed process observation service/driver loop/E2E, full release-host SBOM/license output, release-host performance baselines, and production false-positive-rate evidence."
$technicalLimits = "Technically limited: no live malware, no controlled benign multi-signed system-catalog fixture for positive secondary-catalog acceptance, Authenticode helper Job commit ceilings do not bound physical working set or I/O bytes and its user-CPU limit excludes kernel execution, the write-restricted Authenticode helper impersonation token keeps the parent SID, integrity level, desktop, and ordinary read access because WinRestrictedCodeSid is evaluated only for write access; its four-variable launch environment is attack-surface reduction and carries only parent-PID, handshake-name, SystemRoot, and WINDIR expectations rather than a secret or identity boundary, and same-process code can mutate its own environment; process-creation mitigations do not constrain the already mapped helper image or non-image data, do not isolate identity/profile/registry/desktop/read access, and can be incompatible with non-Microsoft trust providers or injected security modules; no weaker retry is configured; the inherited and read-back-verified TOKEN_MANDATORY_POLICY_NO_WRITE_UP policy enforces no-write-up but does not add no-read-up, no-execute-up, identity, profile, registry, desktop, or AppContainer isolation; TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN may also be present as a documented valid bit; unprivileged SetTokenInformation(TokenMandatoryPolicy) is not used because Windows rejected it with ERROR_PRIVILEGE_NOT_HELD and policy creation remains LSA-owned; the primary process token is privilege-stripped but not write-restricted and same-process code can technically call RevertToSelf; WinTrust/catalog execute under that primary token because the Windows trust stack failed under write restriction with error 127 on the verified host; no AppContainer, separate desktop, or cross-identity IPC is configured, no pre-execution blocking claim without a signed installed driver, no kernel realtime blocking claim, polling can miss processes that start and exit between snapshots, Guard process enumeration is disabled on unsupported non-Windows/non-Linux platforms, no installed service or OS-level polling-loop claim from app-lifetime snapshot observation, no driver-latency claim from synthetic user-mode performance evidence, no Windows Scheduled Task/background-service scheduling claim, no secure-erase claim, no machine-wide dependency installation, and no enterprise update/deployment approval claim."
$technicalLimits = $technicalLimits.Replace(
  "policy creation remains LSA-owned",
  "policy creation remains LSA-owned; canonical TokenVirtualizationAllowed may remain one because it describes inherited capability, while exact-zero TokenVirtualizationEnabled and TokenUIAccess prove inactive legacy virtualization and disabled UIAccess; trusted helper code has no enable path, but this does not remove the capability or isolate SID, profile, registry namespace, desktop/window station, ordinary reads, or inherited standard handles"
)
$technicalLimits += " Exact standard-handle binding narrows inherited helper IPC only; anonymous pipes and the nonce do not provide cross-identity authentication or encryption, prevent same-user handle duplication, or isolate the named-kernel-object namespace."
$technicalLimits += " Scan cancellation remains cooperative user-mode post-start control. Random job UUIDs and per-job runtime tokens prevent accidental cross-job cancellation and bind this client across Local Core subprocesses, but same-user code that learns a UUID remains inside the current-user capability boundary. This is not cross-identity authentication, installed service ownership, kernel cancellation, or pre-execution blocking."
$technicalLimits += " Cooperative in-engine cancellation does not hard-interrupt an already-running filesystem read, one at-most-64-KiB provider text-normalization chunk, one at-most-64-KiB signature/rule search chunk, the bounded ML contribution sort, or a Windows trust helper call. Those operations remain separately bounded where implemented; cancellation is observed at the next explicit checkpoint, and Flutter's exact-process fallback remains a last-resort user-mode process termination with visible diagnostics."
$technicalLimits += " Intra-archive sampling is cooperative, and static archive analysis cancellation does not hard-interrupt one already-running flate2 decoder read; cancellation is observed before the next at-most-64-KiB output read. ZIP metadata entry traversal is bounded to 256 entries, but cancellation is cooperative rather than preemptive."
$technicalLimits += " Non-archive static cancellation is cooperative, not preemptive: one at-most-64-KiB static text-normalization chunk, one UTF-16 decode interval, one at-most-64-KiB static term-search candidate chunk, or one separately bounded structured text traversal can complete before the next checkpoint. ZIP entry-name normalization is cooperative, not preemptive: one header-bounded name of at most 65,535 bytes can complete before the next checkpoint. Input remains bounded by the existing 64 MiB sample cap; OOXML relationship and autorun bodies remain capped at 64 KiB and 16 KiB."
$technicalLimits += " Static reference-search cancellation is cooperative, not preemptive: one at-most-64-KiB static reference-marker candidate or UTF-8-safe reference-body chunk can complete before the next checkpoint."
$technicalLimits += " Static structured-indicator cancellation is cooperative, not preemptive: one at-most-64-KiB carrier, candidate, line, token, path, host, optical-marker, or email-field chunk can complete before the next checkpoint."
$technicalLimits += " ZIP end-of-central-directory search cancellation is cooperative, not preemptive: one at-most-4,096-candidate backward search chunk can complete before the next checkpoint. The existing 65,557-byte search window is a work bound, not a deadline."
$technicalLimits += " PE resource-section mapping cancellation is cooperative, not preemptive: one at-most-4,096-section mapping chunk can complete before the next checkpoint. The PE header's u16 section count and validated in-sample section table are work bounds, not deadlines."
$technicalLimits += " Filesystem enumeration and metadata probes are cooperative, not preemptive; one operating-system directory read or metadata call plus one at-most-128-entry chunk can complete before cancellation is observed. Priority bucketing is cooperative rather than preemptive, so one at-most-128-path classification chunk can complete before cancellation is observed. The encoded path-payload cap excludes Vec, PathBuf, and allocator overhead; priority bucketing transiently owns the source path vector and destination bucket allocations."
$technicalLimits += " Discovery work-item and monotonic time budgets are cooperative rather than preemptive: one operating-system root metadata call or directory-iterator advance and one at-most-128-entry or path-classification chunk can overrun before the next checkpoint. Work items are an application-level work proxy, not an exact filesystem-I/O, syscall, kernel-work, storage-latency, CPU, or RAM bound."
$technicalLimits += " User mode cannot interrupt a kernel or filesystem call that stalls indefinitely. The elapsed budgets are checked only at explicit checkpoints and are not installed-service watchdog, signed-driver, kernel mediation, hard realtime, or pre-execution evidence."
$technicalLimits += " In-target elapsed enforcement remains cooperative: one entered filesystem, Authenticode, or other operating-system call, one at-most-1-MiB hash read, or one separately bounded analyzer/provider chunk can overrun before the next callback. The 1 GiB total-read cap bounds admitted standard scan bytes but is not a wall-clock, CPU, kernel-work, allocator, or pre-execution bound."
$technicalLimits += " Scan-verdict quarantine binding is user-mode and path-based. It detects mutation before quarantine hashing, open-handle/path replacement before move, copied-payload mismatch, and post-move payload mismatch, but it cannot atomically prevent a privileged writer or a final path swap after the last identity check and before rename or removal on every supported filesystem. Such failures remain visible or recovery-journaled; this is not kernel mediation, pre-execution blocking, or protection against administrators, SYSTEM, or kernel compromise."
$technicalLimits += " Trust-mutation hash binding is user-mode and path-based. File allowlisting remains safe after its hash snapshot because later scan suppression also requires that exact hash, while detection feedback performs bounded hashes before and after feature extraction; neither operation holds a kernel-enforced immutable file lease. A privileged writer can race path contents, and same-user code can invoke or alter same-user stores within that identity boundary. This is confirmation and stale-verdict defense, not cross-identity authorization, malware execution prevention, driver enforcement, or protection against administrators, SYSTEM, or kernel compromise."
$technicalLimits += " Atomic restore no-replace activation prevents destination overwrite on the verified Windows, Linux, and Apple primitives, but path-ancestor validation remains point-in-time and user-mode. Administrators, SYSTEM/root, kernel compromise, hostile filesystems, and ancestor replacement outside the final destination-name operation remain outside this guarantee; unsupported platforms fail visibly."
$technicalLimits += " Atomic quarantine ingestion protects only the final destination-name operation on supported Windows, Linux, and Apple primitives; source and ancestor validation remain point-in-time user-mode checks, while cross-filesystem or unsupported atomic rename safely degrades to exclusive verified copy. Administrators, SYSTEM/root, hostile filesystems, kernel compromise, and source mutation after the last identity check remain outside this guarantee. Native direct quarantine remains disabled compatibility code rather than active mutation ownership; Local Core and Guard remain the production mutation owners."
$technicalLimits += " Authenticode helper concurrency is verified with four simultaneous benign child fixtures, not an unbounded production load or installed-service stress test. Child diagnostics are lossy UTF-8-normalized and capped; any handshake or output failure remains fail-closed and produces no trusted verdict."
$technicalLimits += " The parent-child handshake is ephemeral same-user process binding, not encrypted or durable cross-identity IPC. Its random name/token and exact PID checks resist accidental substitution and unprivileged guessing but do not defeat a sufficiently privileged same-user observer, process-memory reader, kernel compromise, PID-reuse outside the live handle check, or trusted code already executing inside either bound process. It is not AppContainer/LPAC, installed LocalSystem, driver, or pre-execution evidence."
$technicalLimits += " Anonymous CreatePipe endpoints are created and connected in the parent before inheritance, so pipe process-ID APIs bind the child's three inherited handles to their parent creator but cannot prove the inheriting child PID back to the parent, prevent same-user handle duplication, or provide a secret, encrypted, durable, or cross-identity channel."
$technicalLimits += " Parent exact-Job and PID-list read-back is point-in-time process confinement, while the child's null-Job IsProcessInJob check proves only membership in some Job; neither authenticates IPC, changes identity, or proves AppContainer, installed LocalSystem, driver, or pre-execution enforcement."
$technicalLimits += " Best-effort Authenticode launch-key zeroization and fixed-buffer ownership cover only Avorax-owned fixed buffers; they do not guarantee erasure of compiler temporaries, UUID/HMAC internals, stack or register spills, allocator or OS copies, pipe buffers, process dumps, paging, same-user or privileged memory reads, or forensic recovery, and they are not secure erasure, durable secret storage, cross-identity isolation, driver, or pre-execution evidence."
$technicalLimits += " This second endpoint check narrows creation-to-connect descriptor drift but is still point-in-time same-user evidence, not cross-identity authentication, encryption, AppContainer, installed LocalSystem, driver, or pre-execution enforcement."
$technicalLimits += " Owner Rights narrows implicit owner authority but does not provide cross-identity isolation: the current-user ACE still intentionally grants protocol read/write, existing process handles and trusted same-user code remain inside the trust boundary, and privileged ownership changes, process injection, handle duplication, descriptor mutation between point-in-time checks, SYSTEM, administrators, or kernel compromise are not prevented."
$technicalLimits += " Named-pipe client-token impersonation authenticates the connected same-user helper token at one handshake message; it does not prevent same-user process injection or handle duplication, encrypt IPC, change identity or logon session, provide AppContainer/LPAC or cross-identity service authentication, or demonstrate driver/pre-execution enforcement."
$technicalLimits += " AuthenticationId and TokenSessionId binding narrows same-user cross-logon-session substitution but remains point-in-time; it does not prove token uniqueness, prevent same-logon-session injection or handle duplication, encrypt IPC, change identity, provide cross-identity authentication or AppContainer/LPAC, or demonstrate driver/pre-execution enforcement."
$technicalLimits += " TokenId and ModifiedId stability detects token replacement or mutation only across one successful client-token validation. It does not bind the impersonation token object to the launch primary-token object, prevent mutation wholly before or after that window, prevent same-session injection or handle duplication, encrypt IPC, provide cross-identity authentication or AppContainer/LPAC, or demonstrate driver/pre-execution enforcement."
$technicalLimits += " Launch-primary TokenId and ModifiedId stability is point-in-time evidence over one parent-held handle from pre-pipe capture through post-handshake read-back. It does not prove that the created child process token remains identical after creation, bind the distinct launch-primary and impersonation token objects, prevent transient mutation between snapshots or mutation after the final read-back, prevent privileged handle duplication or process injection, provide cross-identity IPC authentication or AppContainer/LPAC, or demonstrate driver/pre-execution enforcement."
$technicalLimits += " CreateProcessAsUserW produced a distinct child token object on the verified Windows host, so launch-primary and child TokenId equality is technically unavailable and is not claimed. Child process-token binding instead validates the launch identity and required restricted security profile, captures the child token's own TokenId and ModifiedId at suspended creation, and requires that exact child pair across authenticated pipe-key delivery and key confirmation. The post-response phase extends those launch/child snapshots through flushed response production, but remains point-in-time and does not bind the distinct named-pipe impersonation token object to either primary token, prevent transient replacement or mutation between snapshots or mutation after the final ACK, prevent same-session process injection or privileged handle duplication, encrypt IPC, make the final response ACK secret, provide cross-identity authentication or AppContainer/LPAC, or demonstrate driver/pre-execution enforcement. Fresh response-boundary pipe-client reauthentication proves the connected process identity and required token profile again, but Windows may create a distinct impersonation token object for each ImpersonateNamedPipeClient call, so cross-snapshot impersonation TokenId equality is unavailable and is not claimed. Response MAC binding uses a per-launch key delivered over the authenticated same-user pipe and retained in parent/child memory; it is not encryption, cross-identity authentication, durable token-object binding, or durable secret storage. Handshake key confirmation and response MAC binding use the same per-launch key with distinct fixed domains after delivery over the authenticated same-user pipe; this proves possession by data arriving on the already PID/token-bound pipe at that point, not encryption, cross-identity authentication, durable token-object binding, or durable secret storage. Removing it from the child environment narrows passive environment disclosure, but same-user process-memory read access, sufficiently privileged process injection, pipe-handle duplication, or pipe observation may recover the key or modify both stdout and MAC before authentication. Those actors may also modify key-confirmation protocol data before authentication; this does not close every transient or expand the AppContainer/LPAC, installed LocalSystem, driver, or pre-execution boundary."
$technicalLimits = $technicalLimits.Replace(
  "the write-restricted Authenticode helper impersonation token keeps the parent SID, integrity level, desktop, and ordinary read access because WinRestrictedCodeSid is evaluated only for write access",
  "the Authenticode helper keeps the parent SID, profile/registry namespace, current process window station, and ordinary read access; its primary token is low integrity and its write-restricted impersonation token adds WinRestrictedCodeSid, but neither token boundary changes identity or denies reads"
)
$technicalLimits = $technicalLimits.Replace(
  "the primary process token is privilege-stripped but not write-restricted and same-process code can technically call RevertToSelf",
  "the primary process token is low-integrity and privilege-stripped but not WRITE_RESTRICTED; same-process RevertToSelf returns to that low-integrity primary token"
)
$technicalLimits = $technicalLimits.Replace(
  "WinTrust/catalog execute under that primary token because the Windows trust stack failed under write restriction with error 127 on the verified host",
  "WinTrust/catalog execute under that low-integrity primary token because the Windows trust stack failed under write restriction with error 127 on the verified host"
)
$technicalLimits = $technicalLimits.Replace(
  "no AppContainer, separate desktop, or cross-identity IPC is configured",
  "Job UI limits supplement the private desktop by constraining documented USER/clipboard/desktop-switch/global-atom/system-setting operations but do not create a private window station, change identity, remove filesystem/registry/network/read access, or constrain named kernel objects; the private desktop isolates windows, hooks, menus, and desktop objects only within the current process window station, inherits that station's security descriptor, and does not isolate the station-wide clipboard/global atom table, SID, profile, registry namespace, filesystem/network/read access, or named kernel objects; bounded per-helper desktop heap consumption remains; no AppContainer or cross-identity IPC is configured"
)
$technicalLimits += " Quarantine metadata atomic activation protects only one final destination-name operation at a time. The record and authentication sidecar remain separate non-transactional files; a failure between their replacements can leave a mismatched pair that fails authenticated reads and may require manual recovery. Windows may preserve an adjacent .avorax-replace-backup after an ambiguous replacement failure, and its backup reservation requires same-volume hard-link support. Path and ancestor checks remain point-in-time user-mode checks. Authenticated recovery cannot make multi-file activation atomic or defend against administrators, SYSTEM/root, hostile filesystems, or kernel compromise."
$verifiedScope += " Signed update-package payload extraction uses the shared operating-system atomic no-replace primitive after bounded extraction and repeated destination-parent checks. Harmless extraction collision fixtures preserve both staged payload bytes and competing destination bytes and fail visibly instead of overwriting the destination."
$technicalLimits += " Signed update-package extraction no-replace protects only each final extracted filename on supported Windows, Linux/Android, and Apple primitives. Path and ancestor validation remains point-in-time user-mode checking; unsupported platforms fail visibly, and this does not make install-tree activation, rollback, multi-file updates, or privileged filesystem races atomic."
$verifiedScope += " Update-service staged file copy/write activation keeps absent targets on the shared atomic no-replace primitive and replaces an existing adjacent regular file without first removing its destination name. Windows reserves an adjacent previous-file hard link through no-overwrite creation, preserves every colliding candidate, and calls ReplaceFileW with a null backup parameter. It uses an opened-source identity snapshot followed by active-name rebinding, retained opened destination/reserved-backup identity checks, proof that a missing reserved backup still left the opened old destination active, identity-bound immediate reserved-backup restoration when a failed call leaves the destination absent, rejection of a mismatched backup, and preserved evidence for ambiguous states. Unix uses same-directory atomic rename, exact opened-source identity binding, and stable parent-directory synchronization."
$technicalLimits += " Existing-file atomic replacement is one loose-file operation, not a transaction across app files, service files, docs, engine components, rollback, reports, or service lifecycle. ReplaceFileW has no supported write-through flag; abrupt termination, Windows exceptional replacement states, backup cleanup failure, storage replay, or a hostile filesystem can leave a preserved adjacent .avorax-replace-backup file or the previous destination only at that backup, requiring manual review. Hard-link backup reservation requires same-volume filesystem hard-link support and fails visibly where unavailable. ReplaceFileW requires the verified staged-source handle to close before its unshared replacement-file open, so that source file-ID evidence is point-in-time until the active name is rebound after the call. Unix rename durability depends on successful parent-directory synchronization and truthful local filesystem/storage semantics. Target/source/parent and opened-handle identity checks remain point-in-time user-mode evidence; a same-identity privileged race after the final check, administrators, SYSTEM/root, hostile filesystems, or kernel compromise remain outside the guarantee. Unsupported platforms fail visibly. Windows long-path support applies only to bounded absolute local-drive and UNC paths; relative inputs retain Win32 legacy path-length behavior and device-namespace paths are rejected."
$verifiedScope += " Update-service tree replacement and rollback directory activation move validated destinations to absent backups, activate staged trees into absent destinations, and restore backups only through the shared operating-system atomic directory no-replace primitive. Harmless race fixtures prove a competing backup or destination is preserved together with the original or staged directory and every failure remains visible."
$technicalLimits += " Directory no-replace protects only the three final-name moves within each user-mode update or rollback directory activation. Service stop/start, file-item updates, cleanup, and multiple component activations are not one transaction; a process interruption can temporarily leave the original directory in its sibling backup or the destination absent until authenticated recovery runs, and a competing destination can require manual recovery from the preserved backup. Path and ancestor checks remain point-in-time; unsupported platforms fail visibly, and administrators, SYSTEM/root, hostile filesystems, or kernel compromise remain outside the guarantee."
$verifiedScope += " Authenticated update directory recovery uses a private per-install store, machine-bound DPAPI key protection on Windows, owner-only key storage on Unix, HMAC-bound strict journals, an exclusive cross-process lock, exact allowlisted path derivation, bounded parsing, and harmless state fixtures to restore the backup-move gap or finish completed cleanup without overwriting a competing object."
$technicalLimits += " Directory activation recovery is per-tree and next-start/best-effort; it is not a power-loss-proof package transaction, does not make service/file/multiple-component activation atomic, and cannot defeat administrators, SYSTEM/root, hostile filesystems, key deletion, storage write reordering, or kernel compromise. Ambiguous or unauthenticated state is preserved and requires manual review. A crash during pre-journal staging copy leaves an orphan that is detected and blocked for manual review."
$verifiedScope += " Update recovery source and verifier contracts pin dedicated Ubuntu 24.04 execution of harmless Unix recovery fixtures plus exact owner-only 0700 recovery-directory and 0600 key, lock, and journal modes, including permission repair before authenticated recovery."
$technicalLimits += " The local verifier checks the Unix recovery runtime contract from Windows; actual Unix permission semantics require the hosted ubuntu-24.04 job. Owner-only modes do not encrypt the Unix key and cannot defend against root, administrators, hostile filesystems, storage rollback/reordering, or kernel compromise. Permission repair cannot undo prior disclosure of a broadened Unix recovery key or journal, revoke already-open handles, or restore authenticity after the key was copied; such state requires key replacement and manual review. macOS and Android recovery runtime remain unverified."
$verifiedScope += " Update recovery source and verifier contracts pin dedicated hosted macOS 15 execution of the harmless Unix recovery fixtures, exact owner-only 0700 recovery-directory and 0600 key, lock, and journal modes, and permission repair before authenticated recovery."
$technicalLimits += " The local verifier checks the macOS recovery runtime route from Windows; actual macOS permission semantics require the hosted macos-15 job. This route exercises one hosted macOS 15 runner environment, not every macOS version, architecture, filesystem, installed service identity, or Android recovery runtime. Unix mode bits do not encrypt the recovery key, undo prior disclosure, revoke already-open handles, or resist root, administrators, hostile filesystems, storage rollback/reordering, or kernel compromise."
$verifiedScope += " Windows update activation renames request MOVEFILE_WRITE_THROUGH. Unix recovery namespace changes synchronize stable directory handles after key, lock, journal, rename, and cleanup mutations. A post-rename namespace synchronization failure fails visibly and preserves the authenticated journal plus activation directories for a later recovery pass."
$technicalLimits += " Durability barriers are best-effort user-mode filesystem evidence, not a power-loss-proof package transaction. Windows removal durability, storage hardware truthfulness, hostile filesystems, and multi-component atomicity remain unverified. Directory synchronization may fail after a namespace mutation; Avorax then reports the failure and preserves authenticated recovery evidence instead of claiming a durable success."
$verifiedScope += " Update recovery cleanup first moves staging or backup trees into exact typed no-replace cleanup tombstones, then retires the HMAC-authenticated active journal through a distinct cleanup-journal name. A later recovery pass resumes bounded recognized cleanup, while malformed names, conflicting dispositions, tampered cleanup journals, active-name residue, and ambiguous states remain fail-visible and preserved."
$technicalLimits += " Cleanup tombstones reduce stale active-name ambiguity but do not prove Windows same-volume rename or deletion persistence, storage write ordering, power-loss atomicity, or hostile-filesystem behavior. A replay or reordering that restores an active staging or backup name after its authenticated journal became a cleanup journal still fails closed for manual review; administrators, SYSTEM/root, storage rollback, and kernel compromise remain outside the guarantee."
$verifiedScope += " Update-service tree cleanup performs a bounded no-mutation inventory before removal, validates every nested entry and path chain against links or reparse points, then removes only revalidated regular files and empty directories with visible errors."
$technicalLimits += " Bounded tree cleanup caps 100,000 entries, depth 128, eight GiB of logical regular-file bytes, and 16 MiB of aggregate encoded path payload; it deliberately fails and preserves remaining state when a limit, unsupported kind, concurrent change, or removal error is observed. Inventory and per-entry revalidation are point-in-time user-mode checks; they do not defeat administrators, SYSTEM/root, same-identity hostile filesystem races, open-handle mutation, storage replay, kernel compromise, or prove durable deletion."
$pathAdditions = @(
  "C:\Program Files\Git\cmd",
  "C:\Users\Brent\develop\flutter\bin",
  "C:\Users\Brent\.cargo\bin"
) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
$previousPath = $env:PATH
$previousDontWriteBytecode = $env:PYTHONDONTWRITEBYTECODE
$results = New-Object System.Collections.Generic.List[object]
$startedAll = Get-Date
$overallTimer = [System.Diagnostics.Stopwatch]::StartNew()
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
    $results.Add((Invoke-Step "local-core file-discovery cancellation and bounds regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "file_discovery_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core file-discovery path-memory and priority cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "file_discovery_memory_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core scan discovery work and elapsed-budget regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "resource_budget_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native/local in-target scan inspection resource-budget regressions" $repo $cargo @("test", "--workspace", "scan_inspection_resource_budget_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core heuristic signal regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "heuristic", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core static-feature extraction regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "static_feature", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core app-control policy regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "app_control", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core trust-store boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "trust_store", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core allowlist persistence regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "allowlist", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core training-label feedback regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "training_label", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "platform quarantine permission regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_platform_security\Cargo.toml", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "quarantine restore atomic no-replace regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_platform_security\Cargo.toml", "quarantine_restore_no_replace", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "quarantine ingest atomic no-replace regressions" $repo $cargo @("test", "--workspace", "quarantine_ingest_no_replace", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "quarantine metadata atomic activation regressions" $repo $cargo @("test", "--workspace", "quarantine_metadata_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core quarantine metadata regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "quarantine", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core manual threat quarantine hash-binding regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "manual_threat_quarantine_binding_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core scan cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "scan_cancellation", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "scan job-bound cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "scan_cancellation_is_bound_to_exact_job_and_validated", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "cooperative in-engine cancellation regressions" $repo $cargo @("test", "--workspace", "cooperative_scan_cancellation", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "cooperative archive collection cancellation regressions" $repo $cargo @("test", "--workspace", "cooperative_archive_cancellation", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine static archive analysis cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "static_archive_cancellation", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine non-archive static analysis cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "non_archive_static_cancellation", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine custom provider cancellation and pack-limit regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_provider_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine provider text-normalization cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_provider_normalization_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine static text-normalization cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "static_text_normalization_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine ZIP entry-name normalization cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "zip_name_normalization_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine ZIP EOCD search cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "zip_eocd_cancellation_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine PE resource-section cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "pe_resource_section_cancellation_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine static term-search cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "static_term_search_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine static reference-search cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "static_reference_cancellation_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine static structured-indicator cancellation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "static_structured_indicator_cancellation_", "--", "--test-threads=1")))
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
    $results.Add((Invoke-Step "native-engine native Windows root regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_windows", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine direct Authenticode boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "windows_authenticode::tests", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine direct Authenticode unsigned/malformed regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_direct_authenticode_rejects", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine direct Authenticode Microsoft-signed/hash-binding regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_direct_authenticode_microsoft_signed", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine catalog Authenticode Microsoft-signed/hash-binding regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_catalog_authenticode", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine secondary catalog Authenticode selection regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_secondary_catalog_authenticode", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine secondary embedded Authenticode Microsoft-signed regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_secondary_authenticode", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper isolation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode parallel helper lifecycle regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_lifecycle", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper Job resource-limit regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_job_limits", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper Job UI-restriction regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_job_ui_restrictions", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper Job membership regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_job_membership", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper private-desktop regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_private_desktop", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper standard-handle binding regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_standard_handle", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper pipe-peer process regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_pipe_peer_process", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper parent-child handshake regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_parent_child_handshake", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode handshake pipe security read-back regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_handshake_pipe_security_readback", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode handshake client security read-back regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_handshake_client_pipe_security_readback", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode handshake pipe least-privilege DACL regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_handshake_pipe_dacl_least_privilege", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode handshake pipe owner-rights regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_handshake_pipe_owner_rights", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode handshake pipe client-token regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_handshake_pipe_client_token", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode handshake client logon-session regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_handshake_client_logon_session", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode handshake client token-stability regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_handshake_client_token_stability", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode launch token-stability regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_launch_token_stability", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode child process-token binding regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_child_process_token_binding", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode post-response token-stability regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_post_response_token_stability", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode response client-reauthentication regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_post_response_client_reauthentication", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode response hash-binding regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_response_hash_binding", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode response launch-key MAC regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_response_mac_binding", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode pipe-delivered launch-key regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_pipe_delivered_launch_key", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode launch-key confirmation HMAC regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_handshake_key_confirmation", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode launch-key zeroization regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_launch_key_zeroization", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode fixed launch-key buffer regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_launch_key_fixed_buffer", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper restricted-thread-token regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_restricted_thread_token", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper restricted-process-token regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_restricted_process", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper low-integrity-primary-token regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_low_integrity", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper mandatory no-write-up policy regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_mandatory_policy", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper virtualization/UIAccess token regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_token_safety_flags", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper sanitized-launch regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_sanitized", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper process-mitigation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_process_mitigation", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode helper write-restricted-thread-token regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_helper_write_restricted", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine Authenticode mandatory-hash/file-identity regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_authenticode_file_identity", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine known-good hash regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "known_good", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine known-bad hash regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "known_bad", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine allowlist boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "allowlist", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine quarantine trust regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "quarantine_trust", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine detection-only mutation boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "native_mutation_boundary", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine rule pack coverage" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "rule_pack_loads", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine archive traversal analyzer" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "archive_zip_slip", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine large-file sample bounds" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "large_file_scan_reports_full_hash_and_sample_limit", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine script rule verdict" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "encoded_powershell_rule_returns_probable", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine family indicator fusion" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "indicator_combination_is_probable", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine downloader verdict fusion" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "script_downloader_indicator_becomes_probable", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine normal executable false-positive guard" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "--locked", "--test", "benign_false_positive_gate", "benign_normal_executable_remains_non_malicious", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine risk fusion regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "risk_fusion", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "native-engine bounded process behavior regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_native_engine\Cargo.toml", "process_behavior", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core Native process observation wiring regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "native_process_review", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "local-core bounded risk fusion regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_local_core\Cargo.toml", "bounded_risk_fusion", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service guard-mode config regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "guard_mode", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service known-bad cache regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "known_bad", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service quarantine metadata regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "quarantine", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service driver IPC boundary regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "driver_ipc", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service driver-health probe regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "driver_health", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service native Windows root regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "windows_system", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service self-test regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "self_test", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service process observation regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "process_watch", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service process collection coverage regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "process_collection", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "guard-service process skip regressions" $repo $cargo @("test", "--manifest-path", "core\zentor_guard_service\Cargo.toml", "process_skip", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service staged file activation atomic replacement regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "staged_activation_atomic_replace_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service payload extraction atomic no-replace regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "payload_extraction_no_replace", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service directory activation atomic no-replace regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "directory_activation_no_replace", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service authenticated directory activation recovery regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "activation_recovery", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service Unix activation recovery runtime contract" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "activation_recovery_unix_runtime_contract_is_wired", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service macOS activation recovery runtime contract" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "activation_recovery_macos_runtime_contract_is_wired", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service activation recovery namespace durability regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "activation_recovery_durability_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service activation recovery cleanup tombstone regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "activation_recovery_cleanup_", "--", "--test-threads=1")))
    $results.Add((Invoke-Step "update-service bounded non-following tree cleanup regressions" $repo $cargo @("test", "--manifest-path", "core\avorax_update_service\Cargo.toml", "checked_tree_cleanup_", "--", "--test-threads=1")))
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
    $results.Add((Invoke-Step "guard-service release binary build" $repo $cargo @("build", "--release", "--manifest-path", "core\zentor_guard_service\Cargo.toml")))
    $releaseGuardPath = Join-Path $repo "target\release\zentor_guard_service.exe"
    $results.Add((Invoke-Step "release Authenticode isolated helper IPC/hash-binding smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-authenticode-helper-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath, "-GuardPath", $releaseGuardPath, "-RepoRoot", $repo)))
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
    $results.Add((Invoke-Step "release local-core binary trust-mutation hash-binding smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-release-local-core-trust-mutation-binding-smoke.ps1", "-LocalCorePath", $releaseLocalCorePath)))
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
    $results.Add((Invoke-Step "Flutter protection-loop stale-generation tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "--plain-name", "stale protection loop generation")))
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
    $results.Add((Invoke-Step "Flutter scan cancellation generation/process-ownership tests" $clientRoot $flutter @("test", "test\offline_scan_test.dart", "test\local_core_ipc_diagnostics_test.dart", "test\scan_screen_test.dart", "--plain-name", "scan cancellation")))
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
  $results.Add((Invoke-Step "Small-threat MVP failed-step report smoke" $repo $powershell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools\testing\run-small-threat-mvp-failed-step-report-smoke.ps1", "-RepoRoot", $repo, "-PythonPath", $python, "-FlutterPath", $flutter, "-DartPath", $dart, "-PowerShell7Path", $powerShell7)))
  $results.Add((Invoke-Step "Python source contracts" $repo $python @("-B", "tools\testing\run-python-source-contracts.py")))
  $results.Add((Invoke-Step "Desktop package builder source contracts" $repo $python @("-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_packaging_tools.py", "-v")))
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
  $elapsedAll = $overallTimer.Elapsed.TotalSeconds
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
  Invoke-SmallThreatMvpReportValidator $repo $verificationReportPath $powershell $powerShell7 $requireFullReportValidation
} catch {
  $elapsedAll = $overallTimer.Elapsed.TotalSeconds
  $errorMessage = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
  if ($null -ne $script:SmallThreatMvpFailedStepResult) {
    $results.Add($script:SmallThreatMvpFailedStepResult)
    $script:SmallThreatMvpFailedStepResult = $null
  }
  try {
    $failureReport = New-SmallThreatMvpVerificationReport "failed" $repo $startedAll $elapsedAll $results $python $cargo $flutter $dart $powershell ([bool]$IncludeDefenderEicar) ([bool]$SkipFlutter) ([bool]$SkipRust) $protectionSelfTestReport $dependencyEvidenceReport $performanceGateReport $performanceBenchmarkReport $bundledPackInventoryReport $noEicarHarmlessThreatReport $installedCoreLifecycleReport $releasePrereqHostReport $verifiedScope $optionalDefenderScope $partialScope $technicalLimits $errorMessage
    Write-SmallThreatMvpVerificationReport $verificationReportPath $failureReport
  } catch {
    Write-Warning "Could not write small-threat MVP failure report: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  throw
} finally {
  $overallTimer.Stop()
  $env:PATH = $previousPath
  if ($null -eq $previousDontWriteBytecode) {
    if (Test-Path Env:\PYTHONDONTWRITEBYTECODE) {
      Remove-Item Env:\PYTHONDONTWRITEBYTECODE -ErrorAction Stop
    }
  } else {
    $env:PYTHONDONTWRITEBYTECODE = $previousDontWriteBytecode
  }
}
