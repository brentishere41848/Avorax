# Known Avorax Blockers

Date: 2026-05-30

This file tracks blockers that must be reported honestly and must not be represented as completed protection.

## Current Supersession Notes

- Checkpoint 1647 supersedes several older source-only Rust blockers with focused runtime evidence on this Windows host: local-core ProgramData/config/migration/service-status/local ACL/ClamAV/YARA/AI/native-asset locator fixtures, Guard self-test/post-launch/hash-read/ClamAV fixtures, native product/quarantine trust-root and Microsoft/AuthentiCode fixtures, and signature-compiler source/output fixtures now have matching Cargo tests. Filters that matched `0 tests`, including non-Windows service-mode and Guard ACL filters, remain blocked/partial and must not be claimed.
- Checkpoint 1648 reduces local-core/Guard warning debt and verifies full local-core (`411`) plus Guard (`212`) tests without captured warnings. Compatibility/development modules remain guarded/partial where documented; scoped `allow` attributes must not be treated as proof that dormant controls are active protection.
- Checkpoint 1759 refreshes the blocker register after the local toolchain became available: Flutter/Dart, Cargo/rustfmt, and Git executables are available through explicit paths on this host, and missing-toolchain blockers are historical unless a row names a different environment. The current blockers are now host/release prerequisites: no `.git` metadata in this copied checkout, runtime-only `.NET` with no SDKs, missing Visual Studio Desktop C++ components, unavailable Windows symlink support, missing Flutter Windows `Avorax.exe`, missing installer stage/MSI/setup artifacts, and absent signed-driver/installed-service E2E proof.
- Checkpoint 1760 adds a current verification snapshot that separates verified, partial, blocked, and technically limited surfaces. Current proof covers explicit tool versions, Rust release check/build health, release service binary presence, and repo/source safety gates; release approval remains blocked by no `.NET SDK` inventory, unavailable symlink support, missing Visual Studio Desktop C++ components, missing Windows `Avorax.exe`/installer stage, no installed service/UI E2E, no `.git` metadata, and no signed-driver/pre-execution validation.
- Checkpoint 1870 refreshes release-prerequisite host-only evidence and hardens that evidence path: `avorax-release-prereq-check.ps1` now refuses report paths that resolve outside the repository. The current host-only report remains `ok=false` for three real host blockers: no .NET SDK inventory, unavailable symlink support/Developer Mode, and missing Visual Studio Desktop C++ components.
- Checkpoint 1935 refreshes Windows desktop build-readiness evidence on the current host: Flutter 3.44.4 and Windows desktop device discovery work, but `flutter build windows --debug --no-pub` still fails immediately on Flutter plugin symlink support, host-only release prerequisite evidence writes `dist\release-prereq\host_only_1935.json` with exactly three host errors, and `dotnet --list-sdks` confirms the available `C:\Program Files\dotnet\dotnet.exe` is runtime-only with no SDKs. Windows `Avorax.exe`, installer stage/MSI/setup artifacts, installed service/UI E2E, and signed-driver validation remain blocked.
- Checkpoint 2135 promotes host-only release prerequisite evidence into the small-threat MVP verifier: `generated_reports.release_prereq_host` now points to `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-release-prereq-host.json`, and the full-suite report validator rejects passed reports that omit the prereq report, step, or scope. The current host still records `ok=false` for three actionable release-host blockers: .NET SDK inventory is empty even though `C:\Program Files\dotnet\dotnet.exe` exists, Windows symlink support is unavailable for Flutter plugin builds, and Visual Studio Desktop C++ components are missing. This is an honest blocker, not a failed scanner MVP run.
- Checkpoint 1956 folds Guard Service fixture coverage into the one-command small-threat MVP verifier: `guard_mode` (`17`), `known_bad` (`16`), `quarantine` (`32`), `driver_ipc` (`49`), `driver_health` (`16`), `self_test` (`16`), `process_watch` (`1`), and `process_skip` (`1`) all passed on this Windows host, and the expanded verifier passed in `183.3s`. Installed Guard Service operation, signed-driver IPC, elevated service control, and pre-execution blocking remain unverified or blocked.
- Checkpoint 1957 adds update-service signed package/update regressions to the one-command small-threat MVP verifier and strengthens the verifier with real benign signed `.aup` fixtures: valid Ed25519 manifest/payload verification passes, tampered manifest signatures fail, and tampered payload hashes fail. The update-service crate passes (`180`), source-contracts pass (`513`), and the expanded verifier passes in `229.7s`. Production signer ceremony, installed update-service operation, signed release package staging, MSI integration, and installed update/rollback E2E remain unverified.
- Checkpoint 1958 adds the false-positive gate to the one-command small-threat MVP verifier. The gate passed on this host and keeps benign fixture corpus presence, local-core installer/tool suppression, native installer/MSI trust, and Guard unknown-app labeling regressions in the MVP sweep; source-contracts pass (`513`) and the expanded verifier passes in `189.8s`. Production false-positive-rate evidence remains unverified and must not be inferred from fixture-only gates.
- Checkpoint 1959 adds the non-driver protection gate to the one-command small-threat MVP verifier. The verifier now writes a synthetic self-test fixture with `driver.running=false`, `pre_execution_blocking_available=false`, and `unknown_unsigned_lockdown_blocked_before_launch=false`, then runs `tools\security\zentor-protection-gate.ps1` without `-DriverFeatureEnabled`; the expanded verifier passes in `197s`. This proves Guard/policy verdict gate wiring only and still does not prove signed-driver IPC, installed service behavior, kernel blocking, or pre-execution blocking.
- Checkpoint 1960 adds the branding gate to the one-command small-threat MVP verifier. The gate passed on this host and keeps old product/gaming branding terms out of active source/doc copy before product-copy and security gates run; the focused gate sweep passes in `15.5s` with `Branding gate` green (`1.6s`), and the full expanded verifier passes in `192.6s`. Full packaged release-host branding validation remains separate from source/repo gate proof.
- Checkpoint 1961 adds a bounded JSON verification report to the one-command small-threat MVP verifier. The full verifier writes `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-verification-report.json` with schema version, status, exact tool paths, options, generated report paths, step commands/timings, scope text, partial items, and technical limits; the expanded verifier passes in `191.9s` and the report records `98` steps with no Rust/Flutter skips. An out-of-repo `-ReportPath` is rejected before the sweep starts. This strengthens reproducible evidence but does not replace installed/package/driver E2E proof.
- Checkpoint 1962 adds `tools\testing\validate-small-threat-mvp-report.ps1` so the structured small-threat MVP report can be checked independently after a run. The validator passed against the full `1961` report with `-RequireFullSuite`, rejected a `passed` report with no steps, rejected a `failed` report with no error, rejected an out-of-repo report path, and source-contracts pass (`514`). This improves evidence hygiene only; it does not make installed UI/service/driver/release-host blockers complete.
- Checkpoint 1963 wires the report validator into the one-command small-threat MVP verifier success path. A successful verifier run now writes the JSON report and immediately validates it; full non-Defender/non-skip runs use `-RequireFullSuite`, while skip/optional-Defender runs use structural validation only. The focused skip verifier passed in `15.9s`, the full verifier passed in `192.8s` with `98` steps, and the post-write full-suite validator passed in `0.5s`. This prevents a malformed success report from being treated as a completed verifier run but still does not replace installed UI/service/driver/release-host proof.
- Checkpoint 1964 removes the remaining `SilentlyContinue` match from the active PowerShell tool/script smoke-gate set by making `run-safe-allowlist-smoke.ps1` fail visibly if quarantine-payload enumeration fails. The safe allowlist smoke passed with an allowlisted simulator and zero quarantined files, source-contracts pass (`514`), and the targeted `rg` check over testing/security/perf/branding/windows/driver scripts has no `SilentlyContinue` matches. This strengthens test honesty only; it is not installed service, UI, driver, or release-host proof.
- Checkpoint 1965 makes `evaluate_process_snapshot` fail visibly when IPC omits `process_observations`, instead of defaulting to a successful empty snapshot. Focused local-core `process_snapshot` tests pass (`4`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `196.4s` with `98` steps plus report validation. This strengthens snapshot evidence honesty only; local process monitoring remains snapshot-only and does not prove an installed active polling loop.
- Checkpoint 1966 replaces the Windows app-detector `tasklist.exe` CSV snapshot path with checked local PowerShell/CIM JSON collection, without an app-detector execution-policy override, preserving `pid`, `parent_pid`, `image_path`, and optional `command_line` evidence for Local Core suspicious-process rules. Focused Flutter app-detector tests pass (`10`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `194.7s` with `98` steps plus report validation. This strengthens snapshot evidence quality only; local process monitoring remains snapshot-only and does not prove an installed active polling loop.
- Checkpoint 1967 adds an app-lifetime, best-effort user-mode process snapshot loop tied to a successful Flutter protection start. The loop runs every two minutes through an injectable timer, has no immediate host process read at start, uses a single-flight guard, logs empty/evaluated/suspicious/failed events visibly, and stops on protection stop or controller dispose. Focused protection tests pass (`26`), app visual policy tests pass (`58`), process snapshot event/IPC tests pass (`1`/`6`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `187s` with `98` steps plus report validation. This is not an installed service/driver loop, kernel blocking, or pre-execution blocking.
- Checkpoint 1968 deduplicates repeated routine process snapshot loop info events while preserving every timer evaluation and every warning/failure event. Focused protection tests pass (`27`), app visual policy tests pass (`58`), process snapshot event tests pass (`1`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `187.8s` with `98` steps plus report validation. This improves bounded local history quality only; installed service/driver process observation and kernel/pre-execution blocking remain unverified or blocked.
- Checkpoint 1969 surfaces app-lifetime process snapshot loop timer-start failures in the visible Flutter state error text as well as the `protection_start_limited` event. Focused protection tests pass (`28`), app visual policy tests pass (`58`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `189.5s` with `98` steps plus report validation. This improves failure visibility only; installed service/driver process observation and kernel/pre-execution blocking remain unverified or blocked.
- Checkpoint 1970 adds explicit Flutter state/UI visibility for the app-lifetime process snapshot loop. The Protection screen now surfaces `active`, `attention`, `limited`, or `off` loop state with bounded details, and controller tests prove start, suspicious ticks, timer-start failure, detector/IPC failure, routine dedupe, and stop update that state without adding installed service/driver or pre-execution claims. Focused protection tests pass (`28`), app visual policy tests pass (`58`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `189.9s` with `98` steps plus report validation.
- Checkpoint 1971 aligns the one-command small-threat MVP verifier scope text with checkpoint 1970, so generated reports now explicitly list app-lifetime process snapshot loop `state/UI visibility` as verified evidence rather than only controller/event evidence. Source-contracts pass (`514`), the focused no-Rust/no-Flutter verifier passes in `15.9s`, and the full self-validating small-threat MVP verifier passes in `188.7s` with `98` steps plus report validation. This improves report honesty only; installed service/driver process observation and kernel/pre-execution blocking remain unverified or blocked.
- Checkpoint 1972 extends Protected Apps process snapshot evidence to include active-protection `process_snapshot_loop_*` events. The widget layer now renders a suspicious loop finding and bounded details in the same evidence panel as app-detection snapshots, while keeping the same no-driver/no-pre-execution limits. Focused Protected Apps tests pass (`9`), app visual policy tests pass (`58`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `189.4s` with `98` steps plus report validation.
- Checkpoint 1973 makes Protected Apps select the newest matching process snapshot evidence by `createdAt` instead of trusting local-event list order. A focused widget test injects an older app-detection snapshot before a newer active-protection loop failure and verifies the newer failure is visible while the stale evidence is hidden. Focused Protected Apps tests pass (`10`), app visual policy tests pass (`58`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `191.2s` with `98` steps plus report validation.
- Checkpoint 1974 adds visible UTC recency evidence to the Protected Apps process snapshot panel. When a process snapshot/app-lifetime loop event is shown, the panel now renders `Evidence time (UTC): ...`, and the existing newest-event widget test verifies the newer loop failure timestamp is visible. Focused Protected Apps tests pass (`10`), app visual policy tests pass (`58`), source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `192.1s` with `98` steps plus report validation.
- Checkpoint 1975 aligns the one-command small-threat MVP verifier scope text with checkpoints 1973-1974, so generated reports explicitly list Protected Apps process-evidence newest ordering and UTC timestamp visibility. Source-contracts pass (`514`), the focused no-Rust/no-Flutter verifier passes in `15.5s`, and the full self-validating small-threat MVP verifier passes in `191.6s` with `98` steps plus report validation. This improves report honesty only; installed service/driver process observation and kernel/pre-execution blocking remain unverified or blocked.
- Checkpoint 1976 makes the report validator enforce the checkpoint 1975 Protected Apps process-evidence wording for full-suite reports. `validate-small-threat-mvp-report.ps1 -RequireFullSuite` now fails when `verification_scope.verified` omits `Protected Apps process-evidence newest ordering plus UTC timestamp visibility`; a negative temporary report fixture proves the failure path, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `191.7s` with `98` steps plus report validation. This improves report integrity only; installed service/driver process observation and kernel/pre-execution blocking remain unverified or blocked.
- Checkpoint 1977 hardens app-lifetime scheduled quick-scan concurrency: scheduled timer fires are skipped with `scheduled_quick_scan_skipped` instead of logging `scheduled_quick_scan_started` when a custom target selection is active, Scan/Home/Protection quick-scan controls treat target selection as scan-busy, and scan action-mode changes are rejected during target selection with scan warning evidence. The full-suite report validator now also requires `app-lifetime scheduled quick scans including target-selection skip and scan-mode busy guards`; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `191.2s` with `98` steps plus report validation. This is still app-lifetime Flutter controller/UI proof only, not Windows Scheduled Task/background-service scheduling, packaged desktop click-through E2E, installed service behavior, or pre-execution blocking.
- Checkpoint 1978 closes the remaining Flutter controller target-selection race for direct `runQuickScan`, `runFullScan`, and quarantine original-rescan calls. These paths now log `scan_start_ignored`, set a visible scan error, and make no Local Core scan IPC while target selection is active; the client UI inventory now accounts for the Quarantine `Scan original path` control. The small-threat verifier includes `Flutter scan concurrency controller tests`, the full-suite report validator requires `scan concurrency target-selection controller guards`, the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `193.8s` with `99` steps plus report validation. This is still Flutter controller/runtime proof only; installed desktop click-through E2E, installed local-core/service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1979 blocks direct Custom File/Folder target selection while a scan is starting or running, before `openFile()` or `getDirectoryPath()` can launch an OS picker. Blocked custom scan requests now log `scan_target_selection_busy`, keep `scanTargetSelectionInFlight=false`, and make no Local Core scan IPC. The full-suite report validator now also requires `custom-picker scan-busy controller guards`; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `207.2s` with `99` steps plus report validation. This is Flutter controller/runtime proof only; installed OS picker click-through, installed local-core/service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1980 extends protection self-test controller busy-state enforcement to public Flutter state drift: direct `runProtectionSelfTest` calls now reject when either private in-flight flags or public `state.protectionSelfTestInFlight`/`state.protectionOperationInFlight` are busy, emit `protection_self_test_busy`, keep busy state honest, and make no Local Core self-test IPC. The full-suite report validator now also requires `protection self-test public busy-state guards`; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `205.9s` with `99` steps plus report validation. This is Flutter controller/runtime proof only; installed desktop click-through, installed Guard/local-core service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1981 extends protection start/stop controller busy-state enforcement to public Flutter state drift and self-test overlap. Direct `startProtection` and `stopProtection` calls now reject when either private/public protection-operation busy state or private/public self-test busy state is active, emit `protection_action_busy`, preserve the busy flags, and make no Guard mode/watch/stop-watch Local Core IPC. The full-suite report validator now also requires `protection action public busy-state guards`; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `207.6s` with `99` steps plus report validation. This is Flutter controller/runtime proof only; installed desktop click-through, installed Guard/local-core service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1982 aligns the Home and Protection start/stop UI with the controller guard by disabling those controls when public `protectionSelfTestInFlight` is true, even if `loading` is not set. The full-suite report validator now also requires `protection start-stop self-test-busy UI guards`; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `202.8s` with `99` steps plus report validation. This is Flutter widget/source/runtime proof only; installed desktop click-through, installed Guard/local-core service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1983 blocks security settings changes while protection start/stop or protection self-test is busy. The shared `_beginSecuritySettingsAction` now rejects protection mode, ransomware guard, and scheduled quick-scan settings changes before Guard/ransomware IPC or schedule persistence, emits visible `security_settings_action_busy` warning evidence, and preserves public busy flags; Settings dropdowns, text fields, switch, interval dropdown, and save button are disabled during protection-operation or self-test busy state. The full-suite report validator now also requires `security settings protection-busy controller/UI guards`; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `201.4s` with `99` steps plus report validation. This is Flutter controller/widget/runtime proof only; installed desktop click-through, installed Guard/local-core service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1984 blocks configuration reset while protection start/stop or protection self-test is busy. Direct `resetConfiguration` calls now reject before setting reset-in-flight state, stopping protection, or touching config persistence, emit visible `configuration_reset_busy` warning evidence, and preserve public busy flags; duplicate reset still keeps precedence over protection-busy warnings. The Settings reset button is disabled during protection-operation or self-test busy state. The full-suite report validator now also requires `configuration reset protection-busy controller/UI guards`; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `218.3s` with `99` steps plus report validation. This is Flutter controller/widget/runtime proof only; installed desktop click-through, installed Guard/local-core service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1985 blocks scan starts while security settings writes or configuration reset are busy. Quick/full/custom scans and quarantine original rescan now reject before target planning, auto-action confirmation, OS picker launch, rescan-request logging, scan-start state, or Local Core scan IPC, and `_scanPaths` has the same fallback guard; Home, Scan, and Protection scan controls disable during security-settings or reset busy state. The full-suite report validator now also requires `scan start configuration-busy controller/UI guards`; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `251s` with `99` steps plus report validation. This is Flutter controller/widget/runtime proof only; installed desktop click-through, OS picker E2E, installed local-core/service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1986 blocks manual trust and quarantine mutations while security settings writes or configuration reset are busy. Direct quarantine, restore, delete, allowlist add/remove, and detection-feedback calls now reject before Local Core IPC, emit the existing visible busy warning categories, and preserve public busy flags; security-settings changes and configuration reset also reject while quarantine, allowlist, or detection-feedback actions are busy. Scan-result, Quarantine, Allowlist, and Settings controls disable during the matching busy states. The full-suite report validator now also requires `manual trust actions configuration-busy controller/UI guards` and the `Flutter settings busy-state UI tests` step; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `217.4s` with `100` steps plus report validation. This is Flutter controller/widget/runtime proof only; installed desktop click-through, installed local-core/service behavior, OS picker/elevation behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.
- Checkpoint 1987 blocks direct `Keep / Ignore` controller calls while security settings writes or configuration reset are busy. Direct `ignoreThreat` now rejects before setting `threatIgnoreActionInFlight`, writing `threat_ignored`, or changing the scan row to ignored; blocked calls preserve public busy flags and emit `threat_ignore_busy` warning evidence. The full-suite report validator now also requires `threat ignore configuration-busy controller guard` and the `Flutter threat-ignore controller tests` step; the negative missing-scope fixture fails as expected, source-contracts pass (`514`), and the full self-validating small-threat MVP verifier passes in `225.3s` with `101` steps plus report validation. This is Flutter controller/runtime proof only; installed desktop click-through, installed local-core/service behavior, signed-driver/pre-execution blocking, and production false-positive-rate evidence remain partial, blocked, or technically limited.

## Environment Blockers

- Superseded on the current Windows validation host by checkpoint 1623: Flutter is available through `C:\Users\Brent\develop\flutter\bin`, and `apps\zentor_client` passes `flutter analyze` plus `flutter test --reporter compact` with `464 passed`. Linux/container validation may still need its own Flutter toolchain if that environment is used for release gates.
- Flutter Windows desktop artifact creation remains blocked on this host until symlink support/Developer Mode or an approved symlink-capable build host is available; checkpoint 1935 reconfirms `flutter build windows --debug --no-pub` fails immediately with Flutter's plugin symlink-support prerequisite message.
- Superseded on the current Windows validation host by checkpoint 1548: Dart is available through the installed Flutter SDK, and `packages/zentor_protocol` passes `dart format --set-exit-if-changed lib test`, `dart analyze`, and `dart test --reporter expanded`. Linux/container validation may still need its own Dart toolchain if that environment is used for release gates.
- PowerShell is not installed or is not on `PATH` in the current Linux container, so `.ps1` gates cannot be executed locally here. Bash equivalents should be used where available, and PowerShell gates must run in CI or a Windows validation host.
- Historical checkpoints 574-718 were limited by missing PATH toolchains, but current-host validation has superseded that blocker with explicit Flutter/Dart, Cargo/rustfmt, Git, and bundled Python paths. Plain `git status --short` still cannot provide VCS evidence because `C:\Users\Brent\Documents\Avorax-main` is not a `.git` repository. Gradle/npm/Android tooling remain out of scope for the Windows antivirus release path unless Android or web publishing is attempted.

## Windows Driver Blockers

- No signed Windows minifilter or process-guard driver has been built, installed, run, or self-tested in this environment.
- WDK/EWDK, Visual Studio Build Tools, Administrator installation context, test certificate setup, and a disposable Windows validation VM are required for driver validation.
- Avorax must not claim pre-execution or kernel-level protection until driver installation, IPC, and self-test reports pass.

## Product Readiness Blockers

- Production ML dataset, independent anti-virus validation, production-ready static-model metadata, and production-ready `.zmodel` metadata are not present; checkpoint 823 makes `ml/evaluate_model.py` fail closed for missing/non-finite static-model metrics, checkpoint 824 makes `ml_native/evaluate_native_model.py` fail closed for malformed `.zmodel` metadata, schema drift, invalid fixtures, and insufficient FPR/precision/recall evidence, checkpoint 825 makes native train/export tooling validate schema/model evidence before producing or exporting assets, checkpoint 826 makes static ONNX export refuse production-ready metadata without explicit dataset/sample/metric evidence, checkpoint 827 makes static feature-build/train tooling validate bounded schema-owned feature rows and development-only training summaries, checkpoint 849 makes static/native ML evaluator report outputs checked regular-file evidence written through exclusive temporary files and atomic replacement, checkpoint 850 makes native feature-builder JSONL output schema-validated and atomically activated, checkpoint 851 routes native feature/model/asset outputs through a shared checked output helper, and checkpoint 852 routes static feature/model/metadata/ONNX-byte outputs through checked UUID-temp atomic activation.
- Native ML `.zmodel` strict-schema hardening is runtime-verified in checkpoint 1625: focused Cargo fixtures confirm `NativeModel` and nested `Thresholds` reject unknown fields while the bundled `.zmodel` uses only the allowed runtime schema.
- Native ML `.zmodel` actual-byte read limits are runtime-verified in checkpoint 1625: focused Cargo fixtures confirm native model reads retain non-following regular-file metadata and enforce both metadata-size and actual-read byte limits before UTF-8 and JSON parsing. Replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host.
- Development ML must remain advisory/review-only and must not auto-quarantine by itself.
- Native ML provider/status production-ready metadata honesty is partially runtime-verified in checkpoint 1625: focused native-engine fixtures confirm loaded development models report `production_ready=false`, unloaded models use an explicit false branch, and malformed/non-production `.zmodel` inputs cannot silently become production evidence. Checkpoint 1127 source checks confirm Flutter parses and displays `native_ml_production_ready` instead of inferring production readiness from status/version text; checkpoints 1551 and 1631 supersede the general Flutter/Dart runtime blocker with passing full Flutter client test suites (`464 passed` in checkpoint 1631). A production-ready `.zmodel` still requires real dataset/metric validation.
- Compatibility engines such as ClamAV/YARA must remain optional and disabled by default; Avorax Native Engine must handle core scans and EICAR without them.
- Local heuristic auto-quarantine policy and sample-prefix reads are now part of the small-threat MVP verifier in checkpoint 1951: local-core `heuristic` passed (`19`) on this Windows host, including conservative heuristic-only auto-action gating, bounded script/entropy samples, non-following target inspection, and filename/default branch-honesty fixtures. Earlier focused runtime fixture evidence in checkpoint 1630 verified `heuristic_auto_quarantine_requires_probable_verdict_and_independent_sources`, `obfuscated_script_detection_uses_bounded_sample`, and `entropy_detection_uses_bounded_sample`; source checks in checkpoint 1119 confirm the helper rejects allowlisted, non-probable, confirmed-equivalent, review-only, engine-missing, or single-source heuristic risk records before any heuristic-only automatic file isolation can be treated as eligible, and checkpoint 1283 confirms heuristic samples use explicit chunked prefix limits.
- Local ClamAV compatibility fixture UUID temp-name, command-output drain, sample-prefix, and scan-hash byte-limit hardening have focused runtime fixture evidence in checkpoint 1630: the local-core `clamav` filter passed `11 passed; 0 failed`; source checks in checkpoint 1122 confirm the ClamAV test fixtures no longer use timestamp default fallbacks for temporary paths, checkpoint 1261 confirms local ClamAV SHA-256 inputs are byte-limited before compatibility scan evidence is returned, checkpoint 1281 confirms scanner stdout/stderr are drained while retaining only bounded diagnostic bytes, and checkpoint 1284 confirms the local ClamAV/EICAR precheck sample uses an explicit chunked prefix limit.
- Local/cloud reputation remains disabled and must not be claimed as protection; checkpoint 1120 source checks confirm the local reputation provider returns no `ThreatResult`, reports `unavailable`, and surfaces the no-backend reason in health responses. Checkpoint 1126 source checks confirm Flutter parses, stores, and displays reputation status/reason evidence; checkpoints 1551 and 1631 supersede the general Flutter/Dart runtime blocker with passing full Flutter client test suites (`464 passed` in checkpoint 1631). A real reputation backend remains blocked.
- Installed process/behavior monitor runtime-loop verification remains blocked; checkpoint 1123 source checks confirm local-core health reports monitor `status` as `notActive`, keeps process monitor `capability` separate, and surfaces explicit no-loop reasons instead of claiming installed suspicious-process or behavior enforcement. Checkpoints 1761-1766 add runtime-verified bounded snapshot evaluation, strict Local Core IPC, Flutter client parsing, bounded AppDetector `ProcessObservation` extraction, controller-level protected-app detection submission/event evidence, and Protected Apps local-event evidence UI for supplied process metadata, including strict schemas, inventory/text/finding limits, normalized allowlists, parent-traversal rejection, nested unknown-field rejection, protocol-warning diagnostics, PID parsing, and explainable suspicious-process findings. Checkpoints 1965-1966 tighten that snapshot path by rejecting missing `process_observations` and preserving Windows command-line evidence through checked PowerShell/CIM JSON collection without an app-detector execution-policy override. Checkpoint 1967 adds an app-lifetime best-effort controller loop that evaluates process snapshots every two minutes while protection is active and stops on protection stop/dispose, checkpoint 1968 deduplicates identical routine info events so the bounded local event history is not crowded by repeated empty/evaluated ticks, checkpoint 1969 surfaces loop timer-start failures in the visible Flutter state error text, checkpoint 1970 surfaces current loop state/reason in Flutter state and the Protection `Process monitors` detail, checkpoint 1971 keeps the one-command MVP verifier scope aligned with that state/UI proof, checkpoint 1972 surfaces active-protection loop event evidence on Protected Apps, checkpoint 1973 makes the Protected Apps latest-evidence panel timestamp-selected so noncanonical event ordering cannot surface stale snapshot evidence, checkpoint 1974 shows the selected evidence timestamp in UTC, checkpoint 1975 keeps that Protected Apps evidence scope explicit in generated verifier reports, and checkpoint 1976 makes the full-suite report validator require that scope. This is still not an installed service/driver loop, kernel blocking, or pre-execution blocking. Checkpoint 1125 source checks confirm Flutter parses, stores, and displays monitor status/capability/reason fields; checkpoints 1551 and 1631 supersede the general Flutter/Dart runtime blocker with passing full Flutter client test suites (`464 passed` in checkpoint 1631).
- ProgramData root/error UI runtime verification is partially verified by the current Flutter suite; checkpoint 1128 source checks confirm Flutter parses `program_data_dir_error`, stores and clears it in app state, and surfaces it in Protection and Settings instead of relying only on generic engine errors. Checkpoint 1136 source checks confirm Flutter also displays `program_data_dir` in Settings and clears stale ProgramData root evidence when health data is missing or fails; checkpoint 1551 supersedes the general Flutter/Dart runtime blocker with a passing full Flutter client test suite.
- Local-core IPC/network-exposure UI runtime verification is partially verified by the current Flutter suite; checkpoint 1129 source checks confirm Flutter accepts only the explicit `stdio` IPC mode, treats `network_exposed` as nullable proof rather than defaulting missing/malformed values to false, stores and clears the evidence in state, and displays the boundary in Settings. Checkpoint 1551 supersedes the general Flutter/Dart runtime blocker with a passing full Flutter client test suite.
- Native/AI self-test UI runtime verification is partially verified by the current Flutter suite; checkpoint 1130 source checks confirm Flutter parses nullable `native_self_test` and `ai_self_test` pass/fail evidence, stores and clears it in app state, reports false-without-detail in health events, and displays pass/fail/unknown in Protection and Settings, and checkpoint 1516 confirms Local Core derives native self-test status and error context together instead of a bare `Err(_) => false`. Checkpoints 1547 and 1551 supersede the general Cargo/rustfmt and Flutter/Dart runtime blockers on this host.
- Native asset-directory UI runtime verification is partially verified by the current Flutter suite; checkpoint 1131 source checks confirm Flutter parses `signatures_dir`, `rules_dir`, `ml_dir`, `trust_dir`, and `config_dir`, stores and clears them in app state, and displays the pack/config paths in Settings. Checkpoint 1551 supersedes the general Flutter/Dart runtime blocker with a passing full Flutter client test suite.
- Core/Guard service status-error UI runtime verification is partially verified by the current Flutter suite; checkpoint 1132 source checks confirm Flutter preserves `core_service_status_error` and `guard_status_error`, clears stale service-error evidence, and displays service details in Settings and Protection. Checkpoint 1551 supersedes the general Flutter/Dart runtime blocker with a passing full Flutter client test suite.
- Local AI `ai_status` UI runtime verification is partially verified by the current Flutter suite; checkpoint 1133 source checks confirm Flutter parses top-level `ai_status`, stores it in app state, resets it conservatively on health failure, displays it in Settings, and uses it for the Protection Local AI checklist instead of reusing native ML status. Checkpoint 1551 supersedes the general Flutter/Dart runtime blocker with a passing full Flutter client test suite.
- Native engine `native_error` UI runtime verification is partially verified by the current Flutter suite; checkpoint 1134 source checks confirm Flutter preserves `native_error`, clears stale native-engine error evidence, and displays native-engine details in Settings and Protection separately from aggregate `last_error`. Checkpoint 1551 supersedes the general Flutter/Dart runtime blocker with a passing full Flutter client test suite.
- Aggregate `last_error` UI runtime verification is partially verified by the current Flutter suite; checkpoint 1137 source checks confirm Flutter clears stale `lastEngineError` evidence when later health responses omit `last_error`, preventing recovered failures from staying visible as current diagnostics. Checkpoint 1551 supersedes the general Flutter/Dart runtime blocker with a passing full Flutter client test suite.
- Install/engine root UI runtime verification is partially verified by the current Flutter suite; checkpoint 1135 source checks confirm Flutter preserves `install_path`, `engine_directory`, and `engine_paths_checked`, clears stale install/engine roots and checked paths after missing/failing health data, and displays bounded root evidence in Settings. Checkpoint 1551 supersedes the general Flutter/Dart runtime blocker with a passing full Flutter client test suite.
- Superseded by checkpoint 1550 and reconciled in checkpoint 1756: the root Rust workspace `Cargo.lock` is present and includes `avorax_update_service`; Cargo does not create `core\avorax_update_service\Cargo.lock` for this workspace member. Dependency evidence release mode now passes for the Windows antivirus release path; Android Gradle lock evidence remains a separate Android-publishing prerequisite.
- Rust workspace compile and runtime are now verified by checkpoint 1547 on this Windows host: `cargo test --workspace --no-run` passes and `cargo test --workspace -- --test-threads=1` passes. The earlier update-key elevation blocker (`os error 740`) is closed by embedding an explicit `asInvoker` manifest for update-service test binaries; this only disables Windows installer-name/UAC heuristics for non-privileged validation and does not claim or grant machine-wide service privileges.
- Android dependency readiness needs Gradle dependency-lock generation/review on an Android release host before any Android publishing; current source pins plugin versions, wrapper version, and wrapper `distributionSha256Sum`, checkpoint 1014 reads wrapper evidence through a shared byte-limited handle reader, and checkpoint 1555 enables Gradle dependency locking for Android subprojects. Checkpoint 1756 marks Android lockfile/SDK checks informational for the Windows antivirus release path because Android publishing is out of scope for this Windows product build.
- Python ML dependency metadata and disposable Windows/Python 3.12 install/import smoke tests have passed with exact direct/transitive pins; release still needs complete SBOM/license output from the target release host and exact built artifacts.
- Update package builder path-safety still needs real packaged-stage release-signer verification; source/sanity/benign-fixture checks confirm repo-contained payload/output paths, safe version/channel/key tokens, quoted absolute signer parsing, explicit signer token arrays, PowerShell signer-script success handling, local regular signer validation, non-reparse payload trees, fail-visible reparse rejection during direct payload staging, payload hashing, and package zipping, checked cleanup, atomic manifest/feed writes, regular feed/package outputs, and fail-visible existing component validation instead of catch-and-false evidence.
- Dev update signer hardening needs production-signer ceremony verification; bundled-Python syntax and benign temp-fixture checks confirm explicit dev-key opt-in, Ed25519 key-shape validation, bounded absolute manifest input, link/reparse rejection markers, existing output rejection, and exclusive non-following signature output.
- Rust update signer/key-generator, verifier, manifest, package, rollback, staging, service-control, and CLI fixture coverage is runtime-verified by checkpoint 1624: `cargo test --manifest-path core\avorax_update_service\Cargo.toml -- --test-threads=1` passes with update key generator `4 passed`, sign-manifest bin `0 tests`, and update-service main tests `176 passed`; `cargo fmt --manifest-path core\avorax_update_service\Cargo.toml -- --check` also passes after mechanical formatting. This verifies the local fixture layer for strict keygen arguments, signed-manifest binding, manifest/schema/signature shape, `.aup` package path/text/post-open checks, payload hash/entry/file-size/duplicate/non-empty/actual-byte limits, payload activation revalidation, shared staged activation/source-open checks, update applier section/install-root revalidation, rollback root/snapshot/install-root checks, service-control bounds, and CLI strictness.
- Update-service signed package verification has current-host runtime proof in checkpoint 1957: `update_verifier` passes (`12`) with a real benign signed `.aup` fixture, manifest signature tamper rejection, and payload hash tamper rejection; the full update-service crate passes (`180`) and is wired into the small-threat MVP verifier.
- Update production signer ceremony, real packaged-stage release-signer execution, installed update-service operation, signed release package staging, MSI integration, and end-to-end update/rollback against installed Avorax artifacts remain unverified and must not be claimed by the checkpoint 1624 local Rust fixture pass.
- Update destination copy, rollback recursive copy, staged activation/cleanup, payload-hash bounds, staging-id bounds, CLI status/diagnostic/argument strictness, service-control bounds, service-error reports, dead downloader-module removal, and update-applier cleanup/reporting fixtures are runtime-verified by checkpoint 1624 through the full update-service crate suite (`176 passed`) plus update key generator tests (`4 passed`) and update-service `cargo fmt --check`.
- Installed update-applier integration against real Avorax service processes and artifacts remains unverified; checkpoint 1624 covers local Rust fixtures, not a live service stop/apply/restart cycle on an installed product.
- Superseded by checkpoint 1549: Dart update-manifest typed-field diagnostics and strict-field hardening are now format/analyze/test verified for `packages/avorax_protocol`; malformed manifest strings, integers, booleans, malformed `payload_hashes`, and unknown update-manifest fields fail visibly, and `dart test --reporter expanded` passes with 6 tests.
- Dart protected-app profile validation is runtime-verified in checkpoint 1673: `packages/zentor_protocol/test/zentor_protocol_test.dart` passed (`11`) including missing `protectionProfile` preserving the `standard` compatibility default, present blank values throwing instead of clearing visible policy evidence, and protected-app identity/profile control text rejection before trimming.
- Flutter update-feed strict-field hardening is runtime-verified in checkpoint 1725: `update_service_test.dart` passed (`108`) and covers unknown top-level feed fields plus unknown package-entry fields failing before `.aup` package selection; Dart format reported `0 changed`.
- Flutter local update-feed streamed-file hardening is partially runtime-verified in checkpoint 1590: oversized local `file:` update feeds fail while streaming through `_readBoundedUtf8File` before JSON parsing or HTTP fallback, and source checks in checkpoint 1243 confirm chunked byte-limit enforcement instead of `readAsString()` after a single `length()` check. Growing-file race fixtures remain partial until a provisioned filesystem race host is available.
- Flutter update metadata streamed-size hardening is runtime-verified for the current Flutter fixture layer in checkpoints 1592, 1593, 1594, 1595, 1596, and 1597: oversized remote update-feed and GitHub release metadata responses without `Content-Length` fail while streaming through the metadata byte limit before JSON parsing, and stalled remote update-feed plus GitHub release metadata response streams fail with labeled timeouts before parser use; source checks in checkpoint 1242 confirm update-feed and GitHub release metadata bodies are byte-limited before `http.Response` buffering. Installed Windows update-flow E2E remains partial.
- Flutter update network-timeout hardening is runtime-verified for the current Flutter fixture layer in checkpoints 1594, 1595, 1596, and 1597: stalled update-feed and GitHub release metadata request sends/response streams, stalled redirect response bodies, and stalled package-download streams fail visibly with labeled timeout diagnostics; source checks in checkpoint 1247 confirm HTTP sends and remote update metadata/package/redirect streams use finite request/read timeouts. Installed Windows update-flow E2E remains partial.
- Flutter updater subprocess timeout kill-result, bounded post-kill exit observation, and diagnostic normalization are source/runtime verified in checkpoint 1770: `update_service_test.dart` passed (`108`), `flutter analyze` passed, source-contracts passed (`481`), and no-malware/product-copy gates passed. A real hung elevated updater process and installed update E2E remain partial.
- Flutter local-core scan IPC timeout kill-result, bounded post-kill exit observation, and diagnostic normalization are runtime/source verified in checkpoint 1771: `local_core_ipc_diagnostics_test.dart` passed (`59`) including a hung local-core child fixture that reports timeout, termination request, and post-kill exit observation; source-contracts passed (`481`). Installed local-core process E2E remains partial.
- Flutter local-core subprocess timeout kill-result evidence for Guard self-test, cancel IPC, and elevated PowerShell is runtime verified in checkpoint 1774 with benign hung-Dart-process fixtures requiring `_ipcTerminationStatus(process.kill())`, `await _ipcReapStatus(process)`, and bounded elevated PowerShell stdout/stderr timeout cleanup; `local_core_ipc_diagnostics_test.dart` passes (`62`). Flutter platform-info PowerShell and app-detection process-list timeout cleanup are runtime verified in checkpoint 1773 with benign hung-Dart-process fixtures; `platform_info_service_test.dart` passes (`19`) and `app_detector_test.dart` passes (`9`). Installed subprocess E2E remains partial.
- Flutter update redirect body-bound hardening is runtime/source-marker verified in checkpoint 1725: `update_service_test.dart` passed (`108`) and covers stalled redirect bodies plus bounded redirect body source markers; oversized redirect-body E2E remains partial.
- Flutter local update package canonical-containment hardening is runtime/source-marker verified in checkpoint 1725: `update_service_test.dart` passed (`108`) and covers local package outside-feed rejection plus canonical containment source markers; local symlink/junction fixture execution remains partial.
- Flutter local update package post-copy source revalidation is runtime/source-marker verified in checkpoint 1725: `update_service_test.dart` passed (`108`) and covers staged local package copy source rechecks; source-replacement race E2E remains partial.
- Flutter update package hash-input size bounds are runtime verified in checkpoint 1775: `verifyDownloadedPackage` rejects an oversized managed-cache `.aup` before SHA-256 streaming/updater use, with `update_service_test.dart` passing (`109`). Source checks still confirm package hash inputs are regular-file revalidated before and after the size check.
- Flutter selected-file hash service size/type bounds are further runtime-verified in checkpoint 1776: `HashService` rejects directories, oversized selected files before progress, a selected path that changes after stat, and a file that grows over a test-only hash limit while streaming; `hash_service_test.dart` passes (`6`). Source checks still account for link rejection and chunked SHA-256 streaming without whole-file buffering. Symlink/junction fixture execution remains partial until a host with link creation support is available.
- Guard Service guard-mode config path override hardening is runtime-verified for crate fixtures in checkpoint 1632: `guard_mode` passed `17 passed; 0 failed`, covering absolute config roots, relative/parent-traversal rejection, strict config parsing, and fail-visible corrupt config behavior; installed Windows service environment E2E remains partial.
- Guard Service fixture regressions are now kept in the small-threat MVP verifier by checkpoint 1956: `guard_mode` (`17`), `known_bad` (`16`), `quarantine` (`32`), `driver_ipc` (`49`), `driver_health` (`16`), `self_test` (`16`), `process_watch` (`1`), and `process_skip` (`1`) passed, with source-contracts (`512`) and the full verifier green. This remains fixture/runtime proof only; installed service, signed-driver IPC, and pre-execution blocking are still blocked or partial.
- Guard Service guard-mode/quarantine metadata text-read hardening is runtime-verified for crate fixtures in checkpoint 1632: `guard_mode` and `quarantine` filters passed, confirming bounded non-following config/metadata/auth/key reads before parsing, comparison, or key decoding; replacement-race and installed service E2E remain partial.
- Guard Service event/fatal log base path and fatal-log staging hardening is runtime-verified in checkpoint 1639 for fatal-log staging, checked directory handling, visible secondary-failure reporting, and Guard rustfmt; installed Windows service environment fixture verification remains partial.
- Guard Service quarantine base path hardening is runtime-verified for crate fixtures in checkpoint 1642: `quarantine_root` passed `2 passed; 0 failed`, covering absolute/parent-traversal root validation. Installed Windows service environment verification remains partial.
- Guard Service quarantine metadata-auth write verification is runtime-verified for crate fixtures in checkpoint 1632: `quarantine` passed `32 passed; 0 failed`, covering staged auth verification, tamper visibility, missing-key errors, and legacy compatibility; installed Windows service quarantine E2E remains partial.
- Guard Service quarantine fallback-copy byte limits and partial cleanup are runtime-verified for crate fixtures in checkpoint 1632 through the `quarantine` and full Guard suites; oversized/copy-failure behavior remains limited to fixture coverage until installed service E2E.
- Guard Service guard-mode config fallback hardening is runtime-verified in checkpoint 1639: relative config paths/bases and parent-traversal config bases fail visibly instead of falling back to relative `.avorax/config`; Windows service environment fixture verification remains partial.
- Guard Service `--service` unsupported-platform behavior needs Cargo/rustfmt execution and non-Windows service-mode fixture verification; source checks in checkpoint 943 confirm non-Windows service mode fails visibly instead of aliasing to console watch.
- Guard Service guard-mode JSON schema/value strictness is runtime-verified in checkpoint 1639: `guard_mode.json` rejects unknown fields, corrupt JSON, directory/symlink config inputs, empty source, oversized mode/config evidence, and malformed overrides instead of silently accepting ignored policy; installed Windows service config E2E remains partial.
- Guard Service stdin command strict-schema hardening is runtime-verified for crate fixtures in checkpoint 1632: `driver_ipc` passed `49 passed; 0 failed` and the full Guard suite passed, confirming unknown JSON fields fail instead of becoming dead controls.
- Guard Service nested scan-request strict-schema hardening is runtime-verified for crate fixtures in checkpoint 1632 through the `driver_ipc` and full Guard suites; fake driver metadata or policy controls fail parsing instead of being silently ignored.
- Local-core command strict-schema hardening is runtime-verified in checkpoint 1639: `CoreCommand` denies unknown JSON fields so stray action/policy controls fail parsing instead of being silently ignored as dead controls; installed local-core IPC E2E remains partial.
- Guard Service driver IPC fail-open runtime-root candidate hardening is runtime-verified for crate fixtures in checkpoint 1632: `driver_ipc` passed `49 passed; 0 failed`, covering guarded fail-open roots and caller-supplied trust rejection. Signed-driver/installed IPC E2E remains blocked.
- Guard Service driver IPC hardcoded fail-open root removal is runtime-verified for crate fixtures in checkpoint 1632 through the `driver_ipc` and full Guard suites; installed driver IPC E2E remains blocked.
- Guard Service driver IPC temp fail-open root removal is runtime-verified for crate fixtures in checkpoint 1632 through the `driver_ipc` and full Guard suites; installed driver IPC E2E remains blocked.
- Guard Service driver IPC fail-open lexical path matching is runtime-verified for crate fixtures in checkpoint 1632 through the `driver_ipc` and full Guard suites; signed-driver/installed IPC E2E remains blocked.
- Guard Service known-bad default cache root hardening is runtime-verified for crate fixtures in checkpoint 1632: `known_bad` passed `16 passed; 0 failed`, covering default-root safety; installed-service cache-root E2E remains partial.
- Guard Service known-bad cache actual-byte read limits are runtime-verified for crate fixtures in checkpoint 1632: `known_bad` passed `16 passed; 0 failed`, covering strict schema, malformed hashes, bounded actual-byte reads, missing-file empty compatibility, and default-root safety; replacement-race and installed-service fixtures remain partial.
- Guard Service process hash-cache identity hardening remains partially verified: checkpoint 1642 adds process-watch runtime fixture coverage, while Windows live process replacement race verification remains partial.
- Guard Service finite process-watch inspection-error completion is runtime-verified for crate fixtures in checkpoint 1642: `process_watch` passed `1 passed; 0 failed`, covering visible inspection-error completion instead of a clean no-threat result; Windows process-observation E2E remains partial.
- Local Core realtime watcher empty-plan/status honesty is runtime-verified for current local-core fixtures in checkpoint 1642: `watch` passed `10 passed; 0 failed`; installed local-core watcher smoke verification remains partial.
- Guard Service process/quarantine SHA-256 input byte limits are runtime-verified for crate fixtures in checkpoint 1632 through `driver_ipc`, `quarantine`, and the full Guard suite; replacement-race and installed service/driver E2E remain partial.
- Guard self-test SHA-256 input byte limits are runtime-verified for crate fixtures in checkpoint 1632 through `self_test` (`16 passed; 0 failed`) and the full Guard suite; replacement-race and installed service E2E remain partial.
- Guard Service process-observer skip lexical path matching is runtime-verified for crate fixtures in checkpoint 1642: `process_skip` passed `1 passed; 0 failed`, covering component-aware normalized system-path skip decisions. Live Windows/non-Windows process-observation E2E remains partial.
- Exact-hash trust-store strict-schema hardening remains partially blocked for Guard runtime fixtures; native known-good/known-bad trust-store strict-schema fixtures are now part of the small-threat MVP verifier in checkpoint 1953, and local app-control known-good/known-bad strict-schema fixtures are part of the same verifier in checkpoint 1952. Earlier source checks in checkpoint 913 confirm Guard known-bad, local app-control known-bad/known-good, and native known-good/known-bad JSON schemas reject unknown policy-like fields while preserving explicitly allowed descriptive metadata.
- Native exact-hash trust-store actual-byte read limits are runtime-verified in checkpoint 1626: focused Cargo fixtures confirm native known-good/known-bad store reads retain non-following regular-file metadata, reject malformed/unknown-field/oversized stores, and enforce metadata-size plus actual-read byte limits before UTF-8 and JSON parsing. Replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host.
- Local app-control exact-hash trust-store actual-byte read limits are runtime-verified in checkpoint 1627: focused Cargo fixtures confirm local known-good/known-bad store reads retain non-following regular-file metadata, reject malformed/unknown-field/oversized stores, and enforce metadata-size plus actual-read byte limits before UTF-8 and JSON parsing. Replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host.
- Persisted allowlist entry strict-schema hardening is runtime-verified in checkpoint 1628: focused Cargo fixtures confirm `AllowlistEntry` rejects unknown JSON fields so broad allow or policy-like controls cannot be silently ignored while appearing present in trust data.
- Local allowlist lexical path matching, env-store path hardening, store actual-byte read limits, and selected-file hash byte limits are runtime-verified in checkpoint 1628 for the local-core fixture layer: focused Cargo fixtures cover traversal/env/oversized-file/hash-size/directory/staged-write/error-visibility behavior. Replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host.
- Native allowlist lexical path matching is runtime-verified in checkpoint 1629: focused Cargo fixtures confirm native allowlist path validation, broad-root rejection, exact hash matching, malformed-hash fail-closed behavior, component-aware matching, and sibling-prefix rejection.
- Native Avorax/Zentor product-trust lexical path matching is runtime-verified in checkpoint 1629: focused Cargo fixtures confirm product install, quarantine, and repository trust comparisons use exact controlled roots, reject parent traversal/relative overrides, reject repo lookalikes, and do not trust installer-shaped filenames alone. Unix-only repo symlink fixtures remain platform-limited on this Windows host.
- Native Microsoft system-path lexical matching is runtime-verified in checkpoint 1629 for local parser/path fixtures: focused Cargo fixtures confirm checked system roots, component-boundary matching, bounded Authenticode command output parsing, non-following candidate path inspection, and malformed Authenticode JSON fail-closed behavior. Live Authenticode verification with real Windows trust stores remains an installed Windows E2E limitation.
- Local app-control passthrough lexical path matching is runtime-verified in checkpoint 1641: local-core `app_control` passed `47 passed; 0 failed`, covering app-control traversal/path trust fixtures; installed local-core/service E2E remains partial.
- Local AI training-label strict-schema, runtime-root validation, staged write cleanup reporting, and actual-byte store-read hardening are runtime-verified in checkpoint 1628: focused Cargo fixtures confirm `TrainingLabel` and nested `StaticFeatures` reject unknown fields, malformed/oversized JSONL fails visibly, roots reject relative/parent-traversal overrides, and store reads retain non-following regular-file metadata while enforcing metadata-size plus actual-read byte limits before JSONL parsing. Replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host.
- Local AI model metadata strict-schema hardening is runtime-verified in checkpoint 1629: focused Cargo fixtures confirm `ModelMetadata` and nested `ModelThresholds` reject unknown fields while the bundled local metadata asset parses under the strict schema.
- Local AI model metadata semantic validation and static-feature sample-prefix reads are runtime-verified; checkpoint 1951 adds local-core `static_feature` to the small-threat MVP verifier (`7` passed on this Windows host), covering bounded static-feature sample reads, non-following target inspection, directory/non-file rejection, and filename/extension/default branch-honesty fixtures. Earlier checkpoint 1629 focused Cargo fixtures confirm bounded identity/list fields, finite and ordered thresholds, required production-ready metric/sample evidence, explicit development-model inactive state, and bounded static-feature sample reads.
- Local AI model metadata actual-byte read limits are runtime-verified in checkpoint 1629: focused Cargo fixtures confirm local AI metadata reads retain non-following regular-file metadata and enforce both metadata-size and actual-read byte limits before UTF-8 and JSON parsing. Replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host.
- Local AI ONNX category-score bounds have focused runtime fixture evidence in checkpoint 1630: `onnx_runtime_category_scores_stay_unit_bounded` passed with local-core rustfmt; source/exporter checks in checkpoint 918 confirm Softmax category scores are rejected unless every consumed score is finite and between 0 and 1.
- Local AI threat-label validation has focused runtime fixture evidence in checkpoint 1630: `local_ai_threat_builder_rejects_unsupported_labels` and `local_ai_threat_builder_rejects_non_file_targets` passed with local-core rustfmt; source checks in checkpoint 1117 confirm unsupported confidence and category labels fail visibly during `ThreatResult` construction instead of defaulting to low confidence or unknown category evidence.
- Local trusted-publisher policy config diagnostics need Cargo/rustfmt execution and app-control policy fixture verification; source checks in checkpoint 903 confirm configured trusted publisher names fail visibly when empty or NUL-containing instead of being silently filtered, while malformed observed publisher evidence remains unknown.
- Guard driver IPC trusted-publisher config diagnostics need Cargo/rustfmt execution and signed-driver IPC policy fixture verification; source checks in checkpoint 905 confirm malformed configured trusted-publisher entries fail verdict evaluation visibly instead of being silently filtered, while malformed observed publisher metadata remains non-trusted.
- Guard Service driver-health service-query classification and unsupported-platform reporting need Cargo/rustfmt execution plus Windows/non-Windows service-control fixture verification; source/direct-contract checks confirm nonzero `sc query` output is not reported as not-installed unless bounded output indicates service-absent/1060, checkpoint 941 confirms non-Windows driver-health probes report explicit unsupported-platform errors instead of `notInstalled`, and checkpoint 943 confirms non-Windows `--service` mode fails visibly instead of running console watch.
- Guard Service driver-health Secure Boot PowerShell encoding is runtime-verified in checkpoint 1639 for UTF-16LE `-EncodedCommand` and `-NonInteractive` argument construction; live Windows Secure Boot probe fixture verification remains partial.
- Local-core Core/Guard service-status query classification is runtime-verified in checkpoint 1639: nonzero `sc query` output is not reported as `missing`/`off` unless bounded output indicates service-absent/1060, errors are preserved as bounded diagnostics, and unsupported Guard status remains `unknown` instead of `off`; installed Windows service-control E2E remains partial.
- Local-core fatal-error log staging is runtime-verified in checkpoint 1639: Core fatal-error logs use checked runtime directories, exclusive temporary files, safe existing-target preflight, and rename activation instead of direct final writes; Windows service filesystem E2E remains partial.
- Local-core `--service` unsupported-platform behavior needs Cargo/rustfmt execution and non-Windows service-mode fixture verification; source checks in checkpoint 940 confirm non-Windows Core Service mode fails visibly instead of entering an infinite placeholder loop.
- No-malware-binaries gate hardening needs CI/release-host configuration for explicit `AVORAX_PYTHON` or `-PythonPath`; current bundled-Python checks confirm no ambient Python launch, PowerShell bytecode-free verifier execution with fail-visible caller environment restoration, shell-wrapper bytecode-free source wiring, shell-wrapper absolute non-linked repository/Python/verifier path validation, bounded verifier reads, top-level CLI scan-root validation before path resolution, link/reparse rejection, explicit EICAR text allowances, checkpoint 1103 routes the PowerShell verifier launch through bounded command diagnostics, and a passing repository scan. Shell runtime execution remains blocked here because Bash/WSL is unavailable.
- False-positive/protection Cargo gates are runtime-verified with explicit Cargo in checkpoint 1633: false-positive and protection gates passed. Checkpoint 1958 keeps the false-positive gate in the small-threat MVP verifier, covering benign installer/tool fixtures, local/native false-positive suppression, and Guard unknown-app label honesty. Checkpoint 1959 keeps the protection gate in the same verifier with a synthetic non-driver self-test report and no `-DriverFeatureEnabled`; this covers policy/verdict gate wiring but does not prove signed-driver IPC or pre-execution blocking. Fixture gates do not replace production false-positive-rate evidence.
- Performance gate hardening is runtime-verified with explicit Cargo/Python in checkpoint 1633: `zentor-performance-gate.ps1` passed and wrote `dist\performance\performance_gate_report.json`. Signed-driver latency tests and elevated update-service apply benchmarks remain separate release-host blockers.
- Windows release gate/prerequisite tool-forwarding is partially runtime-verified in checkpoint 1633, reconciled for Windows scope in checkpoint 1756, refreshed in checkpoint 1757, and report-path hardened in checkpoint 1870: release prerequisite execution with explicit dotnet/cargo/flutter paths no longer treats Android Gradle lockfile or Android SDK as Windows release blockers, Rust release service binaries now exist under `target\release`, the prereq check rejects a runtime-only `dotnet.exe` by requiring `dotnet --list-sdks` evidence, and prereq JSON reports must resolve inside the repository. Host-only mode still correctly fails on real Windows-host blockers: missing .NET SDK, unavailable symlink support, and missing Visual Studio Desktop C++ components. Full mode additionally fails on missing Flutter Windows `Avorax.exe` and `dist\windows-msi\stage`. Full top-level release gate still needs packaged fixtures, signed-driver/self-test evidence, installer stage, and a release-capable host.
- Branding/product-copy gate hardening is runtime-verified in checkpoint 1633 on this host: both branding and product-copy gates passed. Checkpoint 1960 keeps the branding gate in the small-threat MVP verifier before product-copy/security gates, covering active source/doc branding drift in the repeatable MVP sweep. Full packaged release-host execution remains separate from these source/repo gates.
- The small-threat MVP verifier now writes structured JSON evidence in checkpoint 1961. `-ReportPath` must resolve to a child path inside the repository and reports are written atomically through the shared security-gate helper. The JSON evidence is a verifier summary, not proof of blocked installed-service, packaged UI, signed-driver, or release-host capabilities.
- Shared security-gate duplicate `Path`/`PATH` child-environment handling is source and gate accounted in checkpoint 1118; checkpoint 1294 makes unreaped post-kill child processes fail visibly in shared PowerShell gate stop helpers; branding, product-copy, and no-malware reruns pass in this duplicate-env shell. Full release-host execution still needs a provisioned host with explicit Cargo/Python/Flutter/package fixtures.
- CI/release workflow tool-path forwarding needs live GitHub Actions verification; source checks confirm CI passes explicit Cargo/Python paths into hardened gates, release update-signing helper scripts use a resolved Cargo executable instead of ambient `cargo`, generated workflow reports/helpers are atomically staged in checkpoint 847, the Windows release workflow runs dependency evidence in release mode without `-AllowKnownBlockers`, checkpoint 830 makes release workflow AI metadata JSON parsing bounded/fail-visible, checkpoint 844 makes dependency-evidence report writes atomically activated under the repository, checkpoint 1083 moves release workflow AI metadata reads onto a byte-limited handle reader instead of `Get-Content -Raw`, and checkpoint 1191 makes the dependency-evidence artifact upload fail visibly if the generated report is missing.
- ZNE/real-world coverage gate hardening needs full execution with a provisioned Cargo path and POSIX shell release host; current source and negative sanity checks confirm explicit Cargo is required, PowerShell gate scripts avoid ambient `cargo`/`powershell`/`rg`, ZNE report writes are atomically staged/replaced through checked temporary regular files, checkpoint 829 makes malformed ZNE native metadata JSON fail as bounded gate evidence, checkpoint 835 makes real-world coverage sample-extension hygiene run before Cargo with safe enumeration and PowerShell-script success handling, checkpoint 857 brings the shell ZNE gate report/metadata path onto bounded regular-file and UUID-temp atomic activation, checkpoint 1008 moves the PowerShell ZNE metadata reader onto the shared byte-limited handle reader, checkpoint 1014 moves PowerShell ZNE UI source scanning onto that reader, and checkpoint 1101 routes PowerShell ZNE/coverage Cargo and branding commands through bounded command diagnostics.
- Threat-intel import tooling needs full release-host feed review and pack compilation; checkpoint 832 makes shared intel JSON/text input helpers bounded and non-link-following, checkpoint 833 rolls the helper posture through developer hash lists, manual report IOCs, known-bad/signature/rule pack compilation, checkpoint 855 adds reparse-aware UUID-temp/fsynced atomic output activation to the shared helper, checkpoint 984 bounds GitHub API metadata responses before JSON parsing, checkpoint 985 rejects negative lengths, non-UTF-8 bodies, and non-object JSON, checkpoint 986 validates GitHub default-branch/tree metadata shape before indicator generation, checkpoint 987 fails closed on truncated GitHub tree metadata, checkpoint 988 normalizes explicit GitHub branch refs before metadata output, checkpoint 989 revalidates GitHub tree rows before metadata JSONL output, checkpoint 990 validates GitHub repo URLs plus owner/repo tokens before API path construction, checkpoint 991 validates source-config shape before import, checkpoint 992 validates manual IOC report schema before JSONL output, checkpoint 993 validates SHA-256 hash-feed metadata before output, checkpoint 994 rejects non-string developer hash JSON entries before output, checkpoint 995 validates generic signature compiler metadata before pack output, checkpoint 996 restricts known-bad pack escalation to confirmed SHA-256 indicators with quarantine policy, checkpoint 997 validates native rule-compiler source pack shape before output, checkpoint 998 validates generated/bundled indicator pack shape before success, checkpoint 999 hardens the local real-world hash-pack wrapper subprocess/temp-output boundary, checkpoint 1000 removes manufactured active metadata defaults from manual IOC import, checkpoint 1001 removes the direct hash-feed `trojan` category default, checkpoint 1002 removes the developer hash-only `unknown` category default, checkpoint 1003 requires explicit generic signature-pack versions, checkpoint 1004 requires explicit known-bad signature-pack versions, checkpoint 1005 requires explicit generated rule-pack versions, checkpoint 1006 validates GitHub metadata source attribution fields before output, checkpoint 1108 streams real-world wrapper helper output into bounded tails instead of collecting full stdout/stderr in memory, checkpoint 1279 hardens native signature compiler source reads with actual-byte accounting before UTF-8 and JSON parsing, and checkpoint 1293 bounds/reports real-world wrapper timeout kill/reap cleanup failures.
- Native threat-intel strict-schema hardening is runtime-verified in checkpoint 1640: `ThreatIntelIndicator` and `ThreatIntelSource` reject unknown fields in native-engine fixtures, and native-engine rustfmt passed.
- Release warning-debt cleanup is runtime-verified in checkpoint 1758: `cargo check --workspace --release` and `cargo build --workspace --release` pass without warning lines, and touched Rust crate tests pass for update key (`4`), update service (`176`), Guard (`212`), local-core (`411`), native engine (`284`), and signature compiler (`6`). The release-build-only dormant-surface annotations keep warning output actionable but do not prove those dormant/limited surfaces are installed, driver-backed, or fully E2E active.
- Windows installer build hardening needs full MSI/EXE execution on a provisioned Windows release host with explicit `dotnet`, `cargo`, and `flutter` paths plus packaged-stage fixtures; current parse/source/negative sanity checks confirm the builder refuses unsafe version tokens, refuses ambient build-tool lookup, stages generated files atomically with Windows PowerShell-compatible backup paths, gates optional ClamAV downloads behind explicit approval, streams ClamAV downloads through HTTPS/final-HTTPS checks with redirect, timeout, and byte limits before pinned hash activation, safely extracts pinned zip packages, keeps signed driver package artifact discovery fail-visible, bounds AI metadata JSON parsing, checkpoint 1012 moves MSI builder JSON reads onto the shared byte-limited handle reader, checkpoint 1088 routes generated driver-install `certutil`/`bcdedit`/`pnputil`/`sc`/`fltmc` diagnostics through the shared bounded System32 runner, checkpoint 1102 routes Flutter/Cargo/dotnet/WiX build commands through bounded diagnostics, resolves VC++ runtime DLLs through checked `SystemRoot`/`WINDIR` `System32`, and avoids ambient PowerShell/System32 tool lookup, silent `C:\Windows` fallback, suppressed driver-helper diagnostics, and unreported generated driver-helper failures.
- API fail-closed configuration/source-route behavior is runtime-verified for current crate fixtures in checkpoint 1641 through the API `route`, `project`, `auth`, `body`, and `error` filters; database-backed deployment smoke remains partial.
- API CORS behavior is runtime-verified for current crate fixtures in checkpoint 1641: `cors` passed `1 passed; 0 failed`, confirming the router source does not use `CorsLayer::permissive()`; browser preflight smoke remains partial.
- API route compatibility and request-bound tests are runtime-verified in checkpoint 1641: `route` passed `32 passed; 0 failed`, and `body` passed `1 passed; 0 failed`; live API smoke remains partial.
- API bearer-token bound tests are runtime-verified in checkpoint 1641: `auth` passed `2 passed; 0 failed`, covering token length/shape checks before hashing.
- API project slug compatibility is runtime-verified in checkpoint 1641: `project` passed `6 passed; 0 failed`, covering Flutter slug compatibility only when the slug resolves to the authenticated project.
- API Axum route syntax is runtime-verified in checkpoint 1641 through the API `route` filter; startup smoke remains partial.
- Flutter cloud telemetry copy is runtime/source-marker verified in checkpoint 1728: `api_client_test.dart` passed (`38`) and covers Avorax heartbeat telemetry copy/source markers; live backend telemetry ingestion remains partial.
- Flutter cloud acknowledgement parse diagnostics and cloud health-check runtime behavior are partially runtime-verified: checkpoint 1778 verifies oversized streamed health responses fail before buffering and stalled response streams surface bounded offline diagnostics through `api_client_test.dart` (`40` passed), and checkpoint 1807 verifies a control/NUL-rich cloud health exception clears busy state, sets Cloud offline, and emits bounded normalized visible/audit diagnostics under `settings`/`warning` through `offline_scan_test.dart` (`112` passed). Source checks in checkpoint 900 confirm health/write 2xx JSON parse and size-limit failures preserve bounded details instead of generic invalid-JSON text. Checkpoint 1145 source checks confirm manual cloud health checks are single-flight, disabled while checking, and convert unexpected exceptions into bounded offline diagnostics. Checkpoint 1166 source checks confirm duplicate cloud checks log settings warning evidence and set visible error state instead of only returning. Checkpoint 1188 surfaces `_cloudHealthCheckInFlight` through `ZentorState.cloudHealthCheckInFlight` so Settings disables Test Cloud Connection while the controller guard is active before status-only busy evidence catches up. Checkpoint 1317 source checks confirm `_cloudDiagnosticText` control/NUL-normalizes cloud exception diagnostics before visible/offline evidence is emitted, checkpoint 1320 confirms `_boundedCloudString` control/NUL-normalizes cloud response status/error strings before health status or write-ack rejection text is emitted, checkpoint 1321 confirms cloud config and outbound metadata with control/NUL characters fail validation before persistence or network transmission, and checkpoint 1323 confirms raw cloud config/payload values are checked before trimming. Installed UI/cloud click-through and live backend smoke remain partial.
- Flutter app-state controller diagnostic normalization is partially runtime-verified: checkpoint 1779 adds an explicit 2048-character app-state UI diagnostic cap and verifies quarantine/allowlist refresh failures normalize control/NUL-rich long local-core exceptions before both visible `errorMessage` text and local-event `details`; checkpoint 1805 adds protection-start Guard IPC exception runtime coverage proving visible/audit diagnostics are bounded and normalized while loading/busy state clears and watcher startup is not attempted after failed Guard-mode IPC; checkpoint 1806 adds scan-cancel IPC exception runtime coverage proving visible/audit diagnostics are bounded and normalized while cancel busy state clears, the scan is not falsely marked cancelled, and the final scan report remains authoritative; checkpoint 1808 adds configuration-reset repository exception runtime coverage proving reset returns false, busy state clears, current settings are preserved, and visible/audit diagnostics are bounded and normalized under `settings`/`error`. Source checks in checkpoint 1311 confirm the shared `_boundedUiDiagnostic` formatter is used broadly before visible UI state or local-event details are emitted. Remaining installed UI click-through diagnostic paths stay partial where not covered by focused runtime fixtures.
- Flutter update-service diagnostic normalization has current-host Flutter fixture coverage for update-check, in-app download, verify, install, rollback, download-cleanup failure, and non-file package probe evidence; source checks in checkpoint 1312 confirm `_boundedUpdateCheckError` bounds and control/NUL-normalizes those diagnostics before update UI/audit evidence is emitted, checkpoint 1568 verifies control/NUL-rich update-check failures are normalized before `updateError`, `errorMessage`, and `update_check_failed` event details through `flutter test test\update_controller_test.dart --reporter compact` (`28 passed`), checkpoint 1571 verifies control/NUL-rich update download failures are normalized before visible `updateError`/`errorMessage` and `update_install_failed` event details through the same focused test (`29 passed`), checkpoint 1572 verifies verify/install/rollback failures are normalized before visible UI state and failure-event details through the focused update-controller suite (`30 passed`), checkpoint 1573 verifies a real `ZentorUpdateService.downloadUpdatePackage` temp-cleanup failure preserves bounded original/cleanup diagnostics through `flutter test test\update_service_test.dart --reporter compact` (`84 passed`), and checkpoint 1574 verifies `verifyDownloadedPackage` rejects non-file cached package paths with bounded probe diagnostics before updater launch through the same focused suite (`85 passed`). Deeper signed package apply/rollback fixtures remain partial.
- Flutter config-recovery diagnostic normalization has current-host Flutter startup fixture coverage; source checks in checkpoint 1314 confirm `_boundedConfigRecoveryDiagnostic` bounds and control/NUL-normalizes parse/validation exceptions before startup recovery reasons or audit evidence are emitted, and checkpoint 1567 verifies malformed persisted config surfaces a visible recovery `errorMessage` plus `configuration_recovered` warning event through `flutter test test\config_validation_test.dart --reporter compact` (`21 passed`).
- Flutter Settings and Device feature diagnostic normalization has current-host Flutter fixture coverage for Device platform-provider failures and Settings log-export controller/widget failures; source checks in checkpoint 1315 confirm `_boundedSettingsDiagnostic` and `_boundedDeviceDiagnostic` bound and control/NUL-normalize exceptions before visible UI evidence is emitted, checkpoint 1569 verifies a control/NUL-rich `deviceSummaryProvider` failure renders as normalized visible Device UI text through `flutter test test\settings_accessibility_test.dart --reporter compact` (`2 passed`), checkpoint 1570 verifies control/NUL-rich log-export failures are normalized before visible `errorMessage` and `logs_export_failed` audit details through `flutter test test\local_event_test.dart --reporter compact` (`35 passed`), and checkpoint 1681 verifies the Settings export dialog failure path shows a failure snackbar without a success snackbar through `settings_accessibility_test.dart` (`9 passed`). Installed Settings/Logs E2E remains partial.
- Flutter shell notification diagnostic normalization has current-host Flutter widget fixture coverage; source checks in checkpoint 1316 confirm notification summaries are bounded and control/NUL-normalized before visible toast evidence is emitted, and checkpoint 1566 verifies a `ZentorShell` notification with control/NUL details renders as normalized one-line text through `flutter test test\navigation_accessibility_test.dart --reporter compact` (`4 passed`).
- Flutter cloud response streamed-size hardening is runtime/source-marker verified in checkpoints 1728 and 1778: `api_client_test.dart` passed (`40`) and covers bounded streamed-response source markers, invalid response handling, visible cloud diagnostics, oversized streamed health responses without `Content-Length`, and stalled stream timeouts; live cloud/backend E2E remains partial.
- API project provisioning remains disabled until a real authenticated admin workflow exists; checkpoint 1641 `project` fixtures verify project creation fails closed instead of issuing unauthenticated keys.
- API error response redaction is runtime-verified in checkpoint 1641: `error` passed `1 passed; 0 failed`, confirming database/internal errors do not return raw error strings in JSON responses.
- Flutter install-report Explorer path validation is runtime/source-marker verified in checkpoint 1726: `local_core_ipc_diagnostics_test.dart` passed (`56`) and covers report path revalidation, remote/device/traversal rejection, Avorax root constraints, and absence of raw Explorer selector interpolation.
- Flutter install-report Explorer command path hardening is runtime/source-marker verified in checkpoint 1726: `local_core_ipc_diagnostics_test.dart` passed (`56`) and covers checked Windows Explorer launch markers; packaged Windows click-through smoke remains partial.
- Flutter elevated updater launch encoding is runtime/source-marker verified in checkpoint 1725: `update_service_test.dart` passed (`108`) and covers checked `-EncodedCommand` use plus absence of raw `-Command` launcher construction; elevated Windows smoke remains partial.
- Flutter service-repair executable path hardening is runtime/source-marker verified in checkpoint 1726: `local_core_ipc_diagnostics_test.dart` passed (`56`) and covers service-query failure visibility plus absolute local executable/path markers; elevated Windows service-repair smoke remains partial.
- Flutter local subprocess launch path hardening is runtime/source-marker verified in checkpoint 1726: `local_core_ipc_diagnostics_test.dart` passed (`56`) and covers scan/cancel IPC path probes, executable/report probe failures, bounded subprocess diagnostics, and cancel timeout kill behavior; installed local-core/Guard smoke remains partial.
- Flutter local-core action IPC protocol-warning handling is runtime-verified for the Flutter IPC fixture layer in checkpoint 1666: `local_core_ipc_diagnostics_test.dart` passed (`51`) including `action responses with protocol warnings fail at runtime`, which covers `ok:true` action responses with bounded protocol warnings failing visibly instead of becoming clean Guard/protection configuration success.
- Flutter local-core watcher IPC protocol-warning handling is runtime-verified for the Flutter IPC fixture layer in checkpoint 1666: `local_core_ipc_diagnostics_test.dart` passed (`51`) including `watcher responses with protocol warnings fail at runtime`, which covers `ok:true` watcher responses with bounded protocol warnings failing visibly instead of becoming clean active realtime-monitoring evidence.
- Flutter local-core cancel IPC protocol-warning handling is runtime-verified for the Flutter IPC fixture layer in checkpoint 1667: `local_core_ipc_diagnostics_test.dart` passed (`52`) including `cancel responses with protocol warnings fail at runtime`, which covers malformed stdout before an `ok:true` cancel response becoming visible cancel IPC failure evidence instead of clean cancellation success.
- Flutter local-core list IPC protocol-warning handling is runtime-verified for the Flutter IPC fixture layer in checkpoint 1666: `local_core_ipc_diagnostics_test.dart` passed (`51`) including `list responses with protocol warnings fail at runtime`, which covers `ok:true` quarantine list responses with bounded protocol warnings failing visibly before rows are parsed as actionable UI evidence; allowlist source-marker coverage remains from checkpoint 1520 and installed local-core/UI E2E remains partial.
- Flutter local-core health IPC protocol-warning handling is runtime-verified for the Flutter IPC fixture layer in checkpoint 1668: `local_core_ipc_diagnostics_test.dart` passed (`53`) including `health responses with protocol warnings surface lastError`, which covers `ok:true` health responses with collected protocol warnings surfacing through `LocalCoreHealth.lastError` instead of disappearing behind normal health fields.
- Flutter scan-target environment path validation and probe diagnostic normalization still need installed UI quick/full scan smoke testing; source/direct-contract checks confirm quick/full scan target suggestions no longer use relative or remote environment roots, checkpoint 1690 Flutter/Dart tests confirm local target-planning and watcher probe failures remain visible for core validation instead of silently shrinking coverage, checkpoint 1303 confirms parent-traversing environment roots are rejected before target planning, checkpoint 1304 confirms NUL-containing environment roots are rejected before target planning, and checkpoint 1313 confirms scan-target probe diagnostics are control/NUL-normalized before scan-start limitation evidence is emitted.
- Flutter scan-start busy-state UI has current-host Flutter fixture coverage but still needs installed UI/E2E control verification; source checks in checkpoint 1182 confirm `_scanStartInFlight` is surfaced through `ZentorState.scanStartInFlight`, Home/Scan/Protection scan-start controls disable while scan start is in flight, Scan action-mode changes disable during scan start, and the public busy flag clears through the same `finally` path as the private guard. Checkpoint 1564 passes `flutter test test\offline_scan_test.dart --reporter compact` with `85 passed`, including duplicate scan-start suppression while a scan is running. Checkpoint 1828 adds Scan-tab widget coverage proving `scanStartInFlight=true` disables the action-mode segmented control plus Quick Scan, Full Scan, Custom File, and Custom Folder start controls. Checkpoint 1829 adds matching Scan-tab widget coverage for `scanStatus=running`. Checkpoint 1830 adds Home/Protection widget coverage proving Home Run Quick Scan/Run Full Scan and Protection Run Quick Scan are disabled for both scan-start and running-scan states.
- Flutter scan-cancellation busy-state UI has current-host Flutter fixture coverage but still needs installed UI/E2E control verification; source checks in checkpoint 1179 confirm `_scanCancelInFlight` is surfaced through `ZentorState.scanCancelInFlight`, the Scan Cancel control disables while cancellation is in flight, and the public busy flag clears from the same `finally` path as the private guard. Checkpoint 1564 adds and passes a duplicate-cancel fixture where pending cancel IPC keeps `scanCancelInFlight` true, the second cancel is logged as `scan_cancel_ignored`, and local-core cancel IPC is not called twice. Checkpoint 1832 adds Scan-tab widget coverage proving a running scan with `scanCancelInFlight=true` shows the Cancel control disabled.
- Flutter Quick Scan automatic-quarantine confirmation is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1823: `scan_screen_test.dart` uses fake quick-scan targets and fake local-core scan IPC, opens the automatic-quarantine scan confirmation dialog, proves Cancel does not scan, and proves Confirm starts exactly one quick scan with `autoQuarantineConfirmedOnly` against the expected fixture path. Installed scan-start click/layout E2E remains partial.
- Flutter Full Scan automatic-quarantine confirmation is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1824: `scan_screen_test.dart` uses a fake full-scan root and fake local-core scan IPC, opens the automatic-quarantine scan confirmation dialog, proves Cancel does not scan, and proves Confirm starts exactly one full scan with `autoQuarantineConfirmedOnly` against the expected fixture root. Installed scan-start click/layout E2E remains partial.
- Flutter Quick Scan detect-only start behavior is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1825: `scan_screen_test.dart` uses fake quick-scan targets and fake local-core scan IPC, proves detect-only Quick Scan does not show the automatic-quarantine confirmation dialog, and proves it starts exactly one quick scan with `ScanActionMode.detectOnly`. Installed scan-start click/layout E2E remains partial.
- Flutter Full Scan detect-only start behavior is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1826: `scan_screen_test.dart` uses a fake full-scan root and fake local-core scan IPC, proves detect-only Full Scan does not show the automatic-quarantine confirmation dialog, and proves it starts exactly one full scan with `ScanActionMode.detectOnly`. Installed scan-start click/layout E2E remains partial.
- Flutter Custom File/Folder automatic-quarantine cancel behavior is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1827: `scan_screen_test.dart` opens the automatic-quarantine confirmation from both custom scan controls and proves Cancel does not call local-core scan IPC before picker/scan handoff. Installed OS-picker confirmation/selection and packaged desktop click/layout E2E remain partial.
- Flutter app-detector process command hardening is runtime/source-marker verified in checkpoint 1726: `app_detector_test.dart` passed (`7`) and covers visible process enumeration failures, bounded process output, and avoiding ambient PATH lookup for process enumeration commands; live Windows/Linux/macOS process-enumeration smoke remains partial.
- Flutter app-detector install-root environment validation is runtime/source-marker verified in checkpoint 1726: `app_detector_test.dart` passed (`7`) and covers absolute local environment-value requirements plus visible install-root probe failures; protected-app UI smoke remains partial.
- Flutter platform PowerShell command hardening is runtime/source-marker verified in checkpoint 1726: `platform_info_service_test.dart` passed (`9`) and covers checked WindowsPowerShell, encoded commands, bounded output, failure diagnostics, and no raw command/PATH lookup source markers; live Windows platform-info smoke remains partial.
- Flutter platform-info environment fallback text is runtime verified in checkpoint 1726 through `platform_info_service_test.dart` (`9`) for bounded platform/provider diagnostics; broader non-Windows and installed Windows fallback smoke remains partial.
- Flutter platform-info JSON diagnostics need live Windows platform-info smoke coverage; Flutter/Dart formatting and probe-failure runtime coverage are verified in checkpoint 1688, and source checks in checkpoint 897 confirm supplied malformed Windows system-info JSON string fields append bounded `platform info parse warnings` before compatibility fallbacks are applied.
- Flutter service-state JSON diagnostics need live Windows service-state smoke coverage; Flutter/Dart formatting and probe-failure runtime coverage are verified in checkpoint 1688, and source checks in checkpoint 898 confirm malformed service-state JSON names/values and entry-limit truncation produce bounded visible warnings instead of silent drop or empty-value fallback.
- Flutter updater PowerShell path hardening is runtime/source-marker verified in checkpoint 1725: `update_service_test.dart` passed (`108`) and covers checked WindowsPowerShell path construction plus `-EncodedCommand`; elevated Windows update-launch smoke remains partial.
- Flutter updater executable discovery hardening is runtime/source-marker verified in checkpoint 1725: `update_service_test.dart` passed (`108`) and covers updater executable validation before launch; installed update verify/apply/rollback smoke remains partial.
- Flutter update rollback support labels are runtime-verified for the Flutter UI/component path in checkpoint 1588: missing package `rollback_supported` metadata remains `Unknown`, explicit `false` is `Unavailable`, explicit `true` is `Available`, and the Updates rollback action is disabled unless `rollbackSupported == true`. Installed Settings/Updates click-layout E2E and real signed-package rollback on an installed host remain partial.
- Flutter Settings cloud health check click-through is runtime-verified for the current Flutter widget/controller fixture layer in checkpoint 1849: enabled Test Cloud Connection routes exactly one API health-check call, moves status online, clears `cloudHealthCheckInFlight`, and records `cloud_health_check_started` plus `cloud_online`; the busy `Checking Cloud` state disables the button and makes zero API calls. Live cloud/backend E2E remains partial.
- Flutter update event severity/category is runtime-verified for the controller path in checkpoint 1587: update check start/completion evidence uses update/info or update/warning as appropriate, install/rollback progress and confirmation-required events use update/warning, and check/install failure events use update/error. Installed Home/Settings/Updates UI event-flow E2E remains partial.
- Flutter update action single-flight behavior and Updates/Settings check/install/rollback click-through are runtime-verified for the controller/widget fixture layer in checkpoints 1586, 1842, and 1846-1848: check/install/rollback share `_updateOperationInFlight`; a pending manual update check blocks overlapping install work before download/verify/install begin, emits update/warning busy evidence, keeps `updateOperationInFlight` true while the first check is pending, and clears the guard after the first check completes. Checkpoint 1186 source checks additionally confirm Home, Settings, and Updates controls disable from `ZentorState.updateOperationInFlight`; checkpoint 1842 verifies Updates-tab install/rollback dialogs where Cancel makes zero update-service calls and Confirm routes exactly one download/verify/install or rollback service sequence to `readyToRestart`; checkpoint 1846 verifies Updates-tab Check for updates routes exactly one check call when enabled and zero calls while rendered as busy/disabled; checkpoint 1847 verifies the same Settings check button behavior; checkpoint 1848 verifies Settings install Cancel makes zero service calls and Confirm routes one download/verify/install sequence to `readyToRestart`. Installed updater-service/elevation/network/package-apply/rollback E2E remains partial.
- Flutter local-core elevation PowerShell hardening is runtime/source-marker verified in checkpoint 1726: `local_core_ipc_diagnostics_test.dart` passed (`56`) and covers elevated PowerShell path/encoded-command markers; elevated Windows Start Core Service/Repair smoke remains partial.
- Flutter local-core executable override hardening is runtime/source-marker verified in checkpoint 1726: `local_core_ipc_diagnostics_test.dart` passed (`56`) and covers executable probe failure diagnostics plus local path validation markers; Windows service executable override fixtures remain partial.
- Flutter local-event export temp allocation, body-size limits, and success-path text bounds are runtime/source-marker verified in checkpoint 1727: `local_event_test.dart` passed (`39`) and covers staged safe target writes, body-size bounds before writes, cleanup diagnostics, non-following cleanup checks, recovery visibility, export failure normalization, duplicate export blocking, and controller containment; installed Logs/Settings click-through remains partial.
- Flutter local-event persistence acknowledgement is runtime-verified in checkpoint 1691; `add()` checks the `SharedPreferences.setString` acknowledgement and fails visibly if local audit-history persistence is rejected.
- Flutter local-event clear acknowledgement is runtime-verified in checkpoint 1691; `clear()` checks the `SharedPreferences.remove` acknowledgement and fails visibly if local audit-history removal is rejected.
- Flutter local-event write-time category/severity and raw text rejection is runtime verified in checkpoint 1727: `local_event_test.dart` passed (`39`) and `zentor_protocol_test.dart` passed (`11`), covering new event category/severity rejection before storage, raw control-text rejection, bounded/blank text handling, persisted forged-row rejection, and typed/bounded protocol fields.
- Flutter config persistence acknowledgement is runtime-verified in checkpoint 1691; config save/reset check `SharedPreferences.setString` and `SharedPreferences.remove` acknowledgements and fail visibly if persisted policy storage rejects the operation.
- Flutter local-event decode recovery details are runtime-verified in checkpoint 1689 with `local_event_test.dart` (`37 passed`): corrupt and oversized persisted event histories produce warning recovery events with bounded decode/size details; checkpoint 1310 confirms recovery diagnostics are control/NUL-normalized before audit evidence is written.
- Flutter local-event malformed-row recovery details are runtime-verified in checkpoint 1689 with `local_event_test.dart` (`37 passed`): partially malformed persisted histories preserve valid rows while recording bounded row-level failure reasons instead of only a malformed-row count. Host-scoped keying remains source-accounted in checkpoint 1331, checkpoint 1310 confirms row/decode/cleanup diagnostics are control/NUL-normalized before audit evidence is written, checkpoint 1326 confirms persisted local-event rows with raw control/NUL characters are treated as malformed instead of being trimmed or downgraded through compatibility fallback, checkpoint 1327 confirms oversized persisted local-event ID/type/message/details values are treated as malformed rows instead of silently truncated into different audit evidence, and checkpoint 1328 confirms excessive persisted local-event row counts fail before per-row parsing.
- Flutter scan-progress missing timestamp diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1670: `local_core_ipc_diagnostics_test.dart` passed (`56`) including malformed/missing `started_at`/`updated_at` progress timestamp evidence adding bounded scan errors before compatibility timestamps are applied.
- Flutter scan-progress job-id diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1670: malformed `job_id` progress evidence adds bounded diagnostics and the malformed progress snapshot is not emitted to the progress callback.
- Flutter scan-progress current-path diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1670: malformed optional `current_path` progress evidence adds bounded diagnostics before compatibility null path fallback is applied.
- Flutter scan-progress percent-range diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1670: finite out-of-range `progress_percent` evidence is rejected with bounded diagnostics before compatibility unknown-progress fallback is applied.
- Flutter scan-progress identity/status diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1670: malformed `scan_type` and `status` progress fields add bounded diagnostics and malformed progress snapshots fail closed instead of using compatibility custom/running fallbacks.
- Flutter scan-progress numeric-field diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1670: malformed/missing required progress counters add bounded diagnostics before compatibility zero fallbacks are applied.
- Flutter scan metric no-evidence labels are runtime verified in checkpoint 1777: `scan_screen_test.dart` passes (`2`) and confirms report-backed metrics show `No report` without `lastScanReport`, live progress facts show `Pending` without a progress snapshot, and explicit `0`/`0s` labels are absent without evidence.
- Flutter engine-unavailable asset-pack labels are runtime-verified for the current Flutter widget layer in checkpoint 1780: Home, Protection, and Settings render zero signature/rule counts as `Unknown` while native-engine readiness is unproven, with `settings_accessibility_test.dart` passing (`13`). Source checks in checkpoint 1052 still confirm signature/rule pack zero counters are labeled missing/loaded only when native engine status is ready. Installed desktop visual/E2E remains partial.
- Flutter Home/Protection/Settings pack-count labels are runtime-verified for the current Flutter widget layer in checkpoint 1780: zero signature/rule counts remain unknown until `nativeEngineStatus == ready`, then explicit zero loaded counts are rendered. Source checks in checkpoint 1053 remain as guardrails for the helper logic. Installed Windows visual/E2E remains partial.
- Flutter Home/Protection/Settings driver-status labels are runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`), `protection_status_test.dart` passed (`1`), and driver/protection copy remains distinct in UI fixtures; installed Windows visual/E2E remains partial.
- Flutter Home/Protection/Settings Guard-status labels are runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) with service/protection status surfaces that do not hard-code running/protected states; installed Windows visual/E2E remains partial.
- Flutter Guard-status unknown fallback is partially runtime-verified for the current Flutter fixture layer in checkpoints 1643 and 1646: `local_core_ipc_diagnostics_test.dart` passed (`42`) for malformed health parsing, and `app_visual_policy_test.dart` passed (`57`) for honest Guard/protection status display; installed local-core health IPC E2E remains partial.
- Flutter native ML and Local AI status labels are runtime-verified for the current Flutter widget layer in checkpoint 1784: Home, Device, Settings, and Scan render allowed native ML statuses `loaded`, `developmentModel`, `modelMissing`, `error`, and unrecognized fallbacks as explicit labels, while Protection renders `AiModelStatus` checklist labels without stale production/active aliases. `scan_screen_test.dart` plus `settings_accessibility_test.dart` pass together (`24`). Installed desktop visual/service E2E remains partial.
- Flutter AI model feature-schema fallback is runtime-verified for the current Flutter widget/parser fixture layer in checkpoint 1785: malformed IPC schema metadata falls back to `unavailable`, Settings renders `unavailable` and blank schema evidence as `Unavailable`, valid schema metadata renders verbatim, and fabricated `1.0.0`/`zne-features-v1` defaults are absent. `settings_accessibility_test.dart` passes (`21`) and source-contracts pass (`481`). Installed Local Core health/UI E2E remains partial.
- Flutter Protection Native Engine checklist labels are runtime-verified for the current Flutter widget layer in checkpoint 1786: `nativeEngineStatus='unavailable'` renders `Unavailable` through the Protection checklist path and does not collapse into generic `Error`. `settings_accessibility_test.dart` passes (`22`). Installed desktop visual/service E2E remains partial.
- Flutter Protection Native Engine metric labels are runtime-verified for the current Flutter widget layer in checkpoint 1781: Protection renders `ready`, `error`, `unavailable`, unknown values, and `lastEngineError` diagnostic override through the status-aware helper; `settings_accessibility_test.dart` passes (`15`). Installed desktop visual/E2E remains partial.
- Flutter Home/Device Native Engine metric labels are runtime-verified for the current Flutter widget layer in checkpoint 1781: Home and Device distinguish `ready`, `error`, `unavailable`, and unknown native-engine evidence, and diagnostic detail overrides ready status with `Attention needed`; `settings_accessibility_test.dart` passes (`15`). Installed desktop visual/E2E remains partial.
- Flutter Settings Native Engine status labels are runtime-verified for the current Flutter widget layer in checkpoint 1781: Settings distinguishes `ready`, `error`, `unavailable`, and unknown native-engine evidence instead of showing raw IPC strings, and diagnostic detail overrides ready status with `Attention needed`; `settings_accessibility_test.dart` passes (`15`). Installed desktop visual/E2E remains partial.
- Flutter Device Guard/driver status labels are runtime-verified for the current Flutter widget layer in checkpoint 1782: Device renders unknown Guard/driver evidence as `Unknown`, and the driver detail does not collapse unknown evidence to `Missing` or `Not running`; `settings_accessibility_test.dart` passes (`17`). Installed desktop visual/service E2E remains partial.
- Flutter watcher-mode status alignment is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) and `offline_scan_test.dart` passed (`96`), covering honest best-effort watcher copy, watcher startup, watcher stop, and watcher limitation handling; installed watcher E2E remains partial.
- Flutter protection-start watcher diagnostic event honesty is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) including `controller logs limited protection starts distinctly`, and `offline_scan_test.dart` passed (`96`) for best-effort watcher start/stop behavior; installed watcher E2E remains partial.
- Flutter watcher active-without-paths diagnostics are runtime-verified for the current Flutter IPC fixture layer in checkpoint 1788: active watcher IPC responses with valid empty watched paths surface bounded diagnostics through both `RealtimeWatcherState.error` and `limitations`, while malformed watched-path evidence is not relabeled as active-without-paths. Focused `local_core_ipc_diagnostics_test.dart` watcher-state filter passes (`5`). Installed watcher E2E remains partial.
- Flutter Protection quarantine-readiness copy is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) and includes protected-state/readiness UI honesty coverage; installed visual/E2E remains partial.
- Flutter driver-status unknown fallback is partially runtime-verified for the current Flutter fixture layer in checkpoints 1643 and 1646: malformed health parser fixtures passed in `local_core_ipc_diagnostics_test.dart` (`42`) and status/protection UI fixtures passed in `app_visual_policy_test.dart` (`57`); installed local-core health IPC E2E remains partial.
- Flutter Device service-detail missing-evidence labels are runtime-verified for the current Flutter widget layer in checkpoint 1782: partially missing service-state maps render `unknown; service evidence missing` for absent Guard/Update rows instead of fabricated not-installed evidence; `settings_accessibility_test.dart` passes (`17`). Installed desktop service/visual E2E remains partial.
- Flutter Scan Core Service status labels are runtime-verified for the current Flutter widget layer in checkpoint 1783: Scan engine-unavailable diagnostics render `unknown`, `unsupported`, `error`, and truly unrecognized Core Service evidence as distinct chip labels, with `scan_screen_test.dart` plus `settings_accessibility_test.dart` passing together (`21`). Installed Windows visual/service E2E remains partial.
- Flutter Protection Core Service status labels are runtime-verified for the current Flutter widget layer in checkpoint 1783: the Protection readiness checklist renders `unknown`, `unsupported`, `error`, and truly unrecognized Core Service evidence distinctly instead of defaulting to fabricated unknown/ready evidence. Installed Windows visual/service E2E remains partial.
- Flutter scan engine-unavailable messages remain source-accounted but installed UI/E2E partial: source checks in checkpoint 1061 confirm stopped, installed, missing, unknown, and error Core Service states keep distinct scanbanner guidance before generic native-engine unavailable copy is used, while checkpoint 1783 adds widget evidence for the visible Core Service status chips.
- Flutter Core Service unsupported-status alignment is runtime-verified for the current Flutter widget layer in checkpoint 1783: local-core non-Windows `unsupported` status is rendered explicitly in Scan/Protection instead of being treated as malformed or unavailable. Installed Windows visual/service E2E remains partial.
- Flutter scan-progress snapshot fail-closed behavior is runtime-verified for the Flutter IPC fixture layer in checkpoint 1670: malformed required progress job-id/type/status/timestamps/counters drop the progress snapshot after bounded diagnostics instead of sending empty/current-time/zero/custom/running placeholders to the UI or progress callback.
- Flutter Home threat-status evidence is runtime-verified for the current Flutter widget layer in checkpoint 1787: Home does not render `Threats found`/`Review threats` without a scan report or with a clean zero-threat report, and renders both only when `lastScanReport.threatsFound > 0`. `settings_accessibility_test.dart` passes (`23`). Installed scan/UI E2E remains partial.
- Flutter clean scan-report error-status evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1670: `clean` final reports with collected scan/protocol errors, including nested progress diagnostics, are presented as `completedWithErrors` instead of clean success.
- Shared Dart config string-list validation is runtime-verified for the shared protocol parser in checkpoint 1673: `packages/zentor_protocol/test/zentor_protocol_test.dart` passed (`11`) including blank scan paths, ransomware protected roots, and trusted-process entries failing instead of being silently filtered, plus raw control/NUL rejection before trimming. Runtime Settings path-list normalization still has checkpoint 1575 coverage for control-character ransomware paths; broader installed Settings UI path-list interaction remains pending.
- Flutter scan event severity/category is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) including scan/custom/cancel event categorization, and `offline_scan_test.dart` passed (`96`) including scan warnings, cancellation, duplicate scan-start, and scheduled detect-only scan behavior; installed UI event-flow E2E remains partial.
- Flutter quarantine/allowlist action event severity/category is partial: source checks in checkpoint 966 confirm quarantine actions log quarantine warning/error evidence and allowlist trust mutations log protection warning/error evidence instead of default app/info history; checkpoint 1577 runtime-verifies overlapping allowlist busy evidence is `protection`/`warning`; checkpoint 1578 runtime-verifies overlapping quarantine busy evidence is `quarantine`/`warning`; checkpoint 1812 runtime-verifies allowlist-add IPC exception evidence is bounded normalized `protection`/`error` while preserving the detected threat state instead of marking it allowlisted; checkpoint 1813 runtime-verifies allowlist-remove IPC exception evidence is bounded normalized `protection`/`error` while keeping the allowlist row active instead of falsely showing normal policy resumed; checkpoint 1814 runtime-verifies manual quarantine IPC exception evidence is bounded normalized `quarantine`/`error` while preserving the detected threat state instead of falsely marking it quarantined; checkpoint 1815 runtime-verifies quarantine restore IPC exception evidence is bounded normalized `quarantine`/`error` while keeping the row quarantined instead of falsely marking it restored; checkpoint 1816 runtime-verifies quarantine delete IPC exception evidence is bounded normalized `quarantine`/`error` while keeping the row quarantined instead of falsely marking it deleted. Broader installed Quarantine restore/delete click-through E2E remains pending.
- Flutter detection-feedback event severity/category is partial: source checks in checkpoint 967 confirm false-positive and malicious feedback confirmations/successes log protection warning evidence and feedback failures log protection error evidence instead of default app/info history, checkpoint 1576 runtime-verifies duplicate feedback busy evidence is `protection`/`warning`, checkpoint 1810 runtime-verifies a false-positive label IPC exception emits bounded normalized `protection`/`error` evidence while preserving the detected threat state instead of suppressing it, and checkpoint 1811 runtime-verifies a malicious label IPC exception emits bounded normalized `protection`/`error` evidence while preserving the detected threat's review recommendation instead of escalating it to quarantine. Broader installed Scan UI event-flow coverage remains pending.
- Flutter Scan-result false-positive feedback click-through is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1820: `scan_screen_test.dart` opens the Mark false positive confirmation dialog for a review detection, proves Cancel does not call local-core, and proves confirm routes the expected threat ID with the `falsePositive` label through detection-label IPC. Installed Scan-result feedback click/layout E2E remains partial.
- Flutter Scan-result malicious feedback click-through is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1821: `scan_screen_test.dart` opens the Mark malicious confirmation dialog for a review detection, proves Cancel does not call local-core, and proves confirm routes the expected threat ID with the `confirmedMalicious` label through detection-label IPC without claiming quarantine/delete. Installed Scan-result feedback click/layout E2E remains partial.
- Flutter detection-feedback single-flight behavior is runtime-verified for the controller path in checkpoint 1576: false-positive and malicious feedback share `_detectionFeedbackInFlight`, duplicate feedback during a pending local-core training-label IPC fails visibly, local-core `labelDetection` is not called twice, and the guard releases after the first IPC completes.
- Flutter detection-feedback busy-state UI is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1794: source checks in checkpoint 1174 confirm `_detectionFeedbackInFlight` is surfaced through `ZentorState.detectionFeedbackInFlight`, Scan result Mark false positive and Mark malicious controls disable while detection feedback is in flight, checkpoint 1576 runtime-verifies the public busy flag is true during pending label IPC and false after completion, and `scan_screen_test.dart` now verifies `detectionFeedbackInFlight=true` disables Mark false positive and Mark malicious for a review threat. Installed Scan-result click/layout E2E remains partial.
- Flutter security-settings single-flight behavior is runtime-verified for the controller path in checkpoint 1579: protection mode, ransomware guard settings, and scheduled quick scan settings share `_securitySettingsActionInFlight`; an overlapping ransomware settings write during pending Guard-mode IPC fails visibly; ransomware-guard IPC is not called; and the guard releases after the mode write completes.
- Flutter in-app scheduled quick scan activation is runtime-verified in checkpoint 1767: timer creation happens before config persistence, pending timers are cancelled on failure, startup timer failures log `scheduled_quick_scan_startup_failed`, and a failing timer factory does not save an enabled schedule or emit a fake success event. Checkpoint 1977 adds runtime/source proof that scheduled timer fires skip instead of starting while custom target selection is active and that scan action-mode changes are blocked during target selection. This remains an app-lifetime timer, not a Windows scheduled task or background service.
- Flutter security-settings busy-state UI is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1795: source checks in checkpoint 1168 confirm `_securitySettingsActionInFlight` is surfaced through `ZentorState.securitySettingsActionInFlight`, the Settings protection/profile, ransomware policy text fields, ransomware-save, and scheduled-scan controls disable while a security settings write is in flight, checkpoint 1579 runtime-verifies the public busy flag is true during pending Guard-mode IPC and false after completion, and `settings_accessibility_test.dart` now verifies `securitySettingsActionInFlight=true` disables the Protection mode dropdown, ransomware protected folders and trusted-process text fields, Save ransomware protection settings button, scheduled quick-scan switch, and scan interval dropdown. Installed Settings click/layout E2E remains partial.
- Flutter Settings security confirmation click-through is runtime-verified for the current Flutter widget/controller/local-core fixture layer in checkpoint 1839: Protection mode Cancel makes no Guard-mode IPC call and Confirm persists Lockdown through one Guard-mode call; ransomware guard Cancel makes no core policy call and Confirm routes/persists protected-root and trusted-process policy; scheduled quick-scan Cancel preserves a disabled schedule and Confirm persists the app-lifetime detect-only schedule. Installed desktop service/local-core policy E2E and true Windows scheduled-task/background scheduling remain partial or technically limited.
- Flutter protection self-test busy-state UI is runtime-verified for the widget layer in checkpoint 1654: `settings_accessibility_test.dart` passed (`3`) including `self-test buttons disable and relabel while busy`, which renders Protection and Settings with `protectionSelfTestInFlight=true` and verifies both self-test buttons relabel to running/busy text and have disabled `onPressed` handlers. Installed desktop click/layout E2E remains partial.
- Flutter Protection/Settings protection self-test click-through is runtime-verified for the current Flutter widget/controller/local-core fixture layer in checkpoint 1838: Protection `Run protection self-test` and Settings `Run Protection Self-Test` each route exactly one call to the local-core self-test stub and render the fixture result. Installed desktop PowerShell/driver self-test E2E remains partial.
- Flutter service-recovery single-flight behavior is runtime-verified for the controller path in checkpoint 1583: Start Core Service, Open install report, and Repair installation share `_serviceActionInFlight`; an overlapping Repair request during pending Start Core Service IPC fails visibly, does not call repair/report IPC, and releases the guard after the first request completes.
- Flutter service-recovery busy-state UI is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1796: source checks in checkpoint 1173 confirm `_serviceActionInFlight` is surfaced through `ZentorState.serviceActionInFlight`, the Scan diagnostics Start Core Service, Open install report, and Repair installation controls disable while a service recovery action is in flight, checkpoint 1583 runtime-verifies the public busy flag is true during pending service IPC and false after completion, and `scan_screen_test.dart` now verifies `serviceActionInFlight=true` disables Start Core Service, Open install report, and Repair installation in engine-unavailable diagnostics. Checkpoint 1833 adds widget/controller/local-core fixture coverage for Start/Open/Repair confirmation click-through and Start cancel no-op; checkpoint 1834 adds matching Open install report and Repair installation cancel no-op coverage. Installed Scan diagnostics/service-control E2E remains partial.
- Flutter threat-ignore event severity/category is runtime-verified for selected controller paths in checkpoint 1584: duplicate ignore busy evidence is logged as `scan`/`warning`, complementing checkpoint 968 source checks for confirmation and confirmed ignore outcomes. Broader installed Scan UI event-flow coverage remains pending.
- Flutter threat-ignore single-flight behavior is runtime-verified for the controller path in checkpoint 1584: Keep/Ignore uses `_threatIgnoreActionInFlight`; duplicate ignore during pending `threat_ignored` audit write fails visibly, does not write a second ignored event, and leaves the detection visible until the first audited ignore completes.
- Flutter threat-ignore busy-state UI is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1794: source checks in checkpoint 1175 confirm `_threatIgnoreActionInFlight` is surfaced through `ZentorState.threatIgnoreActionInFlight`, Scan result Keep / Ignore disables while a threat ignore action is in flight, checkpoint 1584 runtime-verifies the public busy flag is true during pending audit write and false after completion, and `scan_screen_test.dart` now verifies `threatIgnoreActionInFlight=true` disables Keep / Ignore for a review threat. Installed Scan-result click/layout E2E remains partial.
- Flutter Scan-result Keep / Ignore click-through is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1822: `scan_screen_test.dart` opens the Keep and ignore confirmation dialog for a review detection, proves Cancel leaves the threat detected, and proves confirm marks the threat ignored while clearing the ignore busy state. Installed Scan-result ignore click/layout E2E remains partial.
- Flutter scan-cancellation event severity/category is runtime-verified for the controller fixture layer in checkpoint 1672: `offline_scan_test.dart` passed (`101`) including ignored cancellation, successful cancellation, fallback-warning cancellation, and failed cancellation evidence all using scan category with explicit warning/info/error severity. Installed Scan UI click/E2E event-flow coverage remains partial.
- Flutter settings event severity/category is partial: source checks in checkpoint 970 confirm `settings` is an allowed local-event category and developer cloud override, log export, and configuration reset controls use settings category with explicit severity instead of fallback app/info history; checkpoints 1570, 1580, and 1581 runtime-verify selected Settings failure/busy events. Broader installed Settings UI event-flow coverage remains pending.
- Flutter log-export single-flight and Settings/Logs failure/busy/click-through feedback are runtime-verified for controller/widget paths in checkpoints 1674/1681/1682/1683/1841: `local_event_test.dart` passed (`36`) including pending export work keeping `logExportInFlight` true, duplicate export returning no path, emitting `logs_export_busy` as `settings`/`warning`, not starting a second repository export, and clearing the public busy flag after the original export completes; `settings_accessibility_test.dart` covers the Settings export dialog failure path with no fake success, both Settings and Logs busy buttons, and checkpoint 1841 covers Settings Export logs Cancel making zero export calls and Confirm routing exactly one event-repository export call with visible success feedback and a `logs_exported` event. Installed packaged filesystem export E2E coverage remains partial.
- Flutter developer cloud override validation is runtime-verified for the controller, repository, and Settings save/failure/disable/busy widget paths in checkpoints 1675-1680: `offline_scan_test.dart` passed (`102`) including invalid enabled overrides failing before config state mutation or follow-up cloud health checks, with `configuration_save_failed` logged as `settings`/`error`; `config_validation_test.dart` passed (`23`) including repository-level invalid enabled override rejection before persisted JSON is overwritten; `settings_accessibility_test.dart` passed (`8`) including switch/text-field/dialog confirmation, persisted JSON for valid save, invalid override UI failure with no success snackbar/persistence/cloud health call, disable restoring build-config cloud settings in state and persisted JSON, and busy-state disabling of the Settings switch, endpoint/project/key fields, and save button. Packaged Windows E2E interaction remains partial.
- Flutter developer cloud override single-flight behavior is runtime-verified for the controller path in checkpoint 1580: override saves/disables use `_developerCloudOverrideInFlight`, duplicate saves during pending follow-up cloud health-check work fail visibly, and the guard releases after the health check completes.
- Flutter developer cloud override busy-state UI is runtime-verified for the widget layer in checkpoint 1680: source checks in checkpoint 1177 confirm `_developerCloudOverrideInFlight` is surfaced through `ZentorState.developerCloudOverrideInFlight`, Settings developer override switch, endpoint/key fields, and save/disable button disable while a developer cloud override change is in flight; checkpoint 1580 runtime-verifies the public busy flag is true during pending cloud health-check work and false after completion; checkpoint 1680 verifies the Settings switch, endpoint/project/key fields, and save button are disabled when the public busy flag is true. Packaged Windows click/layout coverage remains pending.
- Flutter onboarding completion single-flight behavior is runtime-verified for the controller path in checkpoint 1582: duplicate Continue/completion calls during pending config persistence fail visibly before a second save starts, keep `save` single-called, and release the in-flight guard in `finally`. Busy-state UI is partial: checkpoint 1184 source checks confirm `_onboardingCompletionInFlight` is surfaced through `ZentorState.onboardingCompletionInFlight`, the Onboarding Continue control disables while onboarding completion is in flight, and checkpoint 1582 runtime-verifies the public busy flag is true during pending persistence and false after completion. Installed Onboarding widget click/layout coverage remains pending.
- Flutter configuration reset side-effect cleanup is partial: source checks in checkpoint 1148 confirm confirmed reset stops active local protection before removing preferences, blocks reset if stop evidence is incomplete, and reconfigures the app-lifetime scheduled quick scan timer from reset defaults; checkpoint 1581 runtime-verifies the active-protection stop path completes before preferences reset and returns the app to idle defaults after pending Guard-mode IPC releases; checkpoint 1840 runtime-verifies the Settings reset confirmation dialog Cancel path preserves non-default settings and Confirm restores default config/state with visible success feedback. Installed Settings UI/E2E reset coverage with a real packaged app and active service/driver stop-before-reset remains pending.
- Flutter configuration reset single-flight behavior is runtime-verified for the controller path in checkpoint 1581: duplicate reset calls during pending protection-stop Guard-mode IPC fail visibly before overlapping `stopWatch` or preference-reset work starts, keep local-core stop work single-called, and release the in-flight guard in `finally`.
- Flutter configuration reset busy-state UI is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1797: source checks in checkpoint 1176 confirm `_configurationResetInFlight` is surfaced through `ZentorState.configurationResetInFlight`, Settings Reset configuration disables while configuration reset is in flight, checkpoint 1581 runtime-verifies the public busy flag is true during pending Guard-mode IPC and false after completion, and `settings_accessibility_test.dart` now verifies `configurationResetInFlight=true` disables the Reset configuration control. Installed Settings reset click/layout E2E remains partial.
- Shared Dart local-event category/severity and raw text parsing is runtime-verified in checkpoint 1671: `packages/zentor_protocol/test/zentor_protocol_test.dart` passed (`9`) including missing optional category/severity conservative defaults, present unsupported category/severity fail-closed parsing, and raw control/NUL rejection for ID, type, message, details, timestamp, category, and severity before trimming or fallback handling.
- Shared Dart settings event category alignment is runtime-verified in checkpoint 1671: `LocalEvent.fromJson` preserves `settings` as a first-class event category while forged categories still fail instead of falling back.
- Flutter protection-readiness event severity/category is broadly runtime-verified for the current Flutter controller layer in checkpoint 1802: startup app-detection start, empty process snapshot, no-supported-app detection, malware-engine available-with-diagnostics, app-detection failure, and malware-health failure events use the `protection` category with expected info/warning/error severities and visible diagnostic details. Installed Protected Apps/Settings click-through E2E remains partial.
- Flutter malware-engine health busy-path visibility is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1789: duplicate health refresh paths remain source-accounted with `malware_engine_health_busy` protection warning evidence, and Settings renders `malwareEngineHealthCheckInFlight=true` as a disabled `Checking engine` button with no idle `Check engine` action. `settings_accessibility_test.dart` passes (`24`). Installed Settings click/layout E2E remains partial.
- Flutter protected-app autodetection single-flight behavior and busy-state UI are runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1790: source checks in checkpoint 1158 confirm protected-app detection uses `_appDetectionInFlight`, duplicate startup/rescan overlap fails visibly, and the guard releases in `finally` after disabled, no-app, detected, or failed detection paths; checkpoint 1183 source checks confirm `_appDetectionInFlight` is surfaced through `ZentorState.appDetectionInFlight`; and `settings_accessibility_test.dart` now verifies `appDetectionInFlight=true` renders Protected Apps `Rescanning`, disables the button, hides idle `Rescan`, and keeps automatic detection supported. Installed Protected Apps click/layout E2E remains partial.
- Flutter protected-app mutation event severity/category is partial: source checks in checkpoint 972 confirm manual file/folder selection, detected-app selection, manual app add, and build-hash controls log protection warning/error evidence instead of default app/info history, and checkpoint 1585 runtime-verifies overlapping protected-app busy evidence is `protection`/`warning`. Checkpoint 1079 source checks confirm selected-app path probe failures stop build-hash calculation with protection/error evidence before any hash is written. Checkpoint 1844 runtime-verifies the Protected Apps build-hash dialog: Cancel makes zero hash-service calls and Confirm performs exactly one selected-path hash, saves the calculated hash, sets verified status, records `file_hash_calculated`, and keeps long SHA-256 row evidence bounded. Broader installed Protected Apps UI/filesystem event-flow coverage remains pending.
- Flutter protected-app action single-flight behavior is runtime-verified for the controller path in checkpoint 1585: manual file/folder selection, detected-app selection, and build-hash calculation share `_protectedAppActionInFlight`; overlapping detected-app selection during pending build-hash work fails visibly, preserves the original selected app, and releases the guard after the first hash completes.
- Flutter protected-app action busy-state UI is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1798: source checks in checkpoint 1178 confirm `_protectedAppActionInFlight` is surfaced through `ZentorState.protectedAppActionInFlight`, Protected Apps add file/folder, calculate hash, and detected-app selection rows disable while a protected-app action is in flight, checkpoint 1585 runtime-verifies the public busy flag is true during pending hash work and false after completion, and `settings_accessibility_test.dart` now verifies `protectedAppActionInFlight=true` disables Add file or app, Add folder, Calculate build hash, and detected-app row selection. Checkpoint 1845 runtime-verifies the detected-app row selection click-through: Cancel preserves the manual app and scan scope while Confirm saves the detected app, adds its path to scan scope, records `protected_app_selected`, and fixes the row `ListTile` material boundary. Installed Protected Apps desktop E2E remains partial.
- Flutter service recovery event severity/category is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) including service recovery event categorization, and `offline_scan_test.dart` passed (`96`) including service recovery overlap blocking and exception reporting; installed service-control E2E remains partial.
- Flutter protection-state event severity/category is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) including protection restore/mode-change/stop/limited-start event categorization, and `offline_scan_test.dart` passed (`96`) including start/stop and recovery flows; installed service/driver E2E remains partial.
- Flutter custom scan event severity/category is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) for custom scan picker/no-target event categorization, and `offline_scan_test.dart` passed (`96`) for custom unsupported/blocker scan reports; installed picker/UI E2E remains partial.
- Flutter custom scan target-selection single-flight behavior and busy-state UI are runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1791: source checks in checkpoint 1162 confirm Custom File and Custom Folder share `_scanTargetSelectionInFlight`, duplicate target-picker actions fail visibly before OS picker launch, and the guard releases in `finally` after picker cancellation, picker failure, or scan handoff; checkpoint 1180 source checks confirm the guard is surfaced through `ZentorState.scanTargetSelectionInFlight`; and `scan_screen_test.dart` now verifies `scanTargetSelectionInFlight=true` disables Quick Scan, Full Scan, Custom File, and Custom Folder controls. Installed OS-picker and Scan click/layout E2E remain partial.
- Flutter scan action-mode policy boundary is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `offline_scan_test.dart` passed (`96`), including confirmed auto-action scan mode behavior, unconfirmed auto-action preservation, duplicate scan-start blocking, and scan warning evidence; installed UI E2E remains partial.
- Flutter Home/Protection scan shortcut action-mode behavior is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) including `protection quick scan shortcut is detect only`, and `offline_scan_test.dart` passed (`96`) including scheduled detect-only scan behavior. Checkpoint 1831 adds widget/controller/local-core fixture coverage proving Home Run Quick Scan, Home Run Full Scan, and Protection Run Quick Scan send `ScanActionMode.detectOnly` even when Scan-tab state is `autoQuarantineConfirmedOnly`; installed UI E2E remains partial.
- Flutter update progress event severity/category is runtime-verified for the controller fixture layer in checkpoint 1657: `update_controller_test.dart` passed (`32`) including `update events carry explicit category and severity at runtime`, which covers update check started/failed, update available, install confirmation/started/ready/failed, and rollback started/ready events with explicit update category and expected info/warning/error severities. Installed updater service/release-package E2E remains partial.
- Flutter scheduled scan/self-test/heartbeat event severity/category and runtime behavior is runtime-verified for the controller fixture layer in checkpoint 1658: `offline_scan_test.dart` passed (`101`) including scheduled quick-scan settings/start metadata and `scheduled scan self-test and heartbeat events carry runtime metadata`, which covers protection self-test start, heartbeat success, and heartbeat failure events with explicit scan/protection category and info/warning severity. Installed app-lifetime scheduling, UI event-flow E2E, and live cloud backend smoke remain partial.
- Flutter protection start/stop single-flight behavior is runtime-verified for the controller path in checkpoint 1656: `offline_scan_test.dart` passed (`100`) including `start protection blocks overlapping stop while guard IPC is pending`, which covers one Guard-mode IPC call during pending start, no stop-watch IPC for overlapping stop, visible `protection_action_busy` warning evidence, retained busy state during the pending action, and final guard cleanup after completion. Installed service/driver E2E remains partial.
- Flutter protection start/stop busy-state UI is runtime-verified for the current Flutter widget layer: checkpoint 1655 `settings_accessibility_test.dart` included `protection operation busy disables start stop and self-test UI`, proving Home start, Protection start/stop, and Protection/Settings self-test buttons are disabled while `protectionOperationInFlight=true`; checkpoint 1835 adds Home Stop Protection coverage with `ProtectionStatus.protected` and `protectionOperationInFlight=true`. Installed desktop click/layout E2E remains partial.
- Flutter Home Enable/Stop Protection confirmation click-through is runtime-verified for the current Flutter widget/controller/local-core fixture layer in checkpoint 1836: Home Enable/Stop confirmations open, Cancel does not call Guard/watch IPC stubs, Enable confirm routes Guard mode `balanced` with no watcher call when no watch roots are configured, and Stop confirm routes Guard mode `off` plus watcher-stop. Installed desktop service/driver click-through E2E remains partial.
- Flutter Protection-tab Enable/Stop Protection confirmation click-through is runtime-verified for the current Flutter widget/controller/local-core fixture layer in checkpoint 1837: Protection Enable/Stop confirmations open, Cancel does not call Guard/watch IPC stubs, Enable confirm routes Guard mode `balanced` with no watcher call when no watch roots are configured, and Stop confirm routes Guard mode `off` plus watcher-stop. Installed desktop service/driver click-through E2E remains partial.
- Flutter controller local-event metadata inventory is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) including controller event category/severity coverage, and `local_event_test.dart` passed (`35`) including category/severity constraints before persistence.
- Local-core scan-error detail bounds need Cargo/rustfmt execution and long-error scan fixture verification; source checks in checkpoints 1112-1113 confirm scan errors keep the existing count cap, each error detail is NUL-normalized and truncated before report serialization, and omitted details are represented by an explicit omission notice instead of disappearing silently.
- Native engine scan-summary error detail bounds need Cargo/rustfmt execution and over-cap native scan-error fixture verification; source checks in checkpoint 1115 confirm native scan errors keep the 20-detail cap, NUL-normalize and truncate each detail before summary storage, and replace the final capped entry with an explicit omission notice when additional errors are dropped.
- Flutter scan-report identity/status diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1659: `local_core_ipc_diagnostics_test.dart` passed (`43`) including `scan report records malformed final report fields`, which covers malformed final report `status`, `kind`, and `action_mode` evidence adding bounded scan errors before compatibility fallback values are used.
- Flutter scan-report numeric-field diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1659: `local_core_ipc_diagnostics_test.dart` passed (`43`) including malformed/missing required and optional final report counters adding bounded scan errors instead of silent zero/null fallback evidence.
- Flutter scan-report current-path diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1659: `local_core_ipc_diagnostics_test.dart` passed (`43`) including malformed final report `current_path` becoming null with explicit bounded scan-error evidence.
- Flutter scan-report message diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1659: `local_core_ipc_diagnostics_test.dart` passed (`43`) including malformed final report `message` becoming null with explicit bounded scan-error evidence.
- Flutter dead scan-status wrapper cleanup is Flutter/Dart verified on the current host in checkpoint 1801: `local_core_ipc_diagnostics_test.dart` focused `scan report and progress parsers bound string IPC fields` passed, `dart format` reported no changes, and the fixture confirms the unused private `_scanStatus` wrapper remains absent while `_scanStatusOrNull` stays active in report status parsing.
- Flutter health engine-status diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1669: `local_core_ipc_diagnostics_test.dart` passed (`54`) including `health responses record malformed field diagnostics at runtime`, which covers malformed aggregate `engine_status` adding bounded health diagnostics before compatibility unavailable fallback is applied.
- Flutter health AI-model diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1669: malformed nested `ai_model` status/version/schema/message/production-ready evidence is surfaced through `LocalCoreHealth.lastError` before compatibility default AI model information is applied.
- Flutter health status-string diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1669: malformed YARA, native-engine, native-ML, Core Service, Guard, driver, process monitor, behavior monitor, and reputation status strings add bounded diagnostics before compatibility fallback labels are applied.
- Flutter health numeric-counter diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1669: malformed YARA/native signature/native rule counters add bounded diagnostics before compatibility zero counters are applied.
- Flutter health diagnostic-string diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1669: malformed optional local-core diagnostic strings such as `native_error` add bounded diagnostics before null fallbacks, while absent diagnostic strings remain optional.
- Flutter health metadata/path-string diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1669: malformed optional local-core path metadata such as `install_path`, `engine_directory`, and `program_data_dir` adds bounded diagnostics before null fallbacks, while absent metadata remains optional.
- Flutter nested AI-model health diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1669: malformed nested `ai_model` status, model version, feature schema version, message, and production-ready boolean fields are reported through bounded `lastError` diagnostics before compatibility fallbacks.
- Flutter nested threat-row diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1660: `local_core_ipc_diagnostics_test.dart` passed (`44`) including `scan report drops threats with missing required evidence`, existing malformed timestamp/risk/row fixtures, and source-marker parser checks for required enum/string/numeric evidence.
- Flutter local-core threat label/engine evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1660: malformed or empty `threatName`/`threat_name` and `engine` rows are dropped with explicit scan-error evidence instead of displaying fabricated `Suspicious file` or `zentor` labels.
- Flutter local-core threat timestamp evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1660: malformed `detectedAt`/`detected_at` rows are dropped with explicit scan-error evidence instead of using current-time fallback evidence.
- Flutter local-core threat size evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1660: malformed `sizeBytes`/`size_bytes` rows are dropped with explicit scan-error evidence instead of displaying zero-byte fallback evidence.
- Flutter local-core threat enum evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1660: malformed detection type, threat category, confidence, recommended action, and status rows are dropped with explicit scan-error evidence instead of defaulting to unknown/low/review/detected values.
- Flutter nested risk-score diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1663: `local_core_ipc_diagnostics_test.dart` passed (`47`) including malformed risk-score object evidence, missing/malformed score/verdict/confidence/recommended-action evidence, malformed risk-engine evidence, and malformed required risk-reason rows being dropped instead of defaulting to empty/zero/info/heuristic placeholders.
- Flutter local-core threat reason-summary evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1660: malformed or empty `reasonSummary`/`reason_summary` rows are dropped with explicit scan-error evidence instead of substituting generic "why flagged" text.
- Flutter quarantine-record diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1661: `local_core_ipc_diagnostics_test.dart` passed (`45`) including `quarantine list rejects records with missing required evidence`, which covers malformed or missing quarantine record ID, timestamps, status, execution booleans, file size, labels, paths, source, and action evidence failing record parsing instead of silently falling back.
- Flutter allowlist-record diagnostics are runtime-verified for the Flutter IPC fixture layer in checkpoint 1662: `local_core_ipc_diagnostics_test.dart` passed (`46`) including `allowlist list rejects entries with missing required evidence`, which covers malformed or missing allowlist ID, type, active state, timestamp, reason, creator, file SHA/path evidence, and hash SHA/path evidence failing entry parsing instead of silently falling back.
- Flutter local-core quarantine/allowlist timestamp evidence is runtime-verified for the Flutter IPC fixture layer in checkpoints 1661 and 1662: missing quarantine `quarantinedAt` and allowlist `createdAt` make records malformed instead of manufacturing Unix-epoch evidence.
- Flutter local-core quarantine status evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1661: missing quarantine `status` makes records malformed instead of defaulting to active quarantined UI rows.
- Flutter local-core quarantine execution-claim booleans are runtime-verified for the Flutter IPC fixture layer in checkpoint 1661: missing `blockedBeforeExecution` or `processStarted` makes quarantine records malformed instead of defaulting UI claims to false.
- Flutter local-core quarantine file-size evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1661: missing `fileSize`/`file_size` makes quarantine records malformed instead of defaulting the UI to zero-byte evidence.
- Flutter local-core numeric record helper hardening is partially runtime-verified for the Flutter IPC fixture layer in checkpoint 1661: missing quarantine `fileSize` returns malformed record evidence from `_recordIntField` instead of manufacturing zero; allowlist numeric usage remains source-accounted.
- Flutter local-core boolean record helper hardening is runtime-verified for the Flutter IPC fixture layer in checkpoint 1661 for quarantine records: missing `blockedBeforeExecution` or `processStarted` returns malformed evidence from `_optionalRecordBool` instead of manufacturing `false`.
- Flutter local-core quarantine detection/engine label evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1661: missing or empty `detectionName`/`detection_name` or `engine` makes quarantine records malformed instead of showing unlabeled detections or unnamed engines.
- Flutter local-core quarantine path evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1661: malformed `originalPath`/`original_path` and missing `quarantinePath`/`quarantine_path` make quarantine records malformed before rows are shown.
- Flutter local-core quarantine source/action evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1661: missing `source` or `actionTaken`/`action_taken` makes quarantine records malformed instead of defaulting to `scanner` or `quarantined` UI labels.
- Flutter local-core record-string fallback cleanup is runtime-verified for the Flutter IPC fixture layer in checkpoints 1661 and 1662: missing/empty quarantine and allowlist string fields return malformed record evidence instead of generic fallback text.
- Flutter local-core action record ID validation is runtime-verified for the Flutter IPC fixture layer in checkpoints 1661 and 1662: malformed quarantine and allowlist IDs are rejected before restore/delete/remove controls can target them.
- Flutter local-core allowlist trust-field evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1662: missing allowlist entry type, creator, or active-state fields make entries malformed instead of defaulting to file, `local_user`, or active trust rows.
- Flutter local-core allowlist reason/SHA binding is runtime-verified for the Flutter IPC fixture layer in checkpoint 1662: missing allowlist reason or missing SHA for file IPC rows makes entries malformed before UI/cloud use; valid SHA evidence remains required for file/app/executable rows.
- Flutter local-core hash allowlist path-SHA validation is runtime-verified for the Flutter IPC fixture layer in checkpoint 1662: hash-type allowlist rows require valid SHA-256 evidence in either `sha256` or path instead of accepting arbitrary path text as trust evidence.
- Flutter local-core allowlist type-aware path evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1662: file rows require absolute local paths, and hash rows remain SHA-bound rather than filesystem-path-bound.
- Flutter local-core allowlist reason no-empty-fallback evidence is runtime-verified for the Flutter IPC fixture layer in checkpoint 1662: missing/empty allowlist reasons fail parsing instead of using `reason ?? ''` fallback text.
- Flutter dead integer fallback cleanup is Flutter/Dart verified in checkpoint 1665: `local_core_ipc_diagnostics_test.dart` passed (`48`) including `scan report parser records malformed numeric fields`, which guards that `_scanIntField`, `_optionalScanIntField`, and `_parseNonNegativeInt` remain active, the unused `_intField` zero-fallback helper is absent, and malformed/missing numeric scan-report fields produce explicit diagnostics instead of silent zero fallback evidence.
- Flutter protection self-test step diagnostics are runtime-verified for the Flutter Guard self-test fixture layer in checkpoint 1664: `local_core_ipc_diagnostics_test.dart` passed (`48`) including `protection self-test reports malformed step rows at runtime`, which covers malformed/non-object step rows, malformed names, missing names, malformed reasons, malformed pass flags, and valid passing rows producing explicit PASS/FAIL text instead of silent display fallbacks.
- Flutter protection self-test single-flight and exception handling are runtime-verified for the controller path: checkpoint 1653 covers duplicate in-flight self-test suppression with one local-core self-test IPC call, visible `protection_self_test_busy` warning evidence, retained busy state during the pending call, and final busy cleanup after completion; checkpoint 1809 covers a control/NUL-rich self-test IPC exception with bounded normalized visible/audit diagnostics, loading/busy cleanup, and no PASS/fake success result. Self-test-during-start/stop and installed widget click/layout E2E remain partial.
- Flutter client UI control inventory has current-host Flutter runtime/source-marker verification for high-risk controller and widget guards, and source review accounts for every visible desktop/mobile route, major button, setting, confirmation dialog, engine/status surface, disabled state, and technical limitation in `docs/client-ui.md`. Checkpoint 1138 refreshes the Settings native-engine status inventory for ProgramData/install/engine-root evidence, checkpoint 1139 inventories plus busy-gates the Settings `Check engine` health-refresh control, checkpoint 1140 adds controller-level single-flight health-refresh de-duplication, checkpoint 1141 inventories queued single-flight Quarantine/Allowlist refresh controls, checkpoint 1142 inventories scan-start single-flight controls, checkpoint 1144 inventories scan-cancel single-flight controls, checkpoint 1145 inventories single-flight cloud health checks, checkpoint 1146 inventories shared update-action single-flight controls, checkpoint 1152 inventories quarantine mutation single-flight controls, checkpoint 1164 inventories visible busy-warning behavior for Settings `Check engine` plus Scan `Retry` engine refresh, checkpoint 1165 inventories scan action-mode disabled/blocked behavior, checkpoints 1166 and 1188 inventory visible busy-warning and public busy-state behavior for Test Cloud Connection, checkpoint 1167 inventories detect-only Home/Protection scan shortcuts, and checkpoint 1717 verifies the high-risk matrix with Flutter tests. Packaged desktop click-through, OS picker dialogs, elevation prompts, Windows toast rendering, installed IPC, and service/updater side effects remain partial.
- Flutter quarantine mutation single-flight behavior is runtime-verified for the controller path in checkpoint 1578: restore and delete share `_quarantineActionInFlight`, overlapping delete during pending restore IPC fails visibly, local-core delete IPC is not called, and the guard releases after the restore IPC completes.
- Flutter Scan-result manual quarantine click-through is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1818: `scan_screen_test.dart` opens the Quarantine confirmation dialog for a confirmed benign EICAR-style detection, proves Cancel does not call local-core, and proves confirm routes the expected threat ID through quarantine IPC. Installed Scan-result click/layout E2E remains partial.
- Flutter quarantine action busy-state UI is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1792: source checks in checkpoint 1171 confirm `_quarantineActionInFlight` is surfaced through `ZentorState.quarantineActionInFlight`, Scan result quarantine and Quarantine restore/delete/refresh controls disable while a quarantine action is in flight, checkpoint 1578 runtime-verifies the public busy flag is true during pending restore IPC and false after completion, and `quarantine_screen_test.dart` now verifies `quarantineActionInFlight=true` disables Quarantine Refresh, Restore / Keep, and Delete permanently controls for a quarantined record. Checkpoint 1817 runtime-verifies Quarantine Restore / Keep and Delete permanently dialogs at the widget layer: Cancel does not call local-core and confirm routes the expected quarantine ID through restore/delete IPC. Installed Quarantine click/layout E2E remains partial.
- Flutter quarantine restore/delete path-text bounds are runtime-verified for the current Flutter controller layer in checkpoint 1799: `offline_scan_test.dart` passed (`106`) including a long `originalPath` with NUL/newline/tab controls that is normalized, bounded, truncated with evidence, and used in unconfirmed restore/delete confirmation events while local-core restore/delete call counters remain zero. Source checks in checkpoint 1332 still account for requested/success/failure audit events, duplicate-action busy details, and visible error text using the bounded display path while local-core IPC targets the validated quarantine ID. Installed Quarantine restore/delete click/E2E remains partial.
- Flutter quarantine refresh busy-state controller behavior is runtime-verified in checkpoint 1652: `offline_scan_test.dart` passed (`98`) including `quarantine refresh exposes busy state and queues duplicate refresh`, which covers `quarantineRefreshInFlight` true during pending list IPC, duplicate refresh queueing without parallel list IPC, queued refresh execution, and final busy cleanup. Installed widget click/layout E2E remains partial.
- Flutter allowlist mutation single-flight behavior is runtime-verified for the controller path in checkpoint 1577: add and remove allowlist actions share `_allowlistActionInFlight`, an overlapping remove during pending add IPC fails visibly, local-core remove IPC is not called, and the guard releases after the first IPC completes.
- Flutter Scan-result Add to allowlist click-through is runtime-verified for the current Flutter widget/controller contract layer in checkpoint 1819: `scan_screen_test.dart` opens the Add to allowlist confirmation dialog for a review detection, proves Cancel does not call local-core, and proves confirm routes the expected path through allowlist IPC. Installed Scan-result allowlist click/layout E2E remains partial.
- Flutter allowlist action busy-state and remove/refresh click-through UI are runtime-verified for the current Flutter widget/controller contract layer in checkpoints 1793, 1843, and 1851: source checks in checkpoint 1172 confirm `_allowlistActionInFlight` is surfaced through `ZentorState.allowlistActionInFlight`, Scan result Add to allowlist and Allowlist refresh/remove controls disable while an allowlist action is in flight, checkpoint 1577 runtime-verifies the public busy flag is true during pending add IPC and false after completion, checkpoint 1793 verifies `allowlistActionInFlight=true` disables Allowlist Refresh and Remove controls for an active allowlist entry, checkpoint 1843 verifies Allowlist Remove Cancel makes zero local-core trust-store calls while Confirm routes exactly one remove call, marks the row inactive, and records `allowlist_entry_removed`, and checkpoint 1851 verifies Allowlist Refresh routes one additional list call, preserves the row, and clears `allowlistRefreshInFlight`. Installed Allowlist click/layout and local-core trust-store E2E remain partial.
- Flutter allowlist refresh busy-state controller behavior is runtime-verified in checkpoint 1651: `offline_scan_test.dart` passed (`97`) including `allowlist refresh exposes busy state and queues duplicate refresh`, which covers `allowlistRefreshInFlight` true during pending list IPC, duplicate refresh queueing without parallel list IPC, queued refresh execution, and final busy cleanup. Installed widget click/layout E2E remains partial.
- Engine/control matrix runtime verification is improved by current-host Cargo/rustfmt and Flutter/Dart evidence in checkpoints 1630 and 1631; `docs/audit/engine-control-matrix.md` now accounts for every active detection engine, compatibility engine, protection surface, trust control, quarantine/update control, disabled path, and technical blocker with source or runtime evidence. Installed local-core layout, Windows UI automation, service validation, and driver validation hosts remain blocked, so product-level E2E/driver success claims remain unavailable.
- Guard fail-open and local-core passthrough runtime-root policy is runtime-verified in checkpoint 1650: Guard `driver_ipc` passed (`49`), local-core `app_control` passed (`47`), and local-core `trust_store` passed (`10`), covering SystemRoot/WINDIR-derived roots, no hard-coded `C:\Windows` fallback, relative/parent-traversal override rejection, and lookalike/prefix rejection. Installed signed-driver/local-core E2E remains partial.
- Android release artifact signing is not configured in this Windows-first antivirus release path; Android release builds must be signed by a dedicated mobile release host before any publishing, and debug-signed antivirus artifacts must not be published.
- Update-service System32 `sc.exe` path/output hardening has local Rust fixture coverage in checkpoint 1624 (`service_control` included in the `176 passed` update-service suite and `cargo fmt --check` passed); elevated Windows service-control verification against real service start/stop remains unverified.
- Guard driver-health System32 command path hardening is runtime-verified for crate fixtures in checkpoint 1642: `driver_health` passed `16 passed; 0 failed`, including checked System32 helper command coverage; live Windows command fixture verification remains partial.
- Guard driver-health SystemRoot/WINDIR validation is runtime-verified for crate fixtures in checkpoint 1642 through `driver_health` (`16 passed`); live Windows environment-fixture verification remains partial.
- Guard driver-health SystemRoot/WINDIR source-regression reliability is runtime-verified in checkpoint 1650: Guard `driver_health` passed (`16`) and includes checked System32 path, encoded PowerShell, bounded command output, and no implicit pre-execution-ready success. Live installed driver-health E2E remains partial.
- Guard driver-health IPC helper failure reporting is runtime-verified for crate fixtures in checkpoint 1642 through `driver_health` (`16 passed`); packaged helper E2E remains partial.
- Local-core Guard Service status diagnostics have current-host Rust and Flutter fixture evidence; `guard_status_error` carries checked tool-root/query failure evidence into Flutter health `lastError` instead of leaving an unexplained `unknown` status. Installed Windows service-control fixture verification remains partial.
- Local-core Core Service status diagnostics have current-host Rust and Flutter fixture evidence; `core_service_status_error` carries checked tool-root/query failure evidence into Flutter health `lastError` instead of leaving an unexplained `unknown` status. Installed Windows service-control fixture verification remains partial.
- Local-core ProgramData runtime-root validation is runtime-verified for current crate fixtures in checkpoint 1647: `local_core_program_data_root` passed (`3`) and covers no-relative-fallback plus relative/parent-traversal data-root rejection. Installed Windows/POSIX runtime-root E2E remains partial.
- Local quarantine base runtime-root validation is runtime-verified in checkpoint 1641: `quarantine_root` passed `1 passed; 0 failed`; installed local-core service root E2E remains partial.
- Local quarantine metadata-auth failure visibility is runtime-verified in checkpoint 1636 through `list_rejects_metadata`, `metadata_validation`, and broad `quarantine` filters; legacy unsigned compatibility remains explicitly bounded.
- Local quarantine metadata text-read hardening is runtime-verified in checkpoint 1641: `quarantine_metadata_text_reader` passed `1 passed; 0 failed`, covering bounded non-following metadata reads before auth, JSON parsing, or key decoding.
- Local quarantine restore original-path text validation is runtime-verified in checkpoint 1641: `original_restore_path_text` passed `1 passed; 0 failed`, covering malformed persisted `original_path` rejection.
- Local quarantine payload-path text validation is runtime-verified in checkpoint 1641: `quarantine_payload_path_text` passed `1 passed; 0 failed`, covering malformed persisted `quarantine_path` rejection and `.avoraxq` policy.
- Local quarantine list-time path validation is runtime-verified in checkpoint 1641: `list_rejects_metadata_with_unsafe_restore_or_payload_paths` passed `1 passed; 0 failed`, so unsafe authenticated paths fail before UI/action evidence is returned.
- Local quarantine list-time field validation is runtime-verified in checkpoint 1636: malformed SHA-256, blank required labels, oversized labels, NUL characters, and other control characters fail visibly during listing before rows are returned as UI/audit evidence; local-core rustfmt passed.
- Local quarantine legacy-extension regression cleanup is runtime-verified in checkpoint 1636: current `.avoraxq`-only local-core payload policy fixtures pass instead of preserving stale readable-legacy expectations; local-core rustfmt passed.
- Local quarantine write-time metadata validation is runtime-verified in checkpoint 1636: scanner labels are normalized before payload movement and persisted records are validated before staged JSON/auth writes; local-core rustfmt passed.
- local quarantine restore/delete status preflight is runtime-verified in checkpoint 1636: restore and delete require authenticated records to be `Quarantined` before path or payload handling; local-core rustfmt passed.
- local quarantine restore/delete action metadata is runtime-verified in checkpoint 1636: `action_taken` is updated with `Restored`/`Deleted` status and delete rollback restores the previous action metadata; local-core rustfmt passed.
- Local quarantine payload cleanup revalidation is runtime-verified in checkpoint 1768: restore post-status cleanup and delete payload removal route through `remove_checked_quarantine_payload`, which revalidates the payload as a non-following regular file immediately before removal; local-core `quarantine` passed (`87`), full local-core passed (`419`), rustfmt passed, and source-contracts passed (`481`).
- local quarantine status/action metadata consistency is runtime-verified in checkpoint 1636: list/write metadata validation rejects `action_taken` values that contradict `Quarantined`, `Restored`, or `Deleted` status; local-core rustfmt passed.
- local quarantine execution-claim metadata consistency is runtime-verified in checkpoint 1636: list/write metadata validation rejects records that claim both pre-execution blocking and process start, or a process ID without process-start evidence; local-core rustfmt passed.
- local quarantine source/evidence metadata consistency is runtime-verified in checkpoint 1636: list/write metadata validation accepts only local scanner source evidence and rejects scanner records that claim execution-state evidence; local-core rustfmt passed.
- Flutter quarantine IPC source/action evidence validation is runtime-verified for the current Flutter fixture layer in checkpoint 1643: `local_core_ipc_diagnostics_test.dart` passed (`42 passed`) and covers malformed actionable quarantine record/list rows failing before display/action use; installed local-core/UI E2E remains partial.
- Flutter quarantine IPC process-ID evidence validation is runtime-verified for the current Flutter fixture layer in checkpoint 1643: `local_core_ipc_diagnostics_test.dart` passed (`42 passed`) and covers quarantine parser/list rejection for malformed optional/process evidence; installed local-core/UI E2E remains partial.
- Shared `QuarantineRecord` explicit evidence fields need Dart/Flutter compile/test execution across app and protocol packages; source checks in checkpoint 1379 confirm source/action/execution-state constructor fields are required instead of defaulting to scanner/quarantined/not-started values, and known fixtures pass explicit evidence.
- Flutter optimistic quarantine status/action consistency is runtime-verified for the current Flutter controller layer in checkpoint 1800: successful restore/delete paths with a failed follow-up quarantine refresh assert that the stale local UI row updates both `status` and `actionTaken` to `restored` or `deleted` instead of preserving stale `quarantined` action evidence. Installed Quarantine restore/delete click/E2E remains partial.
- Cloud quarantine metadata evidence preflight is runtime-verified for the current Flutter fixture layer in checkpoint 1643: `api_client_test.dart` passed (`38 passed`) and rejects invalid or inconsistent quarantine metadata before network calls.
- Cloud quarantine metadata evidence persistence is partially runtime-verified in checkpoints 1643, 1641, and 1645: Flutter `api_client_test.dart` passed (`38 passed`) and includes action/source/execution-state evidence in upload payloads; API `quarantine_metadata_evidence_contract`, payload-size, and insert-ack filters passed in checkpoint 1645 with full API tests (`40 passed`), but database-backed backend smoke remains partial.
- Cloud quarantine metadata strict API schema is runtime source-marker verified in checkpoint 1645: API fmt passed, full API tests passed (`40 passed`), and `quarantine_metadata_evidence_contract` passed (`1`); backend malformed-JSON smoke remains partial.
- Cloud API request strict schemas are runtime source-marker verified in checkpoint 1645 through full API tests (`40 passed`) and strict request/project fail-closed source-marker coverage; backend malformed-JSON smoke remains partial.
- Cloud security-event wrapper strict schema is source-accounted by strict enum model coverage and full API tests in checkpoint 1645; backend malformed-event smoke remains partial.
- Cloud security-event empty-batch rejection is runtime source-marker verified in checkpoint 1645: `event_ingest_rejects_empty_batches_source_marker` passed (`1`) and full API tests passed (`40`); backend event-ingest smoke remains partial.
- Cloud protection-run expiry bounds are runtime source-marker verified in checkpoint 1645: `session_expiry_is_bounded_source_marker` passed (`1`) and full API tests passed (`40`); backend session-creation smoke remains partial.
- Cloud protection-run write expiry/status enforcement is runtime source-marker verified in checkpoint 1645: `session_writes_require_active_unexpired_sessions` and `heartbeat_requires_active_update_ack` passed (`1` each), with full API tests (`40`); backend heartbeat/event/end smoke remains partial.
- Cloud ban device/project boundary is runtime source-marker verified in checkpoint 1645: `ban_creation_requires_device_project_match` passed (`1`) and full API tests passed (`40`); backend ban-route smoke remains partial.
- Cloud device-risk project boundary is runtime source-marker verified in checkpoint 1645: `device_risk_requires_device_project_match` passed (`1`) and full API tests passed (`40`); backend risk-route smoke remains partial.
- Cloud protection-run device/project boundary is runtime source-marker verified in checkpoint 1645: `session_device_id_requires_project_match_source_marker` passed (`1`) and full API tests passed (`40`); backend session-route smoke remains partial.
- Cloud detection-report empty aggregate rejection is runtime-verified in checkpoint 1645: `normalized_detections_rejects_empty_aggregate_payload` passed (`1`) and full API tests passed (`40`); backend detection-route smoke remains partial.
- Cloud event batch validate-before-insert is source-marker verified in checkpoint 1645 through full API tests and event ingest source contracts; backend mixed-validity route smoke remains partial.
- Cloud heartbeat active-update acknowledgement is runtime source-marker verified in checkpoint 1645: `heartbeat_requires_active_update_ack` passed (`1`) and full API tests passed (`40`); backend heartbeat race/status smoke remains partial.
- Cloud evidence timestamp bounds are runtime-verified in checkpoint 1645: `client_evidence_timestamp` passed (`2`) and full API tests passed (`40`); backend heartbeat/detection/quarantine timestamp smoke remains partial.
- Cloud event batch transactionality is runtime source-marker verified in checkpoint 1645: event insert acknowledgement and route source contracts passed, with full API tests (`40`); backend mid-batch insert-failure fixtures remain partial.
- Cloud detection-report transactionality is runtime source-marker verified in checkpoint 1645: `detection_report_uses_transaction` passed (`1`) and full API tests passed (`40`); backend mid-report insert/audit-failure fixtures remain partial.
- Cloud heartbeat transactionality is runtime source-marker verified in checkpoint 1645 through active-update, event-insert acknowledgement, and full API tests (`40`); backend heartbeat event-insert failure fixtures remain partial.
- Cloud protection-run creation transactionality is runtime source-marker verified in checkpoint 1645 through session transaction and insert-ack filters plus full API tests (`40`); backend session-audit failure fixtures remain partial.
- Cloud ban creation transactionality is runtime source-marker verified in checkpoint 1645: device/project, insert-ack, and transaction source-marker filters passed, with full API tests (`40`); backend ban-audit failure fixtures remain partial.
- Cloud end-session transactionality is runtime source-marker verified in checkpoint 1645 through active-session/end-session source contracts and full API tests (`40`); backend end-session audit failure fixtures remain partial.
- Cloud device registration transactionality is runtime source-marker verified in checkpoint 1645: device/audit transaction and audit-ack source-marker filters passed, with full API tests (`40`); backend device-audit failure fixtures remain partial.
- Cloud quarantine metadata final payload sizing is runtime source-marker verified in checkpoint 1645: `quarantine_metadata_payload_size` passed (`1`) and full API tests passed (`40`); oversized-payload API smoke remains partial.
- Cloud quarantine metadata insert acknowledgement is runtime source-marker verified in checkpoint 1645: `quarantine_metadata_requires_insert_ack` passed (`1`) and full API tests passed (`40`); affected-row backend fixtures remain partial.
- Cloud security-event insert acknowledgement is runtime source-marker verified in checkpoint 1645: `event_ingest_requires_insert_ack_before_counting_source_marker` passed (`1`) and full API tests passed (`40`); affected-row batch fixtures remain partial.
- Cloud detection-report insert acknowledgement is runtime source-marker verified in checkpoint 1645: `detection_report_requires_insert_acks_before_success_source_marker` passed (`1`) and full API tests passed (`40`); affected-row detection/audit fixtures remain partial.
- Cloud protection-run creation insert acknowledgement is runtime source-marker verified in checkpoint 1645: `session_creation_requires_insert_acks` passed (`1`) and full API tests passed (`40`); affected-row session/audit fixtures remain partial.
- Cloud ban creation insert acknowledgement is runtime source-marker verified in checkpoint 1645: `ban_creation_requires_insert_acks` passed (`1`) and full API tests passed (`40`); affected-row ban/audit fixtures remain partial.
- Cloud device-registration audit insert acknowledgement is runtime source-marker verified in checkpoint 1645: `device_registration_requires_audit_insert_ack_before_response_source_marker` passed (`1`) and full API tests passed (`40`); affected-row device-audit fixtures remain partial.
- Cloud heartbeat event insert acknowledgement is runtime source-marker verified in checkpoint 1645: `heartbeat_requires_event_insert_ack` passed (`1`) and full API tests passed (`40`); affected-row heartbeat event fixtures remain partial.
- Cloud end-session audit insert acknowledgement is runtime source-marker verified in checkpoint 1645 through session write/end-session source contracts and full API tests (`40`); affected-row end-session audit fixtures remain partial.
- Cloud API unused audit-helper removal is runtime source-marker verified in checkpoint 1645: `routes_do_not_keep_unused_audit_helper` passed (`1`) and full API tests passed (`40`).
- In-app update local file-feed trust is runtime-verified for the current Flutter fixture layer in checkpoint 1643: `update_service_test.dart` passed (`106 passed`) and covers local feed trust, local package containment, and revalidation paths; Windows symlink/junction race fixtures remain partial.
- In-app update local file-feed authority rejection is runtime-verified for the current Flutter fixture layer in checkpoint 1643: `update_service_test.dart` passed (`106 passed`) and includes the file-feed authority guard source/runtime fixture coverage; installed update-flow E2E remains partial.
- In-app update local package file-URI trust is runtime-verified for the current Flutter fixture layer in checkpoint 1643: `update_service_test.dart` passed (`106 passed`) and covers local package path authority/traversal/containment checks before local package use; Windows symlink/junction race fixtures remain partial.
- In-app update HTTPS URI authority trust is runtime-verified for the current Flutter fixture layer in checkpoint 1643: `update_service_test.dart` passed (`106 passed`) and covers HTTPS host/authority/userinfo trust gates before feed/package acceptance; installed update-flow E2E remains partial.
- In-app GitHub update HTTPS trust reuse is runtime-verified for the current Flutter fixture layer in checkpoint 1643: `update_service_test.dart` passed (`106 passed`) and covers shared HTTPS trust reuse for GitHub feed, release asset, and redirect paths; installed update-flow E2E remains partial.
- In-app update URI text control/NUL rejection is runtime-verified for the current Flutter fixture layer in checkpoints 1599 and 1600: configured update feed URLs, feed package URLs, and GitHub release `browser_download_url` values containing NUL fail before URI parsing, with normalized visible diagnostics and no unintended network/package fetch for the configured-feed case. Installed Windows update-flow E2E remains partial.
- In-app update required metadata control/NUL rejection is runtime-verified for the current Flutter fixture layer in checkpoint 1601 for feed `product`, feed `latest_version`, and package `package_sha256` values containing NUL; the values fail before comparison/version parsing/SHA validation and diagnostics are normalized. Broader GitHub release required-field fixtures and installed Windows update-flow E2E remain partial.
- In-app update optional metadata control/NUL rejection is runtime-verified for the current Flutter fixture layer in checkpoint 1601 for feed `channel`, feed `minimum_supported_version`, and package `published_at` values containing NUL; the values fail before channel comparison/version comparison/date parsing and diagnostics are normalized. Installed Windows update-flow E2E remains partial.
- In-app update product-field typed/control validation is runtime-verified for the current Flutter fixture layer in checkpoint 1601: a NUL-bearing feed `product` fails through the required string boundary before the Avorax product comparison. Installed Windows update-flow E2E remains partial.
- In-app update release-notes free-text control validation is runtime-verified for the current Flutter fixture layer in checkpoint 1601: multiline release notes with tab/line breaks remain accepted, while NUL-bearing release notes are rejected with normalized diagnostics. Installed Windows update-flow E2E remains partial.
- In-app GitHub update asset-name validation is runtime-verified for the current Flutter fixture layer in checkpoints 1602 and 1603: malformed release-assets redirect paths are refused before trusting redirected asset evidence, and unsafe decoded GitHub fallback asset names such as `nested%5Cupdate-feed.json` are rejected before feed download selection. Installed Windows update-flow E2E remains partial.
- In-app GitHub update redirect Location control/NUL rejection is runtime-verified for the current Flutter fixture layer in checkpoint 1602: a NUL-bearing redirect `Location` fails before URI resolution and diagnostics are normalized. Installed Windows update-flow E2E remains partial.
- In-app GitHub release-assets redirect path-shape validation is runtime-verified for the current Flutter fixture layer in checkpoint 1602: a malformed `release-assets.githubusercontent.com` redirect path is rejected before following the redirect. Installed Windows update-flow E2E remains partial.
- In-app GitHub update redirect raw Location control/NUL rejection is runtime-verified for the current Flutter fixture layer in checkpoint 1602: the untrimmed redirect `Location` is rejected for control/NUL text before trimming or URI resolution. Installed Windows update-flow E2E remains partial.
- In-app update `Content-Length` raw-header control/NUL rejection is runtime-verified for the current Flutter fixture layer in checkpoints 1591 and 1598: remote update-feed, update-package, and GitHub releases metadata `Content-Length` values containing NUL are rejected before body parsing/package writes/GitHub metadata parsing and visible diagnostics are normalized. Installed Windows update-flow E2E remains partial.
- Signed `.aup` archive entry allowlist is runtime-verified in checkpoint 1604: Cargo fixtures reject unexpected archive entries and restricted payload directory entries before manifest reads or payload limit scans; `rustfmt --check core\avorax_update_service\src\update_package.rs` passed.
- Signed `.aup` archive entry-name text guard is runtime-verified in checkpoint 1604: Cargo fixtures reject control-character archive entry names before allowlist/path checks; `rustfmt --check core\avorax_update_service\src\update_package.rs` passed.
- Signed `.aup` restricted payload directory-entry rejection is runtime-verified in checkpoint 1604: Cargo fixtures reject restricted roots such as `payload/tools/` even when represented as ZIP directory entries; `rustfmt --check core\avorax_update_service\src\update_package.rs` passed.
- Signed `.aup` manifest/signature entry cardinality is runtime-verified in checkpoint 1604: Cargo fixtures reject duplicate/missing `manifest.json` and `manifest.sig` entries before archive reads continue; `rustfmt --check core\avorax_update_service\src\update_package.rs` passed.
- Signed manifest scalar raw-text validation is runtime-verified in checkpoint 1634: Cargo fixtures confirm versions, IDs, release dates, release notes URLs, migration steps, and optional package hashes reject raw control characters and surrounding whitespace before trimmed parsing or policy comparison; update-service rustfmt passed.
- Signed manifest payload-hash value raw-text validation is runtime-verified in checkpoint 1634: Cargo fixtures confirm payload hash values reject raw control characters and surrounding whitespace before `.aup` archive open or payload hash comparison; update-service rustfmt passed.
- Signed manifest payload-hash path-key raw-text validation is runtime-verified in checkpoint 1634: Cargo fixtures confirm payload hash path keys reject raw control characters and surrounding whitespace before path normalization or `.aup` archive open; update-service rustfmt passed.
- Normal `.aup` tooling-payload policy is Rust-runtime verified in checkpoint 1635 for signed `tools/` payload rejection and update-service rustfmt; package-builder runtime fixtures for refusing source or leaked `tools/` payload paths remain partial until PowerShell builder fixture execution is added.
- Normal `.aup` tooling activation removal is runtime-verified in checkpoint 1635: update applier section-copy fixtures confirm normal update apply no longer copies `staging/tools` into `install_dir/tools`; update-service rustfmt passed.
- Normal `.aup` migration workflow disabling is Rust-runtime verified in checkpoint 1635 for signed manifest migration-step rejection, `migrations/` payload-root rejection, and applier non-activation; package-builder runtime fixtures for refusing source/leaked migration payloads remain partial until PowerShell builder fixture execution is added.
- Normal `.aup` service payload allowlist is Rust-runtime verified in checkpoint 1635 for signed unknown/nested service payload fixtures: only direct `services/avorax_core_service.exe` and `services/avorax_guard_service.exe` payloads are supported by normal updates; package-builder staging fixtures remain partial.
- local quarantine delete status ordering is runtime-verified in checkpoint 1636: delete writes `Deleted` metadata before payload removal and rolls status back, or reports rollback failure with payload-removal context, when payload deletion fails; local-core rustfmt passed.
- local quarantine delete payload-integrity preflight is runtime-verified in checkpoint 1636: delete verifies payload size/hash integrity before writing `Deleted` metadata or removing the payload; local-core rustfmt passed.
- local quarantine restore status ordering is runtime-verified in checkpoint 1636: restore writes `Restored` metadata before restored-payload cleanup and reports cleanup failure with status-update context; local-core rustfmt passed.
- local quarantine restore metadata-failure cleanup is runtime-verified in checkpoint 1636: an activated restore copy is integrity-checked and removed if the `Restored` metadata write fails, or cleanup failure is reported with metadata-write context; local-core rustfmt passed.
- local quarantine restore parent revalidation is runtime-verified in checkpoint 1636: restore staging rejects linked parents before temp creation and rechecks parent links before activation with visible temp cleanup on parent-preflight failure; platform-gated junction/symlink host coverage remains partial.
- Local quarantine status preflight is runtime-verified in checkpoint 1636: non-infected scan results fail before quarantine directory creation or payload movement; local-core rustfmt passed.
- Local quarantine copy fallback expected-hash preflight is runtime-verified in checkpoint 1636: malformed fallback expected SHA-256 values fail with explicit context before source/destination inspection or payload copy, while bare and prefixed valid hashes compare through normalized evidence; local-core rustfmt passed.
- local quarantine copy fallback source-delete cleanup is runtime-verified in checkpoint 1641: `copy_fallback` passed `7 passed; 0 failed`, including source-delete failure cleanup coverage.
- local quarantine copy fallback verification cleanup is runtime-verified in checkpoint 1641: `copy_fallback` passed `7 passed; 0 failed`, including post-copy verification cleanup coverage.
- Local quarantine finalization cleanup is runtime-verified in checkpoint 1641: `quarantine_finalization` passed `1 passed; 0 failed`, covering post-move cleanup of untracked artifacts on finalization failure.
- Local quarantine staged metadata final-destination exclusivity is runtime-verified in checkpoint 1641: `quarantine_metadata_staged` passed `3 passed; 0 failed`, covering existing final record/auth-sidecar rejection.
- Local quarantine staged metadata parent revalidation is runtime-verified in checkpoints 1636 and 1641 through broad `quarantine` and `quarantine_metadata_staged` fixtures; platform-gated junction/symlink host coverage remains partial.
- Local quarantine staged metadata UUID temp naming is runtime-verified in checkpoints 1636 and 1641 through broad `quarantine` and staged metadata fixtures; platform-gated link-host coverage remains partial.
- Local quarantine staged temp cleanup ownership is runtime-verified in checkpoints 1636 and 1641 through broad `quarantine` and staged metadata fixtures; platform-gated collision/reparse host coverage remains partial.
- Local shared config runtime-root validation is runtime-verified for current crate fixtures in checkpoint 1647: `config_root` passed (`1`) and covers rejection of unsafe config roots instead of relative `.avorax/config` fallback behavior. Installed config-root E2E remains partial.
- Local startup migration runtime-root validation is runtime-verified for current crate fixtures in checkpoint 1647: `migration` passed (`11`) and covers current/legacy migration root validation. Installed migration E2E remains partial.
- Local startup migration copy/hash byte limits need focused runtime fixture review where not superseded by later checkpoints, plus oversized-copy/hash fixtures, and legacy-data migration fixtures; source/direct-contract checks in checkpoint 1257 confirm migration copy is byte-limited during exclusive destination creation and reports cleanup failure context after copy or sync failures; checkpoint 1268 confirms migration hash inputs are metadata-size and actual-byte limited before migrated file evidence is accepted.
- Local AI training-label runtime-root validation is runtime-verified in checkpoint 1628 for relative and parent-traversal env-root rejection plus no-relative-fallback behavior; NUL-root checks remain source-accounted from checkpoint 1215.
- Recovery Vault copy/hash byte limits need focused runtime fixture review where not superseded by later checkpoints, plus oversized-copy/hash fixtures, and backup/restore filesystem fixtures; source/direct-contract checks in checkpoint 1258 confirm vault backup and restore staging copies are byte-limited, use exclusive destination creation, and report cleanup failure context after copy or sync failures; checkpoint 1267 confirms Recovery Vault hash inputs are metadata-size and actual-byte limited before backup or restore verification evidence is accepted.
- Update-service runtime-root validation has local Rust fixture coverage in checkpoint 1624 (`logging`, staging, and rollback root tests included in the `176 passed` update-service suite and `cargo fmt --check` passed); installed update-root verification with real ProgramData/service layout remains unverified.
- Update-service staged file copy byte limits need focused runtime fixture review where not superseded by later checkpoints, plus oversized-copy fixtures, and Windows apply/rollback staging fixtures; source/direct-contract checks in checkpoint 1256 confirm staged file copy is byte-limited before activation and preserves visible cleanup on copy, sync, or activation failure.
- Native quarantine runtime-root validation is runtime-verified in checkpoint 1642: `native_quarantine_root` passed `4 passed; 0 failed`, covering no temp fallback plus relative/parent-traversal root rejection; installed native-engine E2E remains partial.
- Local quarantine fallback-copy byte limits and partial cleanup need Cargo/rustfmt execution plus oversized/copy-failure fixture verification; source/direct-contract checks in checkpoint 1255 confirm fallback payload copy is byte-limited, uses exclusive destination creation, and reports cleanup failure context after copy or sync failures.
- Local quarantine SHA-256 input byte limits need Cargo/rustfmt execution and oversized/replaced local quarantine fixtures; source checks in checkpoint 1265 confirm local quarantine hash inputs are metadata-size and actual-byte limited before quarantine or restore integrity evidence is accepted.
- Local-core main SHA-256 input byte limits need Cargo/rustfmt execution and oversized/replaced manual-quarantine/training/AI threat fixtures; source checks in checkpoint 1266 confirm the shared local-core hash helper is metadata-size and actual-byte limited before manual action or threat evidence is accepted.
- Native quarantine fallback-copy byte limits and partial cleanup are runtime-verified in checkpoint 1638: fallback payload copy is byte-limited, uses exclusive destination creation, and reports cleanup failure context after copy or sync failures; native-engine rustfmt passed.
- Native quarantine SHA-256 input byte limits are runtime-verified in checkpoint 1638: native quarantine hash inputs are metadata-size and actual-byte limited before integrity evidence is accepted; native-engine rustfmt passed.
- Native quarantine metadata field validation is runtime-verified in checkpoint 1638: native detection labels are normalized before payload movement and record hash/label/action fields are validated before staged metadata writes; native-engine rustfmt passed.
- Native quarantine record path validation is runtime-verified in checkpoint 1638: native original/payload record path text is validated before directory creation, payload movement, and staged metadata writes; native-engine rustfmt passed.
- Native quarantine copy fallback expected-hash preflight is runtime-verified in checkpoint 1638: malformed fallback expected SHA-256 values fail with explicit context before source/destination inspection or payload copy, while bare and prefixed valid hashes compare through normalized evidence; native-engine rustfmt passed.
- native quarantine copy fallback source-delete cleanup is runtime-verified in checkpoint 1638: copied destinations are removed after verified fallback copy if original source deletion fails, or cleanup failure is reported with source-delete context; native-engine rustfmt passed.
- native quarantine copy fallback verification cleanup is runtime-verified in checkpoint 1638: copied destinations are removed when post-copy destination metadata/hash verification fails, or cleanup failure is reported with verification context; native-engine rustfmt passed.
- Native quarantine entrypoint source-hash preflight is runtime-verified in checkpoint 1638: stale expected SHA-256 values fail before quarantine directory creation, destination preflight, or payload movement; native-engine rustfmt passed.
- Native quarantine root directory validation is runtime-verified in checkpoint 1638: native quarantine roots are inspected without following links and unsafe roots fail before payload destination preflight or movement; platform-gated reparse coverage remains partial.
- Native quarantine executable-permission stripping is runtime-verified in checkpoint 1638 for POSIX-style executable-bit stripping fixtures; Windows non-executable/ACL behavior still needs validation on a provisioned Windows security host.
- Native quarantine metadata write byte limits are runtime-verified in checkpoint 1638: oversized metadata bytes fail before temporary metadata path creation or staged file writes; native-engine rustfmt passed.
- Native quarantine metadata parent revalidation is runtime-verified in checkpoint 1638: native metadata staging rechecks the parent as an existing non-linked directory before temp writes and final activation; platform-gated race/reparse coverage remains partial.
- Native quarantine metadata final-destination exclusivity is runtime-verified in checkpoint 1638: existing final metadata fails visibly instead of being removed and replaced; native-engine rustfmt passed.
- native quarantine staged temp cleanup ownership is runtime-verified in checkpoint 1638: native metadata cleanup only runs after exclusive temp creation succeeds, so create/open failures on unowned temp-path collisions do not remove existing files or links; native-engine rustfmt passed.
- Native quarantine Windows ACL hardening is runtime-fixture verified in checkpoint 1638 for checked bounded System32 `icacls.exe` invocation before payload destination preflight; real ACL enforcement still needs validation on a provisioned Windows security host.
- Native quarantine finalization cleanup is runtime-verified in checkpoint 1638: post-move finalization failures clean up untracked `.avoraxq` payloads or report cleanup failure with the original finalization error; native-engine rustfmt passed.
- Native product/quarantine trust-root validation is runtime-verified for current crate fixtures in checkpoint 1647: `trust_root` passed (`3`) and covers controlled product/quarantine trust-root behavior. Installed Windows/POSIX native-engine trust-root E2E remains partial.
- Native product repo-root trust validation is runtime-verified in checkpoint 1641: native-engine `repo_root` passed `2 passed; 0 failed`, covering controlled repo-root candidate behavior; installed native-engine E2E remains partial.
- Local passthrough trust-root validation is runtime-verified in checkpoint 1641 through local-core `app_control` (`47 passed`) and `trust_store` (`10 passed`) filters; Windows/POSIX installed passthrough-root E2E remains partial.
- Local app-control default trust-store root hardening is runtime-verified in checkpoint 1641: `trust_store` passed `10 passed; 0 failed`, covering default trust-store root safety fixtures; installed local-core fixture verification remains partial.
- Windows driver helper safety hardening needs manual elevated Windows development-VM verification; source/negative checks confirm TESTSIGNING and SYSTEM startup-task changes require explicit switches, helper scripts no longer launch `bcdedit`, `fltmc`, `sc`, `schtasks`, or `powershell` through ambient PATH lookup, shared and live-remediation System32 resolution no longer silently falls back to `C:\Windows`, and TESTSIGNING/live helper command diagnostics are bounded before any boot-state change or task creation.
- Live driver-remediation staging hardening needs manual elevated Windows development-VM verification; source checks confirm remediation reports, logs, and the generated post-reboot script are atomically staged or bounded, install-helper candidates are regular non-reparse files, generated post-reboot output fields are bounded, the generated SYSTEM script revalidates embedded System32/install-helper paths before launch, requested post-reboot task creation failure now reports `ok=false`/`partial=true` instead of full remediation success, checkpoint 1086 routes top-level bcdedit/schtasks diagnostics through the shared bounded System32 runner, checkpoint 1091 routes generated post-reboot bcdedit/install/fltmc/sc probes through an embedded bounded temp-file diagnostic runner, checkpoint 1092 bounds final catch diagnostics before remediation log/report writes, and checkpoint 1295 makes generated post-reboot stop cleanup fail visibly when a killed child does not exit within the bounded post-kill wait.
- Windows driver install/uninstall script safety hardening needs manual elevated development-VM verification; source/no-confirm checks confirm test-driver install/uninstall scripts require explicit confirmation, validate INF files as regular non-reparse files, avoid ambient `bcdedit`, `fltmc`, `pnputil`, or `sc.exe` launches, preserve structured bounded install/load/start/query/unload/delete `command_diagnostics`, checkpoint 1084 bounds shared System32 command diagnostics through temp-file redirected subprocess output, timeouts, and cleanup checks, checkpoint 1085 routes the separate TESTSIGNING helper bcdedit probes/mutations through that shared bounded diagnostic path, and avoid reporting install/uninstall success without verified filter/service state.
- Windows firmware reboot helper safety hardening needs manual elevated development-VM verification; source checks confirm the UEFI reboot helper requires `-ConfirmFirmwareReboot`, uses checked local `shutdown.exe` instead of ambient PATH lookup, checkpoint 1087 routes the confirmed `shutdown /r /fw` command through the shared bounded System32 diagnostic runner, and checkpoint 1296 bounds Secure Boot query failure warnings.
- Windows driver self-test command path hardening needs built Guard Service and elevated development-VM verification; source/runtime-failure checks confirm the minifilter self-test validates the Guard Service executable, uses direct redirected process execution with a timeout instead of a shell pipeline, bounds Guard subprocess stdout/stderr before diagnostics, parses Guard self-test event/report JSON through bounded helpers, checkpoint 1097 bounds the wrapper's driver build/install/cargo/self-test child-command diagnostics, and the process-guard self-test persists bounded structured `sc query` diagnostics when the service is missing.
- Windows protection self-test Cargo-path hardening needs a provisioned Cargo path and approved elevated development-VM verification; parse/source/negative sanity checks confirm the wrapper refuses ambient Cargo lookup, validates script/report paths, refuses driver installation without explicit `-ConfirmDriverInstall`, builds Guard Service through checked Cargo, passes the checked Guard Service executable explicitly into the minifilter self-test, checkpoint 1007 verifies protection-gate self-test reports are read through the shared bounded handle reader and oversized reports fail visibly, checkpoint 1294 makes the self-test child stop helper fail visibly when a killed child does not exit within the bounded post-kill wait, and the operational docs now show the required confirmation switches.
- Windows driver build/setup tool and report hardening needs a provisioned Visual Studio Build Tools/WDK host; parse/source/negative/runtime failure-mode checks confirm setup/build reports are repo-contained and atomically staged, setup-report consumers parse bounded regular-file JSON before trusting tool paths, checkpoint 845 normalizes bounded PowerShell JSON helper parsing, checkpoint 848 makes PowerShell `File.Replace` calls use real backup paths instead of `$null`, checkpoint 1011 moves shared System32 helper JSON and minifilter/process-guard setup-report readers onto byte-limited handle reads, checkpoint 1084 bounds shared System32 command diagnostics through temp-file redirected subprocess output, timeouts, and cleanup checks, checkpoint 1089 routes setup-dev TESTSIGNING `bcdedit /enum` diagnostics through the shared bounded System32 runner, checkpoint 1090 routes minifilter driver log `fltmc`/`sc` diagnostics through the same bounded runner, checkpoint 1095 routes driver build MSBuild/manual-link diagnostics through bounded subprocess capture, checkpoint 1096 routes setup-dev `vswhere.exe` Visual Studio discovery through bounded subprocess capture, checkpoint 1106 routes minifilter wrapper setup-script delegations through bounded PowerShell diagnostics, checkpoint 1107 routes process-guard wrapper setup/signing delegations through bounded PowerShell diagnostics, checkpoint 1294 makes shared System32 stop cleanup fail visibly when killed child processes remain unreaped, ambient `Get-Command` discovery for MSBuild/signing tools is absent, setup/project/MSBuild/linker/artifact paths are validated before build evidence is trusted, process-guard setup delegation validates the shared setup script before launch, setup tool recursive-discovery and unsafe existing-candidate validation failures are bounded `tool_discovery_errors`, driver object/build-artifact discovery is fail-visible, and Secure Boot plus TESTSIGNING probe failures are recorded as bounded report evidence instead of silently defaulting to disabled.
- Windows driver signing/test-certificate hardening needs an approved development signing host; parse/source/negative sanity checks confirm signing and certificate reports are repo-contained and atomically staged, test certificate creation requires explicit `-ConfirmCreateTestCertificate`, signing target discovery is fail-visible and targets must be regular non-reparse driver artifacts under the repository, test certificate names/thumbprints are token-validated, `signtool` sign/verify diagnostics are structured and bounded per target, and timestamping uses HTTPS. Production driver signing remains blocked on Microsoft Hardware Dev Center signing.
- Windows driver validation report safety needs approved elevated development-VM verification; parse/source/negative sanity checks confirm install/uninstall/self-test reports stay under the repository and use atomic writes, setup reports are validated before trust, minifilter self-test rejects outside Guard Service paths before launch, checkpoint 1093 bounds install/uninstall final catch errors before JSON report writes, checkpoint 1094 bounds build/sign/cert/self-test final catch errors before JSON report writes, and driver uninstall and self-test command failures are bounded report evidence instead of swallowed stderr or success claims.
- Minifilter self-test timeout diagnostics need built Guard Service and approved elevated development-VM verification; parse/source/negative checks confirm timeout process-kill failures are no longer swallowed and self-test failure reports preserve errors.
- Windows driver log collection safety needs elevated development-VM fixture review; parse/source/negative/smoke checks confirm driver log output stays under the repository, is atomically staged, records command exit codes, bounds collected output, and reports event-log read failures visibly.
- Process-guard signing wrapper safety needs approved development signing execution; parse/source/negative checks confirm the wrapper validates the shared signing script, report path, and build-output directory under the repository before delegating to the hardened signer.
- Live driver-remediation log safety needs approved elevated development-VM execution; parse/source checks confirm direct log appends and generated post-reboot direct install-log writes are absent, live command output is recorded with exit codes and bounds, checkpoint 1091 makes generated post-reboot command probes bounded temp-file subprocess diagnostics before JSON reporting, checkpoint 1092 bounds final catch diagnostics before JSON/log reporting, and checkpoint 1299 reads existing `latest.log` content through a bounded handle/tail reader instead of `ReadAllText`.
- Installed smoke-test path-safety hardening needs installed Windows fixture verification; source checks confirm the smoke test validates local non-reparse file/directory types before treating installed artifacts as release evidence or launching Core Service health, signature/rule file enumeration failures are bounded visible errors instead of silent zero counts, service probe failures distinguish missing/uninspectable services from stopped services, checkpoint 1010 moves installed release-manifest reads onto the shared byte-limited handle reader, checkpoint 1081 bounds installed smoke-test error aggregation/output, and checkpoint 1082 bounds the Core Service health subprocess with timeout, stdout/stderr byte limits, hidden launch, output-limit kill, and visible cleanup diagnostics.
- Installer stage-test path-safety hardening needs full packaged-stage fixture verification; source checks confirm stage-test release evidence uses local non-reparse file/directory validation instead of presence-only checks, staged signature/rule/artifact enumeration failures are bounded visible errors instead of silent empty evidence, checkpoint 828 makes malformed staged release manifests fail as bounded JSON gate evidence, checkpoint 1010 moves staged release-manifest reads onto the shared byte-limited handle reader, checkpoint 1014 moves WiX source scanning onto that reader, and checkpoint 1081 bounds installer stage-test error aggregation/output.
- Release-gate path-safety hardening needs full release fixture verification; source checks confirm release-gate helper scripts, reports, AI model files, stage roots, and stage payloads are validated as local non-reparse file/directory evidence before read or execution, dist artifact enumeration failures are bounded visible errors instead of silent missing-artifact evidence, checkpoint 828 makes malformed self-test/AI metadata JSON fail as bounded gate evidence, and checkpoint 1081 bounds top-level release gate error aggregation/output.
- Local-core service-status System32 `sc.exe` path/output hardening is runtime-verified for current crate fixtures in checkpoint 1647: `service_status` passed (`10`) and covers checked System32 helper resolution plus bounded service-query diagnostics. Elevated installed Windows service-control E2E remains partial.
- Guard driver-health bounded command execution is runtime-verified for crate fixtures in checkpoint 1642: `driver_health` passed `16 passed; 0 failed`, covering bounded probe diagnostics, timeouts, and visible cleanup-failure reporting; live Windows driver-health command E2E remains partial.
- Historical Local quarantine `icacls.exe` path/runner evidence from checkpoint 1647 is superseded by checkpoint 2184. Production Local Core no longer launches an ACL subprocess; the shared platform crate applies and reads back the exact DACL through Windows handle APIs. Installed LocalSystem quarantine-root E2E remains partial.
- Historical Guard `icacls.exe` path/runner evidence from checkpoint 1720 is superseded by checkpoint 2184. Production Guard no longer launches an ACL subprocess or derives identity from account environment variables; the shared process-token/DACL path has current runtime coverage. Installed Guard quarantine-root E2E remains partial.
- Guard quarantine metadata field validation is runtime-verified in checkpoint 1637: Guard threat labels are normalized before payload movement and record ID/hash/label/action/source fields are validated before staged metadata/auth writes; Guard rustfmt passed.
- Guard quarantine record path validation is runtime-verified in checkpoint 1637: Guard original/payload record path text is validated before quarantine directory hardening, payload movement, and staged metadata/auth writes; Guard rustfmt passed.
- Guard quarantine expected-hash preflight is runtime-verified in checkpoint 1637: malformed expected SHA-256 values fail before quarantine root resolution, directory hardening, source hashing, or payload movement; Guard rustfmt passed.
- Guard quarantine copy fallback expected-hash preflight is runtime-verified in checkpoint 1637: malformed fallback expected SHA-256 values fail before source/destination inspection or payload copy, while bare and prefixed valid hashes compare through normalized bodies; Guard rustfmt passed.
- guard quarantine copy fallback source-delete cleanup is runtime-verified in checkpoint 1637: copied destinations are removed after verified fallback copy if original source deletion fails, or cleanup failure is reported with source-delete context; Guard rustfmt passed.
- guard quarantine copy fallback verification cleanup is runtime-verified in checkpoint 1637: copied destinations are removed when post-copy destination metadata/hash verification fails, or cleanup failure is reported with verification context; Guard rustfmt passed.
- Guard quarantine finalization cleanup is runtime-verified in checkpoint 1637: post-move finalization failures clean untracked payload, metadata, auth-sidecar, and temp artifacts or report cleanup failure with the original finalization error; Guard rustfmt passed.
- Guard quarantine staged metadata final-destination exclusivity is runtime-verified in checkpoint 1637: Guard metadata, auth-sidecar, and metadata-key activation rejects existing final destinations instead of removing/replacing them and cleans staged temp files visibly on write, validation, preflight, or activation failure; Guard rustfmt passed.
- Guard quarantine staged metadata parent revalidation is runtime-verified in checkpoint 1637: Guard metadata, auth-sidecar, and metadata-key activation validates the parent before temporary writes and rechecks it before activation with visible staged-temp cleanup on parent preflight failure; platform-gated junction/symlink host coverage remains partial.
- Guard quarantine staged metadata UUID temp naming is runtime-verified in checkpoint 1637: Guard metadata, auth-sidecar, and metadata-key activation allocates per-write UUID temp filenames instead of predictable fixed temp names and leaves legacy fixed-temp symlinks untouched; Guard rustfmt passed.
- Guard quarantine staged temp cleanup ownership is runtime-verified in checkpoint 1637: Guard metadata, auth-sidecar, and metadata-key cleanup only runs after exclusive temp creation succeeds, so create/open failures on unowned temp-path collisions do not remove existing files or links; Guard rustfmt passed.
- Guard process inventory PowerShell path/output hardening is partially runtime-verified in checkpoint 1642 through `process_watch` and `process_skip` fixtures plus prior Guard full-crate coverage; live Windows process-query fixture verification remains partial.
- Guard process-stop command path/output hardening remains partially runtime-verified through checkpoint 1642 process fixture coverage and prior Guard process command source checks; live Windows/POSIX stop-command fixture verification remains partial.
- Native Authenticode PowerShell path, output, and subject-parser hardening is runtime-verified for current native-engine fixtures in checkpoint 1647: `microsoft` passed (`18`) and covers checked WindowsPowerShell resolution, bounded signer JSON diagnostics, malformed subject handling, and Microsoft publisher/system-path parsing contracts. Live Authenticode validation against installed artifacts and the real Windows trust store remains partial.
- Native Windows system-path trust root handling is runtime-verified for current native-engine fixtures in checkpoint 1647: `microsoft` passed (`18`) and covers checked `SystemRoot`/`WINDIR`-derived system roots plus component-boundary matching. Installed Windows system-root E2E remains partial.
- Native dead publisher-stub removal is runtime-verified in checkpoint 1644: full native-engine tests passed (`284` lib, `6` bin), `native_trust_does_not_export_dead_publisher_stub` passed (`1`), and native-engine rustfmt passed.
- Native PE resource parser is runtime-verified in checkpoint 1644: full native-engine tests passed and `pe_resource` passed (`3`), covering resource count parsing, truncated-entry rejection, and non-dead-stub source contract; native-engine rustfmt passed.
- Native update signature-stub removal is compile/rustfmt verified in checkpoint 1644: full native-engine tests passed (`284` lib, `6` bin) and the native-engine update-stub direct contract remains absent; signed update verification remains owned by `core\avorax_update_service`.
- Native update rollback-stub removal is compile/rustfmt verified in checkpoint 1644: full native-engine tests passed (`284` lib, `6` bin) and the native-engine rollback-stub direct contract remains absent; rollback remains owned by `core\avorax_update_service`.
- Native updates placeholder-namespace removal is runtime-verified in checkpoint 1644: full native-engine tests passed and `native_engine_does_not_export_placeholder_updates_namespace` passed (`1`); native-engine rustfmt passed.
- Local file-walker non-regular entry handling and walk-error cap visibility are now part of the small-threat MVP verifier in checkpoint 1947 through the local-core `file_walker` Cargo filter (`7` passed on this Windows host). This verifies quick/full walk behavior, non-following metadata source guards, non-regular skip/error reporting guards, and bounded/omitted walk-error details with safe fixtures. Platform-specific symlink/reparse E2E remains partial where the host cannot create the required filesystem objects without an approved fixture.
- Native script analyzer unsupported-type handling is runtime-verified in checkpoint 1644: full native-engine tests passed and `script_analysis_rejects_unsupported_file_types` passed (`1`); native-engine rustfmt passed.
- Native ML feature lookup handling is runtime-verified in checkpoint 1644: full native-engine tests passed and `unknown_feature` passed (`3`), covering visible failure for unknown feature names; native-engine rustfmt passed.
- Native process-start action mapping is runtime-verified in checkpoint 1644: full native-engine tests passed and `process_start_action_mapping_is_exhaustive` passed (`1`); native-engine rustfmt passed.
- Native risk-fusion recommended-action mapping is runtime-verified in checkpoint 1644: full native-engine tests passed and `risk_fusion_recommended_action_mapping_is_exhaustive` passed (`1`); native-engine rustfmt passed.
- Native signature action-policy conversion is runtime-verified in checkpoint 1644: full native-engine tests passed and `action_policy_to_verdict_rejects_unknown_policy` passed (`1`); native-engine rustfmt passed.
- Native signature compiler source/output path hardening is runtime-verified for current compiler fixtures in checkpoint 1647: `zentor-signature-compiler signature_compiler` passed (`6`) and covers checked source/output paths, bounded reads, exclusive staged writes, cleanup, and activation contracts. Release signing/pack ceremony E2E remains partial.
- Native signature-pack strict-schema hardening is runtime-verified in checkpoint 1640: `SignaturePack`, `SignaturePackMetadata`, `NativeSignature`, and `SignatureMatch` reject malformed/unknown-field shapes in native-engine fixtures, representative bundled `.zsig` assets pass the indicator-pack validator, and native-engine rustfmt passed.
- Native rule-pack strict-schema hardening is runtime-verified in checkpoint 1640: `RulePack`, `NativeRule`, `RuleCondition`, and `RuleMatch` reject malformed/unknown-field shapes in native-engine fixtures, `rule_compiler` fixtures reject malformed source packs, representative bundled `.zrule` assets pass the indicator-pack validator, and native-engine rustfmt passed.
- Native signature/rule pack actual-byte read limits need Cargo/rustfmt execution and oversized/replacement fixture verification; source checks in checkpoint 1271 confirm native signature and rule pack readers keep non-following regular-file metadata and enforce both metadata-size and actual-read byte limits before UTF-8 or JSON parsing.
- Native rule match weighting is runtime-verified in checkpoint 1644: full native-engine tests passed and `rule_match_weight_mapping_has_no_wildcard_default` passed (`1`); native-engine rustfmt passed.
- Native threat-intel confidence mapping is runtime-verified in checkpoint 1644: full native-engine tests passed and `default_confidence_mapping_has_no_medium_wildcard` passed (`1`); native-engine rustfmt passed.
- Native threat-intel indicator normalization is runtime-verified in checkpoint 1644: full native-engine tests passed and `indicator_normalizer` passed (`2`), covering explicit normalization branches; native-engine rustfmt passed.
- Native file-walker non-regular entry handling and walk-error cap visibility are now part of the small-threat MVP verifier in checkpoint 1947 through the native-engine `native_file_walker` Cargo filter (`3` passed on this Windows host). This verifies non-following metadata source guards, non-regular skip/error reporting guards, metadata-error honesty, and bounded/omitted native walk-error details. Platform-specific symlink/reparse E2E remains partial where the host cannot create the required filesystem objects without an approved fixture, and native scan-summary boundedness remains covered by prior source/runtime checks.
- Native quick/full scan root validation is now part of the small-threat MVP verifier in checkpoint 1948: native scan env-root validation passed (`3`), quick-scan root planning passed (`3`), and full-scan root planning passed (`1`) on this Windows host. This verifies relative/empty/parent-traversal env-root rejection, checked env-root use, non-following quick-root presence checks, quick-root inspection diagnostics, duplicate-free quick-root planning, and no current-directory/dot fallback for native full scans. Broader Windows/POSIX environment root fixtures and installed scan-root E2E remain partial.
- Native quick-scan candidate probe error reporting is current-host verifier covered in checkpoint 1948 for non-following presence checks and fail-visible root inspection diagnostics. Filesystem permission and broken-symlink/junction/reparse E2E remains partial because the symlink-oriented fixture is Unix-gated and must not be counted as Windows proof.
- Native engine default-root validation is runtime-verified in checkpoint 1642: `native_engine_root` passed `1 passed; 0 failed`, covering default-root candidate validation; installed native asset fixtures remain partial.
- Native exact-hash trust-store bounded-reader, known-good, and known-bad fixtures are now part of the small-threat MVP verifier in checkpoint 1953 through native-engine `trust_store` (`3` passed), `known_good` (`6` passed), and `known_bad` (`10` passed) on this Windows host. This covers strict unknown-field rejection, malformed hash rejection, oversized-store rejection, missing-store empty compatibility, bounded reads, and non-following presence markers. Replacement-race and Unix-only symlink fixtures remain platform-limited.
- Local app-control known-good/known-bad/user-approval policy decisions, strict trust-store schemas, bounded store reads, exact passthrough roots, script subpolicy propagation, publisher trust validation, and fail-closed malformed-hash branches are now part of the small-threat MVP verifier in checkpoint 1952 through local-core `app_control` (`47` passed) and `trust_store` (`10` passed) on this Windows host. Replacement-race/symlink fixtures, live Authenticode E2E, installed UI/service E2E, signed-driver behavior, and pre-execution blocking remain partial, blocked, or technically limited.
- User allowlist and feedback/training-label stores are now part of the small-threat MVP verifier in checkpoint 1954 through local-core `allowlist` (`37` passed), native-engine `allowlist` (`6` passed), and local-core `training_label` (`21` passed) on this Windows host. This covers unsafe-root rejection, traversal-safe matching, strict persisted schemas, bounded store/hash reads, staged writes, malformed persisted hash rejection, native exact-hash/component-aware matching, false-positive suppression/revocation, strict label/static-feature schemas, and feedback store fail-closed behavior. Replacement-race/symlink fixtures and installed Scan/Allowlist UI click-layout E2E remain partial.
- Local quarantine metadata/path/integrity regressions and native quarantine trust-root regressions are now part of the small-threat MVP verifier in checkpoint 1955 through local-core `quarantine` (`88` passed) and native-engine `quarantine_trust` (`3` passed) on this Windows host. This covers authenticated metadata visibility, path/text validation, staged metadata/auth/key writes, payload/hash integrity, restore/delete status ordering, cleanup/finalization behavior, and native quarantine trust-root boundaries at the fixture layer. Installed local-core/service/UI E2E, platform-gated ACL/reparse/race behavior, live-malware validation, signed-driver behavior, pre-execution blocking, and secure-erase claims remain partial, blocked, technically limited, or not claimed.
- Local ClamAV executable discovery and compatibility-signature hardening are now part of the small-threat MVP verifier in checkpoint 1950: local-core `clamav` passed (`11`) on this Windows host, covering no ambient PATH lookup, configured scanner path validation, bounded command output, bounded hash/sample reads, local EICAR signature scanning, infected-exit detection naming, and fail-visible local signature errors. Configured/bundled scanner E2E remains partial and ClamAV remains optional compatibility coverage, not a required core-protection dependency.
- Guard ClamAV executable discovery hardening is runtime-verified for current compatibility fixtures in checkpoint 1642: `clamav` passed `2 passed; 0 failed`; configured/bundled scanner E2E remains partial.
- Guard ClamAV bounded command execution is runtime-verified for current compatibility fixtures in checkpoint 1642 through `clamav` (`2 passed`); configured scanner timeout/output E2E remains partial.
- Guard ClamAV exit-status handling is runtime-verified for current compatibility fixtures in checkpoint 1642 through `clamav` (`2 passed`); configured scanner exit-code E2E remains partial.
- Local ClamAV infected-exit fallback is runtime-verified for current compatibility fixtures in checkpoints 1647 and 1648 through local-core `clamav` (`11` passed); configured scanner output E2E remains partial.
- Guard ClamAV infected-exit fallback is runtime-verified for current compatibility fixtures in checkpoint 1647 through Guard `clamav` (`2` passed); configured scanner output E2E remains partial.
- Guard compatibility scan-target validation and sample-prefix reads need focused runtime fixture review where not superseded by later checkpoints, plus and symlink/reparse/directory filesystem fixture verification; source/direct-contract checks confirm ClamAV and YARA compat helpers require regular non-following scan-target metadata before scanner/rule sample reads, and checkpoint 1283 confirms Guard YARA samples use explicit chunked prefix limits.
- Guard driver IPC hash/YARA target metadata and sample-prefix reads need focused runtime fixture review where not superseded by later checkpoints, plus and driver request filesystem fixture verification; source/direct-contract checks confirm driver verdict hashing and driver IPC YARA samples check non-following scan-candidate metadata before opening request paths, and checkpoint 1283 confirms driver IPC YARA samples use explicit chunked prefix limits.
- Guard driver IPC local hash byte limits need focused runtime fixture review where not superseded by later checkpoints, plus and oversized driver scan-candidate fixture verification; source/direct-contract checks in checkpoint 1252 confirm local SHA-256 evidence reads bounded chunks and rejects candidates above `MAX_DRIVER_HASH_BYTES` instead of using unbounded `std::io::copy`.
- Guard YARA malformed string/confidence diagnostics and actual-byte rule reads need focused runtime fixture review where not superseded by later checkpoints, plus and compat-YARA malformed/oversized/replacement-rule fixture verification; source checks in checkpoints 906-907 confirm service and driver IPC parsers fail malformed `$string` declarations, unquoted pattern values, malformed confidence metadata, and unsupported confidence labels inside accepted rules instead of continuing silently or degrading to low confidence, while checkpoint 1278 confirms Guard Service and driver IPC rule readers retain non-following regular-file metadata and enforce metadata-size plus actual-read byte limits before rule parsing.
- Local ransomware guard persisted-config, actual-byte read limits, and policy-matching strictness are now part of the small-threat MVP verifier in checkpoint 1949 through the local-core `ransomware_guard` Cargo filter (`21` passed on this Windows host). This verifies benign protected-root activity detection, traversal-outside-root rejection, trusted-process suppression boundaries, trusted-process collapsed path equivalence, persisted config strict schema/value validation, directory/symlink/path-safety markers, staged writes, oversized config rejection before parse, and metadata/actual-byte bounded config reads. Installed watcher/service E2E and live-ransomware validation remain partial or disabled.
- Local YARA default rule root hardening, explicit metadata validation, actual-byte rule reads, and sample-prefix reads are now part of the small-threat MVP verifier in checkpoint 1950: local-core `yara` passed (`19`) on this Windows host. This covers embedded fallback behavior, no relative default-rule fallback, fail-visible rule-load errors, confirmed-vs-review rule verdicts, false-positive guard for normal executable text, explicit category/confidence/description/false-positive metadata, malformed pattern rejection, non-following scan/rule paths, directory/oversized rule rejection before read/parse, bounded sample reads, metadata/actual-byte bounded rule reads, unreadable-target error reporting, and non-empty threat file names. Installed local-core/default-rule E2E remains partial.
- Local heuristic provider conservative auto-action gating, bounded script/entropy samples, non-following target inspection, and branch-honesty fixtures are now part of the small-threat MVP verifier in checkpoint 1951 through local-core `heuristic` (`19` passed on this Windows host). Installed service/UI E2E, production false-positive-rate evidence, and live-malware validation remain partial or disabled.
- Local static-feature extraction bounded sample reads, non-following target inspection, directory/non-file rejection, and filename/extension/default branch-honesty fixtures are now part of the small-threat MVP verifier in checkpoint 1951 through local-core `static_feature` (`7` passed on this Windows host). Production ML activation, replacement-race/symlink fixtures, installed local-core/UI E2E, and live-malware validation remain partial or disabled.
- Local YARA status-label alignment is Rust-runtime verified for current local-core fixtures in checkpoint 1647 through `yara` (`19` passed), while Flutter health/status UI alignment still depends on the existing Flutter runtime fixture layer and installed IPC E2E remains partial.
- Local AI model root validation is runtime-verified for current local-core fixtures in checkpoint 1647 through `ai_model` (`1` passed); installed local-core/model layout and production model activation E2E remain partial.
- Local-core native engine asset locator validation is runtime-verified for current local-core fixtures in checkpoint 1647 through `engine_asset_locator` (`4` passed); installed local-core/native-engine asset layout E2E remains partial.
- Guard native/YARA asset-root validation is runtime-verified for current Guard fixtures in checkpoint 1642: `guard_native_asset` passed `2 passed; 0 failed` and `native_asset` passed `4 passed; 0 failed`; installed Guard/native-asset/default-rule E2E remains partial.
- Guard self-test fixture and hash target metadata is runtime-verified for current Guard fixtures in checkpoints 1647 and 1648 through `self_test` (`16` passed); replacement-race, reparse-host, and installed service self-test E2E remain partial.
- Guard self-test handler evidence wording is runtime-verified for current Guard fixtures in checkpoints 1647 and 1648 through `self_test` (`16` passed); Windows/CLI installed self-test E2E remains partial.
- Guard self-test post-launch fallback evidence is runtime-verified for current Guard fixtures in checkpoint 1647 through `post_launch` (`3` passed); installed Guard post-launch E2E remains partial.
- Guard health post-launch fallback status is runtime-verified for current Guard fixtures in checkpoint 1647 through `post_launch` (`3` passed) and `self_test` (`16` passed); installed Guard health E2E remains partial.
- Guard self-test legacy status fields are runtime-verified for current Guard fixtures in checkpoints 1647 and 1648 through `self_test` (`16` passed); Windows/CLI installed self-test E2E remains partial.
- Flutter protection self-test completion severity is runtime-verified for the current Flutter fixture layer in checkpoint 1646: `app_visual_policy_test.dart` passed (`57`) including visible self-test result panel and issue-severity completion event coverage; installed self-test E2E remains partial.
- Flutter health status allowed-set validation has current-host Flutter runtime fixture coverage; source checks in checkpoint 1048 confirm YARA, native-engine, native-ML, Core Service, Guard, and driver health status labels must match explicit allowed sets instead of accepting arbitrary non-empty IPC strings, and checkpoint 1563 passes `flutter test test\local_core_ipc_diagnostics_test.dart --reporter compact` with `42 passed`. Installed local-core health IPC E2E remains partial.
- Flutter startup background-task error boundary remains partial for detached-future failure paths; source checks in checkpoint 1300 confirm app detection, malware-engine health, quarantine refresh, silent update check, and saved protection restore use a shared bounded error/audit boundary instead of detached direct startup invocations, and checkpoint 1567 adds startup runtime evidence for config-recovery warning propagation. Focused runtime fixtures are still needed for unexpected async failures escaping individual startup tasks.
- Flutter scheduled quick-scan timer error boundary has current-host Flutter timer fixture coverage but still needs installed app-lifetime UI/E2E scheduling verification; source checks in checkpoint 1301 confirm periodic quick-scan callbacks use a safe bounded scan error/audit boundary instead of detached async timer futures, checkpoint 1565 verifies a scheduled timer fire launches a detect-only quick scan with `scheduled_quick_scan_started` event evidence through `flutter test test\offline_scan_test.dart --reporter compact` (`86 passed`), and checkpoint 1977 verifies the timer skips with warning evidence instead of logging a start when custom target selection is active.
- Flutter empty scan-target orchestration has current-host Flutter scan-controller fixture coverage; source checks in checkpoint 1302 confirm `_scanPaths` fails empty target lists visibly before `paths.first` or scan-start in-flight state, and checkpoint 1564 passes the empty full-scan target fixture in `offline_scan_test.dart` with no local-core scan call, `completedWithErrors`, and `scan_targets_unavailable` evidence.
- Guard self-test verdict-cache evidence is disabled until a real cache implementation and self-test exist; source checks in checkpoint 946 confirm `verdict_cache_ok` reports `false` instead of unverified success.
- Guard self-test AI model metadata root validation and actual-byte read limits need focused runtime fixture review where not superseded by later checkpoints, plus and installed Guard/self-test metadata fixtures; source/direct-contract checks confirm model metadata discovery uses controlled executable roots, debug current-directory discovery requires a Guard repo marker, and candidate metadata roots must be absolute local paths, while checkpoint 1275 confirms self-test metadata reads retain non-following regular-file metadata and enforce metadata-size and actual-read byte limits before UTF-8 and JSON parsing.
- Guard driver IPC hash-read error reporting is runtime-verified for current Guard fixtures in checkpoint 1647 through `hash_read` (`1` passed), covering visible local hash-read failure reasons. Driver request filesystem E2E with the signed driver path remains partial.
- Flutter update install-root and install-report path handling needs Flutter/Dart test/format and installed Windows UI fixtures; source/direct-contract checks in checkpoint 813 confirm update apply/rollback no longer hardcodes `C:\Program Files\Avorax`, install-report lookup no longer hardcodes `C:\ProgramData\Avorax\reports` or `C:\Program Files\Avorax`, and report roots are derived from validated local environment/executable roots with visible validation errors.
- Flutter update cache staging and activation are runtime-verified for the current Flutter fixture layer in checkpoint 1803: local and remote package source checks still confirm package temp files are reserved with `create(exclusive: true)` before writes and streamed through reserved-temp helpers, and a failed oversized local `.aup` staging path preserves an existing cached package, returns no fake `localPackagePath`, and leaves no temporary `.part` files. Installed Windows update UI/update-service E2E remains partial.
- Flutter scan engine-unavailable UI has current-host Flutter fixture coverage but still needs installed Windows UI/screenshot E2E; source/direct-contract checks in checkpoint 814 confirm the scan UI no longer displays a hardcoded native-engine install path when Core Service did not report one, and checkpoint 1563 passes `flutter test test\app_visual_policy_test.dart --reporter compact` with `57 passed`.
- Flutter Home/Protection/Settings protected-status UI and controller state now have current-host Flutter fixture coverage, but installed Windows visual/screenshot E2E remains partial; source checks in checkpoints 953, 954, 955, 956, 957, 958, 959, and 960 confirm these surfaces check malware/native engine readiness before reporting `Protected`, showing ready-assets/local-only reassurance, displaying the real-time protection metric as fully enabled, showing protected-state Protection explanation copy, showing a raw Settings Antivirus protection label, setting `ProtectionStatus.protected`, or labeling partial protection as fully enabled. Checkpoint 961 source checks confirm limited protection starts log distinct warning evidence instead of plain success. Checkpoint 1523 confirms non-empty `lastEngineError` also forces attention-needed Home/Protection/Settings status and is visible in Settings/Protection diagnostics. Checkpoint 1524 confirms protection-start treats `lastEngineError` as a start limitation and does not set `ProtectionStatus.protected` while engine diagnostics are present. Checkpoint 1527 confirms the Home native-engine metric also shows diagnostic attention/details instead of status-only ready copy when `lastEngineError` is present. Checkpoint 1528 applies the same diagnostic-aware native-engine metric behavior to Device. Checkpoint 1529 applies diagnostic-aware labeling to the Settings `Native status` value. Checkpoint 1530 applies diagnostic-aware labeling to the Protection native-engine metric and checklist row. Checkpoint 1531 prevents the Home native-rule metric from using ready-status fallback evidence while `lastEngineError` is visible. Checkpoint 1532 applies the same ready-fallback guard to Protection native signature/rule count labels. Checkpoint 1533 applies the same ready-fallback guard to Settings native packaged-count labels. Checkpoint 1534 prevents Protection quarantine readiness from reporting available while `lastEngineError` is visible. Checkpoint 1535 makes Protection native-engine detail copy diagnostic-first when `lastEngineError` is visible. Checkpoint 1536 trims Device native-engine diagnostic detail before display. Checkpoint 1537 trims the Settings engine-diagnostic row before display. Checkpoint 1538 trims the Scan engine-unavailable last-error chip before display. Checkpoint 1539 prevents Scan signature/rule pack ready-status fallback labels while engine diagnostics are visible. Checkpoint 1540 prevents native ready-status alone from satisfying protection-start local prevention while engine diagnostics are visible. Checkpoint 1563 verifies the focused Flutter widget/runtime fixture cluster with `app_visual_policy_test.dart` (`57 passed`).
- Flutter realtime watcher local path-probe limitations are runtime-verified for the current Flutter fixture layer in checkpoint 1804: an injected filesystem probe failure for a NUL-rich watch path still leaves Local Core as the final validation boundary, passes the original path to the watcher call, and surfaces a normalized no-NUL limitation/error message in UI state. Installed local-core watcher/service E2E remains partial.
- Update-service CLI install-dir fallback and explicit install-dir validation have local Rust fixture coverage in checkpoint 1624 (`update_cli_install_dir_*`, apply, and rollback tests included in the `176 passed` update-service suite); installed update-service fixture verification remains unverified.
- Update-service apply/rollback install-dir canonicalizer validation, rollback latest-snapshot entry validation, and rollback recursive snapshot-copy validation are runtime-verified by checkpoint 1624 through the update-service rollback/apply tests in the `176 passed` crate suite. Installed update-service rollback against real Avorax artifacts remains separate E2E work.
- Update-service normal `.aup` engine/service/docs/app payload allowlist and applier activation fixtures are runtime-verified by checkpoint 1624 through update-service main tests (`176 passed`), including unknown engine subcomponents, direct service-file allowlists, Markdown-only docs, and restricted app payload targets. PowerShell package-builder fixture coverage remains tracked separately below for builder-host race/reparse and staged artifact evidence.
- Update-service normal `.aup` app component evidence needs builder fixture verification on a provisioned PowerShell/Cargo host; source checks in checkpoint 1441 confirm `components.app` is derived from any staged app payload file so DLL/resource-only app updates do not produce self-invalid manifests.
- Update-service normal `.aup` engine component evidence needs builder fixture verification on a provisioned PowerShell/Cargo host; source checks in checkpoint 1442 confirm empty supported engine runtime directories fail visibly and engine component flags are derived from counted staged runtime files.
- Update-service normal `.aup` docs component evidence needs builder fixture verification on a provisioned PowerShell/Cargo host; source checks in checkpoint 1443 confirm `components.docs` is derived from counted staged docs payload files rather than docs directory presence.
- Update-service normal `.aup` service component evidence needs builder fixture verification on a provisioned PowerShell/Cargo host; source checks in checkpoint 1444 confirm Core and Guard service component flags are derived from explicit staged service payload file checks.
- Update-service normal `.aup` app top-level file staging needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoints 1445 and 1448 confirm top-level app payload source files and destination paths are revalidated at copy time.
- Update-service normal `.aup` app directory staging needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1446 confirm app payload source directories and destination paths are revalidated before recursive staging.
- Update-service normal `.aup` engine component staging needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1447 confirm supported engine runtime component source directories and destination paths are revalidated before recursive staging.
- Update-service normal `.aup` engine checked component staging needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1497 confirm supported engine runtime component paths are resolved from the checked engine source root and runtime-file counts use checked component directories.
- Update-service normal `.aup` service file staging needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1448 confirm allowlisted service source files and destination paths are revalidated before staging.
- Update-service normal `.aup` docs file staging needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1449 confirm Markdown docs source files and destination paths are revalidated before staging.
- Update-service normal `.aup` docs checked source staging needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1498 confirm Markdown docs enumeration and staging-relative path derivation share the checked docs source root.
- Update-service normal `.aup` package artifact activation needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1450 confirm final package, temporary zip, backup, and final hash source paths are revalidated.
- Update-service normal `.aup` zip-entry source revalidation needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1451 confirm each work-tree source file is revalidated immediately before `CreateEntryFromFile`.
- Update-service normal `.aup` archive checked work root needs builder race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1496 confirm ZIP work-file enumeration and entry-name derivation use the checked work directory returned by `Require-Directory`.
- Update-service normal `.aup` zip-entry allowlist needs builder runtime/race fixture verification on a provisioned PowerShell host; source checks in checkpoint 1452 confirm work-tree archive entries outside `manifest.json`, `manifest.sig`, and `payload/...` fail before zipping.
- Update-service normal `.aup` signature output revalidation needs signer race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1453 confirm `manifest.sig` output path validation before signer execution and regular-file validation after signing.
- Update-service normal `.aup` feed package URL derivation needs feed/package fixture verification on a provisioned PowerShell host; source checks in checkpoint 1454 confirm generated feed `package_url` is derived from the checked final package file name instead of a second hardcoded artifact name.
- Update-service normal `.aup` feed output revalidation needs feed-output fixture verification on a provisioned PowerShell host; source checks in checkpoint 1455 confirm feed path validation before atomic write and checked feed path reporting after write.
- Update-service normal `.aup` package output reporting needs package-output fixture verification on a provisioned PowerShell host; source checks in checkpoint 1456 confirm success output reports the checked final package file path.
- Update-service normal `.aup` metadata timestamp consistency needs feed/package metadata fixture verification on a provisioned PowerShell host; source checks in checkpoint 1457 confirm signed manifest `release_date` and feed `published_at` share one captured UTC timestamp.
- Update-service normal `.aup` payload hash source revalidation needs payload-hash race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1458 confirm staged payload files are revalidated immediately before SHA-256 hashing.
- Update-service normal `.aup` atomic writer temp/backup path revalidation needs atomic-writer collision/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1459 confirm generated temp/backup paths are revalidated before write/activation and stale random-name collisions are cleaned through checked regular-file removal.
- Update-service normal `.aup` atomic writer checked-temp activation needs atomic-writer activation race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1460 confirm `File.Replace` and `File.Move` use the checked temporary file returned by `Require-File`.
- Update-service normal `.aup` package checked-temp activation needs package activation race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1461 confirm final package `File.Replace` and `File.Move` use the checked temporary package returned by `Require-File`.
- Update-service normal `.aup` recursive staging pre-copy revalidation needs recursive-copy race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1462 confirm app and supported engine source trees are revalidated immediately before recursive `Copy-Item` staging.
- Update-service normal `.aup` app component no-reparse evidence needs app component fixture verification on a provisioned PowerShell host; source checks in checkpoint 1463 confirm staged app files are counted through the shared no-reparse payload-file helper before `components.app` is set.
- Update-service normal `.aup` docs staging no-reparse enumeration needs docs staging fixture verification on a provisioned PowerShell host; source checks in checkpoint 1464 confirm docs payload files are enumerated through the shared no-reparse payload-file helper before Markdown policy checks and staging.
- Update-service normal `.aup` shared payload-file helper pre-enumeration revalidation needs payload helper race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1465 confirm the shared helper revalidates source trees immediately before recursive file enumeration.
- Update-service normal `.aup` payload hash helper enumeration needs payload-hash helper enumeration fixture verification on a provisioned PowerShell host; source checks in checkpoint 1466 confirm staged payload files for hashing are enumerated through the shared no-reparse payload-file helper before per-file hash revalidation.
- Update-service normal `.aup` top-level app staging pre-enumeration revalidation needs top-level app staging race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1467 confirm the payload root is revalidated immediately before file and directory staging enumeration.
- Update-service normal `.aup` zip work-tree pre-enumeration revalidation needs zip work-tree race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1468 confirm the package work tree is revalidated immediately before archive enumeration.
- Update-service normal `.aup` service payload pre-staging revalidation needs service payload race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1469 confirm the payload root is revalidated immediately before allowlisted service binary staging.
- Update-service normal `.aup` engine child policy pre-enumeration revalidation needs engine child policy race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1470 confirm the engine source tree is revalidated immediately before unknown/pruned child policy enumeration.
- Update-service normal `.aup` docs pre-copy revalidation needs docs copy race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1471 confirm the docs source tree is revalidated immediately before Markdown file copy staging.
- Update-service normal `.aup` work-directory cleanup checked path needs cleanup race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1472 confirm recursive cleanup removes the checked directory returned by `Require-Directory`.
- Update-service normal `.aup` temp/backup file cleanup checked path needs cleanup race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1473 confirm stale temporary and backup file cleanup removes the checked file returned by `Require-File`.
- Update-service normal `.aup` checked directory creation path needs directory creation race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1474 confirm directory creation and final validation use the post-validation full path.
- Update-service normal `.aup` package artifact full-path activation needs package artifact race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1475 confirm temporary zip creation, package target activation, backup activation, cleanup, and final package validation use post-validation full paths.
- Update-service normal `.aup` atomic writer temp/backup full-path activation needs atomic writer race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1476 confirm atomic JSON/feed temp writes, temp validation, backup activation, stale cleanup, and final cleanup use post-validation full paths.
- Update-service normal `.aup` raw UTF-8 full-path write target needs raw write race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1477 confirm raw UTF-8 writes normalize to a full path before `WriteAllText`.
- Update-service normal `.aup` manifest signer checked paths need manifest signer race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1478 confirm signer invocation uses a checked manifest file and post-validation signature output path.
- Update-service normal `.aup` shared item validation full-path lookup needs item validation race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1479 confirm shared `Require-Item` lookup and diagnostics use post-validation full paths.
- Update-service normal `.aup` stale regular-file cleanup full-path existence checks need cleanup race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1480 confirm cleanup validates and normalizes before existence checks and checked removal.
- Update-service normal `.aup` existing directory cleanup full-path existence checks need directory cleanup race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1481 confirm cleanup validates and normalizes before existence checks, tree revalidation, and recursive removal.
- Update-service normal `.aup` component regular-file probe full-path existence checks need probe race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1482 confirm `Test-RegularFile` validates and normalizes before existence checks and checked file evidence.
- Update-service normal `.aup` component directory probe full-path existence checks need probe race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1483 confirm `Test-RegularDirectory` validates and normalizes before existence checks and checked directory evidence.
- Update-service normal `.aup` shared no-reparse tree checked enumeration needs recursive tree race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1484 confirm recursive enumeration uses the checked directory returned by `Require-Directory`.
- Update-service normal `.aup` payload file checked enumeration needs recursive payload-file race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1485 confirm file listing uses the checked payload directory returned by `Require-Directory`.
- Update-service normal `.aup` engine child policy checked enumeration needs child policy race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1486 confirm unknown/pruned child policy enumerates the checked engine directory returned by `Require-Directory`.
- Update-service normal `.aup` docs Markdown checked staging root needs docs staging race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1487 confirm Markdown staging revalidates and derives relative paths from the checked docs directory returned by `Require-Directory`.
- Update-service normal `.aup` top-level app file checked staging root needs app file staging race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1488 confirm direct app file staging enumerates the checked payload root returned by `Require-Directory`.
- Update-service normal `.aup` top-level app directory checked staging root needs app directory staging race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1489 confirm direct app directory staging enumerates the checked payload root returned by `Require-Directory`.
- Update-service normal `.aup` service payload checked staging root needs service staging race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1490 confirm service executable candidates are resolved under the checked payload root returned by `Require-Directory`.
- Update-service normal `.aup` payload hash checked root needs payload hash root race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1491 confirm staged payload hash enumeration and manifest key derivation use the checked payload root returned by `Require-Directory`.
- Update-service normal `.aup` app component checked evidence root needs app component evidence race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1492 confirm manifest `components.app` evidence is derived from the checked staged app root returned by `Require-Directory`.
- Update-service normal `.aup` service component checked evidence root needs service component evidence race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1493 confirm Core/Guard manifest flags are derived from the checked staged services root returned by `Require-Directory`.
- Update-service normal `.aup` engine component checked evidence root needs engine component evidence race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1494 confirm runtime engine manifest flags are derived from the checked staged engine root returned by `Require-Directory`.
- Update-service normal `.aup` docs component checked evidence root needs docs component evidence race/reparse fixture verification on a provisioned PowerShell host; source checks in checkpoint 1495 confirm manifest `components.docs` evidence is derived from the checked staged docs root returned by `Require-Directory`.
- Flutter executable-parent service discovery needs Flutter/Dart test/format and installed Windows UI fixtures; source/direct-contract checks in checkpoint 816 confirm update/Core/Guard executable discovery validates the resolved executable parent instead of building launch candidates from unchecked `Platform.resolvedExecutable.parent.path`.
- Live driver-remediation default roots need approved elevated Windows development-VM verification; parse/source checks in checkpoint 817 confirm report and install-helper defaults are derived from validated ProgramData/ProgramFiles environment roots or explicit overrides instead of hardcoded machine-wide paths.
- Installed smoke-test default roots need installed Windows fixture execution; parse/source checks in checkpoint 818 confirm missing install and ProgramData paths are derived from validated environment roots or explicit parameters instead of fixed machine-wide paths.
- TESTSIGNING helper post-reboot instruction needs approved elevated Windows development-VM verification; parse/source checks in checkpoint 819 confirm it no longer prints a hardcoded Program Files rerun command.
- MSI helper/report and Burn launch-target hardening need full MSI/EXE build fixture execution; parse/source checks in checkpoints 820 and 821 confirm generated driver-install helper defaults, the static install report template, `LaunchTarget`, and `LaunchWorkingFolder` no longer claim fixed machine-wide paths. Checkpoint 821 uses WiX/Burn `[ProgramFiles64Folder]` substitution after validating the FireGiant schema and built-in variable documentation.

## Validation Blockers

- Any failing Rust, Flutter, Dart, performance, false-positive, or release gate must block release-candidate tagging.
- Checkpoint 1545: Rust toolchains are now available in this Windows shell through explicit paths, and the major Rust runtime suites are substantially greener. `cargo test --workspace --no-run` passes; Guard Service runtime passes (`212 passed`, checkpoint 1544); local-core runtime passes (`411 passed`); native-engine library runtime passes (`284 passed`); `cargo test --workspace --exclude avorax_update_service -- --test-threads=1` passes. The update-service elevation blocker observed here is superseded by checkpoint 1547.
- Checkpoint 1546: the Flutter/Dart client blocker is closed on this host. `flutter test --reporter compact` passes with `414 passed`, and `flutter analyze` reports `No issues found`.
- Checkpoint 1551: current-host Flutter client verification remains green after tool installation: `flutter pub get`, `flutter analyze`, and `flutter test` pass from `apps\zentor_client` with `414 passed`. Windows desktop artifact build is still blocked because Flutter plugins require Windows symlink support; enable Developer Mode or use an approved symlink-capable Windows build host before claiming built desktop artifact evidence.
- Checkpoint 1547: the Rust full-workspace runtime blocker is closed on this host. `cargo test -p avorax_update_service -- --test-threads=1` passes with `176 passed`; `cargo test --workspace -- --test-threads=1` passes; and `cargo test --workspace --no-run` passes with only pre-existing warnings in `zentor_local_core` and `zentor_api`.
- Checkpoint 1553: active non-driver release/security gates are partially verified on this host. Branding, product-copy, no-malware-binaries, false-positive, performance, and user-mode protection gates pass with explicit tool paths. The generated protection self-test report is not driver proof: `overall_result=fail` and `pre_execution_blocking_available=false` because no signed/running driver is installed.
- Checkpoint 1554: the intermittent Guard/local-core subgate failures in the top-level Windows release gate are closed. Guard Service passes serial with `212 passed`, local-core passes serial with `411 passed`; checkpoint 1756 supersedes the Android Gradle lockfile as a Windows release blocker. Remaining release blockers are Windows-host/tooling and artifact prerequisites such as missing installer stage and signed packaged artifacts.
- Checkpoint 1555: Rust release service executables are built on this host for installer input (`zentor_local_core.exe`, `zentor_guard_service.exe`, `avorax_update_service.exe`), and Android dependency locking is enabled in source. Windows installer artifacts remain blocked because `flutter build windows --debug --no-pub` fails on missing symlink support/Developer Mode, and `flutter doctor -v` reports missing Visual Studio Desktop C++ components.
- Checkpoint 1557: `tools\windows\avorax-release-prereq-check.ps1` is now the central non-mutating release-host preflight and is wired into the top-level Windows release gate. Checkpoint 1756 updates the Windows preflight so Android Gradle lockfile and Android SDK checks are skipped/informational for the Windows antivirus release path. On this host, host-only preflight still fails visibly on missing explicit `.NET SDK` path, unavailable symlink support, and missing Visual Studio Desktop C++ components.
- Checkpoint 1558: the release prerequisite preflight now emits atomic JSON evidence at `dist\release-prereq\release_prereq_report.json`; the current report is `ok=false` with 6 errors and 26 checks, matching the known release-host blockers.
- Checkpoint 1559: the Windows release workflow now runs and uploads host-only release prerequisite evidence before dependency/build steps. Host-only mode is intentionally not release approval: checkpoint 1757 host-only evidence skips Android lockfile/SDK for the Windows release path and still fails on this host for missing .NET SDK inventory, Windows symlink support, and Visual Studio Desktop C++ components. Full mode remains strict for Windows build artifacts such as `Avorax.exe` and installer stage, while the Rust release service artifacts now pass presence checks after `cargo build --workspace --release`.
- Checkpoint 1560: native signature compiler CLI strictness is verified with focused Rust and Python source-contract tests.
- Checkpoint 1561: the broad Python source-contract runner blocker from stale source anchors is closed on this host; `tools\testing\run-python-source-contracts.py` passes with `481 tests` after refreshing the contracts for current quarantine, update, allowlist, UI status, scan-progress, and controller single-flight implementations.
- Checkpoint 1562: current-host Flutter and Rust verification remains green after tool installation and source-contract cleanup. `flutter analyze` reports `No issues found`, `flutter test --reporter compact` passes with `414 passed`, `cargo test --workspace --no-run` passes, and `cargo test --workspace -- --test-threads=1` passes with existing warnings only.
- The repository may include documentation and scripts for blocked platform workflows, but blocked features must remain marked unavailable or development-only until validated.
- Ransomware simulator output is benign validation evidence only; checkpoint 853 limits it to isolated empty temporary roots, checkpoint 860 uses exclusive flushed fixture writes/appends, and it must not be used as independent ransomware certification.
- Checkpoint 2154 publishes only the verified Windows portable ZIP. MSI/packaged Windows GUI remains blocked by the missing .NET SDK inventory, Visual Studio Desktop C++ components, and Windows symlink support. A standalone internal core EXE is not a verified launcher, and Linux remains blocked until a native Linux build/runtime pass exists; none of these missing artifacts may be replaced by empty, renamed, or untested files.

## Cross-Platform Beta Packaging Status

Native workflow `29086402344` supersedes the package-build portions of the
checkpoint 2154 blocker: Windows MSI/setup, Linux DEB/tar, and macOS arm64/x64
DMG artifacts now build and pass bounded native package verification. This does
not close the following production or installed-host blockers:

- Windows Authenticode signing requires an approved certificate and protected
  signing workflow. The beta MSI and setup EXE are intentionally `NotSigned`.
- macOS Developer ID signing and notarization require approved Apple credentials.
  The beta app is ad-hoc signed and Gatekeeper rejection is recorded.
- Normal installed GUI click-through, Windows service registration/start/stop,
  privilege-boundary IPC, and uninstall behavior need isolated host E2E.
- Driver-backed and pre-execution blocking need a reviewed signed driver,
  authenticated service/helper boundary, and approved elevated VM evidence.
- The ML package remains non-production because its metadata reports
  `production_ready=false`.
- Full production SBOM and dependency-license review remain incomplete even
  though release lockfiles, requirement pins, and wrapper hashes pass.
- The beta must instruct users to keep Microsoft Defender enabled and must not
  claim kernel blocking, tamper protection, or broad/advanced malware defense.

## External Sample Repository Blocker

The external repositories registered in `sources.example.json` expose malware
samples, not an Avorax-authenticated SHA-256 definition feed. Their entries are
disabled and metadata-only. The active GitHub known-bad pack currently contains
zero signatures, so Avorax does not claim automatic blocking for those sources.
Activation requires a reviewed hash-only feed, explicit false-positive owner,
versioned signed package delivery, rollback evidence, and harmless-fixture
verification. Downloading samples to fill the pack is prohibited.

## Checkpoint 2155 Fail-Visible Tooling And Package Verification

Three active PowerShell paths no longer suppress command-discovery or file-
enumeration failures. The installed-core health probe handles only the expected
missing-function exception before loading its checked helper; update-builder
fail-safe artifact enumeration now stops on enumeration errors; and dependency
wildcard validation checks the fixed repository anchor before fail-visible
enumeration. Parser checks, the structured core-health smoke, all eleven update-
builder fail-safe scenarios, `591` source contracts, and the focused 11-gate MVP
verification passed. The self-validating report passed in `42.3s` plus `1.5s`
for final validation.

The merge package run `29094891205` exposed a transient macOS arm64 DMG verify
failure after creation and payload verification had already passed: `hdiutil`
returned `Resource temporarily unavailable`. The package builder now retries
that exact transient condition at most three times with bounded delays. Other
DMG verification failures remain immediate failures. Native macOS CI evidence
is still required before this retry is treated as verified; signing and
notarization blockers are unchanged.

## Checkpoint 2156 Native Package Cleanup Failure Visibility

Linux and macOS tool discovery now handles only the expected missing-command
status before the existing absolute executable validation, without `|| true`.
The macOS package builder fails if signed-app entitlement inspection cannot be
performed, rather than continuing without sandbox evidence. Its EXIT trap now
preserves the original status, reports emergency DMG detach failure, and turns a
detach failure after an otherwise successful path into a failure. Bash parsing,
`16` packaging tests, `591` source contracts, diff checks, and the no-malware-
binaries gate pass locally. Native Linux/macOS package CI remains required;
signing, notarization, installed-host, service, driver, and pre-execution
blockers are unchanged.

## Checkpoint 2157 Deterministic Lockfile Component Inventory

The cross-platform package workflow now creates a deterministic CycloneDX 1.6
lockfile inventory from five Cargo locks, three pub locks, and the exact-pinned
Python verification lock. The real checkout produces `569` deduplicated
components; repeated generation produced identical SHA-256 output, the official
CycloneDX 1.6 schema accepted it, and a workflow-equivalent smoke produced seven
checksum rows for six package fixtures plus the `.cdx.json`. Packaging tests
pass (`22`, with three platform privilege skips on Windows) and source contracts
pass (`591`). The file marks license review partial, final-binary resolution
false, and composition incomplete. Complete license/copyright review, final-
binary dependency resolution, and Android Gradle lock evidence remain blockers;
the lockfile inventory must not be represented as a complete production SBOM.

## Checkpoint 2158 Guard Service Lifecycle Failure Visibility

The Windows Guard Service now reports `StartPending` before `Running`, accepts
stop/shutdown controls only while running, and maps an unexpected monitor-loop
failure to service-specific exit code `1` instead of reporting a clean stopped
state. Runtime and final-status reporting failures are combined so a secondary
Service Control Manager error cannot hide the original protection failure.
Guard rustfmt passed, the two focused lifecycle tests passed, the complete Guard
suite passed (`214`), all workspace test binaries compiled, the Python source-
contract gate passed (`592`), and the no-malware-binaries gate passed. This is
fixture/runtime proof only: no service was installed or started, authenticated
privilege-boundary IPC remains unimplemented, and driver/pre-execution claims
remain blocked on reviewed signing and an approved elevated VM.

The additional strict lint command `cargo clippy --manifest-path
core/zentor_guard_service/Cargo.toml --all-targets --no-deps -- -D warnings`
is not a passing release gate: Rust 1.96 reports `15` pre-existing lints in
unchanged Guard/driver code (argument count, manual helpers, clone/return style,
and DPAPI call style). The dependency-including variant also reports `13`
pre-existing native-engine lints. Neither run reports the checkpoint 2158
lifecycle additions; the existing lint debt remains visible for a separate
reviewed cleanup instead of being represented as passing evidence.

## Checkpoint 2159 Locale-Independent Service Status Queries

Local Core and Guard health no longer launch or parse `sc.exe` for service
status. A shared `windows-service` API helper opens Service Control Manager with
`CONNECT` only, opens one of three fixed product service names with
`QUERY_STATUS` only, classifies absence solely from Windows error `1060`, and
maps typed service states without localized command text. Access-denied and
other SCM failures retain their numeric Windows error in visible diagnostics;
pending/paused states remain conservatively `installed`, not `running`.

Seven focused Core/Guard/SCM tests pass, including a read-only host query and an
unapproved-name rejection; the complete local-core suite passes (`483` in
`147.25s`), source contracts pass (`592`), rustfmt passes, and the no-malware-
binaries gate passes. A freshly built debug local-core health probe returns one
successful response with `core_service_status=missing`, `guard_status=off`, null
status errors, `ipc=stdio`, and `network_exposed=false` on this no-service host.
This supersedes checkpoint 1639/1647 command-output status
evidence for Local Core and Guard only; updater, driver tooling, and driver-health
probes keep their separately bounded command paths. No service was installed,
started, stopped, or reconfigured, and installed service recovery plus
authenticated privilege-boundary IPC remain partial or blocked.

## Checkpoint 2160 Core Service Lifecycle Failure Visibility

The Windows Core Service now reports `StartPending` before native-engine warmup
and reports `Running` only after warmup succeeds. Warmup, running-status, or
shutdown-channel failure is mapped to service-specific exit code `1` instead of
a clean stop or an unreported early return. Controls are accepted only while
running, and a secondary failure to report `Stopped` cannot hide the primary
runtime diagnostic.

Three focused lifecycle/warmup tests pass, the complete local-core suite passes
(`485` in `101.50s`), source contracts pass (`593`), rustfmt passes, and the no-
malware-binaries gate passes. This is Windows runtime fixture evidence only: no
service was registered, installed, started, stopped, or recovered through SCM.
Installed Core Service recovery policy, service ACLs, authenticated privileged
IPC, and elevated-host E2E remain partial or blocked.

## Checkpoint 2161 Authenticated Read-Only Core Service IPC

Core Service now creates `\\.\pipe\AvoraxCoreService.v1` before reporting
`Running`. The pipe uses a protected explicit ACL, rejects remote clients, and
requires exclusive first-instance ownership. Each connection is restricted to
one 16 KiB protocol-v1 message; Windows client PID and token impersonation are
verified, and a failed `RevertToSelf` is fatal rather than recoverable. The only
allowed command is read-only `health`; scan, quarantine, restore, delete, update,
unknown, malformed, wrong-version, unknown-field, and oversized requests fail
closed. The service health payload excludes filesystem paths and explicitly
reports `healthOnly`, local named-pipe transport, no network exposure, and the
remaining user-mode limitations.

Six focused protocol/Windows transport tests pass, including a real local pipe,
exclusive-name collision, client PID authentication, mutation denial, malformed
input, 16 KiB rejection, post-rejection recovery, and clean stop. The complete
local-core suite passes (`492`). Rustfmt and `git diff --check` pass. Strict
Clippy remains non-green on pre-existing native-engine/local-core lint debt; the
new IPC module's one reported null-comparison lint was corrected before final
verification. No service was installed, started, stopped, or reconfigured.
Flutter still uses per-process stdio, no mutating command crosses this service
boundary, installed service/pipe ACL and recovery E2E remain partial, and no
kernel or pre-execution blocking is claimed.

## Checkpoint 2162 Mutually Authenticated Core Service Health Probe

Local Core now exposes the narrow `--service-ipc-health` client mode. Before it
trusts the named pipe, the client queries the fixed `avorax_core_service` name
through Service Control Manager with read-only status access, obtains the
running service PID, connects locally, and requires
`GetNamedPipeServerProcessId` to return that exact PID. It repeats the SCM query
after the response and rejects a service restart or PID change. Pipe I/O uses
overlapped operations with bounded waits and cancellation; response JSON is
limited to 16 KiB and strictly validates protocol version, request ID, client
PID, health-only scope, local transport, no network exposure, bounded counts,
and explicit limitations. Unknown CLI modes fail instead of silently entering
the broad stdio handler.

Twelve focused protocol/transport tests pass, including a real local probe,
wrong server PID, service restart during response, stalled-response cancellation,
degraded-engine failure honesty, strict unknown-field/schema checks, mutation denial, oversized input, recovery,
and clean stop. The complete serialized Local Core suite passes (`498`), Python
source contracts pass (`594`), all workspace test binaries compile, and the
no-malware-binaries gate passes. The first default-parallel Local Core run had
one existing PE-carrier fixture assertion fail after `496` passes; that exact
test passed immediately alone and inside the complete serialized run. Strict
Clippy remains non-green on `16` pre-existing lints outside this change and
reports none in the new IPC/client code. A real no-service host invocation exits `1` with a visible
`avorax_core_service ... Missing` diagnostic; an unknown mode also exits `1`.
No service was installed, started, stopped, or reconfigured. At checkpoint 2162,
Flutter consumption was still partial; checkpoint 2163 below adds it. Installed
service ACL/recovery and elevated-host E2E remain partial, all mutations remain
disabled at the service boundary, and no persistent monitoring, driver
enforcement, or pre-execution blocking is claimed.

## Checkpoint 2163 Flutter Core Service Health Consumption

- Flutter now consumes the native read-only `--service-ipc-health` probe with a
  strict 16 KiB response limit, ten-second timeout, process termination/reaping,
  exact schema checks, PID equality, local/no-network transport, health-only
  scope, authentication flags, bounded counts, and bounded limitations.
- Protection and Settings distinguish service-boundary ready, degraded,
  unavailable, not-checked, and unsupported states. Windows cannot enter the
  full `Protected` state unless this boundary is authenticated and engine-ready
  in addition to the existing native-engine and driver requirements.
- Parser, real benign subprocess, oversized-output, timeout cleanup, widget,
  and Windows controller tests pass. No live malware or external sample
  repository was downloaded, unpacked, retained, or executed.
- Installed-service/UI E2E remains partial. The unsigned beta helper executable,
  installation ACL, trusted-publisher proof, service/pipe ACL, recovery policy,
  and real installed service lifecycle are not independently verified by Dart.
  Service mutations remain disabled; kernel/pre-execution blocking remains
  technically blocked without the reviewed signed-driver path.

## Checkpoint 2164 Signed Hash-Intelligence Update

- **Resolved locally:** Reviewed hash-only imports now pass a strict non-empty `known-bad-sha256` profile before atomic activation. Empty, duplicate, uppercase, partial, lower-confidence, test/unknown-category, contextual, masked, or non-quarantine entries fail visibly and cannot replace the previous output pack.
- **Resolved locally:** A definitions-only wrapper now stages exactly one reviewed signature pack and builds it through the existing Ed25519-signed `.aup` path. A release-binary smoke generated only a benign text hash and temporary test key, required the exact three-entry archive shape, and passed Update Service `--verify` without apply/install.
- **Still blocked:** `cryptwareapps/Malware-Database`, `Cryakl/Ultimate-RAT-Collection`, `Pyran1/MalwareCollection`, and `Pyran1/MalwareDatabaseUnsorted` do not provide a reviewed canonical file SHA-256 feed through the configured metadata-only path. Git blob SHA/path/name/size evidence cannot be promoted to blocking. Their source entries remain disabled and `zentor_github_known_bad.zsig` remains empty.
- **Still partial:** Automatic public definitions delivery requires a maintainer-reviewed SHA-256 feed, protected production Ed25519 key custody, authenticated release publication, feed/version ownership, rollback retention, and installed-host apply/rollback evidence. The local wrapper intentionally performs no network acquisition and no sample download.

## Checkpoint 2165 Reviewed Feed Provenance Validation

- **Resolved locally:** Hash-feed source metadata now uses exact direct/template schemas, HTTPS-only credential-free provenance URLs, an active-row bound, duplicate rejection, and atomic output. Malformed or ambiguous metadata fails before pack compilation.
- **Still blocked:** These structural checks cannot establish that a third party owns a source, classified a file correctly, or will operate a false-positive response process. Production activation still requires maintainer review and signed release ownership; the requested GitHub repository entries remain disabled metadata-only inputs.

## Checkpoint 2166 Definition Revocation and Isolated Rollback

- **Resolved locally:** Engine subcomponent activation no longer merges signed definitions into an existing directory. Each declared signatures/rules/ML/trust component is staged and atomically replaces its predecessor, so removed definitions are actually revoked. Rename failure restores the checked sibling backup.
- **Verified in isolation:** A release-binary smoke builds and verifies a signed signature-only `.aup`, applies it under temporary install/data roots with fake service control, proves the old pack is absent and snapshotted, then rolls back to the exact old pack while removing the new one.
- **Still partial:** No machine-installed service, production ACL, production key, or real service stop/start lifecycle was exercised. Installed update/rollback E2E still requires explicit approval and a disposable test host.

## Checkpoint 2167 Strict Update-Service Lint Gate

- **Resolved locally:** Rust 1.96 strict Clippy now passes for every update-service target with warnings denied. The eleven prior findings were corrected through behavior-neutral conversions, borrows, sorting, CLI iteration, test allocations, and a structured pre-activation failure context. Two intentional source-contract test-module layouts have narrow local layout annotations instead of a crate-wide suppression.
- **Regression-gated:** Windows CI installs the pinned Clippy component and runs `cargo clippy --all-targets -- -D warnings`; a Python source contract requires both the component and exact command.
- **Unchanged limits:** This maintenance checkpoint changes no privilege, service, update-signing, network, installed-host, or malware-handling boundary. Installed service/update E2E and production signer custody remain partial or blocked as documented above.

## Checkpoint 2168 Strict Guard-Service Lint Gate

- **Resolved locally:** Every Guard Service target passes Rust 1.96 strict Clippy with warnings denied and no lint allowances. The fifteen prior Guard findings were corrected with a typed driver-health signal record, standard-library equivalents, explicit default construction, copy semantics, and immutable DPAPI input descriptors. The complete Guard suite passes (`214`), Python source contracts pass (`608`), rustfmt/diff checks pass, and the no-malware-binaries gate passes.
- **Regression-gated:** Windows CI runs `cargo clippy --all-targets --no-deps -- -D warnings` after the complete Guard test suite. A Python source contract requires the pinned Clippy component, Guard working directory, and exact command.
- **Still partial:** `--no-deps` intentionally excludes the native-engine dependency, whose thirteen pre-existing lints remain tracked debt. This maintenance checkpoint does not install/start the Guard Service or driver and does not prove kernel or pre-execution blocking.

## Checkpoint 2169 Strict Native-Engine Lint Gate

- **Resolved locally:** Every native-engine target passes Rust 1.96 strict Clippy with warnings denied and no lint allowances. The thirteen production and six test findings were corrected with typed ZIP-entry views, standard-library equivalents, path-oriented borrowing, explicit test construction, private module naming, and a behavior-equivalent verdict condition. A dedicated threshold regression test preserves both probable-malware branches and the conservative one-signal review result.
- **Regression-gated:** Windows CI runs `cargo clippy --all-targets --no-deps -- -D warnings` in `core/zentor_native_engine`; a Python source contract requires the pinned Clippy component, working directory, and exact command. The complete native suite passes (`433` library plus `6` compiler CLI), the dependent Guard suite passes (`214`), source contracts pass (`609`), and the no-malware-binaries gate passes.
- **Unchanged limits:** This is maintainability and regression evidence, not detection-accuracy, installed-service, signed-driver, or pre-execution proof. No service/driver was changed and no live malware or external sample repository was handled.

## Checkpoint 2170 Strict Local-Core Lint Gate

- **Resolved locally:** Every Local Core binary/test target passes Rust 1.96 strict Clippy with warnings denied and dependencies excluded. The thirteen production and three test findings were corrected without adding lint suppression. The previous ransomware argument-count suppression was removed by replacing positional activity evidence with a named typed record. Quarantine staging keeps exclusive temp ownership and fail-visible cleanup while using direct error propagation.
- **Regression-gated:** Windows CI runs `cargo clippy --all-targets --no-deps -- -D warnings` in `core/zentor_local_core` after the serialized Local Core tests. A Python source contract requires the pinned Clippy component, working directory, and exact command. The complete Local Core suite passes (`498`) and source contracts pass (`610`).
- **Still partial:** The installed Core Service boundary remains authenticated read-only health; mutating scan/quarantine commands remain per-process stdio. File watching and ransomware evaluation remain best-effort, post-activity user-mode controls. This checkpoint does not prove installed-service mutation, persistent monitoring, signed-driver, or pre-execution enforcement.

## Checkpoint 2171 Fail-Visible Watch Timestamps

- **Resolved locally:** Finite watch-poll candidates no longer convert modification-time query or pre-Unix-epoch failures to zero. Timestamp evidence is optional, failures are included in the existing bounded scan diagnostics, and only candidates with valid timestamps may enter the baseline or unchanged-file caches.
- **Conservative fallback:** A candidate without trustworthy timestamp evidence waits for the existing debounce/stability observations and is then rescanned instead of being treated as unchanged. Rechecks remain bounded by the existing 10-second session, 512-file pass, depth-eight, and 32-event limits.
- **Verified:** Timestamp/cache regressions pass, the complete serialized Local Core suite passes (`500` in `153.58s`), strict Clippy and rustfmt pass, source contracts pass (`611`), and the no-malware-binaries gate passes. A fresh release build plus harmless exact-hash watch-poll smoke observed, scanned, detected, and quarantined one temporary fixture.
- **Still partial:** A real filesystem timestamp-query failure was not induced on this host; the conversion and non-cache fallback are runtime-tested through deterministic unit inputs and source-accounted at candidate collection. Monitoring remains app-lifetime finite post-write polling, not a persistent service, OS notification subscription, signed-driver path, or pre-execution enforcement.

## Checkpoint 2172 Bounded Process Command Evidence

- **Resolved locally:** Windows process snapshot collection no longer keeps only the first 2048 command-line UTF-16 code units. Flutter retains a bounded head and tail sample on Unicode scalar boundaries, marks omitted middle content explicitly, and serializes that evidence to Local Core. Local Core independently applies a 4096-scalar head/tail bound for direct callers.
- **Conservative fallback:** Truncated command lines from script hosts and network-capable Windows utilities reach the default review threshold even when no retained suspicious flag is visible. This is an explainable `suspiciousProcess` review result, not a confirmed-malware label or automatic process action.
- **Verified:** Process-monitor tests pass (`10`), process-snapshot IPC tests pass (`5`), the complete Local Core suite passes (`506`), the complete Flutter suite passes (`824`), Flutter analyze, strict Clippy, rustfmt, source contracts (`611`), and the no-malware gate pass. The release-binary smoke verifies long-tail, source-reported truncation, inconsistent evidence rejection, and bounds with `266` synthetic observations and `4` expected findings.
- **Still partial:** Process observation remains an app-lifetime user-mode snapshot. No persistent process service, termination/quarantine action, installed UI/service E2E, representative production false-positive study, signed driver, or pre-execution enforcement is proved.

## Checkpoint 2173 Fail-Closed Process Snapshot Responses

- **Resolved locally:** The Flutter controller no longer treats a Local Core process snapshot response with `ok=false` as a clean evaluation. It also refuses to mark a response successful when parser diagnostics show malformed or dropped evidence.
- **Failure visibility:** Rejected and incomplete responses set the active process loop to `limited`, clear routine-event dedupe state, and write a bounded warning event. Neither path emits `process_snapshot_evaluated` or `process_snapshot_loop_evaluated`.
- **Verified:** Two controller regressions pass, the complete Flutter suite passes (`826`), Flutter analyze is clean, source contracts pass (`612`), and the no-malware-binaries gate passes.
- **Still partial:** This proves app-lifetime controller response handling with benign fakes only. It does not prove an installed persistent process service, real-host process response policy, termination/quarantine, signed-driver enforcement, or pre-execution blocking.

## Checkpoint 2174 Consistent Watch-Poll Response Evidence

- **Resolved locally:** A nominal `ok=true` watch-poll response can no longer become active/clean when watcher and poll activity disagree, the active watcher has no watched paths, or active/inactive mode labels contradict the state.
- **Defense in depth:** The Flutter IPC parser rejects contradictory evidence, and the controller independently repeats the consistency gate before updating status or writing success events. Failure evidence includes bounded watcher and poll state.
- **Verified:** Contradictory activity and invalid active-mode IPC regressions pass, the controller fail-closed regression passes, the complete Flutter suite passes (`828`), Flutter analyze is clean, source contracts pass (`613`), and the no-malware-binaries gate passes.
- **Still partial:** This validates benign subprocess/fake-controller evidence only. Finite watch-poll remains app-lifetime, bounded, post-write user-mode detection without persistent service, OS notification, signed-driver, or pre-execution proof.

## Checkpoint 2175 Fail-Closed Mutation Success Evidence

- **Resolved locally:** Flutter no longer accepts a bare `ok=true` Local Core response as proof that quarantine, restore, delete, allowlist add/remove, detection labeling, guard-mode configuration, or ransomware-guard configuration succeeded. Each operation requires its native response shape and rejects a simultaneous error field.
- **Evidence binding:** Quarantine records must pass the existing strict record parser and carry the expected status; restore/delete and allowlist removal also require the requested identifier. Allowlist entries must pass strict parsing and carry the requested active state. Label/configuration operations require a bounded absolute local result path.
- **Verified:** Missing path, contradictory quarantine status, contradictory allowlist state, and mismatched restore identifier regressions pass. A correctly evidenced manual quarantine remains green. The complete Flutter suite passes (`832`), Flutter analyze is clean, source contracts pass (`614`), and the no-malware-binaries gate passes.
- **Still partial:** Evidence proves the per-process Local Core response is internally complete; it does not independently re-open every written file or prove durability after power loss. Installed authenticated mutation IPC remains disabled, and installed-host ACL/service, signed-driver, and pre-execution behavior remain partial or blocked.

## Checkpoint 2176 Fail-Closed Protection Self-Test Evidence

- **Resolved locally:** Flutter no longer interprets arbitrary Guard stdout or selected words as self-test success. Process exit, stderr, one-line JSON framing, the exact Guard envelope, exact nested report schemas, bounded text, UTC timestamps, unique bounded steps, and all success flags must validate and agree.
- **Failure visibility:** The client returns a typed `passed/details` result. The controller, event severity, stored state, and result-panel color use `passed`; malformed text without the word `FAIL` still renders and logs as an issue.
- **Verified:** Benign subprocess fixtures cover exact success, malformed steps, nonzero exit, stderr output, incomplete envelopes, nested extra fields, invalid/non-UTC timestamps, contradictory flags, and timeout cleanup. Controller typed-failure regression passes. Flutter passes `838`, analyzer is clean, source contracts pass `615`, and the no-malware-binaries gate passes.
- **Still partial:** This proves validation of a freshly launched per-process Guard response, not an installed service identity, trusted publisher, service ACL, signed minifilter, or pre-execution blocking. Those installed-host and production-signing requirements remain pending or technically blocked.

## Checkpoint 2177 Verified Beta.3 Packages And MSI Extraction

- **Resolved:** The current `v0.1.15-beta.3` release is public and points exactly
  to merged commit `c3fc4f1d18bbd0a7c8f38aae1d1d051b8308515a`. All native jobs,
  checksum consolidation, and prerelease publication pass in Desktop Packages
  run `29761712577`.
- **Verified:** Eight public assets are present. All seven package/evidence rows
  in `SHA256SUMS.txt` match GitHub's asset digests, and the checksum file matches
  its own GitHub digest. The Windows workflow performs a bounded real
  administrative MSI extraction and harmless extracted-core lifecycle smoke.
- **Path constraint explained:** An earlier extraction below the long checkout
  failed with Windows Installer `1603`/`1304` at a 273-character output path.
  The same MSI passed below a short opaque temporary root; the verifier now
  enforces that bound and fails visibly when it cannot.
- **Still blocked:** Windows packages are unsigned, macOS packages are ad-hoc
  signed and not notarized, and no machine-wide package was installed during
  this verification. Normal installed UI/service/ACL/update E2E, protected
  signing credentials, signed-driver IPC, and pre-execution enforcement remain
  partial or blocked. Microsoft Defender must remain enabled.

## Checkpoint 2178 Explicit Driver Activation Boundary

- **Resolved locally:** Candidate driver files can no longer trigger an elevated
  deferred custom action during ordinary MSI/EXE installation. Driver activation
  requires a separate invocation with `-ConfirmDriverInstall`.
- **Trust-store safety:** The helper no longer imports a bundled certificate into
  `Root` or `TrustedPublisher`, and it still refuses to enable TESTSIGNING.
- **Verified locally:** `616` source contracts, `22` packaging tests with `3`
  expected Windows symlink skips, PowerShell parser checks, generated-helper
  no-confirm fail-closed runtime, product/no-malware safety gates, an actual
  Avorax MSI database/extraction/lifecycle pass, and rejection of a real cached
  MSI containing a `CustomAction` table before extraction all pass.
- **Verified in CI:** Avorax CI run `29765160511` and Desktop Packages push/PR
  runs `29765128390` and `29765160524` passed. Both fresh Windows MSI/EXE jobs,
  package contracts, Linux x64, macOS arm64/x64, consolidated checksums, Rust,
  Flutter, branding, and security jobs are green.
- **Still blocked:** Production Microsoft driver signing, disposable elevated-host
  install/load/unload/rollback evidence, authenticated driver IPC, and genuine
  pre-execution blocking remain unavailable and must not be claimed.

## Checkpoint 2179 Diagnostic Category Isolation

- **Resolved locally:** Zero-weight diagnostic evidence remains visible in the
  verdict explanation but cannot determine or override a threat category.
- **Verified locally:** The `.tmpupTeBo`/`pup` regression and formerly failing
  legacy Office macro test pass. Native Engine passes `434 + 6`, Local Core
  passes `506`, and rustfmt/clippy pass for both affected crates.
- **Verified in CI:** Avorax CI run `29767214563` and Desktop Packages push/PR
  runs `29767211055` and `29767214589` pass on the final head. PR `#30` merged
  as `f28cad2`. Failed run `29766224417` remains documented, not fake success.
- **Technically limited:** No production false-positive/false-negative rate or
  live-malware claim follows from benign fixtures and deterministic unit tests.

## Checkpoint 2180 Project Readiness And Dependency Evidence

- **Resolved locally:** Dependency package/integrity counts are stable across LF
  and CRLF input, use a finite regex timeout, and fail closed on missing or zero
  summaries. The prior Python lockfile `0/0` false evidence state is rejected.
- **Verified locally:** PowerShell parsing, direct LF/CRLF runtime checks,
  dependency evidence, `617` source contracts, and the full small-threat suite
  (`217/217` in `961.5s`) pass, including the final report validator. The full
  Rust workspace passes `1,408` tests and the full Flutter suite passes `838`.
- **Resolved locally:** Native Authenticode evidence no longer inherits ambient
  PowerShell module discovery. The checked WindowsPowerShell child imports the
  checked built-in Security manifest through a child-only module root and
  module-qualified cmdlets. Four focused probes pass normally and with an
  intentionally invalid parent `PSModulePath`.
- **Partial:** Packaged desktop click-through, installed Core/Guard service and
  authenticated mutation IPC, installed quarantine ACL/DPAPI behavior, installed
  update/rollback, OS picker/export dialogs, and persistent monitoring E2E still
  require a disposable elevated release-style Windows host.
- **Blocked:** Production Windows code/driver signing, signed driver lifecycle
  and pre-execution proof, production update-key custody, and final-artifact
  release signing cannot be completed safely in this unprivileged checkout.
- **Technically limited:** No live-malware corpus, production detection-rate,
  kernel realtime, secure-erase, background scheduler, or Defender-replacement
  claim is made. Development ML and cloud reputation are not production engines.
- **Release prerequisite:** A full SBOM from exact final artifacts plus complete
  license/copyright review remains required; source-level CycloneDX inventory is
  intentionally incomplete.

## Checkpoint 2181 Linux Package Prerequisite Bounds

- **Resolved locally:** The Linux package workflow no longer waits on unbounded
  inline `apt-get` commands. Process, acquisition, and lock waits are bounded;
  retries are finite; timeout exit 124 is visible; and the final failure status
  is returned.
- **Verified locally:** `23` packaging tests pass with `3` expected Windows
  symlink skips, `617` source contracts pass, Bash syntax passes, and harmless
  command doubles prove retry, invalid-config, and cumulative-budget behavior.
- **Operational limit:** External GitHub runner or package-mirror availability
  can still fail the job. The failure is bounded and visible, not converted into
  success.
- **Unchanged product blockers:** Installed package/service/ACL/DPAPI E2E,
  production signing, signed-driver/pre-execution proof, production accuracy,
  update-key custody, and final-artifact SBOM/license review remain open.

## Checkpoint 2182 Quarantine Authentication And Interoperability

- **Resolved locally:** New Local Core and Guard quarantine metadata uses one
  HMAC-SHA-256 contract instead of separate custom keyed-digest domains.
- **Resolved locally:** Local Core accepts the bounded Guard source/actions the
  current Guard really writes, so a Guard record can be listed and restored.
- **Resolved locally:** Missing sidecars and plaintext Windows keys fail closed;
  strict unknown-field and filename/ID checks prevent ambiguous records.
- **Migration boundary:** Only an exact authenticated v1 Local Core or Guard tag
  can migrate, and only after the complete record validates. Unsigned or invalid
  metadata is not migrated.
- **Partial:** Installed LocalSystem key ownership, ACL/DPAPI upgrade and repair,
  unprivileged UI mediation, authenticated service mutations, and package
  install/uninstall lifecycle remain unverified on a disposable elevated host.
- **Technically limited:** Metadata HMAC is not payload encryption, quarantine
  delete is not secure erase, and no driver or pre-execution claim follows.

## Checkpoint 2183 Native Engine Mutation Boundary

- **Resolved locally:** The Native Engine is detection/verdict only in
  production. Auto-quarantine compatibility modes and the direct quarantine
  entry point fail visibly before file or root I/O.
- **Verified locally and on GitHub:** Three focused boundary regressions, all `435 + 6`
  Native Engine tests, all `515` Local Core tests, the `1,423`-test Rust
  workspace, `838` Flutter tests, `619` source contracts, rustfmt, PowerShell
  parsing, strict native Clippy, and the central verifier/report validator
  (`218/218` in `836.4s`) pass. Exact head
  `a7e8ca33d02a2513e6a8b8949ef3120cddc1d58a` passes Avorax CI
  `32291858708` and Desktop Packages runs `32291729128` and `32291858742`.
- **Supported mutation owner:** Local Core remains responsible for authenticated
  quarantine, list, rescan, restore, and delete. Its quick, full, custom,
  watcher, and manual flows still consume Native Engine verdicts in detect-only
  mode.
- **Disabled with blocker:** Native direct/automatic quarantine remains disabled
  because its duplicate unauthenticated record schema, process-bound DPAPI
  context, and missing restore contract cannot safely share the Local Core vault.
- **Partial:** Installed service identity, authenticated mutation IPC, LocalSystem
  DPAPI/ACL behavior, repair/upgrade, and packaged UI click-through still need a
  disposable elevated Windows host.
- **Technically limited:** No kernel interception, pre-execution protection,
  production signing, secure erase, or production detection-rate evidence is
  added by this checkpoint.

## Checkpoint 2184 Quarantine Permission Boundary

- **Resolved locally:** Local Core and Guard no longer resolve `icacls.exe` or
  trust `USERNAME`/`USERDOMAIN` for production quarantine ACLs. Both use the
  actual Windows process-token SID and one shared handle-based DACL helper.
- **Resolved locally:** Windows quarantine directories receive a protected exact
  DACL and process-token SID ownership; payload files additionally deny the
  exact `FILE_EXECUTE` right. Owner and DACL are read back and compared, and
  reparse/wrong-kind objects fail closed. File volume serial/file IDs must also
  match across the data and ACL handles, so path replacement fails visibly.
- **Resolved locally:** Unix opened handles are transferred to the effective
  process UID/GID and quarantine directories are verified at exact mode `0700`;
  payload, metadata, sidecar, and key files are verified at `0600`, with
  device/inode, owner, kind, and mode checks. Forbidden ownership transfer fails
  closed.
- **Resolved locally:** Local Core and Guard reject existing symbolic-link or
  Windows reparse-point ancestors before and after quarantine directory
  creation; redirected vault roots are not accepted.
- **Resolved locally:** Explicit quarantine overrides must end in a dedicated
  `Quarantine` leaf. Existing roots are bounded to `65,536` entries and must
  contain only recognized non-link vault artifact names before any ACL or mode
  is changed. Windows Guard rejects UNC/network overrides, and Local Core's
  arbitrary-base constructor is test-only. Unknown content and wrong object
  kinds fail visibly.
- **Resolved locally:** Local Core's default test quarantine is thread-local and
  temporary. Focused and complete scan suites leave the real ProgramData vault
  unchanged; explicit failure fixtures use a scoped test-only override.
- **Preserved pending operator review:** The existing ProgramData vault contains
  `5,357` record-shaped payload/metadata/auth sets plus one key file (`16,072`
  files, `4,522,733` bytes). Their individual provenance was not audited. No
  file was deleted; count and total bytes stayed unchanged after test isolation.
  Any cleanup requires an explicit authenticated operator action.
- **Resolved locally:** A Linux all-target Guard check exposed and repaired
  process-command imports that were incorrectly Windows-gated plus a Unix-only
  metadata-key test that treated `Option<String>` as `String`. Guard now
  compiles all targets for `x86_64-unknown-linux-gnu`; existing non-fatal
  platform-specific warning debt remains visible.
- **Resolved locally:** Existing bounded metadata, auth-sidecar, and key reads
  repair permissions before content is consumed. Local Core repairs a present
  legacy payload only after record authentication, schema checks, and vault-path
  validation; unsigned and untracked content is not migrated.
- **Resolved locally:** A permission or authenticated-metadata finalization
  failure after payload movement removes only incomplete metadata/auth files.
  The sole payload is retained, its opaque path is reported in the visible
  error, and runtime regressions prevent cleanup from deleting it.
- **Verified locally:** Platform tests pass `6/6` on Windows, Local Core
  quarantine tests pass `112/112`, complete Local Core passes `517/517`, Guard
  quarantine passes `47/47`, complete Guard passes `223/223`, and source
  contracts pass `620/620`. Strict Clippy passes for all affected Windows
  targets and the shared Linux target; Guard's Linux all-target check passes
  with only the documented platform-specific dead-code warnings. The complete
  Rust workspace passes `1,435/1,435`; the central verifier passes `219/219`
  with no failed or skipped steps in `618.0s`, and the independent full-suite
  report validator passes.
- **Verified hosted baseline:** Replacement head
  `7156936ba714b66b6ca88140d48d81697ecf49e4` passed Avorax CI
  `32317397484` and Desktop Packages push/PR runs `32317394123` and
  `32317397452`; merge `a254689666f01159d8d0a67001c1774fcc38628f`
  passed main CI `32318477688` and Desktop Packages `32318477650`.
- **Pending independent Unix runtime evidence:** Checkpoint 2185 adds a bounded
  Ubuntu 24.04 job for the five shared, two Local Core, and two Guard permission
  tests. Until that job runs successfully, Unix mode/ownership behavior remains
  partial rather than inferred from compilation or package success.
- **Local cross-toolchain blocker:** The shared platform crate and Guard compile
  for the installed Linux Rust target. A full Local Core cross-check reaches the
  existing `tract-linalg` C build and stops because this Windows host has no
  `x86_64-linux-gnu-gcc`. No machine-wide compiler was installed; native Ubuntu
  CI is the required runtime/build evidence.
- **Partial:** Installed LocalSystem ACL/DPAPI behavior, unprivileged UI/service
  mediation, repair/upgrade, and package install/uninstall remain unverified on
  a disposable elevated Windows host. Portable user-mode operation cannot
  isolate the vault from another process running as the same SID/UID.
- **Technically limited:** Administrators and LocalSystem remain trusted. DACLs
  and modes do not encrypt payloads, provide secure erase, or establish kernel
  pre-execution enforcement.
- **Technically limited:** Vault-ancestor checks run before and after creation
  but are path-based, not a fully handle-relative NT/`openat2` object-tree
  transaction. Concurrent mutation by an administrator/root-capable principal
  remains inside the trusted computing base. The retained authenticated-payload
  recovery gap documented here is superseded by checkpoint 2187; historical
  unsigned/untracked payload salvage remains an explicit operator task.
- **Technically limited hard-link boundary:** Checkpoint 2186 implements
  handle-based single-link preflight in Local Core and Guard, copy-source
  revalidation before removal, payload/vault-entry postflight before permission
  mutation or record finalization, and visible rejection that preserves an
  already multi-linked source. Windows runtime regressions pass locally; native
  Unix runtime passes hosted on implementation head
  `2613b4131cb31c37e413d7610403fb2d665582e9` in run `32324715015`, job
  `96293537585`, with `16/16` selected tests. The control does not enumerate a
  volume or make link creation and rename/removal atomic. Same-SID/UID and
  administrator/root races remain in the
  trusted computing boundary, alternate paths remain separate scan targets, and
  volume-wide neutralization is not claimed.

## Checkpoint 2185 Native Unix Quarantine Runtime CI

- **Implemented locally:** Avorax CI now has a dedicated `ubuntu-24.04` job with
  pinned Rust `1.96.1`, locked dependencies, fail-fast shell mode, and a
  30-minute job timeout.
- **Expected native evidence:** The job runs five shared platform tests, two
  Local Core Unix permission-routing tests, and two Guard Unix
  permission-routing tests. It installs no packages or machine-wide components.
- **Failed attempt retained:** Run `32319783686`, job `96279486707`, passed the
  five shared tests and then exposed a Unix-only Local Core test compile error:
  `.trim()` was called on `Option<String>`. Guard did not run. This is not
  counted as Unix integration success.
- **Repair verified locally:** The test now explicitly requires `Some(key)`,
  Windows-only imports are gated, and Unix-only warning debt in the permission
  helper is removed. Windows platform tests pass `6/6`, focused Local Core
  quarantine passes `112/112`, source contracts pass `621/621`, and rustfmt,
  diff, branding, product-copy, and no-malware gates pass.
- **Verified hosted:** Replacement run `32320253194`, job `96280869830`, passed
  shared platform `5/5`, Local Core `1+1`, and Guard `1+1`. All Unix job steps
  succeeded on repair commit `029a381af8fb86d1261a72845b61675a194e8447`.
  The earlier failure remains recorded and is not counted as success.
- **Unchanged blockers:** Installed LocalSystem/DPAPI/ACL/service/UI E2E,
  production signing, driver/pre-execution proof, production detection rates,
  and the remaining hard-link race/ancestor-race boundaries remain technically
  limited.

## Checkpoint 2186 Quarantine Hard-Link Policy

- **Verified locally on Windows:** The shared inspector, vault preflight, and
  permission-hardening postflight pass `9/9`. Local Core direct and copy
  hardlink fixtures pass and its complete suite is `519/519`; Guard equivalents
  pass and its complete suite is `225/225`. The Rust workspace passes
  `1,442/1,442`, source contracts pass `622/622`, and the central verifier/report
  validator passes `219/219` with no failures or skips in `605.1s`.
- **Verified hosted Unix evidence:** Avorax CI `32324715015`, job
  `96293537585`, passed shared platform `8/8`, Local Core `1+1+2`, and Guard
  `1+1+2`, for `16/16` selected native tests across seven locked Cargo
  invocations on exact implementation head
  `2613b4131cb31c37e413d7610403fb2d665582e9`.
- **Verified hosted package regression:** Desktop Packages push run
  `32324694830` and PR run `32324715004` both passed package contracts,
  Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMGs, and consolidated
  checksums. No package was installed and branch prerelease publication was
  intentionally skipped.
- **Existing local cross-target lint debt:** Strict Linux Clippy for the changed
  shared platform crate passes. Guard Linux all-target compilation passes, but
  combined strict Guard Clippy fails on 24 existing Windows-only dead-code and
  manual-`ok` diagnostics. This failed command is retained and is not counted as
  success; resolving unrelated platform-gating debt is outside this checkpoint.
- **Technically limited:** The implemented policy rejects a known non-single
  link count and postflights before record finalization. It does not enumerate a
  volume or atomically exclude same-principal/administrator link creation
  between the final check and rename/removal. Alternate names remain separate
  scan targets, and Avorax does not claim volume-wide neutralization.

## Checkpoint 2187 Quarantine Finalization Recovery

- **Resolved locally:** Local Core and Guard write the same strict pre-move
  `avorax-quarantine-finalization-journal-v1` record and domain-separated HMAC.
  Both read back the exact committed bytes, verify authentication, and hold an
  exclusive journal lock through finalization. Guard retains the journal for
  Local Core when post-move finalization fails.
- **Resolved locally:** Local Core runs bounded recovery before list. It can
  finalize an intact isolated payload, discard an abandoned pre-move journal
  only after acquiring the recovery lock and proving the original source intact,
  clean a verified stale journal or orphan sidecar, and replace partial final
  metadata only from authenticated journal evidence. An active writer fails
  visibly and its evidence remains untouched.
- **Fail-closed states:** Missing/tampered auth, unknown JSON fields,
  filename/ID mismatch, changed payload, conflicting final metadata, partial
  related state, and simultaneous source plus payload all fail visibly and
  preserve the payload/journal/final evidence that exists.
- **Verified locally:** Platform passes `9/9`, Local Core passes `534/534`, Guard
  passes `226/226`, the locked Rust workspace passes `1,458/1,458`, source
  contracts pass `623/623`, and strict affected-crate Clippy, rustfmt,
  dependency resolution, and the central verifier/report validator (`219/219`,
  no failures or skips, `533.3s`) pass. Only benign temporary fixtures are used.
- **Verified hosted:** Exact implementation head
  `3e361a4d0b1829017603d3644c4866ccb5d3ad6c` passes Avorax CI run
  `32331431435`. Native Ubuntu job `96312704078` passes shared `8/8`, Local Core
  `1+1+2+1+1`, and Guard `1+1+2+1+1`, totaling `20/20` permission, hard-link,
  journal-lock, and normal-writer tests across 11 locked Cargo invocations.
  Desktop Packages push/PR runs `32331417805` and `32331431406` also pass all
  Windows, Linux, macOS, checksum, and lockfile-SBOM jobs without installation.
- **Partial:** Installed LocalSystem/DPAPI/ACL behavior, packaged UI list/action
  click-through, hostile/non-cooperating same-principal concurrency,
  repair/upgrade interruption, and crash-at-every-instruction E2E still require
  a disposable elevated host.
- **Technically limited:** Recovery is list-triggered Local Core user-mode work,
  not kernel interception. A state containing both source and isolated payload
  is deliberately not auto-resolved because deleting either copy would require
  an unsafe assumption. The lock coordinates cooperating Avorax writers and
  recovery only; same-principal processes that ignore it and administrator/root
  races remain in the trusted computing base. Historical unsigned payloads are
  not promoted.

## Checkpoint 2188 Installer-Owned Service Repair

- **Historical repair claims superseded:** Checkpoints 1936-1937 documented an
  in-app elevated service-registration path with development-checkout guards.
  That path is no longer active. Flutter contains no `New-Service`,
  `Set-Service`, repair executable resolver, or elevated repair launch.
- **Explicitly disabled and verified:** Scan shows `Repair unavailable`, a
  visible installer-required diagnostic, and a bounded tooltip. It provides no
  repair callback. Direct client calls return the installer-owned blocker, and
  controller evidence records `installation_repair_blocked` without a repair-
  requested success event.
- **Existing-service start remains partial:** The confirmed Start Core Service
  flow can only query/start the fixed `avorax_core_service` registration. It
  cannot install or reconfigure it, but its elevated installed-host behavior is
  not yet proven end to end.
- **Blocked prerequisite:** Real service repair/install validation requires a
  disposable elevated Windows host plus an official production-signed MSI/EXE.
  Evidence must cover package provenance, installed paths, service identity,
  ACLs, start/stop, repair, rollback, and uninstall without weakening Defender
  or Windows security.
- **No expanded claim:** This checkpoint changes a privilege boundary, not
  detection coverage. No service, driver, package, Defender exclusion, live
  malware, or pre-execution blocking was used.

## Checkpoint 2189 Process Enumeration Coverage

- **Resolved locally:** Guard process enumeration returns bounded process rows
  plus explicit coverage gaps. Finite watch completion cannot be `ok:true` when
  any collection gap occurred, and combined collection/inspection limitations
  remain distinct.
- **Resolved locally:** Windows counts non-kernel CIM rows without executable
  paths and accounts for malformed/unavailable paths. Linux counts procfs
  entry, link, and image-validation failures while treating non-PID entries and
  `NotFound` churn separately. Missing procfs and unsupported platforms fail
  visibly instead of returning an empty successful list.
- **Resolved locally:** Persistent warnings are structured and deduplicated;
  coverage details and process rows are bounded. The previous PID/path snapshot
  replaces the lifetime PID set, so stale PIDs do not grow memory indefinitely
  and changed-path PID reuse is inspected.
- **Resolved locally:** A zero-row collection with no collector-reported error
  records its own gap. Because Guard should observe at least its own executable,
  a syntactically valid empty Windows envelope or procfs snapshot cannot
  clean-pass.
- **Verified locally:** Guard passes `234/234`, checkpoint filter `8/8`, the
  locked Rust workspace `1,466/1,466`, source contracts `626/626`, strict Guard
  Clippy, rustfmt, PowerShell parsing, and a real Windows command invocation that
  returned `ok:false` with `watchCompletedWithCoverageGaps` and `307` gap
  occurrences over two snapshots. The earlier `220/220` full run is
  superseded by the subsequent empty-snapshot repair and is not counted as
  final. A later green run was also superseded when review found the truncation
  suffix outside the nominal 512-character detail cap; the corrected cap now
  includes that suffix. The definitive central verifier and independent
  validator pass `220/220`, with no failures or skips, in `516.5s`.
- **Verified hosted:** Exact implementation head
  `d8ff525c362003a5396258ad8ffaeb51741b9387` passes Avorax CI
  `32350190743`. Pinned Ubuntu job `96367469456` executes the exact locked
  `process_collection` filter and passes `8/8`, including the native procfs
  malformed-image, empty-root, and unavailable-root fixtures.
- **Verified hosted package regression:** Desktop Packages push run
  `32350121197` and PR run `32350190448` both pass package contracts, Windows
  x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMGs, and consolidated six-
  artifact checksum/lockfile-SBOM evidence. Prerelease publication was
  intentionally skipped; no package was installed or released.
- **Disabled:** Guard process enumeration on non-Windows/non-Linux platforms is
  explicitly disabled. macOS no longer reports absent `/proc` as empty success.
- **Blocked / technically limited:** Installed LocalSystem service-loop E2E
  needs a disposable elevated Windows host. Polling can miss a process that
  starts and exits between snapshots, including indistinguishable same-path PID
  reuse. This is post-launch user-mode observation, not kernel interception,
  pre-execution blocking, Defender replacement, or detection-rate evidence.

## Checkpoint 2190 Native Windows Process Enumeration

- **Resolved locally:** Guard no longer launches WindowsPowerShell/CIM for each
  Windows process snapshot. Toolhelp plus `QueryFullProcessImageNameW` now runs
  in one isolated Windows-only module with limited query access and RAII handle
  ownership. No helper process, encoded script, JSON helper envelope, ambient
  `PATH`, or network input remains in the Windows collector.
- **Resolved locally:** PID records, image memory, and between-call query work
  are bounded. Zero limits fail before Win32 use. Record exhaustion, budget
  exhaustion, early snapshot termination, access/query failures, and unsafe or
  unavailable returned paths remain visible coverage gaps. Exited-PID churn is
  separate and cannot inflate a clean-coverage claim.
- **Verified locally:** The exact native runtime observes the current test
  process. Deterministic fixtures cover access versus churn, zero limits,
  record/time bounds, bad paths, gap propagation, and empty snapshots. Focused
  collection passes `14/14`, Guard `239/239`, the locked workspace
  `1,471/1,471`, source contracts `626/626`, strict Guard Clippy, rustfmt,
  PowerShell parsing, and the release build.
- **Verified locally:** The definitive central verifier and report validator
  pass `220/220` with no failures in `687.6s`. Final release finite-watch samples
  are `185.9ms`, `72.2ms`, and `66.4ms`; the removed PowerShell/CIM path measured
  `1,150.3ms`, `812.0ms`, and `762.7ms` on the same host. These are diagnostic
  samples, not production latency or detection-rate evidence.
- **Verified hosted:** Implementation
  `a928aa0297cadeedd002a4e84cf937250de6bf3b` and evidence
  `9fec6ccbf36d0146e6ac66fe911e48b0449a98a8` are merged by PR `#42` as
  `f66ea472bff3d6f0b9ff4cb3b0cfcf2f25dee92a`. Evidence-head CI
  `32358381763`, package push `32358376699`, package PR `32358381728`,
  merged-main CI `32359532900`, and merged-main packages `32359532935` pass
  Windows, Linux, macOS arm64/x64, and consolidation. Publish is skipped.
- **Dependency boundary:** `windows-sys` stays at the existing locked version;
  only Toolhelp and Threading feature gates were enabled. `Cargo.lock` is
  unchanged and the dependency evidence gate passes.
- **Blocked / technically limited:** The final non-elevated live watch reports
  `ok:false` and 290 access/coverage-gap occurrences across two snapshots.
  Installed LocalSystem visibility, protected process access, event ACLs,
  service lifetime/shutdown, packaged UI mediation, and realistic sustained
  performance need a disposable elevated Windows host.
- **Disabled / technically limited:** Unsupported platforms, including macOS,
  still disable Guard process enumeration explicitly. Polling can miss
  between-snapshot processes and same-path PID reuse, and one native kernel call
  cannot be cancelled mid-call. No kernel, pre-execution, Defender-replacement,
  or complete process-coverage claim is made.

## Checkpoint 2191 Native System-Root Process Skip

- **Resolved locally:** Guard no longer derives `X:\Windows` from each observed
  process image. A lookalike on another drive can no longer select the root
  used to skip its own inspection. The watcher derives one policy from bounded
  `GetSystemWindowsDirectoryW` output instead.
- **Resolved locally:** Guard's `taskkill.exe` discovery no longer trusts
  `SystemRoot` or `WINDIR`. It uses the same native root and rejects a reparse
  target or any linked/reparse ancestor before the existing bounded runner is
  invoked.
- **Verified locally:** The native parser rejects invalid lengths, embedded
  NULs, and absent termination. Runtime tests accept the actual system root and
  reject an other-drive lookalike. Process skip and system-directory filters
  pass `3/3` each, process watch `1/1`, collection `14/14`, Guard `244/244`, the
  workspace `1,476/1,476`, source contracts `626/626`, strict Guard Clippy,
  rustfmt, script parsing, release build, and central verification `220/220` in
  `545.5s`.
- **Verified locally:** Release finite watches took `82.2ms`, `74.2ms` with a
  spoofed child-only Windows environment, and `73.6ms`. All exited zero, wrote
  no stderr, and returned `ok:false` with 280 visibility gaps rather than a fake
  clean result. The count is not threats.
- **Verified hosted:** Implementation
  `67e067d2d74d7561c4a48269284702ca50f1b1a1` and evidence
  `7a48c013a126e9bd68fa705fa7295f6027e29fec` are merged by PR `#43` as
  `d35ed9e9081a0ffb246a6350688bd833bfa6fe9d`. Evidence-head CI
  `32368675449`, package PR `32368675439`, merged-main CI `32369958558`, and
  merged-main packages `32369958304` pass. Consolidation passes and publish is
  skipped; no package is installed or published.
- **Technically limited:** Paths beneath the actual Windows `System32` and
  `SysWOW64` directories and the actual `Explorer.exe` retain a broad skip. A
  compromised or misplaced image within those protected roots could therefore
  be outside this polling inspection path. Replacing this with identity,
  publisher, or richer process-policy evidence needs separate design and false-
  positive validation.
- **Superseded follow-up:** Checkpoint 2192 moves Guard driver-health and
  driver-IPC system-root decisions onto the shared native resolver. Checkpoint
  2194 separately removes mutable environment roots from Native Engine
  Authenticode discovery and removes account-environment/helper execution from
  its private test-only legacy quarantine store.
- **Existing low-severity quality blocker:** Optional workspace-wide strict
  Clippy reports three pre-existing `services/api` style lints
  (`enum_variant_names` and `items_after_test_module`). The API compiles and the
  complete workspace test suite passes; strict Clippy for the changed Guard
  crate passes with `-D warnings`.

## Checkpoint 2192 Guard Native Root Consumers

- **Resolved and exact-head verified:** Guard driver-health no longer trusts
  `SystemRoot` or
  `WINDIR` when locating `sc.exe`, `fltmc.exe`, `bcdedit.exe`, or Windows
  PowerShell. Its component-specific allowlist delegates to the shared native
  Windows-root module, which validates the local-drive root, complete existing
  ancestor chain, final regular file, component count, component length, and
  component alphabet.
- **Resolved and exact-head verified:** Guard driver-IPC no longer grants its
  system-path
  fail-open decision from environment-derived Windows roots. It uses the same
  checked `GetSystemWindowsDirectoryW` result once per Guard process and caches
  both success and error to avoid repeated native/metadata work; a spoofed
  `Q:\SpoofedWindows` environment leaves candidates unchanged.
- **Resolved and exact-head verified:** Native-root resolver errors are no
  longer silently
  converted to an empty Windows candidate list. Verdict evaluation returns the
  error; the native driver port keeps availability through its existing
  reason-bearing fail-open error response, while direct callers receive an
  explicit failure.
- **Verified locally:** Native-root tests pass `5/5`, Guard `247/247`, the
  locked workspace `1,479/1,479`, source contracts `626/626`, strict Guard
  Clippy, rustfmt, PowerShell parsing, and release Guard build. The central
  verifier and independent validator pass `221/221` in `702.3s`; an old report
  missing the new native-root step is rejected as expected.
- **Verified hosted at implementation and merged-main heads:** Commit
  `f6a40cc200764d0925bbcc3032a74e87be21b232` passed Avorax CI
  `32378264705` and package push/PR runs `32378112753`/`32378264725` before PR
  `#44` merged as `71887973206f5287ba50cc8ff6e5eadcf43c678b`. Merged-main
  CI `32381508352` passed. Package run `32381508319` attempt 1 preserved one
  arm64 DMG settle failure; failed-job attempt 2 passed all required jobs and
  skipped publication. Checkpoint 2193 hardens this transient boundary.
- **Verified unchanged:** Read-only inventory after verification is 16,072
  ProgramData quarantine files, zero directories, 4,522,733 bytes, 5,357
  complete payload/metadata/auth sets, one metadata-auth key, and zero pending
  files. `Cargo.lock` and dependency versions are unchanged.
- **Partial / blocked:** No installed driver-health command lifecycle,
  installed LocalSystem service, production-signed driver, authenticated live
  driver IPC, helper ACL attack fixture, package install, or pre-execution
  enforcement was exercised. Those need a disposable elevated Windows host and
  production signing prerequisites.
- **Technically limited:** Actual-root `System32`/`SysWOW64` fail-open and
  process-skip policies remain broad and path-based. Metadata validation and
  later command creation are not one atomic handle-based launch. Native Engine
  helper-root follow-up is superseded by checkpoint 2194; Guard's broad
  process/IPC exceptions remain separate policy work.

## Checkpoint 2193 macOS DMG Verification Settle

- **Failure preserved:** Merged-main Desktop Packages run `32381508319`
  attempt 1 passed every completed platform except macOS arm64. Job
  `96465645009` created its DMG, then all three verification attempts returned
  the exact transient `Resource temporarily unavailable` result. This attempt
  remains failed evidence and is not relabeled as success.
- **Transient classification evidenced:** Failed-job rerun attempt 2 passed
  arm64 job `96772353094` without a source change, then passed consolidation
  job `96774515074`; publication job `96774649572` was skipped. The successful
  run naturally left about 2.5 seconds between creation and first verification,
  while the failed run began after about 0.06 seconds.
- **Resolved locally:** The macOS builder now settles with `sync` plus three
  seconds and retries only the exact resource-busy diagnostic. Five attempts
  and 2/4/8/16-second backoff bound additional wait to 33 seconds including the
  initial settle. Non-transient failures return immediately and the final
  transient failure returns its real status.
- **Verification:** Package contracts pass 24 tests with 3 explicit Windows
  symlink-privilege skips; source contracts pass `626/626`; parser and diff
  checks pass. The expanded central verifier and independent validator pass
  `222/222` in `553.8s`; a stale report without the package step is rejected.
- **Hosted status:** Implementation
  `07e803c42880e7bc556642e206828f4e5c33b815` and evidence
  `21db1719154a698b339bbc69cae532ae3185a22b` merged through PR `#45` as
  `ab1233b4f04a6a4b0d5dd4d949a8003dd41169f1`. Evidence-head CI/package runs
  `32485827199`/`32485827196` and merged-main CI/package runs
  `32487488540`/`32487488604` pass; consolidation passes and publication is
  skipped at both heads.
- **Still blocked / limited:** macOS Developer ID signing and notarization,
  installed package click-through, persistent Guard process collection on
  macOS, installed service behavior, signed-driver enforcement, and
  pre-execution protection remain unavailable or technically limited. A DMG
  build is package evidence, not Defender replacement or detection-rate proof.

## Checkpoint 2194 Native Engine Windows Roots

- **Resolved locally:** Native Engine Authenticode helper discovery and
  Microsoft local-artifact root decisions no longer consume mutable
  `SystemRoot` or `WINDIR`. Bounded `GetSystemWindowsDirectoryW` output is
  validated as one local, normal, non-reparse directory and cached once per
  process, including failures.
- **Resolved locally:** The checked PowerShell candidate has a fixed bounded
  component path, and local Microsoft trust requires both checked system
  location and valid Microsoft Authenticode. A familiar path alone never
  produces a clean verdict.
- **Disabled boundary clarified:** Native Engine production code remains
  detection-only. Its legacy quarantine store is private test-only code; Local
  Core remains the sole production quarantine owner. Compatibility tests now
  use the shared token-SID DACL hardener without `icacls.exe`, `USERNAME`, or
  `USERDOMAIN`.
- **Verified locally:** Native Windows-root tests pass `10/10`, Authenticode
  probes `2/2`, platform ACL/SID tests `4/4`, Native Engine 448 tests, the
  locked workspace `1,486/1,486`, Flutter `838/838`, source contracts
  `626/626`, strict Native Clippy, rustfmt, parsers, standalone offline lock
  check, and `git diff --check`. The central report and validator pass
  `223/223` in `522.3s`.
- **Verified unchanged:** ProgramData quarantine remains 16,072 files, zero
  directories, 4,522,733 bytes, 5,357 complete payload/metadata/auth sets, one
  key, and zero pending files. No vault item was changed or removed.
- **Dependency boundary:** `windows-sys` remains pinned at `0.61.2`. The
  internal platform-security crate is Windows test-only for the disabled
  legacy store. The standalone lock contains 72 packages/70 registry checksums,
  all already represented at exact versions in the root workspace lock.
- **Hosted status:** Implementation head
  `1dee3e25d5131d9b999cce7580e5df0f59a82f47` is on draft PR `#46`; Avorax CI
  `32493387468` passes all five jobs. Desktop Packages push/PR runs
  `32493383509`/`32493387522` pass all builds and consolidation; publication is
  skipped. Documentation-head and merged-main evidence remain pending.
- **Partial / blocked:** Installed LocalSystem/service execution, protected
  helper ACL attack E2E, production code signing, signed-driver IPC, and real
  pre-execution enforcement need approved disposable elevated hosts and signing
  prerequisites.
- **Technically limited:** Metadata validation and later helper launch are not
  atomic. Windows and protection of its real system tree remain trusted.
  32-bit Windows is unsupported and fails conservatively. User-mode polling can
  miss short-lived activity and does not replace Defender or provide kernel
  blocking.

## Checkpoint 2195 Direct Authenticode

- **Implementation head locally and hosted verified:** The PowerShell/JSON signature
  probe is replaced by direct handle-based `WinVerifyTrust`, exact Microsoft
  leaf organization/common-name checks, explicit state cleanup, and a scan-path
  SHA-256 binding read. Focused benign fixtures, full Native/workspace/Flutter
  suites, strict lint, dependency gates, a cold locked release build, and the
  definitive verifier pass locally. Exact implementation-head CI plus all
  Windows/Linux/macOS package jobs pass with publication skipped. Evidence-head
  CI/packages, PR/merge, merged-main checks, and original-tree synchronization
  remain pending.
- **Conservative failure boundary:** Missing or invalid signatures are not
  trusted. Revocation-cache absence, policy/security settings, provider/API
  failures, file I/O, unknown statuses, and WinTrust cleanup failures are
  surfaced as publisher-trust diagnostics and cannot add clean-trust weight.
- **Catalog and multiple-signature blocker:** The current `WTD_CHOICE_FILE`
  implementation evaluates the primary embedded signature. Catalog-only
  signatures and secondary signatures are not enumerated. Supporting them
  safely requires bounded catalog lookup/signature iteration, equivalent chain
  and Microsoft identity validation, hash binding, adversarial fixtures, and
  explicit aggregation policy.
- **Cancellation limitation:** `WTD_CACHE_ONLY_URL_RETRIEVAL` prevents online
  retrieval, but one in-process `WinVerifyTrust` call has no hard cancellation
  deadline. The caller can cancel between files, not while this native call is
  executing. A safe hard deadline would require an isolated authenticated
  helper process and bounded teardown, which is not introduced here.
- **TOCTOU limitation:** Read sharing without write/delete sharing blocks new
  incompatible opens and the second hash prevents trust for bytes different
  from those already scanned. It cannot revoke a writable or memory-mapped
  handle opened earlier, prevent mutation after the verdict, or authorize later
  execution. Kernel/pre-execution enforcement is not claimed.
- **Unchanged product blockers:** Installed LocalSystem/service/UI E2E,
  production package signing, signed-driver IPC, 32-bit Windows support,
  production false-positive/detection-rate evidence, and Defender coexistence
  remain separate release prerequisites. Defender must not be weakened.

## Checkpoint 2196 Catalog Authenticode

- **Locally verified:** Native Engine now falls back from a
  definitively untrusted primary embedded signature to bounded SHA-256 Windows
  catalog lookup on the same open file handle. Up to 16 catalog candidates use
  cache-only `WinVerifyTrust` and the existing exact Microsoft leaf policy.
- **Fail-visible boundary:** Inconclusive embedded verification does not fall
  through. Catalog API, hash-size, path-shape, candidate-limit, WinTrust policy,
  and normal cleanup failures remain diagnostics. UNC/non-local catalog paths
  are rejected. Successful scan trust still requires the second bounded digest
  to match the engine's already-scanned SHA-256.
- **Verification batch:** Boundary tests pass `10/10`; catalog-backed
  WindowsPowerShell fallback and right/wrong digest tests pass `3/3`; direct
  embedded/unsigned/malformed tests pass `5/5`; Native Engine passes `445 + 6`;
  the Rust workspace passes `1,489`; Flutter passes `838/838`; source contracts pass
  `626/626`. The all-features workspace also passes `1,490`. The final
  definitive verifier and independent validator pass `225/225` in `577.2s`.
  Exact implementation/evidence heads, normal PR merge, merged-main CI/packages,
  and preconditioned 12-file synchronization pass with publication skipped.
- **Still limited / blocked after checkpoint 2196:** Secondary embedded signature enumeration,
  in-call hard cancellation, memory-mapped and post-verdict mutation,
  production signing, installed LocalSystem/service/UI E2E, signed-driver IPC,
  pre-execution blocking, and production accuracy remain separate work.

## Checkpoint 2197 Secondary Embedded Authenticode

- **Verified locally, hosted, merged, and synchronized:** Native Engine can enumerate
  secondary embedded signatures only after one valid primary signature establishes a
  definitive policy result. Primary output is restricted to zero or the
  initialized untouched sentinel, secondary requested/returned indices must
  match exactly, and stable reported counts, state close/reset between calls,
  the 16-total cap, exact Microsoft leaf identity, and scanned-content digest
  binding are all mandatory. Secondary
  tests pass `14/14`; Native Engine, complete Rust workspaces, Flutter, source
  contracts, strict lint, and the exact `226/226` verifier/validator pass.
  Implementation and evidence heads, CI and package runs across all target
  platforms, normal PR merge, merged-main checks, and preconditioned 12-file
  synchronization pass with publication skipped.
- **Conservative invalid-primary boundary:** A definitively invalid primary is
  not rescued by a secondary signature. It contributes no embedded publisher
  trust and proceeds only to the existing bounded catalog fallback. This can
  reject unusual files where Windows might expose a usable secondary despite an
  invalid primary; accepting that shape requires stronger policy evidence.
- **Secondary catalog signatures remain unsupported:** Checkpoint 2197 applies
  `WINTRUST_SIGNATURE_SETTINGS` only to `WTD_CHOICE_FILE`. Catalog candidates
  retain checkpoint 2196's one verified signer evaluation. A separate bounded
  design and benign fixture are required before claiming multi-signed catalogs.
- **Host availability:** The runtime test depends on a bounded known-name
  multi-signed Microsoft Edge DLL beneath the installed x64 Edge application
  directory. Absence is a visible test blocker, not a skip or synthetic pass.
- **Unchanged technical limits:** In-process WinTrust calls cannot be hard-
  cancelled. Earlier writable/memory-mapped handles and post-verdict mutation
  remain user-mode TOCTOU limits. No execution authorization, kernel blocking,
  Defender replacement, production accuracy, installed-service, or signed-
  driver claim is introduced.

## Checkpoint 2198 Release Authenticode Isolation

- **Local and implementation-head hosted evidence verified:** Non-debug Native Engine calls are routed
  through a hidden mode of the exact current Local Core or Guard executable.
  The strict schema-v1 protocol binds request and response with a random UUID-v4
  nonce, carries one bounded UTF-16 path plus optional expected SHA-256, and
  bounds request, stdout, stderr, and diagnostic sizes. Debug builds retain the
  direct path for deterministic unit tests. Helper isolation passes `4/4`,
  focused Authenticode passes `26/26`, both host release builds and benign smoke
  pass, Native Engine passes `452 + 6`, both locked workspace variants pass,
  Flutter passes `838/838`, source contracts pass `627/627`, and the definitive
  verifier/validator passes `229/229` in `433s`. Implementation head
  `10668f17e084187014cc4bfa34a6191c47493d7c` passes CI `32597124365` and
  package push/PR `32597113497`/`32597124404` with publication skipped.
  Evidence head `e14e6dd9d80e77823c1c1db8d968c5f86f598ce0`, PR `#50` merge
  `ab6bd8908d679a60515bac0cf3ceb56f3b6f8a45`, merged-main CI/packages, and
  exact 18-file synchronized-tree checks pass with publication skipped.
- **Hard-timeout boundary:** The parent retains a regular non-reparse read handle
  to its bounded current executable, starts it without shell/PATH/network/window,
  assigns it to a kill-on-close Windows Job, enforces a 15-second deadline, and
  separately bounds kill/reap. Spawn, assignment, pipe, timeout, kill, reap,
  protocol, nonce, digest, child, and cleanup failures are visible and supply no
  Microsoft trust. The deadline begins after synchronous Windows process
  creation and Job assignment; the process-creation API call itself has no
  cancellation contract.
- **Privilege boundary remains partial:** The helper intentionally uses the same
  token as its Local Core or Guard parent. It isolates lifetime and failure, but
  is not an AppContainer, restricted-token sandbox, authenticated cross-token
  service, or least-privilege split. A stronger token boundary needs an explicit
  IPC and access design plus installed-service evidence.
- **Current-executable trust boundary:** The running image, operating system
  loader, Job/process/pipe APIs, installed location ACLs, WinTrust providers,
  trust stores, and protected catalog state remain in the trusted computing
  base. Retaining a read handle narrows replacement races but cannot revoke a
  write or memory-map handle opened earlier or stop post-verdict mutation.
- **Secondary catalogs remain unsupported:** Reviewed public contracts establish
  selected secondary signatures for file trust but do not justify applying the
  same index assumptions to `WTD_CHOICE_CATALOG`. Catalog verification therefore
  remains the existing one-signer conservative path until a documented contract
  and benign fixture exist.
- **Unchanged release blockers:** Production package signing, installed
  LocalSystem/service/UI E2E, signed-driver IPC, pre-execution blocking,
  Defender coexistence, and production false-positive/detection-rate evidence
  remain separate prerequisites. Defender must not be weakened.

## Checkpoint 2199 Mandatory Hash And File Identity

- **Local, hosted, merge, and synchronized-tree evidence verified:** Every Microsoft publisher-trust request
  requires a 64-hex SHA-256 supplied by the scanner. The path-only public helper
  and unused aggregate publisher function are removed; helper JSON requires a
  non-null digest. Focused and complete Native, locked workspace, release smoke,
  Flutter, source-contract, security/dependency, and `230/230` verifier evidence
  passes locally. Implementation head `d619c0a5ddb627e9d940d12478d5db9589ee5679`
  passes CI `32601267008` and package push/PR `32601253745`/`32601266989`
  with publication skipped. Evidence head `b000b8dfc9e4e7427380ddbe80dba958d9d16e95`,
  merge `264e4551aa930f75d325ebd3df4522bd4f244941`, merged-main runs, and the exact
  16-file synchronized-tree checks pass with publication skipped.
- **Stable handle evidence:** The candidate's same open handle is queried before
  and after the complete WinTrust/catalog/hash operation for volume/file ID,
  legacy index, creation/write/change times, attributes, allocation/end size,
  link count, delete-pending, and directory state. Query failure, inconsistent
  APIs, or drift is a visible diagnostic and cannot return trust.
- **Compatibility trade-off:** Filesystems/providers that cannot supply the
  required handle identity fail conservatively instead of receiving publisher
  credit. Last-access time is excluded because the verifier's own reads may
  update it. Benign tests use only isolated temporary files and installed
  Microsoft fixtures, never executing candidates.
- **Residual TOCTOU limit:** A writable mapping created before the read-only
  handle can still mutate the file, although digest and metadata drift checks
  detect ordinary changes during verification. The verifier cannot stop a
  mutation after it returns. Closing that boundary needs execution-control or
  caller-held handles through later action; no pre-execution claim is made.
- **Unchanged blockers:** Same-token helper privilege, production signing/key
  custody, installed LocalSystem/service/UI
  E2E, signed-driver IPC, Defender coexistence, and production accuracy remain
  partial, blocked, or technically limited.

## Checkpoint 2200 Secondary Catalog Authenticode

- **Local evidence verified:** Catalog candidates use exact primary/
  secondary selection with stable count, close/reset per attempt, a 16-total
  cap, exact Microsoft signer identity, and mandatory member SHA-256 binding.
  Invalid primaries cannot be rescued and every error remains fail-visible.
- **Regression evidence:** Focused secondary catalog logic passes `2/2`, the
  complete Authenticode module passes `24/24`, Native Engine passes `458 + 6`,
  both locked workspace variants, release host smoke, Flutter `838/838`, source
  contracts `628/628`, and strict gates pass. The definitive verifier/validator
  passes `231/231` in `424.1s` and rejects stale `230`-step evidence.
  Implementation head `882f24d45c13b60b952cfacb94d3eee2563fb0f8`
  passes CI `32605433795` and package push/PR `32605424354`/`32605433783`
  with publication skipped. Evidence head `e863332dec8a646909ba1945aca32875288df76c`
  passes CI/packages, PR `#52` merges with exact-head locking as
  `baa39ac316c58b010cb7805785a1fef47c4f0c19`, merged-main CI/packages pass,
  and all 13 synchronized files plus focused destination checks pass.
- **Partial positive evidence:** The installed WindowsPowerShell fixture can
  prove real primary-catalog provider compatibility and wrong-hash rejection.
  The unit fixture can prove bounded secondary decision logic. Neither is a
  controlled benign catalog with a known valid Microsoft secondary signature,
  so positive secondary acceptance remains partial until such a fixture or a
  disposable Windows test image supplies reproducible evidence.
- **Not a blocking bypass:** The partial fixture does not turn the path into
  success-by-default. WinTrust must validate the exact requested index and the
  existing exact signer/hash policy must pass; otherwise the candidate supplies
  no trust or a visible diagnostic.
- **Remaining boundaries:** Memory-mapped and post-verdict mutation, same-token
  helper privilege, production signing/key custody, installed service/UI E2E,
  signed-driver IPC, Defender coexistence, pre-execution blocking, and
  production accuracy remain partial, blocked, or technically limited.

## Checkpoint 2201 Authenticode Helper Job Resource Limits

- **Local evidence verified:** The release helper Job now requests an exact
  12-second per-process user-CPU ceiling, one active process, 1 GiB per-process
  and whole-Job commit ceilings, kill-on-close, and unhandled-exception dialog
  suppression. It queries and compares every value before candidate input is
  written. API or mismatch failures remain diagnostic and cannot supply trust.
- **Regression evidence:** A real unnamed Job read-back plus mutated
  flag, CPU, process-count, per-process commit, and whole-Job commit values are
  covered by a focused benign test that passes `1/1`. Helper isolation passes
  `5/5`, Authenticode `25/25`, Native Engine `459 + 6`, Flutter `838/838`, and
  source contracts `629/629`. Verifier step 232 and exact full-report
  validation pass `232/232` in `441s`; a copy missing only this step is rejected
  with expected 232, found 231. Strict lint, format, dependency, release-build,
  helper-smoke, and lockfile gates pass; the protected vault is unchanged.
  Implementation `c8673c134c79f2931e9206b424b2d016a19e1cbd` passes CI
  `32609018123` and package push/PR `32609010416`/`32609018053`, including all
  six platform artifacts, consolidation, checksums, and lockfile SBOM with
  publication skipped.
- **Technically limited:** Commit ceilings bound committed virtual memory, not
  physical working set or I/O bytes. Per-process user CPU excludes kernel time.
  The trusted exact-current-executable process starts before Job assignment but
  blocks on stdin; candidate processing begins only after configuration,
  read-back, and assignment. The child still uses the parent's security token.
- **Still blocked or partial:** Restricted-token/authenticated cross-token IPC,
  installed LocalSystem/service/UI E2E, production signing/key custody,
  signed-driver IPC, Defender coexistence, pre-execution blocking, and
  production accuracy remain separate prerequisites. Evidence-head checks,
  merge, and original-tree synchronization are still pending.

## Checkpoint 2202 Deterministic PUP Category Inference

- **Merged-main regression:** CI `32610442133` failed Local Core test
  `zip_entry_script_rule_and_heuristics_are_reported_without_confirmed_quarantine`
  after 534 tests passed. The report remained `ProbableMalware`, detected, and
  carried both expected downloader/script reasons; only its category changed to
  PUA because randomized path `.tmpuPoV59` contained lowercase substring `pup`.
- **Scripted repair:** PUP inference now requires an exact ASCII-alphanumeric
  token. The exact path fragment is a negative fixture and explicit
  `pup_indicator` is a positive fixture. Score, verdict, action, and evidence
  are not weakened.
- **Local evidence verified:** Direct token boundary passes `1/1`, risk fusion
  `7/7`, the triggering archive test 25 repeats, Local Core three parallel
  `535/535` runs, Native `460 + 6`, both locked workspaces, strict gates, source
  contracts `631/631`, and definitive/independent validation `232/232` in
  `517.3s`. Stale same-count evidence without scope is rejected.
- **Additional test race found:** The first default-parallel locked workspace
  run caught an asset-locator negative test exposing
  `AVORAX_ENGINE_ROOT=relative-engine-root` to a concurrent JAR scan. Both
  asset-locator env cases are now isolated in exact child-test processes.
  Production validation remains unchanged; isolation `4/4` and all parallel
  full reruns pass.
- **Unchanged limitations:** Category inference remains keyword-based
  explainability rather than a family classifier. Detection efficacy,
  production false-positive rates, installed E2E, driver/pre-execution
  behavior, and Defender replacement remain separate limits or blockers.
  Hosted checkpoint-2202 evidence, follow-up merge, green merged-main checks,
  and original-tree synchronization remain pending.

## Checkpoint 2202 Integration Closure

- **Resolved:** Evidence-head CI/packages, PR `#54`, exact merge `4e24e47`,
  merged-main CI/packages, preconditioned 15-file original-tree synchronization,
  destination focused checks, release Authenticode helper smoke, and protected-
  vault read-only verification all pass. Publication was skipped and no package
  was installed. This also closes checkpoint 2201's stale evidence-head/merge/
  sync wording.

## Checkpoint 2203 Authenticode Restricted Thread Token

- **Verified locally:** Release-helper WinTrust derives and applies a
  `DISABLE_MAX_PRIVILEGE` `SecurityImpersonation` token before opening the
  candidate. Exact type/level and bounded `TokenPrivileges` read-back allow only
  enabled `SeChangeNotifyPrivilege`; failures and normal revert errors cannot
  become trust. Focused real-token and synthetic sensitive-privilege tests pass
  `2/2`, Authenticode passes `27/27`, Native passes `462 + 6`, Flutter passes
  `838/838`, source contracts pass `632/632`, and the definitive verifier plus
  validator pass `233/233` in `473.5s`. Implementation `710e38a`, evidence
  `1a9703d`, PR `#55`, merge `b70298a`, merged-main CI/packages, exact original-
  tree synchronization, destination checks, and vault audit pass. Publication
  was skipped.
- **Still partial:** The helper process retains the parent process token, SID,
  integrity level, desktop, environment, and ACL access. Same-process native
  code can technically revert thread impersonation. This is not AppContainer,
  a restricted process, a separate desktop, authenticated cross-token IPC, or
  installed LocalSystem service evidence.
- **Unchanged blockers:** Production code/driver signing, installed service/UI
  E2E, signed-driver IPC, pre-execution enforcement, Defender coexistence, and
  production detection/false-positive evidence remain separate prerequisites.

## Checkpoint 2204 Authenticode Restricted Process Token

- **Locally verified process privilege boundary:** Release Local Core and Guard
  derive a restricted primary token with `DISABLE_MAX_PRIVILEGE`, create the exact helper
  suspended through `CreateProcessAsUserW`, restrict inheritance to the three
  stdio pipes with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, assign the validated Job,
  and only then resume. The child validates its effective primary token before
  reading untrusted request data. Process tests `2/2`, helper `9/9`, complete
  Authenticode `29/29` plus two ignored child fixtures, and both release hosts
  pass locally. Exact `234/234` verifier/validator, central gates, and
  adversarial stale/missing-step/missing-scope report rejection pass.
  Implementation head `a0272a3` passes CI `32620196065` and package push/PR
  `32620187506`/`32620196066`. Evidence `930342f`, PR `#56`, merge `a5f982a`,
  merged-main CI/packages, exact 12-file sync, destination checks, and vault
  audit also pass with publication skipped.
- **Fail-visible compatibility policy:** There is no same-token fallback. Token,
  pipe, handle-list, process creation, Job assignment, resume, child read-back,
  timeout, termination, reap, or verification failure supplies no publisher
  trust. This may conservatively withhold Microsoft publisher credit on a host
  that cannot create a process with a restricted version of its own token. The
  current Windows development host proves compatibility for Local Core and
  Guard; installed LocalSystem compatibility remains unproved.
- **Residual identity/access limit:** The restricted primary token keeps the
  parent SID, integrity level, environment, desktop, and ordinary SID-based
  access. `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` prevents unrelated handle
  inheritance but is not AppContainer, restricting-SID isolation, a separate
  desktop, or authenticated cross-identity IPC.
- **Unchanged blockers:** Installed LocalSystem/service/UI E2E, production code
  and driver signing, signed-driver IPC, pre-execution enforcement, Defender
  coexistence, and production detection/false-positive evidence remain separate
  prerequisites.

## Checkpoint 2205 Authenticode Write-Restricted Token

- **Locally verified write-access reduction:** The process keeps checkpoint 2204's
  read-back-verified `DISABLE_MAX_PRIVILEGE` primary token. Before stdin or
  request parsing, the helper applies a `SecurityImpersonation` token created
  with `DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED` and exactly one
  zero-attribute `WinRestrictedCodeSid` API input. Thread read-back validation
  is fail-visible. It protects strict request parsing and read-only candidate
  open/snapshot, is reverted before WinTrust/catalog, and is applied again for
  response output. Focused and complete local runtime evidence passes. Both
  locked workspace variants, strict lint, Flutter `838/838`, source contracts
  `634/634`, and exact verifier/validator `235/235` pass. Implementation head
  `a5597d2` passes CI `32624862111` and package push/PR
  `32624842967`/`32624862058`; evidence-head, merge, merged-main, and
  synchronization evidence remains pending.
- **Bounded restricting-SID evidence:** `TokenRestrictedSids` responses are
  capped at 64 KiB and 16 entries, then require exactly one in-buffer, valid,
  bounded SID byte-equal to Restricted Code with exact mandatory,
  default-enabled, and enabled read-back attributes. API, pointer, length,
  count, attribute, or identity failure cannot supply publisher trust.
- **Benign supported claim:** An isolated child fixture is scripted to retain
  read/hash access to an ordinary user-owned temporary file while a write-open
  is denied and parent-observed bytes remain unchanged. The dedicated filter
  passes `2/2`. This uses no malware and does not execute a candidate.
- **Primary-token compatibility blocker:** Applying the same write-restricted
  SID to the primary token caused the Windows child to terminate before user
  code with `0xC0000142` (`STATUS_DLL_INIT_FAILED`). The implementation keeps
  the privilege-stripped primary token and does not retry with weaker launch
  settings.
- **Windows trust-stack compatibility blocker:** Keeping write restriction
  active through WinTrust/catalog caused release smoke to fail with Windows
  error `127`. The helper now performs only that trusted OS phase under the
  privilege-stripped primary token; token revert and reapplication failures are
  fatal. Full WinTrust write restriction is not claimed.
- **Residual access limit:** `WRITE_RESTRICTED` evaluates restricting SIDs only
  for write access. The impersonation token retains parent SID, integrity,
  environment, desktop, and ordinary read access. Inherited handles and ACLs
  satisfying both access checks can remain usable. The primary token is not
  write-restricted and same-process code can technically call `RevertToSelf`;
  WinTrust/catalog deliberately use that primary token. AppContainer and
  identity isolation are not claimed.
- **Unchanged blockers:** Installed LocalSystem/service/UI E2E, production code
  and driver signing, signed-driver IPC, pre-execution enforcement, Defender
  coexistence, writable mapping/post-verdict mutation, and production
  detection/false-positive evidence remain separate prerequisites.

## Checkpoint 2206 Authenticode Sanitized Launch Status

- **Locally runtime-verified:** `CreateProcessAsUserW` receives an
  explicit bounded Unicode environment with exactly native-root `SystemRoot`
  and `WINDIR`, `CREATE_UNICODE_ENVIRONMENT`, and an explicit checked
  non-reparse `System32` current directory. No inherited environment/current-
  directory fallback is implemented.
- **Compatibility evidence:** benign child state, embedded Edge,
  catalog-backed WindowsPowerShell, unsigned rejection, wrong-hash failure,
  complete Authenticode/workspace suites, and exact `236/236` verification pass
  locally. Independent strict validation passes and controlled stale-count,
  missing-step, and missing-scope reports are rejected. Exact-head hosted,
  merged-main, and installed LocalSystem evidence remain separate.
- **Implementation-head evidence:** `80599a1` passes CI `32629832036` and
  package push/PR `32629820137`/`32629832031`, including all six desktop
  artifacts, checksums, and lockfile SBOM with publication skipped. The
  evidence head, merge, merged main, synchronization, and installed
  LocalSystem evidence remain separate.
- **Residual boundary:** the child still keeps parent SID, integrity, desktop,
  window station, and ordinary read access, and can mutate its own environment.
  `CREATE_UNICODE_ENVIRONMENT` is launch-input hardening, not AppContainer,
  identity/profile isolation, driver enforcement, or pre-execution blocking.

## Checkpoint 2207 Authenticode Process Mitigation Status

- **Verified locally:** The helper creation list adds
  `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` with strict-handle,
  extension-point-disable, dynamic-code-prohibit, Microsoft-signed-only,
  no-remote, no-low-label, and System32-preference values. The child must read
  back all required groups before stdin; no weaker retry is implemented. The
  focused real-child/pure filter passes `2/2`, complete Authenticode passes
  `35/35`, and both release-host smoke runs pass embedded/catalog trust plus
  unsigned/wrong-hash rejection.
- **Evidence status:** Locked workspaces, strict lint, release builds, Flutter
  `838/838`, source contracts `636/636`, and definitive verification
  `237/237` in `462.1s` pass. Four malformed evidence copies are rejected.
  Hosted exact-head, merge, merged-main, installed enterprise security
  integrations, and LocalSystem remain separate evidence.
- **Final-review amendment verified locally:** Strict-handle read-back requires both
  invalid-handle exception and permanent-enforcement flags and rejects
  temporary-only evidence. The stricter focused regression, complete
  Authenticode, strict lint, source contracts, and definitive `237/237` rerun
  pass. Exact implementation-head CI and both package runs pass with publication
  skipped; evidence-head, merge, merged-main, installed enterprise, and
  LocalSystem evidence remain pending.
- **Residual boundary:** Process-creation mitigations do not constrain the
  already mapped helper image or non-image data and do not isolate identity,
  integrity, profile, registry, desktop, or ordinary read access.
  Microsoft-signed-only image loading can conflict with non-Microsoft trust
  providers or injected security modules. AppContainer, driver enforcement,
  and pre-execution blocking are not claimed.

## Checkpoint 2208 Authenticode Low-Integrity Primary Token Status

- **Checkpoint 2207 closed:** Evidence `b36b6eb`, PR `#59`, merge
  `c1d7e969`, merged-main CI `32636058192`, packages `32636058140`, exact
  12-path original-tree synchronization, destination verification, and the
  unchanged vault invariant are complete. Publication was skipped.
- **Verified locally:** The Authenticode helper's privilege-stripped
  primary token is assigned exact `WinLowLabelSid` through
  `SetTokenInformation(TokenIntegrityLevel)` before `CreateProcessAsUserW`.
  Parent and child bounded read-back pass before process launch or stdin;
  no higher-integrity fallback is present.
- **Adversarial evidence:** Pure policy cases reject a wrong SID,
  missing `SE_GROUP_INTEGRITY`, enabled-only evidence, and unrelated
  attributes. A benign child calls `RevertToSelf` and remains unable to
  write an ordinary medium-integrity text fixture while preserving read/hash
  access. Focused filters, complete Authenticode, strict lint, locked builds and
  workspaces, release trust smoke, Flutter `838/838`, source contracts
  `637/637`, and the central verifier/validators `238/238` in `429.7s`
  pass. Four malformed reports are rejected. Implementation `c7ff9b7` passes
  exact-head CI `32638907677` and package push/PR
  `32638895902`/`32638907670` with all six artifacts, checksums, lockfile
  SBOM, and publication skipped. Evidence-head, merge, merged-main, and
  original-tree synchronization subsequently passed: evidence `fa7574f`, PR
  `#60`, merge `1076ac3`, merged-main CI `32640506209`, packages
  `32640506192`, exact 12-path synchronization, destination verification, and
  the unchanged protected-vault invariant close checkpoint 2208.
- **Residual blocker:** Windows Mandatory Integrity Control/no-write-up is not
  identity or read isolation. Parent SID, profile/registry namespace, desktop,
  ordinary read access, and explicitly low-writable objects remain reachable.
  AppContainer/LPAC, authenticated cross-identity IPC, installed LocalSystem
  compatibility, signed-driver enforcement, and pre-execution blocking remain
  unverified, blocked, or technically limited.

## Checkpoint 2209 Authenticode Mandatory Policy Status

- **Focused verified after redesign:** The helper requires the
  LSA-created policy inherited through `CreateRestrictedToken` to contain
  `TOKEN_MANDATORY_POLICY_NO_WRITE_UP`. Parent read-back precedes
  `CreateProcessAsUserW`; child read-back precedes stdin.
- **Privilege boundary:** The initial direct
  `SetTokenInformation(TokenMandatoryPolicy)` attempt failed visibly with
  `ERROR_PRIVILEGE_NOT_HELD` (1314). The setter was removed rather than adding
  privilege, weakening Windows, or swallowing the failure.
- **Fail-closed policy:** `TOKEN_MANDATORY_POLICY_NO_WRITE_UP` is required;
  only the documented optional `TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN` bit is
  allowed beside it. Policy off, new-process-minimum alone, unknown bits, query
  failure, or unexpected result size cannot become publisher trust.
- **Local evidence passed:** The benign real-child and pure policy filters,
  complete Authenticode, strict Native/Local/Guard lint, both locked workspace
  variants, release builds/two-host smoke, Flutter analyze and `838/838`, source
  contracts `639/639`, and definitive verifier/validators `239/239` in
  `433.2s` pass. Five malformed reports are rejected. Evidence `7fd8734`, PR
  `#61`, merge `d07220c`, merged-main CI `32646774829`, packages
  `32646774820`, exact 18-path synchronization, destination focused/full
  checks, and the unchanged vault subsequently close checkpoint 2209.
- **Residual blocker:** No-write-up policy does not add no-read-up,
  no-execute-up, identity, profile, registry, desktop/window-station,
  AppContainer/LPAC, installed LocalSystem, driver, or pre-execution isolation.
- **Definitive-verifier failure retained:** The first full attempt stopped after
  38 recorded steps because Defender removed the Native Rust test executable
  containing a compile-time standard EICAR marker (Cargo OS error 225). No
  Defender setting or exclusion was changed.
- **Remediation verified locally:** Native and Local Core share a bounded
  XOR-encoded marker decoded once at runtime, and both test executables reject
  static marker inclusion. A first retry also remains failed after 233 steps
  because an agent-created Python bytecode cache contained a compile-time-
  joined marker; the contract now runtime-joins fragments. The final `239/239`
  retry and no-malware gate pass. Neither failed report is success evidence.

## Checkpoint 2210 Authenticode Token-Flag Status

- **Verified locally:** Canonical fixed-size
  `TokenVirtualizationAllowed` plus exact-zero `TokenVirtualizationEnabled` and
  `TokenUIAccess` parent/child read-back, pure rejection cases, a real isolated child, a mandatory
  verifier step, independent-validator checks, and documentation pass focused,
  adjacent, complete Authenticode, strict lint, locked workspace, release-host,
  Flutter, source-contract, no-malware, and dependency checks. The definitive
  report passes `240/240` in `458s`; five malformed reports are rejected.
- **Failed first design retained:** The first compiled child returned
  `TokenVirtualizationAllowed=1` and correctly failed the original all-zero
  policy. Microsoft defines that field as capability, not active state; the
  result is not success evidence and the policy now accepts only canonical
  capability values while active virtualization/UIAccess remain forbidden.
- **Fail-closed intent:** Query failure, unexpected size, noncanonical
  capability, enabled virtualization/UIAccess, or child-state drift must prevent
  publisher trust. No setter, extra privilege, or weaker retry exists.
- **Implementation-head hosted evidence passed:** Exact `c744fa9` passes CI
  `32649764260` and package push/PR `32649749634`/`32649764310`, including all
  six artifacts, checksums, lockfile SBOM, and skipped publication.
- **Integration closed:** Evidence `8228daf`, PR `#62`, merge `425e663`,
  merged-main CI `32651609367`, packages `32651609388`, exact 12-path guarded
  synchronization, destination runtime/source checks, exact lockfiles, and the
  unchanged vault all pass. Package publication was skipped. This is verified
  development/destination evidence, not installed LocalSystem proof.
- **Residual blocker:** `TokenVirtualizationAllowed` may remain one; trusted
  helper code has no enable path, but capability is not removed. Inactive
  virtualization and disabled UIAccess do not change SID, credentials, profile, registry namespace,
  desktop/window station, ordinary reads, or intended inherited standard
  handles. AppContainer/LPAC, private desktop, authenticated cross-identity
  IPC, installed LocalSystem, signed-driver enforcement, and pre-execution
  blocking remain partial, blocked, or technically limited.

## Checkpoint 2211 Authenticode Job UI-Restriction Status

- **Verified locally:** The helper Job requests exact
  `JOB_OBJECT_UILIMIT_HANDLES`, `JOB_OBJECT_UILIMIT_READCLIPBOARD`,
  `JOB_OBJECT_UILIMIT_WRITECLIPBOARD`, `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS`,
  `JOB_OBJECT_UILIMIT_DISPLAYSETTINGS`, `JOB_OBJECT_UILIMIT_GLOBALATOMS`,
  `JOB_OBJECT_UILIMIT_DESKTOP`, and `JOB_OBJECT_UILIMIT_EXITWINDOWS`, with
  parent query/read-back of both exact flags and exact returned structure size
  before the suspended child is assigned and resumed.
  Exact/adversarial UI checks pass `2/2`; release Local Core/Guard helper smoke,
  complete Authenticode, both locked workspaces, strict lint, Flutter, and
  corrected central `241/241` verification pass in `434.1s`. Final review found
  and repaired missing returned-size validation, then tightened the central scope
  to require that evidence; neither earlier pass is counted as final evidence.
- **Fail-visible policy:** Configuration, query, exact-flag, assignment, or
  resume failure prevents publisher trust. No reduced-flag or unrestricted
  retry is implemented. Five malformed reports are rejected. Exact
  implementation `024d63f` passes CI `32655155577` and package push/PR
  `32655130037`/`32655155628`, including all six platform artifacts, checksums,
  lockfile SBOM, administrative MSI extraction, and skipped publication.
  Evidence-head, merge, synchronization, and destination evidence remains
  pending.
- **Residual blocker:** `JOB_OBJECT_UILIMIT_DESKTOP` prevents desktop creation
  and switching; it does not create a private desktop or window station. These
  UI limits do not change identity/profile, deny filesystem/registry/network
  reads, constrain named kernel objects, prove installed LocalSystem behavior,
  or provide AppContainer, signed-driver, or pre-execution enforcement.
- **Integration closure:** Evidence `9378955`, PR `#63`, merge `33cafa5`,
  merged-main CI `32656681010`, packages `32656681007`, exact 12-path guarded
  synchronization, destination focused/full checks, exact lockfiles, and the
  unchanged protected vault close checkpoint 2211. Publication was skipped.
  The residual limitations above remain project-level work, not unreported
  checkpoint failures.

## Checkpoint 2212 Authenticode Private Desktop

- **Scripted boundary:** Every release helper launch creates a unique bounded
  `CreateDesktopW` desktop in the current process window station while temporarily
  applying a read-back-verified low-integrity `SecurityImpersonation` token derived
  from the exact child primary token. Successful `RevertToSelf`, exact name and
  byte-count read-back, zero `UOI_FLAGS` inheritance/hook state,
  `STARTUPINFOEXW.lpDesktop`, handle lifetime, and child actual-desktop binding are
  mandatory before candidate input. After confirmed child exit, `CloseDesktop`
  success is checked; RAII remains the failure-path fallback.
- **Fail-visible policy:** Desktop create/query/size/name/flag/attachment/binding
  and token duplicate/apply/read-back/revert errors prevent publisher trust. The
  first medium-integrity creation attempt failed with loader status `0xC0000142`;
  no broad DACL, default, or interactive desktop retry exists.
  Benign child and adversarial tests pass, source contracts pass `642/642`, and
  final review found and repaired unchecked `CloseDesktop` result handling, and
  the definitive retry verifier plus independent validator pass `242/242` in `473.5s`.
  Five malformed report copies are rejected. Complete Authenticode, both locked
  workspaces, strict lint/release/two-host smoke, Flutter, no-malware, dependency,
  exact-lockfile, and protected-vault checks pass locally. Hosted exact-head,
  integration, destination, and installed evidence remain pending. Exact
  implementation `2612b7a` passes CI `32660616609` and package push/PR
  `32660604610`/`32660616617`, including six artifacts, checksums, lockfile SBOM,
  administrative MSI extraction, and skipped publication.
- **Residual blocker:** This is not a private window station. `CreateDesktopW`
  inherits station security and does not isolate station-wide clipboard/global
  atoms, identity, profile, registry, filesystem/network/read access, or named
  kernel objects. Desktop heap consumption remains bounded only by helper lifetime
  and existing concurrency. AppContainer/cross-identity IPC, installed LocalSystem,
  signed-driver, and pre-execution evidence remain separate blockers.

## Checkpoint 2213 Authenticode Standard-Handle Binding

- **Scripted boundary:** Parent `CreatePipe` endpoints must be `FILE_TYPE_PIPE`
  with exact parent-zero/child-`HANDLE_FLAG_INHERIT` flags before process creation.
  `GetNamedPipeInfo` verifies server/read endpoints; exact API return-role assignment
  binds child stdin to read and stdout/stderr to writes without an unsupported write-
  handle query. Before private-
  desktop, token, mitigation, or stdin processing, the child requires exact
  `STARTF_USESTDHANDLES`, exact `GetStdHandle` identity, three valid distinct
  anonymous pipes with queried stdin server/read mode and stdout/stderr identity
  bound to the parent-created write handles,
  then clears inheritance and requires exact-zero flag read-back.
- **Fail-visible policy:** Handle query, type, direction binding, identity, duplicate,
  initial-flag, mutation, or read-back errors prevent publisher trust. The new
  real-child and adversarial tests, verifier step 243, validator, source contract,
  and documentation were scripted before execution. No checkpoint-2213 passing
  result was claimed before execution. Focused checks pass `2/2`, complete
  Authenticode passes `47` with `10` intentional ignores, source contracts pass
  `643/643`, and strict lint/release/two-host smoke/both locked workspaces plus
  Flutter `838/838` and no-malware pass. The definitive verifier/validator pass
  `243/243` in `469.2s`; five adversarial report copies are rejected. Exact
  lockfiles and protected-vault evidence pass. Exact implementation `f0f4c3b`
  passes CI `32665658235` and package push/PR `32665646920`/`32665658257`,
  including all six artifacts, checksums, a 569-component lockfile SBOM,
  administrative MSI extraction, and skipped publication. Evidence-head,
  integration, destination, and installed evidence remain pending; complete
  final-artifact license review remains partial.
- **Residual blocker:** Exact standard-handle binding narrows inherited helper IPC
  only. Anonymous pipes and the nonce do not provide cross-identity authentication
  or encryption, prevent same-user handle duplication, or isolate the named-kernel-
  object namespace. AppContainer, installed LocalSystem, signed-driver, and pre-
  execution evidence remain separate blockers.

## Checkpoint 2215: Authenticode Pipe Peer Binding Is Locally Verified

- **Verified local boundary:** The sanitized helper environment now carries canonical
  nonzero parent-PID evidence alongside `SystemRoot` and `WINDIR`. After standard-
  handle validation, the child requires `GetNamedPipeClientProcessId` for stdin
  and `GetNamedPipeServerProcessId` for stdout/stderr to return that exact parent
  creator PID, distinct from the child PID, before private-desktop, token,
  mitigation, stdin, request, candidate, or trust work.
- **Evidence status:** Real benign-child and malformed/mismatched checks pass `2/2`;
  Authenticode passes `59`/`12`; both locked workspaces pass with Native `487`/`12`
  plus compiler `6/6`; source contracts pass `645/645`; Flutter passes `838/838`;
  strict lint, release/two-host smoke, no-malware, dependency, exact-lockfile, and
  protected-vault gates pass. Verifier/validator pass `245/245` in `469.4s`, and
  seven malformed reports are rejected. No checkpoint-2215 passing result is
  claimed before execution; these are later execution results. Exact implementation
  `cf9055b` passes CI `32675047983` and package push/PR runs
  `32675035927`/`32675048000`, including all six native artifacts, checksums,
  lockfile SBOM, administrative MSI extraction, and skipped publication. Evidence-
  head, merge, merged-main, synchronization, and destination evidence remain pending.
- **Residual blocker:** Anonymous `CreatePipe` endpoints are created and connected
  in the parent. The process-ID APIs identify that parent creator from inherited
  child handles but cannot prove the inheriting child PID back to the parent. The
  launch PID is not secret. Same-user handle duplication, authenticated/encrypted
  cross-identity IPC, AppContainer, installed LocalSystem, signed-driver, and pre-
  execution proof remain separate blockers.
- **Integration closure:** Evidence `79e865c` passes CI `32675987165` and packages
  `32675987151`; PR `#67` merges normally as `c298c3a`; merged-main CI
  `32676733841` and packages `32676733940` pass. Exact 12-path original-tree
  synchronization and destination verifier `245/245`, Authenticode `59`/`12`,
  strict lint, both locked workspaces, Flutter `838/838`, no-malware/dependency,
  exact lockfile, and protected-vault checks pass. Publication is skipped.
  Checkpoint 2215 has no remaining integration blocker.

## Checkpoint 2214: Authenticode Job Membership Is Locally Verified

- **Parent boundary:** After assignment and before `ResumeThread`, the parent is
  scripted to require a nonzero exact match between `PROCESS_INFORMATION.dwProcessId`
  and `GetProcessId`, exact-parent-Job `IsProcessInJob`, and an exact-size
  `JOBOBJECT_BASIC_PROCESS_ID_LIST` with one assigned/listed process and the helper
  PID as its sole entry. Any failure terminates and reaps the suspended helper.
- **Child boundary:** Before standard handles, private desktop, token, mitigation,
  stdin, request, or candidate work, the child is scripted to require nonzero
  `GetCurrentProcessId` and successful null-Job `IsProcessInJob` membership. A false
  result or API error is diagnostic and cannot become trust.
- **Evidence status:** Benign/adversarial checks pass `2/2`; complete Authenticode
  passes `49` with `11` intentional ignores; both locked workspace variants pass
  with Native `485`/`11` plus compiler `6/6`; source contracts pass `644/644`;
  Flutter passes `838/838`; and strict lint, release builds, two-host trust smoke,
  no-malware, dependency, exact-lockfile, and protected-vault gates pass. The
  definitive verifier and standalone validator pass exactly `244/244` in `464.3s`.
  Six adversarial report copies are rejected. No checkpoint-2214 passing result is
  claimed before execution; every passing claim here is from the later execution
  phase. At this local-evidence point, hosted and integration evidence remained
  pending; the later hosted result is recorded immediately below.
- **Hosted status:** Exact implementation `6c3bad3` passes Avorax CI
  `32670186345` and Desktop Packages push/PR runs
  `32670175754`/`32670186350`, including six native artifacts, checksums,
  lockfile SBOM, dependency/license evidence, and administrative MSI extraction.
  Publication is skipped. Evidence head `3014c44` passes CI `32671137010` and
  packages `32671137068`; PR `#66` merges normally as `cbf6203`; merged-main CI
  `32672025315` and packages `32672025303` pass. Exact 12-path synchronization and
  destination contracts/Job-membership/Authenticode/lint/release/trust-smoke/no-
  malware/dependency/full-workspace/Flutter checks pass with exact lockfiles and an
  unchanged vault. Checkpoint 2214 has no remaining integration blocker.
- **Residual blocker:** Parent exact-Job/PID-list read-back is point-in-time. The
  child's null-Job check proves only membership in some Job because it does not own
  the unnamed parent Job handle. `IsProcessInJob` and
  `JOBOBJECT_BASIC_PROCESS_ID_LIST` do not authenticate IPC, change identity, or
  provide AppContainer, installed LocalSystem, signed-driver, or pre-execution
  evidence. Those remain separate blockers.
## Checkpoint 2216 parent-child handshake integration closure

- The dedicated Authenticode parent-child handshake is scripted with exact
  `GetNamedPipeServerProcessId` parent and `GetNamedPipeClientProcessId` child
  binding, random launch token, restrictive low-integrity-compatible ACL,
  bounded overlapped I/O, cancellation settlement, and fail-visible cleanup.
- Local compile/runtime, full verifier `246/246`, and seven malformed-report
  rejection cases pass. Exact implementation
  `472b478c10dad6683ea867616f21c3636fe446de` passes Avorax CI `32680555167`
  and package push/PR `32680536082`/`32680555166`, including all platform jobs,
  six artifacts, checksums, lockfile SBOM, dependency/license evidence, and
  administrative MSI extraction. Evidence `b1c5b4e`, PR `#68`, merge
  `e883c187`, merged-main CI `32682998536`, packages `32682998541`, exact
  13-path guarded synchronization, and destination focused/full verification now
  pass. The destination verifier and standalone validator pass `246/246` in
  `489.4s`; lockfiles and the protected vault remain exact. Publication is
  skipped. Checkpoint 2216 has no remaining integration blocker.
- Same-user process-memory inspection, cross-identity authenticated/encrypted IPC,
  AppContainer/LPAC, installed LocalSystem, production signing, driver, and
  pre-execution proof remain technically limited or require external prerequisites.

## Checkpoint 2217 pipe-security read-back status

- Implemented and locally verified `GetSecurityInfo(SE_KERNEL_OBJECT)` read-back of exactly
  `DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION` under `READ_CONTROL`,
  before event/connect/helper launch. Exact protected SYSTEM/current-user DACL and
  low-integrity no-write-up label mismatches are fail-visible.
- Corrected focused `1/1`, adjacent handshake `2/2`, complete Authenticode
  `54/13`, source contracts `647/647`, Flutter `838/838`, locked workspaces,
  release builds/smoke, and definitive verifier `247/247` in `467.6s` pass. Seven
  malformed reports are rejected. Exact implementation `a518e93` passes CI
  `32687717433` and package push/PR `32687664061`/`32687717444`, including all six
  packages, checksums, SBOM, and administrative MSI extraction with publication
  skipped. Evidence `5fe8dd2`, PR `#69`, merge `3fe2b87`, evidence-head and
  merged-main CI/packages, exact 12-path synchronization, destination
  Authenticode `62/13`, and destination verifier/validator `247/247` now pass.
  Checkpoint 2217 has no remaining integration blocker.
- The control intentionally does not request the full SACL,
  `ACCESS_SYSTEM_SECURITY`, or `SeSecurityPrivilege`. `LABEL_SECURITY_INFORMATION`
  is mandatory-label-only evidence. Same-user privileged mutation/inspection,
  trusted in-process code, SYSTEM/kernel compromise, encrypted cross-identity IPC,
  AppContainer/LPAC, installed LocalSystem, production signing, driver, and
  pre-execution protection remain blocked or technically limited.

## Checkpoint 2218 client-security read-back status

- **Verified and integrated:** after exact client endpoint and parent-PID
  validation, the low-integrity helper uses a `GENERIC_WRITE | READ_CONTROL`
  handle and its current process-token SID to read back the exact DACL and
  mandatory label before token transfer. Failure is visible and has no weaker
  retry. Benign client `1/1`, complete Authenticode `63/13`, source contracts
  `648/648`, strict lint, locked workspaces, release trust smoke, Flutter
  `838/838`, and safety/dependency gates pass. Definitive verifier/validator
  passes `248/248` in `470.1s`; eight malformed reports are rejected. Evidence
  `eb11c81`, PR `#70`, merge `1e453005`, evidence/merged-main CI and packages,
  exact 12-path synchronization, destination Native/Local/Guard/Flutter/lint/
  release/trust-smoke checks, and destination verifier `248/248` in `484.1s`
  pass. Locks and the vault remain exact; publication is skipped.
- `READ_CONTROL` does not add `WRITE_DAC`, `WRITE_OWNER`, full-SACL access,
  `ACCESS_SYSTEM_SECURITY`, or `SeSecurityPrivilege`. No dependency or lockfile
  change is required.
- Same-user privileged mutation/inspection, trusted in-process code, SYSTEM or
  kernel compromise, encrypted cross-identity IPC, AppContainer/LPAC, installed
  LocalSystem, production signing, driver, and pre-execution protection remain
  blocked or technically limited.

## Checkpoint 2219 handshake-DACL least-privilege status

- **Verified and integrated:** SYSTEM retains normalized full control, while
  the current-user ACE is reduced to normalized generic read plus generic write.
  Exact parent and child descriptor read-backs reject broader or narrower rights,
  including execute, delete, `WRITE_DAC`, and `WRITE_OWNER`. Source contract 649
  and definitive step 249 pass. Exact verifier/validator `249/249` in `470.3s`,
  source contracts `649/649`, and eight malformed-report rejections pass. Exact
  SHA `5171fb4e` passes CI `32702550130` and package push/PR
  `32702466511`/`32702550182`; all six packages, checksums, lockfile SBOM, and
  administrative MSI extraction pass with publication skipped. Evidence
  `be122479`, PR `#71`, merge `e6caf818`, evidence/merged-main CI and packages,
  exact 12-path synchronization, destination full workspaces/lint/release/
  trust-smoke/Flutter checks, and destination verifier `249/249` in `486.9s`
  pass. Checkpoint 2219 has no remaining integration blocker.
- **Ownership blocker:** the creator's token default owner is not changed or
  independently read back. If the current user owns the pipe, Windows ownership
  gives implicit `READ_CONTROL` and `WRITE_DAC` regardless of the narrower ACE.
  Point-in-time dual read-backs detect sampled drift but cannot prevent same-user
  descriptor mutation between checks.
- Authenticated/encrypted cross-identity IPC, AppContainer/LPAC, an installed
  LocalSystem boundary, production signing, driver enforcement, and pre-execution
  protection remain technically limited or require external prerequisites.

## Checkpoint 2220 handshake Owner Rights status

- **Scripted, not yet verified:** the pipe explicitly names and reads back the
  current process-token user as owner and applies exact Owner Rights `S-1-3-4`
  with only `READ_CONTROL`. A benign same-user reopen must prove `WRITE_DAC`
  denial while the existing parent/client protocol remains functional.
- Owner/SID/mask/flag/order adversarial tests, verifier step 250, exact validator
  scope, stale-249 rejection, source contract 650, and audit documents are
  scripted. No runtime, hosted, merge, synchronization, or destination result is
  claimed yet.
- Remaining blocker: this is still point-in-time same-user control, not
  encrypted cross-identity IPC. Existing handles, trusted same-user code,
  privileged ownership changes, injection/duplication, SYSTEM/administrators,
  kernel compromise, AppContainer/LPAC, installed LocalSystem, signing, driver
  enforcement, and pre-execution protection remain technically limited or need
  external prerequisites.
- **Local runtime verified, definitive pending:** corrected source contracts
  `650/650`, Owner Rights denial `1/1`, handshake `4/4`, Authenticode `57/13`,
  Native `493/13`, Local Core `536/536`, Guard `248/249`, strict lint, both
  locked workspaces, release/two-host trust smoke, and Flutter `838/838` pass.
  Definitive report/validator, lock/vault, hosted, integration, synchronization,
  and destination evidence are still blockers to checkpoint closure.
- **Definitive local evidence now verified:** exact `250/250` in `452.7s`, both
  validators, and nine malformed-report rejections pass. Lock blobs and the
  read-only protected-vault invariant remain exact. Remaining checkpoint
  blockers are hosted exact-head checks, normal merge, merged-main checks,
  guarded synchronization, and destination verification; the cross-identity
  and pre-execution technical limits remain.
- **Implementation-head hosted evidence now verified:** exact SHA
  `6f90f9234375ceb22107aba426401e38838ec9b8` passes CI `32712875828` and package
  push/PR runs `32712856310`/`32712875850`; both publication jobs are skipped.
  Six artifacts, all seven checksum rows, and the CycloneDX 1.6/569-component
  lockfile SBOM were independently checked. Remaining checkpoint blockers are
  evidence-head checks, normal merge, merged-main checks, guarded sync, and
  destination verification. Cross-identity IPC and pre-execution protection
  remain technically limited.
- **Checkpoint integration blockers closed:** evidence `a99b03a`, merge
  `2bd8956`, exact-head and merged-main CI/packages, guarded 12-path sync, full
  destination suites, and exact destination `250/250` validation pass. The
  checkpoint has no remaining integration blocker. Authenticated cross-identity
  IPC, AppContainer/LPAC or installed LocalSystem isolation, production signing,
  signed-driver enforcement, and demonstrated pre-execution protection remain
  technically limited or require external prerequisites; the overall antivirus
  goal remains active.

## Checkpoint 2221 - Handshake client-token binding

- **Local code path verified; hosted evidence pending:** the helper explicitly requests
  `SecurityImpersonation`; after reading its bounded message the parent uses
  `ImpersonateNamedPipeClient`, exact token state validation, and fail-visible
  `RevertToSelf`. Source contract `651/651`, exact verifier `251/251`, embedded
  and standalone strict validation, and nine malformed-report rejections pass.
  Exact implementation head `014e5b9`, evidence `b60f500`, merge `c4d9975`,
  hosted CI/packages, 12-path guarded synchronization, destination full suites,
  and exact destination verifier `251/251` pass. This checkpoint is closed.
- **Residual technical blocker:** this authenticates one connected same-user
  token. It does not prevent privileged process injection/handle duplication,
  encrypt IPC, change logon identity, establish a cross-identity service/UI
  protocol, provide AppContainer/LPAC, or prove signed-driver/pre-execution
  enforcement. Those installed and signing prerequisites remain external.

## Checkpoint 2222 - Client logon-session binding

- **Local and implementation-head hosted evidence verified:** launch-token and connected-client
  `TokenStatistics.AuthenticationId` plus `TokenSessionId` must match exactly,
  and the launch user SID must equal the pipe owner. Empty IDs, fixed-size
  query failures, drift, or reversion failure stop trust. Source contract 652,
  benign/adversarial tests, exact verifier step 252, strict validation, CI, and
  both final package workflows pass.
- **Residual technical blocker:** same-user cross-logon-session substitution is
  narrowed, but same-logon-session injection or handle duplication is not
  prevented and token uniqueness is not proven. IPC encryption, cross-identity
  authentication, AppContainer/LPAC, installed LocalSystem isolation,
  production signing, signed-driver enforcement, and demonstrated
  pre-execution protection remain technically limited or externally blocked.
- Normal integration, merged-main checks, guarded synchronization, and
  destination verification remain required before checkpoint closure. The
  overall antivirus goal remains active.
- **Full local regression blocker closed:** source contracts
  `652/652`, logon-session `2/2`, Authenticode `69/13`, Native `497/13` plus
  compiler `6/6`, Local Core `536/536`, Guard `248/249`, both locked workspaces,
  strict lint, and Flutter `838/838` pass. Locks and vault remain exact.
  Definitive/malformed-report and implementation-head hosted evidence also
  pass; integration, synchronization, and destination blockers remain.
- **Definitive local blocker closed:** exact `252/252` in `507.8s`, both strict
  validators, and nine malformed-report rejections pass. Remaining checkpoint
  blockers are normal merge, merged-main checks, guarded original-tree
  synchronization, and destination verification. The
  same-session/cross-identity/driver/pre-execution limits remain.
- **Implementation-head hosted blocker closed:** exact `0a24ac2` passes CI
  `32732523250` and package PR/push `32732523189`/`32732497575`. Push attempt 1
  retained a transient arm64 `hdiutil` resource failure after successful build
  and payload checks; failed-job-only attempt 2 passed unchanged. Both final
  bundles provide six artifacts, seven matching checksums, and CycloneDX
  1.6/569-component SBOM evidence with publication skipped. Normal merge,
  merged-main checks, guarded synchronization, and destination verification
  remain blockers to checkpoint closure.
- **Checkpoint integration blockers closed:** evidence `2f02714`, PR `#74`,
  merge `e644d77`, exact evidence-head and merged-main CI/packages, guarded
  12-path synchronization, full destination suites, and exact destination
  `252/252` validation in `496.7s` pass. The checkpoint has no remaining
  integration blocker. Same-session injection/handle duplication,
  cross-identity IPC, AppContainer/LPAC or installed LocalSystem isolation,
  production signing, driver enforcement, and demonstrated pre-execution
  protection remain technically limited or require external prerequisites;
  the overall antivirus goal remains active.
- **Checkpoint 2223 residual boundary:** exact `TokenId`/`ModifiedId`
  before/after stability, adversarial regressions, source contract 653,
  verifier step 253, validator assertions, and documentation pass locally. The
  stability window does not
  bind the impersonation token object to the launch primary-token object,
  detect mutation wholly outside the window, prevent same-session injection or
  handle duplication, authenticate cross-identity IPC, provide
  AppContainer/LPAC or installed LocalSystem isolation, or establish signed-
  driver/pre-execution enforcement.
- **Checkpoint 2223 local verification blocker closed:** focused/full Rust and
  Flutter checks plus exact definitive `253/253` validation in `492.9s` pass,
  and nine malformed reports are rejected. Exact implementation-head CI/
  package evidence, evidence head, normal merge, merged-main checks, guarded
  synchronization, and destination verification still block checkpoint
  closure. Same-session injection/handle duplication, cross-identity IPC,
  AppContainer/LPAC, installed LocalSystem, signing, driver, and pre-execution
  limits remain external or technical blockers for the larger goal.
- **Checkpoint 2223 implementation-head hosted blocker closed:** exact
  `561ac536a55257b05f9c04ada55756d1ab676749` passes CI `32744796324` and
  package PR/push `32744796274`/`32744754697`. Both untouched consolidated ZIP
  streams independently pass the six-platform-artifact, seven-checksum, and
  CycloneDX 1.6/569-component SBOM contract; publication is skipped. Local
  Defender removed extracted MSI/EXE copies and was not weakened. Remaining
  checkpoint blockers are evidence-head checks, normal merge, merged-main
  checks, guarded synchronization, and destination verification. The larger
  installed/cross-identity/signing/driver/pre-execution blockers remain.
- **Checkpoint 2223 integration blockers closed:** evidence `6223ad2`, PR
  `#75`, merge `252a9ade`, exact evidence-head and merged-main CI/packages,
  guarded 12-path sync, full destination suites, and exact destination
  `253/253` validation in `484.8s` pass. A transient evidence-head arm64
  `hdiutil` failure remains recorded before the unchanged failed-job-only retry
  passed. The checkpoint has no remaining integration blocker. Same-session
  injection/handle duplication, cross-identity IPC, AppContainer/LPAC or
  installed LocalSystem isolation, production signing, driver enforcement,
  and demonstrated pre-execution protection remain technically limited or
  require external prerequisites; the overall antivirus goal remains active.
- **Checkpoint 2224 local verification blocker closed:** exact
  launch-primary `TokenId`/`ModifiedId` capture and same parent-held handle
  read-back after process creation and authenticated handshake, bounded cleanup,
  benign/adversarial tests, source contract 654, verifier step 254, validator,
  and documentation pass locally. Target `2/2`, complete Authenticode `65/13`,
  Native `501/13`, both locked workspaces, strict lint, Flutter `838/838`, and
  exact definitive `254/254` in `489.6s` pass; nine malformed reports are
  rejected.
- **Checkpoint 2224 residual technical blocker:** same-handle point-in-time
  evidence does not prove the created child process token remains identical,
  bind launch-primary and impersonation token objects, or prevent transient
  mutation, same-session injection, privileged handle duplication, or process
  injection. Cross-identity IPC, AppContainer/LPAC, installed LocalSystem,
  production signing, signed-driver enforcement, and demonstrated pre-execution
  protection remain technical or external prerequisites.
- **Checkpoint 2224 integration blockers closed:** implementation `c831149`,
  evidence `42d8c7c`, PR `#76`, merge `243bc84`, exact evidence-head and
  merged-main CI/packages, guarded 12-path synchronization, full destination
  Rust/Flutter suites, and destination verifier/validator `254/254` in `494.5s`
  pass. Publication was skipped; locks and the protected vault remain exact.
  The residual identity/isolation/driver limits above and the overall antivirus
  goal remain open, but checkpoint 2224 has no integration blocker.
- **Checkpoint 2225 scripted boundary:** the handshake is now duplex and the
  child waits for exact ACK flow control after its nonce write. Parent
  `TOKEN_QUERY` reads of the exact child process token at suspended creation and
  after authenticated handshake require primary type, launch SID/logon session,
  stripped restricted low-integrity safety state, and exact stability of the
  child token's own `TokenId` and `ModifiedId`; any process/token/profile/ACK/
  timeout/cleanup failure is fail-visible. Benign/adversarial tests, source
  contract 655, verifier step 255, validator, and documentation are scripted.
- **Checkpoint 2225 blocked design replaced:** the first focused runtime failed
  visibly because `CreateProcessAsUserW` produced a child token object with a
  distinct `TokenId` from the supplied launch-primary token on this host.
  Cleanup returned `ok`; the failed exact cross-object equality design is not
  counted as a pass. The repair binds launch identity/security properties and
  captures/rechecks the child token's own object identity instead. Repair tests
  pass `2/2`, complete Authenticode passes `52/52`, and definitive verification
  passes exact `255/255` in `521.1s`.
- **Checkpoint 2225 integration blockers closed:** evidence `d1a1e14`, PR
  `#77`, merge `5792c22`, evidence/merged-main CI and package runs, exact 12-
  path guarded synchronization, full destination Rust/Flutter suites, and
  destination verifier/validator `255/255` in `476.3s` pass. Publication was
  skipped; locks and the protected vault remain exact. Checkpoint 2225 has no
  integration blocker, while its technical limits and the larger goal remain.
- **Checkpoint 2225 residual technical blocker:** this remains point-in-time.
  Exact launch-primary/child `TokenId` equality is technically unavailable and
  not claimed. The viable control does not bind the distinct named-pipe
  impersonation token object to either primary token, prevent replacement or
  mutation after ACK, detect every transient between snapshots, or stop same-
  session process injection or privileged handle duplication. ACK is not a
  secret or encryption boundary. Cross-identity IPC, AppContainer/LPAC,
  installed LocalSystem, production signing, signed-driver enforcement, and
  demonstrated pre-execution protection remain technical/external blockers.
- **Checkpoint 2226 verified and integrated boundary:** the exact duplex handshake now remains
  open through trust work and response flush. Child emits one exact response-
  ready byte and waits for a distinct final ACK. Parent then revalidates the
  same launch `TokenId`/`ModifiedId` and exact live child `TOKEN_QUERY` identity,
  full restricted profile, and captured `TokenId`/`ModifiedId`. Source contract
  656, verifier step 256, exact validator scope, benign/adversarial tests, and
  documentation are implemented. Post-response `3/3`, Authenticode `55/55`,
  Native `506/15` plus compiler `6/6`, both locked workspaces, strict lint,
  release/two-host smoke, and Flutter `838/838` pass. Definitive verifier and
  validator pass `256/256` in `459.6s`, and ten malformed reports are rejected.
- **Checkpoint 2226 integration blockers closed:** evidence `bacf1cc`, PR
  `#78`, merge `bab872d`, evidence/merged-main CI and package runs, exact 12-
  path guarded synchronization, full destination Rust/Flutter suites, and
  destination verifier/validator `256/256` in `438.4s` pass. The evidence arm64
  retry and all support-wrapper failures remain retained and uncredited.
  Publication was skipped; locks and the protected vault remain exact.
  Checkpoint 2226 has no integration blocker, while its technical limits and
  the larger goal remain.
- **Checkpoint 2226 residual technical blocker:** this closes persistent
  post-initial-ACK drift only at a third point-in-time response-ready boundary.
  It does not cryptographically bind response bytes to token snapshots, bind
  the distinct impersonation token object, detect all transients, prevent
  mutation after final ACK or privileged same-session injection/handle
  duplication, encrypt/authenticate cross-identity IPC, provide AppContainer/
  LPAC or installed LocalSystem isolation, or establish signed-driver/pre-
  execution enforcement. External signing/installation prerequisites remain.
- **Checkpoint 2227 verified and integrated client reauthentication boundary:** after exact response-ready validation,
  parent binds the still-connected pipe client PID to the exact retained child
  process handle, freshly impersonates that connection, and repeats the full
  launch SID/logon-session/restricted low-integrity profile plus within-check
  token stability and mandatory revert proof before final ACK. Benign/adversarial
  tests, source contract 657, verifier step 257, validator, and documentation are
  scripted. Focused `2/2`, source contracts `657/657`, complete affected Rust,
  locked workspaces, strict lint/offline/release smoke, and Flutter `838/838`
  pass locally. Definitive verifier/validator passes exact `257/257` in `453.2s`
  and 12 malformed reports are rejected. Evidence `c63fb71`, PR `#79`, normal
  merge `9304681`, exact evidence/merged-main CI and packages, 12-path guarded
  synchronization, full destination Rust/Flutter checks, and destination
  verifier/validator `257/257` in `434s` pass. Publication is skipped; locks
  and the protected vault remain exact. Checkpoint 2227 has no integration
  blocker, while its technical limits and the larger goal remain.
- **Checkpoint 2227 residual technical blocker:** Windows may create a distinct
  impersonation token object per impersonation call, so cross-snapshot token-
  object identity is technically unavailable and not claimed. The control is
  point-in-time and does not cryptographically bind response bytes, catch every
  transient, prevent privileged same-session injection/handle duplication,
  encrypt/authenticate cross-identity IPC, provide AppContainer/LPAC or installed
  LocalSystem isolation, or establish signed-driver/pre-execution enforcement.
- **Checkpoint 2228 scripted response hash boundary:** exact flushed stdout is
  bound to a fixed domain, unsigned little-endian length, and SHA-256 in one
  exact 41-byte frame sent on the retained pipe. Parent validates the frame,
  freshly reauthenticates the client and primary-token evidence before ACK, and
  later requires exact collected stdout length/digest before JSON parsing or
  publisher trust. Three Rust regressions, source contract 658, verifier step
  258, validator, and all documentation are scripted; execution, hosted,
  integration, synchronization, and destination evidence remain pending.
- **Checkpoint 2228 residual technical blocker:** the digest is unkeyed evidence
  on an existing same-user authenticated endpoint, not a secret MAC, encryption,
  cross-identity authentication, or durable token-object binding. It detects
  post-frame stdout changes but cannot stop a sufficiently privileged same-
  session actor from injecting the helper, duplicating handles, or changing both
  stdout and frame before authentication. AppContainer/LPAC, installed
  LocalSystem, production signing, signed-driver enforcement, and demonstrated
  pre-execution protection remain external or technical blockers.
- **Checkpoint 2228 closure and supersession:** the unkeyed response hash
  boundary passed focused, full local, hosted, merged-main, guarded destination,
  and exact `258/258` verification. It is integrated at merge `ab43569` and is
  now deliberately superseded in source by checkpoint 2229 HMAC-SHA-256; its
  historical evidence remains valid for that merged revision.
- **Checkpoint 2229 scripted per-launch response MAC:** exact flushed stdout is
  bound with domain-separated HMAC-SHA-256 under the canonical 36-byte random
  launch token already authenticated on the retained pipe. Parent and child
  retain their exact per-launch key copies; parent verifies in constant time
  before strict JSON or publisher trust. Wrong-key, mutation, length, malformed-
  frame, and bound failures are scripted with benign text-only fixtures. Source
  contract 659, verifier step 259, validator, and documentation are complete;
  exact lock review, source contracts `659/659`, retained response tests `3/3`,
  and wrong-launch-key test `1/1` pass. Full affected/workspace/Flutter/release
  regression, exact `259/259` definitive verification in `441.1s`, both strict
  validators, and 15/15 adversarial report rejections pass. Hosted evidence,
  integration, synchronization, and destination proof remain pending.
- **Checkpoint 2229 repaired PS5 stdin blocker:** Windows PowerShell 5.1 could
  prefix redirected JSON stdin with a UTF-8 BOM in the release Authenticode
  harness and six user wrappers. The harnesses now select BOM-less UTF-8 before
  process/stdin creation and restore prior encoding in `finally`; strict product
  parsing is not weakened. Parsers `8/8`, source `659/659`, twelve consecutive
  Authenticode smokes, six sequential wrapper smokes, and definitive execution
  pass. The signed/installed driver self-test remains externally blocked, but its
  same stdin path is repaired and source-contracted.
- **Checkpoint 2229 implementation-head hosting complete:** exact `eaa4ba3`
  passes all five CI jobs in `32812956518` and every package/consolidation job
  in push/PR runs `32812914763`/`32812956466`; publication is skipped. Both
  untouched consolidated artifacts pass exact six-platform-file, seven-
  checksum, and CycloneDX 1.6/569-component in-stream validation. Evidence-
  head, normal merge, merged-main, guarded synchronization, and destination
  proof remain pending and are not implied by this result.
- **Checkpoint 2229 integration blockers closed:** evidence `f0c72e1`, PR
  `#81`, normal merge `36d67798`, evidence/merged-main CI and package runs,
  23-path guarded synchronization, full destination Rust/Flutter checks, and
  destination verifier/validator `259/259` in `473s` pass. The synchronization
  summary failure and broad-Rust wrapper concurrency attempt remain visible and
  uncredited; exact repair/reruns pass. Publication is skipped, locks and vault
  remain exact. Checkpoint 2229 has no integration blocker, while its residual
  technical limits and the larger antivirus goal remain.
- **Checkpoint 2229 residual technical blocker:** the HMAC key is present in the
  child environment and memory and travels on same-user IPC. Same-user process-
  memory or environment read access, privileged injection, or handle duplication
  may recover it or modify both stdout and MAC before authentication. This is not
  encryption, cross-identity authentication, durable token-object binding,
  AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution
  enforcement.

## Checkpoint 2230 Closure And Residual Limits

- **Execution and integration blockers closed:** source `660/660`, focused/full
  Rust and Flutter regression, strict lint, release smoke, local/destination exact
  `260/260` verifier/validator evidence, hosted CI/packages, PR `#82`, normal
  merge `9690c84`, and guarded 12-path destination synchronization pass.
  Publication was skipped; no release or installation occurred.
- **Residual technical blocker:** the launch/MAC key is absent from the child
  environment but remains in parent/child memory and crosses the authenticated
  same-user pipe. Process-memory read access, privileged injection, pipe-handle
  duplication or observation, compromised endpoints, administrator/SYSTEM, or
  kernel access may recover it or modify both response and MAC. This user-mode
  control is not encryption, cross-identity IPC, AppContainer/LPAC, installed
  LocalSystem, signed-driver, or pre-execution enforcement.
- **Evidence limits remain explicit:** the package source suite skips three
  Windows symlink-positive fixtures because optional symlink privilege is
  unavailable; no execution of those cases is claimed. This does not reopen the
  checkpoint integration blocker or change the residual technical boundary.

## Checkpoint 2231 Closure And Residual Limits

- **Execution and integration blockers closed:** HMAC `2/2`, adjacent pipe/PID/
  token/MAC checks, Native `515/515` plus compiler `6/6`, Local `536/536`, Guard
  `248/248 + 249/249`, both locked workspaces, strict lint/offline/release,
  Flutter `838/838`, and source `661/661` pass locally and at destination where
  applicable. Exact local/destination verifier evidence passes `261/261` in
  `466.4s`/`452.7s`; strict validators and `8/8` adversarial reports pass at
  both stages. Evidence `0f49c76`, PR `#83`, merge `b678027`, hosted and
  merged-main CI/packages, and guarded destination synchronization pass with
  publication skipped.
- **Same-user key boundary remains:** key confirmation proves possession only by
  data arriving on the already PID/token-bound same-user pipe at that point.
  The key remains in parent/child memory and crosses the pipe. Same-user memory
  read, privileged injection, pipe observation, and handle duplication may
  recover it or subvert an endpoint.
- **Domain separation, not independent keys:** handshake confirmation and
  response binding use the same random per-launch key with distinct fixed HMAC
  domains. This is deliberate and dependency-free, but it is not encryption,
  cross-identity authentication, durable secret storage, or durable token-object
  identity.
- **Platform enforcement remains blocked:** this checkpoint does not provide
  AppContainer/LPAC, installed LocalSystem E2E, production signing, a signed
  driver, or demonstrated pre-execution blocking. Those need separate design,
  credentials, disposable elevated hosts, and driver/code-signing evidence.
- **No malware or release claim:** tests use protocol bytes and benign child
  fixtures only. No candidate content is executed; Defender is not weakened;
  nothing is installed, released, or published.

## Checkpoint 2232 Local Evidence And Residual Limits

- **Local evidence verified:** best-effort Authenticode launch-key zeroization
  passes focused `1/1`, Native `516/516`, source `662/662`, strict lint/release,
  PS7/PS5 trust smoke, Flutter `838/838`, and exact verifier/validator `262/262`
  in `459.7s`; `8/8` malformed reports are rejected. Exact implementation,
  evidence, and merged-main CI plus Windows/Linux/macOS package evidence pass
  with publication skipped. Normal PR `#84` merge, guarded exact 15-path
  synchronization, destination full Rust/Flutter/build evidence, destination
  `262/262` in `555.3s`, and `8/8` destination malformed-report rejections pass.
  Checkpoint 2232 is closed while the complete antivirus goal remains active.
- **Owned-buffer scope only:** `zeroize 1.9.0` wraps the parent and child owned
  key strings plus the bounded child pipe-read buffer. Borrowed key slices avoid
  the prior raw 36-byte derived-key array. Key-bearing containers intentionally
  omit `Debug` so routine formatting does not disclose the key.
- **Residual blocker:** best-effort zeroization cannot guarantee removal of
  compiler temporaries, HMAC internals, allocator or OS copies, process dumps,
  paging, or forensic remnants, and it cannot prevent same-user or privileged
  memory reads while the key is live. It is not secure erasure, durable secret
  storage, cross-identity isolation, AppContainer/LPAC, installed LocalSystem,
  signed-driver, or pre-execution enforcement.
- **Safety boundary unchanged:** only protocol bytes and benign fixtures may be
  used; no candidate content is executed, no live malware is retained, Defender
  is not weakened, and nothing is installed, released, or published.

## Checkpoint 2233 Scripted State And Residual Limits

- **Execution remains pending:** the fixed-key implementation, benign tests,
  source contract 663, verifier step 263, validator, adversarial script, and
  documentation are scripted as one batch. No parser, format, compile, test,
  verifier, hosted, integration, synchronization, or destination pass is yet
  claimed for checkpoint 2233.
- **Owned-copy reduction:** all four key owners use
  `Zeroizing<[u8; 37]>` rather than `Zeroizing<String>`. The final byte is a zero
  overflow guard; parent writes exactly 36 bytes and child accepts exactly 36,
  then moves the same fixed buffer without an owned `String` copy.
- **Residual memory blocker:** the key must remain live while handshake and
  response HMACs run. Fixed ownership cannot guarantee cleanup of compiler or
  UUID/HMAC temporaries, stack/register spills, allocator/OS/pipe copies, dumps,
  paging, or forensic remnants and cannot prevent same-user or privileged live
  memory access.
- **Platform blocker unchanged:** this does not provide secure erasure,
  encryption, cross-identity authentication, AppContainer/LPAC, installed
  LocalSystem evidence, production signing, signed-driver behavior, or
  pre-execution enforcement. Those require separate privileged/test-host and
  signing prerequisites; Windows security is not weakened to simulate them.
- **Local execution blocker closed:** fixed-buffer, zeroization, HMAC, pipe,
  complete Authenticode, full Native/Local/Guard, both workspaces, lint,
  offline/release/PS7/PS5.1 smoke, Flutter `838/838`, and source `663/663` pass.
  The `Zeroizing<[u8; 37]>` overflow guard is therefore locally exercised and
  the owned `String` copy is absent by contract. Definitive exact-263 evidence,
  hosted CI/packages, merge, synchronization, and destination proof remain
  open; no pre-execution or secure-erasure claim is made meanwhile.
- **Definitive local blocker closed:** `263/263`, both required PS5.1 strict
  validations, and `8/8` adversarial rejections pass with exact locks and vault.
  Hosted exact-head, merge, synchronization, and destination evidence remain
  open.
- **Optional PS7 validator-host limitation:** PowerShell 7 auto-converts ISO JSON
  timestamp strings to `DateTime`, so the current strict validator rejects that
  host before evidence evaluation. This failure is visible and uncredited;
  Windows PowerShell 5.1 is the verified validator host. It does not affect the
  passing PS7 release smoke, fixed `Zeroizing<[u8; 37]>` overflow guard, removed
  owned `String` copy, or the unchanged secure-erasure/pre-execution limits.
- **Implementation-head hosting blocker closed:** exact `00e9f3c` passes CI
  `32865480443` and package push/PR `32865302082`/`32865480497`; both untouched
  consolidated ZIPs match GitHub digests and pass exact non-extracting package,
  checksum, and 569-component SBOM validation. Publication is skipped.
- **Remaining checkpoint integration work:** evidence-head checks, normal merge,
  merged-main evidence, guarded synchronization, and independent destination
  verification remain open. Production signing, installed elevated/service
  behavior, kernel/pre-execution enforcement, and secure erasure remain blocked
  by their existing external prerequisites and are not claimed.
- **Checkpoint integration blocker closed:** evidence `646000b`, normal merge
  `7467bfd`, evidence/merged-main CI and package artifacts, guarded 12-path
  synchronization, destination full suites, exact `263/263` in `454.1s`, both
  strict validators, and `8/8` adversarial rejections pass. The WindowsApps
  Python reparse alias caused one visible uncredited verifier stop; the explicit
  verified Python binary closed that host-path issue without weakening checks.
- **Residual blockers unchanged:** fixed launch-key storage does not provide
  secure erasure, live-memory protection, cross-identity isolation, installed
  elevated/service evidence, production signing, signed-driver behavior, or
  pre-execution enforcement. Checkpoint 2233 is closed; those external platform
  prerequisites and the complete antivirus project remain active.

## Checkpoint 2234 Scripted State And Residual Limits

- The checkpoint-2233 PowerShell 7 timestamp-coercion blocker has a scripted
  repair: all nine bounded JSON readers preserve strings through native
  `DateKind=String` where available and remain compatible with Windows
  PowerShell 5.1.
- The definitive exact 263-step verifier is scripted to require both distinct,
  checked host executables. Strict JSON string and explicit ISO timestamp
  validation remain unchanged; no coercion is accepted as evidence.
- Source contract 664 and existing malformed-report rejection coverage account
  for the implementation, but no checkpoint-2234 passing result is claimed
  before execution.
- This does not close production signing, installed elevated/service, signed-
  driver, secure-erasure, cross-identity, or pre-execution blockers and does not
  change any antivirus engine verdict.

- **Local parser blocker closed:** focused Windows PowerShell 5.1 and PowerShell
  7 probes plus the same prior 263-step report pass, and source `664/664` passes.
  The definitive exact `263/263` report passes in `469.9s` under both strict
  hosts; adversarial full-suite reports reject `16/16`.
- **Defender test-host interaction remains visible:** one combined root-
  workspace attempt is uncredited after Defender rejects its separate Native
  test executable with OS error 225. No Defender setting changed. Standalone
  Native passes `517/517` plus compiler `6/6`, so this is not used as a product
  failure or a complete-workspace success claim.
- **Implementation-head hosting blocker closed:** exact `708e939` passes CI
  `32878421258` and package push/PR `32878368995`/`32878421335`; both
  consolidated ZIPs match GitHub digests and pass exact non-extracting package,
  checksum, and 569-component SBOM validation. Publication is skipped.
- Evidence-head, merge, guarded synchronization, and destination evidence remain
  open. External signing/service/driver/pre-execution blockers remain unchanged.
- **Checkpoint integration blocker closed:** evidence `a5cf1c5`, normal merge
  `c969351`, evidence/merged-main hosted evidence, guarded 11-path destination
  synchronization, source `664/664`, exact `263/263` in `468.9s`, dual-host
  validators, and `16/16` adversarial rejections pass. The first misquoted
  parse-only helper command is visible and uncredited; the corrected check left
  no stage.
- **Residual blockers unchanged:** three package symlink-positive tests require
  optional Windows symlink privilege and remain explicit skips. Production
  signing, installed elevated/service evidence, signed-driver behavior,
  cross-identity isolation, secure erasure, and pre-execution enforcement still
  require their external prerequisites. Checkpoint 2234 is closed; the complete
  antivirus project remains active.

## Checkpoint 2235 Scripted State And Residual Limits

- Overflow, UTF-8 truncation, negative-diagnostic quality inflation, late
  decisive-evidence omission, and missing synthetic TrustStore provenance have
  scripted repairs and benign/adversarial regressions. Source contract 665 and
  exact verifier cardinality 264 bind the new boundary.
- No checkpoint-2235 passing result is claimed before focused and broad local
  execution, strict definitive/adversarial report validation, hosted exact-head
  evidence, merge, guarded synchronization, and destination verification.
- Production calibration remains blocked by approved representative corpora,
  false-positive/sensitivity targets, and analyst review. Live malware is not
  an acceptable prerequisite; only benign/synthetic/EICAR-safe evidence may be
  used under project policy.
- Installed UI/service E2E, production signing, signed-driver/kernel behavior,
  and pre-execution enforcement retain their existing external prerequisites.
  This checkpoint does not weaken Windows security or claim those capabilities.

- **Local execution blocker closed:** focused and broad Native/Local/Guard,
  both locked workspaces, Flutter `838/838`, source `665/665`, parsers,
  changed-crate strict Clippy, exact locks, and protected vault pass.
- **Visible unrelated lint debt:** workspace-wide `-D warnings` remains blocked
  by existing API `enum_variant_names` and `items_after_test_module` findings.
  Changed-crate strict Clippy passes, so this is neither hidden nor credited as
  checkpoint success; API cleanup is separate from bounded risk fusion.
- **Remaining checkpoint work:** exact 264-step definitive/adversarial report
  evidence, hosted exact-head CI/packages, normal merge, guarded sync, and
  independent destination verification remain open.

- **Definitive local blocker closed:** exact `264/264` in `503.5s`, both strict
  validator hosts, and `16/16` malformed-report rejections pass. The wrong
  initial pwsh path stopped before step one and is not credited.
- **Remaining integration work:** implementation/evidence-head hosted checks,
  normal PR merge, merged-main evidence, guarded original-tree synchronization,
  and independent destination verification remain open.

- **Implementation-head hosting blocker closed:** exact `8fa9630` passes CI
  `32892108074` and package push/PR `32891914251`/`32892108020`; both
  consolidated ZIPs match GitHub digests and pass exact non-extracting package,
  checksum, and 569-component SBOM validation. Publication is skipped.
- **Remaining integration work:** evidence-head hosted checks, normal PR merge,
  merged-main evidence, guarded original-tree synchronization, and independent
  destination verification remain open. External calibration/signing/service/
  driver/pre-execution blockers remain unchanged.

- **Checkpoint integration blocker closed:** evidence `57ce163`, normal merge
  `5fc30c9`, evidence/merged-main hosted CI and packages, guarded exact 13-path
  synchronization, destination source `665/665`, broad/focused engine and
  Flutter suites, exact `264/264` in `488.3s`, dual-host validation, and
  `16/16` adversarial rejections pass. The WindowsApps Python reparse run and
  malformed helper/check command drafts are visible and uncredited.
- **Residual blockers unchanged:** production calibration needs approved
  representative corpora, targets, and analyst review. Installed elevated/
  service E2E, production signing, cross-identity isolation, signed-driver
  behavior, secure erasure, and pre-execution enforcement retain external
  prerequisites. Checkpoint 2235 is closed; the complete project remains active.

## Checkpoint 2236 Scripted State And Residual Limits

- Native process-start command evidence, fake-block action text, dead behavior
  helper wiring, arithmetic overflow, unbounded lowercase allocation, provider
  inventory, tests, verifier/validator, source contract 666, and documentation
  have scripted repairs. Execution evidence remains pending.
- Browser-data access remains disabled until a trusted per-process path-access
  stream exists. Infostealer correlation remains disabled until credential/
  wallet reads, archive staging, and outbound network activity are bound to one
  process under bounded retention.
- Persistence correlation remains disabled until trusted registry/file autorun
  write telemetry and parent trust state exist. Suspicious child lineage remains
  disabled because the event has a parent PID but no verified parent image.
- The explicit process-start API is post-launch and currently has no installed
  app/service callsite. It emits evidence and recommendations only; process stop,
  quarantine mutation, durable monitoring, installed service E2E, signed-driver,
  kernel, and pre-execution proof retain existing prerequisites.
- No checkpoint-2236 passing result is claimed during scripting. Focused, broad,
  definitive exact 265-step, adversarial, hosted, merge, guarded sync,
  destination, lock, and protected-vault evidence remain open.

Focused and broad local execution now passes, including Native `538/538` plus
19 deliberate child-entrypoint ignores and compiler `6/6`, both locked workspace
modes, Flutter `838/838`, and source contracts `666/666`. Locks and the protected
vault remain exact. The API wiring, missing trusted telemetry, definitive
265-step/adversarial evidence, hosted proof, integration, and destination items
above remain genuine blockers or open evidence and are not presented as solved.

Definitive local report evidence now passes exact `265/265` in `523.1s` under
both strict hosts, and `16/16` isolated mutations reject. Hosted, merge, guarded
sync, destination, installed process telemetry, durable service wiring, process
mutation, driver/kernel, and pre-execution proof remain open.

Checkpoint 2236 hosted, merge, guarded-sync, and destination evidence is now
closed. PR `#88`, exact-head/merged-main CI and package matrices, 25-blob
zero-delete synchronization, destination broad suites, exact `265/265` in
`490.8s`, two-host validation, and adversarial `16/16` all pass. This removes the
checkpoint evidence blocker only. Trusted path-access, credential/network,
persistence-write, and parent-image telemetry are still absent, so those four
providers remain disabled. Installed durable process-loop wiring, termination/
quarantine mutation, production calibration, signing, installed E2E,
cross-identity isolation, driver/kernel enforcement, and pre-execution blocking
remain genuine blockers.

## Checkpoint 2237 Process Observation Native Wiring

- The app-lifetime Windows CIM snapshot is scripted to feed at most 16 valid,
  relevant command-bearing observations into Native file-plus-behavior review.
  Exact allowlists bypass before file I/O and every failed/limited review is
  counted and surfaced through bounded Flutter diagnostics. Each process
  executable read is hard-limited to 16 MiB. Exact 266-step and source contract
  667 verification are scripted but not yet run.
- This does not close installed monitoring: collection runs inside the desktop
  app on a two-minute best-effort timer and can race short-lived processes.
  Guard has no trustworthy commandline field, no installed service event stream
  is proven, and POSIX collection supplies no command data.
- Process stop/quarantine based on behavior remains disabled. Parent-image
  lineage, correlated browser/credential/network/persistence telemetry,
  production calibration, signed driver/kernel interception, and pre-execution
  blocking remain blocked by their documented prerequisites.
- No checkpoint-2237 passing result is claimed during scripting. Focused,
  broad, definitive, hosted, merge, sync, and destination evidence remain
  pending.

Focused and broad local evidence now passes: Native `542/542` plus 19 deliberate
ignores and compiler `6/6`, Local `540/540`, Guard `248/248 + 249/249`, both
locked workspaces, Flutter `838/838`, and source contracts `667/667`. The exact
no-skip/no-Defender verifier passes `266/266` in `472.7s`; two strict hosts
accept the report and adversarial variants reject `16/16`. This removes the
local checkpoint evidence blocker only. Hosted, merge, guarded synchronization,
destination, installed durable process observation, production calibration,
mutation, driver/kernel, and pre-execution evidence remain open or blocked.

Checkpoint 2237 hosted, merge, guarded-sync, and destination evidence is now
closed. PR `#89`, exact-head/merged-main CI and package matrices, 24-blob
zero-delete synchronization, destination broad suites, exact `266/266` in
`499.0s`, two-host validation, and adversarial `16/16` all pass. This removes
the checkpoint evidence blocker only. Installed durable process collection,
trusted Guard commandline telemetry, verified parent-image lineage, correlated
browser/credential/network/persistence telemetry, production calibration,
process mutation, signed driver/kernel interception, and pre-execution blocking
remain genuine blockers or disabled capabilities.

## Checkpoint 2238 Protection Loop Generation Binding

- A stopped/replaced process-snapshot or finite watch-poll loop previously did
  not invalidate an already-running asynchronous evaluation. Late completion
  could publish stale active/attention/limited state or an old loop event. Exact
  lifecycle generations and benign race regressions are now scripted.
- This checkpoint deliberately does not claim hard cancellation. Already-started
  CIM, subprocess, or Local Core work may continue until its existing bounded
  timeout/reap path finishes; its old generation only loses publication rights.
- Focused/adjacent tests, Flutter `840/840`, source contracts `668/668`, exact
  no-skip/no-Defender `267/267` in `469.8s`, both strict report validators, and
  adversarial rejection `16/16` pass locally. Locks, processes, and protected-
  vault inventory remain exact. Implementation-head hosted evidence passes;
  evidence-head, merge, guarded-sync, and destination evidence remain pending
  for checkpoint 2238.
- Installed durable process/file telemetry, shorter observation gaps, trusted
  Guard commandlines, parent-image identity, mutation, production calibration,
  driver/kernel interception, and pre-execution blocking remain genuine blockers.

Checkpoint 2238 hosted, merge, guarded-sync, and destination evidence is now
closed. PR `#90`, exact evidence-head/merged-main CI and package matrices,
13-blob zero-delete synchronization, destination Flutter `840/840`, source
contracts `668/668`, exact `267/267` in `464.2s`, two-host validation, and
adversarial `16/16` all pass. This removes the checkpoint evidence blocker
only. Hard cancellation of already-started work, installed durable monitoring,
trusted Guard commandlines, verified parent lineage, mutation, production
calibration, signed driver/kernel interception, and pre-execution blocking
remain genuine blockers or disabled capabilities.

## Checkpoint 2239 Scan Cancellation Ownership

- A late cancellation previously could overlap a replacement scan after the
  old scan released `_scanStartInFlight`; cancellation publication and fallback
  process kill were not bound to an exact scan generation/process lease.
- Any unrelated Local Core `_call` completion could clear the static active-scan
  process slot. This made fallback cancellation unavailable or susceptible to
  retargeting after an await. Exact lease ownership is now scripted.
- Per-generation outcome waiting, replacement-start rejection, visible busy
  controls, benign races/subprocess checks, exact 268-step validation, and source
  contract 669 are scripted but not yet run.
- The current-user-runtime cancellation token is still shared across Local Core
  processes and is not authenticated to a job ID. Cross-instance serialization,
  installed service ownership, kernel cancellation, and pre-execution blocking
  remain genuine blockers and are not claimed.

## Checkpoint 2240 Scan Job Cancellation Binding

- The shared Local Core marker is replaced by one strict, bounded token per
  canonical random scan UUID. Scan/cancel IPC, progress, subprocess ownership,
  response, and token content are explicitly job-bound.
- Exact 269-step verification and source contract 670 are scripted but not yet
  run. This removes accidental stale/wrong-job cancellation only after evidence
  passes.
- Same-user code able to observe a UUID remains inside the capability boundary.
  Cross-identity authentication, installed service ownership, hard interruption
  inside one file inspection, driver/kernel cancellation, and pre-execution
  blocking remain genuine blockers.

## Checkpoint 2241 Cooperative In-Engine Cancellation

- Exact-job cancellation now reaches Native content reads and provider/archive
  boundaries. Interrupted files publish no partial verdict and remain counted
  as unscanned; cancellation-state parse/access failure aborts visibly.
- Exact 270-step verification and source contract 671 pass locally. The
  definitive no-skip/no-Defender report is exact `270/270` in `462.7s`; both
  independent validators pass and adversarial missing-step/scope reports are
  rejected. Hosted, merge, synchronization, and destination evidence pass;
  destination definitive is exact `270/270` in `517.9s` and checkpoint 2241 is
  closed.
- Hard interruption of an active OS read, static analyzer substep, bounded
  archive collect/inflate, synchronous rule/ML operation, or Windows trust
  helper remains technically unavailable in this in-process design. Moving
  every detector behind safely killable isolated workers would require a larger
  authenticated IPC/resource-confinement design and separate regression audit.
- Same-user capability secrecy, installed service ownership, cross-identity
  authentication, driver/kernel cancellation, and pre-execution blocking remain
  genuine blockers. No checkpoint-2241 passing result was claimed during
  scripting.

Focused and broad local component evidence now passes: cancellation `9/9`,
Native `568`, Local Core `546/546`, Flutter `847/847`, source contracts
`671/671`, strict Native/Local lint, locked release build, analyzer, format, and
dual PowerShell parsing. The definitive exact `270/270` report and both
independent validators now pass; hosted/integration/destination evidence also
passes. Workspace-wide strict Clippy remains blocked by two
unchanged API `items_after_test_module` findings and one unchanged API
`enum_variant_names` finding under Rust 1.96; the checkpoint-owned large enum
was repaired and targeted strict lint passes.

## Checkpoint 2242 Cooperative Archive Inflate Cancellation

- Entry-level and 64-KiB inflate-output checkpoints now pass exact typed
  cancellation/probe propagation, focused/full suites, source contract
  `672/672`, and definitive verifier `271/271` with dual validation plus
  missing-step/scope rejection. Hosted, merge, guarded `13/13` synchronization,
  and destination exact `271/271` evidence pass; checkpoint 2242 is closed.
- One active `flate2` decoder read cannot be hard-interrupted by the in-process
  callback. Moving it behind a safely killable worker requires authenticated
  IPC and resource-confinement work beyond this checkpoint.
- Native static archive metadata/relationship inspection remains a separate
  synchronous bounded substep. Same-user capability secrecy, installed service
  ownership, cross-identity authentication, driver/kernel cancellation, and
  pre-execution blocking remain genuine blockers.
- No checkpoint-2242 passing result was claimed during scripting; local proof
  and closure proof are now complete without changing the residual technical
  limits above. One default-parallel Native run exposed a short Authenticode
  key-confirmation race; exact and serial reruns pass, so concurrency hardening
  remains a separate test/reliability lead rather than credited closure proof.

## Checkpoint 2243 Parallel Authenticode Helper Lifecycle

- Bounded stdout/stderr drainers are now established before the initial
  authenticated helper handshake. Early process exit returns bounded child
  output, exit status, worker and cleanup evidence instead of discarding the
  diagnostic behind a short key-confirmation error.
- The reproduced root race was synchronous completion of overlapped pipe I/O:
  the old path trusted the call-site transfer variable. All four key/response
  operations now call `GetOverlappedResult` after immediate or pending success
  before applying exact byte-count checks.
- A second reproduced race was byte-stream coalescing of confirmation plus the
  next response byte. Message-framed local named-pipe transport now preserves
  write boundaries while keeping exact oversized-message rejection.
- Four benign helper children must authenticate and response-bind concurrently
  without a product-wide lock. A separate benign child fills more than an
  ordinary pipe buffer with stderr and exits before handshake; the parent must
  fail visibly, reap it, and report the capped marker. No retry or trust verdict
  is permitted.
- Verifier step 272, strict cardinality/scope validation, source contract 673,
  and all audit documents are scripted. No checkpoint-2243 passing result is
  claimed during scripting.
- **Remaining blocker:** this bounded four-child test is not unbounded production
  load, installed-service/cross-identity stress, kernel mediation, signed-driver
  proof, or pre-execution blocking. Diagnostic text is deliberately capped and
  lossy-normalized. Those limits do not weaken fail-closed trust handling.
- **Verified locally:** focused `2/2`, 20 focused repetitions, complete
  Authenticode default-parallel `83`/`21`, 20 complete repetitions, Native
  `555`/`21` plus compiler `6/6`, Local Core `546/546`, Flutter `847/847`, source
  contracts `673/673`, analyzer, strict component lint, parsers, formatting and
  locked release build pass. Exact 272-step and hosted/integration/destination
  closure remain pending.

## Checkpoint 2244 Static Archive Analysis Cancellation

- The previous blocker that static ZIP metadata and OOXML relationship analysis
  observed cancellation only after the whole substep is repaired in source:
  parser/entry/copy/inflate checkpoints now propagate fallible errors through
  the Native engine before verdict publication.
- Focused/full local and source contract 674 pass. Mandatory step 273 passes in
  an exact `273/273` definitive report, dual validators accept it, and both
  missing-step and missing-parser-scope adversarial copies are rejected.
  Hosted, integration, and destination evidence was still required at that
  local stage; the closure evidence below satisfies that requirement.
- **Hosted outage recovered for this head:** uncredited zero-job and transient
  arm64 `hdiutil` resource-unavailable runs are retained, while exact-head CI
  `32987569318`/`32987888207` and independent PR packages `32987888192` pass.
  Publication is skipped and consolidated artifact `9614177410` passes bounded
  non-extracting inventory/checksum/SBOM validation. PR `#96` remained open at
  that recovery stage; the closure evidence below supersedes that blocker.
- Remaining technical limitation: one already-running `flate2` read is not
  preempted. Non-archive analyzer work, synchronous rule/ML calls, trust helper
  calls, installed service identity, driver mediation, and pre-execution
  blocking remain outside this checkpoint.
- Reputation remains disabled without an authenticated privacy-reviewed
  backend. Browser-data, credential/network, persistence-write, and parent-image
  lineage behavior engines remain disabled without trusted correlated telemetry.
  Checkpoint 2244 does not fake-enable them.

### Checkpoint 2244 Closure

Evidence head `0b566a4ce45e9818db840b09156fbf4a2d0b25f0`, normal PR `#96`
merge `c0cd92f7f10e6205ad209435c24367f54f8cd8b0`, merged-main CI/packages,
bounded artifact validation, guarded `14/14` synchronization, and destination
exact `273/273` verification now pass. Report SHA-256 is
`b5c403d2795bbbd9ff544a6ba431b45c14c2620ec6b99557afb93fed1079a405`;
locks and the protected vault remain exact. The prior integration/destination
blocker is closed.

The technical limits remain: one entered decoder read is not preempted;
non-archive analysis, synchronous rule/ML and trust calls, installed service
identity, driver mediation, and pre-execution blocking require separate work.
Disabled reputation and behavior engines remain disabled with their blockers.

## Checkpoint 2245 Non-Archive Static Cancellation

- Entropy, string-reference/IP/term/UTF-16, PE section/import/debug, and script
  term passes now have scripted cooperative checkpoints and fail-visible error
  propagation. Verifier step 274 and Source contract 675 have not run during
  this implementation-first scripting phase.
- One already-running UTF-8 or UTF-16 lossy/lowercase normalization, one term
  search, one bounded parser/system call, synchronous rule/ML call, or Windows
  trust operation is not forcibly interrupted. The next explicit checkpoint
  observes cancellation; non-archive input remains capped at 64 MiB.
- Reputation remains disabled without an authenticated privacy-reviewed
  backend. Browser-data, credential/network, persistence-write, and parent-image
  lineage engines remain disabled without trusted correlated telemetry.
- Installed service ownership, authenticated cross-identity IPC, signed driver
  mediation, kernel cancellation, and demonstrated pre-execution blocking remain
  blockers. Checkpoint 2245 makes none of those claims.
- During the implementation-first phase no passing result was claimed. Exact
  `274/274`, hosted, merge, package, guarded-sync, and destination evidence were
  prerequisites for checkpoint closure.

Focused `15/15`, analyzer `99/99`, Native `574` plus compiler `6/6`, strict
Native Clippy, and Source contract `675/675` now pass. One earlier complete run
hit five Defender error-225 child-start blocks; the individual tests and clean
complete rerun pass without changing Defender. At that stage exact verifier 274
and all integration/destination prerequisites remained blockers to closure.

Local Core `546/546`, Flutter analyze and `847/847`, strict Local Core lint, and
the locked release build now pass. Locks and the exact protected-vault invariant
remain unchanged. Definitive exact `274/274` and hosted/integration/destination
evidence were the remaining checkpoint-closure blockers.

Definitive local verification now passes exact `274/274` in `539.7s`, and both
independent PowerShell hosts accept the report and reject missing-step and
missing-required-scope adversarial copies. Hosted exact-head CI/packages, normal
merge, guarded synchronization, destination regression, and destination
definitive evidence remain checkpoint-closure blockers. The technical limits
and disabled-engine blockers above remain unchanged.

Implementation-head CI and both independent package matrices now pass, with
publication skipped and bounded non-extracting artifact validation complete.
The remaining checkpoint blockers are exact evidence-head checks, normal PR
merge, merged-main checks/packages, guarded synchronization, destination full
regression, and destination definitive verification. Technical product limits
and disabled-engine blockers remain unchanged.

### Checkpoint 2245 Closure Update

Those checkpoint-specific evidence blockers are resolved. Evidence-head and
merged-main CI/packages pass, publication is skipped, PR `#98` is normally
merged as `48cf932ff23211961386cbf220d05026821322c7`, guarded and post-test sync
checks pass `22/22`, and destination focused/full/quality checks pass.
Destination definitive verification passes exact `274/274` in `502.5s` with
independent PS5/PS7 acceptance. Locks and the protected vault remain exact.

Checkpoint 2245 is closed, but the product blockers listed above are not
resolved: cooperative cancellation is not hard preemption; reputation and
correlation-dependent engines remain disabled; installed cross-identity
service ownership, production signing/notarization, signed driver/kernel
mediation, and demonstrated pre-execution blocking remain blocked or technically
limited. The complete antivirus hardening goal remains active.

## Checkpoint 2246 Native Provider Cancellation And Pack Limits

- Signature/rule byte searches and ML loops previously observed job cancellation
  only after a complete provider call. Rule and required-context evaluation also
  rebuilt a bounded but potentially 64 MiB lowercase sample per item. Shared
  fallible search and one-sample-per-provider paths are now locally verified for normal
  files and bounded archive entries.
- Local sibling pack loading previously had a 2 MiB per-file bound but no exact
  aggregate file/count/byte ceiling. Locally verified fail-visible ceilings are 32
  provider files, 256 inspected directory entries, 16 MiB aggregate bytes,
  4,096 loaded signatures, and 4,096 loaded rules. Construction failure cannot
  partially activate a database.
- Exact verifier step 275, strict validation, Source contract `676/676`, focused
  `19/19`, full component/workspace tests, and release build pass. Definitive
  local evidence is exact `275/275` in `488.1s`; independent PS5/PS7 validators
  pass and reject missing-step/scope mutations. Hosted, merge, package, guarded
  sync, and destination evidence remain pending, so the checkpoint is not closed.
- Remaining technical limitation: callbacks are cooperative, not hard
  interruption. One provider lossy/lowercase normalization, one at-most-64-KiB
  search chunk, the bounded ML contribution sort, an entered filesystem/system
  call, or Windows trust helper work may complete before the next checkpoint.
  Installed cross-identity service ownership, production-calibrated ML/rules,
  signed-driver/kernel mediation, and pre-execution blocking remain separate
  blockers. Reputation and correlation-dependent engines remain disabled.

## Checkpoint 2247 Provider Text Normalization Cancellation

- The whole-sample signature/rule provider normalization gap is locally repaired
  with exact callbacks around at-most-64-KiB input chunks and fail-visible
  propagation before evidence publication. Focused, adjacent, broad, and exact
  `276/276` definitive evidence passes after the scripting batch was frozen.
- One active provider normalization chunk is still cooperative rather than
  forcibly interrupted. Separate static-analyzer normalizations, one search
  chunk, bounded ML sorting, entered filesystem/system calls, and Windows trust
  helper work also remain cooperative or isolated rather than hard-preemptive.
- Exact verifier `276/276`, Source `677/677`, broad regression, dual-validator,
  adversarial report, and exact vault/lock evidence now pass. Hosted exact-head
  CI/packages, normal PR merge, merged-main evidence, guarded synchronization,
  and destination reruns remain checkpoint-closure prerequisites.
- Installed cross-identity service ownership, authenticated service IPC,
  production-calibrated rules/ML, signed driver/kernel mediation, demonstrated
  pre-execution blocking, and Defender replacement remain genuine blockers or
  unsupported claims. Reputation and correlation-dependent providers remain
  disabled until their documented authenticated backend/telemetry prerequisites
  exist.

## Checkpoint 2248 Static Text Normalization Cancellation

- The implementation, five benign regression fixtures, verifier step 277,
  Source contract 678, and documentation are scripted. No checkpoint-2248 test
  has run during this scripting phase. After the batch froze, focused, broad,
  strict, locked-build, Source `678/678`, and definitive exact `277/277` local
  evidence passed. Hosted exact-head, package, merge, guarded-sync, and
  destination evidence remain checkpoint-closure blockers.
- Static normalization cancellation is cooperative. One at-most-64-KiB text
  chunk, one UTF-16 interval, one term search, or one entered system operation
  can complete before the next callback. ZIP entry-name normalization remains
  one header-bounded interval of at most 65,535 bytes.
- Installed cross-identity service ownership, authenticated service IPC,
  production signing and calibration, signed driver/kernel mediation,
  demonstrated pre-execution blocking, and Defender replacement remain genuine
  blockers or unsupported claims.
- Reputation and correlation-dependent behavior engines remain disabled until
  their documented authenticated backend and trusted identity-bound telemetry
  prerequisites exist. Checkpoint 2248 and the complete goal remain active.

## Checkpoint 2249 ZIP Entry-Name Normalization Cancellation

- Four previously uncheckpointed ZIP name conversions are now scripted through
  the shared callback-aware normalizer. Verifier step 278, Source contract 679,
  four benign regressions, and all documentation are scripted. No
  checkpoint-2249 test has run during this scripting phase.
- Verification remains a blocker: focused and full local suites, exact
  `278/278`, dual validators, exact-head hosted CI/packages, normal merge,
  guarded synchronization, and destination reruns are still required.
- Cancellation remains cooperative, not preemptive. One admitted ZIP header
  name of at most 65,535 bytes, one entered system operation, archive inflate
  read, other bounded normalization/search interval, ML sort, or Windows trust
  call may complete before its next checkpoint.
- Installed cross-identity service ownership, authenticated service IPC,
  production signing/calibration, signed driver/kernel mediation, demonstrated
  pre-execution blocking, and Defender replacement remain genuine blockers or
  unsupported claims.
- Reputation and correlation-dependent engines remain disabled until an
  approved authenticated backend and trusted identity-bound telemetry exist.
  Checkpoint 2249 and the complete antivirus goal remain active.

Focused/full local, Source `679/679`, locked build, strict lint, safety, lock,
and vault checks now pass. The local-verification portion of the second bullet is
superseded; definitive exact `278/278`, adversarial report evidence, exact-head
hosted CI/packages, normal integration, guarded synchronization, and destination
reruns remain checkpoint-closure blockers.

Definitive local `278/278`, dual-host validation, and missing-step/scope
rejection now pass and supersede those local blockers. Exact-head hosted
CI/packages, normal PR/merged-main integration, guarded synchronization, and
destination focused/definitive reruns remain open.

## Checkpoint 2250 Static Term-Search Cancellation

- Shared term-search implementation, six benign regressions, verifier step 279,
  exact-cardinality/scope validation, Source contract 680, and documentation are
  scripted. No checkpoint-2250 test has run during this scripting phase.
- Verification is the immediate blocker: focused and adjacent cancellation
  tests, Source `680/680`, full local suites, definitive exact `279/279`, dual
  validator and hostile-report checks, exact-head hosted CI/packages, normal
  integration, guarded synchronization, and destination reruns remain required.
- Cancellation is cooperative. One admitted at-most-64-KiB static term-search
  candidate chunk, UTF-16 decode interval, separate bounded structured traversal,
  entered system operation, ML sort, or trust call may complete before the next
  callback. Existing input caps bound work but do not provide hard preemption.
- Installed cross-identity service ownership, authenticated service IPC,
  production signing/calibration, signed driver/kernel mediation, demonstrated
  pre-execution blocking, and Defender replacement remain genuine blockers or
  unsupported claims. Reputation and correlation-dependent engines remain
  disabled pending an approved authenticated backend and trusted telemetry.
- Checkpoint 2250 and the complete antivirus hardening goal remain active.

Focused/adjacent, Source `680/680`, full Native/Local/Flutter, locked workspace
rerun/release, strict lint, formatting, parser, lock, and vault checks pass. This
supersedes the local-verification portion of the second bullet. The initial
workspace Defender OS-error-225 child-launch block is evidenced by passing exact
reruns and required no Defender change. Definitive exact `279/279`, hostile
report validation, hosted, integration, guarded synchronization, and destination
evidence remain checkpoint-closure blockers.

Definitive local verification now passes exact `279/279`, and both PS5/PS7
validators accept the authentic report while rejecting missing-step and
missing-scope copies. This supersedes the remaining local and hostile-report
portions above. Exact-head hosted CI/packages, normal integration, guarded
synchronization, and clean destination reruns remain checkpoint-closure
blockers.

## Checkpoint 2251 Static Reference-Search Cancellation

- Shared marker and reference-body cancellation boundaries, eight benign
  regressions, verifier step 280, exact-cardinality/scope validation, Source
  contract 681, and documentation are scripted. No checkpoint-2251 test has run
  during this scripting phase.
- Verification is the immediate blocker: focused and adjacent reference/static
  cancellation tests, Source `681/681`, full local suites, definitive exact
  `280/280`, dual-validator/adversarial report checks, exact-head hosted
  CI/packages, normal integration, guarded synchronization, and destination
  reruns remain required.
- Cancellation is cooperative. One admitted at-most-64-KiB reference-marker
  candidate or UTF-8-safe body chunk, another bounded analyzer interval,
  entered system operation, ML sort, archive read, or trust call may finish
  before the next callback. Existing input caps are not hard deadlines.
- Installed cross-identity service ownership, authenticated service IPC,
  production signing/calibration, signed driver/kernel mediation, demonstrated
  pre-execution blocking, and Defender replacement remain genuine blockers or
  unsupported claims. Reputation and correlation-dependent engines remain
  disabled pending an approved authenticated backend and trusted telemetry.
- Checkpoint 2251 and the complete antivirus-hardening goal remain active.

Focused/full local checks, both locked workspace variants, strict lint,
Flutter/Dart, Source `681/681`, exact locks, and read-only vault inventory now
pass. This supersedes the local-verification portion above. Definitive exact
`280/280`, adversarial report validation, exact-head hosted CI/packages, normal
integration, guarded synchronization, and destination reruns remain closure
blockers.

Definitive local `280/280` is no longer a blocker: the exact report passes with
zero failures in `662.9` seconds, independent PS5/PS7 validation accepts it, and
both validators reject missing-step and missing-scope adversarial copies. Report
SHA-256 is
`17b60115b7a419310646789d4dc8b17b157b3e62ab0f1b2da6ec48d0dbe8b5f4`.
Exact-head hosted CI/packages, normal integration, guarded synchronization, and
destination reruns remain checkpoint-closure blockers. The cooperative limit
and the broader installed-service/driver/production blockers remain unchanged.

## Checkpoint 2252 Static Structured-Indicator Cancellation

- Structured callback boundaries, nine benign regressions, verifier step 281,
  exact-cardinality/scope validation, Source contract 682, and documentation
  are scripted. No checkpoint-2252 test has run during this scripting phase.
- Focused/adjacent tests, Source `682/682`, full local suites, definitive exact
  `281/281`, dual-validator/adversarial checks, exact-head hosted CI/packages,
  normal integration, guarded synchronization, and destination reruns remain
  checkpoint-closure blockers.
- Cancellation remains cooperative. One at-most-64-KiB carrier, candidate,
  line, token, path, host, optical-marker, or email-field chunk, another bounded
  analyzer interval, entered operation, archive read, ML sort, or trust call
  may finish before the next callback. Existing input caps are not deadlines.
- Installed cross-identity service ownership and authenticated IPC, production
  signing/calibration, signed driver/kernel mediation, demonstrated
  pre-execution blocking, and Defender replacement remain genuine blockers or
  unsupported claims. Reputation/correlation engines remain disabled pending
  an approved authenticated backend and trusted telemetry.
- Checkpoint 2252 and the complete antivirus-hardening goal remain active.

Focused/adjacent and full local checks now pass, including Source `682/682`,
structured cancellation `9/9`, all String Indicator `54/54`, reference `8/8`,
Native 632 active plus compiler `6/6`, Local Core `546/546`, locked workspace,
release/offline builds, strict lint, Flutter `847/847`, and Dart `14/14`. The
first Native Clippy failure was fail-visible and repaired with a generic
callback helper; exact reruns pass. This supersedes the local-verification part
of the second bullet. Definitive `281/281`, adversarial report validation,
exact-head hosted CI/packages, normal integration, guarded synchronization, and
destination reruns remain checkpoint-closure blockers. Broader installed
service/IPC, driver/kernel, production-accuracy, pre-execution, and Defender-
replacement blockers are unchanged.

Definitive local `281/281` is no longer a blocker: zero steps are non-passing in
`786.9s`, independent PS5/PS7 validation accepts report SHA-256
`039f30500f4a842f7f9785653df8a49b4b01f22963ecb1c340cb7265a2815153`, and
both validators reject missing-step and missing-scope copies. The initial
Defender block of a generated debug test binary and missing-file retry are
uncredited; an exact focused run and complete from-start rerun pass with test-
only debug/incremental metadata disabled and no Defender weakening. Exact-head
hosted CI/packages, normal integration, guarded synchronization, and destination
reruns remain checkpoint-closure blockers. Broader product blockers and the
complete antivirus-hardening goal remain unchanged and active.

Checkpoint 2252 closure blockers are now cleared: PR `#113`, merge `4370debc`,
exact-head and merged-main CI/packages, bounded artifact/SBOM review, guarded
`11/11` synchronization, focused destination checks, and destination exact
`281/281` plus dual validation pass. The disk-full and Defender-blocked attempts
remain uncredited and documented; Defender was not weakened. The verifier's
top-level failure is fail-visible, but a thrown `Invoke-Step` is not appended as
a failed step before report serialization. Improving that per-step diagnostic is
an open verification-harness hardening item, not an antivirus clean verdict.

The checkpoint is closed, but product blockers remain: cooperative rather than
preemptive cancellation for entered operations, installed cross-identity
service ownership and authenticated IPC, production accuracy/calibration,
production signing/notarization, signed driver/kernel mediation, demonstrated
pre-execution blocking, and Defender replacement. Reputation and correlated
telemetry engines remain disabled until their separate trust prerequisites are
met. The complete antivirus-hardening goal remains active.

## Checkpoint 2253 Failed-Step Reporting Blocker

The checkpoint-2252 observability gap is now **scripted for repair but not yet
verified**. Schema v2 records an invoked failure as one terminal failed step,
uses `failure_kind=orchestration` for non-step failures, and preserves the
original throw. A benign intentional first-step failure and six dual-host
report-mutation rejections are scripted as verifier step 282; Source contract
683 pins the boundary.

The blocker remains open until focused execution, exact `282/282` definitive
verification, hosted evidence, normal integration, guarded synchronization,
and destination verification pass. This is evidence-harness hardening only; it
does not reduce the installed service/IPC, production calibration, production
signing/notarization, signed driver/kernel, pre-execution, or Defender-
replacement blockers.

Focused evidence now clears the local producer/validator behavior blocker:
dual parsers, Source `683/683`, one authentic terminal failed-step report, and
six dual-host adversarial rejections pass after the fail-visible `$Host`
variable repair. Broad regression, exact `282/282`, hosted, integration,
guarded-sync, and destination closure remain required. Product blockers are
unchanged.

Broad local regression is no longer a checkpoint blocker: complete Native and
Local Core, locked all-features workspace, standalone Native locked/offline,
locked release workspace, strict Native/Local/Guard lint, Flutter analyze and
`847/847`, Dart `14/14`, and formatting pass. Definitive exact `282/282`, hosted
exact-head evidence, normal integration, guarded synchronization, and
destination verification remain checkpoint-closure blockers. Installed
service/IPC, production calibration/signing, driver/kernel, pre-execution, and
Defender-replacement blockers remain unchanged.

Definitive local verification is no longer a checkpoint blocker: exact
`282/282` passes in `768.6s`, independent PS5/PS7 validation accepts report
SHA-256 `3ad67ee7b7d6aed00b4aafece608a61b664aff1949dd67c2a0b04ff1a592894d`,
and both reject missing-step and missing-scope copies. Exact lock, residue, and
protected-vault audits pass. Hosted exact-head CI/packages, normal integration,
guarded synchronization, and destination verification remain checkpoint-
closure blockers. Product blockers remain unchanged.

Implementation-head hosting is no longer a checkpoint blocker: exact commit
`3fc1fb0907cc194211064784f9ba95cc34f32732` passes PR CI `33091441105` and
Desktop Packages `33091417691`; publication is skipped. Consolidated artifact
`9655292568` matches its GitHub digest and passes bounded non-extracting exact
8-root/6-package/7-checksum/CycloneDX-1.6/569-component review. Evidence-head
CI/packages, normal integration, merged-main CI/packages, guarded sync, and
destination verification remain checkpoint-closure blockers. Installed
service/IPC, production calibration/signing, driver/kernel, pre-execution, and
Defender-replacement blockers remain unchanged.

Checkpoint 2253 closure blockers are now cleared: evidence `09e5a9c`, PR
`#115`, merge `61311d9`, exact-head and merged-main CI/packages, bounded
artifact/SBOM reviews, guarded `12/12` zero-delete synchronization, corrected
focused destination checks, and destination exact `282/282` plus dual-host
validation pass. The rejected Python reparse-shim attempt and invalid zero-path
blob summary remain uncredited; both failed visibly and their corrected routes
pass. The failed-step observability gap from checkpoint 2252 is closed.

Product blockers remain: same-user repository evidence is not remote
attestation; process termination can prevent report serialization; monitoring
and cancellation remain best-effort/cooperative at documented boundaries;
installed cross-identity service ownership and authenticated IPC, production
accuracy/calibration, production signing/notarization, signed driver/kernel
mediation, demonstrated pre-execution blocking, and Defender replacement remain
open. Reputation and correlated telemetry engines remain disabled until their
trust prerequisites are met. The complete antivirus-hardening goal remains
active.

## Checkpoint 2254 ZIP EOCD Cancellation Blocker

The bounded ZIP EOCD traversal now has a scripted cooperative cancellation
repair, but it is not yet verified. Both central-directory consumers, three
benign runtime regressions, mandatory verifier step 283, exact validator scope,
and Source contract 684 are present. Focused, broad, definitive `283/283`,
hosted, integration, guarded-sync, and destination evidence remain checkpoint
blockers.

The residual limitation remains explicit: one at-most-4,096-candidate chunk may
finish before cancellation is observed, and the existing 65,557-byte work bound
is not a deadline. Installed cross-identity service ownership/authenticated IPC,
production calibration/signing, signed driver/kernel mediation, demonstrated
pre-execution blocking, and Defender replacement remain separate blockers.
No checkpoint-2254 test has run during this scripting phase.

Focused execution clears the local implementation blocker: EOCD `3/3`, full
ZIP `45/45`, adjacent cancellation filters `4/4` each, Source `684/684`, and
dual-host parsing pass. Broad regression, definitive exact `283/283`, hostile
report validation, hosted exact-head, integration, guarded synchronization, and
destination evidence remain checkpoint blockers. Product blockers are unchanged.

Broad local regression, locked/offline and release builds, strict linting,
Flutter/Dart regression, lock integrity, zero product processes, and the exact
read-only vault invariant now pass. This clears the broad local blocker only.
Definitive exact `283/283`, hostile report validation, hosted exact-head,
integration, guarded synchronization, and destination evidence remain open.

Definitive exact `283/283`, hostile missing-step/missing-scope rejection, and
exact implementation-head CI/packages now clear those checkpoint blockers.
Evidence-head hosted runs, normal integration, merged-main evidence, guarded
synchronization, and destination verification remain open. Product-level
installed-service, kernel, pre-execution, calibration, and Defender-replacement
blockers are unchanged.

Evidence-head, normal integration, merged-main, guarded synchronization, and
destination verification now pass, closing checkpoint 2254. Cooperative EOCD
cancellation remains bounded but non-preemptive. Installed cross-identity
service/IPC, signed-driver/kernel mediation, production accuracy/signing,
demonstrated pre-execution blocking, and Defender replacement remain open.

## Checkpoint 2255 Open Evidence

Checkpoint 2255 scripts cooperative PE resource section mapping cancellation,
but no checkpoint test has run yet. Focused `3/3`, formatting, Native and full
local regression, Source contract 685, exact definitive `284/284`, hostile
validator mutations, hosted exact-head evidence, integration, guarded sync, and
destination verification remain blockers to a verified checkpoint claim.

Even after those gates pass, one at-most-4,096-section chunk can complete before
the next callback. Installed cross-identity service/IPC, signed driver/kernel
mediation, production calibration/signing, demonstrated pre-execution blocking,
and Defender replacement remain separate product blockers.

Focused, broad, exact `284/284`, hostile report, lock, process, and protected-
vault evidence now clear the local Checkpoint 2255 blockers. Exact-head hosted
CI/packages, normal integration, merged-main evidence, guarded destination sync,
and destination verification remain open. Cooperative at-most-4,096-section
latency and the separate installed-service, kernel, signing/calibration,
pre-execution, and Defender-replacement blockers remain unchanged.

Exact implementation-head hosted CI `33117139169` and package runs
`33117139213`/`33117116754` now clear the branch/PR package blocker, including
six platform artifacts, checksums, CycloneDX 1.6 with 569 unique refs, and
skipped publication. Evidence-head CI/packages, normal integration,
merged-main evidence, guarded destination synchronization, and destination
verification remain open. Cooperative latency and all separate installed-
service, driver/kernel, signing/calibration, pre-execution, and Defender-
replacement blockers remain unchanged.

Evidence-head, normal integration, merged-main, guarded synchronization, and
destination verification now pass, closing checkpoint 2255. Cooperative
at-most-4,096-section latency remains bounded but non-preemptive. Installed
cross-identity service/IPC, signed-driver/kernel mediation, production
accuracy/signing, demonstrated pre-execution blocking, and Defender replacement
remain open product blockers.

## Checkpoint 2256 Open Evidence And Limits

Checkpoint 2256 file discovery cancellation and bounds are scripted but not yet
verified. Five focused benign regressions, Source contract 686, exact definitive
`285/285`, hostile validator mutations, broad locked/all-features regression,
hosted exact-head CI/packages, normal integration, guarded synchronization, and
destination verification remain blockers to closure.

Even after those pass, discovery is cooperative: one OS directory or metadata
operation, one at-most-128-entry chunk, and the bounded priority sort can finish
before cancellation is observed. The 250,000 full/custom cap bounds stored path
count, not aggregate path bytes, filesystem I/O, elapsed time, or kernel work.
Installed cross-identity service ownership, signed-driver/kernel mediation,
production calibration/signing, demonstrated pre-execution blocking, and
Microsoft Defender replacement remain separate open product blockers.

Focused Checkpoint 2256 blockers are cleared by file discovery `5/5`, Source
`686/686`, and Local Core `551/551`. Broad locked/all-features workspace,
definitive exact `285/285`, hostile report validation, hosted exact-head,
integration, guarded synchronization, and destination verification remain open.
All cooperative and separate installed-service/driver/product blockers remain.

Broad and definitive local blockers are now cleared: both locked workspace
variants, strict Local Core Clippy, locked release build, Flutter/Dart suites,
exact verifier `285/285`, independent PS5/PS7 acceptance, and hostile
missing-step/missing-scope rejection pass. Hosted exact-head CI/packages,
normal integration, guarded synchronization, and destination verification remain
checkpoint blockers. Cooperative discovery latency, aggregate path-byte/I/O
bounds, installed cross-identity service ownership, signed-driver/kernel
mediation, production calibration/signing, demonstrated pre-execution blocking,
and Defender replacement remain separate open product blockers.

Hosted implementation-head CI and package blockers are cleared on exact
`75a9620`: PR CI plus PR/push package matrices and both bounded non-extracting
artifact reviews pass, while publication is skipped. Exact evidence-head runs,
normal merge, merged-main evidence, guarded synchronization, and destination
verification remain checkpoint blockers. All cooperative, installed-service,
driver/kernel, production-calibration, pre-execution, and Defender-replacement
product blockers remain unchanged.

Evidence-head, normal integration, merged-main, guarded `13/13`
synchronization, and destination focused plus exact `285/285` verification now
pass, closing Checkpoint 2256. Cooperative OS-call/chunk/sort latency and the
lack of aggregate path-byte, I/O, and elapsed-time bounds remain technical
limits. Installed cross-identity service ownership and authenticated IPC,
signed-driver/kernel mediation, production accuracy/signing, demonstrated
pre-execution blocking, and Microsoft Defender replacement remain open product
blockers; checkpoint closure does not clear them.

## Checkpoint 2257 Path-Memory Blocker Delta

Checkpoint 2257 scripts aggregate encoded-path-payload caps of 8 MiB for Quick
and 128 MiB for Full/Custom discovery and replaces non-cancellable sorting with
stable, cancellable at-most-128-path priority buckets. Exhaustion, overflow, and
callback errors are fail-visible and cannot become a clean scan. Source
contract 687 and definitive step 286 / exact `286/286` were scripted before
testing and are now locally verified.

The earlier lack of any aggregate path-payload ceiling and cancellation during
priority ordering is superseded once verification passes. Exact total memory
remains technically limited because `Vec`, `PathBuf`, allocator overhead, the
source vector, and transient bucket allocations are outside the payload count.
Filesystem I/O, elapsed time, and kernel work also remain unbounded by this
control. Focused, broad, definitive, hosted, integration, guarded-sync, and
destination evidence are checkpoint blockers. Installed cross-identity service
ownership, signed driver/kernel mediation, production calibration/signing,
pre-execution blocking, and Defender replacement remain product blockers.

Focused Checkpoint 2257 verification now passes Source `687/687`, the five new
memory regressions, all overlapping discovery/walker/full/cancellation filters,
Local Core `556/556`, and strict Clippy. The checkpoint's local focused blocker
is cleared. Broad locked regression, exact `286/286`, and adversarial validation
also pass. Hosted exact-head evidence, integration, guarded synchronization, and
destination verification remain checkpoint blockers. Exact total memory,
filesystem I/O/time/kernel work, installed-service, driver, production,
pre-execution, and Defender-replacement limits remain unchanged.

Both locked workspace variants, the locked release build, Flutter `847/847`,
Dart `14/14` and `6/6`, and all analyzers pass for Checkpoint 2257. The broad
local regression blocker is cleared. Exact `286/286` and dual-host adversarial
report validation pass. Hosted exact-head evidence, integration, guarded
synchronization, and destination verification remain checkpoint blockers.
Resource, service, driver, production, pre-execution, and Defender-replacement
blockers remain.

Checkpoint 2257 exact implementation-head CI and both package workflows now
pass, including bounded non-extracting artifact/checksum/SBOM review and skipped
publication. The hosted implementation-head blocker is cleared. Evidence-head
reruns, normal merge, merged-main evidence, guarded destination synchronization,
and destination verification remain checkpoint blockers. Exact total resource,
installed-service, driver, production, pre-execution, and Defender-replacement
blockers remain unchanged.

Evidence-head, normal merge, merged-main, guarded destination synchronization,
and destination exact `286/286` now pass, clearing all Checkpoint 2257 evidence
blockers. The checkpoint is closed. Aggregate encoded path payload is bounded,
but exact total RAM, filesystem I/O, elapsed time, kernel work, installed cross-
identity service ownership, signed driver/kernel mediation, production
calibration/signing, demonstrated pre-execution blocking, and Defender
replacement remain product blockers or technical limits.

Checkpoint 2258 reduces the discovery resource blocker by scripting checked
Quick `100,000` and Full/Custom `1,000,000` application work-item ceilings,
Quick `600s` and Full/Custom `3,600s` monotonic discovery deadlines, and total
Quick `1,800s` plus Full/Custom `10,800s` elapsed budgets. All limit exits are
fail-visible and incomplete. Hosted integration, guarded sync, and destination
evidence remain checkpoint blockers until commands actually pass. Verifier step
287 and Source contract 688 pass locally.

Final-source formatting, Source `688/688`, resource `6/6`, Local Core
`562/562`, strict Clippy, both locked Rust workspace variants, and the locked
all-feature release build now pass. The later local definitive `287/287`,
independent dual-host validation, and all six expected adversarial rejections
passed but are superseded by a cancellation/progress honesty repair. Final-source
focused/broad and definitive `287/287` now pass on the repair, including all six
expected adversarial rejections, but are superseded by the zero-byte progress
repair. Final-source formatting, focused/broad suites, release build, definitive
`287/287`, dual-host validation, and all six adversarial rejections now pass.
Hosted exact-head, integration, guarded-sync, and destination blockers remain.

Exact implementation-head CI and both package matrices now pass on `709e8a9`,
including bounded non-extracting review of both consolidated artifacts with
publication skipped. The remaining checkpoint blockers are evidence-head and
merged-main hosting, normal integration, guarded destination synchronization,
and destination verification.

Exact filesystem I/O bytes, syscall count, kernel work, storage latency, CPU,
allocator/`PathBuf` RAM, and interruption of a stalled kernel/filesystem call
remain technically limited. Installed cross-identity service watchdogs, signed
driver/kernel mediation, production calibration/signing, demonstrated
pre-execution blocking, and Defender replacement remain separate blockers.

Evidence-head and merged-main CI/packages, normal PR `#125` integration,
bounded artifact review, guarded `14/14` synchronization, destination focused
checks, and destination exact `287/287` now clear every Checkpoint 2258 evidence
blocker. The checkpoint is closed. Exact filesystem/kernel resource accounting,
preemption of stalled OS calls, installed cross-identity service ownership,
signed driver/kernel mediation, production calibration/signing, demonstrated
pre-execution blocking, and Defender replacement remain product blockers or
technical limits.

## Checkpoint 2259 Blocker Delta

Checkpoint 2259 implements a bounded answer to two remaining user-mode scan risks:
unbounded standard full-file SHA-256 reads and total elapsed limits that were
observed only before/after, not inside, one retained Native inspection. The new
shared 1 GiB ceiling and cancellation-first in-target callback classification
are fail-visible; timeout files cannot become clean or produce partial verdicts.
Verifier step 288, Source `689/689`, focused and overlapping tests, complete
changed-crate suites, strict Clippy, both locked workspaces, locked release
build, Flutter/Dart, exact `288/288`, and all six dual-host adversarial
rejections pass. The local evidence blocker is cleared. Hosted exact-head,
integration, guarded synchronization, and destination verification remain the
Checkpoint 2259 blockers.

Exact implementation-head CI and both package matrices now pass on `97e16e7`,
including bounded non-extracting checksum/SBOM review with publication skipped.
The hosted implementation-head blocker is cleared. Evidence-head hosting,
normal integration, merged-main evidence, guarded destination synchronization,
and destination verification remain checkpoint blockers.

Hard preemption remains technically blocked in user mode: one entered
filesystem, Authenticode/security-provider, or kernel call may stall past a
deadline. The 1 GiB byte cap is not exact I/O/syscall/kernel/CPU/RAM/time
accounting. Installed cross-identity watchdog ownership, signed driver/kernel
mediation, production calibration/signing, demonstrated pre-execution blocking,
and Defender replacement remain separate product blockers. Checkpoint 2259 does
not claim to clear them, and the full antivirus-hardening goal remains active.

Evidence-head and merged-main CI/packages, normal PR `#127` integration,
bounded artifact review, guarded `13/13` synchronization, destination focused
checks, and destination exact `288/288` now clear every Checkpoint 2259 evidence
blocker. The checkpoint is closed. Hard preemption of entered OS calls, exact
filesystem/kernel resource accounting, installed cross-identity service
ownership, signed driver/kernel mediation, production calibration/signing,
demonstrated pre-execution blocking, and Defender replacement remain product
blockers or technical limits.

## Checkpoint 2260 Blocker Delta

Checkpoint 2260 removes the known fail-open binding where automatic quarantine
could recompute and accept bytes different from the Native verdict SHA-256. The
scripted store now requires a valid matching result path/hash, hashes the
already-opened single-link source, checks Unix or Windows file identity before
move, repeats identity before copy-source removal, and emits a rescan-required
failure without finalized metadata when evidence changed. Six harmless tests,
exact-`288/288` definitive verifier/validator coverage, and Source contract 690
are scripted, but local execution is still pending.

Guard Service now uses the same open-handle hash and identity boundary while
retaining its existing expected process-observation SHA-256. This closes the
equivalent Guard path-reopen gap without claiming pre-execution prevention.

One technical blocker remains: portable cross-platform user mode cannot make the
last identity comparison and following path rename/removal an atomic filesystem
transaction. A privileged writer may race that narrow window. Existing payload
SHA-256 verification and authenticated finalization recovery keep detected
failure visible, but prevention against administrators, SYSTEM, or kernel
compromise requires a different privilege/kernel architecture and is not
claimed. Installed cross-identity service proof, signed driver/kernel mediation,
production calibration/signing, demonstrated pre-execution blocking, and
Defender replacement remain separate product blockers. Changed files require a
rescan; checkpoint 2260 and the full antivirus goal remain active.

Checkpoint 2260 is now closed through exact local and destination `288/288`,
dual-host adversarial report validation, exact-head and merged-main CI/package
evidence, normal PR integration, guarded zero-delete synchronization, and an
unchanged protected vault. The portable user-mode final path race remains a
technical limit rather than an unreported implementation blocker.

## Checkpoint 2261 Blocker Delta

Checkpoint 2261 removes the remaining stale-evidence path for user-confirmed
`Quarantine` from a visible scan-result row. Flutter now sends the row's exact
SHA-256; Local Core rejects empty present evidence, bounds the optional field,
and routes it through the existing
open-handle hash/path-identity store boundary. Changed, oversized, NUL-bearing,
malformed, or mismatched evidence fails before vault mutation and requires a
rescan. Flutter also rejects success records with a different original path or
SHA-256, preventing false quarantined state and audit success.

The separately confirmed `Quarantine file` picker is not a scan-result action
and deliberately remains a fresh bounded snapshot of the current selected file.
Four harmless Local Core tests, Flutter IPC regressions, verifier step 289,
exact-289 validator scope, and Source contract 691 now pass locally. Broad
locked workspaces, release build, Flutter/protocol suites, definitive exact
`289/289` in `659.6s`, and dual-host authentic/adversarial report validation
also pass. Exact implementation/evidence-head CI and Desktop workflows, normal
PR `#131`, merged-main CI/packages, guarded 18-path zero-delete synchronization,
all eight lockfiles, destination exact `289/289` in `651.5s`, and the unchanged
protected vault pass. Publication was skipped. The initial implementation-head
push attempt was concurrency-cancelled and remains an explicit non-pass.

One broad destination Rust orchestration is also retained as a non-pass:
Defender removed a generated Native test harness as inactive
`Trojan:Win32/Wacatac.C!ml`, causing Windows error 225. Defender was not
weakened. Isolated unchanged Native default/all-feature suites each passed
`640/640` plus 21 intentional ignores, and the definitive destination verifier
subsequently passed. This is documented host-security interference, not a
silently converted pass and not a reason to weaken Defender.

Final path mutation is still a cross-platform user-mode operation rather than
one atomic filesystem transaction. Installed cross-identity UI/service proof,
signed driver/kernel mediation, production calibration/signing, demonstrated
pre-execution blocking, and Defender replacement remain separate product
blockers or technical limits. Checkpoint 2261 is closed; the complete antivirus
goal remains active.

## Checkpoint 2262 - Remaining Trust-Mutation Limits

Checkpoint 2262 implements stale-verdict and false-success defenses for visible
scan-row allowlist and feedback actions. Exact row SHA-256 plus explicit
confirmation now cross IPC; Local Core validates before access, rejects changed
bytes before persistence, double-hashes feedback feature collection, and emits
persisted evidence; Flutter requires exact request/receipt equality. Harmless
Rust/Flutter adversarial tests, an isolated release-binary smoke, exact-290
verifier/validator contracts, and Source/audit contracts pass locally. The
definitive verifier passes `290/290` in `621.9s`; both validator hosts accept the
authentic report and reject all six expected mutations. Evidence/head and
merged-main CI/packages, PR `#133`, bounded package review, guarded 26-path
zero-delete synchronization, all eight locks, destination exact `290/290`, and
the unchanged protected vault pass. One earlier destination verifier remains a
visible non-pass because Defender removed an inactive generated Native harness
before execution with error 225 and `DidThreatExecute=False`; Defender was not
weakened, a fresh exact target passed `4/4`, and the full verifier restarted.

This does not create an authenticated cross-identity service boundary or a
kernel-enforced immutable file lease. A privileged writer can still race a
user-mode path, and same-user code remains within the same-user store boundary.
Installed package/UI/service E2E, service identity and ACL proof, signed-driver
kernel mediation, production calibration/signing, demonstrated pre-execution
blocking, and Defender replacement remain separate blockers or technical
limits. Existing broad-root allowlist/exclusion prohibitions remain unchanged.

The protected production vault is not a test root and remains read-only at the
carried 16,072 files, zero directories, 4,522,733 bytes, 5,357 each payload/
metadata/authenticator, one metadata key, and zero pending. No live malware,
fixture execution, Defender weakening, machine-wide install, service/driver
start, release, or publication is part of checkpoint 2262. The complete
antivirus-hardening goal remains active. Checkpoint 2262 is closed; the
cross-identity, immutable-lease, driver, production, pre-execution, and Defender-
replacement limits above remain blockers or technical limits.

## Checkpoint 2263 Remaining Limits

Checkpoint 2263 scripts atomic quarantine restore no-replace activation for
Windows, Linux/Android, and Apple targets. Unsupported platforms are disabled
for this activation and fail visibly. No checkpoint-2263 test ran during
scripting. Local runtime now passes direct Platform `2/2`, Local Core `1/1`,
safe smoke, both locked workspaces, Source `693/693`, Flutter `852/852`, exact
definitive `291/291`, dual-host report validation, and all six adversarial
mutations. Hosted, merge, and destination evidence remains pending.

The final destination component can no longer be intentionally replaced by the
supported activation primitive, but existing ancestor checks remain
point-in-time. A fully handle-relative transaction across every path ancestor,
administrator/SYSTEM/root resistance, hostile-filesystem guarantees, installed
cross-identity service authorization, signed-driver mediation, and
pre-execution blocking remain blockers or technical limits. No live malware,
Defender weakening, vault mutation, install, service/driver start, release, or
publication is authorized.

The first definitive checkpoint 2267 run failed at the release update-package
builder smoke because long absolute Windows staged-log paths were not converted
to verbatim local-drive/UNC form before `MoveFileExW`. The failed report is
preserved and not credited. The repair rejects device namespaces and adds
bounded harmless long-path fixtures, but no repair test ran during repair
scripting. Relative paths retain legacy Win32 path-length behavior. Source 698,
focused 5/5, platform 15/15, update service 212/212, definitive 295/295,
adversarial 14/14, hosted, integration, destination, and closure remain pending;
every earlier blocker remains open.

Local checkpoint 2267 broad evidence passes Source `697/697`, focused `4/4`,
update service `211/211`, strict lint, both locked workspaces, release, Flutter
`852/852`, protocols `14/14 + 6/6`, and exact vault/process checks. Definitive,
adversarial, hosted, integration, synchronization, destination, and closure
evidence remains pending. These passes do not close the remove-to-activate,
multi-file transaction, point-in-time authority, privileged actor, installed
service/driver, pre-execution, signing/deployment, or Defender blockers above.

Implementation-head CI/package and bounded artifact review pass, publication
skips, and PR `#135` merges normally. This closes no authority limitation:
privileged ancestor replacement, hostile filesystems, installed cross-identity
service authorization, signed-driver mediation, and pre-execution blocking
remain blocked or technically limited. Closure-head, merged-main,
synchronization, and destination evidence remains pending.

The checkpoint-2263 closure evidence supersedes that pending status: exact
merged-main CI/packages, bounded artifact review, guarded zero-delete sync,
destination `291/291`, validators/adversarial checks, lockfiles, no residue or
product process, and the protected-vault invariant pass. Checkpoint 2263 is
closed; its stated authority limits remain.

## Checkpoint 2264 Remaining Limits

Checkpoint 2264 scripts atomic no-replace quarantine ingestion for Local Core,
Guard, and disabled Native compatibility code, retaining exclusive verified
copy as the safe fallback. No checkpoint-2264 test ran during scripting;
focused, broad, and definitive exact-292 local evidence now passes. Hosted,
merge, synchronization, and destination evidence remains pending. Broad
workspace Clippy is separately blocked by pre-existing Rust 1.96 lints in
untouched `services/api`; strict lint passes for all three changed crates.

Final-name atomicity is not a kernel-held immutable source lease or a
handle-relative transaction across every ancestor. Privileged source or
ancestor mutation, administrators, SYSTEM/root, hostile filesystems, kernel
compromise, installed cross-identity service authorization, signed-driver
mediation, production accuracy/signing, demonstrated pre-execution blocking,
and Defender replacement remain blocked or technically limited. Native direct
quarantine remains disabled; active mutation ownership stays with Local Core
and Guard. No live malware, Defender weakening, vault mutation, machine-wide
install, service/driver start, release, or publication is authorized.

The pending checkpoint-evidence statement above is superseded by exact
evidence-head and merged-main CI/packages, bounded artifacts, normal PR `#137`
integration, guarded zero-delete synchronization, destination `292/292`, dual-
host authentic and adversarial content validation, all eight lockfiles, zero
residue/processes, and the exact protected vault. Checkpoint 2264 is closed.
The authority, installed-service/driver, production-calibration, pre-execution,
and Defender-replacement limits above remain blockers or technical limits.

## Checkpoint 2265 - Remaining Metadata Atomicity Limits

Checkpoint 2265 scripts a repair for the known ordinary-rename final-name race:
new Local Core and Guard quarantine journal/record/auth activations, plus the
disabled Native compatibility path, now use shared no-replace activation. Local
Core status/recovery replacement also uses no-replace after removing the
validated previous object. A race-created destination is preserved and failure
is visible.

This closes only replacement at each final filename. Local, hosted, integration,
and synchronized-destination execution evidence passes. It does not provide a
transaction across journal, record, and auth files;
Local Core replacement retains a remove-to-activation gap. Authenticated recovery
detects incomplete state but cannot make multi-file activation atomic. Privileged
ancestor/path mutation, administrators, SYSTEM/root, hostile filesystems, kernel
compromise, installed cross-identity service authority, signed-driver mediation,
production calibration/signing, pre-execution blocking, and Defender replacement
remain blockers or technical limits.

No checkpoint-2265 test ran during the scripting phase. Focused and complete
verification was then pending. Focused/broad local regression, strict lint,
locked build/test, safe smoke, Source `695/695`, definitive `293/293`, and
dual-host authentic/adversarial validation now pass. Hosted, integration,
guarded-sync, and destination verification then also pass. No live malware,
Defender change, protected-vault mutation, machine-wide install, service/driver
start, release, or publication is authorized.

Implementation-head CI/packages and bounded artifact review pass with
publication skipped. These results close no remaining metadata-transaction,
privileged-actor, hostile-filesystem, installed-authority, driver,
pre-execution, production-calibration, or Defender-replacement limitation.
Evidence `e19d700`, normal merge `7f25166`, exact merged-main CI/packages,
bounded artifact review, guarded 16-path zero-delete synchronization,
destination exact `293/293`, dual-host adversarial rejection, exact blobs/locks,
zero residue/processes, and the protected-vault invariant close checkpoint 2265.
The listed metadata-transaction, privileged-actor, hostile-filesystem,
installed-authority, driver, pre-execution, production-calibration, signing,
deployment, and Defender-replacement limits remain open.

## Checkpoint 2266 - Signed Update Extraction Remaining Limits

Checkpoint 2266 scripts removal of the signed-package extraction final-name
overwrite race. Completed temporary payloads now cross the shared OS atomic
no-replace boundary after bounded extraction and repeated parent/target checks.
A competing final object is preserved and failure remains visible.

No checkpoint-2266 test ran during the scripting phase. Focused update-service,
full crate, strict lint, locked workspace/release, definitive exact-294,
dual-host adversarial, hosted package, integration, synchronization, and
destination evidence remain pending. The production vault remains protected and
read-only at 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.

The remaining update blockers are explicit. Final-name no-replace does not make
install-tree activation, rollback, or multiple extracted files one transaction.
Ancestor checks remain point-in-time user-mode checks, unsupported platforms
fail visibly, and privileged actors or hostile filesystems remain outside this
guarantee. Installed service authority, production signing ceremony, signed
driver/kernel mediation, pre-execution blocking, Defender replacement, and the
complete antivirus-hardening goal remain open. No live malware, EICAR, fixture
execution, Defender weakening, machine-wide install, service/driver start,
release, or publication is authorized.

Local evidence after batch freeze now passes Source `696/696`, focused `3/3`,
full update service `209/209`, strict lint, both locked workspace suites,
release, Flutter `852/852`, and protocols `14/14 + 6/6`. Exact `294/294`,
adversarial dual-host validation, hosted package targets, integration,
synchronization, destination, and closure remain pending. These passes do not
remove any transaction, privileged-actor, hostile-filesystem, installed-
authority, driver, pre-execution, signing, deployment, or Defender-replacement
blocker listed above.

Definitive local exact `294/294`, dual-host authentic acceptance, `10/10`
mutation rejection, lock/path/process/residue audit, and the exact vault now
pass. Hosted cross-target evidence, normal integration, synchronization,
destination, and closure remain pending. Per-file no-replace still does not
close any update transaction, privileged actor, hostile filesystem, installed
service/driver, pre-execution, signing, deployment, or Defender blocker.

Implementation-head CI and Windows/Linux/macOS package matrices pass at exact
commit `36325846`; publication skips and bounded checksum/SBOM artifact review
passes without extraction or execution. Android runtime/build, normal merge,
merged-main, synchronization, destination, and closure remain pending. Hosted
compilation closes no update transaction, privileged actor, hostile filesystem,
installed authority, driver, pre-execution, signing, deployment, or Defender
blocker.

Evidence-head and merged-main CI/packages, normal PR `#141` integration,
bounded artifact review, guarded exact 15-path synchronization, complete
destination regressions, exact `294/294`, and final blob/lock/backup/vault
audit close checkpoint 2266. The first two sync attempts failed visibly before
activation and are preserved as evidence; the repaired attempt passed. This
closure removes no blocker above: per-file no-replace is still not a package or
install-tree transaction, and Android runtime/build, privileged filesystems,
installed service/driver authority, pre-execution blocking, production signing,
deployment, Defender replacement, and the complete antivirus goal remain open.

## Checkpoint 2267 - Update Staged-File Remaining Limits

Checkpoint 2267 scripts a final-name overwrite repair for shared update-service
staged copy/write activation. A filesystem object appearing after target
removal and the absence/parent rechecks must now be preserved by the shared OS
no-replace primitive, with visible activation failure.

No checkpoint-2267 test ran during the scripting phase. Focused, full crate,
locked workspace/release, exact-295, hostile-report, hosted package,
integration, synchronization, destination, and closure evidence remains
pending. The protected vault remains read-only at 16,072 files, zero
directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
`.metadata_auth_key`, and zero pending.

No-replace does not repair the deliberate remove-to-activate availability gap:
a crash or later failure can leave the target absent. Multi-file staging and
install activation remain non-transactional. Ancestor authority is point-in-
time and user-mode; unsupported platforms fail visibly, and administrators,
SYSTEM/root, hostile filesystems, or kernel compromise remain outside the
guarantee. Installed service authority, production signing/deployment, signed
driver mediation, pre-execution blocking, Defender replacement, and the
complete antivirus-hardening goal remain open. No live malware, EICAR, fixture
execution, Defender weakening, install, service/driver start, release, or
publication is authorized.

Post-repair local evidence passes Source `698/698`, platform `15/15`, focused
`5/5`, update service `212/212`, strict lint, both locked workspaces/release,
Flutter `852/852`, protocols, exact `295/295`, dual-host adversarial `14/14`,
eight unchanged lockfiles, zero process/residue, and the protected-vault
invariant. This closes the local Windows final-name and long-absolute-path
regression evidence only. Hosted cross-target, integration, synchronization,
destination, and closure remain pending. The availability gap, multi-file
transaction, privileged actor, hostile filesystem, installed authority,
driver/pre-execution, signing/deployment, Defender replacement, and complete-
project blockers above remain unchanged.

Implementation-head CI and Windows/Linux/macOS package matrices pass at exact
commit `6e06ac51`; publication skips and bounded checksum/SBOM artifact review
passes without extraction or execution. Android runtime/build, normal merge,
merged-main, synchronization, destination, and closure remain pending. Hosted
compilation closes no update transaction, privileged actor, hostile filesystem,
installed authority, driver, pre-execution, signing, deployment, or Defender
blocker.

Evidence-head and merged-main CI/packages, normal PR `#143` integration,
bounded artifact review, guarded 14-path zero-delete synchronization,
destination Source `698/698`, broad regression, exact `295/295`, dual-host
authentic plus `14/14` adversarial validation, 14/14 blobs, 8/8 locks, 26
backups, zero residue/processes, and the exact protected-vault invariant close
checkpoint 2267. Closure does not repair the remove-to-activate availability
gap or make multi-file activation transactional. Android runtime/build,
privileged filesystems, installed service/driver authority, production signing
and deployment, pre-execution blocking, Defender replacement, and the complete
antivirus-hardening goal remain open.

## Checkpoint 2268 - Update Directory Activation Remaining Limits

Checkpoint 2268 scripts atomic no-replace behavior for the three final-name
directory moves in update tree replacement and rollback activation. It closes
neither the process-wide nor package-wide transaction gap. Service stop/start,
file-item replacement, backup cleanup, crash recovery, and multiple component
activations are separate operations. Power loss or process termination after a
backup move can leave the destination absent and the original tree in its
sibling backup. A race-created destination is intentionally preserved, so an
operator may need to recover the original from the preserved backup.

Path and ancestor validation is still point-in-time. Administrators,
SYSTEM/root, hostile or unusual filesystems, and kernel compromise remain
outside the user-mode guarantee; unsupported platforms fail visibly. No
installed authenticated privileged service boundary, signed driver,
pre-execution interception, production signing/deployment, or Defender
replacement is demonstrated.

No checkpoint-2268 test ran during the scripting phase. Focused, broad,
exact-296, dual-host adversarial, hosted package, integration, synchronized-
destination, and closure evidence remains pending. No live malware, EICAR,
fixture execution, Defender weakening, protected-vault mutation, install,
service/driver start, release, or publication is authorized. The vault remains
exactly 16,072 files with zero pending. The complete antivirus-hardening goal
remains active.

The first focused checkpoint-2268 update run is uncredited after exposing
Windows error 123: adding a verbatim prefix without normalizing a retained Rust
`/` separator made a valid nested absolute path invalid for `MoveFileExW`.
Separator normalization and a nested-path fixture are scripted; post-repair
focused and broad evidence remains pending.

Post-repair local broad evidence now passes through both locked workspaces,
release, Flutter/protocols, strict lint, all six focused fixtures, Source
`699/699`, platform `17/17`, and update aggregate `216/216`. This closes the
local Windows separator/runtime blocker only. Exact-296, adversarial, hosted,
integration, destination, and closure evidence remains pending, while crash
transactionality, manual backup recovery, cross-platform runtime, privileged
filesystems, installed authority, driver/pre-execution, signing/deployment,
Defender replacement, and the whole antivirus goal remain open.

Definitive checkpoint-2268 local evidence now passes exact `296/296` in
`673.5s`; both PowerShell hosts accept the authentic report and reject all
`14/14` adversarial cases. Exact report/adversarial SHA-256 values are
`8b87d0aa72cd0ee51d0c2b6ff9d1ac87dbb392ad19298b4a704a94b2f0f8970c` and
`217771abe632d0647aef3071654190609e367d120ec7afdfaee6ffd057033826`.
Locks, processes, pending files, and the protected vault remain exact. Hosted,
integration, guarded-sync, destination, and closure evidence remain pending;
crash transactionality, manual backup recovery, cross-platform runtime,
privileged filesystems, installed authority, driver/pre-execution,
signing/deployment, Defender replacement, and the whole antivirus goal remain
open.

Implementation-head CI/packages now pass at exact `821d17666` in runs
`33253639931`, `33253626820`, and `33253639896`; publication skips and both
consolidated artifacts pass bounded non-extracting/non-executing 8/6/7/
CycloneDX-1.6/569 review. This closes no cross-platform runtime, crash
transactionality, manual recovery, privileged filesystem, installed authority,
driver/pre-execution, signing/deployment, Defender replacement, or whole-goal
blocker. Evidence-head, integration, destination, and closure remain pending.

Evidence-head and merged-main CI/packages, normal PR `#145` integration,
bounded artifact review, guarded 18-path zero-delete synchronization,
destination Source `699/699`, broad regression, exact `296/296`, dual-host
authentic plus `14/14` adversarial validation, 18/18 blobs, 8/8 locks, 34
backups, zero product residue/processes, and the exact protected-vault invariant
close checkpoint 2268. Closure does not make service/file/component activation
transactional or eliminate crash/manual-recovery windows. Cross-platform
runtime, privileged filesystems, installed service/driver authority, production
signing/deployment, pre-execution blocking, Defender replacement, and the
complete antivirus-hardening goal remain open.

## Checkpoint 2269 Update Activation Recovery Limits

Checkpoint 2269 implements authenticated recovery for the directory backup-
move gap. No checkpoint-2269 test ran during the scripting phase; post-freeze
compilation and focused/broad local regression now pass. Exact-297 validation,
hostile-report checks, and read-only final audit now pass. Exact implementation
`d44b5c65` also passes Avorax CI `33271345848` and package push/PR runs
`33271310749`/`33271345821`; both consolidated artifacts pass bounded
non-extracting inventory/checksum/SBOM review and publication is skipped.
That pending integration state is superseded. Evidence `a933d451`, normal PR
`#147` merge `dfcec4fa`, evidence-head and merged-main CI/packages, bounded
artifact review, exact 21-path zero-delete synchronization, destination Source
`700/700`, broad Rust/Flutter/protocol regression, exact `297/297`, corrected
dual-host destination-local adversarial rejection, exact blobs/locks/backups,
zero process/residue, and the protected-vault invariant close checkpoint 2269.

Recovery is per allowlisted tree and runs on the next apply, rollback, update-
service start, or explicit `--recover`. It is not a durable all-package commit
protocol: service stop/start, app/service files, several engine components,
report cleanup, and rollback are not one atomic transaction. A crash during
pre-journal staging copy creates a detected orphan requiring manual review.
Storage write reordering, full-volume loss, key deletion, ACL/mode changes by
administrators or SYSTEM/root, hostile filesystems, and kernel compromise can
still prevent or subvert recovery. Ambiguous or unauthenticated state is
preserved rather than guessed.

No installed elevated service E2E, Windows power-cut VM test, Unix runtime
recovery test, production signing/deployment, driver/pre-execution proof, or
Defender replacement is claimed. The 16,072-file vault remains untouched with
zero pending, and the complete antivirus-hardening goal remains active.

## Checkpoint 2270 Unix Recovery Runtime Limits

Checkpoint 2270 scripts exact Ubuntu runtime evidence for `0700` recovery
directory and `0600` key/lock/journal modes, including repair from deliberately
broad temporary modes before authenticated recovery. No checkpoint-2270 test
ran during the scripting phase, so the control remains partial until the fixed
hosted Ubuntu 24.04 job passes.

This does not encrypt the Unix key, protect against root/administrators or a
hostile filesystem, prove macOS/Android semantics, exercise an installed
service identity, or provide power-loss-proof multi-component transactions.
Driver/pre-execution enforcement, Defender replacement, production signing/
deployment, and the complete antivirus-hardening goal remain open. No live
malware or protected-vault mutation is involved; the exact 16,072-file vault
has zero pending.

The post-freeze local batch passes Source `701/701`, recovery `19/19`, update
service `229/229 + 4/4`, strict locked lint/workspaces/release, Flutter and
protocols, exact `298/298`, and both authentic plus `14/14` hostile report
cases. This removes local source/wiring/regression uncertainty only. The exact
Ubuntu permission-runtime blocker remains until hosted CI executes the two
`cfg(unix)` fixtures; all root/hostile-filesystem, key-confidentiality,
macOS/Android, installed-service, transaction, driver/pre-execution, Defender-
replacement, signing/deployment, and whole-goal blockers above remain.

Unix mode repair also cannot revoke handles opened before repair or undo a
copied recovery key/journal. Authenticity is blocked after suspected disclosure
until key replacement and manual review; automatic reconciliation must not be
claimed as trustworthy in that state.

Hosted Ubuntu runtime is no longer a blocker for this control: exact commit
`4a01376b` passes CI `33279187609`, and job `99171298396` reports all three
selected Unix recovery tests green. Package push/PR and bounded consolidated
artifact review also pass with publication skipped. macOS/Android runtime,
prior disclosure/open handles, key confidentiality, installed identity,
transactionality, privileged actors/hostile filesystems, signing/deployment,
driver/pre-execution, Defender replacement, and whole-goal blockers remain.

Evidence `6dc6f22a`, normal PR `#149` merge `4fcc4f1a`, evidence-head and
merged-main CI/package runs, bounded artifact review, exact 14-path zero-delete
sync, complete destination regression, `298/298`, dual-host destination-local
`14/14` hostile rejection, and final blob/lock/backup/process/vault audit close
checkpoint 2270. The Ubuntu runtime blocker is removed only for this hosted
filesystem route. Prior disclosure/open handles, unencrypted Unix key,
macOS/Android runtime, installed identity, power-loss/multi-component
transactionality, privileged actors/hostile filesystems, production signing/
deployment, driver/pre-execution, Defender replacement, and whole-goal blockers
remain unchanged.

## Checkpoint 2271 macOS Recovery Runtime Limits

Checkpoint 2271 scripts the missing fixed macOS runtime route for exact `0700`
recovery-directory and `0600` key/lock/journal modes plus repair before
authenticated recovery. No checkpoint-2271 test ran during the scripting
phase, so macOS runtime remains partial until exact-head hosted `macos-15` CI
selects and passes all three filtered tests.

One hosted runner does not prove every macOS version, architecture, filesystem,
installed service identity, or Android runtime. Mode bits do not encrypt the
key, undo prior disclosure, revoke already-open handles, resist root/admin or a
hostile filesystem, make storage ordering trustworthy, or create a power-loss-
proof multi-component update transaction. Production signing/deployment,
driver/pre-execution enforcement, Defender replacement, and the complete goal
remain blocked, limited, or open. No live malware, EICAR, protected-vault
mutation, installation, service/driver start, release, or publication occurs;
the exact 16,072-file vault remains at zero pending.

Exact implementation-head hosted evidence removes the narrow macOS runtime
blocker for one `macos-15` runner: job `99186567140` passes the exact three
fixtures (`3/3`, 245 filtered out), and CI/package/artifact/local-audit evidence
is green with publication skipped. This does not remove Android, broader macOS
environment, installed identity, unencrypted key, prior-disclosure/open-handle,
root/admin, hostile filesystem, storage ordering, power-loss transaction,
production signing/deployment, driver/pre-execution, Defender-replacement, or
whole-project blockers. Evidence-head, merge, destination, and closure proof
remain pending.

Evidence-head and merged-main jobs now pass the same exact `3/3` macOS tests;
normal PR `#151`, guarded 14-path zero-delete synchronization, complete
destination regressions, exact `299/299`, dual-host hostile-report rejection,
and final blob/lock/backup/process/vault audit close checkpoint 2271. The narrow
single-runner macOS runtime blocker is removed.

The following blockers are deliberately not removed: Android runtime; other
macOS versions, architectures, filesystems, and installed identities;
unencrypted or previously disclosed keys and prior open handles; root/admin,
hostile filesystems, storage rollback/reordering, and kernel compromise;
package-wide power-loss transactionality; production signing/notarization and
deployment; privileged installed service evidence; signed driver and proven
pre-execution enforcement; Defender replacement; and complete antivirus-goal
closure.

## Checkpoint 2272 Update Recovery Namespace Durability Limits

Checkpoint 2272 scripts Windows write-through no-replace moves and Unix stable-
directory synchronization after recovery key/lock/journal creation, activation
and recovery renames, directory cleanup, and journal removal. A post-rename
synchronization failure is fail-visible and preserves authenticated evidence
for a later recovery pass.

No checkpoint-2272 test ran during the scripting phase. Post-freeze local
platform/update fixtures, Source `703/703`, full regression, exact `300/300`
verification, and dual-host validation with `16/16` hostile rejections pass.
Windows write-through and injected failure recovery are locally verified.
Hosted Ubuntu/macOS namespace semantics, package evidence, integration,
destination synchronization, and closure remain pending; Unix/macOS durability
therefore remains partial until exact-head hosted runtime evidence passes.

The barriers do not make service lifecycle, loose files, every engine tree,
reports, and rollback one durable transaction. Windows removal durability,
device/cache truthfulness, unsupported or network filesystems, storage rollback
and reordering, administrators/SYSTEM/root, hostile filesystems, kernel
compromise, key loss or prior disclosure, Android runtime, installed elevated-
service identity, VM power-cut behavior, production signing/deployment, signed
driver/pre-execution enforcement, Defender replacement, and complete antivirus-
goal closure remain open, blocked, or technically limited.

No live malware, EICAR, Defender weakening, protected-vault mutation, machine-
wide install, service/driver start, release, or publication is authorized. The
vault remains exactly 16,072 files, zero directories, 4,522,733 bytes, 5,357
each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.

Exact implementation-head evidence removes the narrow fixed-runner hosted
namespace-durability blocker: Ubuntu job `99205069601` and macOS 15 job
`99205069619` each pass all four selected harmless recovery fixtures (`4/4`,
247 filtered out). CI and both package matrices pass with publication skipped,
and both consolidated artifacts pass bounded non-extracting review. Normal
merge, merged-main evidence, destination synchronization, and closure remain
pending. Storage truthfulness, Windows removal persistence, broader filesystems,
installed identities, Android, package-wide power-loss transactionality,
privileged/hostile actors, signing/deployment, driver/pre-execution enforcement,
Defender replacement, and whole-project blockers are not removed.

Evidence-head and merged-main Ubuntu/macOS jobs now pass exact `4/4`; normal PR
`#153`, guarded 14-path zero-delete synchronization, complete destination
regressions, exact `300/300`, dual-host hostile-report rejection, and final
blob/lock/backup/process/vault audit close checkpoint 2272. The narrow hosted
namespace-durability evidence blocker is removed.

The following blockers are deliberately not removed: Windows removal
durability; storage hardware truthfulness; other filesystems, devices, OS
versions, and installed identities; Android runtime; root/admin/SYSTEM, hostile
filesystems, storage rollback/reordering, and kernel compromise; package-wide
power-loss transactionality; production signing/deployment; signed driver and
proven pre-execution enforcement; Defender replacement; and complete
antivirus-goal closure.

## Checkpoint 2273 Cleanup Tombstone Limits

Checkpoint 2273 scripts exact typed cleanup tombstones and a distinct
HMAC-authenticated cleanup-journal retirement state. This narrows the crash
window in which a removed staging/backup name can later look like an unexplained
active orphan. Exact recognized cleanup residue can be resumed; malformed,
conflicting, tampered, restored-active-name, or ambiguous evidence remains
blocked and preserved.

No checkpoint-2273 test ran during the scripting phase. Post-freeze local
Source `704/704`, focused cleanup `8/8`, activation recovery `30/30`, full
update service `4 + 240`, workspace/release/Flutter/protocol suites, exact
`301/301` verifier, dual-host authentic validation, `20/20` hostile mutation
rejection, and final safety audit pass. Hosted package/CI, integration, merge,
destination, and closure evidence remains pending.

This checkpoint does not remove the Windows removal-durability blocker.
`MOVEFILE_WRITE_THROUGH` and Unix directory synchronization are best-effort
user-mode ordering evidence, not proof of same-volume Windows rename/delete
persistence, truthful storage caches, filesystem replay ordering, or one atomic
transaction. A replay that restores an active staging/backup name after the
journal became cleanup state fails closed for manual review. Root/admin/SYSTEM,
hostile filesystems, storage rollback, kernel compromise, installed identity,
Android, production signing/deployment, driver/pre-execution enforcement,
Defender replacement, and complete-goal closure remain blocked, partial, or
technically limited. The 16,072-file vault remains untouched with zero pending.

Exact implementation-head evidence removes only the narrow hosted-execution
blocker for these scripted cleanup paths on the fixed Ubuntu CI route: job
`99223208370` passes update service `4 + 240` and every one of the eight cleanup
regressions. CI and both package matrices pass with publication skipped, and
both consolidated artifacts pass bounded non-extracting review. Normal merge,
merged-main evidence, destination synchronization, and closure remain pending.
Windows removal persistence, truthful storage, broader filesystems/identities,
Android, package-wide power-loss transactionality, privileged/hostile actors,
signing/deployment, driver/pre-execution enforcement, Defender replacement,
and complete-goal blockers are not removed.

Evidence-head and merged-main Ubuntu Rust jobs now pass the complete update
service and all eight cleanup regressions; fixed macOS jobs retain exact `4/4`.
Normal PR `#155`, guarded 13-path zero-delete synchronization, complete
destination regressions, exact `301/301`, dual-host `20/20` content rejection,
and final blob/lock/backup/process/vault audit close checkpoint 2273. The narrow
hosted cleanup-execution and destination-evidence blockers are removed.

The following blockers are deliberately not removed: Windows removal
durability; storage hardware truthfulness; other filesystems, devices, OS
versions, and installed identities; Android runtime; root/admin/SYSTEM, hostile
filesystems, storage rollback/reordering, and kernel compromise; package-wide
power-loss transactionality; production signing/deployment; signed driver and
proven pre-execution enforcement; Defender replacement; and complete
antivirus-goal closure.

## Checkpoint 2274 Bounded Tree Cleanup Limits

Checkpoint 2274 replaces unbounded shared recursive update-tree cleanup with a
two-phase bounded inventory and explicit post-order file/empty-directory
removal. Nested links/reparse points, special entries, over-limit trees, type
changes, reappearing names, non-empty directories, and I/O errors fail visibly.
The shared path is used by update staging, atomic tree replacement, rollback,
and authenticated activation-recovery tombstones.

No checkpoint-2274 test ran during the scripting phase. Post-repair local
evidence passes Source `705/705`, Windows cleanup `8/8`, recovery `30/30`,
update service `4 + 248`, strict locked Rust/release, Flutter `852/852`,
protocols `14/14 + 6/6`, and exact verifier `302/302`.
Final review then found basename-only accounting for retained full paths. The
scripted repair counts aggregate encoded path payload under the 16 MiB cap and
adds a ninth primitive fixture. Focused/full current-head regression now passes;
final-source definitive verification passes exact `302/302` in `669.6s`, and
both report-validator hosts accept the authentic report and reject all `24/24`
adversarial cases. Final read-only audit passes the exact path, lock, process,
residue, and protected-vault invariants. Initial exact-head CI `33306480962`
passed but omitted the two Unix-only fixtures. Both exact Ubuntu commands and a
Source contract are now wired. Final-source Source `705/705`, exact `302/302`
in `665.5s`, dual-host `24/24` adversarial rejection, and final audit pass.
Final implementation-head CI `33307588267` passes all six jobs; raw Ubuntu job
`99246758706` proves both exact Unix tests execute non-empty and pass `1/1`.
Desktop Packages `33307588380` passes all platform and consolidation jobs with
six files, seven checksums, a 569-component CycloneDX 1.6 SBOM, and publication
skipped. The narrow hosted Unix execution blocker is removed on the fixed
Ubuntu 24.04 runner. Evidence-head/merged-main, destination, and closure
evidence remain pending.

The bounds do not create an atomic delete transaction or a kernel-enforced
immutable namespace. Inventory and per-entry revalidation remain point-in-time;
same-identity hostile races, open handles, administrators/SYSTEM/root, hostile
filesystems, storage replay/reordering, kernel compromise, Windows deletion
durability, and truthful hardware remain blocked or technically limited.
Android runtime, installed elevated identity, production signing/deployment,
signed-driver/pre-execution enforcement, Defender replacement, and complete
antivirus-goal closure also remain open. No live malware, Defender change,
machine-wide install, service/driver start, release, publication, or protected-
vault mutation is authorized; the exact 16,072-file vault remains at zero
pending.

### Checkpoint 2275 verifier-host blocker and repair

- The first collision-safe definitive run is failed evidence: 297 steps passed,
  then Defender removed the Native unit-test harness as inactive
  `Trojan:Win32/Wacatac.C!ml`; three late benign tests never started. This is not
  reported as a scanner assertion failure or a passing gate.
- Defender exclusions and security weakening remain forbidden. A dedicated
  benign integration-test target is scripted for the late Native false-positive
  gate and CI prebuild, while the complete Native unit-test suite remains
  required separately.
- Focused runtime proof now passes the new target `3/3`, the complete
  false-positive gate, no-malware gate, and Source `707/707`, with zero Defender
  detections for the dedicated target. Broad regression also passes 1,806 Rust
  tests plus Flutter/protocol suites. The regenerated exact-302 report remains
  pending. Production false-positive-rate evidence remains unverified even
  though the fixture gate passes.
- That exact-302 pending state is superseded locally: the regenerated report
  passes `302/302`, and two validator hosts reject `34/34` adversarial cases.
  Hosted exact-head, destination, and production-rate evidence remain open.
- Final local audit passes 16 modified plus two added paths, zero deletions,
  nine unchanged locks, zero residue/processes, and the exact vault. Hosted,
  merge, synchronization, destination, and production-rate blockers remain.

Evidence-head and merged-main Ubuntu 24.04 jobs now prove both dedicated Unix
link fixtures execute exact non-empty `1/1`; all six CI jobs pass at both heads.
Normal PR `#157`, guarded 15-path zero-delete synchronization, complete
destination regression, exact `302/302`, dual-host `24/24` adversarial
rejection, and final blob/lock/backup/process/vault audit close checkpoint
2274. The narrow hosted Unix execution and synchronized-destination evidence
blockers are removed.

The following blockers are deliberately not removed: point-in-time same-
identity races; Windows deletion durability; storage hardware truthfulness;
other filesystems, devices, OS versions, and installed identities; Android;
root/admin/SYSTEM, hostile filesystems, storage rollback/reordering, and kernel
compromise; package-wide power-loss transactionality; production signing and
deployment; signed driver and proven pre-execution enforcement; Defender
replacement; and complete antivirus-goal closure.

## Checkpoint 2275 Atomic Existing-File Replacement Limits

Checkpoint 2275 scripts removal of the known update-service
remove-before-activate availability gap for an existing loose file. Supported
hosts use one adjacent OS replacement operation; initially absent destinations
remain no-replace. Opened file identity checks bind the staged source and old
destination immediately before replacement and the resulting names afterward.

Windows reserves an adjacent previous-file hard link through no-overwrite
creation and preserves every colliding candidate, then calls `ReplaceFileW`
with a null API backup parameter. Microsoft documents
`REPLACEFILE_WRITE_THROUGH` as unsupported, so the implementation passes zero
flags and does not claim Windows power-loss durability. A failed call that
leaves the destination absent triggers an immediate checked no-replace restore
only after the reserved backup matches the already-opened old destination; the
restored name is rebound to that identity.
Same-file aliases and mismatched/spoofed backups are rejected. If destination
and backup both exist, both are preserved and the operation fails visibly.
Successful replacement requires exact backup identity and checked removal.
A failed call whose reserved backup disappeared is reconciled only after the
destination is rebound to the opened old file; a missing-both state fails visibly.
Because `ReplaceFileW` opens the replacement file without sharing, the verified
staged-source handle closes before the call. Its file ID is rebound to the
active name afterward, leaving an explicitly point-in-time source race boundary.
Hard-link backup reservation requires same-volume filesystem hard-link support
and fails visibly where unavailable.

Unix uses same-directory atomic rename and stable parent-directory
synchronization. Exact Ubuntu 24.04 and macOS 15 test routes are scripted, but
no checkpoint-2275 test ran during the scripting phase. Network, unusual, or
hostile filesystem behavior and dishonest storage caches are not inferred from
local hosted filesystems.

The remaining blockers are explicit. Abrupt process termination can leave the
old Windows file only at a `.avorax-replace-backup` name; there is no
authenticated loose-file journal yet, so ambiguous residue requires manual
review. App files, service files, docs, engine components, rollback, reports,
and service lifecycle are not one package-wide transaction. Path and opened-
handle identity checks remain point-in-time; same-identity final races,
administrators, SYSTEM/root, hostile filesystems, storage replay/reordering,
kernel compromise, installed service identity, Android, production signing/
deployment, signed-driver/pre-execution enforcement, Defender replacement, and
complete-goal closure remain blocked, partial, open, or technically limited.

Source contract 706, the revised staged-file step within exact verifier count
302, dual-host report requirements, harmless runtime fixtures, and all docs are
scripted before execution. Earlier Source `706/706`, Windows `3/3 + 5/5`,
update `6/6`, full regression, exact verifier `302/302`, and dual-host `28/28`
evidence is superseded after a harmless probe proved that the API backup path
could overwrite a competing file. The no-overwrite hard-link repair passes
focused Source `706/706`, platform `3/3 + 7/7`, and update `6/6 + 2/2`; full
local, definitive, Unix hosted, exact-head integration, and destination
evidence remain pending. No live
malware/EICAR, Defender weakening,
protected-vault mutation, machine-wide install, service/driver start, release,
or publication is authorized; the exact 16,072-file vault must remain at zero
pending.

## Checkpoint 2276 Remaining Metadata Transaction Limits

Checkpoint 2276 removes the known Local Core remove-to-activate gap for each
existing JSON record and HMAC sidecar. The remaining blocker is cross-file
transactionality: ordinary filesystems do not atomically replace both names in
one operation. A crash between replacements can leave a mismatched pair;
authenticated reads fail closed and manual recovery may be required. A durable
authenticated multi-file journal or another carefully bounded transactional
design remains future work.

Windows ambiguous failure can leave `.avorax-replace-backup`, same-volume hard-
link support is required, and point-in-time user-mode checks cannot defeat
administrators, SYSTEM/root, hostile filesystems/storage, or kernel compromise.
Installed identity, production signing/deployment, driver/pre-execution
enforcement, Defender replacement, production accuracy, and complete-goal
closure remain blocked, partial, open, or technically limited. Checkpoint 2276
local runtime evidence passes new `3/3`, metadata `21/21`, complete regression,
exact `302/302`, dual-host `52/52` hostile rejection, and final audit. Hosted,
integration, synchronized-destination, installed-identity, and production
evidence remain pending.

## Checkpoint 2277 Remaining Recovery Limits

Checkpoint 2277 scripts the durable authenticated metadata-update journal that
checkpoint 2276 left as future work. Exact previous/proposed JSON/HMAC mismatch
states can now be rolled back automatically while the journal remains.

The blocker is narrowed, not eliminated. JSON and HMAC are still separate file
operations; unknown/missing state needs manual review, journal unlink durability
depends on filesystem/storage truthfulness, and Windows replacement ambiguity
can retain backup evidence. Restore/delete payload movement is not transactionally
joined to metadata and needs a separate bounded action-recovery design.

Installed identity, production signing/deployment and accuracy, signed-driver
pre-execution enforcement, Defender replacement, hostile-administrator/kernel
resistance, secure erasure, and whole-goal closure remain blocked, partial,
open, or technically limited. No checkpoint-2277 test ran during scripting;
post-freeze local focused/full/release/Flutter/protocol and exact `303/303`
verifier evidence now passes, including dual-host rejection of `62/62`
adversarial cases. Hosted cross-platform and destination closure remains open.

That hosted/destination closure is complete through evidence head `f335ffc6`,
PR `#163`, merge `89c0449`, merged-main CI/packages, guarded exact 17-path
zero-delete synchronization, destination `303/303`, dual-host `62/62` hostile
rejection, and final blob/lock/process/residue/vault audit. The remaining
blocker is narrower: restore/delete payload movement and action metadata still
need bounded crash recovery. Two-file atomicity, hostile privileged/storage
actors, installed identity, production signing/accuracy, driver/pre-execution,
Defender replacement, and whole-goal completion remain open or limited.

## Checkpoint 2278 Remaining Action-Recovery Limits

Checkpoint 2278 scripts bounded authenticated confirmed-intent recovery for the
restore/delete crash boundary left by checkpoint 2277. Exact known states can
resume forward; unknown or ambiguous evidence is retained rather than guessed.

The operation is still not one power-loss-proof transaction across journal,
JSON/HMAC, quarantine payload, restore destination, and directory entries. A
crash after staging but before the identity-bound phase intentionally requires
manual review. Point-in-time path/file-ID/hash/link checks do not resist an
administrator, SYSTEM/root, hostile storage/filesystem, or kernel compromise.
No secure erasure is claimed. Windows replacement ambiguity can retain backup
evidence and journal unlink durability depends on storage truthfulness.

No checkpoint-2278 test ran during the scripting phase. Focused/full,
definitive `304/304`, Source `710/710`, and adversarial `34/34` evidence now
pass locally. Hosted/integration, guarded synchronization, destination, and
final exact-vault evidence remain pending. Installed
identity, production signing/deployment and detection accuracy, signed-driver
pre-execution enforcement, Defender replacement, hostile privileged actors,
and completion of the antivirus-hardening goal remain blocked, partial, open,
or technically limited.

Checkpoint 2278 integration is closed: exact-head and merged-main hosted
matrices, guarded destination sync, destination `304/304`, `34/34` hostile
validation, exact blobs/locks/backups, and read-only vault audit pass. Restore/
delete action recovery is no longer an unverified checkpoint blocker. Its
documented storage-durability, unbound-stage manual-review, privileged-actor,
driver/pre-execution, Defender-replacement, installed-identity, and production-
accuracy limitations remain open; the complete antivirus goal remains active.
