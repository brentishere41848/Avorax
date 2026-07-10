# Avorax Hardening Run Log

## Session scope

Lead-engineer product-hardening pass across the Avorax repository. Goal is to move Avorax toward a professional, reliable, secure, honest endpoint protection product through documented architecture, prioritized backlog, tests, and incremental implementation.

## Professional assumptions

- Current repository path is `C:\Users\Brent\Documents\Avorax-main` for this Codex continuation.
- The active product is Avorax. Historical/internal `zentor_*` names remain in code paths and crate/package names.
- The product must remain defensive only. No real malware samples, destructive behavior, stealth, evasion, or unsupported security claims are acceptable.
- The signed Windows driver path is not assumed active unless a validation report proves it is installed, running, communicating, and self-tested.
- The bundled native ML model is treated as development-only unless release metadata and gates prove production readiness.
- MSI/EXE installers are first-install/repair/recovery/offline paths. Normal in-app updates should use verified `.aup` packages.

## 2026-07-10 continuation checkpoint 2154

- Added a prominent English beta safety disclaimer to `README.md` and `docs\portable-beta.md`, and added publishable release notes at `docs\releases\avorax-portable-beta-0.1.0-beta.1.md`. The copy explicitly says the portable beta may miss advanced, novel, targeted, polymorphic, fileless, kernel-level, and large-scale threats; Defender or another supported antivirus must remain enabled.
- Rebuilt and independently re-extracted `dist\Avorax-Portable-Beta-0.1.0-beta.1.zip` after the packaged README changed. Build passed in `5.715s`; archive smoke passed in `4.599s`; current size is `5,886,708` bytes and SHA-256 is `a80155373a869576dad6d015c21221a18815bf3318a253a11c19477af128240b`.
- The release notes refuse fake artifacts: no MSI or packaged Windows GUI can be published until the .NET SDK, Visual Studio Desktop C++ components, and symlink-capable host requirements are satisfied; no standalone core EXE is presented as a usable launcher; no Linux asset is published without a native Linux build/runtime pass.
- Added `test\app_accessibility_audit_test.dart` and responsive shared/screen fixes. All ten main routes plus onboarding pass `21/21` checks for labeled tap targets, Android minimum target sizing, and 200% mobile text without layout overflow. Security notifications and page titles now expose live-region semantics, while high-text headers, status pills, action rows, checklists, metric cards, loading text, and dropdowns remain readable.

## 2026-07-10 continuation checkpoint 2153

- Added `tools\windows\avorax-portable-beta.ps1`, a unified launcher over the existing status, local scan, finite watch, quarantine, and allowlist wrappers. It fixes the executable and engine to the bundle, keeps reports below the selected local data root, initializes allowlist state atomically, bounds watch duration to ten seconds, requires confirmation for destructive/trust mutations, and preserves wrapper failures and scan errors visibly.
- Added `tools\windows\build-avorax-portable-beta.ps1`. It accepts only repository/dist-contained outputs, guards recursive cleanup by exact parent/name/reparse checks, stages the canonical release core plus runtime-only signature/rule/model/trust assets, and verifies packaged status and the harmless lifecycle probe before writing a per-file SHA-256 manifest and ZIP.
- Added `tools\testing\run-avorax-portable-beta-smoke.ps1`. It uses bounded `ZipArchive` inspection and manual extraction, rejects unsafe or duplicate paths, limits entry count/entry size/total size/compression ratio, verifies every manifest file size/hash and rejects extras, then reruns ready status and scan/quarantine/restore/delete lifecycle from the extracted archive.
- Adversarial archive evidence passed for parent traversal, case-insensitive duplicate paths, excessive compression ratio, and a tampered manifest SHA-256. Temporary extraction/runtime roots were removed.
- Built `dist\Avorax-Portable-Beta-0.1.0-beta.1.zip` with SHA-256 `b5e75c2404a486639b79407b9eca2afe90258e9c076a7416679723057af1af02`. The build report records `39` manifested files, `13` signatures, `9` rules, a passing native self-test, local stdio/no-network operation, and successful quarantine restore/delete postconditions.
- Verification passed: all three PowerShell scripts parsed; the final post-documentation archive smoke passed in `5.957s`; dependency-free Python source-contracts passed `582` tests; product-copy and explicit-Python no-malware-binaries gates passed. Reports are `.workflow\ultracode\avorax-hardening\results\2153-portable-beta-build-report.json` and `2153-portable-beta-archive-smoke.json`.
- Classification remains deliberately narrow: verified portable manual scans/status/quarantine lifecycle and extracted-package integrity; partial finite user-mode watch and command-line usability; blocked installed Flutter GUI/MSI/service/driver by the host prerequisites; technically limited unsigned ZIP with no persistent background, Defender replacement, pre-execution blocking, secure erase, or live-malware claim.

## 2026-07-10 continuation checkpoint 2152

- Added `tools\windows\avorax-installed-core-lifecycle-probe.ps1`, a bounded, isolated release/installed-binary lifecycle probe that invokes `avorax-local-scan.ps1` and `avorax-quarantine.ps1` in child script scope rather than launching an ambient PowerShell command.
- The probe creates only harmless ASCII exact-hash fixtures and a temporary local signature pack. It requires confirmed scan quarantine, source removal, a non-executable `.avoraxq` payload under the isolated quarantine root, list consistency, confirmed restore with exact SHA-256 reproduction and payload removal, and confirmed delete with source/payload absence. It writes a structured passed/failed report atomically and removes only a verified GUID-named direct child of the Windows temp root.
- Extended `avorax-installed-smoke-test.ps1` so the lifecycle runs only after all prior installed layout/service/manifest/health checks pass. The smoke validates the lifecycle report status, canonical installed-core hash, scan/list/restore/delete postconditions, cleanup, and no service-mediation/pre-execution claim.
- Extended installer stage and release gates to require the lifecycle probe, local scan wrapper, quarantine wrapper, and shared security-gate helpers in the staged payload.
- Added `generated_reports.installed_core_lifecycle` to the small-threat MVP report. The full-suite validator independently validates its exact schema, executable hash, harmless-fixture policy, distinct quarantine IDs, operation postconditions, cleanup, safety flags, and technical limits; the verifier step and lifecycle scope are mandatory.
- Focused verification passed: PowerShell parser checks for all modified scripts, the lifecycle probe against `target\release\zentor_local_core.exe`, dependency-free Python source-contracts (`581`), and a reconstructed full-suite report validation with `216` steps.
- Negative evidence passed: a lifecycle report changed to `operations.restore.payload_removed=false` failed validation with the expected boolean postcondition diagnostic; capture is `.workflow\ultracode\avorax-hardening\results\2152-tampered-installed-lifecycle-validator.txt`.
- Full MVP verification passed: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2152-small-threat-mvp-installed-lifecycle-report.json` passed all `216` report steps in `1092.7s`; the new lifecycle step passed in `3.8s`, Python source contracts in `3.1s`, Flutter analyzer in `43.7s`, and the final full-suite report validator in `2.2s`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2152-installed-core-lifecycle.md`. Verified scope is the canonical executable plus wrapper stdio lifecycle and installed-smoke wiring. Actual staged/MSI installation, installed Windows service mediation, packaged UI click-through, and signed-driver/pre-execution proof remain partial or blocked. The release-host report still identifies three blockers: no .NET SDK returned by `dotnet --list-sdks`, missing Visual Studio Desktop C++ components, and unavailable Windows symlink support.

## 2026-07-10 continuation checkpoint 2151

- Replaced installed smoke health success-by-substring with a bounded structured parser/probe in `tools\windows\avorax-core-health-probe.ps1`.
- The parser requires exactly one non-progress JSON object, a real boolean `ok=true`, all required health fields, typed non-negative signature/rule counts, `ipc=stdio`, and `network_exposed=false`. Non-JSON output containing the old success substring, missing fields, explicit `ok=false`, multiple responses, network exposure, non-stdio IPC, and non-zero exit are rejected.
- `tools\windows\avorax-installed-smoke-test.ps1` now launches the canonical installed `zentor_local_core.exe`, verifies it hashes identically to `avorax_core_service.exe`, rejects health stderr, and requires engine available, native engine ready, positive signature/rule counts, and native self-test success.
- `tools\windows\avorax-installer-stage-test.ps1` now requires the shared structured health probe in staged installer payloads.
- Added `tools\testing\run-avorax-installed-core-health-probe-smoke.ps1`, which tests seven parser rejection cases and the real release local-core health runtime without installing services or claiming installed E2E. It writes `.workflow\ultracode\avorax-hardening\results\installed-core-health-probe.json`.
- Wired the small-threat verifier to run `Installed smoke structured core-health probe tests`, added `installed smoke structured core-health parser/probe guards` to verified scope, and made both mandatory in full-suite report validation. Source contracts pin the parser, process bounds, canonical/alias checks, ready-state checks, smoke cases, verifier step, and validator scope.
- Focused verification passed locally: PowerShell parser checks, structured parser/runtime smoke, and dependency-free Python source-contracts (`580`).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2151-small-threat-mvp-structured-installed-health-report.json` passed all `215` report steps in `1027.4s`; the new structured health step passed in `2.1s`, and the post-report validator passed in `1.7s`.
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2151-small-threat-mvp-missing-structured-health-step-report.json` failed validation with `passed full-suite report is missing required step: Installed smoke structured core-health probe tests`; captured output is in `.workflow\ultracode\avorax-hardening\results\2151-structured-installed-health-negative-validator.txt`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2151-structured-installed-health.md`. Actual installed service/UI E2E remains blocked until the host has a .NET SDK, Visual Studio Desktop C++ components, and Windows symlink support; signed-driver/pre-execution validation remains separately blocked.

## 2026-07-09 continuation checkpoint 2150

- Extended the status, allowlist, and cancel-scan release-binary wrapper smokes with explicit fail-closed path/report guard evidence.
- `status-wrapper-path-guards.json` proves a missing engine root and an outside-repository report path fail visibly and write no requested report.
- `allowlist-wrapper-path-guards.json` proves unconfirmed add/remove actions and an outside-repository report path fail visibly and write no requested report. The existing positive lifecycle still proves add, list, allowlisted scan preservation, confirmed remove, and post-remove quarantine.
- `cancel-scan-wrapper-path-guards.json` proves missing data-root selection, mutually exclusive isolated/installed root selection, and an outside-repository report path fail visibly. All requested negative reports remain absent, and outside report rejection writes no `cancel-active-scan` token.
- Wired the small-threat verifier and validator to require separate `cancel scan wrapper release-binary path/report guard smoke`, `allowlist wrapper release-binary path/report guard smoke`, and `status wrapper release-binary path/report guard smoke` scopes. Source contracts pin the guard reports, case names, report non-write checks, token non-write check, verifier scopes, and validator scopes.
- Focused verification passed locally: PowerShell parser checks for the three wrapper smokes plus verifier/validator; all three wrapper smokes against `target\release\zentor_local_core.exe`; and dependency-free Python source-contracts (`580`).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2150-small-threat-mvp-user-flow-path-guards-report.json` passed all `214` report steps in `1006.1s`, including cancel (`2.4s`), allowlist (`6.3s`), and status (`2.7s`) wrapper smokes. The post-report `Small-threat MVP report validator` passed in `1.6s`.
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2150-small-threat-mvp-missing-status-path-guard-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: status wrapper release-binary path/report guard smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2150-user-flow-path-guards-negative-validator.txt`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2150-user-flow-path-guards.md`. Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed background monitoring and scheduling E2E, installed driver/guard validation, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-09 continuation checkpoint 2149

- Extended `tools\testing\run-avorax-watch-scan-wrapper-smoke.ps1` so finite watch-scan wrapper invalid input and report-path boundaries are covered by release-binary smoke evidence.
- The smoke now writes `.workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-path-guards.json` with `status=passed` and five blocked cases: missing `-Path`, missing watched root, file path used as a watched root, broad filesystem root, and report path outside the repository.
- The guard cases prove no requested negative report is written: `.workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-missing-path-should-not-exist.json`, `watch-scan-wrapper-missing-root-should-not-exist.json`, `watch-scan-wrapper-wrong-kind-should-not-exist.json`, `watch-scan-wrapper-broad-root-should-not-exist.json`, and a temp outside-repo report all remain absent.
- The guard report records no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no persistent-monitoring claim, no pre-execution claim, no kernel-driver requirement, and no broad default watch roots.
- Wired the small-threat MVP verifier scope to include `watch scan wrapper finite release-binary path/report guard smoke`. `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports missing that scope, and source contracts pin the guard fixtures, diagnostics, report non-write checks, verifier scope, and validator scope.
- Focused verification passed locally: PowerShell parser checks for `tools\testing\run-avorax-watch-scan-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused watch wrapper smoke; and Python source-contracts (`580`).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2149-small-threat-mvp-watch-path-guards-report.json` passed with `214` steps in `779.3s`, including `Watch scan wrapper finite release-binary smoke` (`19.5s`) and final `Small-threat MVP report validator` (`1.5s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2149-small-threat-mvp-missing-watch-path-guard-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: watch scan wrapper finite release-binary path/report guard smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2149-watch-path-guards-negative-validator.txt`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2149-watch-path-guards.md`. Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service/background monitoring E2E, scheduled startup, installed driver/guard validation, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-09 continuation checkpoint 2148

- Hardened Windows timeout cleanup in Flutter helper paths so app detection, platform PowerShell probing, local-core IPC, Guard self-test, cancel IPC, and elevated PowerShell helpers attempt bounded process-tree cleanup for the Avorax-spawned child before falling back to single-process kill/reap diagnostics.
- Added checked `%SystemRoot%\System32\taskkill.exe` resolution with `/PID <pid> /T /F` in `app_detector.dart`, `platform_info_service.dart`, and `local_core_client.dart`; stdout/stderr collection stays bounded and no service install, Defender change, or pre-execution blocking claim is made.
- Extended timeout runtime tests so injected hung Dart fixture processes must actually exit after the timeout path in `app_detector_test.dart`, `platform_info_service_test.dart`, and `local_core_ipc_diagnostics_test.dart`.
- Hardened `tools\testing\run-avorax-watch-scan-wrapper-smoke.ps1` against watcher startup races by running each finite watch for `8` seconds and waiting `2500ms` before writing the harmless fixture. Focused detect/quarantine reports now show `initial_files_observed=0`, `events_observed=1`, `files_scanned=1`, and expected threat/quarantine counts.
- Wired the small-threat MVP verifier to run `Flutter timeout process-tree cleanup tests` and to include `Flutter timeout process-tree cleanup guards` in verified scope. The full-suite validator rejects reports missing that scope.
- Focused verification passed locally: Dart format, focused timeout runtime tests, full changed Flutter test files, explicit verifier timeout test command (`6` tests), Flutter analyze, PowerShell parser checks for the watch smoke/verifier/validator scripts, focused watch-scan wrapper smoke, Python source-contracts (`580`), and a post-run timeout fixture process audit with `remaining_timeout_fixture_processes=0`.
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2148-small-threat-mvp-timeout-process-tree-report.json` passed with `214` steps in `836.9s`, including `Watch scan wrapper finite release-binary smoke` (`18.1s`), `Flutter timeout process-tree cleanup tests` (`6.1s`), and final `Small-threat MVP report validator` (`1.4s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2148-small-threat-mvp-missing-timeout-process-tree-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: Flutter timeout process-tree cleanup guards`; captured output is in `.workflow\ultracode\avorax-hardening\results\2148-timeout-process-tree-negative-validator.txt`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2148-timeout-process-tree-cleanup.md`. Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-09 continuation checkpoint 2147

- Extended `tools\testing\run-avorax-quarantine-wrapper-smoke.ps1` so invalid quarantine wrapper target, ID, and report-path boundaries are covered by release-binary smoke evidence.
- The smoke now proves a missing manual quarantine `-TargetPath` fails visibly with `TargetPath must be an existing file` and does not write `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-missing-target-should-not-exist.json`.
- The smoke proves a manual quarantine target that is a directory fails visibly with `TargetPath must be an existing file` and does not write `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-wrong-kind-should-not-exist.json`.
- The smoke proves an invalid quarantine ID such as `bad/id` fails visibly with `QuarantineId may contain only ASCII letters` and does not write `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-invalid-id-should-not-exist.json`.
- The smoke proves an absolute `-ReportPath` outside the repository fails visibly with `Avorax quarantine report must be inside the repository` and does not write an outside report.
- Added `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-path-guards.json`, recording `status=passed`, the four blocked guard cases, and safety fields for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no pre-execution claim, and no secure-erase claim.
- Wired the small-threat MVP verifier scope to include `quarantine management wrapper release-binary path/report guard smoke`. `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports missing that scope, and source contracts pin the guard fixtures, diagnostics, report non-write checks, verifier scope, and validator scope.
- Focused verification passed locally: PowerShell parser checks for `tools\testing\run-avorax-quarantine-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-quarantine-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py` passed (`580` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2147-small-threat-mvp-quarantine-path-guards-report.json` passed with `213` steps in `760.7s`, including `Quarantine wrapper release-binary smoke` (`7.8s`) and final `Small-threat MVP report validator`.
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2147-small-threat-mvp-missing-quarantine-path-guard-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: quarantine management wrapper release-binary path/report guard smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2147-quarantine-path-guards-negative-validator.txt`.
- Post-documentation gates passed locally: PowerShell parser checks, Python source-contracts (`580`), full-suite validation of `.workflow\ultracode\avorax-hardening\results\2147-small-threat-mvp-quarantine-path-guards-report.json`, `tools\security\zentor-product-copy-gate.ps1`, and `tools\security\zentor-no-malware-binaries-gate.ps1`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2147-quarantine-path-guards.md`. Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2146

- Extended `tools\testing\run-avorax-local-scan-wrapper-smoke.ps1` so the existing `tools\windows\avorax-local-scan.ps1` invalid target and report-path boundaries are covered by release-binary smoke evidence.
- The smoke now proves a missing `-Path` target for `-ScanType File` fails visibly with `Scan target does not exist` and does not write `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-missing-target-should-not-exist.json`.
- The smoke proves a `File` scan pointed at a folder fails visibly with `File scan target is not a file` and does not write `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-wrong-kind-should-not-exist.json`.
- The smoke proves an absolute `-ReportPath` outside the repository fails visibly with `Avorax local scan report must be inside the repository` and does not write an outside report.
- Added `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-path-guards.json`, recording `status=passed`, the three blocked guard cases, and safety fields for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, and no pre-execution claim.
- Wired the small-threat MVP verifier scope to include `local scan wrapper release-binary path/report guard smoke`. `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports missing that scope, and source contracts pin the guard fixtures, diagnostics, report non-write checks, verifier scope, and validator scope.
- Focused verification passed locally: PowerShell parser checks for `tools\testing\run-avorax-local-scan-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-local-scan-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py` passed (`580` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2146-small-threat-mvp-local-scan-path-guards-report.json` passed with `213` steps in `647.7s`, including `Local scan wrapper release-binary smoke` (`6.1s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2146-small-threat-mvp-missing-local-scan-path-guard-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: local scan wrapper release-binary path/report guard smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2146-local-scan-path-guards-negative-validator.txt`.
- Post-documentation gates passed locally: PowerShell parser checks, Python source-contracts (`580`), full-suite validation of `.workflow\ultracode\avorax-hardening\results\2146-small-threat-mvp-local-scan-path-guards-report.json`, `tools\security\zentor-product-copy-gate.ps1`, and `tools\security\zentor-no-malware-binaries-gate.ps1`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2146-local-scan-path-guards.md`. Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2145

- Extended `tools\testing\run-avorax-local-scan-wrapper-smoke.ps1` so the existing `tools\windows\avorax-local-scan.ps1` `Folder` and `-FailOnThreat` paths are covered by release-binary smoke evidence.
- The folder smoke creates only harmless exact-hash fixture bytes plus a benign text file and an isolated temporary `avorax_core.asig` signature pack. It runs `-ScanType Folder -Path <folder> -AutoQuarantineConfirmed`, records `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-folder-quarantine.json`, and verifies `command=scan_folder`, `scan_kind=custom`, `action_mode=autoQuarantineConfirmedOnly`, `files_scanned=2`, `threats_found=1`, `quarantined_files=1`, known-bad fixture removal, and benign fixture preservation.
- The fail-on-threat smoke runs `-ScanType File -FailOnThreat` in detect-only mode, records `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-fail-on-threat.json`, verifies `status=threatsFound`, `action_mode=detectOnly`, `files_scanned=1`, `threats_found=1`, `quarantined_files=0`, visible failure output, and source preservation.
- Wired the small-threat MVP verifier scope to include `local scan wrapper release-binary folder/fail-on-threat smoke`. `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports missing that scope, and source contracts pin the wrapper switch, folder fixtures, fail-on-threat fixtures, reports, verifier scope, and validator scope.
- Focused verification passed locally: PowerShell parser checks for `tools\testing\run-avorax-local-scan-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-local-scan-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py` passed (`580` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2145-small-threat-mvp-local-scan-folder-failon-report.json` passed with `213` steps in `609.7s`, including `Local scan wrapper release-binary smoke` (`5.2s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2145-small-threat-mvp-missing-local-scan-folder-failon-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: local scan wrapper release-binary folder/fail-on-threat smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2145-local-scan-folder-failon-negative-validator.txt`.
- Post-documentation gates passed locally: PowerShell parser checks, Python source-contracts (`580`), full-suite validation of `.workflow\ultracode\avorax-hardening\results\2145-small-threat-mvp-local-scan-folder-failon-report.json`, `tools\security\zentor-product-copy-gate.ps1`, and `tools\security\zentor-no-malware-binaries-gate.ps1`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2145-local-scan-folder-failon.md`. Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2144

- Hardened Flutter shell notification selection in `apps\zentor_client\lib\shared\widgets\zentor_shell.dart`: recent local events are ranked `error` > `warning` > info, and newest timestamps only break ties at the same priority.
- Added widget coverage in `apps\zentor_client\test\navigation_accessibility_test.dart` for a warning `threat_detected` event staying visible over a newer `scan_completed` info event, plus newest-event selection when two warnings tie.
- Extended `apps\zentor_client\test\app_visual_policy_test.dart` and Python source contracts so the bounded recent-event window, priority helper, widget fixtures, verifier step, validator step, and verified scope remain pinned.
- Wired the small-threat MVP verifier to run `Flutter shell notification priority tests` and added `security-prioritized shell notification summaries` to verified scope. The validator now rejects passed no-skip-Flutter reports missing that step/scope.
- Updated `docs\client-ui.md`, `docs\audit\threat-model.md`, `docs\audit\engine-control-matrix.md`, and `TESTING.md` to document that this is in-app local-event notification evidence, not Windows toast delivery.
- Focused verification passed locally: PowerShell parser checks for `tools\testing\verify-small-threat-mvp.ps1` and `tools\testing\validate-small-threat-mvp-report.ps1`; `C:\Users\Brent\develop\flutter\bin\dart.bat format --set-exit-if-changed lib\shared\widgets\zentor_shell.dart test\navigation_accessibility_test.dart test\app_visual_policy_test.dart` (`0 changed` after formatting); `C:\Users\Brent\develop\flutter\bin\flutter.bat analyze`; `C:\Users\Brent\develop\flutter\bin\flutter.bat test test\navigation_accessibility_test.dart --plain-name "shell notification"` (`3` tests); `C:\Users\Brent\develop\flutter\bin\flutter.bat test test\app_visual_policy_test.dart --plain-name "shell exposes in-app notifications"` (`1` test); UI inventory validation (`61` source-accounted controls); and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py` passed (`580` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2144-small-threat-mvp-shell-notification-priority-report.json` passed with `213` report steps in `606.9s`, including `Flutter shell notification priority tests` (`4s`). The verifier's post-report `Small-threat MVP report validator` also passed (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2144-small-threat-mvp-missing-shell-notification-priority-step-report.json` failed full-suite validation with `passed full-suite report is missing required step: Flutter shell notification priority tests`; captured output is in `.workflow\ultracode\avorax-hardening\results\2144-shell-notification-priority-negative-validator.txt`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2144-shell-notification-priority.md`. Remaining proof includes Windows toast delivery, installed packaged UI click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2143

- Added a first-class manual quarantine UI path to `apps\zentor_client\lib\features\quarantine\quarantine_screen.dart`: `Quarantine file` opens only after an explicit destructive confirmation dialog and is disabled while quarantine/configuration/update/scan target-selection work is active.
- Added `ZentorController.quarantineSelectedFile({bool confirmed = false})` in `apps\zentor_client\lib\app\app_state.dart`. It refuses missing confirmation before file picker access, non-desktop hosts, scan/configuration/update/quarantine busy states, picker failures, and cancelled selections; confirmed selections call local-core `quarantine_file` and refresh quarantine state on success.
- Added `LocalCoreClient.quarantineFile(path, threatName, engine)` in `apps\zentor_client\lib\core\local_core\local_core_client.dart`, sending explicit `command`, `path`, `threat_name`, and `engine` JSON fields through the existing local-core stdio IPC boundary.
- Extended Flutter tests: `quarantine_screen_test.dart` covers dialog cancel/confirm, picker call counts, manual quarantine IPC call counts, and disabled controls during busy states; `offline_scan_test.dart` covers confirmation-required, picker cancel/failure, confirmed quarantine, and update-work blocking; `local_core_ipc_diagnostics_test.dart` asserts the exact `quarantine_file` payload labels.
- Wired the small-threat MVP verifier to run `Flutter manual quarantine IPC tests`, and updated `tools\testing\validate-small-threat-mvp-report.ps1` plus source contracts so full-suite reports missing that step fail. The existing scope also records `manual quarantine file-picker UI/controller/IPC guards`.
- Focused verification passed locally: PowerShell parser checks for `tools\testing\verify-small-threat-mvp.ps1` and `tools\testing\validate-small-threat-mvp-report.ps1`; `C:\Users\Brent\develop\flutter\bin\flutter.bat test test\local_core_ipc_diagnostics_test.dart --plain-name "manual quarantine IPC"`; `C:\Users\Brent\develop\flutter\bin\flutter.bat test test\quarantine_screen_test.dart`; `C:\Users\Brent\develop\flutter\bin\flutter.bat test test\offline_scan_test.dart --plain-name quarantine`; `C:\Users\Brent\develop\flutter\bin\flutter.bat analyze`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`580` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2143-small-threat-mvp-manual-quarantine-ui-report.json` passed with `212` report steps in `597.1s`, including `Flutter manual quarantine IPC tests` (`3.6s`), `Flutter quarantine controller tests` (`3.8s`), and `Flutter quarantine screen tests` (`5.1s`). The verifier's post-report `Small-threat MVP report validator` also passed (`1.2s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2143-small-threat-mvp-missing-manual-quarantine-ipc-step-report.json` failed full-suite validation with `passed full-suite report is missing required step: Flutter manual quarantine IPC tests`; captured output is in `.workflow\ultracode\avorax-hardening\results\2143-manual-quarantine-ui-negative-validator.txt`.
- Evidence is recorded in `.workflow\ultracode\avorax-hardening\results\2143-manual-quarantine-ui-controller-ipc.md`. Remaining proof includes installed packaged file-picker click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2142

- Extended `tools\windows\avorax-quarantine.ps1` with a safe `Quarantine` action over release local-core `quarantine_file`.
- Manual quarantine requires a concrete `-TargetPath` and explicit `-ConfirmAction`, rejects `-QuarantineId` for that action, validates the target as an existing non-reparse leaf file, bounds `-ThreatName` and `-Engine` IPC text, invokes local-core through redirected JSON stdin/stdout/stderr, writes repo-contained JSON reports atomically, and restores environment overrides.
- The wrapper records explicit safety/limitation evidence: no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no pre-execution blocking claim, no secure-erase claim, and `manual_quarantine_requires_confirmation=true`.
- Updated `tools\testing\run-avorax-quarantine-wrapper-smoke.ps1`. The smoke uses only harmless exact-hash fixture bytes plus isolated temporary data/quarantine/engine roots, proves `Action Quarantine` without `-ConfirmAction` fails visibly and preserves the source, proves confirmed manual quarantine creates a real quarantined record with the expected detection name and engine label, verifies source removal and `.avoraxq` payload creation, then keeps the existing list, detect-only rescan, confirmed restore, and confirmed delete coverage.
- Wired the small-threat MVP verifier scope from `quarantine management wrapper release-binary rescan/restore/delete smoke` to `quarantine management wrapper release-binary manual/rescan/restore/delete smoke`. `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports missing that stricter scope. Source contracts pin the new action, target validation, confirmation boundary, IPC command, safety field, smoke evidence, verifier scope, and validator scope.
- Focused verification passed locally: PowerShell parser checks for `tools\windows\avorax-quarantine.ps1`, `tools\testing\run-avorax-quarantine-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-quarantine-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`580` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2142-small-threat-mvp-manual-quarantine-wrapper-report.json` passed with `211` steps in `592.3s`, including `Quarantine wrapper release-binary smoke` (`5.9s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2142-small-threat-mvp-missing-manual-quarantine-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: quarantine management wrapper release-binary manual/rescan/restore/delete smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2142-manual-quarantine-negative-validator.txt`.
- Generated wrapper smoke reports include `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-manual.json`, `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-list.json`, `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-rescan.json`, `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-restore.json`, and `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-delete.json`. The manual report records `action=Quarantine`, `explicit_confirmation=true`, `records_count=1`, `raw_response.record.status=quarantined`, `raw_response.record.action_taken=quarantined`, and `manual_quarantine_requires_confirmation=true`.
- Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2141

- Added `tools\windows\avorax-cancel-scan.ps1`, a safe user-facing wrapper over release local-core `cancel_scan`.
- The wrapper resolves `target\release\zentor_local_core.exe`, requires either isolated `-DataRoot` proof or explicit `-UseInstalledDataRoot` for an installed runtime, rejects both together, invokes local-core through redirected JSON stdin/stdout/stderr, validates the returned absolute `cancel-active-scan` token path, proves isolated tokens stay under `DataRoot\runtime`, writes repo-contained JSON reports atomically, and restores `AVORAX_DATA_DIR`.
- The wrapper records explicit safety/limitation evidence: no live malware, no standard EICAR string, no Defender exclusion, no machine-wide component installation, no service installation, no external process kill, no persistent monitoring claim, no pre-execution/kernel blocking claim, `child_process_timeout_cleanup_enabled=true`, and `cooperative-cancel-token-request-only`.
- Added `tools\testing\run-avorax-cancel-scan-wrapper-smoke.ps1`. The smoke uses an isolated temp data root, proves release-binary token creation in `runtime\cancel-active-scan`, verifies `tool=avorax-cancel-scan`, `command=cancel_scan`, `cancel_requested=true`, `cancel_token_exists=true`, `token_under_data_root=true`, `ipc=stdio`, `network_exposed=false`, and verifies negative guards for missing data-root selection and mutually exclusive `-DataRoot`/`-UseInstalledDataRoot`.
- Wired the small-threat MVP verifier to run `Cancel scan wrapper release-binary smoke` after the local scan wrapper smoke. `tools\testing\validate-small-threat-mvp-report.ps1` now requires that step and `cancel scan wrapper release-binary request smoke` scope in full-suite reports. Source contracts now pin the wrapper, smoke, safety flags, limitation text, verifier step, and validator scope.
- Focused verification passed locally: PowerShell parser checks for `tools\windows\avorax-cancel-scan.ps1`, `tools\testing\run-avorax-cancel-scan-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-cancel-scan-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`580` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2141-small-threat-mvp-cancel-scan-wrapper-report.json` passed with `211` steps in `650.3s`, including `Cancel scan wrapper release-binary smoke` (`1.2s`) and final `Small-threat MVP report validator` (`1.2s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2141-small-threat-mvp-missing-cancel-scan-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: cancel scan wrapper release-binary request smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2141-cancel-scan-negative-validator.txt`.
- Generated wrapper smoke report is `.workflow\ultracode\avorax-hardening\results\cancel-scan-wrapper-request.json`. It records `cancel_requested=true`, `cancel_token_exists=true`, `token_under_data_root=true`, `use_installed_data_root=false`, `installed_data_root_requested=false`, `child_process_timeout_cleanup_enabled=true`, and `limitations` including `cooperative-cancel-token-request-only`.
- Remaining proof includes installed packaged UI click-through, installed local-core/service cross-process cancellation E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2140

- Strengthened `tools\testing\run-avorax-local-scan-wrapper-smoke.ps1` so the existing local-scan wrapper progress handling is now release-binary smoke evidence.
- The smoke still creates only harmless exact-hash fixture bytes plus an isolated temporary `avorax_core.asig` signature pack. It now additionally runs `tools\windows\avorax-local-scan.ps1 -ScanType Quick -Path <fixture>` through `target\release\zentor_local_core.exe`, records `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-progress.json`, and verifies `command=quick_scan_selected_paths`, `scan_kind=quick`, `action_mode=detectOnly`, `progress_events>=2`, `files_scanned>=1`, `threats_found>=1`, `quarantined_files=0`, and preserved source bytes.
- The detect-only File scan, explicit confirmed File auto-quarantine, and negative broad Quick auto-quarantine guard remain in the same smoke. The wrapper still defaults to detect-only and refuses broad default-root auto-quarantine without explicit `-Path` targets.
- Updated the small-threat MVP verification scope from `local scan wrapper release-binary smoke` to `local scan wrapper release-binary progress/quarantine smoke`. `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports missing that stricter scope. Source contracts now pin progress JSON line accounting, wrapper report `progress_events`, the progress smoke report, Quick-scan proof, and validator/verifier scope.
- Focused verification passed locally: PowerShell parser checks for `tools\testing\run-avorax-local-scan-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-local-scan-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`579` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2140-small-threat-mvp-local-scan-progress-wrapper-report.json` passed with `210` steps in `584.3s`, including `Local scan wrapper release-binary smoke` (`3.2s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2140-small-threat-mvp-missing-local-scan-progress-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: local scan wrapper release-binary progress/quarantine smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2140-local-scan-progress-negative-validator.txt`.
- Generated wrapper smoke reports include `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-detect.json`, `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-progress.json`, and `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-quarantine.json`. The progress report records `progress_events=3`, `files_scanned=1`, `threats_found=1`, `quarantined_files=0`, and `status=threatsFound`.
- Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, external cancellation E2E from a separate process, persistent background monitoring, signed-driver/pre-execution validation, production ML readiness, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2139

- Extended `tools\windows\avorax-quarantine.ps1` with a `Rescan` action for quarantined payloads.
- `Rescan` requires a concrete `-QuarantineId`, rejects `-ConfirmAction` because the operation is detect-only, requires the selected record to remain `quarantined`, resolves the stored `.avoraxq` payload from `payload_path`/metadata fields, rejects missing/non-absolute/non-`.avoraxq`/reparse payloads, keeps the payload under the checked quarantine root when provided, invokes release local-core `scan_file` with `scan_kind=custom` and `action_mode=detectOnly`, and records rescan status, counts, payload path, raw scan report, and safety flags without restoring or deleting quarantine content.
- Fixed the wrapper report `records_count` to count one returned record as `1` instead of surfacing a scalar-count edge case.
- Updated `tools\testing\run-avorax-quarantine-wrapper-smoke.ps1`. The smoke now creates only harmless exact-hash fixture bytes and an isolated temporary signature pack; proves list count reporting; proves rescan with `-ConfirmAction` fails visibly; proves detect-only rescan reports `threatsFound`, `1` scanned file, at least `1` threat, and `0` quarantines; proves no restore/delete happened during rescan and the `.avoraxq` payload still exists; then proves the existing confirmed restore and confirmed delete flows.
- Wired the small-threat MVP verifier scope to `quarantine management wrapper release-binary rescan/restore/delete smoke`. `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports missing that scope. Source contracts now pin the new action, `EngineRoot` parameter, detect-only scan command, payload resolution helper, no-confirmation rescan boundary, safety fields, smoke report, verifier scope, and validator scope.
- Focused verification passed locally: PowerShell parser checks for `tools\windows\avorax-quarantine.ps1`, `tools\testing\run-avorax-quarantine-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-quarantine-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`579` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2139-small-threat-mvp-quarantine-rescan-wrapper-report.json` passed with `210` steps in `580.1s`, including `Quarantine wrapper release-binary smoke` (`4.9s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2139-small-threat-mvp-missing-quarantine-rescan-scope-report.json` failed full-suite validation with `verification_scope.verified must include required evidence scope: quarantine management wrapper release-binary rescan/restore/delete smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2139-quarantine-rescan-negative-validator.txt`.
- Generated wrapper smoke reports include `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-list.json`, `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-rescan.json`, `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-restore.json`, and `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-delete.json`. The rescan report records `records_count=1`, `rescan_status=threatsFound`, `rescan_files_scanned=1`, `rescan_threats_found=1`, `rescan_quarantined_files=0`, `restore_during_rescan=false`, and `delete_during_rescan=false`.
- Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production ML readiness, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2138

- Added `tools\windows\avorax-status.ps1`, a safe user-facing wrapper over release local-core `health` IPC.
- The wrapper resolves `target\release\zentor_local_core.exe`; optionally sets a checked `AVORAX_ENGINE_DIR`; invokes local-core through redirected JSON stdin/stdout/stderr; validates required health fields; classifies health as `ready`, `degraded`, or `unavailable`; records concrete blockers such as `native_self_test=false`; writes repo-contained JSON reports atomically; restores `AVORAX_ENGINE_DIR`; and supports `-RequireReady` so degraded or unavailable health fails visibly instead of becoming fake readiness.
- The wrapper records explicit safety flags for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no pre-execution blocking claim, no persistent-monitoring claim, no kernel-driver claim, and no trusted network content. The current wrapper reports status only; it does not install, start, or repair services/drivers.
- Added `tools\testing\run-avorax-status-wrapper-smoke.ps1`. The smoke writes only harmless exact-hash fixture bytes plus an isolated temporary `avorax_core.asig` signature pack; proves the release binary loads that temp engine through the wrapper; verifies `health_state=degraded` or `ready`, `engine_status=available`, `native_engine_status=ready`, `native_signature_count>=1`, `ipc=stdio`, `network_exposed=false`, `driver_status=missing`, and explicit no-pre-execution limitations; then proves `-RequireReady` fails visibly on the intentionally incomplete temp engine.
- Wired the small-threat MVP verifier to run `Status wrapper release-binary smoke` after the allowlist wrapper smoke. `tools\testing\validate-small-threat-mvp-report.ps1` now requires that step and `status wrapper release-binary health smoke` scope in `-RequireFullSuite` reports. Source contracts now pin the wrapper response-shape validation, readiness classification, `-RequireReady` failure boundary, safety markers, smoke report, verifier wiring, and validator requirements.
- Focused verification passed locally: PowerShell parser checks for `tools\windows\avorax-status.ps1`, `tools\testing\run-avorax-status-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-status-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`579` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2138-small-threat-mvp-status-wrapper-report.json` passed with `210` steps in `590.4s`, including `Status wrapper release-binary smoke` (`1.7s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2138-small-threat-mvp-missing-status-wrapper-report.json` failed full-suite validation with `passed full-suite report is missing required step: Status wrapper release-binary smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2138-status-wrapper-negative-validator.txt`.
- Generated wrapper smoke report is `.workflow\ultracode\avorax-hardening\results\status-wrapper-health.json`; it records `health_state=degraded`, `ready=false`, `native_signature_count=2`, `native_self_test=false`, `core_service_status=missing`, `guard_status=off`, `driver_status=missing`, `process_monitor_status=notActive`, `behavior_monitor_status=notActive`, and `reputation_status=unavailable` for the isolated smoke engine.
- Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed service repair E2E, installed driver/guard validation, persistent background monitoring, signed-driver/pre-execution validation, production ML readiness, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2137

- Added `tools\windows\avorax-allowlist.ps1`, a safe user-facing wrapper over release local-core allowlist IPC.
- The wrapper supports `List`, confirmed `Add`, and confirmed `Remove`; resolves `target\release\zentor_local_core.exe`; validates add target files and allowlist IDs before IPC; requires `-ConfirmAction` for trust-changing add/remove operations; initializes an explicit repo/temp-scoped allowlist JSON file so add/list/remove do not report fake in-memory persistence; invokes local-core through redirected JSON stdin/stdout/stderr; writes repo-contained JSON reports atomically; and restores `ZENTOR_ALLOWLIST_FILE`.
- The wrapper records explicit safety flags for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no pre-execution blocking claim, no broad-root allowlist, and no folder/hash allowlist support through this wrapper. The current wrapper intentionally manages file allowlist entries only; folder/hash allowlist support remains core/UI functionality outside this release-binary wrapper proof.
- Added `tools\testing\run-avorax-allowlist-wrapper-smoke.ps1`. The smoke writes only harmless exact-hash fixture bytes plus an isolated temporary `avorax_core.asig` signature pack; proves add without `-ConfirmAction` fails visibly; proves confirmed add/list persists an active `sha256:<hex>` entry; proves confirmed-only local scan reports the matching fixture as `allowlisted` with `0` quarantines and preserved source bytes; proves remove without `-ConfirmAction` fails visibly; proves confirmed remove marks the entry inactive; and proves a post-remove confirmed scan quarantines the same harmless fixture again.
- Wired the small-threat MVP verifier to run `Allowlist wrapper release-binary smoke` after the local scan wrapper smoke. `tools\testing\validate-small-threat-mvp-report.ps1` now requires that step and `allowlist wrapper release-binary smoke` scope in `-RequireFullSuite` reports. Source contracts now pin the wrapper CLI actions, confirmation boundary, file-only safety markers, stdin/stdout invocation, smoke reports, verifier wiring, and validator requirements.
- Focused verification passed locally: PowerShell parser checks for `tools\windows\avorax-allowlist.ps1`, `tools\testing\run-avorax-allowlist-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-allowlist-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`577` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2137-small-threat-mvp-allowlist-wrapper-report.json` passed with `209` steps in `584.4s`, including `Allowlist wrapper release-binary smoke` (`4s`) and final full-suite report validation.
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2137-small-threat-mvp-missing-allowlist-wrapper-report.json` failed full-suite validation with `passed full-suite report is missing required step: Allowlist wrapper release-binary smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2137-allowlist-wrapper-negative-validator.txt`.
- Generated wrapper smoke reports are `.workflow\ultracode\avorax-hardening\results\allowlist-wrapper-add.json`, `.workflow\ultracode\avorax-hardening\results\allowlist-wrapper-list.json`, `.workflow\ultracode\avorax-hardening\results\allowlist-wrapper-allowlisted-scan.json`, `.workflow\ultracode\avorax-hardening\results\allowlist-wrapper-remove.json`, and `.workflow\ultracode\avorax-hardening\results\allowlist-wrapper-post-remove-scan.json`.
- Remaining proof includes packaged desktop click-through, installed local-core/service E2E, folder/hash allowlist wrapper support, replacement-race/symlink behavior on an installed host, persistent background service monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2136

- Added `tools\windows\avorax-quarantine.ps1`, a safe user-facing wrapper over release local-core quarantine IPC.
- The wrapper supports `List`, `Restore`, and `Delete`; resolves `target\release\zentor_local_core.exe`; rejects reparse binaries and configured data/quarantine roots; validates quarantine IDs before IPC (`<=128` chars, ASCII letters/digits/hyphen/underscore only); requires `-ConfirmAction` for restore/delete; invokes local-core through redirected JSON stdin/stdout/stderr; writes repo-contained JSON reports atomically; and restores environment overrides.
- The wrapper records explicit safety flags for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no pre-execution blocking claim, and no secure-erase claim. Delete is ordinary quarantine payload deletion after confirmation, not SSD secure erase.
- Added `tools\testing\run-avorax-quarantine-wrapper-smoke.ps1`. The smoke writes only harmless exact-hash fixture bytes plus an isolated temporary `avorax_core.asig` signature pack, creates quarantined records through `tools\windows\avorax-local-scan.ps1`, proves wrapper `List` sees the quarantined record, proves `Restore` without `-ConfirmAction` fails visibly, proves confirmed restore recreates the original fixture bytes, and proves confirmed delete removes the quarantined payload without restoring the original.
- Wired the small-threat MVP verifier to run `Quarantine wrapper release-binary smoke` between the local scan wrapper and watch scan wrapper release-binary smokes. `tools\testing\validate-small-threat-mvp-report.ps1` now requires that step and `quarantine management wrapper release-binary smoke` scope in `-RequireFullSuite` reports. Source contracts now pin the wrapper CLI actions, confirmation boundary, safety markers, stdin/stdout invocation, smoke reports, verifier wiring, and validator requirements.
- Focused verification passed locally: PowerShell parser checks for `tools\windows\avorax-quarantine.ps1`, `tools\testing\run-avorax-quarantine-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-quarantine-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`575` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2136-small-threat-mvp-quarantine-wrapper-report.json` passed with `208` steps in `587.8s`, including `Quarantine wrapper release-binary smoke` (`3.9s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2136-small-threat-mvp-missing-quarantine-wrapper-report.json` failed full-suite validation with `passed full-suite report is missing required step: Quarantine wrapper release-binary smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2136-quarantine-wrapper-negative-validator.txt`.
- Generated wrapper smoke reports are `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-list.json`, `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-restore.json`, and `.workflow\ultracode\avorax-hardening\results\quarantine-wrapper-delete.json`.
- Remaining proof includes packaged desktop click-through, installed local-core/service E2E, persistent background service monitoring, signed-driver/pre-execution validation, production false-positive rates, release-host SBOM/license output, and release packaging on a provisioned host.

## 2026-07-08 continuation checkpoint 2135

- Added `tools\testing\run-release-prereq-host-evidence.ps1`, a ready-or-blocked host evidence wrapper around `tools\windows\avorax-release-prereq-check.ps1 -HostOnly`.
- The wrapper does not install dependencies, enable Developer Mode, change ACLs/settings, weaken Defender, open Windows Settings, or create release artifacts. It runs the prereq checker with explicit `-RepoRoot`, `-CargoPath`, `-FlutterPath`, optional `-DotnetPath`, and a repo-contained `-ReportPath`; then it validates the JSON report schema, `mode=host_only`, repo root, tool path evidence, required host checks, and actionable blocker text.
- Current host evidence is deliberately `blocked`, not green release readiness: `C:\Program Files\dotnet\dotnet.exe` exists but `dotnet --list-sdks` returns no SDKs; Windows symlink support fails with `Administrator privilege required for this operation.`; and Flutter doctor reports missing Visual Studio Desktop C++ build components. Android SDK remains skipped for the Windows antivirus release path.
- Wired the small-threat MVP verifier to run `Release host prerequisite ready-or-blocked evidence` before the dependency evidence gate and to record `generated_reports.release_prereq_host`. `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports without the generated prereq host report, required check statuses, or `release-host prerequisite ready-or-blocked evidence gate` scope. Source contracts now pin the wrapper, verifier wiring, validator requirements, blocker wording, and no-machine-change boundary.
- Focused verification passed locally: PowerShell parser checks for `tools\testing\run-release-prereq-host-evidence.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused prereq wrapper execution captured `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-release-prereq-host.json` as blocked with concrete errors; `validate-small-threat-mvp-report.ps1` accepted the short wiring report; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`573` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2135-small-threat-mvp-release-prereq-host-report.json` passed with `207` steps in `576.5s`, including `Release host prerequisite ready-or-blocked evidence` (`9.3s`), and the verifier's final report-validator pass succeeded (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2135-small-threat-mvp-missing-release-prereq-host-report.json` failed full-suite validation with `small-threat MVP verification report generated_reports is missing required property 'release_prereq_host'`; captured output is in `.workflow\ultracode\avorax-hardening\results\2135-release-prereq-host-negative-validator.txt`.
- Remaining proof includes release-capable Windows host provisioning, Flutter Windows `Avorax.exe`, MSI/installer stage, installed UI/service E2E, signed-driver/pre-execution validation, production false-positive rates, and full release-host SBOM/license output.

## 2026-07-08 continuation checkpoint 2134

- Added `tools\windows\avorax-watch-scan.ps1`, a finite user-facing watch-scan wrapper over the release local-core `watch_poll_scan` command.
- The wrapper requires at least one explicit `-Path` directory, rejects empty/NUL-containing/oversized/missing/reparse targets, rejects broad roots such as filesystem root, Windows, and Program Files, defaults to `detectOnly`, switches to `autoQuarantineConfirmedOnly` only with explicit `-AutoQuarantineConfirmed`, and bounds work with `DurationSeconds` (`1..10`), `PollIntervalMilliseconds` (`50..2000`), and `MaxEvents` (`1..32`).
- The wrapper invokes `target\release\zentor_local_core.exe` through redirected JSON stdin/stdout/stderr, writes repo-contained JSON reports atomically, restores process environment variables, and emits explicit safety flags for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no persistent-monitoring claim, no pre-execution blocking claim, no kernel-driver claim, and no broad default watch roots.
- Added `tools\testing\run-avorax-watch-scan-wrapper-smoke.ps1`, which creates only harmless exact-hash fixture bytes and an isolated temporary signature pack. It proves finite detect-only watch scanning reports a created fixture while leaving it in place with `0` quarantines, proves explicit confirmed quarantine removes only the matching harmless fixture, and proves omitting `-Path` fails visibly with `requires at least one explicit -Path directory`.
- Wired the small-threat MVP verifier to run `Watch scan wrapper finite release-binary smoke` after the local scan wrapper smoke. `tools\testing\validate-small-threat-mvp-report.ps1` now requires that step and `watch scan wrapper finite release-binary smoke` scope in `-RequireFullSuite` reports. Source contracts now pin the wrapper CLI bounds, safety markers, stdin/stdout invocation, smoke reports, verifier wiring, and validator requirements.
- Focused verification passed locally: PowerShell parser checks for `tools\windows\avorax-watch-scan.ps1`, `tools\testing\run-avorax-watch-scan-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-watch-scan-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`572` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2134-small-threat-mvp-watch-scan-wrapper-report.json` passed with `206` steps in `638.5s`, including `Watch scan wrapper finite release-binary smoke` (`9.9s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2134-small-threat-mvp-missing-watch-scan-wrapper-report.json` failed full-suite validation after the required watch-scan step/scope were removed; captured output is in `.workflow\ultracode\avorax-hardening\results\2134-watch-scan-wrapper-negative-validator.txt`.
- Generated wrapper smoke reports are `.workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-detect.json` and `.workflow\ultracode\avorax-hardening\results\watch-scan-wrapper-quarantine.json`.
- Post-documentation gates passed locally: PowerShell parser checks for the wrapper/smoke/verifier/validator; focused watch wrapper smoke; Python source-contracts (`572`); full-suite validation of `.workflow\ultracode\avorax-hardening\results\2134-small-threat-mvp-watch-scan-wrapper-report.json` (`206` steps); Avorax product-copy gate; and no-malware-binaries gate (exit `0`).
- Remaining proof includes packaged desktop click-through, installed local-core/service E2E, persistent background service monitoring, signed-driver/pre-execution validation, production false-positive rates, and release-host SBOM/license output.

## 2026-07-08 continuation checkpoint 2133

- Added `tools\windows\avorax-local-scan.ps1`, a safe local scan wrapper over `target\release\zentor_local_core.exe`.
- The wrapper supports `Quick`, `Full`, `File`, and `Folder` scans; defaults to `detectOnly`; requires explicit `-Path` targets before `-AutoQuarantineConfirmed` can quarantine; resolves reports as repo-contained child paths; invokes local-core through redirected JSON stdin/stdout; restores process environment variables; rejects empty, NUL-containing, oversized, missing, and reparse-point targets; and emits explicit safety flags for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no broad default-root auto-quarantine, and no pre-execution blocking claim.
- Added `tools\testing\run-avorax-local-scan-wrapper-smoke.ps1`, which creates only harmless exact-hash fixture bytes and an isolated temporary signature pack. It proves detect-only reports `threatsFound` while leaving the source fixture in place with `0` quarantines, proves explicit confirmed auto-quarantine quarantines/removes only the matching harmless fixture, and proves `Quick -AutoQuarantineConfirmed` without explicit paths fails with `Auto-quarantine from this wrapper requires explicit -Path targets`.
- Wired the small-threat MVP verifier to run `Local scan wrapper release-binary smoke` after the finite watch-poll release smoke. `tools\testing\validate-small-threat-mvp-report.ps1` now requires that step and `local scan wrapper release-binary smoke` scope in `-RequireFullSuite` reports. Source contracts now pin the wrapper safety markers, CLI modes, stdin/stdout invocation, smoke reports, verifier wiring, and validator requirements.
- Focused verification passed locally: PowerShell parser checks for `tools\windows\avorax-local-scan.ps1`, `tools\testing\run-avorax-local-scan-wrapper-smoke.ps1`, `tools\testing\verify-small-threat-mvp.ps1`, and `tools\testing\validate-small-threat-mvp-report.ps1`; focused `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-avorax-local-scan-wrapper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe`; and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`570` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2133-small-threat-mvp-local-scan-wrapper-report.json` passed with `205` steps in `912.8s`, including `Local scan wrapper release-binary smoke` (`4.1s`) and final `Small-threat MVP report validator` (`2.2s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2133-small-threat-mvp-missing-local-scan-wrapper-report.json` failed full-suite validation with `passed full-suite report is missing required step: Local scan wrapper release-binary smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2133-local-scan-wrapper-negative-validator.txt`.
- Generated wrapper smoke reports are `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-detect.json` and `.workflow\ultracode\avorax-hardening\results\local-scan-wrapper-quarantine.json`.
- Remaining proof includes packaged desktop click-through, installed local-core/service E2E, installed realtime watcher E2E, persistent background scheduling, signed-driver/pre-execution validation, production false-positive rates, and release-host SBOM/license output.

## 2026-07-08 continuation checkpoint 2132

- Added `tools\testing\validate-client-ui-inventory.py`, a dependency-free source gate for the client UI control inventory.
- The gate cross-checks `docs\client-ui.md` against `apps\zentor_client\lib\app\router.dart`, `shared\widgets\zentor_sidebar.dart`, `shared\widgets\zentor_bottom_nav.dart`, and selected high-risk Flutter source markers. It validates the route matrix, desktop/mobile navigation, Control Matrix row shape/statuses, required limitation/empty-state markers, and `61` source-accounted controls across Home, Scan, Protection, Quarantine, Allowlist, Security Events, Settings, Updates, Protected Apps, Onboarding, and Privacy.
- Updated the UI inventory doc to match the visible Settings label `Trusted backup/sync processes text field`.
- Wired the small-threat MVP verifier to run `Client UI inventory source gate` before Dart/Flutter UI tests, and updated `tools\testing\validate-small-threat-mvp-report.ps1` to require the step and matching `client UI tab/button/setting source inventory gate` scope for `-RequireFullSuite` reports.
- Source contracts now pin the new inventory gate, required route/control markers, verifier step, validator step requirement, and scope requirement.
- Focused verification passed locally: `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\validate-client-ui-inventory.py` passed with `11` routes, `9` desktop destinations, `4` mobile destinations, and `61` source-accounted controls; PowerShell parser checks passed for `tools\testing\verify-small-threat-mvp.ps1` and `tools\testing\validate-small-threat-mvp-report.ps1`; and Python source-contracts passed (`568`).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .workflow\ultracode\avorax-hardening\results\2132-small-threat-mvp-client-ui-inventory-report.json` passed with `204` steps in `924.7s`, including `Client UI inventory source gate` (`0.2s`) and final `Small-threat MVP report validator` (`1.7s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2132-small-threat-mvp-missing-client-ui-inventory-report.json` failed full-suite validation with `passed full-suite report is missing required step: Client UI inventory source gate`; captured output is in `.workflow\ultracode\avorax-hardening\results\2132-client-ui-inventory-negative-validator.txt`.
- Remaining proof includes installed packaged desktop click-through, OS picker/elevation/toast rendering, installed local-core/service E2E, signed-driver/pre-execution validation, production false-positive rates, and release-host SBOM/license output.

## 2026-07-08 continuation checkpoint 2131

- Strengthened source-level dependency/license evidence without installing packages, using network access, or claiming a full release-host SBOM.
- `tools\security\avorax-dependency-evidence.ps1` now emits `lockfile_summaries` for Cargo, pub, and Python lockfiles. Each summary records the ecosystem, lockfile path, presence, package count, integrity evidence type, and integrity-entry count. Counts are derived from bounded local reads of the current lockfiles.
- The dependency evidence report now includes `license_inventory` with `status=source_level_partial`, a documented evidence basis, `full_release_sbom_required=true`, `machine_wide_dependency_installation=false`, `network_access_required=false`, a pointer to `docs\dependency-license-inventory.md`, and documented license-note groups for Python ML tooling and the Rust deflate helper family.
- `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports unless dependency evidence includes the new lockfile summaries and license inventory. The validator recomputes lockfile package/integrity counts from the current repository and checks the dependency-license inventory document contains expected license/SBOM markers.
- Source contracts now pin the dependency evidence generator fields, validator fields, lockfile summary validator, license-inventory validator, and no-install/no-network markers.
- Focused verification passed locally: parser checks for `tools\security\avorax-dependency-evidence.ps1` and `tools\testing\validate-small-threat-mvp-report.ps1`; `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\avorax-dependency-evidence.ps1 -RepoRoot . -ReportPath .workflow\ultracode\avorax-hardening\results\2131-dependency-license-evidence.json`; refreshed `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-dependency-evidence.json`; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`567`); and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2130-small-threat-mvp-ransomware-guard-activity-report.json` passed with the stricter dependency/license schema.
- Observed summary counts: root `Cargo.lock` `363` packages and `358` checksum entries; native-engine Cargo lock `89`/`88`; local-core Cargo lock `188`/`186`; guard-service Cargo lock `102`/`100`; API Cargo lock `266`/`265`; Flutter client pub lock `96` packages and `91` SHA-256 entries; Zentor protocol pub lock `48`/`48`; Avorax protocol pub lock `47`/`47`; Python lock `10` exact pins.
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2131-small-threat-mvp-missing-dependency-license-report.json` failed full-suite validation because the generated dependency evidence report was missing `license_inventory`; captured output is in `.workflow\ultracode\avorax-hardening\results\2131-dependency-license-negative-validator.txt`.
- Remaining proof includes complete release-host SBOM/license output from the final build artifacts, Android Gradle dependency-lock generation on an Android-capable host before any Android publishing, production dependency/license review, and release-candidate approval on a provisioned host.

## 2026-07-08 continuation checkpoint 2130

- Expanded the release-binary ransomware-guard smoke from config-only proof to bounded config/activity proof.
- `core\zentor_local_core` now accepts strict `evaluate_ransomware_activity` JSON IPC payloads with required `ransomware_activity`, denied unknown fields, process-path and modified-path text validation, modified-path entry limits, finite `0..1` score checks, renamed-file and time-window bounds, persisted ransomware-guard config loading, protected-root filtering, trusted-process suppression, and critical ransom-note/backup-tamper override handling.
- `tools\testing\run-release-local-core-ransomware-guard-config-smoke.ps1` now verifies release-binary `evaluate_ransomware_activity` behavior using only caller-supplied benign path observations. It proves protected activity is detected, only protected-root paths are counted, outside-only activity is ignored, trusted non-critical activity is suppressed, critical ransom-note/backup-tamper activity is not suppressed, missing activity is rejected, and unbounded path lists are rejected.
- Verifier/report-validator/source-contract wiring now requires `release local-core binary ransomware guard config/activity smoke` and matching verification-scope evidence in full-suite reports.
- Focused verification passed locally: `cargo fmt --manifest-path core\zentor_local_core\Cargo.toml`; `cargo test --manifest-path core\zentor_local_core\Cargo.toml ransomware_activity -- --test-threads=1` passed (`3` tests); `cargo test --manifest-path core\zentor_local_core\Cargo.toml ransomware_guard -- --test-threads=1` passed (`21` tests); and `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-ransomware-guard-config-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe` passed with `Detected protected activity: True`, `Protected paths counted: 25`, `Outside-only ignored: True`, `Trusted non-critical suppressed: True`, `Critical override detected: True`, `Missing activity rejected: True`, and `Unbounded paths rejected: True`.
- Full MVP verification passed locally after a transient first CPL/MSU unit-test failure was retried with more diagnostic assertion output: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2130-small-threat-mvp-ransomware-guard-activity-report.json` passed with `203` steps in `978.1s`, including `release local-core binary ransomware guard config/activity smoke` (`2.3s`) and final `Small-threat MVP report validator` (`2.5s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2130-small-threat-mvp-ransomware-guard-activity-missing-required-step-report.json` failed full-suite validation with `passed full-suite report is missing required step: release local-core binary ransomware guard config/activity smoke`; captured output is in `.workflow\ultracode\avorax-hardening\results\2130-small-threat-mvp-ransomware-guard-activity-negative-validator.txt`.
- Remaining proof includes installed ransomware-guard UI/service E2E, real filesystem change collection from a service or driver, response policy for live endpoint ransomware behavior, signed-driver/pre-execution validation, installed packaged UI click-through, production false-positive rates, and release-host SBOM/license output.

## 2026-07-08 continuation checkpoint 2129

- Added release-binary proof for ransomware-guard configuration persistence and fail-visible validation.
- New `tools\testing\run-release-local-core-ransomware-guard-config-smoke.ps1` runs `target\release\zentor_local_core.exe` through JSON IPC with isolated temporary data, legacy-data, and `AVORAX_RANSOMWARE_GUARD_CONFIG` roots. It creates only benign temporary directories and an inert trusted-process path; it does not simulate encryption, monitor/block real filesystem writes, install services, weaken Defender, or use live malware.
- Verified behavior: `list_ransomware_guard_config` returns a default empty config before persistence; `configure_ransomware_guard` trims and deduplicates protected roots, ignores an empty trusted-process entry, writes the isolated config atomically without leftover staged temp files, and reports `source=avorax_local_core`; `list_ransomware_guard_config` round-trips the same protected roots and trusted process; a broad `C:/` protected root is rejected without modifying the last good config; invalid persisted `C:/Windows` plus empty trusted process fails visibly; and an unknown persisted `enabled` field fails visibly through strict schema parsing.
- Verifier/report-validator wiring now requires `release local-core binary ransomware guard config smoke` and matching `verification_scope.verified` evidence in full-suite reports.
- Focused verification passed locally: PowerShell parser checks for the new smoke, verifier, and validator; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`567` tests); `cargo test --manifest-path core\zentor_local_core\Cargo.toml ransomware_guard -- --test-threads=1` passed (`21` tests); `cargo build --release --manifest-path core\zentor_local_core\Cargo.toml` passed; and `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-ransomware-guard-config-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe` passed with `2` protected roots, `1` trusted process, broad-root rejection, invalid persisted config rejection, and unknown persisted field rejection.
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2129-small-threat-mvp-release-ransomware-guard-config-report.json` passed with `203` steps in `627.6s`, including `release local-core binary ransomware guard config smoke` (`1s`) and final `Small-threat MVP report validator` (`1.2s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2129-negative-missing-release-ransomware-guard-config-report.json` failed full-suite validation with `passed full-suite report is missing required step: release local-core binary ransomware guard config smoke`.
- Post-documentation gates passed: parser checks for the new smoke/verifier/validator, Python source-contracts (`567`), Avorax product-copy gate, no-malware-binaries gate (exit `0`), and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2129-small-threat-mvp-release-ransomware-guard-config-report.json` (`203` steps).
- Remaining proof includes installed ransomware-guard UI/service E2E, real filesystem change monitoring/blocking, signed-driver/pre-execution validation, installed service background loops, packaged UI click-through, production false-positive rates, and response policy for live endpoint ransomware behavior.

## 2026-07-08 continuation checkpoint 2128

- Added release-binary proof for the suspicious-process snapshot observation engine.
- New `tools\testing\run-release-local-core-process-snapshot-smoke.ps1` runs `target\release\zentor_local_core.exe` through JSON IPC with isolated temporary data and legacy-data roots. It sends mocked process observations only; it does not enumerate real host processes, start processes, kill/block processes, install services, weaken Defender, or use live malware.
- Verified behavior: `evaluate_process_snapshot` reports snapshot-only `notActive` status with `userModeSnapshot` capability, `263` observed mocked processes, `8` skipped malformed/over-limit observations, and exactly `2` `suspiciousProcess` findings. The findings explain encoded/hidden script-host evidence and unsigned user-writable remote-transfer evidence. An exact normalized allowlist suppresses the same suspicious remote-transfer fixture to `0` findings, missing `process_observations` returns a visible JSON error, and an unknown nested `auto_quarantine` field exits non-zero while naming the rejected field.
- Verifier/report-validator wiring now requires `release local-core binary process snapshot observation smoke` and matching `verification_scope.verified` evidence in full-suite reports.
- Focused verification passed locally: PowerShell parser checks for the new smoke, verifier, and validator; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`566` tests); `cargo test --manifest-path core\zentor_local_core\Cargo.toml process_snapshot -- --test-threads=1` passed (`4` tests); `cargo build --release --manifest-path core\zentor_local_core\Cargo.toml` passed; and `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-process-snapshot-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe` passed with `263` mocked observations, `8` skipped processes, `2` findings, `0` allowlisted findings, and malformed input exit code `1`.
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2128-small-threat-mvp-release-process-snapshot-report.json` passed with `202` steps in `781.8s`, including `release local-core binary process snapshot observation smoke` (`1s`) and final `Small-threat MVP report validator` (`1.4s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2128-negative-missing-release-process-snapshot-report.json` failed full-suite validation with `passed full-suite report is missing required step: release local-core binary process snapshot observation smoke`.
- Post-documentation gates passed: parser checks for the new smoke/verifier/validator, Python source-contracts (`566`), Avorax product-copy gate, no-malware-binaries gate (exit `0`), and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2128-small-threat-mvp-release-process-snapshot-report.json` (`202` steps).
- Remaining proof includes installed process observation service/driver loop E2E, real OS process inventory collection, service background scheduling, signed-driver/pre-execution validation, installed UI click-through, production false-positive rates, and response policy for live endpoint process actions.

## 2026-07-08 continuation checkpoint 2127

- Added release-binary proof for ZIP nested executable, deceptive nested executable, autorun bundle, autorun.inf command, and shortcut executable bundle carrier review.
- New `tools\testing\run-release-local-core-quick-scan-zip-carrier-review-smoke.ps1` runs `target\release\zentor_local_core.exe` through JSON IPC with isolated temporary data, legacy-data, quarantine, engine, allowlist, and Downloads roots.
- The smoke writes inert benign ZIP fixtures: `invoice-archive.zip` with `invoice.pdf.exe`, `documents-archive.zip` with `documents/receipt.pdf.exe`, `media-autoplay.zip` with `autorun.inf` plus `setup/setup.exe`, `launcher-autoplay.zip` with an autorun executable command, `shortcut-bundle.zip` with `launch/support.lnk` plus `bin/support.exe`, and a benign text note. It creates ZIP files in memory/locally for scanning only; it does not extract archives to disk, execute entries, invoke shell/archive handlers, install packages, download content, or use live malware.
- Verified behavior: `quick_scan_selected_paths` with `scan_kind=quick` and `autoQuarantineConfirmedOnly` scans `5` ZIP carrier fixtures, reports `5` review-only heuristic findings with `archive_suspicious_executable`, `archive_autorun_executable_bundle`, `archive_autorun_inf_executable_command`, and `archive_shortcut_executable_bundle` evidence, reports no scan errors, quarantines `0` files, preserves all source fixtures, and creates no quarantine records.
- Verifier/report-validator wiring now requires `release local-core binary quick-scan ZIP carrier review smoke`, matching `verification_scope.verified` evidence, and `ZIP nested executable/autorun/shortcut carrier review` scope in full-suite reports.
- Focused verification passed locally: PowerShell parser checks for the new smoke, verifier, and validator; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`565` tests); `cargo build --release --manifest-path core\zentor_local_core\Cargo.toml` passed; `cargo test --manifest-path core\zentor_local_core\Cargo.toml quick_scan_reports_zip -- --test-threads=1` passed (`5` tests); and `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-quick-scan-zip-carrier-review-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe` passed with `5` ZIP carriers scanned, `5` threats, and `0` quarantines.
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2127-small-threat-mvp-release-zip-carrier-report.json` passed with `201` steps in `648.8s`, including `release local-core binary quick-scan ZIP carrier review smoke` (`2.5s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2127-negative-missing-release-zip-carrier-report.json` failed full-suite validation with `passed full-suite report is missing required step: release local-core binary quick-scan ZIP carrier review smoke`.
- Post-documentation gates passed: parser checks for the new smoke/verifier/validator, Python source-contracts (`565`), Avorax product-copy gate, no-malware-binaries gate (exit `0`), and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2127-small-threat-mvp-release-zip-carrier-report.json` (`201` steps).
- Remaining proof includes installed packaged desktop click-through, installed service/UI E2E, live archive handler behavior, broader archive parser semantic completeness, encrypted/unsupported archive edge rates beyond existing fail-visible checks, signed-driver/pre-execution validation, and production false-positive-rate evidence.

## 2026-07-08 continuation checkpoint 2126

- Added release-binary proof for registry autorun, URL/LNK shortcut, UNC shortcut, and disk-image autorun carrier review.
- New `tools\testing\run-release-local-core-quick-scan-persistence-shortcut-carrier-smoke.ps1` runs `target\release\zentor_local_core.exe` through JSON IPC with isolated temporary data, legacy-data, quarantine, engine, allowlist, and Downloads roots.
- The smoke writes inert benign fixtures: `autorun.reg`, `support.url`, UTF-16LE `support-link.lnk`, UTF-16LE `support-share.lnk`, `support-media.iso`, plus a benign text note. It does not import registry files, invoke URL/file handlers, resolve shortcut targets, mount disk images, execute autorun commands, download content, or use live malware.
- Verified behavior: `quick_scan_selected_paths` with `scan_kind=quick` and `autoQuarantineConfirmedOnly` scans `5` carrier fixtures, reports `5` review-only heuristic findings with `registry_autorun_remote_launch`, `shortcut_remote_executable_launch`, and `disk_image_autorun_executable` evidence, reports no scan errors, quarantines `0` files, preserves all source fixtures, and creates no quarantine records.
- Verifier/report-validator wiring now requires `release local-core binary quick-scan persistence/shortcut carrier review smoke`, matching `verification_scope.verified` evidence, and `registry/shortcut/disk-image carrier review` scope in full-suite reports.
- Focused verification passed locally: PowerShell parser checks for the new smoke, verifier, and validator; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`564` tests); `cargo build --release --manifest-path core\zentor_local_core\Cargo.toml` passed; and `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-quick-scan-persistence-shortcut-carrier-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe` passed with `5` carriers scanned, `5` threats, and `0` quarantines.
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2126-small-threat-mvp-release-persistence-shortcut-report.json` passed with `200` steps in `659.1s`, including `release local-core binary quick-scan persistence/shortcut carrier review smoke` (`2.5s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2126-negative-missing-release-persistence-shortcut-report.json` failed full-suite validation with `passed full-suite report is missing required step: release local-core binary quick-scan persistence/shortcut carrier review smoke`.
- Post-documentation gates passed: parser checks for the new smoke/verifier/validator, Python source-contracts (`564`), Avorax product-copy gate, no-malware-binaries gate (exit `0`), and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2126-small-threat-mvp-release-persistence-shortcut-report.json` (`200` steps).
- Remaining proof includes installed packaged desktop click-through, installed service/UI E2E, live handler behavior for registry import/URL/LNK/disk images, full shortcut and ISO/UDF semantic parsing, signed-driver/pre-execution validation, and production false-positive-rate evidence.

## 2026-07-08 continuation checkpoint 2125

- Added release-binary proof for autorun INF, email attachment, Office query/macro, OOXML macro relationship, RTF/PDF active content, HTML/SVG web-document, CHM/OneNote, and Office add-in carrier review.
- New `tools\testing\run-release-local-core-quick-scan-document-web-carrier-smoke.ps1` runs `target\release\zentor_local_core.exe` through JSON IPC with isolated temporary data, legacy-data, quarantine, engine, allowlist, and Downloads roots.
- The smoke writes inert benign fixtures: `autorun.inf`, `media-autorun.inf`, `invoice-email.eml`, `remote-query.iqy`, `spreadsheet-link.slk`, macro-enabled and legacy Office carriers, `invoice-package.docm`, RTF/PDF active-content carriers, HTML/SVG web-document carriers, CHM/OneNote carriers, Office add-in carriers, and a benign text note. It does not open documents, execute macros/scripts, invoke shell/application handlers, download content, or use live malware.
- Verified behavior: `quick_scan_selected_paths` with `scan_kind=quick` and `autoQuarantineConfirmedOnly` scans `22` carrier fixtures, reports `22` review-only heuristic findings with the expected reason IDs, reports no scan errors, quarantines `0` files, preserves all source fixtures, and creates no quarantine records.
- Verifier/report-validator wiring now requires `release local-core binary quick-scan document/web carrier review smoke`, matching `verification_scope.verified` evidence, and `autorun INF/email/Office/RTF/PDF/web/help/OneNote/add-in carrier review` scope in full-suite reports.
- Focused verification passed locally: PowerShell parser checks for the new smoke, verifier, and validator; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`563` tests); `cargo build --release --manifest-path core\zentor_local_core\Cargo.toml` passed; and `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-quick-scan-document-web-carrier-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe` passed with `22` carriers scanned, `22` threats, and `0` quarantines.
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2125-small-threat-mvp-release-document-web-report.json` passed with `199` steps in `658s`, including `release local-core binary quick-scan document/web carrier review smoke` (`8s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2125-negative-missing-release-document-web-report.json` failed full-suite validation with `passed full-suite report is missing required step: release local-core binary quick-scan document/web carrier review smoke`.
- Post-documentation gates passed: parser checks for the new smoke/verifier/validator, Python source-contracts (`563`), Avorax product-copy gate, no-malware-binaries gate, and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2125-small-threat-mvp-release-document-web-report.json` (`199` steps).
- Remaining proof includes installed packaged desktop click-through, installed service/UI E2E, live document/application handler behavior, document parser semantic completeness, remote reputation, signed-driver/pre-execution validation, and production false-positive-rate evidence.

## 2026-07-08 continuation checkpoint 2124

- Added release-binary proof for ClickOnce, Java Web Start/JNLP, Windows scriptlet/SCT/WSC, and Windows Installer custom-action carrier review.
- New `tools\testing\run-release-local-core-quick-scan-launch-installer-carrier-smoke.ps1` runs `target\release\zentor_local_core.exe` through JSON IPC with isolated temporary data, legacy-data, quarantine, engine, allowlist, and Downloads roots.
- The smoke writes inert benign fixtures: `support.application`, `support.appref-ms`, `support.jnlp`, `loader.sct`, `component.wsc`, `support-installer.msi`, `support-patch.msp`, plus a benign text note. It does not invoke ClickOnce, Java Web Start, scriptlet/WSH handlers, Windows Installer, App Installer, network downloads, or content execution.
- Verified behavior: `quick_scan_selected_paths` with `scan_kind=quick` and `autoQuarantineConfirmedOnly` scans `7` carrier fixtures, reports `7` review-only `SuspiciousDownloader` heuristic findings with `clickonce_remote_deployment_launch`, `java_web_start_remote_archive_launch`, `windows_scriptlet_remote_script_launch`, and `windows_installer_custom_action_remote_launch`, reports no scan errors, quarantines `0` files, preserves all source fixtures, and creates no quarantine records.
- Verifier/report-validator wiring now requires `release local-core binary quick-scan launch/installer carrier review smoke` and matching `verification_scope.verified` evidence in full-suite reports.
- Focused verification passed locally: PowerShell parser checks for the new smoke, verifier, and validator; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`562` tests); `cargo build --release --manifest-path core\zentor_local_core\Cargo.toml` passed; and `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-quick-scan-launch-installer-carrier-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe` passed with `7` carriers scanned, `7` threats, and `0` quarantines.
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2124-small-threat-mvp-release-launch-installer-report.json` passed with `198` steps in `677.9s`, including `release local-core binary quick-scan launch/installer carrier review smoke` (`3.1s`) and final `Small-threat MVP report validator` (`1.3s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2124-negative-missing-release-launch-installer-report.json` failed full-suite validation with `passed full-suite report is missing required step: release local-core binary quick-scan launch/installer carrier review smoke`.
- Remaining proof includes installed packaged desktop click-through, installed service/UI E2E, live handler behavior for ClickOnce/JNLP/scriptlets/MSI/MSP, Windows trust/capability/prompt semantics, signed-driver/pre-execution validation, and production false-positive-rate evidence.

## 2026-07-08 continuation checkpoint 2123

- Added release-binary proof for Windows App Installer/AppInstaller carrier review.
- New `tools\testing\run-release-local-core-quick-scan-appinstaller-carrier-smoke.ps1` runs `target\release\zentor_local_core.exe` through JSON IPC with isolated temporary data, legacy-data, quarantine, engine, allowlist, and Downloads roots.
- The smoke writes benign inert `support.appinstaller` with `https://example.invalid/packages/support.msixbundle` and benign `docs.appinstaller` with a non-package document link. It does not invoke App Installer, install/register packages, resolve/download URLs, or execute content.
- Verified behavior: `quick_scan_selected_paths` with `scan_kind=quick` and `autoQuarantineConfirmedOnly` scans both fixtures, reports `support.appinstaller` as a review-only `SuspiciousDownloader` heuristic finding with `windows_appinstaller_remote_package_launch`, reports no finding for `docs.appinstaller`, quarantines `0` files, preserves both source fixtures, and creates no quarantine records.
- Verifier/report-validator wiring now requires `release local-core binary quick-scan AppInstaller carrier review smoke` and matching `verification_scope.verified` evidence in full-suite reports.
- Focused verification passed locally: PowerShell parser checks for the new smoke, verifier, and validator; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`561` tests); `cargo build --release --manifest-path core\zentor_local_core\Cargo.toml` passed; and `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-quick-scan-appinstaller-carrier-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe` passed with `2` files scanned, `1` threat, and `0` quarantines.
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2123-small-threat-mvp-release-appinstaller-report.json` passed with `197` steps in `624.3s`, including `release local-core binary quick-scan AppInstaller carrier review smoke` (`1.3s`) and final `Small-threat MVP report validator` (`1.4s`).
- Negative evidence passed: `.workflow\ultracode\avorax-hardening\results\2123-negative-missing-release-appinstaller-report.json` failed full-suite validation with `passed full-suite report is missing required step: release local-core binary quick-scan AppInstaller carrier review smoke`.
- Remaining proof includes installed packaged desktop click-through, installed service/UI E2E, live App Installer handler behavior, Windows package trust/capability semantics, signed-driver/pre-execution validation, and production false-positive-rate evidence.

## 2026-07-08 continuation checkpoint 2122

- Added bounded static Windows App Installer/AppInstaller carrier review for `.appinstaller` manifests.
- `core\zentor_native_engine` now classifies `.appinstaller` as text, counts app-installer manifest markers and remote Windows app package URLs, and emits `windows_appinstaller_remote_package_launch` review-only evidence only when a `.appinstaller` carrier references a remote `.appx`, `.msix`, `.appxbundle`, or `.msixbundle` package.
- `core\zentor_local_core` Quick Scan risky-file selection now includes `.appinstaller`.
- Local-core proof `quick_scan_reports_windows_appinstaller_carrier_for_review` scans benign `Downloads\support.appinstaller` as a `SuspiciousDownloader` heuristic detection and proves `AutoQuarantineConfirmedOnly` leaves the review-only carrier and a benign document-link `.appinstaller` fixture in place.
- Verifier/report-validator wiring now requires `local-core Windows App Installer carrier review reporting`, `native-engine Windows App Installer carrier heuristic detection`, and `Windows App Installer/AppInstaller carrier review` scope in full-suite reports.
- Focused verification passed locally: `cargo fmt --manifest-path core\zentor_native_engine\Cargo.toml`; `cargo fmt --manifest-path core\zentor_local_core\Cargo.toml`; PowerShell parser checks for the verifier and validator; `cargo test --manifest-path core\zentor_native_engine\Cargo.toml appinstaller -- --test-threads=1` (`6` tests); `cargo test --manifest-path core\zentor_local_core\Cargo.toml quick_scan_reports_windows_appinstaller_carrier_for_review -- --test-threads=1` (`1` test); `cargo test --manifest-path core\zentor_local_core\Cargo.toml quick_walk_keeps_risky_files_and_skips_plain_documents -- --test-threads=1` (`1` test); and `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` (`560` tests).
- Full MVP verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2122-small-threat-mvp-windows-appinstaller-report.json` passed in `695.7s`, including `local-core Windows App Installer carrier review reporting` (`1.5s`), `native-engine Windows App Installer carrier heuristic detection` (`0.3s`), and final `Small-threat MVP report validator` (`1.4s`).
- Negative evidence passed: a tampered copy of the 2122 report with the AppInstaller steps/scope removed failed full-suite validation with `passed full-suite report is missing required step: native-engine Windows App Installer carrier heuristic detection`.
- Remaining proof includes installed packaged desktop click-through, installed service/UI E2E, Windows package trust/capability semantics, live App Installer handler behavior, signed-driver/pre-execution validation, and production false-positive-rate evidence.

## 2026-07-08 continuation checkpoint 2121

- Broadened shareable export credential redaction for normal log export and support bundles.
- `LocalEventRepository` now redacts Basic, Digest, Negotiate, and NTLM authorization values through the authorization pattern instead of only bearer-style values.
- Added Cookie/Set-Cookie header redaction, URL-userinfo redaction for values such as `https://user:password@example.test/`, and session/access/refresh token assignment coverage.
- Sensitive map-key redaction now treats cookie/session keys as sensitive alongside authorization/password/token/API-key/client-key/credential keys.
- Raw in-app local event history remains unchanged for audit; only shareable JSON written by `export()` or `exportSupportBundle()` is sanitized.
- Runtime tests now prove Basic auth, cookie header values, session IDs, URL-userinfo passwords, bearer tokens, password/token/API-key assignments, OpenAI/GitHub tokens, JWT-shaped values, and nested sensitive diagnostic keys are absent from exported JSON while safe local paths remain visible.
- The small-threat MVP verifier scope now includes `Basic-auth/cookie/session/URL-userinfo shareable export redaction guards`, and the report validator rejects passed non-skip-Flutter reports that lack that evidence scope.
- Focused verification passed locally: PowerShell parser check; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`560` tests); `flutter test test\local_event_test.dart --plain-name "redacts credentials"` passed (`2` tests); `flutter test test\local_event_test.dart` passed (`44` tests); and `flutter analyze` passed.
- Negative evidence passed: validating `.workflow\ultracode\avorax-hardening\results\2120-small-threat-mvp-shareable-log-redaction-report.json` now fails with `verification_scope.verified must include required evidence scope: Basic-auth/cookie/session/URL-userinfo shareable export redaction guards`.
- MVP verification passed locally with Rust skipped because the change is Flutter/local JSON export privacy hardening plus verifier/report evidence: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -SkipRust -ReportPath .workflow\ultracode\avorax-hardening\results\2121-small-threat-mvp-expanded-export-redaction-report.json` passed with `64` steps in `376.6s`, including `Flutter shareable export credential-redaction tests` (`4.8s`) and final report validation (`1.5s`).
- Remaining proof includes installed packaged desktop click-through, production support-intake/redaction review, installed service behavior, Windows build/package output on a fully provisioned host, signed-driver/pre-execution validation, and broader assurance that every possible proprietary secret format is removed.

## 2026-07-08 continuation checkpoint 2120

- Extended credential redaction from support bundles to normal shareable event-log export.
- `LocalEventRepository.export` now writes sanitized copies of `LocalEvent.toJson()` through `_redactShareableExportValue` before creating `zentor-local-events.json`.
- `LocalEventRepository.exportSupportBundle` now uses the same shareable-export redaction family for diagnostics and local events, preserving the checkpoint 2119 privacy metadata.
- Raw in-app local event history remains unchanged for audit; redaction happens only for JSON written to shareable export files.
- Added Flutter coverage proving exported logs redact credential-like strings such as authorization bearer values, password/token assignments, and OpenAI-style keys while `repository.load()` still contains the original local audit details.
- Promoted this coverage into the small-threat MVP verifier as `Flutter shareable export credential-redaction tests`.
- Updated `tools\testing\validate-small-threat-mvp-report.ps1` so passed non-skip-Flutter reports must contain that step and the `shareable log/support-bundle credential-redaction guards` verification-scope text.
- Updated Python source contracts so the shared redaction helper, event-log export use, support-bundle use, verifier step, and validator requirement cannot silently disappear.
- Focused verification passed locally: PowerShell parser check; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`560` tests); `flutter test test\local_event_test.dart --plain-name "redacts credentials"` passed (`2` tests); `flutter test test\local_event_test.dart` passed (`44` tests); and `flutter analyze` passed.
- Negative evidence passed: validating `.workflow\ultracode\avorax-hardening\results\2119-small-threat-mvp-support-bundle-redaction-report.json` now fails with `passed full-suite report is missing required step: Flutter shareable export credential-redaction tests`.
- MVP verification passed locally with Rust skipped because the change is Flutter/local JSON export privacy hardening plus verifier/report evidence: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -SkipRust -ReportPath .workflow\ultracode\avorax-hardening\results\2120-small-threat-mvp-shareable-log-redaction-report.json` passed with `64` steps in `300.3s`, including `Flutter shareable export credential-redaction tests` (`4.1s`) and final report validation (`1.2s`).
- Remaining proof includes installed packaged desktop click-through, production support-intake/redaction review, installed service behavior, Windows build/package output on a fully provisioned host, signed-driver/pre-execution validation, and broader assurance that every possible proprietary secret format is removed.

## 2026-07-08 continuation checkpoint 2119

- Hardened support-bundle privacy so the export path no longer trusts callers to avoid credential-like strings in event details or diagnostics.
- `LocalEventRepository.exportSupportBundle` now writes sanitized copies of diagnostics and events through `_redactSupportBundleValue` instead of writing the raw maps.
- The redactor replaces sensitive map-key values and free-text tokens with `[redacted]`, including authorization/password/passphrase/secret/token/API-key/client-key/public-client-key/credential keys, bearer tokens, password/token/API-key assignments, OpenAI-style `sk-` keys, GitHub tokens, and JWT-shaped values.
- Support-bundle privacy metadata now records `credential_redaction_applied=true` and `redacted_value_marker=[redacted]`.
- Normal local event history and normal event-log export remain unchanged for local audit; the redaction is applied only to support-bundle output intended for troubleshooting/sharing.
- Focused verification passed locally: `flutter test test\local_event_test.dart --plain-name "support bundle"` (`3` tests), `flutter test test\logs_screen_test.dart test\local_event_test.dart test\settings_accessibility_test.dart --plain-name "support bundle"` (`9` tests), `flutter test test\local_event_test.dart` (`43` tests), `flutter analyze`, and Python source-contracts (`560`).
- MVP verification passed locally with Rust skipped because the change is Flutter/local JSON export privacy hardening: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -SkipRust -ReportPath .workflow\ultracode\avorax-hardening\results\2119-small-threat-mvp-support-bundle-redaction-report.json` passed with `63` steps in `299.2s`, including `Flutter support-bundle export tests` (`6.4s`) and final report validation (`1.2s`).
- Remaining proof includes installed packaged desktop click-through, production support-intake/redaction review, installed service behavior, Windows build/package output on a fully provisioned host, and signed-driver/pre-execution validation.

## 2026-07-08 continuation checkpoint 2118

- Promoted support-bundle export coverage from incidental Flutter test coverage to a first-class small-threat MVP verifier and report-validator requirement.
- `tools\testing\verify-small-threat-mvp.ps1` now runs `Flutter support-bundle export tests` with `test\logs_screen_test.dart`, `test\local_event_test.dart`, and `test\settings_accessibility_test.dart --plain-name support bundle`.
- `tools\testing\validate-small-threat-mvp-report.ps1` now rejects any passed report that did not skip Flutter if the `Flutter support-bundle export tests` step or the `support-bundle export confirmation/busy/privacy guards` verification-scope text is missing.
- Source contracts now pin the verifier step, settings/logs/local-event test files, plain-name filter, report-validator step requirement, and scope requirement.
- Focused verification passed locally: PowerShell parser check; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`559` tests); and `flutter test test\logs_screen_test.dart test\local_event_test.dart test\settings_accessibility_test.dart --plain-name "support bundle"` passed (`8` tests).
- Negative evidence passed: validating `.workflow\ultracode\avorax-hardening\results\2117-small-threat-mvp-flutter-support-bundle-report.json` now fails with `passed full-suite report is missing required step: Flutter support-bundle export tests`.
- MVP verification passed locally with Rust skipped because the change is verifier/report evidence plus Flutter UI/local JSON export coverage: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -SkipRust -ReportPath .workflow\ultracode\avorax-hardening\results\2118-small-threat-mvp-flutter-support-bundle-required-report.json` passed with `63` steps in `336.9s`, including `Flutter support-bundle export tests` (`6.7s`) and final report validation (`1.2s`).
- Remaining proof includes installed packaged desktop click-through, production support-intake/redaction review, installed service behavior, Windows build/package output on a fully provisioned host, and signed-driver/pre-execution validation.

## 2026-07-08 continuation checkpoint 2117

- Added safe diagnostic support-bundle export from Logs and Settings.
- `LocalEventRepository.exportSupportBundle` writes `avorax-support-bundle.json` through the same bounded atomic export path as local event-log export.
- The bundle records schema version, generated UTC timestamp, diagnostics, local events, and privacy flags: no file contents, no quarantine payloads, no credentials, no live malware, local event paths/errors may be present, and manual review is required before sharing.
- `ZentorController.exportSupportBundle(confirmed: true)` requires explicit confirmation, rejects overlapping exports, exposes `supportBundleExportInFlight`, logs confirmation-required/busy/exported/failed events, bounds exported path display, and surfaces failures through state instead of swallowing exceptions.
- Logs and Settings now show an `Export support bundle` action with confirmation dialogs and disabled busy states.
- Focused verification passed locally: `dart format` on changed Dart files; `flutter test test\logs_screen_test.dart` (`6` tests); `flutter test test\local_event_test.dart` (`42` tests); `flutter test test\settings_accessibility_test.dart` (`72` tests); combined `flutter test test\logs_screen_test.dart test\local_event_test.dart test\settings_accessibility_test.dart` (`120` tests); `flutter analyze`; Python source-contracts (`559`); Avorax product-copy gate; and no-malware-binaries gate.
- MVP verification passed locally with Rust skipped because the change is Flutter/local JSON export only: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -SkipRust -ReportPath .workflow\ultracode\avorax-hardening\results\2117-small-threat-mvp-flutter-support-bundle-report.json` passed with `62` steps in `243.2s`; standalone `tools\testing\validate-small-threat-mvp-report.ps1` validation of that report also passed with `require_full_suite=False`.
- Remaining proof includes installed packaged desktop click-through, production support-intake/redaction review, installed service behavior, Windows build/package output on a fully provisioned host, and signed-driver/pre-execution validation.

## 2026-07-08 continuation checkpoint 2116

- Promoted the no-EICAR harmless-threat smoke report into the main small-threat MVP generated-report matrix as `generated_reports.no_eicar_harmless_threat`.
- Updated `tools\testing\verify-small-threat-mvp.ps1` so the full suite writes `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-no-eicar-harmless-threat.json` through `tools\testing\run-no-eicar-local-core-harmless-threat-smoke.ps1 -ReportPath`.
- Updated `tools\testing\validate-small-threat-mvp-report.ps1` so passed non-skip-Rust reports resolve and parse that generated report, require the expected underlying `run-release-local-core-smoke.ps1`, and reject any safety-policy drift such as live malware, standard EICAR string/file creation, Defender exclusions, network access, or machine-wide changes.
- Updated source contracts so the verifier, validator, and no-EICAR wrapper remain wired together and preserve the no-Defender-bypass/no-network policy.
- Focused verification passed locally: PowerShell parser check; `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py` passed (`559` tests); direct no-EICAR smoke passed in `1.5s` and wrote `.workflow\ultracode\avorax-hardening\results\2116-no-eicar-harmless-threat-smoke.json`; and `verify-small-threat-mvp.ps1 -SkipRust -SkipFlutter` passed with `10` steps in `23.5s`.
- Full verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2116-small-threat-mvp-full-report.json` passed with `192` steps in `499.0s`, including `release local-core binary no-EICAR harmless threat validation smoke` (`1.6s`) and `Small-threat MVP report validator -RequireFullSuite` (`1.2s`).
- Negative evidence passed: a copied generated report with `fixture_policy.defender_exclusion_required=true` failed validation with `no-EICAR harmless-threat generated report fixture_policy.defender_exclusion_required must be JSON boolean False.`
- Remaining proof includes installed desktop UI click-through, installed local-core/service E2E, Windows app build/package output on a provisioned host, signed-driver/pre-execution validation, and broader production false-positive-rate evidence.

## 2026-07-08 continuation checkpoint 2115

- Added `tools\testing\run-no-eicar-local-core-harmless-threat-smoke.ps1`, a no-EICAR validation wrapper for the real release local-core safe exact-hash scan/quarantine/restore smoke.
- The script runs `tools\testing\run-release-local-core-smoke.ps1` against the release `zentor_local_core.exe`, writes a repo-contained JSON evidence report, and records that it uses no live malware, no standard EICAR file/string, no Defender exclusion, no network access, and no machine-wide changes.
- Wired the new step into `tools\testing\verify-small-threat-mvp.ps1` as `release local-core binary no-EICAR harmless threat validation smoke`; `tools\testing\validate-small-threat-mvp-report.ps1` now rejects full-suite reports that omit that step or the matching verification scope.
- Added Python source-contract coverage so the wrapper must keep using the release-binary smoke, must write an atomic report, and must not call Defender-exclusion, network, or process-launch bypass helpers.
- Focused verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-no-eicar-local-core-harmless-threat-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe -ReportPath .workflow\ultracode\avorax-hardening\results\2115-no-eicar-harmless-threat-smoke.json` completed in `1.4s`, reporting detect-only `threatsFound`, confirmed-only quarantine, `.avoraxq` payload evidence, quarantine listing, and restore.
- Full verification passed locally: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2115-small-threat-mvp-full-report.json` passed with `192` steps in `500.6s`, including `release local-core binary no-EICAR harmless threat validation smoke` (`1.7s`) and final full-suite report validation (`1.1s`).
- Rechecked release-host prerequisites after local Flutter/Dart/Cargo/Git setup: `.workflow\ultracode\avorax-hardening\results\2115-release-prereq-host-refresh.json` remains `ok=false` because the host still lacks a .NET SDK, Windows symlink support/Developer Mode, and Visual Studio Desktop C++ components.
- Remaining proof includes installed desktop UI click-through, installed local-core/service E2E, Windows app build/package output on a provisioned host, signed-driver/pre-execution validation, and broader production false-positive-rate evidence.

## 2026-07-08 continuation checkpoint 2114

- Wired the release-proven finite `watch_poll_scan` local-core command into Flutter Protection lifecycle as an app-lifetime, user-mode polling loop. The loop starts only after best-effort watcher roots are active, stops on protection shutdown/dispose/failure cleanup, and remains bounded to a 1-minute app timer that runs a 4-second local-core poll with a 200 ms inner poll interval and at most 8 events per tick.
- Added typed `WatchPollScanResult` and `WatchPollScanSummary` parsing in `LocalCoreClient`, including bounded poll metrics, limitations, and scan-error diagnostics for malformed or failed IPC responses.
- Added `watchPollLoopStatus` / `watchPollLoopStatusReason`, single-flight `_watchPollEvaluationInFlight`, routine-event dedupe, explicit busy/failure/limited/threat/clean audit events, and update/configuration guards that treat an active watch-poll loop as active protection work.
- Updated the Protection tab User-mode monitor detail so the finite scan-loop status is visible and the UI continues to state that this is post-write user-mode polling, not persistent service monitoring or kernel pre-execution blocking.
- Updated the small-threat MVP verifier, report validator, and Python source contracts so the full report now requires `Flutter watch-poll IPC diagnostics tests`, `Flutter watch-poll loop controller tests`, and `app-lifetime finite watch-poll scan loop controller evidence`.
- Focused verification passed locally: `flutter test test\offline_scan_test.dart --plain-name watch-poll` (`3` tests), `flutter test test\local_core_ipc_diagnostics_test.dart --plain-name watch-poll` (`2` tests), `flutter analyze`, broader protection/watcher/process IPC subsets, and Python source-contracts (`558`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`191` steps in `498.2s`) for `.workflow\ultracode\avorax-hardening\results\2114-small-threat-mvp-full-report.json`, including `Flutter watch-poll IPC diagnostics tests` (`3.5s`) and `Flutter watch-poll loop controller tests` (`3.5s`).
- Post-documentation gates passed locally: Python source-contracts (`558`), Avorax product-copy gate, no-malware-binaries gate (exit `0`), and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2114-small-threat-mvp-full-report.json` (`191` steps).
- Remaining proof includes installed app/service filesystem monitoring E2E, background/service-mode monitoring while the UI is closed, Windows filesystem notification or minifilter proof, signed-driver/pre-execution validation, packaged desktop UI/service E2E, broader production false-positive-rate evidence, release packaging, and production update/deployment approval evidence.

## 2026-07-07 continuation checkpoint 2113

- Added bounded local-core `watch_poll_scan` IPC for finite user-mode polling sessions. The command validates watch roots through the existing non-following watcher path checks, applies strict `duration_ms`, `poll_interval_ms`, and `max_events` bounds, scans stable new/changed files, and reports explicit limitations instead of claiming persistent service monitoring or pre-execution blocking.
- Added bounded non-following watch candidate collection in `core\zentor_local_core\src\watcher\mod.rs`, including file-count/depth limits and skipped unsafe link/reparse targets.
- Added release-binary proof `tools\testing\run-release-local-core-watch-poll-scan-smoke.ps1`. The smoke runs `target\release\zentor_local_core.exe` directly through JSON IPC with isolated data/quarantine/allowlist/engine roots, writes a temporary exact-hash pack for benign `harmless-watch-poll-known-bad-fixture` bytes, creates `created-during-watch.bin` during the finite polling session, and verifies `1` event observed, `1` file scanned, `1` threat found, `1` file quarantined, source removal, a quarantine record, and a `.avoraxq` payload.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary finite watch-poll scan/quarantine smoke` fail validation.
- Focused verification passed locally: PowerShell parser checks, rustfmt check, local-core watcher Cargo tests (`13`), watch-poll command tests (`2`), release local-core build, focused release watch-poll smoke, Python source-contracts (`558`), and intentional old-report validator failure against 2112.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`189` steps in `494.1s`) for `.workflow\ultracode\avorax-hardening\results\2113-small-threat-mvp-full-report.json`, including the new release watch-poll smoke (`4.7s`).
- Post-documentation gates passed: Python source-contracts (`558`), Avorax product-copy gate, no-malware-binaries gate (exit `0`), and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2113-small-threat-mvp-full-report.json` (`189` steps).
- Remaining proof includes installed realtime watcher/service E2E, installed UI wiring for a long-running watcher loop, broader representative benign false-positive rates, installed desktop UI/service E2E, release packaging, signed-driver/pre-execution validation, and production update/deployment approval evidence.

## 2026-07-07 continuation checkpoint 2112

- Tightened best-effort watcher honesty across local-core and Flutter UI so the product no longer sounds like `start_watch` starts persistent realtime service monitoring or pre-execution blocking.
- Added local-core watch-plan limitations `one-shot-watch-plan-only`, `no-persistent-service-monitor`, and `no-kernel-pre-execution-blocking` alongside the existing accessible-path filtering limitation.
- Updated Protection UI/controller wording from "running monitoring" to "best-effort folder watch plan/roots prepared" wording with visible limitations.
- Added release-binary watcher proof `tools\testing\run-release-local-core-watcher-honesty-smoke.ps1`, which runs `target\release\zentor_local_core.exe` directly through JSON IPC, creates temporary benign path fixtures, verifies `start_watch` accepts only an accessible directory, filters missing/non-directory paths, returns the explicit limitation set, verifies empty `start_watch` stops with no-path limitations, and verifies `stop_watch` reports stopped.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary watcher honesty smoke` fail validation.
- Focused verification passed locally: PowerShell parser checks, local-core watcher Cargo tests (`10`), Flutter watcher/UI subset (`8`), Python source-contracts (`557`), release local-core build, intentional old-report validator failure against 2111, and the new release watcher honesty smoke.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`188` steps in `494.8s`) for `.workflow\ultracode\avorax-hardening\results\2112-small-threat-mvp-full-report.json`, including the new release watcher honesty smoke (`0.6s`).
- Post-documentation gates passed: Python source-contracts (`557`), Avorax product-copy gate, no-malware-binaries gate (exit `0`), and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2112-small-threat-mvp-full-report.json` (`188` steps).
- Remaining proof includes installed realtime watcher/service E2E, broader representative benign false-positive rates, installed desktop UI/service E2E, release packaging, signed-driver/pre-execution validation, and production update/deployment approval evidence.

## 2026-07-07 continuation checkpoint 2111

- Added release-binary allowlist honored proof `tools\testing\run-release-local-core-allowlist-honored-smoke.ps1` for a benign confirmed exact-hash fixture that must remain visible but must not be quarantined after explicit user allowlisting.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, writes a temporary native exact-hash signature pack for `harmless-known-bad-allowlisted-fixture`, adds the fixture through JSON `add_allowlist_entry`, and verifies `list_allowlist` persisted an active `sha256:<hex>` allowlist record before scanning.
- The proof confirms `scan_file` with `scan_kind=custom` and `AutoQuarantineConfirmedOnly` returns `threatsFound`, reports one allowlisted confirmed detection with `recommended_action=allowlist`, has no scan errors, quarantines `0` files, attaches no quarantine ID/path to the detection, preserves source bytes, and creates no quarantine records or `.avoraxq` payloads.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary allowlist confirmed-fixture no-quarantine smoke` fail validation.
- Focused verification passed locally: PowerShell parser checks for changed scripts, Python source-contracts (`556`), and the new release allowlist honored smoke.
- Negative evidence passed: validating the old 2110 full report now fails with `passed full-suite report is missing required step: release local-core binary allowlist confirmed-fixture no-quarantine smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`187` steps in `740.2s`) for `.workflow\ultracode\avorax-hardening\results\2111-small-threat-mvp-full-report.json`, including the new release allowlist honored smoke (`1.7s`).
- Remaining proof includes broader representative benign false-positive rates, installed desktop UI/service E2E, release packaging, installed realtime watcher/service behavior, signed-driver/pre-execution validation, and production update/deployment approval evidence.

## 2026-07-07 continuation checkpoint 2110

- Added release-binary Quick Scan family-script proof `tools\testing\run-release-local-core-quick-scan-family-script-smoke.ps1` for benign ransomware-note/backup-delete, credential-staging/network, miner-pool/persistence, and downloader-plus-persistence script indicators.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, and `ZENTOR_ALLOWLIST_FILE` overrides, while setting `AVORAX_ENGINE_DIR` to the repo root so the release binary loads the real bundled `assets\zentor_native` packs through normal discovery.
- The smoke writes a valid empty allowlist JSON array, preflights bundled `signatures`, `rules`, `ml`, and `trust` directories, writes inert `.ps1`/`.js` family-script fixtures plus a benign note under a temporary `Downloads` folder, and invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`.
- The proof confirms the release binary scans all `4` family-script fixtures, returns `threatsFound`, reports `4` review-only findings for ransomware, infostealer, miner, and persistence categories with bundled rule IDs `ZNE-RULE-RANSOM-BACKUP-DELETE-NOTE`, `ZNE-RULE-INFOSTEALER-CREDS-ARCHIVE-NETWORK`, `ZNE-RULE-MINER-POOL-PERSISTENCE`, and `ZNE-RULE-PERSISTENCE-RUNKEY-SCRIPT`, has no scan errors, quarantines `0` files, preserves every source carrier plus a benign non-matching file, and creates no quarantine records.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan family script review smoke` fail validation.
- Focused verification passed locally: the new release family-script smoke, PowerShell parser checks for changed scripts, Python source-contracts (`555`), and intentional old-report validator failure against 2109 with `passed full-suite report is missing required step: release local-core binary quick-scan family script review smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`186` steps in `844.6s`) for `.workflow\ultracode\avorax-hardening\results\2110-small-threat-mvp-full-report.json`, including the new release Quick Scan family-script review smoke (`2.6s`).
- Post-documentation gates passed: Python source-contracts (`555`), Avorax product-copy gate, no-malware-binaries gate (exit `0`), and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2110-small-threat-mvp-full-report.json` (`186` steps).
- Remaining proof includes broader representative benign script/family corpora and false-positive rates, installed desktop UI/service E2E, release packaging, installed realtime watcher/service behavior, signed-driver/pre-execution validation, and production update/deployment approval evidence.

## 2026-07-07 continuation checkpoint 2109

- Added release-binary Quick Scan script-carrier proof `tools\testing\run-release-local-core-quick-scan-script-carrier-smoke.ps1` for benign `.ps1`, `.jse`, `.cmd`, `.vbs`, `.hta`, and `.wsf` fixtures.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, creates isolated engine subdirectories without signature/rule packs, writes inert script-carrier text fixtures with static encoded-script and/or download-execute markers, and invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`.
- The proof confirms the release binary scans all `6` script-carrier fixtures, returns `threatsFound`, reports `6` review-only heuristic findings with `encoded_script_command` and/or `download_execute_script` evidence, has no scan errors, quarantines `0` files, preserves every source carrier plus a benign non-matching file, and creates no quarantine records.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan script carrier review smoke` fail validation.
- Focused verification passed locally: the new release script-carrier smoke, PowerShell parser checks for changed scripts, Python source-contracts (`554`), and intentional old-report validator failure against 2108 with `passed full-suite report is missing required step: release local-core binary quick-scan script carrier review smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`185` steps in `475.9s`) for `.workflow\ultracode\avorax-hardening\results\2109-small-threat-mvp-full-report.json`, including the new release Quick Scan script-carrier review smoke (`2.3s`).
- Post-documentation gates passed: Python source-contracts (`554`), Avorax product-copy gate, no-malware-binaries gate, and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2109-small-threat-mvp-full-report.json` (`185` steps).
- Remaining proof includes broader representative benign script corpora and false-positive rates, installed desktop UI/service E2E, release packaging, installed realtime watcher/service behavior, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2108

- Added local-core regressions `quick_scan_reports_archive_entry_count_limit_as_not_clean` and `quick_scan_reports_archive_total_content_limit_as_not_clean`, which scan benign ZIP-framed carriers and verify `CompletedWithErrors`, `0` threats, `0` quarantines, skipped-file accounting, visible `archive_content_scan_limited` scan-error detail, and source-file preservation.
- Added native regression `benign_archive_entry_location_observations_do_not_accumulate_into_threat` and filtered weak archive-entry `location_observation` / `filename_observation` evidence out of archive-entry heuristic aggregation, so entry count alone cannot turn benign archive metadata into a threat.
- Mapped native `review_or_quarantine_by_policy` recommendations to local `Review` action unless stronger confirmed evidence maps to quarantine, and tightened the ZIP shortcut bundle regression around review-only behavior.
- Added release-binary Quick Scan archive count/total proof `tools\testing\run-release-local-core-quick-scan-archive-count-total-smoke.ps1` for benign `.zip`, `.jar`, `.appx`, and `.appxbundle` carriers.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, creates isolated engine subdirectories without a signature pack, builds entry-count carriers with `65` stored entries and total-content carriers with five `900 KiB` stored entries, and invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`.
- The proof confirms the release binary scans all `8` count/total archive carriers, returns `completedWithErrors`, reports `8` skipped files and carrier-specific scan errors with `archive_content_scan_limited`, reports `0` threats, quarantines `0` files, preserves each source carrier, and creates no quarantine records.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan archive count/total fail-visible smoke` fail validation.
- Focused verification passed locally: native and local-core rustfmt checks, focused native weak-signal archive regression, focused native archive rule/heuristic regression, focused local-core archive count/total regressions, focused local-core native-action regression, focused local-core ZIP shortcut bundle regression, broad local-core `quick_scan_reports` filter (`50` passed), release local-core build, the new release Quick Scan archive count/total smoke, and Python source-contracts (`553`).
- Negative evidence passed: validating the old 2107 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan archive count/total fail-visible smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`184` steps in `497.4s`) for `.workflow\ultracode\avorax-hardening\results\2108-small-threat-mvp-full-report.json`, including the new release Quick Scan archive count/total fail-visible smoke.
- Post-documentation gates passed: Python source-contracts (`553`), Avorax product-copy gate, no-malware-binaries gate, and full-suite validation of `.workflow\ultracode\avorax-hardening\results\2108-small-threat-mvp-full-report.json` (`184` steps).
- Remaining proof includes live-malware-free production false-positive measurement, representative archive edge rates across broader benign corpora, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2107

- Added local-core regression `quick_scan_reports_nested_archive_depth_limit_as_not_clean`, which scans a benign ZIP chain `level1.zip -> level2.zip -> level3.zip` and verifies `CompletedWithErrors`, `0` threats, `0` quarantines, one skipped file, visible `archive_content_scan_limited` scan-error detail, `configured archive-depth limit` text, and source-file preservation.
- Added release-binary Quick Scan archive depth proof `tools\testing\run-release-local-core-quick-scan-archive-depth-smoke.ps1` for benign nested-depth `.zip`, `.jar`, `.appx`, and `.appxbundle` carriers.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, creates isolated engine subdirectories without a signature pack, builds nested ZIP chains using `System.IO.Compression.ZipArchive` without calling `Expand-Archive`, and invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`.
- The first release-smoke attempt found that an `.appxbundle` fixture containing nested `store.appx` could also trigger review heuristics, so the final proof uses direct ZIP-framed `.appxbundle` depth entries to isolate archive-depth evidence only.
- The proof confirms the release binary scans all `4` depth-limit archive carriers, returns `completedWithErrors`, reports `4` skipped files and carrier-specific scan errors with `archive_content_scan_limited`, `configured archive-depth limit`, and the "did not extract files or treat deeper archive content as clean" explanation, reports `0` threats, quarantines `0` files, preserves each source carrier, and creates no quarantine records.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan archive depth fail-visible smoke` fail validation.
- Focused verification passed locally: local-core rustfmt check, the new local-core archive depth-limit regression, release local-core build, the new release Quick Scan archive depth smoke, and Python source-contracts (`552`).
- Negative evidence passed: validating the old 2106 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan archive depth fail-visible smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`183` steps in `438.9s`) for `.workflow\ultracode\avorax-hardening\results\2107-small-threat-mvp-full-report.json`, including the new release Quick Scan archive depth fail-visible smoke (`1.6s`).
- Remaining proof includes live-malware-free production false-positive measurement, representative archive edge rates across broader benign corpora, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2106

- Added local-core regressions `quick_scan_reports_encrypted_archive_content_limit_as_not_clean` and `quick_scan_reports_unsupported_archive_content_limit_as_not_clean`, which scan benign ZIP local-header fixtures with the encrypted general-purpose flag or unsupported compression method and verify `CompletedWithErrors`, `0` threats, `0` quarantines, one skipped file, visible `archive_content_scan_limited` scan-error detail, and source-file preservation.
- Added release-binary Quick Scan archive encryption/unsupported proof `tools\testing\run-release-local-core-quick-scan-archive-encryption-unsupported-smoke.ps1` for benign encrypted and unsupported-compression `.zip`, `.jar`, `.appx`, and nested `.appxbundle` carriers.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, creates isolated engine subdirectories without a signature pack, writes direct ZIP local-header bytes with encrypted flags or compression method `99` for `.zip`, `.jar`, and `.appx` carriers, builds nested `.appxbundle` carriers using `System.IO.Compression.ZipArchive` without calling `Expand-Archive`, and invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`.
- The proof confirms the release binary scans all `8` encrypted/unsupported archive carriers, returns `completedWithErrors`, reports `8` skipped files and carrier-specific scan errors with `archive_content_scan_limited` and the "did not extract files or treat unscanned archive content as clean" explanation, reports `0` threats, quarantines `0` files, preserves each source carrier, and creates no quarantine records.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan archive encryption/unsupported fail-visible smoke` fail validation.
- Focused verification passed locally: local-core rustfmt check, focused local-core archive content-limit regressions (`4` passed), release local-core build, the new release Quick Scan archive encryption/unsupported smoke, and Python source-contracts (`551`).
- Negative evidence passed: validating the old 2105 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan archive encryption/unsupported fail-visible smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`182` steps in `441s`) for `.workflow\ultracode\avorax-hardening\results\2106-small-threat-mvp-full-report.json`, including the new release Quick Scan archive encryption/unsupported fail-visible smoke (`2.7s`).
- Remaining proof includes live-malware-free production false-positive measurement, representative archive edge rates across broader benign corpora, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2105

- Added local-core regression `quick_scan_reports_truncated_archive_content_limit_as_not_clean`, which scans a benign truncated ZIP local-header fixture and verifies `CompletedWithErrors`, `0` threats, `0` quarantines, one skipped file, visible `archive_content_scan_limited` scan-error detail, and source-file preservation.
- Added release-binary Quick Scan archive truncation proof `tools\testing\run-release-local-core-quick-scan-archive-truncation-smoke.ps1` for benign truncated `.zip`, `.jar`, `.appx`, and nested `.appxbundle` carriers.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, creates isolated engine subdirectories without a signature pack, writes direct truncated ZIP local-header bytes for `.zip`, `.jar`, and `.appx` carriers, builds the nested `.appxbundle` carrier using `System.IO.Compression.ZipArchive` without calling `Expand-Archive`, and invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`.
- The proof confirms the release binary scans all `4` truncated archive carriers, returns `completedWithErrors`, reports at least `4` skipped files and carrier-specific scan errors with `archive_content_scan_limited` and the "did not extract files or treat unscanned archive content as clean" explanation, reports `0` threats, quarantines `0` files, preserves each source carrier, and creates no quarantine records.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan archive truncation fail-visible smoke` fail validation.
- Focused verification passed locally: local-core rustfmt check, the new local-core truncated archive limit regression, release local-core build, the new release Quick Scan archive truncation smoke, and Python source-contracts (`550`).
- Negative evidence passed: validating the old 2104 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan archive truncation fail-visible smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`181` steps in `531.9s`) for `.workflow\ultracode\avorax-hardening\results\2105-small-threat-mvp-full-report.json`, including the new release Quick Scan archive truncation fail-visible smoke (`1.8s`).
- Remaining proof includes live-malware-free production false-positive measurement, representative encrypted/unsupported archive edge rates, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2104

- Fixed local-core archive limit reporting so a native `archive_content_scan_limited` final-verdict evidence item that is not otherwise surfaced as a threat increments skipped files and emits a bounded scan error instead of returning a clean report.
- Added local-core regression `quick_scan_reports_oversized_archive_content_limit_as_not_clean`, which scans a benign ZIP containing a `1 MiB + 1` entry and verifies `CompletedWithErrors`, `0` threats, `0` quarantines, one skipped file, visible `archive_content_scan_limited` scan-error detail, and source-file preservation.
- Added release-binary Quick Scan archive limit proof `tools\testing\run-release-local-core-quick-scan-archive-limit-smoke.ps1` for benign oversized `.zip`, `.jar`, `.appx`, and `.appxbundle` carriers.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, creates isolated engine subdirectories without a signature pack, builds the carriers using `System.IO.Compression.ZipArchive` without calling `Expand-Archive`, and invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`.
- The proof confirms the release binary scans at least `4` oversized archive carriers, returns `completedWithErrors`, reports at least `4` skipped files and carrier-specific scan errors with `archive_content_scan_limited` and the "did not extract files or treat unscanned archive content as clean" explanation, reports `0` threats, quarantines `0` files, preserves each source carrier, and creates no quarantine records.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan archive limit fail-visible smoke` fail validation.
- Focused verification passed locally: local-core rustfmt check, the new local-core oversized archive limit regression, release local-core build, the new release Quick Scan archive limit smoke, and Python source-contracts (`549`).
- Negative evidence passed: validating the old 2103 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan archive limit fail-visible smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`180` steps in `580.8s`) for `.workflow\ultracode\avorax-hardening\results\2104-small-threat-mvp-full-report.json`, including the new release Quick Scan archive limit fail-visible smoke (`2.3s`).
- Remaining proof includes live-malware-free production false-positive measurement, representative encrypted/oversized/unsupported archive edge rates, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2103

- Added release-binary Quick Scan unsafe archive path proof `tools\testing\run-release-local-core-quick-scan-unsafe-archive-path-smoke.ps1` for ZIP-framed archive entries that contain path traversal, Windows drive-root, root-backslash, or nested package traversal names.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, creates isolated engine subdirectories without a signature pack, and builds benign `.zip`, `.jar`, `.appx`, and `.appxbundle` carriers using `System.IO.Compression.ZipArchive` without calling `Expand-Archive`.
- The proof confirms the release binary scans all `4` unsafe archive carriers with `quick_scan_selected_paths`, `scan_kind=quick`, and `AutoQuarantineConfirmedOnly`; reports `4` review-only heuristic findings with `archive_zip_slip` and `archive_content_scan_limited` evidence; emits no scan errors; quarantines `0` files; leaves the carrier sources and benign note in place; and creates no quarantine records.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan unsafe archive path review smoke` fail validation.
- Focused verification passed locally: the new release Quick Scan unsafe archive path smoke and Python source-contracts (`547`).
- Negative evidence passed: validating the old 2102 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan unsafe archive path review smoke`.
- Full verification initially hit a host disk-space failure while rebuilding Flutter test artifacts; after removing only the repository `target\debug` build cache and restarting, the small-threat MVP verifier plus report validator passed (`179` steps in `662.3s`) for `.workflow\ultracode\avorax-hardening\results\2103-small-threat-mvp-full-report.json`, including the new release Quick Scan unsafe archive path review smoke (`2.1s`).
- Remaining proof includes live-malware-free production false-positive measurement, encrypted/oversized/unsupported archive edge rates on representative corpora, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2102

- Added release-binary Quick Scan package archive-entry proof `tools\testing\run-release-local-core-quick-scan-package-archive-entry-smoke.ps1` for bounded ZIP-framed package signature/quarantine behavior across `.jar`, `.apk`, `.xpi`, `.vsix`, `.nupkg`, `.appx`, `.msix`, `.appxbundle`, and `.msixbundle` carriers.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, writes a self-hashed temporary exact-hash signature pack for harmless `zentor-safe-release-package-archive-entry-fixture` bytes, creates benign ZIP-framed package carriers under a temporary `Downloads` folder, and nests APPX/MSIX package bytes inside APPXBUNDLE/MSIXBUNDLE containers without extracting anything to disk.
- The proof confirms the release binary scans all `9` outer package carriers with `quick_scan_selected_paths`, `scan_kind=quick`, and `AutoQuarantineConfirmedOnly`; reports `9` confirmed `Archived entry signature` threats with the safe package signature id and no-extract/no-execute evidence; emits no scan errors; quarantines each outer carrier to `.avoraxq` payloads; lists matching quarantine records; removes only the matched carrier sources; and preserves the benign file.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan package archive-entry safe hash fixture smoke` fail validation.
- Focused verification passed locally: the new release Quick Scan package archive-entry smoke and Python source-contracts (`546`).
- Negative evidence passed: validating the old 2101 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan package archive-entry safe hash fixture smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`178` steps in `429.4s`) for `.workflow\ultracode\avorax-hardening\results\2102-small-threat-mvp-full-report.json`, including the new release Quick Scan package archive-entry smoke (`4.2s`).
- Remaining proof includes live-malware-free production false-positive measurement, encrypted/oversized/unsupported package-archive edge rates on representative corpora, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2101

- Added release-binary Quick Scan nested ZIP archive-entry proof `tools\testing\run-release-local-core-quick-scan-nested-zip-entry-smoke.ps1` for bounded recursive archive-entry signature/quarantine behavior.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, writes a self-hashed temporary exact-hash signature pack for harmless `zentor-safe-release-nested-zip-entry-fixture` bytes, creates a benign outer `safe-release-nested-archive.zip` containing only `archives/inner-safe.zip`, and puts the matching bytes inside the inner archive at `payload/safe-release-nested-entry.txt`.
- The proof confirms the release binary scans the outer ZIP carrier with `quick_scan_selected_paths`, `scan_kind=quick`, and `AutoQuarantineConfirmedOnly`; reports one confirmed `Archived entry signature` threat with the nested safe signature id and no-extract/no-execute evidence; emits no scan errors; quarantines the outer ZIP to a `.avoraxq` payload; lists the matching quarantine record; removes only the matched outer ZIP carrier source; and preserves the benign file.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan nested ZIP archive-entry safe hash fixture smoke` fail validation.
- Focused verification passed locally: the new release Quick Scan nested ZIP archive-entry smoke and Python source-contracts (`545`).
- Negative evidence passed: validating the old 2100 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan nested ZIP archive-entry safe hash fixture smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`177` steps in `428s`) for `.workflow\ultracode\avorax-hardening\results\2101-small-threat-mvp-full-report.json`, including the new release Quick Scan nested ZIP archive-entry smoke (`1.1s`).
- Remaining proof includes live-malware-free production false-positive measurement, encrypted/oversized/unsupported nested-archive edge rates on representative corpora, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2100

- Added release-binary Quick Scan ZIP archive-entry proof `tools\testing\run-release-local-core-quick-scan-zip-entry-smoke.ps1` for bounded archive-entry signature/quarantine behavior.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a valid empty allowlist JSON array, writes a self-hashed temporary exact-hash signature pack for harmless `zentor-safe-release-zip-entry-fixture` bytes, creates a benign `safe-release-archive.zip` containing `payload/safe-release-entry.txt`, and adds a benign non-matching text file under a temporary `Downloads` folder.
- The proof confirms the release binary scans the ZIP carrier with `quick_scan_selected_paths`, `scan_kind=quick`, and `AutoQuarantineConfirmedOnly`; reports one confirmed `Archived entry signature` threat with the safe signature id and no-extract/no-execute evidence; emits no scan errors; quarantines the outer ZIP to a `.avoraxq` payload; lists the matching quarantine record; removes only the matched ZIP carrier source; and preserves the benign file.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke` fail validation.
- Focused verification passed locally: the new release Quick Scan ZIP archive-entry smoke and Python source-contracts (`544`).
- Negative evidence passed: validating the old 2099 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`176` steps in `399.7s`) for `.workflow\ultracode\avorax-hardening\results\2100-small-threat-mvp-full-report.json`, including the new release Quick Scan ZIP archive-entry smoke (`1.0s`).
- Remaining proof includes live-malware-free production false-positive measurement, encrypted/oversized/unsupported archive-host edge rates on representative corpora, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2099

- Added release-binary Quick Scan proof `tools\testing\run-release-local-core-quick-scan-cpl-msu-smoke.ps1` for the checkpoint 2095 CPL/MSU carrier signature/quarantine path.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a self-hashed temporary exact-hash signature pack for harmless `zentor-safe-release-quickscan-cpl-msu-fixture` bytes, creates benign `.cpl` and `.msu` carrier fixtures plus a benign non-matching text file under a temporary `Downloads` folder, then invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`.
- The proof confirms the release binary scans `2` files, reports `2` signature threats, quarantines both carrier fixtures to `.avoraxq` payloads, lists matching quarantine records, removes only the matched carrier source files, and preserves the benign file.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary quick-scan CPL/MSU safe hash fixture smoke` fail validation.
- Focused verification passed locally: release local-core build, the new release Quick Scan CPL/MSU smoke, and Python source-contracts (`543`).
- Negative evidence passed: validating the old 2098 full report now fails with `passed full-suite report is missing required step: release local-core binary quick-scan CPL/MSU safe hash fixture smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`175` steps in `495.7s`) for `.workflow\ultracode\avorax-hardening\results\2099-small-threat-mvp-full-report.json`, including the new release Quick Scan CPL/MSU smoke (`1.6s`).
- Remaining proof includes live-malware-free production false-positive measurement, real CPL/MSU runtime behavior, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2098

- Added release-binary Full Scan proof `tools\testing\run-release-local-core-full-scan-pe-carrier-smoke.ps1` for the checkpoint 2097 PE-carrier signature/quarantine path.
- The smoke runs `target\release\zentor_local_core.exe` directly with process-local temporary `AVORAX_DATA_DIR`, `ZENTOR_LEGACY_DATA_DIR`, `AVORAX_QUARANTINE_DIR`, `ZENTOR_ALLOWLIST_FILE`, and `AVORAX_ENGINE_DIR` overrides.
- The smoke writes a self-hashed temporary exact-hash signature pack for harmless `zentor-safe-release-fullscan-fixture` bytes, creates benign `.dll`, `.sys`, `.scr`, and `.bin` carrier fixtures plus a benign non-matching text file, then invokes JSON `full_scan` with `scan_kind=full` and `AutoQuarantineConfirmedOnly`.
- The proof confirms the release binary scans `5` files, reports `4` signature threats, quarantines all `4` carrier fixtures to `.avoraxq` payloads, lists matching quarantine records, removes only the matched carrier source files, and preserves the benign file.
- Updated the small-threat MVP verifier, full-suite report validator, and Python source contracts so reports missing `release local-core binary full-scan PE carrier safe hash fixture smoke` fail validation.
- Focused verification passed locally: release local-core build, the new release PE-carrier smoke, and Python source-contracts (`542`).
- Negative evidence passed: validating the old 2097 full report now fails with `passed full-suite report is missing required step: release local-core binary full-scan PE carrier safe hash fixture smoke`.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`174` steps in `511.1s`) for `.workflow\ultracode\avorax-hardening\results\2098-small-threat-mvp-full-report.json`, including the new release PE-carrier smoke (`3.1s`).
- Remaining proof includes live-malware-free production false-positive measurement, real PE loader/runtime behavior, installed desktop UI/service E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2097

- Removed the unused local-core `should_signature_scan` / `signature_scan_extension` helper and its source-only regression so Full Scan no longer has a documented dead signature-gating control.
- Added runtime Full Scan proof `full_scan_reports_pe_carrier_safe_simulators_and_quarantines_files`, using benign `.dll`, `.sys`, `.scr`, and `.bin` safe simulator files that contain only `ZENTOR-SAFE-EICAR-SIMULATOR-FILE`.
- The proof confirms each PE-like carrier is scanned by Full Scan, reported as confirmed signature evidence, and quarantined by `AutoQuarantineConfirmedOnly` through the normal quarantine path.
- Updated the small-threat MVP verifier and full-suite report validator so the PE-carrier Full Scan proof is required; the previous 2096 report now fails validation because it lacks this required step.
- Updated source contracts, verification scope, security model, changelog, status, engine-control matrix, and checkpoint evidence file.
- Focused verification passed locally: local-core rustfmt check, local-core `full_scan_reports_pe_carrier_safe_simulators_and_quarantines_files` (`1`), local-core `full_scan` (`3`), Python source-contracts (`541`), and an intentional old-report validator failure for the missing new required step.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`173` steps in `502.8s`) for `.workflow\ultracode\avorax-hardening\results\2097-small-threat-mvp-full-report.json`.
- Remaining proof includes real PE metadata/behavior beyond normal native static/signature analysis, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2096

- Aligned local-core Quick Scan priority ordering with already-selected risky carrier extensions for `.sys`, `.bin`, `.vbe`, `.wsf`, `.hta`, and `.lnk`, while preserving checkpoint 2095 `.com`/`.pif`/`.cpl`/`.msu` priority behavior.
- Added explicit priority regression assertions for `driver.sys`, `payload.bin`, `support.vbe`, `support-ticket.wsf`, `support-ticket.hta`, and `support-link.lnk`.
- Kept the change limited to scan ordering. The priority branch does not create extension-only detections, raise verdicts, trigger quarantine, execute or resolve targets, or claim pre-execution blocking.
- Updated the security model, changelog, status, engine-control matrix, and checkpoint evidence file.
- Focused verification passed locally: local-core rustfmt check, local-core `quick_scan_priority_missing_names_and_extensions_use_explicit_branches` (`1`), local-core `quick_walk_keeps_risky_files_and_skips_plain_documents` (`1`), and Python source-contracts (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`172` steps in `504.4s`) for `.workflow\ultracode\avorax-hardening\results\2096-small-threat-mvp-full-report.json`.
- Remaining proof includes installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, signed-driver/pre-execution validation, and any future proof that priority ordering materially improves wall-clock detection time on representative user hosts.

## 2026-07-07 continuation checkpoint 2095

- Added local-core Quick Scan risky-file routing for `.cpl` Control Panel applets and `.msu` Windows Update packages.
- Made legacy `.com` and `.pif` quick-scan priority routing explicit alongside their existing risky-file candidate handling.
- Added local-core proof `quick_scan_reports_cpl_msu_safe_simulators_and_quarantines_files`, using benign `Downloads\safe-simulator-panel.cpl` and `Downloads\safe-simulator-update.msu` fixtures containing only the safe simulator signature string.
- The proof confirms both fixtures are scanned by Quick Scan, reported as confirmed signature detections, and quarantined by `AutoQuarantineConfirmedOnly` through the normal quarantine path.
- Updated the small-threat MVP verifier, report validator, source contracts, verification scope, security model, changelog, status, engine-control matrix, and checkpoint evidence file.
- Focused verification passed locally: local-core rustfmt check, Python source-contracts (`541`), local-core `quick_scan_reports_cpl_msu_safe_simulators_and_quarantines_files` (`1`), and local-core `quick_walk_keeps_risky_files_and_skips_plain_documents` (`1`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`172` steps in `520.8s`) for `.workflow\ultracode\avorax-hardening\results\2095-small-threat-mvp-full-report.json`.
- Remaining proof includes real PE `.cpl` metadata/behavior beyond normal native PE analysis, MSU/CAB package parsing, Windows Update/package install semantics, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2094

- Added conservative static Windows scriptlet/SCT/WSC carrier review coverage for `.sct` scriptlet and `.wsc` Windows Script Component carriers.
- Native string indicators now count `windows_scriptlet_marker_count`, include scriptlet/registration/script markers, and include `regsvr32`/`scrobj.dll` references in bounded string views.
- Native file-type classification routes `.sct` and `.wsc` through VBS-style static analysis, and heuristic scoring emits review-only `windows_scriptlet_remote_script_launch` only for `.sct`/`.wsc` carriers that combine scriptlet metadata with remote executable/script, remote executable/script network path, or script-host downloader evidence.
- Local-core Quick Scan risky-file selection now includes `.sct` and `.wsc`.
- Added native proof under the `windows_scriptlet` filter (`5` tests): positive `.sct` remote-script evidence, positive `.wsc` script-host downloader evidence, string indicator counting, ordinary scriptlet document-link negative guard, and non-scriptlet remote text negative guard.
- Added local-core proof `quick_scan_reports_windows_scriptlet_carriers_for_review`, using benign `Downloads\loader.sct` and `Downloads\component.wsc` fixtures; both are reported as review-only `SuspiciousDownloader` heuristic detections and `AutoQuarantineConfirmedOnly` leaves the files in place.
- Updated the small-threat MVP verifier, report validator, source contracts, verification scope, security model, changelog, status, engine-control matrix, and checkpoint evidence file.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), native `windows_scriptlet` (`5`), local-core `quick_scan_reports_windows_scriptlet_carriers_for_review` (`1`), and local-core `quick_walk_keeps_risky_files_and_skips_plain_documents` (`1`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`171` steps in `507.9s`) for `.workflow\ultracode\avorax-hardening\results\2094-small-threat-mvp-full-report.json`.
- Remaining proof includes full scriptlet/COM registration semantics, `regsvr32`/`scrobj.dll` runtime behavior, remote scriptlet download/reputation behavior, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2093

- Added conservative static Java Web Start/JNLP carrier review coverage for `.jnlp` launch descriptors.
- Native string indicators now count `java_web_start_marker_count` and `remote_java_web_start_url_count`, with remote `.jar` and `.jnlp` URLs treated as Java Web Start payload/launcher evidence separate from generic URL evidence.
- Native file-type classification routes `.jnlp` through text analysis, and heuristic scoring emits review-only `java_web_start_remote_archive_launch` only for `.jnlp` carriers that combine JNLP/Web Start markers with remote Java archive or launcher evidence.
- Local-core Quick Scan risky-file selection now includes `.jnlp`.
- Added native proof under the `java_web_start` filter (`6` tests): positive remote JAR evidence, text-classification coverage, string indicator counting, ordinary document-link negative guard, and non-JNLP XML negative guard.
- Added local-core proof `quick_scan_reports_java_web_start_carrier_for_review`, using a benign `Downloads\support.jnlp` fixture; it is reported as a review-only `SuspiciousDownloader` heuristic detection and `AutoQuarantineConfirmedOnly` leaves the file in place.
- Updated the small-threat MVP verifier, report validator, source contracts, verification scope, security model, changelog, status, engine-control matrix, and checkpoint evidence file.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), native `java_web_start` (`6`), local-core `quick_scan_reports_java_web_start_carrier_for_review` (`1`), and local-core `quick_walk_keeps_risky_files_and_skips_plain_documents` (`1`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`169` steps in `524.7s`) for `.workflow\ultracode\avorax-hardening\results\2093-small-threat-mvp-full-report.json`.
- Remaining proof includes Java Web Start runtime behavior, Java signing/trust prompt/sandbox semantics, remote JAR/JNLP download/reputation behavior, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2092

- Added conservative static Windows Installer carrier review coverage for `.msi` packages and `.msp` patch packages.
- Native string indicators now count `windows_installer_marker_count` and `windows_installer_custom_action_count`, including CFB header context and installer/custom-action metadata found in bounded UTF-8/UTF-16LE views.
- Native heuristic scoring emits review-only `windows_installer_custom_action_remote_launch` only for `.msi`/`.msp` carriers that combine installer/package markers, custom-action or QuietExec/deferred metadata, and remote executable/script URL, remote executable/script network path, or script-host plus downloader evidence.
- Local-core Quick Scan risky-file selection now includes `.msp` alongside the existing `.msi` carrier path.
- Added native proof under the `windows_installer` filter (`5` tests): positive `.msi` custom-action remote installer evidence, positive `.msp` custom-action script-host evidence, string indicator counting, and ordinary installer/document-link negative guards.
- Added local-core proof `quick_scan_reports_windows_installer_custom_action_carriers_for_review`, using benign `Downloads\support-installer.msi` and `Downloads\support-patch.msp` fixtures; both are reported as review-only `SuspiciousDownloader` heuristic detections and `AutoQuarantineConfirmedOnly` leaves the files in place.
- Updated the small-threat MVP verifier, report validator, source contracts, verification scope, security model, changelog, status, engine-control matrix, and checkpoint evidence file.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), native `windows_installer` (`5`), local-core `quick_scan_reports_windows_installer_custom_action_carriers_for_review` (`1`), and local-core `quick_walk_keeps_risky_files_and_skips_plain_documents` (`1`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`167` steps in `502.6s`) for `.workflow\ultracode\avorax-hardening\results\2092-small-threat-mvp-full-report.json`.
- Remaining proof includes full MSI database/table parsing, installer signature/trust prompt semantics, live install/repair/patch behavior, remote URL download/reputation behavior, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2091

- Added conservative static ClickOnce carrier review coverage for `.application` deployment manifests and `.appref-ms` application references.
- Native string indicators now count ClickOnce deployment markers and remote `.application`/`.appref-ms` URLs separately from generic executable/script URL evidence.
- Native file-type classification routes `.application` and `.appref-ms` through text analysis, and heuristic scoring emits `clickonce_remote_deployment_launch` only for ClickOnce carriers that combine deployment/reference context with remote application, executable/script URL, or remote executable/script network-path evidence.
- Local-core Quick Scan risky-file selection now includes `.application` and `.appref-ms`.
- Added native proof under the `clickonce` filter (`6` tests): positive `.application` remote executable evidence, positive `.appref-ms` remote application evidence, text-classification coverage, and ordinary XML negative guard.
- Added local-core proof `quick_scan_reports_clickonce_carriers_for_review`, using benign `Downloads\support.application` and `Downloads\support.appref-ms` fixtures; both are reported as review-only `SuspiciousDownloader` heuristic detections and `AutoQuarantineConfirmedOnly` leaves the files in place.
- Updated the small-threat MVP verifier, report validator, source contracts, verification scope, security model, changelog, status, engine-control matrix, and checkpoint evidence file.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), native `clickonce` (`6`), local-core `quick_scan_reports_clickonce_carriers_for_review` (`1`), and local-core `quick_walk_keeps_risky_files_and_skips_plain_documents` (`1`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`165` steps in `466.2s`) for `.workflow\ultracode\avorax-hardening\results\2091-small-threat-mvp-full-report.json`.
- Remaining proof includes ClickOnce trust prompt/certificate/zone semantics, live ClickOnce installation behavior, remote URL download/reputation behavior, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2090

- Extended bounded ZIP-framed archive-entry content scanning and Quick Scan risky-carrier selection to `.appxbundle` and `.msixbundle` Windows package bundle carriers.
- Native engine now treats top-level `.appxbundle`/`.msixbundle` paths and nested `.appxbundle`/`.msixbundle` entries as ZIP-framed containers for the existing bounded content sampler, while preserving the same entry count, size, total-byte, unsafe-path, encryption, compression, and depth limits.
- Local-core Quick Scan now keeps `.appxbundle` and `.msixbundle` files in risky-file selection, so Windows package bundles in common user locations are not skipped by the quick walker.
- Added native proof `eicar_inside_appxbundle_and_msixbundle_nested_packages_is_detected`, using in-memory EICAR payloads inside `store-package.appxbundle::packages/store-package.appx::assets/eicar.txt` and `desktop-package.msixbundle::packages/desktop-package.msix::vfs/programfiles/app/eicar.txt`.
- Added local-core proof `quick_scan_reports_appxbundle_msixbundle_nested_package_safe_simulator`, using benign `Downloads\safe-simulator-store-package.appxbundle` and `Downloads\safe-simulator-desktop-package.msixbundle` fixtures with nested inner packages; the outer bundles are quarantined only because confirmed simulator signature evidence is present.
- Updated the small-threat MVP verifier, report validator, source contracts, and verification scope so the one-command suite requires APPXBUNDLE/MSIXBUNDLE nested package signature coverage.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2090-appxbundle-msixbundle-nested-package-quick-scan.md`.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), focused native APPXBUNDLE/MSIXBUNDLE nested package signature test (`1`), focused local-core APPXBUNDLE/MSIXBUNDLE nested package Quick Scan simulator test (`1`), local-core `file_walker` (`7`), native `eicar_inside_` (`9`), native `archive` (`43`), and local-core `quick_scan_reports` (`38`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`163` steps in `381.9s`) for `.workflow\ultracode\avorax-hardening\results\2090-small-threat-mvp-full-report.json`.
- Remaining proof includes APPX/MSIX bundle manifest/resource/capability semantics, Windows package install/registration behavior, package startup-task behavior, non-ZIP-framed package formats beyond fail-visible limits, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2089

- Extended bounded ZIP-framed archive-entry content scanning and Quick Scan risky-carrier selection to `.appx` and `.msix` Windows app package carriers.
- Native engine now treats top-level `.appx`/`.msix` paths and nested `.appx`/`.msix` entries as ZIP-framed containers for the existing bounded content sampler, while preserving the same entry count, size, total-byte, unsafe-path, encryption, compression, and depth limits.
- Local-core Quick Scan now keeps `.appx` and `.msix` files in risky-file selection, so Windows app packages in common user locations are not skipped by the quick walker.
- Added native proof `eicar_inside_appx_and_msix_entries_is_detected_without_extracting_package`, using in-memory EICAR payloads inside `store-package.appx::assets/eicar.txt` and `desktop-package.msix::vfs/programfiles/app/eicar.txt`.
- Added local-core proof `quick_scan_reports_appx_msix_entry_safe_simulator_and_quarantines_outer_packages`, using benign `Downloads\safe-simulator-store-package.appx` and `Downloads\safe-simulator-desktop-package.msix` fixtures; the outer packages are quarantined only because confirmed simulator signature evidence is present.
- Updated the small-threat MVP verifier, report validator, source contracts, and verification scope so the one-command suite requires APPX/MSIX archive-entry signature coverage.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2089-appx-msix-archive-entry-quick-scan.md`.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), focused native APPX/MSIX signature test (`1`), focused local-core APPX/MSIX Quick Scan simulator test (`1`), local-core `file_walker` (`7`), native `eicar_inside_` (`8`), native `archive` (`43`), and local-core `quick_scan_reports` (`37`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`161` steps in `385.2s`) for `.workflow\ultracode\avorax-hardening\results\2089-small-threat-mvp-full-report.json`.
- Remaining proof includes APPX/MSIX manifest/capability semantics, Windows package install/registration behavior, package startup-task behavior, non-ZIP-framed package formats beyond fail-visible limits, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2088

- Extended bounded ZIP-framed archive-entry content scanning and Quick Scan risky-carrier selection to `.nupkg` NuGet package carriers.
- Native engine now treats top-level `.nupkg` paths and nested `.nupkg` entries as ZIP-framed containers for the existing bounded content sampler, while preserving the same entry count, size, total-byte, unsafe-path, encryption, compression, and depth limits.
- Local-core Quick Scan now keeps `.nupkg` files in risky-file selection, so NuGet package files in common user locations are not skipped by the quick walker.
- Added native proof `eicar_inside_nupkg_entry_is_detected_without_extracting_archive`, using an in-memory EICAR payload inside `library-package.nupkg::contentfiles/any/any/eicar.txt`.
- Added local-core proof `quick_scan_reports_nupkg_entry_safe_simulator_and_quarantines_outer_package`, using a benign `Downloads\safe-simulator-library-package.nupkg` fixture containing `contentfiles/any/any/safe-eicar.txt`; the outer NUPKG is quarantined only because confirmed simulator signature evidence is present.
- Updated the small-threat MVP verifier, report validator, source contracts, and verification scope so the one-command suite requires NUPKG archive-entry signature coverage.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2088-nupkg-archive-entry-quick-scan.md`.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), focused native NUPKG signature test (`1`), focused local-core NUPKG Quick Scan simulator test (`1`), local-core `file_walker` (`7`), native `eicar_inside_` (`7`), native `archive` (`43`), and local-core `quick_scan_reports` (`36`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`159` steps in `360.5s`) for `.workflow\ultracode\avorax-hardening\results\2088-small-threat-mvp-full-report.json`.
- Remaining proof includes NuGet package metadata semantics, package restore/install script and build-target behavior, package binary execution behavior, non-ZIP-framed package formats beyond fail-visible limits, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2087

- Extended bounded ZIP-framed archive-entry content scanning and Quick Scan risky-carrier selection to `.vsix` editor-extension packages.
- Native engine now treats top-level `.vsix` paths and nested `.vsix` entries as ZIP-framed containers for the existing bounded content sampler, while preserving the same entry count, size, total-byte, unsafe-path, encryption, compression, and depth limits.
- Local-core Quick Scan now keeps `.vsix` files in risky-file selection, so editor extension packages in common user locations are not skipped by the quick walker.
- Added native proof `eicar_inside_vsix_entry_is_detected_without_extracting_archive`, using an in-memory EICAR payload inside `editor-extension.vsix::extension/assets/eicar.txt`.
- Added local-core proof `quick_scan_reports_vsix_entry_safe_simulator_and_quarantines_outer_package`, using a benign `Downloads\safe-simulator-editor-extension.vsix` fixture containing `extension/assets/safe-eicar.txt`; the outer VSIX is quarantined only because confirmed simulator signature evidence is present.
- Updated the small-threat MVP verifier, report validator, source contracts, and verification scope so the one-command suite requires VSIX archive-entry signature coverage.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2087-vsix-archive-entry-quick-scan.md`.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), focused native VSIX signature test (`1`), focused local-core VSIX Quick Scan simulator test (`1`), local-core `file_walker` (`7`), native `eicar_inside_` (`6`), native `archive` (`42`), and local-core `quick_scan_reports` (`35`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`157` steps in `361.6s`) for `.workflow\ultracode\avorax-hardening\results\2087-small-threat-mvp-full-report.json`.
- Remaining proof includes VSIX manifest/API semantics, editor extension install-time behavior, extension JavaScript/native-code behavior, non-ZIP-framed package formats beyond fail-visible limits, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2086

- Extended bounded ZIP-framed archive-entry content scanning and Quick Scan risky-carrier selection to `.xpi` browser-extension packages.
- Native engine now treats top-level `.xpi` paths and nested `.xpi` entries as ZIP-framed containers for the existing bounded content sampler, while preserving the same entry count, size, total-byte, unsafe-path, encryption, compression, and depth limits.
- Local-core Quick Scan now keeps `.xpi` files in risky-file selection, so browser extension packages in common user locations are not skipped by the quick walker.
- Added native proof `eicar_inside_xpi_entry_is_detected_without_extracting_archive`, using an in-memory EICAR payload inside `browser-extension.xpi::assets/eicar.txt`.
- Added local-core proof `quick_scan_reports_xpi_entry_safe_simulator_and_quarantines_outer_package`, using a benign `Downloads\safe-simulator-extension.xpi` fixture containing `assets/safe-eicar.txt`; the outer XPI is quarantined only because confirmed simulator signature evidence is present.
- Updated the small-threat MVP verifier, report validator, source contracts, and verification scope so the one-command suite requires XPI archive-entry signature coverage.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2086-xpi-archive-entry-quick-scan.md`.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), focused native XPI signature test (`1`), focused local-core XPI Quick Scan simulator test (`1`), local-core `file_walker` (`7`), native `eicar_inside_` (`5`), native `archive` (`41`), and local-core `quick_scan_reports` (`34`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`155` steps in `348.3s`) for `.workflow\ultracode\avorax-hardening\results\2086-small-threat-mvp-full-report.json`.
- Remaining proof includes browser extension manifest/API semantics, browser install-time behavior, non-ZIP-framed extension formats beyond fail-visible limits, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2085

- Extended bounded ZIP-framed archive-entry content scanning and Quick Scan risky-carrier selection to `.apk` packages.
- Native engine now treats top-level `.apk` paths and nested `.apk` entries as ZIP-framed containers for the existing bounded content sampler, while preserving the same entry count, size, total-byte, unsafe-path, encryption, compression, and depth limits.
- Local-core Quick Scan now keeps `.apk` files in risky-file selection, so APKs in common user locations are not skipped by the quick walker.
- Added native proof `eicar_inside_apk_entry_is_detected_without_extracting_archive`, using an in-memory EICAR payload inside `mobile-package.apk::assets/eicar.txt`.
- Added local-core proof `quick_scan_reports_apk_entry_safe_simulator_and_quarantines_outer_package`, using a benign `Downloads\safe-simulator-mobile.apk` fixture containing `assets/safe-eicar.txt`; the outer APK is quarantined only because confirmed simulator signature evidence is present.
- Updated the small-threat MVP verifier, report validator, source contracts, and verification scope so the one-command suite requires APK archive-entry signature coverage.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2085-apk-archive-entry-quick-scan.md`.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), focused native APK signature test (`1`), focused local-core APK Quick Scan simulator test (`1`), local-core `file_walker` (`7`), native `eicar_inside_` (`4`), native `archive` (`40`), and local-core `quick_scan_reports` (`33`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`153` steps in `344.2s`) for `.workflow\ultracode\avorax-hardening\results\2085-small-threat-mvp-full-report.json`.
- Remaining proof includes Android package semantics, APK install-time behavior, non-ZIP-framed archive formats beyond fail-visible limits, installed local-core/service/UI E2E, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2084

- Extended bounded archive-entry content scanning from `.zip` files to `.jar` files.
- Native engine now treats top-level `.jar` paths and nested `.jar` entries as ZIP-framed containers for the existing bounded content sampler, while preserving the same entry count, size, total-byte, unsafe-path, encryption, compression, and depth limits.
- Added native proof `eicar_inside_jar_entry_is_detected_without_extracting_archive`, using an in-memory EICAR payload inside `support-library.jar::payload/eicar.txt`.
- Added local-core proof `jar_entry_safe_simulator_is_detected_and_outer_archive_quarantined`, using a benign `safe-simulator-library.jar` fixture containing `payload/safe-eicar.txt`; the outer JAR is quarantined only because confirmed simulator signature evidence is present.
- Updated the small-threat MVP verifier, report validator, source contracts, and verification scope so the one-command suite requires JAR archive-entry signature coverage.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2084-jar-archive-entry-signature-scan.md`.
- Focused verification passed locally: native/local rustfmt checks, Python source-contracts (`541`), focused native JAR signature test (`1`), focused local-core JAR simulator test (`1`), native `archive` (`39`), local-core safe simulator archive group (`3`), and local-core `quick_scan_reports` (`32`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`151` steps in `351.1s`) for `.workflow\ultracode\avorax-hardening\results\2084-small-threat-mvp-full-report.json`.
- Remaining proof includes installed local-core/service/UI E2E, non-ZIP archive formats beyond fail-visible limits, production false-positive measurement without live malware, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2083

- Added a positive native Windows Authenticode runtime regression for Microsoft-signed publisher trust.
- The new test `authenticode_probe_accepts_microsoft_signed_windows_powershell_binary` resolves the checked local `System32\WindowsPowerShell\v1.0\powershell.exe` helper and requires `microsoft_signature_verdict` to return `true`.
- Preserved checkpoint 2082's negative proof: an unsigned temporary `.exe` still returns `false` without the old positional-argument `-EncodedCommand` failure.
- Updated the small-threat MVP verifier, report validator, source contracts, and verification scope so the one-command suite requires both unsigned-file and Microsoft-signed Authenticode probe regressions.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2083-authenticode-microsoft-signed-probe.md`.
- Focused verification passed locally: native rustfmt check, Python source-contracts (`541`), native `authenticode_probe_accepts` (`2`), native `authenticode_probe` (`4`), native `trust` (`57`), and local-core `quick_scan_reports` (`32`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`149` steps in `351.9s`) for `.workflow\ultracode\avorax-hardening\results\2083-small-threat-mvp-full-report.json`.
- Remaining proof includes invalid-signed publisher policy E2E, candidate replacement-race proof, installed local-core/service/UI E2E, release packaging, production false-positive measurement without live malware, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2082

- Fixed the native Microsoft Authenticode publisher-trust probe's target-path handoff on Windows.
- The previous invocation appended the inspected file path after `-EncodedCommand`; this host rejects that shape with `Cannot process command because a command is already specified with -Command or -EncodedCommand.`
- Native engine now sets process-only `AVORAX_AUTHENTICODE_TARGET_PATH` on the checked WindowsPowerShell child process, and the encoded helper reads that variable before calling `Get-AuthenticodeSignature -LiteralPath $target`.
- Preserved the existing command safety boundary: checked local `System32\WindowsPowerShell\v1.0\powershell.exe`, UTF-16LE `-EncodedCommand`, no raw `-Command`, bounded stdout/stderr pipe draining, 30-second timeout, and fail-visible diagnostics.
- Added a Windows runtime regression proving an unsigned temporary `.exe` returns `false` instead of failing the Authenticode command invocation.
- Updated the small-threat MVP verifier and report validator to require `native-engine Authenticode unsigned-file probe regression`, and updated source contracts to reject the old `.arg(path.as_os_str())` target handoff.
- Aligned the local-core EML attachment Quick Scan assertion with the observed review category after the false publisher diagnostic was removed: `SuspiciousDownloader` or `SuspiciousScript` are accepted, but `email_executable_attachment` evidence, detected status, no quarantine, and fixture preservation are still required.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2082-authenticode-target-path-invocation.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, Python source-contracts passed (`541`), native Authenticode unsigned-file regression passed (`1`), native `authenticode_probe` passed (`3`), native `trust` passed (`56`), local-core safe simulator scan passed (`1`), local-core archive-entry script scan passed (`1`), and local-core `quick_scan_reports` passed (`32`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`148` steps in `344.9s`) for `.workflow\ultracode\avorax-hardening\results\2082-small-threat-mvp-full-report.json`.
- Remaining proof includes live signed/invalid publisher allow/deny E2E with real signed fixtures, installed local-core/service/UI E2E, replacement-race proof around candidate files, release packaging, production false-positive measurement without live malware, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2081

- Extended bounded ZIP archive-entry content analysis from signatures to local rule evaluation and bounded heuristic scoring.
- Native engine now evaluates sampled safe ZIP entries through signature matching, rule VM evaluation, and `heuristics::score_file`, then emits explainable `Archived entry signature`, `Archived entry rule`, and `Archived entry heuristic` evidence using the full archive-entry path.
- The implementation keeps the existing ZIP safety boundary: entries remain in memory, are not extracted to disk, are not executed, and unsafe/encrypted/oversized/unsupported/truncated archive content stays fail-visible through limit evidence.
- Added native proof that an in-memory `script-archive.zip` entry `scripts/dropper.ps1` containing inert PowerShell downloader/encoded-command markers produces both archived rule evidence and archived heuristic evidence.
- Added local-core proof that an inert `script-rule-archive.zip` fixture reports archive-entry signature/rule/heuristic evidence while `AutoQuarantineConfirmedOnly` leaves the outer archive in place because these are review/probable signals, not confirmed quarantine evidence.
- Updated the small-threat MVP verifier and report validator to require native archive embedded rule/heuristic detection and local-core archive-entry script rule/heuristic reporting.
- Source-contract coverage now pins the renamed archive-entry detection helper, archived rule/heuristic evidence titles, native/local-core fixtures, verifier steps, validator requirements, and new verification-scope wording.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2081-zip-archive-entry-rule-heuristic-scan.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, Python source-contracts passed (`541`), native archive-entry rule/heuristic test passed (`1`), local-core archive-entry script rule/heuristic scan passed (`1`), and native `archive` passed (`38`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`147` steps in `346.8s`) for `.workflow\ultracode\avorax-hardening\results\2081-small-threat-mvp-full-report.json`.
- Remaining proof includes encrypted/protected archive scanning beyond fail-visible limits, unsupported ZIP compression methods beyond limit evidence, non-ZIP archive formats, archive payload execution prevention at install-time, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2080

- Extended bounded ZIP archive-entry signature scanning through nested ZIP entries up to the configured archive-depth limit (`3`).
- Native engine recursion uses the same `bounded_zip_entry_samples` path for nested `.zip` entries, keeps stored/deflated entry caps intact, and emits `archive_content_scan_limited` when the nested ZIP depth limit is reached.
- `Archived entry signature` evidence now includes the archive-entry chain, so inner hits show paths such as `archives/inner.zip::payload/eicar.txt`.
- Added native proof that an in-memory EICAR payload inside a deflated nested ZIP entry is detected without extracting files or writing EICAR to disk.
- Added local-core proof that an inert `nested-safe-simulator-archive.zip` fixture containing `archives/inner-safe.zip::payload/safe-eicar.txt` is reported as a confirmed signature detection and quarantines the outer ZIP archive in confirmed-only mode.
- Updated the small-threat MVP verifier and report validator to require native nested archive embedded-signature detection and local-core nested archive-entry simulator scan reporting.
- Source-contract coverage now pins the recursive native helper, nested-depth limit use, nested fixture names, verifier steps, validator requirements, and new verification-scope wording.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2080-nested-zip-archive-entry-signature-scan.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, Python source-contracts passed (`541`), native nested ZIP embedded-signature test passed (`1`), local-core nested ZIP simulator scan passed (`1`), local-core direct+nested archive simulator scan passed (`2`), native `archive` passed (`37`), report validation passed for the full 2080 report, product-copy gate passed, and no-malware-binaries gate exited successfully.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`145` steps in `346.3s`) for `.workflow\ultracode\avorax-hardening\results\2080-small-threat-mvp-full-report.json`.
- Remaining proof includes encrypted/protected nested archive scanning beyond fail-visible limits, unsupported ZIP compression methods, non-ZIP archive formats, archive payload execution prevention at install-time, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2079

- Added bounded ZIP archive-entry content signature coverage for small-threat MVP scans.
- Native ZIP sampling now collects only safe stored or deflated entry bytes within explicit caps: `64` entries, `1 MiB` per entry, and `4 MiB` total.
- Unsafe archive paths, encrypted entries, oversized entries, unsupported compression, malformed metadata, and truncated bodies become fail-visible `archive_content_scan_limited` evidence rather than clean success.
- Native engine signature matching now runs against sampled ZIP entry bytes with synthetic archive-entry paths and emits `Archived entry signature` evidence that names the inner entry without extracting or executing it.
- Added native in-memory EICAR ZIP proof so Defender does not need to allow a disk EICAR test file for this regression.
- Added local-core Quick Scan proof that an inert `safe-simulator-archive.zip` fixture under `Downloads` containing `payload/safe-eicar.txt` is reported as a confirmed signature detection and quarantines the outer ZIP archive in confirmed-only mode.
- Source-contract coverage now pins the ZIP sampling structs/constants/functions, native engine evidence helper, native/local-core tests, verifier steps, report-validator requirements, and new scope text.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2079-zip-archive-entry-signature-scan.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, Python source-contracts passed (`541`), native ZIP content sampling tests passed (`4`), native embedded ZIP signature test passed (`1`), focused local-core ZIP simulator scan test passed (`1`), native `archive` passed (`36`), report validation passed for the full 2079 report, product-copy gate passed, and no-malware-binaries gate exited successfully.
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`143` steps in `340.3s`) for `.workflow\ultracode\avorax-hardening\results\2079-small-threat-mvp-full-report.json`.
- Remaining proof includes encrypted/protected archive scanning beyond fail-visible limits, unsupported ZIP compression methods, non-ZIP archive formats, archive payload execution prevention at install-time, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2078

- Added conservative ZIP shortcut executable bundle review coverage.
- ANE ZIP metadata analysis now records `shortcut_entry_count` from `.lnk`, `.url`, and `.scf` entry names.
- Added `archive_shortcut_executable_bundle`, which requires shortcut carrier entry metadata plus an executable/script companion entry in the same ZIP archive.
- Preserved false-positive control with native negative fixtures for shortcut entries plus document-only companions.
- Kept the behavior entry-metadata-only: shortcut bodies are not parsed, opened, resolved, or executed, and archive payloads are not extracted.
- Added local-core Quick Scan proof that an inert `shortcut-bundle.zip` fixture under `Downloads` is surfaced as a `SuspiciousDownloader` review detection while confirmed-only auto-quarantine leaves it in place.
- Source-contract coverage now pins the ZIP shortcut counter, helper, native fixtures, local-core runtime fixture, and reason ID.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2078-zip-shortcut-executable-bundles.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native shortcut tests passed (`7`), native ZIP shortcut scoring tests passed (`2`), focused local-core ZIP shortcut Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `archive` passed (`31`), native `scoring` passed (`57`), and local-core `quick_scan_reports` passed (`32`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `333.8s`) for `.workflow\ultracode\avorax-hardening\results\2078-small-threat-mvp-full-report.json`.
- Remaining proof includes shortcut body/target parsing, archive payload extraction/inspection, encrypted/protected archive content handling beyond existing fail-visible limits, non-ZIP archive formats, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2077

- Added bounded ZIP-contained `autorun.inf` body command review coverage.
- ANE ZIP analysis now records `autorun_inf_executable_command_count` after reading only small unencrypted stored or deflated `autorun.inf` bodies within explicit `16 KiB` compressed/declared/decoded limits.
- Added `archive_autorun_inf_executable_command`, which requires bounded autorun command evidence plus an executable/script companion entry in the same ZIP archive.
- Encrypted, oversized, unsupported-compression, malformed, or unavailable autorun bodies fail visibly through existing archive limit evidence rather than being treated as clean success.
- Added native positive/negative fixtures for bounded body command counting, encrypted autorun-body skip behavior, and scoring.
- Added local-core Quick Scan proof that an inert `launcher-autoplay.zip` fixture under `Downloads` is surfaced as a `PersistenceIndicator` review detection while confirmed-only auto-quarantine leaves it in place.
- Source-contract coverage now pins the new counter, explicit autorun body limits, bounded body reader, native fixtures, local-core runtime fixture, and reason ID.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2077-zip-autorun-body-commands.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native autorun-body/scoring tests passed (`3`), encrypted autorun-body negative test passed (`1`), native ZIP autorun scoring tests passed (`3`), focused local-core ZIP autorun command Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `archive` passed (`29`), native `scoring` passed (`55`), and local-core `quick_scan_reports` passed (`31`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `337.8s`) for `.workflow\ultracode\avorax-hardening\results\2077-small-threat-mvp-full-report.json`.
- Remaining proof includes archive payload extraction/inspection, Windows AutoRun host behavior, encrypted/protected archive content handling beyond existing fail-visible limits, non-ZIP archive formats, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2076

- Added conservative Quick Scan ZIP autorun executable bundle review coverage.
- ANE ZIP metadata analysis now records `autorun_inf_entry_count` and `autorun_executable_entry_count` from bounded entry names.
- Added `archive_autorun_executable_bundle`, which requires both an `autorun.inf` entry and an executable/script companion entry in the same ZIP archive.
- Preserved false-positive control with native negative fixtures for `autorun.inf` plus document-only companions.
- Kept existing deceptive nested executable behavior stable by using a separate companion suffix helper for autorun bundle evidence.
- Added local-core Quick Scan proof that an inert `media-autoplay.zip` fixture under `Downloads` is surfaced as a `PersistenceIndicator` review detection while confirmed-only auto-quarantine leaves it in place.
- Source-contract coverage now pins the ZIP metadata counters, native fixtures, local-core runtime fixture, and reason ID.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2076-zip-autorun-executable-bundles.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native ZIP autorun analyzer tests passed (`2`), native ZIP autorun scoring tests passed (`2`), focused local-core ZIP autorun Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `archive` passed (`27`), native `scoring` passed (`54`), and local-core `quick_scan_reports` passed (`30`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `344s`) for `.workflow\ultracode\avorax-hardening\results\2076-small-threat-mvp-full-report.json`.
- Remaining proof includes archive payload extraction/inspection, parsing `autorun.inf` body semantics inside archives, encrypted/protected archive content handling beyond existing fail-visible limits, non-ZIP archive formats, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2075

- Added conservative Quick Scan `.iso`/`.img` disk-image autorun carrier review coverage.
- ANE string indicators now count `disk_image_autorun_executable_count` only when file bytes contain an ISO/UDF marker (`CD001`, `NSR02`, or `NSR03`), visible `autorun.inf` text, and an executable/script launch reference.
- Added `disk_image_autorun_executable`, which requires a `.iso` or `.img` carrier plus the combined marker/string evidence.
- Preserved false-positive control with native negative fixtures for ordinary autorun text without a disk-image marker and autorun document links.
- Routed `.iso` and `.img` through Quick Scan risky-file priority so small disk-image carriers are not skipped before static review.
- Added local-core Quick Scan proof that an inert `support-media.iso` fixture under `Downloads` is surfaced as a `PersistenceIndicator` review detection while confirmed-only auto-quarantine leaves it in place.
- Source-contract coverage now pins the `.iso`/`.img` risky extensions, string indicator, native scoring fixtures, local-core runtime fixture, reason ID, and inert fixture name.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2075-disk-image-autorun-carriers.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native disk-image string/scoring tests passed (`6`), focused local-core disk-image Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `scoring` passed (`52`), native `indicator` passed (`10`), local-core `file_walker` passed (`7`), and local-core `quick_scan_reports` passed (`29`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `335.4s`) for `.workflow\ultracode\avorax-hardening\results\2075-small-threat-mvp-full-report.json`.
- Remaining proof includes full ISO/UDF filesystem parsing, image mounting behavior, payload extraction/inspection, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2074

- Expanded conservative ZIP archive review coverage for deceptive nested executable/script names.
- ANE ZIP analysis now uses `suspicious_archive_executable_name` so entries such as `invoice.pdf.exe`, `photo.jpg.scr`, and `readme.txt.js` increment `suspicious_nested_name_count` while ordinary `tools/setup.exe` remains ordinary executable metadata rather than review evidence by name alone.
- Broadened the archive executable/script suffix set used for `contains_executable` to include common script/installer/carrier suffixes without changing the requirement that review evidence also needs a suspicious nested name.
- Added native ZIP analyzer positive/negative fixtures and native scoring positive/negative fixtures for deceptive versus ordinary nested executables.
- Added local-core Quick Scan proof that an inert `documents-archive.zip` fixture under `Downloads` with `documents/invoice.pdf.exe` is surfaced as a review-only `archive_suspicious_executable` detection while confirmed-only auto-quarantine leaves it in place.
- Source-contract coverage now pins the suspicious archive helper, native fixtures, local-core runtime fixture, and reason ID.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2074-zip-deceptive-nested-executables.md`.
- A first ambient `cargo` fmt attempt failed because Cargo was not on this continuation shell's `PATH`; all verification was rerun with explicit `C:\Users\Brent\.cargo\bin\cargo.exe` paths.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native deceptive/ordinary archive analyzer+scoring tests passed (`4`), focused local-core deceptive ZIP Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `archive` passed (`25`), native `scoring` passed (`49`), and local-core `quick_scan_reports` passed (`28`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `342.3s`) for `.workflow\ultracode\avorax-hardening\results\2074-small-threat-mvp-full-report.json`.
- Remaining proof includes nested payload extraction/inspection, encrypted/protected archive content handling beyond existing fail-visible limits, non-ZIP archive formats such as RAR/7z/ISO, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2073

- Added conservative EML executable-attachment carrier review coverage.
- ANE string indicators now count `email_executable_attachment_count` only when MIME email headers are present and `Content-Disposition: attachment` metadata references executable/script names through `filename=` or `name=` parameters.
- Added `email_executable_attachment`, which requires a `.eml` carrier plus executable/script attachment metadata.
- Preserved false-positive control with native negative fixtures for ordinary document attachments and attachment words outside email context.
- Classified `.eml` as text and routed `.eml` through Quick Scan risky-file priority/candidate filtering.
- Added local-core Quick Scan proof that an inert `invoice-email.eml` fixture under `Downloads` is surfaced as a `SuspiciousDownloader` review detection while confirmed-only auto-quarantine leaves it in place.
- Source-contract coverage now pins the `.eml` risky extension, string indicator, native scoring fixtures, local-core runtime fixture, reason ID, and file-type route.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2073-eml-attachment-carriers.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native email string/scoring tests passed (`6`), focused local-core EML Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `file_type` passed (`6`), native `scoring` passed (`47`), local-core `file_walker` passed (`7`), and local-core `quick_scan_reports` passed (`27`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `382.5s`) for `.workflow\ultracode\avorax-hardening\results\2073-small-threat-mvp-full-report.json`.
- Remaining proof includes Outlook `.msg`/OLE parsing, attachment decoding/extraction, full MIME unfolding/RFC2231 parameter parsing, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2072

- Added conservative autorun INF carrier review coverage.
- ANE string indicators now count `autorun_inf_executable_command_count` only when a visible `[autorun]` section contains `open=`, `shellexecute=`, or `shell\...\command=` launch keys that reference executable/script paths.
- Added `autorun_inf_executable_launch`, which requires a `.inf` carrier plus autorun executable/script command evidence.
- Preserved false-positive control with native negative fixtures for ordinary driver INF content and autorun document/web links.
- Classified `.inf` as text and routed `.inf` through Quick Scan risky-file priority/candidate filtering.
- Added file-walker proof that `autorun.inf` is retained by Quick Scan risky-file walking while ordinary `notes.txt` remains skipped.
- Added local-core Quick Scan proof that inert `autorun.inf` and `media-autorun.inf` fixtures under `Downloads` are surfaced as `PersistenceIndicator` review detections while confirmed-only auto-quarantine leaves them in place.
- Source-contract coverage now pins the `.inf` risky extension, string indicator, native scoring fixtures, local-core runtime fixtures, reason ID, file-type route, and file-walker fixture.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2072-autorun-inf-carriers.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native autorun INF string/scoring tests passed (`5`), focused local-core autorun INF Quick Scan test passed (`1`), focused local-core file-walker fixture passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `file_type` passed (`6`), native `scoring` passed (`44`), local-core `file_walker` passed (`7`), and local-core `quick_scan_reports` passed (`26`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `336.4s`) for `.workflow\ultracode\avorax-hardening\results\2072-small-threat-mvp-full-report.json`.
- Remaining proof includes removable-media mount behavior, Windows AutoRun host behavior, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2071

- Added conservative HTML/SVG web-document carrier review coverage.
- ANE string indicators now count `web_document_active_content_count` only when visible web-document markers are present, covering active terms such as `<script`, `javascript:`, event-handler attributes, object-URL/download helpers, `atob(`, `fetch(`, and `XMLHttpRequest`.
- Added `web_document_active_content_remote_launch`, which requires a `.html`, `.htm`, or `.svg` carrier, web-document active-content evidence, and remote executable/script, remote network executable/script path, or script-host plus downloader evidence.
- Preserved false-positive control with native negative fixtures for ordinary HTML web links and active web words outside web-document context.
- Classified `.html`, `.htm`, and `.svg` as document types and routed those extensions through Quick Scan risky-file priority/candidate filtering.
- Added local-core Quick Scan proof that inert `invoice-web.html` and `diagram-loader.svg` fixtures under `Downloads` are surfaced as `SuspiciousDownloader` review detections while confirmed-only auto-quarantine leaves them in place.
- Source-contract coverage now pins the web-document risky extensions, string indicator, native scoring fixtures, local-core runtime fixtures, reason ID, and file-type route.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2071-web-document-carriers.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native web-document/string/scoring tests passed (`5`), focused local-core web-document Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `file_type` passed (`6`), native `scoring` passed (`40`), and local-core `quick_scan_reports` passed (`25`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `335.7s`) for `.workflow\ultracode\avorax-hardening\results\2071-small-threat-mvp-full-report.json`.
- Remaining proof includes browser-engine parsing/rendering, JavaScript execution/sandbox telemetry, browser exploit-family parsing beyond static markers, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2070

- Added conservative PDF active-content carrier review coverage.
- ANE string indicators now count `pdf_active_content_count` only when PDF header evidence is present, covering active PDF action markers such as `/OpenAction`, `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/SubmitForm`, and `/XFA`.
- Added `pdf_active_content_remote_launch`, which requires a `.pdf` carrier, PDF active-content evidence, and remote executable/script, remote network executable/script path, or script-host plus downloader evidence.
- Preserved false-positive control with native negative fixtures for ordinary PDF web links and PDF action words outside a PDF header.
- Classified `.pdf` as a document type and routed `.pdf` through Quick Scan risky-file priority/candidate filtering.
- Added local-core Quick Scan proof that inert `invoice-action.pdf` and `support-launch.pdf` fixtures under `Downloads` are surfaced as `SuspiciousDownloader` review detections while confirmed-only auto-quarantine leaves them in place.
- Source-contract coverage now pins the PDF risky extension, string indicator, native scoring fixtures, local-core runtime fixtures, reason ID, and file-type route.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2070-pdf-active-content-carriers.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native PDF/string/scoring tests passed (`6`), focused local-core PDF Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `file_type` passed (`6`), native `scoring` passed (`36`), and local-core `quick_scan_reports` passed (`24`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `331s`) for `.workflow\ultracode\avorax-hardening\results\2070-small-threat-mvp-full-report.json`.
- Remaining proof includes PDF object-stream parsing, embedded payload decompression/extraction, PDF exploit-family parsing beyond static markers, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2069

- Added conservative RTF external-object carrier review coverage.
- ANE string indicators now count `rtf_external_object_count` only when RTF header evidence is present, covering object, object-link/update, template, field, DDE, include-picture, and include-text terms.
- Added `rtf_external_object_remote_launch`, which requires a `.rtf` carrier, RTF object/template/field evidence, and remote executable/script, remote network executable/script path, or script-host plus downloader evidence.
- Preserved false-positive control with native negative fixtures for ordinary RTF web links and non-RTF object/field words.
- Classified `.rtf` as a document type and routed `.rtf` through Quick Scan risky-file priority/candidate filtering.
- Added local-core Quick Scan proof that inert `invoice-object.rtf` and `support-field.rtf` fixtures under `Downloads` are surfaced as `SuspiciousDownloader` review detections while confirmed-only auto-quarantine leaves them in place.
- Source-contract coverage now pins the RTF risky extension, string indicator, native scoring fixtures, local-core runtime fixtures, reason ID, and file-type route.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2069-rtf-object-carriers.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native RTF/string/scoring tests passed (`6`), focused local-core RTF Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `file_type` passed (`6`), native `scoring` passed (`32`), and local-core `quick_scan_reports` passed (`23`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `327.2s`) for `.workflow\ultracode\avorax-hardening\results\2069-small-threat-mvp-full-report.json`.
- Remaining proof includes embedded OLE payload parsing, RTF exploit-family parsing beyond static strings, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2068

- Extended the conservative Office macro-carrier heuristic to legacy `.doc`, `.xls`, and `.ppt` files.
- Split ANE carrier helpers so `office_macro_auto_run_remote_launch` uses `is_macro_capable_office_carrier`, while `ooxml_macro_external_remote_relationship` remains restricted to macro-enabled OOXML carriers through `is_macro_enabled_ooxml_office_carrier`.
- Added Quick Scan risky-file routing for `.doc`, `.xls`, and `.ppt` so small legacy Office carriers are not skipped before static analysis.
- Added native scoring fixtures for legacy Office remote-script, UNC script, script-host/downloader positives, and an ordinary legacy Office link negative.
- Added local-core Quick Scan proof that inert `invoice-legacy.doc`, `budget-legacy.xls`, and `briefing-legacy.ppt` fixtures under `Downloads` are surfaced as `MaliciousMacro` review detections while confirmed-only auto-quarantine leaves them in place.
- Source-contract coverage now pins the legacy Office fixtures, helper split, test names, and risky extension routing.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2068-legacy-office-macro-carriers.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native legacy Office tests passed (`4`), focused local-core legacy Office Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `office_macro` passed (`5`) and local-core `quick_scan_reports` passed (`22`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `327.6s`) for `.workflow\ultracode\avorax-hardening\results\2068-small-threat-mvp-full-report.json`.
- Remaining proof includes full OLE/VBA stream parsing beyond bounded static strings, protected/encrypted legacy Office parsing, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2067

- Hardened ANE's OOXML relationship skip path so oversized or unsupported `.rels` bodies are fail-visible.
- `bounded_relationship_body` now returns a limit/unsupported error for stored bodies over `MAX_STORED_RELATIONSHIP_BYTES`, deflated bodies over compressed/declared/decoded limits, and unsupported ZIP compression methods instead of returning clean `Ok(None)`.
- Updated existing native oversized stored and declared-over-limit deflated fixtures to require `limit_exceeded`.
- Added a native unsupported-compression fixture proving plaintext-looking remote relationship XML is not inspected when the ZIP compression method is unsupported.
- Added local-core Quick Scan proof that an inert `unsupported-compression-invoice.docm` fixture remains clean and unquarantined because unsupported relationship bytes are not trusted as OOXML evidence.
- Source-contract coverage now pins the unsupported-compression local-core guard, fixture name, and native limit-evidence fixture.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2067-ooxml-relationship-limit-evidence.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native unsupported/oversized/declared-over-limit OOXML tests passed (`3`), focused local-core unsupported-compression OOXML false-positive guard passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `ooxml_` passed (`13`), native `archive` passed (`21`), and local-core `quick_scan_reports` passed (`21`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `323.7s`) for `.workflow\ultracode\avorax-hardening\results\2067-small-threat-mvp-full-report.json`.
- Remaining proof includes parsing additional ZIP compression/encryption variants safely, ZIP64, multidisk archives, full OLE/OpenXML/VBA stream parsing beyond bounded relationship evidence, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2066

- Hardened ANE's ZIP/OOXML relationship trust boundary for encrypted entries.
- Added `ZIP_GENERAL_PURPOSE_ENCRYPTED` parsing for local headers and central-directory entries.
- Encrypted OOXML `.rels` bodies are no longer inspected as plaintext relationship XML; they set limit/unsupported evidence and return without counting external or remote executable relationships.
- Central-directory body reads now require the encrypted bit, data-descriptor bit, compression method, and local header name to match the referenced local header before reading bytes.
- Added native fixtures proving local encrypted `.rels` bodies and central-directory encrypted `.rels` bodies are not inspected even when the fixture bytes contain plaintext-looking remote-script XML.
- Added local-core Quick Scan proof that an inert `encrypted-invoice.docm` fixture remains clean and unquarantined because encrypted relationship bytes are not trusted as OOXML evidence.
- Source-contract coverage now pins the encrypted flag constant, focused native tests, local-core false-positive guard, and fixture name.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2066-ooxml-encrypted-relationship-boundary.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native encrypted OOXML tests passed (`2`), focused local-core encrypted OOXML false-positive guard passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `ooxml_` passed (`12`), native `archive` passed (`20`), and local-core `quick_scan_reports` passed (`20`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `323.8s`) for `.workflow\ultracode\avorax-hardening\results\2066-small-threat-mvp-full-report.json`.
- Remaining proof includes decrypting or safely reporting protected Office content beyond unsupported/limit evidence, unsupported ZIP compression/encryption variants, ZIP64, multidisk archives, full OLE/OpenXML/VBA stream parsing beyond bounded relationship evidence, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2065

- Added bounded central-directory parsing to ANE's ZIP analyzer for OOXML relationship review evidence when ZIP local headers use the data-descriptor flag and zero local sizes.
- Preserved conservative ZIP bounds: central directory parsing is capped at `256 KiB`, entry count remains capped at `256`, ZIP64/multidisk sentinels are fail-visible as limit evidence, and `.rels` bodies still use the existing stored/deflated `64 KiB` limits.
- Added a local-header consistency guard before central-directory body reads: the local header name, method, and data-descriptor bit must match the central entry.
- Kept the analyzer extraction-free: no ZIP entry is written to disk, no Office file is opened, no macro is executed, and unsupported compression methods remain skipped.
- Added native fixtures for data-descriptor central-directory OOXML relationship detection and central/local name mismatch limit evidence.
- Added local-core Quick Scan proof that an inert `descriptor-invoice.docm` fixture under `Downloads` is surfaced as a `MaliciousMacro` review detection while confirmed-only auto-quarantine leaves it in place.
- Source-contract coverage now pins central-directory constants, EOCD lookup, focused native tests, and the local-core runtime fixture.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2065-ooxml-central-directory-relationship-carriers.md`.
- Focused verification passed locally: Rust fmt/check passed for native-engine and local-core, native central-directory/data-descriptor OOXML tests passed (`2`), focused local-core data-descriptor OOXML Quick Scan test passed (`1`), and Python source-contracts passed (`541`).
- Broader verification passed locally: native `ooxml_` passed (`10`), native `archive` passed (`18`), and local-core `quick_scan_reports` passed (`19`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `325.5s`) for `.workflow\ultracode\avorax-hardening\results\2065-small-threat-mvp-full-report.json`.
- Remaining proof includes unsupported ZIP compression methods beyond stored/deflate, ZIP64, multidisk archives, oversized central-directory handling beyond fail-visible limits, full OLE/OpenXML/VBA stream parsing beyond bounded relationship evidence, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2064

- Added bounded raw-deflate support for compressed OOXML `.rels` relationship bodies in ANE's ZIP analyzer.
- Added direct `flate2 = "1.1"` dependency to `core\zentor_native_engine\Cargo.toml` and a test-only `flate2 = "1.1"` dev dependency to `core\zentor_local_core\Cargo.toml`; the root workspace `Cargo.lock` pins `flate2` `1.1.9`, `miniz_oxide` `0.8.9`, `crc32fast` `1.5.0`, and `adler2` `2.0.1`.
- License evidence was checked from locally cached crate manifests: `flate2` `MIT OR Apache-2.0`, `miniz_oxide` `MIT OR Zlib OR Apache-2.0`, `crc32fast` `MIT OR Apache-2.0`, and `adler2` `0BSD OR MIT OR Apache-2.0`.
- Preserved bounds: compressed `.rels` bodies are decoded only for ZIP method `8`, compressed size at most `64 KiB`, declared uncompressed size at most `64 KiB`, and actual decoded output at most `64 KiB`.
- Decode errors set the archive limit flag rather than being treated as clean success.
- Added native fixtures proving bounded deflated relationship detection, declared-size limit skipping, and decode-error evidence.
- Added local-core Quick Scan proof that an inert `compressed-invoice.docm` fixture under `Downloads` is surfaced as a `MaliciousMacro` review detection while confirmed-only auto-quarantine leaves it in place.
- Source-contract coverage now pins the deflate limits, ZIP method constant, focused native tests, and local-core runtime fixture.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, `docs\dependency-license-inventory.md`, and `.workflow\ultracode\avorax-hardening\results\2064-ooxml-deflated-relationship-carriers.md`.
- Focused verification passed locally: Rust fmt passed for native-engine and local-core, native deflated OOXML tests passed (`3`), native OOXML archive/scoring tests passed (`9`), focused local-core deflated OOXML Quick Scan test passed (`1`), local-core `quick_scan_reports` passed (`18`), native `archive` passed (`16`), native `office_macro` passed (`2`), dependency evidence passed, and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `326s`) for `.workflow\ultracode\avorax-hardening\results\2064-small-threat-mvp-full-report.json`.
- Remaining proof includes unsupported ZIP compression methods, ZIP data-descriptor/central-directory-only parsing, full OLE/OpenXML/VBA stream parsing beyond bounded relationship evidence, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2063

- Extended ANE's existing bounded ZIP analyzer with OOXML macro-package relationship signals for `.docm`, `.xlsm`, and `.pptm` files.
- Added `ooxml_vba_project_count`, `ooxml_external_relationship_count`, and `ooxml_remote_executable_relationship_count` to archive analysis.
- Added `ooxml_macro_external_remote_relationship`, which requires a macro-enabled Office extension, a VBA project entry, and a small stored `.rels` body with an external relationship to a remote executable/script URL or remote network executable/script path.
- Preserved bounds and honesty: compressed relationship bodies are not read without inflate support, oversized relationship bodies are skipped, no Office file is opened, no ZIP entry is extracted to disk, and no VBA/macro content is executed.
- Preserved false-positive control with native negative fixtures for ordinary external document links and non-macro `.docx` packages.
- Added local-core Quick Scan proof that inert `invoice-package.docm`, `budget-package.xlsm`, and `briefing-package.pptm` fixtures under `Downloads` are surfaced as `MaliciousMacro` review detections while confirmed-only auto-quarantine leaves them in place.
- Updated `.pptm` quick-scan priority ordering to match its existing risky-candidate treatment.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2063-ooxml-macro-relationship-carriers.md`.
- Focused verification passed locally: Rust fmt passed for native-engine and local-core, native OOXML archive/scoring tests passed (`7`), the focused local-core OOXML macro relationship Quick Scan test passed (`1`), local-core `quick_scan_reports` passed (`17`), native `archive` passed (`14`), native `office_macro` passed (`2`), and Python source-contracts passed (`541`).
- The first full verifier attempt stopped at the `local-core quick-scan small-threat reports` step with exit `101`; the exact first three verifier steps were rerun immediately and passed, including `quick_scan_reports` (`17`), so the full suite was rerun from scratch.
- Full verification passed locally on rerun: the small-threat MVP verifier plus report validator passed (`140` steps in `322s`) for `.workflow\ultracode\avorax-hardening\results\2063-small-threat-mvp-full-report.json`.
- Remaining proof includes deflate/inflate support for compressed OOXML relationship bodies, full OLE/OpenXML/VBA stream parsing beyond bounded entry metadata and stored `.rels` bodies, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2062

- Added conservative macro-enabled Office carrier review evidence for `.docm`, `.xlsm`, and `.pptm` files.
- ANE string indicators now count `macro_auto_run_count` for auto-run macro terms such as `AutoOpen`, `Document_Open`, `Workbook_Open`, and `Presentation_Open`, including bounded UTF-16LE text views where macro markers are visible.
- Added `office_macro_auto_run_remote_launch`, which requires a macro-enabled Office extension plus macro auto-run evidence and remote executable/script, remote network script, script-host, or suspicious downloader evidence.
- Preserved false-positive control with native negative fixtures proving ordinary macro-enabled links and non-macro Office documents with macro words are not flagged by extension or text alone.
- Added local-core Quick Scan proof that inert `invoice.docm`, `budget.xlsm`, and `briefing.pptm` fixtures under `Downloads` are surfaced as `MaliciousMacro` review detections while confirmed-only auto-quarantine leaves them in place.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2062-macro-enabled-office-carriers.md`.
- Focused verification passed locally: Rust fmt passed for native-engine and local-core, native macro string tests passed (`4` focused filters), native macro scoring tests passed (`3` focused filters), native macro risk-fusion test passed (`1`), focused local-core macro-enabled Office Quick Scan test passed (`1`), local-core `quick_scan_reports` passed (`16`), native `office_macro` tests passed (`2`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `319.6s`) for `.workflow\ultracode\avorax-hardening\results\2062-small-threat-mvp-full-report.json`.
- Remaining proof includes real Office compound/OpenXML macro parsing beyond bounded strings, production false-positive measurement without live malware, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2061

- Added conservative remote network executable/script path detection to ANE string indicators.
- The new `remote_network_executable_path_count` covers UNC paths such as `\\fileserver\share\support.ps1` and remote `file://fileserver/share/support.exe` references, while negative fixtures prove ordinary UNC documents and local `file:///C:/...` executable URLs are not counted.
- Extended shortcut and registry carrier review evidence so `shortcut_remote_executable_launch` can be driven by a remote executable/script URL or remote network executable/script path.
- Added local-core Quick Scan proof that an inert UTF-16LE `support-share.lnk` fixture under `Downloads` is surfaced as a `SuspiciousDownloader` review detection with `shortcut_remote_executable_launch` evidence while confirmed-only auto-quarantine leaves it in place.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2061-shortcut-network-path-carriers.md`.
- Focused verification passed locally: Rust fmt passed for native-engine and local-core, native network-path string tests passed (`4` focused filters), native `.lnk` UNC positive/negative tests passed (`2`), focused local-core registry/shortcut/LNK test passed (`1`), local-core `quick_scan_reports` passed (`15`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `317.4s`) for `.workflow\ultracode\avorax-hardening\results\2061-small-threat-mvp-full-report.json`.
- Remaining proof includes real Shell Link target parsing beyond bounded strings, live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2060

- Added conservative `.lnk` shortcut carrier coverage to the existing shortcut heuristic and Quick Scan runtime proof.
- ANE string indicators now inspect a bounded UTF-16LE text view in addition to lossy UTF-8, allowing Windows shortcut-style UTF-16LE URLs to be reviewed without opening or executing the shortcut.
- Extended `shortcut_remote_executable_launch` to `.lnk`, `.url`, and `.scf` carriers, still requiring a remote executable/script URL and retaining a negative ordinary `.lnk` web-link fixture.
- Added local-core Quick Scan proof that an inert `support-link.lnk` fixture under `Downloads` is surfaced as a `SuspiciousDownloader` review detection with `shortcut_remote_executable_launch` evidence while confirmed-only auto-quarantine leaves it in place.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2060-quick-scan-lnk-shortcut-carriers.md`.
- Focused verification passed locally: Rust fmt passed for native-engine and local-core, native UTF-16LE URL-count test passed (`1`), native `.lnk` positive and ordinary-link negative tests passed (`1` each), focused local-core registry/shortcut/LNK test passed (`1`), local-core `quick_scan_reports` passed (`15`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `318.1s`) for `.workflow\ultracode\avorax-hardening\results\2060-small-threat-mvp-full-report.json`.
- Remaining proof includes full Shell Link parsing/emulation, live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2059

- Added local-core Quick Scan runtime coverage for `.bat`, `.cmd`, `.vbs`, and `.vbe` script carrier files.
- The inert `support.bat`, `repair.cmd`, `support.vbs`, and `support.vbe` fixtures use static downloader, execution, and encoded-script markers only; they are not executed by cmd.exe, WSH, or any script host.
- Verified Batch/CMD carriers are surfaced as `SuspiciousDownloader` review detections with `download_execute_script` evidence, and VBS/VBE carriers are surfaced with both `encoded_script_command` and `download_execute_script` evidence, while confirmed-only auto-quarantine leaves all files in place.
- Extended source-contract coverage so this runtime proof remains tied to the risky-extension/file-type work.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2059-quick-scan-batch-vbs-carriers.md`.
- Focused verification passed locally: Rust fmt passed, the focused local-core Batch carrier test passed (`1`), the focused local-core VBS carrier test passed (`1`), local-core `quick_scan_reports` passed (`15`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `302.2s`) for `.workflow\ultracode\avorax-hardening\results\2059-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2058

- Added local-core Quick Scan runtime coverage for `.jse`, `.mjs`, and `.cjs` JavaScript carrier files.
- The inert `support.jse`, `worker.mjs`, and `helper.cjs` fixtures use static encoded/obfuscation, downloader, and execution markers only; they are not executed in Node, WSH, or a browser.
- Verified all three carriers are surfaced as `SuspiciousDownloader` review detections with `encoded_script_command` and `download_execute_script` evidence while confirmed-only auto-quarantine leaves the files in place.
- Extended source-contract coverage so this runtime proof remains tied to checkpoint 2051's risky-extension/file-type work.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2058-quick-scan-javascript-carriers.md`.
- Focused verification passed locally: Rust fmt passed, the focused local-core JavaScript carrier test passed (`1`), local-core `quick_scan_reports` passed (`13`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `300.5s`) for `.workflow\ultracode\avorax-hardening\results\2058-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2057

- Added local-core Quick Scan runtime coverage for `.psm1`, `.psd1`, and `.ps1xml` PowerShell carrier files.
- The inert `profile.psm1`, `module.psd1`, and `types.ps1xml` fixtures use static encoded-command, downloader, and execution markers only; they are not executed or imported.
- Verified all three carriers are surfaced as `SuspiciousDownloader` review detections with `encoded_script_command` and `download_execute_script` evidence while confirmed-only auto-quarantine leaves the files in place.
- Extended source-contract coverage so this runtime proof remains tied to checkpoint 2051's risky-extension/file-type work.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2057-quick-scan-powershell-carriers.md`.
- Focused verification passed locally: Rust fmt passed, the focused local-core PowerShell carrier test passed (`1`), local-core `quick_scan_reports` passed (`12`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `299.3s`) for `.workflow\ultracode\avorax-hardening\results\2057-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2056

- Added conservative review-only native heuristic evidence for `.xlam` and `.xll` Office add-in carriers that reference a remote executable/script URL or combine script-host references with downloader/execution terms.
- Preserved false-positive control: a native negative fixture proves an ordinary `.xlam` documentation link is not flagged by extension alone.
- Added local-core Quick Scan runtime coverage proving inert `addin-loader.xlam` and `report-addin.xll` fixtures under `Downloads` are surfaced as `SuspiciousDownloader` review detections while confirmed-only auto-quarantine leaves both files in place.
- Extended source-contract coverage so the Office add-in carrier heuristic and Quick Scan runtime fixture remain wired to the small-threat MVP evidence chain.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2056-quick-scan-office-addin-carriers.md`.
- Focused verification passed locally: Rust fmt passed, native `office_addin` tests passed (`3`), the focused local-core Office add-in carrier test passed (`1`), local-core `quick_scan_reports` passed (`11`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `350s`) for `.workflow\ultracode\avorax-hardening\results\2056-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2055

- Added conservative review-only native heuristic evidence for `.chm`, `.one`, and `.onepkg` help/OneNote carriers that reference a remote executable/script URL or combine script-host references with downloader/execution terms.
- Preserved false-positive control: a native negative fixture proves an ordinary `.chm` documentation link is not flagged by extension alone.
- Added local-core Quick Scan runtime coverage proving inert `support.chm` and `meeting.onepkg` fixtures under `Downloads` are surfaced as `SuspiciousDownloader` review detections while confirmed-only auto-quarantine leaves both files in place.
- Extended source-contract coverage so the help/OneNote carrier heuristic and Quick Scan runtime fixture remain wired to the small-threat MVP evidence chain.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2055-quick-scan-help-note-carriers.md`.
- Focused verification passed locally: Rust fmt passed, native `help_note` tests passed (`2`), native `ordinary_help_link` test passed (`1`), the focused local-core help/OneNote carrier test passed (`1`), local-core `quick_scan_reports` passed (`10`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `308.3s`) for `.workflow\ultracode\avorax-hardening\results\2055-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2054

- Added conservative review-only native heuristic evidence for `.iqy` and `.slk` Office query/spreadsheet carriers that reference a remote executable/script URL or script host.
- Preserved false-positive control: the heuristic requires carrier extension plus static remote/script-host evidence, and a native negative fixture proves an ordinary `.iqy` data link is not flagged by extension alone.
- Added local-core Quick Scan runtime coverage proving inert `remote-query.iqy` and `spreadsheet-link.slk` fixtures under `Downloads` are surfaced as `SuspiciousDownloader` review detections while confirmed-only auto-quarantine leaves both files in place.
- Extended source-contract coverage so the Office carrier heuristic and Quick Scan runtime fixture remain wired to the small-threat MVP evidence chain.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2054-quick-scan-office-query-carriers.md`.
- Focused verification passed locally: Rust fmt passed, native `office_query` tests passed (`3`), the focused local-core Office carrier test passed (`1`), local-core `quick_scan_reports` passed (`9`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `325.3s`) for `.workflow\ultracode\avorax-hardening\results\2054-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2053

- Added native static string indicators for registry autorun keys, script-host references, and remote executable/script URLs.
- Added review-only native heuristics for `.reg` autorun carriers and `.url`/`.scf` shortcut downloader carriers; ordinary web links do not trigger the shortcut heuristic.
- Added local-core Quick Scan runtime coverage proving inert `autorun.reg` and `support.url` fixtures under `Downloads` are surfaced for review while confirmed-only auto-quarantine leaves both files in place.
- Extended source-contract coverage so the carrier tests and native heuristic markers remain wired to the small-threat MVP evidence chain.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2053-quick-scan-registry-shortcut-carriers.md`.
- Focused verification passed locally: Rust fmt passed, native `registry` tests passed (`3`), native `shortcut` tests passed (`3`), native `web_link` test passed (`1`), local-core focused registry/shortcut carrier test passed (`1`), local-core `quick_scan_reports` passed (`8`), and Python source-contracts passed (`541`).
- Full verification passed locally: the small-threat MVP verifier plus report validator passed (`140` steps in `328.1s`) for `.workflow\ultracode\avorax-hardening\results\2053-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2052

- Added local-core Quick Scan runtime coverage for `.hta` and `.wsf` script-host carrier files under a temporary `Downloads` root.
- The inert fixtures use static text indicators only: `base64`, `MSXML2.XMLHTTP`, and `WScript.Shell`. They are not executed and do not contain live malware.
- Verified both carriers are surfaced as review-only `SuspiciousDownloader` probable-malware detections with `encoded_script_command` and `download_execute_script` evidence, while confirmed-only auto-quarantine leaves the files in place.
- Extended source-contract coverage so the carrier runtime fixture remains tied to checkpoint 2051's risky-extension/file-type work.
- Updated `STATUS.md`, `CHANGELOG.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2052-quick-scan-script-host-carrier-runtime.md`.
- Verification passed locally: Rust fmt passed, the focused new test passed (`1`), local-core `quick_scan_reports` passed (`7`), Python source-contracts passed (`541`), and the full small-threat MVP verifier plus report validator passed (`140` steps in `321s`) for `.workflow\ultracode\avorax-hardening\results\2052-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2051

- Expanded Quick Scan risky-extension selection for additional common carrier formats: PowerShell module/data/type XML files, JavaScript module variants, registry/URL/SCF/CHM carriers, Office add-ins/query files, and OneNote package files.
- Added native file-type classifier behavior for `.ps1xml`, `.hta`, and `.wsf` so files selected by Quick Scan are routed to script-style static analysis where appropriate instead of becoming unknown coverage gaps.
- Added `native-engine file-type classifier regressions` to `tools\testing\verify-small-threat-mvp.ps1`, the verified-scope text, full-suite report validation, and source-contract coverage.
- Negative check passed: the previous 2050 full-suite report fails the expanded validator with `passed full-suite report is missing required step: native-engine file-type classifier regressions`.
- Updated `README.md`, `docs\malware-protection.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, `STATUS.md`, `CHANGELOG.md`, and `.workflow\ultracode\avorax-hardening\results\2051-quick-scan-risky-carrier-file-types.md`.
- Verification passed locally: both Rust fmt checks passed, local-core `file_walker` passed (`7`), native-engine `file_type` passed (`6`), PowerShell parser checks passed, Python source-contracts passed (`541`), product-copy/no-malware gates passed, and the full small-threat MVP verifier plus report validator passed (`140` steps in `332.5s`) for `.workflow\ultracode\avorax-hardening\results\2051-small-threat-mvp-full-report.json`.
- Remaining proof includes live-malware-free production false-positive measurement, installed service/UI E2E, release packaging, and signed-driver/pre-execution validation.

## 2026-07-07 continuation checkpoint 2050

- Wired `tools\testing\verify-small-threat-mvp.ps1` to include `dist\performance\performance_gate_report.json` and `dist\performance\benchmark_report.json` in the structured full-suite report as `generated_reports.performance_gate` and `generated_reports.performance_benchmark`.
- Hardened `tools\testing\validate-small-threat-mvp-report.ps1` so those generated performance reports are parsed and content-validated instead of only being implied by a passing performance gate step.
- The validator now checks performance gate thresholds/status/measurement limitation text, benchmark schema/repo/host/safe fixture policy, exact synthetic corpus size, the native signature and Guard command metrics, `exit_code=0`, non-truncated output, and the non-elevated update-copy simulation disclaimer.
- Added source-contract coverage for the performance generated-report wiring and validator functions.
- Negative checks passed: the prior 2049 full-suite report failed because `generated_reports.performance_gate` was missing, and a copied benchmark report with `safe_fixture_policy='real malware samples'` failed with `performance benchmark generated report safe_fixture_policy mismatch`.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2050-performance-generated-report-validation.md`.
- Verification passed locally: PowerShell parser checks passed, Python source-contracts passed (`540`), the negative missing-key and unsafe-policy smokes failed as expected, and the full small-threat MVP verifier plus report validator passed (`139` steps in `308.6s`) for `.workflow\ultracode\avorax-hardening\results\2050-small-threat-mvp-full-report.json`.
- Remaining performance/release proof includes release-host performance baselines, installed service/UI E2E, signed-driver latency, kernel/pre-execution blocking, and production false-positive-rate evidence.

## 2026-07-07 continuation checkpoint 2049

- Hardened `tools\testing\validate-small-threat-mvp-report.ps1` so the generated `dependency_evidence` report is parsed and content-validated instead of only checked for existence.
- The validator now checks the exact Python direct and lock requirement pins, release lockfile matrix, current manifest/lockfile presence, Gradle wrapper URL/hash pinning, matching repository root, `allow_known_blockers=false`, `ok=true`, `partial=false`, and empty `release_blockers`.
- Added source-contract coverage for the dependency evidence generated-report content validator.
- Added a negative smoke by pointing a copied full-suite report at a copied dependency evidence report with the required Local Core lockfile row set to `lockfile_present=false`; validation failed as expected with `dependency evidence generated report lockfile check 3 lockfile_present must be JSON boolean True.`
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2049-dependency-evidence-content-validation.md`.
- Verification passed locally: PowerShell parser checks passed, Python source-contracts passed (`540`), the 2048 full-suite report passed the new dependency evidence content validator, the negative required-lockfile smoke failed as expected, and the full small-threat MVP verifier plus report validator passed (`139` steps in `302.6s`) for `.workflow\ultracode\avorax-hardening\results\2049-small-threat-mvp-full-report.json`.
- Remaining release/dependency work includes full release-host SBOM/license output, Android Gradle dependency-lock generation on an Android/Gradle-capable host, packaged desktop E2E, and installed service/UI E2E.

## 2026-07-07 continuation checkpoint 2048

- Hardened `tools\testing\validate-small-threat-mvp-report.ps1` so the generated `protection_self_test` report is parsed and content-validated for honest non-driver protection claims.
- The validator now requires the exact synthetic non-driver fixture schema, `overall_result=pass`, the no signed-driver/pre-execution disclaimer, driver communication/installed/running/pre-execution fields all `false`, five non-driver policy/verdict tests `true`, and `unknown_unsigned_lockdown_blocked_before_launch=false`.
- Added source-contract coverage for the protection self-test generated-report content validator.
- Added a negative smoke by pointing a copied full-suite report at a copied protection self-test report with `driver.pre_execution_blocking_available=true`; validation failed as expected with `protection self-test generated report driver.pre_execution_blocking_available must be JSON boolean False.`
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2048-protection-selftest-content-validation.md`.
- Verification passed locally: PowerShell parser checks passed, Python source-contracts passed (`540`), the 2047 full-suite report passed the new protection self-test content validator, the negative pre-execution-claim smoke failed as expected, and the full small-threat MVP verifier plus report validator passed (`139` steps in `305.1s`) for `.workflow\ultracode\avorax-hardening\results\2048-small-threat-mvp-full-report.json`.
- Remaining protection work includes installed local-core/service E2E, installed service repair E2E, signed-driver IPC and pre-execution proof, packaged desktop E2E, and production false-positive-rate evidence.

## 2026-07-07 continuation checkpoint 2047

- Hardened `tools\testing\validate-small-threat-mvp-report.ps1` so the generated bundled pack inventory report is parsed and content-validated instead of only checked for existence.
- The validator now checks bundled inventory schema/version/status, repository and validator paths, expected signature/rule pack lists, exact pack counts, row count, duplicate names/paths, repository-relative pack paths, current file byte sizes, expected signature/rule directories, extensions, and validator-output format evidence.
- Added source-contract coverage for the generated inventory content validator.
- Added a negative smoke by pointing a copied full-suite report at an inventory with `zentor_persistence.zrule` removed; validation failed as expected with `bundled pack inventory report packs count must match total_pack_count: 13 vs 14`.
- Updated `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2047-bundled-pack-inventory-content-validation.md`.
- Verification passed locally: PowerShell parser checks passed, Python source-contracts passed (`540`), the 2046 full-suite report passed the new content validator, the negative content-validation smoke failed as expected, and the full small-threat MVP verifier plus report validator passed (`139` steps in `308.4s`) for `.workflow\ultracode\avorax-hardening\results\2047-small-threat-mvp-full-report.json`.
- Remaining definition-update work includes live network feed import validation, production feed operations, release-host definition update E2E, installed service/UI definition-update E2E, and driver-level pre-execution proof.

## 2026-07-07 continuation checkpoint 2046

- Added optional structured report output to `tools\testing\run-bundled-pack-validation.ps1` through `-ReportPath`.
- The generated JSON records the expected signature/rule inventory, discovered pack counts, total pack count, per-pack path/byte evidence, and bounded validator output for every bundled `.zsig` and `.zrule`.
- `tools\testing\verify-small-threat-mvp.ps1` now writes `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-bundled-pack-inventory.json` and records it in `generated_reports.bundled_pack_inventory`.
- `tools\testing\validate-small-threat-mvp-report.ps1 -RequireFullSuite` now requires that generated report, so old full-suite reports without pack-inventory evidence fail visibly.
- Updated source contracts, `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2046-bundled-pack-inventory-generated-report.md`.
- Verification passed locally: direct bundled pack validation with `-ReportPath` passed (`8` signature packs, `6` rule packs, `14` total), PowerShell parser checks passed, Python source-contracts passed (`540`), the old 2045 report failed the new generated-report requirement as expected, and the full small-threat MVP verifier plus report validator passed (`139` steps in `319.3s`) for `.workflow\ultracode\avorax-hardening\results\2046-small-threat-mvp-full-report.json`.
- Remaining definition-update work includes live network feed import validation, production feed operations, release-host definition update E2E, installed service/UI definition-update E2E, and driver-level pre-execution proof.

## 2026-07-07 continuation checkpoint 2045

- Tightened `tools\testing\run-bundled-pack-validation.ps1` from dynamic enumeration-only validation to explicit expected-inventory validation plus content validation.
- The script now requires the current `8` expected bundled signature packs and `6` expected bundled rule packs, including ransomware, infostealer, miner/PUP, persistence, and script-threat packs.
- Missing expected packs now fail visibly before content validation; a temporary fixture missing `zentor_persistence.zrule` failed with `Missing expected bundled rule pack: zentor_persistence.zrule`.
- Updated source contracts, `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2045-bundled-pack-inventory-guard.md`.
- Verification passed locally: direct bundled pack validation passed (`8` signature packs, `6` rule packs, `14` total), the missing-pack negative fixture passed, PowerShell parser checks passed, Python source-contracts passed (`540`), the 2044 full-suite report validator still passed, and the full small-threat MVP verifier plus report validator passed (`139` steps in `317.2s`) for `.workflow\ultracode\avorax-hardening\results\2045-small-threat-mvp-full-report.json`.
- Remaining definition-update work includes live network feed import validation, production feed operations, release-host definition update E2E, installed service/UI definition-update E2E, and driver-level pre-execution proof.

## 2026-07-07 continuation checkpoint 2044

- Added `tools\testing\run-bundled-pack-validation.ps1` to validate every bundled `assets\zentor_native\signatures\*.zsig` and `assets\zentor_native\rules\*.zrule` pack through `tools\zentor_intel\validate_indicator_pack.py`.
- `tools\testing\verify-small-threat-mvp.ps1` now runs this as `Bundled signature/rule pack validation` and lists `bundled signature/rule pack validation` in `verification_scope.verified`.
- `tools\testing\validate-small-threat-mvp-report.ps1 -RequireFullSuite` now rejects reports missing the bundled pack validation step or verified-scope text.
- Updated source contracts, `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2044-bundled-pack-validation-full-verifier.md`.
- Verification passed locally: direct bundled pack validation passed (`14` packs), focused threat-intel metadata smoke passed, PowerShell parser checks passed, Python source-contracts passed (`540`), and the full small-threat MVP verifier plus report validator passed (`139` steps in `339s`) for `.workflow\ultracode\avorax-hardening\results\2044-small-threat-mvp-full-report.json`.
- Remaining definition-update work includes live network feed import validation, production feed operations, release-host definition update E2E, installed service/UI definition-update E2E, and driver-level pre-execution proof.

## 2026-07-07 continuation checkpoint 2043

- Integrated the harmless threat-intel category/enum metadata smoke into the full small-threat MVP verifier.
- `tools\testing\verify-small-threat-mvp.ps1` now runs `tools\testing\run-threat-intel-category-smoke.ps1` as `Threat-intel pack metadata smoke` and lists `threat-intel pack metadata smoke` in `verification_scope.verified`.
- `tools\testing\validate-small-threat-mvp-report.ps1 -RequireFullSuite` now rejects reports missing the threat-intel pack metadata smoke step or verified-scope text.
- Updated source contracts, `STATUS.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2043-threat-intel-pack-metadata-full-verifier-integration.md`.
- Verification passed locally: focused threat-intel category/metadata smoke passed, PowerShell parser checks passed for the verifier/report validator, Python source-contracts passed (`540`), the full small-threat MVP verifier passed (`138` steps), and full-suite report validation passed for `.workflow\ultracode\avorax-hardening\results\2043-small-threat-mvp-full-report.json`.
- Remaining definition-update work includes live network feed import validation, production feed operations, release-host definition update E2E, installed service/UI definition-update E2E, and driver-level pre-execution proof.

## 2026-07-07 continuation checkpoint 2042

- Hardened `tools\zentor_intel\validate_indicator_pack.py` so signature/rule pack enum-like metadata must use supported canonical values, including confidence, severity, signature type, action policy, file type, rule verdict/action, rule condition type, and PE import category.
- Added action-policy normalization in `tools\zentor_intel\github_intel_common.py`; manual IOC import and signature compilation now normalize aliases such as `review` to `review_only` before JSONL/pack output.
- Expanded `tools\testing\run-threat-intel-category-smoke.ps1` with harmless fake-pack mutations for invalid confidence, severity, signature type, action policy, file type, verdict, action, and condition type.
- Verified all bundled Avorax `.zsig`/`.zrule` packs pass the stricter Python validator (`14` packs).
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `CHANGELOG.md`, `tools\zentor_intel\README.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2042-threat-intel-pack-enum-metadata-validation.md`.
- Verification passed locally: Python `py_compile` passed for changed modules/contracts, focused threat-intel category smoke passed, source-contracts passed (`540`), and bundled pack validation passed (`14`).

## 2026-07-07 continuation checkpoint 2041

- Tightened `tools\zentor_intel\validate_indicator_pack.py` so already-built `.zsig` and `.zrule` packs must use canonical engine category spelling.
- Added `required_canonical_category(...)` in `tools\zentor_intel\github_intel_common.py`; importers/compilers still normalize aliases, but pack validation rejects alias spelling in final pack files.
- Expanded `tools\testing\run-threat-intel-category-smoke.ps1` to verify non-canonical signature/rule pack categories fail visibly.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `CHANGELOG.md`, `tools\zentor_intel\README.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2041-threat-intel-pack-canonical-category-validation.md`.
- Verification passed locally: Python `py_compile` passed for changed category/validator/contracts, focused threat-intel category smoke passed, and Python source-contracts passed (`540`).

## 2026-07-07 continuation checkpoint 2040

- Extended the shared threat-intel category allowlist from hash-only importers into manual IOC import, signature compilation, known-bad pack building, rule compilation, and pack validation.
- Added `optional_category(...)` in `tools\zentor_intel\github_intel_common.py` for report-level category inheritance without arbitrary metadata passthrough.
- Expanded `tools\testing\run-threat-intel-category-smoke.ps1` so harmless fake hashes/strings exercise import, compile, validate, known-bad, and rule-pack category normalization plus invalid-category failures.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `CHANGELOG.md`, `tools\zentor_intel\README.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2040-threat-intel-pack-category-enforcement.md`.
- Verification passed locally: Python `py_compile` passed for changed threat-intel modules/contracts, focused threat-intel category smoke passed, and Python source-contracts passed (`540`).
- Remaining definition-update work includes live network feed import validation, production feed operations, release-host definition update E2E, installed service/UI definition-update E2E, and driver-level pre-execution proof.

## 2026-07-07 continuation checkpoint 2039

- Added a shared threat-intel category allowlist and normalizer in `tools\zentor_intel\github_intel_common.py`.
- Routed `import_hash_feed.py` and `import_github_hashes_only.py` through `required_category(...)`, so explicit `--category` metadata is still required and unsupported category text now fails before JSONL output.
- Added `tools\testing\run-threat-intel-category-smoke.ps1`, using harmless fake hashes to verify valid alias normalization and invalid-category failures for both hash-feed and developer hash-only importers.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `CHANGELOG.md`, `tools\zentor_intel\README.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2039-threat-intel-category-normalization.md`.
- Verification passed locally: Python `py_compile` passed for the changed threat-intel modules, focused threat-intel category smoke passed, and Python source-contracts passed (`540`).
- Remaining definition-update work includes live network feed import validation, production feed operations, release-host definition update E2E, and installed service/UI definition-update E2E.

## 2026-07-07 continuation checkpoint 2038

- Improved Flutter dark-theme accessibility by changing `ZentorColors.secondaryAccent` from `0xFF6C5CFF` to `0xFF8E82FF`, keeping the same visual role while clearing AA contrast on Avorax dark surfaces.
- Added `app_visual_policy_test.dart` contrast-ratio coverage for shared text, accent, success, warning, and danger colors against `background`, `surface`, and `elevatedSurface`.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, `TODO.md`, `CHANGELOG.md`, and `.workflow\ultracode\avorax-hardening\results\2038-flutter-dark-theme-contrast-guard.md`.
- Verification passed locally: Dart format passed with `0 changed` after formatting, focused visual policy tests passed (`59`), Flutter analyze passed, and Python source-contracts passed (`539`).
- Remaining accessibility work includes keyboard traversal audits, per-feature screen-reader coverage, localization-ready text extraction, and packaged desktop visual/click-through E2E.

## 2026-07-07 continuation checkpoint 2037

- Refreshed Windows release-host evidence after Flutter, Dart, Cargo, rustfmt, and Git became available through explicit local paths.
- Confirmed the old missing Flutter/Dart/Rust/Git blocker is superseded for this host.
- Direct `flutter build windows --debug --no-pub` still fails before build because Flutter plugin builds require Windows symlink support.
- Host-only `tools\windows\avorax-release-prereq-check.ps1` with explicit dotnet/cargo/flutter paths wrote `.workflow\ultracode\avorax-hardening\results\2037-release-prereq-host-refresh.json` with `ok=false` and exactly three blockers: no .NET SDK inventory at `C:\Program Files\dotnet\dotnet.exe`, unavailable Windows symlink support/Developer Mode, and missing Visual Studio Desktop C++ components.
- Updated `README.md`, `TESTING.md`, `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\2037-windows-release-host-prereq-refresh.md`.

## 2026-07-05 continuation checkpoint 1612

- Refreshed Guard trusted-publisher exact-match evidence now that Cargo/rustfmt are available in this Windows shell.
- Verified Guard driver verdict logic requires canonical exact trusted-publisher names and ignores externally supplied trusted-publisher metadata for external driver scan commands.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1612-rust-guard-trusted-publisher-exact-match.md`.
- Verification passed locally: `cargo test --manifest-path core\zentor_guard_service\Cargo.toml trusted_publisher_requires_exact_canonical_name -- --test-threads=1`, `driver_request_trusted_publisher_allows_in_lockdown`, `driver_request_avorax_publisher_allows_in_lockdown`, and `external_driver_scan_ignores_caller_supplied_trusted_publisher` each reported `1 passed; 0 failed`; `rustfmt --check core\zentor_guard_service\src\main.rs core\zentor_guard_service\src\driver_ipc.rs` passed.

## 2026-07-05 continuation checkpoint 1613

- Refreshed Guard fail-open exact-root evidence now that Cargo/rustfmt are available in this Windows shell.
- Verified Guard driver verdict fail-open exemptions require exact runtime/product roots, reject lookalike runtime paths in Lockdown, and still allow legitimate Avorax runtime paths.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1613-rust-guard-fail-open-exact-root.md`.
- Verification passed locally: `cargo test --manifest-path core\zentor_guard_service\Cargo.toml fail_open_paths_require_exact_runtime_roots -- --test-threads=1`, `lookalike_runtime_paths_do_not_allow_in_lockdown`, and `driver_fails_open_for_avorax_runtime_paths` each reported `1 passed; 0 failed`; `rustfmt --check core\zentor_guard_service\src\main.rs core\zentor_guard_service\src\driver_ipc.rs` passed.

## 2026-07-05 continuation checkpoint 1614

- Refreshed native/local product-path trust and installer-name trust-removal evidence now that Cargo/rustfmt are available in this Windows shell.
- Verified exact native product roots, repo lookalike rejection, installer-name-only no-trust behavior, local heuristic no-trust behavior for Avorax installer/MSI names, and heuristic propagation of product-path trust errors.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1614-rust-native-product-path-trust-runtime.md`.
- Verification passed locally: ten focused Cargo filters reported `1 passed; 0 failed`; targeted `rustfmt --check` on `core\zentor_native_engine\src\engine.rs`, `core\zentor_native_engine\src\tests\mod.rs`, `core\zentor_native_engine\src\trust\zentor_trust.rs`, and `core\zentor_local_core\src\scanner\heuristic_provider.rs` passed. A broader native-engine rustfmt check still reports existing formatting drift outside this checkpoint scope.

## 2026-07-05 continuation checkpoint 1615

- Refreshed native product-trust diagnostics evidence now that Cargo/rustfmt are available in this Windows shell.
- Verified repo-marker directory checks, repo-marker error honesty, Microsoft publisher trust probe error evidence, and quarantine trust root validation.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1615-rust-native-product-trust-diagnostics-runtime.md`.
- Verification passed locally: six focused Cargo filters reported `1 passed; 0 failed`; `repo_marker_dirs_reject_symbolic_links` is Unix-gated and reported `0 tests` on Windows; targeted `rustfmt --check` on the involved native trust/engine/test files passed.

## 2026-07-05 continuation checkpoint 1616

- Refreshed native sampled-content actual-size evidence now that Cargo is available in this Windows shell.
- Verified `StaticAnalysis.file_size` preserves declared full-file size for sampled content and large-file scans still report full-file hash evidence with a bounded sample.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1616-rust-native-analysis-actual-size-runtime.md`.
- Verification passed locally: `analysis_preserves_declared_file_size_for_sampled_content` and `large_file_scan_reports_full_hash_and_sample_limit` each reported `1 passed; 0 failed`. Formatting remains partial because `rustfmt --check` on the involved analyzer/scan files found existing formatting drift outside any source change in this checkpoint.

## 2026-07-05 continuation checkpoint 1617

- Cleaned targeted native-engine rustfmt drift in analyzer, ZIP, PE parser, scan content-reader, feature-extractor, and signature-matcher files.
- Refreshed native extension default-honesty, ZIP malformed/suffix, and PE resource parser runtime evidence now that Cargo/rustfmt are available.
- Removed three Windows-host unused-import warnings from native test modules by cfg-scoping/minimizing test imports.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1617-rust-native-analyzer-parser-runtime.md`.
- Verification passed locally: eleven focused Cargo filters reported `1 passed; 0 failed`; targeted `rustfmt --check` on the involved native analyzer/parser files passed; broad `cargo test --manifest-path core\zentor_native_engine\Cargo.toml -- --test-threads=1` passed with `284 passed; 0 failed` for lib tests and `6 passed; 0 failed` for the signature compiler, without warnings after cleanup.

## 2026-07-05 continuation checkpoint 1618

- Refreshed local-core cancellation, update traversal/rollback, local quarantine, allowlist, Guard IPC, Guard quarantine metadata-auth, Windows reparse, ACL-account, and DPAPI metadata-key runtime evidence now that Cargo/rustfmt are available.
- Confirmed the stale local metadata-auth filter `authenticated_record_tampering_is_skipped` is obsolete; current behavior reports tampering visibly and `authenticated_record_tampering_is_reported` passes.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1618-rust-update-quarantine-allowlist-runtime.md`.
- Verification passed locally: twenty-eight focused Cargo filters reported `1 passed; 0 failed`; targeted rustfmt checks for involved local-core, update-service, and Guard files passed. Guard symlink-source fixture remains Unix-gated and reports `0 tests` on this Windows host; old local linked-temp and skipped-tamper filters report `0 tests` because current coverage uses the umbrella staged-write fixture and visible tampering report fixture.

## 2026-07-05 continuation checkpoint 1619

- Refreshed native Microsoft Authenticode JSON trust, native placeholder update/export removal, Guard/local YARA bounded reads, native signature-compiler oversized input, Guard streaming SHA-256, and threat-intel generated-signature wiring runtime evidence.
- Confirmed local/Guard quarantine base symlink and linked metadata-key fixtures are Unix-gated and report `0 tests` on this Windows host.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1619-rust-trust-yara-hash-runtime.md`.
- Verification passed locally: eighteen focused Cargo filters reported `1 passed; 0 failed`; targeted rustfmt checks for involved native-engine, Guard, and local-core files passed. Guard YARA, native Authenticode, and quarantine symlink fixtures that require Unix symlink semantics report `0 tests` on this Windows host and remain technically limited here.

## 2026-07-05 continuation checkpoint 1620

- Refreshed stale Cargo-unavailable runtime evidence for local-core app-control/config/bounded/ClamAV filters, Guard hash filters, native ZIP archive path-safety, native hash/signature/suppression validation, and native rule/rule-pack validation.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1620-rust-native-local-rule-hash-runtime.md`.
- Verification passed locally with explicit `C:\Users\Brent\.cargo\bin\cargo.exe`: local-core `app_control` (`47 passed`), `config_writer` (`4 passed`), `bounded_sample` (`5 passed`), `clamav` (`11 passed`); Guard `hash` (`32 passed`); native `archive` (`10 passed`), `rule_compiler` (`13 passed`), `rule_pack_validation` (`6 passed`), `rule_vm_reports` (`2 passed`), `compiler_outputs_pack_metadata_and_hash` (`1 passed`), and fifteen native hash/signature/suppression focused filters (`1 passed; 0 failed` each for matching lib tests). Targeted native rustfmt normalization was applied and `C:\Users\Brent\.cargo\bin\rustfmt.exe --check` passed for the involved native trust/signature/rule/ZIP files.
- Python sanity gates passed after making the native allowlist traversal source contract robust to rustfmt line wrapping: `tools\testing\run-python-source-contracts.py` (`481 tests`) and `py_compile` for the contract runner/test module.
- Existing local-core and Guard compile warning debt remains visible and documented; this checkpoint does not claim installed service, driver, or release packaging coverage.

## 2026-07-05 continuation checkpoint 1621

- Fixed Python native signature/rule pack canonical hashing to use sorted JSON object keys, matching the Rust/serde canonicalization that the native engine enforces for `pack_sha256`.
- Refreshed stale native pack and update-service Cargo/Python blockers in `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1621-native-pack-update-service-runtime.md`.
- Verification passed locally: all bundled native signature packs and rule packs validate with `tools\zentor_intel\validate_indicator_pack.py`; native pack/context focused Cargo filters passed (`repo_native_packs_detect_more_than_eicar`, `signature_pack_loads_and_counts_builtin`, `rule_pack_loads`, `pack_loader`, `pack_hash`, `rule_pack`, and `required_context`); update-service focused filters passed for malformed hashes/versions, package extraction, path safety, staged activation, rollback snapshot safety, service control, oversized entries, driver payload rejection, manifest payload/subcomponent consistency, operational flags, string validation, release-notes/migration validation, and current-version policy validation.
- Sanity verification passed: Python source-contracts (`481 tests`), `py_compile` for the changed Python tooling/contracts, and targeted `rustfmt --check` for the involved update-service Rust files.
- Technical limits remain for three symlink-oriented update-service filters on this Windows host: `symbolic_link`, `checked_recursive_remove`, and `checked_create_dir_rejects_symbolic_link_ancestor` each report `0 tests`.

## 2026-07-05 continuation checkpoint 1622

- Refreshed stale Cargo-unavailable runtime evidence for Guard/local/native error reporting, hash validation, store validation, and size-bound fixtures.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1622-error-size-bound-runtime.md`.
- Verification passed locally with explicit `C:\Users\Brent\.cargo\bin\cargo.exe`: Guard process/cache/config/serialization/direct-start/AI metadata filters passed; local-core app-control/YARA/AI/allowlist/ransomware/training-label/hash-validation filters passed; native trust-store/allowlist/user-approval/false-positive/pack-reader/scan-walker/ML filters passed.
- Sanity verification passed: Python source-contracts (`481 tests`), `py_compile`, targeted rustfmt checks for involved Guard/local/native files after mechanical formatting of native `scan\file_walker.rs`, and a post-format native walker rerun (`1 passed; 0 failed`).
- Existing local-core and Guard warning debt remains visible; native signature-compiler bin reports `0 tests` for library-only native filters while the matching native library tests pass.

## 2026-07-05 continuation checkpoint 1623

- Refreshed current-host Flutter/Dart verification after Flutter, Dart, and Git became available through explicit Windows paths in this shell.
- Mechanically formatted the Flutter client, fixed the resulting analyzer-required braces in `settings_screen.dart`, and updated brittle Python source-contract anchors that depended on pre-format Flutter line wrapping.
- Updated `STATUS.md`, `docs\audit\known-blockers.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1623-flutter-host-runtime-refresh.md`.
- Verification passed locally: `flutter analyze` -> `No issues found`; `flutter test --reporter compact` -> `464 passed`; `dart analyze` for `packages\zentor_protocol` -> `No issues found`; `dart test --reporter compact` -> `8 passed`; Flutter and protocol `dart format --set-exit-if-changed lib test` -> `0 changed` after formatting; Python source-contracts -> `481 tests`; `py_compile` passed.
- Windows desktop artifact verification remains blocked by host symlink support/Developer Mode: `flutter build windows --debug` fails immediately with Flutter's plugin symlink-support prerequisite message.

## 2026-07-05 continuation checkpoint 1624

- Refreshed the Avorax Update Service runtime suite now that Cargo/rustfmt are available through explicit Windows paths.
- Verified signed `.aup` manifest/signature shape, package path safety, payload hash/path/entry limits, duplicate payload rejection, extraction/activation revalidation, rollback validation, service-control bounds, CLI strictness, and update applier payload allowlists through the update-service crate tests.
- Updated `STATUS.md`, `docs\audit\known-blockers.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1624-update-service-runtime-suite.md`.
- Verification passed locally: `cargo test --manifest-path core\avorax_update_service\Cargo.toml -- --test-threads=1` -> update key generator `4 passed`, sign-manifest bin `0 tests`, update-service main tests `176 passed`; `cargo fmt --manifest-path core\avorax_update_service\Cargo.toml -- --check` passed after mechanical formatting; Python source-contracts passed with `481 tests`.
- Remaining update release limits: no production signer ceremony, installed update service E2E, real signed release package staging, MSI integration, or installed Avorax artifact update run is claimed by this checkpoint.

## 2026-07-05 continuation checkpoint 1561

- Refreshed stale dependency-free Python source-contract anchors for current update timeout, local-event, update-package, native/local quarantine, allowlist, UI status-label, scan-progress, realtime watcher, custom scan target-picker, and protected-app single-flight implementations.
- Closed the broad source-contract runner blocker introduced by stale anchors after checkpoint 1560; the runner now passes again with `481 tests`.
- Updated `STATUS.md`, `docs/audit/known-blockers.md`, and `.workflow\ultracode\avorax-hardening\results\1561-source-contract-drift-cleanup.md`.
- Verification passed locally: `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py` -> `python source-contract run passed: 481 tests`; focused Rust checks passed for update package post-open recheck and local quarantine restore action/cleanup tests. The native quarantine linked-parent runtime fixture remains Unix-only in this Windows shell.

## 2026-07-05 continuation checkpoint 1562

- Refreshed current-host verification evidence after Flutter/Dart/Rust installation and the checkpoint 1561 source-contract cleanup.
- `apps\zentor_client` passes `flutter analyze` with `No issues found` and `flutter test --reporter compact` with `414 passed`.
- Rust workspace verification passes `cargo test --workspace --no-run` and `cargo test --workspace -- --test-threads=1` with existing warnings only.
- Updated `STATUS.md` and recorded evidence in `.workflow\ultracode\avorax-hardening\results\1562-current-host-verification-refresh.md`.
- Remaining release blockers are host/artifact prerequisites: Windows symlink support/Developer Mode or equivalent build host, Visual Studio Desktop C++ components, Android SDK/Gradle lockfile generation, Flutter Windows `Avorax.exe`, and MSI/setup installer staging.

## 2026-07-05 continuation checkpoint 1563

- Refreshed focused Flutter runtime fixture evidence for local-core IPC parser boundaries and engine-diagnostic UI policy rows that still had stale `Flutter/Dart runtime blocked` wording.
- Updated `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1563-flutter-ipc-ui-runtime-fixtures.md`.
- Verification passed locally: `flutter test test\local_core_ipc_diagnostics_test.dart --reporter compact` -> `42 passed`; `flutter test test\app_visual_policy_test.dart --reporter compact` -> `57 passed`.
- Remaining gaps are installed local-core IPC E2E and Windows visual/screenshot E2E, plus the previously documented release-host/artifact prerequisites.

## 2026-07-05 continuation checkpoint 1564

- Added a Flutter regression for duplicate scan cancellation while cancel IPC is still pending, proving the second cancel request is visibly ignored and local-core cancel IPC is not called twice.
- Refreshed audit matrix/blocker entries for scan-start concurrency, empty scan targets, and scan-cancel concurrency with focused `offline_scan_test.dart` runtime evidence.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1564-flutter-scan-cancel-concurrency.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> `0 changed` after adding Git to PATH; `flutter test test\offline_scan_test.dart --reporter compact` -> `85 passed`; full `flutter test --reporter compact` -> `415 passed`; `flutter analyze` -> `No issues found`; Python source-contracts -> `481 tests`.
- Remaining gaps are installed Windows scan-control UI/E2E verification and the scheduled quick-scan timer-fire runtime fixture.

## 2026-07-05 continuation checkpoint 1565

- Added an injectable scheduled quick-scan timer factory that defaults to `Timer.periodic`, so scheduling remains production-equivalent while timer-fire behavior is deterministic in tests.
- Added a Flutter runtime fixture proving a scheduled timer fire launches a detect-only quick scan and records `scheduled_quick_scan_started` evidence.
- Refreshed audit matrix/blocker entries for the scheduled quick-scan timer boundary.
- Updated `apps\zentor_client\lib\app\app_state.dart`, `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1565-flutter-scheduled-quick-scan-timer.md`.
- Verification passed locally: `dart format --set-exit-if-changed lib\app\app_state.dart test\offline_scan_test.dart` -> `0 changed`; `flutter test test\offline_scan_test.dart --reporter compact` -> `86 passed`; full `flutter test --reporter compact` -> `416 passed`; `flutter analyze` -> `No issues found`; Python source-contracts -> `481 tests`; serial `py_compile` passed.
- Remaining gap is installed app-lifetime scheduling UI/E2E verification.

## 2026-07-05 continuation checkpoint 1566

- Added a `ZentorShell` widget runtime fixture proving notification summaries normalize control/NUL details into one-line visible UI text before display.
- Refreshed audit matrix/blocker entries for the shell-notification portion of the Flutter UI diagnostic boundary while keeping controller/update/config/settings/device diagnostic paths partial.
- Updated `apps\zentor_client\test\navigation_accessibility_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1566-flutter-shell-notification-normalization.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\navigation_accessibility_test.dart` -> `0 changed`; `flutter test test\navigation_accessibility_test.dart --reporter compact` -> `4 passed`; full `flutter test --reporter compact` -> `417 passed`; `flutter analyze` -> `No issues found`; Python source-contracts -> `481 tests`.

## 2026-07-05 continuation checkpoint 1567

- Added a startup controller runtime fixture proving malformed persisted config surfaces a visible recovery error and `configuration_recovered` warning event.
- Refreshed audit matrix/blocker entries for config-recovery diagnostic runtime evidence while keeping detached-future startup failure paths partial.
- Updated `apps\zentor_client\test\config_validation_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1567-flutter-startup-config-recovery.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\config_validation_test.dart` -> `0 changed`; `flutter test test\config_validation_test.dart --reporter compact` -> `21 passed`; full `flutter test --reporter compact` -> `418 passed`; `flutter analyze` -> `No issues found`; Python source-contracts -> `481 tests`.

## 2026-07-05 continuation checkpoint 1568

- Added a Flutter update-controller runtime fixture proving control/NUL-rich update-check failures are normalized before visible `updateError`, `errorMessage`, and `update_check_failed` event details.
- Refreshed audit matrix/blocker entries for update-check diagnostic runtime evidence while keeping deeper download/package/probe/cleanup update fixtures partial.
- Updated `apps\zentor_client\test\update_controller_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1568-flutter-update-diagnostic-normalization.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_controller_test.dart` -> `0 changed`; `flutter test test\update_controller_test.dart --reporter compact` -> `28 passed`; full `flutter test --reporter compact` -> `419 passed`; `flutter analyze` -> `No issues found`; Python source-contracts -> `481 tests`.

## 2026-07-05 continuation checkpoint 1569

- Added a Device-screen widget runtime fixture proving a control/NUL-rich `deviceSummaryProvider` failure renders as normalized visible UI text instead of raw exception text.
- Refreshed audit matrix/blocker entries for the Device side of the Settings/Device diagnostic boundary while keeping Settings export-log failure fixtures partial.
- Updated `apps\zentor_client\test\settings_accessibility_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1569-flutter-device-diagnostic-normalization.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\settings_accessibility_test.dart` -> `0 changed`; `flutter test test\settings_accessibility_test.dart --reporter compact` -> `2 passed`; full `flutter test --reporter compact` -> `420 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1570

- Added a controller runtime fixture proving control/NUL-rich Settings log-export failures are normalized before visible `errorMessage` and `logs_export_failed` audit details.
- Refreshed audit matrix/blocker entries for the Settings log-export side of the Flutter UI diagnostic boundary while keeping broader controller/update diagnostic fixture coverage partial.
- Updated `apps\zentor_client\test\local_event_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1570-flutter-settings-export-diagnostic-normalization.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\local_event_test.dart` -> `0 changed`; `flutter test test\local_event_test.dart --reporter compact` -> `35 passed`; full `flutter test --reporter compact` -> `421 passed`; `flutter analyze` reported `No issues found`.

## 2026-07-05 continuation checkpoint 1571

- Added a controller runtime fixture proving control/NUL-rich update download failures are normalized before visible `updateError`/`errorMessage` and `update_install_failed` audit details.
- Verified failed downloads do not call verify/install and do not leave an untrusted `localPackagePath` in `updateInfo`.
- Refreshed audit matrix/blocker entries for the update download failure side of the Flutter UI diagnostic boundary while keeping deeper update package/probe/cleanup fixtures partial.
- Updated `apps\zentor_client\test\update_controller_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1571-flutter-update-download-diagnostic-normalization.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_controller_test.dart` -> `0 changed`; `flutter test test\update_controller_test.dart --reporter compact` -> `29 passed`; full `flutter test --reporter compact` -> `422 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`.

## 2026-07-05 continuation checkpoint 1572

- Added a controller runtime fixture proving verify, install, and rollback update exceptions with control/NUL text are normalized before visible update UI state and failure-event details.
- Extended the fake update service with per-phase failure messages so existing behavior tests keep their default diagnostics while the new regression exercises hostile diagnostic text.
- Refreshed audit matrix/blocker entries for update action failure diagnostics while keeping deeper package/probe/cleanup fixtures partial.
- Updated `apps\zentor_client\test\update_controller_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1572-flutter-update-action-diagnostic-normalization.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_controller_test.dart` -> `0 changed`; `flutter test test\update_controller_test.dart --reporter compact` -> `30 passed`; full `flutter test --reporter compact` -> `423 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`.

## 2026-07-05 continuation checkpoint 1573

- Added a real `ZentorUpdateService.downloadUpdatePackage` runtime fixture for combined download/cleanup diagnostics.
- The fixture reserves the service temp package file, replaces it with a directory during a mock download failure, and verifies the resulting combined error keeps bounded normalized original and cleanup diagnostics instead of swallowing cleanup failure.
- Refreshed audit matrix/blocker entries for update cleanup diagnostic evidence while keeping deeper update package/probe fixtures partial.
- Updated `apps\zentor_client\test\update_service_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1573-flutter-update-cleanup-diagnostic-normalization.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `84 passed`; full `flutter test --reporter compact` -> `424 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1574

- Added a real `ZentorUpdateService.verifyDownloadedPackage` runtime fixture proving non-file cached package paths fail before updater launch with bounded probe diagnostics.
- The fixture creates a directory named like a cached `.aup` inside the managed update cache and verifies the probe diagnostic is visible and contains no raw control text.
- Refreshed audit matrix/blocker entries for update package probe evidence while keeping installed signed package apply/rollback fixtures partial.
- Updated `apps\zentor_client\test\update_service_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1574-flutter-update-package-probe-diagnostic.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `85 passed`; full `flutter test --reporter compact` -> `425 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1575

- Added a Flutter controller runtime fixture proving ransomware guard path-list updates reject control/NUL characters before local-core policy writes and before persisted config success.
- Extended the config-validation fake local-core client with `ransomwareGuardCalls` so the regression can prove the invalid path does not cross the privilege/config boundary.
- Refreshed audit matrix/blocker entries for the Flutter app configuration repository, removing the stale general Flutter/Dart runtime blocker for this path-list boundary while keeping broader installed Settings UI coverage partial.
- Updated `apps\zentor_client\test\config_validation_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1575-flutter-config-path-list-runtime.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\config_validation_test.dart` -> `0 changed`; `flutter test test\config_validation_test.dart --reporter compact` -> `22 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `426 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed. A first broad `flutter test` attempt from the repository root failed with `Test directory "test" not found` and was rerun from the correct Flutter package directory.

## 2026-07-05 continuation checkpoint 1576

- Added a Flutter controller runtime fixture proving duplicate detection feedback is blocked while local-core label IPC is pending.
- Extended the offline-scan fake local-core client with a pending label-detection completer so the regression can assert `detectionFeedbackInFlight`, busy event category/severity, no second `labelDetection` call, and guard release after the first IPC completes.
- Refreshed audit matrix/blocker entries for false-positive/malicious feedback single-flight and busy-state runtime evidence while keeping installed Scan UI click/layout E2E partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1576-flutter-detection-feedback-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> formatted 1 file; `flutter test test\offline_scan_test.dart --reporter compact` -> `87 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `427 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed. The first Python source-contract/py_compile attempt was launched from `apps\zentor_client` and failed to find repo-root `tools\`/`tests\`; it was rerun successfully from the repository root.

## 2026-07-05 continuation checkpoint 1577

- Added a Flutter controller runtime fixture proving pending Add to allowlist IPC blocks overlapping allowlist remove.
- Extended the offline-scan fake local-core client with a pending add-allowlist completer so the regression can assert `allowlistActionInFlight`, busy event category/severity, no remove IPC, and guard release after the add completes.
- Refreshed audit matrix/blocker entries for user allowlist mutation single-flight and busy-state runtime evidence while keeping installed UI click/layout E2E and native/local trust-store fixtures partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1577-flutter-allowlist-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> formatted 1 file; `flutter test test\offline_scan_test.dart --reporter compact` -> `88 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `428 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1578

- Added a Flutter controller runtime fixture proving pending quarantine restore IPC blocks overlapping quarantine delete.
- Extended the offline-scan fake local-core client with a pending restore-quarantine completer so the regression can assert `quarantineActionInFlight`, busy event category/severity, no delete IPC, and guard release after the restore completes.
- Refreshed audit matrix/blocker entries for local quarantine mutation single-flight and busy-state runtime evidence while keeping installed Quarantine UI click/layout E2E and native/local restore/delete fixtures partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1578-flutter-quarantine-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> formatted 1 file; `flutter test test\offline_scan_test.dart --reporter compact` -> `89 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `429 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1579

- Added a Flutter controller runtime fixture proving pending Guard-mode settings IPC blocks overlapping ransomware-guard policy writes.
- Extended the offline-scan fake local-core client with a pending Guard-mode completer so the regression can assert `securitySettingsActionInFlight`, busy event category/severity, no ransomware-guard IPC, and guard release after the mode write completes.
- Refreshed audit matrix/blocker entries for security-settings single-flight and busy-state runtime evidence while keeping installed Settings UI click/layout E2E partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1579-flutter-security-settings-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> formatted 1 file; `flutter test test\offline_scan_test.dart --reporter compact` -> `90 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `430 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1580

- Added a Flutter controller runtime fixture proving pending developer-cloud override follow-up health-check work blocks duplicate override saves.
- Added a fake API client with a pending health-check completer so the regression can assert `developerCloudOverrideInFlight`, busy event category/severity, first-endpoint preservation, one health call, and guard release after the health check completes.
- Refreshed audit matrix/blocker entries for developer cloud override single-flight and busy-state runtime evidence while keeping installed Settings UI click/layout E2E and broader cloud smoke coverage partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1580-flutter-developer-cloud-override-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> `0 changed`; `flutter test test\offline_scan_test.dart --reporter compact` -> `91 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `431 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1581

- Added a Flutter controller runtime fixture proving pending configuration-reset protection-stop work blocks duplicate reset attempts.
- Reused the pending Guard-mode fake local-core boundary so the regression can assert `configurationResetInFlight`, settings/warning busy evidence, one Guard-mode IPC, no overlapping watcher stop while the first reset is pending, and guard release after reset completes.
- Refreshed audit matrix/blocker entries for configuration reset side-effect cleanup, single-flight, and busy-state runtime evidence while keeping installed Settings UI click/layout E2E partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1581-flutter-configuration-reset-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> formatted 1 file; `flutter test test\offline_scan_test.dart --reporter compact` -> `92 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `432 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1582

- Added a Flutter controller runtime fixture proving pending onboarding config persistence blocks duplicate completion saves.
- Added a pending-save config repository fake so the regression can assert `onboardingCompletionInFlight`, app/warning busy evidence, one repository `save`, no premature `onboardingComplete` state, and guard release after the first save completes.
- Refreshed audit matrix/blocker entries for onboarding completion single-flight and busy-state runtime evidence while keeping installed Onboarding UI click/layout E2E partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1582-flutter-onboarding-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> formatted 1 file; `flutter test test\offline_scan_test.dart --reporter compact` -> `93 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `433 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1583

- Added a Flutter controller runtime fixture proving pending Start Core Service local-core IPC blocks overlapping service-recovery actions.
- Extended the offline-scan fake local-core client with a pending Start Core Service completer so the regression can assert `serviceActionInFlight`, protection/warning busy evidence, one start request, no repair/report IPC, and guard release after the first service request completes.
- Refreshed audit matrix/blocker entries for service-recovery single-flight and busy-state runtime evidence while keeping installed Scan diagnostics UI click/layout E2E partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1583-flutter-service-recovery-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> `0 changed`; `flutter test test\offline_scan_test.dart --reporter compact` -> `94 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `434 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1584

- Added a Flutter controller runtime fixture proving pending threat-ignore audit writes block duplicate ignore requests.
- Added a pending-event local-event repository fake so the regression can assert `threatIgnoreActionInFlight`, scan/warning busy evidence, one `threat_ignored` event write, one busy event, no premature hidden detection, and guard release after the first audited ignore completes.
- Refreshed audit matrix/blocker entries for threat-ignore single-flight, busy-state, and selected event severity runtime evidence while keeping installed Scan result UI click/layout E2E partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1584-flutter-threat-ignore-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> formatted 1 file; `flutter test test\offline_scan_test.dart --reporter compact` -> `95 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `435 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1585

- Added a Flutter controller runtime fixture proving pending protected-app build-hash work blocks overlapping protected-app selection.
- Extended the offline-scan fake hash service with a pending hash completer and call counter so the regression can assert `protectedAppActionInFlight`, protection/warning busy evidence, one hash call, no selected-app replacement during pending hash work, and guard release after the first hash completes.
- Refreshed audit matrix/blocker entries for protected-app mutation single-flight and busy-state runtime evidence while keeping installed Protected Apps UI click/layout E2E partial.
- Updated `apps\zentor_client\test\offline_scan_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1585-flutter-protected-app-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\offline_scan_test.dart` -> formatted 1 file; `flutter test test\offline_scan_test.dart --reporter compact` -> `96 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `436 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1586

- Added a Flutter controller runtime fixture proving pending manual update checks block overlapping install work before download, verify, or install actions start.
- Extended the update-service fake with a pending check completer so the regression can assert `updateOperationInFlight`, update/warning busy evidence, no package-action calls, and guard release after the first check completes.
- Refreshed audit matrix/blocker entries for update action single-flight runtime evidence while keeping installed Home/Settings/Updates click/layout E2E partial.
- Updated `apps\zentor_client\test\update_controller_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1586-flutter-update-action-single-flight.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_controller_test.dart` -> formatted 1 file; `flutter test test\update_controller_test.dart --reporter compact` -> `31 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `437 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1587

- Added a Flutter controller runtime fixture proving update event metadata is explicit for check, availability, install confirmation, install progress, rollback progress, install failure, and check failure outcomes.
- Added `_expectUpdateEventMetadata` so regressions assert category `update` and the expected `info`, `warning`, or `error` severity instead of only checking event type names.
- Refreshed audit matrix/blocker entries for update event severity/category runtime evidence while keeping installed Home/Settings/Updates event-flow E2E partial.
- Updated `apps\zentor_client\test\update_controller_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1587-flutter-update-event-metadata.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_controller_test.dart` -> formatted 1 file; `flutter test test\update_controller_test.dart --reporter compact` -> `32 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `438 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1588

- Added Flutter widget runtime fixtures for update rollback support labels and action enablement.
- Covered null, false, and true rollback metadata so status rows show `Unknown`, `Unavailable`, or `Available`, and the Updates rollback button stays disabled unless rollback support is explicitly true.
- Refreshed audit matrix/blocker entries for rollback support label runtime evidence while keeping installed Settings/Updates click-layout E2E and real signed rollback partial.
- Updated `apps\zentor_client\test\update_ui_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1588-flutter-update-rollback-ui.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_ui_test.dart` -> formatted 1 file; `flutter test test\update_ui_test.dart --reporter compact` -> `3 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `441 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1589

- Added Flutter runtime fixtures for selected-file hash service type and size guards.
- Covered directory rejection and oversized selected-file rejection before streaming/progress callbacks, using a sparse temp file instead of writing large fixture contents.
- Refreshed audit matrix/blocker entries for selected-file hash size/type runtime evidence while keeping symlink/junction and replacement-race filesystem fixtures partial.
- Updated `apps\zentor_client\test\hash_service_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1589-flutter-hash-service-size-type.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\hash_service_test.dart` -> formatted 1 file; `flutter test test\hash_service_test.dart --reporter compact` -> `4 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `443 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1590

- Added a Flutter runtime fixture for oversized local `file:` update feeds.
- Verified local update feeds fail through the streaming byte limit before JSON parsing or HTTP fallback, using a benign temp file of `maxUpdateFeedBytes + 1` bytes.
- Refreshed audit matrix/blocker entries for local update-feed streaming bounds while keeping growing-file race fixtures partial.
- Updated `apps\zentor_client\test\update_service_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1590-flutter-local-update-feed-streaming.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `86 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `444 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1591

- Added Flutter runtime fixtures for control/NUL text in update `Content-Length` headers.
- Covered remote update-feed and update-package header paths so invalid raw header text fails before JSON parsing or package writes, with normalized diagnostics.
- Refreshed audit matrix/blocker entries for Content-Length raw-header runtime evidence while keeping GitHub releases metadata header fixtures partial.
- Updated `apps\zentor_client\test\update_service_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, and `.workflow\ultracode\avorax-hardening\results\1591-flutter-update-content-length-headers.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> formatted 1 file; `flutter test test\update_service_test.dart --reporter compact` -> `88 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `446 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1592

- Added a Flutter runtime fixture for oversized remote update feeds without `Content-Length`.
- Verified the update checker consumes a streamed response through bounded metadata collection and fails at the update metadata byte limit before JSON parsing.
- Refreshed audit matrix/blocker entries for remote update metadata streamed-size runtime evidence while keeping GitHub release metadata no-Content-Length/oversized and stalled stream fixtures partial.
- Updated `apps\zentor_client\test\update_service_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1592-flutter-remote-update-feed-streaming.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `89 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `447 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1593

- Added a Flutter runtime fixture for oversized GitHub release fallback metadata without `Content-Length`.
- Verified the GitHub fallback resolver streams the API metadata response through the GitHub metadata byte limit and fails before JSON parsing or fallback feed asset selection.
- Refreshed audit matrix/blocker entries for GitHub release metadata streamed-size runtime evidence while keeping stalled stream fixtures partial.
- Updated `apps\zentor_client\test\update_service_test.dart`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1593-flutter-github-metadata-streaming.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `90 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `448 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1594

- Added positive validated request/read timeout injection to `ZentorUpdateService` while preserving the 30-second production defaults.
- Converted stalled update network request/read timeout exceptions into labeled diagnostics such as `Update feed request timed out` and `Update feed response timed out`.
- Added Flutter runtime fixtures for stalled update-feed send and stalled response stream paths using millisecond test-only timeouts and benign in-memory streams.
- Updated Python source contracts so timeout evidence now covers production defaults, validated injected overrides, feed/GitHub/redirect/package timeout use, and labeled timeout conversion.
- Refreshed audit matrix/blocker entries for update network-timeout runtime evidence while keeping GitHub metadata request/read, redirect-body, and package-download stalled fixtures partial.
- Updated `apps\zentor_client\lib\core\updates\update_service.dart`, `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1594-flutter-update-timeout-diagnostics.md`.
- Verification passed locally: `dart format --set-exit-if-changed lib\core\updates\update_service.dart test\update_service_test.dart` -> `0 changed` after formatting; `flutter test test\update_service_test.dart --reporter compact` -> `92 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `450 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1595

- Added Flutter runtime fixtures for stalled GitHub release metadata request and response stream paths during the update-feed fallback flow.
- Verified a hung `api.github.com` release metadata send fails with `GitHub releases request timed out` and a hung metadata stream fails with `GitHub releases response timed out`.
- Fixed response-timeout labeling so labels already ending in `response` do not produce duplicate `response response timed out` diagnostics.
- Updated Python source contracts so GitHub timeout fixture evidence and label-aware response timeout text are pinned.
- Refreshed audit matrix/blocker entries for GitHub metadata timeout runtime evidence while keeping redirect-body and package-download stalled fixtures partial.
- Updated `apps\zentor_client\lib\core\updates\update_service.dart`, `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1595-flutter-github-metadata-timeouts.md`.
- Verification passed locally: `dart format --set-exit-if-changed lib\core\updates\update_service.dart test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `94 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `452 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1596

- Added a Flutter runtime fixture for stalled redirect response bodies in the update-feed GitHub redirect chain.
- Verified the updater drains bounded redirect bodies with the read timeout before following `Location`, so a stalled 302 body fails with `Update feed redirect response timed out` and does not request the redirected URL.
- Updated Python source contracts so redirect-body timeout fixture evidence is pinned.
- Refreshed audit matrix/blocker entries for redirect-body timeout runtime evidence while keeping package-download stalled fixtures partial.
- Updated `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1596-flutter-redirect-body-timeout.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `95 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `453 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1597

- Added a Flutter runtime fixture for stalled remote `.aup` package download streams.
- Verified `downloadUpdatePackage` writes remote package bytes through the reserved-file stream timeout and fails with `downloaded update package download timed out` before package hashing or cache activation.
- Updated Python source contracts so package-download timeout fixture evidence is pinned.
- Refreshed audit matrix/blocker entries for update network-timeout fixture coverage, leaving installed Windows update-flow E2E as the remaining limitation for this cluster.
- Updated `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1597-flutter-package-download-timeout.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> formatted 1 file; `flutter test test\update_service_test.dart --reporter compact` -> `96 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `454 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1598

- Added a Flutter runtime fixture for NUL-bearing GitHub releases metadata `Content-Length` headers during the update-feed fallback flow.
- Verified the updater rejects `GitHub releases Content-Length` before JSON parsing or fallback feed asset selection and normalizes diagnostics without raw NUL text.
- Updated Python source contracts so GitHub metadata Content-Length fixture evidence is pinned.
- Refreshed audit matrix/blocker entries for update Content-Length raw-header fixture coverage, leaving installed Windows update-flow E2E as the remaining limitation.
- Updated `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1598-flutter-github-content-length-header.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `97 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `455 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1599

- Added a Flutter runtime fixture for NUL-bearing GitHub release fallback `browser_download_url` values.
- Verified fallback metadata rejects the GitHub feed asset URL before URI parsing and normalizes visible diagnostics without raw NUL text.
- Updated Python source contracts so the GitHub fallback URL control-character fixture is pinned to the update URI text guard.
- Refreshed audit matrix/blocker entries for update URI text control-character coverage, leaving configured feed URL and feed package URL runtime fixtures partial.
- Updated `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1599-flutter-github-url-control.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `98 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `456 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1600

- Added Flutter runtime fixtures for NUL-bearing configured update feed URLs and feed package `package_url` values.
- Verified configured update feed URLs fail before any HTTP request and feed package URLs fail before URI parsing or package fetch, with normalized diagnostics that do not retain raw NUL text.
- Updated Python source contracts so all three update URI text guard fixture paths are pinned: configured feed URL, feed package URL, and GitHub fallback `browser_download_url`.
- Refreshed audit matrix/blocker entries for update URI text control-character coverage, leaving installed Windows update-flow E2E as the remaining limitation.
- Updated `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1600-flutter-update-url-control.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `100 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `458 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1601

- Added Flutter runtime fixtures for NUL-bearing required update metadata (`product`, `latest_version`, and `package_sha256`), optional update metadata (`channel`, `minimum_supported_version`, and `published_at`), and release notes free-text handling.
- Verified required and optional metadata values fail before product comparison, version/date parsing, or SHA validation, with normalized diagnostics that do not retain raw NUL text.
- Verified release notes still accept normal multiline/tab text while rejecting NUL-bearing free text through the unsupported-control guard.
- Updated Python source contracts so the new metadata and release-notes runtime fixtures are pinned.
- Refreshed audit matrix/blocker entries for update metadata and release-notes control-character coverage, leaving broader GitHub required-field fixtures and installed Windows update-flow E2E as remaining limitations where applicable.
- Updated `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1601-flutter-update-metadata-control.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `103 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `461 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1602

- Added Flutter runtime fixtures for NUL-bearing GitHub update redirect `Location` headers and malformed `release-assets.githubusercontent.com` redirect paths.
- Verified redirect `Location` control text is rejected before URI resolution and before following the redirect, with normalized diagnostics that do not retain raw NUL text.
- Verified malformed release-assets redirect paths are rejected before a second network request follows them.
- Updated Python source contracts so the new redirect guard fixtures are pinned.
- Refreshed audit matrix/blocker entries for GitHub redirect Location and release-assets path-shape coverage, while leaving unsafe decoded GitHub asset-name fixtures and installed Windows update-flow E2E as remaining limitations where applicable.
- Updated `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1602-flutter-github-redirect-guards.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `105 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `463 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1603

- Added a Flutter runtime fixture for unsafe decoded GitHub fallback feed asset names.
- Verified a GitHub release metadata asset whose `browser_download_url` decodes to `nested\update-feed.json` is not trusted as `update-feed.json` and does not trigger a feed download.
- Updated Python source contracts so the decoded asset-name guard fixture is pinned.
- Refreshed audit matrix/blocker entries for GitHub update asset-name boundary coverage, leaving installed Windows update-flow E2E as the remaining limitation.
- Updated `apps\zentor_client\test\update_service_test.dart`, `tests\test_custom_driver_contract.py`, `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1603-flutter-github-asset-name-boundary.md`.
- Verification passed locally: `dart format --set-exit-if-changed test\update_service_test.dart` -> `0 changed`; `flutter test test\update_service_test.dart --reporter compact` -> `106 passed`; full `flutter test --reporter compact` from `apps\zentor_client` -> `464 passed`; `flutter analyze` reported `No issues found`; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-07-05 continuation checkpoint 1611

- Re-ran previously Cargo-blocked local-core publisher exact-match and passthrough exact-root fixtures.
- Verified exact canonical publisher matching, malformed publisher config rejection, lookalike publisher rejection, trusted-publisher allow, strong-malware override, exact passthrough root allow, lookalike path rejection, and unknown unsigned Lockdown block behavior.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1611-rust-local-core-trust-exact-match-runtime.md`.
- Verification passed locally: ten focused Cargo fixtures passed with `1 passed; 0 failed`; `rustfmt --check core\zentor_local_core\src\main.rs core\zentor_local_core\src\app_control\publisher_trust.rs core\zentor_local_core\src\app_control\trust_store.rs core\zentor_local_core\src\app_control\policy.rs` passed.

## 2026-07-05 continuation checkpoint 1610

- Re-ran previously Cargo-blocked local-core scan-target metadata path-safety fixtures that execute on this Windows host.
- Verified non-following target metadata wiring, local-AI non-file target rejection, and native per-file scan-error reporting as skipped scan errors.
- Documented the Unix-only symlink fixture as technically limited on this Windows host because `local_core_scan_target_rejects_symbolic_links` is `#[cfg(unix)]` and reported `0 tests`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1610-rust-local-scan-target-metadata-path-safety.md`.
- Verification passed locally: `scan_and_threat_paths_use_non_following_target_metadata`, `local_ai_threat_builder_rejects_non_file_targets`, `scan_paths_reports_native_file_errors`, `full_scan_handles_inaccessible_or_missing_roots_as_skipped`, `scan_paths_does_not_treat_metadata_failures_as_zero_byte_scans`, and `scan_paths_does_not_count_failed_native_inspections_as_scanned` each passed with `1 passed; 0 failed`; `rustfmt --check core\zentor_local_core\src\main.rs` passed.

## 2026-07-05 continuation checkpoint 1609

- Re-ran previously Cargo-blocked local-core feature/hash bounded-I/O fixtures.
- Verified static feature extraction uses a bounded sample, directories are rejected, SHA-256 evidence streams full-file content with size bounds, and signature threat construction fails closed without hash evidence.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs\audit\engine-control-matrix.md`, and `.workflow\ultracode\avorax-hardening\results\1609-rust-local-core-feature-hash-bounded-io.md`.
- Verification passed locally: `static_feature_extraction_uses_bounded_sample`, `static_feature_extraction_rejects_directories`, `local_core_sha256_for_file_streams_full_file`, `local_core_sha256_for_file_is_size_bounded`, and `signature_threat_builder_rejects_missing_hash` each passed with `1 passed; 0 failed`; `rustfmt --check core\zentor_local_core\src\main.rs core\zentor_local_core\src\ai\feature_extractor.rs` passed.

## 2026-07-05 continuation checkpoint 1608

- Re-ran previously Cargo-blocked local-core progress serialization fixtures.
- Verified normal scan progress emits structured progress JSON and serialization failure handling emits a structured `type:error` line instead of a blank line.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1608-rust-local-core-progress-serialization-runtime.md`.
- Verification passed locally: `cargo test --manifest-path core\zentor_local_core\Cargo.toml progress_event_line -- --test-threads=1` -> `1 passed`; `cargo test --manifest-path core\zentor_local_core\Cargo.toml progress_event_serialization_errors_are_not_blank_lines -- --test-threads=1` -> `1 passed`; `rustfmt --check core\zentor_local_core\src\main.rs` passed.

## 2026-07-05 continuation checkpoint 1607

- Re-ran previously Cargo-blocked local-core IPC text-bound fixtures.
- Verified oversized action mode, threat name, quarantine ID, user note, NUL guard mode, and excessive ransomware protected-root list inputs are rejected before parsing, persistence, config writes, or action handlers use them.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1607-rust-local-core-ipc-text-bounds-runtime.md`.
- Verification passed locally: each focused Cargo fixture passed with `1 passed; 0 failed`, and the compact rerun ended with `all focused local-core IPC text-bound tests passed`.

## 2026-07-05 continuation checkpoint 1606

- Re-ran previously Cargo-blocked local-core IPC path-bound and Guard Service IPC field-bound fixtures.
- Verified local-core rejects oversized/NUL IPC paths and excessive watch path lists before handlers use them.
- Verified Guard rejects oversized/NUL process paths, oversized driver scan-request paths, excessive known-bad hash lists, and caller-supplied trusted/known-good/normalized driver metadata.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1606-rust-ipc-path-field-bounds-runtime.md`.
- Verification passed locally: local-core `ipc_path` -> `3 passed`, local-core `start_watch_rejects_excessive_ipc_paths` -> `1 passed`, Guard `rejects_oversized` -> `11 passed`, Guard `rejects_nul` -> `1 passed`, Guard `command_known_bad_hashes_reject_excessive_entries` -> `1 passed`, Guard `external_driver_scan_ignores_caller_supplied` -> `3 passed`.

## 2026-07-05 continuation checkpoint 1605

- Re-ran previously Cargo-blocked Rust IPC command-size and bounded-line-reader fixtures for local-core and Guard Service now that Cargo is available.
- Verified oversized stdin command JSON is rejected before parsing and oversized command lines are rejected before full-line allocation.
- Updated `STATUS.md`, `docs\audit\engine-control-matrix.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1605-rust-ipc-bounded-command-runtime.md`.
- Verification passed locally: `cargo test --manifest-path core\zentor_local_core\Cargo.toml oversized_json_before -- --test-threads=1` -> `2 passed`; `cargo test --manifest-path core\zentor_guard_service\Cargo.toml oversized_json_before -- --test-threads=1` -> `2 passed`; `cargo test --manifest-path core\zentor_local_core\Cargo.toml core_command_reader -- --test-threads=1` -> `1 passed`; `cargo test --manifest-path core\zentor_guard_service\Cargo.toml guard_command_reader -- --test-threads=1` -> `1 passed`.

## 2026-07-05 continuation checkpoint 1604

- Re-ran previously Cargo-blocked signed `.aup` archive guard fixtures now that the Rust toolchain is available.
- Verified archive allowlisting, restricted payload directory-entry rejection, archive entry-name control-character rejection, and manifest/signature cardinality fixtures in `core\avorax_update_service`.
- Refreshed audit matrix/blocker entries so those controls are recorded as runtime-verified instead of Cargo-blocked.
- Updated `docs\audit\engine-control-matrix.md`, `docs\audit\known-blockers.md`, `STATUS.md`, `RUN_LOG.md`, and `.workflow\ultracode\avorax-hardening\results\1604-rust-update-package-archive-guards.md`.
- Verification passed locally: `cargo test --manifest-path core\avorax_update_service\Cargo.toml read_manifest -- --test-threads=1` -> `10 passed`; `cargo test --manifest-path core\avorax_update_service\Cargo.toml package_archive_entries_are_allowlisted_before_archive_reads -- --test-threads=1` -> `1 passed`; `rustfmt --check core\avorax_update_service\src\update_package.rs` passed; Python source-contracts passed with `481 tests`; `py_compile` passed.

## 2026-06-26 continuation checkpoint 1191

- Hardened `.github/workflows/release-windows.yml` so the dependency-evidence upload fails with `if-no-files-found: error` when `dist\dependency-evidence\dependency_evidence.json` is missing.
- Added a Python source contract that prevents the Windows release workflow from reverting the dependency-evidence artifact upload to `ignore`.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md` with the release-evidence contract.
- Verification passed locally: Python source contracts (`217 tests`), branding gate, product-copy gate, and no-malware binary gate. Live GitHub Actions execution remains unverified in this shell.

## 2026-06-26 continuation checkpoint 1192

- Replaced local app-control `ProtectionMode::Off => unreachable!()` routes with an explicit shared `application_control_off_result()` allow/no-monitor decision.
- Added Rust source tests in `core\zentor_local_core\src\app_control\policy.rs` and a Python source contract that prevents Off-mode panic routes from returning.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1193

- Wired `ApplicationControlPolicy::new(mode)` to construct `ScriptPolicy::new(mode)` instead of leaving the script subpolicy at its Balanced default.
- Added Rust regressions for constructor mode propagation and Lockdown high-risk script blocking, plus a Python source contract to keep the constructor wiring in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1194

- Hardened local ransomware guard path matching so protected-root filtering and trusted-process allowlist checks collapse `.` and `..` segments before comparing paths.
- Added Rust regressions for traversal escaping a protected root and lexically equivalent trusted-process paths, plus a Python source contract to keep the policy-matching normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1195

- Hardened local allowlist path normalization so path validation, exact path matching, and folder allowlist matching collapse `.` and `..` segments before trust decisions.
- Added Rust regressions for traversal escaping a folder allowlist and traversal-derived unsafe root validation, plus a Python source contract to keep the allowlist normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1196

- Hardened native allowlist path normalization so native trust validation and path matching collapse `.` and `..` segments before broad-root checks and descendant comparisons.
- Added Rust regressions for traversal escaping a native allowlist path and traversal-derived unsafe root validation, plus a Python source contract to keep the native allowlist normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1197

- Hardened local app-control passthrough path normalization so product, quarantine, and system root checks collapse `.` and `..` segments before trusted descendant decisions.
- Added Rust regressions for quarantine-root parent traversal escape attempts and traversal-derived dangerous allowlist roots, plus a Python source contract to keep the passthrough normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1198

- Hardened Guard driver IPC fail-open path normalization so system, product, and quarantine fail-open roots collapse `.` and `..` segments before trusted descendant decisions.
- Added a Rust regression for Lockdown fail-open root traversal escape attempts, plus a Python source contract to keep the Guard fail-open normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1199

- Hardened native Avorax/Zentor product trust path normalization so product install, quarantine, and repository roots collapse `.` and `..` segments before trusted descendant decisions.
- Added a Rust regression for native quarantine-root parent traversal escape attempts, plus a Python source contract to keep the native product-trust normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1200

- Hardened native Microsoft system-path trust normalization so Windows system roots collapse `.` and `..` segments before trusted descendant decisions.
- Added Rust regressions for `System32\.\...` staying trusted and `System32\..\...` escaping trust, plus a Python source contract to keep the Microsoft system-path normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1201

- Hardened Guard Service process-observer skip matching so Windows and Unix system-path skip checks collapse `.` and `..` segments before making component-aware root decisions.
- Added a Rust regression for traversal and fake-System32 process paths, plus a Python source contract to keep the process-skip normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1202

- Hardened local-core Windows System32 tool-root handling so `SystemRoot`/`WINDIR` values containing parent traversal are rejected before building checked `sc.exe` or `icacls.exe` launch paths.
- Added Rust source-marker regressions in `core\zentor_local_core\src\windows_tools.rs` and a Python source contract to keep the root normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1203

- Hardened Guard Service Windows System32 tool-root handling so `SystemRoot`/`WINDIR` values containing parent traversal are rejected before building checked `powershell.exe`, `taskkill.exe`, or `icacls.exe` launch paths.
- Extended the Guard external-command source-marker regression and added a Python source contract to keep the root normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1204

- Hardened Guard driver-health Windows System32 tool-root handling so `SystemRoot`/`WINDIR` values containing parent traversal are rejected before building checked `sc.exe`, `fltmc.exe`, `bcdedit.exe`, or Secure Boot PowerShell launch paths.
- Extended the driver-health system-command source-marker regression and added a Python source contract to keep the root normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1205

- Hardened native Microsoft Authenticode WindowsPowerShell tool-root handling so `SystemRoot`/`WINDIR` values containing parent traversal are rejected before signer evidence is collected.
- Extended the native Microsoft trust Authenticode probe source-marker regression and added a Python source contract to keep the root normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1206

- Hardened Avorax Update Service Windows service-control tool-root handling so `SystemRoot`/`WINDIR` values containing parent traversal are rejected before building a checked `sc.exe` launch path.
- Extended the update service-control source-marker regression and added a Python source contract to keep the root normalizer in place.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1207

- Hardened local-core engine asset, ProgramData, and shared-config environment root parsing so parent traversal is rejected before absolute-local path validation.
- Added a cross-platform Rust regression for `AVORAX_DATA_DIR=<temp>\..` plus a Python source contract covering the three local-core env-root entrypoints.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1208

- Hardened local quarantine runtime-root parsing so `AVORAX_QUARANTINE_DIR`, `ZENTOR_QUARANTINE_DIR`, ProgramData-derived roots, and HOME-derived roots reject NUL and parent traversal before `PathBuf` construction and absolute-local path validation.
- Added a cross-platform Rust regression for `AVORAX_QUARANTINE_DIR=<temp>\..` plus a Python source contract for the quarantine env-root validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1209

- Hardened native engine config parsing so `AVORAX_ENGINE_DIR`, `AVORAX_ENGINE_ROOT`, `AVORAX_QUARANTINE_DIR`, ProgramData-derived roots, and HOME-derived roots reject NUL and parent traversal before `PathBuf` construction and absolute-local path validation.
- Added cross-platform Rust regressions for parent-traversing native engine-root and quarantine-root overrides plus a Python source contract for the shared native env-root validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1210

- Hardened update-service ProgramData root parsing so `AVORAX_DATA_DIR`, ProgramData-derived roots, and HOME-derived roots reject NUL and parent traversal before `PathBuf` construction and absolute-local path validation.
- Added a cross-platform Rust regression for `AVORAX_DATA_DIR=<temp>\..` plus a Python source contract for the update-service env-root validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1211

- Hardened local app-control passthrough root parsing so SystemRoot/WINDIR, ProgramFiles, ProgramData, quarantine, and HOME-derived passthrough roots reject NUL and parent traversal before exact-root trust decisions.
- Added a cross-platform Rust regression for `AVORAX_QUARANTINE_DIR=<temp>\..` plus a Python source contract for the passthrough env-root validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1212

- Hardened native product/quarantine trust root parsing so ProgramFiles, ProgramData, quarantine, and HOME-derived native trust roots reject NUL and parent traversal before Avorax/Zentor local-artifact trust decisions.
- Added a cross-platform Rust regression for `AVORAX_QUARANTINE_DIR=<temp>\..` plus a Python source contract for the native product-trust env-root validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1213

- Hardened native scan environment roots so quick/full scan root variables reject parent traversal before scan-root selection.
- Added a Rust regression for parent-traversing native scan root values plus a Python source contract for the native scan env-root helper.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1214

- Hardened local startup migration root parsing so current/legacy ProgramData, LOCALAPPDATA, HOME, and direct data-root overrides reject NUL and parent traversal before data-copy and marker/log paths are built.
- Added a cross-platform Rust regression for `AVORAX_DATA_DIR=<temp>\..` plus a Python source contract for the migration env-root validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1215

- Hardened local AI training-label root parsing so `AVORAX_DATA_DIR`, ProgramData-derived roots, and HOME-derived roots reject NUL and parent traversal before feedback persistence paths are built.
- Added a cross-platform Rust regression for `AVORAX_DATA_DIR=<temp>\..` plus a Python source contract for the training-label env-root validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1216

- Hardened Guard Service config, event-log, and quarantine root parsing so configured roots reject parent traversal before `PathBuf` construction.
- Added Rust regressions for parent-traversing guard config, event-log, and quarantine root overrides plus Python source-contract coverage in the existing Guard env-root contracts.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1217

- Hardened local-core and Guard ClamAV compatibility configured scanner path parsing so explicit `ZENTOR_CLAMAV_CLAMSCAN` values reject NUL and parent traversal before executable `PathBuf` construction.
- Added Rust regressions for malformed configured scanner text plus a Python source contract covering both local-core and Guard ClamAV configured scanner validators.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1218

- Hardened local allowlist trust-store path parsing so `ZENTOR_ALLOWLIST_FILE` must be absolute, local, NUL-free, and parent-traversal-free before allowlist read/write paths are constructed.
- Added a Rust regression for unsafe allowlist env-store text and a Python source contract for the allowlist env-store validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1219

- Hardened local AI model and metadata environment override parsing so `ZENTOR_AI_MODEL` and `ZENTOR_AI_METADATA` reject NUL and parent traversal before model asset path validation.
- Added a Rust regression for unsafe AI asset env text plus a Python source contract for the local AI model env-path validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1220

- Hardened Guard driver IPC fail-open runtime-root candidate parsing so `SystemRoot`, `WINDIR`, ProgramData, ProgramFiles, quarantine, and HOME roots containing NUL or parent traversal are ignored instead of normalized into trusted fail-open roots.
- Added a Rust regression for parent-traversing fail-open environment roots plus a Python source contract for the fail-open env-root filter.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1221

- Hardened update-service CLI install-directory argument parsing so NUL-containing or parent-traversing text is rejected before `PathBuf` construction and absolute-local install-target validation.
- Added Rust regressions/source markers plus a Python source contract for update CLI install-directory text validation.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1222

- Hardened update package path validation so NUL-containing or parent-traversing `.aup` paths fail before package metadata, extension, manifest, hash, payload verification, or extraction reads.
- Added a Rust regression marker plus a Python source contract for the update package path text validator.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1223

- Hardened update apply and rollback install-directory canonicalizers so NUL-containing or parent-traversing install paths fail before `create_dir_all_checked` or filesystem canonicalization.
- Added Rust regression markers in both update applier and rollback plus a Python source contract for service-layer install-directory text validation.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1224

- Hardened rollback latest-snapshot discovery so linked/reparse-backed snapshot entries fail visibly before safe-name filtering or directory selection.
- Added a linked-snapshot Rust regression marker plus a Python source contract for rollback latest-snapshot entry validation.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1225

- Hardened recursive rollback snapshot copying so every source entry passes the shared link/reparse guard before destination path derivation or staged copy.
- Added a linked snapshot-content Rust regression marker plus a Python source contract for rollback copy-entry validation.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1226

- Hardened update package payload extraction activation so the staged temp file and extraction target are revalidated immediately before `rename`.
- Added Rust regression markers for target-race and temp-type activation preflight, plus a Python source contract for the activation helper.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1227

- Hardened update destination tree copying so each payload source entry passes the shared link/reparse guard before destination path derivation or staged copy.
- Added a linked payload-source Rust regression marker plus a Python source contract for update destination copy-entry validation.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1228

- Hardened shared staged-file activation so staged temp files are revalidated as regular non-linked files and removed targets are rechecked before `rename`.
- Added a non-regular staged-temp Rust regression marker plus a Python source contract for shared staged activation preflight.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1229

- Hardened shared staged-temp and payload extraction temp cleanup so cleanup targets are inspected without following links and must be regular files before removal.
- Added Rust regression markers for non-regular cleanup targets plus a Python source contract covering both cleanup helpers.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1230

- Hardened update package file opening so all manifest, signature, hash, payload verification, and extraction reads route through a checked opener that revalidates the package path after `File::open`.
- Added a Rust source marker plus a Python source contract for package post-open path revalidation.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1231

- Hardened update package file opening further so the opener compares pre-open path metadata, opened-handle metadata, and post-open path metadata before any `.aup` bytes are trusted.
- Extended the Rust source marker and Python source contract for package opener metadata consistency.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1232

- Removed the unused direct `sha256_file(path)` update-package helper so package hashing cannot bypass the checked package opener and its post-open metadata consistency checks.
- Extended the Rust source marker and Python source contract to keep the direct helper absent.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1233

- Hardened update package payload archive validation so duplicate normalized payload entries fail before hash verification or extraction can trust one name mapping to multiple ZIP entries.
- Added a Rust regression fixture for duplicate normalized archive paths and a Python source contract for the `BTreeSet` duplicate-name guard.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1234

- Hardened update destination tree copying so canonicalized source and destination roots are revalidated as existing non-linked directories before walking payload entries or staged-copying files.
- Added a Rust source marker and Python source contract for the canonical-root revalidation helper.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1235

- Hardened rollback directory restore copying so canonicalized snapshot and destination roots are revalidated as existing non-linked directories before walking rollback entries or staged-copying files.
- Added a Rust source marker and Python source contract for the rollback canonical-root revalidation helper.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1236

- Hardened update package payload extraction so the canonical extraction destination is revalidated as an existing non-linked directory before staged payload writes begin.
- Added a Rust source marker and Python source contract for the extraction destination canonical-root revalidation helper.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1237

- Hardened signed payload-hash manifest validation so duplicate normalized payload paths fail before the `.aup` archive is opened.
- Added a Rust regression marker that uses a non-ZIP `.aup` fixture to prove the duplicate normalized manifest-path check runs before archive parsing, plus a Python source contract for the ordering.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1238

- Hardened update package metadata validation with non-empty and maximum `.aup` file-size bounds before package opening, hashing, manifest parsing, payload verification, or extraction.
- Added a Rust source marker and Python source contract for the pre-open package-size bounds.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1239

- Hardened update package ZIP handling with a total archive-entry cap before manifest/signature reads, payload hashing, or extraction loops proceed.
- Added a Rust source marker and Python source contract for archive-entry cap ordering.
- Updated `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and `STATUS.md`; Cargo runtime tests remain blocked because `cargo` is not installed or not on `PATH` in this shell.

## 2026-06-26 continuation checkpoint 1240

- Hardened Flutter remote `.aup` downloads so package bytes stream into the reserved temp file with accumulated byte-limit checks instead of buffering `response.bodyBytes`.
- Kept feed and GitHub release metadata on bounded `Response` reads because their JSON limits are small and separately enforced.
- Updated Dart source-marker tests plus a Python source contract; Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this shell.

## Repository inspection summary

### Languages and frameworks

- Flutter/Dart client in `apps/zentor_client`.
- Rust workspace in root `Cargo.toml` with crates under `core/` and `services/api/`.
- Dart shared packages under `packages/`.
- PowerShell + WiX Windows installer/update/release tooling.
- Optional Docker/Postgres/Redis infrastructure under `infra/`.

### Key product areas inspected

- UI shell, routes, Dashboard, Scan, Protection, Quarantine, Settings, Logs, Updates, shared widgets.
- App state/controller, local core IPC, scan target selection, config persistence, logging, update service.
- Native engine signatures, rules, heuristics, trust, verdict fusion, quarantine, quick/full planners.
- Local core scan command surface, allowlist, protection modules, quarantine store.
- Guard service driver IPC, process monitoring, pre-execution policy, driver self-test paths.
- Update service package verification, hash/signature validation, staging/apply/rollback code.
- README, STATUS, docs, installer scripts, security/release gates, CI workflows.

## Prioritized work plan

### P0

- Keep project buildable/testable.
- Create/update `TODO.md`, `RUN_LOG.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`.
- Fix stale Flutter scan errors after successful scans.
- Harden local event loading against corrupt JSON.
- Add focused tests for those safety fixes.
- Add or preserve basic scan/quarantine tests.
- Remove/hide unsupported UI claims or dead controls where touched.

### P1

- Improve Quick Scan and Full Scan target selection/testability.
- Improve local core IPC diagnostics and timeout handling.
- Improve settings persistence and reset/override UX safety.
- Improve logging/report export behavior.
- Refresh stale docs and release runbooks.

### P2

- Wire real best-effort user-mode real-time monitoring into local core start/stop commands.
- Add debounce/stable-file/retry/unchanged-file cache tests.
- Harden guard IPC publisher/signature trust boundary.
- Improve ransomware protected folder UX and harmless simulation tests.

### P3

- Cache native engine in guard path and stream large-file hashing.
- Improve update atomic apply/rollback.
- Enforce production update signing policy.
- Expand CI/release gates.

### P4

- Plugin/rule provider interface.
- Optional disabled cloud reputation provider.
- Accessibility/localization-ready UI pass.
- Exportable support report bundles.
- Performance benchmarks.

## Completed changes in this session

- Created `TODO.md` with P0-P4 product-hardening backlog and safe operating rules.
- Created `ARCHITECTURE.md` documenting repository layout, runtime architecture, scan flow, detection engine, quarantine, protection, updates, and build/test systems.
- Created `SECURITY_MODEL.md` documenting goals, non-goals, trust boundaries, scan safety, detection/action policy, quarantine safety, updates, logging/privacy, known limitations, and safe development rules.
- Created this `RUN_LOG.md` to preserve assumptions, inspection findings, work plan, completed changes, tests, limitations, and next tasks.

## Tests and checks run so far

- Repository inspection commands and file reads.
- `git status --short --branch`.
- Toolchain discovery:
  - Cargo available at `C:\Users\Brent\.cargo\bin\cargo`, version `1.96.0`.
  - Flutter SDK exists at `C:\Users\Brent\dev\flutter\bin` and Cargo at `C:\Users\Brent\.cargo\bin`; both were used via explicit PATH in this pass.
  - PowerShell is available.

## Known limitations / blockers

- Flutter is not on shell `PATH`; use `C:\Users\Brent\dev\flutter\bin\flutter` when running Flutter checks from this Git Bash environment.
- Some Windows service/update tests may require elevation and can fail with Windows elevation error 740 in a non-elevated shell.
- Driver validation requires a signed/installed/self-tested driver report and cannot be assumed complete.
- `packages/avorax_protocol` currently lacks `package:test` dev dependency, so `dart test` expectations for it need cleanup or dependency additions.
- Existing working tree had `AGENTS.md` modified before this implementation pass began.

## Files modified in this session

- `TODO.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `RUN_LOG.md`

## Additional implementation completed

- Hardened `LocalEventRepository.load` to recover from corrupt JSON and skip invalid records.
- Hardened Flutter scan state handling so stale engine errors clear after successful scans and cancelled scans do not keep receiving progress updates.
- Reworked `ScanTargetService` with platform-specific, testable quick/full target planning.
- Added Flutter tests for corrupt event log recovery, quick/full scan target planning, stale error clearing, and scan orchestration invariants.
- Hardened Rust quarantine store listing/restore/delete behavior around corrupt metadata and unsafe payload paths.
- Added Rust quarantine lifecycle tests for restore confirmation, duplicate restore naming, delete confirmation, corrupt metadata, and payload path validation.
- Improved Settings UX with reset confirmation, log-export feedback, and clean developer override disable behavior.
- Improved Dashboard/Protection/Scan/Quarantine UI copy and states to avoid unsupported claims and dead controls.
- Added quarantine restore/delete confirmation dialogs in the Flutter UI.
- Added visual policy tests for quarantine destructive-action confirmation and protection service-state honesty.
- Added `TESTING.md` and `CHANGELOG.md`, and linked engineering docs from `README.md`.
- Updated `STATUS.md` with current hardening work, verification, and blockers.
- Added best-effort user-mode watcher planning/evaluation for requested existing directories, debounce waiting, stable-file retry, unchanged-file scan suppression, and monitor-only review observations.
- Added Rust tests for `start_watch` command output and watcher debounce/cache/monitor-only behavior.
- Added Flutter IPC diagnostics tests for missing core executable, non-zero exit with stderr, malformed JSON, timeout/kill, and health-summary recovery messaging.
- Wired Flutter protection startup/shutdown to local core `start_watch` / `stop_watch`, stores watched paths/mode in app state, keeps selected protected app paths in scan/watch paths, and labels `userModeBestEffort` as honest best-effort user-mode monitoring in the Protection screen.
- Upgraded Updates to be fully operated from inside the app for normal update flows: default GitHub feed URL, check/download/hash-verify/install state transitions, ready-to-restart result, in-app rollback button, and Update Service `--rollback` snapshot restore.

## Final verification in this pass

- `cd apps/zentor_client && C:\Users\Brent\develop\flutter\bin\flutter.bat analyze` passed with no issues.
- Current in-app update pass: `cd apps/zentor_client && C:\Users\Brent\develop\flutter\bin\flutter.bat analyze` passed with no issues.
- Current in-app update pass: `cd apps/zentor_client && C:\Users\Brent\develop\flutter\bin\flutter.bat test` passed 37 tests including update controller/service coverage.
- Current in-app update pass: `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bins` passed.
- Current in-app update pass: `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed 64 tests.
- Current in-app update pass: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml` passed 19 tests.
- Current in-app update pass: `cd packages/zentor_protocol && C:\Users\Brent\develop\flutter\bin\dart.bat test` passed 4 tests.
- Current in-app update pass: `cd apps/zentor_client && C:\Users\Brent\develop\flutter\bin\flutter.bat build windows --debug` produced `build\windows\x64\runner\Debug\Avorax.exe`.
- Current in-app update installer build: `powershell -ExecutionPolicy Bypass -File installer/windows/build-msi.ps1 -Version 0.2.16 -RequireLocalCore -AllowDevelopmentModel` produced `dist\Avorax-AntiVirus-0.2.16-x64.msi` and `dist\Avorax-AntiVirus-0.2.16-x64-setup.exe`.
- Current in-app update installer stage verification passed; staged core health reported native engine `ready`, 17 signatures, 11 rules, development ML loaded, and native self-test true.
- Current in-app update artifact hashes: MSI `8e6b9101f8369ee5663c6d89754f72c1521a5c950d5ab9a8cda4f8a927196efa`; EXE `26a123cf3f9d91504a52a8ef8c05cad36174d18c8c4c70fa45bec19b7f49c9d7`.
- `cd apps/zentor_client && C:\Users\Brent\develop\flutter\bin\flutter.bat test` passed 34 tests after IPC diagnostics and protection watcher UI wiring.
- `cd apps/zentor_client && C:\Users\Brent\develop\flutter\bin\flutter.bat build windows --debug` produced `build\windows\x64\runner\Debug\Avorax.exe`.
- `powershell -ExecutionPolicy Bypass -File installer/windows/build-msi.ps1 -Version 0.2.15 -RequireLocalCore -AllowDevelopmentModel` produced `dist\Avorax-AntiVirus-0.2.15-x64.msi` and `dist\Avorax-AntiVirus-0.2.15-x64-setup.exe`.
- `powershell -ExecutionPolicy Bypass -File tools/windows/avorax-installer-stage-test.ps1 -StagePath dist/windows-msi/stage` passed; staged core health reported native engine `ready`, 17 signatures, 11 rules, development ML loaded, and native self-test true.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed 64 tests after user-mode watcher additions.
- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml` passed 19 tests.
- `cd packages/zentor_protocol && C:\Users\Brent\develop\flutter\bin\dart.bat test` passed 4 tests.

## Current blockers

- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml` is blocked by Microsoft Defender error 225 on the generated test executable because the native-engine crate contains antivirus-style synthetic fixtures/signatures.
- Signed driver validation remains unavailable in this environment, so kernel/pre-execution protection cannot be claimed verified.
- Update-service elevated tests and full release gates still require an elevated/provisioned Windows release environment.

## Recommended next work

1. Harden guard-service IPC trust boundary so caller-provided publisher/signature fields cannot bypass policy unless verified by a trusted driver/service path.
2. Add ransomware protected-folder settings, allowlist validation, and harmless simulation tests.
3. Run full release gates in a provisioned elevated Windows environment before tagging a new release.


## 2026-06-03 hardening continuation

### Completed changes

- Added streaming scan-content reads in `core/zentor_native_engine`: file scans now compute the full-file SHA-256 via buffered I/O while keeping a bounded 64 MiB analysis sample, reducing memory pressure on large files.
- Extended `FileScanVerdict` with `file_size_bytes`, `scanned_bytes`, and `scan_sample_limited` metadata so reports can distinguish full-file identity from bounded content analysis.
- Expanded Quick Scan planning to include deduplicated high-risk Windows locations: Downloads, Desktop, user/all-users Startup folders, TEMP/LocalAppData temp, and common Edge/Chrome/Firefox profile/download areas when present.
- Hardened Full Scan traversal by not following links and excluding quarantine, `.avorax`, `.git`, `target`, `build`, `.dart_tool`, and `node_modules` trees by default.
- Hardened native-engine quarantine copy fallback so the copied payload hash must match the expected SHA-256 before the original file is deleted; metadata now also records file size.
- Updated local core threat conversion to use native-engine file-size metadata instead of re-reading metadata after a possible quarantine/move.
- Updated Scan UI copy to describe progress, hashes, skipped/error reporting, and conservative large-file handling.
- Updated `TODO.md`, `ARCHITECTURE.md`, and `SECURITY_MODEL.md` for the implemented scan/quarantine hardening.

### Files modified

- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `TODO.md`
- `apps/zentor_client/lib/features/scan/scan_screen.dart`
- `core/zentor_local_core/src/main.rs`
- `core/zentor_native_engine/src/engine.rs`
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs`
- `core/zentor_native_engine/src/scan/content_reader.rs`
- `core/zentor_native_engine/src/scan/file_walker.rs`
- `core/zentor_native_engine/src/scan/quick_scan_planner.rs`
- `core/zentor_native_engine/src/scan/scan_result.rs`
- `core/zentor_native_engine/src/tests/mod.rs`

### Tests/checks run

- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml` passed: 35 tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed: 64 tests.
- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml` passed: 19 tests.
- `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bins` passed.
- `cd apps/zentor_client && flutter analyze` passed with no issues.
- `cd apps/zentor_client && flutter test` passed: 37 tests.
- `cd apps/zentor_client && flutter build windows --debug` produced `build\windows\x64\runner\Debug\Avorax.exe`.
- `cargo build --release --manifest-path core/zentor_local_core/Cargo.toml` passed and the rebuilt core service was copied beside the debug app as `avorax_core_service.exe` and `zentor_local_core.exe`.
- Local core health check passed with `ok: true` and native engine `ready`.

### Known limitations

- Existing tag `v0.2.2` already exists in the repository while newer tags through `v0.2.16` also exist; creating a new release with the same tag is not possible without deleting/moving an existing published tag, which should not be done casually.
- Push to `origin/main` succeeded; remote `main` now points at commit `97bca2697cbf3b79dedaaa4d4213f934cb72aa2b`.
- Release tag `v0.2.2` already exists remotely at `f40292ec024206e5b138fb5665f16a9a1e36bfa9`, and the GitHub release already exists at `https://github.com/brentishere41848/Avorax/releases/tag/v0.2.2` (`Zentor 0.2.2`). It was not moved/overwritten because that would rewrite an existing published release tag while newer tags through `v0.2.16` exist.
- Build warnings remain in `zentor_local_core` for existing unused compatibility paths; tests still pass.
- Signed Windows driver validation was not performed in this environment; kernel/pre-execution protection remains documented as developmental unless separately installed, signed, and self-tested.

### Next recommended tasks

1. Harden guard-service IPC trust boundary so caller-provided publisher/signature fields cannot bypass policy unless verified by a trusted driver/service path.
2. Add ransomware protected-folder settings, allowlist validation, UI event history, and harmless simulation tests.
3. Add protocol/UI surfacing for scan sample-limit metadata in exported reports.
4. Choose a new release tag above the current latest (`v0.2.16`) or explicitly decide to move/recreate `v0.2.2` if that is truly intended.


## 2026-06-03 hardening continuation 2

### Completed changes

- Hardened guard-service pre-execution metadata trust: caller-provided publisher/signature metadata no longer grants trusted-publisher allow decisions unless it includes trusted verifier provenance.
- Hardened guard-service hash trust: readable files are hashed locally; caller-provided hashes are accepted only as a fallback for unreadable race-window files and only when supplied by a trusted verifier source.
- Added `signature_verified_by` and `sha256_verified_by` fields to driver IPC scan requests with serde defaults for backward-compatible deserialization.
- Added ransomware protected-root policy support and trusted-process suppression in `RansomwareGuardConfig`.
- Added tests covering unverified publisher spoofing, unverified hash spoofing, trusted fallback hash provenance, protected-root filtering, and trusted ransomware process suppression.

### Files modified

- `core/zentor_guard_service/src/driver_ipc.rs`
- `core/zentor_guard_service/src/self_test.rs`
- `core/zentor_local_core/src/protection/ransomware_guard.rs`
- `TODO.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `RUN_LOG.md`

### Tests/checks run

- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml` passed: 22 tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed: 67 tests.
- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml` passed: 35 tests.
- `cd apps/zentor_client && flutter analyze` passed with no issues.
- `cd apps/zentor_client && flutter test` passed: 37 tests.

### Known limitations

- The new ransomware policy object is implemented and tested in core logic, but UI/settings persistence still needs wiring so users can edit protected folders and trusted backup/sync tools.
- Existing Rust warnings remain for developmental/compatibility modules that are intentionally present but not wired into every build path.

### Next recommended tasks

1. Add UI/settings persistence for ransomware protected roots and trusted process allowlists.
2. Add recent protection/ransomware event history to the Flutter UI.
3. Add a release tag above current latest rather than moving the already-published `v0.2.2`.


## 2026-06-03 hardening continuation 3

### Completed changes

- Added local core `configure_ransomware_guard` IPC support with persistence for protected roots, trusted process allowlists, update timestamps, and validation that rejects broad root-style protected folders.
- Extended `CoreCommand` with `protected_roots` and `trusted_process_allowlist` fields.
- Extended shared Dart `ZentorConfig` with `ransomwareProtectedRoots` and `ransomwareTrustedProcesses` JSON/copyWith support.
- Added Flutter settings controls for ransomware protected folders and trusted backup/sync process paths, with save wiring through the app controller to local core IPC.
- Included configured ransomware protected roots in best-effort real-time watch path planning when those paths exist.
- Extended local event persistence with category/severity metadata and updated the Logs screen to summarize protection events and warnings.
- Updated TODO/architecture/security docs to mark P0/P1 complete and the newly implemented P2 protection settings/logging work done.

### Files modified

- `TODO.md`
- `RUN_LOG.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `core/zentor_local_core/src/api/mod.rs`
- `core/zentor_local_core/src/main.rs`
- `packages/zentor_protocol/lib/zentor_protocol.dart`
- `apps/zentor_client/lib/app/app_state.dart`
- `apps/zentor_client/lib/core/local_core/local_core_client.dart`
- `apps/zentor_client/lib/core/logging/local_event_repository.dart`
- `apps/zentor_client/lib/features/logs/logs_screen.dart`
- `apps/zentor_client/lib/features/settings/settings_screen.dart`
- `apps/zentor_client/test/config_validation_test.dart`
- `apps/zentor_client/test/local_event_test.dart`

### Tests/checks run

- `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed: 69 tests.
- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml` passed: 22 tests.
- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml` passed: 35 tests.
- `cd apps/zentor_client && flutter analyze` passed with no issues.
- `cd apps/zentor_client && flutter test` passed: 39 tests.
- `cd apps/zentor_client && flutter build windows --debug` produced `build\windows\x64\runner\Debug\Avorax.exe`.

### Current status

- No known remaining P0/P1 hardening gaps are tracked after this pass.
- Remaining open items are P3/P4 production/release hardening or optional stretch work: update apply rollback hardening, production update-key policy, expanded CI/release gates, protocol test-dependency cleanup, plugin/cloud-provider interfaces, accessibility, support bundles, and benchmarks.
- Existing Rust warnings remain for developmental/compatibility paths, but the verification commands above passed.
- Signed Windows driver validation still requires a signed/installed/self-tested driver report in a provisioned environment.


## 2026-06-03 hardening continuation 4

### Completed changes

- Added static contract tests requiring guard pre-execution verdicts to reuse a cached native engine and requiring driver-path hashing to use streaming I/O.
- Replaced per-request `ZentorNativeEngine::initialize` in `core/zentor_guard_service/src/driver_ipc.rs` with a shared `OnceLock` cache containing a mutex-protected native engine instance.
- Changed guard-service SHA-256 calculation from full-file `fs::read` to buffered streaming I/O.
- Bounded the optional compatibility YARA fallback to a buffered 1 MiB sample instead of reading the entire candidate file.
- Updated `TODO.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `TESTING.md`, and `CHANGELOG.md` for the guard cache/streaming hardening work.
- Added explicit update-service production verification policy: normal CLI verify/apply paths reject dev signing keys unless `--allow-development-key` or `AVORAX_ALLOW_DEVELOPMENT_UPDATES=1` is present.
- Added static contract coverage for the update-service production/dev-key policy.
- Added update apply rollback-on-failure logic: if staged payload copying fails after a snapshot is created, the update service attempts to restore the snapshot, restart services, write a structured failed update report, and return an explicit rollback-restored error.
- Added static contract coverage for rollback-on-apply-failure behavior.
- Fixed a ransomware-guard configuration unit test to use harmless temporary protected folders and a temporary trusted-process fixture instead of hard-coded nonexistent Windows paths; assertions now match the product's normalized persisted path format.

### Files modified

- `TODO.md`
- `RUN_LOG.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `TESTING.md`
- `CHANGELOG.md`
- `tests/test_custom_driver_contract.py`
- `core/zentor_guard_service/src/driver_ipc.rs`
- `core/avorax_update_service/src/main.rs`
- `core/avorax_update_service/src/update_applier.rs`
- `core/avorax_update_service/src/update_verifier.rs`
- `core/avorax_update_service/src/rollback.rs`
- `core/zentor_local_core/src/main.rs`

### Tests/checks run

- RED check before implementation: `uv run pytest tests/test_custom_driver_contract.py -q` failed as expected on missing native-engine cache and streaming guard hashing.
- After implementation: `uv run pytest tests/test_custom_driver_contract.py -q` passed: 9 tests.
- After implementation: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml driver_ipc -- --nocapture` passed: 14 driver IPC tests.
- Full guard service tests passed: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml` passed: 22 tests.
- Local core tests passed: `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed: 69 tests.
- Update service compile check passed: `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bin avorax_update_service`.
- Updated contract tests passed: `uv run pytest tests/test_custom_driver_contract.py -q` passed: 11 tests.
- Update service unit-test execution was attempted with `cargo test --manifest-path core/avorax_update_service/Cargo.toml` and `cargo test --manifest-path core/avorax_update_service/Cargo.toml --bin avorax_update_service`; both were blocked before tests ran by Windows elevation error 740 because the update service test binaries inherit a require-administrator manifest.
- Flutter analyze passed with no issues.
- Flutter tests passed: 45 tests.
- Final local-core rerun passed after fixture fix: `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed: 69 tests.

### Current status

- Guard pre-execution latency and memory behavior are improved without expanding security claims.
- Remaining open items are accessibility, support bundles, benchmarks, and optional provider/plugin architecture.


## 2026-06-04 hardening continuation 5

### Completed changes

- Fixed the broken `packages/avorax_protocol` Dart test target by adding a `package:test` dev dependency and a reproducible `pubspec.lock`.
- Added `packages/avorax_protocol/test/update_manifest_test.dart` covering update manifest parsing, conservative defaults, and exact wire-key serialization.
- Added `AvoraxUpdateManifest.toJson()` so the shared protocol model can round-trip the `.aup` manifest schema used by the verifier and app code.
- Expanded `.github/workflows/ci.yml` to run `dart test` for `packages/avorax_protocol`.
- Added a Windows CI security/performance gate job covering product-copy, no-malware-binaries, false-positive, protection, and performance gates.
- The CI protection gate uses a synthetic non-driver self-test fixture and deliberately does not claim kernel-driver validation; driver-feature release validation still requires a signed/installed/self-tested driver report.
- Updated `TODO.md`, `TESTING.md`, and `CHANGELOG.md` for the completed protocol and CI gate work.

### Files modified

- `.github/workflows/ci.yml`
- `TODO.md`
- `TESTING.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `packages/avorax_protocol/lib/update_manifest.dart`
- `packages/avorax_protocol/pubspec.yaml`
- `packages/avorax_protocol/pubspec.lock`
- `packages/avorax_protocol/test/update_manifest_test.dart`

### Tests/checks run

- RED check before implementation: `cd packages/avorax_protocol && dart test` failed with missing `package:test` dependency.
- `cd packages/avorax_protocol && dart test` passed after adding tests and `toJson()`.
- `cd packages/avorax_protocol && dart analyze && dart test` passed.
- `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1` passed.
- `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1 -RepoRoot .` passed.
- `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/security/zentor-protection-gate.ps1 -RepoRoot . -SelfTestReport dist/ci-selftest-report.json` passed in non-driver configuration.
- `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/perf/zentor-performance-gate.ps1 -RepoRoot .` passed and wrote `dist/performance/performance_gate_report.json`.
- `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/security/zentor-false-positive-gate.ps1 -RepoRoot .` passed.

### Current status

- The highest-priority broken `avorax_protocol` test setup is fixed and covered by meaningful schema tests.
- CI now exercises the previously open security/protection/performance gate backlog where feasible on GitHub-hosted Windows runners.
- Remaining open work is P4-level: accessibility/localization readiness, support bundle export, benchmarks, and optional provider/plugin architecture.


## 2026-06-04 hardening continuation 6

### Completed changes

- Added explicit navigation semantics for desktop sidebar items: a `Primary navigation` landmark plus `Current page, <label>` and `Open <label>` labels.
- Added mobile bottom-navigation current-page semantics and per-destination tooltips.
- Hardened the desktop sidebar layout by replacing the fixed `Column`/`Spacer` body with a scrollable list so navigation remains reachable and does not overflow on constrained heights.
- Added `apps/zentor_client/test/navigation_accessibility_test.dart` covering desktop/sidebar and mobile bottom-navigation semantics.
- Updated `TODO.md` and `CHANGELOG.md` for the completed navigation accessibility slice while leaving broader page-level accessibility/localization work open.

### Files modified

- `TODO.md`
- `RUN_LOG.md`
- `CHANGELOG.md`
- `apps/zentor_client/lib/shared/widgets/zentor_sidebar.dart`
- `apps/zentor_client/lib/shared/widgets/zentor_bottom_nav.dart`
- `apps/zentor_client/test/navigation_accessibility_test.dart`

### Tests/checks run

- RED/diagnostic check: initial `flutter test test/navigation_accessibility_test.dart` failed because expected semantics were missing and then exposed a real constrained-height sidebar overflow.
- Focused rerun passed: `flutter test test/navigation_accessibility_test.dart`.

### Current status

- Navigation accessibility and constrained-height desktop sidebar behavior are improved without changing product capability claims.
- Remaining open work is P4-level: broader accessibility/localization readiness, support bundle export, benchmarks, and optional provider/plugin architecture.


## 2026-06-04 hardening continuation 7

### Completed changes

- Added `tools/perf/avorax-benchmark.py`, a safe benchmark harness that uses harmless synthetic files and existing test commands.
- The benchmark report covers synthetic traversal/hashing, native signature test wall-clock timing, guard pre-execution decision test wall-clock timing, and non-elevated synthetic update-copy simulation.
- Wired the benchmark harness into `tools/perf/zentor-performance-gate.ps1` so the existing performance gate also writes `dist/performance/benchmark_report.json`.
- Updated `TODO.md`, `TESTING.md`, and `CHANGELOG.md` to distinguish safe trend benchmarks from future elevated/provisioned real update apply and signed-driver latency benchmarks.

### Files modified

- `TODO.md`
- `TESTING.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `tools/perf/avorax-benchmark.py`
- `tools/perf/zentor-performance-gate.ps1`

### Tests/checks run

- `python tools/perf/avorax-benchmark.py --file-count 32 --file-size 4096` passed and wrote `dist/performance/benchmark_report.json`.
- `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/perf/zentor-performance-gate.ps1 -RepoRoot .` passed and invoked the benchmark harness.

### Current status

- Safe performance trend benchmarking is available and integrated into the performance gate without using malware samples or claiming elevated update/driver validation.
- Remaining open work is P4-level: broader accessibility/localization readiness, support bundle export, elevated/provisioned update/driver benchmarks, and optional provider/plugin architecture.


## 2026-06-04 hardening continuation 8

### Completed changes

- Hardened allowlist evaluation so file/app/executable entries that record a hash require both the normalized path and SHA-256 to match.
- Hardened allowlist creation so file/app/executable approvals hash the current target file and fail closed if the file cannot be hashed.
- Hardened legacy/path-only file/app/executable entries so they fail closed instead of trusting mutable paths.
- Preserved explicit hash-entry behavior as the only global hash trust mechanism.
- Hardened quarantine restore so the quarantined payload must still match the recorded size and SHA-256 before Avorax moves it back to the original path.
- Added regression tests for replaced-payload allowlist bypasses, hash-scope separation, fail-closed allowlist creation, and tampered quarantine payload restore.
- Updated `TODO.md`, `SECURITY_MODEL.md`, and `CHANGELOG.md` with the protection boundary changes.

### Files modified

- `TODO.md`
- `SECURITY_MODEL.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `core/zentor_local_core/src/allowlist/allowlist_store.rs`
- `core/zentor_local_core/src/quarantine/quarantine_store.rs`

### Tests/checks run

- `cargo test --manifest-path core/zentor_local_core/Cargo.toml allowlist -- --nocapture` passed with 8 focused allowlist tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml quarantine -- --nocapture` passed with 18 focused quarantine/protection tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml -- --nocapture` passed with 76 local-core tests.

### Current status

- Two protection-reducing trust-boundary gaps are closed: mutable path-only file/app/executable allowlist approvals and restore of tampered quarantine payloads.
- Remaining work continues with further protection-quality review of scanner, ransomware, guard, update, and UI honesty paths.


## 2026-06-04 hardening continuation 9

### Completed changes

- Hardened ransomware guard trusted-process suppression so exact-path trusted backup/sync processes can still suppress ordinary mass-modification signals, but cannot suppress critical ransom-note or backup-tamper signals.
- Added a regression test proving critical ransom-note/backup-tamper activity still produces a high-confidence signal for a trusted backup process path.
- Updated `TODO.md`, `SECURITY_MODEL.md`, and `CHANGELOG.md` with the ransomware trust-boundary behavior.

### Files modified

- `TODO.md`
- `SECURITY_MODEL.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `core/zentor_local_core/src/protection/ransomware_guard.rs`

### Tests/checks run

- `cargo test --manifest-path core/zentor_local_core/Cargo.toml ransomware_guard -- --nocapture` passed with 7 focused ransomware/config tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml -- --nocapture` passed with 77 local-core tests.

### Current status

- Trusted backup/sync process policy is now less bypass-prone: compromise-like ransom-note or backup-tamper behavior remains visible even for trusted process paths.
- Remaining work continues with further protection-quality review of scanner, guard, update, UI honesty, and elevated/provisioned driver validation paths.


## 2026-06-04 hardening continuation 10

### Completed changes

- Hardened app-control trust precedence so strong probable-malware evidence is evaluated before known-good hashes, exact user hash approvals, and trusted-publisher allow decisions.
- Preserved confirmed-malware priority above everything and preserved ordinary trusted known-good/user/publisher allow behavior when no strong probable-malware evidence is present.
- Added regression tests for strong probable-malware overriding stale known-good, user-approved, and trusted-publisher trust records.
- Updated `TODO.md`, `SECURITY_MODEL.md`, and `CHANGELOG.md` with the app-control precedence behavior.

### Files modified

- `TODO.md`
- `SECURITY_MODEL.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `core/zentor_local_core/src/app_control/policy.rs`
- `core/zentor_local_core/src/main.rs`

### Tests/checks run

- `cargo test --manifest-path core/zentor_local_core/Cargo.toml strong_probable_malware_overrides -- --nocapture` passed with 3 focused trust-precedence tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml lockdown_allows -- --nocapture` passed with 3 trust-preservation tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml -- --nocapture` passed with 80 local-core tests.

### Current status

- Stale trust records can no longer silently allow execution when current scan/risk evidence says a payload is probably malicious.
- Remaining work continues with further protection-quality review of scanner, guard, update, UI honesty, and elevated/provisioned driver validation paths.


## 2026-06-04 hardening continuation 11

### Completed changes

- Hardened the user-mode watcher unchanged-file cache by changing duplicate suppression from size-only to a size-plus-modified-time fingerprint.
- Added regression coverage proving a same-size rewrite with a new file modified timestamp is rescanned instead of skipped as unchanged.
- Preserved the existing debounce/stable-file behavior for initial writes and size-growth events.
- Updated `TODO.md`, `SECURITY_MODEL.md`, and `CHANGELOG.md` with the watcher cache behavior.

### Files modified

- `TODO.md`
- `SECURITY_MODEL.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `core/zentor_local_core/src/watcher/mod.rs`

### Tests/checks run

- `cargo test --manifest-path core/zentor_local_core/Cargo.toml unchanged_file_cache -- --nocapture` passed with 2 focused watcher cache tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml -- --nocapture` passed with 81 local-core tests.

### Current status

- User-mode real-time monitoring no longer suppresses a same-size payload replacement solely because the file size matches the previous scan.
- Remaining work continues with further protection-quality review of scanner, guard, update, UI honesty, and elevated/provisioned driver validation paths.


## 2026-06-04 hardening continuation 12

### Completed changes

- Hardened training-label suppression so suppression decisions use the newest valid label for a file hash instead of any older suppressing label.
- Added regression coverage proving a later `ConfirmedMalicious` label revokes an older `FalsePositive` suppression for the same hash.
- Preserved exact-hash suppression for current `FalsePositive` and `TrustedApp` labels.
- Updated `TODO.md`, `SECURITY_MODEL.md`, and `CHANGELOG.md` with the training-label behavior.

### Files modified

- `TODO.md`
- `SECURITY_MODEL.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `core/zentor_local_core/src/ai/training_labels.rs`

### Tests/checks run

- `cargo test --manifest-path core/zentor_local_core/Cargo.toml confirmed_malicious_label_revokes_prior_false_positive_suppression -- --nocapture` failed before the fix, proving the regression covered the stale-suppression bug.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml training_labels -- --nocapture` passed with 2 focused label-store tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml -- --nocapture` passed with 82 local-core tests.

### Current status

- A later confirmed-malicious user label can now revoke older false-positive/trusted-app suppression for the same hash.
- Remaining work continues with further protection-quality review of scanner, guard, update, UI honesty, and elevated/provisioned driver validation paths.


## 2026-06-04 hardening continuation 13

### Completed changes

- Added a native detection-provider interface and registry with provider inventory/status reporting.
- Added regression coverage for enabled provider evaluation, disabled provider non-evaluation, and native-engine status exposing provider inventory without UI/provider coupling.
- Added honest disabled/unavailable provider inventory entries for future compatibility/YARA and cloud-reputation sources when they are not configured/enabled.
- Added `CloudReputation` as an evidence source and mapped it in local-core conversion to optional reputation engine/reason categories.
- Updated `TODO.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `TESTING.md`, and `CHANGELOG.md` with the provider interface and disabled cloud-reputation behavior.

### Files modified

- `TODO.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `TESTING.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `core/zentor_local_core/src/main.rs`
- `core/zentor_native_engine/src/detection_provider.rs`
- `core/zentor_native_engine/src/engine.rs`
- `core/zentor_native_engine/src/lib.rs`
- `core/zentor_native_engine/src/tests/mod.rs`
- `core/zentor_native_engine/src/verdict/risk_fusion.rs`

### Tests/checks run

- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml provider -- --nocapture` failed before implementation because `crate::detection_provider` did not exist, proving the new provider API contract was absent.
- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml provider -- --nocapture` passed with 3 focused provider tests after implementation.
- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml -- --nocapture` passed with 38 native-engine tests.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml -- --nocapture` passed with 82 local-core tests after adding the cloud-reputation evidence-source mapping.
- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml -- --nocapture` passed with 22 guard-service tests.

### Current status

- Native engine now has a provider registry/status contract for future detection sources while keeping disabled providers from contributing evidence.
- Cloud reputation remains disabled/unavailable unless a real backend is configured; the product should surface that honestly rather than imply cloud coverage.
- Remaining open backlog items are broader accessibility/localization readiness and elevated/provisioned benchmark/driver validation paths.


## 2026-06-04 hardening continuation 14

### Completed changes

- Added shell-level accessibility semantics for the active route title and main content area on both mobile and desktop layouts.
- Added a Flutter widget regression test proving `ZentorShell` exposes `Page title, <route>` and `Main content, <route>` semantics without relying on visual-only text.
- Kept the broader accessibility/localization backlog open; this slice improves screen-reader landmarks but does not claim full per-feature accessibility or localization readiness.
- Updated `TODO.md`, `CHANGELOG.md`, and `TESTING.md` with the focused accessibility coverage.

### Files modified

- `TODO.md`
- `CHANGELOG.md`
- `TESTING.md`
- `RUN_LOG.md`
- `apps/zentor_client/lib/shared/widgets/zentor_shell.dart`
- `apps/zentor_client/test/navigation_accessibility_test.dart`

### Tests/checks run

- `flutter test test/navigation_accessibility_test.dart --plain-name "shell exposes page title and main content landmark"` failed before the shell semantics implementation because no page-title/main-content semantics were exposed.
- `flutter test test/navigation_accessibility_test.dart --plain-name "shell exposes page title and main content landmark"` passed after adding the shell semantics and deterministic test provider overrides.
- `flutter test test/navigation_accessibility_test.dart` passed with 3 navigation/accessibility widget tests.
- `flutter analyze` passed for `apps/zentor_client` with no issues.

### Current status

- The Flutter shell now exposes route-aware screen-reader landmarks for the active page title and main content region.
- Remaining open backlog items are broader per-feature accessibility/localization readiness and elevated/provisioned benchmark/driver validation paths.


## 2026-06-04 hardening continuation 15

### Completed changes

- Added Settings screen section-heading semantics so screen readers can navigate General, Cloud, Protection, Native Engine, Diagnostics, and related settings groups as headings.
- Added focused Settings accessibility widget coverage for section-heading labels.
- Fixed the developer-options `SwitchListTile` Material warning by giving it its own transparent Material surface inside the colored settings panel, preserving visible/focus feedback.
- Kept the broader accessibility/localization backlog open; this is a focused per-feature Settings improvement rather than a full app-wide audit.
- Updated `TODO.md`, `CHANGELOG.md`, and `TESTING.md` with the Settings accessibility coverage.

### Files modified

- `TODO.md`
- `CHANGELOG.md`
- `TESTING.md`
- `RUN_LOG.md`
- `apps/zentor_client/lib/features/settings/settings_screen.dart`
- `apps/zentor_client/test/settings_accessibility_test.dart`

### Tests/checks run

- `flutter test test/settings_accessibility_test.dart --plain-name "settings exposes screen-reader section headers"` failed before implementation because Settings section headings had no screen-reader section semantics.
- `flutter test test/settings_accessibility_test.dart --plain-name "settings exposes screen-reader section headers"` passed after implementation.
- `flutter test test/navigation_accessibility_test.dart test/settings_accessibility_test.dart` passed.
- `flutter analyze` passed for `apps/zentor_client` with no issues.

### Current status

- Settings has route-independent screen-reader section headings and no longer emits the developer-options switch Material warning during widget tests.
- Remaining open backlog items are broader per-feature accessibility/localization readiness and elevated/provisioned benchmark/driver validation paths.


## 2026-06-04 hardening continuation 16

### User-reported failure

Protection self-test showed:

- `PASS Driver installed`: `ZentorAvFilter` is installed but not loaded.
- `FAIL Driver running`.
- `FAIL Driver IPC alive`.
- `FAIL Pre-execution block self-test`.

### Live host diagnosis

- `sc.exe query ZentorAvFilter` reports the file-system driver service is installed but `STATE: STOPPED`.
- `fltmc filters` does not list `ZentorAvFilter`.
- `bcdedit /enum` in this non-elevated Git Bash shell shows no TESTSIGNING entry.
- `bcdedit.exe //set testsigning on` failed with `Access is denied`, confirming elevation is required. A later elevated remediation attempt failed with `The value is protected by Secure Boot policy and cannot be modified or deleted`, proving Secure Boot is the active blocker on this host.
- `fltmc.exe load ZentorAvFilter` failed with `0x80070005 Access is denied`, so this session cannot activate the driver live.
- `sc.exe stop avorax_guard_service` failed with `OpenService FAILED 5: Access is denied`, so this session cannot replace/restart the installed Guard Service binary live.

### Completed code/product changes

- Guard driver health now reports additional fields: `loadAttempted`, `loadSucceeded`, `loadError`, and `rebootRequired`.
- Guard driver health now attempts `fltmc load ZentorAvFilter` only when the driver service is installed, the filter is not running, and Windows TESTSIGNING is already enabled.
- Guard driver health now re-probes `fltmc filters` and driver IPC after a guarded load attempt.
- Self-test failure reasons now surface the exact driver-policy blocker in `Driver running`, `Driver IPC alive`, and `Pre-execution block self-test` instead of generic text.
- Packaged `avorax-install-driver.ps1` generation no longer silently enables TESTSIGNING; it reports `testsigning_required`/`reboot_required` and asks the user/admin to enable TESTSIGNING explicitly and reboot.
- Added `tools/windows/avorax-enable-test-signing.ps1` as an explicit elevated development helper with a clear reboot warning.
- Added static and Rust regression tests for TESTSIGNING policy reporting, guarded auto-load attempts, IPC failure classification, and installer/helper contracts.
- Updated `TODO.md`, `CHANGELOG.md`, `SECURITY_MODEL.md`, and `docs/windows-driver.md`.

### Files modified

- `TODO.md`
- `CHANGELOG.md`
- `SECURITY_MODEL.md`
- `RUN_LOG.md`
- `docs/windows-driver.md`
- `installer/windows/build-msi.ps1`
- `tools/windows/avorax-enable-test-signing.ps1`
- `tests/test_custom_driver_contract.py`
- `core/zentor_guard_service/src/driver_health.rs`
- `core/zentor_guard_service/src/driver_ipc.rs`
- `core/zentor_guard_service/src/self_test.rs`

### Tests/checks run

- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml driver_health -- --nocapture` passed with 4 tests.
- Rebuilt guard health command reports `status=testSigningRequired` and `rebootRequired=true` on this host.
- Rebuilt guard self-test now explains that pre-execution blocking is inactive because the minifilter is not loaded and TESTSIGNING is off.
- `python -m pytest tests/test_custom_driver_contract.py` passed with 13 tests.
- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml -- --nocapture` passed with 26 tests.
- `cargo build --manifest-path core/zentor_guard_service/Cargo.toml --release` passed.

### Current status

- The code/provisioning path is fixed and verified.
- The live machine still requires an elevated admin terminal and reboot to load the currently installed test-signed driver:
  1. Elevated terminal: `bcdedit /set testsigning on`
  2. Reboot.
  3. Elevated terminal after reboot: run the packaged driver install/load self-test or `fltmc load ZentorAvFilter`.
  4. Restart/replace the installed Guard Service with the newly built binary or reinstall from a rebuilt package.
- This non-elevated Hermes shell cannot perform those live OS steps; Windows returned `Access is denied` for both boot-policy change and service control.


## 2026-06-04 hardening continuation 17

### User-reported failure

Updates page showed:

- `Status: Update failed`
- `Last error: Bad state: Update feed returned HTTP 404.`

### Root cause

- Installed builds use `https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json` by default.
- GitHub's `/releases/latest` route ignores prereleases.
- Current Avorax release assets existed on `v0.2.31`, including `update-feed.json`, but `v0.2.31` was marked prerelease, so the `/latest/download/update-feed.json` route returned 404.
- Direct tag URL `https://github.com/brentishere41848/Avorax/releases/download/v0.2.31/update-feed.json` returned the expected feed.

### Live release fix

- Used GitHub API credentials from Git Credential Manager without printing secrets.
- Updated release `v0.2.31` from prerelease to non-prerelease so GitHub's `/releases/latest/download/update-feed.json` resolves for existing installed builds.
- Verified the live URL now returns the 0.2.31 update-feed JSON without a cache-bypass query.

### Code fix

- Added a Flutter update-service fallback for the trusted GitHub latest feed path.
- If `/releases/latest/download/update-feed.json` returns 404, the app queries `https://api.github.com/repos/<owner>/<repo>/releases?per_page=20`, finds the newest non-draft release asset named `update-feed.json`, and loads that asset.
- Dev-channel builds may use prerelease release assets through the fallback; non-dev channels skip prereleases.
- Arbitrary feed URLs and non-404 feed errors still fail honestly instead of faking update success.

### Files modified

- `TODO.md`
- `CHANGELOG.md`
- `RUN_LOG.md`
- `docs/in-app-updates.md`
- `apps/zentor_client/lib/core/updates/update_service.dart`
- `apps/zentor_client/test/update_service_test.dart`

### Tests/checks run

- Live 404 reproduced with `curl -I -L https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json` before release correction.
- GitHub REST API inspection showed `v0.2.31` had `update-feed.json` but was marked prerelease.
- Tag-specific feed URL returned HTTP 200.
- New regression test failed before implementation: `flutter test test/update_service_test.dart --plain-name "falls back to GitHub release asset feed when latest download 404s"`.
- New regression test passed after implementation.
- Live latest feed URL returned the 0.2.31 JSON.
- `flutter test test/update_service_test.dart` passed with 7 tests.
- `flutter analyze` passed for `apps/zentor_client`.


## 2026-06-04 release push 0.2.32

### Requested action

- User asked to push `0.2.32` after the update-feed and driver-remediation fixes.

### Release plan

- Publish a real `v0.2.32` GitHub release with Windows MSI, setup EXE, `.aup`, and `update-feed.json` assets.
- Build the Windows client with `AVORAX_APP_VERSION=0.2.32` and the default GitHub update feed URL.
- Verify tag-specific and `latest` update-feed URLs after publishing.


## 2026-06-04 updater hotfix 0.2.33

### Symptom

- User reported the Updates screen showing `Last error: Bad state: Avorax Update Service failed. Exit code: 1` while updating from 0.2.31 to 0.2.32.

### Evidence

- Installed updater status log showed `manifest signature verification failed` for `--verify`.
- Direct installed-updater verification of the 0.2.32 package succeeds when `--allow-development-key` is supplied.
- Flutter client was invoking `--verify` and `--apply` without `--allow-development-key` even though the build/feed channel is `dev`.
- `setx AVORAX_ALLOW_DEVELOPMENT_UPDATES true` succeeded as a live user-level workaround; the UI must be restarted to inherit it.

### Fix

- Added `_updaterArgsFor` so dev-channel updates append `--allow-development-key` for verify/apply.
- Added Flutter regression coverage for the dev-channel updater argument.
- Plan: publish 0.2.33 with the corrected client and latest update feed.

## 2026-06-26 continuation checkpoint 1241

- Hardened Flutter local `.aup` update package handling so download-time local package copy performs the existing lexical feed-directory containment check and then repeats containment after resolving the existing feed directory and package path canonically.
- Added Dart source-marker coverage and a Python source contract to keep canonical local package containment before `final source = File(...)` and package-byte copy.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`264 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1241-flutter-local-update-package-canonical-containment.md`.
- Flutter/Dart runtime tests and Windows symlink/junction fixture execution remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1242

- Hardened Flutter update metadata downloads so remote update-feed and GitHub release fallback response bodies are collected from `http.StreamedResponse` chunks with accumulated byte-limit checks before constructing a buffered `http.Response`.
- Removed the remaining `http.Response.fromStream` metadata path from the update service.
- Added Dart source-marker coverage and a Python source contract for bounded metadata response streaming.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`265 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1242-flutter-update-metadata-stream-bounds.md`.
- Flutter/Dart runtime tests with oversized/no-`Content-Length` fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1243

- Hardened Flutter local `file:` update-feed parsing so local feed JSON is read through a bounded chunked UTF-8 helper instead of `readAsString()` after a single `length()` check.
- The local feed reader rechecks regular-file status before and after streaming and enforces the configured feed byte limit while accumulating chunks.
- Added Dart source-marker coverage and a Python source contract for bounded local feed file reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`266 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1243-flutter-local-update-feed-stream-bounds.md`.
- Flutter/Dart runtime tests with growing/oversized local feed fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1244

- Hardened Update Service `.aup` payload hashing and extraction so the bytes actually read from ZIP entries are limited, in addition to existing ZIP-declared size validation.
- Added `sha256_reader_limited` and `copy_reader_limited`; extraction now tracks actual aggregate bytes and cleans up staged temp files when per-entry, aggregate-size, or copy failures occur.
- Added a Rust source-marker test and Python source contract for the actual-byte payload boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`267 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1244-update-package-payload-actual-byte-limits.md`.
- Cargo/rustfmt and malformed ZIP fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1245

- Hardened Flutter local `.aup` package copy so the source path is revalidated as a regular file after bounded streaming and before the staged package can be hashed and activated into the update cache.
- Added Dart source-marker coverage and a Python source contract for the post-stream local package source recheck.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`268 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1245-flutter-local-update-package-post-copy-source-recheck.md`.
- Flutter/Dart runtime source-replacement race fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1246

- Hardened Flutter update redirect handling so redirect response bodies are drained through a small bounded helper before following allowed GitHub release redirect hops.
- Replaced unbounded `streamed.stream.drain<void>()` with `_drainBoundedRedirectBody` and documented the redirect-body byte cap.
- Updated Dart source-marker coverage and the Python source contract for remote update package streaming.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`268 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1246-flutter-update-redirect-body-bounds.md`.
- Flutter/Dart runtime redirect-body fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1247

- Hardened Flutter update networking with finite request-send and stream-read timeouts for remote update feed metadata, GitHub release metadata, redirects, and package downloads.
- Added `updateNetworkRequestTimeout` and `updateNetworkReadTimeout`, and routed `_client.send(...)`, remote metadata stream reads, redirect body drains, and downloaded package stream writes through those timeouts.
- Updated Dart source-marker coverage and added a Python source contract for update network timeouts.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`269 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1247-flutter-update-network-timeouts.md`.
- Flutter/Dart stalled request/stream fixture verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1248

- Hardened Flutter update package hashing so staged/cached package hash inputs are size-bounded before SHA-256 streaming.
- `_sha256File` now checks regular-file status, rejects oversized package hash inputs, and revalidates regular-file status before opening the hash stream.
- Added Dart source-marker coverage and a Python source contract for the package hash input bound.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`270 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1248-flutter-update-package-hash-input-bounds.md`.
- Flutter/Dart oversized cached package fixture verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1249

- Hardened Flutter selected-file hashing for protected-app build hash evidence.
- `HashService.sha256ForFile` now rejects oversized selected files before streaming, rechecks non-following file type after `stat()`, and enforces the same size limit against bytes actually read while keeping chunked SHA-256 streaming.
- Updated Dart source-marker coverage and added a Python source contract for selected-file hash bounds.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`271 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1249-flutter-selected-file-hash-bounds.md`.
- Flutter/Dart oversized-file and replacement-race hash fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1250

- Hardened Flutter local event writes so invalid category/severity classifications fail before storage instead of being silently downgraded to `app` or `info`.
- Preserved compatibility fallback for loading existing persisted local history, so old or forged stored rows do not block startup while new audit evidence remains fail-fast.
- Updated Dart regression/source-marker coverage and added a Python source contract for the write-time classification boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`272 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1250-flutter-local-event-write-classification.md`.
- Flutter/Dart runtime tests and formatting remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1251

- Hardened Flutter cloud JSON response handling for health, protection-run creation, heartbeat, end-run, detection-report, and quarantine-metadata calls.
- `ZentorApiClient` now sends requests through `http.Client.send`, bounds `http.StreamedResponse` chunks before building an `http.Response`, checks Content-Length, and applies a finite response-read timeout.
- Removed late `response.bodyBytes.length` size enforcement and direct `_httpClient.get/post` use from the cloud client.
- Updated Dart source-marker coverage and added a Python source contract for streamed cloud response bounds.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`273 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1251-flutter-cloud-response-stream-bounds.md`.
- Flutter/Dart oversized, invalid Content-Length, and stalled response fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1252

- Hardened Guard driver-IPC local SHA-256 evidence hashing.
- `driver_ipc.rs` now reads driver scan candidates in 64 KiB chunks, tracks bytes actually read, and fails visibly above `MAX_DRIVER_HASH_BYTES` instead of using unbounded `std::io::copy` into the hasher.
- Existing non-following regular-file scan-candidate validation remains in front of hashing.
- Updated Rust source-marker coverage and strengthened existing Python source contracts for Guard hashing.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`273 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1252-guard-driver-ipc-hash-byte-limits.md`.
- Cargo/rustfmt and oversized driver scan-candidate fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1253

- Hardened Guard quarantine fallback payload copy.
- `core/zentor_guard_service/src/main.rs` now copies fallback quarantine payload bytes through a bounded chunked helper, rejects payload copies above `MAX_GUARD_QUARANTINE_COPY_BYTES`, and no longer uses direct `io::copy` for this path.
- Partial guard quarantine destinations are cleaned up after copy or sync failures, with cleanup failure context preserved instead of leaving ambiguous partial payload evidence.
- Existing non-following source/destination checks, exclusive destination creation, sync-before-source-delete, and post-copy hash verification remain in place.
- Updated Rust source-marker coverage and added a Python source contract for the bounded copy/partial cleanup boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`274 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1253-guard-quarantine-copy-bounds.md`.
- Cargo/rustfmt and oversized/copy-failure Guard quarantine fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1254

- Hardened native-engine quarantine fallback payload copy.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now copies fallback quarantine payload bytes through a bounded chunked helper, rejects payload copies above `MAX_NATIVE_QUARANTINE_COPY_BYTES`, and no longer uses direct `io::copy` for this path.
- Partial native quarantine destinations are cleaned up after copy or sync failures, with cleanup failure context preserved instead of leaving ambiguous partial payload evidence.
- Existing non-following source/destination checks, exclusive destination creation, sync-before-source-delete, and post-copy hash verification remain in place.
- Updated Rust source-marker coverage and added a Python source contract for the bounded copy/partial cleanup boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`275 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1254-native-quarantine-copy-bounds.md`.
- Cargo/rustfmt and oversized/copy-failure native quarantine fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1255

- Hardened local-core quarantine fallback payload copy.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now copies fallback quarantine payload bytes through a bounded chunked helper, rejects payload copies above `MAX_LOCAL_QUARANTINE_COPY_BYTES`, and no longer uses direct `io::copy` for this path.
- Partial local quarantine destinations are cleaned up after copy or sync failures, with cleanup failure context preserved instead of leaving ambiguous partial payload evidence.
- Existing non-following source/destination checks, exclusive destination creation, sync-before-source-delete, and post-copy hash verification remain in place.
- Updated Rust source-marker coverage and added a Python source contract for the bounded copy/partial cleanup boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`276 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1255-local-quarantine-copy-bounds.md`.
- Cargo/rustfmt and oversized/copy-failure local quarantine fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1256

- Hardened update-service staged file copying.
- `core/avorax_update_service/src/path_safety.rs` now copies staged payload bytes through a bounded chunked helper, rejects staged copies above `MAX_STAGED_FILE_COPY_BYTES`, and no longer uses direct `std::io::copy` for this path.
- Existing staged temp cleanup after copy, sync, or activation failures remains fail-visible.
- Existing path-chain checks, exclusive staged temp creation, sync-before-activation, activation revalidation, and target rechecks remain in place.
- Updated Rust source-marker coverage and added a Python source contract for the bounded staged-copy boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`277 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1256-update-staged-copy-bounds.md`.
- Cargo/rustfmt and oversized staged-copy/apply fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1257

- Hardened local-core legacy migration file copying.
- `core/zentor_local_core/src/migration.rs` now copies migrated file bytes through a bounded chunked helper, rejects migration copies above `MAX_MIGRATION_COPY_BYTES`, and no longer uses direct `io::copy` for this path.
- Existing partial destination cleanup after copy or sync failures remains fail-visible.
- Existing non-following source/destination checks, exclusive destination creation, sync, and size plus SHA-256 verification remain in place.
- Updated Rust source-marker coverage and added a Python source contract for the bounded migration-copy boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`278 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1257-local-migration-copy-bounds.md`.
- Cargo/rustfmt and oversized migration-copy fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1258

- Hardened Recovery Vault backup and restore-staging file copying.
- `core/zentor_local_core/src/protection/recovery_manager.rs` now copies recovery payload bytes through a bounded chunked helper, rejects recovery copies above `MAX_RECOVERY_COPY_BYTES`, and no longer uses direct `io::copy` for this path.
- Partial recovery destinations are cleaned up after copy or sync failures, with cleanup failure context preserved instead of leaving ambiguous partial payload evidence.
- Existing non-following source/backup/hash checks, exclusive destination creation, restore-temp preflight, sync, and size plus SHA-256 verification remain in place.
- Updated Rust source-marker coverage and added a Python source contract for the bounded Recovery Vault copy boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`279 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1258-recovery-vault-copy-bounds.md`.
- Cargo/rustfmt and oversized Recovery Vault copy fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1259

- Hardened Rust update manifest signer input reads.
- `core/avorax_update_service/src/bin/avorax_sign_manifest.rs` now streams manifest bytes through `read_file_bounded`, counts actual bytes read, and no longer uses direct `std::fs::read` for the manifest input.
- Existing manifest path, ancestor, link/reparse, regular-file, declared-size, exclusive signature output, argument strictness, and key-shape validation remain in place.
- Added Python source-contract coverage for actual-byte bounded manifest reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`280 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1259-rust-update-signer-manifest-read-bounds.md`.
- Cargo/rustfmt and oversized/replaced manifest signer fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1260

- Hardened local-core file/app/executable allowlist hashing.
- `core/zentor_local_core/src/allowlist/allowlist_store.rs` now rejects selected allowlist trust targets above `MAX_ALLOWLIST_HASH_BYTES` and tracks actual bytes read while streaming SHA-256.
- Existing non-following regular-file inspection, allowlist store bounded reads, strict entry schemas, env-path validation, staged writes, and cleanup reporting remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded selected-file allowlist hashing.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`281 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1260-local-allowlist-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced selected-file allowlist fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1261

- Hardened local ClamAV compatibility scan hashing.
- `core/zentor_local_core/src/scanner/clamav_provider.rs` now rejects scan hash inputs above `MAX_CLAMAV_HASH_BYTES` and tracks actual bytes read while streaming SHA-256.
- Existing non-following regular-file inspection, bounded local EICAR sampling, bounded ClamAV command output, timeout handling, scanner path validation, and no-ambient-PATH discovery remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded local ClamAV hash inputs.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`282 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1261-local-clamav-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced ClamAV scan-target hash fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1262

- Hardened Guard Service process/quarantine SHA-256 hashing.
- `core/zentor_guard_service/src/main.rs` now rejects Guard hash inputs above `MAX_GUARD_HASH_BYTES` before opening and tracks actual bytes read while streaming SHA-256.
- Existing non-following regular-file inspection, symlink/reparse rejection, Guard quarantine copy bounds, and driver-IPC hash bounds remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded Guard Service hash inputs.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`283 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1262-guard-service-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced Guard process/quarantine hash fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1263

- Hardened Guard self-test SHA-256 hashing.
- `core/zentor_guard_service/src/self_test.rs` now rejects diagnostic hash targets above `MAX_GUARD_SELF_TEST_HASH_BYTES` before opening and tracks actual bytes read while streaming SHA-256.
- Existing self-test symlink/reparse rejection, typed self-test evidence, and bounded AI metadata reads remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded Guard self-test hash inputs.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`284 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1263-guard-self-test-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced Guard self-test hash fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1264

- Hardened native quarantine SHA-256 hashing.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now rejects native quarantine hash inputs above `MAX_NATIVE_QUARANTINE_HASH_BYTES` before opening and tracks actual bytes read while streaming SHA-256.
- Existing non-following payload inspection, exclusive payload-copy bounds, partial cleanup, sync, and destination preflight remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded native quarantine hash inputs.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`285 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1264-native-quarantine-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced native quarantine hash fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1265

- Hardened local-core quarantine SHA-256 hashing.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now rejects local quarantine hash inputs above `MAX_LOCAL_QUARANTINE_HASH_BYTES` before opening and tracks actual bytes read while streaming SHA-256.
- Existing metadata authentication, restore staging, exclusive copy bounds, partial cleanup, sync, and destination preflight remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded local quarantine hash inputs.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`286 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1265-local-quarantine-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced local quarantine hash fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1266

- Hardened local-core main SHA-256 hashing.
- `core/zentor_local_core/src/main.rs` now rejects manual-quarantine, feedback/training, and local-AI threat hash inputs above `MAX_LOCAL_CORE_HASH_BYTES` before opening and tracks actual bytes read while streaming SHA-256.
- Existing non-following scan-target inspection and symlink/reparse rejection remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded local-core main hash inputs.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`287 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1266-local-core-main-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced local-core manual-quarantine/training/AI threat hash fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1267

- Hardened Recovery Vault SHA-256 hashing.
- `core/zentor_local_core/src/protection/recovery_manager.rs` now rejects Recovery Vault hash inputs above `MAX_RECOVERY_HASH_BYTES` before opening and tracks actual bytes read while streaming SHA-256.
- Existing exclusive backup/restore copy bounds, sync, destination preflight, and partial cleanup remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded Recovery Vault hash inputs.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`288 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1267-recovery-vault-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced Recovery Vault hash fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1268

- Hardened local-core legacy migration SHA-256 hashing.
- `core/zentor_local_core/src/migration.rs` now rejects migration hash inputs above `MAX_MIGRATION_HASH_BYTES` before opening and tracks actual bytes read while streaming SHA-256.
- Existing bounded migration copies, exclusive destination creation, sync, staged marker/event writes, and cleanup reporting remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded migration hash inputs.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`289 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1268-local-migration-hash-bounds.md`.
- Cargo/rustfmt and oversized/replaced legacy migration hash fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1269

- Hardened local-core quarantine metadata text reads.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now validates quarantine record, auth sidecar, and metadata-key paths with non-following regular-file metadata before reading.
- The metadata reader rejects declared oversize inputs and tracks actual bytes read while streaming before UTF-8 parsing, authentication, JSON parsing, or metadata-key decoding.
- Existing authenticated metadata, legacy unsigned-record compatibility, staged writes, bounded payload copies, and bounded payload hashing remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded quarantine metadata text reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`290 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1269-local-quarantine-metadata-read-bounds.md`.
- Cargo/rustfmt and oversized/link/replacement local quarantine metadata fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1270

- Hardened Guard Service config and quarantine metadata text reads.
- `core/zentor_guard_service/src/main.rs` now routes guard-mode config, Guard quarantine auth-sidecar, and Guard metadata-key reads through a shared bounded UTF-8 file reader after non-following regular-file metadata validation.
- The shared reader rejects declared oversize inputs and tracks actual bytes read while streaming before config parsing, auth comparison, or metadata-key decoding.
- Existing guard-mode strict JSON/value validation, Guard quarantine metadata-auth write verification, bounded payload copies, and bounded process/quarantine hashing remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded Guard text reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`291 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1270-guard-text-read-bounds.md`.
- Cargo/rustfmt and oversized/link/replacement Guard config and metadata fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1271

- Hardened native signature and rule pack text reads.
- `core/zentor_native_engine/src/signatures/signature_db.rs` and `core/zentor_native_engine/src/rules/rule_parser.rs` now retain non-following regular-file metadata for pack reads, reject declared oversize inputs, and track actual bytes read while streaming before UTF-8 and JSON parsing.
- Existing pack presence checks, sibling enumeration error reporting, strict pack schemas, self-hash validation, duplicate-ID checks, and bounded definition-count/metadata validation remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded native signature/rule pack reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`292 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1271-native-pack-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement native pack fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1272

- Hardened native trust-store and native ML model text reads.
- `core/zentor_native_engine/src/trust/store_io.rs` and `core/zentor_native_engine/src/ml/model_runner.rs` now retain non-following regular-file metadata, reject declared oversize inputs, and track actual bytes read while streaming before UTF-8 and JSON parsing.
- Existing trust-store strict schemas, missing-store compatibility, native ML strict schema and semantic validation, and native model path-safety checks remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded native trust-store and `.zmodel` reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`293 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1272-native-trust-model-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement native trust-store and model fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1273

- Hardened local app-control and persisted allowlist trust-data text reads.
- `core/zentor_local_core/src/app_control/store_io.rs` and `core/zentor_local_core/src/allowlist/allowlist_store.rs` now retain non-following regular-file metadata, reject declared oversize inputs, and track actual bytes read while streaming before UTF-8 and JSON parsing.
- Existing app-control strict schemas, default trust-store discovery checks, allowlist env-path validation, strict persisted allowlist schemas, staged writes, and selected-file hash byte limits remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded local app-control trust-store and persisted allowlist reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`294 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1273-local-trust-store-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement local app-control trust-store and allowlist fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1274

- Hardened Guard Service known-bad cache text reads.
- `core/zentor_guard_service/src/known_bad_cache.rs` now keeps non-following regular-file metadata for present cache files, preserves the missing-cache-as-empty compatibility branch, rejects declared oversize inputs, and tracks actual bytes read while streaming before UTF-8 and JSON parsing.
- Existing known-bad strict schema, hash validation, corrupt-store reporting, default cache discovery checks, and driver/health/self-test error propagation remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded Guard known-bad cache reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`295 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1274-guard-known-bad-cache-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement Guard known-bad cache fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1275

- Hardened local AI and Guard self-test model-metadata text reads.
- `core/zentor_local_core/src/ai/model_runner.rs` and `core/zentor_guard_service/src/self_test.rs` now retain non-following regular-file metadata, reject declared oversize inputs, and track actual bytes read while streaming before UTF-8 and JSON parsing.
- Existing model metadata strict schema, semantic validation, environment/root validation, self-test metadata discovery, and self-test model-status fail-visible parsing remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded local AI and Guard self-test metadata reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`296 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1275-ai-metadata-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement AI metadata fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1276

- Hardened local AI training-label store reads.
- `core/zentor_local_core/src/ai/training_labels.rs` now keeps existing missing-store compatibility, retains non-following regular-file metadata for present JSONL stores, rejects declared oversize inputs, and tracks actual bytes read while streaming before JSONL parsing.
- Existing strict `TrainingLabel`/`StaticFeatures` schemas, newest-label suppression selection, root/env validation, staged writes, exclusive temp files, sync, and cleanup reporting remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded training-label store reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`297 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1276-training-label-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement training-label JSONL fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1277

- Hardened local ransomware-guard persisted config reads.
- `core/zentor_local_core/src/main.rs` now retains non-following regular-file metadata for present `ransomware_guard.json` policy files, rejects declared oversize inputs, and tracks actual bytes read while streaming before UTF-8 and JSON parsing.
- Existing missing-config default behavior, strict persisted config schema/value validation, path-safety checks, staged writes, and protected-root/trusted-process lexical matching remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded ransomware config reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`298 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1277-ransomware-config-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement ransomware config fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1278

- Hardened compatibility YARA rule text reads across local-core, Guard Service, and driver IPC.
- `core/zentor_local_core/src/scanner/yara_provider.rs`, `core/zentor_guard_service/src/main.rs`, and `core/zentor_guard_service/src/driver_ipc.rs` now retain non-following regular-file metadata for present rule files, reject declared oversize inputs, and track actual bytes read while streaming before UTF-8 and rule parsing.
- Existing optional/disabled compatibility posture, default-rule root checks, path-safety checks, malformed-rule diagnostics, confidence/category metadata validation, and local-rule size limits remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded YARA rule reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`299 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1278-yara-rule-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement YARA rule fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1279

- Hardened native signature compiler source JSON reads.
- `core/zentor_native_engine/src/bin/zentor-signature-compiler.rs` now retains non-following regular-file metadata for source JSON, rejects declared oversize inputs, and tracks actual bytes read while streaming before UTF-8 and JSON parsing.
- Existing source link/reparse/non-regular rejection, signature-pack schema validation, checked output directories, existing-target preflight, exclusive UUID temp files, fsync, cleanup, and rename activation remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded native signature compiler source reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`300 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1279-signature-compiler-source-read-bounds.md`.
- Cargo/rustfmt and oversized/replacement native signature compiler source fixtures remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1280

- Hardened local quarantine ACL stderr capture.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now drains the `icacls.exe` stderr pipe while retaining only `MAX_QUARANTINE_COMMAND_OUTPUT_BYTES + 1` bytes for bounded truncation-aware diagnostics.
- Existing checked System32 `icacls.exe` resolution, stdin nulling, stdout discard, bounded error excerpts, and fail-visible ACL errors remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded-drain local quarantine ACL stderr handling.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`301 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1280-local-quarantine-acl-stderr-drain.md`.
- Cargo/rustfmt and Windows ACL stderr fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1281

- Hardened Guard ACL, Guard ClamAV, and local ClamAV command-output readers.
- `core/zentor_guard_service/src/main.rs` and `core/zentor_local_core/src/scanner/clamav_provider.rs` now drain helper stdout/stderr streams while retaining only bounded diagnostic bytes plus a truncation sentinel.
- Existing checked Guard/local scanner discovery, timeouts, stdout/stderr reader threads, timeout kill/reap reporting, ACL System32 resolution, and fail-visible scanner/ACL errors remain in place.
- Added Rust source-marker coverage and Python source contracts for bounded-drain Guard/local command-output handling.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`302 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1281-guard-local-command-output-drain.md`.
- Cargo/rustfmt and noisy-scanner/Windows ACL stderr fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1282

- Hardened update-package manifest and signature ZIP-entry reads.
- `core/avorax_update_service/src/update_package.rs` now streams `manifest.json` and `manifest.sig` entries with actual-byte accounting before UTF-8 conversion, Ed25519 signature decoding, or manifest JSON parsing.
- Existing archive entry-count limits, package path/open revalidation, strict manifest schemas, signature-length validation, payload hash manifest bounds, and payload hash/extraction actual-byte limits remain in place.
- Added Rust source-marker coverage and a Python source contract for actual-byte bounded update manifest/signature ZIP-entry reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`303 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1282-update-manifest-zip-entry-read-bounds.md`.
- Cargo/rustfmt and malformed signed-update package fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1283

- Hardened bounded sample-prefix readers across local heuristic, local YARA, Guard YARA, driver IPC YARA, and local AI static-feature extraction.
- `core/zentor_local_core/src/scanner/heuristic_provider.rs`, `core/zentor_local_core/src/scanner/yara_provider.rs`, `core/zentor_guard_service/src/main.rs`, `core/zentor_guard_service/src/driver_ipc.rs`, and `core/zentor_local_core/src/ai/feature_extractor.rs` now read bounded samples through explicit chunk limits instead of `take(...).read_to_end`.
- Existing non-following regular-file target checks, 1 MiB sample ceilings, YARA rule actual-byte reads, and heuristic/static-feature error propagation remain in place.
- Added a Python source contract for chunk-limited sample-prefix readers.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`304 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1283-sample-prefix-reader-chunk-limits.md`.
- Cargo/rustfmt and sample filesystem fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1284

- Hardened the local ClamAV/EICAR signature precheck sample reader.
- `core/zentor_local_core/src/scanner/clamav_provider.rs` now scans the bounded local signature sample through an explicit chunk limit instead of `reader.by_ref().take(limit)`.
- Existing non-following regular-file target checks, bounded local signature sample size, EICAR/safe-simulator overlap logic, local ClamAV command-output drain, and scan hash byte limits remain in place.
- Added a Python source contract for the chunk-limited local ClamAV signature sample reader.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`305 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1284-local-clamav-signature-sample-chunk-limit.md`.
- Cargo/rustfmt and local ClamAV sample fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1285

- Hardened Guard driver-health external command execution.
- `core/zentor_guard_service/src/driver_health.rs` now runs `sc.exe`, `fltmc.exe`, `bcdedit.exe`, Secure Boot PowerShell, and driver IPC helper probes through a bounded runner that closes stdin, drains stdout/stderr while retaining capped diagnostics, times out hung probes after 30 seconds, and reports kill/reap/read failures visibly.
- Existing checked System32 tool resolution, non-following tool/helper metadata checks, unsupported-platform driver-health reporting, explicit service-absent parsing, and bounded driver-health excerpts remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded driver-health command execution.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`306 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1285-guard-driver-health-command-runner.md`.
- Cargo/rustfmt and Windows driver-health command fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1286

- Hardened Guard process inventory and process-stop subprocess execution.
- `core/zentor_guard_service/src/main.rs` now runs the Windows process inventory PowerShell probe plus Windows `taskkill.exe` and POSIX `kill` stop commands through a bounded runner that closes stdin, drains stdout/stderr while retaining capped diagnostics, times out hung probes after 30 seconds, and reports kill/reap/read failures visibly.
- Existing checked System32 PowerShell/taskkill resolution, fixed absolute POSIX kill candidates, non-following tool/path metadata checks, Windows process JSON byte limits, and process-stop failure reporting remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded Guard process command execution.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`307 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1286-guard-process-command-runner.md`.
- Cargo/rustfmt plus Windows process-query and POSIX/Windows process-stop fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1287

- Hardened native Microsoft Authenticode PowerShell probing.
- `core/zentor_native_engine/src/trust/microsoft_trust.rs` now collects `Get-AuthenticodeSignature` JSON through a bounded runner that closes stdin, drains stdout/stderr while retaining capped diagnostics, times out hung probes after 30 seconds, and reports kill/reap/read failures visibly.
- Existing checked WindowsPowerShell resolution, non-following candidate-file checks, 64 KiB Authenticode JSON parse limit, strict signature JSON shape, and Microsoft subject parsing remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded Authenticode command execution.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`308 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1287-native-authenticode-command-runner.md`.
- Cargo/rustfmt and Windows Authenticode timeout/output fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1288

- Hardened local-core Core/Guard service-status subprocess execution.
- `core/zentor_local_core/src/main.rs` and `core/zentor_local_core/src/protection/guard_service.rs` now run checked `System32\sc.exe query` probes through bounded runners that close stdin, drain stdout/stderr while retaining capped diagnostics, time out hung probes after 30 seconds, and report kill/reap/read failures visibly.
- Existing checked `sc.exe` resolution, non-following candidate metadata checks, unsupported-platform reporting, explicit service-absent parsing, and bounded status-output parsing remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded Core/Guard service-status command execution.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`309 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1288-local-service-status-command-runner.md`.
- Cargo/rustfmt and Windows service-status timeout/output fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1289

- Hardened update-service service-control subprocess execution.
- `core/avorax_update_service/src/service_control.rs` now runs checked `System32\sc.exe start/stop` commands through a bounded runner that closes stdin, drains stdout/stderr while retaining capped diagnostics, times out hung commands after 30 seconds, and reports kill/reap/read failures visibly.
- Existing checked `sc.exe` resolution, service-name token bounds, unsupported-platform failures, and update apply/rollback failure propagation remain in place.
- Added Rust source-marker coverage and a Python source contract for bounded update service-control command execution.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`310 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1289-update-service-control-command-runner.md`.
- Cargo/rustfmt and elevated Windows service-control timeout/output fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1290

- Hardened Flutter local-core scan IPC timeout cleanup evidence.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now includes the `Process.kill()` result in scan IPC timeout errors, reporting either `Termination requested` or `Termination request failed` instead of discarding the child-process termination result.
- Existing bounded IPC stdout/stderr readers, malformed JSON diagnostics, nonzero-exit diagnostics, scan progress parsing, and timeout behavior remain in place.
- Updated the Dart IPC diagnostics test and added a Python source contract for visible local-core IPC timeout kill-result evidence.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`311 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1290-flutter-local-core-ipc-timeout-kill-evidence.md`.
- Flutter/Dart test and formatting remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1291

- Hardened Flutter updater subprocess timeout cleanup evidence.
- `apps/zentor_client/lib/core/updates/update_service.dart` now includes the `Process.kill()` result in updater timeout errors, reporting either `Termination requested` or `Termination request failed` alongside existing bounded stdout/stderr diagnostics.
- Existing checked updater executable discovery, elevated PowerShell launch path, updater process timeout, and bounded diagnostic collection remain in place.
- Updated the Dart update-service source-marker test and added a Python source contract for visible updater timeout kill-result evidence.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`312 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1291-flutter-updater-timeout-kill-evidence.md`.
- Flutter/Dart test and formatting remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-26 continuation checkpoint 1292

- Hardened remaining Flutter subprocess timeout cleanup evidence.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart`, `apps/zentor_client/lib/core/platform/platform_info_service.dart`, and `apps/zentor_client/lib/core/apps/app_detector.dart` now include child-process termination evidence for Guard self-test IPC, cancel IPC, elevated PowerShell helper, platform PowerShell probes, and protected-app process enumeration timeouts.
- Existing checked executable discovery, bounded stdout/stderr readers, timeout behavior, and visible nonzero-exit diagnostics remain in place.
- Updated Dart source-marker tests and added a Python source contract for visible termination evidence on those timeout paths.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`313 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1292-flutter-subprocess-timeout-kill-evidence.md`.
- Flutter/Dart test and formatting remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1293

- Hardened Python release-evidence subprocess timeout cleanup.
- `tools/perf/avorax-benchmark.py` and `tools/zentor_intel/build_realworld_detection_pack.py` now bound timeout cleanup by reporting kill/reap failures and using finite post-kill waits instead of unbounded `wait()` calls.
- Existing bounded stdout/stderr tails, benchmark diagnostics, atomic report activation, real-world pack temp-output handling, and no-live-malware posture remain in place.
- Added Python source-contract coverage for benchmark and real-world detection-pack timeout cleanup failure visibility.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`314 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1293-python-release-subprocess-timeout-cleanup.md`.
- Runtime release-host timeout fixture execution remains blocked until a provisioned host with the required Python release inputs is available.

## 2026-06-27 continuation checkpoint 1294

- Hardened shared PowerShell release/security gate stop cleanup.
- `tools/security/avorax-security-gate-tools.ps1`, `tools/windows/avorax-system32-tools.ps1`, and `tools/windows/zentor-protection-selftest.ps1` now throw visible bounded errors when a killed timeout/output-limited child process does not exit within the 5000 ms post-kill wait.
- Existing bounded temp-file diagnostics, output-size checks, hidden child launch windows, explicit tool paths, and cleanup-on-success behavior remain in place.
- Added Python source-contract coverage for fail-visible unreaped-child cleanup in the shared PowerShell gate stop helpers.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`315 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1294-powershell-gate-stop-cleanup.md`.
- Full release, System32, and elevated protection-self-test timeout fixtures remain blocked until a provisioned Windows validation host is available.

## 2026-06-27 continuation checkpoint 1295

- Hardened live driver-remediation generated post-reboot stop cleanup.
- `tools/windows/avorax-fix-driver-live.ps1` now generates a SYSTEM post-reboot command runner that throws visible cleanup evidence when a killed timeout/output-limited child process does not exit within the 5000 ms post-kill wait.
- Existing generated command output byte limits, temp-file diagnostics, checked embedded System32/install-helper paths, and atomic post-reboot report activation remain in place.
- Added Python source-contract coverage for fail-visible unreaped-child cleanup in the generated post-reboot remediation helper.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`316 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1295-live-remediation-post-reboot-stop-cleanup.md`.
- Elevated live-remediation timeout/output-limit fixtures remain blocked until an approved Windows development VM is available.

## 2026-06-27 continuation checkpoint 1296

- Hardened UEFI firmware reboot helper diagnostics.
- `tools/windows/avorax-open-firmware-settings.ps1` now bounds Secure Boot query failure warnings with `Get-AvoraxBoundedDiagnostic` instead of writing raw exception text before the confirmed firmware reboot path.
- Existing `-ConfirmFirmwareReboot`, administrator requirement, checked System32 `shutdown.exe` lookup, and bounded `shutdown /r /fw` command diagnostics remain in place.
- Added Python source-contract coverage for bounded Secure Boot query warning diagnostics.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`317 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1296-firmware-helper-secure-boot-warning-bounds.md`.
- The firmware reboot helper remains blocked from runtime execution here because it can reboot the machine into UEFI firmware settings.

## 2026-06-27 continuation checkpoint 1297

- Hardened local-core and Guard quarantine ACL command timeouts.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` and `core/zentor_guard_service/src/main.rs` now run checked `icacls.exe` ACL hardening commands with 30 second timeout polling, visible kill/reap cleanup diagnostics, and bounded stderr excerpts on timeout.
- Existing checked System32 tool resolution, stdout discard, bounded stderr drain/readers, and ACL failure reporting remain in place.
- Added Python source-contract coverage for local and Guard ACL timeout cleanup diagnostics.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`318 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1297-quarantine-acl-command-timeouts.md`.
- Cargo/rustfmt and Windows ACL timeout fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1298

- Hardened Guard driver-health child-process cleanup visibility.
- `core/zentor_guard_service/src/driver_health.rs` now reports kill/reap cleanup failures when driver-health command startup loses stdout/stderr pipes or when `try_wait` polling fails, instead of discarding cleanup errors with `let _ = child.kill()` / `let _ = child.wait()`.
- Existing checked System32 tool resolution, bounded stdout/stderr readers, timeout kill/reap diagnostics, probe-error reporting, and bounded driver-health excerpts remain in place.
- Added Python source-contract coverage for driver-health missing-pipe and poll-failure cleanup diagnostics.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`319 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1298-guard-driver-health-cleanup-diagnostics.md`.
- Cargo/rustfmt and Windows driver-health missing-pipe/poll-failure fixture execution remain blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1299

- Hardened live driver-remediation existing-log reads.
- `tools/windows/avorax-fix-driver-live.ps1` now reads existing `latest.log` content through `Read-ExistingLogTextBounded`, using a checked file handle, explicit byte cap, tail seek, complete-read loop, UTF-8 decoding, and existing atomic log activation instead of `[System.IO.File]::ReadAllText`.
- Existing report/log path validation, direct append removal, log block caps, command-output bounds, and generated post-reboot report bounds remain in place.
- Added Python source-contract coverage for bounded live-remediation log reads.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`320 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1299-live-remediation-log-read-bounds.md`.
- Elevated live-remediation log fixture execution remains blocked until an approved Windows development VM is available.

## 2026-06-27 continuation checkpoint 1300

- Hardened Flutter startup background-task error visibility.
- `apps/zentor_client/lib/app/app_state.dart` now launches app detection, malware-engine health check, quarantine refresh, silent update check, and saved protection restore through `_runStartupTask`.
- Unexpected startup-task failures are bounded with `_boundedUiDiagnostic`, recorded as error-severity audit events, and surfaced through `state.errorMessage` instead of becoming detached background future failures.
- Added Python source-contract coverage that verifies the startup tasks use the shared boundary and that the former direct startup invocations are absent.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`321 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1300-flutter-startup-task-error-boundary.md`.
- Flutter/Dart runtime and formatting remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1301

- Hardened Flutter scheduled quick-scan timer error visibility.
- `apps/zentor_client/lib/app/app_state.dart` now routes `Timer.periodic` callbacks through `_runScheduledQuickScanSafely`.
- Unexpected scheduled-scan failures are bounded with `_boundedUiDiagnostic`, recorded as scan error audit events, and surfaced through `state.errorMessage` instead of becoming detached timer future failures.
- Added Python source-contract coverage that verifies the timer callback uses the safe launcher and that the former direct async timer invocation is absent.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`322 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1301-flutter-scheduled-scan-timer-boundary.md`.
- Flutter/Dart timer/runtime verification was blocked in that shell; checkpoint 1565 supersedes this with current-host Flutter timer fixture evidence.

## 2026-06-27 continuation checkpoint 1302

- Hardened Flutter scan orchestration empty-target handling.
- `apps/zentor_client/lib/app/app_state.dart` now checks `_scanPaths` for an empty target list before setting scan-start in-flight state or reading `paths.first`.
- Empty scan targets produce a visible `completedWithErrors` report, warning audit event, cleared current-scan path, and UI error message instead of a possible uncaught range failure.
- Added Python source-contract coverage that verifies the guard appears before `paths.first` and before `_scanStartInFlight = true`.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`323 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1302-flutter-empty-scan-targets.md`.
- Flutter/Dart runtime scan-controller verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1303

- Hardened Flutter scan-target environment root parsing.
- `apps/zentor_client/lib/core/scanning/scan_target_service.dart` now rejects environment roots containing `..` path segments before accepting them as absolute local quick/full scan target roots.
- Existing remote/relative environment-root rejection, non-following target probes, visible probe limitations, and local-core final validation remain in place.
- Extended Python source-contract coverage for scan-target planning environment parent-traversal rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`323 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1303-flutter-scan-target-env-parent-traversal.md`.
- Flutter/Dart formatting and runtime scan-target fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1304

- Hardened Flutter scan-target environment root NUL handling.
- `apps/zentor_client/lib/core/scanning/scan_target_service.dart` now rejects environment roots containing NUL before accepting them as absolute local quick/full scan target roots.
- Existing remote/relative and parent-traversal environment-root rejection, non-following target probes, visible probe limitations, and local-core final validation remain in place.
- Extended Python source-contract coverage for scan-target planning environment NUL rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`323 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1304-flutter-scan-target-env-nul.md`.
- Flutter/Dart formatting and runtime scan-target fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1305

- Hardened Flutter Windows helper root validation.
- `apps/zentor_client/lib/core/platform/platform_info_service.dart`, `apps/zentor_client/lib/core/apps/app_detector.dart`, `apps/zentor_client/lib/core/updates/update_service.dart`, and `apps/zentor_client/lib/core/local_core/local_core_client.dart` now reject NUL-containing or parent-traversing `SystemRoot`/`WINDIR` values before building WindowsPowerShell, `tasklist.exe`, Explorer, or elevation launcher paths.
- Existing no-ambient-PATH lookup, no silent `C:\Windows` fallback, checked regular-file probes, bounded stdout/stderr, and timeout kill-result evidence remain in place.
- Added Python source-contract coverage for all four Flutter Windows helper root boundaries.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`324 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1305-flutter-windows-helper-root-validation.md`.
- Flutter/Dart formatting and Windows helper runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1306

- Hardened Flutter local-core environment override path validation.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now rejects NUL-containing or parent-traversing values for Core/Guard executable overrides and ProgramData/ProgramFiles-derived install/report roots before accepting them as absolute local paths.
- Existing absolute-local checks, regular-file probes, executable-parent validation, install-report allowed-root validation, and visible validation errors remain in place.
- Added Python source-contract coverage for local-core executable and directory environment override validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`325 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1306-flutter-local-core-env-overrides.md`.
- Flutter/Dart formatting and local-core Windows UI runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1307

- Hardened Flutter app-detector known install-root environment validation.
- `apps/zentor_client/lib/core/apps/app_detector.dart` now rejects NUL-containing or parent-traversing `ProgramFiles`, `ProgramFiles(x86)`, and `HOME` values before planning protected-app search paths.
- Existing missing/blank optional-root handling, relative/remote root filtering, non-following install-path probes, and visible app-detection failure propagation remain in place.
- Added Python source-contract coverage for app-detector known-root NUL and parent-traversal rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`326 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1307-flutter-app-detector-known-root-validation.md`.
- Flutter/Dart formatting and protected-app UI runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1308

- Hardened Flutter platform-info environment fallback text.
- `apps/zentor_client/lib/core/platform/platform_info_service.dart` now routes `USER`, `USERNAME`, `USERDOMAIN`, and `PROCESSOR_ARCHITECTURE` fallback values through bounded platform string parsing before they populate device user, permissions, or architecture evidence.
- `_boundedPlatformString` now normalizes control and NUL characters to spaces before trimming and length-bounding, so PowerShell JSON fields, diagnostics, service-state values, and environment fallback evidence share the same UI-safe text boundary.
- Added Python source-contract coverage for platform-info environment fallback bounds and normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`327 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1308-flutter-platform-env-fallback-bounds.md`.
- Flutter/Dart formatting and platform-info runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1309

- Hardened Flutter app-detection diagnostics.
- `apps/zentor_client/lib/core/apps/app_detector.dart` now normalizes control and NUL characters before bounding process-list, process-launch, and install-path probe diagnostics.
- Existing bounded process output collection, timeout kill-result evidence, checked command paths, and visible app-detection failure propagation remain in place.
- Added Python source-contract coverage for app-detection diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`328 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1309-flutter-app-detector-diagnostic-normalization.md`.
- Flutter/Dart formatting and app-detection process/probe runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1310

- Hardened Flutter local-event recovery diagnostics.
- `apps/zentor_client/lib/core/logging/local_event_repository.dart` now normalizes control and NUL characters before bounding persisted-history decode, cleanup, malformed-row, and maintenance diagnostics that can become local audit recovery events.
- Existing local-event write/clear acknowledgements, recovery detail preservation, row-level malformed record evidence, and export path safety remain in place.
- Added Python source-contract coverage for local-event recovery diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`329 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1310-flutter-local-event-diagnostic-normalization.md`.
- Flutter/Dart formatting and local-event recovery runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1311

- Hardened Flutter app-state controller diagnostics.
- `apps/zentor_client/lib/app/app_state.dart` now normalizes control and NUL characters before bounding the shared `_boundedUiDiagnostic` output used by scan, update, quarantine, allowlist, protection, cloud, app-detection, settings, onboarding, and startup error paths.
- Existing controller catch blocks, visible UI error state, local-event failure details, and exact truncation behavior remain in place.
- Added Python source-contract coverage for controller-wide UI diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`330 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1311-flutter-app-state-diagnostic-normalization.md`.
- Flutter/Dart formatting and controller runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1312

- Hardened Flutter update-service diagnostics.
- `apps/zentor_client/lib/core/updates/update_service.dart` now normalizes control and NUL characters before bounding `_boundedUpdateCheckError` output used by update check, feed fallback, package download, cleanup, rollback, and file-probe failures.
- Existing updater fallback text, diagnostic length cap, and truncation behavior remain in place.
- Added Python source-contract coverage for update-service diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`331 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1312-flutter-update-service-diagnostic-normalization.md`.
- Flutter/Dart formatting and update-service runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1313

- Hardened Flutter scan-target probe diagnostics.
- `apps/zentor_client/lib/core/scanning/scan_target_service.dart` now normalizes all ASCII control and NUL characters before bounding `_boundedScanTargetDiagnostic` output used in quick/full scan target inspection limitations.
- Existing scan-target inclusion behavior, non-following probes, unknown-error fallback, whitespace collapse, and exact truncation behavior remain in place.
- Added Python source-contract coverage and a Flutter source-marker assertion for scan-target diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`332 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1313-flutter-scan-target-diagnostic-normalization.md`.
- Flutter/Dart formatting and scan-target runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1314

- Hardened Flutter config-recovery diagnostics.
- `apps/zentor_client/lib/core/config/config_repository.dart` now normalizes all ASCII control and NUL characters before bounding `_boundedConfigRecoveryDiagnostic` output used in persisted-policy recovery reasons.
- Existing config validation, recovery fallback text, diagnostic length cap, and truncation behavior remain in place.
- Added Python source-contract coverage and a Flutter source-marker assertion for config-recovery diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`333 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1314-flutter-config-recovery-diagnostic-normalization.md`.
- Flutter/Dart formatting and config-recovery runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1315

- Hardened Flutter Settings and Device feature diagnostics.
- `apps/zentor_client/lib/features/settings/settings_screen.dart` and `apps/zentor_client/lib/features/device/device_screen.dart` now normalize all ASCII control and NUL characters before bounding feature-level visible diagnostic text.
- Existing fallback text, diagnostic length caps, export-log error handling, Device provider error handling, and truncation behavior remain in place.
- Added Python source-contract coverage and Flutter source-marker assertions for Settings and Device diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/client-ui.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`334 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1315-flutter-feature-diagnostic-normalization.md`.
- Flutter/Dart formatting and Settings/Device runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1316

- Hardened Flutter shell notification summaries.
- `apps/zentor_client/lib/shared/widgets/zentor_shell.dart` now normalizes all ASCII control and NUL characters before whitespace-collapsing and bounding local-event notification text.
- Existing notification event selection, one-line display, notification length cap, and truncation behavior remain in place.
- Added Python source-contract coverage and a Flutter source-marker assertion for notification text normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/client-ui.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`335 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1316-flutter-shell-notification-normalization.md`.
- Flutter/Dart formatting and shell notification runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1317

- Hardened Flutter cloud API diagnostics.
- `apps/zentor_client/lib/core/network/zentor_api_client.dart` now normalizes all ASCII control and NUL characters before bounding `_cloudDiagnosticText` output used by cloud network, acknowledgement, and health-check failures.
- Existing cloud optionality, fallback text, diagnostic length cap, streamed response bounds, and truncation behavior remain in place.
- Added Python source-contract coverage and a Flutter source-marker assertion for cloud diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`336 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1317-flutter-cloud-diagnostic-normalization.md`.
- Flutter/Dart formatting and cloud runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1318

- Hardened Flutter updater subprocess diagnostics.
- `apps/zentor_client/lib/core/updates/update_service.dart` now normalizes all ASCII control and NUL characters in updater stdout/stderr text before adding labels and bounding the combined update-service diagnostic.
- Existing timeout kill-result evidence, stdout/stderr labels, diagnostic length cap, and truncation behavior remain in place.
- Added Python source-contract coverage and a Flutter source-marker assertion for updater subprocess diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`337 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1318-flutter-updater-subprocess-diagnostic-normalization.md`.
- Flutter/Dart formatting and updater subprocess runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1319

- Hardened Flutter local-core IPC diagnostics.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now normalizes all ASCII control and NUL characters in `_ipcDiagnosticOrNull` before diagnostic truncation.
- Existing status/enum parsing, path validation, max diagnostic length, and truncation behavior remain in place.
- Added Python source-contract coverage and a Flutter source-marker assertion for local-core IPC diagnostic normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`338 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1319-flutter-local-core-ipc-diagnostic-normalization.md`.
- Flutter/Dart formatting and local-core IPC runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1320

- Hardened Flutter cloud response strings.
- `apps/zentor_client/lib/core/network/zentor_api_client.dart` now normalizes all ASCII control and NUL characters in `_boundedCloudString` before cloud health status and write-ack rejection strings are truncated or emitted.
- Existing cloud response byte limits, acknowledgement parsing, ID-token validation, diagnostic length caps, and exception diagnostic normalization remain in place.
- Added Python source-contract coverage and a Flutter source-marker assertion for cloud response string normalization.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`339 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1320-flutter-cloud-response-string-normalization.md`.
- Flutter/Dart formatting and cloud runtime fixtures remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1321

- Hardened cloud outbound configuration and metadata validation.
- `packages/zentor_protocol/lib/zentor_protocol.dart` now rejects ASCII control and NUL characters in cloud endpoint, project ID, and public client key text during config validation and config JSON parsing.
- `apps/zentor_client/lib/core/network/zentor_api_client.dart` now rejects ASCII control and NUL characters in outbound cloud metadata strings before detection or quarantine telemetry payloads are serialized.
- Existing cloud optionality, endpoint URL validation, length caps, SHA-256 validation, response parsing, and response diagnostic normalization remain in place.
- Added Python source-contract coverage plus Dart/Flutter source-marker fixtures for config and outbound metadata validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`340 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1321-cloud-outbound-control-text-rejection.md`.
- Flutter/Dart/package runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1322

- Hardened shared config string-list parsing.
- `packages/zentor_protocol/lib/zentor_protocol.dart` now rejects ASCII control and NUL characters in persisted `scanPaths`, `ransomwareProtectedRoots`, and `ransomwareTrustedProcesses` entries before local policy is restored.
- Existing trimming, blank-entry rejection, entry-count limits, and per-entry length limits remain in place.
- Added Python source-contract coverage plus Dart/Flutter source-marker fixtures for persisted config string-list control-character rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`341 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1322-shared-config-string-list-control-text-rejection.md`.
- Flutter/Dart/package runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1323

- Hardened raw shared control-text validation before trimming.
- `packages/zentor_protocol/lib/zentor_protocol.dart` now checks raw cloud endpoint/project/key strings and raw config string-list entries for ASCII control and NUL characters before trimming.
- `packages/zentor_protocol/lib/zentor_protocol.dart` now rejects ASCII control and NUL characters in protected-app identity fields before app name, path, source/platform/profile, or SHA-256 helpers can trim them.
- `apps/zentor_client/lib/core/network/zentor_api_client.dart` now checks raw outbound cloud metadata strings for ASCII control and NUL characters before trimming and serializing them.
- Added Python source-contract coverage plus Dart/Flutter source-marker fixtures for raw control-text rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`342 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1323-shared-raw-control-text-rejection.md`.
- Flutter/Dart/package runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1324

- Hardened runtime ransomware path-list settings.
- `apps/zentor_client/lib/app/app_state.dart` now rejects ASCII control and NUL characters in raw runtime protected-root and trusted-process entries before trimming, backslash normalization, deduplication, persistence, or shared guard policy writes.
- Existing blank-entry filtering, duplicate removal, entry-count limits, and per-entry length limits remain in place.
- Added Python source-contract coverage plus Flutter source-marker fixtures for runtime path-list control-character rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`343 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1324-runtime-path-list-control-text-rejection.md`.
- Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1325

- Hardened shared LocalEvent parsing.
- `packages/zentor_protocol/lib/zentor_protocol.dart` now rejects ASCII control and NUL characters in raw persisted LocalEvent ID, type, message, details, timestamp, category, and severity strings before trimming or optional fallback handling.
- Existing required-field checks, timestamp parsing, category/severity allowlists, optional fallback compatibility, and length caps remain in place.
- Added Python source-contract coverage plus protocol/client config test fixtures for raw LocalEvent control-character rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`344 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1325-local-event-raw-control-text-rejection.md`.
- Dart/package/Flutter runtime tests remain blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1326

- Hardened Flutter LocalEventRepository raw text handling.
- `apps/zentor_client/lib/core/logging/local_event_repository.dart` now rejects ASCII control and NUL characters in persisted local-event ID, type, message, details, timestamp, category, and severity strings while loading history.
- New local-event writes now reject ASCII control and NUL characters in type, message, details, category, and severity before trimming, truncation, classification fallback, or storage.
- Existing malformed-row recovery, valid-neighbor preservation, unsupported legacy category/severity fallback, write acknowledgements, clear acknowledgements, export safety, and diagnostic normalization remain in place.
- Added Python source-contract coverage plus Flutter local-event source-marker fixtures for raw LocalEventRepository control-character rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`345 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1326-flutter-local-event-repository-raw-control-text-rejection.md`.
- Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1327

- Hardened Flutter LocalEventRepository persisted history length handling.
- `apps/zentor_client/lib/core/logging/local_event_repository.dart` now validates persisted local-event ID, type, message, and details length before constructing local audit-history rows.
- Oversized persisted ID/type/message/details values are treated as malformed rows with recovery evidence instead of being silently truncated into different visible/exported audit evidence.
- Existing new-event text truncation for app-generated type/message/details, malformed-row recovery, valid-neighbor preservation, timestamp bounds, control/NUL rejection, and legacy category/severity fallback compatibility remain in place.
- Added Python source-contract coverage plus Flutter local-event source-marker fixtures for persisted oversized text rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`346 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1327-flutter-local-event-repository-oversized-text-rejection.md`.
- Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1328

- Hardened Flutter LocalEventRepository persisted row-count handling.
- `apps/zentor_client/lib/core/logging/local_event_repository.dart` now rejects persisted local-event JSON arrays with more than 1000 records before per-row parsing begins.
- Excessive persisted row counts now produce visible local-event recovery evidence instead of spending unbounded CPU/RAM before the 200-row retention cap can apply.
- Existing 200-row newest-first retention for ordinary histories, byte-size JSON cap, malformed-row recovery, valid-neighbor preservation, timestamp bounds, control/NUL rejection, and oversized-text rejection remain in place.
- Added Python source-contract coverage plus Flutter local-event source-marker fixtures for pre-iteration row-count rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`347 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1328-flutter-local-event-repository-row-count-cap.md`.
- Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1329

- Hardened Flutter LocalEventRepository log-export body limits.
- `apps/zentor_client/lib/core/logging/local_event_repository.dart` now rejects encoded local-event export JSON bodies larger than 2 MiB.
- Oversized export bodies fail before temporary-file allocation and are rechecked before the reserved writer opens the staged output file.
- Existing export confirmation, controller single-flight behavior, non-following target checks, exclusive temp reservation, reserved writer flush, rename activation, cleanup-failure visibility, 200-row retention, and persisted history input caps remain in place.
- Added Python source-contract coverage plus Flutter local-event source-marker fixtures for export body-size rejection.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`348 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1329-flutter-local-event-export-body-size-cap.md`.
- Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1330

- Hardened Flutter log-export success path text.
- `apps/zentor_client/lib/app/app_state.dart` now routes successful export paths through `_boundedExportPath`, which reuses the shared UI diagnostic normalizer to bound and control/NUL-normalize path text before audit details or snackbar/UI return text use it.
- Existing export confirmation, controller single-flight behavior, repository body-size cap, non-following target checks, exclusive temp reservation, reserved writer flush, rename activation, and cleanup-failure visibility remain in place.
- Added Python source-contract coverage plus Flutter local-event source-marker fixtures for bounded export success path text.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`349 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1330-flutter-log-export-success-path-bounds.md`.
- Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1331

- Hardened Flutter LocalEventRepository host-scoped storage keying.
- `apps/zentor_client/lib/core/logging/local_event_repository.dart` now routes `Platform.localHostname` through `_eventsHostKeySegment` before constructing the host-scoped SharedPreferences key.
- Host key segments are lowercased, safe-tokenized to `[a-z0-9._-]`, stripped of leading/trailing separators, bounded to 128 characters, and given an `unknown-host` fallback when empty.
- Existing legacy unsuffixed history fallback/migration, current-host authoritative behavior, storage acknowledgements, malformed-row recovery, and export safety remain in place.
- Added Python source-contract coverage plus Flutter local-event source-marker fixtures for safe bounded host key segments.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`350 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1331-flutter-local-event-host-key-segment.md`.
- Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1332

- Hardened Flutter quarantine restore/delete path evidence.
- `apps/zentor_client/lib/app/app_state.dart` now routes quarantine `originalPath` through `_boundedQuarantinePath`, reusing the shared UI diagnostic normalizer before confirmation, requested/success/failure audit details, duplicate-action busy details, and visible restore/delete error text.
- Local-core restore/delete IPC still targets the validated `quarantineId`; local-core metadata authentication, payload integrity, absolute restore-path, parent-link, conflict, and staged-restore checks remain the filesystem enforcement boundary.
- Added Python source-contract coverage plus a Flutter source-marker fixture for bounded quarantine action path text.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`351 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1332-flutter-quarantine-action-path-bounds.md`.
- Flutter/Dart runtime tests remain blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1333

- Hardened local-core quarantine restore original-path metadata validation.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now routes persisted `record.original_path` through `validate_original_restore_path_text` before filesystem path use.
- The helper rejects blank values, NUL characters, oversized values, explicit `.` or `..` path segments, non-absolute paths, and paths without a file-name leaf before restore conflict/preflight/staging logic runs.
- Existing local-core restore confirmation, payload integrity, parent-link rejection, destination conflict rejection, staged restore activation, and quarantine-ID targeting remain in place.
- Added Rust regression coverage plus Python source-contract coverage for the new restore-path text boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`352 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1333-local-quarantine-restore-original-path-text.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1334

- Hardened local-core quarantine payload-path metadata validation for restore and delete.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now routes persisted `record.quarantine_path` through `validate_quarantine_payload_path_text` before filesystem path use in restore/delete.
- The helper rejects blank values, NUL characters, oversized values, explicit `.` or `..` path segments, non-absolute paths, paths without a file-name leaf, and extensions other than `.avoraxq` before canonical containment, symlink/reparse, payload-integrity, restore, or delete checks run.
- Existing canonical quarantine-store containment, payload symlink/reparse rejection, payload integrity checks, staged restore, and delete-by-validated-ID behavior remain in place.
- Added Rust regression coverage plus Python source-contract coverage for the new payload-path text boundary.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`353 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1334-local-quarantine-payload-path-text.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1335

- Hardened local-core quarantine listing path evidence.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now validates authenticated metadata `original_path` and `quarantine_path` with the same text-boundary helpers during `list()` before returning records.
- Unsafe persisted path metadata now fails visibly with contextual `invalid original path` or `invalid payload path` quarantine metadata errors instead of leaving later restore/delete or Flutter parsing as the first boundary.
- Existing authenticated metadata verification, quarantine ID validation, restore/delete confirmation, payload integrity, and canonical store containment remain in place.
- Added Rust regression coverage plus Python source-contract coverage for list-time restore/payload path validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`354 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1335-local-quarantine-list-path-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1336

- Hardened local-core quarantine listing field evidence.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now validates authenticated metadata SHA-256, detection name, engine, source, action, and optional user-note fields before returning records.
- Malformed persisted hashes, blank required labels, oversized labels, NUL characters, or other control characters now fail visibly with contextual `invalid quarantine metadata fields` errors instead of rendering forged UI/audit evidence.
- Existing authenticated metadata verification, quarantine ID validation, list-time path validation, restore/delete confirmation, payload integrity, and canonical store containment remain in place.
- Added Rust regression coverage plus Python source-contract coverage for list-time hash/display-field validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`355 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1336-local-quarantine-metadata-field-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1337

- Aligned local-core quarantine Rust regression expectations with the current `.avoraxq` payload policy.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` no longer keeps tests named as though legacy `.zentorq` or older extension records remain readable in the local-core Recovery Vault path.
- The updated Rust regressions now expect legacy payload extensions to fail visibly during `list()` with `invalid payload path` and `quarantine payload has unsafe extension` evidence.
- Added Python source-contract coverage so the stale readable-legacy regression names and expectations do not silently return.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`356 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1337-local-quarantine-legacy-extension-regressions.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1338

- Hardened local-core quarantine write-time metadata handling.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now normalizes untrusted scanner detection/engine labels before the quarantine payload is moved or copied.
- `write_record` now validates quarantine ID, restore path text, payload path text, SHA-256, display fields, source/action fields, and optional user note before serialization or staged JSON/auth writes.
- Invalid direct metadata writes fail before `record.json` or `record.json.auth` can be created, while scanner-provided label control characters are bounded/normalized instead of orphaning a moved payload.
- Added Rust regression coverage plus Python source-contract coverage for pre-move label normalization and pre-persistence record validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`358 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1338-local-quarantine-write-time-metadata.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1339

- Hardened local-core quarantine store status preflight.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now rejects `Clean`, `Error`, and `EngineUnavailable` scan results before quarantine directory creation, source inspection, hashing, or payload move/copy.
- This makes `QuarantineStore::quarantine_file` fail closed if a caller is miswired, while preserving the manual quarantine command path that intentionally constructs an `Infected` result.
- Added Rust regression coverage plus Python source-contract coverage for the pre-filesystem status guard.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`359 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1339-local-quarantine-status-preflight.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1340

- Hardened native-engine quarantine metadata field handling.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now bounds and control-normalizes detection labels before native payload movement.
- Native quarantine records now validate SHA-256, detection name, engine, and action fields before staged metadata writes.
- Existing native payload integrity verification, exclusive copy fallback, hash byte limits, staged metadata activation, and unsupported native restore behavior remain in place.
- Added Rust regression coverage plus Python source-contract coverage for pre-move label normalization and native record-field validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`361 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1340-native-quarantine-metadata-field-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1341

- Hardened Guard quarantine metadata field handling.
- `core/zentor_guard_service/src/main.rs` now bounds and control-normalizes Guard threat reason/engine labels before payload movement.
- Guard quarantine records now validate ID, SHA-256, detection name, engine, action, source, and optional user note before staged metadata/auth writes.
- Existing Guard source/destination hash verification, exclusive copy fallback, metadata-auth sidecar verification, bounded metadata reads, and ACL hardening remain in place.
- Added Rust regression coverage plus Python source-contract coverage for pre-move Guard label normalization and Guard record-field validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`363 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1341-guard-quarantine-metadata-field-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1342

- Hardened native-engine quarantine record path validation.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now validates native `original_path` and payload `quarantine_path` text before quarantine directory creation, payload move/copy, or staged metadata writes.
- The native record-path helper rejects blank values, NUL characters, control characters, oversized values, explicit `.` or `..` path segments, non-absolute paths, paths without a file-name leaf, and non-`.avoraxq` payload extensions.
- Native record validation reuses the same path boundary before accepting staged metadata evidence, while existing detection-label normalization, SHA-256 validation, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Rust regression coverage plus Python source-contract coverage for native pre-move path validation and pre-write record path validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`364 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1342-native-quarantine-record-path-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1343

- Hardened Guard quarantine record path validation.
- `core/zentor_guard_service/src/main.rs` now validates Guard `original_path` and payload `quarantine_path` text before quarantine directory hardening, payload move/copy, or staged metadata/auth writes.
- The Guard record-path helper rejects blank values, NUL characters, control characters, oversized values, explicit `.` or `..` path segments, non-absolute paths, paths without a file-name leaf, and non-`.avoraxq` payload extensions.
- Guard record validation reuses the same path boundary before accepting staged metadata/auth evidence, while existing threat-label normalization, SHA-256 validation, payload integrity verification, exclusive copy fallback, bounded metadata/auth reads, and ACL hardening remain in place.
- Added Rust regression coverage plus Python source-contract coverage for Guard pre-move path validation and pre-write record path validation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`365 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1343-guard-quarantine-record-path-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1344

- Hardened Guard quarantine expected-hash preflight.
- `core/zentor_guard_service/src/main.rs` now normalizes the expected SHA-256 passed to `quarantine_file` and rejects malformed values before quarantine root resolution, directory hardening, source metadata reads, source hashing, or payload move/copy.
- Guard source and destination hash comparisons now compare normalized SHA-256 bodies while preserving the existing `sha256:<hex>` record evidence format.
- Existing Guard path validation, threat-label normalization, payload integrity verification, exclusive copy fallback, bounded metadata/auth reads, and ACL hardening remain in place.
- Added Rust regression coverage plus Python source-contract coverage for invalid expected-hash preflight ordering.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`366 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1344-guard-quarantine-expected-hash-preflight.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1345

- Hardened Guard quarantine copy fallback expected-hash preflight.
- `core/zentor_guard_service/src/main.rs` now normalizes the expected SHA-256 passed directly to `copy_then_remove_verified` and rejects malformed values before source inspection, destination inspection, or payload copy.
- Guard fallback destination hash comparisons now normalize destination hash evidence before comparison, so valid bare and prefixed expected hashes are accepted consistently while malformed values fail closed.
- Existing Guard quarantine entrypoint hash preflight, path validation, threat-label normalization, payload integrity verification, exclusive copy fallback, bounded metadata/auth reads, and ACL hardening remain in place.
- Added Rust regression coverage plus Python source-contract coverage for fallback invalid expected-hash ordering and bare-hash compatibility.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`367 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1345-guard-quarantine-copy-fallback-hash-preflight.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1346

- Hardened local-core quarantine copy fallback expected-hash evidence.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now reports malformed fallback expected SHA-256 values with explicit `invalid local quarantine copy expected sha256` context before source inspection, destination inspection, or payload copy.
- Local-core fallback keeps accepting valid bare and prefixed expected hashes through the shared normalizer before comparing against destination hash evidence.
- Existing local status preflight, record path validation, metadata normalization, payload integrity verification, exclusive copy fallback, bounded metadata/auth reads, and ACL hardening remain in place.
- Added Rust regression coverage plus Python source-contract coverage for fallback invalid expected-hash ordering and bare-hash compatibility.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`368 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1346-local-quarantine-copy-fallback-hash-preflight.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1347

- Hardened native-engine quarantine copy fallback expected-hash evidence.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now reports malformed fallback expected SHA-256 values with explicit `invalid native quarantine copy expected sha256` context before source inspection, destination inspection, or payload copy.
- Native fallback keeps accepting valid bare and prefixed expected hashes through the shared normalizer before comparing against destination hash evidence.
- Existing native record path validation, metadata normalization, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Rust regression coverage plus Python source-contract coverage for fallback invalid expected-hash ordering and bare-hash compatibility.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`369 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1347-native-quarantine-copy-fallback-hash-preflight.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1348

- Hardened native-engine quarantine entrypoint expected-hash preflight.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now hashes the source and rejects stale expected SHA-256 values before quarantine directory creation, destination preflight, or payload move/copy.
- Native post-move verification now compares the quarantined payload hash against the pre-move source hash and records the verified quarantined hash after the comparison.
- Existing native record path validation, metadata normalization, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Rust regression coverage plus Python source-contract coverage for stale source-hash preflight ordering.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`370 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1348-native-quarantine-source-hash-preflight.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1349

- Hardened native-engine quarantine root handling.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now routes native quarantine root creation through `ensure_native_quarantine_root_directory`, then inspects the root without following links.
- Native quarantine roots that are symlinks, Windows reparse points, non-directories, or uninspectable paths now fail before payload destination preflight or payload move/copy.
- Existing native source-hash preflight, record path validation, metadata normalization, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Unix Rust regression coverage plus Python source-contract coverage for root validation ordering and link/reparse/non-directory rejection markers.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`371 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1349-native-quarantine-root-directory-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1350

- Hardened native-engine quarantine payload permissions.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now calls `remove_executable_permissions(&quarantine_path)?` after the moved/copied payload is validated as a regular quarantine destination and before the quarantined payload is hashed or recorded.
- The native helper strips POSIX execute bits where Unix permissions apply and is an explicit no-op on non-Unix targets, matching the current local-core/Guard source posture without making unverified Windows non-executable claims.
- Existing native source-hash preflight, root validation, record path validation, metadata normalization, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Unix Rust regression coverage plus Python source-contract coverage for executable-bit stripping and ordering before hash/record acceptance.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`372 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1350-native-quarantine-non-executable-payload.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1351

- Hardened native-engine quarantine metadata write bounds.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now caps staged native quarantine metadata at `MAX_NATIVE_QUARANTINE_METADATA_BYTES` before deriving a temporary metadata path or opening a staged file.
- Oversized metadata bytes fail visibly with `native quarantine metadata exceeds maximum length`, and the regression asserts no final or temporary metadata artifact is left behind.
- Existing native source-hash preflight, root validation, executable-bit stripping, record path validation, metadata field normalization, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Rust regression coverage plus Python source-contract coverage for metadata byte-limit ordering before temp-file creation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`373 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1351-native-quarantine-metadata-write-byte-limit.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-27 continuation checkpoint 1352

- Hardened native-engine quarantine metadata parent validation.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now rechecks the metadata parent directory as an existing non-linked directory before temporary metadata writes and again before final metadata activation.
- The metadata parent check does not recreate a missing parent, reducing the chance of writing metadata into a newly created or redirected root that is detached from the quarantined payload.
- Existing native source-hash preflight, root validation, executable-bit stripping, record path validation, metadata field/byte limits, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Unix Rust regression coverage plus Python source-contract coverage for linked metadata-parent rejection and ordering before temp write/final activation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`374 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1352-native-quarantine-metadata-parent-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1353

- Hardened native-engine quarantine metadata final activation.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now treats an existing final metadata destination as a visible conflict instead of removing and replacing it before staged activation.
- Existing symlink/reparse/non-file destination rejection remains in place, while ordinary existing final metadata stays unchanged and the staged temporary file is cleaned up on preflight failure.
- Existing native source-hash preflight, root validation, executable-bit stripping, record path validation, metadata field/byte limits, metadata parent revalidation, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Rust regression coverage plus Python source-contract coverage for final metadata destination exclusivity and absence of `fs::remove_file(path)` in the destination preflight helper.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`375 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1353-native-quarantine-metadata-final-destination-exclusive.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1354

- Hardened native-engine quarantine root ACL handling on Windows.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now calls `harden_native_quarantine_root_acl(path)?` after native quarantine root creation/non-link validation and before payload destination preflight.
- The native ACL helper resolves `icacls.exe` through checked local System32 roots derived from `SystemRoot`/`WINDIR`, rejects NUL/parent-traversal/remote roots, rejects linked/reparse/non-file tool candidates, closes stdin, discards stdout, drains bounded stderr, and times out hung ACL commands with kill/reap diagnostics.
- Existing native source-hash preflight, root validation, executable-bit stripping, record path validation, metadata field/byte limits, metadata parent revalidation, final metadata exclusivity, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for checked System32 `icacls.exe` launch, bounded stderr, timeout handling, and absence of ambient `Command::new("icacls")`.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`376 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1354-native-quarantine-windows-acl-hardening.md`.
- Cargo/rustfmt and Windows ACL runtime verification remain blocked because `cargo`, `rustfmt`, and a provisioned Windows ACL fixture host are not available in this shell.

## 2026-06-28 continuation checkpoint 1355

- Hardened native-engine quarantine post-move finalization cleanup.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now wraps post-move payload validation, executable-bit stripping, hash verification, record validation, and staged metadata writes in a finalization block.
- If finalization fails after the payload has been moved/copied into quarantine, the native store attempts to remove the untracked `.avoraxq` payload; cleanup failure is reported with the original finalization error instead of being swallowed.
- Existing native source-hash preflight, root validation and ACL hardening, executable-bit stripping, record path validation, metadata field/byte limits, metadata parent revalidation, final metadata exclusivity, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata activation remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for the finalization block, untracked-payload cleanup, and visible cleanup-failure context.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`377 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1355-native-quarantine-finalization-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1356

- Hardened local-core quarantine post-move finalization cleanup.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now wraps post-move payload validation, executable-permission removal, hash verification, record construction, metadata write, and auth-sidecar write in a finalization block.
- If finalization fails after the payload has been moved/copied into quarantine, local-core now attempts to remove the untracked payload plus record JSON, record JSON temp, auth sidecar, and auth temp sidecar artifacts; cleanup failures are aggregated and reported with the original finalization error.
- Existing local status preflight, root validation/ACL hardening, metadata normalization, write-time record validation, metadata auth, bounded metadata reads, copy fallback hash preflight, payload integrity verification, exclusive copy fallback, hash byte limits, and staged metadata/auth activation remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for the finalization block and artifact cleanup targets.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`378 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1356-local-quarantine-finalization-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1357

- Hardened Guard quarantine post-move finalization cleanup.
- `core/zentor_guard_service/src/main.rs` now wraps post-move payload validation, executable-permission removal, destination hash verification, record construction, and staged metadata/auth writes in a finalization block.
- If finalization fails after the payload has been moved/copied into quarantine, Guard now attempts to remove the untracked payload plus record JSON, record JSON temp, auth sidecar, and auth temp sidecar artifacts; cleanup failure is reported with the original finalization error.
- Existing Guard expected-hash preflight, path validation, threat-label normalization, payload integrity verification, exclusive copy fallback, bounded metadata/auth reads, write-time metadata validation, metadata-auth verification, and ACL hardening remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for the finalization block and artifact cleanup targets.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`379 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1357-guard-quarantine-finalization-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1358

- Hardened Guard quarantine staged metadata/auth/key activation.
- `core/zentor_guard_service/src/main.rs` now rejects existing final metadata, auth-sidecar, and metadata-key destinations before staged activation instead of removing and replacing them.
- Guard staged writes now clean temporary files visibly on write failure, temporary validation failure, final-destination preflight failure, or activation failure.
- Existing Guard metadata field/path validation, expected-hash preflight, payload integrity verification, exclusive payload copy fallback, metadata-auth verification, finalization cleanup, and ACL hardening remain in place.
- Added Rust regression/source-marker coverage plus Python source-contract coverage for final-destination exclusivity and staged temp cleanup.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`380 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1358-guard-quarantine-metadata-final-exclusivity.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1359

- Hardened local-core quarantine staged metadata/auth/key activation.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now rejects existing final metadata, auth-sidecar, and metadata-key destinations before staged activation instead of removing and replacing them.
- Local-core staged writes now clean temporary files visibly on write failure, temporary validation failure, final-destination preflight failure, or activation failure.
- Existing local status preflight, metadata field/path validation, expected-hash preflight, payload integrity verification, exclusive payload copy fallback, metadata-auth verification, finalization cleanup, and ACL hardening remain in place.
- Added Rust regression/source-marker coverage plus Python source-contract coverage for final-destination exclusivity and staged temp cleanup.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`381 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1359-local-quarantine-metadata-final-exclusivity.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1360

- Hardened Guard and local-core quarantine staged metadata/auth/key parent-directory preflight.
- `core/zentor_guard_service/src/main.rs` and `core/zentor_local_core/src/quarantine/quarantine_store.rs` now validate staged metadata parent directories before temporary writes and recheck them before final activation.
- If the parent-directory activation preflight fails after a temporary metadata/auth/key file has been written, the staged temp file is cleaned up with visible context instead of being left behind.
- Existing final-destination exclusivity, staged temp validation, metadata field/path validation, expected-hash preflight, payload integrity verification, metadata-auth verification, and finalization cleanup remain in place.
- Expanded Rust source-marker coverage plus Python source-contract coverage for parent preflight ordering and cleanup context.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`381 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1360-quarantine-metadata-parent-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1361

- Hardened Guard and local-core quarantine staged metadata/auth/key temporary naming.
- `core/zentor_guard_service/src/main.rs` and `core/zentor_local_core/src/quarantine/quarantine_store.rs` now allocate per-write UUID temporary filenames inside the staged writer instead of using predictable fixed temp names from callsites.
- Legacy fixed temp symlinks such as `record.json.tmp`, `record.json.auth.tmp`, and `.metadata_auth_key.tmp` are no longer touched by new metadata staging.
- Existing parent-directory revalidation, final-destination exclusivity, staged temp validation, metadata field/path validation, expected-hash preflight, payload integrity verification, metadata-auth verification, and finalization cleanup remain in place.
- Updated Rust source-marker/fixture coverage plus Python source-contract coverage for UUID temp allocation and fixed-temp callsite removal.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`381 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1361-quarantine-metadata-uuid-temp-staging.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1362

- Hardened Guard and local-core quarantine staged metadata/auth/key temp cleanup ownership.
- `core/zentor_guard_service/src/main.rs` and `core/zentor_local_core/src/quarantine/quarantine_store.rs` now return create/open failures from exclusive temp creation without running staged-temp cleanup, so unowned temp-path collisions are not removed.
- Cleanup remains visible after successful exclusive create if later write or sync operations fail.
- Existing UUID temp naming, parent-directory revalidation, final-destination exclusivity, staged temp validation, metadata field/path validation, expected-hash preflight, payload integrity verification, metadata-auth verification, and finalization cleanup remain in place.
- Expanded Rust source-marker coverage plus Python source-contract coverage for create-failure ownership and write/sync cleanup context.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: Python source contracts (`381 tests`). Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1362-quarantine-metadata-owner-aware-temp-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1363

- Hardened native quarantine staged temp cleanup ownership.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now returns create/open failures from exclusive temp creation without running staged-temp cleanup, so unowned temp-path collisions are not removed.
- Cleanup remains visible after successful exclusive create if later write or sync operations fail.
- Existing native metadata byte limits, parent revalidation, final-destination exclusivity, UUID temp naming, staged temp validation, record validation, payload integrity verification, and finalization cleanup remain in place.
- Added Python source-contract coverage and expanded Rust source-marker coverage for create-failure ownership and write/sync cleanup context.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 382 tests`. Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1363-native-quarantine-metadata-owner-aware-temp-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1364

- Hardened native quarantine copy fallback source-delete failure cleanup.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs` now removes a verified copied destination if deleting the original source fails after fallback copy, or reports cleanup failure with the source-delete error context.
- Existing native expected-hash preflight, destination exclusivity, byte-limited copy, sync-before-verification, hash-mismatch cleanup, executable-bit stripping, staged metadata activation, and finalization cleanup remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for the source-delete failure cleanup branch and ordering after destination hash verification.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 383 tests`. Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1364-native-quarantine-copy-source-delete-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1365

- Hardened guard quarantine copy fallback source-delete cleanup and local quarantine copy fallback source-delete cleanup.
- `core/zentor_guard_service/src/main.rs` and `core/zentor_local_core/src/quarantine/quarantine_store.rs` now remove verified copied destinations if deleting the original source fails after fallback copy, or report cleanup failure with source-delete context.
- Existing expected-hash preflight, destination exclusivity, byte-limited copy, sync-before-verification, hash-mismatch cleanup, executable-bit stripping/finalization behavior, and staged metadata activation remain in place.
- Added Rust source-marker coverage plus a combined Python source-contract for Guard/local source-delete failure cleanup ordering after destination hash verification.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 384 tests`. Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1365-guard-local-quarantine-copy-source-delete-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1366

- Hardened native quarantine copy fallback verification cleanup, guard quarantine copy fallback verification cleanup, and local quarantine copy fallback verification cleanup.
- `core/zentor_native_engine/src/quarantine/quarantine_store.rs`, `core/zentor_guard_service/src/main.rs`, and `core/zentor_local_core/src/quarantine/quarantine_store.rs` now remove copied destinations if post-copy destination metadata/hash/normalization verification fails, or report cleanup failure with verification context.
- Existing expected-hash preflight, destination exclusivity, byte-limited copy, sync-before-verification, hash-mismatch cleanup, source-delete cleanup, executable-bit stripping/finalization behavior, and staged metadata activation remain in place.
- Added Rust source-marker coverage plus a combined Python source-contract for native/Guard/local verification failure cleanup ordering after exclusive destination copy and before hash-mismatch/source-delete handling.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 385 tests`. Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1366-quarantine-copy-verification-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1367

- Hardened local quarantine delete status ordering.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now writes `Deleted` metadata before removing the isolated payload; if payload removal fails, it restores the previous status or reports rollback failure with the payload-removal error context.
- Existing confirmation gating, quarantine ID validation, payload path validation, canonical store containment, metadata auth, staged metadata activation, and no secure-erase claim remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for status-before-payload-removal ordering and rollback evidence.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 386 tests`. Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1367-local-quarantine-delete-status-ordering.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1368

- Hardened local quarantine restore status ordering.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now writes `Restored` metadata after staged restore activation and before removing the old isolated payload; restored-payload cleanup failures include status-update context.
- Existing confirmation gating, quarantine ID validation, restore path validation, parent-link checks, conflict checks, payload integrity, staged restore activation, metadata auth, and no secure-erase claim remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for restored-status-before-payload-cleanup ordering and cleanup evidence.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 387 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1368-local-quarantine-restore-status-ordering.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1369

- Hardened local quarantine restore metadata-failure cleanup.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now verifies and removes an activated restore copy if writing `Restored` metadata fails, or reports cleanup failure with metadata-write context.
- Existing confirmation gating, quarantine ID validation, restore path validation, parent-link checks, conflict checks, payload integrity, staged restore activation, restored-status ordering, restored-payload cleanup, metadata auth, and no secure-erase claim remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for metadata-write-failure cleanup ordering and diagnostics.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 388 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1369-local-quarantine-restore-metadata-failure-cleanup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1370

- Hardened local quarantine delete payload-integrity preflight.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now verifies the quarantined payload size/hash against the authenticated record before writing `Deleted` metadata or removing the payload.
- Existing confirmation gating, quarantine ID validation, payload path validation, canonical store containment, delete status ordering, rollback-on-removal-failure, metadata auth, and no secure-erase claim remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for payload-integrity-before-status-update ordering.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 389 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1370-local-quarantine-delete-payload-integrity-preflight.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1371

- Hardened local quarantine restore parent revalidation.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now rejects linked restore parents before restore temp creation and rechecks the parent before activation, cleaning the staged temp file visibly on parent preflight failure.
- Existing confirmation gating, quarantine ID validation, restore path validation, conflict checks, payload integrity, staged restore activation, restored-status ordering, restored-payload cleanup, metadata-failure cleanup, metadata auth, and no secure-erase claim remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for parent revalidation before staging and activation.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 390 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1371-local-quarantine-restore-parent-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1372

- Hardened local quarantine restore/delete status preflight.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now requires authenticated records to still be `Quarantined` before restore/delete path or payload handling.
- Existing confirmation gating, quarantine ID validation, restore/delete path validation, payload integrity checks, restore parent revalidation, delete payload-integrity preflight, restore/delete status ordering, restore metadata-failure cleanup, metadata auth, and no secure-erase claim remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for status-before-path-use ordering.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 391 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1372-local-quarantine-restore-delete-status-preflight.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1373

- Hardened local quarantine restore/delete action metadata consistency.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now writes `action_taken` as `restored` with `Restored` status and `deleted` with `Deleted` status; delete rollback restores the previous action metadata alongside the previous status.
- Existing confirmation gating, quarantine ID validation, restore/delete status preflight, restore/delete path validation, payload integrity checks, restore parent revalidation, delete payload-integrity preflight, restore/delete status ordering, restore metadata-failure cleanup, metadata auth, and no secure-erase claim remain in place.
- Added Rust source-marker coverage plus Python source-contract coverage for action metadata ordering and rollback.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 392 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1373-local-quarantine-action-metadata-consistency.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-06-28 continuation checkpoint 1374

- Hardened local quarantine status/action metadata validation.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now rejects records whose `action_taken` does not match `Quarantined`, `Restored`, or `Deleted` status before list or write evidence is trusted.
- Existing confirmation gating, quarantine ID validation, restore/delete status preflight, restore/delete action metadata updates, restore/delete path validation, payload integrity checks, restore parent revalidation, delete payload-integrity preflight, restore/delete status ordering, restore metadata-failure cleanup, metadata auth, and no secure-erase claim remain in place.
- Added Rust fixture/source-marker coverage plus Python source-contract coverage for status/action metadata consistency.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 393 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1374-local-quarantine-status-action-metadata-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1375

- Hardened local quarantine execution-claim metadata validation.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now rejects records that claim both pre-execution blocking and process start, or a process ID without process-start evidence, before list or write evidence is trusted.
- Existing confirmation gating, quarantine ID validation, restore/delete status preflight, restore/delete action metadata updates, status/action metadata validation, restore/delete path validation, payload integrity checks, restore parent revalidation, delete payload-integrity preflight, restore/delete status ordering, restore metadata-failure cleanup, metadata auth, and no secure-erase claim remain in place.
- Added Rust fixture/source-marker coverage plus Python source-contract coverage for execution-claim metadata consistency.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 394 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1375-local-quarantine-execution-claim-metadata-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1376

- Hardened local quarantine source/evidence metadata validation.
- `core/zentor_local_core/src/quarantine/quarantine_store.rs` now accepts only the documented local `scanner` source for this local quarantine store and rejects scanner records that claim execution-state evidence.
- `apps/zentor_client/lib/features/quarantine/quarantine_screen.dart` now labels only explicit `scanner` values as Scanner; unsupported source strings remain `Unknown source` instead of defaulting to a trusted scanner label.
- Existing confirmation gating, quarantine ID validation, restore/delete status preflight, restore/delete action metadata updates, status/action metadata validation, execution-claim contradiction checks, restore/delete path validation, payload integrity checks, restore parent revalidation, delete payload-integrity preflight, restore/delete status ordering, restore metadata-failure cleanup, metadata auth, and no secure-erase claim remain in place.
- Added Rust fixture/source-marker coverage plus Python source-contract coverage for source/evidence metadata consistency and explicit UI labels.
- Updated `STATUS.md`, `SECURITY_MODEL.md`, `docs/audit/engine-control-matrix.md`, `docs/audit/known-blockers.md`, and this run log.
- Focused verification passed locally: `python source-contract run passed: 395 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1376-local-quarantine-source-evidence-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1377

- Hardened Flutter local-core quarantine IPC source/action evidence validation.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now rejects quarantine IPC rows whose `actionTaken` value does not match the parsed `Quarantined`/`Restored`/`Deleted` status before the row can become UI action evidence.
- Flutter now also rejects local-core quarantine IPC rows whose source evidence falls outside the local scanner boundary, including scanner rows that claim pre-execution or process-start evidence.
- Existing quarantine record ID/path/hash/time/status/file-size/detection/engine/source/action field validation, required execution booleans, UI unknown-source labeling, Rust local quarantine metadata validation, and no secure-erase claim remain in place.
- Added Flutter source-marker coverage plus Python source-contract coverage for quarantine IPC source/action evidence validation.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 396 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1377-flutter-quarantine-ipc-source-action-validation.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1378

- Hardened Flutter local-core quarantine IPC process-ID evidence validation.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now reads `processId`/`process_id` as quarantine IPC evidence and rejects rows where that field is present but malformed.
- Local scanner quarantine rows now also require process-ID evidence to be absent/null before display or restore/delete action use, matching the local scanner boundary that does not claim process-start provenance.
- Existing quarantine record ID/path/hash/time/status/file-size/detection/engine/source/action field validation, required execution booleans, source/action evidence matching, UI unknown-source labeling, Rust local quarantine metadata validation, and no secure-erase claim remain in place.
- Added Flutter source-marker coverage plus Python source-contract coverage for scanner process-ID evidence rejection.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 397 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1378-flutter-quarantine-ipc-process-id-validation.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1379

- Hardened shared `QuarantineRecord` protocol evidence construction.
- `packages/zentor_protocol/lib/zentor_protocol.dart` now requires quarantine `source`, `blockedBeforeExecution`, `processStarted`, and `actionTaken` fields instead of defaulting them to scanner/quarantined/not-started values.
- Existing Flutter local-core parsing, app-state status replacement, API upload fixtures, offline scan fixtures, UI unknown-source labeling, and Rust local quarantine metadata validation remain explicit about quarantine evidence.
- Added Python source-contract coverage that rejects restored constructor defaults and confirms known app/test fixtures pass explicit quarantine evidence fields.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 398 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1379-shared-quarantine-record-explicit-evidence.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1380

- Hardened Flutter optimistic quarantine status/action evidence consistency.
- `apps/zentor_client/lib/app/app_state.dart` now maps local replacement status to matching `actionTaken` evidence when a restore/delete action succeeds before the refresh result arrives.
- Restored optimistic rows now carry `actionTaken=restored`, deleted optimistic rows carry `actionTaken=deleted`, and the old stale `actionTaken: item.actionTaken` copy path is covered by a source contract.
- Existing confirmation gating, quarantine action single-flight behavior, local-core refresh after mutation, IPC quarantine source/action/process-ID validation, shared explicit `QuarantineRecord` evidence fields, and Rust local quarantine metadata validation remain in place.
- Added Python source-contract coverage for optimistic status/action mapping.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 399 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1380-flutter-quarantine-optimistic-status-action-consistency.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1381

- Hardened cloud quarantine metadata upload evidence preflight.
- `apps/zentor_client/lib/core/network/zentor_api_client.dart` now rejects quarantine cloud uploads whose `actionTaken` does not match status or whose source/execution-state evidence falls outside the local scanner boundary before building the cloud URI or sending a request.
- Added a Dart fixture for inconsistent quarantine evidence rejected before network calls and source markers for the new action/source evidence helpers.
- Existing cloud config validation, cloud payload text/hash validation, bounded cloud response reads, local quarantine IPC evidence validation, shared explicit `QuarantineRecord` fields, and Rust local quarantine metadata validation remain in place.
- Added Python source-contract coverage for quarantine cloud preflight ordering and helper behavior.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 400 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1381-cloud-quarantine-upload-evidence-preflight.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1382

- Hardened cloud quarantine metadata evidence persistence.
- `apps/zentor_client/lib/core/network/zentor_api_client.dart` now includes the same validated `action_taken`, `source`, `blocked_before_execution`, and `process_started` evidence fields in the outbound quarantine metadata payload.
- `services/api/src/models.rs` and `services/api/src/routes.rs` now require those fields, validate `action_taken` against status, restrict the current cloud quarantine source to the documented local `scanner` boundary, reject scanner execution-state claims, and store the evidence fields in the `quarantine_metadata` event payload.
- Added Dart payload-observation coverage plus Rust/source-marker and Python source-contract coverage so future changes cannot validate quarantine evidence locally while dropping or ignoring it at upload/API persistence.
- Existing cloud config validation, cloud payload text/hash validation, bounded cloud response reads, local quarantine IPC evidence validation, shared explicit `QuarantineRecord` fields, and Rust local quarantine metadata validation remain in place.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 401 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1382-cloud-quarantine-evidence-persistence.md`.
- Dart/Flutter and Rust runtime verification remain blocked because `dart`, `flutter`, `cargo`, and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1383

- Hardened the cloud quarantine metadata API schema against ignored JSON controls.
- `services/api/src/models.rs` now marks `QuarantineMetadataRequest` with `#[serde(deny_unknown_fields)]`, so extra quarantine upload fields are rejected by deserialization instead of being silently accepted and dropped.
- The existing Rust source-marker test and Python source-contract coverage now require the strict schema marker alongside the explicit action/source/execution evidence fields and API persistence checks.
- Existing quarantine metadata evidence validation from checkpoint 1382 remains in place: action/status matching, local `scanner` source restriction, scanner execution-state rejection, and persisted event evidence fields.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 401 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1383-cloud-quarantine-strict-api-schema.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1384

- Hardened concrete cloud API request models against ignored top-level JSON controls.
- `services/api/src/models.rs` now marks `CreateProjectRequest`, `RegisterDeviceRequest`, `CreateSessionRequest`, `HeartbeatRequest`, `DetectionReportRequest`, `DetectionReportItem`, `QuarantineMetadataRequest`, and `CreateBanRequest` with `#[serde(deny_unknown_fields)]`.
- Intentional flexible content remains explicit inside the existing `serde_json::Value` payload/environment fields; unknown top-level request fields are no longer silently accepted by concrete request models.
- Added Python source-contract coverage for the top-level request schema markers.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 402 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1384-cloud-api-request-strict-schemas.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1385

- Hardened batched cloud security-event wrappers against ignored top-level JSON controls.
- `services/api/src/models.rs` now marks `SecurityEventRequest` with `deny_unknown_fields` in the internally tagged enum attribute, so event objects may contain only `event_type` and the documented `payload` field.
- The event `payload: serde_json::Value` remains the explicit flexible event-content boundary and is still size-bounded by the route before insertion.
- Updated Python source-contract coverage for the strict event wrapper while preserving payload flexibility.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 402 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1385-cloud-security-event-wrapper-strict-schema.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1386

- Hardened batched cloud security-event ingestion against no-op success acknowledgements.
- `services/api/src/routes.rs` now rejects empty event batches with `event batch must contain at least one event` before the maximum-count check or the final `inserted` acknowledgement path.
- Non-empty event batches still keep the existing count cap, per-payload JSON-size validation, authenticated session/project matching, and inserted-count acknowledgement.
- Added Rust source-marker coverage and Python source-contract coverage for the empty-batch rejection ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 403 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1386-cloud-event-empty-batch-rejection.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1387

- Hardened cloud protection-run expiry validation.
- `services/api/src/routes.rs` now requires `expires_at` to be after the server-side `started_at` timestamp and no more than `MAX_API_SESSION_TTL_HOURS` (24 hours) after session creation before inserting a `protection_runs` row.
- This matches the Flutter client's current one-hour protection-run request while rejecting expired or excessively long sessions before persistence.
- Added Rust source-marker coverage and Python source-contract coverage for expiry validation ordering before session insertion.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 404 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1387-cloud-protection-run-expiry-bounds.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1388

- Hardened cloud protection-run write routes against expired or ended sessions.
- `services/api/src/routes.rs` now reads session project/status/expiry through `session_context`, routes heartbeat and event ingestion through `active_session_project`, and rejects sessions that are not `active` or have expired before accepting telemetry writes.
- The active-session helper checks the authenticated project match before status or expiry so unauthorized callers do not learn whether another project's guessed session is ended or expired.
- End-session now rejects non-active sessions before mutation and performs an active-only conditional update, checking `rows_affected()` so an already-ended/raced session cannot receive a fake success acknowledgement.
- Added Rust source-marker coverage and Python source-contract coverage for active/unexpired heartbeat/event writes and active-only end-session updates.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 405 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1388-cloud-session-write-active-expiry-enforcement.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1389

- Hardened cloud ban creation project boundaries.
- `services/api/src/routes.rs` now validates `request.device_id` with `ensure_device_in_project(&state, request.device_id, auth.project_id)` before inserting a `bans` row or writing `ban_status_changed` audit evidence.
- The helper queries `devices` by both `id` and authenticated `project_id`, so a valid device UUID from another project fails before the route can create cross-project ban state.
- Added Rust source-marker coverage and Python source-contract coverage for the project/device preflight ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 406 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1389-cloud-ban-device-project-boundary.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1390

- Hardened cloud device-risk reads against fake clean responses for unknown or cross-project devices.
- `services/api/src/routes.rs` now validates the requested `device_id` with `ensure_device_in_project(&state, device_id, auth.project_id)` before reading `risk_scores` or returning the compatibility default `score=0`, `severity=info`, and empty reasons.
- Existing behavior for a real project-owned device with no stored risk score remains a bounded neutral response; missing or cross-project devices now fail before that default can become risk evidence.
- Added Rust source-marker coverage and Python source-contract coverage for device-risk preflight ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 407 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1390-cloud-device-risk-project-boundary.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1391

- Hardened cloud protection-run creation project boundaries.
- `services/api/src/routes.rs` now validates any supplied session `device_id` with `ensure_device_in_project(&state, device_id, project_id)` before inserting a `protection_runs` row or writing `protection_session_created` audit evidence.
- Existing anonymous/no-device protection-run creation remains supported, but unknown or cross-project device UUIDs now fail before they can become session evidence.
- Added Rust source-marker coverage and Python source-contract coverage for session device/project preflight ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 408 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1391-cloud-session-device-project-boundary.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1392

- Hardened cloud detection-report ingestion against empty aggregate success.
- `services/api/src/routes.rs` now rejects `detections: []` with `detection report must contain at least one detection` before count-bound checks, database inserts, `automated_detection_reported` audit evidence, or `ok: true` acknowledgement.
- Existing legacy single-detection payloads and non-empty aggregate detection reports remain supported.
- Added Rust unit/source-marker coverage and Python source-contract coverage for empty aggregate rejection and ordering before the report-count limit.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 409 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1392-cloud-detection-empty-aggregate-rejection.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1393

- Hardened cloud security-event ingestion against partial writes on validation failure.
- `services/api/src/routes.rs` now normalizes the full event batch into `normalized_events` and runs `validate_json_value_size` for every payload before the first `events` insert.
- Valid batches keep the existing per-event insert behavior and inserted count; invalid later events no longer leave earlier rows behind before the route returns a validation error.
- Added Rust source-marker coverage and Python source-contract coverage for validate-before-insert ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 410 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1393-cloud-event-batch-validate-before-insert.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1394

- Hardened cloud heartbeat acknowledgement against stale active-session evidence.
- `services/api/src/routes.rs` now conditionally updates `last_heartbeat_at` with `id`, authenticated `project_id`, `status = 'active'`, and `expires_at > now()` before inserting the heartbeat event.
- The route checks `heartbeat_result.rows_affected() == 1` before event insertion, so a session that becomes ended, expired, or mismatched after the initial session check does not receive `ok: true` heartbeat event evidence.
- Added Rust source-marker coverage and Python source-contract coverage for update-ack-before-event-insert ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 411 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1394-cloud-heartbeat-active-update-ack.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1395

- Hardened cloud client evidence timestamps against misleading audit/history times.
- `services/api/src/routes.rs` now validates heartbeat `client_timestamp`, detection `detected_at`, and quarantine `quarantined_at` through `validate_client_evidence_timestamp` before event/detection persistence.
- The API accepts evidence within a 10-minute future clock-skew window and a 30-day past window; values outside that range fail with explicit `BadRequest` diagnostics instead of being stored as trusted evidence.
- Added Rust unit/source-marker coverage and Python source-contract coverage for the shared timestamp bounds and all three cloud evidence call sites.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 412 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1395-cloud-evidence-timestamp-bounds.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1396

- Hardened cloud security-event batch persistence against partial database writes.
- `services/api/src/routes.rs` now starts a database transaction after full event-batch normalization/size validation, writes each event with `execute(&mut *tx)`, and commits before returning the inserted-count acknowledgement.
- The route preserves existing valid-batch semantics while preventing mid-batch database failures from leaving earlier event rows committed under a failed response path.
- Added Rust source-marker coverage and Python source-contract coverage for transaction begin/write/commit ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 413 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1396-cloud-event-batch-transaction.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1397

- Hardened cloud detection-report persistence against partial detection/audit writes.
- `services/api/src/routes.rs` now starts a database transaction after report normalization, writes all detection rows and the `automated_detection_reported` audit row with `execute(&mut *tx)`, and commits before returning `ok: true`.
- This keeps detection evidence and its audit summary together if a database write fails mid-report.
- Added Rust source-marker coverage and Python source-contract coverage for detection-row/audit transaction ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 414 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1397-cloud-detection-report-transaction.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1398

- Hardened cloud heartbeat persistence against partial heartbeat update/event writes.
- `services/api/src/routes.rs` now starts a database transaction after heartbeat payload validation, conditionally updates `last_heartbeat_at` through `execute(&mut *tx)`, inserts heartbeat event evidence through the same transaction, and commits before returning `ok: true`.
- This preserves the active/unexpired session acknowledgement from checkpoint 1394 while preventing a failed heartbeat event insert from leaving a standalone heartbeat timestamp update.
- Added Rust source-marker coverage and Python source-contract coverage for heartbeat update/event transaction ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 415 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1398-cloud-heartbeat-transaction.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1399

- Hardened cloud protection-run creation against partial session/audit writes.
- `services/api/src/routes.rs` now starts a database transaction after project/device/expiry validation, inserts the `protection_runs` row and `protection_session_created` audit evidence with `execute(&mut *tx)`, and commits before returning the session response.
- This prevents an active session row from being created without matching lifecycle audit evidence if the audit insert fails.
- Added Rust source-marker coverage and Python source-contract coverage for session-row/audit transaction ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 416 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1399-cloud-session-creation-transaction.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1400

- Hardened cloud ban creation against partial ban/audit writes.
- `services/api/src/routes.rs` now starts a database transaction after device/project/status/reason validation, inserts the `bans` row and `ban_status_changed` audit evidence with `execute(&mut *tx)`, and commits before returning the ban ID.
- This prevents actionable ban state from being created without matching audit evidence if the audit insert fails.
- Added Rust source-marker coverage and Python source-contract coverage for ban-row/audit transaction ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 417 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1400-cloud-ban-creation-transaction.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1401

- Hardened cloud end-session persistence against partial ended-status/audit writes.
- `services/api/src/routes.rs` now starts a database transaction after active-session authorization/status checks, applies the active-only `ended` status update with `execute(&mut *tx)`, verifies `rows_affected()`, inserts `protection_session_ended` audit evidence through the same transaction, and commits before returning `ok: true`.
- This prevents ended lifecycle state from being recorded without matching audit evidence if the audit insert fails.
- Added Rust source-marker coverage and Python source-contract coverage for end-session status/audit transaction ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 418 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1401-cloud-end-session-transaction.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1402

- Hardened cloud device registration against unaudited device state.
- `services/api/src/routes.rs` now starts a database transaction after project/device field validation, upserts the `devices` row with `fetch_one(&mut *tx)`, writes `device_registered` audit evidence with `execute(&mut *tx)`, and commits before returning the device response.
- Audit metadata records only whether a display name was present, avoiding raw display-name or external-device-ID duplication in audit metadata.
- Added Rust source-marker coverage and Python source-contract coverage for device-row/audit transaction ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 419 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1402-cloud-device-registration-transaction.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1403

- Hardened cloud quarantine metadata persistence against oversized final event payloads.
- `services/api/src/routes.rs` now builds the quarantine metadata event payload once, validates it with `validate_json_value_size(&payload, "quarantine_metadata")`, and only then binds the validated payload into the `events` insert.
- Existing field-level validation, action/status matching, scanner-source restrictions, and execution-state claim rejection remain in place.
- Added Rust source-marker coverage and Python source-contract coverage for final quarantine metadata payload-size validation before insertion.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 420 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1403-cloud-quarantine-metadata-payload-size.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1404

- Hardened cloud quarantine metadata persistence against success acknowledgements without an inserted event row.
- `services/api/src/routes.rs` now stores the result of the `quarantine_metadata` event insert, checks `result.rows_affected() != 1`, and returns an internal error instead of `ok: true` if the database does not acknowledge exactly one inserted row.
- Existing final payload-size validation from checkpoint 1403 remains before the insert.
- Added Rust source-marker coverage and Python source-contract coverage for insert acknowledgement before success.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 421 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1404-cloud-quarantine-metadata-insert-ack.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1405

- Hardened cloud security-event batch ingestion against inserted-count acknowledgements without confirmed row writes.
- `services/api/src/routes.rs` now checks each event insert result with `result.rows_affected() != 1` before incrementing `inserted`, so the returned inserted count can only advance after the database acknowledges exactly one row for that event.
- Existing batch prevalidation, size limits, active/unexpired session authorization, transactionality, and commit-before-acknowledgement remain in place.
- Added Rust source-marker coverage and Python source-contract coverage for event insert acknowledgement before counting.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 422 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1405-cloud-event-insert-ack.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1406

- Hardened cloud detection-report persistence against success acknowledgements without confirmed detection/audit row writes.
- `services/api/src/routes.rs` now checks each detection insert with `detection_result.rows_affected() != 1` before moving to audit evidence, and checks the `automated_detection_reported` audit insert with `audit_result.rows_affected() != 1` before committing and returning `ok: true`.
- Existing detection normalization, empty-report rejection, timestamp bounds, transactionality, and commit-before-success behavior remain in place.
- Added Rust source-marker coverage and Python source-contract coverage for detection-row and audit-row insert acknowledgements.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 423 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1406-cloud-detection-insert-acks.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1407

- Hardened cloud protection-run creation against session responses without confirmed session/audit row writes.
- `services/api/src/routes.rs` now checks the protection session insert with `session_result.rows_affected() != 1` and the `protection_session_created` audit insert with `audit_result.rows_affected() != 1` before committing and returning the session response.
- Existing expiry bounds, device/project validation, transactionality, and commit-before-response behavior remain in place.
- Added Rust source-marker coverage and Python source-contract coverage for session-row and audit-row insert acknowledgements.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 424 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1407-cloud-session-insert-acks.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1408

- Hardened cloud ban creation against ban responses without confirmed ban/audit row writes.
- `services/api/src/routes.rs` now checks the ban insert with `ban_result.rows_affected() != 1` and the `ban_status_changed` audit insert with `audit_result.rows_affected() != 1` before committing and returning the ban ID.
- Existing ban status validation, device/project validation, transactionality, and commit-before-response behavior remain in place.
- Added Rust source-marker coverage and Python source-contract coverage for ban-row and audit-row insert acknowledgements.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 425 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1408-cloud-ban-insert-acks.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1409

- Hardened cloud device registration against device responses without confirmed audit evidence.
- `services/api/src/routes.rs` now checks the `device_registered` audit insert with `audit_result.rows_affected() != 1` before committing and returning the device response.
- Existing project/device validation, transactional upsert/audit persistence, and minimal audit metadata remain in place.
- Added Rust source-marker coverage and Python source-contract coverage for device-registration audit insert acknowledgement.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 426 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1409-cloud-device-audit-insert-ack.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1410

- Hardened cloud heartbeat persistence against `ok: true` without confirmed heartbeat event evidence.
- `services/api/src/routes.rs` now checks the heartbeat event insert with `event_result.rows_affected() != 1` before committing and returning `ok: true`.
- Existing active/unexpired session update acknowledgement, timestamp bounds, environment JSON sizing, transactionality, and commit-before-success behavior remain in place.
- Added Rust source-marker coverage and Python source-contract coverage for heartbeat event insert acknowledgement.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 427 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1410-cloud-heartbeat-event-insert-ack.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1411

- Hardened cloud end-session persistence against `ok: true` without confirmed session-end audit evidence.
- `services/api/src/routes.rs` now checks the `protection_session_ended` audit insert with `audit_result.rows_affected() != 1` before committing and returning `ok: true`.
- Existing active-only status update acknowledgement, transactionality, and commit-before-success behavior remain in place.
- Extended Rust source-marker coverage and Python source-contract coverage for end-session audit insert acknowledgement.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 427 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1411-cloud-end-session-audit-insert-ack.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1412

- Removed the unused cloud API `audit` helper from `services/api/src/routes.rs`.
- This keeps audit persistence route-local, transaction-scoped, and covered by explicit insert acknowledgement checks instead of leaving a dead helper that writes audit rows directly through `state.db`.
- Added Rust source-marker coverage and Python source-contract coverage that `routes.rs` does not keep an `audit` helper.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 428 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1412-cloud-unused-audit-helper-removed.md`.
- Rust runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1413

- Hardened in-app update feed trust for local feed/package flows.
- `apps/zentor_client/lib/core/updates/update_service.dart` now accepts `file:` update feeds only when they resolve to absolute local paths without query, fragment, or parent traversal.
- Direct `UpdateInfo` use now revalidates `update.feedUrl` through `_isTrustedFeedUri(update.feedUrl)` before package download, verify, or install metadata can proceed.
- Added Dart source-marker coverage and Python source-contract coverage for local file-feed trust and direct `UpdateInfo` feed revalidation.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 429 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1413-update-local-file-feed-trust.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1414

- Hardened in-app update local feed trust so `file:` feed URIs with a non-empty authority/host are rejected before path conversion.
- `apps/zentor_client/lib/core/updates/update_service.dart` now fails closed for `file://host/...`-style feed authorities instead of relying on platform-specific `Uri.toFilePath()` behavior.
- Added Dart source-marker coverage and Python source-contract coverage for local feed authority rejection.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 430 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1414-update-file-feed-authority-guard.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1415

- Hardened in-app update local package trust for local feed/package flows.
- `apps/zentor_client/lib/core/updates/update_service.dart` now accepts a `file:` package URL from a local `file:` feed only when the package URI itself rejects non-empty authorities, resolves through `Uri.toFilePath()`, is an absolute local path, and contains no parent traversal.
- The existing local feed-directory containment and canonical existing-package checks remain in place after this earlier trust gate.
- Added Dart source-marker coverage and Python source-contract coverage for local package file-URI trust.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 431 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1415-update-local-package-file-uri-trust.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1416

- Hardened in-app update HTTPS URI trust for feed and package flows.
- `apps/zentor_client/lib/core/updates/update_service.dart` now routes HTTPS feed and package trust through `_isTrustedHttpsUri`, requiring a URI authority, a non-empty host, and empty `userInfo` so authority-less HTTPS strings or embedded credentials are not treated as trusted update sources.
- Added Dart source-marker coverage and Python source-contract coverage for HTTPS feed/package host-authority requirements.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 432 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1416-update-https-uri-authority-trust.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1417

- Hardened GitHub update feed/asset/redirect URI trust.
- `apps/zentor_client/lib/core/updates/update_service.dart` now requires `_isTrustedHttpsUri` for latest-download GitHub feed matching, trusted GitHub release asset naming, and release-asset redirect acceptance.
- This keeps GitHub-specific host/path allowlists from accepting authority-less HTTPS URIs or HTTPS URIs with embedded `userInfo` credentials.
- Added Dart source-marker coverage and Python source-contract coverage for the shared GitHub HTTPS trust gate.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 433 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1417-update-github-https-trust-gate.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1418

- Hardened update URI text parsing before feed/package URL parsing.
- `apps/zentor_client/lib/core/updates/update_service.dart` now rejects raw control/NUL characters in the configured update feed URL, feed package URLs, and GitHub release `browser_download_url` values before calling `Uri.parse`.
- The same `_requireUpdateUriText` helper backs all three URI text boundaries.
- Added Dart source-marker coverage and Python source-contract coverage for pre-parse update URI text rejection.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 434 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1418-update-uri-text-control-guard.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1419

- Hardened required update metadata string parsing.
- `apps/zentor_client/lib/core/updates/update_service.dart` now rejects raw control/NUL characters in required update feed/package fields and required GitHub release fields before those strings are compared, parsed, or used as URL inputs.
- Free-form optional release notes remain separately bounded by their existing release-notes limit.
- Added Python source-contract coverage and extended Dart source-marker coverage for required metadata control-character rejection.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 435 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1419-update-required-metadata-control-guard.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1420

- Hardened optional update metadata string parsing.
- `apps/zentor_client/lib/core/updates/update_service.dart` now rejects raw control/NUL characters in optional update feed string fields such as `channel` and `minimum_supported_version`, and in optional package `published_at` before `DateTime.tryParse`.
- Free-form release notes remain governed by the existing release-notes byte/character cap and are not forced through this strict metadata-token validator.
- Added Python source-contract coverage and extended Dart source-marker coverage for optional metadata control-character rejection.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 436 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1420-update-optional-metadata-control-guard.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1421

- Hardened update feed product matching.
- `apps/zentor_client/lib/core/updates/update_service.dart` now parses the feed `product` field through `_requiredString(feed, 'product')` before comparing it to `Avorax Anti-Virus`, so non-string, empty, oversized, or control/NUL-containing product evidence fails through the same required metadata boundary as the rest of the feed.
- Added Dart source-marker coverage and Python source-contract coverage for the product-field boundary and removal of the previous direct `feed['product']` comparison.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 437 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1421-update-product-field-boundary.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1422

- Hardened update release-notes free-text parsing.
- `apps/zentor_client/lib/core/updates/update_service.dart` now rejects NUL, DEL, and non-display C0 control characters in bounded free-text metadata while still allowing tabs, line feeds, and carriage returns for normal multiline release notes.
- `_optionalBoundedString` now applies the free-text control guard before returning release notes to UI state.
- Added Dart source-marker coverage and Python source-contract coverage for the free-text control guard and allowed line-break exceptions.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 438 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1422-update-release-notes-free-text-guard.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1423

- Hardened GitHub update release asset-name trust.
- `apps/zentor_client/lib/core/updates/update_service.dart` now routes GitHub release asset path names through `_safeTrustedGithubAssetName`, which delegates to `_safeUpdateAssetName` and returns `null` on unsafe names before fallback or redirect matching can trust them.
- This keeps GitHub fallback/redirect logic from comparing decoded path segments that fail the existing update asset-name rules.
- Extended Dart source-marker coverage and Python source-contract coverage for the safe GitHub asset-name wrapper.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 438 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1423-update-github-asset-name-boundary.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1424

- Hardened GitHub update redirect Location parsing before URI resolution.
- `apps/zentor_client/lib/core/updates/update_service.dart` now applies `_requireUpdateUriText(location, '$label redirect location')` after the existing Location presence/length check and before `currentUri.resolve(location)`.
- Added Dart source-marker coverage and Python source-contract coverage for the pre-resolve Location control/NUL rejection.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 439 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1424-update-redirect-location-control-guard.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1425

- Hardened GitHub release-asset redirect path trust.
- `apps/zentor_client/lib/core/updates/update_service.dart` now requires the final `release-assets.githubusercontent.com` redirect hop to use a `github-production-release-asset` path with at least three non-empty, non-dot segments.
- This narrows the final GitHub release asset redirect allowance while preserving the normal signed GitHub asset URL shape already covered by existing fixtures.
- Added Dart source-marker coverage and Python source-contract coverage for the stricter release-assets path shape.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 440 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1425-update-release-assets-path-shape.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1426

- Hardened GitHub update redirect Location raw-header validation.
- `apps/zentor_client/lib/core/updates/update_service.dart` now reads `rawLocation`, applies the max length check and `_requireUpdateUriText(rawLocation, '$label redirect location')`, and only then trims for URI resolution.
- This prevents leading/trailing raw control characters from being removed before the redirect Location text guard runs.
- Added Dart source-marker coverage and Python source-contract coverage for raw Location validation before trim and before `currentUri.resolve(location)`.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 441 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1426-update-redirect-location-raw-guard.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1427

- Hardened update `Content-Length` header parsing.
- `apps/zentor_client/lib/core/updates/update_service.dart` now treats a missing header as absent, but length-checks any present value and rejects raw control/NUL characters before `value.trim()` or numeric parsing.
- This prevents leading/trailing raw control characters in feed, GitHub release metadata, or package `Content-Length` headers from being removed before validation.
- Added Dart source-marker coverage and Python source-contract coverage for raw `Content-Length` validation before trim and parse.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 442 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1427-update-content-length-raw-guard.md`.
- Dart/Flutter runtime verification remains blocked because `dart` and `flutter` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1428

- Hardened signed `.aup` archive entry validation.
- `core/avorax_update_service/src/update_package.rs` now validates the full archive entry-name set before manifest reads and inside payload limit scanning.
- Only `manifest.json`, `manifest.sig`, and safe `payload/...` entries are accepted; payload directory entries must also pass the existing `safe_relative_path` normalization after removing a trailing slash.
- Added a Rust fixture test for rejecting an unexpected archive entry and Python source-contract coverage for the pre-read allowlist ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 443 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1428-update-aup-archive-entry-allowlist.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1429

- Hardened signed manifest scalar validation.
- `core/avorax_update_service/src/update_manifest.rs` now routes manifest versions, safe tokens, release dates, release notes URLs, migration steps, and optional `package_sha256` through raw scalar text validation before trimmed parsing.
- The new helper rejects raw control characters and surrounding whitespace so signed manifest metadata cannot hide unsafe text through `trim()` normalization.
- Added Rust fixture/source-marker tests and Python source-contract coverage for raw scalar validation before trim.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 444 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1429-update-manifest-scalar-raw-guard.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1430

- Hardened signed manifest payload-hash value validation.
- `core/avorax_update_service/src/update_package.rs` now routes each signed `payload_hashes` value through `validate_payload_hash_value` before opening the `.aup` archive for payload matching.
- The helper rejects raw control characters and surrounding whitespace before SHA-256 shape validation, so malformed signed hashes fail as manifest-shape errors instead of later payload mismatches.
- Added Rust fixture tests for whitespace-wrapped and control-character hash values failing before archive open, plus Python source-contract coverage for the helper and ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 445 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1430-update-payload-hash-value-raw-guard.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1431

- Hardened signed manifest payload-hash path-key validation.
- `core/avorax_update_service/src/update_package.rs` now routes each signed `payload_hashes` path key through `validate_payload_hash_path_text` before path normalization or `.aup` archive opening.
- The helper preserves the existing NUL rejection and now also rejects raw control characters and surrounding whitespace before duplicate-normalization checks.
- Added Rust fixture tests for whitespace-wrapped and control-character path keys failing before archive open, plus Python source-contract coverage for the helper and ordering.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 446 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1431-update-payload-hash-path-raw-guard.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1432

- Hardened normal `.aup` tooling payload policy.
- `core/avorax_update_service/src/update_package.rs` now rejects signed `tools/` payload roots through the shared restricted-payload guard during payload limit validation, hash verification, and extraction.
- `tools/update/avorax-build-update-package.ps1` now refuses source `tools/` directories and also rejects any leaked `tools/` payload path before hashing the package manifest.
- Added Rust fixture markers for `tools/` payload rejection and Python source-contract coverage for the verifier/builder policy.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 447 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1432-update-tools-payload-policy.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1433

- Removed the remaining normal update applier activation path for `tools/` payload sections.
- `core/avorax_update_service/src/update_applier.rs` no longer copies `staging/tools` into `install_dir/tools` during normal `.aup` apply.
- Added a Rust source-marker test and Python source-contract coverage to keep normal update apply limited to app, services, engine, docs, and migrations payload sections.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 448 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1433-update-applier-no-tools-activation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1434

- Disabled normal `.aup` migration payload half-support until a separate explicit migration workflow exists.
- `core/avorax_update_service/src/update_manifest.rs` now rejects non-empty signed `migration_steps` after validating their text shape, so malformed steps still fail visibly and safe-looking steps do not enable an unsupported workflow.
- `core/avorax_update_service/src/update_package.rs` now rejects `migrations/` payload roots through the restricted-payload guard and no longer treats migration steps as a payload-root declaration.
- `tools/update/avorax-build-update-package.ps1` now refuses source `migrations/` directories and leaked `migrations/` payload paths before hashing manifest payload evidence.
- `core/avorax_update_service/src/update_applier.rs` no longer copies `staging/migrations` into `install_dir/migrations` during normal `.aup` apply.
- Added Rust fixture markers and Python source-contract coverage for manifest, verifier, builder, and applier migration-policy behavior.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 449 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1434-update-migrations-disabled.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1435

- Tightened normal `.aup` service payload policy.
- `core/avorax_update_service/src/update_package.rs` now accepts only direct `services/avorax_core_service.exe` and `services/avorax_guard_service.exe` payloads when the matching manifest component is declared.
- Unknown service payload files and nested service paths now fail as unsupported normal-update payloads instead of being allowed by any enabled service component.
- `tools/update/avorax-build-update-package.ps1` remains source-accounted as staging only the two known service binaries into `payload/services`.
- Added Rust fixture markers and Python source-contract coverage for service payload shape and allowlist behavior.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 450 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1435-update-service-payload-allowlist.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1436

- Tightened normal `.aup` engine payload policy.
- `core/avorax_update_service/src/update_package.rs` now accepts engine payload files only under explicit runtime subdirectories: `engine/signatures`, `engine/rules`, `engine/ml`, and `engine/trust`.
- `native_engine_assets` is now a parent declaration and no longer authorizes unknown engine subdirectories or direct engine-root files by itself.
- `tools/update/avorax-build-update-package.ps1` now stages only those runtime engine subdirectories for normal updates, deliberately prunes known installer-stage-only `engine/config`, `engine/test_corpus`, and `engine/threat_intel` source children, and rejects any other leaked engine payload before signing/hash manifest creation.
- Added Rust fixture markers and Python source-contract coverage for unknown engine subcomponents, direct subcomponent files, builder pruning, and fail-closed engine payload allowlisting.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 451 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1436-update-engine-payload-allowlist.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1437

- Tightened normal `.aup` engine payload activation.
- `core/avorax_update_service/src/update_applier.rs` now routes `staging/engine` through `copy_engine_payload_section` instead of copying the whole engine tree to `install_dir/engine`.
- The applier now enumerates engine payload children, rejects unknown subcomponents, rejects subcomponent files, detects duplicate normalized component names, and copies only `signatures`, `rules`, `ml`, and `trust` component directories to canonical destinations.
- Added Rust fixture/source-marker coverage and Python source-contract coverage for the applier engine activation allowlist.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 452 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1437-update-applier-engine-activation-allowlist.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1438

- Tightened normal `.aup` service payload activation.
- `core/avorax_update_service/src/update_applier.rs` now routes `staging/services` through `copy_service_payload_section` instead of copying the whole services tree into the install root.
- The applier now enumerates service payload entries, rejects unsupported service files, rejects nested service directories, detects duplicate normalized service filenames, and stages only `avorax_core_service.exe` and `avorax_guard_service.exe` through the bounded atomic `copy_file_staged` path.
- Added Rust fixture/source-marker coverage and Python source-contract coverage for the applier service activation allowlist.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 453 tests`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1438-update-applier-service-activation-allowlist.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1439

- Tightened normal `.aup` docs payload policy and activation.
- `core/avorax_update_service/src/update_package.rs` now requires normal docs payload entries to be Markdown files under `docs` before the signed manifest component declaration can authorize them.
- `tools/update/avorax-build-update-package.ps1` now stages docs through `Copy-NormalUpdateDocsPayload`, rejects non-Markdown docs files, and rejects leaked unsupported docs paths before payload hashes are signed.
- `core/avorax_update_service/src/update_applier.rs` now routes `staging/docs` through `copy_docs_payload_section` instead of copying the whole staged docs tree; the applier enumerates docs files, rejects non-regular or non-Markdown entries, and stages accepted docs through bounded atomic file activation.
- Added Rust fixture/source-marker coverage and Python source-contract coverage for docs verifier, builder, and applier Markdown-only behavior.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 454 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1439-update-docs-payload-markdown-only.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1440

- Tightened normal `.aup` app payload policy and activation so `payload/app` cannot bypass restricted update sections.
- `core/avorax_update_service/src/update_package.rs` now rejects app payload entries whose first install-root child is `engine`, `docs`, `tools`, `driver`, `driver-tools`, or `migrations`, and rejects managed service/updater executable names under `app`.
- `tools/update/avorax-build-update-package.ps1` now rejects leaked `app/` payload paths that would target those restricted install-root surfaces or managed service/updater executables before signed manifest hash creation.
- `core/avorax_update_service/src/update_applier.rs` now routes `staging/app` through `copy_app_payload_section`, validates the staged app tree before copy, and only then performs the existing app tree activation.
- Added Rust fixture/source-marker coverage and Python source-contract coverage for app-payload restricted-path and managed-executable bypass rejection.
- Updated `STATUS.md`, `RUN_LOG.md`, `SECURITY_MODEL.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 455 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1440-update-app-payload-restricted-targets.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1441

- Tightened normal `.aup` app component evidence in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now sets `components.app` from the count of actual staged app payload files instead of only checking for `payload/app/Avorax.exe`.
- This keeps DLL/resource-only app updates valid when they intentionally carry app payload files, while still letting the verifier reject packages whose manifest does not declare `app` for an `app/` payload root.
- Added Python source-contract coverage for the app-component evidence boundary.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 456 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1441-update-app-component-evidence.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1442

- Tightened normal `.aup` engine component evidence in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now fails visibly when a supported normal engine component directory is present but contains no runtime files.
- The builder now derives `native_engine_assets`, `signatures`, `rules`, `ml_model`, and `trust_packs` from counted staged runtime files rather than directory presence alone.
- Added Python source-contract coverage for runtime-file evidence and removal of directory-presence component flags.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 457 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1442-update-engine-component-file-evidence.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1443

- Tightened normal `.aup` docs component evidence in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now derives `components.docs` from counted staged docs payload files instead of docs directory presence.
- This aligns manifest evidence with the existing Markdown-only docs payload builder path, which already rejects empty docs sources and non-Markdown docs files.
- Added Python source-contract coverage for docs component file evidence and removal of directory-presence docs component flags.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 458 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1443-update-docs-component-file-evidence.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1444

- Tightened normal `.aup` service component evidence in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now records explicit staged Core and Guard service payload paths and derives `components.core_service` / `components.guard_service` from those checked staged files.
- This keeps service component manifest evidence aligned with the allowlisted service payload staging path.
- Added Python source-contract coverage for staged service-file evidence and removal of inline service component path checks.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 459 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1444-update-service-component-file-evidence.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1445

- Tightened normal `.aup` app top-level file staging in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates each top-level app payload source file through `Require-File` at copy time instead of copying raw `FullName` after an earlier enumeration check.
- Added Python source-contract coverage to prevent the raw top-level app file copy path from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 459 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1445-update-app-file-copy-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1446

- Tightened normal `.aup` app directory staging in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates each app payload source directory through `Require-Directory`, validates the destination path with `Assert-NoReparsePath`, and then performs the recursive copy.
- Added Python source-contract coverage to prevent the raw recursive app directory copy path from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 459 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1446-update-app-directory-copy-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1447

- Tightened normal `.aup` engine runtime component staging in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates each supported engine component source directory through `Require-Directory`, validates the component destination path with `Assert-NoReparsePath`, and then performs the recursive copy.
- Added Python source-contract coverage to prevent the raw recursive engine component copy path from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 459 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1447-update-engine-component-copy-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1448

- Tightened normal `.aup` top-level app and service file staging in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates copied service source files through `Require-File`, checks their payload service destination paths with `Assert-NoReparsePath`, and then copies through explicit `$sourceFile`/`$destinationFile` variables.
- Top-level app payload files now use the same explicit source-file and destination-path revalidation before copy into `payload/app`.
- Added Python source-contract coverage to prevent the raw inline destination copy paths from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 459 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1448-update-file-destination-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1449

- Tightened normal `.aup` docs file staging in the update-package builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates each Markdown docs source file through `Require-File`, checks the destination file path with `Assert-NoReparsePath`, and then copies through an explicit `$sourceFile` variable.
- Added Python source-contract coverage to prevent the raw inline docs file copy path from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 459 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1449-update-docs-file-destination-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1450

- Tightened update-package artifact activation in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates the final package path, temporary zip path, and backup path before package creation/replacement and revalidates the final package file before hashing it for the update feed.
- Added Python source-contract coverage for the package/temp/backup path checks and the final `Require-File` hash source.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 460 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1450-update-package-artifact-path-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1451

- Tightened update-package zipping in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates each work-tree source file with `Require-File` immediately before `CreateEntryFromFile`, and the zip writer uses the checked `$sourceFile` path instead of the enumerated path.
- Added Python source-contract coverage for the zip-entry source revalidation and checked-path use.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 460 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1451-update-zip-entry-source-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1452

- Tightened update-package zip-entry policy in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now rejects work-tree archive entries outside `manifest.json`, `manifest.sig`, and `payload/...` immediately before `CreateEntryFromFile`.
- Added Python source-contract coverage for the builder-side zip-entry allowlist and unsupported-entry error.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 460 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1452-update-zip-entry-allowlist.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1453

- Tightened update-package manifest signing in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates the `manifest.sig` output path before invoking the external signer and revalidates the produced signature as a regular file before package creation continues.
- Added Python source-contract coverage for the signer output path check and post-signature `Require-File`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 460 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1453-update-signature-output-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1454

- Tightened update-feed package reference generation in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now derives feed `package_url` from the checked final package file name instead of repeating the artifact name as a second hardcoded string.
- Added Python source-contract coverage to prevent hardcoded feed package URL drift from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 460 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1454-update-feed-package-url-derivation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1455

- Tightened update-feed output handling in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates the feed path before atomic write, retains the checked final feed file path from `Require-File`, and reports that checked path in the success output.
- Added Python source-contract coverage for feed path revalidation, checked feed file retention, and checked feed output reporting.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 460 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1455-update-feed-output-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1456

- Tightened update-package success output in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now reports the checked final package file path from `Require-File` instead of the original package path variable.
- Added Python source-contract coverage to prevent unchecked package success output from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 460 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1456-update-package-output-reporting.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1457

- Tightened update metadata timestamp consistency in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now captures one UTC ISO timestamp and uses it for both signed manifest `release_date` and generated feed `published_at`.
- Added Python source-contract coverage to prevent separate manifest/feed timestamp calls from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 461 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1457-update-metadata-timestamp-consistency.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1458

- Tightened update-package payload hashing in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates each staged payload source file with `Require-File` immediately before SHA-256 hashing and hashes the checked `$payloadFile` path.
- Added Python source-contract coverage to prevent enumerated-path payload hashing from returning.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 461 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1458-update-payload-hash-source-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1459

- Tightened update atomic JSON/feed writes in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates generated temporary and backup paths before writing/activation and removes stale random-name collisions through checked regular-file cleanup.
- Added Python source-contract coverage for the atomic writer temp/backup path checks and stale-collision cleanup calls.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1459-update-atomic-writer-temp-path-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1460

- Tightened update atomic JSON/feed activation in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now retains the checked temporary file returned by `Require-File` and uses that checked path for both `File.Replace` and `File.Move`.
- Expanded Python source-contract coverage for checked-temp activation and absence of direct pre-validation temp path activation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1460-update-atomic-writer-checked-temp-activation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1461

- Tightened update package activation in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now retains the checked temporary package returned by `Require-File` and uses that checked path for final `.aup` `File.Replace` and `File.Move`.
- Expanded Python source-contract coverage for checked temporary package activation and absence of direct pre-validation temp package path activation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1461-update-package-checked-temp-activation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1462

- Tightened recursive app and engine staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates app and supported engine source trees immediately before recursive `Copy-Item` staging.
- Expanded Python source-contract coverage for app and engine pre-copy tree revalidation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1462-update-recursive-staging-pre-copy-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1463

- Tightened app component evidence in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now counts staged app payload files through `Get-RegularPayloadFiles`, aligning app manifest evidence with the no-reparse docs and engine evidence paths.
- Expanded Python source-contract coverage for app component no-reparse evidence and absence of the direct staged-app `Get-ChildItem` path.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1463-update-app-component-no-reparse-evidence.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1464

- Tightened docs staging enumeration in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now enumerates docs payload files through `Get-RegularPayloadFiles`, aligning docs staging with the no-reparse docs component evidence path.
- Expanded Python source-contract coverage for docs staging no-reparse enumeration and absence of the direct docs `Get-ChildItem` path.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1464-update-docs-staging-no-reparse-enumeration.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1465

- Tightened the shared payload-file enumeration helper in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates source trees immediately before recursive file enumeration in `Get-RegularPayloadFiles`, covering app/docs/engine component evidence and docs staging callers.
- Expanded Python source-contract coverage for the helper-level pre-enumeration tree revalidation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1465-update-shared-payload-helper-pre-enumeration-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1466

- Tightened payload hashing enumeration in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now enumerates staged payload files for hashing through `Get-RegularPayloadFiles` before each file is revalidated immediately before SHA-256 hashing.
- Expanded Python source-contract coverage for helper-based payload hash enumeration and absence of the direct staged-payload `Get-ChildItem` path in the hash loop.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1466-update-payload-hash-helper-enumeration.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1467

- Tightened top-level app staging enumeration in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates the payload root immediately before top-level file and directory staging enumeration.
- Expanded Python source-contract coverage for pre-enumeration root revalidation around both top-level app staging enumerations.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1467-update-top-level-app-staging-pre-enumeration-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1468

- Tightened update package zip work-tree enumeration in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates the package work tree immediately before archive file enumeration, while preserving per-file revalidation before `CreateEntryFromFile`.
- Expanded Python source-contract coverage for work-tree pre-enumeration revalidation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1468-update-zip-work-tree-pre-enumeration-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1469

- Tightened service payload staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates the payload root immediately before staging allowlisted service binaries, while preserving per-file service source and destination validation.
- Expanded Python source-contract coverage for service payload pre-staging revalidation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1469-update-service-payload-pre-staging-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1470

- Tightened engine child policy enumeration in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates the engine source tree immediately before checking known runtime components, pruned installer-only children, and unsupported engine children.
- Expanded Python source-contract coverage for engine child policy pre-enumeration revalidation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1470-update-engine-child-policy-pre-enumeration-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1471

- Tightened docs payload copy staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now revalidates the docs source tree immediately before Markdown file copy staging, while preserving per-file source and destination validation.
- Expanded Python source-contract coverage for docs pre-copy revalidation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 462 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1471-update-docs-pre-copy-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1472

- Tightened update work-directory cleanup in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now removes the checked directory returned by `Require-Directory` after tree revalidation, rather than removing the pre-validation input path string.
- Expanded Python source-contract coverage for checked cleanup path usage.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 463 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1472-update-work-directory-cleanup-checked-path.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1473

- Tightened stale temporary and backup file cleanup in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now removes the checked file returned by `Require-File`, rather than removing the pre-validation input path string.
- Expanded Python source-contract coverage for checked regular-file cleanup path usage.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 464 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1473-update-temp-backup-file-cleanup-checked-path.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1474

- Tightened checked directory creation in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now normalizes to a full path after no-reparse path validation and uses that post-validation full path for directory creation and final directory validation.
- Expanded Python source-contract coverage for checked directory creation path usage.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 465 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1474-update-checked-directory-creation-path.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1475

- Tightened package artifact activation in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now derives post-validation full paths for final package, temporary zip, and backup files and uses those full paths for temp zip creation, package target activation, backup activation, cleanup, and final package validation.
- Expanded Python source-contract coverage for package artifact full-path activation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 465 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1475-update-package-artifact-full-path-activation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1476

- Tightened atomic JSON/feed temporary and backup handling in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now derives post-validation full paths for atomic temp and backup files and uses those full paths for stale cleanup, write, final temp validation, backup activation, and final cleanup.
- Expanded Python source-contract coverage for atomic writer temp/backup full-path activation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 465 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1476-update-atomic-writer-temp-backup-full-path-activation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1477

- Tightened raw UTF-8 writes in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now normalizes the raw UTF-8 writer input to a full path before `WriteAllText`, keeping the final write target aligned with checked atomic temp paths.
- Expanded Python source-contract coverage for the raw UTF-8 full-path write target.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 465 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1477-update-raw-utf8-full-path-write-target.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1478

- Tightened update manifest signing in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now passes a checked manifest file and post-validation signature output path to the external signer, then revalidates produced signature output through that checked target.
- Expanded Python source-contract coverage for manifest signer checked paths.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 465 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1478-update-manifest-signer-checked-paths.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1479

- Tightened shared item validation in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now normalizes paths after no-reparse path validation and uses post-validation full paths for shared `Get-Item` lookup and item-kind diagnostics in `Require-Item`.
- Expanded Python source-contract coverage for shared item validation full-path lookup.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 466 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1479-update-shared-item-full-path-lookup.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1480

- Tightened stale regular-file cleanup in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now validates cleanup paths for reparse traversal, normalizes them to a full path, uses that full path for the existence check, and delegates removal through `Require-File` on the checked path.
- Expanded Python source-contract coverage for cleanup full-path existence checks and checked removal.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 466 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1480-update-cleanup-full-path-existence-check.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1481

- Tightened existing directory cleanup in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now validates cleanup directories for reparse traversal, normalizes them to a full path, uses that full path for the existence check, and delegates tree revalidation/removal through `Require-Directory` on the checked path.
- Expanded Python source-contract coverage for directory cleanup full-path existence checks and checked recursive removal.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 466 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1481-update-directory-cleanup-full-path-existence-check.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1482

- Tightened component regular-file probes in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now validates component file probe paths for reparse traversal, normalizes them to a full path, uses that full path for the existence check, and delegates file evidence through `Require-File` on the checked path.
- Expanded Python source-contract coverage for component regular-file probe full-path existence checks and checked file evidence.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 467 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1482-update-component-file-probe-full-path-existence-check.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1483

- Tightened component directory probes in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now validates component directory probe paths for reparse traversal, normalizes them to a full path, uses that full path for the existence check, and delegates directory evidence through `Require-Directory` on the checked path.
- Expanded Python source-contract coverage for component directory probe full-path existence checks and checked directory evidence.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 468 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1483-update-component-directory-probe-full-path-existence-check.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1484

- Tightened shared no-reparse tree validation in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now enumerates the checked directory returned by `Require-Directory` during recursive reparse validation instead of falling back to the pre-validation input path string.
- Expanded Python source-contract coverage for checked recursive tree enumeration.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 469 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1484-update-no-reparse-tree-checked-enumeration.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1485

- Tightened payload file enumeration in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked payload directory through `Require-Directory`, validates that checked directory for recursive reparse entries, and enumerates payload files from that checked directory instead of the pre-validation input path string.
- Expanded Python source-contract coverage for checked payload file enumeration and updated the existing engine component contract to reject the old `$Path` enumeration.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1485-update-payload-file-checked-enumeration.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1486

- Tightened engine child policy enumeration in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked engine directory through `Require-Directory`, validates that checked directory for recursive reparse entries, and enumerates unknown/pruned engine source children from that checked directory instead of the pre-validation input path string.
- Expanded the existing Python source-contract coverage for engine component policy to reject old `$SourceEngine` child enumeration.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1486-update-engine-child-policy-checked-enumeration.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1487

- Tightened docs Markdown staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked docs directory through `Require-Directory`, revalidates that checked directory before Markdown staging, and derives Markdown relative paths from that checked root instead of the pre-validation input path string.
- Expanded the existing Python source-contract coverage for docs payload staging to reject old `$SourceDocs` tree validation and relative path derivation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1487-update-docs-markdown-checked-staging-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1488

- Tightened top-level app file staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked payload root through `Require-Directory`, revalidates that checked root before direct app file staging, and enumerates top-level app files from that checked root instead of the pre-validation input path string.
- Expanded the existing Python source-contract coverage for top-level app file staging to reject old `$payloadSource` direct file enumeration.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1488-update-app-file-checked-staging-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1489

- Tightened top-level app directory staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked payload root through `Require-Directory`, revalidates that checked root before direct app directory staging, and enumerates top-level app directories from that checked root instead of the pre-validation input path string.
- Expanded the existing Python source-contract coverage for top-level app directory staging to reject old `$payloadSource` direct directory enumeration.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1489-update-app-directory-checked-staging-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1490

- Tightened service payload staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked payload root through `Require-Directory`, revalidates that checked root before service payload staging, and resolves Core/Guard service executable candidates from that checked root instead of the pre-validation input path string.
- Expanded the existing Python source-contract coverage for service payload staging to reject old `$payloadSource` service candidate paths.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1490-update-service-payload-checked-staging-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1491

- Tightened payload hash root handling in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked staged payload root through `Require-Directory`, enumerates payload hash inputs from that checked root, and derives manifest payload-hash keys from that checked root instead of the pre-validation input path string.
- Expanded the existing Python source-contract coverage for payload hashing to reject old `$payload` helper enumeration and relative path derivation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1491-update-payload-hash-checked-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1492

- Tightened app component evidence in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked staged app root through `Require-Directory` before deriving manifest `components.app` evidence.
- Expanded the existing Python source-contract coverage for app component evidence to reject old `$payloadApp` helper enumeration.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1492-update-app-component-checked-evidence-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1493

- Tightened service component evidence in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked staged services root through `Require-Directory` before deriving Core/Guard service manifest flags.
- Expanded the existing Python source-contract coverage for service component evidence to reject old `$payloadServices` service evidence paths.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1493-update-service-component-checked-evidence-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1494

- Tightened engine component evidence in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked staged engine root through `Require-Directory` before deriving signatures/rules/ml/trust runtime component manifest flags.
- Expanded the existing Python source-contract coverage for engine component evidence to reject old `$payloadEngine` runtime evidence paths.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1494-update-engine-component-checked-evidence-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1495

- Tightened docs component evidence in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked staged docs root through `Require-Directory` before deriving manifest `components.docs` evidence.
- Expanded the existing Python source-contract coverage for docs component evidence to reject old `$payloadDocs` helper enumeration.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1495-update-docs-component-checked-evidence-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1496

- Tightened package archive work-root handling in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked work directory through `Require-Directory`, revalidates that checked root, enumerates ZIP work files from that checked root, and derives archive entry names from that checked root instead of the pre-validation `$work` string.
- Expanded the existing Python source-contract coverage for package artifact creation to reject old `$work` archive enumeration and entry-name derivation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1496-update-archive-checked-work-root.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1497

- Tightened engine runtime component staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked engine source root through `Require-Directory`, resolves supported runtime component paths from that checked root, and counts runtime files from checked component directories before recursive staging.
- Expanded the existing Python source-contract coverage for engine component staging to reject old `$SourceEngine` component path resolution and old `$source` runtime-file counting.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1497-update-engine-checked-component-staging.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1498

- Tightened docs payload staging in the normal `.aup` builder.
- `tools/update/avorax-build-update-package.ps1` now resolves the checked docs source root through `Require-Directory`, enumerates Markdown docs files through the shared payload-file helper from that checked root, and derives staging-relative paths from that checked root.
- Expanded the existing Python source-contract coverage for docs payload staging to reject old `$SourceDocs` Markdown enumeration and staging-root derivation.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/in-app-updates.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- PowerShell parse-only verification passed for `tools/update/avorax-build-update-package.ps1`.
- Full gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1498-update-docs-checked-source-staging.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1499

- Tightened signed `.aup` archive manifest/signature entry cardinality.
- `core/avorax_update_service/src/update_package.rs` now rejects duplicate `manifest.json` or `manifest.sig` entries and requires both entries to appear exactly once before manifest reads, signature reads, payload hash scans, or extraction loops proceed.
- Added a Rust fixture test for duplicate `manifest.json` rejection and expanded Python source-contract coverage for the cardinality guard.
- Updated Rust payload-policy test package fixtures to include minimal `manifest.json` and `manifest.sig` entries so future Cargo execution still reaches the intended payload-policy assertions under the new cardinality guard.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1499-update-aup-manifest-signature-cardinality.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1500

- Expanded signed `.aup` manifest/signature cardinality fixture coverage.
- `core/avorax_update_service/src/update_package.rs` now includes explicit Rust fixtures for duplicate `manifest.sig` rejection and missing `manifest.sig` rejection, complementing the existing duplicate `manifest.json` fixture.
- Expanded Python source-contract coverage so the duplicate and missing signature fixture names remain present.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1500-update-aup-signature-cardinality-fixtures.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1501

- Expanded signed `.aup` manifest/signature cardinality fixture coverage.
- `core/avorax_update_service/src/update_package.rs` now includes an explicit Rust fixture for missing `manifest.json` rejection, completing duplicate/missing manifest/signature fixture symmetry around the checkpoint 1499 cardinality guard.
- Expanded Python source-contract coverage so the missing manifest fixture name remains present.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1501-update-aup-missing-manifest-fixture.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1502

- Tightened signed `.aup` payload validation.
- `core/avorax_update_service/src/update_package.rs` now rejects archives with zero payload files during payload-limit validation, preventing payload hashing or extraction from reporting success on a manifest/signature-only no-op archive.
- Added a Rust empty-payload fixture and expanded Python source-contract coverage for the non-empty payload guard.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1502-update-aup-non-empty-payload-validation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1503

- Tightened signed `.aup` archive validation for restricted payload directory entries.
- `core/avorax_update_service/src/update_package.rs` now applies restricted payload-root checks during archive entry-name validation, so entries such as `payload/tools/`, `payload/migrations/`, and driver payload roots fail even when represented only as ZIP directory entries.
- Added a Rust fixture for a restricted `payload/tools/` directory entry and expanded Python source-contract coverage for the archive-name guard.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1503-update-aup-restricted-directory-entry-rejection.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1504

- Tightened signed `.aup` archive entry-name text validation.
- `core/avorax_update_service/src/update_package.rs` now rejects raw ZIP entry names containing NUL/control characters or excessive length before manifest/payload allowlist and payload path checks continue.
- Added a Rust fixture for a control-character payload entry name and expanded Python source-contract coverage for the archive entry-name text guard.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1504-update-aup-entry-name-text-guard.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1505

- Tightened signed `.aup` payload extraction activation.
- `core/avorax_update_service/src/update_package.rs` now passes the canonical extraction destination into payload file activation and revalidates the target parent chain against that root immediately before `std::fs::rename`.
- Expanded Python/Rust source-contract coverage so activation must recheck the temp file, target parent chain, and final target before rename.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1505-update-aup-extraction-parent-chain-activation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1506

- Tightened shared staged-file activation used by update apply/staged writes.
- `core/avorax_update_service/src/path_safety.rs` now revalidates the target parent chain against the operation boundary after any existing target removal and immediately before `std::fs::rename`.
- Expanded Python/Rust source-contract coverage so shared staged activation must keep the post-removal parent-chain recheck before rename.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1506-update-staged-activation-parent-chain.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1507

- Tightened shared staged-file copy source handling used by update apply/staged writes.
- `core/avorax_update_service/src/path_safety.rs` now checks staged copy sources as regular bounded files before open, compares the opened handle metadata against pre/post-open source metadata, and rejects changed sources before payload bytes are copied.
- Expanded Python/Rust source-contract coverage so source-open revalidation remains before `copy_staged_file_payload_limited`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1507-update-staged-source-open-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1508

- Tightened update apply payload-section enumeration.
- `core/avorax_update_service/src/update_applier.rs` now revalidates app, service, engine, and docs payload-section roots as directory/non-reparse paths immediately before walking or reading entries.
- Expanded Python/Rust source-contract coverage so section-root revalidation must occur before `WalkDir::new(source)` or `std::fs::read_dir(source)`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1508-update-apply-section-root-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1509

- Tightened update apply install-root revalidation.
- `core/avorax_update_service/src/update_applier.rs` now revalidates the canonical install directory as an existing directory/non-reparse path after canonicalization and again immediately before payload-section activation.
- Expanded Python/Rust source-contract coverage so install-root revalidation remains before app/service/engine/docs apply work begins.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1509-update-apply-install-root-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-04 continuation checkpoint 1510

- Tightened rollback restore install-root revalidation.
- `core/avorax_update_service/src/rollback.rs` now revalidates the canonical install directory as an existing directory/non-reparse path after canonicalization and again immediately before copying rollback snapshot items.
- Expanded Python/Rust source-contract coverage so rollback install-root revalidation remains before the restore loop.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1510-rollback-install-root-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1511

- Tightened rollback snapshot canonical-root revalidation.
- `core/avorax_update_service/src/rollback.rs` now revalidates the canonical rollback root and canonical rollback snapshot directories as existing directory/non-reparse paths before restore reads snapshot contents.
- Expanded Python/Rust source-contract coverage so root/snapshot revalidation remains after canonicalization and containment checks.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1511-rollback-snapshot-root-revalidation.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1512

- Tightened rollback latest-snapshot root enumeration.
- `core/avorax_update_service/src/rollback.rs` now resolves the rollback root to a canonical, revalidated directory/non-reparse path before `restore_latest_snapshot` enumerates snapshot entries.
- Expanded Python/Rust source-contract coverage so latest-snapshot enumeration remains after canonical root revalidation while existing linked/reparse snapshot-entry rejection stays in place.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1512-rollback-latest-root-enumeration.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1513

- Tightened update failure-path staging cleanup diagnostics.
- `core/avorax_update_service/src/update_applier.rs` now includes staging cleanup failures in returned error context on stop-service, payload-apply, rollback-restore, and restart failure paths, while keeping the same structured report fields.
- Expanded Python/Rust source-contract coverage so failed update contexts retain cleanup evidence instead of relying only on `update_report.json`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/reports/update-flow-audit.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1513-update-failure-cleanup-context.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1514

- Tightened Guard finite process-watch completion honesty.
- `core/zentor_guard_service/src/main.rs` now distinguishes inspected processes from inspection-error outcomes; finite `watch_processes` returns `ok:false` with `watchCompletedWithInspectionErrors` when metadata/hash/native/compat inspection errors occurred and no confirmed threat was observed.
- Expanded Rust/Python source-contract coverage so process inspection errors cannot collapse into a clean `watchCompleted` no-threat success claim.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 470 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1514-guard-watch-inspection-error-completion.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1515

- Tightened Local Core realtime watcher empty-plan honesty.
- `core/zentor_local_core/src/watcher/mod.rs` now reports `mode: "stopped"` and explicit `no-accessible-watch-paths` or `no-watch-paths-requested` limitations when `start_watch` receives no usable watched directory, instead of returning an inactive `userModeBestEffort` state that could be misread as partial monitoring.
- Expanded Rust/Python source-contract coverage so all-invalid and empty watcher plans remain inactive, pathless, stopped, and limitation-bearing.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 471 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1515-local-core-watcher-empty-plan.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1516

- Tightened Local Core native self-test health evidence coupling.
- `core/zentor_local_core/src/main.rs` now derives `native_self_test` and `native_self_test_error` together through `native_self_test_status_and_error(...)`, so engine self-test errors cannot regress to a bare `false` without the error detail branch.
- Expanded Rust/Python source-contract coverage so the health response no longer contains the old `Err(_) => false` self-test branch and keeps the error-context branch.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 471 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1516-local-core-native-self-test-status-error.md`.
- Cargo/rustfmt runtime verification remains blocked because `cargo` and `rustfmt` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1517

- Tightened Flutter local-core action IPC success honesty.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now treats `ok:true` action responses with IPC protocol warnings as failed action results instead of clean success.
- Expanded Python/Dart source-contract coverage so `_actionResult` reads bounded `scanErrors`/`scan_errors` protocol warnings before accepting `ok:true`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 472 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1517-flutter-action-ipc-protocol-warning.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1518

- Tightened Flutter local-core watcher IPC success honesty.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now treats `ok:true` watcher responses with IPC protocol warnings as watcher errors instead of clean realtime-monitoring state.
- Expanded Python/Dart source-contract coverage so `_watcherProtocolError` reads bounded `scanErrors`/`scan_errors` protocol warnings before accepting `ok:true`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 473 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1518-flutter-watcher-ipc-protocol-warning.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1519

- Tightened Flutter local-core cancel IPC success honesty.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now treats `ok:true` cancel IPC responses with collected protocol warnings as cancellation failures instead of clean success.
- Expanded Python/Dart source-contract coverage so `_sendCancelScanRequest` checks `stdout.protocolWarnings` before accepting `ok:true`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 474 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1519-flutter-cancel-ipc-protocol-warning.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1520

- Tightened Flutter local-core list IPC success honesty.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now rejects `ok:true` quarantine and allowlist list responses that include collected IPC protocol warnings before records are parsed as trusted UI evidence.
- Expanded Python/Dart source-contract coverage so `listQuarantine` and `listAllowlist` route through `_rejectListProtocolWarnings(...)`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 475 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1520-flutter-list-ipc-protocol-warning.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1521

- Tightened Flutter local-core health IPC diagnostic honesty.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart` now folds collected `scanErrors`/`scan_errors` protocol warnings from `ok:true` health responses into `healthDiagnostics`, so they surface through `LocalCoreHealth.lastError` instead of disappearing behind normal health fields.
- Expanded Python/Dart source-contract coverage so `healthSummary` records protocol warnings before `_healthLastErrorWithDiagnostics(...)` aggregates the final status diagnostic.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1521-flutter-health-ipc-protocol-warning.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1522

- Tightened Flutter malware-engine health audit severity honesty.
- `apps/zentor_client/lib/app/app_state.dart` now logs an available engine health result as `warning` when `healthDetails` contains diagnostics, while clean available results remain `info` and unavailable results remain `warning`.
- Expanded Python/Dart source-contract coverage so `healthEventSeverity` is derived after `healthDetails` and used by the malware-engine health event.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1522-flutter-health-event-severity.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1523

- Tightened Flutter protected-status UI handling for engine diagnostics.
- Home, Protection, and Settings engine-attention helpers now treat a non-empty `lastEngineError` as attention-required evidence even when malware/native engine status values otherwise look available/ready.
- Settings now shows an `Engine diagnostic` row for `lastEngineError`, and Protection native-engine details include the same diagnostic.
- Updated Python/Dart source-contract coverage so these surfaces cannot present fully green protection while engine diagnostics are present.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1523-flutter-engine-diagnostic-status-ui.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1524

- Tightened Flutter protection-start state handling for engine diagnostics.
- `apps/zentor_client/lib/app/app_state.dart` now includes non-empty `lastEngineError` in protection-start limitations, logs the start as `protection_start_limited`, and prevents `ProtectionStatus.protected` when engine diagnostics are present.
- Expanded Python/Dart source-contract coverage so `engineDiagnosticWarning` is included in `startWarning`, `errorMessage`, and the `engineFullyReady` guard.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1524-flutter-protection-start-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1525

- Tightened Flutter scan-start audit handling for engine diagnostics.
- `apps/zentor_client/lib/app/app_state.dart` now includes non-empty `lastEngineError` in scan-start limitations, so scans started while engine diagnostics are visible log `scan_started_with_limitations` at warning severity instead of clean `scan_started`/info evidence.
- Expanded Python/Dart source-contract coverage so `engineDiagnosticLimitation` is built before scan-start event logging and included in `scanStartLimitations`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1525-flutter-scan-start-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1526

- Tightened scheduled quick-scan start audit handling for engine diagnostics.
- `_runScheduledQuickScan` now includes non-empty `lastEngineError` as `scheduledScanDiagnostic` details and logs `scheduled_quick_scan_started` at warning severity when engine diagnostics are visible, instead of always emitting scan/info start evidence.
- Expanded Python/Dart source-contract coverage so the scheduled quick-scan start event derives severity from `scheduledScanDiagnostic`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1526-flutter-scheduled-scan-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1527

- Tightened Home native-engine metric handling for engine diagnostics.
- `apps/zentor_client/lib/features/home/home_screen.dart` now routes the `Avorax Native Engine` metric through state-aware `_nativeEngineLabel(state)` and `_nativeEngineDetail(state)`, so non-empty `lastEngineError` shows `Attention needed` plus diagnostic detail instead of ready/native-engine reassurance.
- Expanded Python/Dart source-contract coverage so the Home native-engine metric cannot use status-only ready labeling when engine diagnostics are present.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1527-home-native-engine-diagnostic-metric.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1528

- Tightened Device native-engine metric handling for engine diagnostics.
- `apps/zentor_client/lib/features/device/device_screen.dart` now routes the `Avorax Native Engine` metric through state-aware `_nativeEngineLabel(state)` and includes `lastEngineError` in `_nativeEngineDetail(state)`, so the Device page cannot show status-only `Ready` while current engine diagnostics exist.
- Expanded Python/Dart source-contract coverage so the Device native-engine metric checks `lastEngineError` before `nativeEngineStatus` and includes the diagnostic detail.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1528-device-native-engine-diagnostic-metric.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1529

- Tightened Settings native-status row handling for engine diagnostics.
- `apps/zentor_client/lib/features/settings/settings_screen.dart` now routes the `Native status` value through state-aware `_nativeEngineLabel(state)`, so non-empty `lastEngineError` shows `Attention needed` instead of status-only `Ready` while the existing `Engine diagnostic` row remains visible.
- Expanded Python/Dart source-contract coverage so Settings checks `lastEngineError` before `nativeEngineStatus` for the native status value.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1529-settings-native-status-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1530

- Tightened Protection native-engine metric and checklist handling for engine diagnostics.
- `apps/zentor_client/lib/features/protection/protection_screen.dart` now routes both the `Avorax Native Engine` metric value and the `Native Engine` checklist row through state-aware `_nativeEngineChecklistLabel(state)`, so non-empty `lastEngineError` shows `Attention needed` instead of status-only `Ready`.
- Expanded Python/Dart source-contract coverage so Protection checks `lastEngineError` before `nativeEngineStatus` for native-engine status values.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1530-protection-native-engine-diagnostic-status.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1531

- Tightened Home native-rule count fallback handling for engine diagnostics.
- `apps/zentor_client/lib/features/home/home_screen.dart` now keeps real `nativeRuleCount > 0` evidence visible, but only uses the `nativeEngineStatus == 'ready'` fallback to show `0 rules loaded` when no `lastEngineError` is visible.
- Expanded Python/Dart source-contract coverage so the Home native-rule count helper checks `lastEngineError` before using ready-status fallback evidence.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1531-home-native-rule-count-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1532

- Tightened Protection native pack/count fallback handling for engine diagnostics.
- `apps/zentor_client/lib/features/protection/protection_screen.dart` now keeps real native signature/rule count evidence visible, but only uses `nativeEngineStatus == 'ready'` fallback labels for `Native rules`, `Signature Pack`, and `Rule Pack` when no `lastEngineError` is visible.
- Expanded Python/Dart source-contract coverage so Protection pack/count helpers check `lastEngineError` before using ready-status fallback evidence.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1532-protection-native-pack-count-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1533

- Tightened Settings native packaged-count fallback handling for engine diagnostics.
- `apps/zentor_client/lib/features/settings/settings_screen.dart` now keeps real native signature/rule count evidence visible, but only uses `nativeEngineStatus == 'ready'` fallback labels for `Native signatures` and `Native rules` when no `lastEngineError` is visible.
- Expanded Python/Dart source-contract coverage so Settings packaged-count helpers check `lastEngineError` before using ready-status fallback evidence.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1533-settings-native-packaged-count-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1534

- Tightened Protection quarantine readiness handling for engine diagnostics.
- `apps/zentor_client/lib/features/protection/protection_screen.dart` now prevents the `Quarantine` checklist row from reporting `Available` while `lastEngineError` is visible, even if malware/native engine status values otherwise look available/ready.
- Expanded Python/Dart source-contract coverage so `_quarantineReadinessLabel(state)` checks `lastEngineError` before returning `Available`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1534-protection-quarantine-readiness-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1535

- Tightened Protection native-engine detail copy ordering for engine diagnostics.
- `apps/zentor_client/lib/features/protection/protection_screen.dart` now makes `_nativeEngineProtectionDetail(state)` show `Engine diagnostic: ...` as the first native-engine detail line when `lastEngineError` is visible, instead of leading with the reassuring native-engine-ready scanner copy.
- Expanded Python/Dart source-contract coverage so the engine diagnostic detail appears before `Primary offline scanner` copy.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1535-protection-native-engine-detail-diagnostic-first.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1536

- Tightened Device native-engine diagnostic detail normalization.
- `apps/zentor_client/lib/features/device/device_screen.dart` now derives a trimmed `diagnostic` from `lastEngineError` before rendering Device `Engine diagnostic: ...`, avoiding raw whitespace-preserved diagnostic copy while keeping diagnostic-first detail.
- Expanded Python/Dart source-contract coverage so Device native-engine detail uses `final diagnostic = state.lastEngineError?.trim()` and `Engine diagnostic: $diagnostic`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1536-device-native-engine-diagnostic-detail-trimmed.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1537

- Tightened Settings engine-diagnostic row normalization.
- `apps/zentor_client/lib/features/settings/settings_screen.dart` now derives a trimmed `engineDiagnostic` in the Settings build path before rendering the `Engine diagnostic` value row, avoiding raw whitespace-preserved `lastEngineError` display.
- Expanded Python/Dart source-contract coverage so Settings requires `final engineDiagnostic = state.lastEngineError?.trim();` and `_ValueRow('Engine diagnostic', engineDiagnostic!)`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1537-settings-engine-diagnostic-row-trimmed.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1538

- Tightened Scan engine-unavailable last-error diagnostic normalization.
- `apps/zentor_client/lib/features/scan/scan_screen.dart` now derives a trimmed `scanEngineDiagnostic` before rendering the `Last error` diagnostic chip, so whitespace-only engine errors are hidden and visible engine errors do not preserve leading/trailing whitespace.
- Expanded Python/Dart source-contract coverage so Scan requires `final scanEngineDiagnostic = state.lastEngineError?.trim();`, `scanEngineDiagnostic?.isNotEmpty ?? false`, and `value: scanEngineDiagnostic!`.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1538-scan-engine-last-error-trimmed.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1539

- Tightened Scan signature/rule pack status fallback handling for engine diagnostics.
- `apps/zentor_client/lib/features/scan/scan_screen.dart` now passes `engineDiagnosticVisible` into `_assetPackStatusLabel(...)`, preserving real count evidence while suppressing ready-status `Missing` fallback labels when `lastEngineError` is visible.
- Expanded Python/Dart source-contract coverage so Scan pack labels require `required bool engineDiagnosticVisible`, `nativeEngineStatus == 'ready' && !engineDiagnosticVisible`, and `engineDiagnosticVisible:` call-site evidence.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1539-scan-pack-status-engine-diagnostic.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1540

- Tightened protection-start local prevention gating for engine diagnostics.
- `apps/zentor_client/lib/app/app_state.dart` now computes `engineDiagnosticWarning` before `hasLocalPrevention` and requires `nativeEngineReadyWithoutDiagnostic` before native ready-status can satisfy local prevention, so a native-ready status with visible diagnostics no longer starts the watcher/configuration path as local prevention evidence by itself.
- Protection-start failure logs and visible error copy now include the engine diagnostic warning when diagnostics were the blocker.
- Expanded Python/Dart source-contract coverage so `engineDiagnosticWarning` appears before `final hasLocalPrevention`, `nativeEngineReadyWithoutDiagnostic` gates local prevention and protected-state readiness, and `preventionFailureDetails` includes diagnostic evidence.
- Updated `STATUS.md`, `RUN_LOG.md`, `docs/audit/known-blockers.md`, and `docs/audit/engine-control-matrix.md`.
- Focused verification passed locally: `python source-contract run passed: 476 tests`.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1540-protection-start-native-ready-diagnostic-gate.md`.
- Flutter/Dart runtime verification remains blocked because `flutter` and `dart` are not installed or not on `PATH` in this Codex shell.

## 2026-07-05 continuation checkpoint 1541

- Tightened malware-engine health diagnostic normalization before UI/audit storage.
- `apps/zentor_client/lib/app/app_state.dart` now trims each non-empty health detail before joining `healthDetails`, then stores `lastEngineError: healthDetails` and clears it when `healthDetails.isEmpty`.
- This prevents raw whitespace-preserved `health.lastError` from being stored directly while keeping self-test fallback diagnostics and health-event severity behavior intact.
- Updated `apps/zentor_client/test/app_visual_policy_test.dart` to use formatter-stable source windows and to verify trimmed health-details, `lastEngineError: healthDetails`, and `clearLastEngineError: healthDetails.isEmpty`.
- Updated `tests/test_custom_driver_contract.py` to account for Dart formatter output and the new normalized health-details flow.
- Focused verification passed locally: `python source-contract run passed: 476 tests`, `dart format --set-exit-if-changed` passed for the touched Dart files, and `flutter test test\app_visual_policy_test.dart --plain-name "controller app detection and malware health events are categorized"` passed.
- Full available gate verification is recorded in `.workflow/ultracode/avorax-hardening/results/1541-malware-health-details-normalized.md`.

## 2026-07-05 continuation checkpoint 1542

- Started real Rust workspace verification now that the Rust toolchain is available through absolute paths.
- Fixed native-engine compile blockers: `core/zentor_native_engine/src/trust/microsoft_trust.rs` now uses `anyhow::ensure!` consistently, and `core/zentor_native_engine/src/engine.rs` now constructs `ScanProgress` with `ScanJobId(...)` instead of a raw `String`.
- Fixed an update-service syntax blocker in `core/avorax_update_service/src/main.rs` by correcting the `checked_cli_install_dir_from_text(cli_positional_value_or_reject(...)? )` call shape.
- Ran rustfmt on the touched Rust files and updated formatter-stable Python source contracts after Rust/Dart format output changed source layout.
- Focused Rust verification passed locally: `cargo test --manifest-path core\zentor_native_engine\Cargo.toml --no-run`.
- Workspace Rust verification is now materially unblocked further but still failing on documented update-service and guard-service compile errors; details are recorded in `.workflow/ultracode/avorax-hardening/results/1542-rust-workspace-compile-triage.md`.

## 2026-07-05 continuation checkpoint 1543

- Continued Rust workspace compile triage and removed the remaining `cargo test --workspace --no-run` blockers across update-service, guard-service, and local-core.
- `core/avorax_update_service/src/update_applier.rs` now derives `Debug` for payload helper structs used by `unwrap_err()` tests and uses valid offset substring searches; `core/avorax_update_service/src/update_package.rs` now calls extraction helper methods through `Self::...`.
- `core/zentor_guard_service/src/main.rs` now separates ClamAV command output from ACL command output with `BoundedGuardClamavCommandOutput`, uses the correct `windows-sys` DPAPI bindings, and the guard test env lock recovers from poisoned locks so one failing test does not hide later evidence; `driver_ipc.rs` initializes and recovers its test env lock correctly.
- `core/zentor_local_core/src/main.rs` now builds the native-engine-unavailable health body through `serde_json::Map` instead of a huge `json!` macro; local-core DPAPI imports and test-only `Debug`/type/offset-search compile issues were fixed.
- Verification passed: `cargo test --workspace --no-run`, `cargo test --manifest-path` no-run for update-service/guard/local-core, `python source-contract run passed: 476 tests`, and `rustfmt --check` for touched Rust files.
- Runtime verification remains partial: full `cargo test --workspace` stops on an update-key test executable requiring elevation (`os error 740`), and `cargo test -p zentor_guard_service -- --test-threads=1` now reports `188 passed; 24 failed` with remaining guard source-marker, signature-pack fixture, and external-driver-scan JSON failures.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1543-rust-workspace-no-run-unblocked.md`.

## 2026-07-05 continuation checkpoint 1544

- Continued real Rust runtime stabilization now that Flutter, Dart, Cargo, rustfmt, and Git are available through explicit Windows paths.
- Repaired native engine asset authenticity drift by updating current `.zsig` and `.zrule` `pack_sha256` metadata to match the canonical signed-pack content, without changing signature/rule bodies.
- Reworked native-engine test fixtures so signature/rule packs are generated through the same canonical pack builders/verifiers used by production, and fixed a stale threat-intel action policy fixture.
- Brought Guard Service runtime tests to green by fixing source-marker drift, native/rule pack verification fallout, external-driver JSON fallout, and fatal-log source assertions.
- Improved local-core runtime behavior by serializing `ScanProgress` as camelCase JSON and by adding a controlled staged replace path for quarantine restore/delete metadata status updates while preserving exclusive first-write semantics.
- Verification passed: targeted `rustfmt --check`; `cargo test --workspace --no-run`; `cargo test -p zentor_guard_service -- --test-threads=1` (`212 passed`); `cargo test -p zentor_native_engine signature -- --test-threads=1` (native signature library `45 passed`, signature compiler `5 passed`); canonical local verifier for all bundled `.zsig`/`.zrule` packs.
- Runtime verification remains partial: `cargo test -p zentor_local_core -- --test-threads=1` improved to `388 passed; 23 failed`; `cargo test --workspace --exclude avorax_update_service -- --test-threads=1` still fails because of those local-core regressions; full `cargo test --workspace` remains blocked by the update-key test executable requiring elevation (`os error 740`).
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1544-guard-native-runtime-assets-local-core-partial.md`.

## 2026-07-05 continuation checkpoint 1545

- Continued Rust runtime stabilization and closed the remaining local-core runtime cluster from checkpoint 1544.
- Local-core now reports scan progress as camelCase JSON, preserves context in allowlist/migration/quarantine/ransomware guard errors, uses staged replacement for restore/delete quarantine metadata status updates, rejects authenticated tampered-payload restore fixtures, and keeps source contracts aligned with the safer metadata/diagnostic paths.
- Native-engine runtime source/fixture drift is repaired for PE resource parsing, asset alias checks, scan/cancel/restore source contracts, invalid ML schema diagnostics, native quarantine cleanup ordering, rule-pack sibling inspection, Microsoft trust probe compatibility, quarantine trust roots, and risk-fusion omission text.
- Verification passed: `cargo test -p zentor_local_core -- --test-threads=1` (`411 passed`); `cargo test -p zentor_native_engine --lib -- --test-threads=1` (`284 passed`); `cargo test --workspace --exclude avorax_update_service -- --test-threads=1` passed; `cargo test --workspace --no-run` passed.
- Full workspace runtime still stops before executing update-service runtime tests because `avorax_generate_update_key` requires elevation on this host (`os error 740`).
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1545-local-core-native-runtime-green.md`.

## 2026-07-05 continuation checkpoint 1546

- Continued Flutter/Dart runtime stabilization now that Flutter and Dart are installed and available through explicit Windows paths.
- Fixed client update-feed redirect handling so trusted GitHub release feeds map to the explicit `update-feed.json` asset name without loosening normal `.aup` package URL validation.
- Fixed local event/audit durability: multiline event `details` are allowed for readable path-plus-diagnostic evidence, unsafe control characters remain rejected, corrupt persisted local event history recovery is retained across the next write, and successful background quarantine/allowlist refreshes no longer clear unrelated scan/protection error banners.
- Cleaned Flutter analyzer blockers by restoring the missing protected-app `DetectedApp` import, removing dead helper wrappers, updating source-marker tests, adding the direct test dependency on `path_provider_platform_interface`, and keeping IPC/list parsing null-safety explicit.
- Verification passed: `flutter test --reporter compact` (`414 passed`); `flutter analyze` (`No issues found`); focused suites for update service/controller, local-core IPC diagnostics, visual policy, offline scan, local events, platform info, and scan target planning passed during triage.
- Remaining full-project blocker is unchanged from checkpoint 1545: full Rust workspace runtime still cannot complete because the update-key test executable requires elevation on this host.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1546-flutter-runtime-analyze-green.md`.

## 2026-07-05 continuation checkpoint 1547

- Continued Rust update-service runtime stabilization and closed the full-workspace elevation blocker from checkpoints 1545-1546.
- Added an explicit Windows `asInvoker` manifest for update-service binaries from `core/avorax_update_service/build.rs`, preventing Windows installer-name/UAC heuristics from requiring elevation for non-privileged test execution. This does not weaken ACL/service privilege checks for real machine-wide update operations.
- Fixed Windows path-chain validation in `core/avorax_update_service/src/path_safety.rs` by skipping bare drive/prefix components such as `\\?\C:` before `symlink_metadata`, while still checking real existing ancestors for links/reparse points.
- Updated update-service package fixtures and regression tests so package hash/extraction tests use valid manifest/signature archive shape, duplicate ZIP entries are treated fail-closed if rejected by the ZIP writer, and formatter/source-marker assertions track the active checked open path.
- Verification passed: `cargo test -p avorax_update_service -- --test-threads=1` (`176 passed`); `cargo test --workspace -- --test-threads=1` passed; `cargo test --workspace --no-run` passed. The no-run gate still reports pre-existing warnings in `zentor_local_core` and `zentor_api`, but no update-service warnings remain.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1547-rust-workspace-runtime-green.md`.

## 2026-07-05 continuation checkpoint 1548

- Closed the focused Dart protocol-package verification blocker now that Dart is available through the installed Flutter SDK.
- Ran `dart pub get` for `packages/zentor_protocol`; dependency resolution succeeded with only newer-compatible-version notices constrained by the current lock/constraints.
- Ran `dart format --set-exit-if-changed lib test`; the first run formatted `lib/zentor_protocol.dart` and `test/zentor_protocol_test.dart`, and the verification rerun reported `Formatted 2 files (0 changed)`.
- Verification passed from `packages/zentor_protocol`: `dart analyze` (`No issues found`) and `dart test --reporter expanded` (`8 passed`).
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1548-zentor-protocol-dart-green.md`.

## 2026-07-05 continuation checkpoint 1549

- Closed the focused Dart update-manifest protocol verification blocker for `packages/avorax_protocol`.
- Ran `dart pub get` for `packages/avorax_protocol`; dependency resolution succeeded with only newer-compatible-version notices constrained by current package constraints.
- Ran Dart formatter on `packages/avorax_protocol`; the first run formatted `lib/update_manifest.dart` and `test/update_manifest_test.dart`, and the verification rerun reported `Formatted 3 files (0 changed)`.
- Verification passed from `packages/avorax_protocol`: `dart analyze` (`No issues found`) and `dart test --reporter expanded` (`6 passed`).
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1549-avorax-protocol-dart-green.md`.

## 2026-07-05 continuation checkpoint 1550

- Continued dependency/release evidence hardening now that Cargo, Flutter, Dart, and rustfmt are available through explicit Windows paths.
- Confirmed `cargo generate-lockfile --manifest-path core\avorax_update_service\Cargo.toml` succeeds and updates the root workspace `Cargo.lock`; Cargo does not create a package-local `core\avorax_update_service\Cargo.lock` for this workspace member.
- Updated `tools/security/avorax-dependency-evidence.ps1` so the update service lockfile check points at the root workspace `Cargo.lock`.
- Updated `docs/dependency-license-inventory.md`, `docs/audit/known-blockers.md`, `docs/integration.md`, and `STATUS.md` to remove stale root/update-service Rust lockfile blockers.
- Verification passed: `cargo test --workspace --no-run` after lockfile refresh; dependency evidence with `-AllowKnownBlockers` now reports only `apps\zentor_client\android\gradle.lockfile`; release-mode dependency evidence fails on that same single remaining blocker.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1550-dependency-evidence-lockfiles.md`.

## 2026-07-05 continuation checkpoint 1551

- Re-ran Flutter client verification on the current Windows host after Flutter/Dart installation.
- Verification passed from `apps\zentor_client`: `flutter pub get`, `flutter analyze` (`No issues found`), and `flutter test` (`414 passed`).
- Windows desktop build remains blocked by host configuration, not by a Dart analyzer/test failure: `flutter build windows --debug --no-pub` exits with Flutter's symlink-support/Developer Mode requirement for plugins.
- Dependency evidence was re-run with `-AllowKnownBlockers`; the generated JSON report is `partial=true` with the single release blocker `apps\zentor_client\android\gradle.lockfile`.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1551-flutter-client-current-host.md`.

## 2026-07-05 continuation checkpoint 1552

- Updated stale current audit/matrix wording that still described Flutter/Dart runtime verification as generally blocked after checkpoints 1546 and 1551 passed the client suite on this Windows host.
- `docs/audit/known-blockers.md` now points affected UI/runtime blocker entries at checkpoint 1551 while retaining true remaining limits for unavailable backends, runtime loops, and platform fixture gaps.
- `docs/audit/engine-control-matrix.md` now points selected Flutter startup, scan-target, and update-bound rows at checkpoint 1551/1552 runtime evidence instead of stale toolchain-blocked wording.
- Focused Flutter regression verification passed from `apps\zentor_client`: `flutter test test\update_service_test.dart test\local_core_ipc_diagnostics_test.dart test\offline_scan_test.dart test\config_validation_test.dart test\local_event_test.dart test\api_client_test.dart test\hash_service_test.dart` (`303 passed`).
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1552-flutter-matrix-runtime-deblock.md`.

## 2026-07-05 continuation checkpoint 1553

- Ran active security/performance gates with explicit tool paths. Branding, product-copy, no-malware-binaries, false-positive, performance, and protection gates passed.
- Fixed a real protection self-test wrapper path bug: Cargo builds `zentor_guard_service.exe` under the workspace `target\release`, not under `core\zentor_guard_service\target\release`.
- Updated the minifilter self-test default Guard Service path and the Python source contract to guard the workspace target path.
- Generated `dist\windows-driver-validation\selftest_report.json` through the benign user-mode Guard self-test path. The report remains honest: user-mode Guard verdict tests pass, but `overall_result=fail` and `pre_execution_blocking_available=false` because no signed/running driver is installed.
- Windows release gate was exercised and still fails, as expected for this checkout, on Android Gradle dependency evidence, missing installer stage/artifacts, and a top-level local-core subgate report; direct `cargo test --manifest-path core\zentor_local_core\Cargo.toml` passed with `411 passed`.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1553-security-release-gates-protection-selftest.md`.

## 2026-07-05 continuation checkpoint 1554

- Continued Windows release-gate stabilization after checkpoint 1553 exposed intermittent Guard/local-core subgate failures.
- Added a Guard driver-IPC test helper that serializes non-mutating verdict evaluations against the existing environment-root mutation tests, and kept raw parent-traversal fail-open paths fail-closed instead of normalizing them into trusted runtime roots.
- Updated `tools\windows\zentor-release-gate.ps1` so Guard Service and local-core Cargo subgates run with `-- --test-threads=1`; these suites intentionally test process-wide environment-variable hardening, so serial execution is deterministic without dropping coverage.
- Verification passed: `rustfmt --check core\zentor_guard_service\src\driver_ipc.rs`; focused Guard tests for safe EICAR and unverified publisher metadata; Guard Service serial suite (`212 passed`); local-core serial suite (`411 passed`).
- Re-ran the top-level Windows release gate. It now fails with 4 expected release blockers only: missing Android Gradle dependency lockfile, missing installer stage, missing MSI artifact, and missing setup EXE artifact. Guard Service and local-core subgate failures no longer appear.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1554-release-gate-guard-env-race.md`.

## 2026-07-05 continuation checkpoint 1555

- Continued release prerequisite work on the remaining Gradle/installer blockers.
- Built the real Rust release service binaries used by the Windows installer: `target\release\zentor_local_core.exe`, `target\release\zentor_guard_service.exe`, and `target\release\avorax_update_service.exe`.
- Enabled Android Gradle dependency locking in `apps\zentor_client\android\build.gradle.kts` for all subprojects so an Android-capable release host can generate a real `gradle.lockfile` instead of relying only on pinned plugin versions.
- Improved `installer\windows\build-msi.ps1` so missing Flutter Windows output reports the concrete prerequisites and explicitly refuses placeholder `Avorax.exe` staging.
- Verification passed: Rust release build for the three service packages; dependency evidence with `-AllowKnownBlockers` still reports only `apps\zentor_client\android\gradle.lockfile`; installer script parse check.
- Verified remaining blockers on this host: `flutter doctor -v` reports missing Android SDK and missing Visual Studio Desktop C++ components, and `flutter build windows --debug --no-pub` still fails because Flutter plugin builds require Windows symlink support/Developer Mode.
- Re-ran the top-level Windows release gate after the prerequisite work; it still fails with the same 4 expected blockers only: Android Gradle lockfile, missing installer stage, missing MSI, and missing setup EXE.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1555-release-prereqs-rust-services-android-locking.md`.

## 2026-07-05 continuation checkpoint 1556

- Added focused Python source-contract coverage for the release prerequisite work from checkpoint 1555.
- `tests\test_custom_driver_contract.py` now asserts Android Gradle dependency locking remains enabled with `lockAllConfigurations()`.
- The same suite now asserts `installer\windows\build-msi.ps1` keeps missing Flutter Windows output fail-visible, names symlink support and Visual Studio C++ prerequisites, and refuses placeholder app executable staging.
- Verification passed through a direct bundled-Python import/call harness for the three focused contract tests, because bundled Python still has no `pytest` module installed. Installer PowerShell parse and dependency evidence with `-AllowKnownBlockers` also passed.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1556-release-prereq-source-contracts.md`.

## 2026-07-05 continuation checkpoint 1557

- Added `tools\windows\avorax-release-prereq-check.ps1`, a non-mutating preflight for release-host prerequisites.
- The preflight requires explicit Dotnet/Cargo/Flutter paths, checks Android Gradle locking and lockfile evidence, verifies Rust service release executables, checks for real Flutter Windows `Avorax.exe` and installer stage output, tests symlink capability in an isolated temp directory, and parses bounded `flutter doctor -v` diagnostics.
- Wired the preflight into `tools\windows\zentor-release-gate.ps1` and added explicit `-DotnetPath` handling so the top-level gate does not assume an ambient or hardcoded dotnet path.
- Updated installer README and Python source contracts for the new preflight and release-gate wiring.
- Verification passed: PowerShell parse checks, focused direct Python source-contract harness, and expected preflight failure with 6 concrete errors on this host.
- Re-ran the top-level Windows release gate with explicit Cargo/Python/Dotnet/Flutter paths. It now fails with 5 top-level errors: dependency evidence, release prerequisite subgate, missing installer stage, missing MSI, and missing setup EXE. The prerequisite subgate contains the detailed Android SDK, Gradle lockfile, symlink, Visual Studio C++, Flutter app, and stage blockers.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1557-release-prereq-preflight-gate.md`.

## 2026-07-05 continuation checkpoint 1558

- Extended the release prerequisite preflight with atomic JSON evidence output.
- `tools\windows\avorax-release-prereq-check.ps1` now accepts `-ReportPath` and writes `ok`, timestamp, tool paths, per-check results, errors, and warnings through the shared `Write-AvoraxGateJsonFileAtomic` helper.
- `tools\windows\zentor-release-gate.ps1` now writes the prerequisite subgate report to `dist\release-prereq\release_prereq_report.json`.
- Verification passed: PowerShell parse checks, focused direct Python source-contract harness, expected preflight failure, generated JSON report inspection (`ok=false`, 6 errors, 26 checks), and expected top-level release-gate failure with 5 errors.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1558-release-prereq-json-report.md`.

## 2026-07-05 continuation checkpoint 1559

- Wired release prerequisite evidence into `.github\workflows\release-windows.yml`.
- Added explicit `-HostOnly` mode to `tools\windows\avorax-release-prereq-check.ps1`; host-only reports `mode=host_only` and marks build artifact checks as `skipped` instead of pretending artifacts should already exist.
- The workflow now runs the host-only preflight after WiX restore, uploads `dist\release-prereq\release_prereq_report.json` with `if: always()`, and keeps the preflight as a real failing gate instead of using `continue-on-error`.
- Hardened the preflight path handling so relative `-RepoRoot .` and relative `-ReportPath dist\...` inputs are resolved to checked local Windows paths before validation/output.
- Verification passed: focused direct Python source-contract harness for the preflight/workflow checks. Host-only preflight generated `ok=false`, `mode=host_only`, 26 checks, 4 errors, and 5 skipped artifact checks on this host. Full preflight generated `ok=false`, `mode=full`, 26 checks, and the expected 6 release blockers.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1559-release-workflow-prereq-evidence.md`.

## 2026-07-05 continuation checkpoint 1560

- Hardened the native signature compiler CLI in `core\zentor_native_engine\src\bin\zentor-signature-compiler.rs`.
- Replaced permissive `value_after(...)` parsing with `parse_signature_compiler_args(...)`, which rejects unknown flags, duplicate flags, missing values, option-looking values, empty values, and mixed `--help`/`-h` usage.
- Kept `--input`, `--output`, and `--metadata` mandatory and preserved the explicit default signature-pack version for omitted `--version`.
- Added Rust unit coverage and Python source-contract coverage for strict signature compiler arguments.
- Verification passed: `rustfmt --check`; focused Rust signature-compiler tests (`6 passed`); focused Python source-contract harness for the three native signature compiler contract tests.
- Broad `tools\testing\run-python-source-contracts.py` still fails with 17 unrelated/stale source-contract anchors after the signature-compiler contract fixes; the signature-compiler failures from the first broad run are resolved.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1560-native-signature-compiler-cli-strictness.md`.

## 2026-07-05 continuation checkpoint 1625

- Re-ran native ML runtime fixtures now that Cargo/rustfmt are available on the Windows host.
- Verified `.zmodel` strict schema, malformed/invalid schema rejection, bounded model reads, directory/oversized input rejection, unknown/non-finite/unbounded feature rejection, explicit unloaded production-ready false branch, and feature-vector/fallback handling.
- Normalized existing native-engine rustfmt drift with `cargo fmt --manifest-path core\zentor_native_engine\Cargo.toml`; the rerun `cargo fmt --manifest-path core\zentor_native_engine\Cargo.toml -- --check` passed.
- Verification passed: `cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_model -- --test-threads=1` (`19 passed`), `cargo test --manifest-path core\zentor_native_engine\Cargo.toml ml -- --test-threads=1` (`23 passed`), Python source-contracts (`481 tests`), and `py_compile`.
- `git status --short` remains unavailable because `C:\Users\Brent\Documents\Avorax-main` has no `.git` directory in this checkout.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1625-native-ml-runtime-suite.md`.

## 2026-07-05 continuation checkpoint 1626

- Re-ran native exact-hash trust-store fixtures now that Cargo/rustfmt are available on the Windows host.
- Verified native trust-store bounded reader behavior, known-good store schema/hash/path-context handling, known-bad store schema/hash/path-context handling, and benign known-bad imported-pack fixtures.
- Verification passed: `cargo test --manifest-path core\zentor_native_engine\Cargo.toml trust_store -- --test-threads=1` (`3 passed`), `cargo test --manifest-path core\zentor_native_engine\Cargo.toml known_good -- --test-threads=1` (`6 passed`), `cargo test --manifest-path core\zentor_native_engine\Cargo.toml known_bad -- --test-threads=1` (`10 passed`), `cargo fmt --manifest-path core\zentor_native_engine\Cargo.toml -- --check`, Python source-contracts (`481 tests`), and `py_compile`.
- Replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host; no live malware was used.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1626-native-trust-store-runtime-suite.md`.

## 2026-07-05 continuation checkpoint 1627

- Re-ran local-core app-control trust-store fixtures now that Cargo/rustfmt are available on the Windows host.
- Verified local known-good/known-bad strict schemas, malformed hash handling, oversized store rejection, bounded store reads, passthrough root validation, script policy propagation, publisher trust validation, user-approval hash handling, and default asset-root hardening.
- Verification passed: `cargo test --manifest-path core\zentor_local_core\Cargo.toml app_control -- --test-threads=1` (`47 passed`), `cargo test --manifest-path core\zentor_local_core\Cargo.toml trust_store -- --test-threads=1` (`10 passed`), `cargo fmt --manifest-path core\zentor_local_core\Cargo.toml -- --check`, Python source-contracts (`481 tests`), and `py_compile`.
- Existing local-core warning debt remains visible in Cargo output; replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1627-local-app-control-trust-store-runtime-suite.md`.

## 2026-07-05 continuation checkpoint 1628

- Re-ran local allowlist and local AI training-label fixtures now that Cargo/rustfmt are available on the Windows host.
- Verified allowlist strict persisted schemas, unsafe root blocking, traversal-safe folder matching, env-path rejection, oversized persisted-store rejection, bounded store reads, selected-file hash byte limits, directory rejection before hashing, staged writes, cleanup-error reporting, ID validation, explicit hash/path matching, malformed persisted hash rejection, and local-core confirmation/list error fixtures.
- Verified training-label false-positive suppression/revocation, malformed/missing/oversized store handling, strict top-level and nested feature schemas, unsafe ID rejection, relative/parent-traversal root rejection, no relative fallback, staged writes, cleanup-error reporting, actual-byte read bounds, and explicit empty latest-label branch.
- Verification passed: `cargo test --manifest-path core\zentor_local_core\Cargo.toml allowlist -- --test-threads=1` (`35 passed`), `cargo test --manifest-path core\zentor_local_core\Cargo.toml training_label -- --test-threads=1` (`21 passed`), `cargo fmt --manifest-path core\zentor_local_core\Cargo.toml -- --check`, Python source-contracts (`481 tests`), and `py_compile`.
- Existing local-core warning debt remains visible in Cargo output; replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1628-local-allowlist-training-label-runtime-suite.md`.

## 2026-07-05 continuation checkpoint 1629

- Re-ran native allowlist, native Avorax/Zentor product trust, native Microsoft trust parser/path, local AI metadata, local AI model runner, and local static-feature fixtures now that Cargo/rustfmt are available on the Windows host.
- Verified native allowlist broad-root rejection, exact hash matching, malformed-hash fail-closed behavior, component-aware path matching, and sibling-prefix rejection.
- Verified native product trust exact roots, quarantine root env validation, repo lookalike rejection, non-following repo marker checks, and installer-name-only no-trust behavior.
- Verified Microsoft trust local fixtures for checked system roots, component-boundary matching, bounded Authenticode command output parsing, non-following candidate path inspection, and malformed Authenticode JSON fail-closed behavior.
- Verified local AI metadata strict schemas, finite/ordered thresholds, required production metric evidence, packaged metadata parsing, development-model inactive state, env-path rejection, bounded metadata reads, directory rejection before metadata read, deterministic local output, explicit unknown top-category branch, non-following static-feature target metadata, bounded sample reads, and filename/extension default honesty.
- Verification passed: `cargo test --manifest-path core\zentor_native_engine\Cargo.toml allowlist -- --test-threads=1` (`6 passed`), `cargo test --manifest-path core\zentor_native_engine\Cargo.toml zentor -- --test-threads=1` (`12 passed`), `cargo test --manifest-path core\zentor_native_engine\Cargo.toml trust_root -- --test-threads=1` (`3 passed`), `cargo test --manifest-path core\zentor_native_engine\Cargo.toml microsoft -- --test-threads=1` (`18 passed`), `cargo test --manifest-path core\zentor_local_core\Cargo.toml model_metadata -- --test-threads=1` (`7 passed`), `cargo test --manifest-path core\zentor_local_core\Cargo.toml model_runner -- --test-threads=1` (`13 passed`), `cargo test --manifest-path core\zentor_local_core\Cargo.toml static_feature -- --test-threads=1` (`7 passed`), native/local rustfmt checks, Python source-contracts (`481 tests`), and `py_compile`.
- `cargo test --manifest-path core\zentor_native_engine\Cargo.toml product_trust -- --test-threads=1` matched `0 tests`; it is recorded as non-evidence and superseded by the `zentor`/`trust_root` filters above.
- Existing local-core warning debt remains visible; live Authenticode, production AI dataset validation, replacement-race, Unix-only symlink, and installed E2E fixtures remain partial.
- Full evidence is recorded in `.workflow/ultracode/avorax-hardening/results/1629-native-trust-local-ai-runtime-suite.md`.
