# Avorax Hardening Run Log

## Session scope

Lead-engineer product-hardening pass across the Avorax repository. Goal is to move Avorax toward a professional, reliable, secure, honest endpoint protection product through documented architecture, prioritized backlog, tests, and incremental implementation.

## Professional assumptions

- Current repository path is `C:\Users\Brent\Avorax`.
- The active product is Avorax. Historical/internal `zentor_*` names remain in code paths and crate/package names.
- The product must remain defensive only. No real malware samples, destructive behavior, stealth, evasion, or unsupported security claims are acceptable.
- The signed Windows driver path is not assumed active unless a validation report proves it is installed, running, communicating, and self-tested.
- The bundled native ML model is treated as development-only unless release metadata and gates prove production readiness.
- MSI/EXE installers are first-install/repair/recovery/offline paths. Normal in-app updates should use verified `.aup` packages.

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

