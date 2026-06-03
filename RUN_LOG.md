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
- Remaining open items are expanded CI/release gates, protocol test-dependency cleanup, accessibility, support bundles, benchmarks, and optional provider/plugin architecture.
