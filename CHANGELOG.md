# Changelog

All notable Avorax changes should be documented here. Version entries avoid unsupported marketing claims and focus on implemented, testable behavior.

## Unreleased - Guard pre-execution performance and CI hardening

### Added

- Added regression coverage that requires the guard pre-execution path to reuse a cached native engine and stream file hashing instead of repeatedly initializing ANE or loading whole files into memory.
- Added update-service production verification policy coverage so normal CLI verify/apply paths reject development signing keys unless explicitly enabled.
- Added update-apply rollback-on-copy-failure contract coverage.
- Hardened ransomware-guard configuration tests to use temporary harmless fixtures rather than nonexistent absolute Windows paths.
- Added `packages/avorax_protocol` test dependency and update-manifest schema tests covering parsing, conservative defaults, and exact wire-key serialization.
- Added CI coverage for Avorax protocol tests plus product-copy, no-malware-binaries, false-positive, protection, and performance gates.
- Added Flutter navigation accessibility tests for desktop/sidebar and mobile bottom navigation semantics.
- Added `tools/perf/avorax-benchmark.py`, a safe synthetic benchmark harness for traversal/hashing, native signature test timing, guard decision timing, and non-elevated update-copy simulation.

### Changed

- Guard-service driver IPC now reuses a shared `ZentorNativeEngine` instance protected by a mutex for pre-execution verdicts.
- Guard-service driver IPC now hashes files with buffered streaming I/O.
- The optional compatibility YARA fallback now reads a bounded 1 MiB buffered sample instead of reading the entire candidate file.
- Avorax Update Service CLI now defaults to production update verification; development-signed packages require `--allow-development-key` or `AVORAX_ALLOW_DEVELOPMENT_UPDATES=1`.
- Avorax Update Service now attempts to restore the rollback snapshot and restart services if payload copying fails after services have been stopped.
- Shared Avorax update manifest models can now serialize back to the verifier/app wire format with `toJson()`.
- Desktop sidebar navigation now exposes an explicit primary-navigation landmark, current-page labels, and scrolls instead of overflowing on constrained heights.
- Mobile bottom navigation now exposes current-page semantics and per-destination tooltips.
- The PowerShell performance gate now invokes the safe benchmark harness and writes `dist/performance/benchmark_report.json`.

### Verified

- Custom driver contract tests pass: `uv run pytest tests/test_custom_driver_contract.py -q`.
- Guard driver IPC tests pass: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml driver_ipc -- --nocapture`.
- Update service compile check passes: `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bin avorax_update_service`.
- Custom driver/update contract tests now cover rollback-on-apply-failure and pass with 11 tests.
- `packages/avorax_protocol` analyze and tests pass.
- Product-copy, no-malware-binaries, false-positive, protection, and performance gates pass locally in the non-driver configuration.
- Navigation accessibility widget tests pass.
- Updated performance gate passes and generates the safe benchmark report.

### Known limitations

- Update service unit-test binaries require elevation in this Windows shell because of the service manifest; use compile checks and static contract tests here, or rerun elevated for full unit execution.

## 0.2.31 - Custom driver integration and dev release

### Added

- Added live Windows Filter Manager IPC support in the guard service: it connects to `\\ZentorAvFilterPort`, receives kernel scan requests, evaluates them through the real driver verdict policy, and replies with native allow/block verdicts.
- Added driver contract regression tests covering minifilter callback registration, driver/user-mode service naming, package inclusion, health reporting, and live Filter Manager IPC wiring.
- Added in-app rollback action that invokes Avorax Update Service rollback and reports `Ready to restart` after rollback finishes.
- Added controller tests for in-app check/download/verify/install and rollback state/event transitions.

### Changed

- The custom minifilter now registers create/open, write, rename/set-information, and section-acquire callbacks instead of only classifying all create events as generic opens.
- Driver requests now include richer metadata such as desired access, create disposition, file attributes, size, timestamp, and rename targets.
- Driver health reporting now distinguishes an installed test-signed driver from a driver blocked because Windows test-signing mode is disabled.
- The driver build script can use the repo's merged WDK target fallback and manually link a `.sys` when reduced WDK targets compile objects but do not emit the driver binary.
- Default build config now points to the GitHub release `update-feed.json`, so installed builds do not start with updates disabled unless explicitly overridden.
- Update Service CLI now includes `--rollback [install_dir]` for app-triggered rollback to the newest rollback snapshot.
- Updates UI enables rollback from inside the app, shows rolling-back busy state, and displays restart guidance after apply/rollback.

### Verified

- Custom driver contract tests pass: `uv run pytest tests/test_custom_driver_contract.py -q`.
- Guard service tests pass: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml`.
- Guard service, local core, and update service release builds succeed.
- Flutter analyze passes for `apps/zentor_client`.
- Flutter tests pass for `apps/zentor_client`.
- Flutter Windows release build succeeds and produces `build\\windows\\x64\
unner\\Release\\Avorax.exe`.
- MSI, setup EXE, signed development driver package, `.aup`, and `update-feed.json` were built for 0.2.31.

### Known limitations

- This is a development/test-signed driver release. Windows must trust the Avorax Driver Test Certificate and have test-signing enabled before the custom driver can load; production driver distribution still requires Microsoft hardware/driver signing.
- The packaged AI model is still explicitly marked `production_ready=false`; release artifacts were built with `-AllowDevelopmentModel`, and AI-only auto-quarantine remains disabled.
- Non-elevated updater smoke could not execute `avorax_update_service.exe` because its manifest correctly requires administrator elevation; the UAC prompt was cancelled in this session.

## 0.2.15 - Product hardening sprint

### Added

- Added `ARCHITECTURE.md` describing the Flutter client, Rust local core, native engine, guard service, assets, installer/update path, and trust boundaries.
- Added `SECURITY_MODEL.md` documenting defensive goals, non-goals, scan safety, quarantine safety, update safety, logging/privacy policy, and known limitations.
- Added `TESTING.md` with concrete Flutter, Rust, Dart, and release-gate commands plus current environment blockers.
- Added `TODO.md` and `RUN_LOG.md` to track the P0-P4 hardening backlog, assumptions, completed changes, tests, limitations, and next tasks.
- Added scan target planning support for testable platform-specific quick/full scan scopes.
- Added tests for quick scan high-risk target selection, Linux persistence target planning, corrupt local event recovery, stale scan error clearing, and scan report orchestration.
- Added Flutter IPC diagnostics tests for missing core executable, stderr/non-zero exit, malformed JSON, timeout/kill, and recovery messaging.
- Added best-effort user-mode folder watcher planning/evaluation tests for debounce, stable-file retry, unchanged-file cache suppression, and monitor-only review observations.
- Added quarantine lifecycle tests for restore confirmation, duplicate restore names, delete confirmation, corrupt metadata recovery, and unsafe quarantine payload paths.

### Changed

- Quick Scan planning now prioritizes high-risk user locations such as Downloads, Desktop, startup/autostart folders, temp directories, and recently suspicious executable/script paths instead of broad launcher/application trees.
- Successful scans now clear stale engine error messages instead of leaving the UI in a misleading warning state.
- Local event history loading now recovers from corrupt JSON or invalid records without crashing the app.
- Settings diagnostics now show snackbar feedback for log export and require confirmation before resetting configuration.
- Developer cloud override can be disabled cleanly from Settings without leaving stale override state.
- Dashboard status labels now use explicit product states: Protected, Attention needed, Scan running, Threats found, Protection disabled, and Update required.
- Scan progress UI no longer displays a disabled Pause control until pause/resume is actually implemented.
- Logs screen mojibake in event separators was corrected.
- Quarantine restore/delete now validates quarantine payload paths before moving or deleting files.
- Local core IPC now preserves executable-missing, stderr/non-zero exit, malformed JSON, and timeout diagnostics instead of collapsing them into generic native-engine failures.
- Protection startup now requests best-effort user-mode folder monitoring for selected existing protected paths and shows that mode honestly in the Protection screen without claiming kernel pre-execution blocking.

### Verified

- Flutter analyze passes for `apps/zentor_client`.
- Flutter tests pass for `apps/zentor_client`.
- Flutter Windows debug build succeeds and produces `build\windows\x64\runner\Debug\Avorax.exe`.
- Rust local core tests pass.
- Rust guard service tests pass.
- Dart protocol tests pass.

### Known limitations

- `core/zentor_native_engine` tests were blocked by Microsoft Defender with Windows error 225 because the generated test executable includes antivirus-style test fixtures/signatures.
- Kernel/pre-execution protection still must be treated as available only when the signed driver is installed, running, communicating, and self-tested.
- Native ML remains conservative; development-only models must not be used as sole authority for irreversible action.
