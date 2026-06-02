# Changelog

All notable Avorax changes should be documented here. Version entries avoid unsupported marketing claims and focus on implemented, testable behavior.

## Unreleased - In-app update flow

### Added

- Updates page now performs the full normal update path in-app: check feed, download signed `.aup`, verify hash/package, invoke Avorax Update Service, and report `Ready to restart` when apply finishes.
- Added in-app rollback action that invokes Avorax Update Service rollback and reports `Ready to restart` after rollback finishes.
- Added controller tests for in-app check/download/verify/install and rollback state/event transitions.

### Changed

- Default build config now points to the GitHub release `update-feed.json`, so installed builds do not start with updates disabled unless explicitly overridden.
- Update Service CLI now includes `--rollback [install_dir]` for app-triggered rollback to the newest rollback snapshot.
- Updates UI enables rollback from inside the app, shows rolling-back busy state, and displays restart guidance after apply/rollback.

### Verified

- Flutter analyze passes for `apps/zentor_client`.
- Flutter tests pass for `apps/zentor_client`.
- Flutter Windows debug build succeeds and produces `build\\windows\\x64\\runner\\Debug\\Avorax.exe`.
- Rust update service compiles with `cargo check --bins`.
- Rust local core and guard service tests pass.
- Dart protocol tests pass.

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
