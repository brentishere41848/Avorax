# Changelog

All notable Avorax changes should be documented here. Version entries avoid unsupported marketing claims and focus on implemented, testable behavior.

## 0.2.33 - Dev-channel updater hotfix

### Fixed

- Dev-channel in-app updates now pass `--allow-development-key` to the elevated Avorax Update Service for both verify and apply, matching the dev feed/package signing policy.
- This fixes the installed UI error `Avorax Update Service failed. Exit code: 1` when updating from 0.2.31 to a dev-channel `.aup` package.

### Verified

- Installed 0.2.31 updater reproduces the failure without the dev flag and verifies the 0.2.32 package when the flag is supplied.
- `flutter test test/update_service_test.dart` passes with regression coverage for the explicit dev flag.
- `flutter analyze` passes.

## 0.2.32 - Driver remediation, update feed fallback, and accessibility hardening

### Added

- Added regression coverage that requires the guard pre-execution path to reuse a cached native engine and stream file hashing instead of repeatedly initializing ANE or loading whole files into memory.
- Added update-service production verification policy coverage so normal CLI verify/apply paths reject development signing keys unless explicitly enabled.
- Added update-apply rollback-on-copy-failure contract coverage.
- Hardened ransomware-guard configuration tests to use temporary harmless fixtures rather than nonexistent absolute Windows paths.
- Added `packages/avorax_protocol` test dependency and update-manifest schema tests covering parsing, conservative defaults, and exact wire-key serialization.
- Added CI coverage for Avorax protocol tests plus product-copy, no-malware-binaries, false-positive, protection, and performance gates.
- Added Flutter navigation accessibility tests for desktop/sidebar and mobile bottom navigation semantics.
- Added Flutter shell accessibility coverage for current page title and main content landmarks.
- Added Settings accessibility coverage for screen-reader section headings.
- Added `tools/perf/avorax-benchmark.py`, a safe synthetic benchmark harness for traversal/hashing, native signature test timing, guard decision timing, and non-elevated update-copy simulation.
- Added local-core allowlist regression tests covering replaced-payload path bypasses, hash-scope separation, explicit hash trust, and fail-closed file approval creation.
- Added quarantine restore regression coverage that rejects tampered quarantined payloads before restoring.
- Added ransomware guard regression coverage that prevents trusted backup/sync process paths from suppressing critical ransom-note or backup-tamper signals.
- Added application-control regression coverage proving strong probable-malware evidence overrides stale known-good hashes, exact user hash approvals, and trusted-publisher signatures.
- Added real-time watcher cache regression coverage proving same-size rewrites with changed file modified timestamps require a new scan.
- Added training-label regression coverage proving a newer confirmed-malicious label revokes an older false-positive/trusted suppression for the same hash.
- Added native detection-provider registry/interface tests for enabled-provider evaluation, disabled-provider suppression, and provider inventory exposure.
- Added Windows driver-health regression coverage for installed-but-stopped test-signed drivers, guarded auto-load attempts, IPC failures, and explicit TESTSIGNING remediation.
- Added `tools/windows/avorax-enable-test-signing.ps1`, an explicit elevated development helper that enables Windows TESTSIGNING only with user/admin intent and warns that a reboot is required.
- Added Flutter update-service regression coverage for the GitHub `/releases/latest/download/update-feed.json` 404 case, verifying dev builds can recover through the GitHub releases API and still consume a signed `.aup` feed.

### Changed

- Guard-service driver IPC now reuses a shared `ZentorNativeEngine` instance protected by a mutex for pre-execution verdicts.
- Guard-service driver IPC now hashes files with buffered streaming I/O.
- The optional compatibility YARA fallback now reads a bounded 1 MiB buffered sample instead of reading the entire candidate file.
- Avorax Update Service CLI now defaults to production update verification; development-signed packages require `--allow-development-key` or `AVORAX_ALLOW_DEVELOPMENT_UPDATES=1`.
- Avorax Update Service now attempts to restore the rollback snapshot and restart services if payload copying fails after services have been stopped.
- Shared Avorax update manifest models can now serialize back to the verifier/app wire format with `toJson()`.
- Desktop sidebar navigation now exposes an explicit primary-navigation landmark, current-page labels, and scrolls instead of overflowing on constrained heights.
- Mobile bottom navigation now exposes current-page semantics and per-destination tooltips.
- App shell content now exposes screen-reader page-title and main-content semantics for the active route on desktop and mobile layouts.
- Settings sections now expose screen-reader heading semantics, and the developer-options switch has its own Material surface so focus/ink feedback is not hidden by the settings panel.
- The PowerShell performance gate now invokes the safe benchmark harness and writes `dist/performance/benchmark_report.json`.
- File/app/executable allowlist entries now store the approved file SHA-256 at creation time and require both path and hash to match before suppressing detection/action.
- Legacy/path-only file/app/executable allowlist entries now fail closed instead of trusting mutable paths.
- File/app/executable allowlist creation now fails closed when the target cannot be hashed instead of silently creating path-only trust.
- Quarantine restore now verifies quarantined payload size and SHA-256 before moving the payload back to the original path.
- Ransomware trusted-process suppression now applies only to ordinary mass-modification activity; ransom-note and backup-tamper signals override trusted-process suppression.
- Application control now evaluates strong probable-malware evidence before known-good hashes, exact user approvals, and trusted-publisher allow decisions so stale trust records cannot silently allow newly suspicious payloads.
- Real-time watcher duplicate-scan suppression now fingerprints file size plus modified time so same-size payload replacements are rescanned instead of treated as unchanged.
- Training-label false-positive/trusted-app suppressions now use the newest valid label for a file hash, so later confirmed-malicious labels revoke older suppressions.
- Native engine status now exposes detection-provider inventory, including built-in signatures, rules, heuristics, ML, disabled compatibility/YARA, and disabled cloud reputation provider states, without requiring UI code to know provider internals.
- Guard driver health now attempts to load `ZentorAvFilter` only when the service is installed and Windows TESTSIGNING is already enabled, re-probes filter/IPC state after the load attempt, and reports explicit TESTSIGNING/reboot requirements when Windows policy blocks the installed development driver. If Secure Boot blocks TESTSIGNING, the self-test now reports `secureBootBlocksTestSigning` instead of repeating an impossible `bcdedit` instruction.
- The packaged driver install helper no longer silently enables TESTSIGNING; it fails with a structured `testsigning_required`/`reboot_required` report until the separate elevated helper has been run and the machine rebooted.
- In-app update checks now fall back from the trusted GitHub `/releases/latest/download/update-feed.json` URL to the GitHub releases API when the latest-download route returns 404, allowing dev-channel builds to discover `update-feed.json` assets on prerelease/dev releases instead of leaving the Updates page stuck in a generic HTTP 404 state.

### Verified

- Custom driver contract tests pass: `uv run pytest tests/test_custom_driver_contract.py -q`.
- Guard driver IPC tests pass: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml driver_ipc -- --nocapture`.
- Update service compile check passes: `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bin avorax_update_service`.
- Custom driver/update contract tests now cover rollback-on-apply-failure and pass with 11 tests.
- `packages/avorax_protocol` analyze and tests pass.
- Product-copy, no-malware-binaries, false-positive, protection, and performance gates pass locally in the non-driver configuration.
- Navigation accessibility widget tests pass, including shell page-title/main-content landmarks.
- Settings accessibility widget tests pass, including section heading semantics.
- Flutter client analysis passes: `flutter analyze`.
- Updated performance gate passes and generates the safe benchmark report.
- Local-core protection tests pass: `cargo test --manifest-path core/zentor_local_core/Cargo.toml -- --nocapture` with 82 tests.
- Native-engine tests pass: `cargo test --manifest-path core/zentor_native_engine/Cargo.toml -- --nocapture` with 38 tests.
- Guard-service tests pass: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml -- --nocapture` with 26 tests.
- Guard-service release build passes: `cargo build --manifest-path core/zentor_guard_service/Cargo.toml --release`.
- Live Windows host check confirmed `ZentorAvFilter` installed but stopped, `fltmc load ZentorAvFilter` blocked by access/policy, and `bcdedit /set testsigning on` blocked in the non-elevated shell with `Access is denied`.
- Live GitHub update feed check passes: `https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json` returns the feed JSON.
- Flutter update-service tests pass: `flutter test test/update_service_test.dart` with 7 tests.
- Flutter client analysis passes after the update fallback change: `flutter analyze`.

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
