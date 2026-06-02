# Avorax Anti-Virus Status

## Current Phase

Product-hardening sprint for Avorax Anti-Virus. MSI/EXE installers remain first-install, repair, recovery, offline, and manual-install paths only. Normal app updates target signed `.aup` packages applied by Avorax Update Service.

## Current Commit

- Current checkpoint commit: this working tree; run `git log -1 --oneline` after commit for the exact SHA.
- Current release tag: not created from this checkpoint because full Rust, Flutter, Dart, installer, and driver gates are not all runnable in this local environment.

## Completed Items In This Checkpoint

- Added `core/avorax_update_service`, a Rust Windows service and CLI for `--verify` and `--apply` of signed `.aup` packages.
- Added `.aup` manifest validation for Avorax product identity, format version, channel, monotonic version, Ed25519 signature metadata, package hash, per-file payload hashes, and explicit rejection of driver updates.
- Added structured update payload application for `app`, `services`, `engine`, `docs`, `tools`, and `migrations` sections, with rollback snapshot creation before replacement.
- Reworked the Flutter update service so normal updates use `update-feed.json` plus `.aup` packages, verify package SHA-256, call `avorax_update_service --verify`, and elevate `avorax_update_service --apply` instead of launching an EXE/MSI installer.
- Added an Updates screen, sidebar route, update status rows, and app-state plumbing for download, verify, and install progress.
- Added `AVORAX_UPDATE_FEED_URL` and `AVORAX_UPDATE_CHANNEL` build config values.
- Updated Windows MSI packaging to build, include, install, and register `avorax_update_service.exe`, and to create `C:\ProgramData\Avorax\updates\staging`, `rollback`, and `logs`.
- Added `tools/update/avorax-build-update-package.ps1`, which builds a structured `.aup` from the installer stage and refuses unsigned packages or packages missing the Update Service/engine assets.
- Added release-gate checks that reject normal updater code paths referencing `setup.exe`, `.msi`, `msiexec`, or `launchUrl`, and require `.aup` usage.
- Added installed smoke-test and installer-stage checks for the Update Service, update directories, update tools, and ML/native-engine assets.
- Added `docs/in-app-updates.md` and `docs/reports/update-flow-audit.md`.
- Added `packages/avorax_protocol` with shared update manifest models for future client/service protocol alignment.
- Wired the Scan page engine-unavailable recovery actions to real local operations: elevated Avorax Core Service start, explicit service registration/start repair, and install-report opening.
- Added audit logging for install-report open and installation-repair requests, and made scan errors distinguish stopped or missing Core Service states from generic native-engine unavailability.
- Generated `dist\Avorax-AntiVirus-0.2.14-x64.msi` and `dist\Avorax-AntiVirus-0.2.14-x64-setup.exe` from a local Windows toolchain provisioned with Flutter 3.44.0, Rust 1.96.0, .NET SDK 8.0.421, and WiX 6.0.2.
- Generated release installer artifacts for this checkpoint: `dist\Avorax-AntiVirus-0.2.15-x64.msi` and `dist\Avorax-AntiVirus-0.2.15-x64-setup.exe`.
- Patched Windows MSI/EXE packaging so the Avorax Native Engine installed layout (`engine\config`, `engine\signatures`, `engine\rules`, `engine\ml`, and `engine\trust`) is staged into the installer automatically for both direct MSI installs and the EXE bootstrapper.
- Added visible installer proof UI: the MSI uses `WixUI_Minimal` with a license/proof page, and the EXE bootstrapper uses WiX Standard BA visible UI/progress while embedding the MSI.
- Verified the staged Avorax Core Service can load the packaged installed engine layout from `dist\windows-msi\stage\engine`, with native engine status `ready`, 17 native signatures, 11 native rules, development ML loaded, and native self-test passing.
- Preserved native signature category evidence in the risk-fusion path so confirmed hash signatures retain their declared threat category in final verdicts.
- Tightened the installer stage gate so generated WiX validation checks visible product-facing copy, visible installer UI/progress, and native-engine assets without failing on non-visible WiX IDs or technical compatibility paths.
- Created `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `TESTING.md`, `CHANGELOG.md`, `TODO.md`, and `RUN_LOG.md` for the hardening sprint.
- Hardened Flutter scan orchestration so successful scans clear stale engine errors and cancelled scan progress cannot overwrite cancelled state.
- Reworked Quick Scan target planning into testable platform-specific scopes for Windows/macOS/Linux high-risk locations.
- Hardened local event history loading so corrupt JSON or invalid records cannot crash startup or logs.
- Hardened quarantine restore/delete safety with explicit payload-path validation, corrupt metadata recovery, restore/delete confirmation tests, and duplicate restore-name handling.
- Added UI confirmation dialogs for quarantine restore and permanent delete actions.
- Improved Settings safety with reset confirmation, log-export feedback, and clean developer override disable behavior.
- Polished dashboard/protection/scan states to avoid unsupported claims, remove dead Pause/Keep controls, and show real Core Service status instead of hard-coded running text.
- Added visual policy tests for destructive quarantine confirmation and protection service-state honesty.
- Added best-effort user-mode watcher planning and file-event evaluation in `core/zentor_local_core/src/watcher/mod.rs`, including accessible-path filtering, debounce waiting, stable-file retry, unchanged-file cache suppression, and monitor-only review observations that do not label or block malware.
- Wired `start_watch` to return an honest `userModeBestEffort` watcher state for existing requested paths instead of always returning stopped.
- Improved Flutter `LocalCoreClient` IPC diagnostics for executable-missing, stderr/non-zero exit, malformed JSON, and timeout cases; health summary now exposes IPC failures through `lastError` for recovery UI messaging.
- Wired Flutter protection startup/shutdown to `start_watch` / `stop_watch` for selected existing protected folders, keeps selected app paths in scan/watch paths, and displays `userModeBestEffort` honestly as best-effort user-mode monitoring without claiming kernel pre-execution blocking.
- Upgraded normal updating to be fully driven from the Updates page: default GitHub release feed, in-app check/download/hash-verify/install, ready-to-restart state, in-app rollback, and Update Service `--rollback` support.

## Blockers

- `cargo test --manifest-path core/avorax_update_service/Cargo.toml` builds but cannot execute the elevated update-service test binaries in this non-elevated shell: Windows returns `os error 740`.
- Windows release and protection gates still require a driver validation/self-test report at `dist\windows-driver-validation\selftest_report.json`; this environment has not built, installed, run, or self-tested the signed driver path.
- `packages/avorax_protocol` does not declare `package:test` as a dev dependency, so `dart test` cannot run for that package without a package metadata change.
- No production update signing key is configured here. The package builder intentionally refuses unsigned `.aup` output.
- No signed Windows driver has been built, installed, run, or self-tested in this environment.
- Current `cargo test --manifest-path core/zentor_native_engine/Cargo.toml` is blocked by Microsoft Defender with Windows error 225 because the generated test executable contains antivirus-style synthetic fixtures/signatures.

## Tests Passed Locally

- PowerShell parser check for `installer/windows/build-msi.ps1`, `tools/windows/avorax-installer-stage-test.ps1`, `tools/windows/zentor-release-gate.ps1`, and `tools/update/avorax-build-update-package.ps1`.
- PowerShell parser re-check for patched `installer/windows/build-msi.ps1` and `tools/windows/avorax-installer-stage-test.ps1`.
- `git diff --check` passed with line-ending warnings only.
- `powershell -ExecutionPolicy Bypass -File tools/branding/branding-check.ps1`
- `powershell -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1`
- `powershell -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1`
- `powershell -ExecutionPolicy Bypass -File installer/windows/build-msi.ps1 -Version 0.2.14 -SkipFlutterBuild -RequireLocalCore -AllowDevelopmentModel`
- `powershell -ExecutionPolicy Bypass -File tools/windows/avorax-installer-stage-test.ps1 -StagePath dist/windows-msi/stage`
- Staged Core Service health command with `AVORAX_ENGINE_ROOT=dist/windows-msi/stage`; result reported `engine_status=available`, `native_engine_status=ready`, `native_signature_count=17`, `native_rule_count=11`, and `native_self_test=true`.
- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml`
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml`
- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml`
- `cd apps/zentor_client && flutter analyze`
- `cd apps/zentor_client && flutter test`
- `cd packages/zentor_protocol && dart pub get && dart test` using the Dart SDK bundled with Flutter.
- `powershell -ExecutionPolicy Bypass -File tools/security/zentor-false-positive-gate.ps1`
- Current hardening pass: `cd apps/zentor_client && flutter analyze` using `C:\Users\Brent\develop\flutter\bin\flutter.bat`.
- Current in-app update pass: `cd apps/zentor_client && flutter analyze` passed with no issues.
- Current in-app update pass: `cd apps/zentor_client && flutter test` passed 37 tests including update controller/service coverage.
- Current in-app update pass: `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bins` passed.
- Current in-app update pass: `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed 64 tests.
- Current in-app update pass: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml` passed 19 tests.
- Current in-app update pass: `cd packages/zentor_protocol && dart test` passed 4 tests.
- Current in-app update pass: `cd apps/zentor_client && flutter build windows --debug` produced `build\windows\x64\runner\Debug\Avorax.exe`.
- Current in-app update installer build: `powershell -ExecutionPolicy Bypass -File installer/windows/build-msi.ps1 -Version 0.2.16 -RequireLocalCore -AllowDevelopmentModel` produced `dist\Avorax-AntiVirus-0.2.16-x64.msi` and `dist\Avorax-AntiVirus-0.2.16-x64-setup.exe`.
- Current in-app update installer stage verification passed, and staged core health reported native engine `ready`, 17 signatures, 11 rules, development ML loaded, and native self-test true.
- Current in-app update artifact hashes: MSI `8e6b9101f8369ee5663c6d89754f72c1521a5c950d5ab9a8cda4f8a927196efa`; EXE `26a123cf3f9d91504a52a8ef8c05cad36174d18c8c4c70fa45bec19b7f49c9d7`.
- Current hardening pass: `cd apps/zentor_client && flutter test` passed 34 tests after IPC diagnostics and protection watcher UI wiring.
- Current hardening pass: `cd apps/zentor_client && flutter build windows --debug` produced `build\windows\x64\runner\Debug\Avorax.exe`.
- Release installer build: `powershell -ExecutionPolicy Bypass -File installer/windows/build-msi.ps1 -Version 0.2.15 -RequireLocalCore -AllowDevelopmentModel` produced `dist\Avorax-AntiVirus-0.2.15-x64.msi` and `dist\Avorax-AntiVirus-0.2.15-x64-setup.exe`.
- Installer stage verification: `powershell -ExecutionPolicy Bypass -File tools/windows/avorax-installer-stage-test.ps1 -StagePath dist/windows-msi/stage` passed, and staged core health reported native engine `ready`, 17 signatures, 11 rules, development ML loaded, and native self-test true.
- Current hardening pass: `cargo test --manifest-path core/zentor_local_core/Cargo.toml` passed 64 tests after adding best-effort user-mode watch planning/debounce/cache tests.
- Current hardening pass: `cargo test --manifest-path core/zentor_guard_service/Cargo.toml` passed 19 tests.
- Current hardening pass: `cd packages/zentor_protocol && dart test` passed 4 tests.

## Tests Blocked Locally

- `cargo test --manifest-path core/avorax_update_service/Cargo.toml` is blocked by Windows elevation requirement for the update-service test binaries in this shell.
- `cd packages/avorax_protocol && dart pub get && dart test` is blocked because `package:test` is not declared.
- `powershell -ExecutionPolicy Bypass -File tools/windows/zentor-release-gate.ps1` is blocked by the missing driver self-test report.

- Current hardening pass: `cargo test --manifest-path core/zentor_native_engine/Cargo.toml` is blocked by Microsoft Defender error 225 on the generated test executable.

## Exact Next Task

Harden guard-service IPC trust boundary so caller-provided publisher/signature fields cannot bypass policy unless verified by a trusted driver/service path.

## Final Limitations

Avorax must not claim kernel-level or pre-execution protection until the signed driver path is built, installed, running, and self-tested. In-app updates do not silently update drivers; driver updates require a separate explicit driver workflow.
