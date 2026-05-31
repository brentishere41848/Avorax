# Avorax Anti-Virus Status

## Current Phase

In-app signed updater implementation for Avorax. MSI/EXE installers remain first-install, repair, recovery, offline, and manual-install paths only. Normal app updates now target signed `.aup` packages applied by Avorax Update Service.

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

## Blockers

- `cargo` is not installed or not on `PATH` in this Windows checkout, so Rust compilation/tests and false-positive gates that depend on Rust are blocked locally.
- `flutter` is not installed or not on `PATH`, so Flutter analysis/tests are blocked locally.
- `dart` is not installed or not on `PATH`, so Dart package tests are blocked locally.
- WiX/MSI generation and full installer-stage validation require a complete Windows build stage that is not present in this checkout.
- No production update signing key is configured here. The package builder intentionally refuses unsigned `.aup` output.
- No signed Windows driver has been built, installed, run, or self-tested in this environment.

## Tests Passed Locally

- PowerShell parser check for `installer/windows/build-msi.ps1`, `tools/windows/avorax-installer-stage-test.ps1`, `tools/windows/zentor-release-gate.ps1`, and `tools/update/avorax-build-update-package.ps1`.
- `git diff --check` passed with line-ending warnings only.
- `powershell -ExecutionPolicy Bypass -File tools/branding/branding-check.ps1`
- `powershell -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1`
- `powershell -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1`

## Tests Blocked Locally

- `cargo test --manifest-path core/avorax_update_service/Cargo.toml`
- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml`
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml`
- `cargo test --manifest-path core/zentor_guard_service/Cargo.toml`
- `powershell -ExecutionPolicy Bypass -File tools/security/zentor-false-positive-gate.ps1`
- `cd apps/zentor_client && flutter pub get && flutter analyze && flutter test`
- `cd packages/zentor_protocol && dart pub get && dart test`
- `cd packages/avorax_protocol && dart pub get && dart test`
- `powershell -ExecutionPolicy Bypass -File tools/windows/zentor-release-gate.ps1`
- `powershell -ExecutionPolicy Bypass -File installer/windows/build-msi.ps1`

## Exact Next Task

Run CI or a provisioned Windows build host with Cargo, Flutter, Dart, WiX, signing configuration, and installer tooling; then fix any compile/test failures before creating a release tag.

## Final Limitations

Avorax must not claim kernel-level or pre-execution protection until the signed driver path is built, installed, running, and self-tested. In-app updates do not silently update drivers; driver updates require a separate explicit driver workflow.
