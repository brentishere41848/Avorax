# Zentor Anti-Virus Status

## Current Phase

Phase 1: product cleanup and branding.

## Completed Work

- Zentor project structure is present with Flutter client, Rust engine/service crates, native assets, docs, tools, installer folders, and archived legacy website material.
- Active API naming has been moved toward device and security-event terminology.
- SQL migration duplicate device table/column definitions have been cleaned up.
- Project control files are present.
- Baseline repository audit report added at `docs/reports/repo-audit.md`.
- Windows driver setup scripts fail honestly when Visual Studio Build Tools/EWDK are missing.
- Removed unrelated active test fixture path wording from allowlist tests.
- Replaced test-only `fake` engine labels with explicit fixture provider labels.
- Replaced platform `placeholder` notes with honest validation-state wording.

## Blockers

- No signed Windows driver has been built, installed, run, or self-tested in this environment.
- Production ML dataset and independent anti-virus validation are not present.
- Rust, Flutter, and Dart CLIs are not installed or not on `PATH` in this local environment.

## Tests Passed

- `tools/branding/branding-check.ps1`
- `tools/security/zentor-product-copy-gate.ps1`
- Focused cleanup search for removed terms in changed active files.

## Tests Failing

- `cargo test --workspace` could not run because `cargo` is not installed or not on `PATH`.
- `flutter analyze` and `flutter test` could not run because `flutter` is not installed or not on `PATH`.
- `dart test` for `packages/zentor_protocol` could not run because `dart` is not installed or not on `PATH`.
- `tools/security/zentor-false-positive-gate.ps1` fixture checks pass, but the gate cannot complete without `cargo`.
- `tools/windows/zentor-release-gate.ps1` cannot complete without toolchains and a driver self-test report.
- `core/zentor_windows_minifilter/scripts/setup-dev-env-check.ps1` and `core/zentor_windows_process_guard/scripts/setup-dev-env-check.ps1` fail because Visual Studio Build Tools/EWDK are missing.
- `cargo test --manifest-path core/zentor_local_core/Cargo.toml allowlist scanner quarantine` could not run because `cargo` is not installed or not on `PATH`.

## Current Commit

This checkpoint commit. Use `git log -1 --oneline` for the exact SHA.

## Next Exact Task

Continue Phase 1 by tightening branding/product-copy gates for remaining active product claims, then move to Phase 2/3 ZNE implementation work once cleanup gates remain stable.

## Handoff

- Last completed checkpoint: Phase 1 active wording cleanup in allowlist, scanner/quarantine tests, and platform validation notes.
- Current incomplete task: Strengthen gates for stricter active product language without flagging Rust keywords such as `match` or `matches!`.
- Files changed: `core/zentor_local_core/src/allowlist/allowlist_store.rs`, `core/zentor_local_core/src/scanner/mod.rs`, `core/zentor_local_core/src/quarantine/quarantine_store.rs`, `core/zentor_amsi_provider/README.md`, `core/zentor_linux_fanotify_guard/README.md`, `core/zentor_macos_endpoint_extension/README.md`, `core/zentor_windows_process_guard/usermode_test/test_process_block.cpp`, `STATUS.md`.
- Tests run: branding check, product copy gate, focused `rg` cleanup search.
- Known failures: Rust/Flutter/Dart tests are blocked by missing local toolchains; Windows driver checks are blocked by missing Visual Studio Build Tools/EWDK.
- Next command to run: `powershell -ExecutionPolicy Bypass -File tools/branding/branding-check.ps1`.
- Next implementation step: update gates to catch active user-facing legacy/unrelated wording while excluding code syntax and approved archival locations.

## Final Limitations

Zentor must not claim kernel-level or pre-execution protection until the signed driver path is built, installed, running, and self-tested. No anti-virus can guarantee complete protection.
