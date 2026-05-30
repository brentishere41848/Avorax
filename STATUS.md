# Zentor Anti-Virus Status

## Current Phase

Phase 0: repository audit and publication readiness.

## Completed Work

- Zentor project structure is present with Flutter client, Rust engine/service crates, native assets, docs, tools, installer folders, and archived legacy website material.
- Active API naming has been moved toward device and security-event terminology.
- SQL migration duplicate device table/column definitions have been cleaned up.
- Project control files are present.

## Blockers

- No signed Windows driver has been built, installed, run, or self-tested in this environment.
- Production ML dataset and independent anti-virus validation are not present.
- This workspace was not a Git checkout when audited, so publication requires initializing Git and connecting the target remote.

## Tests Passed

- `tools/branding/branding-check.ps1`
- `tools/security/zentor-product-copy-gate.ps1`

## Tests Failing

- Rust test commands for `zentor_native_engine`, `zentor_local_core`, and `zentor_guard_service` could not run because `cargo` is not installed or not on `PATH`.
- Flutter/Dart tests could not run because `flutter` and `dart` are not installed or not on `PATH`.
- `tools/security/zentor-false-positive-gate.ps1` fixture checks pass, but the gate cannot complete without `cargo`.
- `tools/windows/zentor-release-gate.ps1` cannot complete without toolchains and a driver self-test report.

## Next Exact Task

Run Rust, Dart/Flutter, false-positive, performance, protection, and release gates in an environment with the required toolchains and Windows driver self-test artifacts.

## Final Limitations

Zentor must not claim kernel-level or pre-execution protection until the signed driver path is built, installed, running, and self-tested. No anti-virus can guarantee complete protection.
