# Zentor Anti-Virus Status

## Current Phase

Phase 1: product cleanup and branding, with Phase 0 audit documentation refreshed.

## Current Commit

- Current checkpoint commit: this commit; run `git log -1 --oneline` for the exact SHA after checkout.
- Base commit before this checkpoint: `44e4b55`
- Current tag: none detected in this environment

## Phase Progress

- Phase 0: in progress / partially complete. Audit documents now exist under `docs/audit/`, and the repository has a root Rust workspace for the documented baseline command.
- Phase 1: in progress. Active product-copy gates were tightened for product-facing UI, docs, package, and installer paths.
- Phases 2-19: not marked complete in this checkpoint; existing engine/service implementations and tests provide partial coverage, but remaining phase work must continue in order.

## Completed Items In This Checkpoint

- Added repository-level `Cargo.toml` workspace covering the active Rust crates.
- Added `docs/audit/repo-audit.md`, `docs/audit/active-components.md`, and `docs/audit/known-blockers.md`.
- Updated `PLANS.md` to list Phases 0 through 19 and the current priority.
- Updated `AGENTS.md` with active string category rules and release gate expectations without introducing blocked product language into active files.
- Strengthened `tools/security/zentor-product-copy-gate.ps1` to scan broader active product-facing paths and additional unsupported claim categories while avoiding self-matching literal claim phrases.
- Made `tools/branding/branding-check.sh` directly executable for local Unix-like validation.
- Updated the Windows MSI packaging script to find Rust binaries produced under the root Cargo workspace target directory.

## Blockers

- Cargo/Rust is not installed or not on `PATH` in this Windows checkout, so Rust and false-positive gates must run in CI or a provisioned Rust environment.
- Flutter is not installed or not on `PATH` in this Windows checkout.
- Dart is not installed or not on `PATH` in this Windows checkout.
- No signed Windows driver has been built, installed, run, or self-tested in this environment.
- Production ML dataset, independent validation, and production-ready model metadata remain unavailable.

## Tests Passed

- `powershell -ExecutionPolicy Bypass -File tools\branding\branding-check.ps1`
- `powershell -ExecutionPolicy Bypass -File tools\security\zentor-product-copy-gate.ps1`

## Tests Failing Or Blocked

- GitHub Actions release run `26709325568` for `v0.2.3` failed because `build-msi.ps1` did not look in the root workspace `target\release` directory for `zentor_local_core.exe`; the script has been updated to support that output path.
- `cargo test --workspace` is blocked in this Windows checkout because `cargo` is not installed or not on `PATH`.
- `powershell -ExecutionPolicy Bypass -File tools\security\zentor-false-positive-gate.ps1` is blocked because it requires `cargo`.
- `flutter analyze` and `flutter test` are blocked because Flutter is not installed.
- `dart test` is blocked because Dart is not installed.
- Windows driver validation is blocked by missing Windows, WDK/EWDK, signing, installation, and administrator self-test environment.

## Remaining Work

- Continue Phase 1 by running the PowerShell product-copy gate in a PowerShell-capable environment and fixing any findings.
- Continue Phase 2+ implementation in order, without marking driver or production ML features complete until their mandatory validation gates pass.
- Run Flutter, Dart, PowerShell, performance, false-positive, protection, release, and installer gates in a provisioned environment.

## Exact Next Step

Push this checkpoint to GitHub, then use the Windows release workflow to publish the next prerelease installer build if the workflow passes.

## Handoff

This checkpoint established the root Rust workspace and refreshed audit/control documentation. PowerShell branding and product-copy gates pass locally. Rust, false-positive, Flutter, Dart, and driver gates remain environment-blocked here and are documented rather than faked.

## Final Limitations

Zentor must not claim kernel-level or pre-execution protection until the signed driver path is built, installed, running, and self-tested. No anti-virus can guarantee complete protection.
