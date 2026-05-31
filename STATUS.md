# Zentor Anti-Virus Status

## Current Phase

False-positive and protection-health UX hardening after Phase 1 product cleanup.

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
- Added native trust helpers for Microsoft signature checks, Zentor-owned paths, Zentor installer artifacts, and publisher trust without blindly trusting unsigned system-folder files.
- Suppressed Zentor installer/MSI/internal artifacts from weak heuristic findings unless a confirmed signature or known-bad hash matches.
- Raised weak-signal heuristic thresholds so Downloads, Temp, setup/MSI names, unsigned/unknown publisher, and installer-like names remain observations/likely-clean unless stronger independent evidence exists.
- Hidden native `Observation` verdicts from normal scan threat results.
- Changed scan-result UX so low/medium heuristic-only findings show `Review suggested` or `Observation`, not `Detected`.
- Limited default `Quarantine` and `Delete permanently` buttons to confirmed/probable high-confidence results.
- Reworked the Protection screen explanation and checklist so `Partially Protected` states explain the missing guard/driver/self-test components and make Cloud disabled explicitly optional.
- Reworked the Device tab into `Device & Protection Health` and removed the unprofessional `Flutter local core active` wording.
- Extended false-positive gates and tests for Zentor installer EXE, Zentor MSI, setup.exe in Downloads, Zentor internal files, normal Downloads EXEs, and native installer trust.

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
- `cargo fmt --manifest-path core\zentor_native_engine\Cargo.toml` is blocked because `cargo` is not installed or not on `PATH`.
- `cargo fmt --manifest-path core\zentor_local_core\Cargo.toml` is blocked because `cargo` is not installed or not on `PATH`.
- `powershell -ExecutionPolicy Bypass -File tools\security\zentor-false-positive-gate.ps1` is blocked because it requires `cargo`.
- `flutter analyze` and `flutter test` are blocked because Flutter is not installed.
- `dart format ...` and `dart test` are blocked because Dart is not installed.
- Windows driver validation is blocked by missing Windows, WDK/EWDK, signing, installation, and administrator self-test environment.

## Remaining Work

- Run Rust, Flutter, Dart, false-positive, protection, performance, release, and installer gates in a provisioned environment with Cargo, Flutter, Dart, and driver tooling available.
- Keep iterating on false-positive policy using signed-publisher validation and real build artifact hash metadata when those are available.
- Continue Phase 2+ implementation in order, without marking driver or production ML features complete until their mandatory validation gates pass.

## Exact Next Step

Install/provide Cargo, Flutter, and Dart in this checkout or run CI, then execute `cargo test --workspace`, `flutter analyze`, `flutter test`, `dart test`, and `powershell -ExecutionPolicy Bypass -File tools\security\zentor-false-positive-gate.ps1`.

## Handoff

This checkpoint reduced false positives for weak heuristic-only results, Zentor installers/MSIs/internal files, normal Downloads/setup executables, and low/medium native observations. PowerShell branding and product-copy gates pass locally. Rust, false-positive, Flutter, Dart, and driver gates remain environment-blocked here and are documented rather than faked.

## Final Limitations

Zentor must not claim kernel-level or pre-execution protection until the signed driver path is built, installed, running, and self-tested. No anti-virus can guarantee complete protection.
