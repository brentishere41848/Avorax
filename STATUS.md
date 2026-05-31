# Zentor Anti-Virus Status

## Current Phase

Safe external malware-intelligence support after `v0.2.5`.

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
- Added safe GitHub malware-repository metadata and hash-only import tools under `tools/zentor_intel/`.
- Added disabled-by-default external source config for Pyran1 malware repositories in `assets/zentor_native/threat_intel/sources.example.json`.
- Added empty safe `.zsig` packs for GitHub hash-only known-bad and lab known-bad indicators.
- Added `tools/security/zentor-no-malware-binaries-gate.ps1` and `.sh`, wired into the Windows release gate.
- Added docs for safe external malware-intel handling, metadata-only mode, hash-only mode, and disabled lab mode.
- Added native engine tests for GitHub hash-only known-bad SHA-256 confirmation and policy quarantine.

## Blockers

- Cargo/Rust is not installed or not on `PATH` in this Windows checkout, so Rust and false-positive gates must run in CI or a provisioned Rust environment.
- Flutter is not installed or not on `PATH` in this Windows checkout.
- Dart is not installed or not on `PATH` in this Windows checkout.
- No signed Windows driver has been built, installed, run, or self-tested in this environment.
- Production ML dataset, independent validation, and production-ready model metadata remain unavailable.

## Tests Passed

- `powershell -ExecutionPolicy Bypass -File tools\branding\branding-check.ps1`
- `powershell -ExecutionPolicy Bypass -File tools\security\zentor-product-copy-gate.ps1`
- `powershell -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1`
- `python tools\zentor_intel\import_github_malware_metadata.py --config assets\zentor_native\threat_intel\sources.example.json --output $env:TEMP\zentor_metadata.jsonl`
- `python tools\zentor_intel\import_github_hashes_only.py ...` with a safe temporary SHA-256 fixture
- `python tools\zentor_intel\build_known_bad_from_github.py ...` with a safe temporary SHA-256 fixture
- `python tools\zentor_intel\validate_indicator_pack.py --input $env:TEMP\zentor_github_known_bad.zsig`
- Lab-download rejection smoke tests for missing env/flag and repository-local output folder.

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

- Run Rust, Flutter, Dart, false-positive, protection, performance, release, no-malware-binaries, and installer gates in a provisioned environment with Cargo, Flutter, Dart, and driver tooling available.
- Keep iterating on false-positive policy using signed-publisher validation and real build artifact hash metadata when those are available.
- Continue Phase 2+ implementation in order, without marking driver or production ML features complete until their mandatory validation gates pass.

## Exact Next Step

Push this checkpoint and let CI run the Rust/Flutter/Dart checks; do not tag another release unless CI and the release workflow pass.

## Handoff

This checkpoint adds safe metadata-only/hash-only external malware-intelligence support. It does not clone malware repos, download malware, execute samples, or ship samples. PowerShell branding, product-copy, and no-malware-binaries gates pass locally. Rust, false-positive, Flutter, Dart, and driver gates remain environment-blocked here and must run in CI or a provisioned environment.

## Final Limitations

Zentor must not claim kernel-level or pre-execution protection until the signed driver path is built, installed, running, and self-tested. No anti-virus can guarantee complete protection.
