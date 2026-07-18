# Process Command Truncation Verification

Checkpoint: 2172
Date: 2026-07-18
Scope: bounded user-mode process snapshot command-line evidence

## Verified

- The Windows Flutter collector keeps a bounded head and tail sample on Unicode scalar boundaries instead of only the first 2048 UTF-16 code units.
- Flutter sends `command_line_truncated=true` when middle content was omitted.
- Local Core independently keeps a bounded head and tail sample for command lines over 4096 characters.
- Suspicious flags in the retained tail are evaluated normally.
- A truncated command line for a script host or network-capable Windows utility reaches the default review threshold even when the omitted middle cannot be inspected.
- Exact-limit benign commands are not mislabeled as truncated.
- Truncation flags without command evidence and NUL-containing command evidence are rejected as skipped observations instead of being silently ignored.
- The release binary verifies long-tail, source-reported truncation, allowlist, item-bound, and malformed-input behavior with synthetic observations only.

## Partial

- Process observations are point-in-time user-mode snapshots collected while the Flutter app is active.
- Omitted middle text is not reconstructed. The verdict explains that manual review is required.
- Detection quality and false-positive rates for real production command lines require representative, privacy-reviewed telemetry and are not established by synthetic fixtures.

## Disabled Or Blocked

- This control does not stop, suspend, terminate, or quarantine a process.
- Persistent process monitoring and pre-execution enforcement remain partial or blocked by installed-service, authenticated IPC, signed-driver, release-signing, and disposable-host prerequisites.

## Technical Limits

- Flutter retains 2048 Unicode scalar values and Local Core retains 4096 Unicode scalar values, with an explicit middle-omission marker.
- Local Core accepts at most 256 process observations and emits at most 64 findings per request.
- A source-reported truncated security-sensitive command receives a conservative review score, not a confirmed-malware verdict.
- No live malware, external malware sample, service mutation, Defender change, or machine-wide component was used.

## Commands And Results

```powershell
cargo test --manifest-path core\zentor_local_core\Cargo.toml process_monitor -- --test-threads=1
# 10 passed; 0 failed

cargo test --manifest-path core\zentor_local_core\Cargo.toml process_snapshot_ipc -- --test-threads=1
# 5 passed; 0 failed

cargo test --manifest-path core\zentor_local_core\Cargo.toml -- --test-threads=1
# 506 passed; 0 failed; finished in 143.55s

flutter test test\app_detector_test.dart --reporter compact
# 11 passed; 0 failed

flutter test --reporter compact
# 824 passed; 0 failed

flutter analyze
# No issues found; finished in 37.2s

cargo fmt --manifest-path core\zentor_local_core\Cargo.toml -- --check
# exit 0

cargo clippy --manifest-path core\zentor_local_core\Cargo.toml --all-targets --no-deps -- -D warnings
# exit 0; 0 warnings

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py
# python source-contract run passed: 611 tests

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# exit 0

cargo build --release --manifest-path core\zentor_local_core\Cargo.toml
# exit 0; final rebuild finished in 9.51s

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-process-snapshot-smoke.ps1 -RepoRoot .
# exit 0; 266 synthetic observations, 12 bounded/invalid skips, 4 expected findings, 0 allowlisted findings, malformed input exit code 1
```
