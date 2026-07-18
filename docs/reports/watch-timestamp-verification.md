# Watch Timestamp Verification

Checkpoint: 2171
Date: 2026-07-18
Scope: finite user-mode watch-poll modification-time and unchanged-file caching

## Verified

- File modification time is optional evidence rather than an ambiguous zero fallback.
- Query failures and pre-Unix-epoch timestamps become bounded watch scan diagnostics.
- Only candidates with valid modification times enter baseline and unchanged-file caches.
- Candidates with unavailable timestamps wait for debounce/stability and are conservatively rescanned under the existing limits.
- Normal timestamped files retain duplicate suppression and same-size rewrite detection.
- The release watch-poll smoke observed, scanned, detected, and quarantined one harmless exact-hash fixture in isolated temporary data.

## Partial

- A real filesystem timestamp-query failure was not induced on this host. Deterministic unit inputs exercise pre-epoch rejection and the non-cache evaluator path; source contracts account for collection and baseline wiring.
- Monitoring remains finite app-lifetime polling and may observe changes only after writes occur.

## Disabled Or Blocked

- No feature was disabled by this checkpoint.
- Persistent service monitoring, OS filesystem notifications, signed-driver enforcement, and pre-execution blocking remain partial or blocked by their existing design, signing, approval, and disposable-host prerequisites.

## Technical Limits

- Conservative rescans can increase I/O only for candidates whose modification time cannot be trusted. Existing limits remain 10 seconds per command, 512 candidates per pass, depth eight, and 32 reported events.
- No service or driver was installed, started, stopped, loaded, or reconfigured.
- No live malware or external sample repository was downloaded, cloned, unpacked, retained, or executed.

## Commands And Results

```powershell
cargo test --manifest-path core\zentor_local_core\Cargo.toml watcher::tests -- --test-threads=1
# 10 passed; 0 failed

cargo test --manifest-path core\zentor_local_core\Cargo.toml watch_poll_scan -- --test-threads=1
# 2 passed; 0 failed

cargo test --manifest-path core\zentor_local_core\Cargo.toml -- --test-threads=1
# 500 passed; 0 failed; finished in 153.58s

cargo fmt --manifest-path core\zentor_local_core\Cargo.toml -- --check
# exit 0

cargo clippy --manifest-path core\zentor_local_core\Cargo.toml --all-targets --no-deps -- -D warnings
# exit 0; 0 warnings

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py
# python source-contract run passed: 611 tests

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# exit 0

cargo build --release --manifest-path core\zentor_local_core\Cargo.toml
# exit 0; final incremental release rebuild completed in 10.78s

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-watch-poll-scan-smoke.ps1 -RepoRoot .
# exit 0; 1 event, 1 file scanned, 1 threat found, 1 temporary fixture quarantined
```
