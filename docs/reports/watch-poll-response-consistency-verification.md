# Watch-Poll Response Consistency Verification

Checkpoint: 2174
Date: 2026-07-18
Scope: Flutter IPC and controller handling of finite watch-poll evidence

## Verified

- Watcher and poll activity flags must agree.
- Active evidence requires watcher mode `userModeBestEffort`, at least one watched path, and poll mode `finiteUserModePolling`.
- Inactive evidence requires a stopped/off watcher and stopped poll.
- Parser rejection sets `ok=false` with a bounded consistency error.
- The controller independently emits `watch_poll_loop_failed`, sets `limited`, and emits no clean event for contradictory nominal success.

## Partial

- Runtime tests use benign JSON subprocess output and fake controller responses.
- Observation remains finite while the Flutter application is active.

## Disabled Or Blocked

- This control does not prevent writes or stop/quarantine processes.
- Persistent service monitoring, OS notification integration, and pre-execution enforcement require separate installed-host work.

## Technical Limits

- The gate validates internal response consistency, not whether the subprocess observed every filesystem event.
- Existing duration, poll interval, event, path, diagnostics, and text bounds remain unchanged.
- No live malware, external sample repository, Defender change, service/driver mutation, or machine-wide installation was used.

## Commands And Results

```powershell
flutter test test\local_core_ipc_diagnostics_test.dart --plain-name "watch-poll"
# 3 passed; 0 failed

flutter test test\offline_scan_test.dart --plain-name "watch-poll"
# 4 passed; 0 failed

flutter analyze
# No issues found

flutter test --reporter compact
# 828 passed; 0 failed

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py
# python source-contract run passed: 613 tests

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# exit 0

git diff --check
# exit 0
```
