# Protection Self-Test Response Verification

Checkpoint: 2176
Date: 2026-07-20
Scope: Flutter Guard self-test IPC, controller status, and result-panel evidence

## Verified

- The Guard process must exit zero, emit no stderr, and emit exactly one bounded JSON response line.
- The Guard event, self-test report, driver, Guard, test, AI, and step objects require exact fields and types.
- Text and list sizes are bounded; control characters, duplicate step names, malformed or non-UTC timestamps, and timestamps more than five minutes apart fail closed.
- Every step, report `passed`, `overall_result`, and outer `ok` must agree.
- Controller events, state, error handling, and panel styling use a typed boolean rather than message text.

## Partial

- Runtime coverage uses benign Dart subprocess fixtures and controller fakes.
- The executable path is checked as a regular launchable file, but this checkpoint does not independently verify its Authenticode publisher or installation ACL.

## Disabled Or Blocked

- Installed Guard/Core Service lifecycle and ACL verification require an approved disposable elevated Windows host run.
- Production minifilter enforcement requires Microsoft driver signing and the reviewed installed-driver path.

## Technical Limits

- A valid per-process response is not proof of persistent service monitoring or pre-execution blocking.
- No live malware, external malware repository, Defender change, machine-wide install, service mutation, or driver mutation was used.

## Commands And Results

```powershell
flutter analyze --no-pub
# No issues found

flutter test --no-pub test\local_core_ipc_diagnostics_test.dart
# 88 passed; 0 failed

flutter test --no-pub test\offline_scan_test.dart
# 189 passed; 0 failed

flutter test --no-pub test\settings_accessibility_test.dart
# 72 passed; 0 failed

flutter test --no-pub --reporter compact --concurrency=1
# 838 passed; 0 failed

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py
# python source-contract run passed: 615 tests

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# exit 0

git diff --check
# exit 0
```

An earlier parallel three-file Flutter invocation failed while copying a test
compiler artifact with Windows error 112 (`device is full`). A later disk probe
showed 241.659 GiB free. No project or user files were deleted. All three suites
then passed individually, and the complete 838-test run passed serially with
`--concurrency=1`; the transient parallel compiler failure is not counted as a
product test failure.
