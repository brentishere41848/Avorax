# Core Service Health Client Verification

Date: 2026-07-17

## Scope

This checkpoint adds a native, read-only Windows client for Core Service health.
It does not install or start a service and does not expose scan, quarantine,
restore, delete, or update mutations across the privileged boundary.

## Classification

| Area | Classification | Evidence / limitation |
| --- | --- | --- |
| Fixed CLI health mode | Verified | `--service-ipc-health` is the only added mode; unknown or multiple modes fail visibly, and overall `ok` is false for a degraded engine even when transport authentication succeeds |
| Pipe server authentication | Verified in local Windows fixtures | Connected server PID must equal the running `avorax_core_service` SCM PID before the request and the unchanged SCM PID after the response |
| Protocol and resource bounds | Verified | Strict protocol v1, 16 KiB maximum, matching request/client IDs, health-only scope, local/no-network transport, bounded counts/text, overlapped I/O timeout and cancellation |
| Installed Core Service | Partial | No service was installed, started, stopped, or reconfigured; installed ACL, recovery, restart, and elevated-host E2E remain unverified |
| Flutter service health display | Partial | Flutter still uses the per-process stdio health path and does not consume this probe yet |
| Privileged service mutations | Disabled | Protocol v1 permits only read-only `health` |
| Persistent or pre-execution protection | Technically limited/blocked | User-mode health observation is not kernel enforcement and does not prove pre-execution blocking |
| External malware repositories | Disabled/blocked | Registered sources remain metadata-only; no sample bytes were downloaded and no automatic signatures were activated |

## Commands And Results

All commands ran from the repository root on Windows.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `git diff --check` | Passed; Git printed only expected LF-to-CRLF working-copy notices for audit Markdown |
| `cargo check -p zentor_local_core` | Passed |
| `cargo test -p zentor_local_core core_service_ipc::tests -- --nocapture` | Passed: 12 tests |
| `cargo test -p zentor_local_core windows_service_ -- --nocapture` | Passed: 3 tests |
| `cargo run -q -p zentor_local_core -- --service-ipc-health` | Expected fail-closed exit `1`: service status `Missing` on this no-service host |
| `cargo run -q -p zentor_local_core -- --unknown-mode` | Expected fail-closed exit `1`: unsupported argument |
| `cargo test -p zentor_local_core` | First parallel run: 496 passed, 1 existing PE-carrier fixture assertion failed |
| `cargo test -p zentor_local_core tests::full_scan_reports_pe_carrier_safe_simulators_and_quarantines_files -- --nocapture` | Passed on immediate focused rerun |
| `cargo test -p zentor_local_core -- --test-threads=1` | Final pass: 498 tests; the PE-carrier fixture and degraded-engine honesty regression both passed |
| `python -B tools/testing/run-python-source-contracts.py` | Passed: 594 tests |
| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1 -PythonPath <checked-python>` | Passed: exit `0` |
| `cargo test --workspace --no-run` | Passed: all workspace test binaries compiled |
| `cargo clippy -p zentor_local_core --all-targets --no-deps -- -D warnings` | Non-green: 16 pre-existing lints outside this change; no lint points to `core_service_ipc.rs` or the new `windows_tools.rs` code |

## Adversarial Coverage

- Wrong pipe server PID is rejected before a request is trusted.
- A service PID change between request and response is rejected.
- A server that withholds its response is canceled within the test timeout.
- Unknown fields, wrong protocol/request/client IDs, mutation scope, network
  transport, false readiness, excessive counts, and missing limitations fail.
- Oversized and malformed client input fails without killing the service worker;
  a later valid client still succeeds.

No live malware, repository archive, malware executable, driver, installer, or
machine-wide security setting was downloaded, executed, installed, or changed.
