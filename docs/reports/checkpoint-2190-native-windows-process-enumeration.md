# Checkpoint 2190 Native Windows Process Enumeration

Date: 2026-08-20

## Objective

Checkpoint 2189 made incomplete process enumeration fail-visible, but the
Windows collector still launched WindowsPowerShell and CIM for every snapshot.
The default Guard poll interval is 750 ms, while measured finite watches using
that helper took about 763-1,150 ms on this host. Process observation could
therefore spend most of each polling cycle starting and waiting for a helper.

This checkpoint replaces that helper with a bounded native Win32 collector. It
does not expand the claim beyond best-effort post-launch user-mode observation.

## Change

The new Windows-only `windows_processes.rs` module:

- snapshots PIDs with `CreateToolhelp32Snapshot`, `Process32FirstW`, and
  `Process32NextW`;
- opens processes with only `PROCESS_QUERY_LIMITED_INFORMATION`;
- obtains Win32 image paths with `QueryFullProcessImageNameW` and
  `PROCESS_NAME_WIN32`;
- closes every successful snapshot and process handle through one RAII handle;
- caps a snapshot at 65,536 PID records;
- reuses one 32,768 UTF-16 code-unit path buffer;
- applies a two-second collection budget between native image queries;
- rejects zero record limits and zero time budgets before calling Win32;
- uses saturating coverage-gap accounting and retains only the first detail;
- treats PIDs 0 and 4 as explicit kernel exclusions;
- treats `ERROR_INVALID_PARAMETER` as expected exited-PID churn; and
- treats access denial, image-query failure, early snapshot termination,
  record exhaustion, and budget exhaustion as incomplete coverage.

The existing collection conversion still requires every returned image to be
an absolute, non-followed regular file. Invalid, missing, reparse-point, or
uninspectable images become coverage gaps. An otherwise empty collection still
creates a gap, so native enumeration cannot turn no evidence into clean proof.

The Windows process path no longer starts a child process, looks up
PowerShell, executes CIM, encodes a script, or parses helper JSON. Existing
process-stop commands remain on the bounded checked runner. Their non-zero exit
diagnostic now reports bounded stderr first, bounded stdout second, or an
explicit no-output message instead of leaving captured stdout unused.

No dependency version changed. `windows-sys` remains at the locked existing
version; only its `Win32_System_Diagnostics_ToolHelp` and
`Win32_System_Threading` feature gates were enabled. `Cargo.lock` is unchanged.

## Runtime And Performance Evidence

The release Guard was invoked with the same two-snapshot finite watch used for
the checkpoint 2189 live path:

```powershell
$payload = '{"command":"watch_processes","poll_interval_ms":100,"max_iterations":1,"protection_mode":"observeOnly"}'
$payload | .\target\release\zentor_guard_service.exe
```

Host-local wall-clock observations were:

| Collector | Run 1 | Run 2 | Run 3 |
|---|---:|---:|---:|
| Checkpoint 2189 PowerShell/CIM release path | 1,150.3 ms | 812.0 ms | 762.7 ms |
| Checkpoint 2190 final native release path | 185.9 ms | 72.2 ms | 66.4 ms |

These are diagnostic samples on one loaded host, not a production latency
benchmark or driver-latency claim. The important functional result is that all
three native runs returned protocol exit code 0 with response `ok:false`, action
`watchCompletedWithCoverageGaps`, and 290 gap occurrences across the initial
snapshot plus one poll. The first detail was access denied for PID 236. The gap
count varies with live process state; it is not a malware or unique-threat
count. No process was stopped or quarantined.

The result remains intentionally non-clean because a non-elevated user-mode
process cannot query every protected process image. Faster enumeration does not
convert partial visibility into a Defender-replacement claim.

## Local Verification

```powershell
cargo test --locked -p zentor_guard_service process_collection -- --test-threads=1
# 14 passed; 0 failed

cargo test --locked -p zentor_guard_service -- --test-threads=1
# 239 passed; 0 failed; 0 ignored

cargo test --workspace --locked -- --test-threads=1
# 1,471 passed; 0 failed; 0 ignored

cargo clippy --locked -p zentor_guard_service --all-targets -- -D warnings
# passed; 0 warnings

cargo fmt --all -- --check
# passed

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py
# python source-contract run passed: 626 tests

cargo build --release --locked -p zentor_guard_service
# passed
```

The focused Windows runtime test observes the current test process through the
real native APIs. Deterministic fixtures distinguish access gaps from exited
PID churn, prove the time and record limits remain visible, reject zero limits,
preserve gaps through collection conversion, reject unsafe paths, and prevent
empty finite watches from clean-passing. Both modified PowerShell scripts also
parse successfully.

## Central Verification

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot . -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .verification\checkpoint-2190-small-threat-mvp-final-report.json
```

The definitive report spans `2026-08-20T09:44:31.9462202Z` through
`2026-08-20T09:55:59.6238706Z`. It has status `passed`, records exactly
`220/220` passed steps, zero failures, an empty error field, and `687.6s`
elapsed. The verifier's built-in independent `-RequireFullSuite` report
validator passed in `1.8s`.

The verified scope now explicitly states that Guard native Windows enumeration
and Linux procfs coverage gaps are bounded, fail-visible, and cannot become a
clean finite-watch result. The no-malware-binaries, false-positive, protection,
performance, dependency, branding, product-copy, Flutter, protocol, release
binary, quarantine lifecycle, and update package gates all passed. Standard
EICAR/Defender integration remained opt-in and was not run.

## Hosted Evidence

Exact implementation head
`a928aa0297cadeedd002a4e84cf937250de6bf3b` is in PR `#42` and passes Avorax
CI run `32356686816`. All five jobs pass:

- Flutter/protocol `96387285422`;
- branding/copy `96387285651`;
- security/protection/performance `96387285657`;
- native Unix quarantine/process coverage `96387285689`; and
- Rust/local-core/Guard/update/API `96387285704`.

The pinned Ubuntu job runs the exact locked `process_collection` filter and
passes `9/9`, including native procfs malformed/unavailable-image fixtures and
the cross-platform source boundary for the Win32 collector.

Desktop Packages push run `32356656322` and PR run `32356686469` both pass
package contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG,
and consolidated checksum/lockfile-SBOM evidence. Consolidation jobs
`96391021281` and `96390367305` pass. Publish jobs `96391116275` and
`96390431544` are intentionally skipped. No package was installed or released.

## Existing Vault Check

Read-only inventory after focused, workspace, central, release, and live
finite-watch verification remains:

```text
C:\ProgramData\Avorax\Quarantine
16,072 files; 0 directories; 4,522,733 bytes
5,357 .avoraxq payloads
5,357 JSON records
5,357 auth sidecars
1 .metadata_auth_key
0 pending journals or sidecars
```

No existing quarantine artifact was changed or deleted.

## Failed And Superseded Attempts

- The first broad Guard run reached one stale source-marker test that still
  searched for the removed JSON parser. The production code had compiled; the
  source assertion was corrected before the final `239/239` run.
- The first strict Clippy pass rejected a test-only
  `field_reassign_with_default`. The fixture now initializes the field in its
  struct literal; strict Clippy then passed.
- The first source-contract run used a stale slice endpoint before the Windows
  function and failed its intended assertions. The slice now starts at the
  Windows collector and finds the following Linux cfg marker from that offset;
  the dependency-free runner then passed `626/626`.
- `python -m unittest tests.test_custom_driver_contract` discovered zero tests,
  because this repository uses its own dependency-free function runner.
  `python -m pytest` then failed because pytest is not installed in the bundled
  runtime. No package was installed; the repository runner is the counted
  result.
- Early native timing samples were diagnostic only and were superseded by the
  final release rebuild and three-run measurement above.

No failed or superseded invocation is counted as final success.

## Classification

| Classification | Control | Evidence and boundary |
|---|---|---|
| Verified locally | Native Windows process enumeration | Real Toolhelp/OpenProcess/QueryFullProcessImageNameW runtime test and finite release command pass without PowerShell/CIM. |
| Verified locally | Coverage honesty | Access, query, path, record, budget, early-end, and empty-snapshot gaps remain bounded and prevent clean finite-watch success. |
| Verified locally | Resource ownership | RAII closes snapshot/process handles; one bounded path buffer is reused; only limited query access is requested. |
| Verified hosted | Cross-platform regression | Exact implementation CI is green; pinned Ubuntu passes `process_collection` `9/9`; Windows/Linux/macOS packages build and consolidate. |
| Partial / blocked | Installed LocalSystem visibility | A disposable elevated Windows host must still prove installed service identity, protected-process visibility, ACLs, event logging, lifetime, shutdown, and UI mediation. |
| Disabled | Guard process enumeration on macOS/other unsupported platforms | Unsupported platforms fail explicitly. No empty-success fallback exists. |
| Technically limited | Polling and protected processes | Short-lived processes can occur between snapshots, same-path PID reuse can be indistinguishable, and protected images can deny user-mode queries. |
| Technically limited | Protection timing | This is post-launch observation, not kernel interception, pre-execution blocking, Defender replacement, or detection-rate evidence. |

No live malware, standard EICAR file, Defender setting, service/driver action,
package installation, machine-wide component, network sample, or release was
used. Generated `.verification` evidence remains untracked.
