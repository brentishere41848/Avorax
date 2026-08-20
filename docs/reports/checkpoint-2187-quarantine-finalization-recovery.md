# Checkpoint 2187 Quarantine Finalization Recovery

Date: 2026-08-20

## Objective

Checkpoint 2184 deliberately preserved a sole opaque payload when quarantine
metadata finalization failed, but normal listing could not safely turn that
payload back into an authenticated record. This checkpoint adds recoverable
pre-move intent for Local Core and Guard while preserving fail-closed behavior,
bounded work, and one Local Core lifecycle owner.

## Change

Local Core and Guard now write the same strict wrapper before source mutation:

```text
<id>.pending.auth
<id>.pending
```

The auth sidecar is staged first. The `.pending` file is the commit marker and
contains format `avorax-quarantine-finalization-journal-v1` plus the already
validated quarantine record. Authentication uses HMAC-SHA-256 domain
`avorax-quarantine-finalization-journal-v1\0`, separate from final-record domain
`avorax-quarantine-record-v2\0`.

Each writer reads the committed journal back, requires exact byte equality,
verifies its HMAC, acquires an exclusive operating-system file lock, and keeps
that lock through source movement, final-record verification, and journal
cleanup. Local Core recovery uses the same non-blocking lock. An active Local
Core or Guard writer therefore fails listing visibly instead of being mistaken
for an abandoned transaction; a crashed writer releases the lock automatically.

Local Core runs recovery before normal listing and examines at most `65,536`
vault entries. After lock and authentication it enforces strict JSON, ID and
payload-path binding, record-claim validation, regular/single-link state,
recorded size, SHA-256 integrity, permission hardening, current final-record
HMAC, and readback equality.

The recovery state machine can:

- finalize an intact isolated payload when the original source is absent;
- replace incomplete final metadata from the authenticated journal;
- remove a stale journal after an exact authenticated final record and intact
  status-appropriate payload verify;
- clean a pre-move journal only after its lock is free, no payload/final metadata
  exists, and the original source still matches kind, link count, size, and hash;
- remove an orphan journal-auth sidecar when no related state exists, or after a
  current authenticated final record and status-appropriate payload verify.

It refuses automatic mutation for missing/tampered auth, unknown fields,
filename/ID mismatch, changed payload, conflicting final record, incomplete
related state, both source and payload, unavailable/active journal lock, or an
excessive vault entry count. Existing evidence remains in place.

## Local Verification

```powershell
cargo test --locked -p zentor_local_core active_pending_finalization_lock_blocks_concurrent_recovery -- --test-threads=1
# 1 passed; active writer blocked recovery and retained all evidence

cargo test --locked -p zentor_local_core pending_finalization -- --test-threads=1
# 11 passed; 0 failed

cargo test --locked -p zentor_guard_service guard_finalization_journal -- --test-threads=1
# 1 passed; 0 failed

cargo test --locked -p zentor_local_core safe_eicar_simulator_is_detected_and_auto_quarantined_by_confirmed_mode -- --test-threads=1
# 1 passed; normal Local Core finalization and locked-journal cleanup succeeded

cargo test --locked -p zentor_guard_service known_malicious_hash_is_quarantined -- --test-threads=1
# 1 passed; normal Guard finalization and locked-journal cleanup succeeded

cargo test --locked -p avorax_platform_security
# 9 passed; 0 failed

cargo test --locked -p zentor_local_core -- --test-threads=1
# 534 passed; 0 failed

cargo test --locked -p zentor_guard_service -- --test-threads=1
# 226 passed; 0 failed

cargo test --workspace --locked -- --test-threads=1
# 1,458 passed; 0 failed

C:\Users\Brent\AppData\Local\Python\pythoncore-3.14-64\python.exe -B tools\testing\run-python-source-contracts.py
# 623 passed; 0 failed

cargo clippy --locked -p avorax_platform_security -p zentor_local_core -p zentor_guard_service --all-targets -- -D warnings
# passed; 0 warnings

cargo fmt --all -- --check
# passed

cargo metadata --locked --no-deps --format-version 1
# passed

$repo = (Resolve-Path '.').Path
$python = 'C:\Users\Brent\AppData\Local\Python\pythoncore-3.14-64\python.exe'
$cargo = (Get-Command cargo).Source
$flutter = (Get-Command flutter).Source
$dart = (Get-Command dart).Source
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot $repo -PythonPath $python -CargoPath $cargo -FlutterPath $flutter -DartPath $dart -ReportPath "$repo\.verification\checkpoint-2187-small-threat-mvp-report.json"
# 219 passed; 0 failed; 0 skipped; 533.3s
# built-in independent -RequireFullSuite validator passed in 1.5s
```

The final report spans `2026-08-20T04:04:45.0821841Z` through
`2026-08-20T04:13:38.4066718Z`, has status `passed`, contains exactly `219`
steps with status `passed`, and has an empty error field.

## Failed And Superseded Attempts

The first source-contract runs exposed three stale assertions from the previous
unrecoverable finalization policy. After those were corrected, three new
contract assumptions were also wrong: one searched for a nonexistent public
`rescan` function, one sliced the wrong source region for the HMAC helper, and
one assumed a literal platform suffix parser implementation. The assertions
were corrected before the complete runner passed `623/623`.

The first lock compile failed because `File::by_ref()` was ambiguous between the
`Read` and `Write` traits. The bounded reader now calls `Read::take` explicitly;
the focused test and every full suite were rerun.

An earlier central run passed `219/219` in `545s`, but manual post-run review
found a concurrency defect: recovery could remove a valid pre-move journal while
its writer was still between journal commit and source movement. That run is not
the final evidence. The journal lifetime lock, persisted-byte readback, Windows
cross-handle regression, normal Local/Guard writer tests, full Rust suites, and
the final `219/219` central run were added or rerun afterward.

No failed or superseded command is counted as final success.

## Existing Vault Check

Read-only inventory before and after focused, full, and central verification is
identical:

```text
C:\ProgramData\Avorax\Quarantine
16,072 files; 0 directories; 4,522,733 bytes
5,357 .avoraxq payloads
5,357 JSON records
5,357 JSON auth sidecars
1 metadata key
0 .pending journals; 0 .pending.auth sidecars
```

No existing quarantine artifact was changed or deleted.

## Dependency And Diff Review

`Cargo.toml`, all affected crate manifests, and `Cargo.lock` are unchanged. The
implementation uses the Rust `1.96.1` standard-library file-lock API and already
pinned HMAC, SHA-256, serialization, UUID, platform-security, `windows-sys`, and
`libc` dependencies. It adds no package, license, build script, network fetch,
or machine-wide component.

The bounded Ubuntu quarantine job is extended from seven to 11 locked Cargo
invocations. It adds Local Core active-lock and normal-writer tests plus Guard
journal-lock and normal-writer tests. The job still uses pinned Rust `1.96.1`,
`ubuntu-24.04`, fail-fast Bash, serial tests, and a 30-minute timeout, and
installs no system package. Hosted success is not claimed until the exact
implementation commit passes.

Generated `.verification` output is untracked and excluded from publication.

## Classification

| Classification | Control | Evidence and boundary |
|---|---|---|
| Verified locally | Local Core journal writer and recovery | Strict/domain-separated journal, persisted-byte/HMAC verification, active-writer lock refusal, isolated-payload completion, partial/stale cleanup, and adversarial state tests; Local Core `534/534`. |
| Verified locally | Guard journal writer interoperability | Same schema/domain/lock, normal quarantine finalization, and Local contract compatibility; Guard `226/226`. |
| Verified locally | Fail-closed malformed/ambiguous states | Missing/tampered auth, unknown fields, ID/path mismatch, changed payload, conflicting final record, incomplete state, duplicate source/payload, and active writer preserve evidence. |
| Verified locally | Full regression and safety gates | Workspace `1,458/1,458`; source contracts `623/623`; strict Clippy; central verifier/report validator `219/219` in `533.3s`; branding, product-copy, no-malware, false-positive, protection, performance, dependency, Flutter, analyzer, scan, quarantine, restore, and delete gates passed. |
| Pending hosted | Native Unix lock and writer runtime | Exact tests are wired into the bounded Ubuntu job, but no run is called successful before the implementation commit is pushed and completes. |
| Partial / blocked | Installed interruption and UI/service recovery | LocalSystem DPAPI/ACL ownership, packaged UI messaging/click-through, repair/upgrade interruption, and crash-at-every-instruction package E2E require a disposable elevated Windows host. |
| Unsupported | Historical unsigned payload salvage | Automatic recovery requires a current authenticated journal or final record; old untracked payloads are not promoted. |
| Technically limited | Hostile filesystem concurrency | The lock coordinates cooperating Avorax processes. Same-principal software that ignores locks and administrator/root mutation remain in the trusted computing base. |
| Technically limited | Protection scope | Recovery is list-triggered user-mode work. It does not prove kernel interception, installed persistent monitoring, process stop, pre-execution blocking, production detection rates, secure erase, or Defender replacement. |

No live malware, standard EICAR file, Defender exclusion, service/driver start or
installation, package installation, machine-wide setting, secure-erase action,
existing-vault mutation, or project-file deletion was used. All runtime fixtures
were benign and isolated.
