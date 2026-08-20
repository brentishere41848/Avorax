# Checkpoint 2189 Process Enumeration Evidence

Date: 2026-08-20

## Objective

Guard process observation previously returned only a list of visible process
images. Per-entry procfs failures and Windows processes without an exposed
`ExecutablePath` could disappear from that list. A finite watch could therefore
return `watchCompleted` with `ok:true` even though the user-mode collector did
not have complete observable-process coverage.

This checkpoint makes process-enumeration limitations bounded, visible, and
part of the verdict. It does not turn polling into pre-execution protection.

## Change

Guard now returns a `ProcessCollection` containing both observed processes and
`ProcessCollectionCoverage`. Coverage evidence uses a saturating count and only
one diagnostic bounded to 512 characters, including any truncation suffix.
Every snapshot is capped at 65,536 PID records. A collection with no observable
executable image and no collector-reported error records a coverage gap because
the running Guard should at least observe its own image; valid empty output
cannot clean-pass.

Windows process collection now:

- runs checked System32 WindowsPowerShell without an execution-policy bypass;
- makes CIM errors terminating;
- emits a strict JSON envelope containing accessible process rows and a count
  of non-kernel rows with no executable path;
- rejects empty output, unknown fields, excessive rows/counts, and malformed
  envelopes;
- accounts for empty, relative, missing, non-regular, or uninspectable paths as
  coverage gaps instead of silently dropping them;
- treats a valid zero-row envelope as incomplete evidence.

Linux procfs collection now:

- fails visibly when the procfs root is unavailable;
- distinguishes expected non-PID entries and `NotFound` process churn from
  malformed or inaccessible entries;
- counts directory-entry, `read_link`, target-validation, and still-live PID
  image failures as coverage gaps;
- stops with visible partial-coverage evidence at the record limit;
- treats a zero-row procfs snapshot as incomplete evidence.

Unsupported non-Windows/non-Linux platforms now return an explicit disabled
diagnostic. In particular, macOS no longer turns an absent `/proc` directory
into an empty successful snapshot.

Finite process watches accumulate initial and polling coverage gaps. A watch
with any gap returns `ok:false` and either
`watchCompletedWithCoverageGaps` or
`watchCompletedWithCoverageGapsAndInspectionErrors`. Existing inspection-only
failures retain `watchCompletedWithInspectionErrors`.

Persistent watches write a structured
`processCollectionCoverageLimited` event on the first limited snapshot. The
warning is deduplicated while active and can arm again only after three
consecutive clear polls. A log-write failure remains fatal and visible.

The old lifetime `HashSet<u32>` was replaced with the previous bounded
PID-to-path snapshot. Exited PIDs leave the snapshot, and a reused PID with a
different image path is inspected. This also bounds watcher memory to the
current process inventory.

## Runtime Evidence

The real Guard stdin command path was executed on this Windows host with one
finite poll:

```powershell
'{"command":"watch_processes","poll_interval_ms":100,"max_iterations":1,"protection_mode":"observeOnly"}' | cargo run -q -p zentor_guard_service
```

It returned `ok:false`, action `watchCompletedWithCoverageGaps`, and `307`
coverage-gap occurrences across the initial snapshot plus one poll. The first
detail states that Win32_Process did not expose an executable path for one or
more non-kernel processes. This is expected partial evidence from the current
non-elevated user-mode context; it is not 307 unique threats and no process was
stopped or quarantined.

## Local Verification

```powershell
cargo test --manifest-path core\zentor_guard_service\Cargo.toml process_collection -- --test-threads=1
# 8 passed; 0 failed

cargo test -p zentor_guard_service
# 234 passed; 0 failed; 0 ignored

cargo test --workspace --locked
# 1,466 passed; 0 failed; 0 ignored

cargo clippy -p zentor_guard_service --all-targets --locked -- -D warnings
# passed; 0 warnings

cargo fmt --all -- --check
# passed

py -B tools\testing\run-python-source-contracts.py
# 626 passed; 0 failed
```

The PowerShell parser accepts both the central verifier and report validator.
The process-collection filter covers finite-watch result honesty, zero-row
snapshot rejection, combined inspection/collection limitations, warning
deduplication, bounded diagnostics, PID reuse with a changed image, and strict
Windows envelope behavior. The same filter selects native procfs
malformed/unavailable-image, empty-root, and missing-root fixtures on Linux.
The pinned Ubuntu CI job executes this exact locked filter. Avorax CI run
`32350190743`, job `96367469456`, passes all `8/8` selected tests on native
Ubuntu, including malformed-image, empty-root, and unavailable-root procfs
fixtures.

## Central Verification

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot . -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .verification\checkpoint-2189-small-threat-mvp-final-report.json
```

The earlier report spanning `2026-08-20T07:53:47.0550159Z` through
`2026-08-20T08:03:10.1942209Z` passed `220/220`, but manual diff review then
identified the valid-empty snapshot edge. That run is superseded and is not
counted as final verification.

The first post-empty-snapshot report spanned
`2026-08-20T08:15:06.5927834Z` through `2026-08-20T08:23:56.8132282Z` and
passed `220/220` in `530.2s`. Subsequent diff review found that the diagnostic
prefix allowed 512 characters before adding `...[truncated]`, exceeding the
documented cap. The implementation and boundary fixture now include the suffix
inside the 512-character maximum. That report is also superseded.

The definitive post-review report spans `2026-08-20T08:29:49.2759698Z`
through `2026-08-20T08:38:25.8497492Z`, has status `passed`, and records exactly
`220/220` passed steps, zero failures, zero skips, an empty error field, and
`516.5s` elapsed. The required `guard-service process collection coverage
regressions` step passed in `0.2s`. Recorded step durations range from `0.1s`
to `44.2s`.

The verifier's built-in `-RequireFullSuite` validator passed in `1.5s`. A
separate invocation also passed and reported `status: passed; steps: 220;
require_full_suite: True`.

Exact implementation head `d8ff525c362003a5396258ad8ffaeb51741b9387`
passes Avorax CI run `32350190743`: Rust/local-core/Guard job `96367469244`,
branding/copy job `96367469428`, native Ubuntu job `96367469456`,
Flutter/protocol job `96367469475`, and security/protection/performance job
`96367469627` all complete successfully.

Desktop Packages push run `32350121197` and PR run `32350190448` both pass
package contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64
DMGs, and consolidated six-artifact checksum/lockfile-SBOM evidence.
Consolidation jobs `96370430780` and `96370779650` pass. Each workflow's
prerelease publication job is intentionally skipped; no artifact was installed
or published as a release.

## Existing Vault Check

Read-only inventory after focused, workspace, live command, and central
verification remains:

```text
C:\ProgramData\Avorax\Quarantine
16,072 files; 0 directories; 4,522,733 bytes
5,357 .avoraxq payloads
5,357 JSON records
5,357 JSON auth sidecars
1 .metadata_auth_key
0 .pending journals; 0 .pending.auth sidecars
```

No existing quarantine artifact was changed or deleted.

## Failed And Superseded Attempts

- `py -m pytest` failed because the existing AppData Python runtime has no
  `pytest`. No package was installed. The repository's dependency-free runner
  passed `626/626` and is the counted result.
- The first two-script parser wrapper used `"$file:"`, which PowerShell rejected
  before either project script was parsed. The wrapper was corrected to
  `"${file}:"`; both actual scripts then parsed successfully. The failed wrapper
  is not counted as project verification.
- The first central `220/220` run completed before manual review found that a
  syntactically valid zero-row collection with no error could still clean-pass.
  The empty-snapshot branch and fixtures were added, raising Guard to `234`
  tests and the process filter to `8`; that earlier report is superseded.
- The first post-empty-snapshot `220/220` run completed before manual review
  found that the `...[truncated]` marker sat outside the stated 512-character
  maximum. The implementation and exact-bound fixture were corrected; the
  `530.2s` report is superseded by the final `516.5s` report.

No failed or superseded invocation is counted as final success.

## Classification

| Classification | Control | Evidence and boundary |
|---|---|---|
| Verified locally | Finite-watch coverage honesty | Deterministic provider fixtures prove any collection gap or zero-row snapshot prevents `ok:true`; inspection and collection limitations remain distinct and explainable. |
| Verified locally | Windows collection envelope | Strict benign runtime fixtures verify row/count parsing, unknown-field rejection, bad-path accounting, count bounds, and no execution-policy bypass. The real command path returned a fail-visible partial result. |
| Verified locally | Persistent warning deduplication | Runtime state tests prove one warning while limited, rearming only after three clear polls; the production watcher writes the structured event. |
| Verified locally | Bounded state and PID reuse | Snapshot and diagnostic bounds are enforced; changed image paths on reused PIDs require inspection and stale PIDs no longer remain forever. |
| Verified hosted | Native Linux procfs collection | Avorax CI `32350190743`, pinned Ubuntu job `96367469456`, passes the exact locked `process_collection` filter `8/8` on implementation head `d8ff525c362003a5396258ad8ffaeb51741b9387`. Benign temp-procfs tests exercise malformed/unavailable images, empty roots, and missing roots; the central Windows verifier separately requires the cross-platform subset. |
| Disabled | Guard process enumeration on unsupported platforms | Non-Windows/non-Linux platforms fail explicitly. macOS Guard polling is disabled rather than reported as empty success. |
| Partial / blocked | Installed persistent Guard loop | Requires a disposable elevated Windows host to test LocalSystem visibility, event ACLs, service lifetime, shutdown, performance, and UI mediation. |
| Technically limited | Polling coverage | A process that starts and exits between snapshots can be missed; an immediately reused PID with the same path can also be indistinguishable. Only a verified signed driver or approved OS event source could support a stronger claim. |
| Technically limited | Protection timing | This remains best-effort post-launch user-mode observation. It does not prove kernel interception, pre-execution blocking, Defender replacement, or a production detection rate. |

No dependency, lockfile, network input, live malware, standard EICAR file,
Defender setting, service/driver state, package installation, machine-wide
setting, quarantine artifact, or existing project file was removed or changed
by the runtime fixtures. Generated `.verification` evidence remains untracked.
