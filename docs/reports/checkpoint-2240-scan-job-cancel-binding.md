# Checkpoint 2240 - Scan Job Cancellation Binding

## Objective

Remove the shared current-user cancellation-token ambiguity left by checkpoint
2239. Bind scan creation, progress, process ownership, cancel IPC, response
validation, and cooperative runtime observation to one exact scan job UUID.

## Scripted Implementation

- The Flutter client creates a random canonical UUID before starting each scan.
  It sends that `job_id` with the scan command and stores the same ID in the
  exact active-process lease.
- Cancel refuses to launch without an active lease. It sends the captured job
  ID, requires the Local Core response to echo that exact ID, and retains the
  existing exact-process fallback without rereading mutable ownership.
- Local Core rejects missing, malformed, oversized, or noncanonical job IDs.
  Scan progress uses the caller-bound ID rather than creating another ID after
  process start.
- Cancellation uses `runtime/cancel-scan-<job UUID>` instead of one shared
  token. Token JSON is staged with exclusive non-following writes, synced,
  bounded to 1 KiB, strict-schema parsed, and required to contain the exact job
  ID. A wrong or old job token is not observed by another scan.
- The PowerShell wrapper requires `-JobId` and independently validates the
  canonical ID, echoed response, exact token leaf, bounded JSON, schema, job
  binding, data-root containment, and non-reparse path.

## Scripted Coverage

- Rust regressions cover exact-job cancellation, a wrong-job token, mismatched
  token content, malformed JSON, over-limit content, missing/noncanonical IPC
  IDs, staged cleanup, and symlink rejection in isolated temporary data roots.
- Flutter subprocess coverage proves the scan process publishes one UUID and a
  separate cancel process receives that same UUID even while unrelated Local
  Core IPC completes.
- Wrapper smoke coverage adds required job-ID evidence and rejects malformed
  IDs before any report or token is written.
- The definitive verifier adds mandatory `scan job-bound cancellation
  regressions`; strict full-suite validation requires exactly 269 steps.
  Source contract 670 binds product code, benign adversarial tests, wrapper,
  verifier, validator, documentation, and unchanged dependency scope.

No checkpoint-2240 passing result is claimed during scripting. No live malware,
EICAR file, candidate execution, Defender change, machine-wide install,
service/driver start, dependency, lockfile, release, publication, or protected-
vault mutation is involved.

## Local Verification

- Focused cancellation checks pass: Rust cancellation `5/5`, canonical IPC ID
  `1/1`, scan-loop cancellation `1/1`, and Flutter cancellation `4/4` plus the
  repaired source marker `1/1`.
- Local Core passes `543/543`; strict Local Core Clippy, release build, cancel
  wrapper smoke, local scan wrapper smoke, representative direct release smoke,
  Flutter analyze, and the complete Flutter suite `847/847` pass.
- Python source contracts pass `670/670`. All 38 modified PowerShell files parse
  under Windows PowerShell 5.1 and PowerShell 7. Formatting and `git diff
  --check` pass with only expected checkout line-ending notices.
- The definitive no-skip/no-Defender verifier ran from
  `2026-08-26T07:01:43.1256621Z` through
  `2026-08-26T07:09:38.1561571Z` and passed exactly `269/269` steps with zero
  failed verifier steps in `475s`. Its built-in Windows PowerShell 5.1 and
  PowerShell 7 validators passed; separate `-RequireFullSuite` runs passed.
- Controlled report copies missing the job-bound cancellation step or exact
  UUID scope were rejected with `268` instead of `269` and the required-scope
  diagnostic respectively.

The first Python source-contract run exposed three stale source assertions and
a later full Flutter run exposed one stale single-line cancel assertion. Those
test contracts were repaired and the complete suites rerun successfully. One
initial Clippy invocation used the wrong working directory and failed before
compilation; the exact manifest invocation then passed. The first negative-
evidence wrapper correctly received validator exit `1` but its own diagnostic
regex was too strict for wrapped PowerShell output; a simpler bounded wrapper
then recorded both expected rejections without counting either as success.

## Hosted Implementation Evidence

- Exact implementation commit `511eb18050c8913099e4641e99d7bedb46b65059`
  passes Avorax CI PR run `32941736916` and Desktop Packages push/PR runs
  `32941701666` and `32941736885`.
- Both package runs pass package contracts, Windows x64 MSI/setup EXE, Linux
  x64 DEB/tar, macOS x64/arm64 DMGs, consolidation, checksums, and lockfile
  SBOM. Both publication jobs are explicitly skipped; no release was created.
- Consolidated artifacts `9597342672` and `9597199315` are respectively
  `131904219` and `131525034` bytes. Their downloaded SHA-256 values exactly
  match GitHub digests
  `da0ac68d6a4284e8139f11077f3d85bdd34c730138967b3731500341ed68b58d`
  and
  `d4d926ce975a2a8f5e280ba60ec142d38495114bfba97cf900ccd6603cc0af04`.
- Bounded in-stream validation, without extraction or execution, proves exact
  eight-entry root inventories, six platform release files, seven independent
  matching checksum rows, and CycloneDX 1.6 lockfile SBOMs with 569 components.

Evidence-head checks, normal PR merge, merged-main evidence, guarded original-
tree synchronization, and destination verification remain pending.

## Limits

This remains cooperative user-mode cancellation after scan start. A random job
UUID is a same-user capability and prevents accidental cross-job targeting; it
is not a secret against same-user code that can observe the UUID. The work does
not prove cross-identity authentication, installed service ownership, kernel
cancellation, pre-execution blocking, or hard interruption inside one bounded
file inspection.
