# Checkpoint 2239 - Scan Cancellation Ownership

## Objective

Prevent cancellation of an old scan from overlapping, retargeting, or
overwriting a replacement scan. Bind controller publication and Local Core
fallback termination to the exact scan that accepted the cancellation request.

## Scripted Implementation

- Every controller scan owns a monotonically increasing generation. The active
  generation and its cancellation request/outcome are explicit controller
  state, independent of visible `ScanStatus`.
- `cancelScan()` captures the exact active generation before calling Local Core.
  Its success, failure, cleanup, and final state require that generation.
- A completed scan that returns while cancellation is pending waits on the exact
  per-generation outcome. Accepted cancellation converts the real report to a
  cancelled report; a delayed cancellation exception preserves the completed
  report and records the failure visibly.
- Manual quick/full/custom/rescan, file/folder picker, scheduled quick scan, and
  visible Home/Protection/Scan/Quarantine start controls remain blocked until
  cancellation resolves.
- `LocalCoreClient` wraps the active scan process in an exact lease. Cancel
  captures the lease before IPC and delay, then kills only that captured process.
  `_call` clears the static slot only when its own non-null scan lease remains
  identical, so unrelated IPC and older scan completion cannot clear or retarget
  current ownership.

## Scripted Coverage

- Two benign controller races hold scan and cancel futures independently. They
  require replacement manual/scheduled starts to remain blocked and require a
  delayed cancel failure to preserve a completed clean report.
- A widget regression requires every Scan screen start control and action-mode
  selector to be disabled by cancellation alone.
- Local Core source/runtime regressions launch a benign command-only Dart test
  subprocess. A concurrent quarantine-list IPC must not clear the active scan
  lease; cancellation must terminate and reap the exact sleeping scan process.
  The fixture never scans or executes candidate content.
- The definitive verifier adds mandatory step `Flutter scan cancellation
  generation/process-ownership tests`. Its strict validator requires exactly
  268 steps, four verified-scope clauses, and the cross-instance token limit.
  Source contract 669 binds implementation, tests, UI, verifier/validator,
  documentation, and unchanged dependencies.

No checkpoint-2239 passing result is claimed during scripting. No live malware,
EICAR file, Defender change, machine-wide install, service/driver start,
dependency, lockfile, release, publication, candidate execution, or protected-
vault mutation is involved.

## Local Verification

After the complete scripting batch, the six focused cancellation ownership
tests, 16 adjacent cancellation/UI regressions, and 59 relevant UI tests passed.
The corrected full Flutter suite passed `845/845`; source contracts passed
`669/669`; Flutter analyze, Dart format, Git diff validation, and Windows
PowerShell 5.1/PowerShell 7 parser checks passed. Root, Native Engine, and
Flutter lockfile SHA-256 values remained exact. A read-only invariant check of
the protected vault returned 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, zero pending
items, and zero reparse points.

The explicit-tool, no-skip, no-Defender definitive verifier then passed exactly
`268/268` steps with zero failures or skips from
`2026-08-26T04:19:27.6082751Z` through `2026-08-26T04:27:19.1498007Z`
in `471.5s`. Independent Windows PowerShell 5.1 and PowerShell 7 validation
passed. Eleven controlled malformed-report mutations on both hosts were
rejected `22/22`. Report SHA-256 is
`4331723c28e51e889978f481cc86082d1ee6bd57ce8cbd941769d99959495e66`.
Hosted exact-head evidence remains pending.

## Limits

Cancellation is cooperative user-mode post-start control. The Local Core
cancellation token remains shared in the current user runtime and is not
authenticated to a cross-instance job ID. Controller serialization and exact
process leasing constrain this client instance; they do not prove arbitrary
cross-instance serialization, installed service ownership, cross-identity IPC,
driver/kernel interception, or pre-execution blocking.
