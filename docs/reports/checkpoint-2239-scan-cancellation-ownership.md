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

## Exact Implementation-Head Hosted Evidence

Commit `0b0aead1e725c67d10fcacd4d4e8e113ee60f3fc` is PR `#91`'s exact
implementation head. Avorax CI run `32930494586` passes all five mandatory
jobs. Desktop Packages push `32930448777` and PR run `32930494592` pass package
contracts, Windows MSI/EXE, Linux DEB/tar, both macOS DMGs, consolidation,
checksums, lockfile SBOM creation, and evidence upload. Publication jobs
`98065115237` and `98064888856` are skipped; no release or prerelease is
created.

Consolidated artifacts `9593421332` and `9593395490` are 131,753,478 and
131,752,211 bytes with SHA-256
`7528117206ee11f8456a72ed6d18a7838eac1102168bd6253763a7fcd48c8e36` and
`1ee8f3142e15d3d728ca7c4665af500321fd5a214853d1e1f7fd3e7ecc08e4dd`.
Both match GitHub's digests and pass bounded in-stream validation without
extraction or execution: exact eight root entries, six platform release files,
seven matching checksum rows, and CycloneDX 1.6 lockfile SBOM evidence with 569
components.

## Integration And Destination Closure

Evidence head `fb4b1cf5fdcd723bef48d2da110ddb038838231b` passes CI
`32931893838` and packages `32931893808`; publication `98067942213` is skipped.
Artifact `9593749447` is 131,756,565 bytes with SHA-256
`b45dd10032412313d0db419b71e020eb39d4e017de5668173bd8a65900d53025`
and passes the same bounded non-extracting validation.

PR `#91` merges normally as `bee5193c36a8636211d95b8e91a6ce9224b7b0fe`
with exact parents `2435b3139ff012eda7cb565774c039e1db1d5fbc` and
`fb4b1cf5fdcd723bef48d2da110ddb038838231b`. Merged-main CI
`32932815722` and packages `32932815727` pass; publication `98071571653`
is skipped. Artifact `9594188176` is 131,718,396 bytes with SHA-256
`06bdc080af570c2d12c71e0068fdfcc46c34a25d4c9f7eecb5ab6dbf7be80bea`
and passes exact 8-root/6-release/7-checksum/CycloneDX 1.6/569-component
in-stream validation. No release is created.

Guarded synchronization copies exact `21/21` Git-filtered blobs and 7,747,274
bytes into `C:\Users\Brent\Documents\Avorax-main` with zero deletes, residue,
or remaining stage. The first sync attempt stopped before replacement because
Windows PowerShell 5.1 lacks the required overwrite overload; a bounded cleanup
proved zero changed targets before the successful PowerShell 7 retry.

Destination format, focused cancellation `6/6`, analyzer, source contracts
`669/669`, and a final sequential full Flutter run `845/845` pass. The C: drive
initially had only 0.34 GB free: an interrupted compiler run and a retry with an
explicit disk-full diagnostic are not credited. An exFAT D:-temp run completed
`844/845` with one transient isolated subprocess-fixture cleanup race; its exact
focused rerun passed `1/1`. D: was not used for Rust quarantine proof because
exFAT lacks the required ACL semantics. Four untouched hosted ZIPs totaling
526,980,650 bytes were instead byte-exact archived to
`D:\Avorax-Codex-Evidence\checkpoint-2239`, restoring C: working space without
losing evidence.

The final destination no-skip/no-Defender verifier passes exactly `268/268`
from `2026-08-26T06:02:19.1747256Z` through
`2026-08-26T06:10:09.4014246Z` in `470.2s`. Both independent validators pass,
11 controlled mutations under both hosts reject `22/22`, and report SHA-256 is
`f198239723c3dcb07f0146fcb03c766520df894dce09ec2e8383e0d9acaff491`.
Locks, zero repo processes/sync residue, and the protected-vault invariant
remain exact. Checkpoint 2239 is closed; the complete antivirus project remains
active.

## Limits

Cancellation is cooperative user-mode post-start control. The Local Core
cancellation token remains shared in the current user runtime and is not
authenticated to a cross-instance job ID. Controller serialization and exact
process leasing constrain this client instance; they do not prove arbitrary
cross-instance serialization, installed service ownership, cross-identity IPC,
driver/kernel interception, or pre-execution blocking.
