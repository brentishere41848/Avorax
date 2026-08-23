# Checkpoint 2214: Authenticode Job Membership

## Status

Implementation and definitive local verification are complete. Hosted exact-head,
evidence-head, PR/merge, merged-main, original-tree synchronization, and destination
verification remain pending, so the checkpoint is not integrated or closed.
No checkpoint-2214 passing result is claimed before execution; every passing claim
below comes from the later execution phase.

## Scripted Boundary

- After `AssignProcessToJobObject` and before `ResumeThread`, the parent requires
  the nonzero `PROCESS_INFORMATION.dwProcessId` to equal `GetProcessId` from the
  still-open process handle.
- `IsProcessInJob` must confirm membership in the exact parent-created Job.
- `QueryInformationJobObject(JobObjectBasicProcessIdList)` must return exactly
  `sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)`, exactly one assigned process,
  exactly one listed process, and the helper PID as the sole list entry.
- Any parent-side identity, API, returned-size, count, or PID mismatch terminates
  and reaps the still-suspended child; there is no resume or weaker retry.
- As its first in-process check, before standard handles, private desktop, token,
  mitigation, stdin, request, or candidate work, the child requires nonzero
  `GetCurrentProcessId` and successful `IsProcessInJob` membership in some Job.
- Child-side query failure or a false result is diagnostic and cannot become
  Microsoft publisher trust.

## Scripted Evidence

- A benign isolated child passes through the real parent assignment and exact
  membership read-back, independently checks its current Job membership, and
  emits only `AVORAX_JOB_MEMBERSHIP_OK`. The fixture never executes a candidate.
- Pure adversarial evidence rejects wrong returned byte counts, zero or multiple
  assigned/listed counts, absent or substituted list PIDs, zero or mismatched
  process identities, false exact-Job evidence, and false child membership.
- The central verifier adds exact step 244:
  `native-engine Authenticode helper Job membership regressions`.
- The independent validator requires exactly 244 successful steps, the exact
  step, parent and child scope, fail-visible cleanup semantics, and the residual
  limitation. A stale 243-step report must fail.
- Source contracts account for the APIs, ordering, tests, verifier, validator,
  dependency statement, and every required audit surface.

## Technical Limits

Parent exact-Job and PID-list read-back is point-in-time process confinement,
while the child's null-Job `IsProcessInJob` check proves only membership in some
Job. The child cannot recover the unnamed parent Job handle by identity, so it
does not independently prove that exact Job. A Windows PID is unique only while
the process remains alive; the parent retains the process handle through exit.

The one-active-process Job limit and kill-on-close behavior remain mandatory, but
Job membership does not authenticate or encrypt anonymous-pipe IPC, change SID or
profile, deny ordinary reads, or create AppContainer/LPAC isolation. It is not
installed LocalSystem evidence, driver interception, or pre-execution blocking.

No live malware, network retrieval, installation, service/driver start, Defender
change, release, publication, or protected-quarantine mutation is permitted.

## Local Evidence

- Both PowerShell parsers pass. The first command form lost `$` variables in the
  calling shell and failed before parsing a file; the corrected literal command is
  the evidence. Initial `rustfmt --check` found import wrapping only; mechanical
  formatting and the repeated check pass. `git diff --check` passes.
- The host Python lacks `pytest`; the repository's required standalone source-
  contract runner passes `644/644` and does not depend on that optional module.
- Focused real-child/adversarial Job membership passes `2/2`. Complete Windows
  Authenticode passes `49` with `11` intentional isolated-child ignores.
- Native Engine passes `485` with `11` intentional ignores and the signature
  compiler passes `6/6`. Both standard and all-feature locked workspace variants
  pass. Strict all-target/all-feature Native, Local Core, and Guard Clippy passes
  with warnings denied.
- Locked release Local Core and Guard builds pass. The first manual trust-smoke
  command rejected relative binary paths before fixture work; the corrected
  absolute-path two-host smoke passes embedded/catalog Microsoft trust, unsigned
  rejection, scanned-hash mismatch failure, and no fixture execution.
- Flutter analysis reports no issues and the complete Flutter suite passes
  `838/838`. No-malware and dependency-evidence gates pass.
- The definitive report
  `.verification/checkpoint-2214-job-membership-definitive-report.json` passes
  exactly `244/244`, with zero failed/skipped steps, from
  `2026-08-23T22:04:41.5595827Z` through `2026-08-23T22:12:25.8846277Z`
  (`464.3s`). Its embedded validator and a separate standalone invocation pass.
- Six fresh adversarial copies are rejected: stale `243` count, renamed required
  step, removed parent scope, removed child scope, removed technical-limit scope,
  and a skipped required step.
- Root Cargo, Native Cargo, and Git-filtered Flutter lockfiles remain exact at
  blobs `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`.
- The protected vault remains exactly `16,072` files, zero directories,
  `4,522,733` bytes, `5,357` each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending.

## Hosted Evidence

Implementation commit, exact-head CI/package workflows, evidence-head, normal
PR/merge, merged-main checks, guarded synchronization, and destination rechecks
remain pending. No release, publication, install, service/driver start, or direct
main push is authorized.

## Current Classification

- Verified: checkpoint-2214 implementation and definitive local evidence above.
- Partial: hosted, integration, synchronization, destination, installed, and final-
  artifact evidence remains pending.
- Disabled/blocked: installed service/driver and pre-execution claims remain
  unavailable; no weaker fallback is enabled.
- Technically limited: parent exact-Job/PID-list state is point-in-time and child
  null-Job membership identifies only some Job; IPC and identity are unchanged.
