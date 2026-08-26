# Checkpoint 2241 - Cooperative In-Engine Scan Cancellation

## Objective

Reduce the remaining interval in which an exact job-bound cancellation can be
requested while Local Core is synchronously inspecting one file. Preserve
honest accounting: an interrupted file must never publish a partial verdict or
be counted clean, and failure to validate cancellation state must fail visibly.

## Scripted Implementation

- Native Engine defines separate typed errors for accepted cooperative
  cancellation and failure of the cancellation probe. Callers can distinguish
  both through exported predicates without matching diagnostic strings.
- The content reader checks cancellation before preflight, before each
  at-most-1-MiB read request, and after the complete hash read. Sample and full
  hash data are not returned after accepted cancellation.
- `scan_file_with_cancellation` carries one mutable probe through content read,
  static analysis, publisher trust, signatures, bounded archive samples and
  entries, rules, heuristics, ML, and the final verdict-publication boundary.
- Archive sample collection is checked before and after its existing bounded
  operation; each returned sample and recursive nested archive is checked before
  analysis. Existing 64-entry, 4-MiB total, 1-MiB entry, and depth limits stay
  unchanged.
- Local Core passes `scan_cancellation_requested(job_id)` directly into the
  Native scan. Typed cancellation marks the current file plus remaining queue
  unscanned and ends with `Cancelled`. Typed probe failure aborts the command
  with the bounded job-token diagnostic; it is not swallowed as a file error.

## Scripted Coverage

- Native regressions distinguish both typed errors, cancel a sparse benign file
  between content reads, surface probe failure, stop before provider verdict
  publication, and observe the bounded archive boundary.
- Local Core regressions invoke the Native scan directly with an exact existing
  token, reject a malformed token as probe failure, and pin unscanned accounting
  plus fail-visible branching in production source.
- The definitive verifier adds mandatory `cooperative in-engine cancellation
  regressions`; full-suite validation requires exactly 270 steps and exact
  verified/technical-limit scope text. Source contract 671 binds code, benign
  tests, verifier, validator, control matrix, threat model, blockers,
  dependencies, status, run log, and this report.

No checkpoint-2241 passing result is claimed during scripting. No live malware,
EICAR file, candidate execution, Defender change, machine-wide install,
service/driver start, dependency, lockfile, release, publication, or protected-
vault mutation is involved.

## Local Verification

- Focused workspace cancellation regressions pass `9/9`: six Native and three
  Local Core. Complete Native library passes `568` tests plus compiler targets;
  Local Core passes `546/546` after the final enum repair.
- Source contracts pass `671/671`; verifier/validator parse under Windows
  PowerShell 5.1 and PowerShell 7. Rustfmt, `git diff --check`, strict Native and
  Local Core Clippy, locked workspace release build, Flutter analyze, and full
  Flutter `847/847` pass.
- The first source-contract run exposed 39 stale current-cardinality assertions
  and two old direct-scan/content-reader source markers. They were repaired while
  historical 269-step evidence remained unchanged, then all 671 reran cleanly.
- Initial workspace strict Clippy exposed the checkpoint's large result enum;
  the verdict is now boxed and both changed components pass `-D warnings`.
  Workspace-wide strict Clippy remains blocked by three unchanged API-service
  Rust-1.96 lints: two `items_after_test_module` and one `enum_variant_names`.
  The complete locked release build still passes.

The first definitive run completed all 270 product steps but its embedded
validator failed visibly because two new scope assertions referenced the
undefined `$technicalLimitsText` variable. Both references now use the
canonical `$technicalLimitText`; source contract 671 forbids the misspelling.
The complete verifier was rerun rather than accepting the earlier product-step
results.

The rerun passed exact `270/270` from `2026-08-26T09:06:47.5880082Z` through
`2026-08-26T09:14:30.2652828Z` in `462.7s`, with no failed mandatory step,
Rust/Flutter skip, or Defender/EICAR opt-in. Report SHA-256 is
`15be81e12ab47b2851d421e00db5a5b921cbf485c77a213808331c1734b3db59`.
Independent Windows PowerShell 5.1 and PowerShell 7 full-suite validation pass.
Adversarial copies are rejected when the mandatory step is removed (`269`
steps) or when the exact cooperative-cancellation limit is removed.

Root, Native, and Flutter lock hashes remain exact. The protected quarantine
vault remains `16072` files, zero directories, `4522733` bytes, `5357` each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, zero pending files, and
zero reparse points. Hosted exact-head evidence, normal integration, guarded
original-tree synchronization, and destination verification remain pending.

## Limits

Cancellation is cooperative at explicit boundaries. It does not hard-interrupt
an already-running filesystem read, static analyzer substep, bounded archive
collection or inflate, synchronous rule/ML call, or Windows trust helper call.
Those operations may finish before the next checkpoint. The UUID remains a
same-user capability; installed service ownership, cross-identity
authentication, driver/kernel cancellation, and pre-execution blocking remain
partial, blocked, or technically limited.
