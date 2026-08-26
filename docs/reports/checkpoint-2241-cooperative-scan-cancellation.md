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

## Implementation-Head Hosted Evidence

Implementation head `810cea36a8ea14b518a884c56b4d5366c069a3f8` passes Avorax CI
run `32952521600` at the exact PR head. All five jobs pass: Flutter client and
protocol, Rust Local Core and Guard, branding/copy, Unix quarantine permission
runtime, and security/protection/performance gates.

Desktop Packages push run `32952457220` and PR run `32952521616` pass package
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMGs, and
consolidation/checksums. Publication jobs `98130675426` and `98133110658` are
explicitly skipped; no release or prerelease is created.

Consolidated artifacts `9601135988` and `9601425781` are `132013855` and
`131914377` bytes. Downloaded SHA-256 values exactly match GitHub digests
`7b14b7594d04e557f5f03bacbeaa1b5aef8e403cb2907c0dbdfb36483c7d94b6`
and
`fa152bca11d3779c9013bfbf2fe29d67508a00ba8f7a1c516984e8bf5cd52424`.
Bounded in-stream validation, without extraction or execution, passes exact
eight unique regular root entries, six platform files, seven matching internal
checksum targets, clean ZIP reads, and one CycloneDX 1.6 lockfile SBOM with
exactly 569 components. Evidence-head hosting, merge, synchronization, and
destination verification remain open.

## Integration And Destination Closure

Evidence head `dc44b9f6b3af60d4caacfd626e19ecd4a7dc1f7e` passes Avorax CI
`32954883621` and Desktop Packages PR run `32954883591`. Publication job
`98141092965` is skipped. Consolidated artifact `9602378676` is `132010980`
bytes; GitHub and downloaded SHA-256 both equal
`c0b87ebb0acef91ed0060a492872626bb64a3856d8aeda08eda2b91e5a290104`.
Its bounded non-extracting validation passes the same exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component contract. Redundant
manual dispatch `32954878909` was cancelled after the automatic PR run started
and is not credited.

PR `#93` merged normally as
`68f766301041ee5e106569b7bd0afe1c63f3165d`, with exact parents
`96a7042496c00e340fd22f0fb28917fb8d72e191` and
`dc44b9f6b3af60d4caacfd626e19ecd4a7dc1f7e`. Merged-main CI
`32957262066` and Desktop Packages `32957262029` pass; publication job
`98146445860` is skipped. Main consolidated artifact `9603036370` is
`132009707` bytes with matching GitHub/download SHA-256
`4cf6184511f815a64902c6d1ab991dc50354eea6b55fa34f4144e60a671fe8bf`
and passes the same non-extracting artifact contract.

Guarded synchronization copied exact merge content for `19/19` inventoried
paths (`17` modified, `2` added), with zero deletion, mismatch, or temporary
residue. Every modified destination target matched the old main blob before
copy. Destination focused cancellation passes `9/9`; complete Native reports
`549` passed and `19` intentional ignores plus compiler `6/6`; Local Core
passes `546/546`; Flutter passes `847/847`; source contracts `671/671`, analyzer,
strict Native/Local lint, and locked workspace release build pass.

Destination definitive verification passes exact `270/270` from
`2026-08-26T10:41:01.5134634Z` through
`2026-08-26T10:49:39.4241350Z` in `517.9s`. Independent Windows PowerShell
5.1/PowerShell 7 validators pass; report SHA-256 is
`f74307775a173e49c359f30e06e0b8b627fecfc5e13258ebd28906dfa415df9d`.
The three lock hashes remain exact and the protected vault remains `16072`
files, zero directories, `4522733` bytes, `5357` each
`.avoraxq`/`.json`/`.auth`, one metadata key, zero pending, and zero reparse
points. Checkpoint 2241 is closed; the complete antivirus goal remains active.

## Limits

Cancellation is cooperative at explicit boundaries. It does not hard-interrupt
an already-running filesystem read, static analyzer substep, bounded archive
collection or inflate, synchronous rule/ML call, or Windows trust helper call.
Those operations may finish before the next checkpoint. The UUID remains a
same-user capability; installed service ownership, cross-identity
authentication, driver/kernel cancellation, and pre-execution blocking remain
partial, blocked, or technically limited.
