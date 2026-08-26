# Checkpoint 2242 - Cooperative Archive Inflate Cancellation

## Objective

Reduce cancellation latency inside Native Engine's bounded ZIP sample
collection. Preserve existing archive safety limits and keep cancellation or
probe failure distinct from malformed/limited archive evidence.

## Scripted Implementation

- The ZIP sampler accepts an internal fallible cancellation checkpoint while
  the existing public entrypoint preserves compatibility through an infallible
  no-cancel callback.
- Local-header and central-directory sampling invoke the checkpoint before each
  parsed entry. Stored-body copies are checked before and after the bounded
  copy.
- Deflate sampling replaces one `read_to_end` with an explicit output loop. A
  checkpoint runs before every read request and after completion; each request
  is capped at 64 KiB and the existing 1 MiB per-entry output bound remains.
- Callback errors propagate unchanged through the ZIP analyzer and archive
  scanner. Typed cancellation remains cancellation; token-probe failure remains
  a fail-visible command error. Neither becomes `limit_exceeded`, a partial
  archive result, or a verdict.
- Existing 64 sampled-entry, 4 MiB sampled-total, 1 MiB sampled-entry, maximum
  recursion depth, encryption, path, and malformed archive policies remain
  unchanged.

## Scripted Coverage

- Benign analyzer tests cancel before a second stored entry and between bounded
  inflate output reads, proving no completed collection is returned.
- Scanner adapter tests use a benign stored local-header fixture and prove
  intra-collection cancellation retains the typed Native cancellation error
  while probe failure remains a distinct fail-visible check error.
- The definitive verifier adds mandatory `cooperative archive collection
  cancellation regressions`; full-suite validation requires exactly 271 steps
  and exact verified/technical-limit scope. Source contract 672 binds source,
  tests, verifier, validator, matrix, threat model, blockers, dependencies,
  status, run log, and this report.

No checkpoint-2242 passing result is claimed during scripting. No live malware,
EICAR file, candidate execution, Defender change, machine-wide install,
service/driver start, dependency, lockfile, release, publication, or protected-
vault mutation is involved.

## Local Verification

- Focused cooperative archive cancellation passes `4/4`; adjacent cooperative
  scan cancellation passes `9/9`. Complete Native Engine passes `553` tests
  with `19` intentional isolated-child ignores plus signature compiler `6/6`;
  Local Core passes `546/546`.
- Source contracts pass `672/672`. Windows PowerShell 5.1 and PowerShell 7
  parsers pass; rustfmt, `git diff --check`, strict Native/Local Clippy, locked
  workspace release build, Flutter analyzer, and Flutter `847/847` pass.
- The definitive verifier passes exact `271/271` from
  `2026-08-26T11:10:24.2677488Z` through
  `2026-08-26T11:19:19.9980328Z` in `535.7s`, with zero failed/skipped steps,
  Rust/Flutter enabled, and Defender/EICAR opt-in disabled. Embedded and
  independent Windows PowerShell 5.1/PowerShell 7 validation pass. Report
  SHA-256 is
  `730d83aefb8d3d6d8f1673f7394594aae83af2a25573efe64d57dfe2ca6466db`.
- Adversarial copies are rejected when the mandatory checkpoint step is
  removed (`270` steps) or the exact at-most-64-KiB inflate scope is removed.
  The first adversarial harness invocation stopped early on expected native
  stderr, and its next scope assertion did not tolerate PowerShell line
  wrapping; both harness defects were corrected before the two-rejection pass.
- The initial rustfmt check found four formatting-only differences and the
  repository formatter repaired them. Optional `pytest` is absent from both
  existing Python runtimes, so two attempted pytest invocations failed before
  collection and are uncredited; no dependency was installed and the
  repository's dependency-free runner produced the credited `672/672` result.
  One initial parser command had invalid parent-shell variable escaping and is
  likewise uncredited; corrected fail-closed PS5/PS7 parser runs pass.
- Root, Native, and Flutter lock hashes remain exact. The protected vault stays
  `16072` files, zero directories, `4522733` bytes, `5357` each
  `.avoraxq`/`.json`/`.auth`, one metadata key, zero pending, and zero reparse.
  Hosted exact-head evidence, normal merge, guarded synchronization, and
  independent destination verification remain pending.

## Limits

Cancellation remains cooperative. It cannot hard-interrupt one already-running
`flate2` decoder read; cancellation is observed before the next at-most-64-KiB
output request. Native static analysis has separate bounded archive metadata,
OOXML relationship, and autorun inspection that remains synchronous. Active
filesystem reads, rule/ML calls, and the Windows trust helper retain their
documented boundaries. Same-user token visibility, installed service ownership,
cross-identity authentication, driver/kernel cancellation, and pre-execution
blocking remain partial, blocked, or technically limited.
