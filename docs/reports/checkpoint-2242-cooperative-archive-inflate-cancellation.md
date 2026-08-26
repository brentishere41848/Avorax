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

## Implementation-Head Hosted Evidence

Implementation head `ef1944db1e84fd8cbdff9c8db200073640e281ae` passes Avorax
CI PR run `32963240331`. All five jobs pass: branding/copy, Flutter client and
protocol, Rust Local Core and Guard, Unix quarantine permission runtime, and
security/protection/performance gates.

Desktop Packages push run `32963175466` and PR run `32963240244` pass package
contracts, Windows x64 MSI/setup EXE, Linux x64 DEB/tar, macOS arm64/x64 DMGs,
and consolidation/checksums. Publication jobs `98163620162` and `98164407214`
are explicitly skipped; no release or prerelease is created.

Consolidated artifacts `9605102016` and `9605194147` are `131922540` and
`131921189` bytes. Downloaded SHA-256 values exactly match GitHub digests
`96f8bb64f3bfd9af53600cab71b9baffb26a1fe9a3b50d3b26f541409fc536f4`
and
`92042d73caa0f4e6326c9a24c3344c2b9efa2535d2f629b02b584955ac9c94e2`.
Bounded in-stream validation, without extraction or execution, passes exactly
eight unique regular root entries, six platform files, seven matching internal
checksum targets, clean ZIP reads, and one CycloneDX 1.6 lockfile SBOM with
exactly 569 components. Evidence-head hosting, merge, synchronization, and
destination verification remain open.

## Integration And Destination Closure

Evidence head `bedac3896165f17422151c0ad514e7f2c507cea9` passes Avorax CI
`32965133555` and Desktop Packages PR run `32965133524`. Publication job
`98169278119` is skipped. Consolidated artifact `9605774079` is `131920671`
bytes; GitHub and downloaded SHA-256 both equal
`01a4a9643bd31902e787ce3afd62db81d588fa3434d9981aff538cc488a8200c`.
Its bounded non-extracting validation passes the exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component contract.

PR `#94` merged normally as
`31e476a3d9d960575827cbfa2da66db779f287dd`, with exact parents
`68f766301041ee5e106569b7bd0afe1c63f3165d` and
`bedac3896165f17422151c0ad514e7f2c507cea9`. Merged-main CI
`32966419598` and Desktop Packages `32966419580` pass; publication job
`98175322074` is skipped. Main consolidated artifact `9606492259` is
`131962074` bytes with matching GitHub/download SHA-256
`fbc54923e23d5916a6681ec888326b048a2c75f16e592c164a4b4c28dab263c7`
and passes the same non-extracting artifact contract.

Guarded synchronization applied exact merge content for `13/13` inventoried
paths (`12` modified, `1` added), with zero deletion, mismatch, reparse, or
temporary residue. Every modified destination target matched the old main blob
through Git's configured path filters before replacement. Destination focused
archive cancellation passes `4/4` and adjacent cancellation passes `9/9`.
Complete Native passes `553` with `19` intentional child-fixture ignores plus
compiler `6/6`; Local Core `546/546`, Flutter `847/847`, source contracts
`672/672`, analyzer, strict Native/Local lint, locked release build, and dual
PowerShell parsing pass.

The first default-parallel destination Native run exposed one isolated helper
handshake race: the wrong-response-MAC parent received a short key-confirmation
message (`552` passed, `1` failed, `19` ignored). The exact failing test then
passed, and the complete serial Native rerun passed `553`/`19` plus compiler
`6/6`; the failed parallel run is uncredited and remains the next hardening
lead. A first read-only sync helper compared raw LF blobs to CRLF worktree
bytes and refused before mutation; Git path-filter hashing repaired the helper.
An initial parser wrapper expanded its error preference in the parent shell,
and the first verifier invocation correctly rejected a report path outside the
destination repository; corrected fail-closed reruns pass. None of these
attempts touched the protected vault or weakened host security.

Destination definitive verification passes exact `271/271` from
`2026-08-26T12:32:28.2854077Z` through
`2026-08-26T12:40:55.9600402Z` in `507.6s`. Independent Windows PowerShell
5.1/PowerShell 7 validators pass; report SHA-256 is
`2cb5cf20cbedce244d240de260da5d28db65c91cbb53972edbd47964a8fed4c2`.
The three lock hashes remain exact and the protected vault remains `16072`
files, zero directories, `4522733` bytes, `5357` each
`.avoraxq`/`.json`/`.auth`, one metadata key, zero pending, and zero reparse
points. Checkpoint 2242 is closed; the complete antivirus goal remains active.

## Limits

Cancellation remains cooperative. It cannot hard-interrupt one already-running
`flate2` decoder read; cancellation is observed before the next at-most-64-KiB
output request. Native static analysis has separate bounded archive metadata,
OOXML relationship, and autorun inspection that remains synchronous. Active
filesystem reads, rule/ML calls, and the Windows trust helper retain their
documented boundaries. Same-user token visibility, installed service ownership,
cross-identity authentication, driver/kernel cancellation, and pre-execution
blocking remain partial, blocked, or technically limited.
