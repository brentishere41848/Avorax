# Checkpoint 2234 - PowerShell JSON String Validation

## Objective

Remove the verifier-host discrepancy exposed by checkpoint 2233 without
weakening strict report types. PowerShell 7.5 and later may coerce ISO-8601 JSON
strings to `DateTime` during `ConvertFrom-Json`; Windows PowerShell 5.1 leaves
them as strings. The report contract requires timestamp properties to remain
JSON strings before explicit invariant-culture ISO-8601 parsing.

## Scripted implementation

- `ConvertFrom-AvoraxGateJsonPreservingStrings` uses the native `DateKind`
  parameter with exact `String` behavior when that parameter exists and keeps
  the compatible Windows PowerShell 5.1 call shape otherwise.
- All nine bounded JSON readers in the strict small-threat report validator use
  that helper. Strict object, property, scalar type, timestamp, path, scope,
  generated-report, status, and exact 263-step checks remain unchanged.
- The definitive verifier resolves checked regular-file paths for distinct
  Windows PowerShell 5.1 and PowerShell 7 executables, then requires the exact
  generated report to pass the same validator under both hosts.
- Source contract 664 accounts for helper dispatch, all nine readers, distinct
  checked hosts, exact scope wording, documentation, and unchanged step count.

## Scripted adversarial coverage

Existing strict report validation still rejects non-string timestamps,
malformed JSON, missing or extra schema fields, unsafe paths, false success,
incorrect step counts, and inconsistent nested evidence. Checkpoint execution
will additionally run the same benign prior exact report through both hosts and
then run the existing isolated malformed-report suite. No candidate file or
malware fixture is executed.

## Evidence state

No checkpoint-2234 passing result is claimed during scripting. After the full
batch was scripted, Windows PowerShell 5.1 and PowerShell 7 parser checks passed,
the focused valid 263-step checkpoint-2233 report passed under both hosts, and
numeric/object timestamp plus malformed JSON fixtures were rejected `4/4`.
Source contracts pass `664/664`.

Broad local regression passes Native `517/517` with 19 intentional isolated
child-fixture ignores plus signature compiler `6/6`, Local `536/536`, Guard
`248/248 + 249/249`, Flutter analyze, and Flutter `838/838`. A combined root
workspace run passed platform security, update service, API, and Local Core,
then Defender blocked its separate Native test executable with OS error 225.
That combined run is fail-visible and uncredited; the exact standalone Native
suite above passed without changing Defender.

The definitive report passes exact `263/263`, with zero failed verifier steps,
`include_defender_eicar=false`, `skip_rust=false`, and `skip_flutter=false`, in
`469.9s`. Its post-report strict validator passes first under Windows PowerShell
5.1 and then under PowerShell 7. Eight full-suite mutations per host covering
timestamp type confusion, status/options, cardinality, required dual-host scope,
and failed-step evidence are rejected `16/16`.

## Exact Implementation-Head Hosted Evidence

Implementation commit `708e93907f588a211b0dfe3863f8157eaa8d1dc8` is PR
`#86`'s exact head. Avorax CI run `32878421258` passes all five jobs without a
retry. Desktop Packages push `32878368995` and PR `32878421335` pass package
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS x64/arm64 DMGs,
consolidation, checksums, and evidence upload. Publication jobs `97910531652`
and `97907714051` are explicitly skipped; no release or prerelease is created.

Consolidated artifacts `9575787747` and `9575480016` are 131,538,658 and
131,528,096 bytes. Their downloaded SHA-256 values exactly match GitHub at
`0a6a6ba0031b84f3f7c15dfde1b09256f24324cd74a89c066659962fe6668e5d`
and `eabac11ac088712ecd29dfdf977ba9b0318724322eada3d65672b7f4b2640047`.
Bounded in-stream review, without extraction or execution, passes exactly eight
unique regular root entries, six platform release files, seven matching
checksum rows, and one CycloneDX 1.6 lockfile SBOM with 569 components.
Evidence-head checks, normal merge, merged-main evidence, guarded
synchronization, and destination verification remain pending.

## Integration And Destination Closure

Evidence head `a5cf1c5a311159feba3bbb9fa3276b68c5093a60` passes Avorax
CI `32881438307` and Desktop Packages `32881438208` without retry. Publication
job `97915871533` is skipped. Consolidated artifact `9576386744` is
131,680,378 bytes; its downloaded SHA-256 matches GitHub at
`565d4ec592d7a2704d4ffb64d104d4c91fc1e75d2aadc0295e3b8e5b5deccb03`
and its non-extracting review passes exact 8/6/7/CycloneDX 1.6/569 evidence.

PR `#86` merges normally as
`c969351dd7fae979d6b49df9e870db92a4e51f23`, with exact parents
`7467bfd61a077a8783f3c333ef2488a9d00433f2` and
`a5cf1c5a311159feba3bbb9fa3276b68c5093a60`. Merged-main CI
`32884202709` and packages `32884202759` pass without retry; publication
`97929408266` is skipped. Artifact `9577913781` is 131,563,257 bytes with
matching GitHub/download SHA-256
`1766f2a3a5d01e2366ba004ed611837768063aff7b65ee87f526c23ab8b7d228`
and passes the same non-extracting package/SBOM review.

Guarded base `7330416` preconditions, root containment, reparse rejection,
checked staging, temporary hash verification, and atomic replacement
synchronize exactly 11 paths and 6,434,655 bytes to the merge with zero delete
or residue. The stage is removed only after exact 11-file inventory, merge-hash,
and reparse checks. One first parse-only helper invocation was misquoted by its
outer shell and failed before helper execution; it is retained as uncredited.
The corrected PS5.1 syntax check passed and created no stage.

Destination PS5.1/PS7 parsers, source contracts `664/664`, and exact merge/lock
hashes pass. The no-skip/no-Defender verifier passes exact `263/263`, zero
failed/skipped, from `2026-08-25T19:00:55.9094290Z` through
`2026-08-25T19:08:44.8756230Z` in `468.9s`; both post-report validators pass.
The three package symlink-positive source tests remain explicitly skipped on
Windows because optional symlink privilege is absent. All `16/16` destination
report mutations are rejected across both hosts.

No test process or sync residue remains. The protected vault remains exactly
16,072 files, zero directories, 4,522,733 bytes, 5,357 each payload/JSON/auth,
one metadata key, and zero pending/reparse. Nothing was installed, released,
published, executed as candidate content, or changed in Defender. Checkpoint
2234 is closed; the complete antivirus project remains active.

## Limits

This repairs evidence parsing only. It does not expand antivirus detection,
quarantine, installed-service, signing, driver, or pre-execution capability.
Both PowerShell hosts remain trusted verification prerequisites. The change
adds no dependency, feature, or lockfile change.
