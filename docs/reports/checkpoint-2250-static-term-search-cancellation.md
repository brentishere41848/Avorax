# Checkpoint 2250 - Static Term-Search Cancellation

Status: **Verified, hosted, merged, synchronized, and destination-tested**

The complete antivirus-hardening goal remains active. This checkpoint narrows
one cancellation-latency gap in bounded Native static analysis; it does not by
itself establish production antivirus completion, Defender replacement, or
pre-execution blocking.

## Prior Verified Baseline

- Checkpoint 2249 implementation merge
  `ee8267b16b0c1b88bad86d98e9b81c6a329eadfb`, closure documentation commit
  `a6e9c696b51987b677012f5fea1b14b31f804fc8`, and normal closure merge
  `be7eecc30df459ed922d6c96550fd19823ee63c8` are the exact branch base.
- PR `#108` exact-head Avorax CI run `33040170513` and merged-main Avorax CI
  run `33040582289` passed all five jobs. No Desktop Packages, publish, release,
  installer, service, or driver workflow ran for that documentation-only merge.
- Guarded destination synchronization covered exactly four modified documents,
  zero additions, and zero deletions; independent Git-filter-aware comparison
  passed `4/4`, with no synchronization residue.
- The clean destination definitive verifier passed exact `278/278`, zero failed
  or skipped, from `2026-08-27T04:59:42.7928737Z` through
  `2026-08-27T05:07:10.8123425Z` in 448 seconds. Embedded and independent PS5
  and PS7 validators accepted report SHA-256
  `00c0202ac86a41d5491720d30f81d3019f5bde5db0cb28c5910d69cdc00f8e46`.
- Root Cargo, Native Cargo, and Flutter lock SHA-256 values were exact at
  `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
  `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
  `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
  The protected vault was exact at 16,072 files, zero directories, 4,522,733
  bytes, 5,357 each payload/metadata/auth, one key, zero pending/temp, and zero
  reparse points.

## Risk And Objective

String Indicator groups, script term groups, PE-import terms, and decoded UTF-16
marker probes operated on bounded views, but an individual standard-library
`matches` or `contains` search could traverse the complete view after one
callback. At the existing 64 MiB ordinary-sample cap, cancellation latency for a
single absent or late term was therefore larger than the surrounding 64-KiB
normalization and provider-search intervals.

Checkpoint 2250 gives these exact static term-search consumers one shared,
fallible, non-overlapping byte-search responsibility. It checks the exact
scan-job callback before every at-most-64-KiB candidate-start chunk and after
completion, while preserving cross-chunk matches and Rust `str::matches`
non-overlapping count behavior.

## Scripted Implementation

- `signatures/search.rs` owns
  `count_exact_non_overlapping_with_cancellation`. It rejects an empty needle,
  handles shorter inputs without indexing, uses checked/bounded candidate
  windows, saturates the public evidence count, advances by the full needle
  length after a match, and propagates every callback error.
- The String Indicator analyzer and script analyzer use the shared counter for
  grouped explainable counts. The PE-import analyzer uses it for suspicious API
  category counts.
- Script `contains_any` and String Indicator UTF-16 marker probes reuse the
  existing shared exact-search primitive, which has the same 64-KiB candidate
  chunk boundary.
- No analyzer evidence is published by the exercised call paths after an
  injected callback error. File-verdict publication remains behind successful
  completion of the whole static analysis stage.
- The obsolete whole-view production forms `.matches(term).count()`,
  `text.contains(term)`, and `text.contains(marker)` are absent from these
  consumers.

## Scripted Benign Regression Evidence

Six non-executing tests are scripted under the `static_term_search_` filter:

1. shared-search cancellation on the second candidate chunk;
2. cross-chunk exact matches and non-overlapping count compatibility;
3. fail-visible empty-needle rejection;
4. String Indicator term-search interruption before evidence;
5. script term-search interruption before evidence; and
6. PE-import term-search interruption before evidence.

Verifier step 279 runs this exact filter single-threaded. The report validator
requires exactly 279 steps, the named step, the verified boundary, and the
cooperative technical limit. Source contract 680 pins implementation wiring,
removed whole-view forms, all six test names, verifier/validator contracts, and
this audit/documentation set.

No checkpoint-2250 test has run during this scripting phase. The implementation,
test scripts, verifier, validator, Source contract 680, and documentation were
completed before execution as requested; every checkpoint-2250 result remains
unverified until the next phase.

## Safety And Dependencies

Fixtures contain only ordinary benign in-memory text and byte arrays. They are
never executed. This checkpoint downloads, unpacks, retains, or executes no
malware; creates no live EICAR file; changes no Defender setting; and installs or
starts no machine-wide component, service, driver, or installer. It does not
read from, write to, or alter the protected quarantine vault.

The implementation uses Rust slices, checked arithmetic, iterators, and the
already locked `anyhow` boundary. It adds no dependency, feature, build script,
network source, package source, license obligation, or lockfile change.

## Limits And Verification Plan

Cancellation remains cooperative, not preemptive. One at-most-64-KiB static
term-search candidate chunk can finish after its callback admits it. One
at-most-64-KiB normalization chunk, one UTF-16 decode interval, one separately
bounded structured line/predicate traversal, an entered OS/filesystem call,
bounded ML sorting, or one Windows trust call may also finish before the next
checkpoint. Existing 64 MiB ordinary-sample and smaller archive-body caps remain
the memory/work boundary.

The next phase must run formatting/parser checks, Source `680/680`, focused and
adjacent cancellation tests, full Native/Local Core/Flutter/workspace/release and
security regressions, exact lock/vault checks, then the definitive exact
`279/279` verifier with independent PS5/PS7 acceptance and adversarial report
rejection. Hosted exact-head CI/packages, bounded artifact review, normal PR
integration, merged-main evidence, guarded zero-delete destination sync, and
clean destination focused/definitive reruns remain required before checkpoint
closure.

## Local Verification Evidence

- Formatting and dual PS5/PS7 parser checks pass. Source contracts pass exact
  `680/680` using the dependency-free repository runner.
- The dedicated static term-search filter passes `6/6`; adjacent non-archive
  cancellation, static text normalization, and provider-search filters pass
  `15/15`, `5/5`, and `9/9`.
- Full Native passes 615 active library tests plus compiler CLI `6/6`; 21
  documented child fixtures remain intentionally ignored and are exercised by
  their parent tests. Local Core passes `546/546`. Flutter analyze reports no
  issue and Flutter tests pass `847/847` with concurrency one.
- Locked workspace tests and the locked release build pass. Strict all-target
  Native/Local Clippy with warnings denied passes.
- The first locked workspace attempt had one host failure: Windows Defender
  returned OS error 225 while the environment-spoof regression tried to launch
  its already-built benign test child. The standalone test, the exact
  workspace-feature test, and a complete locked workspace rerun all pass. No
  Defender setting or exclusion was changed.
- All three lock hashes and the protected vault invariant remain exact. The
  vault was inspected read-only and not mutated.

This verifies the implementation locally but does not yet satisfy hosted,
integration, guarded-sync, or destination closure requirements.

## Definitive Local Verification

- The definitive verifier passes exact `279/279`, zero failed and zero skipped,
  from `2026-08-27T05:59:15.7292499Z` through
  `2026-08-27T06:10:05.6522100Z` in `649.9s`.
- Embedded and independently invoked PS5 and PS7 validators accept report
  SHA-256
  `b011b66f3c6af642898170b4192a94889eb8fe8d4c6b0e8419a93f7b40baee40`.
  Both hosts reject a copied report missing verifier step 279 and one missing
  the new static-term verified-scope sentence with exit code `1`.
- The complete verifier includes the security, dependency, package-source,
  bounded synthetic-performance, update, scan, quarantine, restore, delete,
  allowlist, watcher, process-observation, logging, configuration, and UI
  control gates. No optional Defender-EICAR probe was requested.
- All three lock hashes remain exact. A read-only post-run inventory confirms
  the protected vault at 16,072 files, zero directories, 4,522,733 bytes,
  5,357 each payload/metadata/auth, one key, zero pending/temp, and zero reparse
  points.

## Hosted, Integration, And Destination Evidence

- Exact implementation head `0847f3e1e0e907eea4db62dd8a4a5d1aadaad177`
  passes package push run `33045290583`, PR `#109` CI run `33046384310`, and PR
  package run `33046384413`. PR `#109` merges normally as
  `a423fb6f2b926f44c04f21702f708514691f9bc5` with exact parents
  `be7eecc30df459ed922d6c96550fd19823ee63c8` and the implementation head.
- Merged-main CI `33047841657` passes all five jobs. Merged-main packages
  `33047841686` pass contracts, Windows MSI/EXE, Linux DEB/tar, both macOS DMGs,
  and consolidation. Publication is skipped in every package workflow.
- Consolidated artifacts `9635711594`, `9636300557`, and `9636729381` are
  respectively 131,980,599, 132,101,087, and 131,977,967 bytes. Their SHA-256
  values are
  `0bb20102ce08747c86f3307167af096c39915626c401f2c1f49b77b7e52fe02e`,
  `d5583851a3dfbc91e8e04b5838d8c59c461cd09b8a40ecda02f0e2625637d4bf`,
  and `71e8024f83d2cdf366c86cdf3745d288ad42189060b131fd57f079f35a6f50e1`.
  Every digest and size matches GitHub. Bounded in-stream review confirms exact
  eight root entries, six platform packages, seven checksum targets, and a
  CycloneDX 1.6 SBOM with 569 unique components. No artifact is extracted or
  executed.
- Guarded synchronization from `be7eecc` to `a423fb6` audits and applies exact
  `14/14` paths: thirteen modifications, one addition, and zero deletions.
  Independent Git-filter-aware comparison passes `14/14`; no staging residue
  remains.
- Destination Source contracts pass `680/680`; focused static term-search tests
  pass `6/6`; formatting passes. The definitive destination verifier passes
  exact `279/279`, zero failed or skipped, from
  `2026-08-27T07:18:04.9339385Z` through
  `2026-08-27T07:29:32.6075212Z` in `687.6s`. Embedded and independently invoked
  PS5 and PS7 validators accept report SHA-256
  `70ade0c2a2929b022f95a5469eb7f548ac1415fe9ca2661c0414b56ccb533ab5`.
- All three lock hashes remain exact in source and destination. The protected
  vault remains read-only and exact at 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each payload/metadata/auth, one key, zero pending/temp,
  and zero reparse points.

## Closure

The implementation sequence, local and definitive verification, exact-head
hosted checks, bounded artifact review, normal integration, merged-main checks,
zero-delete guarded synchronization, and destination verification all pass.
Checkpoint 2250 is closed. The complete antivirus-hardening goal remains active.

Cancellation remains cooperative and the technical limits in this report are
unchanged. This checkpoint does not claim installed service ownership,
driver/kernel mediation, production detection accuracy, pre-execution blocking,
or Defender replacement. No release, publication, installation, service/driver
start, Defender change, live-malware action, or protected-vault mutation
occurred.
