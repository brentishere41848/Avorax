# Checkpoint 2251 - Static Reference-Search Cancellation

Status: **Verified, hosted, merged, synchronized, and destination-tested**

The complete antivirus-hardening goal remains active. This checkpoint narrows
one cooperative cancellation-latency gap in the Avorax Native Engine string
indicator provider. It does not establish production antivirus completion,
installed-service ownership, pre-execution blocking, or Defender replacement.

## Prior Verified Baseline

- Checkpoint 2250 is closed through normal merge
  `aaa0885ecf49a101764d3806c8a92e2f9288c136` and guarded destination
  synchronization.
- Destination Source contracts passed `680/680`; the closure-state definitive
  rerun passed exact `279/279`, zero failed or skipped, in `656.5s`. Independent
  PS5/PS7 validators accepted report SHA-256
  `0ed8a34c82707f1e14a77081621482ce7307e834b288f0d2e599e49dfe57f549`.
- Root Cargo, Native Cargo, and Flutter lock SHA-256 values were exact at
  `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
  `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
  `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
- The protected quarantine inventory was read-only and exact at 16,072 files,
  zero directories, 4,522,733 bytes, 5,357 each payload/metadata/auth, one key,
  zero pending/temp, and zero reparse points.

## Risk And Objective

The String Indicator engine already bounds ordinary input to 64 MiB and checks
cancellation between reference groups and every 1,024 references. However,
each URL or remote network-path group still used one complete-tail `str::find`
for an absent or late marker and another complete-tail predicate search for the
reference terminator. One search could therefore traverse the remaining ASCII
or decoded UTF-16 view after a single callback.

Checkpoint 2251 gives those exact searches two documented responsibilities:

1. the shared exact finder locates the first marker while checking the scan-job
   callback before every at-most-64-KiB candidate-start chunk; and
2. the String Indicator reference-body scanner locates the first Unicode
   whitespace or existing delimiter while checking before every at-most-64-KiB
   UTF-8-safe byte chunk.

The change must preserve first-match order, reference counts, suffix
classification, Unicode whitespace behavior, remote/local path distinctions,
and fail-visible callback errors before `StringIndicators` or a verdict can be
published.

## Scripted Implementation

- `signatures/search.rs` owns `find_exact_with_cancellation`. It rejects an
  empty needle, handles shorter input without indexing, preserves matches that
  cross a chunk boundary, returns the first exact byte offset, and propagates
  arbitrary callback errors.
- `analyzers/strings.rs` owns `reference_end_with_cancellation`. Chunks end only
  on valid UTF-8 boundaries, so `char::is_whitespace` and the prior delimiter
  set retain their existing semantics.
- Both `http://`/`https://` marker loops and both UNC/`file://` marker loops use
  the shared finder. Both URL and network-path body traversals use the bounded
  terminator scanner.
- Existing 1,024-reference checkpoints remain as a second bound around
  per-reference classification work. Counts continue to use saturating
  arithmetic.
- The old whole-tail `text[search_start..].find(marker)` and predicate-body
  forms are absent from the production reference paths.

## Scripted Benign Regression Evidence

Eight non-executing tests are scripted under the
`static_reference_cancellation_` filter:

1. shared finder cancellation on its second candidate chunk;
2. first-match and cross-chunk offset compatibility;
3. fail-visible empty-needle rejection;
4. URL marker-search interruption before evidence;
5. URL reference-body interruption before evidence;
6. remote network-path marker-search interruption before evidence;
7. remote network-path body interruption before evidence; and
8. Unicode whitespace detection when the multibyte delimiter crosses a chunk
   boundary.

Verifier step 280 runs this exact filter single-threaded. The independent
report validator requires exactly 280 steps, the named step, both verified
scope statements, and the cooperative technical limit. Source contract 681
pins implementation wiring, removed whole-tail forms, all eight test names,
the verifier/validator contract, and this documentation set.

No checkpoint-2251 test has run during this scripting phase. The implementation,
test scripts, verifier, validator, Source contract 681, and documentation are
complete before execution as requested. No checkpoint-2251 behavior is
described as verified yet.

## Safety And Dependencies

Fixtures contain only ordinary benign in-memory text and byte arrays and are
never executed. This checkpoint downloads, unpacks, retains, executes, or
writes no candidate content; creates no live EICAR file; changes no Defender
setting; and installs or starts no machine-wide component, service, driver, or
installer. It does not read from, write to, or alter the protected quarantine
vault.

The implementation uses Rust slices, strings, UTF-8 boundary checks, iterators,
checked/saturating arithmetic, and the already locked `anyhow` boundary. It
adds no dependency, feature, build script, network/package source, license
obligation, or lockfile change.

## Limits And Verification Plan

Cancellation remains cooperative, not preemptive. One admitted at-most-64-KiB
reference-marker candidate chunk or UTF-8-safe reference-body chunk can finish
after its callback. A normalization chunk, UTF-16 decode interval, structured
line traversal, entered OS/filesystem call, bounded ML sort, archive inflate
read, or Windows trust call retains its separately documented limit. The
existing 64 MiB ordinary-sample cap bounds total input but is not a deadline.

The execution phase must begin only after the entire scripting batch is
complete. It must run formatting and dual PowerShell parser checks, Source
`681/681`, focused and adjacent cancellation/compatibility suites, full Native,
Local Core, Flutter, locked workspace/release, strict lint, packaging and
security gates, exact lock/vault checks, then definitive exact `280/280`
verification with independent PS5/PS7 validation and adversarial report
rejection. Exact-head hosted CI/packages, bounded artifact review, normal PR
integration, merged-main evidence, guarded zero-delete destination sync, and
clean destination focused/definitive reruns remain checkpoint-closure
requirements.

No release, publication, installation, service/driver start, Defender change,
live-malware action, or protected-vault mutation is authorized or claimed.

## Local Verification Evidence

- Rustfmt and dual PS5/PS7 parser checks pass. Source contracts pass exact
  `681/681` using the dependency-free repository runner.
- The dedicated static reference-search filter passes `8/8`; prior static term
  search passes `6/6`; all String Indicator tests pass `45/45`; adjacent
  non-archive cancellation passes `15/15`.
- Full Native passes 623 active library tests plus compiler `6/6`; 21 documented
  child fixtures remain intentionally ignored and are exercised by parent
  tests. Local Core passes `546/546` in both standard and all-feature locked
  workspace runs.
- Strict all-target/all-feature Native, Local Core, and Guard Clippy passes.
  Standalone locked/offline Native check and locked release workspace build
  pass.
- Flutter analyze reports no issue; Flutter tests pass `847/847` with
  concurrency one. Dart protocol tests pass `14/14`.
- The first focused compile exposed a test-only `expect_err`/`Debug` bound on a
  private count struct. The tests now obtain the injected error through an
  explicit match without adding an unnecessary production trait. The first
  Source run exposed a replaced historical checkpoint-2245 scope sentence;
  that exact sentence was restored and the new limit was added separately.
  Focused and complete reruns pass.
- Root Cargo, Native Cargo, and Flutter lock hashes remain exact at the expected
  values. Flutter resolved the existing pinned dependencies without changing
  `pubspec.lock`.
- Read-only inventory confirms the protected vault remains exact at 16,072
  files, zero directories, 4,522,733 bytes, 5,357 each payload/metadata/auth,
  one key, zero pending/temp, and zero reparse points.

This verifies the implementation locally but does not yet satisfy definitive
`280/280`, adversarial report, hosted, integration, guarded-sync, or destination
closure requirements. The cooperative limit remains unchanged.

## Definitive Verification Evidence

- The definitive Windows PowerShell 5.1 verifier completed with status
  `passed`: exact `280/280`, zero failures, elapsed `662.9` seconds. The exact
  `native-engine static reference-search cancellation regressions` step appears
  once and passed.
- Report:
  `.workflow/ultracode/avorax-hardening/results/checkpoint-2251-local-verification-report-final.json`.
  SHA-256:
  `17b60115b7a419310646789d4dc8b17b157b3e62ab0f1b2da6ec48d0dbe8b5f4`.
- Independent `-RequireFullSuite` validation accepts that exact report under
  Windows PowerShell 5.1 and PowerShell 7 with exact 280-step cardinality.
- Adversarial copies are rejected by both validators: removing the new step
  yields 279 and fails exact cardinality; preserving 280 steps but removing the
  new verified-scope sentence fails required-scope validation. The two exact
  temporary copies were removed after the checks.
- A post-verifier read-only audit reconfirms all three expected lock hashes and
  the protected-vault invariant: 16,072 files, zero directories, 4,522,733
  bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and
  zero pending/temp/reparse entries.

This supersedes the earlier definitive-local pending statement. Exact-head
hosted CI/packages, normal PR integration, guarded source synchronization, and
destination reruns remain required before checkpoint closure. Cancellation
remains cooperative, and the complete antivirus-hardening goal remains active.

## Hosted, Integration, And Artifact Evidence

- Exact implementation head
  `96a3e7364be610e8d39d8439298d1754281e86f5` passes package push run
  `33056399005`, PR `#111` Avorax CI `33057936885`, and PR packages
  `33057936960`. PR `#111` merges normally as
  `3e58dc15bf4cf9d11ffa71eea190cd02630bfa72` with exact parents
  `aaa0885ecf49a101764d3806c8a92e2f9288c136` and the implementation head.
- Merged-main Avorax CI `33059344281` passes all five jobs. Merged-main
  Desktop Packages `33059344276` passes package contracts, Windows MSI/EXE,
  Linux DEB/tar, both macOS DMGs, and consolidation. Its publish job is
  explicitly skipped; no release or prerelease is created.
- Consolidated branch, PR, and merged-main artifacts are respectively
  `9640316965` (`132,038,711` bytes, SHA-256
  `618f3df58f74949429a06fd334dbc2613c8dd37534f40239c120f2b52d89ca81`),
  `9640970990` (`132,034,629` bytes, SHA-256
  `cc1b8551b7bc25661f0736a51a6520ebf7771ff5fbd0de130ae6afd1f26cf4c2`),
  and `9641615032` (`132,263,957` bytes, SHA-256
  `ad33996687f71102c5acdb8b3f4ae923e815e45496de4f4f76aec284ac97e604`).
  GitHub binds all three to their exact workflow heads.
- Bounded non-extracting review of the branch and merged-main artifacts
  verifies eight safe root entries, six platform packages, seven checksum
  targets, and CycloneDX 1.6 with 569 unique components. The merged-main
  archive has `135,675,404` uncompressed bytes. No package is extracted or
  executed and the final main review is memory-only with zero retained temp
  files. The PR artifact is recorded from GitHub metadata and the successful
  hosted package job; it was not independently downloaded.
- Initial local artifact-review attempts with an overly narrow SBOM/checksum
  filename assumption or cleanup syntax error are uncredited and fail visibly.
  One exact `132,263,957`-byte temp ZIP left by the cleanup typo was found only
  under the Windows temp root and deleted by exact file path; a follow-up found
  zero matching residue. The final memory-only review passes.

## Guarded Destination Evidence

- Git-filter-aware preconditions prove the eleven existing destination files
  equal base `aaa0885` and the new report path is absent. The initial raw-byte
  precheck correctly stops on expected CRLF/LF differences and writes nothing.
- Guarded Git-blob synchronization from `aaa0885` to merge `3e58dc15` applies
  exact `12/12` paths: eleven modifications, one addition, zero deletions, and
  `6,897,688` bytes. Containment, parent/target reparse, object-type, base-blob,
  staged-blob, atomic replacement, rollback, and final raw-blob checks pass.
  One first invocation has a PowerShell collision-expression parse error before
  staging; the report remains absent and zero sync residue is confirmed before
  the corrected invocation. Independent comparison then passes `12/12`.
- Destination Source contracts pass `681/681`; focused static reference-search
  tests pass `8/8`; workspace formatting passes. The definitive destination
  verifier passes exact `280/280`, zero non-passing steps, from
  `2026-08-27T10:01:41.8866849Z` through
  `2026-08-27T10:13:39.3773608Z` in `717.5s`.
- Embedded and independently invoked Windows PowerShell 5.1 and PowerShell 7
  validators accept destination report SHA-256
  `d3e26d29be79899efdcae8b7982256dff93cfe78f238301a9f751065f4815e6b`.
  The three lock hashes, all 12 synchronized blobs, zero test-process/sync
  residue, and the read-only protected-vault invariant remain exact.

## Closure

Checkpoint 2251 is closed. Its implementation, test contracts, local and
definitive verification, exact-head hosted checks, normal integration,
merged-main checks, bounded artifact review, guarded zero-delete sync, and
destination reruns pass.

The complete antivirus-hardening goal remains active. Cancellation is still
cooperative, and this checkpoint does not claim installed-service ownership,
driver/kernel mediation, production detection accuracy, pre-execution
blocking, or Defender replacement. No release, publication, installation,
service/driver start, Defender change, live-malware action, or protected-vault
mutation occurred.
