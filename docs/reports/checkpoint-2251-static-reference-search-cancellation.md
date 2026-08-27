# Checkpoint 2251 - Static Reference-Search Cancellation

Status: **Verified locally / hosted integration pending**

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
