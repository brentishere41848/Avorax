# Checkpoint 2236 - Bounded Process Behavior

## Objective

Turn the Native process-start API and behavior helper collection into an honest,
bounded, explainable boundary. Consume only telemetry the event actually owns,
fuse behavior with complete file evidence, prevent overflow/resource abuse and
false-positive inflation, and explicitly disable engines whose required
telemetry does not exist. Do not claim process blocking or pre-execution.

## Scripted Implementation

- `analyze_process_start` validates nonzero PID and NUL-free command telemetry
  before file I/O. It computes behavior evidence first and injects that evidence
  into the normal scan pipeline before `RiskFusion` shapes the final report.
- Security-tamper inspection retains at most 16 KiB across UTF-8-safe command
  head and tail slices. It uses exact executable context, bounded ASCII token
  boundaries, distinct indicator classes, saturating arithmetic, and a score cap
  of 75. Raw commands are not exposed in evidence.
- Exact script-host identity adds zero-weight context. One process command cannot
  create multiple independent strong reasons, so command evidence alone remains
  observation/review rather than probable-malware or automatic action.
- Because analysis is explicitly post-start and performs no mutation, high-risk
  actions now return `recommend_stop_and_quarantine`; the false `block` result is
  removed. Suspicious results remain `allow_and_monitor` recommendations.
- Ransomware scoring uses the shared high-write helper. Browser/persistence path
  classifiers avoid proportional lowercase allocations, credential and
  persistence scores use final saturating addition, and child-name comparison is
  allocation-free and exact.

## Custom Engine Inventory

| Engine | State | Responsibility or blocker |
|---|---|---|
| `native.behavior.ransomware_window` | Enabled at explicit API | Bounded post-write file-activity correlation; not pre-write blocking |
| `native.behavior.process_script_host` | Enabled at explicit API | Zero-weight exact script-host observation |
| `native.behavior.process_security_tamper` | Enabled at explicit API | Bounded post-start contextual command review; no process mutation |
| `native.behavior.browser_data_access` | Disabled | No trusted per-process browser-data path access telemetry |
| `native.behavior.infostealer_correlation` | Disabled | No correlated credential/wallet read, archive, and network telemetry |
| `native.behavior.persistence_correlation` | Disabled | No trusted autorun registry/file write plus parent-signature telemetry |
| `native.behavior.suspicious_child_lineage` | Disabled | Parent PID exists, but verified parent image identity does not |

## Scripted Coverage

Benign/adversarial Rust fixtures cover exact host names and lookalikes, quoted
terms under a benign executable, duplicate terms, direct and shell-hosted utility
commands, oversized multibyte input, omitted-middle diagnostics, overflow inputs,
invalid PID/NUL events, evidence-before-file-I/O, pre-fusion evidence, provider
inventory uniqueness/status/reasons, harmless known-bad recommendation semantics,
and absence of fake `block` action text.

The definitive verifier adds mandatory step `native-engine bounded process
behavior regressions`. The strict validator requires exactly 265 steps and five
new verified-scope clauses. Source contract 666 binds implementation, tests,
verifier/validator, engine inventory, documentation, and unchanged dependency/
lockfile scope.

No checkpoint-2236 passing result is claimed during scripting. No live malware,
candidate execution, Defender change, machine-wide install, service/driver
start, dependency, feature, lockfile, release, publication, or protected-vault
mutation is involved.

## Local Execution Evidence

- Focused Native process-behavior regressions pass `19/19`. Strict Native
  all-target/all-feature Clippy, complete Native `538/538` with 19 deliberately
  ignored child entrypoints plus compiler `6/6`, rustfmt, and both Windows
  PowerShell 5.1 and PowerShell 7 parser checks pass.
- Both locked Rust workspace modes pass with one serial test thread, including
  the repeated `--all-features` run with exit code zero. Flutter analyze reports
  no issues and the complete Flutter suite passes `838/838`.
- The repository dependency-free Python source-contract runner passes exact
  `666/666`; `git diff --check` reports no errors. Exact SHA-256 values remain
  `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`
  (root Cargo), `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`
  (Native Cargo), and
  `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`
  (Flutter).
- The protected vault remains read-only and exact: 16,072 files, zero
  directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending/temp/reparse entries. No test process
  remains.
- Visible uncredited attempts are retained honestly: initial rustfmt drift was
  formatted before the passing check; an outer-shell-expanded PS5 parser command
  was corrected; a transferred all-features session lost its process handle and
  was fully rerun; Flutter was first invoked from the repository root and found
  no `test` directory; `unittest` discovered zero pytest-style functions and
  optional `pytest` was absent, so the repository's dependency-free runner was
  used without installing anything. None is credited as product verification.

Definitive exact 265-step, independent adversarial report, hosted exact-head,
merge, guarded synchronization, and destination evidence remain pending.

## Definitive Local Evidence

- The no-skip/no-Defender verifier passes exact `265/265`, zero failed or
  skipped report steps, in `523.1s`. The new bounded process-behavior step passes
  in `0.3s`; embedded and independent Windows PowerShell 5.1 and PowerShell 7
  validators accept the same strict report.
- Report SHA-256 is
  `57f7c1cff6283eb424f92a95f511e695bb60242add571a0139b08ae3a68de162`.
  Options are exact: `skip_flutter=false`, `skip_rust=false`, and
  `include_defender_eicar=false`.
- Eight isolated report mutations covering Defender enablement, failed status,
  failed final step, missing process-behavior target, missing bounded-sample
  scope, missing honest-action scope, skipped Rust, and stale 264-step scope are
  rejected by both validator hosts, exact `16/16`.
- Three package source-contract symlink-positive fixtures remain explicitly
  skipped because Windows symlink creation requires optional privilege; their
  parent verifier step passes. The first adversarial harness execution completed
  its generated files but its caller lost the final output window, so it is
  uncredited; the complete repeated harness is the credited `16/16` result.

Exact implementation-head hosted CI/package evidence, normal PR merge, guarded
original-tree synchronization, and independent destination verification remain
pending. This checkpoint and the whole antivirus project remain active.

## Exact Implementation-Head Hosted Evidence

- PR `#88` binds implementation/evidence head
  `8ec7f67de41747a97173a9a6508bbdfb982cb0aa`. Avorax CI run
  `32904894596` passes all five jobs. Desktop Packages push run `32904862805`
  and PR run `32904894580` both pass package contracts, Windows x64 MSI/EXE,
  Linux x64 DEB/tar, macOS x64/arm64 DMGs, consolidation, checksums, and evidence
  upload.
- Publication jobs `97989631395` and `97991365780` are both skipped. No release
  or prerelease is created.
- Consolidated artifact `9584740958` is 131,785,747 bytes with SHA-256
  `d373594aa2916c262f44ebe2448d5f6b3df697ee297ff8c008f086a6eaf4e392`;
  artifact `9584941678` is 131,799,199 bytes with SHA-256
  `af27a6441d84be609fdb36ea2b6b65b296ad2934c73dad361863bc4e8d880cc7`.
  Bounded in-stream validation, without extraction or execution, passes exact
  eight root entries, six platform release files, seven matching checksum rows,
  and CycloneDX 1.6 lockfile SBOM evidence with 569 components for both.

Evidence-head hosted runs, normal PR merge, merged-main hosted evidence, guarded
original-tree synchronization, and independent destination verification remain
pending. This hosted result does not change the documented post-start API limits.

## Integration And Destination Closure

- Evidence commit `f24c7b58915dc54831cf9f097eb9a60c13c05e89` passes
  CI `32906638178` and Desktop Packages `32906638195`; publication job
  `97994982862` is skipped. Consolidated artifact `9585362967` is 131,793,867
  bytes with SHA-256 `4de44b4fce1b052cf4261a8639a7b9e3411a9567edd33e0b7a77e45f3c29be1c`
  and passes exact bounded non-extracting 8-root/6-release/7-checksum/CycloneDX
  1.6/569-component validation.
- PR `#88` merges normally as `b28dfd6b1ec8b7dd510d60128f2484c327b6b89a`
  with parents `5fc30c918ff832af7154034bc62dbbb2b09d6ce5` and
  `f24c7b58915dc54831cf9f097eb9a60c13c05e89`. Merged-main CI
  `32907875014` and Desktop Packages `32907874963` pass; publication
  `98000529939` is skipped. Artifact `9585995999` is 131,740,338 bytes with
  SHA-256 `f51af83c30cc5d05489d13d85146c6ada4436ff27c12103ac43a8cda675117a8`
  and passes the same in-stream validation. No release is created.
- Guarded synchronization validates checkpoint-2235 closure or merge-base
  preconditions, containment, reparse boundaries, and desired merge blobs before
  copying exactly 25 paths and 6,669,190 bytes. It deletes nothing and leaves no
  stage/temp residue. The first PS5.1 run hit an unavailable three-argument
  `.NET File.Move` overload before replacing any target; a dedicated checked
  cleanup removed only the isolated stage/temp state, and the corrected PS7 run
  passed. All 25 destination files match source bytes and merge Git blob IDs.
- Destination checks pass parser hosts, rustfmt, source contracts `666/666`,
  focused process behavior `19/19`, strict Native all-target/all-feature Clippy,
  Native `538/538` plus 19 deliberate child-fixture ignores and compiler `6/6`,
  Local `537/537`, Guard `248/248 + 249/249`, both locked workspace modes,
  Flutter analyze, and Flutter `838/838`.
- The destination no-skip/no-Defender verifier passes exactly `265/265` with
  zero failed/skipped from `2026-08-25T23:25:04.0740027Z` through
  `2026-08-25T23:33:14.9481622Z` in `490.8s`. The new target occurs once and
  passes in `0.3s`; embedded and independent PS5.1/PS7 validators pass. Eight
  isolated mutations per host reject `16/16`. Report SHA-256 is
  `1c4ca9976b7675c7f8c3d6e20368b7ad6c8f83c9f4c3bea1d0f66e27ce66af28`.
- Three package source-contract symlink-positive fixtures remain explicitly
  skipped inside their passing parent step because Windows symlink creation
  needs optional privilege; the definitive report itself has zero skipped steps.
  A destination `git status` probe found no `.git`, one draft confused file
  SHA-1 with Git blob IDs, and one PS7 parser wrapper omitted its path argument.
  Corrected checks passed; none of those drafts is credited.
- Locks remain exact, no test process or sync residue remains, and the protected
  vault is unchanged at 16,072 files, zero directories, 4,522,733 bytes, 5,357
  each `.avoraxq`/`.json`/`.auth`, one key, and zero pending/temp/reparse.

Checkpoint 2236 is closed. The complete antivirus project remains active.

## Limits

This public API is not currently connected to the installed app/service process
snapshot loop. It is post-start, advisory, and cannot terminate or quarantine a
process. Bounded head/tail evidence can miss middle arguments; alternate command
forms and telemetry races remain possible. Disabled providers must remain
disabled until their exact trusted telemetry and bounded correlation windows are
implemented and verified. Production calibration, installed E2E, signing,
cross-identity isolation, driver/kernel enforcement, and pre-execution blocking
remain external prerequisites.
