# Checkpoint 2258 - File Discovery Work And Time Bounds

Status: **Closed through hosted integration and synchronized destination verification**

## Scope

Checkpoint 2257 bounded retained file count, encoded path payload, and priority
classification cancellation. It did not bound directory entries, filtered
ordinary files, enumeration errors, or other iterator work that is not retained
as a scan path. It also did not enforce a discovery-specific monotonic deadline,
and Quick/Custom scan inspection had no total elapsed-time ceiling.

Checkpoint 2258 adds conservative application-level work and elapsed budgets to
Quick, Full, and Custom scans. A reached or overflowed limit is an incomplete
scan with a bounded error. It is never converted to Clean or ThreatsFound-only
success.

## Implemented Contracts

- Quick discovery allows at most 100,000 work items and 600 seconds.
- Full and Custom discovery allow at most 1,000,000 work items and 3,600 seconds.
- One work item gates each explicit root-inspection attempt and each `WalkDir`
  iterator advance. This includes the root yielded by `WalkDir`, directory and
  file entries, non-candidates, non-regular entries, errors, and the final
  exhaustion probe when budget remains.
- Work accounting uses checked addition. Overflow marks the work limit, adds a
  bounded incomplete-discovery error, and stops before another root inspection
  or iterator advance.
- A monotonic `Instant` starts before the first root. Deadline checks share the
  existing cooperative checkpoints before each root, before every at-most-128
  iterator entries, after each root, before every at-most-128 priority bucket,
  and after completed priority classification.
- Cancellation is evaluated before the deadline at each shared checkpoint,
  including before and after retained target work and after successful zero-file
  Native Engine initialization. If both are observable, the report remains
  `Cancelled`; cancellation callback errors still abort visibly.
- Priority deadline exit retains every discovered path, just as cancellation
  does, so no ownership loss can hide retained work.
- Quick total scan elapsed time is capped at 1,800 seconds. Full and Custom are
  capped at 10,800 seconds. All clocks begin before discovery. A total-time
  exit counts every retained current/remaining file as skipped and reports the
  exact scan mode without claiming clean coverage. Incomplete progress remains
  indeterminate instead of being published as 100 percent.
- Time is checked before each retained file and after every completed or failed
  target inspection, including the final retained file. A zero-file scan also
  checks after Native Engine initialization. Native Engine unavailability owns
  its skipped-file count and does not enter the inspection loop, preventing a
  simultaneous time/cancel observation from counting the same files twice.
- Native Engine unavailability skips each retained file exactly once, bypasses
  target inspection, and leaves final progress indeterminate instead of
  publishing a misleading 100 percent.
- When retained targets total zero bytes, running progress uses the bounded
  retained-file count rather than publishing 100 percent before inspection. A
  genuinely zero-file running scan remains indeterminate until terminal status.
- Local Core treats file-count, path-byte, work-item, and discovery-time exits
  uniformly as incomplete discovery.

## Test And Evidence Scripting

Six benign Rust regressions are scripted under the `resource_budget_` filter:

1. non-candidate files consume discovery work and the limit is fail-visible;
2. work-counter overflow fails visibly;
3. a zero monotonic deadline stops before root filesystem I/O;
4. cancellation takes precedence over an already expired deadline;
5. priority deadline exit retains all discovered paths; and
6. inclusive total elapsed limits apply to Quick, Full, and Custom.

Definitive verifier step 287 is `local-core scan discovery work and
elapsed-budget regressions`. The strict report validator requires exact
`287/287`, the new step, six verified-scope statements, and four technical-limit
statements. Source contract 688 pins implementation order, tests, verifier,
validator, audit documents, dependency honesty, and the scripting boundary.

No checkpoint-2258 test ran during the scripting phase. Execution starts only
after implementation, test, verifier, validator, source-contract, and document
scripting are complete.

## Verification Plan

Focused checks will parse verifier and validator under Windows PowerShell 5.1
and PowerShell 7, run formatting/diff checks, run Source contracts, execute the
new `resource_budget_` regressions, overlapping discovery/full-scan/cancellation
filters, complete Local Core, and strict Local Core Clippy. Broad evidence will
then run locked standard and all-feature Rust workspaces, release all-feature
build, Flutter/Dart analysis and tests, the exact no-skip/no-Defender definitive
verifier, independent dual-host validation, structured adversarial report
mutations, safety gates, lock review, hosted CI/packages when path filters apply,
normal PR/merge, and guarded destination synchronization.

Focused, broad, and definitive local outcomes are recorded below. Hosted,
integration, guarded-sync, and destination evidence remain pending until those
commands actually run.

## Focused Local Evidence

After the complete scripting boundary, Windows PowerShell 5.1 and PowerShell 7
each parsed the verifier and validator `2/2`. Source contracts pass exact
`688/688`, formatting and diff checks pass, and all three lock hashes remain
exact.

The new `resource_budget_` filter passes `6/6`. Overlapping discovery,
file-walker, Full Scan, and scan-cancellation filters pass `15/15`, `20/20`,
`3/3`, and `8/8`. Full Local Core passes `562/562`, and strict all-target,
all-feature Local Core Clippy passes with warnings denied.

## Broad Local Evidence

Standard and all-feature locked Rust workspace suites pass. In both variants,
Native Engine reports 638 passed and 21 intentionally ignored isolated child
fixtures; Local Core reports `562/562`. The locked all-feature release workspace
build passes.

Flutter analyzes cleanly and passes `847/847`. Zentor and Avorax Dart protocol
packages analyze cleanly and pass `14/14` and `6/6`. No dependency or lockfile
change was introduced. Definitive and hostile report validation are recorded
below. Hosted exact-head evidence, normal integration, guarded destination sync,
and destination reruns remain required.

## Superseded Definitive Local Evidence

The pre-final-diff no-skip, no-Defender-host-integration verifier passed exact
`287/287` with
zero failed or non-null-error steps in `712.7s`. Its 209,030-byte canonical
report has SHA-256
`732ddae0269b7d1987d2b157fcd449ef092c684058a0d7c7c3ad89e333784c51`.
The new work/time-budget step passes, and the report keeps Defender/EICAR host
integration false.

Independent `-RequireFullSuite` validation accepts that report under Windows
PowerShell 5.1 and PowerShell 7. Both hosts reject all three structured
adversarial copies with exit code 1: 286 steps, missing checkpoint verified
scope, and missing checkpoint technical-limit scope. The exact owned mutation
files were removed and residue is zero.

Final review subsequently added post-target and zero-file elapsed checkpoints
plus engine-unavailable skip-count isolation. This report no longer represents
the final source and is retained only as superseded evidence. Final-source
focused, broad Rust, definitive, hosted, integration, guarded-sync, and
destination evidence remain required.

## Final-Source Repair Evidence

After the final diff repair, formatting and Source `688/688` pass. The new
resource filter passes `6/6`, complete Local Core passes `562/562`, and strict
all-target/all-feature Local Core Clippy passes. Both standard and all-feature
locked Rust workspace suites pass with Native Engine 638 passed / 21
intentionally ignored isolated child fixtures and Local Core `562/562`; the
locked all-feature release workspace build passes. The unchanged Flutter/Dart
source retains the earlier clean analyzer and `847/847`, `14/14`, and `6/6`
evidence.

## Superseded Final-Source Definitive Local Evidence

The final-source no-skip, no-Defender-host-integration verifier passes exact
`287/287` with zero failed or non-null-error steps in `633.1s`. The canonical
209,024-byte report has SHA-256
`7d26d4ae9327a4b186462dbe894222b65702975fb8334ea7e5465ce37cd595bd`.
Its schema is 2, status is `passed`, all 287 steps pass, and optional
Defender/EICAR host integration is false.

Independent `-RequireFullSuite` validation accepts the final report under
Windows PowerShell 5.1 and PowerShell 7. Both hosts reject all three final-source
structured adversarial copies with exit code 1: 286 steps, missing checkpoint
verified scope, and missing checkpoint technical-limit scope. The exact owned
mutation files were removed and residue is zero.

Late final review subsequently added cancellation-first post-target and zero-file
checkpoints and made EngineUnavailable completion progress indeterminate. This
report no longer represents the final source and is retained only as superseded
evidence.

## Late Final-Diff Repair Scripting

The complete late repair batch includes implementation, the existing benign
resource-budget regression, verifier and validator scope, Source contract, and
all checkpoint/audit documents. No test was run between identifying this edge
and completing the batch.

The first post-scripting focused command failed during compilation before test
execution because the new zero-file cancellation diagnostic passed `&str` to a
`String`-accepting bounded error helper. The explicit owned conversion is now
scripted. That failed attempt is uncredited; all evidence must come from the
repaired source.

## Superseded Final Definitive Local Evidence

On the repaired source, PS5/PS7 parser checks pass `2/2` each, Source contracts
pass `688/688`, the resource filter passes `6/6`, complete Local Core passes
`562/562`, and strict all-target/all-feature Clippy passes. Both locked standard
and all-feature workspaces pass with Native Engine 638 passed / 21 intentionally
ignored isolated child fixtures and Local Core `562/562`; the locked all-feature
release workspace build passes. Unchanged Flutter/Dart source retains the clean
analyzer and `847/847`, `14/14`, and `6/6` broad evidence and is exercised again
by the definitive verifier's targeted UI/protocol tests and analyzer.

The final no-skip, no-Defender-host-integration verifier passes exact `287/287`
with zero failed or non-null step errors in `638.5s`. The canonical 209,286-byte
schema-2 report has SHA-256
`401d4d4cb50dc7a61750ae26b7de529df3f2033063d3915649c4717aa6c78208`;
status is `passed`, all 287 steps pass, `skip_flutter=false`, `skip_rust=false`,
and optional Defender/EICAR host integration is false.

Independent `-RequireFullSuite` validation accepts the final report under
Windows PowerShell 5.1 and PowerShell 7. Both hosts reject all three final
structured adversarial copies with exit code 1: 286 steps, missing checkpoint
verified scope, and missing checkpoint technical-limit scope. The exact owned
mutation files were removed and residue is zero.

Final progress review then found that the shared ETA calculation could publish
100 percent before inspecting retained zero-byte files. This report is retained
only as superseded evidence.

## Zero-Byte Progress Repair Scripting

The shared progress calculation now falls back to bounded retained-file progress
when total estimated bytes are zero, while a running zero-file scan remains
indeterminate. The existing `resource_budget_` test exercises zero, partial, and
zero-file states, and verifier/validator scope, Source contract, matrix, threat,
blocker, dependency, testing, status, and run evidence are scripted. No test ran
between identifying this edge and completing the full batch. Final-source local,
hosted, integration, guarded-sync, and destination evidence remain open.

## Final-Source Definitive Local Evidence

After the zero-byte progress repair, formatting, PS5/PS7 parser checks, Source
`688/688`, resource-budget `6/6`, complete Local Core `562/562`, strict
all-target/all-feature Clippy, both locked workspace variants, and the locked
all-feature release workspace build pass. Native Engine reports 638 passed with
21 intentionally ignored isolated child fixtures in both workspace variants.

The final no-skip, no-Defender-host-integration verifier passes exact `287/287`
with zero failed or non-null-error steps in `634.4s`. The canonical 209,503-byte
schema-2 report has SHA-256
`078a4edc9a25aed4ab572936c0d34629152af0f4c0ee633e6e5a7a2c2177cad0`;
status is `passed`, `skip_flutter=false`, `skip_rust=false`, and optional
Defender/EICAR host integration is false.

Independent `-RequireFullSuite` validation accepts the final report under
Windows PowerShell 5.1 and PowerShell 7. Both hosts reject all three final
structured adversarial copies with exit code 1: 286 steps, missing checkpoint
verified scope, and missing checkpoint technical-limit scope. The exact owned
mutation files were removed and residue is zero. Hosted exact-head, integration,
guarded-sync, and destination evidence remain open.

## Hosted Implementation-Head Evidence

Exact implementation commit `709e8a9d56f89dd13b8e296334b187ff2a99d6f2`
passes PR `#125` Avorax CI run `33149543048`, PR Desktop Packages run
`33149543030`, and push Desktop Packages run `33149509580`. All five CI jobs,
both package-contract jobs, all eight platform build jobs, both consolidation
jobs, Windows administrative MSI extraction without installation, and checksum/
SBOM generation pass. Both prerelease-publication jobs are intentionally skipped.

The untouched push consolidated artifact `9677471939` is 132,106,765 bytes with
SHA-256 `ee1a1f997370d837a52622aa442e3b4f2d09f33ee6a04a3fa8a067f0767c2b51`.
The untouched PR artifact `9677431721` is 132,150,306 bytes with SHA-256
`94624412693ce298859e59f14c8977ec159711740bb693eaf3a935d2ee5a3c7f`.
Both local downloads match GitHub artifact metadata exactly.

Bounded, non-extracting in-stream review of each artifact passes exactly eight
safe root entries, six packages, seven matching checksum targets, CycloneDX
1.6, and 569 non-empty unique component references, with zero duplicate, unsafe,
encrypted, directory, or link entries. No package was extracted, installed, or
executed. The exact owned review files and script were removed with zero residue.
Evidence-head hosted checks, normal PR merge, merged-main evidence, guarded
destination synchronization, and destination verification are recorded below.

## Integration And Destination Closure

Exact evidence commit `1523810728b0a4b5e67765e31f7d6d30473afeec`
passes Avorax CI `33150862275` and PR Desktop Packages `33150862448`; the
publication job is intentionally skipped. Consolidated artifact `9677952419`
is 132,149,066 bytes with SHA-256
`76b4972b196c916cfb9eef9db7dd10e141d0e377b745da3c713783efea4c58b4`.
Its bounded, non-extracting review passes exact 8-root/6-package/7-checksum/
CycloneDX-1.6/569-unique-ref inventory with zero unsafe or special entries and
zero residue.

PR `#125` merges normally as
`73920a978cfa15e803e29b40d37a9964e91ee0be`. Merged-main CI `33151851259`
and Desktop Packages `33151851251` pass all jobs; publication remains skipped.
The untouched merged-main artifact `9678412188` is 132,179,061 bytes with
SHA-256 `d10e677c23360fdfdaf4db99511f823d4c325fb2d89412a7f6ef65f732eb7450`.
Bounded in-stream review passes exact 8/6/7 inventory, CycloneDX 1.6 with 569
unique non-empty component references, 136,138,120 declared uncompressed bytes,
and zero unsafe, duplicate, encrypted, directory, link, extraction, execution,
installation, or owned residue.

Read-only destination preflight verifies all old-base/absence conditions.
Guarded same-directory staging, backup, and atomic activation synchronize exact
`14/14` paths: 13 modified, one added, zero deleted, 7,588,496 staged bytes,
no rollback, exact merged-blob equality, and zero staging/backup residue.

The synchronized destination passes PS5/PS7 parser `2/2`, Source `688/688`,
formatting, resource-budget `6/6`, complete Local Core `562/562`, and strict
all-target/all-feature Local Core Clippy. Its no-skip/no-Defender definitive
verifier passes exact `287/287` with zero failed or non-null-error steps in
`698.5s`. Independent PS5 and PS7 validators accept the 200,845-byte schema-2
report with SHA-256
`70ff765a95fd881aafd11255d2a92cb22bff9f447efecdc222a777fa93cdb379`.

Root, Native, and Flutter lock SHA-256 values remain exact at
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
No Avorax/Zentor process remains. The read-only protected-vault invariant is
exactly 16,072 files, zero directories, 4,522,733 bytes, 5,357 each payload/
metadata/auth file, one metadata key, and zero unknown, pending, temporary, or
reparse entry. `.verification` remains untracked and untouched. No artifact was
installed, released, or published. Checkpoint 2258 is closed; the complete
antivirus-hardening goal and all limits below remain active.

## Technical Limits

- Work items are an application-level work proxy. They do not equal exact
  filesystem I/O bytes, syscalls, kernel work, storage latency, CPU, or RAM.
- Discovery and elapsed budgets are cooperative. One operating-system root
  metadata call or directory-iterator advance plus one at-most-128-entry or
  path-classification chunk can overrun before the next checkpoint.
- User mode cannot interrupt a kernel or filesystem call that stalls
  indefinitely. No installed-service watchdog, signed driver, kernel mediation,
  hard realtime, or pre-execution blocking is claimed.
- Encoded path payload still excludes `Vec`, `PathBuf`, and allocator overhead;
  priority classification transiently owns the source vector and buckets.
- Skipped/undiscovered entries are not counted exactly because enumerating them
  would defeat the bound. They are explicitly not reported clean.

## Safety And Dependencies

The checkpoint adds no dependency or lockfile change. It uses `std::time` and
existing `walkdir`, `anyhow`, and Local Core scan/report code. Fixtures contain
ordinary benign text only and are never executed. No malware, Defender setting,
machine-wide install, service/driver start, release, publication, or quarantine
mutation is part of the checkpoint. `.verification` and
`C:\ProgramData\Avorax\Quarantine` remain outside all writes.

The complete antivirus-hardening goal remains active after this checkpoint.
