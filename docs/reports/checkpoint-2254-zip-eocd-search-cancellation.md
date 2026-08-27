# Checkpoint 2254: ZIP EOCD Search Cancellation

Date: 2026-08-27

Status: verified locally and at implementation head / integration pending

## Objective

Make the bounded ZIP end-of-central-directory (EOCD) lookup cooperatively
cancellable in both Native Engine consumers. Preserve valid commented-archive
behavior, the existing 65,557-byte search bound, parser limits, evidence
semantics, and fail-visible callback errors.

This checkpoint does not add an archive extractor, execute archive contents,
change verdict thresholds, or claim preemptive cancellation.

## Implementation

`core/zentor_native_engine/src/analyzers/archives/zip.rs` now:

- replaces the infallible EOCD finder with
  `find_end_of_central_directory_with_cancellation`;
- invokes the caller callback before the first candidate and before every next
  block of at most 4,096 backward candidate offsets;
- returns callback failures unchanged through `anyhow::Result`;
- propagates that result from both central-directory sample collection and
  static archive analysis, before central metadata, sample, or evidence work;
- retains the ZIP comment-length equality check and existing maximum search
  window; and
- updates test-only direct finder callers to supply an explicit never-cancel
  callback.

Three benign in-memory fixtures cover sample-path interruption, analysis-path
interruption, and preserved valid long-comment semantics. Fixtures contain
ordinary text only and are parsed in memory; they are never executed or
extracted.

## Verification Contract

The definitive verifier adds mandatory step 283:

`native-engine ZIP EOCD search cancellation regressions`

It runs the exact `zip_eocd_cancellation_` Rust filter. The independent report
validator requires exact cardinality 283, the dedicated step, exact verified
scope for both consumers and fail-visible propagation, plus the cooperative
4,096-candidate and 65,557-byte-window technical-limit statements.

Source contract 684 pins the production helper, both callers, callback
interval, absence of the old infallible finder, all three runtime regressions,
verifier/validator requirements, documentation coverage, and dependency
statement.

## Control Matrix

| Control | Responsibility | Scripted state | Evidence required |
|---|---|---|---|
| Native ZIP EOCD finder | Locate a structurally valid trailing EOCD inside the bounded ZIP comment window | Callback-aware; no clean fallback on callback error | Three focused Rust regressions |
| Central-directory sample path | Collect bounded archive-entry content for nested detection without extraction | Uses the shared fallible finder before metadata/sample work | Sample-path interruption and preserved-content assertions |
| Static ZIP analysis path | Produce bounded archive metadata and heuristics | Uses the shared fallible finder before metadata/evidence work | Analysis-path interruption assertion |
| Compatibility behavior | Accept valid archives with comments and retain existing search/parse limits | No format or threshold change | Long-comment success fixture and full Native regression |
| Definitive evidence | Prevent stale reports from claiming this boundary | Exact step 283 and exact scope/cardinality validation scripted | Exact `283/283` report plus adversarial report rejection |
| Installed service, driver, and Defender replacement | Require separate installed/kernel evidence | Unchanged; partial, blocked, technically limited, or unclaimed | Not supplied by this checkpoint |

## Safety And Residual Risk

Cancellation is cooperative. Up to 4,096 candidate offsets can be examined
after one successful callback before the next callback. The 65,557-byte search
window bounds work but is not a wall-clock deadline. A process termination,
entered OS operation, or other analyzer interval remains governed by its own
documented boundary.

Malformed inputs still receive bounded parsing and fail-safe limit treatment;
an arbitrary callback error is not converted into `None`, local-header
fallback, a clean sample result, partial archive evidence, or a verdict. This
does not prove installed service ownership, cross-identity IPC, production
detection calibration, signed-driver mediation, pre-execution blocking, or
Defender replacement.

The change adds no dependency, package source, license obligation, network
content, or lockfile change. It does not access the protected quarantine vault,
alter Defender, install machine-wide components, start a service/driver,
publish a package, or create a release.

## Scripting Boundary

No checkpoint-2254 test has run during this scripting phase. The complete code,
benign adversarial tests, verifier step 283, exact validator scope, Source
contract 684, and audit documents were scripted first as requested.

Execution must proceed in this order: parser/source/focused checks; adjacent and
full local regression; strict lint/build/Flutter/Dart checks; from-start exact
`283/283` definitive verification; independent PS5/PS7 acceptance and hostile
report mutations; exact-head hosted CI/packages with publication skipped;
normal PR integration; green merged-main evidence; guarded zero-delete
destination synchronization; and focused plus definitive destination reruns.

Until all required evidence passes, every new row remains **Scripted /
unverified** and checkpoint 2254 remains open. The complete antivirus-hardening
goal remains active after this checkpoint.

## Focused Local Evidence

After the complete scripting boundary, the exact EOCD filter passes `3/3` on
both initial and corrected reruns. The complete ZIP module passes `45/45`;
adjacent static-archive, archive-collection, and ZIP entry-name cancellation
filters each pass `4/4`. Source contracts pass exact `684/684`, PS5 and PS7 each
parse verifier and validator `2/2`, and `git diff --check` passes.

The first formatting check reported one layout-only change. `cargo fmt` applied
it and the exact formatting check now passes. The first two parser invocations
were invalid because the outer shell expanded `$file` before the child hosts;
they are uncredited. Corrected literal-script invocations pass under both hosts.
An explicit custom-contract-only run passed `673`; the required default runner
then included its 11 hash-intel contracts and passed exact `684/684`.

The first four matrix rows are now **Verified locally (focused)**. Definitive
step 283 remains **Scripted / unverified** pending broad regression and exact
`283/283`; hosted, integration, guarded-sync, and destination evidence remain
open. Locks and protected-vault evidence are audited with the broad batch.

## Broad Local Evidence

Both full locked workspace commands pass from the repository root: the standard
suite and `--all-features` suite each exit `0`. Native passes `635/635` with 21
documented benign child-process fixtures ignored, its signature compiler passes
`6/6`, Local Core passes `546/546`, Platform Security passes `9/9`, and updater
passes `203/203`. The separate Flutter analyzer is clean, Flutter passes
`847/847`, and the Dart protocol suite passes `14/14`.

The standalone Native locked/offline check, full locked release workspace
build, and strict `-D warnings` Native/Local/Guard Clippy runs all exit `0`.
Root Cargo, Native Cargo, and Flutter lock SHA-256 values remain respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.

A read-only audit found zero Avorax/Zentor processes and reconfirmed the
protected vault at exactly 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending/temp/reparse entries. No vault item was modified. The local broad
implementation is verified; definitive `283/283`, hostile report mutations,
exact-head hosted evidence, integration, guarded synchronization, and
destination reruns remain open.

## Definitive Local Evidence

The from-start Windows PowerShell verifier passes exact `283/283`, with zero
failed or skipped steps, in `837.4s` from
`2026-08-27T18:24:36.8209444Z` through
`2026-08-27T18:38:34.2663802Z`. The 203,497-byte schema-v2 report is
`.workflow/ultracode/avorax-hardening/results/checkpoint-2254-small-threat-mvp-verification-report.json`
with SHA-256
`cf38010ecb1c7d6d016d09b9cfe338b0604b8183eb2898b06e578d96e0c59e74`.
It records `failure_kind=null`, 283 passed-step `error=null` values, exactly one
checkpoint EOCD step, the expected first step, and terminal `Dependency evidence
gate`. Flutter and Rust were not skipped; the Defender/EICAR host probe was not
requested.

The verifier's built-in PS5/PS7 validation and separate independent PS5/PS7
full-suite validation accept the report. PS5 rejects a 282-step copy missing the
new EOCD step; PS7 rejects a separate 283-step copy missing the exact new
verified scope. Both exact regular-file copies were removed, and zero
checkpoint-2254 temporary entries remain.

Post-verifier read-only checks reconfirm all three lock hashes, zero product
processes, and the protected vault at exactly 16,072 files, zero directories,
4,522,733 bytes, 5,357 each payload/metadata/auth, one metadata key, and zero
pending/temp/reparse entries. Checkpoint 2254 is **verified locally**; hosted,
integration, guarded-sync, and destination closure remain separate gates.

## Hosted Implementation-Head Evidence

Exact implementation commit `216542ca6bcd22f013e089b45a0756fc40aed22f`
passes PR `#117` Avorax CI run `33103301314`. Branding/copy,
security/protection/performance, Flutter/protocol, Rust Local Core/Guard/update/
API, and Unix quarantine-permission jobs all succeed. PR Desktop Packages run
`33103301308` and push run `33103285518` pass package contracts, Windows x64
MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, and consolidation; publication
is explicitly skipped and no release is created.

GitHub reports consolidated push artifact `9660015011`,
`avorax-desktop-release-0.1.15`, as 132,076,431 bytes with digest
`sha256:e08a36fcc3bf12462c2f1747f155445101b39473ed8364753f0a789a933b5089`.
The independently downloaded untouched ZIP matches both values. A bounded,
non-extracting review verifies exactly eight safe root entries, six platform
packages, seven matching checksum targets, and one CycloneDX 1.6 lockfile SBOM
with 569 components and 569 unique references. It finds zero unsafe, duplicate,
encrypted, or link entries. No artifact was extracted, installed, or executed;
the exact temporary ZIP and its empty owned directory were removed.

This closes implementation-head evidence only. Evidence-head CI/packages,
normal PR integration, merged-main evidence, guarded destination synchronization,
and destination verification remain required. The complete antivirus-hardening
goal remains active.
