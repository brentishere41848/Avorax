# Checkpoint 2247: Provider Text Normalization Cancellation

## Status

Implementation-first scripting, local verification, exact-head hosted evidence,
normal PR integration, merged-main evidence, guarded synchronization, and
destination verification are complete. No checkpoint-2247 test has run during
this scripting phase; execution began only after that batch was frozen.
Checkpoint 2247 is closed, while the complete antivirus hardening goal remains active.
Source contract 677 and exact verifier step 276 are part of the passing evidence.

## Objective

Remove the remaining whole-sample cancellation gap in Native signature and rule
provider text preparation. Preserve exact lossy UTF-8 replacement, ASCII-only
case folding, matching behavior, explanations, conservative thresholds, pack
limits, and fail-visible verdict publication.

## Scripted Implementation

- `signatures/text.rs` prepares provider text in at-most-64-KiB input chunks.
  It invokes the exact job-bound callback before every chunk and after the final
  chunk. Arbitrary callback errors return `Err`; the partial `String` is dropped.
- A maximum three-byte pending prefix preserves valid UTF-8 code points split at
  a chunk boundary. The helper applies the same replacement-character grouping
  as `String::from_utf8_lossy` to malformed or truncated UTF-8 and folds only
  ASCII uppercase characters, matching the previous one-shot result.
- Signature DB, direct signature matcher, and ASCII signature wrappers use the
  shared helper. Rule DB and direct rule VM use it for sample text and the
  already platform-bounded display path before evaluating any rule condition.
- The existing one-prepared-sample-per-provider architecture remains. Ordinary
  files and bounded archive entries inherit the same callback through existing
  engine wiring, so cancellation or probe failure precedes evidence fusion and
  outer verdict publication.

## Scripted Evidence

- Benign ASCII, valid non-ASCII UTF-8, malformed bytes, truncated sequences, and
  valid/malformed sequences crossing the exact chunk boundary compare against
  the previous one-shot normalization result.
- Multi-chunk callback cancellation and arbitrary callback failures must remain
  visible. Signature ASCII wrapper, Signature DB, and Rule DB integration tests
  require failure before match/evidence return.
- Mandatory verifier step `native-engine provider text-normalization
  cancellation regressions` selects the dedicated benign regression prefix.
- Strict full-report validation requires exactly 276 steps, the new step, and
  exact verified/technical-scope statements. Source contract 677 pins every
  source, test, verifier, validator, documentation, and dependency boundary.

## Local Execution Evidence

- Dedicated normalization regressions pass `7/7`; all Native provider
  regressions pass `26/26`; adjacent signature tests pass `62/62` plus compiler
  `6/6`; rule `44/44`, ML `40/40`, and archive `71/71` filters pass.
- Complete Native Engine passes `600` active tests with `21` documented child
  fixtures ignored plus compiler `6/6`. Local Core passes `546/546`; Flutter
  analyze reports no issues and Flutter passes `847/847`; Source contracts pass
  `677/677`. Strict affected-crate Clippy, formatting, the locked workspace,
  and the locked release workspace build pass.
- An additional non-gating strict whole-workspace Clippy invocation reaches
  three existing `services/api` style lints (`items_after_test_module` twice and
  `enum_variant_names` once). No checkpoint-2247 file is implicated; affected
  Native and Local Core strict lint passes.
- The definitive verifier passed exact `276/276`, zero failed and zero skipped,
  from `2026-08-26T23:07:30.367868Z` through
  `2026-08-26T23:15:41.7081091Z` in `491.3s`. Report SHA-256 is
  `3fe607aac49c1d327eb1162b6352cc4be2d336077cbad73396f0948cc631dd7c`.
  Independent Windows PowerShell 5.1 and PowerShell 7 validation passes.
  Removing the mandatory step or the exact provider-chunk technical scope is
  rejected with exit code `1`.
- Dependency locks remain exact: root Cargo
  `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
  Native Cargo
  `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
  and Flutter
  `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
  Read-only vault inventory remains exactly 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each payload/metadata/auth, one metadata key, zero
  pending files, and zero reparse points.

## Hosted And Integration Evidence

- Exact evidence head `2df54084e904a8b849cf94f6c3cb1e9ddd2f8296`
  passes Desktop Packages push run `33023772283`, Avorax CI PR run
  `33023891024`, and Desktop Packages PR run `33023891013`. Every required job
  passes and publication is skipped.
- Untouched push artifact `9627948738` is 131,986,685 bytes with SHA-256
  `da049a47330b38a0eaa1c778ccb88d57107bac9db9160be61a6e24fafc8ead85`;
  untouched PR artifact `9627940274` is 132,037,526 bytes with SHA-256
  `e7d3f493377ca5544f7ed7c1349393b8b20737020f7cc6e58bba57aa3ff62a93`.
  Bounded validation without extraction or execution finds the exact eight root
  entries, six platform files, seven checksum targets, CycloneDX 1.6, and 569
  components in both artifacts.
- PR `#103` merges normally as
  `d51c82346b60826b369412d9572680eba8c0304d`, with exact parents
  `146b536e9064ffc3e318b81866665fd039622835` and
  `2df54084e904a8b849cf94f6c3cb1e9ddd2f8296`. Merged-main Avorax CI
  `33024847737` and Desktop Packages `33024847755` pass; publication is skipped.
  Main artifact `9628247565` is 132,043,593 bytes with SHA-256
  `b72597cf8c73452bdb25874c2a37177bb5d68b15be97788f55247f2725472495`
  and passes the same non-extracting 8/6/7/CycloneDX-1.6/569 validation.
- Guarded synchronization from base
  `146b536e9064ffc3e318b81866665fd039622835` to the exact merge passes audit,
  apply, and independent Git-attribute-aware comparison for all `18/18` paths,
  with zero deletes, mismatches, or staging residue.

## Destination Evidence

- In `C:\Users\Brent\Documents\Avorax-main`, Source contracts pass `677/677`,
  dedicated normalization regressions pass `7/7`, and workspace formatting
  passes.
- Definitive verification passes exact `276/276`, zero failed and zero skipped,
  from `2026-08-27T00:08:19.0100665Z` through
  `2026-08-27T00:17:08.6667314Z` in `529.6s`. Embedded and separately invoked
  Windows PowerShell 5.1 and PowerShell 7 validators pass. Report SHA-256 is
  `e215048203573a72dab0b8b6a64304a3af44231356861629cdc83e21f38a2782`.
- Root, Native, and Flutter dependency locks remain exact. The protected
  quarantine remains read-only and exact at 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each payload/metadata/auth, one metadata key, zero
  pending/temp files, and zero reparse points. No artifact was extracted or
  executed, no release was published, and no machine-wide component was
  installed.

Checkpoint 2247 is closed. Provider text cancellation remains cooperative and
bounded, the separate static-analyzer normalization remains technically limited,
and disabled correlation-dependent providers retain their blockers. The complete
antivirus hardening goal remains active.

## Safety

Tests use ordinary text and explicitly malformed benign byte arrays only. They
do not download, unpack, retain, or execute malware or candidate fixtures. They
use no live EICAR file and never modify Defender. The protected
`C:\ProgramData\Avorax\Quarantine` vault remains read-only. No service, driver,
installer, release, publication, or machine-wide component is changed.

## Limits And Honest Claims

Cancellation remains cooperative. One active at-most-64-KiB normalization
chunk, one at-most-64-KiB signature/rule search chunk, the bounded ML
contribution sort, an entered filesystem/system call, a separate static-analyzer
normalization, or Windows trust helper work can finish before the next callback.
The existing 64 MiB file sample and 1 MiB archive-entry sample remain.

This checkpoint does not claim constant memory, hard preemption, installed
cross-identity service ownership, kernel cancellation, production detection
accuracy, signed-driver enforcement, pre-execution blocking, or Defender
replacement. Reputation and correlation-dependent behavior providers remain
disabled with their documented blockers. The complete antivirus goal remains
active.

## Required Verification Sequence

1. Freeze the complete source/test/verifier/validator/contract/documentation
   batch before running any checkpoint-2247 test.
2. Run focused `native_provider_normalization_`, adjacent provider, Source 677,
   formatting, parser, and strict affected-component checks.
3. Run complete Native, Local Core, Flutter, locked workspace, release build,
   security, dependency, and clean-diff regressions.
4. Run the definitive no-skip/no-Defender verifier and require exact `276/276`.
   Validate independently with Windows PowerShell 5.1 and PowerShell 7 and prove
   missing-step/scope mutations are rejected.
5. Obtain exact-head hosted CI/package evidence with publication skipped, merge
   through a normal PR, verify merged main, guarded-sync with zero deletes, and
   repeat destination focused/full/definitive evidence before closure.

## Closure-Document Finalization Evidence

- Closure-document commit `d4ec776fed288b76538c63267a64d4b1eff3fe17`
  passes PR `#104` CI `33026575011` and merges normally as
  `01b0701422bd8f620be5df5ee9f56a0ea5d0754b`, with exact parents
  `d51c82346b60826b369412d9572680eba8c0304d` and
  `d4ec776fed288b76538c63267a64d4b1eff3fe17`. Merged-main CI
  `33027022675` passes all five jobs; docs-only path policy starts no package or
  publication workflow.
- Guarded synchronization changes exactly four documentation blobs, with zero
  additions/deletes/mismatches/residue. Final destination Source `677/677`,
  focused normalization `7/7`, and formatting checks pass.
- The first final definitive verifier is uncredited because its broad
  Authenticode filter exited `101` without a captured test name or diagnostic.
  The exact focused rerun passed 83 active tests with 21 documented child
  fixtures ignored. A complete clean rerun passed exact `276/276`, zero
  failed/skipped, from `2026-08-27T00:39:50.7509959Z` through
  `2026-08-27T00:48:19.24196Z` in `508.5s`. Embedded and independent PS5/PS7
  validators accept report SHA-256
  `ff23775d20ad62821d8fbc7f6bdeaf4e58c2f5b59ade7d01958b0669a32363be`.
- All synchronized blobs, dependency locks, and the read-only protected-vault
  invariant remain exact. Checkpoint 2247 is fully finalized; the complete
  antivirus hardening goal remains active.
