# Checkpoint 2246: Native Provider Cancellation And Pack Limits

## Status

Checkpoint 2246 is closed. The implementation-first chronology is preserved by
this historical statement: No checkpoint-2246 test has run during this scripting
phase. Focused, broad, definitive, hosted, integration, synchronization, and
destination checks have since passed. Source contract 676 and exact verifier
step 275 are part of the accepted evidence. The complete antivirus hardening
goal remains active.

## Objective

Reduce cancellation latency and repeated allocation inside the custom Native
signature, rule, and ML providers while placing exact aggregate ceilings around
local signature/rule sibling packs. Preserve existing detection semantics,
explanations, conservative thresholds, archive limits, error visibility, and the
detection-only Native mutation boundary.

## Scripted Implementation

- `signatures/search.rs` owns exact and masked matching over at-most-64-KiB
  candidate-position chunks. Empty patterns, unequal masks, checked range
  failures, cancellation, and arbitrary callback errors return `Err`.
- Byte-pattern, ASCII, UTF-16, EICAR, signature required-context, and rule term
  searches use that shared fallible path. Matching across a chunk boundary is
  preserved.
- `SignatureDb` and `RuleDb` each prepare lowercase file content once per
  provider invocation. Rule paths are likewise normalized once. Existing
  compatibility wrappers install an infallible callback and retain results.
- Signature evaluation checks before each signature and context, and pattern
  loops checkpoint within long searches. Rule evaluation checks each rule,
  condition, and long search. No partial match vector is returned on failure.
- Native ML scoring checks before every one of its at-most-128 weights and every
  contribution, around validation and before result publication. The existing
  development-only model metadata and auto-quarantine restrictions are unchanged.
- The engine binds these callbacks to the exact scan job for ordinary files.
  Bounded archive entries now use cancellation-aware static analysis plus the
  same signature/rule provider calls before any outer file verdict is returned.
- Signature and rule sibling discovery rejects more than 32 matching provider
  files, more than 256 inspected directory entries, or more than 16 MiB total
  pack bytes. Activation rejects more than 4,096 loaded signatures or 4,096
  loaded rules. Every accumulation uses checked arithmetic; the remaining
  aggregate byte budget is enforced again while each pack is read, so growth
  after directory inventory fails visibly. A constructor error cannot replace
  the active database.

## Scripted Evidence

- Benign exact/masked cross-chunk searches, callback cancellation/failure, and
  compatibility parity.
- Signature/rule/ML wrapper parity and arbitrary callback error propagation.
- Excess sibling-pack, inspected-directory-entry, aggregate metadata/read-byte,
  and aggregate loaded-item rejection in isolated temporary directories or
  in-memory structures.
- Engine source wiring for ordinary and archive-entry static/signature/rule/ML
  provider paths before verdict publication.
- Python Source contract 676 pins implementation, absence of obsolete provider
  calls, exact limits, verifier/validator wording, documentation, and dependency
  scope.
- `verify-small-threat-mvp.ps1` adds mandatory step `native-engine custom
  provider cancellation and pack-limit regressions` and reports the exact
  verified and technically limited boundaries.
- `validate-small-threat-mvp-report.ps1 -RequireFullSuite` requires exactly 275
  steps, the new step, and every checkpoint scope statement.

## Safety

Tests use ordinary benign bytes, the already decoded EICAR test marker, and
isolated temporary empty pack files. They never download, unpack, retain, or
execute malware. Candidate fixtures are never executed. The real
`C:\ProgramData\Avorax\Quarantine` vault is read-only and must remain at its exact
protected invariant. No Defender setting, service, driver, installer, release,
or machine-wide component is changed.

## Limits And Honest Claims

Cancellation remains cooperative, not hard preemption. One provider UTF-8 lossy
lowercase normalization, one at-most-64-KiB search chunk, the bounded at-most-128
ML contribution sort, an entered read/system call, or Windows trust helper work
can finish before the next checkpoint. Ordinary sampled input remains capped at
64 MiB and each sampled archive entry at 1 MiB. Aggregate pack ceilings limit
resource use but do not prove pack authenticity; authenticity remains the
responsibility of the existing signed update/activation and local configuration
boundaries.

This checkpoint does not claim installed cross-identity service ownership,
kernel cancellation, signed-driver enforcement, production detection accuracy,
pre-execution blocking, or Defender replacement. Reputation and behavior
providers that require trusted correlated telemetry remain disabled with their
documented blockers. The complete antivirus hardening goal remains active.

## Required Verification Sequence

1. Run focused `native_provider_` tests, Source contract 676, formatting, parser,
   and strict affected-component lint only after this scripting batch is frozen.
2. Run complete Native, Local Core, Flutter, locked workspace, security,
   dependency, and clean-diff regressions.
3. Run the definitive no-skip/no-Defender verifier and require exact `275/275`.
   Independently validate with Windows PowerShell 5.1 and PowerShell 7, then
   prove malformed reports missing the step or scope are rejected.
4. Obtain exact-head hosted CI/package evidence with publication skipped,
   merge through a normal PR, verify merged main, and perform guarded destination
   synchronization with zero deletes and canonical blob comparison.
5. Repeat destination focused/full/definitive evidence and recheck all lock hashes
   plus the protected-vault invariant before closing checkpoint 2246.

## Execution Log

- Formatting, `git diff --check`, and Windows PowerShell 5.1/PowerShell 7 parser
  checks passed after the scripting batch was frozen.
- The first focused `native_provider_` run compiled successfully and passed
  18/19 tests. Its only failure was the new engine source test comparing
  archive-helper markers, which live after the main scan return, against the
  earlier main-verdict position. Product code did not fail.
- A test-only repair split the assertion into main-scan-before-verdict and
  archive-helper-before-completion regions. The exact rerun passed `19/19`.
- The first Source run executed all 676 contracts and found 44 historical
  verifier-cardinality assertions still pinned to 274. A mechanical count-only
  repair moved those assertions to 275; the full rerun passed `676/676`.

## Local Verification Evidence

- Adjacent signature/compiler `62/62`, rule `43/43`, ML `17/17`, and archive
  `71/71` filters pass. Full Native passes library `593` and compiler `6/6` with
  21 documented child-fixture entrypoints ignored. Local Core is `546/546`.
- Flutter analyze reports no issues and Flutter passes `847/847`. Workspace
  rustfmt, strict Native and Local Core all-target/all-feature Clippy, locked
  workspace tests, and `cargo build --workspace --release --locked` pass.
- An additional strict workspace-wide Clippy probe is non-gating and fails only
  on three pre-existing `services/api` style lints: two
  `items_after_test_module` and one `enum_variant_names`. No checkpoint file is
  implicated; the ordinary locked workspace test and release build pass.
- Definitive verification passes exact `275/275`, zero failed/skipped, from
  `2026-08-26T21:35:34.3063496Z` through
  `2026-08-26T21:43:42.4436595Z` in `488.1s`. Rust and Flutter are not skipped;
  Defender integration remains opt-in and was off. Embedded and independently
  invoked PS5/PS7 validators pass. Both shells reject separate copies with the
  required provider step or verified scope removed.
- Canonical report:
  `.verification/checkpoint-2246-full-report.json`; SHA-256
  `5c38555423a46188172e828f1193e24d44dab8e4c3613308c11b6151365a44a8`.
- Lock hashes and the protected vault invariant remained exact at local
  verification. The integration and destination evidence below supersedes the
  historical pending state.

## Hosted And Integration Evidence

- Implementation commit `52a0995fafda2f8b2d467b1359924c61604f777b`
  passed exact-head Avorax CI `33017144188` and Desktop Packages push/PR runs
  `33017129545` and `33017144209`. All required jobs passed; publication was
  skipped. PR `#100` merged normally as
  `f3c2c9f331748d0e340abe6cd1e33a4e435769b9`, with exact parents
  `7d45726e346c3f25cceb079442869ae6916fb843` and
  `52a0995fafda2f8b2d467b1359924c61604f777b`.
- PR consolidated artifact `9625320449` is 132,074,772 bytes with SHA-256
  `8a25f5f192c4798c1f18d365f1e8d39ccfc76307a723392b3a6eb634e7a6f2fa`.
  Bounded validation without extraction or execution found the exact eight root
  entries, six platform files, seven checksum targets, CycloneDX 1.6, and 569
  components.
- Merged-main Avorax CI `33018138486` and Desktop Packages `33018138334`
  passed, with publication skipped. Main artifact `9625857946` is 132,001,624
  bytes with SHA-256
  `e5cdd5e6d36e6f933816f4c95132e467ad270ba830cd9458c5bc6afbdefdb828`
  and passes the same bounded non-extracting 8/6/7/CycloneDX-1.6/569 inventory.
- Guarded synchronization from base
  `7d45726e346c3f25cceb079442869ae6916fb843` to the exact merge passes audit,
  apply, and independent Git-attribute-aware canonical comparison for `21/21`
  paths, with zero deletes and no staging residue.

## Destination Evidence

- In `C:\Users\Brent\Documents\Avorax-main`, focused provider tests pass
  `19/19`, Source contracts pass `676/676`, and workspace formatting passes.
- Definitive verification passes exact `275/275`, with zero failed or skipped,
  from `2026-08-26T22:25:08.4194801Z` through
  `2026-08-26T22:33:43.7654199Z` in `515.3s`. Rust and Flutter are not skipped;
  Defender/EICAR integration remains opt-in and was off. Embedded and separately
  invoked PowerShell 5.1 and PowerShell 7 validators pass. Report SHA-256 is
  `12e27ad9e3f28058896ea03f66f1c91a6133a82b1827079869d937cd927ede65`.
- The root, Native, and Flutter dependency locks remain exact. The protected
  quarantine remains read-only and exact at 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each payload/metadata/auth, one metadata key, zero
  pending files, and zero reparse points. No package was extracted or executed,
  no release was published, and no machine-wide component was installed.

Checkpoint 2246 is closed. Cancellation and Windows trust remain cooperative
and bounded rather than hard-preemptive, correlation-dependent engines remain
disabled with blockers, and no service, driver, kernel, production-accuracy,
pre-execution, or Defender-replacement claim is added. The complete antivirus
hardening goal remains active.
