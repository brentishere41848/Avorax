# Checkpoint 2235 - Bounded Risk Fusion

## Objective

Harden the two central score and verdict aggregation paths against adversarial
weights, unbounded display evidence, invalid UTF-8 truncation, omitted decisive
evidence, and incomplete engine provenance. Preserve conservative detection
thresholds and keep diagnostics fail-visible without claiming production
false-positive calibration or pre-execution blocking.

## Scripted Implementation

- Native risk fusion accumulates signed weights in a saturating `i64`, then
  clamps the result to the public 0..100 score. Extreme `i32` inputs can no
  longer panic in debug builds or wrap in release builds.
- Local Core accumulates only clamped positive contributions directly into a
  saturating `u8`. Only positive reasons count toward high-quality evidence and
  independent-source thresholds, so negative diagnostics cannot elevate a
  file to probable-malware or automatic-quarantine eligibility.
- Native report evidence is stable-sorted by descending absolute decision
  weight before the existing 32-item report limit. A decisive signature or
  trust item arriving after many weak diagnostics remains visible; equal
  weights retain input order.
- Native evidence identifiers, titles, and details are bounded to 256, 256,
  and 1,024 UTF-8 bytes. User-visible explanations are bounded to 2,048 bytes.
  Ellipsis truncation backs up to a valid character boundary and includes its
  suffix inside the bound.
- Synthetic known-good or allowlist evidence is added before engine provenance
  is collected, so `TrustStore` is reported exactly once when it participates.
  Verdict/category decisions still use the complete pre-report evidence set.

## Scripted Benign And Adversarial Coverage

- Native regressions cover multiple `i32::MAX`/`i32::MIN` weights, multibyte
  identifiers/titles/details crossing each byte boundary, explanation bounds,
  decisive evidence placed after 32 diagnostics, and TrustStore provenance.
- Local Core regression covers extreme positive and negative weights, score
  saturation, conservative verdict/action behavior, and rejection of negative
  diagnostic quality/source inflation.
- The definitive verifier adds mandatory step `local-core bounded risk fusion
  regressions`; the strict report validator requires exactly 264 steps and the
  four new verified-scope clauses.
- Source contract 665 binds implementation, tests, verifier, validator, exact
  cardinality, documentation, and unchanged dependency/lockfile scope.

No checkpoint-2235 passing result is claimed during scripting. No candidate
content is opened or executed by these pure fixtures. No live malware, Defender
change, machine-wide install, service/driver start, release, publication,
dependency, feature, or lockfile change is involved.

## Verification State

Implementation, benign/adversarial tests, verifier/validator updates, source
contract, and documentation are scripted. Focused checks, broad local suites,
the definitive exact 264-step report, malformed-report rejection, exact-head
hosted CI/packages, normal PR merge, guarded synchronization, and independent
destination verification remain pending.

## Limits

Risk scores remain explainable weighted policy, not a statistical probability.
This checkpoint does not establish production sensitivity, specificity, or
false-positive rates and does not replace signed definitions, behavioral
telemetry, analyst review, or installed end-to-end testing. Absolute-weight
ordering is a reporting policy only; all complete evidence still participates
in verdict and category calculation. The 32-item report and 2,048-byte
explanation intentionally omit lower-magnitude detail and disclose that count.
No installed service, kernel, driver, signing, or pre-execution capability is
added or claimed.

## Local Execution Evidence

Focused Native risk fusion passes `10/10`; focused Local bounded fusion passes
`1/1`; source contracts pass `665/665`; rustfmt and both PowerShell parser hosts
pass. Two attempted pytest invocations stopped before collection because the
available Python hosts intentionally have no pytest; they are visible and
uncredited. The repository's dependency-free source-contract runner is the
credited path.

Broad Native passes `520` with 19 intentional isolated child-fixture ignores
plus signature compiler `6/6`; Local passes `537/537`; Guard passes `248/248`
and all-features `249/249`; Flutter analyze and `838/838` pass. Both complete
locked workspace variants pass. Strict all-target/all-feature Clippy passes for
the changed Native and Local crates. An additional workspace-wide strict
Clippy attempt is uncredited because existing API code triggers
`enum_variant_names` and `items_after_test_module`; no checkpoint-2235 file is
in those diagnostics.

Root, Native, and Flutter lock hashes remain exactly
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
The protected vault remains exact at 16,072 files, zero directories, 4,522,733
bytes, 5,357 each payload/JSON/auth, one metadata key, and zero pending/reparse.
Definitive, hosted, integration, synchronization, and destination evidence
remain pending.

## Definitive Local Evidence

The no-skip/no-Defender verifier passes exactly `264/264` with zero failed or
skipped steps from `2026-08-25T19:38:33.8452358Z` through
`2026-08-25T19:46:57.3735345Z` in `503.5s`. The Native and Local risk-fusion
targets each occur exactly once. Embedded and independent strict validation
passes under both Windows PowerShell 5.1 and PowerShell 7.

Eight isolated report mutations per host covering stale 263-step cardinality,
missing Local target, missing overflow scope, missing positive-only scope,
Defender opt-in, Rust skip, failed report status, and failed step are rejected
`16/16`. Report SHA-256 is
`3c28abf05ba1b004ff0a16448690b8245baad0fd658ee0893bf052f3cdc719ed`.
The first verifier invocation supplied a nonexistent conventional PowerShell 7
path and stopped before step one or report creation; it is visible and
uncredited. The checked bundled runtime path completed the credited run.

No test process remains. Locks and the protected-vault invariant remain exact.
Hosted exact-head, normal merge, guarded synchronization, and destination
verification remain pending.
