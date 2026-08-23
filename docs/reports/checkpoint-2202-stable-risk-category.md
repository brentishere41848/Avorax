# Checkpoint 2202: Stable Risk Category Inference

## Objective

Make Native Engine category explanations deterministic when positive evidence
details contain arbitrary file or archive paths, without weakening verdicts or
discarding useful evidence.

## Triggering Evidence

PR `#53` and its evidence head passed, but merged-main CI `32610442133` failed
one Local Core archive test after 534 peers passed. The generated report was
still `ProbableMalware`, detected, and contained the expected encoded-script and
download/execute reasons. Its category alone became
`PotentiallyUnwantedApp`: randomized temporary path `.tmpuPoV59` lowercased to
a string containing the unbounded substring `pup`.

## Scripted Repair

- `pup` category inference requires an exact token separated by characters
  that are not ASCII alphanumeric.
- A positive-weight downloader fixture containing the exact CI path fragment
  must remain `SuspiciousDownloader`.
- An explicit `pup_indicator` fixture must remain
  `PotentiallyUnwantedApp`.
- The existing `native-engine risk fusion regressions` verifier step remains
  one step, but the independent validator now requires that step and the new
  verified-scope statements. The exact suite count remains 232.
- Python source contracts pin the implementation, both outcomes, verifier
  wording, and validator enforcement.

Verdict thresholds, risk weights, evidence retention, recommended actions,
signatures, rules, and quarantine policy are unchanged. This fixes deterministic
classification/explanation; it does not claim a semantic family classifier or
production category accuracy.

## Execution Evidence

Per the requested sequence, implementation, regressions, verifier, validator,
source contracts, and documentation were completed before the first
checkpoint-2202 test. At the end of that scripting phase no test or verifier
pass was claimed.

Initial focused execution passed the direct token test `1/1`, complete risk-
fusion `7/7`, the triggering Local Core archive test 25 consecutive times,
Local Core `535/535`, Native Engine `460 + 6`, strict Local/Native Clippy,
parsers, formatting, and source contracts `630/630`. The first default-parallel
locked workspace run then found a separate pre-existing test-only env race:
asset-locator tests could expose an intentionally relative engine root to a
concurrent JAR scan. Both env cases are now scripted through exact isolated
child-test processes, with production discovery unchanged.

After that isolation repair, asset tests pass `4/4`, Local Core passes three
default-parallel runs at `535/535`, both locked workspace variants pass, and
strict Native/Local/Guard Clippy passes. The final source-contract count is
`631/631`; format, parser, diff, lockfile, release, Flutter/analyzer, security,
dependency, and package-source gates pass.

The definitive report runs from `2026-08-23T01:47:24.8501521Z` to
`2026-08-23T01:56:02.2284761Z` and passes exactly `232/232` in `517.3s`. Its
built-in validator and a separate strict invocation pass. The stale checkpoint-
2201 report has the same step count but lacks the new token-boundary scope and
is rejected. The protected vault and lockfiles are unchanged.

Implementation head `43ce4d462e35a0c638171028d158b5dc08f55805`
passes exact-head Avorax CI `32611742164` and Desktop Packages push/PR runs
`32611721124`/`32611742152`. Both package runs pass package contracts, Windows
x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, six-artifact
consolidation, checksums, and lockfile SBOM evidence. Both publication jobs are
skipped. No artifact was installed, released, or published. Evidence-head
checks, follow-up merge, green merged-main evidence, and safe original-tree
synchronization remain pending.
