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

## Integration Closure

Evidence head `dee97b41eab002e2c15e5ba4c9102f992fe0b17c` passed Avorax CI
`32612516929` and Desktop Packages PR run `32612516881`; publication was
skipped. PR `#54` merged that exact head as
`4e24e47fc2732fd83d6f2fa403766aff46796d5c`. Merged-main Avorax CI
`32613299479` passed every job, including the previously nondeterministic Local
Core archive gate. Merged-main Desktop Packages `32613299509` passed package
contracts, Windows MSI/EXE, Linux DEB/tar, both macOS architectures,
consolidation, checksums, and lockfile SBOM generation with publication skipped.

Exactly 15 changed files were synchronized to
`C:\Users\Brent\Documents\Avorax-main` only after all existing destinations
matched the prior merged Git blobs and both new report paths were absent. Every
destination then matched merged-main Git blob and source SHA-256 evidence.
Destination source contracts `631/631`, rustfmt, risk fusion `7/7`, asset
locator `4/4`, Job limit `1/1`, helper isolation `5/5`, five repeats of the
triggering archive regression, strict Native/Local Clippy, and the release
Local Core/Guard Authenticode helper smoke passed. The read-only quarantine
audit remained exactly 16,072 files, zero directories, 4,522,733 bytes, 5,357
each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.
No release, publication, installation, service/driver start, Defender change,
or protected-vault mutation occurred.
