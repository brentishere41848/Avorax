# Checkpoint 2200: Secondary Catalog Authenticode

## Objective

Apply the existing Microsoft publisher policy to bounded secondary signatures
on each system-catalog candidate without weakening the required conjunction:
valid Windows trust, exact Microsoft leaf identity, and the scanner-supplied
SHA-256 of the already scanned member bytes.

## Scripted Boundary

Each catalog candidate supplies `WINTRUST_SIGNATURE_SETTINGS` to the existing
handle-based `WTD_CHOICE_CATALOG` request. The verifier requests primary index
zero and the secondary count, accepts primary output only when it is zero or
provider-untouched, requires every requested secondary index exactly, and
rejects count drift. Every WinTrust state is closed and reset before another
signature is selected. At most 16 total signatures are considered per catalog
and at most 16 catalogs remain enumerable.

An invalid primary signature is not rescued by a secondary signature. A valid
non-Microsoft primary may continue to bounded secondaries; only a valid exact-
Microsoft signer whose member bytes match the mandatory expected SHA-256 can
supply trust. Errors, unknown statuses, count overflow/drift, wrong indexes,
hash mismatch, and state or catalog cleanup failures remain diagnostic.

## Verification Design

- A deterministic benign unit test covers ordered secondary selection,
  Microsoft acceptance, invalid-primary short circuit, limit rejection, and
  visible callback errors for the catalog label.
- A read-only installed WindowsPowerShell fixture exercises the real catalog
  provider with signature settings and proves the primary catalog/hash path,
  including wrong-hash rejection. The fixture is never executed.
- The central verifier adds one mandatory focused filter and the independent
  full-suite validator requires exactly 231 steps plus the new scope and
  technical-limit language.
- Source contracts pin catalog-specific signature settings, exact index/count
  handling, tests, verifier wiring, and honest partial classification.

## Honest Limitation

This repository and host do not provide a controlled benign system catalog
with a known valid Microsoft secondary signature. Synthetic aggregation proves
the bounded decision logic, and the installed fixture proves real primary
catalog API compatibility and content binding, but neither proves a positive
secondary-catalog acceptance on every supported Windows version. That route is
classified **partial**, not fully verified or silently disabled. It remains
fail-closed because no secondary can supply trust unless WinTrust validates the
requested exact index and the existing signer/hash policy also passes.

Memory-mapped and post-verdict mutation, same-token helper privilege,
production signing, installed LocalSystem/service/UI behavior, signed-driver
IPC, pre-execution blocking, Defender replacement, and production detection
accuracy remain separate limitations or blockers.

## Local Execution Evidence

Per the requested sequencing rule, implementation, tests, verifier/validator,
source contracts, and documentation were completed before any checkpoint-2200
test execution.

The focused secondary-catalog filter passes `2/2`; existing catalog,
secondary-embedded, helper, and file-identity filters pass `3/3`, `3/3`, `4/4`,
and `4/4`. The complete Authenticode module passes `24/24`, Native Engine passes
`458/458` plus signature compiler `6/6`, both locked workspace variants pass,
release Local Core and Guard builds plus the two-host helper smoke pass, Flutter
analyze reports no issues, Flutter tests pass `838/838`, and Python source
contracts pass `628/628`. Rustfmt, strict Native/Local/Guard Clippy, branding,
product-copy, no-malware, dependency, packaging, and lockfile gates pass.

The first parallel workspace run exposed an existing test-isolation defect:
the cancellation regression changed process-wide `AVORAX_DATA_DIR`, allowing a
concurrent EICAR-read regression to observe its cancel token. The cancellation
case now runs in the existing isolated child-test harness; its focused rerun and
both complete locked workspace variants pass. No production scan behavior was
relaxed.

The first definitive verifier execution completed all 231 substantive steps,
then exposed a fail-visible validator wiring defect: the validated
`technically_limited` string was not assigned before its required-scope check.
The assignment and a source contract were added. The clean rerun and independent
validation pass exactly `231/231` from `2026-08-22T23:20:17.3944083Z` through
`2026-08-22T23:27:21.5206131Z` in `424.1s`; the new validator rejects the stale
checkpoint-2199 `230`-step report. The protected vault remains exactly 16,072
files, zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`,
one metadata key, and zero pending.

Implementation head `882f24d45c13b60b952cfacb94d3eee2563fb0f8` passes
Avorax CI `32605433795` and Desktop Packages push/PR runs `32605424354` and
`32605433783`. Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMG, package
contracts, six-artifact consolidation, checksums, and lockfile CycloneDX SBOM
all pass. Both prerelease publication jobs are skipped. Evidence head
`e863332dec8a646909ba1945aca32875288df76c` passes CI `32606194450` and package
PR run `32606194213`. PR `#52` merged with exact-head locking as
`baa39ac316c58b010cb7805785a1fef47c4f0c19`; merged-main CI `32606989492` and
packages `32606989456` pass with publication skipped. Exactly 13 files
synchronized after base/absence preconditions; merge blobs and raw hashes,
focused destination checks, and the protected vault invariant pass.
