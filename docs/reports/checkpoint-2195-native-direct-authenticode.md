# Checkpoint 2195: Native Direct Authenticode

Date: 2026-08-22
Status: implementation-head locally and hosted verified; evidence-head/merge pending

## Scope And Ownership

This checkpoint replaces Native Engine's WindowsPowerShell Authenticode probe
with direct Windows trust APIs. Native Engine remains detection-only in
production. Local Core remains the sole production owner of quarantine,
authenticated metadata, recovery, rescan, restore, and deletion.

No live malware is used. Tests are limited to benign temporary bytes and an
installed Microsoft-signed Windows binary; no fixture is executed. This work
does not alter Defender, install a package or machine-wide component, start a
service or driver, publish a release, or claim pre-execution blocking.

## Finding

The previous probe launched WindowsPowerShell, imported a Security module,
serialized Authenticode state to JSON, and parsed that output. Checkpoint 2194
bounded helper discovery and child-process resources, but metadata checks and
later launch remained separate, ambient platform behavior remained in the
decision path, and the signature verdict was not bound to the exact bytes
already hashed by the scan engine.

## Implementation

The Windows-only `windows_authenticode` module now:

1. requires an absolute, bounded, NUL-free path;
2. opens a regular non-reparse file with read sharing only and no write/delete
   sharing;
3. calls `WinVerifyTrust` on that open handle with no UI, cache-only URL
   retrieval, whole-chain revocation checking, and MD2/MD4 disabled;
4. extracts the primary verified signer from WinTrust state and requires both
   exact `Microsoft Corporation` organization and an allowlisted exact
   Microsoft common name;
5. treats missing/invalid signatures as false while revocation, policy,
   provider, I/O, cleanup, and unknown statuses remain visible errors;
6. closes WinTrust state on every verify outcome and reports cleanup failure;
7. on the scan path, rereads no more than 512 MiB through the same handle with
   a 128 KiB buffer and requires the result to equal the engine SHA-256; and
8. checks pre/post length, last-write time, and attributes and enforces the
   byte ceiling during every read so a growing file cannot create unbounded
   work.

The compatibility path-only API remains available for the existing trust
surface, but the engine uses the SHA-256-bound API. Production no longer
contains an Authenticode script, child process, module import, JSON parser, or
PowerShell output runner.

## Dependency Contract

No package or version was added. Existing pinned `windows-sys 0.61.2` gained
only the Foundation, FileSystem, Cryptography/Catalog/SIP, and WinTrust feature
gates needed by the implementation. Both lockfiles are unchanged. The
dependency-evidence gate passed; `windows-sys` remains `MIT OR Apache-2.0` in
the inventory. Final-artifact SBOM and notice review remain release gates.

## Local Verification

The implementation, tests, verifier, validator, source contracts, and docs were
fully scripted before test execution began. Focused Windows evidence passed:

- direct boundary/status/path/hash/cleanup tests: `7/7`;
- benign unsigned and malformed fixtures: `2/2`;
- catalog-only WindowsPowerShell conservative rejection: `1/1`;
- embedded Microsoft Edge signer and right/wrong SHA-256 binding: `2/2`;
- engine fail-visible diagnostic evidence: `1/1`; and
- Native Engine native Windows-root regressions: `10/10`.

Broader local evidence passed:

- complete Native Engine: `440` library tests plus `6` binary tests;
- strict Native Engine all-target/all-feature Clippy with `-D warnings`;
- full Rust workspace: `1,484/1,484` tests;
- full Flutter suite: `838/838` tests and `flutter analyze`;
- Python source contracts: `626/626` tests;
- rustfmt, PowerShell parsers, diff, dependency, no-malware, false-positive,
  product-copy, branding, update, quarantine, restore, logging, and resource
  gates; and
- a cold `cargo build --workspace --release --locked` in an isolated target,
  which passed in `3m27s`. Cargo then removed exactly `4,033` isolated files
  (`1.4 GiB`) from the prevalidated temp target.

The definitive verifier ran from `2026-08-22T14:59:32.8735961Z` through
`2026-08-22T15:10:58.9771126Z` and passed exactly `224/224` steps with zero
failed or skipped verifier steps in `686.1s`. Its independent full-suite
validator passed again in `2.7s`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .verification\checkpoint-2195-small-threat-mvp-definitive-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -RepoRoot . -ReportPath .verification\checkpoint-2195-small-threat-mvp-definitive-report.json -RequireFullSuite
```

The validator requires exactly 224 steps and all three direct-Authenticode step
names. It rejected checkpoint 2194's otherwise valid 223-step report with the
expected exact-count error. The packaging-contract step internally ran 24
tests with three explicit skips because this host lacks optional Windows
symlink-creation privilege; the verifier step passed and no antivirus runtime
behavior was skipped. Hosted package runners remain required.

## Exact Implementation-Head Evidence

Implementation commit
`1e6f86a32f80f6cecec737f249d90a858c0fcb39` passed:

- Avorax CI pull-request run `32581595210`;
- Desktop Packages push run `32581579353`; and
- Desktop Packages pull-request run `32581595294` on draft PR `#47`.

Both package runs passed package contracts, Windows x64 MSI/EXE construction
and non-installing administrative extraction, Linux x64 DEB/tar construction,
macOS arm64/x64 DMG construction, six-artifact consolidation, checksums, and
lockfile SBOM evidence. Both prerelease publication jobs were skipped. No
artifact was installed or released.

## Failures Preserved And Repaired

1. The first direct boundary run passed `6/7`; generic `TRUST_E_FAIL` overlapped
   a broad certificate HRESULT range and was incorrectly classified as an
   invalid signature. It is explicitly excluded and remains fail-visible.
2. The immediate retry exposed a missing `TRUST_E_FAIL` import at compile time.
   The import was restored before the complete focused rerun passed `7/7`.
3. WindowsPowerShell produced `0/2` positive fixture results because its valid
   Microsoft signature is catalog-backed. The test now proves conservative
   catalog rejection and uses embedded-signed Microsoft Edge for positive and
   hash-binding evidence.
4. The first full workspace run exposed a process-wide `AVORAX_DATA_DIR` race
   between parallel Local Core tests. The two negative environment tests now
   mutate that variable only in exact isolated child-test processes. Focused
   regressions and the complete `1,484/1,484` workspace rerun passed.

## Protected Vault Evidence

Read-only inventories before and after the definitive verifier were identical:
`16,072` files, zero directories, `4,522,733` bytes, `5,357` each of
`.avoraxq`, `.json`, and `.auth`, one `.metadata_auth_key`, and zero pending
files. No vault file was opened for mutation.

## Classification

- **Verified locally:** direct handle-based primary embedded Authenticode,
  exact Microsoft signer identity, scanned-content SHA-256 binding,
  conservative failure classification, dependency/source contracts, complete
  Rust/Flutter regression, cold locked release build, and definitive `224/224`
  verification.
- **Verified at implementation head:** exact-head CI plus Windows/Linux/macOS
  package jobs, consolidated checksums/SBOM, and skipped publication.
- **Partial / pending:** evidence-head CI/packages, PR merge, merged-main
  CI/packages, and original-tree synchronization.
- **Disabled / blocked:** catalog-signature fallback, secondary-signature
  enumeration, 32-bit Windows packaging, production signing, signed-driver
  IPC, and true pre-execution enforcement.
- **Technically limited:** `WinVerifyTrust` has no hard in-call cancellation;
  cache-only revocation completeness depends on local Windows trust caches;
  pre-existing writable or memory-mapped handles and post-verdict mutation are
  not eliminated. This is a conservative user-mode scan trust signal, not a
  Defender replacement, execution authorization, or detection-rate claim.
