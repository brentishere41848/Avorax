# Checkpoint 2196 Native Catalog Authenticode

Date: 2026-08-22

## Scope

Checkpoint 2196 reduces false-positive risk for legitimate Windows files that
are signed through a Windows security catalog rather than an embedded primary
signature. It preserves the two-part trust rule: Windows must validate the
signature and the verified leaf signer must match Avorax's exact Microsoft
organization/common-name policy.

This checkpoint does not enumerate secondary embedded signatures, authorize
execution, install a service or driver, alter Defender, or claim pre-execution
blocking or a production detection rate.

## Checkpoint 2195 Closure

Checkpoint 2195 merged through PR `#47` as
`b2ceb927bb839ae8531d831fc769545564f95314`. Merged-main Avorax CI run
`32583368808` passed. Desktop Packages run `32583368801` passed package
contracts, Windows x64 MSI/EXE plus non-installing administrative extraction,
Linux x64 DEB/tar, macOS arm64/x64 DMGs, six-artifact consolidation, checksums,
and lockfile SBOM generation; prerelease publication was skipped.

The 19 explicit checkpoint files were synchronized to
`C:\Users\Brent\Documents\Avorax-main` only after all 19 old/new preconditions
matched. Every destination then matched the committed source by Git blob and
SHA-256. Focused destination checks passed 7 direct boundary tests, 6 direct
trust tests, 626 source contracts, strict Native Clippy, and rustfmt. The
protected ProgramData quarantine remained exactly 16,072 files, zero
directories, 4,522,733 bytes, 5,357 each of `.avoraxq`, `.json`, and `.auth`,
one `.metadata_auth_key`, and zero pending files.

## Implementation

After a definitive non-trusted primary embedded result, the Native Engine now:

1. acquires a SHA-256 catalog administrator context;
2. computes the exact 32-byte catalog member hash from the same open candidate
   handle used by direct Authenticode;
3. builds the canonical uppercase hexadecimal member tag;
4. enumerates no more than 16 matching catalogs;
5. validates each fixed catalog-path buffer as one bounded, NUL-terminated,
   absolute local-drive path with no trailing data;
6. evaluates each candidate with no-UI, cache-only `WinVerifyTrust`;
7. applies the same exact Microsoft leaf organization/common-name policy;
8. on scan paths, rereads the same handle under the existing 512 MiB/128 KiB
   content-binding limits and requires the already-scanned SHA-256; and
9. explicitly releases WinTrust state, the current catalog context, and the
   catalog administrator context, making normal cleanup failures visible.

An inconclusive embedded result does not fall through to catalog verification.
Catalog API, hash-size, path-shape, candidate-limit, policy, and cleanup failures
remain diagnostics and contribute no clean trust weight.

## Safe Fixtures

Runtime tests use only benign host files and temporary harmless bytes:

- installed catalog-backed WindowsPowerShell is the positive catalog fixture;
- installed embedded-signed Microsoft Edge remains the embedded positive;
- temporary plain text and malformed non-PE bytes remain negative fixtures;
- right and intentionally wrong SHA-256 values exercise content binding; and
- pure fixed-buffer tests exercise relative, UNC, unterminated, and trailing-data
  catalog paths without reading or executing any catalog payload.

No fixture is executed. No live malware is downloaded, unpacked, or retained.

## Verification

The entire implementation, focused tests, source contracts, central verifier,
independent validator, and documentation were updated before executing the
checkpoint test batch. The full-suite report now requires exactly 225 steps and
adds `native-engine catalog Authenticode Microsoft-signed/hash-binding
regressions`.

Verification order (local steps 1 through 5 executed; hosted/integration steps
6 and 7 pending):

1. formatting and PowerShell parser checks;
2. direct/catalog boundary and benign runtime tests;
3. source contracts and strict affected-crate Clippy;
4. complete Native Engine, workspace, Flutter, dependency, and security gates;
5. definitive 225-step verifier plus independent validator;
6. exact-head hosted CI/packages, PR/merge, and merged-main checks; and
7. preconditioned original-tree synchronization and final read-only vault audit.

Steps 1 through 5 passed locally. Focused evidence passed direct/catalog
boundary `10/10`, catalog-backed Microsoft signer/hash binding/fallback `3/3`, direct
embedded/unsigned/malformed `5/5`, and publisher diagnostics `1/1`. The first
strict Native Clippy run found `field_reassign_with_default`; initializing
`CATALOG_INFO.cbStruct` in the struct expression fixed it, after which strict
Clippy and the affected runtime tests passed again.

Final review strengthened the benign catalog fixture so it explicitly fails the
primary embedded path before succeeding through catalog verification. Complete
Native Engine tests then passed `445 + 6`, the standard locked Rust workspace
passed `1,489`, the all-features workspace passed `1,490`, Flutter analyzer and
all `838` tests passed, and source contracts passed `626/626`. The final
definitive report passed `225/225` verifier steps with zero failed or skipped
steps from `2026-08-22T16:53:12Z` to `2026-08-22T17:02:49Z` (`577.2s`); a
separate strict validator invocation accepted the report. Three symlink tests
were explicitly skipped inside the
passing packaging-source-contract step because optional Windows symlink
privilege was unavailable.

The post-suite read-only ProgramData audit matched the protected invariant
exactly: 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending. Hosted
exact-head CI/packages, merge, and original-tree synchronization are not yet
claimed.

## Remaining Limits

- Secondary embedded signatures are not enumerated.
- Catalog and WinTrust native calls have no hard in-call cancellation.
- Earlier writable or memory-mapped handles and post-verdict mutation remain
  user-mode TOCTOU limits.
- Windows catalog registration, trust stores, crypto providers, and protected
  system state remain trusted operating-system boundaries.
- Installed LocalSystem/service/UI behavior, production signing, signed-driver
  IPC, pre-execution enforcement, Defender coexistence, and production accuracy
  require separate evidence.
