# Checkpoint 2199 Native Authenticode File Identity

Date: 2026-08-22

## Status

Implementation, benign tests, release smoke changes, verifier/validator
contracts, source contracts, and audit documentation were scripted before test
execution. Focused and complete local verification now passes. Exact-head
hosted CI/packages, merge, merged-main checks, and original-tree synchronization
remain pending.

## Scope

Checkpoint 2199 removes path-only Microsoft publisher trust and makes the
scanner's exact full-file SHA-256 mandatory through every direct and isolated
Authenticode path. It also captures stable identity and mutation metadata from
the same open candidate handle before and after embedded/catalog WinTrust and
content binding.

This checkpoint does not add a detection signal, execute a fixture, install a
component, weaken Defender, publish a package, or claim pre-execution blocking.

## Mandatory Hash Contract

The public Microsoft trust function accepts only `path + expected_sha256`. The
unused aggregate publisher lookup is removed. Direct verification and the
strict schema-v1 child request require one non-null 64-hex SHA-256; missing,
null, malformed, or mismatched values fail visibly. Embedded and catalog trust
both reread the bounded open handle and require the digest of those bytes to
match the scanner's digest.

## Handle Snapshot

The parent/helper direct verifier opens one bounded regular non-reparse file
without write or delete sharing. A fixed-size snapshot queries:

- volume serial and 128-bit file ID;
- legacy 64-bit file index;
- creation, last-write, and change times;
- file attributes;
- allocation size and logical end size;
- link count; and
- delete-pending and directory state.

Legacy and extended volume, creation/write time, size, link-count, and attribute
values must agree. The file must remain non-directory, non-reparse, linked, and
not pending deletion. Any
query failure, inconsistency, or before/after drift is a diagnostic and cannot
be converted into trusted or clean evidence. If the trust operation and final
snapshot both fail, the result retains both errors.

Last-access time is intentionally excluded because reads may update it.

## Benign Adversarial Verification

The completed scripting batch ran in this order:

1. PowerShell parser, rustfmt, diff, and source-contract checks.
2. Focused mandatory-hash/file-identity tests, all helper/direct/catalog/
   secondary Authenticode regressions, and Local Core/Guard entry tests.
3. Strict Native/Local/Guard Clippy, locked release host builds, and the
   non-installing two-host release smoke with mandatory hashes for embedded
   Edge, catalog-backed Windows PowerShell, and unsigned temporary text plus a
   wrong-digest failure.
4. Complete locked Rust workspace variants, Flutter analyzer/tests, security and
   dependency gates, and exact `230/230` definitive verification plus an
   independent validator.
5. Exact-head hosted CI/packages, normal PR merge, merged-main checks, and
   preconditioned original-tree synchronization with focused destination tests.

Temporary tests may deny a pre-existing writer and create a benign hardlink to
prove link-count drift. They never execute the files. Only EICAR text and benign
fixtures are permitted. The protected ProgramData vault must remain at its exact
recorded invariant and `.verification` must remain untracked.

## Known Limits

- Required identity queries may be unavailable on a filesystem/provider. That
  fails conservatively and can reduce trusted-publisher credit.
- A writable mapping created before the restrictive handle can still mutate
  pages. The verifier cannot revoke it.
- Mutation after the verdict remains possible; the verifier does not authorize
  or block later execution.
- The child uses the same token as its parent and is not a sandbox or privilege
  split.
- Secondary catalog signatures remain unsupported.
- Production signing, installed LocalSystem/service/UI operation, signed-driver
  IPC, pre-execution blocking, Defender coexistence, and production accuracy
  remain separate prerequisites.

## Evidence

- PowerShell parser checks, final `cargo fmt --check`, `git diff --check`, and
  `python -B tools/testing/run-python-source-contracts.py` pass; source
  contracts report `627/627`. No lockfile changed.
- `cargo test --manifest-path core/zentor_native_engine/Cargo.toml
  native_authenticode_file_identity -- --test-threads=1` passes `4/4`.
  Helper/direct/catalog/secondary filters pass `4/4`, `4/4`, `3/3`, and `3/3`;
  corrected Local Core and Guard host-entry filters pass `1/1` each.
- Strict all-target Native/Local/Guard Clippy passes. Locked release Local Core
  and Guard builds pass, followed by the two-host non-installing Authenticode
  smoke. No fixture is executed and no service is started.
- The initial full Native run exposed one test-only self-match after `455`
  passes. Scoping that source assertion to production fixed it; the focused
  regression passes `1/1` and the complete rerun passes `456/456` plus compiler
  `6/6`. Both `cargo test --workspace --locked` and the corresponding
  `--all-features` variant pass.
- `flutter analyze` reports no issues and `flutter test` passes `838/838`.
  Security, no-malware, dependency, performance, package-source, scan,
  quarantine/restore/delete, update, watcher, process, and UI gates all pass in
  the definitive verifier.
- `.workflow/ultracode/avorax-hardening/results/2199-small-threat-mvp-full-report.json`
  records `230/230`, zero failed/skipped, from
  `2026-08-22T21:48:54.6573771Z` through
  `2026-08-22T21:57:19.3170451Z` (`504.6s`). Independent
  `-RequireFullSuite` validation passes; checkpoint 2198's `229`-step report is
  rejected with the expected exact-count diagnostic.
- Read-only post-suite inventory remains 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one metadata key, and
  zero pending. `.verification` remains untracked.

Implementation head `d619c0a5ddb627e9d940d12478d5db9589ee5679`
passes Avorax CI `32601267008` and Desktop Packages push/PR
`32601253745`/`32601266989`. Package contracts, Windows x64 MSI/EXE, Linux x64
DEB/tar, macOS arm64/x64 DMG, six-artifact consolidation, checksums, and
lockfile CycloneDX SBOM pass. Both prerelease publication jobs are explicitly
skipped.

Evidence head `b000b8dfc9e4e7427380ddbe80dba958d9d16e95` passes Avorax CI
`32602128535` and Desktop Packages `32602128573`. PR `#51` merged with exact-
head locking as `264e4551aa930f75d325ebd3df4522bd4f244941`. Merged-main CI
`32602820696` and packages `32602820702` pass; package contracts, every platform,
consolidation, checksums, and lockfile SBOM pass while publication is skipped.

All 16 explicit files synchronized to the original tree only after each
existing destination matched checkpoint 2198 and the new report was absent.
Every destination matches the merged Git blob and raw source SHA-256.
Destination source contracts (`627/627`), identity/helper tests (`4/4` each),
rustfmt, strict Native/Local/Guard Clippy, locked release builds, and both-host
benign smoke pass. The protected vault is unchanged. No installation, release,
publication, service/driver start, or Defender change occurred.
