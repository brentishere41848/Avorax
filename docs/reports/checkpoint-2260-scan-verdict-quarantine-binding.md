# Checkpoint 2260 - Scan Verdict Quarantine Binding

Status: **Implementation-head local and hosted verification complete; merge and destination integration pending**

## Scope

Local Core converted a Native Engine verdict into a new `ScanResult` immediately
before automatic quarantine, but recomputed the selected path hash and the
quarantine store ignored the verdict hash. If harmless or hostile software
changed or replaced a detected file between scanning and quarantine, Avorax
could quarantine different current bytes under the earlier threat label while
the visible threat row retained the earlier SHA-256. That was a fail-open
scan-verdict-to-mutation boundary.

Guard Service already compared its process-observation hash before quarantine,
but it hashed by reopening the path and did not bind the still-opened source
identity to that path immediately before move or copy-source removal. The same
shared path-identity hardening therefore applies to Guard without changing its
post-launch or privilege claims.

## Implemented Contracts

- Automatic quarantine now carries the exact Native verdict SHA-256 through
  `quarantine_selected_file`; manual quarantine remains an explicit separate
  path that takes a fresh bounded hash snapshot of the current file.
- `QuarantineStore::quarantine_file` requires an infected result, a valid
  SHA-256, and an exact selected-path/result-path match before any vault
  directory creation or payload mutation.
- The store hashes the already-opened, single-link source handle. A malformed
  verdict hash or bytes that no longer match the verdict fail visibly with a
  rescan-required error. The current file remains in place and no finalized
  quarantine record is created.
- Cross-platform file identity compares Unix device/inode or Windows volume
  serial/file index. The selected path must still identify the opened source
  immediately before rename. Copy fallback repeats this check immediately
  before source removal and removes an untrusted copy destination on failure.
- Guard now hashes its already-opened single-link source, delays vault creation
  until the expected scan hash matches, checks source path identity before each
  move attempt, and repeats identity validation before copy-source removal.
- Existing destination SHA-256 checks, protected permissions, authenticated
  finalization journal, metadata HMAC, atomic record writes, restore validation,
  and fail-visible cleanup behavior remain in force.

## Test And Evidence Scripting

Six benign regressions share the `scan_quarantine_binding_` prefix:

1. unchanged open-handle/path identity is accepted;
2. a harmless path replacement is rejected while both files are preserved;
3. changed harmless bytes are rejected before vault creation;
4. malformed verdict SHA-256 is rejected before vault creation;
5. a mismatched verdict path is rejected before vault creation; and
6. Local Core's automatic hash-bound helper surfaces changed bytes and preserves
   the replacement for an explicit rescan.

The existing definitive `platform quarantine permission regressions`,
`local-core quarantine metadata regressions`, and `guard-service quarantine
metadata regressions` steps execute the six new tests plus the existing Guard
changed-hash and quarantine regressions, so the strict suite remains exact
`288/288`. The verifier now records the verified binding and its technical
limit, and the independent validator requires those scope statements. Source
contract 690 pins implementation order, Local Core scan/manual and Guard wiring,
both identity mechanisms, every new test marker, verifier/validator scope,
documents, dependency honesty, and this sequencing boundary.

No checkpoint-2260 test ran during the initial scripting phase. The complete
source, test, verifier, validator, source-contract, and documentation batch was
scripted first as requested. Initial execution then found three stale test-only
expectations for the old path-reopen marker and the old empty-vault-directory
behavior; those assertions were updated to require open-handle hashing and no
vault creation, and their complete suites passed on rerun.

## Local Verification

Local verification completed on 2026-08-28:

- `cargo fmt --all -- --check` and `git diff --check` passed. The latter emitted
  only expected Git LF-to-CRLF working-copy warnings.
- Windows PowerShell 5.1 and PowerShell 7 parsed the verifier and validator:
  `4/4` files/hosts passed.
- `python.exe -B tools/testing/run-python-source-contracts.py` passed
  `690/690`.
- `cargo test --workspace scan_quarantine_binding_ -- --test-threads=1`
  passed the six new benign regressions. Complete platform, Local Core, and
  Guard suites passed `11/11`, `568/568`, and `248/248`; the all-feature Guard
  variant passed `249/249`.
- Strict all-target/all-feature no-dependency Clippy passed for Platform, Local
  Core, and Guard. Both `cargo test --locked --workspace` and its
  `--all-features` variant passed; Native Engine passed `640/640` with 21
  intentional isolated child fixtures ignored, and its compiler passed `6/6`.
- `cargo build --locked --workspace --release --all-features` passed.
- Flutter analyze passed with zero issues and the complete client passed
  `847/847`. Zentor Protocol and Avorax Protocol analyzed cleanly and passed
  `14/14` and `6/6`.
- The no-skip, no-Defender definitive verifier passed exactly `288/288` in
  `651.3s`, from `2026-08-28T12:14:25.5835337Z` through
  `2026-08-28T12:25:16.9524278Z`. Windows PowerShell 5.1 and PowerShell 7 both
  accepted the full-suite report. Report SHA-256:
  `3011587770e133542bf6f007f7213130722d9ff0fbd1e22af65d7b64ba23433b`.
- Adversarial copies missing either the checkpoint verified scope or the
  required user-mode race limitation were rejected by the validator.
- Before and after verification, no Avorax/Zentor product process was running.
  The protected vault remained exactly 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending files.

## Hosted Implementation-Head Verification

Commit `864bfddd14f8dfd9710878b15388fad4a3ee8e07` is the exact head of
PR `#129`. Hosted evidence completed on 2026-08-28:

- Avorax CI pull-request run `33171430624` passed all five jobs: security,
  protection, and performance gates; Rust Local Core and Guard; branding and
  copy; Unix quarantine permissions; and Flutter client/protocol.
- Desktop Packages push run `33171402684` and pull-request run `33171430602`
  both passed package contracts, Windows x64 MSI/setup EXE, Linux x64 DEB/tar,
  macOS x64/arm64 DMGs, and consolidation/checksum jobs at the same exact head.
- Each package run produced five evidence bundles: Windows, Linux, macOS x64,
  macOS arm64, and `avorax-desktop-release-0.1.15`. The consolidated bundle
  contains the required six native release files plus a 569-component lockfile
  SBOM and `SHA256SUMS.txt`; its push/PR archive SHA-256 digests are
  `e72222ee154a0221fce703eb4896230954048278f1cffa5c79ef9fdd33e61442`
  and `399c150f26e62972d178564d37436fead1b6519b012261367eec21adc2f9c2c0`.
- Both `Publish desktop beta prerelease` jobs were skipped. No hosted artifact
  was installed, released, or published.

The evidence-only documentation commit, its exact-head hosted checks, normal PR
merge, merged-main verification, guarded zero-delete destination
synchronization, and destination verification remain pending.

## Technical Limits

The binding is user-mode and path-based. It detects mutation before quarantine
hashing, a replaced path before move, copy mismatch, replacement before copy
source removal, and post-move payload mismatch. It cannot make every filesystem
path operation atomic with the final identity check. A privileged writer could
still race the final check and rename/removal on some filesystems. A detected
post-move mismatch remains fail-visible and recovery-journaled rather than a
false success, but may require bounded recovery.

This checkpoint does not claim kernel mediation, pre-execution blocking,
protection from administrators/SYSTEM/kernel compromise, secure erasure, an
installed cross-identity service, or Defender replacement. It binds quarantine
to scanned content; it does not stop later execution or mutation outside that
operation.

## Safety And Dependencies

Checkpoint 2260 adds no dependency, package source, license class, downloaded
runtime, machine-wide component, or lockfile change. It reuses SHA-256,
already-opened file handles, existing Windows file identity APIs, Unix metadata,
the existing quarantine journal, and existing bounded copy/hash limits.

Tests use only harmless text fixtures in isolated temporary directories and
never execute candidate files. No live malware, EICAR file, Defender setting,
machine-wide install, service/driver start, release, publication, or protected-
quarantine mutation is part of this checkpoint. `.verification` remains
untracked and unstaged. The complete antivirus-hardening goal remains active.
