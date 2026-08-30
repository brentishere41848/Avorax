# Checkpoint 2272 Update Recovery Namespace Durability

Date: 2026-08-30

Status: **Closed through hosted integration and synchronized destination verification**

## Purpose

Checkpoint 2272 narrows a crash-recovery gap between durable recovery-file
contents and the filesystem namespace entries that make those files and update
directories reachable. It does not claim a power-loss-proof package
transaction.

No checkpoint-2272 test ran during the scripting phase. Production changes,
benign tests, the focused verifier step, report-validator contracts, source
contracts, and documentation were written first as one reversible batch.

## Scripted Controls

- Windows atomic no-replace moves request `MOVEFILE_WRITE_THROUGH` while still
  omitting replacement flags.
- Unix opens a stable ordinary directory, binds pre-open/opened/post-sync
  device and inode identity, and calls `sync_all` after key, lock, journal,
  rename, and cleanup namespace mutations.
- Key, journal, and lock files retain their existing file-content and metadata
  synchronization before the parent namespace barrier.
- Backup and staged-directory renames are followed by a namespace barrier
  before the next irreversible activation or cleanup step.
- A post-rename barrier failure returns a visible error and preserves the
  authenticated journal plus staging/backup/destination state for a later
  recovery pass.
- Recovery re-runs the relevant namespace barrier before removing backup or
  journal evidence.

The Linux `fsync(2)` documentation explicitly distinguishes file-data sync
from synchronization of the containing directory entry. Microsoft documents
`MOVEFILE_WRITE_THROUGH` as waiting for the move to reach disk. These APIs are
used conservatively and their filesystem/device limitations remain explicit:

- https://man7.org/linux/man-pages/man2/fsync.2.html
- https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw

## Harmless Tests Scripted

- A stable Unix temporary directory synchronizes; a regular file is rejected
  as a directory-sync target.
- A simulated barrier failure after the backup move preserves journal,
  staging, and backup state; a fresh recovery restores the original tree.
- A simulated barrier failure after staged activation preserves journal,
  active destination, and backup; a fresh recovery finishes cleanup.
- The existing Ubuntu 24.04 and macOS 15 jobs select the new harmless Unix
  namespace-durability fixture through their fixed
  `activation_recovery_unix_` filter.
- The definitive verifier gains one focused durability step and therefore
  requires exactly 300 successful steps for a full report.

Fixtures contain only benign text and temporary directories. They are never
executed as programs.

## Files In The Frozen Batch

- `core/avorax_platform_security/src/lib.rs`
- `core/avorax_update_service/src/activation_recovery.rs`
- `tests/test_custom_driver_contract.py`
- `tools/testing/verify-small-threat-mvp.ps1`
- `tools/testing/validate-small-threat-mvp-report.ps1`
- `RUN_LOG.md`
- `STATUS.md`
- `TESTING.md`
- `docs/audit/engine-control-matrix.md`
- `docs/audit/known-blockers.md`
- `docs/audit/threat-model.md`
- `docs/dependency-license-inventory.md`
- `docs/malware-protection.md`
- this report

No dependency, manifest, lockfile, detection threshold, custom-engine
responsibility, quarantine format, driver, service-install, or UI control is
changed.

## Verification Required After Freeze

1. Parse PowerShell 5.1 and PowerShell 7 verifier/validator scripts.
2. Run Source contracts and the focused platform/update durability fixtures.
3. Run full platform-security and update-service tests, format, strict locked
   lint, both locked workspace variants, and locked all-feature release.
4. Run Flutter and both protocol analysis/test suites.
5. Run the exact non-Defender/no-skip 300-step verifier.
6. Require both validator hosts to accept the authentic report and reject
   malformed scope, count, path, and option mutations.
7. Obtain exact-head Ubuntu 24.04, macOS 15, broad CI, and desktop package
   evidence with publication skipped.
8. Integrate through a normal PR, verify merged main, synchronize only the
   frozen paths with backups and zero deletes, and repeat destination evidence.

## Local Verification Evidence

Post-freeze PowerShell 5.1 and PowerShell 7 parsing pass `2/2` on each host.
Source contracts pass exact `703/703`. The focused durability failure tests pass
`2/2`; platform security passes `18/18`; update service passes `232/232`; and
the separate Windows-executed Unix and macOS route contracts each pass `1/1`.
Formatting, strict locked all-target/all-feature Clippy, both locked workspace
test variants, and the locked all-target/all-feature release build exit zero.
The all-feature workspace groups are `18 + 4 + 232 + 41 + 251 + 583 + 642 +
6`, with zero failures and 21 documented isolated child-fixture ignores.

Flutter analysis reports no issues and the client passes `852/852`; Zentor and
Avorax protocol analysis/tests pass `14/14 + 6/6`. The authoritative full
verifier passes exact `300/300`, zero failed or skipped, in `575.4s`, with the
Defender/EICAR opt-in false. Its 228,867-byte report SHA-256 is
`9f6c54f97135044f2ae7e6b63f881b1084b0959316c24ceeea618f171cc1d531`.

Both validator hosts accept the authentic report. Eight content mutations on
each host are rejected, exact `16/16`; the 18,173-byte adversarial result
SHA-256 is
`e57c8d8520adfe071139b0132dd66a06ecbdb074c2b7f41db79c92a956997209`.
The adversarial audit initially exposed that the validator did not require the
post-mutation directory-sync failure limitation. That run is uncredited; the
validator and Source contract were tightened before the final verifier and
adversarial repeats.

An earlier full-verifier attempt is retained as failed because active Microsoft
Defender blocked the generated Native debug test executable before the false-
positive tests could run, returning Windows error 225. Defender was not
disabled or excluded. The 224,565-byte failed report is retained under
`.verification` with SHA-256
`3d59c71b583ae58aed954ea410c6e7b97741c8e94929efca1ef6924909e0675d`.
The unchanged focused gate and both complete repeats pass with explicit
`CARGO_PROFILE_TEST_DEBUG=0` and `CARGO_INCREMENTAL=0` test-only codegen.

All nine tracked dependency lockfiles match `origin/main`; no product process
remains. The read-only vault audit matches the protected invariant exactly.

## Implementation-Head Hosted Evidence

Exact implementation `62d257c3d03bd093cc2159c3f0287bac93ec295c`
passes all six Avorax CI jobs in run `33291974131`. Ubuntu job `99205069601`
and macOS 15 job `99205069619` each pass the exact four harmless
`activation_recovery_unix_` fixtures, including namespace durability:
`4 passed; 0 failed; 247 filtered out`.

Desktop Packages push/PR runs `33291944899`/`33291974128` pass contracts,
Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMG, consolidation, checksums,
and lockfile SBOM. Both prerelease-publication jobs are explicitly skipped.
Untouched consolidated artifacts `9726370706` and `9726376070` were retained
under untracked `.verification` and reviewed in-stream without extraction or
execution. They are respectively 132,681,746 bytes with SHA-256
`7b0b4c3dd0b46c79203710ebd6ad1f44b22686eff461d32db4383e2362b01218`
and 132,685,547 bytes with SHA-256
`a047776e9a96a17b36fd082a6863a7651e6bae9b26e2145dad8718a23c7877d2`.
Both pass exact 8-entry/6-platform/7-checksum inventory and CycloneDX 1.6 with
569 components.

The final local audit is 2,550 bytes with SHA-256
`264be91a7311bc6f8794a31cbcf4add9284a23f2bc654b500cff7eb6148943e8`.
It passes the exact 13-modified/one-added/zero-delete scope, nine unchanged
lockfiles, definitive/adversarial evidence, zero product processes, and the
protected vault invariant.

Hosted Ubuntu/macOS namespace durability is verified on those fixed runners.
The following closure section supersedes the then-pending merge,
synchronization, destination, and closure state. The complete antivirus-
hardening goal remains active.

## Evidence-Head, Merge, And Destination Closure

Evidence head `31fb2f4eb271d374f6c86d3eef30d61b7938d343` passes all six
Avorax CI jobs in run `33292650533`. Ubuntu job `99206875322` and macOS 15 job
`99206875245` each pass the exact four selected tests, `4 passed; 0 failed; 247
filtered out`. Desktop Packages run `33292650535` passes with publication
skipped. Consolidated artifact `9726612614` is 132,692,760 bytes with SHA-256
`3b5cdf5c00d30af3d05059170eeadc11151ab4b580bf5efd3a4a1a318044b26f`.

Normal PR `#153` merges as
`0c4f151aeb5c7e3f9271b6d5567d4d6930fcb1d9`. Merged-main Avorax CI run
`33293330097` passes all six jobs. Ubuntu job `99208660715` and macOS job
`99208660662` each pass exact `4/4`, with 247 filtered. Desktop Packages run
`33293330096` passes with publication skipped. Consolidated artifact
`9726836596` is 133,279,297 bytes with SHA-256
`a4afa9bb2f7456bac051e47843763c69b8cc55ffa8fcaa6259e19b6f0cf0da3b`.
Both artifacts pass bounded in-stream exact 8-entry/6-platform/7-checksum
inventory and CycloneDX 1.6 with 569 components, without extraction or
execution.

Guarded synchronization copies exact 13 modified and one added path with zero
deletes and preserves 26 verified backups. Sync-report SHA-256 is
`2cd375564f69d7f035f4d8c15230da35b3ee14ed18f8e030581fd0c305bf114e`.
The synchronized `C:\Users\Brent\Documents\Avorax-main` destination passes:

- `python -B tools/testing/run-python-source-contracts.py`: `703/703`.
- Rust format, strict locked all-target/all-feature Clippy, both locked
  workspace test variants, and locked all-target/all-feature release.
- Flutter analysis and `852/852` tests.
- Zentor and Avorax protocol analysis/tests: `14/14 + 6/6`.
- The no-skip/no-Defender verifier: exact `300/300` in `717.8s`. Its 220,116-
  byte report SHA-256 is
  `ef4aba38c9c658cdf34b395a990abceff05b13e0458734e8923f16213438e94d`.

PowerShell 5.1 and 7 accept that authentic report. The destination-local
adversarial audit accepts both authentic host cases and rejects all `16/16`
host/mutation cases; its 15,680-byte result SHA-256 is
`8815c156e5fb451e4cc44afb17c2d98e1118d5c4356a5891eda98ab5d922619e`.
Final audit SHA-256
`503c4da1b8f72eab3f8fe2f39f7a61a41b73144e2f11b94225942a910a595935`
passes 14 exact merge blobs, nine unchanged active lockfiles, 26 backups, zero
product processes/pending files/temporary roots, and the unchanged protected-
vault invariant.

Checkpoint 2272 is closed. Verified scope remains fixed hosted Ubuntu 24.04 and
macOS 15 runners plus the synchronized Windows destination. Storage hardware
truthfulness, Windows removal durability, other filesystems/devices/identities,
Android, privileged or hostile filesystem actors, package-wide power-loss
transactionality, production signing/deployment, driver/pre-execution
enforcement, Defender replacement, and the complete antivirus-hardening goal
remain partial, blocked, or technically limited.

## Remaining Limits

Durability barriers are best-effort user-mode filesystem evidence. They do not
prove truthful storage hardware, battery-backed caches, every filesystem,
network filesystem replay behavior, Windows deletion durability, protection
against administrators/root/SYSTEM or a hostile filesystem, recovery after key
loss/disclosure, or one atomic transaction spanning services, files, engine
components, reports, and rollback. A directory sync can fail after a rename;
Avorax reports that state and preserves authenticated evidence instead of
claiming success.

Android runtime, installed elevated-service identity, VM power-cut testing,
production signing/deployment, signed-driver/pre-execution enforcement, and
Defender replacement remain partial, blocked, or technically limited.

No live malware, EICAR, Defender weakening, protected-vault mutation,
machine-wide installation, service/driver start, release, or publication is
part of this checkpoint. The protected quarantine remains exactly 16,072 files,
zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`, `.json`, and `.auth`,
one `.metadata_auth_key`, and zero pending. The complete antivirus-hardening
goal remains active.
