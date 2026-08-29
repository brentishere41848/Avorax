# Checkpoint 2268 - Update Directory No-Replace

Status: **Closed through hosted integration and synchronized destination verification**

Date: 2026-08-29

## Objective

Prevent update tree replacement and rollback directory activation from
overwriting a backup or destination created after point-in-time preflight.
Preserve fail-visible errors and all recoverable directory state without
claiming a whole-update transaction.

## Scripted implementation

- Added `rename_directory_no_replace` to the shared platform-security crate.
  Both file and directory APIs use one target-specific implementation:
  zero-flag `MoveFileExW` on Windows, `renameat2(RENAME_NOREPLACE)` on
  Linux/Android, and `renamex_np(RENAME_EXCL)` on Apple. Unsupported targets
  fail visibly.
- Replaced ordinary directory renames in update tree activation for
  destination-to-backup, staging-to-destination, and backup recovery.
- Applied the same three-move contract to rollback directory activation.
- Preserved full activation and recovery error chains. A recovery collision
  does not replace the competing destination or delete the original backup.
- Added hookable internal activation helpers solely to place deterministic,
  harmless race fixtures in the two production preflight-to-move windows.

## Scripted verification

- Two platform tests cover absent destination success and competing directory
  preservation.
- Two update-tree tests cover a backup created after preflight and a destination
  created after backup movement.
- Two rollback tests cover the same windows.
- Source contract 699 requires all six no-replace calls, forbids ordinary rename
  in both production modules, inventories the fixtures, and binds documentation.
- Definitive verifier step 296 runs the four update-service race fixtures.
- The validator requires exactly 296 steps plus verified and technically
  limited scope text.
- Seven report mutations run under PowerShell 5.1 and 7, for 14 required
  rejections after both hosts accept the authentic report.

No checkpoint-2268 test ran during the scripting phase. All counts above are
scripted expectations, not credited execution evidence.

## Control and engine accounting

The changed controls are the shared directory no-replace primitive, update tree
backup/activation/recovery, and rollback backup/activation/recovery. Hash and
signature matching, local rules/YARA, static file and PE analysis, archive
limits, bounded heuristics, ML, Authenticode, process observation, allowlists,
exclusions, caching, quarantine actions, thresholds, custom engine
responsibilities, and explainable verdict aggregation are unchanged and retain
their existing verified, partial, disabled, blocked, or technically limited
states. No dead control or fake success is introduced: unsupported primitives,
activation collisions, and recovery collisions return visible errors.

## Technical limits

Directory no-replace protects only the three final-name moves within each user-
mode update or rollback directory activation. Service stop/start, file-item
updates, cleanup, crash recovery, and multiple component activations are not one
transaction. A crash can leave the original directory in a sibling backup or
the destination absent. A competing destination can require manual recovery
from the preserved backup. Path and ancestor checks remain point-in-time;
unsupported platforms fail visibly, and administrators, SYSTEM/root, hostile
filesystems, or kernel compromise remain outside the guarantee. This is not an
installed privileged-service, signed-driver, or pre-execution claim.

## Safety and invariants

Fixtures contain only inert ASCII marker bytes in isolated temporary
directories and are never executed. No live malware, EICAR, network content,
Defender weakening, machine-wide installation, service/driver start,
quarantine-vault mutation, force reset, direct-main push, release, or
publication is authorized. `C:\ProgramData\Avorax\Quarantine` remains read-only
at the protected invariant: 16,072 files, 0 directories, 4,522,733 bytes, 5,357
each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.
`.verification` remains untracked and must never be staged or deleted.

## First focused failure and repair

The initial platform filter passed `2/2`. The update-service filter compiled and
passed `3/4`, then `MoveFileExW` returned error 123 before the intended race
because a nested Rust path retained `/` after Windows verbatim prefixing. The
run is not credited. The repair normalizes separators before namespace
validation and extends the platform absent-destination fixture to a nested
forward-slash path. No post-repair test had run when this repair was scripted.

Post-repair focused `2/2 + 4/4`, Source `699/699`, platform `17/17`, and update
service aggregate `216/216` pass. The first strict Clippy 1.96 run reached every
changed crate cleanly, then failed on three pre-existing API layout lints. Three
narrow source attributes retain externally tagged event names and adjacent
source-contract test placement without changing serialized values or runtime
behavior. The failed lint run is not credited; a repeat is required.

Strict Clippy subsequently passes, and the all-target/all-feature locked root
workspace passes with Native Engine `642 passed` plus 21 intentional child-
fixture ignores. A documented `core\Cargo.toml` command was rejected before
compilation because no such workspace manifest exists; it is uncredited and
corrected to the established default locked root-workspace command.

## Local broad evidence

The repaired batch now passes format, PowerShell 5.1/7 parsing, focused platform
`2/2`, focused update/rollback `4/4`, dependency-free Source `699/699`, platform
`17/17`, aggregate update service `216/216`, strict all-target/all-feature
Clippy, both locked root-workspace variants, and the locked all-feature release
build. Native Engine reports `642 passed` with 21 intentional isolated child-
fixture ignores in each workspace variant. Flutter analysis and client tests
pass `852/852`; protocol analysis/tests pass `14/14 + 6/6`.

No tracked lockfile changed. Post-run audit reports zero product processes, zero
repository pending files, and the exact protected-vault invariant. Exact-296
definitive verification, dual-host adversarial validation, hosted exact-head
evidence, integration, guarded original-tree synchronization, destination
verification, and closure remain pending. These local results do not expand the
technical scope or close the complete antivirus-hardening goal.

## Remaining work

Run focused checks only after this complete scripting batch is frozen, then
broad local regressions, strict lint/locked builds, exact-296 definitive
verification, dual-host adversarial validation, hosted exact-head CI/package
evidence, normal PR integration, guarded original-tree synchronization, and
destination verification. Installed authority, Android runtime evidence,
production signing/deployment, driver/pre-execution behavior, Defender
replacement, and the complete antivirus-hardening goal remains active.

## Definitive local evidence

The final-source definitive command completed with exit code 0 in `673.5s`.
Its 223,673-byte JSON report records status `passed`, exactly `296/296` passed
steps, no failed steps, Defender/EICAR opt-in `false`, Flutter skip `false`, and
Rust skip `false`. The new `update-service directory activation atomic no-
replace regressions` step passed in `0.3s`. Report SHA-256 is
`8b87d0aa72cd0ee51d0c2b6ff9d1ac87dbb392ad19298b4a704a94b2f0f8970c`.

The verifier's integrated Windows PowerShell 5.1 and PowerShell 7 validators
both accepted the authentic report. The independent adversarial script then
accepted the authentic report on both hosts and rejected all seven mutations
on both hosts, exact `14/14`. Its 16,805-byte result SHA-256 is
`217771abe632d0647aef3071654190609e367d120ec7afdfaee6ffd057033826`.
An initial adversarial invocation used the nonexistent handoff parameter
`WindowsPowerShellPath`, stopped at parameter binding, and is uncredited; the
supported `PowerShell5Path` invocation is the recorded passing run.

The post-definitive read-only audit reports zero product processes and zero
repository pending files. The protected vault remains exactly 16,072 files,
zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
`.metadata_auth_key`, and zero pending. Active lock hashes remain
`50841a39418e4f9ea8c1e76e11518ab406fb7255013bbd9d06ec158219427f8a`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Hosted exact-head, normal PR integration, merged-main, guarded synchronization,
destination verification, and closure remain pending. The complete antivirus-
hardening goal remains active.

## Hosted implementation-head evidence

Exact implementation commit
`821d17666fd5739525c3803c15c98341046035eb` is the head of normal PR `#145`.
Avorax CI run `33253639931` passes all five jobs. Desktop Packages push run
`33253626820` and PR run `33253639896` pass package contracts, Linux x64,
Windows x64 MSI/EXE with non-installing administrative extraction, macOS arm64,
macOS x64, consolidation, checksums, and lockfile SBOM generation. Publication
is skipped in both runs.

The untouched push consolidated artifact `9715355338` is 132,522,285 bytes with
SHA-256
`3d13592cc487928e2eb2e3e52b648ed131237a335b12552cf8dce89d86d209fd`.
The untouched PR artifact `9715311146` is 132,521,280 bytes with SHA-256
`966977a56e6740963346c7464c7ed1b4ac6d9f89941c563c52d7f30507503a0b`.
Bounded in-stream review of each verifies exactly eight safe root entries, six
platform packages, seven matching checksum targets, and CycloneDX 1.6 with 569
components. Neither ZIP was extracted or executed. The retained validation
result SHA-256 values are
`062d71c7d977c888164a17472c7f70bd61ff537fd574a001f92bd4e852ac113b` and
`c26ef57d6f0683253a3658118ba72ccfb9e81ce30c701c11bb52ba26a98b637a`.

Evidence-head CI/packages, normal merge, merged-main CI/packages, guarded
synchronization, destination verification, and closure remain pending. Hosted
build evidence does not prove cross-platform runtime semantics, whole-update
transactionality, production signing/deployment, installed authority,
driver/pre-execution behavior, or Defender replacement.

## Evidence Head And Normal Integration

Evidence commit `635ccc21e3b7d106c33dd5bd719fdc22926e209f` passes Avorax
CI `33254651157` and Desktop Packages `33254651121`; publication is skipped.
Consolidated artifact `9715575145` is 132,522,226 bytes with SHA-256
`803fdc2f63f63c21a7f56474f7b22df02d7a946344f5961e00707c7af5a79e77`.
Bounded stream validation, without extraction or execution, confirms exact
8-root/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components;
the 606-byte validation result SHA-256 is
`653ea925f3b3ad188a2b8ca4c206942b21d577e29b7797a259c81debd05ad64c`.

PR `#145` merges normally as
`99891d10c387c196f84b30630e2177ba7e8a9333`. Merged-main Avorax CI
`33255233149` and Desktop Packages `33255233172` pass; publication is skipped.
Artifact `9715798339` is 133,137,514 bytes with SHA-256
`9d9acefdf87d186d81b5975cae9adbb6c9899ba7415d97aff5067478c45b915c`
and passes the same bounded non-extracting/non-executing review. The 604-byte
validation result SHA-256 is
`70b2dbcc635ec37dc7107c48edb591213b9d1053448ac10d1d5fbc46f8fe3e88`.

## Guarded Synchronization And Destination Evidence

Guarded synchronization applies exactly 17 modified plus one added project
path with zero deletes. The sync report SHA-256 is
`586ef969e3a21ec729a0afd82eda85123575b548809dadf614c6160c505249ff`;
all 34 expected before/replaced backup files are present.

At `C:\Users\Brent\Documents\Avorax-main`, PowerShell 5.1/7 parsing,
formatting, Source `699/699`, focused platform `2/2`, focused update/rollback
`4/4`, platform `17/17`, update service `216/216`, strict lint, both locked
workspace variants, locked all-feature release, Flutter analysis plus
`852/852`, and protocol analyses/tests `14/14 + 6/6` pass. The no-skip/no-
Defender verifier passes exact `296/296` in `665.0s`. Its 214,543-byte report
SHA-256 is
`77cecb9be36bc4350dcf1e321e1c7cc0e11ea52b0303da1554f9c9c993da02e7`.

PowerShell 5.1 and 7 accept the authentic destination report and reject all 14
adversarial host/mutation cases. The 12,970-byte adversarial result SHA-256 is
`3bcc0829a3d972e49c23ba77d8691377822f2841cf6cee61955d93c6d1a9ea32`.
The first final-audit invocation failed visibly because the previously recorded
checkpoint-2194 temporary root was absent. Read-only inspection found zero
Avorax/Zentor temporary roots; the corrected audit records that absence and
still rejects every unexpected root instead of fabricating preservation.

Final destination audit SHA-256
`8826367c8fbd9e79622311f8f2f92095bd3c4e999ec6b77f7cd051a83676d066`
passes 18/18 exact merge blobs, 8/8 active lockfiles, 34 backups, zero product
processes or pending/temporary roots, and the exact read-only vault invariant.

Checkpoint 2268 is closed. Every documented whole-update transaction, crash/
manual-recovery, point-in-time path, privileged-actor, hostile-filesystem,
cross-platform runtime, installed service/driver, pre-execution, signing/
deployment, Defender-replacement, and whole-project limit remains active.
