# Checkpoint 2275 Atomic Existing-File Replacement

Date: 2026-08-30

Status: **Collision-safe repair local closure evidence passed / hosted and integration evidence pending**

## Purpose

Checkpoint 2275 removes the update service's deliberate remove-before-activate
window for existing loose files. Before this checkpoint, staged copy/write
activation deleted a validated existing target and then moved the staged file
into the absent name. Process termination or a later activation failure could
leave an app or service file missing.

No checkpoint-2275 test ran during the scripting phase. Production code,
harmless and adversarial regressions, hosted runtime wiring, Source contract
706, the existing 302-step verifier contract, exact report validation, and all
audit/operational documentation were written first as one reversible batch.

## Scripted Protocol

1. Revalidate the staged source, existing destination, and shared parent as
   ordinary non-link/non-reparse filesystem objects.
2. Require source and destination to be distinct adjacent names.
3. Open both files and bind each current path to its opened file identity
   immediately before the operating-system replacement call.
4. On Windows, reserve a unique adjacent hard link to the opened previous
   destination through no-overwrite creation. Every colliding candidate is
   preserved. Snapshot the opened staged-source file ID, close that source
   handle because `ReplaceFileW` opens the replacement without sharing, then
   call `ReplaceFileW` with a null API backup parameter and no unsupported
   flags. On success, rebind the active destination to the staged-source ID and
   the reserved backup to the retained previous-destination handle before
   checked backup removal.
5. If a failed Windows call left the destination absent, require the reserved
   backup to identify the already-opened previous destination,
   then restore it through the existing write-through no-replace primitive and
   rebind the restored name. Reject a mismatched/spoofed backup. If both
   destination and the identity-bound backup exist, preserve both and report
   the ambiguous state. If no backup exists, accept that failed-call state only
   after proving the destination still identifies the opened old file.
6. On Unix, use same-directory atomic `rename`, bind the resulting destination
   to the staged source handle, and synchronize the stable parent-directory
   handle before success.
7. Keep initially absent destinations on the existing OS no-replace path so a
   competing final object is preserved.
8. Never use an unsupported replacement fallback and never convert identity,
   synchronization, backup, cleanup, or inspection failure into success.

## Scripted Benign And Adversarial Fixtures

All fixtures contain harmless ASCII bytes in isolated temporary directories
and are never executed:

- an existing adjacent regular file is replaced and no temporary backup
  remains after complete success;
- a non-adjacent source is rejected before either file changes;
- source and destination hard links to the same file identity are rejected
  before mutation;
- a pre-existing Windows backup candidate remains byte-for-byte unchanged and
  reservation proceeds only through no-overwrite hard-link creation at another
  candidate;
- sixteen occupied Windows backup candidates remain byte-for-byte unchanged and
  bounded reservation fails visibly before replacement;
- a Unix symbolic-link destination is rejected and its external target is
  preserved;
- Windows failure reconciliation restores an existing backup to a missing
  destination through no-replace activation;
- a Windows failure without a backup is accepted only while the destination
  still identifies the opened old file; missing-both state fails visibly;
- an ambiguous Windows destination-plus-backup state preserves both files;
- a mismatched Windows backup is rejected and never restored to a missing
  destination;
- the update-service existing-target, absent-target, collision, parent-chain,
  non-regular, and long-absolute-Windows-path fixtures use the new split route;
- source contracts forbid `std::fs::remove_file(target)` in staged activation,
  require the native replacement/identity/backup/sync boundaries, pin exact
  Linux/macOS hosted tests, and require current verifier/validator/docs text.

The verifier retains exactly 302 steps by replacing the historical staged-file
step with `update-service staged file activation atomic replacement
regressions`, filtered by `staged_activation_atomic_replace_`. The full-suite
validator requires that exact step and the new verified/technical-limit scope.

## Honest Limits

This is one loose-file namespace operation, not an atomic package transaction.
App files, service files, docs, engine components, rollback snapshots, reports,
and service stop/start remain separate operations. Windows documents that
`REPLACEFILE_WRITE_THROUGH` is unsupported, so this implementation passes zero
flags. An abrupt process termination or exceptional Windows replacement state
can leave the previous file only at the adjacent
`.avorax-replace-backup` name; that evidence is preserved for manual review.
The checkpoint does not yet add an authenticated loose-file recovery journal.
Hard-link backup reservation requires same-volume filesystem hard-link support
and fails visibly where it is unavailable.
The Windows source handle must close before `ReplaceFileW` performs its
unshared replacement-file open, so source identity is point-in-time until the
active destination is rebound to the captured file ID after the call.

Unix parent-directory synchronization is best-effort user-mode durability
evidence. Network or hostile filesystems, dishonest storage caches, replay or
reordering, a same-identity race after the last path/handle check,
administrators, SYSTEM/root, kernel compromise, and power loss remain outside
the guarantee. Unsupported platforms fail visibly.

This checkpoint changes update activation only. It changes no detector,
signature/rule/hash intelligence, custom-engine responsibility, verdict
threshold, quarantine authority, realtime monitor, driver/pre-execution claim,
or Defender relationship. No live malware or EICAR fixture is used. Defender
is not weakened, no machine-wide component is installed or started, and no
release or publication occurs. The protected vault must remain exactly 16,072
files, zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`, `.json`, and
`.auth`, one `.metadata_auth_key`, and zero pending. The complete
antivirus-hardening goal remains active.

## Superseded Pre-Collision-Repair Verification

Focused verification after the script freeze produced this evidence:

- the first Source run executed 706 contracts and exposed two stale historical
  checkpoint-2267 scope strings; after exact contract repair, two complete runs
  pass `706/706`;
- the first Windows replacement run passed both pre-mutation rejections but
  failed success activation `2/3` with `ERROR_SHARING_VIOLATION`, proving that
  `ReplaceFileW` cannot run while the staged source handle remains open;
- after preserving the verified source file ID, closing that handle, and
  rebinding the active name after the call, replacement passes `3/3` and all
  Windows recovery/adversarial fixtures pass `5/5`;
- update staged activation passes `6/6`; directory/non-regular rejection passes
  `2/2`;
- strict platform and update-service Clippy pass; Rust formatting, PowerShell
  verifier/validator parsing, and `git diff --check` pass.

No focused fixture executed a payload or touched the protected vault. The full
local regression then passed:

- strict locked workspace Clippy;
- both locked workspace test variants, including exact all-target/all-feature
  totals of 1,801 executed tests, 21 intentionally ignored child fixtures, and
  zero failures;
- locked all-target/all-feature release build;
- Flutter analysis plus `852/852` tests;
- Zentor protocol analysis plus `14/14` tests and Avorax protocol analysis plus
  `6/6` tests.

The final-source no-skip/no-Defender verifier passed exact `302/302` in 720.3
seconds with zero failed, skipped, or error-bearing steps and Defender/EICAR
opt-in disabled. Its 232,230-byte JSON report has SHA-256
`8cdec8f3d30f279a0faad434cd3238235e9fa7000526dcafc0919b2e36148867`.
Independent Windows PowerShell 5.1 and PowerShell 7 validation each accepted
the authentic report. The same two hosts rejected all 28 host/mutation cases
covering 14 unique missing, stale, count, status, tool-host, and report-path
mutations. The 26,716-byte adversarial result has SHA-256
`a47ed3f1d7f2c0f75a1d69900748e03ccd2d9a2b82a56caa12300bc3e3428571`.

No local fixture executed a payload, installed or started a product component,
changed Defender, downloaded an artifact, or touched the protected vault.
The final read-only local audit passes the exact 15 modified plus one added
path set with zero deletions, nine unchanged dependency lockfiles, zero product
process/pending/temp residue, and the protected-vault invariant. Its 1,892-byte
JSON evidence has SHA-256
`5793f7a6fbbc4da9b18855f7905816f909e6b621e5f42bd46b789c431e0cc7e8`.

Final diff review then found that `ReplaceFileW` overwrites an already-existing
API backup path. A harmless isolated Win32 probe confirmed the competing bytes
were replaced by the old destination. This makes all evidence above historical
and superseded for final-source credit. The scripted repair reserves the old
destination under an adjacent no-overwrite hard link, preserves every
collision, and passes a null backup parameter to `ReplaceFileW`; the platform
regression and source/verifier/document contracts now require that boundary.
After the repair batch froze, focused repaired-source evidence passes Source
`706/706`, replacement `3/3`, reservation/recovery `7/7`, update activation
`6/6`, update rejection `2/2`, strict platform/update Clippy, Rust formatting,
four PowerShell parsers, and `git diff --check`.

Complete repaired-source regression then passes strict locked workspace Clippy,
both locked workspace test variants, locked all-target/all-feature release,
Flutter analysis plus `852/852`, Zentor protocol analysis plus `14/14`, and
Avorax protocol analysis plus `6/6`. The exact all-target/all-feature Rust run
executes 1,803 tests, intentionally ignores 21 native child fixtures, and has
zero failures. All nine tracked dependency lockfiles remain byte-unchanged
against `origin/main`.

## Remaining Hosted And Integration Verification

- the hosted Windows full platform suite plus exact Linux/macOS replacement
  fixtures;
- exact-head CI/packages, bounded artifact metadata/log review, normal PR/merge,
  merged-main evidence, guarded zero-delete destination synchronization, and
  definitive destination verification.

No hosted or integration result in this remaining list is claimed before
execution.

## Defender-Safe Verifier Harness Repair

The first definitive run after the collision-safe replacement repair is
retained as failed evidence. It recorded 297 passing steps, then the
`False-positive gate` failed because Microsoft Defender removed the generated
Native unit-test executable as inactive `Trojan:Win32/Wacatac.C!ml`. Cargo
reported OS error 225 before the three requested Native benign tests could
start. Defender reports `DidThreatExecute=False`; no exclusion or security
weakening was applied. The failed report records 298 steps in 716.9 seconds,
is 228,184 bytes, and has SHA-256
`da9d426f915bf9d1010b335fff3587d5d2f9e98e9cec414ccd1b0407f4d12da0`.

The failure exposed a verifier architecture problem rather than a scanner
assertion: the late benign gate repeatedly relaunched the same large unit-test
harness that contains the Native engine's adversarial detection fixture corpus.
The scripted repair adds `tests/benign_false_positive_gate.rs`, a small
integration target that links the production library without compiling its
`cfg(test)` fixture modules. It initializes from bundled assets, uses only
harmless temporary ASCII files, scans detect-only, requires clean/likely-clean
or observation verdicts as appropriate, rejects invented trusted-publisher
evidence, and proves no quarantine directory or record is created.

The late gate runs all three tests in that target once. The verifier's earlier
normal-executable guard selects the same target explicitly, CI prebuilds it
with the lockfile, Source contracts prevent a return to the monolithic gate,
and report/adversarial validation requires the honest harness scope. This does
not remove, skip, or replace the full Native unit-test regression suite and does
not establish a production false-positive rate. No new harness test ran during
this repair scripting phase.

After that scripting batch froze, formatting, five PowerShell parsers, diff
checks, Source `707/707`, and strict integration-target Clippy pass. The
dedicated target passes all three benign scans, the complete false-positive
gate passes, and the no-malware-binaries gate passes with Defender active.
Read-only Defender history has zero detections for the dedicated target. Its
current 3,235,328-byte binary SHA-256 is
`8dd534b6956aef8bd33c9f5e34459c492917b09eace530c9544e7b2f0da56906`.
Broad regression and regenerated definitive evidence remain mandatory.

The subsequent broad rerun passes strict locked workspace Clippy, both locked
workspace test variants, the locked all-target/all-feature release build,
Flutter analysis plus `852/852`, and protocol analysis/tests `14/14 + 6/6`.
The exact Rust total is 1,806 executed tests, 21 intentional Native child-fixture
ignores, and zero failures; this includes the three-test benign integration
target. All nine tracked dependency lockfiles remain unchanged. Regenerated
exact-302, adversarial, and audit evidence remain pending.

The regenerated definitive run passes exact `302/302` in `708.4s`, with zero
failed, skipped, or error-bearing steps and Defender/EICAR opt-in disabled. Its
232,732-byte report SHA-256 is
`13998e76443539d9eac4d9c38940a82d26011cc490c801d16de23df4f8edd3f0`.
The atomic replacement step passes in `2.9s` and the dedicated late
false-positive gate passes in `5.1s`. Both PowerShell hosts accept the authentic
report and reject all 34 host/mutation cases across 17 unique adversarial
changes. The 32,960-byte result SHA-256 is
`3ea4610cdb1e89df351a454efbee340ab7395ee3ce2faac802ab390bf9655c9a`.
The original Defender-blocked run remains archived failed evidence. The final
audit result follows; hosted/integration evidence remains pending.

The warning-free final read-only audit then passes the exact 16 modified plus
two added paths, zero deletions, nine unchanged lockfiles, zero product
process/pending/temp residue, and the exact protected-vault invariant. Its
2,114-byte JSON SHA-256 is
`98627e5c9dc3de32c885212e2770edb49eb28ec1734af6b55bfc4f37fd57f1c2`.
Only hosted/integration and destination closure evidence remains for this
checkpoint.
