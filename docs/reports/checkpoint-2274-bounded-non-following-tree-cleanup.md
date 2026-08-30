# Checkpoint 2274 Bounded Non-Following Tree Cleanup

Date: 2026-08-30

Status: **Post-repair definitive local verification passed; hosted evidence pending**

## Purpose

Checkpoint 2274 removes the shared update-service dependency on unrestricted
recursive tree deletion. It makes cleanup structure, resource limits, mutation
ordering, and errors explicit without claiming atomic or durable deletion.

No checkpoint-2274 test ran during the scripting phase. Production code,
harmless/adversarial regressions, Source contract 705, verifier step 302, exact
report-validator requirements, and all audit/operational documentation were
written first as one reversible batch.

## Scripted Protocol

1. Require a non-link/non-reparse directory root.
2. Inventory the complete tree without mutation in post-order.
3. Cap the tree at 100,000 entries, depth 128, 8 GiB of logical regular-file
   bytes, and 16 MiB of aggregate encoded path payload with checked arithmetic.
4. Validate every existing path chain and every nested item against symbolic
   links and Windows reparse points.
5. Accept only regular files and directories; reject special filesystem
   objects with a visible error.
6. Begin mutation only after the complete inventory succeeds.
7. Revalidate every path chain, item kind, and reparse status immediately before
   its explicit `remove_file` or `remove_dir` operation.
8. Require every removed name to remain absent; never fall back to
   `std::fs::remove_dir_all` and never swallow an error.

The primitive is shared by update staging cleanup, atomic tree replacement,
rollback cleanup, and authenticated activation-recovery cleanup tombstones.

## Scripted Benign And Adversarial Fixtures

All fixtures use harmless ASCII bytes in isolated temporary directories and are
never executed:

- a bounded nested regular tree is fully removed while its parent remains;
- an entry-count excess fails before any mutation;
- a depth excess fails before any mutation;
- a logical regular-file byte excess fails before any mutation;
- an aggregate encoded path-payload excess fails before any mutation;
- a regular file replaced by a directory between inventory and deletion fails
  visibly and preserves the replacement;
- a regular file that changes logical size after inventory fails visibly and
  remains present;
- a Unix nested symbolic link blocks cleanup and preserves its external target;
- a source contract requires explicit file/empty-directory removal and forbids
  recursive deletion fallback;
- authenticated recovery preserves its cleanup journal and tombstone when a
  nested link makes removal unjustifiable.

The verifier adds `update-service bounded non-following tree cleanup
regressions` with filter `checked_tree_cleanup_`. Full-suite report validation
requires exactly 302 steps plus exact verified-scope and technical-limit text.

## Failure Policy

- Limit or arithmetic overflow fails before mutation.
- A nested link/reparse point or unsupported object is never deleted.
- Missing, type-changed, reappearing, or non-empty entries fail visibly.
- Once deletion begins, a later failure may leave a partial tombstone tree; the
  remaining state and authenticated journal are not reported as cleaned.
- No cleanup error is converted into success or ignored.

## Honest Limits

Inventory and per-entry revalidation are point-in-time user-mode checks. They
do not defeat a same-identity hostile filesystem race, prior open handle,
administrator, SYSTEM/root, hostile filesystem, storage replay/reordering,
kernel compromise, or dishonest device cache. Explicit empty-directory removal
is safer and bounded but is not atomic, durable-delete proof, or secure erasure.
The update remains a per-tree recovery protocol rather than one package-wide
transaction.

No detection engine, custom engine, verdict threshold, quarantine authority,
realtime monitor, signed driver, pre-execution claim, or Defender relationship
changes in this checkpoint. No live malware or EICAR fixture is used. Defender
is not weakened, no machine-wide component is installed or started, and no
release or publication occurs. The protected vault remains exactly 16,072
files, zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`, `.json`, and
`.auth`, one `.metadata_auth_key`, and zero pending. The complete
antivirus-hardening goal remains active.

## Superseded Pre-Repair Evidence

All execution occurred after the scripting freeze:

- format and `git diff --check` pass; Source contracts pass `705/705`;
- Windows `checked_tree_cleanup_` passed `7/7`; activation recovery passed
  `30/30`; update service passes `4 + 247`;
- strict locked Clippy, both locked workspace variants, and the locked all-
  target/all-feature release build pass;
- Flutter analysis and `852/852` tests pass; protocol suites pass
  `14/14 + 6/6`;
- the definitive report passes exact `302/302` with zero skipped or failed
  steps, zero non-null step errors, and Defender/EICAR integration disabled in
  694 seconds;
- the 231,383-byte definitive report has SHA-256
  `326f4755e9d86e972e64a02da317d9ac6daa82ca118a0b34c34a7ceee6073829`;
- Windows PowerShell 5.1 and PowerShell 7 both accept the authentic report and
  reject all `24/24` adversarial host/mutation cases; and
- final read-only audit passes the exact 13 modified plus one added path set,
  zero deletions, nine unchanged lockfiles, zero product process/pending/temp
  residue, and the protected-vault invariant.

This report does not credit those results to current HEAD. Final diff review
found that the 16 MiB counter covered only basenames while the inventory retained
full paths. The complete repair counts aggregate encoded path payload,
updates source/report contracts, and adds a before-mutation path-payload limit
fixture.

## Post-Repair Definitive Local Evidence

- format/diff and Source `705/705` pass;
- Windows cleanup passes `8/8`, recovery `30/30`, and update service
  `4 + 248`;
- strict locked Clippy, both locked workspace variants, and locked all-target/
  all-feature release pass;
- Flutter analysis and `852/852` pass; protocols pass `14/14 + 6/6`.
- final-source definitive verification passes exact `302/302` in `669.6s`,
  with zero failed/skipped/error steps and Defender/EICAR opt-in disabled;
- the 231,397-byte report has SHA-256
  `7daf28a3904c16a356550afb44a0b7233699b371f3c4d119239ef44979c3bc63`;
- Windows PowerShell 5.1 and PowerShell 7 accept the authentic report and reject
  all `24/24` adversarial host/mutation cases; and
- final read-only audit passes the exact 13 modified plus one added path set,
  zero deletions, nine unchanged lockfiles, zero product process/pending/temp
  residue, and the protected-vault invariant.

The superseded report remains historical only; the evidence above is the
current final-source local result.

## Remaining Evidence

Windows does not execute the nested-link primitive and authenticated-recovery
fixtures gated by `cfg(unix)`. Exact-head hosted Ubuntu must run both before
cross-platform runtime credit. Exact-head CI/package review without extraction,
execution, or publication; normal PR merge; merged-main checks; guarded zero-
delete destination synchronization; full destination regression; and closure
audit remain pending. Checkpoint 2274 and the complete antivirus-hardening goal
remain active.
