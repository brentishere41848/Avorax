# Checkpoint 2274 Bounded Non-Following Tree Cleanup

Date: 2026-08-30

Status: **Closed through hosted integration and synchronized destination verification**

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

## Pre-Hosted-Coverage-Repair Definitive Local Evidence

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

Initial exact-head CI `33306480962` passed, but raw logs showed that the Ubuntu
job filtered only existing recovery-runtime tests and did not execute either
new `cfg(unix)` link fixture. The workflow now invokes both tests by fully
qualified name with `--exact`, and Source contract 705 pins that route. Because
this is a tracked workflow/test-contract repair, the evidence above remains
valid pre-repair history but is not current final-source credit.

## Final-Source Hosted-Coverage-Repair Local Evidence

- the first Source run failed visibly because the existing Ubuntu-job contract
  expected 13 Cargo commands and four fail-fast shells;
- the repaired contract requires exact 15 commands, five fail-fast shells, the
  dedicated step, both fully qualified Unix test names, and `--exact`;
- Source passes `705/705`; format/diff, cleanup `8/8`, recovery `30/30`, and
  update service `4 + 248` pass;
- definitive verification passes exact `302/302` in `665.5s`, with zero
  failed/skipped/error steps and Defender/EICAR opt-in disabled;
- the 231,401-byte report has SHA-256
  `73f63eef30abbb2e1109ce112224128dc87717e9c6ba4363eb8d3842beb49552`;
- both validator hosts accept the authentic report and reject all `24/24`
  adversarial cases; and
- final audit passes 14 modified plus one added path, zero deletions, nine
  unchanged locks, zero product process/pending/temp residue, and the protected-
  vault invariant.

## Exact Implementation-Head Hosted Evidence

Final implementation head
`c91519af3e03e8254e6dc215d9528f70a80fc2f5` passes all six Avorax CI jobs in
PR run `33307588267`. Ubuntu 24.04 job `99246758706` contains the dedicated
`Test bounded cleanup Unix link safety` step. Its raw log proves non-empty exact
execution:

- `path_safety::tests::checked_tree_cleanup_nested_link_fails_before_mutation`:
  `running 1 test`, named `ok`, `1 passed; 0 failed`;
- `activation_recovery::tests::activation_recovery_checked_tree_cleanup_nested_link_preserves_evidence`:
  `running 1 test`, named `ok`, `1 passed; 0 failed`.

Desktop Packages PR run `33307588380` passes package contracts, Windows x64
MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, and consolidation. The
consolidation job requires six platform files, creates seven release checksums,
and reports CycloneDX 1.6 with 569 lockfile components. The prerelease
publication job is skipped. GitHub metadata binds all five retained workflow
artifact bundles to the same implementation head. Consolidated artifact
`9731114476` is 132,719,373 bytes with Actions archive SHA-256
`a62b1e98c5dd161031216445c18f1666b42ef0517071e5257fffc7d28cb839a4`;
the four platform evidence artifacts are `9731098756`, `9731024272`,
`9731041481`, and `9731109966`. Inspection was limited to GitHub metadata and
bounded workflow-log evidence; no artifact was downloaded, extracted, or
executed, and no release was published.

## Evidence-Head, Merge, And Destination Closure

Evidence head `8fe3cec18181546e7bf6e7bd1ac4deaa193d32b8` passes all six
Avorax CI jobs in run `33308297789`. Ubuntu 24.04 job `99248653943` executes
both dedicated cleanup link fixtures by fully qualified name with `--exact`;
each reports `running 1 test`, its exact name as `ok`, and `1 passed; 0 failed`.
Desktop Packages run `33308297858` passes contracts, Windows x64 MSI/EXE,
Linux x64 DEB/tar, both macOS DMGs, and consolidation with publication skipped.
Consolidated artifact `9731350472` is 133,268,182 bytes with Actions archive
SHA-256 `e8397280378ec308a70610f64418ce12e75e1fe54e74fc7bb3bf0eb671d97dba`.

Normal PR `#157` merges as
`59fb56d732d949f347f334b2504a09570dd73fbe`. Merged-main CI run
`33308936338` passes all six jobs; Ubuntu job `99250355386` again proves exact
non-empty `1/1 + 1/1` execution. Desktop Packages run `33308936319` passes all
build and consolidation jobs with publication skipped. Consolidated artifact
`9731641198` is 132,667,431 bytes with Actions archive SHA-256
`70b976f1d77ec7359c44d3e48a532c382432f1ac32f201173dd7bf3ae1bd354b`.
Both package runs prove six release files, seven checksums, and CycloneDX 1.6
with 569 components. Review used metadata and bounded logs only; no artifact
was downloaded, extracted, or executed.

Guarded synchronization applies exact 14 modified and one added path with zero
deletes and preserves 28 verified backups. Sync-report SHA-256 is
`ceb2c4d2680011b1a41b9630be536906198f03395e2d08877128d9818fa6b462`.
The synchronized `C:\Users\Brent\Documents\Avorax-main` destination passes
Source `705/705`, Rust format, strict locked all-target/all-feature Clippy, both
locked workspace test variants, locked all-target/all-feature release, Flutter
analysis and `852/852`, and protocol analysis/tests `14/14 + 6/6`.

The destination no-skip/no-Defender verifier passes exact `302/302` in 668
seconds. Its 222,657-byte report SHA-256 is
`c4a95e939462465ce62fe2f6a0a68409906d520870c1c3a8f53ae531a591e0e1`.
PowerShell 5.1 and 7 accept both authentic host cases and reject all `24/24`
host/mutation cases, covering twelve mutations on each host. The 20,094-byte
adversarial result SHA-256 is
`7328b2ee5762de84f1d3054e24554f10aae2f20bad2f8442abf466210b6b014f`;
no content mutation is rejected only by an unexpected candidate-path boundary.
Final audit SHA-256
`d15e592a1f11f361dcfd737bfeed8807552881dcaa4e6f5f955b2570416991db`
passes all 15 exact merge blobs, nine unchanged active lockfiles, 28 backups,
zero product processes/pending files/temporary roots, and the unchanged
protected-vault invariant.

Checkpoint 2274 is closed. Bounded cleanup remains point-in-time user-mode
evidence rather than atomic or durable deletion. Same-identity races, open
handles, administrators/SYSTEM/root, hostile filesystems, storage replay,
kernel compromise, Windows deletion persistence, installed identity, Android,
production signing/deployment, signed-driver/pre-execution enforcement,
Defender replacement, and the complete antivirus-hardening goal remain open,
blocked, partial, or technically limited as documented.
