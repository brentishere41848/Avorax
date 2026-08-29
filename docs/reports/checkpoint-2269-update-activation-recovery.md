# Checkpoint 2269 - Authenticated Update Activation Recovery

Date: 2026-08-29 (Europe/Brussels)

Status: **Implementation-head local and hosted verification passed; integration
pending**

## Objective

Close the fail-unsafe availability gap where update or rollback directory
activation can stop after the installed destination is moved to a backup but
before the staged tree becomes the destination. Recovery must never trust an
arbitrary path from package or journal input and must never overwrite a
competing filesystem object.

## Scripted implementation

- `core/avorax_update_service/src/activation_recovery.rs` owns one private
  per-install `.avorax-update-recovery` store, one exclusive OS file lock, one
  authentication key, strict authenticated journals, path derivation, state
  reconciliation, bounded reports, and benign fixtures.
- Records use `deny_unknown_fields`, schema version 1, a random 128-bit
  lowercase-hex ID, canonical install-boundary SHA-256, one exact allowlisted
  destination, and whether the destination existed. Journals are domain-
  separated HMAC-SHA-256 and cannot supply staging, backup, or restore paths.
- Allowed trees are exactly `engine`, `engine/signatures`, `engine/rules`,
  `engine/ml`, and `engine/trust`. Every derived path remains under the
  canonical install boundary and existing path chains reject links/reparse
  points.
- The 32-byte random HMAC key is stored as a machine-bound DPAPI blob on Windows
  with UI forbidden and an exact verified DACL. Unix uses an owner-only 0700
  directory and 0600 file. Decrypted DPAPI output is zeroed before `LocalFree`.
- Journal/key reads are capped at 16 KiB, recovery-directory enumeration at 128
  entries, inspected parents at 512 entries, report errors at 4096 characters,
  and operation allocation at 16 random attempts.
- Recovery removes abandoned pre-activation staging, restores the backup-move
  gap with atomic no-replace rename, removes a completed activation backup, or
  retires a stale completed journal. Ambiguous, unauthenticated, unknown,
  oversized, wrong-kind, linked/reparse, or orphan state fails visibly and is
  preserved.
- Update apply, rollback restore, update-service startup, and strict manual
  `--recover [install_dir]` invoke recovery. Success and failure emit bounded
  structured `activation_recovery_report.json`; CLI failure also remains in the
  existing status path. App payload validation forbids the recovery store.
- Rollback and update tree replacement share the same activation primitive;
  duplicate activation/recovery implementations were removed.

## Scripted harmless coverage

Sixteen module fixtures cover normal commit reconciliation, a true fresh-call
backup restore, fresh-call completed cleanup, new-destination abort/completion,
journal tampering, ambiguous competing state, orphans, unknown entries,
oversized journals, concurrent lock refusal, unknown fields, exact allowlisting,
strict operation IDs/tags, and bounded report errors. Additional platform, CLI,
and app-payload tests cover private files, DPAPI round trip, strict CLI wiring,
and the reserved store. Fixtures contain only harmless ASCII data in temporary
directories and are never executed.

Source contract 700 pins implementation, dependencies, lockfile edges,
verifier/validator text, docs, and safety invariants. Verifier step 297 runs the
`activation_recovery` filter. The validator requires exact `297/297` and seven
new scope assertions. The untracked checkpoint adversarial script must accept
the authentic report on PowerShell 5.1 and 7 and reject seven mutations on both
hosts, exact `14/14`.

## Control status matrix

| Surface | Status before execution | Exact limitation / blocker |
| --- | --- | --- |
| Private recovery store and permissions | Verified locally | Platform and recovery tests pass; installed-context review remains pending |
| Windows DPAPI key protection | Verified locally | Windows DPAPI round trip passes; machine scope is not protection from administrators/SYSTEM |
| Unix owner-only key protection | Partial | Source and compile coverage pass; hosted Unix runtime evidence remains pending |
| HMAC journal authenticity and strict parsing | Verified locally | Tamper and strict-schema fixtures pass; key deletion or privileged substitution remains outside the guarantee |
| Backup-gap and completed-cleanup reconciliation | Verified locally | Focused fresh-call fixtures and aggregate update-service tests pass |
| Ambiguous/forged/orphan fail-safe behavior | Verified locally | Harmless fixtures pass; manual review is deliberately required for real ambiguous state |
| Apply/rollback/service/manual wiring and reports | Partial | Unit, source, CLI, and aggregate wiring pass; installed elevated-service E2E remains blocked/pending |
| Multi-component package transaction | Technically limited | Service lifecycle, files, engine components, cleanup, and rollback are not one transaction |
| Power-loss durability | Technically limited | No filesystem/storage ordering guarantee or power-cut VM evidence |
| Pre-journal staging-copy interruption | Partial | Orphan is detected and blocked, not automatically deleted |
| Unsupported non-Windows/non-Unix targets | Disabled | Secure private-key storage fails visibly |
| Detection/custom engines | Unchanged | This checkpoint adds no detection coverage or blocking authority |

Exact implementation head `d44b5c65c009d7378852b86246812ebe7115b1f2`
passes all five Avorax CI jobs in pull-request run `33271345848`. Desktop
Packages push/PR runs `33271310749`/`33271345821` pass package contracts,
Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMGs, consolidation,
checksums, and lockfile SBOM generation. Both prerelease publication jobs are
skipped.

The untouched consolidated artifacts were downloaded only into untracked
`.verification` and inspected in-stream without extraction or execution:

- push artifact `9720317057`: 132,640,696 bytes, SHA-256
  `1c1a6d752ac08fad2b54fc665e7eff919d66443f1583efa65705f98aa5bff9f9`;
- PR artifact `9720376440`: 132,629,422 bytes, SHA-256
  `bada0debaf61adcd46396a60ab2ef49bf81b01d46fd0e328fbf3979ed118d2c5`.

Each contains exactly eight expected root entries, six platform packages,
seven checksum targets whose streamed SHA-256 values match, and one valid
CycloneDX 1.6 lockfile SBOM with 569 components. This is clean hosted build,
package-contract, inventory, and checksum evidence. It is not package
installation, production signing/notarization, runtime recovery on Unix,
elevated-service E2E, power-cut durability, release approval, or publication.

## Local execution evidence

The complete implementation/test/verifier/documentation batch was frozen before
execution. The first formatting check failed on layout only; `cargo fmt --all`
repaired it and the repeat passed. The first recovery compile exposed three
real implementation mistakes (`getrandom::fill` against getrandom 0.2, a
`PathBuf` success arm treated as `()`, and an ambiguous `by_ref` call). They
were repaired before any fixture could run, and the focused recovery repeat
passed `18/18`.

The first Source run executed all 700 contracts and failed three stale source-
shape assertions after directory activation moved into the shared recovery
primitive. The contracts were repaired to inspect that primitive and the
repeat passed `700/700`. The first update-service aggregate reached its tests
and reported eight failures: one stale wrong-kind diagnostic, rollback recovery
running before rollback preflight, and six cascading failures after the first
panic poisoned the test environment lock. Destination preflight was restored
before staging, rollback preflight now precedes recovery, focused repeats
passed, and the aggregate repeat passed `228/228` plus keygen `4/4`, exact
`232/232`.

The first strict Clippy run then found only three local lint defects: a dead
test helper, two production-visible test accessors, and one needless return.
Those were repaired. Moving the accessors behind `cfg(test)` made three Source
contracts split production text too early; their split marker was corrected to
the actual test module and Source again passed `700/700`. Strict locked Clippy
then passed.

Credited local results are:

- PowerShell 5.1 and PowerShell 7 parse the verifier, validator, and adversarial
  script.
- Formatting passes; focused Windows DPAPI passes `1/1`; recovery passes
  `18/18`; platform security passes `18/18`; update service passes `232/232`;
  Source contracts pass `700/700`; strict locked Clippy passes.
- `cargo test --workspace --locked -- --test-threads=1` exits 0. The largest
  native-engine suite passes `642` with 21 intentional isolated child-fixture
  ignores, and its signature-compiler binary passes `6/6`.
- The locked all-target/all-feature workspace exits 0 with crate groups
  `18 + 4 + 228 + 41 + 251 + 583 + 642 + 6` passed, zero failures, and the
  same 21 intentional child-fixture ignores.
- The locked all-target/all-feature release workspace build exits 0 and
  finishes the optimized profile.
- Flutter analysis reports no issues and the client passes `852/852`. Both
  protocol analyzers report no issues; Zentor protocol passes `14/14` and
  Avorax protocol passes `6/6`.

The first exact-297 verifier attempt is uncredited. It passed the new recovery
step and update-service aggregate, then the release apply-tamper smoke found
that `apply-preflight` recovery created the private store before package
signature verification. Recovery was moved after successful package
authentication but remains before staging, snapshot, service stop, or payload
activation. Rust and Source ordering contracts now pin `verify < recover <
extract`; the focused Rust contract passes `1/1`, Source passes `700/700`, the
release binary rebuild passes, and the exact failed tamper smoke now passes
without any install-directory write. A complete definitive repeat remains
required.

The complete definitive repeat passes exact `297/297` in `685.6s`, with no
failed steps, no Rust or Flutter skip, and Defender/EICAR opt-in false. The
225,076-byte report SHA-256 is
`a16a4b143964f6e2a5bae4a4b0ee10997cf882a166c155657f240e1429e62584`.
PowerShell 5.1 and 7 both accept the authentic full-suite report.

The first adversarial invocation is uncredited because a PowerShell 5.1
parameter default evaluated `$PSScriptRoot` before the script body and stopped
before any mutation ran. Defaults now resolve in the body; both hosts parse the
script and the repeat accepts the authentic report on both while rejecting all
seven mutations on both, exact `14/14`. The 14,332-byte result SHA-256 is
`e0bf98f99510330d7ac2dfad8af34bd1b82ab55ed46b0ecdc3c332b76d76bebe`.

Read-only final local audit passes exact 19 modified plus two added paths and
zero deletes, eight active lockfiles with only the intentional root
`Cargo.lock` delta, zero product processes, pending files, workflow residue,
or temporary product roots, and the exact protected vault. Its report SHA-256
is `38e69a072e2c611200771c7c3847fd09e554f7ee53eec9922a41a7cbed2aaebf`.
Exact-head hosted CI/package review, PR/merge, guarded destination
synchronization, and destination verification remain pending.

The final post-repair clean-build review repeats the locked all-target/all-
feature workspace with exact passing groups `18 + 4 + 228 + 41 + 251 + 583 +
642 + 6`, zero failures, and 21 intentional child-fixture ignores. The locked
all-feature release build also exits 0. Dependency review confirms only exact
direct edges to already locked `hmac 0.12.1` and `zeroize 1.9.0`, plus feature
flags on existing `windows-sys 0.61.2`; there is no new package version or
license class. Final diff/threat review finds no known critical/high issue in
this checkpoint and retains every partial/technical limit below.

Two loose final no-malware-gate follow-ups are uncredited: one supplied the
relative text `python`, and one resolved the WindowsApps reparse alias; both
were rejected before scanning. The corrected call uses the same checked bundled
Python executable as the definitive verifier and passes.

## Remaining execution sequence

Commit only the hosted-evidence documentation, keep `.verification` untracked,
then obtain exact evidence-head CI/packages, perform normal PR/merge and
merged-main checks, apply guarded zero-delete destination synchronization, run
destination full verification, and close the checkpoint without closing the
whole hardening goal.

Recovery filter `18/18`, platform `18/18`, update service `232/232`, Source
`700/700`, definitive verifier `297/297`, adversarial rejection `14/14`, and
exact implementation-head hosted CI/packages are now evidenced. Evidence-head,
merged-main, and synchronized-destination evidence remain pending.

## Safety and current evidence

No checkpoint-2269 test ran during the scripting phase; the execution above
started only after that complete batch was frozen. No live malware,
EICAR, Defender weakening, fixture execution, network download, machine-wide
installation, service/driver start, force reset, direct-main push, release,
publication, or protected-vault write occurred during local execution. Hosted
artifacts were treated as untrusted opaque ZIP containers and were not
extracted or executed. `.verification` remains untracked and must never be
staged or deleted.

The protected vault remains exactly 16,072 files, zero directories, 4,522,733
bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending. This invariant must be checked read-only before and after relevant
execution.

Authenticated update directory recovery uses a private per-install store,
machine-bound DPAPI key protection on Windows, owner-only key storage on Unix,
HMAC-bound strict journals, an exclusive cross-process lock, exact allowlisted
path derivation, bounded parsing, and harmless state fixtures to restore the
backup-move gap or finish completed cleanup without overwriting a competing
object. This scope is locally runtime/source verified and exact implementation-
head hosted build/package verified as listed above; installed-context evidence
remains pending.

Directory activation recovery is per-tree and next-start/best-effort; it is not
a power-loss-proof package transaction, does not make service/file/multiple-
component activation atomic, and cannot defeat administrators, SYSTEM/root,
hostile filesystems, key deletion, storage write reordering, or kernel
compromise. Ambiguous or unauthenticated state is preserved and requires manual
review. The complete antivirus-hardening goal remains active.
