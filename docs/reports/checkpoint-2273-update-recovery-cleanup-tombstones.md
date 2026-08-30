# Checkpoint 2273 Update Recovery Cleanup Tombstones

Date: 2026-08-30

Status: **Implementation-head verified; evidence-head, merge, destination, and closure pending**

## Purpose

Checkpoint 2273 narrows the crash/replay gap between update staging or backup
cleanup and retirement of its authenticated recovery journal. It does not claim
durable deletion or a power-loss-proof package transaction.

No checkpoint-2273 test ran during the scripting phase. Production changes,
benign/adversarial tests, verifier step 301, exact report-validator contracts,
Source contract 704, and all audit/operational documentation were written first
as one reversible batch.

## Implemented Protocol

1. Recovery authenticates the active strict journal and derives only an exact
   allowlisted update destination.
2. A staging or backup tree selected for cleanup moves atomically and no-replace
   into `.avorax-update-recovery` under one of four exact dispositions:
   `aborted-existing-staging`, `recovered-existing-staging`,
   `completed-existing-backup`, or `aborted-new-staging`.
3. Source and cleanup parents cross the existing namespace durability boundary.
4. Recovery verifies that active destination/staging/backup names are in a valid
   final state.
5. The already HMAC-authenticated active journal moves no-replace from
   `<operation>.json` to `<operation>.cleanup.json`.
6. Only then are the typed directory tombstone and cleanup journal removed.
7. On restart, a bounded exact inventory resumes active journals, authenticated
   cleanup journals, and exact orphan cleanup tombstones. Unknown names,
   malformed IDs/dispositions, links/reparse points, multiple tombstones,
   restored active names, tampered HMACs, and ambiguous states fail visibly.

The summary adds `removed_cleanup_tombstones`; cleanup is not reported complete
until the relevant removal call succeeds. Errors are returned with context and
are not swallowed.

## Benign And Adversarial Evidence

All fixtures are harmless ASCII data in isolated temporary directories and are
never executed:

- interruption after typed directory cleanup staging but before journal
  retirement resumes with the exact disposition;
- interruption after authenticated cleanup-journal staging finishes both
  removals;
- an exact orphan tombstone with no journal is removed within the bounded
  inventory;
- an orphan tombstone beside a replay-restored active staging/backup sibling
  fails before orphan cleanup and preserves both pieces of evidence;
- a disposition inconsistent with authenticated active state fails and
  preserves journal plus tombstone;
- a tampered cleanup journal fails authentication/parsing and is preserved;
- a malformed cleanup operation name is rejected and preserved.
- multiple orphan dispositions for one operation are rejected together and
  preserved.

The verifier adds `update-service activation recovery cleanup tombstone
regressions` with filter `activation_recovery_cleanup_`. Full-suite validation
requires exactly 301 steps, the exact step, three verified-scope statements, and
two technical-limit statements. Source contract 704 pins production ordering,
all dispositions/tests, verifier/validator wiring, docs, safety, and dependency
claims.

## Failure Policy

- A cleanup rename collision is not replaced.
- More than one cleanup disposition for an operation is ambiguous.
- Active staging/backup residue beside a cleanup journal blocks cleanup.
- A cleanup journal must retain a valid HMAC and matching operation ID.
- Unknown or malformed recovery-root entries block the whole pass.
- A reparse point or wrong entry kind is never treated as removable cleanup.
- Failures remain visible; evidence that cannot be justified is preserved.

## Local Verification Evidence

The batch froze before execution. The credited local commands include:

```powershell
python -B tools\testing\run-python-source-contracts.py
cargo fmt --all -- --check
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml `
  activation_recovery_cleanup_ -- --test-threads=1
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml `
  activation_recovery -- --test-threads=1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File tools\testing\verify-small-threat-mvp.ps1 `
  -RepoRoot . `
  -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2273-update-recovery-cleanup-tombstones-report.json
```

Local results:

- the first Source run executed 704 tests with one stale source-contract
  expectation for the removed cleanup helper; the contract was corrected and
  the dependency-free rerun passed exact `704/704`;
- cleanup tombstones pass `8/8`, complete activation recovery passes `30/30`,
  and the full update service passes `4 + 240`;
- formatting and diff checks, strict affected/workspace Clippy, both locked
  workspace variants, and locked all-target/all-feature release pass; the two
  workspace variants retain 21 documented isolated child-fixture ignores;
- final diff review found that orphan cleanup preceded the unexplained active-
  sibling guard; the guard was moved before every orphan deletion, an eighth
  preservation regression/source-order contract was added, and the earlier
  verifier report was superseded by a complete rerun;
- Flutter analysis and `852/852` pass; protocol analysis/tests pass
  `14/14 + 6/6`;
- the definitive verifier passes exact `301/301`, zero failed/skipped and zero
  non-null step errors, in `597.3s`; Defender/EICAR integration opt-in is false;
- the 229,793-byte authoritative report SHA-256 is
  `412da5f6f77c0f1567293ae1903dbd0595094f0e0f9fe696606efbdc328bd88a`;
- PowerShell 5.1 and 7 accept the authentic report and reject ten mutations per
  host, exact `20/20`, covering the required step/scopes/limits, count, terminal
  status, tool host, and generated-report path boundary;
- final local audit passes 12 tracked modifications, one new report, zero
  deletions, nine unchanged lockfiles, zero product process/pending/temp
  residue, and the exact protected-vault invariant.

The adversarial summary SHA-256 is
`13f43e1a2e0ed0700923d87ed87b611b7d04097ceda097dc596c0b5585e52c9d`.

## Implementation-Head Hosted Evidence

Exact implementation `b594573f744b57dccf13f358e972720d54c288a3` passes all
six Avorax CI jobs in run `33298892119`. Rust job `99223208370` passes Local
Core `583/583`, Guard `250/250`, update service `4 + 240`, and backend API
`41/41`; its log names all eight cleanup-tombstone regressions as passed. macOS
15 job `99223208360` passes its four selected harmless recovery-permission and
namespace-durability fixtures with 255 filtered out.

Desktop Packages push/PR runs `33298848017`/`33298892093` pass contracts,
Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMG, consolidation, checksums,
and lockfile SBOM. Both prerelease-publication jobs are explicitly skipped.
Untouched consolidated artifacts `9728478108` and `9728452926` were retained
under untracked `.verification` and reviewed in-stream without extraction or
execution. They are respectively 132,703,055 bytes with SHA-256
`13789e0101df1aa6a122b4053e2b6c8fb81266c17ce32f74483913e29ffbf8a4`
and 132,700,501 bytes with SHA-256
`480605b3e0a8045cb230c0b9f113afb097561c68dd2d02853bea243d473da901`.
Both pass exact 8-entry/6-platform/7-checksum inventory and CycloneDX 1.6 with
569 components.

The final local audit is 2,530 bytes with SHA-256
`9b85e79e2e93d9f6c724997123b1c42208e59c5e96af8ca9206d87d3eae4cba6`.
It passes exact 12-modified/one-added/zero-delete scope, nine unchanged
lockfiles, definitive/adversarial evidence, zero product processes, and the
protected vault invariant.

The cleanup state machine is verified locally and at implementation head on
the fixed runners. Evidence-head CI/packages, normal merge, merged-main
evidence, guarded destination synchronization, destination verification, and
checkpoint closure remain pending, so the complete antivirus-hardening goal
remains active.

## Honest Limits

Typed tombstones reduce stale active-name ambiguity. They do not prove that a
same-volume Windows rename or deletion survived power loss, that hardware or a
filesystem honored ordering, or that all package components form one
transaction. If replay restores an active staging/backup name after its journal
became cleanup state, Avorax fails closed for manual review.

Administrators, SYSTEM/root, hostile filesystems, storage rollback/reordering,
kernel compromise, installed-service identity, Android, production signing and
deployment, signed-driver/pre-execution enforcement, Defender replacement, and
production detection accuracy remain outside this checkpoint.

No live malware, Defender weakening, machine-wide installation, service/driver
start, release, publication, or protected-vault mutation occurs. The eight
checkpoint fixtures contain no EICAR. The inherited definitive verifier uses
only its established safe EICAR text and simulator fixtures with
`include_defender_eicar=false`; no fixture is executed. The protected quarantine
remains exactly 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`, `.json`, and `.auth`, one `.metadata_auth_key`, and zero pending.
The complete antivirus-hardening goal remains active.
