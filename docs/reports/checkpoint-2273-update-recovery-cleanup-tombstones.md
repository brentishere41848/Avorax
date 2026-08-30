# Checkpoint 2273 Update Recovery Cleanup Tombstones

Date: 2026-08-30

Status: **Closed through hosted integration and synchronized destination verification**

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
the fixed runners. The following closure section supersedes the then-pending
evidence-head, merge, synchronization, destination, and closure state. The
complete antivirus-hardening goal remains active.

## Evidence-Head, Merge, And Destination Closure

Evidence head `e5fb59f9a3eace0f96cb2e253180bc5c1af935a4` passes all six
Avorax CI jobs in run `33299903289`. Ubuntu Rust job `99225949053` passes the
complete update service, including all eight cleanup regressions. macOS 15 job
`99225949039` passes the exact four selected recovery fixtures, `4 passed; 0
failed; 255 filtered out`. Desktop Packages run `33299903309` passes with
publication skipped. Consolidated artifact `9728821306` is 132,703,422 bytes
with SHA-256
`1046b7733dc4b6be17aadce5ff3b342af36a4933503680db755e847f89a6e74b`.

Normal PR `#155` merges as
`6bcfe8c62ff7c22a521a996fa9255ef6faaca79d`. Merged-main Avorax CI run
`33300730156` passes all six jobs. Ubuntu Rust job `99228250332` passes update
service `4 + 240` and names all eight cleanup regressions as green; macOS job
`99228250162` passes exact `4/4`, with 255 filtered. Desktop Packages run
`33300730155` passes with publication skipped. Consolidated artifact
`9728990794` is 132,694,723 bytes with SHA-256
`c7a01a1982d9c909e091b48509c083c874fbca05bad322ea1c4c7d8c83ccde6a`.
Both artifacts pass bounded in-stream exact 8-entry/6-platform/7-checksum
inventory and CycloneDX 1.6 with 569 components, without extraction or
execution.

Guarded synchronization copies exact 12 modified and one added path with zero
deletes and preserves 24 verified backups. Sync-report SHA-256 is
`b58c6642800d01ea04e886101148dc9834814c59f5577a86efb3012c02c850c9`.
The synchronized `C:\Users\Brent\Documents\Avorax-main` destination passes:

- `python -B tools/testing/run-python-source-contracts.py`: `704/704`.
- Rust format, strict locked all-target/all-feature Clippy, both locked
  workspace test variants, and locked all-target/all-feature release.
- Flutter analysis and `852/852` tests.
- Zentor and Avorax protocol analysis/tests: `14/14 + 6/6`.
- The no-skip/no-Defender verifier: exact `301/301` in `706.2s`. Its 221,445-
  byte report SHA-256 is
  `deb434da82cd8c3b1ccf2f3f0ba3cfc1e596ee2aae70847facc2dfd5b5dd7948`.

PowerShell 5.1 and 7 accept that authentic report. The first destination
adversarial run is explicitly uncredited because its candidates were outside
the repository and path rejection preceded content checks. The corrected in-
root audit accepts both authentic host cases and rejects all `20/20` content
mutations with zero unexpected candidate-path rejections; its 15,438-byte
result SHA-256 is
`8f2fbfdaee122208029c7f15625c3dae3ef74de6ebafa3718c197836a3d41adb`.
Final audit SHA-256
`6a7d8ab2d1ed18112e800d2b9e014df484fc22d5f200754d5dfcbe0080cb3eeb`
passes 13 exact merge blobs, nine unchanged active lockfiles, 24 backups, zero
product processes/pending files/temporary roots, and the unchanged protected-
vault invariant.

Checkpoint 2273 is closed. Verified scope remains the fixed hosted Ubuntu and
macOS 15 runners plus the synchronized Windows destination. Storage hardware
truthfulness, Windows removal durability, other filesystems/devices/identities,
Android, privileged or hostile filesystem actors, package-wide power-loss
transactionality, production signing/deployment, driver/pre-execution
enforcement, Defender replacement, and the complete antivirus-hardening goal
remain partial, blocked, or technically limited.

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
