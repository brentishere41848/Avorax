# Checkpoint 2278 Quarantine Action Recovery

## Status

Closed through hosted integration and synchronized-destination verification. The
implementation, harmless tests, CI jobs, verifier step 304, validator
assertions, source contract 710, and documentation were completed as one batch
before test execution. No
checkpoint-2278 test ran during the scripting phase. The frozen batch now
passes focused, broad, definitive, and adversarial local verification.

The complete antivirus-hardening goal remains active. This checkpoint does not
claim production detection accuracy, Defender replacement, kernel or
pre-execution blocking, installed-service identity, signed-driver enforcement,
secure erasure, or whole-product completion.

## Protected Boundary

The real `C:\ProgramData\Avorax\Quarantine` vault must remain read-only and
unchanged: 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending
artifacts. All checkpoint fixtures use harmless isolated ASCII in temporary
directories. No live malware, downloaded sample, fixture execution, Defender
change, machine-wide installation, service/driver start, release, or
publication is permitted.

## Failure Being Repaired

Restore previously activated a destination before recording `Restored`; a
crash could leave both restored bytes and a `Quarantined` record/payload.
Delete recorded `Deleted` before removing the payload; a crash could leave a
terminal record plus an executable-looking payload in quarantine. The existing
metadata-update rollback journal intentionally covers only the JSON/HMAC pair,
not these multi-step lifecycle actions.

## Scripted Design

Local Core now creates one strict, at-most-1-MiB
`{id}.action.pending` envelope with a dedicated HMAC domain before restore
staging or delete metadata mutation. It binds:

- format and quarantine ID;
- confirmed action (`restore` or `delete`) and phase (`prepared` or
  `restoreStaged`);
- exact previous and terminal JSON/HMAC bytes;
- a controlled absolute staging path adjacent to the restore destination; and
- after staging, the operating-system identity of the verified single-link
  staging file (Windows volume/file ID or Unix device/inode).

The prepared-to-staged phase update uses atomic adjacent existing-file
replacement and is re-opened, locked, authenticated, and schema-validated.
Metadata-update, finalization, and action journals for one ID are mutually
conflicting. Races fail visibly and preserve evidence instead of guessing.

## Recovery Matrix

| Action / state | Required evidence | Recovery result | Classification |
| --- | --- | --- | --- |
| Delete; previous/previous | Authenticated intent; known metadata; payload valid when present | Drive JSON/HMAC to `Deleted`, remove payload, verify absence, remove journal | Verified locally / hosted pending |
| Delete; next/previous | Same | Complete HMAC, remove payload, verify, clean | Verified locally / hosted pending |
| Delete; previous/next | Same | Complete JSON, remove payload, verify, clean | Verified locally / hosted pending |
| Delete; next/next | Same | Remove remaining payload when present, verify, clean | Verified locally / hosted pending |
| Restore `prepared`; no staging/destination | Exact previous pair and intact quarantine payload | Remove abandoned intent only; leave item quarantined | Verified locally / hosted pending |
| Restore `prepared`; staging or destination exists | Artifact is not identity-bound | Fail visibly and preserve all evidence for manual review | Verified locally / hosted pending |
| Restore `restoreStaged`; staging only | Identity/platform/single-link/size/hash match; payload intact | No-replace activate, reverify destination, drive `Restored`, remove payload, reverify, clean | Verified locally / hosted pending |
| Restore `restoreStaged`; destination only | Same persistent identity and content | Drive/verify `Restored`, remove payload if present, reverify, clean | Verified locally / hosted pending |
| Restore `restoreStaged`; both or neither | Ambiguous state | Fail visibly and preserve evidence | Verified locally / hosted pending |
| Any malformed, oversized, linked, conflicting, active, tampered, unknown, missing, or identity-mismatched state | Exact trusted evidence unavailable | Fail visibly; do not infer success or delete evidence | Verified locally / hosted pending |

Journal cleanup occurs only after exact terminal metadata, payload absence, and,
for restore, repeated identity/content validation of the destination.

## Harmless Regression Inventory

- Four exact delete metadata-pair combinations and already-absent payload.
- Prepared restore cleanup and unbound-stage preservation.
- Restore-staged continuation from staging, destination, and committed cleanup.
- Persistent identity mismatch, duplicate restore artifacts, HMAC tamper,
  unknown metadata, oversize, active lock, conflicting update journal, existing
  action journal, and Unix linked-journal rejection.
- Platform artifact-name bounds and persistent file-identity replacement.
- Real Linux and macOS CI filters plus one definitive verifier step.

Fixtures are data only and are never executed.

## Local Verification After Freeze

```powershell
cargo test --locked --manifest-path core/avorax_platform_security/Cargo.toml persistent_file_identity_accepts_same_file_and_rejects_replacement -- --test-threads=1
cargo test --locked --manifest-path core/avorax_platform_security/Cargo.toml quarantine_action_recovery_artifact_names_are_bounded_and_recognized -- --test-threads=1
cargo test --locked --manifest-path core/zentor_local_core/Cargo.toml quarantine_lifecycle_action_recovery_ -- --test-threads=1
cargo test --locked --manifest-path core/zentor_local_core/Cargo.toml quarantine_
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo build --locked --workspace --all-features --release
python -B tools/testing/run-python-source-contracts.py
powershell -ExecutionPolicy Bypass -File tools/testing/verify-small-threat-mvp.ps1
powershell -ExecutionPolicy Bypass -File tools/testing/validate-small-threat-mvp-report.ps1 -ReportPath <report> -RequireFullSuite
```

Flutter/protocol, branding, product-copy, no-malware, dependency, artifact,
hosted exact-head, PR/merge, merged-main, guarded synchronization, destination,
adversarial-report, final-diff, lockfile, process/residue, and protected-vault
checks are part of the closure sequence.

The focused platform checks pass `1/1` each and the Windows action-recovery
filter passes `15/15`. Platform passes `31/31`, Local Core quarantine passes
`157/157`, complete Local Core passes `614/614`, strict workspace Clippy and
both locked workspace variants pass, and the all-feature release build passes.
Native Engine reports `642` passed with `21` intentional isolated child-fixture
ignores and zero failures. Source contracts pass exact `710/710`. Flutter
analysis and `852/852`, Zentor protocol analysis and `14/14`, Avorax protocol
analysis and `6/6`, the 61-control UI inventory, branding, product-copy,
no-malware-binaries, dependency evidence, and package-source contracts pass.

The no-skip/no-Defender verifier passes exact `304/304` in `705.3s`; its
236,658-byte report SHA-256 is
`70b89132cc48e02666e3e620fa96d7c30e632f13038fe879091a9dfa16c4c5f0`.
PowerShell 5.1 and 7 accept the authentic report and reject `34/34` hostile
cases across 17 current checkpoint mutations. The 30,151-byte adversarial
result SHA-256 is
`0f861402347669daa0d96094c392775231c6e0b69fbca8af3baca88ac09c9bf4`.

Observed failures were retained as evidence and repaired rather than hidden:
the first compile exposed an invalid `Copy` derive and two moved-value uses;
the first Source run found nine stale contracts; the first broad quarantine
run found two stale source assertions plus Guard action compatibility; and the
first adversarial harness run exposed a PowerShell closure-scope defect. All
were corrected and their affected plus broad suites rerun green. A `unittest`
invocation ran zero source tests and `pytest` was unavailable; neither is
claimed as evidence, and the repository's dependency-free runner supplied the
passing exact `710/710`. Two malformed no-malware-gate invocations were rejected
before scanning; the exact absolute-path gate and the definitive verifier gate
then passed.

The final local audit passes over the complete 17-path checkpoint diff with
zero tracked deletions, zero staged `.verification` paths, nine unchanged
tracked dependency lockfiles, zero Avorax/Zentor processes or temporary roots,
and zero repository pending-file residue. Its read-only protected-vault audit
preserves the exact invariant: 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending artifacts.

Exact implementation head `6abbffb3a68070663430d73fe690e622d009653e`
passes PR `#165` Avorax CI `33346196118` and Desktop Packages PR/push runs
`33346196123`/`33346170948`. CI passes all six jobs, including actual Ubuntu
and macOS action recovery. Package jobs pass Windows MSI/EXE, Linux DEB/tar,
macOS arm64/x64 DMG, six release files, seven checksum targets, and a
569-component CycloneDX lockfile SBOM. Publication is skipped. Consolidated PR
artifact `9742414827` is 133,133,600 bytes with hosted digest
`f60e09788925a30cfd724176f42eaec088e5a5398b2cd3d4ed729e24bdc10662`.
Only hosted metadata and logs were inspected; no artifact was downloaded,
extracted, installed, or executed.

That pending state is superseded by the closure evidence below.

## Hosted Integration And Destination Closure

Evidence head `3fd90e767236e59b976a4111f02b63807be17aa4` passes CI
`33347492393` and Desktop Packages `33347492407`. PR `#165` merged normally as
`1683a13fb6c4a6f7af7ff553305f0d7da3a46554`. Merged-main CI
`33348691591` and Desktop Packages `33348691613` pass; publication is skipped.
The latter produces six release files, seven checksum targets, and a
569-component CycloneDX lockfile SBOM. Consolidated artifact `9743072994` is
133,143,711 bytes with hosted digest
`2d9552eb2db2985ec23e333e50fa0908aa3acc2b9485e51e045c52e9daa25150`.
Only hosted metadata/logs were inspected.

The first guarded-sync preflight rejected the inherited checkpoint-2277 report
description before activation. After the exact report path transformation was
fixed, complete preflight and activation passed. Guarded synchronization
applied 16 modified plus one added path, zero deletions, and 32 verified
backups; sync report SHA-256 is
`da7fc6e7359cb2877466f37ba900a0e19cfbb5ee67deac00a3dd42228c87c207`.

Destination Source `710/710`, rustfmt, both platform identity/name checks,
action recovery `15/15`, and strict workspace Clippy pass. Exact no-skip/no-
Defender verification passes `304/304` in `760.9s`; the 227,917-byte report
SHA-256 is
`e93040e010e60cd9c77f7750964e836e4aee42a93d76259737e98b30b3c01d3b`.
PowerShell 5.1 and 7 accept the authentic report and reject all `34/34` hostile
cases across 17 mutations. The 33,280-byte adversarial result SHA-256 is
`e2cbcd7a23441a8063a38be18e768a1f2527ce2cb9d9b0425af03f0634fc87ac`.

Final destination audit SHA-256 is
`86ad411e3709408a5e29837e3ad1ee69c97c59c5e829908090e3fe4fe5c9d06a`.
It confirms all 17 merge blobs, nine unchanged lockfiles, 32 backups, zero
product-process/pending/temp residue, and the unchanged protected vault. The
first audit-wrapper invocation rejected an incorrect template token count
before audit execution; the corrected full audit passed. No artifact was
downloaded, extracted, installed, executed, released, or published.

## Residual Limits

- The action journal is one self-authenticated file, but the whole operation is
  not a power-loss-proof filesystem transaction.
- A crash after staging exists but before its identity reaches the authenticated
  journal intentionally requires manual review.
- File identity, path, ancestor, hash, and link-count checks are point-in-time
  user-mode evidence. They cannot defeat administrators, SYSTEM/root, hostile
  filesystems/storage, or kernel compromise.
- Journal unlink durability depends on truthful filesystem/storage behavior;
  Windows atomic replacement may preserve adjacent backup evidence after an
  ambiguous failure.
- Confirmed-intent replay is bounded recovery, not secure erase, general
  transactionality, installed identity, driver mediation, or pre-execution
  blocking.
