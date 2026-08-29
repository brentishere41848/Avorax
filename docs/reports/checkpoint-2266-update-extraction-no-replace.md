# Checkpoint 2266 - Signed Update Extraction No-Replace

Status: **Implementation-head hosted verification passed / integration pending**

## Risk

`UpdatePackage::extract_payload_to` verifies and bounds package entries, writes
each entry to an exclusive temporary file, syncs it, checks the final target is
absent, and rechecks the destination parent. The final operation was still
ordinary rename. On platforms where rename replaces an existing target, a file
created after the last absence check could be silently overwritten.

## Scripted Repair

- `avorax_update_service` now depends on the existing internal
  `avorax_platform_security` workspace crate.
- `activate_extracted_payload_file` retains its temporary-file validation,
  target-absence check, and repeated parent-chain validation, then calls
  `activate_extracted_payload_no_replace`.
- The helper delegates to `rename_file_no_replace`, which uses zero-flag
  `MoveFileExW`, `renameat2(RENAME_NOREPLACE)`, or
  `renamex_np(RENAME_EXCL)` on supported targets and fails visibly elsewhere.
- Ordinary `std::fs::rename(temp_target, target)` is forbidden in this path.

## Scripted Evidence

| Control | Current state | Evidence boundary |
| --- | --- | --- |
| Absent target activation | Locally verified | Harmless staged bytes move to the final target and the staging name disappears. |
| Competing target race | Locally verified | Both staged and competing ASCII bytes remain; error contains `without replacing`. |
| Parent/path ordering | Locally verified | Two destination-parent checks surround the absent-target preflight and precede no-replace activation. |
| Platform boundary | Windows runtime verified / cross-target build pending | The Windows focused fixture passes; Linux/Android and Apple hosted package builds remain pending. |
| Unsupported target behavior | Disabled / fail-visible | No replacement-capable fallback. |
| Definitive evidence | Locally verified | Focused verifier step, exact `294/294`, strict PS5/PS7 validation, and ten host/mutation rejections pass. |
| Detection/custom engines | Unchanged | Full regression keeps every existing signal, threshold, allowlist, exclusion, and verdict responsibility accounted for. |

The new focused step is `update-service payload extraction atomic no-replace
regressions` with filter `payload_extraction_no_replace`. Source contract 696
pins code, dependency/lock edge, fixtures, verifier, validator, documentation,
safety, and residual limits.

## Required Execution Order

1. Parse PowerShell scripts, run formatting/diff checks, Source contracts, and
   the focused extraction fixtures.
2. Run the complete update-service suite and strict all-target/all-feature
   Clippy.
3. Run both locked workspace suites and the locked all-feature release build.
4. Run Flutter/protocol and other focused regressions required by the definitive
   verifier.
5. Run the no-skip/no-Defender verifier at exact `294/294`, then validate the
   authentic report on PowerShell 5.1 and 7 and reject bounded mutations.
6. Obtain exact-head CI/packages with publication skipped, merge by normal PR,
   verify merged-main evidence, perform guarded zero-delete destination sync,
   and repeat destination verification and final audit.

No checkpoint-2266 test ran during the scripting phase. At batch freeze every
runtime item above was pending; the following sections record later execution.

## Local Execution Evidence

Execution began only after the complete scripting batch froze. Two preliminary
Source runs failed visibly: the first exposed two contract defects in report
grammar and an obsolete ordinary-rename assertion, and the second exposed one
dependency-document marker split by Markdown. Those three test-contract defects
were repaired; the final Source run passes exact `696/696`.

- Formatting and PowerShell 5.1/7 parsing pass.
- Focused extraction no-replace tests pass `3/3`.
- The full update-service suite passes `209/209`; strict all-target/all-feature
  Clippy passes.
- Both locked workspace suites pass. The all-feature Native Engine section
  passes `642/642` with 21 intentional platform-gated ignores; no test fails.
- The locked all-feature release build passes.
- Flutter analysis and all `852/852` client tests pass. Zentor and Avorax
  protocol analysis plus `14/14 + 6/6` tests pass.

At this local-broad stage, exact `294/294`, dual-host authentic/adversarial,
hosted exact-head CI/packages, normal PR merge, guarded synchronization,
destination rerun, and closure audit remained pending. The next section
supersedes the local definitive and adversarial portions of that statement.

## Definitive Local Evidence

The no-skip/no-Defender verifier passes exact `294/294`, all steps passed, in
`653.4s`. The 220,507-byte report has SHA-256
`8f9e033d6e6cf1ace2025e8f0069787fdf05c391864cff93b335ad9561cd115f`.
Independent PowerShell 5.1 and 7 validators accept that authentic report, and
both reject all five required evidence mutations (`10/10`). Their 11,569-byte
result has SHA-256
`38d0f88b02e357cabdff92f76cacdc7129ddc354eddec035681f7d52e6c888a5`.

The first final-audit attempt stopped visibly because PowerShell 5.1 promoted
the audit script's expected `git --error-unmatch` stderr to an exception. The
audit was repaired to use a successful empty `git ls-files` query, parsed on
both hosts, and reran successfully. Its 2,071-byte report has SHA-256
`86481f29f90e88bd06664b806c08a11c73935d9426e58361706256889e3795d3`:
14 modified paths, one added report, zero deletes, one internal root-lock edge,
seven other lockfiles unchanged, zero product processes or pending residue, the
preserved checkpoint-2194 temporary root, and the exact protected-vault
invariant. Hosted, integration, synchronization, destination, and closure
evidence remains pending.

## Hosted Implementation Head

Implementation commit `36325846ccc0b61ef5a86d75c62e7fe3463835da` is PR
`#141` exact head. Avorax CI `33239461936` passes all five jobs. Desktop
Packages push/PR runs `33239451192` and `33239461879` pass Windows x64 MSI/EXE,
Linux x64 DEB/tar, macOS x64/arm64 DMG, package contracts, checksums, and the
lockfile SBOM. Both publish jobs are skipped.

Consolidated artifacts `9711051283` and `9711127072` are 132,341,276 and
132,614,885 bytes with SHA-256
`5d542ec008bc0d6b226544f8c9726ce4987a689d88ea867516a8b2c5cc59cd71` and
`a9a4b954a6dd95cd7580ade4e6af7b365a076357470f254d2dcff6528902207e`.
Bounded stream inspection, without extraction or execution, verifies exact
8-root/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components in
both artifacts. Evidence-head reruns, normal merge, merged-main evidence,
guarded synchronization, destination verification, and closure remain pending.

## Safety and Limits

Only harmless temporary ASCII bytes are used and fixtures are never executed.
No live malware, EICAR, Defender weakening, machine-wide install,
service/driver start, release, or publication is authorized. The protected
`C:\ProgramData\Avorax\Quarantine` vault is never a test root and remains
read-only at 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.

No-replace is atomic only for one final extracted filename. It does not make
all package entries, install-tree activation, rollback, or service transitions
one transaction. Ancestor checks remain point-in-time user-mode checks and do
not defeat administrators, SYSTEM/root, hostile filesystems, or kernel
compromise. Installed authenticated service authority, production signing,
signed-driver mediation, demonstrated pre-execution blocking, Defender
replacement remain open. The complete antivirus-hardening goal remains active.
