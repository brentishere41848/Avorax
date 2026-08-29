# Checkpoint 2266 - Signed Update Extraction No-Replace

Status: **Closed through hosted integration and synchronized destination verification**

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
| Absent target activation | Verified | Harmless staged bytes move to the final target and the staging name disappears in local and synchronized-destination tests. |
| Competing target race | Verified | Both staged and competing ASCII bytes remain; error contains `without replacing` in local and destination tests. |
| Parent/path ordering | Verified | Source contract pins two destination-parent checks around absent-target preflight and before no-replace activation. |
| Platform boundary | Windows runtime and desktop cross-target build verified | Windows runtime fixture passes; hosted Windows, Linux, and Apple package builds pass. Android runtime/build remains unverified. |
| Unsupported target behavior | Disabled / fail-visible | No replacement-capable fallback. |
| Definitive evidence | Verified | Local and destination exact `294/294`, strict PS5/PS7 validation, local content mutation rejection, hosted integration, and exact-blob audit pass. |
| Detection/custom engines | Unchanged / broad regression green | Full local, hosted, and destination regression keeps every existing signal, threshold, allowlist, exclusion, and verdict responsibility accounted for. |

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

## Evidence Head And Merge

Evidence commit `954f713990f725d4bb8263466f43bb2f64968eb2` passes exact-head
CI `33240400063` and Desktop Packages `33240400070`, with publication skipped.
Artifact `9711435827` is 132,342,121 bytes with SHA-256
`806d79252cb8ca2d969072c03815efdeb9e754c0a8afe48c64126ee0f546aaad`.
Bounded stream review passes exact 8 roots, 6 platform files, 7 checksum
targets, and CycloneDX 1.6 / 569 components without extraction or execution.

PR `#141` merges normally as
`7c90919a6a859b7b366f8da2ae12e5567f846f53`. Exact merged-main CI
`33241371058` and Desktop Packages `33241371099` pass, with publication
skipped. Artifact `9711617151` is 132,346,444 bytes with SHA-256
`f0ef070e5934050e3f067b56a55b85a55cb43349e89a63749fa4388d5f10358b`
and passes the same bounded non-extracting/non-executing review.

## Synchronized Destination Closure

- The first guarded-sync attempt failed before activation because Windows
  PowerShell 5.1 lacks the requested three-argument `System.IO.File.Move`
  overload. The second failed before activation because PowerShell 5.1 rejected
  a null `System.IO.File.Replace` backup path. Both destination snapshots stayed
  unchanged; their 14-file exact-base backup inventories are preserved.
- The repaired third attempt uses an explicit replacement-backup path and the
  two-argument move for additions. It applies 14 modified plus one added path,
  zero deleted. The sync report SHA-256 is
  `e18645465b6b89da9828767adee730fd8a8a1dee922d49c25c5b22e3505a1791`.
- Destination formatting, Source `696/696`, focused extraction `3/3`, update
  service `209/209`, strict Clippy, both locked workspace variants, locked
  all-feature release, Flutter analyze and `852/852`, and protocol analyze/tests
  `14/14 + 6/6` pass.
- The destination no-skip/no-Defender verifier passes exact `294/294`, zero
  failed steps, in `634.6s`. Its 211,753-byte report SHA-256 is
  `922c46f6896c665d76938c6379c57231ffc44183ef842e4420b5cae8761b343c`;
  embedded PowerShell 5.1 and 7 validation accepts it.
- The destination adversarial audit accepts both authentic hosts and rejects
  ten mutation candidates. Because those candidates live under the source
  `.verification`, repository containment rejects them before their content is
  evaluated; this is not credited as duplicate content-mutation evidence. The
  definitive local run already rejects all five intended content mutations on
  both hosts, and final audit proves the destination validator is the exact
  merged blob. Destination adversarial result SHA-256 is
  `128ac21c94496eab98dab1e1107d3900e8d04c637f9bee8e826ec1d56c6e833c`.
- Final destination audit report SHA-256
  `d933d3f2e3e9270ec32b3e4c2cb1399d8c9d9546dd22a1d1b41e7022f656d2d2`
  confirms all 15 exact merge/source/destination blobs, all eight lockfiles,
  three preserved backup inventories, zero pending residue or product
  processes, and the exact protected-vault invariant.

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

Checkpoint 2266 is closed. Closure does not expand the per-file no-replace
boundary or close any whole-package transaction, installed authority,
production signing, driver, pre-execution, Defender-replacement, or complete-
project limit above.
