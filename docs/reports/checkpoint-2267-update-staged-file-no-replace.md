# Checkpoint 2267: Update Staged-File No-Replace

Date: 2026-08-29  
Status: implementation-head hosted verification passed; integration and destination evidence pending

## Risk

`copy_file_staged` and `write_bytes_staged` share `activate_staged_file` for
update-service file replacement. That helper deliberately removed a validated
existing target, confirmed absence, revalidated the destination parent, and
then used ordinary `std::fs::rename`. A competing object created after the
absence check could therefore be silently replaced at the last mutation step.

## Scripted Repair

Final staged-file activation now calls
`avorax_platform_security::rename_file_no_replace`. The existing target-kind,
link/reparse, boundary, removal, absence, and repeated parent-chain checks stay
in place. The operating-system primitive now makes a final-name collision fail
visibly instead of overwriting the competing object. Unsupported platforms
continue to fail visibly through the shared helper.

Five harmless update-service tests cover replacement of an existing regular file through the
remove-then-no-replace sequence, direct activation to an absent target,
preservation of both benign byte strings on collision, Windows long absolute
paths, and source ordering. A platform-level long-path fixture covers the
shared primitive directly.
The focused definitive step uses the exact `staged_activation_no_replace`
filter. The report validator requires exact 295 steps plus both verified scope
claims and all residual-limit claims. Seven independent report mutations are
scripted for PowerShell 5.1 and 7 rejection.

## Verification Matrix

| Control | Scripted evidence | State before execution |
| --- | --- | --- |
| Shared copy/write activation | Platform no-replace helper replaces ordinary rename | Locally verified on Windows |
| Existing regular target | Harmless old/new fixture | Locally verified |
| Absent final target | Harmless staged-byte fixture | Locally verified |
| Competing final target | Both harmless files must remain byte-exact | Locally verified |
| Long absolute Windows path | Bounded verbatim local-drive/UNC conversion plus platform and update-service fixtures | Locally verified on Windows |
| Validation ordering | Source contract and Rust source-order test | Verified |
| Definitive evidence | Focused step, exact 295 validator, seven hostile mutations on two hosts | Verified locally: 295/295 and 14/14 rejection |
| Dependencies and licenses | Existing internal helper only; no manifest or lock delta | Verified locally; 8/8 lockfiles unchanged |
| Destination and protected vault | Guarded exact-blob synchronization and invariant audit | Pending |

## Engine And Control Accounting

This checkpoint changes only update-service staged-file mutation. Hash and
signature matching, local rule/YARA parsing, static/PE/archive analysis,
bounded heuristics, Authenticode, process observation, risk fusion, allowlists,
exclusions, cache policy, quarantine, restore, logging, settings, and every
custom provider retain their documented responsibility and state. No disabled
or partial engine is promoted by this repair.

## Execution Order

The complete code, Rust tests, Python source contracts, focused verifier step,
exact report validator, dual-host adversarial script, and documentation were
written before execution. No checkpoint-2267 test ran during the scripting
phase. After this batch freezes, execution must proceed through focused checks,
full local regression, exact 295-step verification, dual-host authentic and
adversarial validation, exact-head hosted CI/packages, normal PR merge, guarded
destination synchronization, destination rerun, and final closure audit.

## Safety And Limits

Only harmless temporary ASCII byte fixtures are used and no fixture is
executed. No live malware, EICAR, Defender weakening, machine-wide install,
service/driver start, release, publication, or protected-vault mutation is
authorized. `C:\ProgramData\Avorax\Quarantine` remains read-only at 16,072
files, zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`, `.json`, and
`.auth`, one `.metadata_auth_key`, and zero pending.

No-replace closes only the final-name collision after deliberate target
removal. The remove-to-activate availability gap remains: a crash or activation
failure can leave the target absent. Multi-file staging/install activation is
not transactional. Path and ancestor checks remain point-in-time user-mode
checks; unsupported platforms fail visibly, while administrators, SYSTEM/root,
hostile filesystems, and kernel compromise remain outside the guarantee. This
does not demonstrate installed authority, signed-driver mediation,
pre-execution blocking, production signing, deployment, or Defender
replacement. The complete antivirus-hardening goal remains active.

## Local Broad Evidence

The first dual-host parse command failed before parsing because its Windows
PowerShell argument binding did not receive a valid path. The corrected
absolute-path invocation passes all three scripts on PowerShell 5.1 and 7.
Two `python -m pytest` attempts also stopped before collection because neither
available Python runtime contains `pytest`; no package was installed. The
documented dependency-free runner then passes exact Source `697/697`.

Rust formatting passes. Focused staged activation passes `4/4`; the full update
service passes `211/211` across its key-generator and service binaries, and
strict all-target/all-feature Clippy passes. Both locked workspace test variants
pass; the Native Engine section is `642/642` with 21 intentional isolated
child-fixture ignores. The locked all-feature release build passes.

Flutter analysis and all `852/852` client tests pass. Zentor and Avorax
protocol analysis plus `14/14 + 6/6` tests pass. Post-run process and vault
checks remain exact at zero product processes, 16,072 files, zero directories,
4,522,733 bytes, and zero pending. Definitive exact-295, dual-host adversarial,
hosted, integration, synchronization, destination, and closure evidence remains
pending; all technical limits above stay in force.

## First Definitive Failure And Scripted Repair

The first definitive run passed every step through the new staged-file
no-replace regression and the update-service apply/rollback smokes. It then
failed visibly at `release update-package builder signed verify smoke`.
`MoveFileExW` returned Windows error 3 for a valid absolute staged update-log
path longer than the legacy `MAX_PATH` boundary. The failed 152,351-byte report
is preserved under `.verification` with SHA-256
`282747873caa9a0b7ba0caf8a85f13eb66287044d7446b9021ab08d6adc4dd77`;
it is not counted as passing evidence.

The repair batch adds bounded Windows verbatim conversion for absolute local-
drive and UNC paths before the zero-flag `MoveFileExW` call. Existing verbatim
local/UNC inputs remain bounded, `\\.\` and non-drive/non-UNC verbatim device
namespaces fail visibly, and relative paths retain legacy Win32 path-length
behavior. This does not relax caller path or ancestor validation.

Platform and update-service long-path fixtures, a dedicated Source contract,
verifier/validator scope, the seventh report mutation, and documentation were
all scripted before repair testing. No repair test ran during this scripting
phase. Rerun targets were Source 698, focused 5/5, update service 212/212,
platform 15/15, exact verifier 295/295, and dual-host adversarial 14/14.

## Repaired Definitive Local Evidence

The first post-repair `cargo fmt --check` exposed two layout-only diffs; the
formatter was run and the repeat check passed. Source passes `698/698`.
Platform security passes `15/15`, focused staged activation passes `5/5`, and
the update service passes `212/212`. Strict all-target/all-feature Clippy for
both affected crates passes. The previously failing release package-builder
smoke now passes on the long absolute update-log path.

Both default and all-feature locked workspaces pass. Native Engine reports
`642/642` with 21 intentional child-fixture ignores in each variant; the
large-file test takes about 158 seconds. The locked all-feature release build,
Flutter analysis and `852/852` client tests, and protocol analysis/tests
`14/14 + 6/6` pass. A documented root-level Flutter test invocation was
rejected before collection by Flutter 3.44.4; running `flutter test` from the
client directory passed and the command documentation is corrected.

The no-skip/no-Defender verifier passes exact `295/295` in 684 seconds. Its
222,196-byte report SHA-256 is
`17a32dd8ee483963cbf95c72cc8542910baee414f86f4ed1353d18d1beeebe6d`.
PowerShell 5.1 and 7 independently accept the authentic report. Both hosts
reject all seven content mutations (`14/14`); the 14,882-byte adversarial
result SHA-256 is
`3522a224bfa32f90c52b7f22780df97d7682b7d8576b2b1ce7c791786f96e65a`.

Final local audit passes 13 modified plus one added project path, zero deletes,
eight unchanged lockfiles, zero product processes, pending files, or workflow
temporary residue, the preserved checkpoint-2194 temporary root, and the exact
read-only vault invariant. Audit SHA-256 is
`1c85496c4af5992a7640bde84c2dbef18acc0fc5be05845478e873f7e235f892`.
Hosted exact-head CI/packages, normal PR integration, guarded destination
synchronization, destination reruns, and closure remain pending. All technical
limits above and the complete antivirus-hardening goal remain active.

## Hosted Implementation Head

Implementation commit `6e06ac51043e3a9c3e76f33ed9152149171b0c30` is PR
`#143` exact head. Avorax CI `33247109048` passes all five jobs. Desktop
Packages push/PR runs `33247093108` and `33247109041` pass Windows x64 MSI/EXE,
Linux x64 DEB/tar, macOS x64/arm64 DMG, package contracts, checksums, and the
lockfile SBOM. Both publication jobs are skipped.

Consolidated artifacts `9713357241` and `9713425200` are 132,370,079 and
132,399,216 bytes with SHA-256
`3c41b7b64e89cfba05e88b0e49e923a68819bf363e76843ebbdad84aa515b4db` and
`a73ea1449e9918571855a2d3be693bf8283ea3a2457d2b41afa5a2972b58ac91`.
Bounded stream inspection, without extraction or execution, verifies exact
8-root/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components in
both artifacts. Evidence-head reruns, normal merge, merged-main evidence,
guarded synchronization, destination verification, and closure remain pending.
