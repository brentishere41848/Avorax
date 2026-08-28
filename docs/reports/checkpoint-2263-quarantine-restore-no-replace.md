# Checkpoint 2263 - Quarantine Restore No-Replace Activation

Status: **Locally verified; hosted integration pending**

Checkpoint 2263 prevents a quarantine restore from replacing a file that
appears at the original path after the last destination preflight. It does not
change detection thresholds, execute a candidate, weaken Microsoft Defender,
install a service or driver, or claim pre-execution blocking.

## Risk

Local Core stages verified restore bytes beside the original path, rechecks
path ancestors and destination absence, and then previously called the general
filesystem rename operation. On Unix, rename can replace an existing file. A
concurrent creator between the absence check and activation could therefore
lose its file even though the user-facing restore contract promises not to
overwrite an existing destination.

## Scripted Implementation

- `avorax_platform_security::rename_file_no_replace` exposes one fail-visible
  cross-platform boundary for restoring an absent destination.
- Windows uses `MoveFileExW` with zero flags, intentionally omitting
  `MOVEFILE_REPLACE_EXISTING`.
- Linux and Android use `renameat2` with `RENAME_NOREPLACE`.
- Apple platforms use `renamex_np` with `RENAME_EXCL`.
- Other platforms return an explicit unsupported error. There is no fallback
  to replacement-capable rename.
- Local Core restore activation calls the shared primitive after its existing
  parent, payload-integrity, and destination checks. Existing staged-file
  cleanup remains fail-visible.

## Scripted Verification

- Shared platform runtime fixtures cover successful absent-destination
  activation and a competing destination whose bytes must remain unchanged.
- A Local Core runtime fixture calls the exact restore activation helper with a
  competing file and requires both the competing bytes and staged bytes to
  survive the rejected activation.
- The safe quarantine/restore smoke creates a harmless destination collision,
  requires restore rejection, unchanged competing bytes, an intact payload,
  and still-quarantined authenticated metadata before removing only that
  temporary collision and completing the normal restore.
- The definitive verifier adds `quarantine restore atomic no-replace
  regressions`. Full-suite validation requires exactly `291` steps and the new
  verified and technical-limit scope.
- Source contracts pin the operating-system calls, zero/no-replace flags,
  Local Core wiring, absence of the old activation rename, fixtures, verifier,
  validator, documentation, dependency, and safety claims.

No checkpoint-2263 test ran during the scripting phase. Focused, broad,
definitive, and adversarial execution began only after the complete scripted
batch was frozen. Hosted, merge, and synchronized-destination evidence remains
pending.

## Local Verification

| Command / evidence | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed after applying the four formatting-only changes identified by the first check. |
| `python -m pytest tests/test_custom_driver_contract.py -q` | `693/693` passed after replacing one obsolete source-contract expectation for the removed general rename. |
| PowerShell 5.1 parser checks for the smoke, verifier, and validator | Passed. The first wrapper invocation had a shell-variable quoting error before parsing the scripts; the corrected invocation passed. |
| `cargo test --manifest-path core/avorax_platform_security/Cargo.toml quarantine_restore_no_replace -- --test-threads=1` | `2/2` passed. |
| `cargo test --manifest-path core/zentor_local_core/Cargo.toml quarantine_restore_no_replace -- --test-threads=1` | `1/1` passed. |
| `tools/testing/run-safe-quarantine-restore-smoke.ps1` | Passed; the competing destination was preserved, authenticated quarantined state remained intact, and normal restore completed only after the fixture-owned collision was removed. |
| strict all-target/all-feature Clippy for Platform Security and Local Core | Passed with warnings denied. |
| `cargo test --locked --workspace -- --test-threads=1` and the all-feature equivalent | Both passed. Platform Security passed `13/13`; Local Core passed `581/581`; Native Engine passed `640/640` plus 21 intentional ignores; the remaining workspace suites passed. |
| `cargo build --locked --workspace --release --all-features` | Passed. |
| Flutter analyze and full Flutter test suite | Passed; `852/852` tests. Zentor protocol passed `14/14`; Avorax protocol analyze and `6/6` tests passed. |
| `tools/testing/verify-small-threat-mvp.ps1` without optional Defender/EICAR | Exact `291/291` passed, zero failed/skipped, in `666.2s`. |
| `tools/testing/validate-small-threat-mvp-report.ps1 -RequireFullSuite` | Passed independently under Windows PowerShell 5.1 and PowerShell 7. |
| Untracked dual-host adversarial report audit | The authentic report was accepted twice; all six missing-step/scope/limit mutations were rejected. |

The definitive report is
`.workflow/ultracode/avorax-hardening/results/2263-small-threat-mvp-quarantine-restore-no-replace-report.json`,
216,409 bytes, SHA-256
`92360dc643cb81f8e4c4eb1bdcd181a1c705870524d29213bf842a44f5e61f3b`.
It ran from `2026-08-28T22:32:51Z` through `2026-08-28T22:43:57Z`.
The successful adversarial summary is 7,378 bytes, SHA-256
`ee70503c16b53aedccd5da6777fce7569f8bd6d6f89bf4617d7e452e40104db7`.
Its first untracked run exposed only a harness stderr-capture issue under
PowerShell 5.1; no product test was bypassed, and the corrected harness reran
the authentic and all adversarial cases from the beginning.

## Control Matrix

| Control / engine responsibility | Current checkpoint state | Evidence boundary |
| --- | --- | --- |
| Restore final-name activation | **Locally verified** | OS atomic no-replace primitive is wired for Windows, Linux/Android, and Apple targets; Windows runtime and hosted cross-target compile/package evidence are separate boundaries. |
| Competing destination preservation | **Locally verified** | Platform, Local Core, and safe-smoke fixtures preserve destination and staged bytes after rejection. |
| Existing restore integrity/metadata flow | **Unchanged** | Payload SHA-256, authenticated metadata, staging, parent validation, status transition, and cleanup remain in place. |
| Unsupported platform behavior | **Disabled / fail-visible** | Restore activation returns unsupported rather than using replacement-capable rename. |
| Ancestor replacement by privileged actors | **Technically limited** | Parent checks remain point-in-time user-mode checks; no kernel transaction or driver is introduced. |
| Signature/hash/rule/static/PE/archive/heuristic/ML/Authenticode/process/verdict engines | **Unchanged** | No detection responsibility or threshold changes in checkpoint 2263. |

## Safety And Protected State

All new fixtures contain ordinary harmless ASCII and are never executed. No
live malware is downloaded, unpacked, retained, or run. The smoke uses only a
GUID-named temporary root and may remove only files it created there. Defender
is not changed or weakened. Nothing is installed machine-wide, and no service,
driver, package, release, or publication is started.

The protected production vault remains read-only and must retain **16,072
files, 0 directories, 4,522,733 bytes**, with 5,357 each `.avoraxq`, `.json`,
and `.auth`, one `.metadata_auth_key`, and zero pending files.
`.verification/` remains untracked and must never be staged or deleted.

## Dependency Delta

Checkpoint 2263 adds no dependency, package source, binary fixture, license
class, network fetch, or lockfile change. It uses the already pinned `libc` and
`windows-sys` dependencies of `avorax_platform_security`. Exact lockfiles,
license evidence and local locked tests/builds pass. Hosted package SBOMs,
final diff review, merge, and destination review remain required before closure.

The complete antivirus-hardening goal remains active; completion of checkpoint
2263 must not be represented as completion of the whole antivirus project.
