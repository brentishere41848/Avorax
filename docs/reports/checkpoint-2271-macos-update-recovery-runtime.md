# Checkpoint 2271 - macOS Update Recovery Runtime

Date: 2026-08-30 (Europe/Brussels)

Status: **Definitive local verification passed; hosted macOS execution pending**

## Objective

Close checkpoint 2270's concrete macOS runtime-evidence gap for authenticated
update recovery. A fixed hosted macOS 15 job must execute the existing harmless
Unix permission fixtures and prove exact owner-only modes plus repair before
authenticated state is consumed. The checkpoint changes no update policy or
detector authority.

## Scripted implementation and tests

- Production recovery continues to use the shared Unix hardeners. No fallback,
  dependency, key format, journal format, or mutation authority changes.
- The fixed `macos-15` job uses pinned checkout and Rust actions, Rust `1.96.1`,
  a 30-minute job bound, `cargo test --locked`, the exact update-service
  manifest, the `activation_recovery_unix_` filter, and one test thread.
- That filter must select the two `cfg(unix)` runtime fixtures plus the existing
  Unix wiring contract. The fixtures require `0700` on the recovery directory,
  `0600` on the key, lock, and authenticated journal, and repair deliberately
  broadened temporary modes before recovery succeeds.
- A separate all-platform Rust wiring test isolates the macOS job block and
  pins its runner, action revisions, toolchain, command, filter, and serial
  execution.
- Source contract 702 pins implementation, workflow, verifier, validator,
  documentation, safety boundaries, and the exact protected-vault invariant.
- Verifier step 299 runs the macOS wiring test. Exact-299 validation requires
  the step and five verified/limited scope statements.
- The untracked adversarial validator must accept the authentic report on
  PowerShell 5.1 and 7 and reject seven mutations on each host, exact `14/14`.

## Control matrix before execution

| Surface | Status | Exact blocker or limitation |
| --- | --- | --- |
| macOS recovery directory mode | Partial | Scripted `0700` fixture requires a passing exact-head hosted `macos-15` run |
| macOS key/lock/journal mode | Partial | Scripted `0600` fixture requires the same hosted run; the key remains unencrypted |
| macOS permission repair | Partial | Harmless temporary `0777` repair fixture requires hosted execution |
| Ubuntu recovery runtime | Verified from checkpoint 2270 | Unchanged fixed Ubuntu 24.04 evidence |
| Windows DPAPI/DACL recovery | Verified from checkpoint 2269 | Unchanged by this checkpoint |
| Android recovery runtime | Partial | No Android runtime route or device/emulator evidence |
| macOS environment breadth | Technically limited | One hosted macOS 15 runner does not prove every OS version, architecture, filesystem, or installed identity |
| Root/administrator resistance | Technically limited | Mode bits cannot resist root, administrators, hostile filesystems, or kernel compromise |
| Key confidentiality and prior exposure | Technically limited | Unix key storage is owner-only, not encrypted; repair cannot undo copying or revoke open handles |
| Package transactionality | Technically limited | Recovery remains per-tree and next-start/best-effort, not one power-loss-proof package transaction |
| Detection and custom engines | Unchanged | No hash/signature/rule/YARA/static/PE/archive/heuristic/ML/process/aggregator responsibility changes |

## Planned evidence sequence

After this complete scripting batch is frozen: parse PowerShell on both hosts,
run Source 702 and focused recovery/wiring tests, strict format/lint, both
locked workspaces, locked release, Flutter/protocol regressions, exact no-skip/
no-Defender 299-step verification, authentic and adversarial report validation,
and read-only lock/process/residue/vault audits. Then collect exact-head hosted
CI and package evidence, review artifacts in-stream without extraction or
execution, integrate through a normal PR, synchronize exact zero-delete paths,
and repeat destination verification before closure.

No checkpoint-2271 test ran during the scripting phase. No live malware,
EICAR, download, network fixture, candidate execution, Defender weakening,
machine-wide installation, service/driver start, release, publication, or
protected-vault mutation is involved. `.verification` remains untracked. The
protected invariant remains 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending. The complete antivirus-hardening goal remains active.

## Post-freeze local evidence

- PowerShell 5.1 and 7 parse all three changed scripts; format and diff checks
  pass. The macOS workflow wiring regression passes `1/1`.
- The first complete Source run executed all 702 tests and failed visibly on
  one existing Ubuntu job-slice assertion because the new macOS Cargo command
  was included in that slice. Ending the Ubuntu slice at the new macOS job
  boundary repairs the ownership contract; the credited repeat passes exact
  `702/702`.
- Activation recovery passes `20/20`; platform security passes `18/18`; update-
  service and workspace strict locked all-target/all-feature Clippy pass.
- Both locked workspace variants pass groups
  `18 + 4 + 230 + 41 + 251 + 583 + 642 + 6`, zero failures, with 21 documented
  isolated Native child fixtures ignored. The locked all-target/all-feature
  release build passes.
- Flutter analysis passes and client tests pass `852/852`; Zentor and Avorax
  protocol analysis/tests pass `14/14 + 6/6`.
- Definitive no-skip/no-Defender verification passes exact `299/299` in
  `665.1s`. Its 227,630-byte report SHA-256 is
  `1d9b40247407ccb9ac3f009cd614051d05472f076c3bd8f52571a2a6c22c3d30`.
  PowerShell 5.1 and 7 both accept the authentic schema-2 report.
- The independent validator audit accepts both authentic host cases and rejects
  all `14/14` hostile host/mutation cases. Its 12,615-byte result SHA-256 is
  `f19f29478bcf374b880c1788f1d71a4cb43300fa2cd0c214423c1d269bfba338`.
- Read-only checks find no active lockfile change, product process, pending
  repository file, product temporary root, or protected-vault drift. The vault
  remains exact at 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
  payload/metadata/authenticator, one metadata key, and zero pending.

This Windows evidence verifies the exact workflow and validation route, not
macOS filesystem semantics. Exact-head hosted `macos-15` execution, package
evidence, normal integration, guarded zero-delete destination synchronization,
destination regression, and closure remain pending. Android and all stated
technical limits remain open; the complete antivirus-hardening goal is active.
