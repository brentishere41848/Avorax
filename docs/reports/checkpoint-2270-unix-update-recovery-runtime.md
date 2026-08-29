# Checkpoint 2270 - Unix Update Recovery Runtime Evidence

Date: 2026-08-29 (Europe/Brussels)

Status: **Complete scripting batch frozen; execution pending**

Post-freeze status: **Local contracts and regressions verified; hosted Unix
runtime, integration, and destination evidence pending**

## Objective

Replace checkpoint 2269's source/compile-only Unix recovery permission claim
with an explicit, harmless runtime route on fixed Ubuntu 24.04. The route must
prove exact owner-only permissions for the recovery directory, authentication
key, lock, and journal, and must prove that overly broad modes are repaired
before authenticated recovery consumes state.

## Scripted implementation and tests

- Production continues to use the shared platform-security hardeners on every
  recovery directory and private-file open. No new recovery implementation or
  weaker fallback was added.
- Two `cfg(unix)` tests inspect filesystem metadata without following links.
  They require mode `0700` for `.avorax-update-recovery` and `0600` for
  `.activation_auth_key`, `.activation.lock`, and authenticated journals.
- The repair fixture deliberately changes only temporary harmless artifacts to
  mode `0777`, then requires recovery to restore `0700`/`0600` before accepting
  and reconciling the authenticated journal.
- The fixed `ubuntu-24.04` `quarantine-unix` CI job runs the exact
  `activation_recovery_unix_` filter, serially and with the locked update-
  service manifest. The filter is expected to select the two Unix runtime
  tests and one all-platform wiring contract.
- A dedicated verifier step pins the source/workflow contract. The definitive
  report validator requires exact `298/298`, the step name, three verified-
  scope statements, and three technical-limit statements.
- Source contract 701 accounts for the test markers, fixed CI runner and
  command, verifier, validator, all audit documents, and safety invariants.
- The untracked adversarial script must accept the authentic report on
  PowerShell 5.1 and 7 and reject seven scope/step mutations on each host,
  exact `14/14`.

## Control matrix before execution

| Surface | Status | Exact blocker or limitation |
| --- | --- | --- |
| Unix recovery directory mode | Partial | Exact `0700` fixture is scripted; hosted Ubuntu runtime has not run |
| Unix key/lock/journal mode | Partial | Exact `0600` fixtures are scripted; hosted Ubuntu runtime has not run |
| Mode repair before recovery | Partial | Benign `0777` repair fixture is scripted; hosted Ubuntu runtime has not run |
| Windows DPAPI/DACL recovery | Verified from checkpoint 2269 | Unchanged by this checkpoint |
| macOS recovery runtime | Partial | Unix code path compiles, but no macOS permission/runtime fixture is routed |
| Android recovery runtime | Partial | Unix code path may compile for target builds, but no Android runtime is routed |
| Root/administrator resistance | Technically limited | Owner-only modes do not protect against root, administrators, kernel compromise, or a hostile filesystem |
| Unix key confidentiality | Technically limited | The local key is owner-only but not encrypted at rest |
| Prior Unix key/journal exposure | Technically limited | Mode repair cannot undo disclosure, revoke an already-open handle, or restore trust after key copying; replace the key and manually review preserved state |
| Power-loss/package atomicity | Technically limited | Per-tree best-effort recovery is not a power-loss-proof multi-component package transaction |
| Detection and custom engines | Unchanged | No hash/rule/YARA/static/PE/archive/heuristic/ML/process/aggregator responsibility changes |

## Planned evidence sequence

After this full scripting batch is frozen: parse scripts, run the focused
source/wiring and Windows recovery regressions, broad locked Rust/Flutter/
protocol suites, exact no-skip/no-Defender `298/298`, dual-host adversarial
validation, read-only vault/process/lockfile audit, exact-head hosted CI and
package evidence, normal PR/merge, guarded zero-delete destination sync, and
destination verification. Counts above are contracts and expectations, not
credited execution evidence yet.

No checkpoint-2270 test ran during the scripting phase. No live malware,
EICAR, network download, fixture execution, Defender weakening, machine-wide
installation, service/driver start, release, publication, or protected-vault
mutation is involved. The protected invariant remains 16,072 files, zero
directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
`.metadata_auth_key`, and zero pending. The complete antivirus-hardening goal
remains active.

## Post-freeze local evidence

- Corrected PowerShell 5.1 and 7 parser calls pass. The first two outer-shell
  calls were malformed before parsing and are uncredited.
- The first format check exposed layout only; `cargo fmt --all` repaired it.
  The first complete Source run then exposed stale CI command counters; the
  repaired repeat passes exact `701/701`.
- The wiring contract passes `1/1`; Windows activation recovery passes
  `19/19`; update service passes `229/229 + 4/4`; platform security passes
  `18/18`; strict locked all-target/all-feature Clippy passes.
- Both locked workspace variants pass groups
  `18 + 4 + 229 + 41 + 251 + 583 + 642 + 6`, with 21 documented isolated
  native child fixtures ignored. The locked all-target/all-feature release
  build passes.
- Flutter analysis passes for all three packages. Client tests pass `852/852`;
  protocol tests pass `14/14 + 6/6`.
- The no-skip/no-Defender verifier passes exact `298/298` in `635.4s`. Its
  225,988-byte report SHA-256 is
  `fb35ed8fe64b352418b461d7e53f048fa380cd301bc18a1f703a059c1c5571ef`.
  PowerShell 5.1 and 7 accept the authentic report.
- The independent validator audit accepts both authentic host cases and rejects
  all `14/14` hostile host/mutation cases. Its 14,503-byte result SHA-256 is
  `63e13f73af15cea62d8221efda72174bdb2de3abdcc2ec5d0d9fbb93f2182914`.
- Read-only checks find no lockfile diff, product process, or pending/temporary
  product residue. The protected-vault invariant remains exact. The final local
  audit report SHA-256 is
  `fb351451b345bf1dcce7e0291cb0443ea50dc4f714e2d62ac58c05855fcd9471`.

This local Windows evidence verifies the source/workflow contract and Windows
regressions; it cannot execute either `cfg(unix)` fixture. Exact Unix permission
semantics remain partial until fixed hosted Ubuntu 24.04 selects and passes all
three `activation_recovery_unix_` tests. Hosted packages, normal integration,
guarded zero-delete destination synchronization, destination regression, and
closure evidence remain pending.

Final review additionally records that mode repair narrows subsequent pathname
access only. It cannot undo prior key/journal disclosure or revoke existing
handles; copied-key state requires key replacement and manual review. The first
local `298/298` report predating this contract is superseded; the final-source
`635.4s` report above includes the mandatory limitation and is authoritative.
