# Checkpoint 2270 - Unix Update Recovery Runtime Evidence

Date: 2026-08-30 (Europe/Brussels)

Status: **Closed with exact hosted, integration, and destination evidence**

Post-freeze status: **Verified on hosted Ubuntu 24.04 and synchronized Windows
destination; residual limits remain explicit**

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

## Control matrix at closure

| Surface | Status | Exact blocker or limitation |
| --- | --- | --- |
| Unix recovery directory mode | Verified hosted Ubuntu 24.04 | Exact `0700` fixture passes on both implementation and merged-main heads |
| Unix key/lock/journal mode | Verified hosted Ubuntu 24.04 | Exact `0600` fixtures pass on both implementation and merged-main heads; the key remains unencrypted |
| Mode repair before recovery | Verified hosted Ubuntu 24.04 | Benign `0777` repair fixture passes on both implementation and merged-main heads |
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

## Implementation-head hosted evidence

Exact implementation `4a01376b27c332376815a031775baf7d456cb9bd`
passes all five Avorax CI jobs in run `33279187609`. Ubuntu 24.04 job
`99171298396` passes the dedicated step and selects exactly the two Unix runtime
fixtures plus the wiring contract: `3 passed; 0 failed; 244 filtered out`.
This verifies exact `0700` recovery-directory, exact `0600` key/lock/journal,
and successful mode repair on the hosted Ubuntu filesystem.

Desktop Packages push/PR runs `33279152023`/`33279187604` pass contracts,
Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMG, consolidation, checksums,
and lockfile SBOM; both publication jobs are skipped. Untouched consolidated
artifacts `9722589339` and `9722639285` were reviewed in-stream without
extraction or execution. They are respectively 132,644,983 bytes with SHA-256
`06ab72f4b4aa1b326fed68735a9c7d8f5fac30ceedccbaee9e8ba1248f28473c`
and 132,671,691 bytes with SHA-256
`54d084be42011a21886d513d1bbb867f170c67e0c1b234673c54bcc536e2d091`.
Both pass exact 8-root/6-platform/7-checksum inventory and CycloneDX 1.6 with
569 components.

The Ubuntu 24.04 mode and repair rows are now **Verified hosted**. This does
not undo prior disclosure, revoke open handles, encrypt the key, prove macOS/
Android runtime, exercise an installed service identity, or close any power-
loss, privileged actor, hostile filesystem, driver/pre-execution, Defender-
replacement, signing/deployment, or whole-project limit. At implementation
head, evidence-head hosted checks, normal merge, guarded destination
synchronization, destination verification, and closure remained pending; the
completed evidence below supersedes that state.

## Integration and destination closure evidence

Evidence commit `6dc6f22ac07465953b45a6c4b1dcd05bdc6dc424` passes all five
Avorax CI jobs in run `33279985483`. Ubuntu job `99173414467` passes the two
Unix runtime fixtures and wiring contract, exact `3 passed; 0 failed; 244
filtered out`. Desktop Packages PR run `33279985653` passes all platform and
consolidation jobs with publication skipped. Consolidated artifact
`9722892732` is 132,637,119 bytes with SHA-256
`6a7ff68e0dcc7fd5d472e9e1c547f4640e675c32ffea70abb64ac98569fbb61f`.

Normal PR `#149` merges as
`4fcc4f1aa5c34fc6a097c1036784a5766e120bb3`. Merged-main Avorax CI run
`33280845843` passes all five jobs; Ubuntu job `99175636100` again reports
exact `3 passed; 0 failed; 244 filtered out`. Desktop Packages run
`33280845849` passes every build and consolidation job with publication
skipped. Consolidated artifact `9723086300` is 132,643,423 bytes with SHA-256
`6e3a2c09d6ae6011922c6eb505edbfd4d680ec6631e78ded5e888d4234992890`.
Both artifacts pass bounded in-stream review without extraction or execution:
eight root entries, six platform packages, seven matching checksums,
CycloneDX 1.6, and 569 components.

Guarded synchronization applies exactly 13 modified plus one added merge path
with zero deletes and preserves 26 ordinary/replaced backups. Sync report
SHA-256 is
`70d1a323483c0522e258d90f9a9819f67c289fa2a89a84ad7470eccbb1d7478c`.
At `C:\Users\Brent\Documents\Avorax-main`, Source `701/701`, formatting,
strict locked all-target/all-feature Clippy, both locked workspace variants,
locked all-target/all-feature release, Flutter analysis/client `852/852`, and
protocol analysis/tests `14/14 + 6/6` pass. Rust groups are
`18 + 4 + 229 + 41 + 251 + 583 + 642 + 6`, zero failures, with 21 documented
isolated child-fixture ignores.

The destination no-skip/no-Defender verifier passes exact `298/298` in
`648.1s`. Its 217,645-byte report SHA-256 is
`ad30b477fbb66e5c27036fcdaa0bdc8b03358b9085103b51c8247b3b85059c73`.
PowerShell 5.1 and 7 accept it; the destination-local adversarial audit rejects
all seven content mutations on both hosts, exact `14/14`, with zero boundary-
only rejections. Its 14,267-byte SHA-256 is
`34abb95fe97a19c187b1826de71fb71a43fac3d60f44ae84d8399353effb523c`.

Final destination audit SHA-256
`474ee7c3f0dd828bf7dcec770d32177b8d847f593c8ee0fa1dd47f8a527f918c`
passes exact 14/14 merge blobs, all eight unchanged active lockfiles, 26
backups, zero product processes/pending/temporary roots, and the exact
protected-vault invariant. No known critical/high issue remains inside this
checkpoint scope. Checkpoint 2270 is closed; the complete antivirus-hardening
goal is not closed.

No live malware, EICAR, Defender weakening, machine-wide installation,
service/driver start, release, publication, or protected-vault write occurred.
`.verification` remains untracked. Permission repair still cannot undo prior
disclosure or revoke open handles; the Unix key is not encrypted; macOS and
Android runtime, installed-service identity, power-loss package atomicity,
privileged/hostile filesystem resistance, production signing/deployment,
driver/pre-execution authority, Defender replacement, and whole-project
completion remain partial, technically limited, blocked, or open.
