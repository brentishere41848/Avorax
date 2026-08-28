# Checkpoint 2262 - Manual Trust-Mutation Hash Binding

Status: **Closed; implementation integrated and synchronized destination verified**

Checkpoint 2262 addresses stale scan evidence and false action-success evidence
for the two manual trust mutations reachable from a visible scan-result row:
adding the detected file to the allowlist and saving false-positive or confirmed-
malicious feedback. This checkpoint does not change malware classification
thresholds, execute a candidate, weaken Microsoft Defender, install a service or
driver, or claim pre-execution blocking.

## Risk

Before this checkpoint, both actions supplied only a path to Local Core. The
allowlist store hashed whatever bytes occupied that path when the command ran,
and detection feedback separately extracted features and hashed the current
path. A file replaced after the scan verdict could therefore create trust state
for bytes different from the visible row. Flutter also accepted incomplete
success evidence: allowlist add checked active state but not exact type/path/
SHA-256, while detection feedback checked only that a store path looked local.

## Scripted Implementation

- `LocalCoreClient.addAllowlistEntry` now accepts the complete `ThreatResult`,
  sends its exact path and SHA-256 plus `confirmed=true`, and accepts success
  only for an active file entry with the exact normalized path and hash.
- `LocalCoreClient.labelDetection` sends the same exact scan SHA-256, requested
  label, previous verdict, and `confirmed=true`. It requires a bounded valid
  label ID, matching hash/label/previous verdict, and mutually consistent local
  store paths before returning success.
- Local Core independently requires explicit confirmation for allowlist add and
  detection feedback. Bounded SHA-256 syntax is validated before store or file
  access. Unsupported feedback labels fail visibly instead of silently becoming
  `unsure`.
- `AllowlistStore::add_with_expected_sha256` hashes the current regular local
  file, compares it to the scan hash before persistence, and leaves the store
  untouched on mismatch. Later suppression still requires both path and exact
  hash.
- Detection feedback hashes before and after bounded static-feature extraction.
  A pre-existing mismatch or an observed mid-extraction change fails with a
  rescan-required error before append. Successful IPC returns compact evidence
  derived from the persisted label rather than the untrusted request alone.
- Existing safe allowlist scripts now send server-side confirmation. The
  standalone wrapper still hashes a freshly selected current file because it
  has no earlier scan-row verdict; it does not claim prior-verdict binding.

## Scripted Verification

- Harmless Rust regressions cover omitted confirmation, malformed SHA-256 before
  file/store access, changed bytes with zero persistence, matching bytes with
  exact persisted evidence, and allowlist-store hash admission.
- Flutter IPC regressions capture exact request fields and reject wrong
  allowlist active/type/path/hash evidence plus missing, malformed, mismatched,
  or contradictory feedback evidence.
- `tools/testing/run-release-local-core-trust-mutation-binding-smoke.ps1` uses
  only isolated temporary ASCII fixtures. It proves changed-byte rejection,
  server-confirmation rejection, matching persistence, response/store equality,
  unchanged fixture bytes, zero quarantine creation, no fixture execution, no
  live malware, no EICAR, and no Defender change.
- The definitive verifier adds `release local-core binary trust-mutation hash-
  binding smoke`; full-suite validation requires exact `290` steps and the new
  verified/technical-limit scope. Source contracts are expanded for every new
  implementation, request, response, smoke, verifier, validator, safety, and
  documentation obligation.

No checkpoint-2262 test ran during the scripting phase. After the source, test,
verifier, validator, and documentation batch was complete, execution produced
this evidence:

- Formatting checks passed. The first focused Local Core run compiled and
  passed `6/8`; two test-only fixtures had not initialized the configured
  allowlist file. After fixing only those fixtures, the rerun passed `8/8`.
- Flutter Local Core IPC passed `97/97`; the overlapping offline/scan-screen
  suites passed `238/238`; the full client suite later passed `852/852` and
  `flutter analyze` reported no issues.
- Source contracts passed `692/692`. Optional `pytest` invocations are not
  credited because that module was unavailable; the repository-owned,
  dependency-free runner supplied the passing evidence.
- Strict Local Core Clippy passed with all targets/features. The release Local
  Core built successfully. The first two PowerShell 5.1 smoke attempts exposed
  only harness stdin-encoding incompatibilities and are not credited; the
  harness adopted the repository's BOM-free console-input pattern, then the
  real release-binary smoke passed under PowerShell 5.1 and PowerShell 7.
- Both locked Rust workspace variants passed. Major totals are Platform
  `11/11`, Update Service `203/203`, Guard `248/248`, Local Core `580/580`,
  Native Engine `640/640` plus 21 intentional isolated-child fixture ignores,
  and Native signature compiler `6/6`. The locked all-feature release workspace
  build passed. Zentor protocol passed `14/14`; Avorax protocol analyzed cleanly
  and passed `6/6`.
- The definitive no-skip/no-Defender verifier passed exact `290/290`, zero
  failed/skipped, in `621.9s` from `2026-08-28T19:55:31.7558504Z` through
  `2026-08-28T20:05:53.6630327Z`. Its 214,814-byte report is
  `.workflow/ultracode/avorax-hardening/results/2262-small-threat-mvp-manual-trust-mutation-hash-binding-report.json`
  with SHA-256
  `d0d544184c5f5974abb48b111bb2e274519b27d493f53e9d6a2aa5b2fd0f735b`.
- Integrated and independent PowerShell 5.1/7 validation accepted the authentic
  report. The independent adversarial audit rejected all six combinations of
  missing required step, verified scope, and technical limit across both hosts.
  Its retained 6,245-byte result has SHA-256
  `555c8217fd2e3b46a18f202e9d5ea5e013c9358f9dc9cdb82ea3c86afc9a4730`.

The local result alone did not establish hosted behavior. The independently
recorded implementation-head evidence below now covers that commit; evidence-
head hosting, integration, and destination proof remain separate.

## Hosted Implementation-Head Evidence

Exact implementation commit
`0460c4f5a4db237ee261d642e3f94ef1ff285719` passes PR `#133` CI run
`33206972057`, package push run `33206952538`, and package PR run
`33206972034`. Every CI job passes. In both package runs the package contract,
Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, and consolidation
jobs pass; `Publish desktop beta prerelease` is explicitly skipped.

Consolidated artifacts `9700500463` and `9700448185` match GitHub metadata
exactly:

- push: 132,346,685 bytes, SHA-256
  `f52b71490729d9dfc123b9d7b459bc8189374331f3544eb30f11ae97891ae9b2`;
- PR: 132,471,456 bytes, SHA-256
  `ad9af733b6a1795058214ade742e484828951f7fffb95146c6f5349ebfc562cd`.

Bounded non-extracting ZIP-stream review passes for both: exact eight unique
safe root files, six platform packages, seven matching checksum targets,
CycloneDX 1.6 with 569 components, and zero encrypted, special, traversal, or
over-limit entries. No package was extracted, installed, or executed.

## Evidence-Head And Integration Evidence

Evidence commit `61c3ed2d16b2422cf18924c63bb33272a4f16036` passed
Avorax CI `33208443938` and Desktop Packages PR run `33208443931`. Every
source and platform package job passed; publication was skipped. Consolidated
artifact `9700940590` matched GitHub at 132,285,278 bytes and SHA-256
`836dbfcf7898aaf7fb27884438f449035c899112ce6679ffa106ca0f72d0e5ad`.
Bounded non-extracting review again passed exact 8-root/6-package/7-checksum/
CycloneDX-1.6/569-component evidence.

PR `#133` merged normally as
`25115ffef2be5595b9a8744245dbecacef4e227f`, with exact parents
`4db4d92ff9bc8e4d1ea057841db9f2cbe2c410e9` and
`61c3ed2d16b2422cf18924c63bb33272a4f16036`. Merged-main CI
`33209411475` and Desktop Packages `33209411481` passed, with publication
again skipped. Consolidated main artifact `9701360508` matched GitHub at
132,284,228 bytes and SHA-256
`aecc5ca29045e5740e50e6a6c785317849d974d9acd5f0f5803d0208f046a427`.
It passed the same bounded non-extracting validation. No hosted artifact was
installed, extracted, executed, released, or published.

## Guarded Synchronization And Destination Evidence

Guarded synchronization required every existing destination file to match the
exact old Git blob and both new paths to be absent. It rejected links/reparse
parents, active product processes, source drift, staging collisions, or any
protected-vault deviation before activation. Short verified backups and
same-directory staging supported rollback. Exact activation synchronized 26
paths to `C:\Users\Brent\Documents\Avorax-main`: 24 modified, two added, zero
deleted. The generated apply report has SHA-256
`deea441065b58d2f78162ffaa8815a9a9b49ef3b7d3515e7994fe1f00789bb0e`.

Destination Source passed `692/692`; focused Local Core passed `8/8`; Flutter
IPC passed `97/97`; strict all-feature Local Core Clippy and both-host release
smokes passed. Both locked Rust workspace variants passed with Platform
`11/11`, Update Service `203/203`, Local Core `580/580`, Native `640/640` plus
21 intentional isolated-child ignores, and compiler `6/6`. The all-feature
release workspace build, Flutter analyze and `852/852`, and protocol `14/14`
plus `6/6` passed.

The first destination definitive attempt is retained as a failed host-security
event, not a pass. After 39 passed steps, Defender removed the generated Native
test harness before execution as inactive `Trojan:Win32/Wacatac.C!ml` with
`DidThreatExecute=False`, causing Windows error 225. Its 85,458-byte schema-v2
failed report has SHA-256
`1713a3c856c5d8d860b04021c5011485042119b3649e184ec62a0828b08b0032`.
Defender was not weakened and nothing was restored or allowlisted. A fresh
isolated build of the exact failed Native target then passed `4/4`.

The full verifier restarted from step one and passed exact `290/290`, zero
failed/skipped, in `728.3s`, from `2026-08-28T21:11:23.4782666Z` through
`2026-08-28T21:23:31.8534843Z`. Its 206,462-byte destination report is
`.workflow/ultracode/avorax-hardening/results/2262-destination-small-threat-mvp-manual-trust-mutation-hash-binding-report.json`
with SHA-256
`dd2471f176fca7c3138198cb52e034d539e5a4808ffb2ae5b9d2e759301c8cea`.
Integrated and independently rerun Windows PowerShell 5.1 and PowerShell 7
validators accepted it. A fresh dual-host adversarial audit accepted both
authentic validations and rejected all six missing-step/scope/limit mutations;
its 7,026-byte result SHA-256 is
`ccbe1ea62a8baddb2872c2644cb55e18e3d416ccc83f91cb72ace77dd0732a94`.

Final independent audit passed all 26 raw and normalized path hashes, all eight
lockfiles, zero synchronization sidecars, zero product processes, and the exact
protected vault. Its report SHA-256 is
`b4f08d6d022cf0e880b3f27baded377f27b2f7ed8f766dffaff39eec63f33fd6`.
Checkpoint 2262 is closed; the complete antivirus-hardening goal remains active.

## Verification Commands

Executed focused commands after the scripting batch froze included:

```powershell
cargo fmt --all -- --check
cargo test --locked --manifest-path core\zentor_local_core\Cargo.toml manual_trust_mutation_binding_ -- --test-threads=1
flutter test test\local_core_ipc_diagnostics_test.dart
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "[void][scriptblock]::Create([IO.File]::ReadAllText('tools/testing/run-release-local-core-trust-mutation-binding-smoke.ps1'))"
pwsh.exe -NoLogo -NoProfile -NonInteractive -Command "[void][scriptblock]::Create([IO.File]::ReadAllText('tools/testing/run-release-local-core-trust-mutation-binding-smoke.ps1'))"
python -B tools\testing\run-python-source-contracts.py
cargo clippy --locked --manifest-path core\zentor_local_core\Cargo.toml --all-targets --all-features -- -D warnings
cargo build --locked --release --manifest-path core\zentor_local_core\Cargo.toml
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File tools\testing\run-release-local-core-trust-mutation-binding-smoke.ps1
pwsh.exe -NoLogo -NoProfile -NonInteractive -File tools\testing\run-release-local-core-trust-mutation-binding-smoke.ps1
```

Broad execution used both `cargo test --locked --workspace` variants, the
locked all-feature release workspace build, `flutter analyze`, full `flutter
test`, and both protocol suites. The definitive command used
`tools/testing/verify-small-threat-mvp.ps1` without optional Defender/EICAR
integration and wrote the checkpoint-specific report above.

## Control Matrix

| Control / engine responsibility | Current checkpoint state | Evidence boundary |
| --- | --- | --- |
| Scan-result allowlist request binding | **Verified** | Exact row path/SHA-256 and explicit confirmation cross Flutter IPC; success requires active file type plus exact path/hash. Local, hosted, merged, and destination evidence passes. |
| Scan-result feedback request binding | **Verified** | Exact row SHA-256, requested label, previous verdict, and explicit confirmation cross IPC. Local and synchronized destination evidence passes. |
| Local Core trust admission | **Verified** | Malformed evidence fails before access; stale bytes fail before persistence; unsupported labels fail visibly. Local and destination release paths pass. |
| Persisted success evidence | **Verified** | Allowlist entry and compact persisted label receipt match request and isolated persisted evidence. Local and destination adversarial proof passes. |
| Signature/hash/rule/static/PE/archive/heuristic/ML/Authenticode/process/verdict engines | **Unchanged** | No detection-engine responsibility or threshold changes in checkpoint 2262. |
| Installed packaged UI/service click-through | **Partial** | Source/widget/controller/IPC and release-child proof pass; installed package and cross-process service E2E remain separate. |
| Cross-identity authorization and immutable file lease | **Disabled / blocked** | Current Local Core is a same-user child interface; no signed service/driver or kernel lease is introduced. |
| Privileged final path/content race prevention | **Technically limited** | User-mode double hashing and hash-bound allowlisting detect ordinary stale content but cannot defeat administrators, SYSTEM, kernel compromise, or every race. |

## Safety And Protected State

The protected production vault is out of scope and must remain read-only. Its
carried checkpoint-2261 invariant is **16,072 files, 0 directories, 4,522,733
bytes**, with 5,357 each `.avoraxq`, `.json`, and `.auth`, one
`.metadata_auth_key`, and zero pending files. The new smoke points only to a
GUID-named temporary root and removes only that owned root. `.verification/`
remains untracked and must never be staged or deleted.

No live malware is downloaded, unpacked, retained, or executed. The scripted
fixtures are ordinary ASCII bytes and are never launched. Defender remains
enabled and unchanged. Nothing is installed machine-wide, no service or driver
is started, and no package is published or released.

## Dependency Delta

Checkpoint 2262 adds no dependency, package source, binary fixture, license
class, network fetch, or lockfile change. Existing pinned Rust and Flutter/Dart
graphs remain authoritative. Local and destination dependency evidence, both
locked workspace variants, all eight exact lockfiles, hosted package/SBOM
review, final diff, and destination audit pass. Final-binary legal/notice
provenance and production signing/notarization remain separate release work.

Checkpoint 2262 is closed. The complete antivirus-hardening goal remains active;
this checkpoint must not be represented as completion of the whole antivirus.
