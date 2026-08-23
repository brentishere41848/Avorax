# Checkpoint 2203: Authenticode Restricted Thread Token

## Objective

Reduce the privileges used by release-helper WinTrust processing without
changing the exact Microsoft signer, scanned-content hash, Job, timeout, or
failure-visible trust policy.

## Threat And Design

Checkpoint 2198 isolated WinTrust in a bounded child and checkpoint 2201 added
Job resource limits, but a LocalSystem Guard/Core parent still gave the helper
process an equally privileged token. A malformed candidate or defective trust
provider should not receive unnecessary enabled token privileges during path
opening, catalog lookup, chain inspection, or hash binding.

The one-shot helper now duplicates its current process token as a
`SecurityImpersonation` token, derives a Windows restricted token with
`DISABLE_MAX_PRIVILEGE`, validates it before use, assigns it only to the current
helper thread, and reads the effective thread token back before opening the
candidate. Validation requires the exact impersonation token type and level,
caps `TokenPrivileges` data at 64 KiB and 256 entries, and permits only
`SeChangeNotifyPrivilege` to remain enabled. Microsoft documents that privilege
as the sole `DISABLE_MAX_PRIVILEGE` exception. `IsTokenRestricted` is
deliberately not used because it reports restricting-SID presence, not
privilege-only restriction.

Normal completion and verification-error paths call `RevertToSelf`. Token open,
duplication, restriction, type/level query, bounded privilege read, sensitive
enabled privilege, assignment, read-back, verification, or revert failure is a
diagnostic and cannot supply publisher trust. A best-effort Drop revert covers
unwinding, while the normal path reports cleanup failure explicitly.

## Scripted Verification

All implementation, test, verifier, validator, source-contract, and
documentation changes were completed before the first checkpoint-2203 test.
No passing result is claimed at the end of this scripting phase.

| Control | Planned evidence | Pre-execution classification |
| --- | --- | --- |
| Real restricted impersonation token | Windows unit creates, applies, reads back, validates, reverts, and repeats | Scripted, unverified |
| Sensitive privilege rejection | Benign synthetic `LUID_AND_ATTRIBUTES` keeps traverse allowed but rejects another enabled LUID | Scripted, unverified |
| Release Local Core and Guard compatibility | Existing helper smoke proves embedded Edge, catalog PowerShell, unsigned text, and wrong hash through both release hosts | Scripted, unverified |
| Central verifier | New mandatory focused step; exact full count increases from 232 to 233 | Scripted, unverified |
| Report integrity | Validator requires the step, least-privilege scope, residual process-token limitation, and exact 233 count | Scripted, unverified |
| Dependency boundary | Existing pinned `windows-sys 0.61.2`; no new feature, crate, package, executable, or network path | Source-accounted, unverified |

Planned focused commands include:

```powershell
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_authenticode_helper_restricted_thread_token -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_authenticode_helper -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml windows_authenticode::tests -- --test-threads=1
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml
cargo build --release --manifest-path core\zentor_guard_service\Cargo.toml
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-authenticode-helper-smoke.ps1 -LocalCorePath target\release\zentor_local_core.exe -GuardPath target\release\zentor_guard_service.exe -RepoRoot .
python tools\testing\run-python-source-contracts.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2203-small-threat-mvp-restricted-token-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2203-small-threat-mvp-restricted-token-report.json -RequireFullSuite
```

Focused checks are followed by complete Native, locked workspace, strict lint,
Flutter/analyzer, safety/dependency/package gates, the definitive verifier,
adversarial stale/missing-scope report rejection, exact-head hosted CI/packages,
normal PR merge, merged-main evidence, and preconditioned original-tree sync.

## Local Execution Evidence

The requested scripting-first sequence was preserved. After the complete batch
above was scripted, the restricted-token filter passed `2/2`, the complete
Windows Authenticode module passed `27/27`, and complete Native Engine passed
`462 + 6`. Strict Native, Local Core, and Guard Clippy, rustfmt, release Local
Core/Guard builds, and the two-host release Authenticode helper smoke passed.
The smoke verified embedded Edge trust, catalog-backed WindowsPowerShell trust,
unsigned rejection, and wrong-hash rejection without executing fixtures.

Both standard and all-feature locked Rust workspace suites passed. Flutter
analyze reported no issues, Dart protocol tests passed `14/14`, complete Flutter
passed `838/838`, and Python source contracts passed `632/632`. Cargo and Flutter
lockfiles are unchanged.

The definitive report ran from `2026-08-23T03:30:00.4835295Z` through
`2026-08-23T03:37:54.0647224Z` and passed exactly `233/233` steps with zero
failed steps in `473.5s`. Its built-in strict validator and a separate
`-RequireFullSuite` invocation passed. The same validator rejected checkpoint
2202's stale 232-step report and a temporary 233-step report missing the exact
privilege-stripped-token scope.

A post-suite read-only audit preserved the protected vault at exactly 16,072
files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending. Hosted
exact-head CI/package evidence, PR/merge, merged-main evidence, and safe
original-tree synchronization remain pending. No release, publication,
installation, service/driver start, Defender change, or vault mutation occurred.

## Hosted Implementation-Head Evidence

Implementation head `710e38ad78616b09736eafae14fd92f65b8b8b5c` passes
exact-head Avorax CI `32616072172`. Desktop Packages push run `32616060448` and
PR run `32616072173` pass package contracts, Windows x64 MSI/EXE, Linux x64
DEB/tar, macOS arm64/x64 DMG, six-artifact consolidation, checksums, and
lockfile SBOM evidence. Both publication jobs are skipped. No artifact was
installed, released, or published.

The documentation evidence commit, its exact-head CI/package checks, normal PR
merge, merged-main evidence, and preconditioned original-tree synchronization
remain pending.

## Residual Limits

This is thread privilege reduction, not a sandbox. The helper process retains
its parent process token, SID, integrity level, desktop, environment, and access
rights. Same-process native code could call `RevertToSelf`; no AppContainer,
restricted process token, separate desktop, authenticated cross-token IPC, or
installed LocalSystem boundary is proved. The Job still bounds commit rather
than physical working set or I/O, and its CPU limit excludes kernel time.
Writable mappings, mutation after verdict, positive secondary-catalog fixture
coverage, production package signing, installed service/UI E2E, driver IPC,
pre-execution blocking, Defender replacement, and production detection-rate
evidence remain partial, blocked, or technically limited.

## Safety

Tests use only installed read-only Microsoft binaries and temporary benign text.
No fixture is executed. No live malware, EICAR host integration, download,
network acquisition, installation, service/driver start, Defender change,
release, publication, or protected-quarantine mutation is permitted.
