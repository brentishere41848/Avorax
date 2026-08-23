# Checkpoint 2204: Authenticode Restricted Process Token

## Objective

Replace release Authenticode helper process-token inheritance with a verified
privilege-stripped primary token while preserving exact Microsoft signer,
scanned-content hash, timeout, Job, protocol, and fail-visible behavior.

Checkpoint 2203 integration is closed before this implementation: evidence head
`1a9703d`, PR `#55`, merge `b70298a`, merged-main CI `32617710173`, packages
`32617710182`, exact 12-file original-tree synchronization, destination focused
checks, and the protected-vault audit passed with publication skipped.

## Threat And Design

Checkpoint 2203 restricts the WinTrust thread, but its process still retains the
parent process token and same-process native code can call `RevertToSelf`.
Checkpoint 2204 creates a restricted primary token from the current process
token with `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` and launches the exact
locked current executable through `CreateProcessAsUserW`.

The child starts with `CREATE_SUSPENDED`. Only its stdin, stdout, and stderr pipe
handles are inheritable, and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` names exactly
those three distinct valid handles. The configured kill-on-close/resource-limit
Job is assigned before `ResumeThread`, so no helper instruction or candidate
processing runs outside the Job. Launch, handle-list, assignment, resume,
termination, or reap failures remain visible and cannot supply trust.

Before reading the helper request, the child opens and validates its effective
process token as an exact primary token with bounded `TokenPrivileges`; only
`SeChangeNotifyPrivilege` may remain enabled. The existing restricted
impersonation token remains defense in depth around direct candidate opening and
WinTrust. No fallback to the parent's unrestricted process token is allowed.

## Scripted Verification

All implementation, test, verifier, validator, source-contract, and
documentation changes are scripted before the first checkpoint-2204 test. No
passing result is claimed at the end of this scripting phase.

| Control | Planned evidence | Pre-execution classification |
| --- | --- | --- |
| Restricted primary token | Real child reads back exact primary type and bounded enabled privileges | Scripted, unverified |
| Exact handle inheritance | Win32 attribute-list construction names exactly three validated stdio handles; invalid/duplicate handles fail | Scripted, unverified |
| Suspended Job boundary | Child starts suspended, Job assignment precedes resume, and failure cleanup terminates/reaps | Scripted, unverified |
| Timeout compatibility | Benign ignored child fixture sleeps; parent must terminate and reap within the existing bounds | Scripted, unverified |
| Release compatibility | Local Core and Guard smoke must retain embedded/catalog Microsoft trust plus unsigned/wrong-hash rejection | Scripted, unverified |
| Central evidence | Dedicated verifier step; strict full count rises from 233 to 234 and validator requires exact scope | Scripted, unverified |
| Dependency boundary | Existing pinned `windows-sys 0.61.2`; add only its `Win32_System_Pipes` feature | Source-accounted, unverified |

Planned focused commands include:

```powershell
cargo fmt --all -- --check
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_authenticode_helper_restricted_process -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_authenticode_helper -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml windows_authenticode::tests -- --test-threads=1
cargo clippy --manifest-path core\zentor_native_engine\Cargo.toml --all-targets --all-features -- -D warnings
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml
cargo build --release --manifest-path core\zentor_guard_service\Cargo.toml
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-authenticode-helper-smoke.ps1 -LocalCorePath <absolute-local-core-path> -GuardPath <absolute-guard-path> -RepoRoot <absolute-repo-path>
python -B tools\testing\run-python-source-contracts.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2204-small-threat-mvp-restricted-process-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2204-small-threat-mvp-restricted-process-report.json -RequireFullSuite
```

Focused checks are followed by complete locked Rust workspace variants, strict
Local Core/Guard lint, Flutter/analyzer, security/dependency/package gates,
definitive verification, adversarial stale/missing-scope report rejection,
vault audit, exact-head hosted CI/packages, normal PR merge, merged-main
evidence, and preconditioned original-tree synchronization.

## Local Execution Evidence

The requested scripting-first sequence was preserved. After the complete batch
above was scripted, the restricted-process filter passed `2/2`, the complete
helper filter passed `9/9`, and the Windows Authenticode module passed `29/29`
with only its two internal child fixtures intentionally ignored. Complete Native
Engine passed `464` with two child fixtures ignored, plus `6/6` signature
compiler tests. Strict Native, Local Core, and Guard Clippy, rustfmt, locked
release Local Core/Guard builds, and the two-host release Authenticode helper
smoke passed.

The release smoke verified mandatory hash-bound nonce IPC, embedded Edge trust,
catalog-backed Windows PowerShell trust, unsigned rejection, and wrong-hash
rejection through both hosts without executing a candidate. Both standard and
all-feature locked Rust workspace suites passed. Flutter analyze reported no
issues, Dart protocol tests passed `14/14`, and complete Flutter passed
`838/838`.

Python source contracts passed `633/633`; package source contracts passed
`21/21` with three Windows privilege-dependent symlink cases explicitly
skipped. Branding, product-copy, no-malware, false-positive, protection,
performance, prerequisite, bundled-pack, and dependency-evidence gates passed.
Cargo and Flutter lockfiles are unchanged.

The definitive report ran from `2026-08-23T05:07:31.2524711Z` through
`2026-08-23T05:15:05.704596Z` and passed exactly `234/234` steps with zero
failed steps in `454.4s`. Its built-in strict validator and a separate
`-RequireFullSuite` invocation passed. The same validator rejected checkpoint
2203's stale 233-step report, a temporary 234-step report missing the exact new
step, and a temporary 234-step report missing the required exact handle-list
scope. Temporary adversarial reports were removed.

A post-suite read-only audit preserved the protected vault at exactly 16,072
files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.
Exact-head hosted CI/packages, PR/merge, merged-main evidence, and safe
original-tree synchronization remain pending. No live malware, installation,
service/driver start, Defender change, release, publication, or protected-vault
mutation occurred.

## Hosted Implementation-Head Evidence

Implementation head `a0272a3654c959b68def34025ff7c18d1285e243` passes
exact-head Avorax CI `32620196065`. Desktop Packages push run `32620187506` and
PR run `32620196066` pass package contracts, Windows x64 MSI/EXE, Linux x64
DEB/tar, macOS arm64/x64 DMG, six-artifact consolidation, checksums, and
lockfile SBOM evidence. Both publication jobs are skipped. No artifact was
installed, released, or published.

The documentation evidence commit, its exact-head CI/package checks, normal PR
merge, merged-main evidence, and preconditioned original-tree synchronization
remain pending.

## Integration Closure

Evidence head `930342f59de1b11f458dc33ae8570e1eb7a6fd33` passed Avorax CI
`32620868967` and Desktop Packages `32620868963`. PR `#56` merged normally with
exact-head locking as `a5f982a993659641d08ff45750894b3bfd969074`.
Merged-main CI `32621422088` and packages `32621422056` passed every platform,
six-artifact consolidation/checksums, and lockfile SBOM; publication was
skipped.

All 12 original-tree preconditions matched checkpoint 2203 or valid absence.
Exactly those files synchronized to `C:\Users\Brent\Documents\Avorax-main` and
matched merged Git blobs plus raw source SHA-256. Destination contracts
`633/633`, restricted process `2/2`, Authenticode `29/29` plus two ignored child
fixtures, rustfmt, strict Native Clippy, release Local Core/Guard builds, and
two-host benign smoke passed. The protected vault remained exactly 16,072
files, zero directories, 4,522,733 bytes, 5,357 each payload/metadata/auth, one
key, and zero pending. No artifact was installed, released, or published.

## Residual Limits

This is privilege stripping, exact handle inheritance, and pre-resume Job
containment, not an AppContainer or identity sandbox. The restricted primary
token keeps the parent SID, integrity level, environment, desktop, and ordinary
SID-based access because no restricting SIDs are configured. `CreateProcessAsUserW`
and Windows token/pipe/Job semantics remain trusted. The environment is
inherited and untrusted configuration remains subject to each existing parser.

The Job still bounds commit rather than physical working set or I/O, and its
CPU ceiling excludes kernel time. Writable mappings, post-verdict mutation,
positive secondary-catalog fixture coverage, production package signing,
installed LocalSystem E2E, signed-driver IPC, pre-execution blocking, Defender
replacement, and production detection-rate evidence remain partial, blocked,
or technically limited.

## Safety

Tests use only installed read-only Microsoft binaries, temporary benign text,
and ignored Rust test-process fixtures. Candidate fixtures are never executed.
No live malware, EICAR host integration, network acquisition, installation,
service/driver start, Defender change, release, publication, or protected-vault
mutation is permitted.
