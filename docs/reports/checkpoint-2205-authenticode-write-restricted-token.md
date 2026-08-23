# Checkpoint 2205: Authenticode Write-Restricted Token

## Objective

Reduce the release Authenticode helper's write authority without weakening its
cache-only embedded/catalog verification. Keep checkpoint 2204's verified
`DISABLE_MAX_PRIVILEGE` primary process token, then apply a
`SecurityImpersonation` token that also uses `WRITE_RESTRICTED` and exactly one
`WinRestrictedCodeSid` before stdin or untrusted request parsing. Verify the
effective thread-token state around request parsing, read-only candidate
preparation, and response output while preserving valid Windows trust/catalog
behavior.

Checkpoint 2204 is closed first. Evidence head
`930342f59de1b11f458dc33ae8570e1eb7a6fd33` passed Avorax CI `32620868967`
and Desktop Packages PR `32620868963`. PR `#56` merged normally with exact-head
locking as `a5f982a993659641d08ff45750894b3bfd969074`; merged-main CI
`32621422088` and packages `32621422056` passed every platform,
consolidation/checksums, and lockfile SBOM while publication was skipped.
Exactly 12 preconditioned files synchronized to
`C:\Users\Brent\Documents\Avorax-main`; every Git blob and raw SHA-256 matched.
Destination contracts `633/633`, process token `2/2`, Authenticode `29/29`
plus two ignored child fixtures, rustfmt, strict Native Clippy, release builds,
and two-host benign smoke passed. The protected vault remained exact.

## Security Design

Microsoft's restricted-token contract performs a second restricting-SID access
check. `WRITE_RESTRICTED` applies that second check only to write access. Avorax
creates the well-known Restricted Code SID with `CreateWellKnownSid`, supplies
one zero-attribute `SID_AND_ATTRIBUTES` input to `CreateRestrictedToken`, and
retains `DISABLE_MAX_PRIVILEGE` in the same call. This token is applied to the
helper thread before stdin is read. Windows returns that active restricting SID
with exact mandatory, default-enabled, and enabled attributes.

The resulting token is accepted only when all of these conditions hold:

- token type is exactly `SecurityImpersonation`;
- only `SeChangeNotifyPrivilege` may remain enabled;
- `TokenRestrictedSids` has a bounded response and count;
- every returned SID pointer and length stays inside the returned buffer;
- the single SID is structurally valid, at most `SECURITY_MAX_SID_SIZE`, has
  exact `SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED`
  attributes, and byte-matches `WinRestrictedCodeSid` exactly.

The parent validates the privilege-stripped primary token before
`CreateProcessAsUserW`; the child reads back that effective primary token before
request parsing. The child then creates, applies, and reads back the
write-restricted impersonation token before stdin or request parsing. Strict
request parsing and read-only candidate open/size/identity snapshot remain
under it. The helper reverts fail-visibly before WinTrust, catalog, signer, and
content-hash work under the privilege-stripped primary token. It creates,
applies, and reads back a fresh restricted token before serializing/writing the
response. Token setup, validation, revert, or reapplication failure prevents
publisher trust.

An initial design also applied the restricting SID to the primary token. On the
supported Windows host, that child terminated before user code with
`0xC0000142` (`STATUS_DLL_INIT_FAILED`). The final design keeps the verified
checkpoint-2204 primary token; it does not retry a failed launch with weaker
settings or silently bypass the write-restricted thread token.

A first release smoke also kept the thread token active through WinTrust and
catalog work. Embedded Edge verification fell through and the catalog hash API
returned Windows error `127`. The implementation does not retry a failed trust
call. Instead, the final scope performs the trusted OS trust/catalog phase once
under the already privilege-stripped primary token and records that write
restriction does not cover this phase.

This boundary does not revoke rights already represented by the three inherited
stdio handles. It also does not promise that every possible write is denied: an
object whose ACL independently grants the required write to both normal and
restricting access checks may remain writable. The regression therefore makes
the exact supported claim that an ordinary user-owned temporary file cannot be
opened for write while its read/hash path remains usable.

## Verification Plan

All final-design implementation, benign test, verifier, validator,
source-contract, audit, threat-model, dependency, status, and run-log changes
are scripted before running that complete batch. Preliminary focused runs first
showed that Windows returns canonical restricting-SID attributes `0x00000007`,
then showed that a write-restricted primary token stops in the loader with
`0xC0000142`. The first release smoke then showed Windows trust/catalog error
`127` while the thread restriction remained active. Those findings shaped the
final pre/post-trust write-restriction design.
No final-design passing result is claimed at the end of this scripting phase.

| Control | Planned evidence | Pre-execution classification |
| --- | --- | --- |
| Exact restricting SID | Real token query plus pure missing/duplicate/wrong-SID/unexpected-attribute policy cases | Verified locally |
| Write denial with read continuity | Ignored child fixture reads and hashes an isolated benign file but receives access denied for a write open | Verified locally |
| Existing process/thread boundary | Privilege-stripped primary plus pre/post-trust write-restricted thread read-back filters retain exact type, privilege, SID, and cleanup evidence | Verified locally |
| Publisher compatibility | Embedded Edge, catalog-backed Windows PowerShell, unsigned, and wrong-hash release smoke through Local Core and Guard | Verified locally |
| Central evidence | Dedicated write-restricted step; strict count rises from 234 to 235 and validator requires exact scope | Verified locally, `235/235` |
| Dependency boundary | Existing pinned `windows-sys 0.61.2`; add only `Win32_System_SystemServices` for official SID-attribute constants | Verified locally; no lockfile change |

## Focused Local Evidence

The final pre/post-trust design passes its focused local checks:

- dedicated write-restriction tests: `2/2`;
- existing restricted-process tests: `2/2`;
- existing restricted-thread tests: `2/2`;
- complete Windows Authenticode module: `31/31`, with only three isolated child
  fixtures intentionally ignored;
- strict Native Clippy and rustfmt;
- Python source contracts: `634/634`;
- locked release Local Core and Guard builds;
- two-host release smoke: embedded Edge and catalog-backed Windows PowerShell
  Microsoft trust, unsigned rejection, and wrong-hash failure all pass.

The smoke executes no candidate.

## Full Local Evidence

- `cargo test --workspace --locked -- --test-threads=1`: passed;
- `cargo test --workspace --all-features --locked -- --test-threads=1`: passed;
- complete Native Engine: `466` tests plus signature compiler `6/6`, with three
  isolated child fixtures intentionally ignored;
- strict Native Engine, Local Core, and Guard Clippy: passed;
- `flutter analyze`: no issues;
- complete Flutter suite: `838/838`;
- Python source contracts: `634/634`;
- definitive verifier: `235/235`, status `passed`, from
  `2026-08-23T06:52:03Z` through `2026-08-23T06:59:53Z` in `470.1s`;
- built-in and independent `-RequireFullSuite` report validation: passed;
- adversarial report validation: stale count rejected with expected `235` but
  found `234`; missing required checkpoint-2205 step rejected; missing exact
  pre/post-trust scope rejected; controlled copies removed;
- read-only protected-vault audit: 16,072 files, zero directories, 4,522,733
  bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, zero
  pending.

Exact implementation head `a5597d263208e3ceeb35f75aa29a09559459f3d3`
passes Avorax CI `32624862111` and Desktop Packages push/PR runs
`32624842967`/`32624862058`. Package contracts, Windows x64 MSI/EXE, Linux x64
DEB/tar, macOS arm64/x64 DMG, six-artifact consolidation, checksums, and
lockfile SBOM evidence pass. Publication was skipped. Evidence-head checks,
merge, merged-main, and original-tree synchronization remain pending.

Reproducible focused and definitive commands include:

```powershell
cargo fmt --all -- --check
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_authenticode_helper_write_restricted -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_authenticode_helper_restricted_process -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_authenticode_helper_restricted_thread_token -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml windows_authenticode::tests -- --test-threads=1
cargo clippy --manifest-path core\zentor_native_engine\Cargo.toml --all-targets --all-features -- -D warnings
python -B tools\testing\run-python-source-contracts.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2205-small-threat-mvp-write-restricted-token-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2205-small-threat-mvp-write-restricted-token-report.json -RequireFullSuite
```

Focused checks are followed by complete locked workspace variants, strict
Local Core/Guard lint, release builds and two-host smoke, Flutter/analyzer,
security/dependency/package gates, definitive verification, adversarial
stale/missing-step/missing-scope report rejection, a read-only vault audit,
exact-head hosted checks, normal PR merge, merged-main evidence, and
preconditioned original-tree synchronization.

## Residual Limits

`WRITE_RESTRICTED` and `WinRestrictedCodeSid` reduce write access while the
impersonation token is active; they do not create an AppContainer, change
identity, lower integrity, isolate the desktop, sanitize the inherited
environment, authenticate cross-identity IPC, or limit ordinary read access.
The helper retains the parent SID. Existing inherited handle rights and objects
whose ACL satisfies both access checks remain outside the ordinary-file
regression's claim. The primary process token is privilege-stripped but not
write-restricted, same-process code can technically call `RevertToSelf`, and
WinTrust/catalog intentionally execute under that primary token because the
verified host returned error `127` under write restriction.

The Job still bounds commit rather than physical working set or I/O and its CPU
limit excludes kernel time. Writable mappings, post-verdict mutation,
production package signing, installed LocalSystem E2E, signed-driver IPC,
pre-execution blocking, Defender replacement, and production detection-rate
evidence remain partial, blocked, or technically limited.

## Safety

Tests use only installed read-only Microsoft binaries and isolated benign text.
Candidate fixtures are never executed. No live malware, EICAR host integration,
network acquisition, installation, service/driver start, Defender change,
release, publication, or protected-vault mutation is permitted.
