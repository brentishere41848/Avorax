# Checkpoint 2207: Authenticode Process Mitigation Policy

## Status

Verified locally. Implementation, benign child regressions, source contracts,
verifier/validator changes, audit records, and this report were scripted as one
batch before test execution.

No checkpoint-2207 passing result is claimed before execution; the results
below were recorded only after that complete batch ran.

## Checkpoint 2206 Integration Closure

Checkpoint 2206 evidence head
`5bbe6bd7285e1f8a47f22949bc27b2206a73ae54` passed Avorax CI
`32630589688` and Desktop Packages `32630589681`. PR `#58` merged normally as
`8e9b6720c17711e39a4e4d31604728d5a61c1bf1`. Merged-main Avorax CI
`32631277590` and Desktop Packages `32631277605` passed Windows x64 MSI/EXE,
Linux x64 DEB/tar, macOS arm64/x64 DMG, consolidation, checksums, and lockfile
SBOM; publication was skipped.

Exactly 12 preconditioned paths synchronized to
`C:\Users\Brent\Documents\Avorax-main` and matched merged Git blobs plus raw
source SHA-256. Destination source contracts `635/635`, sanitized launch
`2/2`, complete Authenticode `33/33` with four intentional child-fixture
ignores, strict Native Clippy, locked Local Core/Guard release builds, and the
two-host embedded/catalog/hash-binding smoke passed. The protected vault stayed
exact at 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.

## Objective

The checkpoint-2206 helper starts with a privilege-stripped primary token,
write-restricted request/output thread tokens, exact inherited handles, a
bounded Job, and sanitized environment/current-directory state. It did not yet
apply exploit or image-loading mitigations during process creation.

Checkpoint 2207 adds `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` beside the
existing exact handle-list attribute. Its immutable `DWORD64` enables:

- permanent strict handle checks;
- legacy extension-point disable;
- dynamic-code prohibition;
- Microsoft-signed-only executable image loading;
- remote executable image rejection;
- low-mandatory-label executable image rejection; and
- System32 executable image preference.

The child reads back binary-signature, dynamic-code, extension-point,
image-load, and strict-handle policies with `GetProcessMitigationPolicy` before
stdin or request parsing. Missing, store-only, partial, malformed, or unreadable
evidence fails visibly and cannot become publisher trust. Attribute sizing,
initialization, handle-list update, mitigation update, process creation, or
read-back failure has no weaker retry.

Microsoft documents that a process-creation mitigation value persists through
the attribute-list lifetime and cannot be changed after the child starts:
[UpdateProcThreadAttribute](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).

## Source Contract

- The attribute list is sized for exactly two attributes.
- The mitigation policy is stored in a `Box<u64>` so its address remains valid
  until `DeleteProcThreadAttributeList`.
- The three inherited pipe handles remain exact, distinct, valid, and the only
  handles named by `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
- The process is still created suspended, assigned to the configured Job, and
  resumed only after successful assignment.
- Child read-back precedes the first write-restricted token entry and all stdin,
  JSON, path, candidate, WinTrust, and response work.
- Policy application/read-back failure is diagnostic; there is no process
  launch without the mitigation attribute.
- Strict-handle read-back requires both invalid-handle exception and permanent
  enforcement flags; temporary debugger-induced evidence is rejected.

`windows-sys 0.61.2` exposes the attribute key, API, policy selectors, and
native structures but does not expose the documented process-creation policy
bit constants. The source therefore defines only the seven reviewed Microsoft
bit values locally and has a pure exact-word regression. No new binding crate
or dynamic API loader is introduced.

## Local Evidence

| Control | Evidence | Classification |
| --- | --- | --- |
| Exact policy word | Pure regression requires the seven documented bits and rejects missing Microsoft-only, dynamic-code, extension, each image-load, absent strict-handle, or temporary-only strict-handle evidence; focused filter passed `2/2` | Verified locally |
| Attribute lifetime | Source contract requires two attributes and boxed stable policy storage until list deletion; source contracts passed `636/636` | Verified locally |
| Real child read-back | Ignored benign child fixture queried all five native policy groups before stdin and passed on the Windows host | Verified locally |
| Trust compatibility | Local Core and Guard release smoke passed embedded Edge trust, catalog-backed WindowsPowerShell trust, unsigned rejection, and wrong-hash rejection without executing a fixture | Verified locally |
| Central evidence | Definitive verifier and built-in plus independent validators passed exactly `237/237`; four controlled malformed report copies were rejected | Verified locally |
| Dependency boundary | Existing pinned `windows-sys 0.61.2`; no Cargo feature, dependency, or lockfile change | Verified locally; hosted package/SBOM evidence pending |

## Verification Results

- PowerShell parsing and rustfmt passed. Process-mitigation, restricted-process,
  sanitized-launch, and write-restricted filters passed `2/2` each. Complete
  Authenticode passed `35/35` with five intentional ignored benign child
  fixtures.
- Strict Native, Local Core, and Guard Clippy passed. Locked Local Core and
  Guard release builds and both release-host smoke runs passed. Standard and
  all-feature locked Rust workspaces passed; Native Engine reported `470`
  tests plus `6/6` signature-compiler tests with five intentional ignores.
- Flutter analyze and all `838/838` Flutter tests passed. Source contracts
  passed `636/636`. `Cargo.lock` and `apps/zentor_client/pubspec.lock` remained
  unchanged.
- The final-review definitive report passed exactly `237/237` steps from
  `2026-08-23T10:20:56.5184238Z` through
  `2026-08-23T10:28:38.6621624Z` in `462.1s`. Its built-in validator and a
  separate strict invocation passed.
- Controlled copies with 236 steps, a missing mitigation step, missing exact
  verified scope, or missing exact technical-limit scope were each rejected
  and removed. A read-only vault audit remained exact at 16,072 files, zero
  directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending.

Exact implementation head
`a9d930a63c4e453bfdea2e2e41d99a9004287e56` passed Avorax CI
`32634033002` and Desktop Packages push/PR runs
`32634021590`/`32634032975`. Both package runs passed contracts, Windows x64
MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, consolidation, six-artifact
checksums, and lockfile SBOM; publication was skipped. Evidence-head checks,
normal PR merge, merged-main checks, and safe original-tree synchronization
remain pending.

Final review compared read-back flags with the Windows SDK and Microsoft strict
handle policy contract. The source now requires both invalid-handle exception
and permanent-enforcement flags and adds a temporary-only rejection fixture.
The stricter focused regression passed `2/2`, complete Authenticode passed
`35/35` with five intentional child-fixture ignores, strict Native Clippy and
source contracts `636/636` passed, and the fresh definitive rerun and strict
validators passed `237/237` in `462.1s`.

## Limits

Process-creation mitigations do not constrain the already mapped helper image
or non-image data. They do not lower integrity, change identity, isolate the
profile/registry/desktop, remove ordinary read access, prevent same-process
`RevertToSelf`, or create AppContainer/authenticated cross-identity IPC.

Microsoft-signed-only image loading can be incompatible with non-Microsoft
trust providers, injected security modules, or future third-party helper
dependencies. Avorax does not retry with weaker policy. Local release-host
compatibility cannot prove every installed enterprise configuration. Existing
writable mappings, post-verdict mutation, production signing, installed
LocalSystem E2E, driver enforcement, pre-execution blocking, Defender
replacement, and production accuracy remain partial, blocked, or technically
limited.

## Safety

Tests use ignored benign Rust child fixtures, installed read-only Microsoft
binaries, and temporary benign text only. Candidate fixtures are never
executed. No live malware, download, install, service/driver start, Defender
change, release, publication, or protected-quarantine mutation is permitted.
