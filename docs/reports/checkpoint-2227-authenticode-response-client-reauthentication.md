# Checkpoint 2227 - Authenticode Response Client Reauthentication

Date: 2026-08-25 (Europe/Brussels)

## Objective

Reauthenticate the exact still-connected Authenticode named-pipe client after
the helper has flushed its response and emitted the exact response-ready marker,
but before launch/child token read-back and final ACK. This narrows persistent
pipe-client process or security-context drift across trust work without claiming
durable identity, encrypted IPC, or pre-execution enforcement.

## Implemented Boundary

After validating the bounded response-ready byte, the parent queries
`GetProcessId` on the exact retained child process handle and
`GetNamedPipeClientProcessId` on the exact retained server pipe instance. The
existing parent-child evidence validator requires the still-connected client PID
to equal that live process-handle PID and keeps parent and child IDs nonzero and
distinct.

The parent then calls `ImpersonateNamedPipeClient` again on that same connection.
The fresh thread token must repeat exact SecurityImpersonation token type and
level, launch user SID, AuthenticationId and session ID, privilege stripping,
zero restricting SIDs, low integrity, mandatory no-write-up, canonical
virtualization state, and disabled UIAccess. Its own `TokenId` and `ModifiedId`
must remain stable across the complete second validation. `RevertToSelf` must
succeed and a subsequent thread-token open must prove no impersonation remains.

Only after response-client process binding and token reauthentication succeed
does the parent revalidate the retained launch token and exact live child process
token, then send the final ACK. Process-handle, pipe peer, PID binding,
impersonation, token query/profile/stability, revert, launch/child read-back,
ACK, timeout, cancellation, termination, reap, desktop, or worker failure is
diagnostic and cannot become publisher trust. No weaker retry exists.

## Scripted Regressions And Evidence

The benign production regression runs the existing isolated child fixture under
the bounded restricted helper lifecycle, requires successful output, and proves
the parent test thread has no token before or after completion. The adversarial
regression supplies an invalid process handle and then an invalid pipe handle;
both must fail with phase-specific diagnostics while leaving no parent thread
token. Candidate fixtures are never executed.

Source contract 657 pins the production ordering from exact response-ready
validation through client PID binding, fresh token reauthentication, launch and
child token read-back, and final ACK. It also requires both Rust regressions,
the central verifier target, exact validator count/scopes, this report, audit
coverage, and explicit limitations.

The definitive verifier adds the mandatory step `native-engine Authenticode
response client-reauthentication regressions`. Strict validation now requires
exactly 257 successful steps plus the new verified and technically-limited scope
fragments. Stale 256-step evidence cannot satisfy this source revision.

No checkpoint-2227 passing result is claimed during scripting. Production code,
benign/adversarial Rust tests, source contract 657, exact 257-step verifier and
validator contracts, and all required documentation are being completed before
any checkpoint-2227 parser, formatter, build, lint, test, smoke, or verifier run.

## Security Limits

This is a second point-in-time authentication of the still-connected pipe, not
a durable token-object identity proof. Windows may create a distinct
impersonation token object for each `ImpersonateNamedPipeClient` call, so
cross-snapshot impersonation `TokenId` equality is technically unavailable and
is not claimed. Each snapshot instead proves exact identity/security profile and
intra-validation object stability.

The ready byte, final ACK, and response bytes remain unencrypted flow control
and are not cryptographically bound to either token snapshot. The control cannot
observe every transient between checks or after final ACK, prevent privileged
same-session injection or handle duplication, defeat a compromised parent or
kernel, or provide cross-identity IPC, AppContainer/LPAC, installed LocalSystem,
production signing, signed-driver enforcement, or demonstrated pre-execution
blocking.

## Dependency And Safety Boundary

The change reuses pinned `windows-sys` process, named-pipe, impersonation, and
token-query APIs plus existing repository verification tooling. It adds no
crate, package, feature, binary, network source, script host, runtime component,
or lockfile change. No live malware, malware repository, downloaded candidate,
executable fixture, Defender change, machine-wide installation, service/driver
start, release, or publication is involved. The protected quarantine remains
read-only and `.verification` remains outside staging.

## Scripting-Phase Status

Implementation, regressions, source/verifier/validator contracts, and report,
status, run-log, control-matrix, threat-model, blocker, and dependency records
are scripted. Execution and all local, hosted, integration, synchronization,
and destination evidence remain pending. The complete antivirus goal remains
active.

## Initial Focused Execution

The two new benign/adversarial Rust regressions compile and pass `2/2`; both
PowerShell parsers and `git diff --check` pass. The first formatter check rejected
one mechanically noncanonical call layout, and the first source-contract run
executed all 657 contracts but failed the new documentation matrix because the
known-blockers record described the behavior without the explicit `reauth` term.
Neither failed check is credited as a pass. The call layout and exact blocker
wording are repaired without changing behavior or weakening a contract; the
complete focused rerun passes.

## Corrected Focused And Full Local Verification

After the exact formatting and blocker-wording repairs, both PowerShell parsers,
`cargo fmt --check`, `git diff --check`, source contracts `657/657`, and the
focused response-client reauthentication regressions `2/2` pass. The complete
Authenticode module passes `72` tests with `15` intentionally ignored benign
fixtures. Native passes `508` tests with `15` ignored plus signature compiler
`6/6`; Local Core passes `536/536`; Guard passes `248/248`.

Both standard and all-feature locked workspace test suites pass. Strict
all-target/all-feature Clippy passes for Native, Local Core, and Guard; standalone
Native locked/offline all-target/all-feature checking passes. Locked release
builds pass for Local Core and Guard, and the benign two-host release smoke
verifies mandatory hash-bound nonce IPC, embedded/catalog Microsoft trust,
unsigned rejection, and hash mismatch without executing candidate content.
Flutter analysis reports no issues and all `838/838` tests pass.

This is full local regression evidence, not definitive 257-step, hosted,
package, integration, synchronization, or destination evidence. Those phases
remain pending and the complete antivirus goal remains active.

## Definitive Local Evidence

The no-skip, no-Defender/EICAR Windows PowerShell 5.1 verifier ran from
`2026-08-24T23:39:54.4842664Z` through `2026-08-24T23:47:27.7479027Z` and
passed exact `257/257`, zero failed or skipped, in `453.2s`. The new mandatory
response client-reauthentication target passed in `0.2s`. Both the embedded and
independently repeated `-RequireFullSuite` validators accept the report.

Twelve controlled malformed copies covering schema, failed status, Defender
option, both skip options, missing target, both new verified-scope fragments,
both new technical-limit fragments, failed final step, and stale 256-step count
are rejected with exit code 1. Two exact cleanup attempts were rejected by local
command policy before execution, so the isolated copies remain only under
untracked `.verification`; no product or protected-vault path was touched.

Root Cargo, Native Cargo, and Flutter lock blobs remain
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. The read-only protected quarantine
remains exactly 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
payload/metadata/auth, one metadata-auth key, and zero pending/temp. Hosted,
package, integration, synchronization, and destination evidence remain pending.

## Implementation-Head Hosted Evidence

Exact implementation `cef0d282acf58e9260492ac3dd7b300fdd9ee5f4` passes all
five Avorax CI jobs in run `32791340856`. Desktop Packages push and draft-PR
runs `32791317044` and `32791340840` pass package contracts, Windows x64 MSI/
EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, and consolidation; publication is
skipped. Draft PR `#79` remains unmerged.

Untouched consolidated artifacts `9543648381` and `9543559227` have SHA-256
`264f26824cca39b1852cff2cafc549a4a85ab1560f1d29378a0351765df92eb9`
and `f67375780a6a32527a26aaeb25ac7b9e2acc1b7b2a7b5196806fe40eca3800e0`.
Read-only in-stream validation, without extraction or execution, requires and
passes exactly eight root entries, six platform files, seven matching SHA-256
rows, and a CycloneDX 1.6 lockfile SBOM with 569 components in each artifact.

The implementation-head runs are supporting evidence; complete integration and
destination closure is recorded below. No release or publication occurred.

## Integration And Destination Closure

Evidence commit `c63fb71a4cd0834d8a014b646b40197cbc6119bb` passes all five
Avorax CI jobs in run `32792981574`. Desktop Packages run `32792981950`
passes package contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, both macOS
DMGs, and consolidation; publication is skipped. Untouched consolidated
artifact `9544267760` has SHA-256
`0ecaf5ea3e976c282dae9afe2fd36bf7f2f587d9ec932a337a8a70f936f79c5d`
and passes exact eight-root-entry, six-platform-file, seven-checksum, and
CycloneDX 1.6/569-component in-stream validation without extraction or
execution.

PR `#79` was made ready and head-locked, then normally merged without admin
bypass or direct-main push as
`9304681badde248533788806bbe84a298726e241`. Its parents are main
`bab872d50daf5bbcc775a53e3c0788c51770ca33` and exact evidence
`c63fb71a4cd0834d8a014b646b40197cbc6119bb`. Merged-main CI
`32794436961` and packages `32794437034` pass all jobs; publication is
skipped. Untouched artifact `9544647451` has SHA-256
`e56a600c0515f9760e552088906db4a141b2aadf596c032155d5f1246f463fd4`
and passes the same exact stream-only checks without extraction or execution.

The merge changes exactly 12 paths from its first parent with zero deletes.
Preconditioned atomic synchronization copied those exact blobs to
`C:\Users\Brent\Documents\Avorax-main`, preserving unrelated files. A raw
hash audit first exposed expected LF/CRLF working-tree normalization; the
corrected path-aware Git-filter audit passed. Three PowerShell 5.1 sync helper
attempts failed before the first destination replacement because `ArgumentList`,
three-argument `File.Move`, and null-backup `File.Replace` were unavailable or
invalid. The corrected wrapper reused only exact staged blobs, completed all 12
replacements, verified every result, and removed exact backups. A later blob
wrapper incorrectly assumed the destination was a Git repository; corrected
absolute comparison through the authoritative repository passes `12/12`.
These support failures are retained and uncredited. Zero staging files, backups,
or deletes remain.

Destination parsers pass `2/2`, source contracts `657/657`, and the focused
response client-reauthentication target passes `2/2`. Complete Authenticode
passes `72/15`; Native passes `508/15` plus signature compiler `6/6`; Local
Core passes `536/536`; Guard passes `248/248`. Both standard and all-feature
locked workspaces, strict Native/Local/Guard Clippy, standalone Native locked/
offline checking, locked release builds, the benign two-host Authenticode smoke,
Flutter analysis, and Flutter `838/838` pass.

The destination definitive verifier ran from
`2026-08-25T01:04:32.3781546Z` through `2026-08-25T01:11:46.4460196Z`
and passes exact `257/257`, zero failed/skipped, in `434s`; the mandatory new
target passes in `0.2s` and the independent Windows PowerShell 5.1 validator
accepts the full report. The three lock blobs remain exact. The read-only vault
remains 16,072 files, zero directories, 4,522,733 bytes, 5,357 each payload,
metadata, and auth, one metadata-auth key, and zero pending/temp. `.verification`
remains untracked and unstaged.

Checkpoint 2227 is closed. Fresh response-boundary reauthentication remains the
documented point-in-time control, not cross-snapshot token-object equality,
cryptographic response binding, cross-identity/AppContainer isolation,
installed LocalSystem, signed-driver, or pre-execution proof. Nothing was
installed, executed as candidate content, released, or published, and the
complete antivirus goal remains active.
