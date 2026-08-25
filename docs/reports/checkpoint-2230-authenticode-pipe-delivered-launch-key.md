# Checkpoint 2230 - Authenticode Pipe-Delivered Launch Key

## Objective

Remove the per-launch handshake/MAC key from the restricted helper's environment
without weakening exact child identity, cancellation, response authentication,
or fail-visible diagnostics. This is same-user user-mode hardening, not
cross-identity IPC, encryption, driver enforcement, or pre-execution blocking.

## Scripted Control

The parent still creates a canonical random 36-byte UUID key and a distinct
canonical named-pipe UUID. The sanitized child environment now contains only the
canonical pipe name, canonical parent PID, and checked native
`SystemRoot`/`WINDIR`; it contains no launch token or response MAC key.

After connection and before disclosing the key, the parent binds the pipe client
PID to the exact retained child process, authenticates the connected
SecurityImpersonation token's user/logon session and restricted profile, and
revalidates retained launch/child token stability. Only then does it deliver the
exact key over the retained duplex pipe. The child first verifies exact parent
PID and applied pipe ACL/mandatory label, reads a bounded key, requires canonical
random UUID syntax distinct from the pipe UUID, derives HMAC, and writes exact
ACK. Parent validates ACK and repeats launch/child stability before request
processing can continue.

Malformed, oversized, truncated, non-UTF-8, noncanonical, same-as-pipe, missing-
ACK, incomplete-I/O, timeout, process/token mismatch, or cancellation failure is
diagnostic and cannot become publisher trust. Existing response-ready client
reauthentication, HMAC verification before JSON, bounded termination/reap, and
embedded/catalog Microsoft-publisher requirements remain unchanged.

## Scripted Tests And Evidence Contract

- A real benign isolated child completes the production handshake and
  authenticated response while proving
  `AVORAX_AUTHENTICODE_HANDSHAKE_TOKEN` is absent before and after key receipt.
- Existing sanitized-environment regression requires exactly four entries:
  pipe name, parent PID, `SystemRoot`, and `WINDIR`.
- Source contract 660 requires parent identity/token checks before key delivery,
  child pipe/process/security checks before key read, exact ACK ordering, no
  production environment read/write of the key, benign child regression,
  verifier target, strict validator scope, and synchronized documentation.
- The central verifier adds `native-engine Authenticode pipe-delivered
  launch-key regressions`; full-suite validation requires exactly 260 steps.

## Dependency And Safety Boundary

No crate, package, feature, lockfile, executable, network source, service,
driver, installer, or machine-wide component is added. Fixtures emit fixed
benign text and are never candidate-executed. No Defender setting, installed
service/driver, publication path, or protected quarantine content is touched.

## Verification Status

No checkpoint-2230 passing result is claimed during scripting. Implementation,
test scripting, source contract 660, exact 260-step verifier/validator changes,
and audit/threat/dependency/status documentation are complete before any
checkpoint-2230 formatter, parser, compiler, test, smoke, or verifier execution.

After that complete scripting phase, local execution passed both PowerShell
parsers, formatting/diff checks, source contracts `660/660`, the new benign
pipe-delivered-key regression `1/1`, adjacent handshake/token/MAC targets
`9/9`, Native `513 passed/18 ignored` plus signature compiler `6/6`, Local Core
`536/536`, Guard `248/248` and all-features `249/249`, both locked workspace
modes, strict affected-crate Clippy, offline Native resolution, three release
builds, PS7/PS5 release Authenticode smoke, Flutter analyze, and Flutter
`838/838`. At that point definitive 260-step verification, hosted exact-head
evidence, integration, synchronization, and destination proof still remained
pending; the definitive local result is recorded below.

## Definitive Local Evidence

The no-skip, no-Defender-integration verifier ran from
`2026-08-25T07:53:23.8458080Z` through
`2026-08-25T08:01:03.7456483Z` and passed exact `260/260`, zero failed or
report-level skipped steps, in `459.9s`. The new pipe-delivered launch-key step
passed in `0.2s`. The embedded strict validator and an independently repeated
Windows PowerShell 5.1 `-RequireFullSuite` invocation accept the report.

Sixteen isolated `.verification` report copies are rejected with nonzero exit:
changed schema, failed overall status, Defender/EICAR enabled, either Flutter or
Rust skip, renamed mandatory target, each of six checkpoint verified-scope
claims, each of two technical-limit claims, failed final step, and stale
259-step evidence. They remain untracked and are never staged.

The package source-contract unittest reports three expected Windows skips for
symlink creation requiring optional privileges; its other 21 tests pass and the
central verifier records the complete step as passed. This does not claim those
Windows symlink-positive fixtures executed. A PS7-only independent validator
attempt is uncredited because PS7 converts ISO JSON strings to `DateTime` by
default while the strict validator requires original string types; the intended
PS5 host and embedded PS5 invocation both pass. The first adversarial harness
stopped on expected native stderr before counting rejection; corrected capture
passes `16/16`. Earlier source-contract and stdout-assertion failures remain
documented in the run log and are not credited.

Root/Native/Flutter lock blobs remain exact. No test process remains. The
read-only protected vault remains 16,072 files, zero directories, 4,522,733
bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending/temp/reparse. Nothing was installed, published, executed as candidate
content, or changed in Defender. Hosted exact-head, integration,
synchronization, and destination evidence remain pending.

## Technical Limits

Removing the key from the environment narrows passive same-user environment
disclosure. The key still exists in parent/child memory and crosses the
authenticated same-user pipe. Same-user process-memory read access, sufficiently
privileged injection, pipe-handle duplication or observation, compromised
endpoints, administrator/SYSTEM, or kernel compromise may recover it or modify
both response and MAC. This is not encryption, cross-identity authentication,
durable secret/token-object binding, AppContainer/LPAC, installed LocalSystem,
signed-driver, or pre-execution enforcement. The complete antivirus project
remains active.
