# Checkpoint 2231 Authenticode Key-Confirmation HMAC

Date: 2026-08-25 (Europe/Brussels)

## Status

Scripting and definitive local execution are complete. Exact-head hosted CI and
package evidence, PR/merge, guarded original-tree synchronization, and
independent destination verification remain pending. No hosted, integration, or
destination result is claimed yet. No checkpoint-2231 passing result is claimed
during scripting; every passing result below was obtained only after the entire
scripted implementation, test, verifier, contract, and documentation batch was
complete.

## Objective

Replace the fixed public one-byte launch-key ACK with cryptographic proof that
the exact already PID/token-bound same-user pipe client possesses the canonical
36-byte per-launch key delivered by the parent. Preserve all existing pipe
security, process identity, connected-client token, launch/child token stability,
cancellation, terminate/reap, response HMAC-SHA-256, and fail-visible error
boundaries.

## Scripted Implementation

- Production no longer defines or accepts `AUTHENTICODE_HELPER_HANDSHAKE_ACK`.
- The child computes an exact 32-byte HMAC-SHA-256 under the delivered key with
  fixed domain `avorax-authenticode-handshake-key-confirmation-v1`.
- The authenticated context is exact and ordered: unsigned little-endian `u64`
  canonical pipe-name byte length, every canonical pipe-name byte, unsigned
  little-endian `u32` parent PID, then unsigned little-endian `u32` child PID.
- Canonical random pipe UUID validation remains mandatory. Parent/child PIDs
  must be nonzero and distinct.
- Parent reads into a 33-byte buffer to expose extension, requires exactly 32
  bytes, and calls `Hmac::verify_slice` under its retained key and exact pipe/PID
  context before post-confirmation launch and child token stability checks.
- Child pipe opening, parent-PID binding, applied DACL/mandatory-label read-back,
  bounded 37-byte key read, UTF-8/canonical UUID validation, and response MAC
  key retention remain fail-visible.
- Any wrong length, context, key, MAC, I/O, timeout, early exit, or unsettled
  cancellation remains an error and enters existing bounded child termination
  and reap cleanup. There is no public-byte fallback.

## Scripted Benign Tests

- Exact valid HMAC generation and constant-time verification.
- Empty, truncated, extended, and single-byte-mutated confirmations.
- Wrong key, canonical wrong pipe, wrong parent PID, and wrong child PID.
- Zero parent/child PID and equal parent/child PID rejection.
- Existing real restricted child success path under production key delivery.
- A real restricted benign child reads the production-delivered key but computes
  confirmation under another fixed test UUID key; the parent must report the
  HMAC failure, terminate, and reap it. Candidate content is never executed.

## Scripted Contracts And Verification

- The source contract 661 accounts for exact production ordering, fixed-marker
  absence, HMAC context, constant-time verification, adversarial tests, docs,
  mandatory verifier target, and independent validator requirements.
- The central verifier adds `native-engine Authenticode launch-key confirmation
  HMAC regressions` and targets
  `native_authenticode_handshake_key_confirmation` serially.
- Full-suite report validation now requires exactly 261 steps, the new mandatory
  step, three key-confirmation verified-scope fragments, and the explicit
  same-user technical-limit fragment. Stale exact 260-step checkpoint-2230
  reports must fail.
- Parser, formatting, focused Rust, complete Native/Local/Guard, strict Clippy,
  locked/offline workspace, release/smoke, Flutter, safety/dependency, definitive
  verifier, malformed-report, hosted exact-head, merge, synchronization, and
  destination execution remain pending.

## Dependency And Lock Contract

This checkpoint uses the already pinned `hmac 0.12.1`, `sha2 0.10.9`, `uuid`,
`anyhow`, `windows-sys`, and standard library surface. It adds no crate, package,
feature, or lockfile change, executable, script host, network source, service,
driver, installer, or license obligation. Root, standalone Native, and Flutter
lock blobs must remain exact during execution review.

## Threat Model And Limits

The key-confirmation HMAC and response HMAC-SHA-256 reuse one random per-launch
key under distinct fixed domains. This proves point-in-time possession by data
arriving on the already PID/token-bound same-user pipe. It does not encrypt IPC,
authenticate a different Windows identity, provide durable secret storage or
durable token-object identity, prevent same-user memory read, privileged process
injection, pipe observation, or handle duplication, establish AppContainer/LPAC
or installed LocalSystem isolation, or demonstrate signed-driver/pre-execution
enforcement. No Defender-replacement claim is made.

## Safety

No live malware is downloaded, stored, unpacked, or executed. Tests use only
fixed UUIDs, protocol bytes, and benign Rust child fixtures. Nothing is installed,
released, published, or started as a service/driver; Defender is not weakened;
the protected quarantine vault must remain read-only and exact.

## Local Execution Evidence

- PowerShell 7 and corrected Windows PowerShell 5.1 parse both verifier scripts;
  `cargo fmt --check` and `git diff --check` pass. The dependency-free source
  runner passes exact `661/661` contracts. An earlier outer-shell-expanded PS5
  parser wrapper and one stale checkpoint-2230 source assertion failed visibly,
  were corrected, and are not credited.
- The new focused target passes `2/2`. Pipe-delivery passes `1/1`, parent/child
  PID and child-token targets pass `2/2` each, and wrong response-MAC key passes
  `1/1`. Complete Native passes `515/515` with 19 intentional ignored child
  entrypoints, signature compiler `6/6`, Local Core `536/536`, Guard `248/248`,
  and all-feature Guard `249/249`.
- The standard locked workspace passes. The first parallel all-feature workspace
  run failed one existing launch-token stability parent test after a zero-byte
  child pipe close; HMAC verification rejected it fail-visibly. The exact real
  test then passed ten consecutive isolated executions, and the complete locked
  all-feature workspace passed serially with Native `515/515`, 19 intentional
  ignores, and compiler `6/6`. The initial failure remains part of the evidence.
- Strict all-target/all-feature Clippy passes for Native, Local Core, and Guard;
  standalone Native locked/offline checking passes. All three locked release
  builds and PS7/PS5 isolated Authenticode smoke pass embedded/catalog Microsoft
  trust, unsigned rejection, and hash-mismatch failure without fixture execution.
- Flutter analysis reports no issues and all `838/838` client tests pass. The
  pinned resolution reports 33 newer incompatible versions; no dependency or
  lockfile change was made.

## Definitive Local Evidence

The no-skip, no-Defender-integration verifier ran from
`2026-08-25T10:19:35.3708813Z` through
`2026-08-25T10:27:21.7980983Z` and passed exact `261/261`, zero failed or
report-level skipped steps, in `466.4s`. The new launch-key confirmation HMAC
step passed in `0.3s`. The embedded validator and independently repeated Windows
PowerShell 5.1 `-RequireFullSuite` validation both accept the report.

Eight isolated report mutations are rejected `8/8`: failed overall status,
Defender/EICAR enabled, Rust skipped, stale 260-step evidence, renamed mandatory
HMAC step, missing HMAC verified scope, missing HMAC technical-limit scope, and a
failed final step. All variants remain untracked under `.verification`.

Root, Native, and Flutter lock blobs remain exact at
`bc43621213d9bede816a6e062146996116fb92fc`,
`1d9d96a172c258a584066a9adbb5a10a8feff97d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. No checkpoint test process remains.
The protected vault remains 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending/temp/reparse. Nothing was installed, released, published, executed as
candidate content, or changed in Defender.

## Exact Implementation-Head Hosted Evidence

Implementation commit `a3ef715f808edeaaa7e9bae39b8085173d183192`
was pushed only to the checkpoint branch and is the exact head of PR `#83`.
Avorax CI run `32837753355` passes all five jobs: branding/copy, Flutter
client/protocol, security/protection/performance, Rust Local Core/Guard/Update/
backend, and Unix quarantine permissions.

Desktop Packages runs `32837712672` (push) and `32837753111` (PR) pass package
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS x64/arm64 DMGs, and
consolidation/checksums. Publication jobs `97774038187` and `97775157486` are
explicitly skipped; no release or prerelease was created.

Consolidated artifacts `9559719743` and `9559858142` are 131,486,380 and
131,484,239 bytes. Their downloaded SHA-256 values exactly match GitHub digests
`8833d9e1cf1f63d242b63d2e10bf93e2d97e4b5660b786c17f9420773a8135e4` and
`31fb549ec83cb390aa11aa414628b70b72bd381435fca37fd18701af70263076`.
Without extracting or executing either artifact, in-stream validation passes
exactly eight unique regular root entries, six platform release files, seven
checksum targets with matching internal SHA-256, clean ZIP reads, and one
CycloneDX 1.6 lockfile SBOM with exactly 569 components. Evidence-head hosted
checks, normal merge, synchronization, and destination proof remained pending at
that implementation-head stage.

## Integration And Destination Closure

Evidence commit `0f49c76e316fc4103fae4c655cc6f119f487d751` passes all five
Avorax CI jobs in run `32839839948` and all package jobs in PR run
`32839839992`; publication job `97781098855` is skipped. The consolidated
evidence-head artifact is `9560563684`, 131,647,453 bytes, with GitHub SHA-256
`56e8f5bff444e43c64ecdf7fafaae963ca3bfdf5c69362effc3a41f2144da36a`.

PR `#83` merged normally as
`b678027bf4b6522fdf12c2eebc2df2fd15c14684`, with exact parents
`9690c84a81148551a51ab16b8d2db9b2e02ba086` and
`0f49c76e316fc4103fae4c655cc6f119f487d751`. Merged-main CI
`32841378314` passes all five jobs. Desktop Packages `32841378372` passes
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS x64/arm64 DMGs, and
consolidation; publication job `97784458641` is skipped. No release was created,
and the release list remains headed by `v0.1.15-beta.3` from 2026-07-20.

Merged-main consolidated artifact `9560976668` binds to exact merge head, is
131,646,181 bytes, and has matching GitHub/downloaded SHA-256
`b1da2eef2de556d6d15a31886aa13171f21eedfbd3fa97c9a81e21fafbcc56b1`.
Without extraction or execution, in-stream validation passes exact eight unique
regular root entries, six platform release files, seven matching checksum rows,
clean ZIP reads, and one CycloneDX 1.6 lockfile SBOM with 569 components.

The merge has 12 paths relative to previous main, including the already closed
checkpoint-2230 report. Relative to the exact checkpoint-2231 start merge
`4bd0b1582080271526072dca81459064a4d0648c`, destination work is exact 11
paths: ten modified files, one new report, and zero deletes. An initial read-only
precondition against older main `9690c84` rejected `RUN_LOG.md` before staging;
the destination instead exactly matched known checkpoint-2230 closure blob
`f6ad6cee79bf714ab493d53e8022ea3a7f19a5c3` from `4bd0b15`. Corrected exact-
start preconditions, root containment, and reparse checks then permitted atomic
application of `11/11` files, 6,694,886 bytes. No unrelated destination path was
changed, and the checked external staging directory was removed.

Destination verification passes both parser hosts, formatting, source contracts
`661/661`, HMAC `2/2`, pipe delivery `1/1`, parent/child PID `2/2`, child-token
binding `2/2`, and wrong response-key `1/1`. Native passes `515/515` with 19
intentional ignored child entrypoints plus compiler `6/6`; Local Core passes
`536/536`; Guard passes `248/248` and all-features `249/249`. Both locked
workspaces pass serially, as do strict Native/Local/Guard Clippy, offline Native
resolution, all three release builds, PS7/PS5 Authenticode smoke, Flutter analyze,
and Flutter `838/838`.

The destination no-skip/no-Defender verifier ran from
`2026-08-25T11:41:07.796987Z` through `2026-08-25T11:48:40.4769471Z` and
passed exact `261/261`, zero failed or skipped steps, in `452.7s`; the HMAC step
passed in `0.3s`. Embedded and independent Windows PowerShell 5.1 strict
validation pass, and eight isolated adversarial destination reports are rejected
`8/8`. Two outer-shell parser-wrapper quoting errors occurred before the intended
PS5/PS7 parser logic and are uncredited; corrected invocations pass.

Post-test all 11 synchronized files match the merge blobs and source raw SHA-256.
Root, Native, and Flutter lock blobs remain exact. No test process, sync temp, or
external stage remains. The protected vault remains 16,072 files, zero
directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
`.metadata_auth_key`, and zero pending/temp/reparse. Nothing was installed,
released, published, executed as candidate content, or changed in Defender.
Checkpoint 2231 is closed; the complete antivirus project remains active.
