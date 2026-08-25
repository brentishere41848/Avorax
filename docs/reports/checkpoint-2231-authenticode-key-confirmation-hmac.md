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

## Pending Integration Sequence

1. Review the final implementation diff and commit only the checkpoint source
   and documentation; `.verification` remains untracked.
2. Push only the checkpoint branch, obtain exact-head CI and desktop-package
   evidence, and require publication jobs to remain skipped.
3. Add hosted evidence, rerun exact evidence-head gates, open the PR, merge
   normally, and verify merged-main CI/packages without creating a release.
4. Guardedly synchronize only exact merge-delta files to the original tree and
   independently repeat destination verification and read-only reconciliation.

Checkpoint 2231 is not the completion of the antivirus project. After closure,
the highest-value unblocked defensive risk remains the next task.
