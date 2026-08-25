# Checkpoint 2229 Authenticode Response Launch-Key MAC

Date: 2026-08-25 (Europe/Brussels)

## Objective

Supersede checkpoint 2228's unkeyed response digest with a per-launch
HMAC-SHA-256 while retaining its bounded fixed-frame protocol, response-ready
client reauthentication, primary-token stability checks, cancellation, and
strict pre-JSON failure ordering.

## Scripted Implementation

Native Engine declares direct `hmac = "0.12"` and uses RustCrypto
`Hmac<Sha256>`. The response MAC input is exactly:

1. fixed domain `avorax-authenticode-response-mac-binding-v1\0`;
2. exact response byte count encoded as unsigned little-endian `u64`;
3. every bounded stdout byte, including the JSON newline.

The exact canonical RFC 4122 version-4 handshake UUID string is the 36-byte
per-launch key. The parent creates and retains it; the child validates and
retains the exact value received in its sanitized launch environment. Child
writes and flushes stdout, sends the existing fixed 41-byte marker/length/tag
frame on the retained duplex pipe, and waits for final ACK. Parent accepts only
the exact frame and a canonical 1..16,384-byte length, freshly reauthenticates
the connected client, repeats launch and child token checks, sends ACK, waits
for bounded exit, collects bounded stdout, and calls constant-time
`verify_slice` before strict JSON parsing or publisher trust.

All failures remain diagnostic. There is no fallback to an unkeyed digest,
unchecked JSON, alternate helper, PowerShell probe, or trust-on-error path.

## Scripted Tests And Contracts

- Existing response hash-named regressions remain for historical verifier
  continuity but now exercise HMAC frame, length, mutation, and strict ordering.
- A new `native_authenticode_response_mac_binding_rejects_wrong_launch_key`
  regression launches the real isolated test child. That child authenticates the
  handshake with the correct environment token, writes only fixed benign text,
  and deliberately forms its frame under a different fixed valid test UUID.
  Parent retains the correct launch key and must reject the MAC.
- Pure adversarial coverage rejects empty/oversized input, malformed, truncated,
  extended, wrong-marker, zero/oversized-length, changed-tag, same-length-byte,
  wrong-length, and wrong-key evidence.
- source contract 659 requires direct dependency, exact domain/key/frame dataflow,
  key retention on both endpoints, constant-time verification before JSON, the
  wrong-key child fixture, verifier target, validator scope, and documentation.
- The central verifier adds `native-engine Authenticode response launch-key MAC
  regressions`; strict full-suite validation requires exactly 259 steps and the
  new verified and technically limited scope.

## Dependency Boundary

`hmac` `0.12.1` is already pinned in the root workspace through Local Core and
Guard, and cached metadata records `MIT OR Apache-2.0`. Checkpoint 2229 makes it
a direct Native Engine dependency and reuses `sha2` 0.10. Exact root and Native
standalone lock generation and delta review were intentionally deferred until
the entire scripting batch was complete. Offline resolution is now complete:
root adds one Native `hmac` edge; standalone Native adds `hmac 0.12.1`,
`subtle 2.6.1`, the `digest` subtle edge, and one Native edge, without version
updates. Exact root/Native/Flutter blobs are `bc43621213d9bede816a6e062146996116fb92fc`,
`1d9d96a172c258a584066a9adbb5a10a8feff97d`, and unchanged
`51fa085a41168aa1deadace8b5395614db43649e`. No executable, network service,
script host, machine-wide component, or live-malware material is added.

## Verification Status

No checkpoint-2229 passing result is claimed during scripting. After the full
scripting batch, offline lock generation/review, PowerShell 7/5.1 parsers,
rustfmt/diff checks, source contracts `659/659`, retained response tests `3/3`,
and the new wrong-launch-key regression `1/1` pass. Optional `pytest` is absent
and was not installed; the required dependency-free runner supplied the passing
source evidence.

Complete local regression passes: Authenticode `84 passed/17 ignored`, Native
Engine `512 passed/17 ignored` plus signature compiler `6/6`, Local Core
`536/536`, Guard standard `248/248` and all-feature `249/249`, both root
workspace modes, locked/offline checks, strict affected-crate Clippy, locked
release builds, release Authenticode smoke, Flutter analysis and `838/838`, and
all required safety/dependency gates.

## PS5 Redirected-Input Repair

Definitive execution exposed a real harness/wrapper defect: Windows PowerShell
5.1 may construct redirected child stdin with a UTF-8 BOM. Strict Rust JSON
parsers correctly rejected that byte before both the release Authenticode smoke
and the general Local Scan wrapper. The product parser was not relaxed.

The release Authenticode harness plus scan, cancel, allowlist, quarantine,
finite-watch, status, and blocked driver-self-test paths now save the current
`Console.InputEncoding`, select `UTF8Encoding(false)` before child process/stdin
creation, close stdin, and restore the previous encoding in `finally`. Both PS5
and PS7 parse all eight scripts; source contracts remain `659/659`; the release
Authenticode smoke passes 12 consecutive repetitions; and all six user wrapper
smokes pass sequentially and again inside the definitive verifier. The driver
path remains runtime-blocked without an approved signed installed driver, so
only its source/parse contract is claimed.

## Definitive Local Evidence

The credited no-skip/no-Defender-integration verifier ran from
`2026-08-25T05:02:46.0085093Z` through `2026-08-25T05:10:07.1292531Z` and
passed exact `259/259`, zero failed or skipped, in `441.1s`. The new response
launch-key MAC target passed in `0.2s`. The verifier's embedded strict validator
and an independently repeated Windows PowerShell 5.1 `-RequireFullSuite`
invocation accept the report.

Fifteen isolated untracked report copies are rejected with exit 1: changed
schema, failed overall status, enabled Defender/EICAR, either Flutter or Rust
skip, renamed mandatory MAC target, each of five MAC verified-scope statements,
each of two MAC technical-limit statements, a failed final step, and stale
258-step evidence. They remain only under `.verification` and are never staged.

Earlier verifier attempts are not credited. The first lost Flutter's temporary
`output.dill`; its stuck child was explicitly reaped and the exact five-file
group then passed `6/6`. A later run exposed the Authenticode BOM, and the next
exposed the shared wrapper BOM. Unsupported `StandardInputEncoding`, too-late
`BaseStream`, parser/runner path, byte-probe quoting, and first adversarial
harness attempts also remain uncredited. Each failure produced a bounded repair
and passing regression rather than a retry-only success claim.

Root Cargo, standalone Native Cargo, and Flutter Git blobs remain exactly
`bc43621213d9bede816a6e062146996116fb92fc`,
`1d9d96a172c258a584066a9adbb5a10a8feff97d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. The protected vault remains
read-only and exact: 16,072 files, zero directories or reparse points, 4,522,733
bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending/temp.

## Implementation-Head Hosted Evidence

Exact implementation head `eaa4ba31bf942b570eb7fb55304831c9a0c30ba4`
passes all five Avorax CI jobs in run `32812956518` without retry. Desktop
Packages push/PR runs `32812914763`/`32812956466` pass package contracts,
Windows x64 MSI/EXE including administrative extraction without installation,
Linux x64 DEB/tar, macOS x64/arm64 DMGs, consolidation, checksums, dependency
evidence, and the lockfile SBOM. Both publication jobs are skipped.

Untouched consolidated artifacts `9550661340`/`9550842112` are
`131454491`/`131288897` bytes with SHA-256
`68a8a98d21e49e76e5e5a1dffbca6a1cfa95b2291fe00e4ef613abc545efd112`/
`07d5154cc1a66ef0675e6b93ba4a9d8d83b7647098107cf01feee28dfe0cf739`.
Bounded in-stream validation, without extraction or execution, proves exactly
eight root regular entries: six platform artifacts, `SHA256SUMS.txt`, and a
CycloneDX 1.6 lockfile SBOM. All seven checksum rows independently match and
the SBOM contains exactly 569 components.

Evidence-head checks, normal integration, merged-main evidence, guarded
synchronization, and destination proof remain pending. This hosted evidence
does not complete either checkpoint 2229 or the antivirus project.

## Technical Limits

The launch token is ephemeral but is not guaranteed secret from every process
under the same Windows user. It appears in the child's sanitized environment and
memory and is sent on same-user IPC. Same-user process-memory or environment read
access, privileged process injection, handle duplication, a compromised parent,
administrator/SYSTEM, or kernel compromise may recover the key or modify both
stdout and HMAC before authentication. HMAC-SHA-256 does not encrypt IPC,
provide cross-identity authentication, bind durable token objects, or establish
AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution
enforcement. Embedded/catalog signature and primary/secondary signature limits
remain as documented by the Authenticode engine; this checkpoint changes only
the helper response boundary. The complete antivirus goal remains active.
