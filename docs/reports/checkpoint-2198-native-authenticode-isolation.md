# Checkpoint 2198 Native Authenticode Isolation

Date: 2026-08-22

## Status

Implementation, test scripts, verifier/validator contracts, source contracts,
and audit documentation were completed before execution. The completed local
verification batch now passes. Hosted exact-head CI/package evidence, merge, and
original-tree synchronization remain pending and are not claimed here.

## Scope

Checkpoint 2198 places non-debug Native Engine Authenticode decisions behind a
bounded child-process lifetime. It preserves checkpoint 2195-2197 behavior:
direct handle-based cache-only WinTrust, exact verified Microsoft leaf identity,
bounded secondary embedded signatures, bounded catalog fallback, and optional
binding to the SHA-256 already computed by the scanner. Debug builds retain the
direct verifier so Rust unit-test harnesses do not need production entry modes.

This checkpoint addresses hard cancellation only. It does not add a new
detection signal, authorize execution, weaken Defender, install a service or
driver, publish a package, or claim pre-execution protection.

## Process Boundary

The release client resolves the exact current Local Core or Guard executable and
requires an absolute local-drive, bounded, regular non-reparse file. It opens
that file with read sharing only and retains the handle across launch and result
validation. The child starts with one exact hidden argument, redirected pipes,
no shell, no ambient PATH lookup, no network action, and no visible window.

A Windows Job configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` contains the
child lifetime. Normal completion is polled against a 15-second deadline.
Timeout triggers termination and a separately bounded two-second reap. Pipe
readers cap output and diagnostics. Any spawn, Job assignment, input, timeout,
kill, reap, output, exit, or cleanup failure is returned as a bounded diagnostic
and supplies no trust.

The 15-second deadline starts after synchronous process creation and Job
assignment. Windows process creation itself has no cancellation contract in
this design; a stalled creation API remains a documented operating-system
boundary rather than a falsely claimed hard end-to-end deadline.

## Protocol

One strict schema-v1 JSON request carries:

- a random UUID-v4 nonce;
- one bounded UTF-16 Windows path with no embedded NUL; and
- an optional lowercase 64-hex expected SHA-256.

One bounded response must match schema and nonce exactly. Success and failure
fields cannot contradict one another. Extra fields, malformed or excess data,
invalid nonce/path/hash, wrong response nonce, nonzero exit, or child-reported
error fail visibly. The child calls the existing direct verifier and never
executes an inspected file.

## Host Entry Points

Local Core and Guard recognize exact hidden helper and client-self-test modes
before ordinary startup. Guard rejects unknown or multiple arguments rather
than falling through to service behavior. No separately shipped helper binary is
introduced.

## Benign Verification Plan

The completed batch must run, in order:

1. Parser, format, source-contract, focused protocol, nonce, timeout, and host-
   lock tests.
2. Strict Native Engine lint and focused direct/catalog/secondary Authenticode
   regressions.
3. Release Local Core and Guard builds plus a non-installing smoke against an
   installed embedded-signed Edge file, catalog-backed Windows PowerShell,
   unsigned temporary text, and a deliberately wrong expected digest. Fixtures
   are inspected only and never executed.
4. Complete locked Rust workspace variants, Flutter analyzer/tests, security and
   dependency gates, and the exact 229-step verifier plus independent validator.
5. Exact-head hosted CI/package evidence, normal PR merge, merged-main evidence,
   and preconditioned original-tree synchronization with focused destination
   checks.

Only EICAR text and benign fixtures are permitted. The protected ProgramData
vault must remain at its recorded invariant and `.verification` must remain
untracked.

## Known Limits

- The child has the same token as its parent. This is a timeout/process-failure
  boundary, not least-privilege isolation or a sandbox.
- The running image, installed location ACLs, operating system loader, Job/
  process/pipe APIs, WinTrust providers, trust stores, and catalog state remain
  trusted.
- A retained read handle cannot revoke writable or mapped handles opened earlier
  or prevent mutation after the verdict.
- Secondary catalog signatures remain unsupported because the reviewed contract
  does not justify applying file-signature index semantics to catalog trust.
- Production signing, installed LocalSystem/service/UI operation, signed-driver
  IPC, pre-execution blocking, Defender coexistence, and production accuracy
  remain separate release prerequisites.

## Evidence

Local evidence on the Windows validation host:

- PowerShell parsing, rustfmt, `git diff --check`, and source contracts
  (`627/627`) pass.
- Helper isolation passes `4/4`; focused Authenticode regressions pass `26/26`;
  exact Local Core and Guard hidden-mode entry tests pass `1/1` each.
- Strict Native Engine, Local Core, and Guard Clippy passes. Locked Local Core
  and Guard release builds pass.
- The non-installing release smoke passes on both Local Core and Guard for
  embedded-signed Edge, catalog-backed Windows PowerShell, unsigned temporary
  text, and deliberately wrong SHA-256. No fixture is executed.
- Native Engine passes `452 + 6`; both complete locked Rust workspace variants
  pass; Flutter analyze passes and Flutter tests pass `838/838`.
- The definitive report passes exactly `229/229` with zero failed or skipped
  steps in `433s`. Independent `-RequireFullSuite` validation accepts it and
  rejects stale 226-step evidence.
- The protected vault remains exactly 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each payload/metadata/auth extension, one metadata key,
  and zero pending.

No hosted CI run, package build, merge, synchronization, installation, release,
or publication is claimed yet. Local release builds and smoke are not installed
package or production-signing evidence.
