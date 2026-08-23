# Checkpoint 2215: Authenticode Pipe-Peer Process Binding

Date: 2026-08-24

## Status

Implemented and locally verified. The complete implementation, test, verifier,
validator, source-contract, threat-model, dependency, and audit batch was written
before execution as requested. No checkpoint-2215 passing result is claimed before
execution; every result below comes from the later execution phase. Hosted exact-
head, merge, synchronization, and destination evidence remain pending.

## Threat

Checkpoint 2213 proved exact inherited standard-handle type, direction, identity,
and inheritance state. It did not ask Windows which process created the opposite
end of each pipe. A substituted or unexpectedly connected handle must not reach
publisher-trust request parsing merely because it is a pipe with the expected
direction and numeric handle identity.

## Scripted Control

- The parent adds exactly one bounded launch-environment value,
  `AVORAX_AUTHENTICODE_PARENT_PID`, generated from nonzero
  `GetCurrentProcessId`. The environment remains explicit Unicode state and now
  contains exactly the canonical parent PID, `SystemRoot`, and `WINDIR`.
- The child parses the parent PID as 1..10 UTF-16 units containing canonical ASCII
  decimal only. Empty, zero, leading-zero, signed, whitespace, non-ASCII,
  embedded-NUL, oversized, and out-of-`u32` values fail visibly.
- After exact standard-handle validation and inheritance clearing, the child calls
  `GetNamedPipeClientProcessId` on inherited stdin, whose read handle is the
  `CreatePipe` server end, and `GetNamedPipeServerProcessId` on inherited stdout
  and stderr, whose write handles are client ends.
- All three queried PIDs must be nonzero, equal the exact sanitized parent PID, and
  differ from the child `GetCurrentProcessId`. Missing/malformed environment,
  failed API calls, zero/self IDs, or any mismatch stops before private desktop,
  token, mitigation, stdin, request, candidate, or WinTrust work.
- No weaker retry, path-only trust, swallowed exception, or fallback is added.

## Scripted Evidence

- A benign isolated real-child fixture traverses the real low-integrity token,
  handle list, Job, private desktop, and pipe launch path, validates all three peer
  process IDs, and emits only `AVORAX_PIPE_PEER_PARENT_BINDING_OK`. It never opens
  or executes a candidate fixture.
- Pure adversarial evidence rejects zero expected/current IDs, self-parent state,
  zero or mismatched stdin/stdout/stderr peer IDs, and malformed canonical PID
  text.
- The central verifier adds exact step 245,
  `native-engine Authenticode helper pipe-peer process regressions`.
- The independent full-suite validator requires exactly 245 successful steps, the
  exact step, three verified-scope clauses, the exact anonymous-pipe limitation,
  and the updated three-variable environment limitation.
- Source contract 645 binds the production API roles, ordering, fail-visible
  evidence, verifier/validator text, documentation, and no-dependency-change claim.

## Technical Limit

Anonymous `CreatePipe` endpoints are created and connected in the parent before
inheritance. `GetNamedPipeClientProcessId` and
`GetNamedPipeServerProcessId` therefore bind the child's three inherited handles
to their parent creator; they do not prove the inheriting child PID back to the
parent. The parent separately retains exact process-handle/PID and Job membership
evidence from checkpoint 2214.

The parent-PID environment value is an expectation, not a secret. This control does
not prevent a sufficiently privileged or same-user process from duplicating an
already accessible handle, and it does not authenticate or encrypt anonymous-pipe
traffic. It is not durable cross-identity IPC, AppContainer/LPAC, installed
LocalSystem evidence, driver interception, or pre-execution blocking.

No live malware, network retrieval, installation, service/driver start, Defender
change, release, publication, protected-vault mutation, candidate execution, or
machine-wide dependency change is permitted.

## Local Execution Evidence

- Both PowerShell parsers, `git diff --check`, and final `cargo fmt --check` pass.
  The initial format check requested three mechanical line wraps. The host Python
  has no optional `pytest` module, so the required dependency-free runner was used
  and passes all `645/645` source contracts. Two contract assertions initially
  exposed formatter/newline coupling; their whitespace-stable forms pass.
- The real-child and pure adversarial pipe-peer filter passes `2/2`. Complete
  Authenticode passes `59` with `12` intentional isolated-child ignores.
- Both locked standard and all-feature workspaces pass. Native Engine reports
  `487` passed and `12` ignored, and the signature compiler passes `6/6` in each.
  Strict all-target/all-feature Native, Local Core, and Guard Clippy pass with
  warnings denied.
- Locked release Local Core and Guard builds pass. The two-host benign smoke proves
  embedded and catalog Microsoft trust, unsigned rejection, and scanned-hash
  mismatch failure without executing any candidate fixture.
- Flutter analyze reports no issues and Flutter passes `838/838`. The no-malware
  and dependency-evidence gates pass. Their first manual invocations were rejected
  before inspection because they used a relative Python path and a malformed
  report path; corrected absolute invocations are the evidence.
- Definitive report
  `.verification/checkpoint-2215-pipe-peer-definitive-report.json` passes exactly
  `245/245`, zero failed/skipped, from `2026-08-23T23:42:39.2919181Z` through
  `2026-08-23T23:50:28.7327336Z` (`469.4s`). Its embedded validator and a separate
  full-suite validator pass. Seven fresh copies are rejected for stale count,
  renamed step, missing order/API/failure scope, missing technical-limit scope,
  and skipped required step.
- Root Cargo, Native Cargo, and Git-filtered Flutter lockfiles remain exact at
  `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`. The protected vault remains exactly
  `16,072` files, zero directories, `4,522,733` bytes, `5,357` each
  `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.

Hosted exact-head/evidence-head checks, normal merge, merged-main evidence,
guarded original-tree synchronization, and destination verification remain
pending. No release, publication, install, service/driver start, Defender change,
candidate execution, or protected-vault mutation occurred.

## Current Classification

- Verified: local implementation, focused/adversarial runtime, complete regression,
  definitive report/validator, exact lockfiles, and protected-vault invariant.
- Partial: hosted exact-head, merge, original-tree synchronization, destination,
  installed LocalSystem, and production-signed evidence remain pending.
- Disabled/blocked: no weaker fallback is enabled if peer-process evidence is
  unavailable.
- Technically limited: child-side parent-creator binding is not parent-side child
  authentication, secret IPC, encryption, or same-user duplication prevention.
