# Checkpoint 2243 - Parallel Authenticode Helper Lifecycle

Date: 2026-08-26

## Trigger

The checkpoint-2242 destination full Native run executed with default test
parallelism and exposed one fail-closed Authenticode helper startup failure. The
wrong-response-MAC parent received an empty or short launch-key confirmation;
the diagnostic showed cleanup results but discarded the already bounded child
stdout and stderr. The exact test and a full serial rerun passed, so no trust
verdict was accepted from the failed run, but the parallel lifecycle and early
failure evidence required hardening.

The first checkpoint-2243 default-parallel Authenticode run made the race
deterministic and the new child diagnostics identified its exact cause: when an
overlapped `ReadFile` or `WriteFile` completed synchronously, the parent trusted
the call-site transfer variable instead of obtaining the authoritative count
from `GetOverlappedResult`. A healthy child could therefore be mistaken for a
zero-byte key confirmation and terminated fail-closed.

A later stress repetition exposed a separate framing race: byte-mode transport
could coalesce the exact 32-byte key confirmation with the first byte of the
next response-binding write. The parent's intentional one-byte overlength guard
then rejected an honest 33-byte read. This was a transport framing defect, not
an authentication bypass; the parent failed closed and accepted no result.

## Scripted Repair

- The restricted process is returned immediately after suspended launch,
  token/job validation, and resume. The caller starts bounded stdin/stdout/
  stderr workers before completing the initial authenticated named-pipe
  handshake. A child can no longer block initial-handshake diagnosis by filling
  an undrained standard-output pipe.
- Initial-handshake failure remains fail-closed. The helper is terminated or
  already exited, reaped, and its private desktop is closed. Bounded writer,
  stdout, stderr, exit-status, termination, reap, and desktop diagnostics are
  preserved in the returned error. There is no retry and no accepted result.
- Key delivery, key-confirmation read, response-ready read, and response ACK
  write now settle through `GetOverlappedResult` after both pending and immediate
  completion. The same exact byte-count checks remain mandatory.
- The local handshake pipe now uses message type and server message read mode.
  Each child write remains a distinct message, so the overlength guard detects
  an actually oversized protocol frame rather than a coalesced next frame.
- Four benign helpers are launched concurrently behind a barrier. Each must
  independently complete pipe authentication, response MAC binding, exit, and
  cleanup without a product-wide mutex.
- A benign ignored child writes more than an ordinary anonymous-pipe buffer to
  stderr and exits before connecting to the handshake. Its parent regression
  requires a bounded diagnostic containing the child marker and exact clean
  exit status. Fixtures are test executables only and never scan or execute
  candidate content.

## Verification Contract

Mandatory verifier step 272 is `native-engine Authenticode parallel helper
lifecycle regressions`. The strict report validator requires exact cardinality
272 plus verified scope for pre-handshake drain ordering, four-way concurrency,
and bounded early-exit evidence. It also requires technically limited scope:
this is not unbounded production or installed-service stress; text is lossy
UTF-8-normalized and capped; every handshake/output failure remains fail-closed.

Source contract 673 binds implementation ordering, both benign regressions,
verifier/validator wording and cardinality, and all checkpoint documents.

## Limits And Status

The four-helper test is bounded evidence, not proof for arbitrary load, installed
service identities, kernel mediation, or pre-execution blocking. Authenticode
trust still requires a valid Windows trust result and verified Microsoft signer
under the existing embedded/catalog and primary/secondary signature policies.
The helper remains user-mode, per-invocation isolated, timeout-bounded, and
fail-closed; diagnostics do not create a verdict.

## Local Verification

- Focused lifecycle tests pass `2/2`. Twenty focused repetitions pass, covering
  80 concurrently launched authenticated child handshakes and 20 bounded early-
  failure paths.
- The complete Authenticode area passes `83` active tests with `21` intentional
  child-fixture ignores under default parallelism. Twenty subsequent complete
  parallel repetitions pass `20/20`, totaling 1660 active parent tests and 420
  intentional ignores.
- Complete Native passes `555` active tests with `21` intentional ignores plus
  compiler `6/6`; Local Core passes `546/546`. Flutter analyzer is clean and
  Flutter passes `847/847`.
- Source contracts pass `673/673`; Windows PowerShell 5.1 and PowerShell 7
  parsers, rustfmt, diff check, strict Native/Local Clippy, and locked workspace
  release build pass. All three lock hashes remain exact. The protected vault
  remains `16072` files, zero directories, `4522733` bytes, `5357` each payload/
  JSON/auth, one metadata key, zero pending, and zero reparse points.
- The first full source-contract run exposed 41 stale cardinality/lifecycle
  assumptions and the second exposed 40 companion cardinality strings; corrected
  `673/673` passes. Two incorrectly filtered exact Cargo commands selected zero
  tests and are uncredited; corrected fully qualified tests pass `1/1` each.
- Two default-parallel Authenticode attempts are uncredited but diagnostic: the
  first identified non-authoritative synchronous overlapped byte counts and the
  second identified byte-stream cross-frame coalescing. Both failed closed and
  accepted no trust result. Their repaired paths pass the complete and repeated
  parallel evidence above.
- Definitive verification passes exact `272/272` from
  `2026-08-26T13:13:03.3773124Z` through
  `2026-08-26T13:21:44.8175976Z` in `521.4s`, with Defender integration off and
  no Rust or Flutter skips. Embedded and independent Windows PowerShell 5.1 and
  PowerShell 7 validation pass. Report SHA-256 is
  `81b5937b0f86c94b8b7c17865c742b31839723e776a1d249a56dd22331fdd700`.
- An adversarial `271`-step copy is rejected for exact cardinality and a copy
  without the message-framing scope is rejected for missing mandatory evidence.
  Both validators exit nonzero; these copies remain untracked under
  `.verification`.

## Hosted Implementation And Local-Evidence Head

Exact head `ee804f19223fd2237c2fd1af971a10a13f0b2a8f` passes Avorax CI PR
run `32974393351` and Desktop Packages push/PR runs `32974348589`/
`32974393379`. Both publication jobs are skipped; no release is created.

Consolidated artifacts `9609491152`/`9609575687` are `131938207`/
`131955514` bytes. Their downloaded SHA-256 values exactly match GitHub:
`5e84b251d5d6d50d83d9d85325cbc24778e7852900bd55c15b4d025b4047ab18` and
`5dfa5eb6c57862bc9ce57aa246cc88750af06e5f561cce0e7589faf71f77108c`.
Non-extracting in-stream review passes an exact eight-entry inventory in each
bundle: six platform installers/archives, one checksum file with seven verified
rows, and one CycloneDX 1.6 lockfile SBOM with 569 components. No artifact was
extracted or executed.

Evidence-head hosted checks, normal integration, guarded synchronization, and
destination verification remain pending.
