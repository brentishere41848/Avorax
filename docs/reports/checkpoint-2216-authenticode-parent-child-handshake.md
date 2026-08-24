# Checkpoint 2216: Authenticode Parent-Child Handshake

Date: 2026-08-24

## Status

Implemented, locally verified, and implementation-head hosted verified. The production implementation, benign and
adversarial tests, verifier, validator, source contract, dependency record, threat
model, and audit records were written as one batch before tests, as requested. No
checkpoint-2216 passing result is claimed before execution. Exact implementation
`472b478c10dad6683ea867616f21c3636fe446de` passes hosted CI and both package
events. Merge, synchronization, and destination verification remain pending.

## Threat

The inherited anonymous-pipe checks from checkpoint 2215 prove to the child that
its three peer endpoints were created by the exact parent. Because `CreatePipe`
connects both endpoints in the parent before inheritance, those handles cannot
also prove to the parent that the expected launched child is the peer. A helper
substitution must fail before request, candidate, hash, signer, or WinTrust work.

## Scripted Control

- The parent creates one random local named pipe with
  `FILE_FLAG_FIRST_PIPE_INSTANCE`, `FILE_FLAG_OVERLAPPED`, one instance, byte
  mode, and `PIPE_REJECT_REMOTE_CLIENTS`. It is non-inheritable and has a protected
  DACL granting only the current user and SYSTEM plus a low-integrity mandatory
  label so the deliberately low-integrity child can write the handshake.
- The pipe name and a distinct random launch token are canonical RFC 4122 version
  4 UUID values in the exact sanitized child environment. Empty, malformed,
  noncanonical, non-v4, same-value, missing, or non-Unicode values fail visibly.
- The parent begins overlapped `ConnectNamedPipe` before process creation. After
  the exact process is created suspended, Job-assigned/read back, and resumed,
  `GetNamedPipeClientProcessId` must equal `PROCESS_INFORMATION.dwProcessId`.
- Before all existing helper trust work, the child opens only that pipe, verifies
  with `GetNamedPipeServerProcessId` that its server is the exact canonical parent
  PID, and writes the exact launch token in one bounded operation.
- Parent connect/read waits include both the event and live helper process handle.
  Timeout, early child exit, API failure, PID mismatch, malformed or mismatched
  token, and incomplete I/O are errors. Pending I/O is cancelled with `CancelIoEx`
  and proven settled with `GetOverlappedResult`; if settlement cannot be proven,
  its stable heap state and handles are intentionally retained rather than freed
  while Windows may still reference them. The helper is then terminated/reaped.
- There is no weaker retry, anonymous-pipe identity overclaim, swallowed error,
  path-only trust, or success fallback.

## Scripted Evidence

- A benign real-child fixture traverses restricted process creation and the
  handshake, exercises both process-ID queries and exact token crossing, and
  emits only `AVORAX_PARENT_CHILD_PROCESS_BINDING_OK`. It opens and executes no
  candidate fixture.
- Pure adversarial tests reject zero, self, and mismatched parent/server and
  child/client IDs; malformed pipe/token UUIDs; same pipe/token IDs; short tokens;
  and exact-length token mismatches.
- All prior isolated child fixtures explicitly perform the mandatory handshake,
  including the bounded timeout fixture, so no legacy fixture bypasses or hangs
  before its intended assertion.
- The central verifier adds exact step 246,
  `native-engine Authenticode helper parent-child handshake regressions`. The
  independent validator requires exactly 246 successful steps, the exact step,
  control/failure scope, and technical-limit scope.
- Source contract 646 binds production APIs, ordering, ACL/low-integrity policy,
  timeout/cancellation behavior, cleanup, tests, verifier/validator, dependency
  features, and audit documentation.

## Technical Limit

This is ephemeral same-user parent-child process binding, not encryption, a
durable or cross-identity authenticated protocol, or a secret against sufficiently
privileged same-user inspection. A process-memory reader, kernel compromise,
trusted code already executing inside either bound process, or equivalent process
access remains outside this control. Exact PID checks are made against the live
process handle and live pipe peer, but do not establish a general PID identity
protocol after those objects close.

The control is not AppContainer/LPAC, installed LocalSystem evidence, production
code signing, a driver, kernel interception, or pre-execution blocking. Embedded
and catalog signatures still require valid Authenticode plus a verified Microsoft
signer; existing bounded signature-count and catalog-candidate limits remain.

No live malware, download, candidate execution, installation, service/driver
start, Defender change, release, publication, or protected-vault mutation is part
of this checkpoint.

## Local Execution Evidence

- Both PowerShell parsers, Python compile, final `cargo fmt --check`, and
  `git diff --check` pass. The initial format check requested mechanical layout
  only. The first focused runtime found that `GetNamedPipeInfo` correctly returns
  `PIPE_REJECT_REMOTE_CLIENTS` with the endpoint bit; the exact expected mode was
  repaired. One stale multiline source marker was also repaired.
- The real-child and adversarial handshake filter passes `2/2`; Python source
  contracts pass `646/646`. Complete Authenticode passes `53` with `13`
  intentional isolated-child ignores, including every migrated legacy child path.
- Strict all-target/all-feature Native, Local Core, and Guard Clippy pass with
  warnings denied. Both locked standard and all-feature workspaces pass; Native
  Engine reports `489` passed and `13` ignored, and the signature compiler passes
  `6/6` in each. Full Flutter passes `838/838`, and Flutter analyze passes.
- Locked release Local Core and Guard builds pass. The two-host benign release
  smoke proves embedded/catalog Microsoft trust, unsigned rejection, scanned-hash
  mismatch failure, and the mandatory new handshake without executing a candidate.
- Definitive report
  `.verification/checkpoint-2216-parent-child-handshake-definitive-report.json`
  passes exactly `246/246`, zero failed/skipped, from
  `2026-08-24T01:22:28.6132319Z` through `2026-08-24T01:30:56.7842318Z`
  (`508.1s`). Its embedded validator and a separate full-suite validator pass.
  Seven fresh malformed copies are rejected for stale count, renamed or skipped
  handshake step, missing PID/ACL/technical-limit scope, and false Rust-skip state.
- Root Cargo, Native Cargo, and Git-filtered Flutter lockfiles remain exact at
  `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`. The protected vault remains exactly
  `16,072` files, zero directories, `4,522,733` bytes, `5,357` each
  `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.

## Implementation-Head Hosted Evidence

- PR `#68` targets `main` from the checkpoint branch. Exact implementation
  `472b478c10dad6683ea867616f21c3636fe446de` passes Avorax CI pull-request run
  `32680555167` from `2026-08-24T01:40:43Z` through `2026-08-24T01:48:34Z`.
  Branding/copy, Rust Local Core/Native/Guard/update/backend, Flutter/protocol,
  security/protection/performance, and Unix quarantine-permission jobs all pass.
- Desktop Packages push run `32680536082` and pull-request run `32680555166`
  pass on the same exact SHA. Both pass package contracts, Windows x64 MSI/EXE,
  Linux x64 DEB/tar, macOS arm64/x64 DMGs, consolidated six-artifact checksums,
  lockfile SBOM, dependency/license evidence, and administrative MSI extraction
  without installation. Their prerelease-publication jobs are skipped.
- Hosted artifacts are workflow evidence only. No release, publication,
  installation, service/driver start, Defender change, or protected-vault mutation
  occurred.

## Current Classification

- Verified: local implementation, focused/adversarial runtime, complete regression,
  definitive verifier/validator, exact lockfiles/protected-vault invariant, and
  exact implementation-head hosted CI/package matrices.
- Partial: merge, merged-main hosted evidence, guarded synchronization, and
  destination verification remain pending.
- Disabled/blocked: no weaker fallback is enabled if handshake evidence fails.
- Technically limited: same-user PID/token binding is not cross-identity IPC,
  AppContainer, installed-service, driver, or pre-execution evidence.
