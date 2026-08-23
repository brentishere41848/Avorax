# Checkpoint 2213: Authenticode Standard-Handle Binding

## Status

Implementation and definitive local verification are complete. The complete implementation,
benign/adversarial tests, verifier step, strict report validator, source contract,
dependency review, and audit documentation were written before any checkpoint-2213
test execution. No checkpoint-2213 passing result was claimed before execution.
The definitive verifier and independent validator pass `243/243`. Exact
implementation head `f0f4c3b82dcb30b6851b26db7a88ab2b6e9a4af8` passes hosted
CI and package evidence; evidence-head checks and integration remain pending.

## Scripted Boundary

- Every parent and child endpoint returned by `CreatePipe` must be a valid
  `FILE_TYPE_PIPE` handle. `GetNamedPipeInfo` verifies server/read endpoints;
  exact documented API return-role assignment binds child stdin to read and
  stdout/stderr to writes without an unsupported write-handle query.
- Parent endpoints must have exact-zero handle flags after inheritance is removed;
  child endpoints must have exactly `HANDLE_FLAG_INHERIT` before creation.
- Before private-desktop, token, mitigation, restricted-thread-token, request, or
  candidate processing, the child reads exact `STARTF_USESTDHANDLES` startup state
  and requires `GetStdHandle` to return the same three valid, distinct handles.
- Child stdin must report server/read mode; stdout and stderr identities must match
  the parent-created write handles. All three must initially carry exactly
  `HANDLE_FLAG_INHERIT`.
- The child clears `HANDLE_FLAG_INHERIT` on all three and requires exact-zero
  `GetHandleInformation` read-back before continuing.
- Handle query, type, direction binding, identity, duplicate, initial-flag, mutation, or
  read-back failure remains diagnostic and cannot become publisher trust.

## Scripted Evidence

- A benign isolated child validates actual startup/standard-handle binding and
  inheritance clearing, then emits only `AVORAX_STANDARD_HANDLE_BINDING_OK`.
- Pure adversarial evidence rejects absent/extra startup flags, startup/standard
  mismatch, null/invalid/duplicate handles, non-pipe types, missing server mode,
  missing/unknown initial flags, and any remaining inheritance flag.
- Parent construction also validates every endpoint before `CreateProcessAsUserW`.
- The central verifier adds exact step 243:
  `native-engine Authenticode helper standard-handle binding regressions`.
- The independent validator requires exactly 243 steps, exact step presence,
  parent and child verified-scope language, fail-visible language, and the residual
  technical limit. Source contracts account for APIs, ordering, tests, verifier,
  validator, and every documentation surface.

## Technical Limits

Exact standard-handle binding narrows inherited helper IPC only. Anonymous pipes
and the nonce do not provide cross-identity authentication or encryption, prevent
same-user handle duplication, or isolate the named-kernel-object namespace. The
helper still retains its documented SID/profile/registry/read/window-station limits.
This is not AppContainer, installed LocalSystem proof, signed-driver enforcement,
kernel interception, or pre-execution blocking.

No candidate fixture is executed. No live malware, network retrieval, installation,
service/driver start, Defender change, release, publication, or protected-quarantine
mutation is permitted.

## Local Evidence

- PowerShell verifier/validator parsing, Rust formatting, and source contracts
  `643/643` pass.
- Exact child/adversarial standard-handle checks pass `2/2`; complete Authenticode
  passes `47` with `10` intentional isolated-child ignores.
- The first strict Clippy run rejected a default-then-field startup initializer.
  A single complete `STARTUPINFOW` initializer repaired it; strict Native/Local
  Core/Guard Clippy then passed with all targets/features and warnings denied.
- Locked release Local Core/Guard builds and the two-host release Authenticode
  smoke pass embedded/catalog Microsoft trust, unsigned rejection, and scanned-
  content hash mismatch failure with the new child validation active.
- Both locked workspace variants pass with Native Engine `483` passed/`10`
  ignored and signature compiler `6/6`. No-malware, Flutter analyze, and
  Flutter `838/838` pass.
- Microsoft documents that write-only pipes need additional `FILE_READ_ATTRIBUTES`
  for `GetNamedPipeInfo`, which `CreatePipe` does not promise. Before compilation,
  the scripted design was corrected to query server/read endpoints only and bind
  stdout/stderr through exact API return roles plus startup/`GetStdHandle` identity.
  No unsupported write-handle query or overstated direction claim remains.
- `.verification/checkpoint-2213-standard-handle-definitive-report.json` passes
  exactly `243/243` from `2026-08-23T20:39:17.9286117Z` through
  `2026-08-23T20:47:07.1219125Z` (`469.2s`), and the independent full-suite
  validator accepts it. Fresh stale-count, renamed-step, missing-child-scope,
  missing-limit-scope, and skipped-required-step copies are all rejected.
- Root Cargo, Native Cargo, and Git-filtered Flutter lockfiles remain exact at
  blobs `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`. The Flutter working file uses the
  checkout's normal CRLF representation but has an empty Git diff.
- The protected vault remains exactly `16,072` files, zero directories,
  `4,522,733` bytes, `5,357` each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending.
- Exact implementation head `f0f4c3b82dcb30b6851b26db7a88ab2b6e9a4af8`
  passes Avorax CI pull-request run `32665658235` and Desktop Packages push/PR
  runs `32665646920`/`32665658257`. Both package runs build and upload Windows
  x64 MSI/setup EXE, Linux x64 DEB/tar, and macOS x64/arm64 DMGs, then require
  all six artifacts, checksums, dependency/license evidence, and the 569-component
  lockfile SBOM. Windows administrative MSI extraction passes without installation.
  License review remains partial and prerelease publication is skipped.

## Pending Verification

Evidence-head hosted CI and package evidence, normal merge, merged-main evidence,
guarded original-tree synchronization, and destination checks remain pending.
