# Checkpoint 2224 - Authenticode Launch Token Stability

Date: 2026-08-24 (Europe/Brussels)

## Objective

Detect persistent replacement or modification of the exact low-integrity,
privilege-stripped primary token used to launch the isolated Authenticode
helper. Before handshake pipe creation, the parent snapshots
`TokenStatistics.TokenId` and `ModifiedId` from the same parent-held token
handle later passed to `CreateProcessAsUserW`. It queries that same handle
after successful process creation while the child remains suspended and again
after child-process, connected-client-token, and random-token handshake
authentication.

An empty initial token ID, exact-size `TokenStatistics` query failure, token-
instance drift, or modified-context drift fails visibly. A post-creation
failure terminates and reaps the helper; no weaker retry can become Microsoft
publisher trust.

## Scripted Implementation

- `AuthenticodeParentChildHandshake` retains the initial launch-token
  `TokenId`/`ModifiedId` evidence, not a serialized credential or copied token.
- `create` captures that evidence before `CreateNamedPipeW`, alongside the
  existing launch SID and logon-session evidence.
- The same parent-held `OwnedToken` handle is passed to
  `CreateProcessAsUserW`, checked before Job assignment and `ResumeThread`, and
  checked again after the authenticated handshake.
- The existing exact-size `TokenStatistics` query path remains fail-visible.
- A dedicated evidence validator rejects low/high drift in either LUID and an
  empty initial token ID with launch-specific diagnostics.
- A benign isolated helper regression exercises the full production path;
  adversarial pure-evidence cases cover all four drift fields and an empty ID.
  Candidate fixtures are never executed as scanned content.
- Source contract 654 accounts for ordering, same-handle use, cleanup,
  adversarial cases, verifier/validator scope, and documentation. The
  definitive verifier adds one mandatory step and now requires exactly 254.

## Security Boundary

This is point-in-time stability evidence for one parent-held launch token from
pre-pipe capture through post-handshake read-back. It does not prove that the
created child process token remains identical after creation and does not bind
the distinct launch-primary and impersonation token objects. Transient
mutation between snapshots, mutation after the final read-back, privileged
handle duplication, and process injection are not prevented.

The control also does not provide encrypted or cross-identity authenticated
IPC, AppContainer/LPAC or installed LocalSystem isolation, a signed driver, or
demonstrated pre-execution enforcement. Those remain separate technical or
external prerequisites.

## Scripting-Phase Status

No checkpoint-2224 passing result is claimed during scripting. Production
code, benign/adversarial Rust regressions, source contract 654, the exactly 254
step verifier contract, independent report validation, and audit/status/
dependency documentation were written before running any checkpoint-2224
test, formatter, parser, build, lint, or verifier.

This checkpoint adds no crate, package, feature, or lockfile change. It does
not install or start a service/driver, alter Defender, read or mutate candidate
malware, modify protected quarantine content, publish a package, or claim that
the complete antivirus project is finished.

## Verification Evidence

Focused verification passes: both PowerShell parsers, `rustfmt --check`, source
contracts `654/654`, launch-token stability `2/2`, complete Authenticode
`65/13`, and Native Engine `501/13` plus signature compiler `6/6`. Both locked
root-workspace variants, strict Native/Local/Guard Clippy with warnings denied,
standalone locked/offline Native check, Flutter lock enforcement and analysis,
and Flutter `838/838` also pass.

The definitive report ran from `2026-08-24T17:16:01.686336Z` through
`2026-08-24T17:24:11.3481687Z` and passed exactly `254/254`, with zero failed
or skipped steps, in `489.6s`; the new target passed in `0.2s`. Embedded and
independently repeated `-RequireFullSuite` validation pass. Nine controlled
mutations covering schema, status, Defender option, both skip flags, missing
target step, missing verified scope, missing technical-limit scope, and final-
step drift are each rejected with exit code 1.

Three initial support-command results remain explicit. The first parser wrapper
itself had an invalid `$file:` interpolation and was corrected before both
target scripts parsed; neither target script had a parse error. The default
`py -3` environment lacked `pytest`, so the repository's dependency-free runner
was used and passed all `654`; no package was installed. The first
`rustfmt --check` reported three formatting-only differences, `cargo fmt`
applied them, and the repeated check passed. The launch-token Rust tests passed
before and after formatting.

Exact lock blobs remain `7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. The protected vault remains exact
at 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one metadata key, and zero pending.

## Implementation-Head Hosted Evidence

Exact implementation commit
`c83114908c64e9a9c0f21be68d2612fe85895fda` passes Avorax CI run
`32756812158` and Desktop Packages push/pull-request runs `32756761690` and
`32756812207` without a retry. All five CI jobs pass. Both package runs pass
package contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64
DMG, and consolidation. Both prerelease-publication jobs are explicitly
skipped.

The untouched consolidated artifacts `9532117732` and `9531753034` were
downloaded as original GitHub ZIP streams. Their ZIP SHA-256 values are
`0305f2a0439195829ab7f3a1888a132637fcd5efb4f5e2f3ce8982eb384e8a37` and
`a666dce5767f367b27dc14a6232dcb14117b5728bbef71e0eed58c6286d16ace`.
Independent in-stream inspection, without extracting or executing any
candidate installer, proves exactly eight entries in each ZIP: six platform
artifacts, one CycloneDX lockfile SBOM, and `SHA256SUMS.txt`. Each manifest has
exactly seven rows and all seven SHA-256 values match their archive entries.
Both SBOMs are CycloneDX 1.6 with 569 components.

Checkpoint 2224 is implementation-head hosted verified but not closed. The
evidence commit and its exact-head checks, normal PR/merge, merged-main
evidence, guarded original-tree synchronization, and independent destination
verification remain pending. Nothing was installed, executed, released, or
published.

## Integration And Destination Closure

Evidence commit `42d8c7cbce6d06a988e44c9359116e6ca5afc961` passes Avorax
CI `32760087362` and Desktop Packages `32760087347`. Consolidated artifact
`9532855811`, retained as an untouched ZIP with SHA-256
`12fdec083382b65a649b46c4a5416c98618d9fc183891ad74121b5ffc045f07f`,
passes the exact eight-entry, seven-manifest-row, seven-hash, and CycloneDX
1.6/569-component checks. Its publication job is skipped.

PR `#76` became ready only after those exact-head checks and merged normally
with head locking as `243bc84d34120af67f2bec1b93e1f5a0e8e92f3c`. Merged-main
Avorax CI `32761688896` and Desktop Packages `32761688853` pass. The main
consolidated artifact `9533505060` has untouched ZIP SHA-256
`16d13bc6ca39dd3679273ed0531d9f34739f5c2e9370df5bba60ad81b9db6137`
and independently passes the same eight-entry, seven-hash, CycloneDX 1.6/569-
component contract. Main publication is also skipped.

All 11 modified destination files exactly matched merge parent `252a9ade` and
the new checkpoint report was absent. Exactly those 12 paths were copied to
`C:\Users\Brent\Documents\Avorax-main`, with zero deletes. Every destination
normalized Git blob matches merge `243bc84d`, and every raw SHA-256 matches the
source.

Destination parsers `2/2`, source contracts `654/654`, launch-token stability
`2/2`, Native Engine `501/13` plus compiler `6/6`, Local Core `536/536`, Guard
`249/249`, both locked root-workspace variants, root/Native formatting, strict
Native/Local/Guard Clippy, standalone locked/offline Native, Flutter lock
enforcement and analysis, and Flutter `838/838` pass. Destination definitive
verification ran from `2026-08-24T18:40:04.7310075Z` through
`2026-08-24T18:48:19.2737858Z` and passed exact `254/254`, zero failed/skipped,
in `494.5s`; the launch-token target passed in `0.2s`. Embedded and independent
Windows PowerShell strict validation pass.

Four closure-support wrapper mistakes remain explicit. One malformed watcher
format expression exited before observing or starting a workflow; the corrected
watcher followed the already-created main runs. Two separate read-only wrappers
completed their substantive ZIP/path checks but each omitted a space before
`Write-Output`; neither is counted as a pass, and each complete corrected rerun
passes. A final parser/source-contract wrapper had the same output-spacing typo
and exited before the source-contract runner; its corrected complete rerun
passes both parsers and `654/654`. No production code, test contract, or
security policy was weakened.

The three lock blobs and protected-vault invariant remain exact at 16,072 files,
zero directories, 4,522,733 bytes, 5,357 each payload/metadata/auth extension,
one metadata key, and zero pending. Nothing was installed, executed as candidate
content, released, or published. Checkpoint 2224 is closed; its documented
point-in-time identity limits and the complete antivirus hardening goal remain
open.
