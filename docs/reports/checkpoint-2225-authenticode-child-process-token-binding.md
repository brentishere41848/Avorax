# Checkpoint 2225 - Authenticode Child Process-Token Binding

Date: 2026-08-24 (Europe/Brussels)

## Objective

Bind the exact primary token currently attached to the isolated Authenticode
child process to the launch identity and required restricted security profile,
then prove that child token object remains stable across the handshake. The
parent queries the child process token with `TOKEN_QUERY` immediately after
`CreateProcessAsUserW` while the child is suspended and again after exact child
PID, connected-client-token, random nonce, and launch-token authentication.

The handshake is duplex. After writing its random launch token, the child must
wait for an exact one-byte ACK. The parent sends that ACK only after the second
child process-token query proves exact `TokenStatistics.TokenId` and
`ModifiedId` equality with the child values captured while suspended. This
removes the child-exit race from the post-authentication query.

## Scripted Implementation

- The parent handshake pipe uses bounded overlapped duplex I/O; the child opens
  it with `GENERIC_READ | GENERIC_WRITE | READ_CONTROL` and still performs the
  existing exact client endpoint, PID, DACL, owner, and low-integrity-label
  checks.
- An exact process handle from `PROCESS_INFORMATION` is passed to
  `OpenProcessToken` with only `TOKEN_QUERY`. Invalid handles, open failure,
  exact-size token query failure, or empty IDs fail visibly.
- Before Job assignment or `ResumeThread`, the suspended child must be an exact
  primary token with the launch user SID, AuthenticationId/session, stripped
  privileges, zero restricting SIDs, low-integrity/no-write-up policy,
  canonical virtualization state, and disabled UIAccess. Its own nonempty
  `TokenId`/`ModifiedId` pair is then captured.
- After client-token impersonation/reversion, exact nonce comparison, and
  launch-token stability, the parent reopens the token currently attached to
  the exact child while that child waits for ACK, repeats the complete profile
  validation, and requires exact equality with the captured child four-field
  pair before sending ACK.
- Missing, malformed, duplicate-length, incomplete, timed-out, or unsettled ACK
  I/O cannot become publisher trust. Existing post-creation failure handling
  terminates and reaps the child without a weaker retry.
- A benign production-path regression plus adversarial token type, identity,
  logon session, restricting SID, policy, UIAccess, four-field drift, empty
  child IDs, invalid process handle, and malformed ACK cases are scripted.
  Source contract 655 and the exactly 255-step verifier/validator contract
  account for ordering, access rights, cleanup, evidence, and limits.

## Security Boundary

The initial focused runtime proved that `CreateProcessAsUserW` produced a child
primary token with a distinct `TokenId` from the supplied launch-primary token
on this verified Windows host. Cross-object `TokenId` equality is therefore
technically unavailable and is not claimed. The viable control binds the child
to the launch identity and restricted profile, then compares the child token's
own `TokenId`/`ModifiedId` across two point-in-time snapshots.

This does not bind the distinct named-pipe impersonation token object to either
primary token, prevent replacement or mutation after ACK, detect every
transient between-snapshot mutation, or prevent same-session process injection
or privileged handle duplication. The ACK is flow control, not a secret or
encryption mechanism.

The control does not provide cross-identity authenticated IPC, AppContainer/
LPAC, installed LocalSystem isolation, production signing, signed-driver
enforcement, or demonstrated pre-execution blocking. Those remain technical or
external prerequisites.

## Scripting-Phase Status

No checkpoint-2225 passing result is claimed during scripting. Production code,
benign/adversarial Rust regressions, source contract 655, the exactly 255-step
verifier contract, independent report validation, and audit/status/dependency
documentation were written before running any checkpoint-2225 parser,
formatter, build, lint, test, or verifier.

This checkpoint adds no crate, package, feature, or lockfile change. It does not
install or start a service/driver, alter Defender, read or mutate candidate
malware, modify protected quarantine content, execute a candidate fixture,
publish a package, or claim that the complete antivirus project is finished.

## Verification Evidence

The first post-scripting focused run compiled successfully. The pure adversarial
case passed, while the benign production-path case failed visibly before resume
because the child token `TokenId` differed from the launch-primary `TokenId`;
cleanup reported `ok`. That failed design is not counted as a pass and directly
motivated the documented profile-plus-child-stability repair above. Focused
reruns then pass `2/2`; the complete Authenticode filter passes `52/52`, and the
Native Engine passes `503` tests with `13` explicitly ignored plus signature
compiler `6/6`.

Both locked root-workspace variants, strict Native/Local/Guard Clippy, standalone
locked/offline Native all-target checking, Flutter analysis, and Flutter
`838/838` pass. The dependency-free Python source-contract runner passes
`655/655`; both modified PowerShell scripts parse; `cargo fmt --all -- --check`
and `git diff --check` pass. Optional `pytest` was absent from both existing
Python runtimes, so no package was installed; the complete dependency-free
runner supplied the required evidence instead.

Definitive verification ran from `2026-08-24T19:26:42.1793451Z` through
`2026-08-24T19:35:23.2776529Z` and passed exactly `255/255`, zero failed or
skipped, in `521.1s`; the checkpoint target passed in `0.3s`. Embedded and
independently repeated `-RequireFullSuite` validation pass. Nine isolated
malformed copies covering schema, status, Defender option, both skip flags,
missing target step, missing verified scope, missing technical-limit scope, and
failed final step were each rejected with exit code `1` and removed.

Root Cargo, Native Cargo, and Flutter lock blobs remain exactly
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Read-only inventory confirms the
protected vault remains exactly 16,072 files, zero directories, 4,522,733
bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending/temp. Implementation-head hosting is recorded below; evidence-head
checks, normal merge, guarded original-tree synchronization, and destination
verification remain pending, so checkpoint 2225 is not yet closed.

## Implementation-Head Hosted Evidence

Exact implementation `311d9a26c3781843bc9208c9adf4747f56b22168` passes
Avorax CI `32769512557` and Desktop Packages push/PR runs `32769502849`/
`32769512526` without reruns. CI completes all five jobs. Both package runs pass
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, and
consolidation; both publication jobs are explicitly skipped.

Consolidated artifacts `9536055246` and `9536052725` were retained as untouched
ZIP streams with SHA-256
`cb6f82d7074c3e69fcf48cb9414dbad73508328807a06f9bf591a42b5ac92911` and
`f69f08c600f05509dd930e438355ea304d7edb6b4ecd1bbbada871e5344a69fc`.
In-stream inspection, without extracting or executing candidate installers,
proves exactly eight entries each: six platform artifacts, one versioned
CycloneDX 1.6 lockfile SBOM, and `SHA256SUMS.txt`. All seven checksum rows name
present entries and match streamed SHA-256 values; each SBOM has exactly 569
components.

Two inspection-wrapper issues remain explicit. The first JavaScript wrapper
failed to parse before execution because PowerShell backticks conflicted with
its template literal and created nothing. The corrected wrapper first rejected
a stale generic SBOM filename assumption after reading the first ZIP; selecting
the exact versioned `*-lockfile.cdx.json` entry then validated both complete
streams. Neither failed attempt is counted as evidence. Draft PR `#77` remains
at the exact implementation head. Evidence-head checks, normal merge, merged-
main evidence, guarded synchronization, and destination verification remain
pending; nothing was installed, executed, released, or published.
