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
pending/temp. Implementation-head hosting and complete integration closure are
recorded below.

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
streams. Neither failed attempt is counted as evidence. Nothing was installed,
executed, released, or published.

## Integration And Destination Closure

Evidence commit `d1a1e147386c64b085920414bf80f8030a480965` passes Avorax
CI `32771093960` and Desktop Packages PR run `32771093928`; its publication job
is skipped. Untouched consolidated artifact `9536921340` has SHA-256
`c07b8cfc65f7c5e2e99ba7c9c141f6dbb8cf966b489400922c7fe92ec8c406e6`
and passes the same exact eight-entry, seven-checksum, CycloneDX 1.6, and 569-
component in-stream checks.

PR `#77` was clean and head-locked to the evidence commit, then merged normally
without a direct-main push as merge `5792c22f3815f4eccbc97a78d5ae9e01873193f5`.
Merged-main CI `32773257838` and Desktop Packages `32773257841` pass all CI,
contract, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, and
consolidation jobs; publication is skipped. Merged artifact `9537511908` has
SHA-256 `0c169ba2bbb561801834509b059db27472e5dd54744915d13ad8f87b57a21047`
and independently passes the exact eight-entry, seven-checksum, and 569-
component SBOM checks without extraction or execution.

The merge changed exactly 12 paths from parent `243bc84d34120af67f2bec1b93e1f5a0e8e92f3c`.
Every existing destination path first matched that parent and the new report
was absent. Exactly those 12 paths were copied with zero deletes to
`C:\Users\Brent\Documents\Avorax-main`; every normalized destination blob
matches the merge and every raw SHA-256 matches the source. No unrelated
destination change was overwritten.

Destination parsers `2/2`, source contracts `655/655`, target `2/2`, complete
Authenticode `52/52`, Native `503` passed/`13` ignored plus compiler `6/6`,
Local Core `536/536`, Guard `248/248`, both locked workspaces, strict Native/
Local/Guard Clippy, standalone locked/offline Native all-targets/all-features,
Flutter analysis, and Flutter `838/838` pass. Definitive destination
verification ran from `2026-08-24T20:44:58.0820536Z` through
`2026-08-24T20:52:54.3725037Z` and passed exact `255/255`, zero failed or
skipped, in `476.3s`; the checkpoint step passed in `0.3s`. Its embedded and an
independent Windows PowerShell 5.1 `-RequireFullSuite` validator pass.

Support-wrapper failures remain explicit and are not counted as product
evidence: one adversarial-report command was blocked before execution by its
recursive cleanup shape; one artifact JavaScript wrapper failed parsing and
created nothing; one artifact inspection rejected a stale generic SBOM name;
and one synchronization JavaScript wrapper failed interpolation before copying
anything. Corrected bounded reruns passed. A standalone validator invocation
under PowerShell 7 also rejected ISO timestamps because that interpreter
auto-converted JSON strings to `DateTime`; the exact supported Windows
PowerShell 5.1 invocation then passed `255/255`, matching the verifier's
embedded validator. The PowerShell 7 mismatch is not counted as a pass.

Final read-only checks retain the three exact lock blobs and protected-vault
invariant above. No service or driver was installed or started, Defender was
not weakened, candidate installers were not extracted or executed, and no
release or publication occurred. Checkpoint 2225 is closed; its documented
point-in-time, identity, isolation, signed-driver, and pre-execution limits and
the complete antivirus goal remain active.
