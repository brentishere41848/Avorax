# Checkpoint 2221 - Authenticode Handshake Client-Token Binding

Date: 2026-08-24

## Objective

Bind the dedicated Authenticode helper handshake to the security token of the
client that actually wrote the bounded launch-token message. Existing controls
already bind a random pipe/token, both process IDs, endpoint shape, exact owner,
DACL, Owner Rights, and mandatory label. This checkpoint adds Windows-native
client-token authentication before the launch token can be accepted.

## Scripted Implementation

- The low-integrity helper opens the client endpoint with explicit
  `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`; it does not request
  delegation or dynamic context tracking.
- After the parent reads the one bounded handshake message, it calls
  `ImpersonateNamedPipeClient` on the verified server endpoint. The read must
  precede impersonation because NPFS supplies the security context of the last
  message read.
- The parent opens the resulting thread token with bounded query buffers and
  requires exact `SecurityImpersonation`, the launch user SID, privilege
  stripping, zero restricting SIDs, the Low Mandatory Level SID, no-write-up
  mandatory policy, canonical virtualization capability, inactive
  virtualization, and disabled UIAccess.
- The parent always calls `RevertToSelf` after token inspection and then proves
  that no thread token remains. Impersonation, query, validation, revert, or
  post-revert failure is diagnostic and aborts helper trust work; there is no
  weaker retry or fake success.
- Token-user reads validate both API-reported sizes and the returned SID pointer
  range before formatting the SID. Empty restricting-SID lists are accepted by
  the bounded parser only where the caller explicitly requires zero; the
  write-restricted verification token still requires exactly one
  `WinRestrictedCodeSid`.

Microsoft's platform contract is the basis for the ordering and cleanup:
[`ImpersonateNamedPipeClient`](https://learn.microsoft.com/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
uses the security context of the last message read, and
[`Impersonating a Named Pipe Client`](https://learn.microsoft.com/windows/win32/ipc/impersonating-a-named-pipe-client)
documents default `SecurityImpersonation` and mandatory `RevertToSelf` cleanup.

## Scripted Verification Contract

- Two benign Rust regressions exercise a real parent/child pipe-token readback
  and post-operation parent-thread reversion, then reject wrong token type,
  level, user SID, restricting SID, integrity SID/attributes, mandatory policy,
  virtualization state, and UIAccess evidence. The child fixture is never
  treated as or executed as malware.
- Python source contracts require the exact API ordering, explicit SQOS,
  bounded token-user pointer validation, complete failure/revert paths,
  adversarial fixtures, verifier step, validator clauses, and audit documents.
- The definitive verifier adds
  `native-engine Authenticode handshake pipe client-token regressions`; the
  full-suite validator requires exactly 251 steps and the source contract 651.
- The verifier report must separate verified behavior from the residual
  same-user, cross-identity, AppContainer/LPAC, driver, and pre-execution limits.

No checkpoint-2221 passing result is claimed during scripting. Per the requested
sequence, focused checks, full regressions, definitive report validation,
malformed-report rejection, exact-head hosted evidence, normal PR integration,
guarded destination synchronization, and destination verification begin only
after this complete source/test/verifier/validator/document batch is scripted.

## First Focused Execution Finding

The first focused runtime command compiled the code and passed the adversarial
evidence test, but the real pipe-token test failed before trust because Windows
returned a four-byte `TokenRestrictedSids` zero-count header rather than the
larger Rust flexible-array struct size. This was a safe fail-closed result, not
success evidence. The parser now accepts the bounded DWORD header, reads count
without dereferencing a full `TOKEN_GROUPS`, returns an empty list only for exact
zero count, and performs the existing offset/entry bounds before any nonempty
entry read. The source contract now protects that zero-count parsing rule. A
corrected focused rerun and every broader check remain pending.

The next combined rerun stopped at source contract 651 before Rust execution:
the new zero-count assertions searched only the client-token validator slice,
while the bounded parser is intentionally a shared function later in the file.
The contract scope was corrected to the complete production module. This failed
contract attempt is not runtime or passing evidence.

The corrected focused and full functional runs then passed, but the first
strict Clippy run rejected test-only `Vec::new()` followed by immediate pushes
under `-D warnings`. The fixture now initializes its first adversarial cases
with `vec![]`; that lint failure is not a strict-lint success claim and its rerun
remains pending.

## Focused And Full Local Evidence

- PowerShell parsers, Python compile, rustfmt/diff checks, source contracts
  `651/651`, focused client-token `2/2`, all handshake `6/6`, and Authenticode
  `67` passed with `13` intentional isolated child fixtures ignored.
- Native Engine passed `495/13`; signature compiler `6/6`; Local Core `536/536`;
  Guard `248/248` standard and `249/249` all-feature. Locked/offline Native
  all-target/all-feature check, strict Native/Local/Guard Clippy, and both locked
  root workspace suites pass.
- Flutter analyze reports no issues and the complete Flutter suite passes
  `838/838`. Dependency resolution reported 33 newer incompatible versions but
  retained the checked-in lockfile; no dependency was upgraded.
- Root Cargo, Native Cargo, and Flutter lock blobs remain exactly
  `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`.
- Read-only protected-vault inventory remains exactly 16,072 files, zero
  directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending/temp. No vault object changed.

Definitive local verification ran from `2026-08-24T11:22:40.5122436Z` through
`2026-08-24T11:30:48.4898041Z` and passed exact `251/251` in `487.9s`, with no
failed or skipped step. The client-token target passed in `0.3s`; Defender/EICAR
remained opt-in and neither Rust nor Flutter was skipped. Embedded and standalone
`-RequireFullSuite` validation accepted the report. Nine controlled untracked
copies were rejected for stale 250-step evidence, renamed target, missing SQOS,
token-validation, failure, or residual-limit scope, failed/skipped target, and
`skip_rust=true`.

Post-verifier lock blobs and the protected-vault inventory remain exact. Exact-
head hosted evidence, integration, guarded destination sync, and destination
verification remain pending. Local suites do not complete the checkpoint or the
overall antivirus goal.

## Implementation-Head Hosted Evidence

Implementation commit `014e5b98ec703e30b8c59a7d26f6511f1c5aa7ed`
was pushed only to the checkpoint branch and opened as draft PR `#73`. Exact-
head Avorax CI `32722684598` and Desktop Packages push/PR runs `32722662492`
and `32722684574` pass. The CI run covers Rust/Clippy, Unix quarantine
permissions, security/protection/performance, branding/copy, and Flutter/
protocol jobs.

Both package runs pass package contracts, Windows x64 MSI/EXE, Linux x64
DEB/tar, macOS arm64/x64 DMG, and consolidation/checksum jobs; publication is
explicitly skipped. Each downloaded consolidated evidence bundle contains six
platform release files, one CycloneDX 1.6 lockfile SBOM with 569 components,
and seven SHA-256 rows that all match. Nothing was installed, executed,
released, or published. Evidence-head checks, normal merge, merged-main checks,
guarded destination synchronization, and destination verification remain
pending.

## Integration And Destination Closure

Evidence commit `b60f500d59629682d84f532c7e0f16d623f6b6b4` passed Avorax
CI `32724454733` and Desktop Packages `32724454722`. PR `#73` merged normally
with exact-head locking as `c4d997510cf698209b72c83c7a80b2d82524505f`.
Merged-main CI `32725907346` and packages `32725907352` passed; all platform,
consolidation, checksum, and CycloneDX 1.6/569-component SBOM evidence passed,
while publication was skipped.

All 12 original-tree preconditions matched merge parent `2bd8956` or valid
absence. Exactly those paths were synchronized to
`C:\Users\Brent\Documents\Avorax-main`; every normalized Git blob and raw
SHA-256 matched merge `c4d9975`. Destination focused tests, complete locked Rust
workspaces, strict Native/Local/Guard Clippy, release two-host trust smoke,
Flutter analyze and `838/838`, and source contracts `651/651` passed.

The destination definitive report ran from
`2026-08-24T12:38:04.9752085Z` through
`2026-08-24T12:45:48.5598504Z` and passed exact `251/251` in `463.5s`, with zero
failed or skipped step. Embedded and independent strict validation passed. The
three lock blobs and protected-vault invariant remained exact. No artifact was
installed, executed, released, or published. Checkpoint 2221 is closed; its
documented same-user and external-prerequisite limits, and the complete
antivirus goal, remain active.

The first definitive invocation selected
`C:\Users\Brent\AppData\Local\Microsoft\WindowsApps\python.exe` through
`Get-Command`. The security gate correctly rejected that reparse-point alias at
`release signed hash-intelligence definitions package smoke`, wrote a failed
partial report, and stopped. Earlier steps from that run are not counted as a
definitive pass. The corrected invocation uses the bundled regular-file Python
runtime under `.cache\codex-runtimes`; the complete corrected rerun is the
passing 251-step evidence recorded above.

## Security Boundary And Limits

`ImpersonateNamedPipeClient` authenticates the connected same-user helper token
for the one message that was read. Exact PID checks, random launch material,
SQOS, token identity, low integrity, DACL/owner readback, and reversion are
cumulative controls. They do not encrypt the channel, change identity or logon
session, prevent privileged same-user process injection or handle duplication,
create AppContainer/LPAC, authenticate a future cross-identity service/UI
channel, or demonstrate signed-driver or pre-execution enforcement. Installed
LocalSystem and production-signed E2E remain external prerequisites.

## Dependency And Safety Impact

The implementation uses the already pinned `windows-sys` Win32 Pipes, Security,
Threading, and FileSystem features. It adds no crate, package, feature, or
lockfile change. No live malware, EICAR file, Defender exclusion, machine-wide
installation, service/driver start, package execution, release, or publication
is involved. The protected quarantine vault remains read-only and out of scope.
