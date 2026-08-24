# Checkpoint 2222 - Authenticode Client Logon-Session Binding

Date: 2026-08-24

## Objective

Narrow the remaining same-user named-pipe substitution boundary by binding the
connected Authenticode helper token to the exact Windows logon session of the
low-integrity, privilege-stripped primary token used to launch that helper.
Checkpoint 2221 proves the connected token's user and safety state, but a SID
alone does not distinguish two logon sessions for the same account.

## Scripted Implementation

- Before handshake pipe creation, the parent reads the exact launch primary
  token user SID, `TokenStatistics.AuthenticationId`, and `TokenSessionId`.
  The launch SID must also equal the current-user SID that owns the pipe.
- `TOKEN_STATISTICS` and the session ID use the existing fixed-size
  `GetTokenInformation` helper, which rejects API failure and any returned-size
  mismatch. An all-zero expected authentication LUID is rejected.
- After the bounded message read and `ImpersonateNamedPipeClient`, the parent
  reads the same values from the connected thread token. Both 32-bit halves of
  `AuthenticationId` and the exact `TokenSessionId` must match before the
  random launch token can be accepted.
- Query or validation failure remains diagnostic. Existing mandatory
  `RevertToSelf` and empty-parent-thread-token proof still run; no weaker retry,
  alternate identity probe, or success fallback exists.

The implementation follows the Windows token contracts documented for
[`TOKEN_STATISTICS`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics)
and
[`TOKEN_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class).

## Scripted Verification Contract

- A benign real parent/child regression uses only the existing ignored helper
  fixture, verifies the bounded handshake, and proves that the parent thread is
  reverted afterward. The fixture is never treated as malware and is not a
  malware sample.
- Adversarial unit cases reject drift in either `AuthenticationId` half, drift
  in `TokenSessionId`, and an empty expected authentication LUID.
- Python source contract 652 requires pre-pipe launch-token capture, exact SID
  ownership, fixed-size token queries, exact comparisons, fail-visible cases,
  both regressions, verifier scope, validator scope, and this documentation.
- The definitive verifier adds `native-engine Authenticode handshake client
  logon-session regressions`; strict validation requires exactly 252 steps and
  the new verified and technically limited scope statements.

No checkpoint-2222 passing result is claimed during scripting. Per the required
sequence, focused checks, complete local regressions, definitive report and
malformed-report validation, exact-head hosted evidence, normal PR integration,
guarded original-tree synchronization, and destination verification begin only
after this complete implementation/test/verifier/validator/document batch is
scripted.

## Security Boundary And Limits

Exact `AuthenticationId` plus `TokenSessionId` binding narrows same-user
cross-logon-session substitution at the inspected message. It is point-in-time
evidence, not token uniqueness. It does not prevent same-logon-session process
injection or handle duplication, encrypt the pipe, change identity, provide
cross-identity service authentication, create AppContainer/LPAC isolation, or
demonstrate signed-driver or pre-execution enforcement. Installed LocalSystem,
production signing, driver signing, and true pre-execution protection remain
separate external prerequisites.

## Dependency And Safety Impact

The code reuses the pinned `windows-sys` Security token types and features. It
adds no crate, package, feature, or lockfile change. This scripting batch does
not use live malware or EICAR, execute an untrusted fixture, modify Defender,
install a package or machine-wide component, start a service/driver, publish a
release, or mutate the protected quarantine vault.

## Focused Execution Evidence

The PowerShell verifier and validator parse, and the Python contract module
compiles. The first `rustfmt --check` reported two formatting-only differences;
the project formatter applied them and the check now passes. The first attempted
focused contract invocation selected a bundled Python without `pytest`, so no
contract ran and no test result is claimed for that attempt. The repository's
dependency-free runner then executed all 652 contracts and found two stale
source-contract expectations: a nonexistent slice terminator and the old
two-argument checkpoint-2221 validator call. Both expectations were corrected;
the complete rerun passes `652/652`.

The new benign/adversarial logon-session filter passes `2/2`. Existing
client-token binding passes `2/2`, parent/child process binding passes `2/2`,
complete Authenticode passes `69` with `13` intentional isolated child fixtures
ignored, and the locked Native Engine passes `497` with the same `13` ignores
plus signature compiler `6/6`. Strict Native all-target/all-feature Clippy also
passes with warnings denied. Broader Local Core, Guard, workspace, Flutter,
definitive, hosted, integration, synchronization, and destination evidence
remain pending; this focused evidence does not close the checkpoint.

## Full Local Regression Evidence

Both locked root workspace variants pass. Local Core passes `536/536`; Guard
passes `248/248` standard and `249/249` with all features. Strict Native, Local
Core, and Guard all-target/all-feature Clippy pass with warnings denied. Flutter
analyze reports no issues and the complete client suite passes `838/838`.
Dependency resolution reported 33 newer versions outside current constraints
but retained the checked-in lockfile and introduced no upgrade.

Root Cargo, Native Cargo, and Flutter lock blobs remain exactly
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Read-only protected-vault
inventory remains exactly 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending/temp. Definitive verification, adversarial report validation, hosted
evidence, integration, guarded synchronization, and destination verification
remain pending; the complete antivirus goal remains active.

## Definitive Local Evidence

The definitive report ran from `2026-08-24T13:11:31.6208659Z` through
`2026-08-24T13:19:59.4049555Z` and passed exact `252/252` in `507.8s`, with
zero failed or skipped steps. The new logon-session target passed in `0.3s`;
Defender/EICAR remained opt-in, while neither Rust nor Flutter was skipped.
The report is `.workflow/ultracode/avorax-hardening/results/checkpoint-2222-local-report.json`.

The verifier's embedded strict validator and an independent Windows PowerShell
`-RequireFullSuite` invocation accept the report. Two attempted independent
validations under PowerShell 7 rejected ISO timestamps because that host
materializes them as `DateTime` rather than the JSON strings required by the
validator; those host-mismatch attempts are not validation success evidence.
The exact Windows PowerShell host used by the verifier passes independently.

Nine controlled untracked report copies were rejected for stale 251-step
evidence, renamed target, missing launch-capture scope, missing connected-match
scope, missing failure scope, missing residual-limit scope, failed target,
skipped target, and `skip_rust=true`. Hosted exact-head evidence, normal PR
integration, merged-main checks, guarded original-tree synchronization, and
destination verification remain pending.

## Implementation-Head Hosted Evidence

Implementation commit `0a24ac25fcdedf1ef50af8acb9b71499caf9ac69`
was pushed only to the checkpoint branch and opened as draft PR `#74`. Exact-
head Avorax CI `32732523250` passes all branding/copy, security/protection/
performance, Flutter/protocol, Rust, and Unix quarantine-permission jobs.

Desktop Packages PR run `32732523189` passes package contracts, Windows x64
MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, and consolidation/checksum
jobs. Push run `32732497575` initially failed only because the arm64 runner's
`hdiutil verify` returned `Resource temporarily unavailable` for all five
bounded retries after app build, payload validation, signing checks, benign
package smoke, and DMG creation had passed. The identical PR job passed. A
failed-job-only rerun of the unchanged push head passed arm64 in `6m24s`, then
passed consolidation; the final push run is attempt 2 with success. This
transient first attempt is not counted as passing evidence.

Both final package runs explicitly skip prerelease publication. Independently
downloaded consolidated bundles each contain six platform release files, a
CycloneDX 1.6 lockfile SBOM with 569 components, and seven SHA-256 rows that all
match recomputed hashes. Nothing was installed, executed, released, or
published. Evidence-head checks, normal merge, merged-main checks, guarded
original-tree synchronization, and destination verification remain pending.
