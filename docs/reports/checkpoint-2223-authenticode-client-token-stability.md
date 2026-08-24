# Checkpoint 2223 - Authenticode Client Token Stability

Date: 2026-08-24 (Europe/Brussels)

## Objective

Detect replacement or mutation of the impersonated named-pipe client token
while the parent validates its security properties. This checkpoint snapshots
the exact `TokenStatistics.TokenId` and `ModifiedId` before all client-token
property checks and queries both again after every successful check.

An empty initial token ID, an exact-size token-statistics query failure, token-
instance drift, or token-modification drift is a diagnostic error and cannot
become Microsoft publisher trust. Existing exact SID,
`AuthenticationId`/`TokenSessionId`, low-integrity, privilege, mandatory-policy,
virtualization, UIAccess, pipe-process, nonce, ACL, and mandatory
`RevertToSelf` checks remain unchanged.

## Scripted Implementation

- `AuthenticodeTokenStabilityEvidence` holds both halves of the token-object
  LUID and modified-context LUID without serializing either value.
- `query_authenticode_token_stability` uses the existing exact-size
  `TokenStatistics` query path and rejects an empty initial token ID.
- `validate_authenticode_pipe_client_token` snapshots before privilege and
  property queries, validates all existing evidence, then queries and compares
  the same token handle again.
- `validate_authenticode_token_stability_evidence` rejects low/high drift in
  either `TokenId` or `ModifiedId` with distinct fail-visible diagnostics.
- A real isolated parent/child handshake regression proves the production path
  and `RevertToSelf`; adversarial pure evidence cases cover four drift variants
  and an empty initial token ID. No fixture is executed as candidate content.
- The definitive verifier adds a mandatory token-stability step and the
  independent validator now requires exactly 253 steps plus verified and
  technically-limited scope contracts.

## Security Boundary

This check detects token replacement or mutation only across one successful
client-token validation. It does not bind the impersonation token object to the
launch primary-token object, and it cannot prevent mutation wholly before or
after that window. It also does not prevent same-session injection or handle
duplication, encrypt IPC, authenticate cross-identity service IPC, provide
AppContainer/LPAC, or demonstrate driver or pre-execution enforcement.

Microsoft documents `TokenId` as identifying one local token-object instance
and `ModifiedId` as changing whenever the token changes. This checkpoint uses
those values only for an in-process before/after stability comparison; it does
not assume that a primary token and an impersonation token share a `TokenId`.
The API contract is documented in
[`TOKEN_STATISTICS`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics).

## Scripting-Phase Status

No checkpoint-2223 passing result is claimed during scripting. Code, benign
and adversarial Rust tests, source contract 653, the exact 253-step verifier
contract, independent validator assertions, and all audit documentation were
written before any test execution. Verification, evidence commits, exact-head
hosting, normal PR/merge, guarded synchronization, and destination proof remain
pending.

This checkpoint adds no crate, package, feature, or lockfile change. It does
not install or start a service/driver, alter Defender, touch protected
quarantine content, execute malware, publish a package, or claim that the whole
antivirus project is complete.

## Local Verification Evidence

Parser checks `2/2`, `rustfmt --check`, token stability `2/2`, prior logon-
session `2/2`, source contracts `653/653`, complete Authenticode `71/13`,
Native Engine `499/13` plus compiler `6/6`, both locked workspace variants,
strict Native/Local/Guard Clippy, standalone locked/offline Native check,
Flutter analyze, and Flutter `838/838` pass.

The definitive report ran from `2026-08-24T15:13:23.6533587Z` through
`2026-08-24T15:21:36.5966555Z` and passed exact `253/253` in `492.9s`, with
zero failed or skipped steps. The new token-stability target passed in `0.2s`.
Embedded and independently repeated `-RequireFullSuite` validation pass, and
nine controlled report mutations are rejected.

One standalone offline-check command was first invoked from
`apps/zentor_client` with the repository-relative Native manifest path and
correctly failed because that path does not exist from the subdirectory. The
same exact check was immediately rerun from the repository root and passed in
`2.76s`; this was a command work-directory error, not a source or test failure.

All three lock blobs remain exact. The protected quarantine inventory is
rechecked separately before commit. Normal PR/merge, guarded synchronization,
and destination proof remain pending, so checkpoint 2223 is locally and at its
implementation head verified but not closed.

## Implementation-Head Hosted Evidence

Exact implementation commit
`561ac536a55257b05f9c04ada55756d1ab676749` passes Avorax CI run
`32744796324` and Desktop Packages pull-request/push runs `32744796274` and
`32744754697`. The CI run completed all five jobs. Both package runs completed
package contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64
DMG, and consolidation successfully. Prerelease publication was explicitly
skipped in both runs.

The original consolidated artifact ZIP from each package run was downloaded
without extracting its candidate executables. Independent stream-based checks
proved exactly eight archive entries: six platform artifacts, one CycloneDX
lockfile SBOM, and `SHA256SUMS.txt`. Each manifest had exactly seven rows and
all seven SHA-256 values matched the corresponding ZIP entry. Both SBOMs are
CycloneDX 1.6 with 569 components.

An ordinary `gh run download` extraction completed with success but local
Defender removed the Windows MSI and EXE from both extracted directories. No
Defender setting was changed. This endpoint event is not represented as an
artifact-integrity failure because the untouched GitHub ZIP streams retained
both entries and their hashes independently matched; the extracted directories
are not used as complete-package evidence.

Evidence-head CI/packages, normal merge, merged-main checks, guarded original-
tree synchronization, and destination verification remain pending. Nothing
was installed, executed, released, or published.
