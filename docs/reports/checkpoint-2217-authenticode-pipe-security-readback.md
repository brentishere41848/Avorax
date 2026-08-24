# Checkpoint 2217: Authenticode Pipe Security Read-Back

Date: 2026-08-24

## Status

Implementation, benign and adversarial tests, verifier step 247, exact validator
contracts, source contract 647, and audit documentation were scripted as one batch
before execution. The corrected implementation and complete local regression are
verified. Exact implementation-head CI and package evidence is also verified.
Evidence-head checks, PR merge, guarded original-tree synchronization, merged-main
evidence, and destination verification remain pending.

## Threat

Checkpoint 2216 supplies a protected current-user/SYSTEM DACL and a low-integrity
no-write-up mandatory label to `CreateNamedPipeW`, but source construction alone
does not prove that Windows applied the exact descriptor. An API, descriptor,
binding, or future wiring defect could otherwise leave a broader or incorrectly
labeled handshake endpoint while the parent continues toward publisher trust.

## Implemented Control

- Immediately after named-pipe endpoint validation and before event creation,
  connection, process creation, or helper launch, the parent calls
  `GetSecurityInfo` with `SE_KERNEL_OBJECT` and exactly
  `DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION`.
- Microsoft documents both requested components as requiring `READ_CONTROL` for
  query. The existing inbound named-pipe server handle supplies that access. The
  code does not request the full SACL, `ACCESS_SYSTEM_SECURITY`, or
  `SeSecurityPrivilege` and adds no privilege-enabling path.
- `GetSecurityDescriptorControl`, `GetSecurityDescriptorDacl`,
  `GetSecurityDescriptorSacl`, `GetAclInformation`, and `GetAce` collect bounded
  structured evidence. ACLs are capped at eight ACEs and 4,096 bytes; every ACE
  type, size, boundary, flag, mask, and SID is validated.
- Generic pipe/file access is normalized with `MapGenericMask`. Exact evidence
  requires `SE_DACL_PROTECTED`, a present nondefault DACL with exactly ordered
  zero-flag full-control access-allowed ACEs for SYSTEM and the current user, and
  one present nondefault zero-flag low-integrity no-write-up mandatory-label ACE.
- Query, null result, control-flag, ACL bound/count, ACE type/size/flag/mask/SID,
  extra/missing principal, ACE order, access, label, or policy mismatch is a
  visible error. It
  closes the server handle and cannot reach connection or helper launch. There is
  no weaker retry or success fallback.

## Test Evidence

- A real benign restricted-child handshake traverses the production creation
  path, so successful process binding also requires the new descriptor read-back.
  The test executes only the test binary as its helper and never executes a
  candidate fixture.
- Pure adversarial cases reject an unprotected DACL, missing or changed user,
  extra administrator, changed ACE order, missing label, missing no-write-up,
  medium label, duplicate label, zero protection control, and malformed expected
  contracts.
- The central verifier adds exact step 247, `native-engine Authenticode handshake
  pipe security read-back regressions`. The independent full-suite validator
  requires exactly 247 successful steps, that exact step, least-privilege scope,
  and fail-visible scope.
- Source contract 647 pins APIs, ordering, forbidden privilege expansion, tests,
  verifier/validator contracts, dependency delta, and all audit documents.

## Technical Limit

`GetSecurityInfo` is a point-in-time read immediately after creation. The parent
owns the handle and grants DACL mutation only to itself/current user and SYSTEM,
but a sufficiently privileged same-user process, injected trusted code, SYSTEM,
or kernel compromise remains outside this user-mode control. This reads only the
mandatory-label portion of the SACL through `LABEL_SECURITY_INFORMATION`; it
intentionally does not read the full SACL or claim a general SACL audit.

Exact ACL/MIC read-back does not encrypt or authenticate cross-identity IPC,
prevent same-user process-memory access, provide AppContainer/LPAC, demonstrate
an installed LocalSystem service, prove production signing, add a driver, or
provide pre-execution blocking. Existing valid-Authenticode-and-verified-
Microsoft-signer requirements and bounded embedded/catalog limitations remain.

No live malware, candidate execution, download, installation, service/driver
start, Defender change, publication, release, or protected-vault mutation is part
of this checkpoint.

## Local Verification

- PowerShell parsers `2/2`, Python compilation, final Rust formatting, diff check,
  and source contracts `647/647` pass.
- Corrected focused read-back passes `1/1`; adjacent parent-child handshake passes
  `2/2`; complete Authenticode passes `54` with `13` intentional ignores.
- Strict Native, Local Core, and Guard Clippy pass. Both locked standard and
  all-feature workspaces pass with Native `490` passed/`13` ignored and signature
  compiler `6/6`; all remaining workspace tests pass.
- Release Local Core and Guard builds plus the two-host benign Authenticode smoke
  pass. The first smoke command used relative paths and was correctly rejected;
  the required absolute-path rerun passed.
- Flutter analyze reports no issues and the complete client suite passes
  `838/838`.
- The definitive verifier ran from `2026-08-24T03:33:43.0094933Z` through
  `2026-08-24T03:41:30.6365127Z` and passed exactly `247/247`, with zero failed or
  skipped steps, in `467.6s`. Its embedded validator and an independent
  `-RequireFullSuite` invocation pass.
- Seven isolated malformed reports are rejected: missing step, renamed step,
  missing immediate-read-back scope, missing structured-ACL scope, missing
  least-privilege scope, failed target step, and skipped target step.
- Root Cargo, Native Cargo, and Flutter lock hashes remain respectively
  `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`.
- Read-only protected-vault evidence remains exactly `16,072` files, zero
  directories, `4,522,733` bytes, `5,357` each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending.

## Hosted Implementation Evidence

- Exact implementation `a518e93d42e9d2dad3e3898f463c455d71156528` is on
  draft PR `#69`.
- Avorax CI `32687717433` passes all five jobs at that exact head: branding/copy,
  Rust Local Core/Native/Guard/update/API tests and lint, Unix quarantine
  permissions, Flutter/protocol, and security/protection/performance gates.
- Desktop Packages push `32687664061` and PR `32687717444` pass package contracts,
  Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, dependency/license
  evidence, administrative MSI extraction, and consolidation.
- The downloaded exact push artifact contains the six platform packages plus a
  CycloneDX 1.6 lockfile SBOM with `569` components. All seven entries match
  `SHA256SUMS.txt` exactly.
- Both `Publish desktop beta prerelease` jobs are skipped. No package was
  installed, released, or published.

## Initial Execution Finding

The first focused runtime compiled but rejected a text-form exact comparison:
Windows mapped generic all (`GA`) to file all (`FA`) for the pipe object and added
the SACL auto-inherited display flag (`S:AI`) while preserving the exact two DACL
principals and low-integrity no-write-up label. That failure is not counted as a
pass. The implementation and adversarial contracts were repaired to compare
bounded structured ACE evidence with official generic-right normalization rather
than SDDL spelling. The corrected focused, adjacent, full, and definitive runs
above pass; the failed text-comparison run is retained as diagnostic evidence and
is not counted as success.
