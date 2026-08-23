# Checkpoint 2210: Authenticode Token Virtualization and UIAccess

Date: 2026-08-23 (Europe/Brussels)

## Objective

Require the one-shot Windows Authenticode helper's privilege-stripped,
low-integrity primary token to report canonical virtualization capability
evidence, legacy virtualization inactive, and UIAccess disabled. This prevents
active legacy redirection or UIAccess from making the helper's effective
Windows boundary differ from its documented low-integrity/no-write-up behavior.

## Scripted Implementation

- `GetTokenInformation` reads `TokenVirtualizationAllowed`,
  `TokenVirtualizationEnabled`, and `TokenUIAccess` as exact fixed-size `DWORD`
  values through the existing bounded scalar helper.
- `validate_authenticode_primary_token` requires `TokenVirtualizationAllowed`
  to be a canonical Boolean and requires `TokenVirtualizationEnabled` and
  `TokenUIAccess` to equal zero after primary-token type, privilege, Low
  Mandatory SID, and mandatory no-write-up policy validation.
- Parent read-back occurs before `CreateProcessAsUserW`. The actual child calls
  the same validator before stdin or request parsing, so requested state is not
  confused with inherited process state.
- Any query failure, unexpected result size, noncanonical capability value,
  enabled virtualization/UIAccess value, or child drift is a diagnostic error
  and cannot become Microsoft publisher trust. There is no setter, added
  privilege, or weaker retry.

Microsoft documents `TokenVirtualizationAllowed` as the token capability,
`TokenVirtualizationEnabled` as the active state, and `TokenUIAccess` as the
UIAccess flag. The active virtualization and UIAccess fields must be zero;
capability alone is not described as active protection state.

## Benign Evidence

- Pure validation accepts both canonical capability values while active state
  remains zero, rejects enabled virtualization/UIAccess, and rejects a
  non-Boolean capability value.
- A dedicated isolated child validates the real process primary token and emits
  `AVORAX_TOKEN_VIRTUALIZATION_UIACCESS_DISABLED_OK` only after all parent and
  child read-back checks pass.
- The central verifier adds one mandatory focused filter, increasing the strict
  report contract from 239 to 240 steps.
- The independent report validator requires the exact step, verified-scope
  language, technical-limit language, and exact 240-step count.
- A Python source contract accounts for implementation, tests, verifier,
  validator, and all required documentation.

The complete implementation/test/verifier/documentation batch was intentionally
scripted before running any check, as requested.

The first focused real-child run compiled after one fixture-wiring repair, then
failed visibly because Windows returned `TokenVirtualizationAllowed=1`. That
failed attempt is not success evidence. It proved the original exact-zero
capability requirement confused permission with active state; the policy was
redesigned to accept only canonical capability evidence while still requiring
exact-zero active virtualization and UIAccess. The repaired real-child and pure
filter then passed `2/2`.

## Local Verification

- PowerShell parser checks and Rust formatting pass. The six adjacent
  mandatory-policy, low-integrity, restricted-process, sanitized-launch,
  process-mitigation, and write-restricted filters each pass `2/2`.
- Complete Authenticode testing passes `41` tests with `8` intentional ignored
  child fixtures. Full Native testing passes `477` with `8` intentional ignores;
  the signature compiler adds `6/6` passes.
- Strict Native, Local Core, and Guard Clippy pass. The locked Rust workspace
  passes `1,524` tests with `8` ignored, and the locked all-features workspace
  passes `1,525` with `8` ignored. Locked release Local Core and Guard builds and
  the benign two-host release Authenticode smoke pass without executing a
  candidate fixture.
- Flutter analyze reports no issues and the Flutter suite passes `838/838`.
  The dependency-free Python source-contract runner passes `640/640` after two
  stale prior text assertions failed visibly and were repaired.
- The no-malware-binaries and dependency-evidence gates pass. Cargo and Flutter
  lockfiles are unchanged.
- The definitive report
  `.verification/checkpoint-2210-small-threat-mvp-definitive-report.json` passes
  exactly `240/240` steps, with zero failed or skipped, from
  `2026-08-23T15:35:08.5267528Z` through `2026-08-23T15:42:46.5568341Z`
  (`458` seconds). A separate full-suite validator accepts it. Five controlled
  reports with a stale count, renamed step, or removed verified/technical-limit
  scope are rejected.
- Read-only checks preserve the protected quarantine invariant: `16,072` files,
  zero directories, `4,522,733` bytes, `5,357` each `.avoraxq`/`.json`/`.auth`,
  one `.metadata_auth_key`, and zero pending files.

## Hosted Implementation-Head Evidence

Exact implementation head `c744fa90cf3ac9802e8055780a5d05e804b8b39d`
passes:

- Avorax CI pull-request run `32649764260`: Rust/Native lint and tests, Flutter,
  Unix quarantine permissions, security/protection/performance gates, branding,
  dependency evidence, and no-malware checks all succeed.
- Desktop Packages push run `32649749634` and pull-request run `32649764310`:
  Windows x64 MSI/setup EXE, Linux x64 DEB/tar, macOS x64/arm64 DMGs, package
  contracts, dependency/license evidence, administrative MSI extraction without
  installation, six-artifact consolidation, lockfile SBOM, checksums, and
  evidence upload all succeed. The prerelease publication job is skipped in
  both runs.

Evidence-head checks, normal merge, merged-main evidence, and guarded
original-tree synchronization remain pending and are not claimed here.

## Honest Boundary

Canonical `TokenVirtualizationAllowed` may remain one because it describes an
inherited capability. Exact-zero `TokenVirtualizationEnabled` proves legacy
virtualization is inactive, and exact-zero `TokenUIAccess` prevents UIAccess
treatment. Trusted helper code has no activation path, but the capability is
not removed. These checks do not create a new SID, profile, registry namespace,
desktop or window station; they do not remove ordinary reads or the three
intended inherited standard handles. They are not AppContainer/LPAC, private-desktop isolation,
authenticated cross-identity IPC, installed LocalSystem proof, a signed driver,
kernel interception, pre-execution blocking, or production detection-rate
evidence.

No candidate fixture is executed. No live malware, Defender change,
machine-wide installation, service/driver start, release, or publication is
part of this checkpoint.

## Dependency Contract

Checkpoint 2210 adds no crate, package, Cargo feature, or lockfile change. It
reuses `TokenVirtualizationAllowed`, `TokenVirtualizationEnabled`,
`TokenUIAccess`, and `GetTokenInformation` from the existing pinned
`windows-sys 0.61.2` `Win32_Security` feature (`MIT OR Apache-2.0`). Final
artifact license and notice review remains a separate release-host requirement.
