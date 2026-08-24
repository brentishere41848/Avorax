# Checkpoint 2220: Authenticode pipe Owner Rights

Date: 2026-08-24

## Scripting Status

The implementation, benign/adversarial tests, central verifier, independent
validator, source contract 650, audit, threat-model, dependency, status, and
run-log batch is fully scripted before execution. No checkpoint-2220 passing
result is claimed during scripting. Focused, full, hosted, integration, and
destination evidence must be added only after the corresponding commands run.

## Control Change

The handshake security descriptor now sets the exact current process-token user
SID as owner and reads that owner back from both the parent server handle and the
child client handle. Its exact SDDL is
`O:<current-user-sid>D:P(A;;GA;;;SY)(A;;GRGW;;;<current-user-sid>)(A;;RC;;;OW)S:(ML;;NW;;;LW)`.
The third ordered, zero-flag allow ACE uses the Windows Owner Rights SID
`S-1-3-4` (SDDL `OW`) and grants only `READ_CONTROL`.

Microsoft documents that an applied Owner Rights ACE causes Windows to ignore
the owner's otherwise implicit `READ_CONTROL` and `WRITE_DAC`. The explicit
current-user generic-read/generic-write ACE still supplies the protocol and
descriptor-query access needed by the parent and low-integrity child. SYSTEM
retains full control.

`GetSecurityInfo(SE_KERNEL_OBJECT)` now requests exactly
`OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
LABEL_SECURITY_INFORMATION`. A null, invalid, or mismatched owner; missing,
reordered, wrong-SID, zero-mask, `WRITE_DAC`-augmented, flagged, or extra Owner
Rights ACE; or any existing DACL/label mismatch is diagnostic before token
exchange or publisher trust. There is no weaker descriptor or access fallback.

## Scripted Evidence

- The existing real child fixture must still prove exact parent/client protocol
  access and both owner/DACL/mandatory-label read-backs.
- A separate benign, random, local-only named pipe uses the production security
  descriptor and verifies that a same-user `CreateFileW` reopen requesting only
  `WRITE_DAC` fails with `ERROR_ACCESS_DENIED`.
- Adversarial evidence mutates the owner, Owner Rights SID, zero and augmented
  masks, flags, and ACE order. Candidate files are neither created nor executed.
- The definitive verifier adds `native-engine Authenticode handshake pipe
  owner-rights regressions` and must emit exactly 250 steps.
- The independent validator requires the exact step, owner/denial/rejection
  scopes, residual limitation, and exact successful step count. A stale
  249-step report must fail.

## Technical Limit

Owner Rights narrows the default owner authority; it is not cross-identity
isolation. The current-user ACE intentionally retains protocol read/write,
already-open process handles and trusted same-user code remain in the trust
boundary, and privileged ownership changes, process injection, handle
duplication, or descriptor mutation between point-in-time checks are not
prevented. SYSTEM, administrators, and kernel compromise remain outside this
user-mode control.

This checkpoint adds no encryption, AppContainer/LPAC, installed LocalSystem
boundary, production signing, driver enforcement, or pre-execution protection.
It does not claim that named-pipe contents are secret from the same user.

## Dependency Delta

Checkpoint 2220 adds no crate, package, feature, or lockfile change. It reuses
the pinned `windows-sys 0.61.2` SDDL, security-information, SID, named-pipe, and
file-open bindings already enabled under MIT OR Apache-2.0. No network content,
executable fixture, machine-wide component, privilege enablement, or license
obligation is introduced.

## Planned Verification

After this scripting batch: parse the PowerShell files, compile the Python
contracts, check Rust formatting, run source contract 650, run the focused real
Owner Rights denial and adjacent parent/client fixtures, then complete Native,
both locked workspaces, strict Native/Local Core/Guard Clippy, release builds,
two-host benign trust smoke, Flutter analyze/tests, safety/dependency gates,
definitive exact-250 verification, independent validation, malformed-report
rejection, exact lock review, and read-only protected-vault inventory. Only then
may exact-head hosted CI/packages, a normal PR merge, guarded original-tree
synchronization, and destination verification proceed.

## References

- Microsoft Learn, `SID Strings`: `OW` is `SDDL_OWNER_RIGHTS`.
- Microsoft Learn, `Special Identity Groups`: `S-1-3-4` represents the current
  owner and suppresses implicit `READ_CONTROL` and `WRITE_DAC` when its ACE is
  applied.
- Microsoft Learn, `Security Identifiers Technical Overview`: the same Owner
  Rights semantics and SID are documented for Windows access control.

No live malware, EICAR creation, candidate execution, network retrieval,
installation, service/driver start, Defender change, protected-vault mutation,
release, or publication is part of this checkpoint.

## Corrected Local Verification

- PowerShell parsers `2/2` and Python compilation pass. The first Rust format
  check requested only normal formatter layout; formatting was applied and the
  corrected check passes. That first check is not counted as success.
- The first source-contract run executed all 650 contracts and found two stale
  historical assertions after the owner scope changed. They were repaired
  without weakening the current contract; the corrected run passes `650/650`.
- The exact Owner Rights denial test passes `1/1`. All four handshake security
  filters pass, and complete Authenticode passes `57` with `13` intentionally
  ignored isolated-child fixtures. Native passes `493/13` and its signature
  compiler `6/6`; locked/offline all-target/all-feature Native checking and
  strict Native Clippy pass.
- Both standard and all-feature locked root workspaces pass. Local Core passes
  `536/536`; Guard passes `248/248` standard and `249/249` all-feature. Strict
  Local Core and Guard Clippy, locked release builds, and the benign two-host
  Authenticode smoke pass embedded/catalog Microsoft trust, mandatory hash
  binding, unsigned rejection, and wrong-hash failure without fixture execution.
- Flutter analyze reports no issues and its complete suite passes `838/838`.
  The definitive verifier, independent validator, malformed-report checks,
  lock/vault review, hosted evidence, merge, synchronization, and destination
  verification remain pending and are not claimed by this section.

## Definitive Local Evidence

- The definitive report ran from `2026-08-24T09:26:52.1091780Z` through
  `2026-08-24T09:34:24.8241696Z` in `452.7s` and passed exactly `250/250`, zero
  failed and zero skipped. The target Owner Rights step passed. Embedded and
  separately invoked Windows PowerShell full-suite validation pass.
- Nine isolated malformed reports are rejected: stale 249-step count, renamed
  required step, missing owner scope, missing denial scope, missing rejection
  scope, missing residual limitation, failed target, skipped target, and
  `skip_rust=true`. The first long inline generator failed before creating any
  variant because of command quoting; the corrected isolated structured-JSON
  generator produced all nine. The failed attempt is not success evidence.
- Root Cargo, Native Cargo, and Flutter lock blobs remain exactly
  `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`.
- Read-only protected-vault evidence remains exactly 16,072 files, zero
  directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending/temp files. No vault item was changed.
- Checkpoint 2220 is locally verified. Hosted exact-head CI/package evidence,
  normal PR integration, merged-main evidence, guarded original-tree
  synchronization, and destination verification remain pending. Local
  checkpoint completion is not completion of the antivirus project.

## Implementation-Head Hosted Evidence

- Exact SHA `6f90f9234375ceb22107aba426401e38838ec9b8` passes Avorax CI PR run
  `32712875828`: Rust, Flutter/protocol, security/protection/performance, Unix
  quarantine permissions, and branding all succeed.
- Desktop Packages push run `32712856310` and PR run `32712875850` pass package
  contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS x64/arm64 DMGs, and
  consolidated checksum/SBOM evidence. Both prerelease publication jobs are
  explicitly skipped.
- The downloaded push artifact contains exactly six release files. Its seven
  non-empty `SHA256SUMS.txt` rows all match independent SHA-256 recomputation.
  The checksummed lockfile SBOM is CycloneDX 1.6 with 569 components and metadata
  component `Avorax Anti-Virus`.
- Draft PR `#72` is clean and points at the exact implementation SHA. No package
  was installed, executed, released, or published. Evidence-head checks, normal
  merge, merged-main evidence, guarded original-tree synchronization, and
  destination verification remain pending.
