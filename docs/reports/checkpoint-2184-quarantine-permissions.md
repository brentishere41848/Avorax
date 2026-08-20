# Checkpoint 2184 Quarantine Permission Boundary

Date: 2026-08-20

## Findings

Local Core and Guard previously implemented quarantine permissions separately.
On Windows those paths depended on `icacls.exe`, and Guard derived an account
name from mutable environment variables. On Unix, production code did not
enforce and verify one exact owner/mode contract. Permission changes were not
bound to the same opened object used for data validation.

An absolute quarantine override could also identify an arbitrary existing
directory. Applying private vault permissions to such a directory could change
unrelated user content. The initial bounded-content proposal allowed only 4,096
entries; inspection of the existing vault showed that this limit was too low,
so the accepted bound is 65,536 recognized vault artifacts.

The audit also found that Local Core tests without an explicit override could
use the real ProgramData vault. The existing
`C:\ProgramData\Avorax\Quarantine` inventory contained 16,072 files and
4,522,733 bytes before the final verification pass: 5,357 opaque payloads,
5,357 metadata records, 5,357 authentication sidecars, and one key file. These
names are vault-shaped, but their individual provenance was not audited. No
existing vault file was deleted. After this baseline was recorded, focused,
complete, workspace, and central test runs left the file count and total bytes
unchanged.

## Repairs

- Added the internal `avorax_platform_security` workspace crate so Local Core
  and Guard share one fail-closed permission implementation.
- Windows obtains the current identity from the process token. It opens targets
  without following reparse points, validates object kind, and binds data and
  ACL handles to the same volume serial and file ID.
- Windows directories receive process-token SID ownership and one exact
  protected private DACL. Quarantine payloads additionally deny only
  `FILE_EXECUTE` to Everyone. Owner and DACL are read back and compared.
- Unix uses opened descriptors, the effective UID/GID, device/inode checks, and
  exact mode verification: `0700` for vault directories and `0600` for payload,
  metadata, authentication sidecar, and key files.
- Local Core and Guard reject symlink/reparse ancestors before and after vault
  creation. Wrong-kind or redirected objects fail visibly.
- Explicit overrides must end in a dedicated case-insensitive `Quarantine`
  leaf. Windows Guard overrides must also resolve to a local drive path; UNC
  vaults are rejected. Before permissions can change, an existing root is
  enumerated with a 65,536-entry bound and may contain only recognized non-link
  regular vault artifacts. Unknown content fails before ACL or mode mutation.
- The arbitrary-base Local Core constructor is test-only, so production callers
  cannot bypass environment-root and dedicated-leaf validation.
- Metadata, authentication-sidecar, and key permissions are repaired and
  verified before bounded reads. An authenticated legacy payload is repaired
  only after record authentication, schema validation, and vault-path checks.
- If permission or metadata finalization fails after the payload was moved, the
  sole payload is retained under its opaque name and the error reports its path;
  only incomplete metadata/auth files are cleaned up.
- Local Core tests now receive a thread-local temporary `Quarantine` directory.
  The deterministic failure test uses a scoped test-only override.
- Added platform, Local Core, Guard, source-contract, root-confusion, path
  identity, finalization, legacy-record, and test-isolation regressions.

## Verification

```powershell
cargo test --manifest-path core\avorax_platform_security\Cargo.toml -- --test-threads=1
# 6 passed; 0 failed

cargo test --manifest-path core\zentor_local_core\Cargo.toml quarantine -- --test-threads=1
# 112 passed; 0 failed

cargo test --manifest-path core\zentor_guard_service\Cargo.toml quarantine -- --test-threads=1
# 47 passed; 0 failed

cargo test --manifest-path core\zentor_local_core\Cargo.toml -- --test-threads=1
# 517 passed; 0 failed

cargo test --manifest-path core\zentor_guard_service\Cargo.toml -- --test-threads=1
# 223 passed; 0 failed

cargo test --workspace --all-targets --quiet -- --test-threads=1
# 1,435 passed; 0 failed

python -B tools\testing\run-python-source-contracts.py
# 620 passed; 0 failed

powershell -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot . -ReportPath .verification\2184-small-threat-mvp-report.json
# 219 passed; 0 failed; 0 skipped; 618.0s

powershell -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -RepoRoot . -ReportPath .verification\2184-small-threat-mvp-report.json -RequireFullSuite
# passed independently; status=passed; steps=219
```

Strict Clippy passes for all affected Windows crates. Strict Clippy also passes
for the shared crate targeting `x86_64-unknown-linux-gnu`, and Guard passes an
all-target Linux check with only existing platform-specific dead-code warnings.
`cargo fmt --check`, `cargo metadata --locked --no-deps`, dependency evidence,
PowerShell parser checks, branding, product-copy, no-malware-binary,
false-positive, protection, performance, and `git diff --check` gates pass.

The deterministic CycloneDX 1.6 lockfile inventory contains 570 components.
Three independent outputs for version `0.1.15-beta.3` have SHA-256
`D04315EEB9326F73D0C327D18B5D143DBDFAFBFB8110A215197C7B3589DB0BBE`.
Direct dependencies added by this checkpoint are existing licensed workspace
dependencies (`anyhow`, `libc`, `windows-sys`, and test-only `tempfile`); their
license evidence is recorded in `docs/dependency-license-inventory.md`.

The first central-verifier attempt failed honestly at the branding gate because
a new compatibility test contained a literal retired-brand token. The test was
changed to construct that legacy extension without leaving active retired copy
in source. The focused regression, all 620 source contracts, and the standalone
branding gate then passed before the complete 219-step verifier was restarted
from step one and passed.

The final manual diff review then found two additional policy gaps: the
arbitrary-base constructor was still compiled in production despite having only
test callers, and Guard did not reject Windows UNC overrides. Both were closed.
The first post-review source-contract run failed because its assertion expected
the test-only constructor text to be absent from the source file; it now
requires the `#[cfg(test)]` gate and absence of a public constructor instead.
All 620 source contracts, complete Rust suites, and the final 219-step verifier
then passed again from clean command starts.

After focused, complete, workspace, and central verification, the pre-existing
ProgramData vault remained exactly 16,072 files and 4,522,733 bytes. Local test
fixtures were confined to temporary directories. The structured verifier report
is `.verification/2184-small-threat-mvp-report.json` and is intentionally not
committed.

## Hosted Verification

Implementation head `fc287d91c792be74e45ab3204831b00d6d9cd1bf` in PR `#36`
passed Avorax CI run `32315144870`: branding/copy, Flutter/protocol, Rust Local
Core/Guard, and security/protection/performance jobs all completed successfully.
Desktop Packages push run `32315126623` and pull-request run `32315144889` both
passed package contracts, Linux x64 DEB/tar, Windows x64 MSI/EXE, macOS
arm64/x64 DMG, and consolidated checksum jobs. Prerelease publication was
intentionally skipped by branch policy because this checkpoint is not a release
tag.

The Ubuntu 24.04 jobs natively compiled Local Core and Guard and verified the
Linux packages. The current package workflow does not execute Unix-specific
permission unit tests, so native Unix runtime permission behavior remains
partial rather than being inferred from a successful package build.

## Classification

| Classification | Control or engine | Evidence and boundary |
|---|---|---|
| Verified locally | Shared Windows permission engine | Process-token SID, exact owner/protected DACL readback, payload execute deny, reparse/wrong-kind rejection, and same-file handle identity have runtime regressions. |
| Partial | Shared Unix permission engine | Effective UID/GID, descriptor identity, exact `0700`/`0600`, ownership transfer, and fail-closed mismatch behavior have source regressions, cross-target checks, and a native Ubuntu release build. The hosted package workflow does not execute the Unix-only runtime tests. |
| Verified locally | Local Core quarantine lifecycle | Focused `112/112`, complete `517/517`, safe quarantine/restore/delete smokes, legacy migration, finalization retention, and temporary test-vault isolation pass. |
| Verified locally | Guard quarantine lifecycle | Focused `47/47`, complete `223/223`, shared metadata/permission interoperability, process evidence, and root preflight pass. |
| Verified locally | Repository regression boundary | Rust workspace `1,435/1,435`, source contracts `620/620`, central verifier `219/219`, independent report validation, lint, format, dependency, branding, safety, and performance gates pass. |
| Partial | Installed Windows product | Installed LocalSystem owner/DACL/DPAPI behavior, unprivileged UI-to-service mediation, repair/upgrade, package install/uninstall, and click-through UI E2E require a disposable elevated Windows host. |
| Verified hosted | Cross-platform package build boundary | Runs `32315126623` and `32315144889` independently passed Linux x64 DEB/tar, Windows x64 MSI/EXE, macOS arm64/x64 DMG, and consolidated checksums for implementation head `fc287d91c792be74e45ab3204831b00d6d9cd1bf`. This is package build/inspection evidence, not installation or runtime protection proof. |
| Disabled or blocked | Full Local Core Linux runtime cross-check | This Windows host reaches `tract-linalg` but lacks `x86_64-linux-gnu-gcc`; no machine-wide cross compiler was installed. Native Ubuntu package compilation passes, but the current workflow does not run the full Local Core or Unix permission test suites. |
| Partial | Retained payload recovery | A finalization failure preserves the sole opaque payload and reports its path, but a dedicated authenticated recovery workflow is not yet implemented. |
| Partial | Pre-existing ProgramData vault provenance | The 5,357 record-shaped sets were preserved exactly as requested. Count and total-byte baselines stayed stable after test isolation, but each historical record has not been provenance-reviewed; cleanup requires an explicit authenticated operator action. |
| Technically limited | Same-principal and privileged attackers | Portable user-mode permissions do not isolate data from another process running as the same SID/UID. Administrators, LocalSystem, and root remain trusted. |
| Technically limited | Filesystem race and hard links | Ancestor checks are path-based rather than a fully handle-relative object-tree transaction. Existing alternate hard links are not volume-wide neutralized. |
| Technically limited | Protection claims | Permissions do not encrypt payloads, securely erase SSD data, or prove kernel/pre-execution blocking. No such claim is made. |

No live malware, standard EICAR string, Defender exclusion, service/driver
operation, administrator install, network definition download, machine-wide
component, project-file deletion, or existing quarantine deletion was used.
