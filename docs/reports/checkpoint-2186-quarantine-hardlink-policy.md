# Checkpoint 2186 Quarantine Hard-Link Policy

Date: 2026-08-20

## Objective

Checkpoint 2184 documented that moving one detected path could leave another
hard link to the same file accessible. This checkpoint adds a bounded,
fail-visible policy without enumerating an unbounded volume or claiming an
atomic filesystem transaction.

## Change

The shared `avorax_platform_security` crate now reads link count from an already
opened file object:

- Windows calls `GetFileInformationByHandle` and uses `nNumberOfLinks`;
- Unix reads `MetadataExt::nlink` from descriptor metadata;
- unsupported platforms fail visibly rather than assuming one link;
- every count other than exactly one is rejected with the path, label, and
  observed count.

The control runs before vault permission mutation, while validating existing
vault entries, and in both quarantine owners:

1. Local Core and Guard open and validate the source before hashing/mutation.
2. The opened source is checked again immediately before rename.
3. Copy fallback keeps its actual input file open and rechecks it before source
   removal. If the count changed, the copied destination is cleaned and the
   original is preserved with a visible error.
4. Moved/copied payload hardening checks again before chmod/DACL mutation and
   before authenticated record finalization.

Benign hardlink fixtures use only temporary directories. A pre-existing
multi-linked source remains at both names, no quarantine payload is created,
and no authenticated record is written.

## Local Verification

```powershell
cargo fmt --all -- --check
# passed

cargo test --locked -p avorax_platform_security
# Windows host: 9 passed; 0 failed

cargo test --locked -p zentor_local_core hard_link
# 2 passed; 0 failed

cargo test --locked -p zentor_guard_service hard_link
# 2 passed; 0 failed

cargo test --locked -p zentor_local_core -- --test-threads=1
# 519 passed; 0 failed

cargo test --locked -p zentor_guard_service -- --test-threads=1
# 225 passed; 0 failed

cargo test --workspace --locked -- --test-threads=1
# 1,442 passed; 0 failed

C:\Users\Brent\AppData\Local\Python\pythoncore-3.14-64\python.exe -B tools\testing\run-python-source-contracts.py
# 622 passed; 0 failed

cargo clippy --locked -p avorax_platform_security -p zentor_local_core -p zentor_guard_service --all-targets -- -D warnings
# passed

cargo clippy --locked --target x86_64-unknown-linux-gnu -p avorax_platform_security --all-targets -- -D warnings
# passed

cargo check --locked --target x86_64-unknown-linux-gnu -p zentor_guard_service --all-targets
# passed with the existing platform-specific dead-code warnings

$repo = (Resolve-Path '.').Path
$python = 'C:\Users\Brent\AppData\Local\Python\pythoncore-3.14-64\python.exe'
$cargo = (Get-Command cargo).Source
$flutter = (Get-Command flutter).Source
$dart = (Get-Command dart).Source
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot $repo -PythonPath $python -CargoPath $cargo -FlutterPath $flutter -DartPath $dart -ReportPath "$repo\.verification\checkpoint-2186-small-threat-mvp-report.json"
# 219 passed; 0 failed; 0 skipped; 605.1s
# independent -RequireFullSuite report validation passed

git diff --check
# passed
```

## Failed Attempts

The concrete Python installation does not contain `pytest`, so
`python -m pytest -q tests/test_custom_driver_contract.py` failed with
`No module named pytest`. No dependency was installed. The repository's
dependency-free `tools/testing/run-python-source-contracts.py` runner is the
authoritative source-contract command and passes `622/622`.

The new source contract initially failed because its Windows order assertion
sliced the whole platform file and selected the directory SID lookup. After the
slice was narrowed to `harden_windows_quarantine_file`, a second run exposed a
Guard-specific cleanup-label mismatch in the test. Both assertion defects were
fixed; neither was treated as production success, and the complete final run is
`622/622`.

A combined strict Linux Clippy command for the platform crate and Guard failed
on 24 existing Guard diagnostics: Windows-only service/process helpers are dead
code under the Linux target, and one existing parser triggers `manual_ok_err`.
This command is not counted as success. The changed shared platform crate passes
strict Linux Clippy, and Guard passes Linux all-target compilation with its
existing warnings. Native Ubuntu runtime remains the relevant cross-platform
gate.

A standalone protection-gate command failed because its default
`dist/windows-driver-validation/selftest_report.json` did not exist. This was
not counted as success. The central verifier generated its bounded synthetic
non-driver report, reran the same protection gate without a driver-feature
claim, and passed. No driver or service was installed or started.

## Existing Vault Check

A read-only inventory after every local test and verifier run reported the same
real vault baseline as checkpoint 2184:

```text
C:\ProgramData\Avorax\Quarantine
16,072 files; 4,522,733 bytes
5,357 .avoraxq payloads; 5,357 JSON records; 5,357 auth sidecars; 1 key
```

No existing vault artifact was changed or deleted.

## Dependency And Diff Review

`Cargo.toml`, `Cargo.lock`, and all three affected crate manifests are unchanged.
The implementation reuses the already pinned `windows-sys` and `libc` APIs, so
it adds no package, license, build-script, or network-fetch surface. The final
workspace inventory contains exactly `1,442` Rust tests. The intended diff is
limited to the shared platform crate, Local Core, Guard, the bounded Ubuntu job,
one source-contract file, and the checkpoint's status/audit/quarantine reports;
generated `.verification` output remains untracked.

## CI Scope

The existing pinned `ubuntu-24.04` quarantine job still runs the complete shared
platform crate and now adds `hard_link` filters for Local Core and Guard. The job
has seven `cargo test --locked` invocations, fail-fast Bash, serial tests, and a
30-minute timeout. It installs no package or machine-wide component. Exact
implementation head `2613b4131cb31c37e413d7610403fb2d665582e9` passed Avorax
CI run `32324715015`; job `96293537585` passed shared `8/8`, Local Core
`1+1+2`, and Guard `1+1+2`, for `16/16` selected native tests. Desktop Packages
push run `32324694830` and PR run `32324715004` both passed package contracts,
Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMGs, and consolidated
checksums. Branch prerelease publication was intentionally skipped.

## Classification

| Classification | Control | Evidence and boundary |
|---|---|---|
| Verified locally | Windows handle link count and permission postflight | Shared platform `9/9`; a two-link payload is rejected before DACL mutation. |
| Verified locally | Local Core direct and copy policy | Two focused adversarial tests plus complete Local Core `519/519`; source and alternate remain, destination/record stay absent. |
| Verified locally | Guard direct and copy policy | Two focused adversarial tests plus complete Guard `225/225`; source and alternate remain, destination/record stay absent. |
| Verified locally | Full regression and safety gates | Rust workspace `1,442/1,442`; central verifier/report validator `219/219` in `605.1s`; branding, product-copy, no-malware, false-positive, protection, performance, dependency, Flutter, and analyzer gates pass. |
| Verified locally | Wiring and workflow contract | Source contracts `622/622`; affected Windows Clippy and Linux shared-platform Clippy pass. |
| Verified hosted | Native Unix hardlink runtime | Avorax CI `32324715015`, job `96293537585`: shared `8/8`, Local Core `1+1+2`, and Guard `1+1+2`, totaling `16/16` selected native tests on exact implementation head `2613b4131cb31c37e413d7610403fb2d665582e9`. |
| Verified hosted | Cross-platform package regression | Desktop Packages push `32324694830` and PR `32324715004` passed Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMGs, and consolidated checksums without package installation or prerelease publication. |
| Technically limited | Volume-wide aliases and concurrent mutation | Avorax does not enumerate all links on a volume or atomically exclude same-SID/UID, administrator, or root link creation between the final check and mutation. Alternate names remain independent scan targets. |
| Unchanged partial | Installed service/UI flow | LocalSystem ownership, cross-account UI/service mediation, package lifecycle, and elevated-host click-through still require a disposable test host. |

No live malware, standard EICAR string, Defender exclusion, service/driver
operation, package installation, machine-wide component, existing quarantine
mutation, or project-file deletion was used. The fixtures contain only benign
text and temporary hard links. This checkpoint does not claim secure erase,
kernel interception, pre-execution blocking, production detection rates, or
volume-wide neutralization.
