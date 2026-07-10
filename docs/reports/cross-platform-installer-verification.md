# Cross-Platform Installer Verification

Date: 2026-07-10

Target version: `0.1.15`

Release commit: `7b1f8130a652e27d8750954e88b63f3b7f32de2a`

Release workflow: [Desktop Packages run 29088539809](https://github.com/brentishere41848/Avorax/actions/runs/29088539809)

Release: [Avorax Desktop Beta v0.1.15-beta.1](https://github.com/brentishere41848/Avorax/releases/tag/v0.1.15-beta.1)

All native package jobs, checksum consolidation, publication, and the separate
`main` CI run passed. The lightweight release tag points directly to the release
commit above. This report distinguishes package proof from installed UI,
service, signing, and production-protection claims.

## Result Classification

### Verified

- Reproducible source checks listed below pass at the source commit.
- Six platform packages were produced and published by native GitHub-hosted
  runners from the tagged release commit.
- Every package hash matches the consolidated `SHA256SUMS.txt` artifact.
- Packaged local-core health reports `engine_status=available`, native self-test
  true, 13 active signatures, 9 local rules, and ML production readiness false.
- Harmless exact-hash fixtures prove detect-only, confirmed-only quarantine,
  quarantine listing, integrity-preserving restore, and source restoration.
- Windows MSI administrative extraction, Linux DEB/tar extraction, and macOS
  DMG mount verification each ran without installing a machine-wide service.
- No smoke used live malware, wrote the standard EICAR string, required network
  access, changed machine-wide state, or weakened Microsoft Defender.

### Partial

- Package extraction or mounting verifies payloads and local-core behavior, but
  is not normal installed GUI click-through E2E.
- Best-effort user-mode file/process observation is covered by source and
  bounded fixture tests, not persistent installed-host protection evidence.
- Dependency evidence is source-level and partial; a complete production SBOM
  and independent license review remain required.

### Disabled Or Blocked

- Windows Authenticode production signing is blocked on an approved certificate
  and protected signing workflow; both Windows artifacts are `NotSigned`.
- macOS distribution signing and notarization are blocked on an Apple Developer
  identity and notarization credentials; Gatekeeper rejects these ad-hoc builds.
- The bundled ML model remains disabled for production verdict authority because
  its metadata reports `production_ready=false`.
- Driver-backed or pre-execution blocking remains unavailable without a reviewed,
  signed, installed driver and isolated elevated verification.

### Technically Limited

- This beta is not a replacement for Microsoft Defender or another supported
  antivirus. It is intended for small, known test signals and local scanning.
- No evidence in this report proves kernel blocking, macOS Endpoint Security,
  Linux fanotify permission blocking, tamper resistance, or enterprise policy.
- Windows service registration/start/stop and restore conflict UI flows were not
  exercised by installing these unsigned beta packages.
- Secure erasure is not claimed, including on SSDs.

## Local And Source Verification

| Check | Command | Result |
| --- | --- | --- |
| Packaging tests | `python -m unittest discover -s tests -p test_packaging_tools.py -v` | Passed: 12 tests on Windows; 2 Unix-only symlink cases skipped as expected |
| Packaging Python compile | `python -m py_compile tools/packaging/package_manifest.py tools/packaging/smoke_local_core.py tools/packaging/create_release_checksums.py tests/test_packaging_tools.py` | Passed |
| Shell syntax | `bash -n installer/common/stage-desktop-payload.sh installer/linux/build-linux.sh installer/macos/build-macos.sh` | Passed |
| Windows installer parse | PowerShell parser API against `installer/windows/build-msi.ps1` | Passed |
| Portable core lifecycle | `python tools/packaging/smoke_local_core.py --core <portable>/zentor_local_core.exe --engine-root <portable>` | Passed: health, detect-only, quarantine, list, restore |
| Dart source analysis | `dart analyze lib test` in `apps/zentor_client` | Passed: no issues |
| Focused update UI tests | `flutter test test/update_ui_test.dart test/update_controller_test.dart --reporter compact` | Passed: 50 tests |
| Full Flutter suite | `flutter test --reporter compact` in `apps/zentor_client` | Passed: 812 tests |
| Python source contracts | `python tools/testing/run-python-source-contracts.py` | Passed: 590 tests |
| UI inventory | `python tools/testing/validate-client-ui-inventory.py` | Passed: 11 routes, 9 desktop destinations, 4 mobile destinations, 61 controls |
| Product-copy gate | `powershell -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1` | Passed |
| No-malware-binary gate | `powershell -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1 -RepoRoot . -PythonPath <python>` | Passed |
| Dependency evidence | `powershell -ExecutionPolicy Bypass -File tools/security/avorax-dependency-evidence.ps1 -RepoRoot . -ReportPath .workflow/packaging/dependency-evidence.json` | Passed; source-level license inventory remains partial |
| Rust workspace | `cargo test --workspace --locked --quiet` | Passed: 1,382 tests, 0 failed |
| Rust formatting | `cargo fmt --all -- --check` | Passed |
| Guard cross-target compile | `cargo check --manifest-path core/zentor_guard_service/Cargo.toml --target <target> --locked` | Passed for Linux x64, macOS x64, and macOS arm64 |

The Rust run initially exposed two process-environment races in parallel tests.
They now share crate-wide locks, focused suites passed repeatedly in parallel,
and the complete workspace passed. A full Linux local-core cross-compile was not
used as evidence on Windows because the host lacks `x86_64-linux-gnu-gcc`; the
native Linux package job provides the executable build/runtime evidence.

## Native Package Matrix

| Package | Status | Native evidence |
| --- | --- | --- |
| Windows x64 MSI | Verified package | Built; staged core smoke passed; `msiexec /a` administrative extraction passed; extracted core smoke passed; manifest/hash passed; Authenticode `NotSigned` recorded |
| Windows x64 setup EXE | Verified package | WiX Burn bundle built; payload/hash passed; Authenticode `NotSigned` recorded; no install or service start performed |
| Linux x64 DEB | Verified package | Built on Linux; `ldd` recorded; no setuid/setgid payload; extracted manifest and packaged-core lifecycle smoke passed |
| Linux x64 tar.gz | Verified package | Built on Linux; separate extraction, manifest verification, and packaged-core lifecycle smoke passed |
| macOS Apple Silicon DMG | Verified package | Built on macOS; arm64 core verified; ad-hoc code signature and DMG integrity verified; mounted manifest and core lifecycle smoke passed; Gatekeeper rejection recorded |
| macOS Intel DMG | Verified package | Built on macOS; x86_64 core verified; ad-hoc code signature and DMG integrity verified; mounted manifest and core lifecycle smoke passed; Gatekeeper rejection recorded |

## Artifact Hashes

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `Avorax-AntiVirus-0.1.15-x64.msi` | 17,699,179 | `2133a13dc1e3b11d4e4c806dda658d9235b3a0a7b013da6c169ee371baf6b6a2` |
| `Avorax-AntiVirus-0.1.15-x64-setup.exe` | 18,606,887 | `2ad574ea94801945a865b9624680c873d5fbb1522f8155645a1a83cf99e96396` |
| `Avorax-AntiVirus-0.1.15-linux-x64.deb` | 14,295,710 | `57a6c4ad6af9873001a72bcf2020bfec234c2e795eb338692f4446ae8f64a306` |
| `Avorax-AntiVirus-0.1.15-linux-x64.tar.gz` | 18,491,525 | `399c4952f0e3939fa79144866e0dfcb93ccc93489925a3d9e614fed8f6ba3054` |
| `Avorax-AntiVirus-0.1.15-macos-arm64.dmg` | 31,594,161 | `e522edfa1402b3e07e42a555f739ec5c9c678427d5554ab79942a752b3e7838a` |
| `Avorax-AntiVirus-0.1.15-macos-x64.dmg` | 32,960,048 | `ba89b69c3315fd1230322cfb64c81ac158c35e057988633836b7d43a92b05a56` |

Hashes were independently recomputed after downloading all seven public release
assets. Exactly six package files and six checksum entries were present. Every
value matched both the published checksum file and GitHub's asset digest.

## Native Workflow Results

| Job | Result |
| --- | --- |
| Package contracts | Success |
| Windows x64 MSI/EXE | Success |
| Linux x64 DEB/tar | Success |
| macOS arm64 DMG | Success |
| macOS x64 DMG | Success |
| Consolidate/checksum | Success |
| Publish prerelease | Success: tag and seven public release assets created |

The downloaded Windows signatures were independently inspected on the local
Windows host and again reported `NotSigned` with no signer certificate.

The separate [main CI run 29088524971](https://github.com/brentishere41848/Avorax/actions/runs/29088524971)
also passed at the release commit. The automatic duplicate package run was
cancelled by the workflow's per-ref concurrency group when the explicit
publication dispatch started; the successful dispatch is the authoritative
release run.

## Release Gate

The packages were published only as an explicitly labeled experimental beta
prerelease. The release retains the README disclaimer, beta notice in each
payload, checksum file, unsigned/not-notarized warnings, and instruction to keep
Microsoft Defender enabled. Production or broad-protection claims remain blocked
by the limitations above.
