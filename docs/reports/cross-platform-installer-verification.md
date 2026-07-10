# Cross-Platform Installer Verification

Date: 2026-07-10

Target version: `0.1.15`

Source commit: `abf256c52050ee714fd49c374671844dea51c64e`

Native workflow: [Desktop Packages run 29086402344](https://github.com/brentishere41848/Avorax/actions/runs/29086402344)

All native package jobs and the checksum-consolidation job passed. The release
job was intentionally skipped because this was a branch push, not an approved
release dispatch. This report distinguishes package proof from installed UI,
service, signing, and production-protection claims.

## Result Classification

### Verified

- Reproducible source checks listed below pass at the source commit.
- Six platform packages were produced by native GitHub-hosted runners.
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
| `Avorax-AntiVirus-0.1.15-x64.msi` | 17,695,083 | `44b5f8e7e9c90e780cbd3b3d560a82c2a3d90777059d5b1fa4c86b209abbe1e2` |
| `Avorax-AntiVirus-0.1.15-x64-setup.exe` | 18,603,355 | `d31cadf242abb286da3563b65aab23439c0d8956beca9f41a8390ef76d046f08` |
| `Avorax-AntiVirus-0.1.15-linux-x64.deb` | 14,295,268 | `26363d286aae89255e636dd7fee722da4c07d331a33ee522b2ca36fbaacaac0f` |
| `Avorax-AntiVirus-0.1.15-linux-x64.tar.gz` | 18,491,611 | `b27b4d094f925aad88875a3420f20277e4b6f64b88915dd17d3b8da58cd1e1a2` |
| `Avorax-AntiVirus-0.1.15-macos-arm64.dmg` | 30,975,709 | `e8fe5d14d27567b12d6caeaef6b03939c50a23bd65a1ef0df03762cc6de04165` |
| `Avorax-AntiVirus-0.1.15-macos-x64.dmg` | 32,960,052 | `ef809fe5464f4a8359f07b500714d86b016f6673daf3046ea5668c0727fc8a80` |

Hashes were independently recomputed after downloading all five workflow
artifacts. Exactly six package files and six checksum entries were present, and
every value matched the consolidated checksum file.

## Native Workflow Results

| Job | Result |
| --- | --- |
| Package contracts | Success |
| Windows x64 MSI/EXE | Success |
| Linux x64 DEB/tar | Success |
| macOS arm64 DMG | Success |
| macOS x64 DMG | Success |
| Consolidate/checksum | Success |
| Publish prerelease | Skipped as expected for branch push |

The downloaded Windows signatures were independently inspected on the local
Windows host and again reported `NotSigned` with no signer certificate.

## Release Gate

The packages are suitable only for an explicitly labeled experimental beta
prerelease. Publication must retain the README disclaimer, the beta notice in
each payload, checksum file, unsigned/not-notarized warnings, and instruction to
keep Microsoft Defender enabled. Production or broad-protection claims remain
blocked by the limitations above.
