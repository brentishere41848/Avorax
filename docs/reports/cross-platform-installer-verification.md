# Cross-Platform Installer Verification

Date: 2026-07-10

Target version: `0.1.15`

This report separates source/local verification from native package-runner
evidence. It must be updated with workflow run links, artifact hashes, and exact
native results before a cross-platform beta release is called verified.

## Verified locally

| Check | Command | Result |
| --- | --- | --- |
| Packaging Python tests | `python -m unittest discover -s tests -p test_packaging_tools.py -v` | Passed: 9 tests on Windows; 2 Unix symlink cases skipped by platform |
| Python parse/compile | `python -m py_compile tools/packaging/package_manifest.py tools/packaging/smoke_local_core.py tools/packaging/create_release_checksums.py tests/test_packaging_tools.py` | Passed |
| Shell syntax | `bash -n installer/common/stage-desktop-payload.sh installer/linux/build-linux.sh installer/macos/build-macos.sh` | Passed |
| Windows installer PowerShell parse | PowerShell parser API against `installer/windows/build-msi.ps1` | Passed |
| Existing packaged-core lifecycle | `python tools/packaging/smoke_local_core.py --core <portable>/zentor_local_core.exe --engine-root <portable>` | Passed: health, detect-only, quarantine, list, restore; no EICAR/live malware/network/machine-wide change |
| Dart source analysis | `dart analyze lib test` in `apps/zentor_client` | Passed: no issues |
| Focused update UI/controller tests | `flutter test test/update_ui_test.dart test/update_controller_test.dart --reporter compact` | Passed: 50 tests |
| Full Flutter suite | `flutter test --reporter compact` in `apps/zentor_client` | Passed: 812 tests |
| Python source contracts | `python tools/testing/run-python-source-contracts.py` | Passed: 590 tests |
| UI control inventory | `python tools/testing/validate-client-ui-inventory.py` | Passed: 11 routes, 9 desktop destinations, 4 mobile destinations, 61 controls |
| Product-copy gate | `powershell -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1` | Passed |
| No-malware-binary gate | `powershell -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1 -RepoRoot . -PythonPath <bundled-python>` | Passed |
| Dependency evidence | `powershell -ExecutionPolicy Bypass -File tools/security/avorax-dependency-evidence.ps1 -RepoRoot . -ReportPath .workflow/packaging/dependency-evidence.json` | Passed |
| Rust workspace | `cargo test --workspace --locked --quiet` | Passed: 1,382 tests; 0 failed |
| Rust formatting | `cargo fmt --all -- --check` | Passed |

The Rust run initially exposed two pre-existing process-environment races in
parallel update-service and local-core tests. Their module-local locks were
replaced by crate-wide test locks, missing lock users were covered, and source
contracts now reject recurrence. The affected 201-test and 486-test groups each
passed three consecutive default-parallel runs before the full workspace pass.

## Native package evidence

| Package | Status | Required evidence |
| --- | --- | --- |
| Windows x64 MSI | Pending native runner | Build, staged smoke, administrative extraction, payload inventory, unsigned status, SHA-256 |
| Windows x64 setup EXE | Pending native runner | Build, WiX bundle inspection, unsigned status, SHA-256 |
| Linux x64 DEB | Pending native runner | Build, `ldd`, no setuid/setgid, extract, manifest verify, packaged-core smoke, SHA-256 |
| Linux x64 tar.gz | Pending native runner | Build, manifest verify, packaged-core smoke, SHA-256 |
| macOS Apple Silicon DMG | Pending native runner | Build, ad-hoc `codesign`, mount, manifest verify, mounted-core smoke, not-notarized status, SHA-256 |
| macOS Intel DMG | Pending native runner | Build, ad-hoc `codesign`, mount, manifest verify, mounted-core smoke, not-notarized status, SHA-256 |

## Host blocker

The local Windows host is not a release-capable Windows GUI/WiX host. Flutter
reports missing Visual Studio Desktop C++/CMake components, Windows symlink
support is unavailable to the clean checkout, and `dotnet --info` reports no
installed SDK. No machine-wide prerequisite was installed or setting changed.
Windows artifact evidence must come from the repository's native CI runner.

## Technical limits

- Package extraction/mount verification is not normal installed UI
  click-through E2E.
- Windows service registration/start/stop remains unverified until an explicitly
  approved isolated install test is run.
- Public beta artifacts are unsigned or ad-hoc signed, not production signed.
- No package proves signed-driver, kernel, Endpoint Security, fanotify
  permission, or pre-execution blocking.
- The bundled ML metadata remains `production_ready=false`.
- No live malware is downloaded, retained, unpacked, or executed.
