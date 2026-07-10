# Avorax Windows Installers

Build the Windows MSI and EXE installers from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.9 -DotnetPath C:\Path\To\dotnet.exe -CargoPath C:\Path\To\cargo.exe -FlutterPath C:\Path\To\flutter.bat
```

Before attempting a release build, run the non-mutating prerequisite preflight:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\avorax-release-prereq-check.ps1 -DotnetPath C:\Path\To\dotnet.exe -CargoPath C:\Path\To\cargo.exe -FlutterPath C:\Path\To\flutter.bat
```

The preflight does not install tools, download packages, enable Developer Mode, or change machine security settings. It fails visibly when Android Gradle lock evidence, Windows symlink support, Visual Studio C++ build components, Rust release services, Flutter `Avorax.exe`, or the installer stage are missing.

The script:

- Builds the Flutter Windows release app unless `-SkipFlutterBuild` is passed.
- Requires explicit tool paths through `-DotnetPath`, `-CargoPath`, and `-FlutterPath` or `AVORAX_DOTNET`, `CARGO`, and `AVORAX_FLUTTER`; it refuses ambient PATH lookups for release tools.
- Builds the Avorax Core Service with the checked Cargo executable when service binaries are missing, and fails release packaging if they are still missing.
- Stages the Flutter runtime DLLs and app assets.
- Copies `avorax_core_service.exe` and legacy-compatible `zentor_local_core.exe` beside `Avorax.exe`; this is the local Avorax Native Engine command surface used by the Flutter app.
- Copies `avorax_guard_service.exe` and legacy-compatible `zentor_guard_service.exe` beside `Avorax.exe` and fails release packaging if the Guard Service is missing.
- Registers and starts the visible `avorax_core_service` and `avorax_guard_service` Windows services.
- Copies Avorax Native Engine signatures, rules, ML model assets, trust packs, and installed aliases under `C:\Program Files\Avorax\engine`.
- Creates `C:\ProgramData\Avorax\` runtime folders for config, logs, events, quarantine, scans, cache, reports, and migration data.
- Writes `C:\ProgramData\Avorax\reports\install_report.json` with package-time install expectations. Runtime service state still requires the installed smoke test.
- Writes `engine\trust\avorax_release_manifest.json` with SHA-256 hashes for packaged Avorax files.
- Copies safe validation assets, release gates, protection self-tests, performance/false-positive checks, safe simulator tools, and threat-intel import tools.
- Copies Windows minifilter and process-guard driver source, build scripts, signing scripts, install/uninstall scripts, and self-test scripts.
- Writes `install-manifest.json` into the install folder and Flutter release folder so a built MSI/EXE can be audited for included components.
- Skips ClamAV compatibility by default. Avorax Native Engine is the primary scanner.
- Refuses to download the optional ClamAV compatibility runtime unless `-AllowClamAVDownload` is passed; cached packages are still SHA-256 verified before safe extraction.
- Copies Visual C++ runtime DLLs from the checked `SystemRoot`/`WINDIR` `System32` directory when present.
- Includes local privacy/security/driver/native-engine documentation.
- Uses the local WiX .NET tool from `dotnet-tools.json`.
- Produces `dist\Avorax-AntiVirus-<version>-x64.msi`.
- Produces `dist\Avorax-AntiVirus-<version>-x64-setup.exe`.

Release packaging fails if `avorax_core_service.exe`, `avorax_guard_service.exe`, or required engine assets cannot be included:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.9 -RequireLocalCore -AllowDevelopmentModel -DotnetPath C:\Path\To\dotnet.exe -CargoPath C:\Path\To\cargo.exe -FlutterPath C:\Path\To\flutter.bat
```

`-AllowIncompletePayload` exists only for local packaging diagnostics and must not be used for release installers. A normal MSI/EXE build installs the app, local core, Guard Service, assets, engine packs, validation tools, docs, and manifest together.

ClamAV compatibility is optional and disabled by default. Use `-IncludeClamAVCompatibility` only when explicitly testing compatibility mode:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.9 -IncludeClamAVCompatibility -AllowClamAVDownload -DotnetPath C:\Path\To\dotnet.exe -CargoPath C:\Path\To\cargo.exe -FlutterPath C:\Path\To\flutter.bat
```

When compatibility mode is included, the MSI places ClamAV in `C:\Program Files\Avorax\ClamAV` and the Avorax local core discovers `clamscan.exe` there automatically. If the pinned ClamAV zip is not already cached under `installer\windows\cache`, add `-AllowClamAVDownload` to permit the HTTPS download; the script stages the download to a temporary file, verifies the pinned SHA-256, and rejects unsafe zip entry paths before extraction. Avorax does not install ClamAV as a hidden service and does not silently enable persistence.

The EXE installer is a WiX Burn bootstrapper that contains the MSI. It is useful for GitHub Releases and users who expect a single setup executable. It installs the same files and follows the same privacy and visibility rules as the MSI.

The MSI build requires AI model assets. If model metadata is `production_ready=false`, pass `-AllowDevelopmentModel` for a non-production installer:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.9 -RequireLocalCore -AllowDevelopmentModel -DotnetPath C:\Path\To\dotnet.exe -CargoPath C:\Path\To\cargo.exe -FlutterPath C:\Path\To\flutter.bat
```

After installing a built MSI or EXE, validate the deployed layout and service state:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\avorax-installed-smoke-test.ps1
```

The installed smoke test does not accept a textual `"ok":true` substring as
health proof. It launches the canonical installed `zentor_local_core.exe` with
bounded stdin/stdout/stderr, parses exactly one structured health response,
checks the local stdio/no-network boundary, verifies the installed
`avorax_core_service.exe` alias has the same SHA-256, and requires loaded
signatures/rules plus a passing native self-test. Any malformed, ambiguous,
degraded, or stderr-producing result fails visibly.

After those checks pass, the installed smoke runs the packaged
`avorax-installed-core-lifecycle-probe.ps1` against the canonical installed
core. The probe uses isolated harmless exact-hash fixtures and must prove scan,
`.avoraxq` quarantine, list, SHA-256-verified restore, confirmed delete, and
temporary-data cleanup. Its report is written to
`C:\ProgramData\Avorax\reports\installed_core_lifecycle_report.json`. This is a
direct executable/wrapper stdio validation and does not claim that the Windows
service mediated the scan or that a driver blocked execution.

Before making a release decision, validate the generated MSI stage:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\avorax-installer-stage-test.ps1
```

The stage test fails if the app, service executables, installed `engine\` packs, release self-trust manifest, smoke-test tooling, or Avorax-named installer artifacts are missing.

The Guard Service is not a kernel driver and does not provide true pre-execution blocking by itself. It monitors process starts and can stop/quarantine confirmed threats after launch when the user enables that protection mode. High-confidence non-confirmed detections remain review-only. True pre-execution blocking still requires the Windows driver validation workflow.

The MSI packages driver tooling and validation scripts, but it does not silently install unsigned or test-signed drivers and does not silently enable Windows TESTSIGNING. Driver activation must go through the documented driver workflow and self-test.

Set `AVORAX_GUARD_MODE` or `AVORAX_PROTECTION_MODE` to `blockConfirmedThreats`, `monitorOnly`, `disabled`, `balanced`, `lockdown`, or `developerMode` before starting the service to control post-launch behavior. If no mode is configured, the service defaults to blocking confirmed threats only.

The Flutter app also asks local core to write the shared Guard mode file when the protection profile changes. Environment variables take precedence over the file so managed deployments can enforce a mode.
