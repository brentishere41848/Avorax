# Avorax Windows Installers

Build the Windows MSI and EXE installers from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.9
```

The script:

- Builds the Flutter Windows release app unless `-SkipFlutterBuild` is passed.
- Builds the Avorax Core Service with Cargo when Cargo is available, and fails release packaging if it is still missing.
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
- Copies Visual C++ runtime DLLs from `C:\Windows\System32` when present.
- Includes local privacy/security/driver/native-engine documentation.
- Uses the local WiX .NET tool from `dotnet-tools.json`.
- Produces `dist\Avorax-AntiVirus-<version>-x64.msi`.
- Produces `dist\Avorax-AntiVirus-<version>-x64-setup.exe`.

Release packaging fails if `avorax_core_service.exe`, `avorax_guard_service.exe`, or required engine assets cannot be included:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.9 -RequireLocalCore -AllowDevelopmentModel
```

`-AllowIncompletePayload` exists only for local packaging diagnostics and must not be used for release installers. A normal MSI/EXE build installs the app, local core, Guard Service, assets, engine packs, validation tools, docs, and manifest together.

ClamAV compatibility is optional and disabled by default. Use `-IncludeClamAVCompatibility` only when explicitly testing compatibility mode:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.9 -IncludeClamAVCompatibility
```

When compatibility mode is included, the MSI places ClamAV in `C:\Program Files\Avorax\ClamAV` and the Avorax local core discovers `clamscan.exe` there automatically. Avorax does not install ClamAV as a hidden service and does not silently enable persistence.

The EXE installer is a WiX Burn bootstrapper that contains the MSI. It is useful for GitHub Releases and users who expect a single setup executable. It installs the same files and follows the same privacy and visibility rules as the MSI.

The MSI build requires AI model assets. If model metadata is `production_ready=false`, pass `-AllowDevelopmentModel` for a non-production installer:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.9 -RequireLocalCore -AllowDevelopmentModel
```

After installing a built MSI or EXE, validate the deployed layout and service state:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\avorax-installed-smoke-test.ps1
```

The Guard Service is not a kernel driver and does not provide true pre-execution blocking by itself. It monitors process starts and can stop/quarantine confirmed threats after launch when the user enables that protection mode. High-confidence non-confirmed detections remain review-only. True pre-execution blocking still requires the Windows driver validation workflow.

The MSI packages driver tooling and validation scripts, but it does not silently install unsigned or test-signed drivers and does not silently enable Windows TESTSIGNING. Driver activation must go through the documented driver workflow and self-test.

Set `AVORAX_GUARD_MODE` or `AVORAX_PROTECTION_MODE` to `blockConfirmedThreats`, `monitorOnly`, `disabled`, `balanced`, `lockdown`, or `developerMode` before starting the service to control post-launch behavior. If no mode is configured, the service defaults to blocking confirmed threats only.

The Flutter app also asks local core to write the shared Guard mode file when the protection profile changes. Environment variables take precedence over the file so managed deployments can enforce a mode.
