# Avorax Windows Installers

Build the Windows MSI and EXE installers from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.1
```

The script:

- Builds the Flutter Windows release app unless `-SkipFlutterBuild` is passed.
- Builds `zentor_local_core.exe` with Cargo when Cargo is available.
- Stages the Flutter runtime DLLs and app assets.
- Copies the Avorax Rust local core beside `Avorax.exe`.
- Copies `zentor_guard_service.exe` beside `Avorax.exe`.
- Registers the visible `zentor_guard_service` Windows service for post-launch Guard monitoring.
- Copies Avorax Native Engine signatures, rules, ML model assets, and trust packs beside the app.
- Skips ClamAV compatibility by default. Avorax Native Engine is the primary scanner.
- Copies Visual C++ runtime DLLs from `C:\Windows\System32` when present.
- Includes local privacy/security docs.
- Uses the local WiX .NET tool from `dotnet-tools.json`.
- Produces `dist\Avorax-AntiVirus-<version>-x64.msi`.
- Produces `dist\Avorax-AntiVirus-<version>-x64-setup.exe`.

Use `-RequireLocalCore` to fail the build if `zentor_local_core.exe` cannot be included:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.1 -RequireLocalCore -AllowDevelopmentModel
```

ClamAV compatibility is optional and disabled by default. Use `-IncludeClamAVCompatibility` only when explicitly testing compatibility mode:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.1 -IncludeClamAVCompatibility
```

When compatibility mode is included, the MSI places ClamAV in `C:\Program Files\Avorax\ClamAV` and the Avorax local core discovers `clamscan.exe` there automatically. Avorax does not install ClamAV as a hidden service and does not silently enable persistence.

The EXE installer is a WiX Burn bootstrapper that contains the MSI. It is useful for GitHub Releases and users who expect a single setup executable. It installs the same files and follows the same privacy and visibility rules as the MSI.

The MSI build requires AI model assets. If model metadata is `production_ready=false`, pass `-AllowDevelopmentModel` for a non-production installer:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.1 -RequireLocalCore -AllowDevelopmentModel
```

The Guard Service is not a kernel driver and does not provide true pre-execution blocking by itself. It monitors process starts and can stop/quarantine confirmed or high-confidence threats after launch. True pre-execution blocking still requires the Windows driver validation workflow.
