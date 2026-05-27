# Pasus Windows Installers

Build the Windows MSI and EXE installers from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.1.0
```

The script:

- Builds the Flutter Windows release app unless `-SkipFlutterBuild` is passed.
- Builds `pasus_local_core.exe` with Cargo when Cargo is available.
- Stages the Flutter runtime DLLs and app assets.
- Copies the Pasus Rust local core beside `Pasus.exe`.
- Copies `pasus_guard_service.exe` beside `Pasus.exe`.
- Copies `assets\models\pasus_static_malware_model.onnx` and metadata beside the app.
- Copies `assets\yara\pasus_core_rules.yar` beside the app.
- Bundles the official Windows ClamAV runtime beside the Pasus local core.
- Copies Visual C++ runtime DLLs from `C:\Windows\System32` when present.
- Includes local privacy/security docs.
- Uses the local WiX .NET tool from `dotnet-tools.json`.
- Produces `dist\Pasus-<version>-x64.msi`.
- Produces `dist\Pasus-<version>-x64-setup.exe`.

Use `-RequireLocalCore` to fail the build if `pasus_local_core.exe` cannot be included:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.1.0 -RequireLocalCore
```

ClamAV is bundled by default from the official Cisco-Talos GitHub release and the downloaded ZIP is SHA-256 verified by the build script. Pasus also works without it, but signature scanning reports `Engine Unavailable` until ClamAV is present through the MSI, PATH, or `PASUS_CLAMAV_CLAMSCAN`. Pasus does not fake clean scan results when the engine is unavailable.
Use `-SkipClamAV` only for development builds where ClamAV is supplied separately:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.1.0 -SkipClamAV
```

The MSI places ClamAV in `C:\Program Files\Pasus\ClamAV` and the Pasus local core discovers `clamscan.exe` there automatically. Pasus does not install ClamAV as a hidden service and does not silently enable persistence.

The bundled runtime includes `freshclam.exe`, but signature database updates are still explicit. If no local ClamAV database is available, Pasus must report the scan error honestly instead of pretending files are clean.

The EXE installer is a WiX Burn bootstrapper that contains the MSI. It is useful for GitHub Releases and users who expect a single setup executable. It installs the same files and follows the same privacy and visibility rules as the MSI.

The MSI build requires AI model assets. If model metadata is `production_ready=false`, pass `-AllowDevelopmentModel` for a non-production installer:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.1.0 -RequireLocalCore -AllowDevelopmentModel
```
