# Avorax Installer Audit

## Installer Technology

Avorax Windows installers are built by `installer/windows/build-msi.ps1`.

- MSI technology: WiX Toolset v4 via the repo-local .NET tool manifest.
- EXE setup technology: WiX Burn bootstrapper wrapping the MSI.
- CI entry point: `.github/workflows/release-windows.yml`.
- Main output artifacts:
  - `dist/Avorax-AntiVirus-<version>-x64.msi`
  - `dist/Avorax-AntiVirus-<version>-x64-setup.exe`

## Inputs

- Flutter app build output: `apps/zentor_client/build/windows/x64/runner/Release/Avorax.exe`
- Local core helper: `target/release/zentor_local_core.exe`
- Guard service helper: `target/release/zentor_guard_service.exe`
- Native engine assets: `assets/zentor_native/`
- AI compatibility model assets: `assets/models/`
- Trust and safe test assets: `assets/trust/`, `assets/test/`, `assets/threats/`
- Driver validation tools: `core/zentor_windows_minifilter/`, `core/zentor_windows_process_guard/`
- Validation tools: `tools/branding/`, `tools/security/`, `tools/perf/`, `tools/windows/`, `tools/zne/`
- Safe simulator and threat-intel tools: `tools/simulators/`, `tools/zentor_intel/`
- Documentation: `docs/` and `README.md`

## Current Staging Behavior Before This Fix

The installer staged the Flutter release folder as the install root and copied native assets into:

- `assets/zentor_native/`
- `assets/models/`
- `assets/test/`
- `assets/trust/`
- `assets/threats/`

It copied helper binaries as:

- `zentor_local_core.exe`
- `zentor_guard_service.exe`

The Guard Service was registered as `zentor_guard_service`.

## Current Failure Reason For Engine Unavailable

Installed builds could show:

- `Avorax local core is not available.`
- `Avorax Native Engine unavailable.`
- `Native engine assets are missing or failed to load.`

The likely failure points were:

- The requested product layout uses Avorax runtime names (`avorax_core_service.exe`, `avorax_guard_service.exe`) while the app and MSI primarily used legacy helper names.
- The native engine discovery path relied on repo-style `assets/zentor_native` locations and current-directory walking before installed product layout was defined.
- The MSI did not stage the requested clean installed engine layout under `C:\Program Files\Avorax\engine`.
- The local core binary was packaged as a stdio helper but not registered as `Avorax Core Service`, so the installed product could not honestly report a Core Service as installed/running.
- ProgramData directories and install diagnostics were not first-class MSI outputs.

## Service Install Behavior Before This Fix

- Guard Service: installed and started by MSI as `zentor_guard_service`.
- Core Service: not registered as a Windows service.
- Driver tools: copied, but drivers were not silently installed.

## Engine Asset Install Behavior Before This Fix

Native engine assets were copied under `assets/zentor_native`, matching development layout. The requested installed layout under `engine\signatures`, `engine\rules`, `engine\ml`, and `engine\trust` was not produced.

## App Launch Behavior

The EXE bootstrapper used WiX Burn's standard bootstrapper. It launched the MSI chain and published release artifacts, but the installer UX was still mostly stock WiX behavior and did not provide a product-specific final diagnostics page.

## Logs And Reports

Before this fix, there was no required installed `C:\ProgramData\Avorax\reports\install_report.json` and no installed smoke-test script dedicated to validating the installed Avorax layout.

## Target Fix

The fixed installer must:

- Stage `Avorax.exe`, `avorax_core_service.exe`, and `avorax_guard_service.exe`.
- Preserve legacy helper aliases only as compatibility files.
- Stage the clean engine layout under `engine\`.
- Register `avorax_core_service` and `avorax_guard_service`.
- Create required `C:\ProgramData\Avorax` directories.
- Write an install manifest and release hash manifest.
- Include a smoke-test script that can validate installed files, engine assets, services, and install report.
- Keep driver installation explicit and never silently enable Windows TESTSIGNING.
