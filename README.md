# Avorax

Avorax is a privacy-first desktop anti-malware and security client. It is a real Flutter application for Android, iOS, Windows, macOS, and Linux, with a Rust local core for desktop malware scanning and quarantine.

Avorax v1 runs Quick Scan, Full Scan, and Custom Scan flows fully offline. Scanning, quarantine, allowlist, logs, diagnostic support bundles, and scan results do not require Avorax Cloud, an account, an API, a login, or internet. Runtime data comes only from local state, local configuration, real API responses when optional cloud features are enabled, selected path hashing, local core results, and real errors.

## Engineering docs

- `ARCHITECTURE.md` explains the client/core/engine/service/update architecture and trust boundaries.
- `SECURITY_MODEL.md` documents implemented protections, explicit non-goals, safe scan/quarantine/update rules, and known limitations.
- `TESTING.md` lists the current Flutter, Rust, Dart, build, and release-gate commands.
- `TODO.md` tracks the prioritized P0-P4 hardening backlog.
- `RUN_LOG.md` records hardening-session assumptions, completed changes, verification, and blockers.
- `CHANGELOG.md` records implemented product changes without unsupported security claims.
- `docs/portable-beta.md` documents the interim portable Windows scanner, commands, verification, and explicit protection limits.

## Portable Windows Scanner Beta

> **Beta safety disclaimer:** Avorax Portable Scanner Beta is experimental and
> must not be used as the only antivirus on a device. It can scan common local
> threats covered by its current signatures, rules, static analysis, and
> conservative heuristics, but it may miss advanced, novel, targeted,
> polymorphic, fileless, kernel-level, or large-scale malware and ransomware.
> Keep Microsoft Defender or another supported antivirus enabled. No antivirus
> can guarantee detection of every threat.

The currently verified small-threat artifact is
`dist\Avorax-Portable-Beta-0.1.0-beta.1.zip` (SHA-256
`a80155373a869576dad6d015c21221a18815bf3318a253a11c19477af128240b`).
Extract it to a local folder, run `Avorax-Status.cmd`, and then run
`Avorax-Quick-Scan.cmd`. The package contains the canonical local core and
local engine assets; it needs no account or network service.

This unsigned portable beta provides manual scans and a finite explicit-folder
user-mode watch only. It does not install a service or driver, start with
Windows, replace Microsoft Defender, provide persistent background protection,
or block files before execution. Do not disable Defender. See
`docs/portable-beta.md` for the PowerShell actions and verified limits.

## Repository Layout

```text
apps/
  zentor_client/          Flutter 3 Material 3 client application
packages/
  zentor_protocol/        Shared Dart protocol and state models
core/
  zentor_local_core/      Rust stdin/stdout local security core
services/
  api/                   Rust Axum Avorax API
infra/
  docker-compose.yml     Local Postgres, Redis, and API
  migrations/            PostgreSQL schema
docs/
  client-ui.md
  privacy.md
  integration.md
  malware-protection.md
  quarantine.md
  api-config.md
```

## Get The Code

```powershell
git clone https://github.com/brentishere41848/Avorax.git Avorax
cd Avorax
```

The active GitHub repository is `brentishere41848/Avorax`, and the app update checker uses that repository's GitHub Releases by default.

## Run The Flutter App

```powershell
cd apps/zentor_client
flutter pub get
flutter run -d windows
flutter run -d macos
flutter run -d linux
flutter run -d android
flutter run -d ios
```

Avorax opens to the native Flutter Home screen. It does not open a browser, WebView, iframe, localhost page, Electron app, Tauri app, React app, Next.js app, or Vite app.

## Run The Backend API

The easiest local backend path is Docker Compose:

```powershell
cd C:\Users\Brent\CodexProjects\Avorax
docker compose -f infra/docker-compose.yml up --build
```

The API listens on:

```text
http://127.0.0.1:8000
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/v1/health
```

The local compose stack seeds a development project/client key that matches the Flutter defaults:

```text
AVORAX_PROJECT_ID=avorax-default
AVORAX_PUBLIC_CLIENT_KEY=avorax-public-client
```

Run the Flutter app against the local API:

```powershell
cd apps/zentor_client
flutter run -d windows `
  --dart-define=AVORAX_API_BASE_URL=http://127.0.0.1:8000 `
  --dart-define=AVORAX_PROJECT_ID=avorax-default `
  --dart-define=AVORAX_PUBLIC_CLIENT_KEY=avorax-public-client
```

To run only Postgres and Redis in Docker, then the API with Cargo:

```powershell
cd C:\Users\Brent\CodexProjects\Avorax
docker compose -f infra/docker-compose.yml up postgres redis

cd services/api
$env:DATABASE_URL="postgres://zentor:zentor@localhost:15432/zentor"
$env:REDIS_URL="redis://localhost:16379"
$env:AVORAX_ENABLE_DEV_SEED="true"
$env:AVORAX_DEV_PROJECT_ID="avorax-default"
$env:AVORAX_DEV_PUBLIC_CLIENT_KEY="avorax-public-client"
cargo run
```

When running with Cargo directly, the API listens on `http://127.0.0.1:8000` unless you set `AVORAX_API_BIND_ADDR`.

## Avorax Cloud Configuration

The app uses build-time Avorax Cloud settings by default. Users are not asked to paste API settings during first launch.

```powershell
flutter run -d windows `
  --dart-define=AVORAX_API_BASE_URL=https://YOUR_API_HERE `
  --dart-define=AVORAX_PROJECT_ID=YOUR_PROJECT_ID `
  --dart-define=AVORAX_PUBLIC_CLIENT_KEY=YOUR_PUBLIC_CLIENT_KEY
```

Cloud is optional. The app defaults to local protection and does not call Avorax Cloud before allowing scans. Use `Settings > Cloud` or developer options to test a cloud endpoint when remote reporting, updates, or future account/license features are needed.

Developer endpoint overrides are hidden under `Settings > Advanced > Developer options`.

## App Updates

Avorax checks the configured GitHub release feed from `brentishere41848/Avorax` for newer tagged builds and shows visible update state in Home, Settings, and Updates. It does not silently install updates. Normal in-app updates use signed `.aup` packages: the user chooses `Download, verify, install`, Avorax downloads only the referenced `.aup`, verifies the feed SHA-256, asks Avorax Update Service to verify the signed manifest/package metadata, then applies the staged update and reports `Ready to restart` when the service finishes.

MSI/EXE installers remain first-install, repair, recovery, offline, and manual-install paths. They are not the normal in-app update target, and Avorax must not execute downloaded EXE installers for normal updates.

Release builds should be tagged with `vMAJOR.MINOR.PATCH`. Release automation must publish a versioned `update-feed.json` and signed `.aup` package for normal in-app updates; MSI/EXE artifacts remain installer and recovery assets.

Normal `.aup` engine payloads update only runtime packs under `engine\signatures`, `engine\rules`, `engine\ml`, and `engine\trust`; broader engine layout changes require MSI/EXE packaging or a separate explicit workflow.

Override the update repository at build time when needed:

```powershell
flutter build windows --release `
  --dart-define=AVORAX_UPDATES_REPO_OWNER=YOUR_GITHUB_USER `
  --dart-define=AVORAX_UPDATES_REPO_NAME=YOUR_REPO
```

## Desktop Local Core

```powershell
cd core/zentor_local_core
cargo test
cargo build --release
```

The Flutter client talks to the local core over stdin/stdout JSON commands. The core is not exposed to the network. Set `ZENTOR_LOCAL_CORE` to the built executable path when running the Flutter app if the binary is not beside the app process.

## Malware Scanning

Desktop scanning uses Avorax Native Engine (ANE) as the primary engine:

- Native signatures in `assets/zentor_native/signatures/zentor_core.zsig`.
- Native deterministic rules in `assets/zentor_native/rules/zentor_rules.zrule`.
- Static analyzers for file type, strings, entropy, PE metadata, scripts, and ZIP archives.
- Conservative heuristic scoring and false-positive controls.
- Pure Rust native ML runtime using `assets/zentor_native/ml/zentor_native_model.zmodel`.
- No cloud, ClamAV, or YARA dependency for Quick Scan, Full Scan, Custom Scan, EICAR detection, or quarantine.

Native signature packs are compiled with:

```powershell
cargo run --manifest-path core\zentor_native_engine\Cargo.toml --bin zentor-signature-compiler -- `
  --input assets\zentor_native\signatures\zentor_core.zsig `
  --output assets\zentor_native\signatures\zentor_core.zsig `
  --metadata assets\zentor_native\signatures\zentor_core.metadata.json `
  --version 0.1.1
```

The compiler validates metadata, rejects unsafe broad signatures, emits pack metadata, and records a canonical pack hash that ANE verifies on load.

Weak signals do not become scary detections by themselves: a normal `.exe` in Downloads, an unknown CLI binary, a VPN installer, or an unsigned developer tool is not shown as malware unless stronger independent signals combine.

Native ML support is offline-first and honest. The included `.zmodel` is a development model marked `production_ready=false`; it proves deterministic local inference but cannot auto-quarantine by itself or claim production AI protection. The `ml_native/` folder contains the developer training/export pipeline and schemas. User labels are saved locally for export; the production app does not retrain itself silently.

Android and iOS show an honest unavailable state for full malware quarantine because mobile OS sandboxing prevents full-device scanning.

Scan types:

- Quick Scan is a targeted fast scan. It checks high-risk locations such as Downloads, Desktop, temp folders, and startup/autostart locations, but only walks a shallow depth and scans risky file types such as executables, scripts, installers, Windows App Installer/AppInstaller manifests, archives, shortcuts, macro-enabled documents, PowerShell module/data files, registry/URL/SCF/CHM carriers, Office add-ins/query files, and OneNote packages.
- Full Scan checks accessible local drives or home filesystem areas, respects OS permissions, skips denied paths, and reports skipped counts.
- Custom Scan checks only the file or folder selected by the user.

Scan modes:

- Detect only: Avorax lists suspicious or infected files and does not quarantine or delete anything.
- Auto-quarantine confirmed threats: Avorax quarantines confirmed signature detections when not allowlisted. Heuristic findings are shown for review.
- Review non-confirmed detections: compatibility mode name retained for older clients, but automatic quarantine is still limited to confirmed threats. Probable, suspicious, and heuristic findings remain review-only unless the user chooses an action.

Scan results are grouped into confirmed threats, probable malware, suspicious items, and low-priority observations. Low-priority observations are hidden by default.

### Safe Validation Without Defender EICAR Alerts

Microsoft Defender may block the standard EICAR test string before Avorax can scan it. Do not disable Defender just to test Avorax. For a no-EICAR local proof, build the release local core and run the harmless exact-hash validation smoke:

```powershell
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\testing\run-no-eicar-local-core-harmless-threat-smoke.ps1 `
  -LocalCorePath target\release\zentor_local_core.exe
```

The smoke creates only temporary harmless bytes, a temporary exact-hash rule, and isolated data/quarantine roots. It verifies detect-only reporting, confirmed-only quarantine, listing, and restore without writing the standard EICAR string, weakening Defender, using live malware, or changing machine-wide settings.

Quick Scan also reviews `.appinstaller` manifests that point to remote Windows app packages (`.appx`, `.msix`, `.appxbundle`, or `.msixbundle`). This is static manifest review only: Avorax does not invoke App Installer, download package URLs, install/register packages, or auto-quarantine those review-only findings in confirmed-only mode.

The full small-threat MVP verifier also records the no-EICAR report as `generated_reports.no_eicar_harmless_threat` and validates that report's safety flags during `-RequireFullSuite`.

For a stricter release-core lifecycle proof, run
`tools\windows\avorax-installed-core-lifecycle-probe.ps1` with an explicit
`-LocalCorePath`, `-EvidenceRoot`, and repo-contained `-ReportPath`. It uses the
real scan and quarantine wrappers to verify `.avoraxq` creation, list, restore
with the original SHA-256, and confirmed deletion. It creates no standard EICAR
file, requires no Defender exclusion, makes no machine-wide changes, and does
not claim installed service mediation or pre-execution blocking.

### Diagnostic Log Exports And Support Bundles

Logs and Settings can export explicitly confirmed local JSON diagnostics for troubleshooting. Normal event-log export writes `zentor-local-events.json`; support-bundle export writes app/engine/service/update diagnostics plus local event history. Neither export includes file contents, quarantine payloads, live malware, hidden network upload, or credential collection. Credential-like values in exported event details and support-bundle diagnostics are redacted before writing shareable JSON, including authorization headers, cookie/session values, API keys, bearer tokens, URL userinfo, and common token-shaped values, while raw in-app local event history is preserved for local audit. Event details can still include local paths and errors, so review exported files before sharing them.

## Real-Time And Ransomware Protection

Avorax Guard is offline-first. The default release uses a visible user-mode helper with best-effort post-launch blocking where the OS allows it. A Windows minifilter development path exists for known-threat pre-execution blocking, but Avorax must not claim that mode is active unless the driver is installed, running, communicating with the service, and passing self-test. Production distribution requires Microsoft driver signing.

v0.1.13 adds prevention-first protection profiles:

- Balanced Protection: confirmed threats block, suspicious items review, unknown apps allow-and-monitor.
- Lockdown Protection: unknown apps are blocked until trusted or approved by exact hash.
- Developer Mode: unknown developer tools are monitored/reviewed without broadly blocking normal workflows.

Lockdown blocks unknown apps as unknown. It must not label a normal executable as a virus unless a native signature, native rule, native ML, or behavior signal supports that verdict. True before-launch Lockdown enforcement still requires the active driver path; otherwise Avorax reports post-launch fallback.

Ransomware Guard watches for behavior such as rapid mass file modification, suspicious renames, entropy jumps, ransom-note patterns, and backup tampering. Recovery Vault can restore protected copies when available. Avorax does not claim it can decrypt files without a backup, snapshot, or key.

## Quarantine And Allowlist

When scan mode allows quarantine and a confirmed infected file is detected, Avorax moves it to the Avorax quarantine folder, renames it with a safe `.avoraxq` extension, removes executable permissions where supported, and stores JSON metadata. Avorax does not permanently delete files automatically. Legacy quarantine records remain readable for migration.

Allowlist entries are explicit. Avorax blocks unsafe root paths such as `C:\`, `C:\Windows`, `/`, `/usr`, `/bin`, `/sbin`, and `/etc`.

## Build

```powershell
cd apps/zentor_client
flutter build apk
flutter build ios
flutter build windows
flutter build macos
flutter build linux
```

Platform builds require the normal Flutter toolchain for that platform. iOS and macOS require Xcode on macOS.

Before relying on a Windows release build, run the host-only prerequisite check
with explicit local tool paths:

```powershell
powershell -ExecutionPolicy Bypass `
  -File tools\windows\avorax-release-prereq-check.ps1 `
  -RepoRoot C:\Users\Brent\Documents\Avorax-main `
  -DotnetPath 'C:\Program Files\dotnet\dotnet.exe' `
  -CargoPath 'C:\Users\Brent\.cargo\bin\cargo.exe' `
  -FlutterPath 'C:\Users\Brent\develop\flutter\bin\flutter.bat' `
  -HostOnly `
  -ReportPath .workflow\ultracode\avorax-hardening\results\release-prereq-host-refresh.json
```

This check does not install components or change Windows settings. A Windows
desktop build requires Flutter Windows desktop support, Developer Mode or other
symlink support for plugin builds, Visual Studio Desktop C++ build components,
and a .NET SDK for installer tooling.

## Windows Installers

For normal testing, installing the MSI or EXE is easier than running the app from source. Use the installer from GitHub Releases when available, or build one locally with:

```powershell
cd C:\Users\Brent\CodexProjects\Avorax
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.2.14 -RequireLocalCore -AllowDevelopmentModel
```

The installers are written to:

```text
dist\Avorax-AntiVirus-0.2.14-x64.msi
dist\Avorax-AntiVirus-0.2.14-x64-setup.exe
```

Install either file:

- `Avorax-AntiVirus-0.2.14-x64-setup.exe` is the easiest option for most users.
- `Avorax-AntiVirus-0.2.14-x64.msi` is better for clean installer testing and enterprise-style deployment checks.

The MSI/EXE installs the app, Avorax Core Service, Avorax Guard Service, Avorax Native Engine assets under `C:\Program Files\Avorax\engine`, app assets, safe validation assets, release gates, driver tooling, safe simulator tools, threat-intel tools, docs, `install-manifest.json`, and ProgramData runtime folders. On Windows it registers `avorax_core_service` and `avorax_guard_service` as visible Windows services so local scanning and post-launch confirmed-threat monitoring can run without the UI. It does not replace the Windows driver-development VM workflow. True pre-execution blocking still requires WDK or EWDK, administrator rights, test-signing in a disposable VM, the minifilter/process-guard driver path, and the driver validation scripts.

The installer stages the Flutter Windows release app, `avorax_core_service.exe`, `avorax_guard_service.exe`, legacy-compatible helper names, Avorax Native Engine assets, app assets, bundled Flutter/plugin DLLs, Visual C++ runtime DLLs available on the build machine, local privacy/security docs, validation tooling, and `engine\trust\avorax_release_manifest.json` hashes for packaged Avorax files. Compatibility engines are not required for normal scanning. Avorax does not install hidden services or stealth persistence; the services are user-visible and removable through normal Windows service/app uninstall paths.

After installing, validate the deployed layout and service state with:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\avorax-installed-smoke-test.ps1
```

The MSI and EXE installer builds fail if the local core, Guard Service, Avorax Native Engine packs, model assets, trust/test assets, docs, or validation tooling are missing. They also fail when metadata says `production_ready=false` unless you pass `-AllowDevelopmentModel` for an explicitly non-production build. The EXE installer is a WiX Burn bootstrapper that contains and runs the MSI, so it installs the same complete payload.

Avorax Native Engine updates use signed native packs when update infrastructure is configured. Avorax must report native engine errors honestly instead of pretending files are clean.

GitHub Releases are built by `.github/workflows/release-windows.yml`. Push a version tag such as `v0.1.0` and GitHub Actions will build and attach both the `.msi` and `.exe` installers to the release.

## Windows Driver Validation

On a disposable Windows driver-development VM with Visual Studio Build Tools or EWDK and WDK installed:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-protection-selftest.ps1 -BuildDriver -InstallDriver -CargoPath C:\Path\To\cargo.exe
```

The workflow writes `dist\windows-driver-validation\selftest_report.json`. It refuses ambient Cargo lookup; pass `-CargoPath` or set `CARGO` to an absolute local Cargo executable path. If the driver is missing or not running, Avorax must show post-launch fallback instead of pre-execution blocking.

Additional release gates:

```powershell
powershell -ExecutionPolicy Bypass -File tools\security\zentor-false-positive-gate.ps1 -CargoPath C:\Path\To\cargo.exe
powershell -ExecutionPolicy Bypass -File tools\security\zentor-protection-gate.ps1 -CargoPath C:\Path\To\cargo.exe
powershell -ExecutionPolicy Bypass -File tools\perf\zentor-performance-gate.ps1 -CargoPath C:\Path\To\cargo.exe -PythonPath C:\Path\To\python.exe
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-release-gate.ps1 -CargoPath C:\Path\To\cargo.exe -PythonPath C:\Path\To\python.exe -FlutterPath C:\Path\To\flutter.bat
```

## Test

```powershell
cd apps/zentor_client
flutter test
flutter analyze

cd ../../packages/zentor_protocol
dart test

cd ../../core/zentor_local_core
cargo test

cd ../../services/api
cargo test
cargo check
```

## Intentionally Not Implemented In v1

- No silent kernel driver install. Driver protection is optional, user-visible, and requires explicit installation/signing.
- No hidden process behavior.
- No stealth startup persistence.
- No hidden unrelated file scanning.
- No full-system antivirus claim on mobile.
- No WebView, iframe, embedded localhost dashboard, Electron, Tauri, React, Next.js, or Vite runtime UI.
- No credential collection.
- No browser cookie access.
- No disabling other security tools.
- No fake users, fake bans, fake charts, fake virus results, or fake protection statistics.
