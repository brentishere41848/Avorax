# Pasus

Pasus is a privacy-first desktop anti-malware and security client. It is a real Flutter application for Android, iOS, Windows, macOS, and Linux, with a Rust local core for desktop malware scanning and quarantine.

Pasus v1 runs Quick Scan, Full Scan, and Custom Scan flows fully offline. Scanning, quarantine, allowlist, logs, and scan results do not require Pasus Cloud, an account, an API, a login, or internet. Runtime data comes only from local state, local configuration, real API responses when optional cloud features are enabled, selected path hashing, local core results, and real errors.

## Repository Layout

```text
apps/
  pasus_client/          Flutter 3 Material 3 client application
  pasus_website/         Next.js marketing website for Pasus Anti-Malware
packages/
  pasus_protocol/        Shared Dart protocol and state models
core/
  pasus_local_core/      Rust stdin/stdout local security core
services/
  api/                   Rust Axum Pasus API
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

## Run The Flutter App

```powershell
cd apps/pasus_client
flutter pub get
flutter run -d windows
flutter run -d macos
flutter run -d linux
flutter run -d android
flutter run -d ios
```

Pasus opens to the native Flutter Home screen. It does not open a browser, WebView, iframe, localhost page, Electron app, Tauri app, React app, Next.js app, or Vite app.

## Run The Backend API

The easiest local backend path is Docker Compose:

```powershell
cd C:\Users\Brent\CodexProjects\Pasus
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

The local compose stack seeds a development project/key that matches the Flutter defaults:

```text
PASUS_PROJECT_ID=pasus-default
PASUS_PUBLIC_GAME_KEY=pasus-public-client
```

Run the Flutter app against the local API:

```powershell
cd apps/pasus_client
flutter run -d windows `
  --dart-define=PASUS_API_BASE_URL=http://127.0.0.1:8000 `
  --dart-define=PASUS_PROJECT_ID=pasus-default `
  --dart-define=PASUS_PUBLIC_GAME_KEY=pasus-public-client
```

To run only Postgres and Redis in Docker, then the API with Cargo:

```powershell
cd C:\Users\Brent\CodexProjects\Pasus
docker compose -f infra/docker-compose.yml up postgres redis

cd services/api
$env:DATABASE_URL="postgres://pasus:pasus@localhost:15432/pasus"
$env:REDIS_URL="redis://localhost:16379"
$env:PASUS_DEV_PROJECT_ID="pasus-default"
$env:PASUS_DEV_PUBLIC_GAME_KEY="pasus-public-client"
cargo run
```

When running with Cargo directly, the API listens on `http://127.0.0.1:8000` unless you set `PASUS_API_BIND_ADDR`.

## Pasus Cloud Configuration

The app uses build-time Pasus Cloud settings by default. Users are not asked to paste API settings during first launch.

```powershell
flutter run -d windows `
  --dart-define=PASUS_API_BASE_URL=https://YOUR_API_HERE `
  --dart-define=PASUS_PROJECT_ID=YOUR_PROJECT_ID `
  --dart-define=PASUS_PUBLIC_GAME_KEY=YOUR_PUBLIC_GAME_KEY
```

Cloud is optional. The app defaults to local protection and does not call Pasus Cloud before allowing scans. Use `Settings > Cloud` or developer options to test a cloud endpoint when remote reporting, updates, or future account/license features are needed.

Developer endpoint overrides are hidden under `Settings > Advanced > Developer options`.

## App Updates

Pasus checks GitHub Releases for newer tagged builds and shows a visible update state in Home and `Settings > Updates`. It does not silently install updates. When a newer release exists, the user can choose `Download Update`, which opens the release installer or GitHub release page.

Release builds should be tagged with `vMAJOR.MINOR.PATCH`. The Windows release workflow builds Flutter with the tag version, publishes MSI/EXE assets, and the installed app compares that local version against the latest GitHub release.

Override the update repository at build time when needed:

```powershell
flutter build windows --release `
  --dart-define=PASUS_UPDATES_REPO_OWNER=YOUR_GITHUB_USER `
  --dart-define=PASUS_UPDATES_REPO_NAME=YOUR_REPO
```

## Desktop Local Core

```powershell
cd core/pasus_local_core
cargo test
cargo build --release
```

The Flutter client talks to the local core over stdin/stdout JSON commands. The core is not exposed to the network. Set `PASUS_LOCAL_CORE` to the built executable path when running the Flutter app if the binary is not beside the app process.

## Malware Scanning

Desktop scanning uses Pasus Native Engine (PNE) as the primary engine:

- Native signatures in `assets/pasus_native/signatures/pasus_core.psig`.
- Native deterministic rules in `assets/pasus_native/rules/pasus_rules.prule`.
- Static analyzers for file type, strings, entropy, PE metadata, scripts, and ZIP archives.
- Conservative heuristic scoring and false-positive controls.
- Pure Rust native ML runtime using `assets/pasus_native/ml/pasus_native_model.pmodel`.
- No cloud, ClamAV, or YARA dependency for Quick Scan, Full Scan, Custom Scan, EICAR detection, or quarantine.

Weak signals do not become scary detections by themselves: a normal `.exe` in Downloads, an unknown CLI binary, a VPN installer, or an unsigned developer tool is not shown as malware unless stronger independent signals combine.

Native ML support is offline-first and honest. The included `.pmodel` is a development model marked `production_ready=false`; it proves deterministic local inference but cannot auto-quarantine by itself or claim production AI protection. The `ml_native/` folder contains the developer training/export pipeline and schemas. User labels are saved locally for export; the production app does not retrain itself silently.

Android and iOS show an honest unavailable state for full malware quarantine because mobile OS sandboxing prevents full-device scanning.

Scan types:

- Quick Scan is a targeted fast scan. It checks high-risk locations such as Downloads, Desktop, temp folders, and startup/autostart locations, but only walks a shallow depth and scans risky file types such as executables, scripts, installers, archives, shortcuts, and macro-enabled documents.
- Full Scan checks accessible local drives or home filesystem areas, respects OS permissions, skips denied paths, and reports skipped counts.
- Custom Scan checks only the file or folder selected by the user.

Scan modes:

- Detect only: Pasus lists suspicious or infected files and does not quarantine or delete anything.
- Auto-quarantine confirmed threats: Pasus quarantines confirmed signature detections when not allowlisted. Heuristic findings are shown for review.
- Auto-quarantine all detections: Pasus may quarantine eligible non-low-confidence local detections. Low-confidence heuristic findings remain review-only.

Scan results are grouped into confirmed threats, probable malware, suspicious items, and low-priority observations. Low-priority observations are hidden by default.

## Real-Time And Ransomware Protection

Pasus Guard is offline-first. The default release uses a visible user-mode helper with best-effort post-launch blocking where the OS allows it. A Windows minifilter development path exists for known-threat pre-execution blocking, but Pasus must not claim that mode is active unless the driver is installed, running, communicating with the service, and passing self-test. Production distribution requires Microsoft driver signing.

v0.1.13 adds prevention-first protection profiles:

- Balanced Protection: confirmed threats block, suspicious items review, unknown apps allow-and-monitor.
- Lockdown Protection: unknown apps are blocked until trusted or approved by exact hash.
- Developer Mode: unknown developer tools are monitored/reviewed without broadly blocking normal workflows.

Lockdown blocks unknown apps as unknown. It must not label a normal executable as a virus unless a native signature, native rule, native ML, or behavior signal supports that verdict. True before-launch Lockdown enforcement still requires the active driver path; otherwise Pasus reports post-launch fallback.

Ransomware Guard watches for behavior such as rapid mass file modification, suspicious renames, entropy jumps, ransom-note patterns, and backup tampering. Recovery Vault can restore protected copies when available. Pasus does not claim it can decrypt files without a backup, snapshot, or key.

## Quarantine And Allowlist

When scan mode allows quarantine and a confirmed infected file is detected, Pasus moves it to the Pasus quarantine folder, renames it with a safe `.pasusq` extension, removes executable permissions where supported, and stores JSON metadata. Pasus does not permanently delete files automatically.

Allowlist entries are explicit. Pasus blocks unsafe root paths such as `C:\`, `C:\Windows`, `/`, `/usr`, `/bin`, `/sbin`, and `/etc`.

## Website

The marketing website lives in `apps/pasus_website`.

```powershell
cd apps/pasus_website
npm install
npm run dev
npm run build
npm test
```

The website presents Pasus as `Pasus Anti-Malware`, shows licensing as coming soon, offers a waitlist, and links only to real release assets when they exist.

## Build

```powershell
cd apps/pasus_client
flutter build apk
flutter build ios
flutter build windows
flutter build macos
flutter build linux
```

Platform builds require the normal Flutter toolchain for that platform. iOS and macOS require Xcode on macOS.

## Windows Installers

```powershell
cd C:\Users\Brent\CodexProjects\Pasus
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Version 0.1.0 -RequireLocalCore
```

The installers are written to:

```text
dist\Pasus-0.1.0-x64.msi
dist\Pasus-0.1.0-x64-setup.exe
```

The installer stages the Flutter Windows release app, `pasus_local_core.exe`, `pasus_guard_service.exe`, Pasus Native Engine assets, app assets, bundled Flutter/plugin DLLs, Visual C++ runtime DLLs available on the build machine, and local privacy/security docs. Compatibility engines are not required for normal scanning. Pasus does not install hidden services or stealth persistence.

The MSI and EXE installer builds fail if model assets are missing. They also fail when metadata says `production_ready=false` unless you pass `-AllowDevelopmentModel` for an explicitly non-production build. The EXE installer is a WiX Burn bootstrapper that contains and runs the MSI.

Pasus Native Engine updates use signed native packs when update infrastructure is configured. Pasus must report native engine errors honestly instead of pretending files are clean.

GitHub Releases are built by `.github/workflows/release-windows.yml`. Push a version tag such as `v0.1.0` and GitHub Actions will build and attach both the `.msi` and `.exe` installers to the release.

## Windows Driver Validation

On a disposable Windows driver-development VM with Visual Studio Build Tools or EWDK and WDK installed:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\pasus-protection-selftest.ps1 -BuildDriver -InstallDriver
```

The workflow writes `dist\windows-driver-validation\selftest_report.json`. If the driver is missing or not running, Pasus must show post-launch fallback instead of pre-execution blocking.

Additional release gates:

```powershell
powershell -ExecutionPolicy Bypass -File tools\security\pasus-false-positive-gate.ps1
powershell -ExecutionPolicy Bypass -File tools\security\pasus-protection-gate.ps1
powershell -ExecutionPolicy Bypass -File tools\perf\pasus-performance-gate.ps1
powershell -ExecutionPolicy Bypass -File tools\windows\pasus-release-gate.ps1
```

## Test

```powershell
cd apps/pasus_client
flutter test
flutter analyze

cd ../../packages/pasus_protocol
dart test

cd ../../core/pasus_local_core
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
