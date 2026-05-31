# Avorax Repository Audit

Date: 2026-05-31
Commit audited: `d5c778a`

## Scope

This audit covers the active Avorax Anti-Virus repository state, including Rust crates, Flutter/Dart packages, Windows driver validation scripts, installer/release tooling, CI workflows, branding gates, archived legacy material, and known blockers. It does not claim product readiness or driver-level protection.

## Inventory

- Active app files under `apps/`: 172
- Core files under `core/`: 258
- Service/API files under `services/`: 10
- Tooling files under `tools/`: 21
- Documentation files under `docs/`: 34
- GitHub workflow files under `.github/`: 2

Rust crates:

- `core/zentor_native_engine/Cargo.toml`
- `core/zentor_local_core/Cargo.toml`
- `core/zentor_guard_service/Cargo.toml`
- `services/api/Cargo.toml`

Flutter/Dart packages:

- `apps/zentor_client/pubspec.yaml`
- `packages/zentor_protocol/pubspec.yaml`

Windows driver/service validation paths:

- `core/zentor_windows_minifilter/`
- `core/zentor_windows_process_guard/`
- `tools/windows/zentor-protection-selftest.ps1`
- `tools/windows/zentor-release-gate.ps1`

Installer and release paths:

- `installer/windows/build-msi.ps1`
- `.github/workflows/ci.yml`
- `.github/workflows/release-windows.yml`

Archived legacy material:

- `archive/` contains inactive legacy website code.
- The dedicated migration note is the allowed historical legacy-brand reference.

## Baseline Checks

Passed:

- `powershell -ExecutionPolicy Bypass -File tools/branding/branding-check.ps1`
- `powershell -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1`

Blocked by missing local toolchains:

- `cargo test --workspace`: `cargo` is not installed or not on `PATH`.
- `flutter analyze`: `flutter` is not installed or not on `PATH`.
- `flutter test`: `flutter` is not installed or not on `PATH`.
- `dart test` in `packages/zentor_protocol`: `dart` is not installed or not on `PATH`.
- `tools/security/zentor-false-positive-gate.ps1`: fixture checks start, but Rust test execution is blocked by missing `cargo`.

Windows driver environment checks:

- `core/zentor_windows_minifilter/scripts/setup-dev-env-check.ps1` fails clearly because Visual Studio Build Tools with Desktop C++ workload or an EWDK Developer Command Prompt is missing.
- `core/zentor_windows_process_guard/scripts/setup-dev-env-check.ps1` delegates to the minifilter environment check and fails for the same reason.

## Findings

1. The repository has the expected major product areas: Flutter client, Rust native engine, local core, guard service, Windows driver validation paths, installer tooling, CI workflows, docs, and release gates.
2. The active branding and product-copy gates pass in this environment.
3. The local machine cannot compile or test the Rust, Flutter, or Dart code until the required toolchains are installed or CI is used.
4. The Windows driver path is not production-active. It requires WDK/EWDK, Administrator workflow, signing setup, installation, IPC validation, and passing self-test before any pre-execution protection claim.
5. Production ML readiness is not established. Development model behavior must remain review/supportive and must not auto-quarantine by itself.
6. Archived website material remains under `archive/` and is not part of active builds.

## Required Next Checks

Run these in a provisioned build environment:

```powershell
cargo test --workspace
cd apps\zentor_client; flutter pub get; flutter analyze; flutter test
cd ..\..\packages\zentor_protocol; dart pub get; dart test
powershell -ExecutionPolicy Bypass -File tools\security\zentor-false-positive-gate.ps1
powershell -ExecutionPolicy Bypass -File tools\perf\zentor-performance-gate.ps1
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-release-gate.ps1
```

Run Windows driver validation only in a disposable development VM with WDK/EWDK and explicit test-signing setup:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-protection-selftest.ps1 -BuildDriver -InstallDriver
```

## Phase 0 Result

Phase 0 is partially complete: the repository has been inventoried, content gates passed, and local toolchain/driver blockers are documented. Compile/test completion is blocked by missing local Rust, Flutter, Dart, and WDK/EWDK tooling.
