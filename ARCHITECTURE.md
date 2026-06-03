# Avorax Architecture

Avorax is a defensive, offline-first antivirus / anti-malware / endpoint protection monorepo. The product is split into a Flutter desktop/mobile client, Rust local security engines and services, shared Dart protocol packages, installer/update tooling, and documentation/gate scripts.

## Top-level layout

```text
apps/zentor_client/              Flutter client application
packages/zentor_protocol/        Shared Dart protocol/state models
packages/avorax_protocol/        Shared update manifest models
core/zentor_native_engine/       Primary Rust detection engine
core/zentor_local_core/          Local stdin/stdout command surface for the UI
core/zentor_guard_service/       Real-time/pre-execution guard service logic
core/avorax_update_service/      Signed .aup update verifier/apply service
core/zentor_windows_minifilter/  Windows minifilter driver development path
core/zentor_windows_process_guard/ Windows process guard development path
services/api/                    Optional Rust Axum cloud/API service
assets/zentor_native/            Native signatures, rules, trust, ML assets
tools/                           Branding, security, performance, update, Windows gates
installer/windows/               WiX MSI/EXE packaging
infra/                           Local Docker infrastructure
docs/                            Product, safety, and engineering documentation
```

Historical internal names such as `zentor_*` remain in paths and APIs. Product-facing copy should use Avorax names unless explaining migration or internal architecture.

## Runtime architecture

```text
Flutter UI
  | local JSON commands over stdin/stdout
  v
Avorax Core Service / zentor_local_core
  | loads engine assets, scans files/folders, records quarantine/log state
  v
Avorax Native Engine / zentor_native_engine
  | signatures + rules + heuristics + trust + development ML interface
  v
Scan verdicts, reports, quarantine actions

Avorax Guard Service
  | best-effort process/file protection and driver-facing IPC
  v
Native Engine + policy + allowlist/trust stores

Avorax Update Service
  | verifies signed .aup packages and applies staged app/service/engine updates
  v
Install directory + ProgramData update staging/rollback/logs
```

## Flutter client

The Flutter app owns product navigation, user-visible state, settings, logs, update checks, and local scan orchestration.

Important files:

- `apps/zentor_client/lib/app/app_state.dart`: central Riverpod controller for scans, settings, cloud/update state, local events, protection actions, and quarantine actions.
- `apps/zentor_client/lib/app/router.dart`: routes for Dashboard, Scan, Quarantine, Allowlist, Protection, Device, Logs, Settings, Updates, and Privacy.
- `apps/zentor_client/lib/shared/widgets/zentor_shell.dart`: responsive application shell.
- `apps/zentor_client/lib/core/scanning/scan_target_service.dart`: quick/full scan target planning.
- `apps/zentor_client/lib/core/local_core/local_core_client.dart`: local core process IPC and JSON parsing.
- `apps/zentor_client/lib/core/logging/local_event_repository.dart`: local structured event persistence/export.
- `apps/zentor_client/lib/core/config/config_repository.dart`: persisted settings plus build-time config overlay.
- `apps/zentor_client/lib/core/updates/update_service.dart`: feed/package update selection and `.aup` verification/apply handoff.

The UI must remain honest: if a service, driver, ML model, cloud provider, or protection mode is disabled/unavailable, it should show an attention/unavailable state rather than claiming full protection.

## Scan flow

1. The UI requests Quick Scan, Full Scan, or Custom Scan.
2. `ScanTargetService` selects paths:
   - Quick Scan: high-risk user-writable/startup/temp locations and risky file types, not whole disk traversal.
   - Full Scan: accessible local drives/home filesystem areas with exclusions and permission-error handling.
   - Custom Scan: selected file/folder only.
3. `ZentorController` invokes `LocalCoreClient.scanPaths` or `scanFile`.
4. `zentor_local_core` loads the native engine and resolves engine assets from installed paths, environment overrides, or repo assets.
5. `zentor_native_engine` streams file reads for SHA-256/size metadata while retaining a bounded 64 MiB content sample for signature/rule/heuristic analysis, so large files do not need to be fully loaded into memory.
6. Results are converted to protocol models and displayed with progress, detections, skipped files, errors, full-file hash, file size, scanned-byte count, and sample-limit flags where available.
7. Confirmed threats may be quarantined only under explicit scan policy and allowlist checks.

## Detection engine

The native engine is the source of truth for local malware verdicts. It includes:

- Hash/string/byte/PE/script signature matching.
- Native deterministic rule packs.
- Heuristics for risky filenames, locations, scripts, packer/import indicators, ransomware/persistence patterns, entropy, and false-positive suppression.
- Trust stores and known-good/known-bad inputs.
- A development ML model interface. The bundled development model is not production-ready and must not be marketed as production AI protection.
- Verdict fusion into clean, unknown, suspicious, probable, confirmed/test threat-style results with evidence and reason codes.

Large-file and archive handling must be conservative and explicit when content is partially scanned or skipped. Current native engine file scans compute the full-file SHA-256 via streaming I/O and analyze a bounded sample; verdict metadata marks when the analysis sample was limited.

## Quarantine

Quarantine is intended to be reversible and explicit:

- Confirmed malicious files are moved to a quarantine folder with a safe non-executable extension.
- Metadata records original path, detection name, reason codes/evidence, timestamp, size, and hashes where available.
- Restore requires confirmation, validates the destination, prevents path traversal, and avoids overwriting existing files.
- Permanent delete requires explicit user action.

The local core has a richer quarantine store than the native engine's create-only path. Long-term architecture should consolidate lifecycle operations so UI, core, and engine expose consistent list/restore/delete semantics.

## Real-time and ransomware protection

The guard service provides best-effort user-mode protection and driver-facing policy evaluation. Kernel/pre-execution enforcement requires the Windows minifilter path to be built, installed, signed, running, communicating with the service, and passing self-test.

User-mode protection should monitor high-risk folders, debounce events, wait for files to become stable, avoid rescanning unchanged files, and publish structured events to the UI. Ransomware protection should focus on protected folders and harmless simulation-tested behaviors such as rapid modifications, rename/write/delete bursts, extension changes, and ransom-note-like filenames.

## Updates

Normal app updates are signed `.aup` packages, not raw installer execution from inside the app. The update service verifies product identity, version/channel, package hash, manifest signature, and payload hashes before apply. Payload sections are staged, rollback metadata is created, and app/service/engine files are replaced only after verification.

Installer MSI/EXE remains a first-install, repair, recovery, offline, and manual-install path.

## Build and test systems

- Rust workspace: `Cargo.toml` with crates under `core/` and `services/api/`.
- Flutter app: `apps/zentor_client/pubspec.yaml`.
- Dart protocol packages: `packages/zentor_protocol`, `packages/avorax_protocol`.
- Windows installer: PowerShell + WiX via `installer/windows/build-msi.ps1`.
- Release gates: PowerShell scripts under `tools/branding`, `tools/security`, `tools/perf`, `tools/windows`, `tools/zne`, and `tools/update`.

Baseline local checks:

```powershell
cargo test --manifest-path core/zentor_native_engine/Cargo.toml
cargo test --manifest-path core/zentor_local_core/Cargo.toml
cargo test --manifest-path core/zentor_guard_service/Cargo.toml
cargo test --manifest-path core/avorax_update_service/Cargo.toml
cd apps/zentor_client; flutter analyze; flutter test
cd packages/zentor_protocol; dart test
```

Some Windows service/update tests may require elevation. Driver gates require a signed/installed/self-tested driver report.
