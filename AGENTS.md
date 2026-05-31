# Avorax Agent Instructions

Build Avorax Anti-Virus as a legitimate, privacy-first anti-virus and anti-malware desktop client.

Product names:

- Product: Avorax Anti-Virus
- Short name: Avorax
- Product family: Avorax Security
- Engine: Avorax Native Engine
- Engine short name: ANE
- Services: Avorax Core Service and Avorax Guard Service

Required boundaries:

- Do not implement stealth behavior, rootkit behavior, malware-like persistence, credential theft, unrelated file scanning, or hidden surveillance.
- Do not claim kernel-level or pre-execution protection unless the signed driver path is actually built, installed, running, and self-tested.
- Do not replace the Flutter client with a web dashboard, WebView, iframe, Electron, Tauri, React, Vite, or Next.js runtime UI.
- Do not add fake runtime users, fake charts, fake detections, fake scan results, or pretend protection metrics.
- Keep telemetry explicit, minimal, documented, and related to anti-virus protection events.
- Prefer deterministic rules and auditable decisions over opaque automated punishment.
- Every admin action and automated rule decision must be audit logged.
- Do not include real malware binaries, download malware automatically, execute suspicious files, disable security tools, or create evasion or credential-theft tooling.
- Use safe validation only: EICAR, harmless known-bad test hashes, feature-vector fixtures, public indicators without binaries, and simulators that operate only in temporary test folders.
- Avoid active product language for unrelated enforcement, gaming, marketing websites, or legacy branding. Historical legacy naming is allowed only in the dedicated migration note and archived material.

Repository layout:

- `apps/zentor_client/`: Flutter desktop client.
- `core/zentor_native_engine/`: primary Rust detection engine.
- `core/zentor_local_core/`: local scan/core command surface.
- `core/zentor_guard_service/`: real-time guard and driver-facing service logic.
- `core/zentor_windows_minifilter/` and `core/zentor_windows_process_guard/`: Windows driver validation paths.
- `packages/zentor_protocol/`: Dart protocol models.
- `assets/zentor_native/`: signatures, rules, trust data, ML assets, and safe test corpus.
- `tools/`: branding, security, performance, Windows, simulator, and threat-intel gates.
- `installer/windows/`: Windows MSI/EXE packaging.
- `docs/`: architecture, limitations, safety, and validation documentation.
- `archive/`: inactive historical material only.

Engineering expectations:

- Keep the monorepo clean and typed.
- Runtime data must come only from local app state, local config, real API responses, selected file/app hash verification, and real errors/loading/empty states.
- Prefer small crates/modules with explicit ownership boundaries.
- Add or update tests for rules, API handlers, and SDK payload construction when behavior changes.
- Document commands and integration details in README and `docs/`.
- When platform-native APIs require real credentials, provide clear interfaces and comments rather than fake behavior.

Build commands:

- Rust crate tests: `cargo test --manifest-path core/zentor_native_engine/Cargo.toml`, `cargo test --manifest-path core/zentor_local_core/Cargo.toml`, `cargo test --manifest-path core/zentor_guard_service/Cargo.toml`, and `cargo test --manifest-path services/api/Cargo.toml`.
- Flutter client: `cd apps/zentor_client && flutter pub get && flutter analyze && flutter test`.
- Dart protocol: `cd packages/zentor_protocol && dart pub get && dart test`.
- Branding gate: `powershell -ExecutionPolicy Bypass -File tools/branding/branding-check.ps1`.
- Product copy gate: `powershell -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1`.
- False-positive gate: `powershell -ExecutionPolicy Bypass -File tools/security/zentor-false-positive-gate.ps1`.
- Windows release gate: `powershell -ExecutionPolicy Bypass -File tools/windows/zentor-release-gate.ps1`.

Forbidden active string categories in product-facing content:

- Legacy internal project naming and casing variants except in the dedicated migration note and `archive/`.
- Unrelated game-enforcement, fair-play, match/session telemetry, or setup language for games.
- Fake protection claims such as absolute-protection guarantees, unsupported certification claims, or unsupported customer-scale claims.

Release commands:

- Run all relevant tests and gates before tagging.
- Build Windows installers through `.github/workflows/release-windows.yml` or `installer/windows/build-msi.ps1`.
- Do not create release-candidate tags unless mandatory gates pass.

Release gates:

- Branding and product-copy gates must pass for active product-facing content.
- Rust, Flutter, Dart, false-positive, performance, protection, driver, and installer gates must pass or have explicit blocker documentation before release decisions.
- Release-candidate tags must not be created unless mandatory gates pass.

Definition of done:

- The implementation is real, defensive, locally testable, and documented.
- New behavior has focused tests or an explicit documented blocker when required tools are unavailable.
- `STATUS.md` records completed work, blockers, passing checks, failing checks, current commit, and the next exact task.
- Driver, ML, and protection claims are honest and backed by self-tests or clearly shown as unavailable/development-only.
