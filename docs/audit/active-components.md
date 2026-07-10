# Active Avorax Components

Date: 2026-06-25

This inventory identifies the active components that should remain part of the
Avorax Anti-Virus product foundation. Archived legacy material under `archive/`
is excluded from active build and release decisions.

See `docs/audit/engine-control-matrix.md` for the source-accounted matrix of
active detection engines, compatibility engines, protection surfaces, trust
controls, update controls, and technical blockers.

## Desktop Application

- `apps/zentor_client/` - Flutter desktop client for Avorax Anti-Virus.
- `packages/zentor_protocol/` - Dart protocol models shared by the client and local surfaces.

## Rust Engine and Services

- `core/zentor_native_engine/` - primary Avorax Native Engine (ANE) scanner, signatures, rules, analyzers, verdicts, quarantine, telemetry, threat-intel import, and safe test logic.
- `core/zentor_local_core/` - local command surface for scanning, scan jobs, compatibility providers, allowlist, quarantine, recovery, and application-control policy.
- `core/zentor_guard_service/` - real-time guard and driver-facing service logic.
- `services/api/` - backend API crate retained for service/API integration tests; it is not a replacement for the desktop client.

## Platform Validation Paths

- `core/zentor_windows_minifilter/` - Windows minifilter validation scripts and user-mode test harness.
- `core/zentor_windows_process_guard/` - Windows process guard validation scripts and user-mode test harness.
- `core/zentor_amsi_provider/` - AMSI validation path.
- `core/zentor_linux_fanotify_guard/` and `core/zentor_macos_endpoint_extension/` - platform validation notes and development-only protection paths.

## Native Assets and Fixtures

- `assets/zentor_native/signatures/` - `.zsig` signature packs.
- `assets/zentor_native/rules/` - `.zrule` rule packs.
- `assets/zentor_native/ml/` - Avorax native `.zmodel` development model and metadata.
- `assets/zentor_native/trust/` - `.ztrust` known-good and known-bad test trust data.
- `assets/zentor_native/test_corpus/` and `tests/fixtures/` - safe fixtures only; no real malware binaries.

## Tooling and Release Gates

- `tools/branding/` - active branding/product-purity checks.
- `tools/security/` - false-positive, product-copy, and protection gates.
- `tools/perf/` - performance gate scripts.
- `tools/windows/` - Windows driver/protection self-test and release gate orchestration.
- `tools/zentor_intel/` - safe threat-intel import and pack compilation helpers.
- `tools/simulators/` - safe simulators restricted to temporary test folders.
- `installer/windows/` - Windows installer packaging scripts.
- `.github/workflows/` - CI and Windows release workflows.

## Active Build Entry Points

- Repository Rust workspace: `cargo test --workspace`.
- Individual Rust crates: `cargo test --manifest-path core/zentor_native_engine/Cargo.toml`, `core/zentor_local_core`, `core/zentor_guard_service`, and `services/api`.
- Flutter client: `cd apps/zentor_client && flutter pub get && flutter analyze && flutter test`.
- Dart protocol: `cd packages/zentor_protocol && dart pub get && dart test`.
- Release gates: branding, product copy, false-positive, performance, protection, Windows release, and installer checks documented in `AGENTS.md` and `STATUS.md`.
