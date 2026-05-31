# Known Avorax Blockers

Date: 2026-05-30

This file tracks blockers that must be reported honestly and must not be represented as completed protection.

## Environment Blockers

- Flutter is not installed or is not on `PATH` in the current Linux container, so `flutter analyze` and `flutter test` cannot be completed locally.
- Dart is not installed or is not on `PATH` in the current Linux container, so `dart test` for `packages/zentor_protocol` cannot be completed locally.
- PowerShell is not installed or is not on `PATH` in the current Linux container, so `.ps1` gates cannot be executed locally here. Bash equivalents should be used where available, and PowerShell gates must run in CI or a Windows validation host.

## Windows Driver Blockers

- No signed Windows minifilter or process-guard driver has been built, installed, run, or self-tested in this environment.
- WDK/EWDK, Visual Studio Build Tools, Administrator installation context, test certificate setup, and a disposable Windows validation VM are required for driver validation.
- Avorax must not claim pre-execution or kernel-level protection until driver installation, IPC, and self-test reports pass.

## Product Readiness Blockers

- Production ML dataset, independent anti-virus validation, and production-ready `.zmodel` metadata are not present.
- Development ML must remain advisory/review-only and must not auto-quarantine by itself.
- Compatibility engines such as ClamAV/YARA must remain optional and disabled by default; Avorax Native Engine must handle core scans and EICAR without them.

## Validation Blockers

- Any failing Rust, Flutter, Dart, performance, false-positive, or release gate must block release-candidate tagging.
- The repository may include documentation and scripts for blocked platform workflows, but blocked features must remain marked unavailable or development-only until validated.
