# Avorax Testing

This file documents the test and build checks used for the Avorax hardening sprint.

## Toolchain notes

On this Windows development machine, Flutter is installed at:

```text
C:\Users\Brent\dev\flutter\bin
```

From Git Bash, prefer explicit `.bat` invocations:

```bash
'/c/Users/Brent/dev/flutter/bin/flutter.bat' analyze
'/c/Users/Brent/dev/flutter/bin/flutter.bat' test
'/c/Users/Brent/dev/flutter/bin/dart.bat' test
```

## Flutter client

```bash
cd apps/zentor_client
'/c/Users/Brent/dev/flutter/bin/flutter.bat' analyze
'/c/Users/Brent/dev/flutter/bin/flutter.bat' test
'/c/Users/Brent/dev/flutter/bin/flutter.bat' build windows --debug
```

Current coverage includes API failure handling, startup smoke tests, app detection empty states, scan target planning, offline scan orchestration, stale error clearing, and local event log corruption recovery.

## Rust local core

```bash
cargo test --manifest-path core/zentor_local_core/Cargo.toml
```

Current coverage includes file walking, heuristic detection, YARA-style rule behavior, AI/model safety gates, allowlist validation, quarantine metadata/restore/delete safety, guard mode configuration, ransomware guard simulation, and scan job cancellation primitives.

## Rust guard service

```bash
cargo test --manifest-path core/zentor_guard_service/Cargo.toml
```

Current coverage includes configured guard modes, driver IPC verdict behavior, known-good/known-bad handling, lockdown behavior, mock process monitoring, cached native-engine reuse for pre-execution verdicts, and streaming guard-file hashing.

Focused driver/guard contract checks can be run with:

```bash
uv run pytest tests/test_custom_driver_contract.py -q
cargo test --manifest-path core/zentor_guard_service/Cargo.toml driver_ipc -- --nocapture
```

## Rust native engine

```bash
cargo test --manifest-path core/zentor_native_engine/Cargo.toml
```

Known environment limitation: Microsoft Defender may block the native-engine test executable with Windows error 225 because antivirus test fixtures intentionally resemble malware signatures. That is an environment/security-tool block, not a successful test run. Re-run in a trusted development folder or with an explicit developer exclusion only if appropriate.

## Dart protocol package

```bash
cd packages/zentor_protocol
'/c/Users/Brent/dev/flutter/bin/dart.bat' test

cd ../avorax_protocol
'/c/Users/Brent/dev/flutter/bin/dart.bat' analyze
'/c/Users/Brent/dev/flutter/bin/dart.bat' test
```

`packages/avorax_protocol` covers shared update manifest parsing/defaults/serialization for `.aup` verifier and app compatibility.

## Release/build gates

Run these before tagging or shipping an installer when the required Windows/PowerShell environment is available:

```bash
powershell.exe -ExecutionPolicy Bypass -File tools/branding/branding-check.ps1
powershell.exe -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1
powershell.exe -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1 -RepoRoot .
powershell.exe -ExecutionPolicy Bypass -File tools/security/zentor-false-positive-gate.ps1
powershell.exe -ExecutionPolicy Bypass -File tools/security/zentor-protection-gate.ps1 -RepoRoot . -SelfTestReport <selftest_report.json>
powershell.exe -ExecutionPolicy Bypass -File tools/perf/zentor-performance-gate.ps1 -RepoRoot .
powershell.exe -ExecutionPolicy Bypass -File tools/windows/zentor-release-gate.ps1
```

The performance gate also runs `tools/perf/avorax-benchmark.py`, which writes `dist/performance/benchmark_report.json`. The harness uses harmless synthetic files, existing Rust test commands, and a non-elevated update-copy simulation. It is useful for trend tracking but does not replace signed-driver latency tests or elevated update-service apply benchmarks.

CI now runs the product-copy, no-malware-binaries, false-positive, protection, and performance gates. The CI protection gate uses a synthetic non-driver self-test fixture and does not claim kernel driver validation; driver-feature release gates still require a real signed/installed/self-tested driver report.

Some service/driver/update gates may require elevation or a signed installed driver. If they cannot run, document the blocker in `RUN_LOG.md` and do not claim the gated capability as verified.

Current Windows limitation: `cargo test --manifest-path core/avorax_update_service/Cargo.toml` and `--bin avorax_update_service` can fail before running tests with Windows error 740 because the update-service test binaries inherit a require-administrator manifest. In a non-elevated shell, use `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bin avorax_update_service` plus `uv run pytest tests/test_custom_driver_contract.py -q`, or rerun the Rust unit tests from an elevated developer shell. The static contract test also checks that update apply attempts rollback restoration and service restart on payload-copy failure; elevated integration tests are still needed for real service stop/start/apply paths.
