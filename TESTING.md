# Avorax Testing

This file documents the test and build checks used for the Avorax hardening sprint.

## Toolchain notes

On this Windows development machine, Flutter is installed at:

```text
C:\Users\Brent\develop\flutter\bin
```

From Git Bash, prefer explicit `.bat` invocations:

```bash
'/c/Users/Brent/develop/flutter/bin/flutter.bat' analyze
'/c/Users/Brent/develop/flutter/bin/flutter.bat' test
'/c/Users/Brent/develop/flutter/bin/dart.bat' test
```

From PowerShell in Codex, prepend Git for Flutter/Dart helper scripts if this shell has not inherited the user PATH:

```powershell
$env:Path = 'C:\Program Files\Git\cmd;C:\Users\Brent\develop\flutter\bin;C:\Users\Brent\.cargo\bin;' + $env:Path
& 'C:\Users\Brent\develop\flutter\bin\flutter.bat' analyze
& 'C:\Users\Brent\develop\flutter\bin\flutter.bat' test --reporter compact
```

## Flutter client

```bash
cd apps/zentor_client
'/c/Users/Brent/develop/flutter/bin/flutter.bat' analyze
'/c/Users/Brent/develop/flutter/bin/flutter.bat' test
'/c/Users/Brent/develop/flutter/bin/flutter.bat' build windows --debug
```

Current coverage includes API failure handling, startup smoke tests, app detection empty states, scan target planning, offline scan orchestration, stale error clearing, local event log corruption recovery, local log/support-bundle export flows, shareable export credential redaction, navigation semantics, shell page-title/main-content accessibility semantics, and Settings section-heading semantics.

Focused support-bundle coverage:

```powershell
cd apps\zentor_client
flutter test test\logs_screen_test.dart test\local_event_test.dart test\settings_accessibility_test.dart
```

The repository/controller/widget tests verify explicit confirmation, cancel behavior, duplicate-export suppression, disabled busy states, bounded JSON export, privacy flags, diagnostic summaries, credential redaction for bearer/API-key/JWT plus Basic-auth, cookie/session, and URL-userinfo cases, raw-history preservation for local audit, and no file contents or quarantine payloads.

The small-threat MVP verifier also runs `Flutter support-bundle export tests` and
`Flutter shareable export credential-redaction tests` whenever Flutter is not
skipped, and the report validator rejects passed non-skip-Flutter reports that
omit either required export evidence step.

## Rust local core

```bash
cargo test --manifest-path core/zentor_local_core/Cargo.toml
```

Current coverage includes file walking, heuristic detection, YARA-style rule behavior, AI/model safety gates, allowlist validation, quarantine metadata/restore/delete safety, guard mode configuration, ransomware guard simulation/config/activity validation, suspicious-process snapshot observation, scan job cancellation primitives, and Quick Scan review-only carrier coverage such as Windows App Installer/AppInstaller manifests. The full small-threat MVP verifier also runs release-binary smokes against `target\release\zentor_local_core.exe` for ransomware-guard config persistence, bounded caller-supplied activity evaluation, fail-visible validation, process snapshot observation, and selected review-only carriers, including AppInstaller, ClickOnce/JNLP/scriptlet/installer, document/web, registry/shortcut/disk-image, and ZIP nested-executable/autorun/shortcut carrier review.

## Rust guard service

```bash
cargo test --manifest-path core/zentor_guard_service/Cargo.toml
```

Current coverage includes configured guard modes, driver IPC verdict behavior, known-good/known-bad handling, lockdown behavior, mock process monitoring, cached native-engine reuse for pre-execution verdicts, and streaming guard-file hashing.

Focused driver/guard contract checks can be run with:

```bash
uv run pytest tests/test_custom_driver_contract.py -q
python tools/testing/run-python-source-contracts.py
cargo test --manifest-path core/zentor_guard_service/Cargo.toml driver_ipc -- --nocapture
```

Use `tools/testing/run-python-source-contracts.py` when pytest is unavailable; it executes the dependency-free source-contract functions directly without installing packages.

Flutter shell notifications are verified as in-app local-event summaries, not
as Windows toast delivery. The focused regression is:

```powershell
cd apps\zentor_client
flutter test test\navigation_accessibility_test.dart --plain-name "shell notification"
```

That fixture checks control-text normalization, warning/error priority over
newer informational scan events, and newest-event selection when severity
priority is tied.

## Rust native engine

```bash
cargo test --manifest-path core/zentor_native_engine/Cargo.toml
cargo test --manifest-path core/zentor_native_engine/Cargo.toml provider -- --nocapture
```

Current coverage includes native signatures, deterministic rules, heuristics, development-model safety, threat-intel pack import, streaming large-file metadata, quarantine copy fallback, behavior/ransomware windows, detection-provider registry/status behavior, and bounded static carrier review signals including `.appinstaller` remote Windows app package manifests.

Known environment limitation: Microsoft Defender may block the native-engine test executable with Windows error 225 because antivirus test fixtures intentionally resemble malware signatures. That is an environment/security-tool block, not a successful test run. Re-run in a trusted development folder or with an explicit developer exclusion only if appropriate.

For a safe local Avorax validation when Defender blocks standard EICAR content,
use the no-EICAR harmless-threat smoke instead of weakening Defender:

```powershell
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\testing\run-no-eicar-local-core-harmless-threat-smoke.ps1 `
  -LocalCorePath target\release\zentor_local_core.exe `
  -ReportPath .workflow\ultracode\avorax-hardening\results\no-eicar-harmless-threat-smoke.json
```

This proof uses temporary harmless exact-hash fixture bytes and isolated
runtime roots. It must report `standard_eicar_file_created=false`,
`standard_eicar_string_written=false`, `defender_exclusion_required=false`, and
`live_malware_used=false`.

The full small-threat MVP verifier writes the no-EICAR evidence as
`generated_reports.no_eicar_harmless_threat`, and the full-suite report
validator parses that generated report instead of trusting step presence alone.

For a direct local Avorax scan using the release local-core binary, use the
local scan wrapper. It is detect-only by default and refuses broad
auto-quarantine unless explicit target paths are supplied. Quick and Full
release-binary scans emit progress JSON lines; the wrapper counts them in
`progress_events` and treats malformed non-progress stdout as a visible error:

```powershell
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-local-scan.ps1 `
  -ScanType Quick `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-quick-scan.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-local-scan.ps1 `
  -ScanType File `
  -Path C:\path\to\file.bin `
  -AutoQuarantineConfirmed `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-file-scan.json
```

The wrapper records `standard_eicar_string_written=false`,
`defender_exclusion_required=false`, `machine_wide_changes=false`,
`service_installation_attempted=false`, and
`pre_execution_blocking_claimed=false`. The wrapper progress smoke records
`local-scan-wrapper-progress.json` with `progress_events>0`,
`action_mode=detectOnly`, and `quarantined_files=0`. The same smoke records
`local-scan-wrapper-folder-quarantine.json` for an explicit `Folder` target with
`command=scan_folder`, `scan_kind=custom`, `files_scanned=2`,
`threats_found=1`, and `quarantined_files=1`, proving the harmless known-bad
fixture is quarantined while the benign folder file remains. It also records
`local-scan-wrapper-fail-on-threat.json` for `-FailOnThreat`, proving a
detect-only threat result returns failure semantics with `quarantined_files=0`
and the source file still present. The path-guard smoke records
`local-scan-wrapper-path-guards.json` and proves missing scan targets, `File`
scans pointed at folders, and report paths outside the repository all fail
visibly before writing a scan report. It is a release-binary local scan path,
not proof of installed service behavior, external cross-process cancellation
E2E, or kernel pre-execution blocking.

For release-binary scan cancellation from a shell, use the cancel-scan wrapper.
Use an isolated `-DataRoot` for local proof, or explicitly choose
`-UseInstalledDataRoot` only when you intend to request cancellation in an
installed runtime. The wrapper refuses to write to an implicit default runtime:

```powershell
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-cancel-scan.ps1 `
  -DataRoot $env:TEMP\avorax-cancel-proof `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-cancel-scan.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-cancel-scan.ps1 `
  -UseInstalledDataRoot `
  -ReportPath .workflow\ultracode\avorax-hardening\results\installed-cancel-scan.json
```

The wrapper records `cancel_requested=true`, the absolute
`cancel_token_path`, `cancel_token_exists`, `token_under_data_root`,
`standard_eicar_string_written=false`, `defender_exclusion_required=false`,
`machine_wide_component_installation=false`,
`service_installation_attempted=false`, `process_kill_attempted=false`,
`external_process_kill_attempted=false`,
`pre_execution_blocking_claimed=false`, and
`persistent_monitoring_claimed=false`. This is cooperative cancel-token request
evidence. Running-scan observation is covered by local-core cancellation
regressions; installed UI/service cross-process cancellation E2E and kernel
pre-execution blocking remain separate verification items.

For release-binary local status/health from a shell, use the status wrapper.
It reports engine, self-test, service, guard, driver, monitor, IPC, and
limitation fields. Use `-RequireReady` when a degraded or unavailable status
should fail the command:

```powershell
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-status.ps1 `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-status.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-status.ps1 `
  -RequireReady `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-status-ready.json
```

The wrapper records `health_state`, `ready`, concrete `blockers`,
`standard_eicar_string_written=false`, `defender_exclusion_required=false`,
`machine_wide_changes=false`, `service_installation_attempted=false`,
`pre_execution_blocking_claimed=false`, `persistent_monitoring_claimed=false`,
and `kernel_driver_claimed=false`. It is status evidence only; missing services
or drivers are reported as limitations and blockers, not treated as installed
protection.

For release-binary file allowlist management from a local shell, use the
allowlist wrapper. Add and remove require explicit confirmation. The wrapper
uses a concrete allowlist JSON file and refuses fake in-memory persistence:

```powershell
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-allowlist.ps1 `
  -Action List `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-allowlist-list.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-allowlist.ps1 `
  -Action Add `
  -TargetPath C:\path\to\trusted-file.exe `
  -ConfirmAction `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-allowlist-add.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-allowlist.ps1 `
  -Action Remove `
  -AllowlistId ALLOWLIST_ENTRY_ID `
  -ConfirmAction `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-allowlist-remove.json
```

The wrapper records `standard_eicar_string_written=false`,
`defender_exclusion_required=false`, `machine_wide_changes=false`,
`service_installation_attempted=false`, `pre_execution_blocking_claimed=false`,
and `broad_root_allowlist_allowed=false`. This wrapper currently manages file
allowlist entries only; folder/hash allowlist support and installed UI/service
E2E remain separate verification items.

For release-binary quarantine management from a local shell, use the quarantine
wrapper. Manual quarantine requires a concrete target file and explicit
confirmation because it creates a quarantine record and removes the source file.
Rescan is detect-only and does not accept confirmation because it must not
restore or delete quarantine content. Restore and delete require explicit
confirmation and a concrete quarantine ID from `List`; delete is not secure
erase:

```powershell
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-quarantine.ps1 `
  -Action List `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-quarantine-list.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-quarantine.ps1 `
  -Action Quarantine `
  -TargetPath C:\path\to\suspicious-file.bin `
  -ThreatName "Manual quarantine" `
  -Engine "avorax-manual-quarantine-wrapper" `
  -ConfirmAction `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-quarantine-manual.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-quarantine.ps1 `
  -Action Rescan `
  -QuarantineId <id-from-list> `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-quarantine-rescan.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-quarantine.ps1 `
  -Action Restore `
  -QuarantineId <id-from-list> `
  -ConfirmAction `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-quarantine-restore.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-quarantine.ps1 `
  -Action Delete `
  -QuarantineId <id-from-list> `
  -ConfirmAction `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-quarantine-delete.json
```

The wrapper records `standard_eicar_string_written=false`,
`defender_exclusion_required=false`, `machine_wide_changes=false`,
`service_installation_attempted=false`, `pre_execution_blocking_claimed=false`,
`manual_quarantine_requires_confirmation=true`, `restore_during_rescan=false`,
`delete_during_rescan=false`, and `secure_erase_claimed=false`. The quarantine
wrapper smoke records `quarantine-wrapper-manual.json`, proves manual
quarantine without `-ConfirmAction` fails visibly, and proves confirmed manual
quarantine through `target\release\zentor_local_core.exe` creates a quarantined
record and `.avoraxq` payload using harmless fixture bytes. It also records
`quarantine-wrapper-path-guards.json`, proving missing manual targets, directory
targets, invalid quarantine IDs, and repo-escaping report paths fail before
report creation or quarantine mutation. It is a release-binary quarantine
management path, not proof of installed service/UI E2E, persistent protection,
or secure deletion.

The Flutter Quarantine tab also exposes `Quarantine file`. That control is
confirmation-gated before opening the OS file picker, refuses scan,
configuration, update-package, target-selection, and quarantine mutation busy
states, and sends local-core `quarantine_file` IPC with `threat_name=Manual
quarantine` and `engine=avorax-ui-manual-quarantine`. The full small-threat MVP
verifier now runs `Flutter manual quarantine IPC tests` plus the quarantine
controller/screen tests, and the report validator rejects full-suite evidence
without that IPC step. This is widget/controller/IPC proof; installed packaged
filesystem picker click-through remains partial.

For a finite best-effort user-mode watch scan using the release local-core
binary, use the watch-scan wrapper. It requires explicit watched directories,
is detect-only by default, and intentionally runs for a bounded duration rather
than claiming persistent service or kernel blocking behavior:

```powershell
cargo build --release --manifest-path core\zentor_local_core\Cargo.toml

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-watch-scan.ps1 `
  -Path C:\Users\Brent\Downloads `
  -DurationSeconds 8 `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-watch-scan.json

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-watch-scan.ps1 `
  -Path C:\Users\Brent\Downloads `
  -DurationSeconds 8 `
  -AutoQuarantineConfirmed `
  -ReportPath .workflow\ultracode\avorax-hardening\results\local-watch-scan-quarantine.json
```

The wrapper records `mode=finiteUserModePolling`,
`persistent_monitoring_claimed=false`,
`pre_execution_blocking_claimed=false`, `kernel_driver_required=false`,
`service_installation_attempted=false`, and
`broad_default_watch_roots_allowed=false`. It rejects missing `-Path`, broad
roots, reparse points, and out-of-range duration/poll/event limits. It is useful
for safe local validation of small-threat watch behavior, not proof of installed
background service monitoring, scheduled startup, or pre-execution blocking.

The watch wrapper smoke intentionally uses `-DurationSeconds 8` and waits
`2500ms` before writing the harmless fixture so the release-binary watcher has
time to establish its baseline before event generation. Checkpoint 2148 also
adds `Flutter timeout process-tree cleanup tests`; the Windows timeout paths use
the checked local `taskkill.exe /PID <pid> /T /F` only for Avorax-spawned helper
children and then verify the injected hung Dart fixtures have exited. Full-suite
reports must include `Flutter timeout process-tree cleanup guards`, and the
validator rejects reports that omit that evidence.

Checkpoint 2149 extends the same watch wrapper smoke with
`watch-scan-wrapper-path-guards.json`. The guard report proves missing watched
paths, missing roots, file paths used as watch roots, broad filesystem roots, and
report paths outside the repository all fail before watch polling or report
creation. Full-suite reports must include
`watch scan wrapper finite release-binary path/report guard smoke`.

Checkpoint 2150 extends the status, allowlist, and cancel-scan wrapper smokes
with `status-wrapper-path-guards.json`, `allowlist-wrapper-path-guards.json`, and
`cancel-scan-wrapper-path-guards.json`. The reports prove missing engine roots,
unconfirmed allowlist mutations, missing/conflicting cancel data-root choices,
and report paths outside the repository fail visibly without writing requested
negative reports. Outside-repository cancel-report rejection must also leave the
`cancel-active-scan` token absent. Full-suite reports must include all three
`status wrapper`, `allowlist wrapper`, and `cancel scan wrapper` release-binary
`path/report guard smoke` scopes.

Checkpoint 2151 replaces installed-smoke core health substring matching with
`tools/windows/avorax-core-health-probe.ps1`. The focused
`run-avorax-installed-core-health-probe-smoke.ps1` rejects seven malformed or
unsafe response cases and probes the real release local-core binary. Full-suite
reports must contain `Installed smoke structured core-health probe tests` and
the `installed smoke structured core-health parser/probe guards` scope. This is
release-binary parser/probe evidence; installed service/UI E2E remains blocked
until the release host prerequisites are available.

Checkpoint 2152 adds a complete isolated scan/quarantine/list/restore/delete
probe for the canonical local-core executable:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-installed-core-lifecycle-probe.ps1 `
  -LocalCorePath target\release\zentor_local_core.exe `
  -EvidenceRoot . `
  -ReportPath .workflow\ultracode\avorax-hardening\results\installed-core-lifecycle.json
```

The probe uses only harmless ASCII exact-hash fixtures, isolated runtime roots,
and the real local-scan/quarantine wrappers. It requires `.avoraxq` payload
creation, list consistency, restored SHA-256 equality, payload removal after
restore/delete, source absence after delete, and verified temp cleanup. Full
reports must contain `Installed core lifecycle probe release-binary smoke`, the
`installed core scan/quarantine/restore/delete lifecycle probe` scope, and a
schema-valid `generated_reports.installed_core_lifecycle`. This is executable
and wrapper stdio evidence, not installed Windows service IPC or UI click-through
proof.

## Portable Small-Threat Beta

Build the non-installing beta from the canonical release core:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\build-avorax-portable-beta.ps1 `
  -RepoRoot C:\Users\Brent\Documents\Avorax-main `
  -Version 0.1.0-beta.1 `
  -LocalCorePath target\release\zentor_local_core.exe `
  -ReportPath .workflow\ultracode\avorax-hardening\results\2153-portable-beta-build-report.json `
  -ReplaceExisting
```

Verify the final ZIP after bounded extraction, manifest hashing, ready-state
probing, and the harmless scan/quarantine/restore/delete lifecycle:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\testing\run-avorax-portable-beta-smoke.ps1 `
  -RepoRoot C:\Users\Brent\Documents\Avorax-main `
  -ArchivePath dist\Avorax-Portable-Beta-0.1.0-beta.1.zip `
  -ReportPath .workflow\ultracode\avorax-hardening\results\2153-portable-beta-archive-smoke.json
```

Checkpoint 2153 passed with `39` manifested files, `13` signatures, `9` rules,
native self-test success, and matching build/smoke archive SHA-256
`a80155373a869576dad6d015c21221a18815bf3318a253a11c19477af128240b`.
The archive smoke rejected parent traversal, case-insensitive duplicate paths,
excessive compression ratio, and a tampered manifest hash, then removed its
temporary roots. Run source contracts with:

```powershell
& 'C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  tools\testing\run-python-source-contracts.py tests\test_custom_driver_contract.py
```

Result: `582` tests passed. This verification does not claim an installed UI,
service, persistent monitor, signed archive, driver, Defender replacement, or
pre-execution blocking.

## Dart protocol package

```bash
cd packages/zentor_protocol
'/c/Users/Brent/develop/flutter/bin/dart.bat' test

cd ../avorax_protocol
'/c/Users/Brent/develop/flutter/bin/dart.bat' analyze
'/c/Users/Brent/develop/flutter/bin/dart.bat' test
```

`packages/avorax_protocol` covers shared update manifest parsing/defaults/serialization for `.aup` verifier and app compatibility.

## Release/build gates

Run these before tagging or shipping an installer when the required Windows/PowerShell environment is available:

```bash
powershell.exe -ExecutionPolicy Bypass -File tools/branding/branding-check.ps1
powershell.exe -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1
powershell.exe -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1 -RepoRoot . -PythonPath C:\path\to\python.exe
powershell.exe -ExecutionPolicy Bypass -File tools/security/avorax-dependency-evidence.ps1 -RepoRoot . -ReportPath dist\dependency-evidence.json
powershell.exe -ExecutionPolicy Bypass -File tools/security/zentor-false-positive-gate.ps1 -CargoPath C:\path\to\cargo.exe
powershell.exe -ExecutionPolicy Bypass -File tools/security/zentor-protection-gate.ps1 -RepoRoot . -SelfTestReport <selftest_report.json> -CargoPath C:\path\to\cargo.exe
powershell.exe -ExecutionPolicy Bypass -File tools/perf/zentor-performance-gate.ps1 -RepoRoot . -CargoPath C:\path\to\cargo.exe -PythonPath C:\path\to\python.exe
powershell.exe -ExecutionPolicy Bypass -File tools/windows/zentor-release-gate.ps1 -CargoPath C:\path\to\cargo.exe -PythonPath C:\path\to\python.exe -FlutterPath C:\path\to\flutter.bat
```

The no-malware-binaries gate intentionally refuses ambient `python` lookup. Set `AVORAX_PYTHON` or pass `-PythonPath` with an absolute local Python executable.
The dependency-evidence gate performs source-level pin/lockfile/wrapper-hash checks without launching ambient package managers. It also emits source-level lockfile package/integrity summaries and a partial license-inventory block that keeps `full_release_sbom_required=true` until a release host produces complete SBOM/license output from final artifacts. It fails release mode when required lockfiles are missing; `-AllowKnownBlockers` is only for explicitly partial local reports, and reports with remaining blockers set `partial=true`.
The false-positive and protection gates intentionally refuse ambient `cargo` lookup. Set `CARGO` or pass `-CargoPath` with an absolute local Cargo executable.
The performance gate intentionally refuses ambient `cargo` and `python` lookup. Pass both `-CargoPath` and `-PythonPath`, or set `CARGO` and `AVORAX_PYTHON`. Performance target parameters must be between 1 and 60000 milliseconds; invalid target evidence fails the gate.
The top-level Windows release gate runs the dependency-evidence gate in release mode, forwards explicit `-CargoPath`, `-PythonPath`, and `-FlutterPath` values to its toolchain subgates, refuses ambient `cargo`, `python`, or `flutter` lookup, and validates trusted gate paths as local non-reparse paths including existing parent directories.
Release-gate JSON evidence also uses strict boolean checks for driver `communication_port_ok` and AI model `production_ready`; string values are schema failures, not truthy release approval.
The Windows MSI builder applies the same strict JSON boolean validation to AI model `production_ready` before allowing production packaging or explicitly development-model packaging.
The ZNE release gate validates native ML/signature/rule metadata as typed JSON evidence: `production_ready` is boolean, `pack_sha256` is a 64-character SHA-256 hex string, and signature/rule counts are positive integers. The shell variant also refuses ambient Python and requires `AVORAX_PYTHON`.
The installer stage test validates the release self-trust manifest as typed JSON evidence: safe relative paths, 64-character SHA-256 hashes, non-negative byte counts, no duplicate manifest paths, and hash/byte-count matches against the actual staged files.
The installed smoke test applies the same release self-trust manifest checks against the installed files before accepting installed-layout evidence.
The update package builder writes its manifest and update feed through checked atomic UTF-8 staging, treats signer commands as explicit token arrays, and accepts PowerShell signer scripts that create a regular `manifest.sig` without a native exit code.

For a fast Windows release-host readiness check after installing tools, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\windows\avorax-release-prereq-check.ps1 `
  -RepoRoot C:\Users\Brent\Documents\Avorax-main `
  -DotnetPath 'C:\Program Files\dotnet\dotnet.exe' `
  -CargoPath 'C:\Users\Brent\.cargo\bin\cargo.exe' `
  -FlutterPath 'C:\Users\Brent\develop\flutter\bin\flutter.bat' `
  -HostOnly `
  -ReportPath .workflow\ultracode\avorax-hardening\results\release-prereq-host-refresh.json
```

Host-only mode skips missing release artifacts and reports only build-host
prerequisites. It still fails honestly for missing .NET SDKs, unavailable
Windows symlink support, and missing Visual Studio Desktop C++ components.

The small-threat MVP verifier captures that same readiness state through a
ready-or-blocked evidence wrapper:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\testing\run-release-prereq-host-evidence.ps1 `
  -RepoRoot C:\Users\Brent\Documents\Avorax-main `
  -CargoPath 'C:\Users\Brent\.cargo\bin\cargo.exe' `
  -FlutterPath 'C:\Users\Brent\develop\flutter\bin\flutter.bat' `
  -ReportPath .workflow\ultracode\avorax-hardening\results\small-threat-mvp-release-prereq-host.json
```

This wrapper is allowed to pass the MVP verifier only when the generated host
report is either fully ready or blocked with concrete actionable prereq errors.
It must not install tools, enable Developer Mode, change Windows settings,
weaken Defender, or claim Windows release packaging. Full-suite reports must
include `generated_reports.release_prereq_host`, the `Release host prerequisite
ready-or-blocked evidence` step, and the matching verification-scope text.

The performance gate also runs `tools/perf/avorax-benchmark.py`, which writes `dist/performance/benchmark_report.json`. The harness uses harmless synthetic files, existing Rust test commands, and a non-elevated update-copy simulation. It is useful for trend tracking but does not replace signed-driver latency tests or elevated update-service apply benchmarks.

CI now runs the product-copy, no-malware-binaries, false-positive, protection, and performance gates. The small-threat MVP verifier also runs the branding gate before product-copy/security gates so active source/doc branding drift fails the repeatable MVP sweep. The CI protection gate uses a synthetic non-driver self-test fixture and does not claim kernel driver validation; driver-feature release gates still require a real signed/installed/self-tested driver report. The small-threat MVP verifier uses the same boundary for its protection gate step: no `-DriverFeatureEnabled`, `driver.running=false`, and no pre-execution blocking claim.
Protection self-test report fields must be JSON booleans set to `true`; string values such as `"true"` or `"false"` are rejected as schema failures and do not count as passing evidence.

`tools/testing/verify-small-threat-mvp.ps1` writes a structured JSON report by
default to
`.workflow/ultracode/avorax-hardening/results/small-threat-mvp-verification-report.json`.
Use `-ReportPath <repo-child.json>` to choose a different repo-contained report
path. Paths outside the repository are rejected before the sweep starts.
After writing a success report, the small-threat MVP verifier runs
`tools/testing/validate-small-threat-mvp-report.ps1` automatically. Full
Rust/Flutter runs without `-IncludeDefenderEicar` use the validator's
`-RequireFullSuite` mode; skip runs use structural validation only.
Validate an existing report with
`tools/testing/validate-small-threat-mvp-report.ps1 -RepoRoot . -ReportPath .workflow/ultracode/avorax-hardening/results/small-threat-mvp-verification-report.json`.
Add `-RequireFullSuite` when the report is expected to represent the full
Rust/Flutter MVP sweep. The validator checks schema, status, timestamps,
tool-path fields, generated report paths, passed-step evidence, scope text, and
failure semantics; it rejects misleading reports such as `passed` with no steps
or `failed` with no error.

Small-threat MVP reports use schema version 2. Every passed step has
`error=null`. An invoked command failure is recorded once as the terminal
`status=failed` step with the same bounded error as the top-level report and
`failure_kind=step`; a failure outside `Invoke-Step` uses
`failure_kind=orchestration` and has no failed step. Run the benign focused
regression with checked local tool paths:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/testing/run-small-threat-mvp-failed-step-report-smoke.ps1 -RepoRoot . -PythonPath C:\path\to\python.exe -FlutterPath C:\path\to\flutter.bat -DartPath C:\path\to\dart.bat -PowerShell7Path C:\path\to\pwsh.exe
```

The smoke intentionally uses that Python executable as the nested verifier's
Cargo host so the first command fails without creating or executing a candidate
fixture. Both PowerShell hosts must accept the authentic failure report and
reject missing, non-terminal, and errorless failed-step mutations.

Some service/driver/update gates may require elevation or a signed installed driver. If they cannot run, document the blocker in `RUN_LOG.md` and do not claim the gated capability as verified.

Current Windows limitation: `cargo test --manifest-path core/avorax_update_service/Cargo.toml` and `--bin avorax_update_service` can fail before running tests with Windows error 740 because the update-service test binaries inherit a require-administrator manifest. In a non-elevated shell, use `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bin avorax_update_service` plus `uv run pytest tests/test_custom_driver_contract.py -q`, or rerun the Rust unit tests from an elevated developer shell. The static contract test also checks that update apply attempts rollback restoration and service restart on payload-copy failure; elevated integration tests are still needed for real service stop/start/apply paths.

## Checkpoint 2254 ZIP EOCD cancellation

The focused benign runtime filter is:

```powershell
cargo test --manifest-path core/zentor_native_engine/Cargo.toml `
  zip_eocd_cancellation_ -- --test-threads=1
```

It must pass exactly three tests: central-directory sample cancellation,
central-directory static-analysis cancellation, and valid long-comment
compatibility. Source contracts must then pass exact `684/684`. A complete
definitive report for this revision must pass exact `283/283` and include
`native-engine ZIP EOCD search cancellation regressions` plus the exact
verified and technical-limit scope enforced by the independent PS5/PS7
validator. No checkpoint-2254 command in this section has run during the
scripting phase.

Focused checkpoint-2254 results now pass exact EOCD `3/3`, complete ZIP
`45/45`, adjacent cancellation `4/4 + 4/4 + 4/4`, Source `684/684`, and PS5/PS7
parser `2/2` each. Formatting and diff hygiene pass after one layout-only
repair. These results do not replace full Native/Local/Flutter/Dart regression
or definitive exact `283/283` verification.

Broad checkpoint-2254 regression now passes both locked workspace variants,
Native `635/635` plus compiler `6/6`, Local Core `546/546`, Platform Security
`9/9`, updater `203/203`, Flutter `847/847` with clean analysis, Dart protocol
`14/14`, locked/offline Native check, locked release workspace build, and
strict Native/Local/Guard Clippy. Exact `283/283` definitive verification and
independent hostile report validation remain mandatory.

Definitive checkpoint-2254 verification now passes exact `283/283` in `837.4s`
under both built-in and independent PS5/PS7 validation. Missing-step and
missing-scope mutations are rejected. Exact implementation-head CI and desktop
packages pass on Windows, Linux, and both macOS architectures with publication
skipped; the untouched consolidated artifact passes bounded non-extracting
`8/6/7/CycloneDX-1.6/569` validation.

Checkpoint-2254 closure additionally passes evidence-head and merged-main CI/
packages, corrected guarded `13/13` destination synchronization, destination
PS5/PS7 parser `2/2`, formatting, Source `684/684`, EOCD `3/3`, and definitive
destination `283/283` in `702.4s`. The destination report SHA-256 is
`13e7ad30df65a3e85ae9747627b1687c91aa54930cb6e3403fa5dd5c2377f981`.

## Checkpoint 2255 Scripted Coverage

Checkpoint 2255 adds three benign PE resource cancellation regressions under
`pe_resource_section_cancellation_`: chunk interruption, valid resource-count
compatibility, and exact parser-level callback-error propagation. Definitive
verification now has 284 required steps and Source contract 685. These tests and
contracts are scripted but have not run in this phase; no pass claim is made
until focused, broad, definitive, and independent validation complete.

Checkpoint 2255 local verification now passes focused `3/3`, full PE resource
`6/6`, Source `685/685`, dual-host syntax, both locked workspace suites, strict
Clippy/offline/release builds, Flutter `847/847`, and Dart `14/14 + 6/6`.
Definitive verification passes exact `284/284` in `695.9s`; separate PS5/PS7
validation passes and isolated missing-step/missing-scope reports are rejected.
The definitive report SHA-256 is `ff8411143e5437e15266c87e789c02d3d5c151a701543651aab3f7e297de7d3b`.

Exact implementation `67f2d26` also passes hosted CI `33117139169` and package
runs `33117139213`/`33117116754`, with all platform and consolidation jobs
green and publication skipped. Untouched consolidated artifacts
`9665343047`/`9665714554` match GitHub digests and each pass bounded,
non-extracting exact 8-entry/6-package/7-checksum/CycloneDX-1.6/569-unique-ref
validation. Evidence-head, integration, merged-main, guarded synchronization,
and destination reruns remain required.

Checkpoint-2255 closure additionally passes evidence-head and merged-main CI/
packages, guarded `13/13` destination synchronization, destination PS5/PS7
parser `2/2`, formatting, Source `685/685`, cancellation `3/3`, and definitive
destination `284/284` in `667.7s`. The destination report SHA-256 is
`853db9a32a3e18f1b8704d9965bf60ab56f52f89f2c280a828278ac73cfade58`.

## Checkpoint 2256 Scripted Coverage

Checkpoint 2256 adds Local Core file discovery `file_discovery_` regressions for cancellation
before the next at-most-128-entry chunk, callback-error propagation, explicit
file-limit failure, a cancelled scan report before Native Engine startup, and a
malformed job-token error. All fixtures are ordinary benign text and are never
executed.

Definitive verification now requires 285 steps, including `local-core
file-discovery cancellation and bounds regressions`; Source contract 686 binds
the source, tests, validator, and docs. No Checkpoint 2256 test has run during
the scripting phase. Required order is focused parser/format/source and Cargo
checks, broad locked and all-features regression, exact `285/285` verification,
independent/hostile validation, hosted exact-head evidence, normal integration,
guarded destination sync, and destination reruns.

Checkpoint 2256 focused results: PS5/PS7 parser `2/2` each, rustfmt and diff
check pass, Source contract `686/686`, file discovery `5/5`, walker `10/10`,
full scan `3/3`, cancellation `8/8`, and Local Core `551/551`. The first Local
Core attempt was `550/551` due only to an obsolete indentation-sensitive source
marker; the strengthened semantic-order assertion passes `1/1` before the clean
full rerun. Definitive verifier `285/285` and later evidence remain pending.

Broad and definitive Checkpoint 2256 results supersede that pending statement:
standard/all-features locked workspace tests, strict Local Core Clippy, locked
release build, Flutter `847/847`, Dart `14/14` and `6/6`, and exact `285/285`
pass. Independent PS5/PS7 validators accept the 206,090-byte report, SHA-256
`74681a86670805ffeb23b9903a7f5cd70a0c008b91bbe7aff7ab256228b23f33`,
and both reject missing-step and missing-scope mutations. The three lock hashes,
zero product processes/residue, and protected-vault invariant remain exact.
Hosted exact-head, integration, guarded synchronization, and destination reruns
remain required for checkpoint closure.

Checkpoint 2256 exact implementation head `75a9620` additionally passes PR CI
`33128336666` and PR/push package runs `33128336642`/`33128313733`. Both
consolidated artifacts pass bounded non-extracting 8/6/7/CycloneDX-1.6/569
review and publication is skipped. Exact evidence-head reruns, merged-main,
guarded destination synchronization, and destination verification remain
required for closure.

Checkpoint-2256 closure additionally passes evidence-head and merged-main CI/
packages, bounded non-extracting review of artifacts `9670029088` and
`9670342529`, guarded `13/13` destination synchronization, destination PS5/PS7
parser `2/2`, formatting, Source `686/686`, focused discovery `5/5`, and exact
destination `285/285` in `649.5s`. The destination report contains zero failed
or non-null-error steps and has SHA-256
`2e71dd42a28345c602580bf70297a862f010a516873ae81cf6a074436dd5734f`.
No candidate fixture or package was extracted, installed, or executed.

## Checkpoint 2257 Scripted Coverage

Checkpoint 2257 adds five benign `file_discovery_memory_` tests: encoded
path-payload exhaustion and checked-add overflow are fail-visible; three-bucket
priority ordering remains stable; cancellation at the second at-most-128-path
checkpoint retains all 300 in-memory path values; and an arbitrary callback
error propagates exactly. No candidate file is executed.

Source contract 687 binds the 8 MiB Quick and 128 MiB Full/Custom payload caps,
checked byte accumulation before path retention, limit/error wiring, absence of
the old `sort_by_key`, the five regressions, verifier step 286, exact `286/286`
validator cardinality, scope claims, and all checkpoint docs. No Checkpoint
2257 test ran during scripting. Focused checks began only after this entire
batch; broad and definitive/adversarial local verification now pass. Hosted
exact-head evidence, integration, guarded synchronization, and destination
reruns follow.

Checkpoint 2257 focused results: PS5/PS7 parser `2/2` each, final rustfmt and
diff checks, Source `687/687`, new path-memory `5/5`, discovery `10/10`, walker
`15/15`, Full Scan `3/3`, scan cancellation `8/8`, Local Core `556/556`, and
strict all-target/all-feature Clippy pass. The first rustfmt check reported four
mechanical line wraps; `cargo fmt --all` and the repeat check pass. No live
malware or candidate execution was used. Broad and definitive local suites now
pass; hosted evidence, integration, guarded sync, and destination reruns remain
required.

Checkpoint 2257 broad results: standard and all-feature locked Rust workspace
tests pass, as does the locked all-feature release build. Native Engine reports
638 passed / 21 intentionally ignored child fixtures and Local Core `556/556`
in each variant. Flutter passes `847/847`; Zentor and Avorax protocols pass
`14/14` and `6/6`; all analyzers are clean. Lockfiles remain unchanged.

Checkpoint 2257 definitive results: exact `286/286`, zero failed/error steps,
and `643.3s`. The canonical report is 207,098 bytes with SHA-256
`b989a2cc9d0d42a0a7404e6d778c97617ad449af8ddef520c6b732d3ce3d1833`;
Defender/EICAR host integration remained disabled by default. Independent PS5
and PS7 strict validation pass. Both hosts reject each structured 285-step,
missing-verified-scope, and missing-technical-scope mutation with exit 1, and
owned mutation residue is zero. Hosted evidence, integration, guarded sync, and
destination reruns remain required.

Checkpoint 2257 hosted implementation-head results: exact commit `c3e24b3`
passes CI `33136854819`, PR packages `33136854871`, and push packages
`33136852044`; prerelease publication is skipped. Consolidated artifacts
`9672658548` and `9672583268` match hosted byte counts and pass bounded,
non-extracting exact 8-root/6-package/7-checksum/CycloneDX-1.6/569-unique-ref
review. No package was extracted, installed, or executed and owned review
residue is zero. Evidence-head, merged-main, guarded-sync, and destination
evidence remain required.

Checkpoint 2257 closure results: evidence-head CI/packages and merged-main
CI/packages pass with publication skipped. Evidence and main artifacts pass the
same bounded non-extracting 8/6/7/CycloneDX-1.6/569 review. Guarded destination
sync passes `13/13` with zero delete or residue. Destination parsers, Source
`687/687`, formatting, focused `5/5`, lock hashes, and definitive exact
`286/286` pass. Independent PS5/PS7 validation accepts the 198,448-byte report,
SHA-256
`8c2d69538f3853efc0b17a86888776a1fab37297a29a39a0247bc8f7ea4e6ec2`.

Checkpoint 2258 adds the `resource_budget_` Local Core filter with six benign
tests: non-candidate work accounting, checked-counter overflow, zero-deadline
pre-I/O exit, cancellation-before-deadline precedence, deadline-safe priority
path retention, and inclusive Quick/Full/Custom total elapsed limits. Definitive
step 287 is `local-core scan discovery work and elapsed-budget regressions`; the
full-suite validator requires exact `287/287` and the new verified/technical
scope. Source contract 688 pins the complete batch.

No checkpoint-2258 test ran during scripting. After the scripting boundary, run
dual PowerShell parsing, formatting/diff checks, Source contracts, the new and
overlapping Local Core filters, complete Local Core/Clippy, locked workspace and
release builds, Flutter/Dart suites, definitive verification, dual-host
validation, structured adversarial report mutations, safety/lock gates, hosted
integration, and guarded destination synchronization. Never enable the optional
Defender/EICAR host integration for this checkpoint.

Checkpoint 2258 focused results now pass: PS5/PS7 parser `2/2` each, Source
`688/688`, formatting/diff checks, `resource_budget_` `6/6`, discovery `15/15`,
walker `20/20`, Full Scan `3/3`, cancellation `8/8`, Local Core `562/562`, and
strict all-target/all-feature Local Core Clippy. Broad results also pass both
locked Rust workspace variants, the locked all-feature release build, Flutter
analyze and `847/847`, plus clean Zentor/Avorax Dart analysis and `14/14` and
`6/6`. Definitive and later evidence are recorded below.

Checkpoint 2258 pre-final-diff definitive results passed exact `287/287`, zero
failed or non-null-error steps, in `712.7s`. The superseded report is 209,030 bytes with
SHA-256
`732ddae0269b7d1987d2b157fcd449ef092c684058a0d7c7c3ad89e333784c51`;
Defender/EICAR host integration remained disabled. Independent PS5 and PS7
strict validation pass. Both hosts reject each 286-step,
missing-verified-scope, and missing-technical-scope structured mutation with
exit 1; owned mutation residue is zero. Hosted, integration, guarded-sync, and
destination reruns remain required. Final review then added post-target and
zero-file elapsed checkpoints plus engine-unavailable skip isolation, so
final-source focused, broad Rust, and definitive evidence must be rerun.

Checkpoint 2258 final-repair focused and broad Rust reruns pass: formatting,
Source `688/688`, resource-budget `6/6`, Local Core `562/562`, strict Clippy,
both locked workspace variants, and the locked all-feature release build. In
both workspace variants Native Engine reports 638 passed / 21 intentionally
ignored isolated child fixtures and Local Core `562/562`. Final-source
definitive verification then passes exact `287/287`, zero failed/non-null-error
steps, in `633.1s`, with optional Defender/EICAR host integration false. The
209,024-byte report has SHA-256
`7d26d4ae9327a4b186462dbe894222b65702975fb8334ea7e5465ce37cd595bd`.
Independent PS5/PS7 strict validation passes; both hosts reject the 286-step,
missing-verified-scope, and missing-technical-scope mutations with exit 1. Exact
owned mutation residue is zero. Hosted, integration, guarded-sync, and
destination evidence remain required.

Late final review then found two related honesty edges: EngineUnavailable could
publish final 100-percent progress, and cancellation arriving during the final
metadata/inspection operation could lack a next loop iteration for observation.
Implementation, the existing benign regression, verifier/validator scope,
Source contract, and documents were updated as one batch before another test.
The preceding `287/287` report is superseded; final-source focused, broad,
definitive, adversarial, hosted, integration, guarded-sync, and destination
evidence must be rerun.

The first post-scripting `resource_budget_` command failed during compilation,
before any test ran, because the new zero-file cancellation diagnostic supplied
`&str` where the bounded error helper requires `String`. The source now performs
the explicit conversion. This failed attempt is not credited; the focused filter
and all later suites must pass on the repaired source.

On the repaired source, PS5/PS7 parser checks pass `2/2` each, Source passes
`688/688`, resource tests pass `6/6`, Local Core passes `562/562`, strict Clippy
passes, both locked workspace variants pass, and the locked all-feature release
build passes. Native Engine reports 638 passed / 21 intentionally ignored
isolated child fixtures in each workspace variant. The final no-skip/no-Defender
verifier passes exact `287/287`, zero failed/non-null step errors, in `638.5s`.
Its 209,286-byte report has SHA-256
`401d4d4cb50dc7a61750ae26b7de529df3f2033063d3915649c4717aa6c78208`.
Independent PS5/PS7 strict validation passes and both hosts reject all three
structured mutations with exit 1; exact mutation residue is zero. Hosted,
integration, guarded-sync, and destination evidence remain required.

Final progress review then found that a zero total-byte estimate could produce
100 percent before retained zero-byte files were inspected. The shared progress
calculator, existing `resource_budget_` regression, verifier/validator scope,
Source contract, and documents were updated as one complete batch before any
new test. Running progress now uses file-count fallback for retained zero-byte
files and stays indeterminate for zero retained files. The preceding `287/287`
report is superseded; final-source focused, broad, definitive, adversarial,
hosted, integration, guarded-sync, and destination evidence must be rerun.

On the final zero-byte-repaired source, formatting, PS5/PS7 parser checks,
Source `688/688`, resource-budget `6/6`, Local Core `562/562`, strict Clippy,
both locked workspace variants, and the locked all-feature release build pass.
The definitive no-skip/no-Defender verifier passes exact `287/287`, zero failed
or non-null-error steps, in `634.4s`. Its 209,503-byte schema-2 report has SHA-256
`078a4edc9a25aed4ab572936c0d34629152af0f4c0ee633e6e5a7a2c2177cad0`.
Independent PS5/PS7 strict validation passes; both hosts reject the 286-step,
missing-verified-scope, and missing-technical-scope copies with exit 1. Exact
mutation residue is zero. Hosted, integration, guarded-sync, and destination
evidence remain required.

Exact implementation `709e8a9d56f89dd13b8e296334b187ff2a99d6f2`
passes PR `#125` CI `33149543048`, PR packages `33149543030`, and push packages
`33149509580`; both publication jobs are skipped. Consolidated artifacts
`9677471939` and `9677431721` match GitHub byte size/SHA-256 and each pass bounded
non-extracting exact 8-root/6-package/7-checksum/CycloneDX-1.6/569-unique-ref
review with zero unsafe, duplicate, encrypted, directory, or link entries. No
artifact was extracted, installed, or executed and owned review residue is zero.
Evidence-head, merged-main, guarded-sync, and destination testing remain required.

Checkpoint 2258 closure evidence now passes. Evidence-head CI/packages and
merged-main CI/packages pass with publication skipped; all four consolidated
artifacts pass bounded non-extracting exact 8-root/6-package/7-checksum/
CycloneDX-1.6/569-unique-ref review. Guarded destination sync passes `14/14`
with 13 modifications, one addition, zero deletes, 7,588,496 staged bytes, and
zero residue. Destination parsers, Source `688/688`, formatting, resource
`6/6`, Local Core `562/562`, and strict Clippy pass. The destination no-skip/no-
Defender verifier passes exact `287/287` in `698.5s`; independent PS5/PS7
validators accept the 200,845-byte report with SHA-256
`70ff765a95fd881aafd11255d2a92cb22bff9f447efecdc222a777fa93cdb379`.
All locks and the read-only protected vault remain exact. Checkpoint 2258 is
closed, while product-level kernel, service/driver, production, pre-execution,
and Defender-replacement verification remains open.

Checkpoint 2259 preserved the scripting boundary: implementation, four benign
regressions, verifier/validator changes, Source contract 689, and docs were
completed before any new test command. The focused
`scan_inspection_resource_budget_` filter passes `4/4`; Native content and
cancellation overlaps pass `3/3` and `61/61`, while Local resource and
cancellation overlaps pass `8/8` and `14/14`. Source passes exact `689/689`,
Local Core `564/564`, Native Engine 640 passed / 21 intentionally ignored,
compiler `6/6`, and exact strict Clippy passes for both changed crates. Both
locked workspace variants, the locked all-feature release build, Flutter
analyze plus `847/847`, and both Dart analyzers plus `14/14` and `6/6` pass.

Definitive step 288 is `native/local in-target scan inspection resource-budget
regressions`. The no-skip/no-Defender verifier passes exact `288/288` in
`667.4s`; PS5/PS7 accept its 210,919-byte report with SHA-256
`aba47033b18eead7eca3c192b13c6f9c599743b768bce4c28fbd0b6ed0a7d224`.
Both hosts reject missing-step, missing-verified-scope, and missing-technical-
scope mutations with exit 1, and owned residue is zero. The root, Native, and
Flutter lock hashes and read-only 16,072-file vault remain exact. An additional
repo-wide Clippy command is not credited because three unchanged `services/api`
lints fail outside the official CI Clippy scope; changed-crate strict Clippy is
green. A mistaken `pytest` invocation ran no contract because the optional
module is not installed; it is uncredited, and the repository-owned dependency-
free Source runner passes exact `689/689`. Tests use harmless bytes and pure
boundary values; they neither allocate a 1 GiB fixture nor execute candidate
content. Hosted exact-head matrices, integration, guarded destination sync, and
destination evidence remain required.

Exact implementation `97e16e7b6e1051788f36bbd51e68b1e3890c5d0c` passes PR
`#127` CI `33160451724`, push packages `33160424802`, and PR packages
`33160451797`; both publication jobs are skipped. Consolidated artifacts
`9681909119` and `9681997334` match GitHub byte size/SHA-256 and each pass a
bounded non-extracting exact 8-root/6-package/7-checksum/CycloneDX-1.6/569-
unique-ref review. No artifact was extracted, installed, or executed, and owned
review residue is zero. Evidence-head CI/packages, normal merge, merged-main
evidence, guarded destination sync, and destination testing remain required.

Checkpoint 2259 closure evidence now passes. Evidence-head CI/packages and
merged-main CI/packages pass with publication skipped; both consolidated
artifacts pass bounded non-extracting exact 8-root/6-package/7-checksum/
CycloneDX-1.6/569-unique-ref review. Guarded destination sync passes `13/13`
with 12 modifications, one addition, zero deletes, 7,571,661 activated bytes,
and zero residue. Destination parsers, Source `689/689`, formatting, focused
`4/4`, Local Core `564/564`, and strict changed-crate Clippy pass. The
destination no-skip/no-Defender verifier passes exact `288/288` in `685.6s`;
independent PS5/PS7 validators accept the 202,267-byte report with SHA-256
`601d7eb11e5c6e09f917f4810f5d409f95b7ae15d2e8947c07b1eabcce482ab9`.
All locks and the read-only protected vault remain exact. Checkpoint 2259 is
closed, while hard OS-call preemption, exact kernel accounting, installed
service/driver, production, pre-execution, and Defender-replacement verification
remain open.

## Checkpoint 2260 - Scan Verdict Quarantine Binding

Checkpoint 2260 uses six harmless tests with the shared
`scan_quarantine_binding_` prefix. Run the focused batch only after the complete
checkpoint source/test/verifier/validator/document scripting boundary:

```powershell
cargo test --workspace scan_quarantine_binding_ -- --test-threads=1
```

The tests replace or rewrite only isolated temporary harmless text files. They
verify open-file identity, exact Native verdict SHA-256 binding, invalid-hash and
path rejection, no vault creation on preflight failure, current-file
preservation, and visible rescan-required diagnostics. Candidate fixtures are
never executed. The definitive verifier's existing `platform quarantine
permission regressions`, `local-core quarantine metadata regressions`, and
`guard-service quarantine metadata regressions` steps cover the same tests plus
existing Guard changed-hash coverage while keeping the expected full-suite
count at `288/288`.
Source contract 690 additionally pins call wiring, check ordering, both platform
identity representations, validator scope, documents, and dependency honesty.

This evidence does not prove atomic kernel mediation: a privileged final-check
path race may remain between the last identity comparison and rename/removal.
Post-move SHA-256 verification and authenticated recovery remain fail-visible.
No Defender weakening, machine-wide installation, service/driver start, live
malware, release, publication, or protected production-vault mutation is part
of these tests; changed files require an explicit rescan.

## Checkpoint 2261 - Manual Threat Quarantine Hash Binding

The complete implementation/test/verifier/document batch must exist before
running this focused benign regression:

```powershell
cargo test --manifest-path core/zentor_local_core/Cargo.toml manual_threat_quarantine_binding_ -- --test-threads=1
```

The four tests use only temporary harmless bytes. They prove changed scan-result
content remains in place with no vault creation, a matching SHA-256 succeeds
through real `quarantine_file` command handling, the separate hash-less manual
file-picker path keeps its fresh snapshot, and empty/whitespace-only/
oversized/NUL/malformed SHA-256 evidence fails before mutation.

The Flutter `manual quarantine IPC` filter proves a visible threat row sends
its exact SHA-256, the standalone picker omits it, and path/hash-mismatched
success records fail instead of updating controller state. The definitive
verifier adds `local-core manual threat quarantine hash-binding regressions` as
step 289; full-suite validation requires exact `289/289`, that step, and the
new verified-scope contract. Source contract 691 pins the complete boundary.

No checkpoint-2261 test ran during scripting. After that batch froze, focused
Local Core passed `4/4`, quarantine coverage `137/137`, Flutter Local Core IPC
`94/94`, offline controller coverage `27/27`, Source `691/691`, strict
all-feature Local Core Clippy, both locked workspace suites, the locked
all-feature release build, Flutter analyze and `849/849`, Zentor protocol
`14/14`, and Avorax protocol analyze plus `6/6`.

The definitive command used explicit checked tool paths, no skip switch, and no
Defender-EICAR integration switch:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File tools/testing/verify-small-threat-mvp.ps1 -RepoRoot <repo> -PythonPath <bundled-python> -CargoPath <cargo.exe> -FlutterPath <flutter.bat> -DartPath <dart.bat> -PowerShell7Path <pwsh.exe> -ReportPath .workflow/ultracode/avorax-hardening/results/2261-small-threat-mvp-manual-threat-quarantine-hash-binding-report.json
```

It passed exact `289/289`, zero failed/skipped, in `659.6s`. Both Windows
PowerShell 5.1 and PowerShell 7 independently accepted the authentic report
with `-RequireFullSuite` and rejected both a missing-required-scope and a
missing-required-step copy. The report SHA-256 is
`0074fd8b38a7edf01c132b4ac3ec0d6a8428ad738ebaaf09c985b4ccb59274a8`.

Exact implementation head `0f223dacf412876f3c0da27b3207fc23aa605741`
also passes Avorax CI `33187857398`, Desktop Packages dispatch/PR
`33187853083`/`33187857457`, and Desktop push `33187798963` attempt 2. Push
attempt 1 was cancelled by workflow concurrency and is retained as a non-pass.
All publication jobs were skipped. Three consolidated artifact ZIP streams pass
bounded non-extracting exact 8-entry/6-platform/7-checksum/CycloneDX 1.6/569-
component review; no installer was extracted or executed.

Evidence head `b66aaed3388139c19ff76385bf5ec5cc06adf219` and normal PR
`#131` integration passed. Merge `1877bbabaeb1fd6e6169d1ca3f92a9438185b3d4`
passed merged-main CI/packages. Guarded synchronization copied exactly 18
paths, changed 17, added one, deleted none, and preserved all eight lockfiles.

In `C:\Users\Brent\Documents\Avorax-main`, one broad locked Rust orchestration
is retained as failed because Defender removed the generated Native harness as
inactive `Trojan:Win32/Wacatac.C!ml` (`DidThreatExecute=False`), producing
Windows error 225 after Platform `11/11` and Local Core `572/572`. Defender was
not weakened. Isolated unchanged Native default/all-feature runs each passed
`640/640` with 21 intentional ignores, compiler passed `6/6`, both non-Native
workspace variants and the locked all-feature release build passed, Flutter
analyze and `849/849` passed, and protocols passed `14/14` and `6/6`.

The same definitive command in the destination tree passed exact `289/289`,
zero failed/skipped, in `651.5s`. Its 204,507-byte report SHA-256 is
`4b7f531dd61c0c7c00496ad331061d50161c9a6487f6b7ecd1046bb5e8bdcf25`.
Integrated and independent Windows PowerShell 5.1 and PowerShell 7 validators
accepted it with `-RequireFullSuite`. Final audit passed 18/18 synchronized
paths, 8/8 locks, zero sidecars/processes, and the exact protected vault.
Checkpoint 2261 is closed; the complete antivirus-hardening goal remains active.

Tests never execute candidate content and did not mutate the protected
production vault. The result remains user-mode/path-based and does not prove
atomic final path mutation, installed service/UI E2E, driver/kernel mediation,
pre-execution blocking, secure erase, production detection quality, or Defender
replacement.

## Checkpoint 2262 - Manual Trust-Mutation Hash Binding

The complete batch was scripted before execution. Scan-result allowlist and
detection-feedback requests now carry exact SHA-256 plus server-side explicit
confirmation; Local Core rejects malformed or changed evidence before storage;
and Flutter requires request-bound persisted success evidence. All fixtures are
ordinary temporary ASCII bytes and are never executed.

No checkpoint-2262 test ran during the scripting phase. After the scripting
batch froze, the focused checks used were:

```powershell
cargo fmt --all -- --check
cargo test --locked --manifest-path core\zentor_local_core\Cargo.toml manual_trust_mutation_binding_ -- --test-threads=1
flutter test test\local_core_ipc_diagnostics_test.dart
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "[void][scriptblock]::Create([IO.File]::ReadAllText('tools/testing/run-release-local-core-trust-mutation-binding-smoke.ps1'))"
pwsh.exe -NoLogo -NoProfile -NonInteractive -Command "[void][scriptblock]::Create([IO.File]::ReadAllText('tools/testing/run-release-local-core-trust-mutation-binding-smoke.ps1'))"
python -B tools\testing\run-python-source-contracts.py
```

Build the locked release Local Core before running
`tools/testing/run-release-local-core-trust-mutation-binding-smoke.ps1`. The
definitive verifier adds `release local-core binary trust-mutation hash-binding
smoke`; `-RequireFullSuite` requires exact `290/290`, zero failed/skipped, the
new step, and the new verified/technical-limit scope. Focused Local Core passed
`8/8`, IPC `97/97`, overlapping UI `238/238`, Source `692/692`, and release
smokes passed on PowerShell 5.1/7. Both locked Rust workspaces, all-feature
release build, Flutter analyze plus `852/852`, and protocol `14/14` plus `6/6`
passed. Definitive verification passed exact `290/290` in `621.9s`; both hosts
accepted the authentic report and rejected all six adversarial mutations.
Evidence/head CI/packages, normal PR integration, merged-main CI/packages, and
bounded non-extracting package review passed with publication skipped.

Guarded destination synchronization applied exact 26 paths: 24 modified, two
added, zero deleted. Destination Source `692/692`, focused Local Core `8/8`, IPC
`97/97`, strict all-feature Clippy, both-host release smoke, both locked Rust
workspaces, all-feature release, Flutter analyze/`852/852`, and both protocol
suites passed. A first destination verifier attempt stopped after 39 passes
because Defender removed the generated Native harness before execution as
inactive `Trojan:Win32/Wacatac.C!ml` with `DidThreatExecute=False` (error 225).
Defender was not weakened; failed report SHA-256 is
`1713a3c856c5d8d860b04021c5011485042119b3649e184ec62a0828b08b0032`.
A fresh isolated target passed `4/4`; the complete verifier then restarted and
passed exact `290/290`, zero failed/skipped, in `728.3s`. Integrated and
independent PS5/PS7 validators accept its 206,462-byte report with SHA-256
`dd2471f176fca7c3138198cb52e034d539e5a4808ffb2ae5b9d2e759301c8cea`;
all six destination adversarial mutations reject. Final audit passes 26/26
paths, 8/8 locks, zero sidecars/processes, and the exact vault.
The protected production vault is never a test root. No live malware, fixture
execution, Defender weakening, installation, service/driver start, release, or
publication is permitted. Checkpoint 2262 is closed; the full goal remains open.

## Checkpoint 2263 Scripted Verification

No checkpoint-2263 test ran during the scripting phase. After the batch is
frozen, run formatting and parser checks, focused platform and Local Core
`quarantine_restore_no_replace` regressions, the safe quarantine/restore smoke,
source contracts, strict lint, locked workspaces, client/protocol regression,
release builds, and the definitive verifier. Full report validation now
requires exact `291` steps including `quarantine restore atomic no-replace
regressions`, plus the verified no-replace scope and its ancestor-race limit.
Only harmless temporary ASCII fixtures are permitted; the production vault is
never a test root.

After that freeze, Source `693/693`, focused Platform `2/2`, focused Local Core
`1/1`, safe restore collision smoke, strict changed-crate Clippy, both locked
Rust workspace suites, the all-feature release build, Flutter analyze/`852/852`,
and protocol `14/14` plus `6/6` passed. The definitive verifier passed exact
`291/291`, zero failed/skipped, in `666.2s`; its 216,409-byte report SHA-256 is
`92360dc643cb81f8e4c4eb1bdcd181a1c705870524d29213bf842a44f5e61f3b`.
PS5/PS7 full-suite validation passed, the authentic report was accepted twice,
and all six adversarial missing-step/scope/limit mutations rejected. The first
format/source/parser-wrapper findings and the first adversarial stderr-capture
failure are retained as tooling preparation evidence; corrected checks reran
from the beginning. No product process or smoke root remains and the protected
vault is exact. Hosted, merge, guarded-sync, and destination execution remains
pending.

Implementation-head hosting now passes CI `33218470626` and package push/PR
`33218432833`/`33218470623` at exact SHA
`db43c763cd2094f467983b5fe9262c847dcf2a2b`; both publication jobs skip.
Untouched consolidated artifacts `9704536389` and `9704698986` pass bounded
stream validation with exact 8 roots, 6 packages, 7 checksums, and CycloneDX
1.6 / 569 components. Their outer SHA-256 values are
`93b68faf96a312a0f2abe7f61ffc12ebbd6e3425f59d7a1d2b7274e2f0d57d32`
and `c3696035a78047c3dfbe88b37bea0b2a332a15fccd4c6928561f8f8e6100aae5`;
neither ZIP is extracted or executed. PR `#135` merges normally as
`ed0484a605c7f5cc7a62d8c2dd8459ee969cec57`. Closure-head, merged-main,
guarded-sync, and destination tests remain pending.

The historical checkpoint-2263 pending status above is superseded: merged-main
CI/packages, bounded artifact review, guarded zero-delete synchronization,
destination Source `693/693`, exact `291/291`, both validators, all six
adversarial mutations, and final exact-state audit pass. See the checkpoint
report for commit, run, artifact, and digest evidence.

## Checkpoint 2264 Scripted Verification

No checkpoint-2264 test ran during the scripting phase. After the entire batch
is frozen, begin with:

```powershell
cargo fmt --all -- --check
python -B tools\testing\run-python-source-contracts.py
cargo test --workspace quarantine_ingest_no_replace -- --test-threads=1
```

The focused workspace filter must run exactly the Local Core, Guard, and Native
compatibility collision fixtures. Then run strict changed-crate Clippy, both
locked workspaces, all-feature release, Flutter/client/protocol regressions,
safe quarantine/restore smoke, and the definitive verifier. Full-suite report
validation requires exact `292` steps including `quarantine ingest atomic
no-replace regressions`, plus the ingest verified and technical-limit scope.
Only harmless temporary ASCII fixtures may be used; never execute them or use
the protected production vault as a test root.

The frozen batch has now passed formatting, dual-host script parsing, Source
`694/694`, focused collision `3/3`, broader quarantine filters, strict
all-feature Clippy for all three changed crates, both locked workspace suites,
locked all-feature release, safe quarantine/restore smoke, Flutter analyze and
`852/852`, and protocol analyze/tests `14/14 + 6/6`. Broad workspace Clippy is
recorded as non-passing because untouched `services/api` triggers Rust 1.96
`items_after_test_module` and `enum_variant_names`; this checkpoint does not
hide or broaden itself to repair that unrelated crate. Definitive exact-292 now
passes `292/292`, zero failed/skipped, in `659.4s`; independent PS5/PS7
validation and all six adversarial missing-step/scope rejections pass.

Checkpoint 2264 closure additionally passes exact evidence-head and merged-main
CI/packages with publication skipped, bounded non-extracting review of both
consolidated artifacts, guarded 17-path zero-delete synchronization, and the
complete destination rerun. Destination Source is `694/694`; focused collision
is `3/3`; both locked workspaces, release, Flutter `852/852`, protocols, and
exact definitive `292/292` pass. Independent PS5/PS7 validation accepts report
SHA-256 `2d019c6dfe7faae629b28f9a9b11c6e6694db76b1950221281cfcd83d11c423e`.
The first destination adversarial attempt is not credited because path
containment rejected outside-repository candidates before content checks; its
corrected in-repository rerun rejects all six intended mutations. Final audit
passes all 17 blobs, eight lockfiles, zero residue/processes, and the protected
vault invariant.

## Checkpoint 2265 Quarantine Metadata No-Replace

Checkpoint 2265 adds a focused Rust workspace filter:

```powershell
cargo test --workspace quarantine_metadata_no_replace -- --test-threads=1
```

The filter selects one harmless collision fixture in each of Local Core, Guard,
and the disabled Native compatibility writer. Each fixture calls its production
metadata activation wrapper, requires a visible no-replace error, and verifies
that both staged fixture bytes and competing destination bytes remain unchanged.
The Python source contract also verifies production wiring, Local Core's
validated remove-before-no-replace replacement order, verifier/validator scope,
documentation, safety, and dependency claims.

The definitive verifier now requires the new step and exact 293-step full-suite
evidence. The validator rejects missing per-file atomicity, remove-to-activation,
multi-file transaction, unsupported-platform, or authenticated-recovery limits.
No checkpoint-2265 test ran during the scripting phase. Focused checks, broad
local regression, exact-293 verification, hosted evidence, merge, guarded sync,
and destination rerun began only after the scripting batch froze.

After the frozen batch, formatting, Source `695/695`, focused collision `3/3`,
broader quarantine `8 + 3 + 51 + 140 + 39`, strict changed-crate Clippy, both
locked workspaces, locked all-feature release, safe smoke, Flutter `852/852`,
and protocols `14/14 + 6/6` pass. Definitive verification passes exact
`293/293`, zero failed/skipped, in `659.4s`. Independent PowerShell 5.1 and 7
validation accepts the 219,352-byte report with SHA-256
`d526b2548ed90a62fd7e6a23b4383d393bbe878ce4488d5073fcbce8c5bf3a94`;
both hosts reject all eight missing-evidence mutations (`16/16`). Hosted,
integration, guarded-sync, and destination execution were then completed.

Implementation-head CI `33233682635` and package push/PR runs
`33233673950`/`33233682629` pass at exact commit `e4a1bb8`; both publication
jobs skip. Consolidated artifacts `9709386808`/`9709458957` pass bounded stream
validation without extraction or execution: exact 8 root entries, 6 platform
files, 7 checksums, and CycloneDX 1.6 with 569 components. Evidence-head,
merged-main, guarded-sync, and destination reruns now also pass.

Closure evidence passes exact evidence-head and merged-main CI/packages with
publication skipped, plus bounded non-extracting review of all three additional
consolidated artifacts. Guarded synchronization applies 16 exact paths with zero
deletes. Destination formatting, Source `695/695`, focused collision `3/3`,
broader quarantine, strict lint, both locked workspace variants, all-feature
release, safe smoke, Flutter `852/852`, and protocols `14/14 + 6/6` pass. The
destination definitive verifier passes `293/293`, zero failed/skipped, in
`641.1s`; both validators accept its 210,606-byte report with SHA-256
`db38434aaf46278bda4c68b425f1de34890c33b11e03873d7b25786c49018a7a`.
Eight unique mutations are rejected by both hosts (`16/16`), result SHA-256
`6f139935aee964dad3efad33bbf040896e87f81c2052bcc2cc4f6966e0a1b556`.
Final audit passes all 16 blobs, eight active lockfiles, zero residue/processes,
and the protected-vault invariant.

## Checkpoint 2266 - Signed Update Extraction No-Replace

All production, fixture, verifier, validator, Source-contract, lock, and
documentation changes were scripted before execution. No checkpoint-2266 test
ran during the scripting phase.

Run the frozen batch in this order:

```powershell
cargo fmt --all -- --check
& 'C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' tools\testing\run-python-source-contracts.py
cargo test --manifest-path core\avorax_update_service\Cargo.toml payload_extraction_no_replace -- --test-threads=1
cargo test --manifest-path core\avorax_update_service\Cargo.toml -- --test-threads=1
cargo clippy --manifest-path core\avorax_update_service\Cargo.toml --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --release --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2266-update-extraction-no-replace-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2266-update-extraction-no-replace-report.json -RequireFullSuite
```

The focused filter must run three harmless tests: absent-target activation,
competing-target preservation, and activation source ordering. The definitive
report must contain exact `294/294`, no skips or failed steps, the focused step,
verified collision wording, and the final-name/ancestor/install-tree limits.
PowerShell 5.1 and 7 must accept the authentic report and reject bounded
content mutations. No live malware, EICAR, fixture execution, Defender change,
machine-wide install, service/driver start, release, or publication is allowed.
The 16,072-file protected vault is never a test root and must retain zero
pending files.

Local execution after batch freeze now passes formatting, final Source
`696/696`, focused `3/3`, full update service `209/209`, strict Clippy, both
locked workspace variants, locked all-feature release, Flutter analysis and
`852/852`, and protocol analysis/tests `14/14 + 6/6`. Two earlier Source runs
failed visibly with two then one contract defect; all three were repaired before
the final pass. Exact `294/294`, authentic/adversarial dual-host validation,
hosted evidence, integration, synchronization, destination execution, and final
closure remain pending.

Definitive local execution passes exact `294/294`, all passed, no skips and no
Defender-EICAR, in `653.4s`. The report is 220,507 bytes with SHA-256
`8f9e033d6e6cf1ace2025e8f0069787fdf05c391864cff93b335ad9561cd115f`.
Both PowerShell hosts accept it and reject five unique mutations each (`10/10`);
the result SHA-256 is
`38d0f88b02e357cabdff92f76cacdc7129ddc354eddec035681f7d52e6c888a5`.
The first final-audit invocation is not credited because its expected Git
failure became terminating PowerShell 5.1 stderr. After a successful-query
repair and dual-host parse, final audit passes 14 modified plus one added path,
zero deletes, eight lock checks, zero processes/residue, and the exact vault.
Hosted, merge, synchronization, destination, and closure testing remains.

Implementation-head CI `33239461936` and package push/PR runs
`33239451192`/`33239461879` pass at exact SHA `36325846`; both publication
jobs skip. Consolidated artifacts `9711051283`/`9711127072` pass bounded stream
validation without extraction or execution: exact eight root entries, six
platform files, seven checksum targets, and CycloneDX 1.6 with 569 components.
Evidence-head reruns, integration, merged-main, synchronization, destination,
and closure tests remain pending.

Checkpoint 2266 closure additionally passes evidence-head and merged-main
CI/packages with publication skipped, bounded non-extracting review of both
additional consolidated artifacts, and guarded exact 15-path zero-delete
synchronization. Two sync attempts failed before activation on PowerShell 5.1
API compatibility and are retained as failed evidence; the repaired attempt
passed without deleting destination data.

The complete destination rerun passes Source `696/696`, focused `3/3`, update
service `209/209`, strict Clippy, both locked workspace variants, locked
all-feature release, Flutter `852/852`, protocols `14/14 + 6/6`, and definitive
`294/294` in `634.6s`. Both validators accept the authentic 211,753-byte report
with SHA-256
`922c46f6896c665d76938c6379c57231ffc44183ef842e4420b5cae8761b343c`.
The destination adversarial run accepts both authentic hosts and rejects all ten
candidates, but those candidates are rejected first by repository containment
because evidence intentionally remains under the source `.verification`; it is
not credited as duplicate content-mutation proof. The earlier local run proves
all five content mutations on both hosts, and final blob audit proves the
destination validator is exact merged content. Final audit passes 15/15 blobs,
8/8 locks, all three backup inventories, zero residue/processes, and the
protected-vault invariant.

## Checkpoint 2267 Update Staged-File No-Replace

The full implementation/test/verifier/documentation batch was scripted before
execution. No checkpoint-2267 test ran during the scripting phase. Run only
after the batch is frozen:

```powershell
cargo fmt --all -- --check
python -B tools\testing\run-python-source-contracts.py
cargo test --manifest-path core\avorax_platform_security\Cargo.toml -- --test-threads=1
cargo test --manifest-path core\avorax_update_service\Cargo.toml staged_activation_no_replace -- --test-threads=1
cargo test --manifest-path core\avorax_update_service\Cargo.toml -- --test-threads=1
cargo clippy --manifest-path core\avorax_update_service\Cargo.toml --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --release --locked
Push-Location apps\zentor_client; flutter analyze; flutter test; Pop-Location
Push-Location packages\zentor_protocol; flutter analyze; flutter test; Pop-Location
Push-Location packages\avorax_protocol; flutter analyze; flutter test; Pop-Location
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2267-update-staged-file-no-replace-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2267-update-staged-file-no-replace-report.json -RequireFullSuite
```

The focused filter must select five harmless tests. The platform suite must
select fifteen tests, including its long absolute Windows path and namespace
builder fixtures. The definitive report must
pass exact `295/295`, include the staged-file activation step and exact scope/
limit text, and be accepted by PowerShell 5.1 and 7. Both hosts must reject all
seven bounded report mutations (`14/14`). No live malware, EICAR, fixture
execution, Defender change, machine-wide install, service/driver start,
release, publication, or protected-vault test root is allowed. The 16,072-file
vault must remain read-only with zero pending.

Checkpoint 2267 local broad execution passes PowerShell 5.1/7 parsing after one
pre-parse argument-binding failure, formatting, dependency-free Source
`697/697`, focused `4/4`, update service `211/211`, strict Clippy, both locked
workspaces, locked release, Flutter `852/852`, and protocols `14/14 + 6/6`.
Two `python -m pytest` commands collected no tests because `pytest` is absent;
the documented dependency-free runner was used without installing packages.
Exact `295/295`, dual-host report mutation rejection, hosted/integration,
synchronization, destination, and closure testing remains pending.

The first definitive attempt failed visibly at the release update-package
builder smoke because the shared Windows no-replace call did not convert a long
absolute update-log path to bounded verbatim form. Preserve failed report hash
`282747873caa9a0b7ba0caf8a85f13eb66287044d7446b9021ab08d6adc4dd77`.
The scripted repair must rerun formatting, parsing, Source `698/698`, platform
`15/15`, focused staged activation `5/5`, update service `212/212`, strict
Clippy, both workspaces/release, Flutter/protocols, exact `295/295`, and seven
mutations on both hosts. No repair test ran before that repair batch froze.

Post-repair execution passes Source `698/698`, platform `15/15`, focused
staged activation `5/5`, update service `212/212`, strict platform/update
Clippy, both locked workspace variants, locked all-feature release, Flutter
analysis and `852/852`, and both protocol analyses plus `14/14 + 6/6`. The
initial post-repair format check found two layout-only diffs; formatting and the
repeat check pass. Flutter 3.44.4 rejected `flutter test apps\zentor_client`
before collection, so the reproducible commands above enter each project
directory; that client invocation passes all 852 tests.

Definitive no-skip/no-Defender verification passes exact `295/295` in 684
seconds. The 222,196-byte report SHA-256 is
`17a32dd8ee483963cbf95c72cc8542910baee414f86f4ed1353d18d1beeebe6d`.
PowerShell 5.1 and 7 independently accept it and reject all seven content
mutations on both hosts (`14/14`). Final audit passes 13 modified plus one
added path, zero deletes, eight unchanged lockfiles, zero product processes or
pending/workflow residue, and the exact protected-vault invariant. Hosted,
integration, destination, and closure testing remains pending.

Implementation-head CI `33247109048` and package push/PR runs
`33247093108`/`33247109041` pass at exact SHA `6e06ac51`; both publication
jobs skip. Consolidated artifacts `9713357241`/`9713425200` pass bounded stream
validation without extraction or execution: exact eight root entries, six
platform files, seven checksum targets, and CycloneDX 1.6 with 569 components.
Evidence-head reruns, integration, merged-main, synchronization, destination,
and closure tests remain pending.

Evidence-head CI/packages `33248103914`/`33248103915` pass at exact commit
`2770e5a5`; normal PR `#143` merge `7079debe` passes merged-main CI/packages
`33248770005`/`33248770099`. Consolidated artifacts `9713666252` and
`9713854005` pass bounded non-extracting/non-executing exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component validation. All
publication jobs skip.

The guarded destination sync applies 13 modified plus one added path and zero
deletes; report SHA-256 is
`e8df4ac7830f7e3d70b92f30e99f3562de5a841a667174cb6659650dd4e22e17`.
At `C:\Users\Brent\Documents\Avorax-main`, corrected parsing, formatting,
Source `698/698`, platform `15/15`, focused `5/5`, update service `212/212`,
strict lint, both locked workspaces, locked release, Flutter analyze/tests
`852/852`, and Dart protocol analyze/tests `14/14 + 6/6` pass. The definitive
command above passes exact `295/295` with no skips and Defender/EICAR opt-in
false in `658.4s`; the 213,457-byte report SHA-256 is
`fe90577d13ede4a77ad4464c9312344c254c74b2f6225ff085b8a187fe2662b9`.

PowerShell 5.1 and 7 accept that authentic report and reject all 14 bounded
mutation cases. The adversarial result SHA-256 is
`feada8887ecd9c10037eb167619cf5f4d04d5981eb281f8d12e1320aad0f30d1`.
Final destination audit SHA-256
`31b748f46cb34d72f65ae832528155802c90f7b69c596b1748f4630d19ee3e30`
passes exact 14 blobs, eight locks, 26 backups, zero product processes/pending,
the preserved temporary root, and the protected-vault invariant. Checkpoint
2267 testing is closed; technical limits remain as documented.

## Checkpoint 2268 Update Directory No-Replace

The complete implementation, test, verifier, adversarial, source-contract, and
documentation batch was scripted before execution. No checkpoint-2268 test ran
during the scripting phase. After the batch is frozen, run in this order:

```powershell
cargo fmt --all -- --check
cargo test --manifest-path core\avorax_platform_security\Cargo.toml directory_no_replace_activation -- --test-threads=1
cargo test --manifest-path core\avorax_update_service\Cargo.toml directory_activation_no_replace -- --test-threads=1
$env:PYTHONDONTWRITEBYTECODE='1'; python -m pytest -q tests/test_custom_driver_contract.py
cargo test --manifest-path core\avorax_platform_security\Cargo.toml -- --test-threads=1
cargo test --manifest-path core\avorax_update_service\Cargo.toml -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked -- --test-threads=1
cargo build --workspace --all-targets --all-features --release --locked
Push-Location apps\zentor_client; flutter analyze; flutter test; Pop-Location
Push-Location packages\zentor_protocol; flutter analyze; flutter test; Pop-Location
Push-Location packages\avorax_protocol; flutter analyze; flutter test; Pop-Location
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2268-update-directory-no-replace-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2268-update-directory-no-replace-report.json -RequireFullSuite
```

Expected new focused counts are platform `2/2` and update-service `4/4`;
expected broad totals after this batch are platform `17/17`, aggregate update
service `216/216`, Source `699/699`, and verifier `296/296`. These are
expectations, not credited evidence. The adversarial script must accept the
authentic report under PowerShell 5.1 and 7 and reject all seven mutations on
both hosts (`14/14`). Tests may touch only isolated temporary data. No live
malware, EICAR, Defender change, fixture execution, machine-wide installation,
service/driver start, release, publication, or protected-vault test root is
allowed. The 16,072-file vault must remain read-only with zero pending.

First focused attempt: format initially required layout-only changes, then
passed; both PowerShell parsers passed. Platform `2/2` passed. Update service
compiled and passed `3/4`, then exposed Windows error 123 because a `/`
separator was retained under the verbatim prefix. That run is uncredited. The
scripted repair normalizes separators before namespace validation and adds the
case to the platform fixture. Repeat format, platform, and update filters before
any broader test.

Post-repair focused `2/2 + 4/4`, Source `699/699`, platform `17/17`, and update
service aggregate `216/216` pass. The first strict Clippy 1.96 run is uncredited:
all changed crates checked cleanly, then three existing API source-layout lints
failed under `-D warnings`. Targeted documented allowances preserve stable JSON
event names and adjacent source-contract modules without runtime changes. Repeat
format and strict lint before locked workspaces.

The documented `core\Cargo.toml` invocation was rejected before compilation
because that workspace manifest does not exist. It is uncredited and corrected
above to the checkpoint-2267 default locked root-workspace command. The stricter
all-target/all-feature locked root workspace already passes; run the corrected
default-feature variant next.

Local broad repeat passes format, both PowerShell parsers, focused platform
`2/2`, focused update/rollback `4/4`, Source `699/699`, platform `17/17`, update
aggregate `216/216`, strict Clippy, default and all-target/all-feature locked
workspaces, locked all-feature release, Flutter `852/852`, and protocols
`14/14 + 6/6`. Both Native variants report `642 passed` with 21 intentional
child-fixture ignores. No lockfile changed; post-run audit has zero product
processes/pending and the exact protected-vault invariant. Definitive 296-step
and adversarial evidence remain pending.

Final-source definitive execution exits 0 in `673.5s`: exact `296/296`, no
failed or skipped Rust/Flutter work, and no Defender/EICAR opt-in. The 223,673-
byte report SHA-256 is
`8b87d0aa72cd0ee51d0c2b6ff9d1ac87dbb392ad19298b4a704a94b2f0f8970c`.
Both report-validator hosts accept the authentic report. Seven structured
mutations on both hosts are rejected, exact `14/14`; the 16,805-byte result
SHA-256 is
`217771abe632d0647aef3071654190609e367d120ec7afdfaee6ffd057033826`.
The first adversarial command used an unsupported parameter and stopped before
execution; it is uncredited. Post-run process, pending-file, lock, and protected-
vault audits pass. Hosted, integration, guarded-sync, destination, and closure
evidence remain pending.

Implementation-head PR `#145` at exact commit `821d17666fd5739525c3803c15c98341046035eb`
passes CI `33253639931` and Desktop Packages push/PR
`33253626820`/`33253639896`; publication is skipped. Untouched consolidated
artifacts `9715355338` and `9715311146` pass bounded in-stream validation with
exact 8 roots, 6 platform packages, 7 checksum targets, CycloneDX 1.6, and 569
components. They were not extracted or executed. Evidence-head, merge,
merged-main, guarded-sync, destination, and closure tests remain pending.

Evidence-head CI/packages `33254651157`/`33254651121` pass at exact commit
`635ccc21`; normal PR `#145` merge `99891d10` passes merged-main CI/packages
`33255233149`/`33255233172`. Consolidated artifacts `9715575145` and
`9715798339` pass bounded non-extracting/non-executing exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component validation. All
publication jobs skip.

The guarded destination sync applies 17 modified plus one added path and zero
deletes; report SHA-256 is
`586ef969e3a21ec729a0afd82eda85123575b548809dadf614c6160c505249ff`.
At `C:\Users\Brent\Documents\Avorax-main`, parsing, formatting, Source
`699/699`, focused `2/2 + 4/4`, platform `17/17`, update service `216/216`,
strict lint, both locked workspaces, locked release, Flutter analyze/tests
`852/852`, and Dart protocol analyze/tests `14/14 + 6/6` pass. The definitive
command passes exact `296/296` with no skips and Defender/EICAR opt-in false in
`665.0s`; the 214,543-byte report SHA-256 is
`77cecb9be36bc4350dcf1e321e1c7cc0e11ea52b0303da1554f9c9c993da02e7`.

PowerShell 5.1 and 7 accept that authentic report and reject all 14 bounded
mutation cases. The adversarial result SHA-256 is
`3bcc0829a3d972e49c23ba77d8691377822f2841cf6cee61955d93c6d1a9ea32`.
Final destination audit SHA-256
`8826367c8fbd9e79622311f8f2f92095bd3c4e999ec6b77f7cd051a83676d066`
passes exact 18 blobs, eight locks, 34 backups, zero product processes/pending/
temporary roots, and the protected-vault invariant. Checkpoint 2268 testing is
closed; technical limits remain as documented.

## Checkpoint 2269 Authenticated Update Activation Recovery

The complete implementation, benign-fixture, verifier, validator, adversarial,
source-contract, and documentation batch was scripted before execution. No
checkpoint-2269 test ran during the scripting phase. After freezing this batch,
run in this order:

```powershell
cargo fmt --all -- --check
powershell.exe -NoProfile -Command "[void][scriptblock]::Create([IO.File]::ReadAllText('tools/testing/verify-small-threat-mvp.ps1')); [void][scriptblock]::Create([IO.File]::ReadAllText('tools/testing/validate-small-threat-mvp-report.ps1')); [void][scriptblock]::Create([IO.File]::ReadAllText('.verification/checkpoint-2269-validator-adversarial.ps1'))"
pwsh.exe -NoProfile -Command "[void][scriptblock]::Create([IO.File]::ReadAllText('tools/testing/verify-small-threat-mvp.ps1')); [void][scriptblock]::Create([IO.File]::ReadAllText('tools/testing/validate-small-threat-mvp-report.ps1')); [void][scriptblock]::Create([IO.File]::ReadAllText('.verification/checkpoint-2269-validator-adversarial.ps1'))"
cargo test --manifest-path core\avorax_platform_security\Cargo.toml windows_machine_secret_dpapi_round_trip_is_non_plaintext -- --test-threads=1
cargo test --manifest-path core\avorax_update_service\Cargo.toml activation_recovery -- --test-threads=1
$env:PYTHONDONTWRITEBYTECODE='1'; python tools\testing\run-python-source-contracts.py
cargo test --manifest-path core\avorax_platform_security\Cargo.toml -- --test-threads=1
cargo test --manifest-path core\avorax_update_service\Cargo.toml -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked -- --test-threads=1
cargo build --workspace --all-targets --all-features --release --locked
Push-Location apps\zentor_client; flutter analyze; flutter test; Pop-Location
Push-Location packages\zentor_protocol; flutter analyze; flutter test; Pop-Location
Push-Location packages\avorax_protocol; flutter analyze; flutter test; Pop-Location
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2269-update-activation-recovery-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2269-update-activation-recovery-report.json -RequireFullSuite
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .verification\checkpoint-2269-validator-adversarial.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\2269-update-activation-recovery-report.json
```

Expected values are recovery filter `18/18`, platform `18/18`, update service
`232/232`, Source `700/700`, and verifier `297/297`. They are expectations, not
evidence. The adversarial audit must accept the authentic report under Windows
PowerShell 5.1 and PowerShell 7 and reject seven mutations on both hosts, exact
`14/14`. Tests may use only isolated temporary benign ASCII fixtures; they must
not execute candidate content, touch the protected vault, install/start a
service or driver, change Defender, release, or publish.

The post-freeze local checkpoint-2269 run now passes both script parsers,
format, focused DPAPI `1/1`, recovery `18/18`, Source `700/700`, platform
`18/18`, update service `232/232`, strict locked Clippy, default and all-target/
all-feature locked workspaces, and the locked all-feature release build. The
all-feature test groups pass `18 + 4 + 228 + 41 + 251 + 583 + 642 + 6` with
zero failures and 21 intentional isolated child-fixture ignores. Flutter
analysis and `852/852` pass; protocol analysis/tests pass `14/14 + 6/6`.

The first formatting check, recovery compile, Source, update aggregate, Clippy,
and post-Clippy Source attempts are not credited; their exact defects and
repairs are recorded in
`docs/reports/checkpoint-2269-update-activation-recovery.md`. Run the exact-297
verifier and validator/adversarial commands next, then perform read-only audit,
hosted exact-head, integration, guarded sync, and destination verification.

The first exact-297 run is not credited: its release apply-tamper smoke found
that recovery initialized the install-local store before signature rejection.
The repaired order is package verification, recovery, then extraction. The
focused Rust ordering contract `1/1`, Source `700/700`, release rebuild, and
the exact failed smoke pass. Repeat the complete verifier; do not substitute
the focused rerun for definitive evidence.

The complete repeat passes exact `297/297` in `685.6s` with no skips and no
Defender/EICAR opt-in. Both PowerShell hosts accept the authentic report and
the repaired adversarial script rejects all `14/14` host/mutation cases. The
first adversarial call stopped before fixture execution because of a
PowerShell 5.1 parameter-default incompatibility and is uncredited. Read-only
audit passes exact diff, lock, process, pending, temporary-residue, and vault
invariants. Exact implementation-head hosted results follow; evidence-head,
merged-main, and destination verification remain next.

Exact implementation head `d44b5c65c009d7378852b86246812ebe7115b1f2`
passes Avorax CI `33271345848` and Desktop Packages push/PR runs
`33271310749`/`33271345821`. Publication is skipped. The two downloaded
consolidated artifacts were validated without extraction or execution:

```powershell
.verification\checkpoint-2237-validate-consolidated.ps1 -Path .verification\checkpoint-2269-implementation-push-artifact-9720317057.zip -ExpectedBytes 132640696 -ExpectedSha256 1c1a6d752ac08fad2b54fc665e7eff919d66443f1583efa65705f98aa5bff9f9
.verification\checkpoint-2237-validate-consolidated.ps1 -Path .verification\checkpoint-2269-implementation-pr-artifact-9720376440.zip -ExpectedBytes 132629422 -ExpectedSha256 bada0debaf61adcd46396a60ab2ef49bf81b01d46fd0e328fbf3979ed118d2c5
```

Both report exact eight root entries, seven matching streamed checksums,
CycloneDX 1.6, and 569 components. Evidence-head, merged-main, and destination
verification remain required; these package checks are not installation or
runtime-recovery evidence.

Checkpoint-2269 closure evidence now passes. Evidence-head CI/packages
`33272364663`/`33272364645` pass exact commit `a933d451`; normal PR `#147`
merge `dfcec4fa` passes merged-main CI/packages
`33273388570`/`33273388568`. Consolidated artifacts `9720745014` and
`9720920236` pass bounded non-extracting/non-executing exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component review; publication
skips.

The guarded destination sync applies 19 modified and two added paths with zero
deletes; report SHA-256 is
`3303650d17490017fb514b0cf6d9b14eda59c568f93708ac2f942480dcc01da9`.
At `C:\Users\Brent\Documents\Avorax-main`, Source `700/700`, format, strict
locked Clippy, both locked workspace variants, locked all-feature release,
Flutter analysis/tests `852/852`, and protocols `14/14 + 6/6` pass. Exact
verification passes `297/297` in `737.4s`, no skips and Defender/EICAR false;
report SHA-256 is
`7710ee35419bfbf9f4c1868291cc511703e9313706e9fcd050a793bd9345598d`.

The first destination adversarial run is uncredited because its mutation files
were outside the destination and every rejection was a path-boundary result.
The corrected destination-local run is accepted on both PowerShell hosts and
rejects all `14/14` content mutations; SHA-256 is
`1b21fa2a7251f0d0e15871e47c941477f3612d79e5af32efa0d4d9e1c759c361`.
Final audit SHA-256
`6f82ec176934bfee9f8431ed77ba4800a6816503d1b8bd53d47ad31cc023ffa0`
passes 21 exact blobs, eight locks, 38 backups, zero product process/pending/
temporary residue, and the protected-vault invariant. Checkpoint 2269 testing
is closed; installed-context, Unix runtime, power-cut, service/driver, and
pre-execution limits remain unverified or technically limited.

## Checkpoint 2270 Unix Recovery Test Plan

The complete checkpoint-2270 test batch is scripted before execution. The
fixed Ubuntu 24.04 route will run `activation_recovery_unix_` and is expected
to select two `cfg(unix)` runtime fixtures plus one wiring contract. Windows
focused recovery is expected to rise to `19/19`, update-service aggregate to
`233/233`, Source to `701/701`, and the definitive verifier to exact `298/298`.
These are expected contracts, not results.

Post-freeze execution must include script parsing, focused permission/recovery
checks, strict locked lint, both locked workspace suites, locked release,
Flutter `852/852`, protocols `14/14 + 6/6`, exact verifier validation, authentic
PowerShell 5.1/7 acceptance, exact `14/14` adversarial rejection, hosted Ubuntu,
package/SBOM checks, destination regression, and final read-only audit. No
checkpoint-2270 test ran during the scripting phase. No live malware, EICAR,
fixture execution, Defender change, service/driver start, install, release,
publication, or protected-vault write is permitted; the 16,072-file vault has
zero pending. The complete antivirus-hardening goal remains active.

## Checkpoint 2270 Local Results

After the scripted batch froze, focused and broad local execution passed:

```powershell
cargo test --locked --manifest-path core/avorax_update_service/Cargo.toml activation_recovery -- --test-threads=1
cargo test --workspace --locked -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked -- --test-threads=1
cargo build --workspace --release --all-targets --all-features --locked
flutter analyze
flutter test
powershell.exe -File tools/testing/verify-small-threat-mvp.ps1 ... -ReportPath .workflow/ultracode/avorax-hardening/results/checkpoint-2270-unix-update-recovery-report.json
```

Results are recovery `19/19`, update service `229/229 + 4/4`, Source
`701/701`, platform security `18/18`, both locked Rust suites and release,
Flutter `852/852`, protocols `14/14 + 6/6`, and exact verifier `298/298` in
`635.4s`. PowerShell 5.1/7 accept report SHA-256
`fb35ed8fe64b352418b461d7e53f048fa380cd301bc18a1f703a059c1c5571ef`;
the independent runner rejects `14/14` mutations with results SHA-256
`63e13f73af15cea62d8221efda72174bdb2de3abdcc2ec5d0d9fbb93f2182914`.
The first full Source run's stale workflow counters failed visibly and were
repaired before this credited repeat. Hosted Ubuntu must still run
`activation_recovery_unix_`; local Windows success is not Unix permission
runtime evidence.

Final review tightened the mandatory technical-limit contract: mode repair
cannot undo prior key/journal disclosure, revoke existing handles, or restore
authenticity after key copying. The earlier exact-298 report is superseded; the
final-source verifier and both-host hostile-validation result above are final.

Implementation-head hosted verification passes Avorax CI `33279187609`; fixed
Ubuntu job `99171298396` selects exact `activation_recovery_unix_` tests and
reports `3 passed; 0 failed; 244 filtered out`. Package push/PR runs
`33279152023`/`33279187604` pass all six platform outputs and skip publication.
Consolidated artifacts `9722589339`/`9722639285` pass bounded in-stream exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component validation without
extraction or execution. Evidence-head, merged-main, and destination reruns are
still required.

## Checkpoint 2270 Integration And Destination Results

Evidence-head CI/packages `33279985483`/`33279985653` and merged-main
CI/packages `33280845843`/`33280845849` pass. Ubuntu jobs
`99173414467`/`99175636100` each select the two runtime fixtures plus wiring
contract and report `3 passed; 0 failed; 244 filtered out`. Publication skips.
Artifacts `9722892732`/`9723086300` pass bounded in-stream exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component review without
extraction or execution.

After guarded 13-modified/one-added/zero-delete synchronization, the exact
destination commands pass:

```powershell
python -B tools/testing/run-python-source-contracts.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked -- --test-threads=1
cargo build --workspace --release --all-targets --all-features --locked
flutter analyze
flutter test
powershell.exe -File tools/testing/verify-small-threat-mvp.ps1 ... -ReportPath .workflow/ultracode/avorax-hardening/results/checkpoint-2270-destination-unix-update-recovery-report.json
```

Results are Source `701/701`, Rust groups
`18 + 4 + 229 + 41 + 251 + 583 + 642 + 6`, Flutter `852/852`, protocols
`14/14 + 6/6`, and exact no-skip/no-Defender verifier `298/298` in `648.1s`.
Both PowerShell hosts validate the authentic report and reject all `14/14`
destination-local mutations with zero boundary-only rejections. The final
14-blob/8-lock/26-backup/process/residue/vault audit passes. Checkpoint 2270 is
closed; target/runtime and authority limits outside its scope remain.

## Checkpoint 2271 macOS Recovery Test Plan

The scripting phase is complete before execution. The fixed `macos-15` job
runs:

```bash
cargo test --locked \
  --manifest-path core/avorax_update_service/Cargo.toml \
  activation_recovery_unix_ \
  -- --test-threads=1
```

The hosted filter must select exact owner-only artifact mode, broad-mode repair,
and Unix wiring tests. Local post-freeze checks must cover PowerShell 5.1/7
parsing, Source `702/702`, the separate macOS wiring test, recovery and update-
service suites, format, strict locked lint, both locked workspace variants,
locked all-feature release, Flutter/protocol analysis and tests, and exact no-
skip/no-Defender `299/299`. Both validator hosts must accept the authentic
report and reject seven mutations each, exact `14/14`.

Exact-head hosted CI must show the macOS job selecting and passing all three
`activation_recovery_unix_` tests. Package jobs remain regression evidence only
and must be reviewed without extracting or executing artifacts. Normal PR/
merge, exact zero-delete guarded destination synchronization, destination full
verification, and final blob/lock/process/residue/vault audit are required for
closure. No checkpoint-2271 test ran during scripting. Android, installed
identity, broader macOS environments, root/admin, hostile filesystems, key
confidentiality/prior exposure, package transactionality, signing, driver/pre-
execution, and Defender-replacement limits remain explicit.

### Checkpoint 2271 closure evidence

Exact-head and merged-main fixed `macos-15` jobs each pass the three selected
`activation_recovery_unix_` tests (`3 passed; 0 failed; 245 filtered out`).
From the synchronized repository root, the destination passes the following
credited commands:

```powershell
python -B tools\testing\run-python-source-contracts.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked -- --test-threads=1
cargo build --workspace --release --all-targets --all-features --locked
Push-Location apps\zentor_client
flutter analyze
flutter test --reporter compact
Pop-Location
Push-Location packages\zentor_protocol
dart analyze
dart test
Pop-Location
Push-Location packages\avorax_protocol
dart analyze
dart test
Pop-Location
```

Source passes `702/702`; both Rust workspace variants have zero failures and
21 documented isolated child-fixture ignores; release and lint pass; Flutter
passes `852/852`. Zentor and Avorax protocol `dart analyze` plus `dart test`
pass `14/14 + 6/6`.

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File tools\testing\verify-small-threat-mvp.ps1 `
  -RepoRoot . `
  -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2271-destination-macos-update-recovery-report.json
```

The verifier passes exact `299/299` in `661.9s`, with no skips and without the
Defender/EICAR opt-in. The report is 218,889 bytes with SHA-256
`038e42e303cfff6f50327a78bde261f889de314458263bc56424ad6cb8d10bba`.
PowerShell 5.1/7 accept it; seven content mutations on each host are rejected,
exact `14/14`. Final destination audit verifies 14 blobs, 8 unchanged locks,
26 backups, zero product process/pending/temp residue, and the exact vault.

## Checkpoint 2272 Update Recovery Namespace Durability

No checkpoint-2272 test ran during the scripting phase. After the complete
batch is frozen, run focused evidence first:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -B tools\testing\run-python-source-contracts.py
cargo test --locked --manifest-path core\avorax_platform_security\Cargo.toml unix_directory_metadata_sync -- --test-threads=1
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml activation_recovery_durability_ -- --test-threads=1
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml activation_recovery_unix_runtime_contract_is_wired -- --test-threads=1
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml activation_recovery_macos_runtime_contract_is_wired -- --test-threads=1
```

Then run format, strict locked all-target/all-feature lint, full platform and
update crates, both locked workspace variants, locked release, Flutter, both
protocol suites, and the definitive verifier. A full report must contain exact
300 passed steps, no Rust/Flutter skip, and no Defender/EICAR opt-in. Test both
PowerShell hosts against the authentic report and malformed count/scope/path/
option copies.

The hosted Ubuntu 24.04 and macOS 15 jobs must each select the additional
`activation_recovery_unix_namespace_durability_barriers_execute` fixture. These
tests use benign text and temporary directories only; no fixture is executed as
a program. They do not prove Windows deletion durability, storage hardware,
hostile filesystems, installed identity, Android, or package-wide atomicity.

### Checkpoint 2272 local evidence

Post-freeze local execution passes PowerShell 5.1/7 parsing, Source `703/703`,
focused durability `2/2`, Unix/macOS route contracts `1/1` each, platform
`18/18`, update service `232/232`, strict locked Clippy, both locked workspace
variants, locked all-feature release, Flutter analysis/tests `852/852`, and
protocol analysis/tests `14/14 + 6/6`.

Run the definitive verifier with test-only no-debug/non-incremental codegen on a
host where Defender heuristically blocks the generated debug test harness:

```powershell
$env:CARGO_PROFILE_TEST_DEBUG='0'
$env:CARGO_INCREMENTAL='0'
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File tools\testing\verify-small-threat-mvp.ps1 `
  -RepoRoot . `
  -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2272-update-recovery-namespace-durability-report.json
```

This does not disable Defender or add an exclusion. The final report passes
exact `300/300`, zero failed/skipped, in `575.4s`, with Defender/EICAR opt-in
false; SHA-256 is
`9f6c54f97135044f2ae7e6b63f881b1084b0959316c24ceeea618f171cc1d531`.
Both validator hosts accept it and reject all `16/16` content mutations. Hosted
Ubuntu/macOS, integration, guarded destination synchronization, destination
full verification, and closure remain required.

### Checkpoint 2272 implementation-head hosted evidence

Avorax CI `33291974131` passes all six jobs at exact SHA
`62d257c3d03bd093cc2159c3f0287bac93ec295c`. Its Ubuntu job `99205069601`
and macOS 15 job `99205069619` each run:

```bash
cargo test --locked \
  --manifest-path core/avorax_update_service/Cargo.toml \
  activation_recovery_unix_ \
  -- --test-threads=1
```

Each selects owner-only artifacts, private-mode repair, namespace durability,
and workflow wiring: `4 passed; 0 failed; 247 filtered out`. Desktop Packages
push/PR `33291944899`/`33291974128` pass every build and consolidation job with
publication skipped. Consolidated artifacts `9726370706`/`9726376070` pass
bounded in-stream exact inventory, internal SHA-256, and CycloneDX checks
without extraction or execution. Merge, merged-main, guarded zero-delete
destination synchronization, destination full verification, and final audit
remain required before checkpoint closure.

### Checkpoint 2272 closure evidence

Evidence-head and merged-main fixed Ubuntu 24.04 and macOS 15 jobs each pass
the exact four selected `activation_recovery_unix_` tests (`4 passed; 0 failed;
247 filtered out`). From the synchronized repository root, the credited
destination commands are:

```powershell
python -B tools\testing\run-python-source-contracts.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked -- --test-threads=1
cargo build --workspace --release --all-targets --all-features --locked
Push-Location apps\zentor_client
flutter analyze
flutter test --reporter compact
Pop-Location
Push-Location packages\zentor_protocol
dart analyze
dart test
Pop-Location
Push-Location packages\avorax_protocol
dart analyze
dart test
Pop-Location
```

Source passes `703/703`; both Rust workspace variants have zero failures and
21 documented isolated child-fixture ignores; release and lint pass; Flutter
passes `852/852`; protocol tests pass `14/14 + 6/6`.

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File tools\testing\verify-small-threat-mvp.ps1 `
  -RepoRoot . `
  -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2272-destination-update-recovery-namespace-durability-report.json
```

The verifier passes exact `300/300` in `717.8s`, with no skips and Defender/
EICAR opt-in false. The 220,116-byte report SHA-256 is
`ef4aba38c9c658cdf34b395a990abceff05b13e0458734e8923f16213438e94d`.
PowerShell 5.1 and 7 accept it; eight content mutations on each host are
rejected, exact `16/16`. Final destination audit verifies 14 blobs, nine
unchanged locks, 26 backups, zero product process/pending/temp residue, and the
exact protected vault.

## Checkpoint 2273 Update Recovery Cleanup Tombstones

Checkpoint 2273 tests only harmless ASCII files in isolated temporary
directories. Fixtures are moved/read as data and are never executed. No live
malware, EICAR, network content, Defender setting, machine-wide install,
service/driver start, release, publication, or protected-vault mutation belongs
to this checkpoint.

The complete scripting batch must freeze before running these focused checks:

```powershell
python -B tools\testing\run-python-source-contracts.py
cargo fmt --all -- --check
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml `
  activation_recovery_cleanup_ -- --test-threads=1
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml `
  activation_recovery -- --test-threads=1
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File tools\testing\verify-small-threat-mvp.ps1 `
  -RepoRoot . `
  -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2273-update-recovery-cleanup-tombstones-report.json
```

The focused filter must select all eight `activation_recovery_cleanup_` tests.
Source must report exactly `704` tests, and the definitive no-skip/no-Defender
report must contain exactly `301` passed steps before it may be credited. Both
PowerShell 5.1 and 7 validators must accept the authentic report and reject
wrong count, missing step/scope, malformed path, tampered host, and terminal
status mutations.

No checkpoint-2273 test ran during the scripting phase. After freeze, Source
passed `704/704` after one initial stale-contract failure was repaired; cleanup
passed `8/8`, activation recovery `30/30`, and the full update service
`4 + 240`. Formatting/diff checks, strict affected and workspace Clippy, both
locked workspace variants, and locked all-feature release passed. Flutter
analysis/tests passed `852/852`; protocols passed `14/14 + 6/6`.

The definitive no-skip verifier passed exact `301/301`, zero failed/skipped and
zero non-null step errors, in `597.3s`. Defender/EICAR integration opt-in was
false. The 229,793-byte report SHA-256 is
`412da5f6f77c0f1567293ae1903dbd0595094f0e0f9fe696606efbdc328bd88a`.
PowerShell 5.1 and 7 accepted the authentic report and rejected ten mutations
per host, exact `20/20`. Final local audit passed 12 tracked modifications, one
new report, zero deletions, nine unchanged lockfiles, zero product process,
pending-file, or temporary-root residue, and the exact 16,072-file,
4,522,733-byte protected-vault invariant.

A final diff review after the first local sweep found and repaired an orphan-
tombstone ordering issue: unexplained active staging/backup siblings are now
rejected before any orphan tombstone is removed. The eighth regression proves
both pieces of evidence survive. The exact results and report hash above come
from the complete post-repair rerun; the earlier report is superseded.

Hosted CI/package, merge, destination, and closure evidence remains pending.
Windows same-volume rename/delete persistence, storage ordering, hostile
filesystems, VM power-cut behavior, installed identity, package-wide atomicity,
and the complete antivirus-hardening goal remain outside this focused test.

### Checkpoint 2273 implementation-head hosted evidence

Avorax CI `33298892119` passes all six jobs at exact SHA
`b594573f744b57dccf13f358e972720d54c288a3`. Ubuntu Rust job `99223208370`
runs the locked complete update-service suite and reports `4 + 240` passed,
including each of the eight named `activation_recovery_cleanup_` tests. macOS
15 job `99223208360` reports `4 passed; 0 failed; 255 filtered out` for its
selected recovery-permission and namespace-durability fixtures.

Desktop Packages push/PR `33298848017`/`33298892093` pass every build and
consolidation job with publication skipped. Consolidated artifacts
`9728478108`/`9728452926` pass bounded in-stream exact inventory, internal
SHA-256, and CycloneDX checks without extraction or execution. Evidence-head,
normal merge, merged-main, guarded zero-delete destination synchronization,
destination full verification, and final closure audit remain required.

### Checkpoint 2273 closure evidence

Evidence-head and merged-main fixed Ubuntu Rust jobs execute the full update
service and name all eight cleanup regressions as passed. Fixed macOS 15 jobs
each pass the exact four selected recovery fixtures (`4 passed; 0 failed; 255
filtered out`). From the synchronized repository root, the credited destination
commands are:

```powershell
python -B tools\testing\run-python-source-contracts.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked --no-fail-fast -- --test-threads=1
cargo build --workspace --release --all-targets --all-features --locked
Push-Location apps\zentor_client
flutter analyze
flutter test
Pop-Location
Push-Location packages\zentor_protocol
dart analyze
dart test
Pop-Location
Push-Location packages\avorax_protocol
dart analyze
dart test
Pop-Location
```

Source passes `704/704`; both Rust workspace variants have zero failures and
21 documented isolated child-fixture ignores; release and lint pass; Flutter
passes `852/852`; protocol tests pass `14/14 + 6/6`.

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File tools\testing\verify-small-threat-mvp.ps1 `
  -RepoRoot . `
  -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2273-destination-update-recovery-cleanup-tombstones-report.json
```

The verifier passes exact `301/301` in `706.2s`, with no failed/skipped steps,
no non-null step errors, and Defender/EICAR opt-in false. The 221,445-byte
report SHA-256 is
`deb434da82cd8c3b1ccf2f3f0ba3cfc1e596ee2aae70847facc2dfd5b5dd7948`.
PowerShell 5.1 and 7 accept it; ten content mutations on each host are rejected,
exact `20/20`. An earlier off-root mutation run is uncredited because candidate
path rejection preceded content validation. Final destination audit verifies
13 blobs, nine unchanged locks, 24 backups, zero product process/pending/temp
residue, and the exact protected vault.

## Checkpoint 2274 Verification

The complete checkpoint batch was written before execution. No checkpoint-2274
test ran during the scripting phase. After freeze, run the focused harmless
checks first:

```powershell
python -B tools\testing\run-python-source-contracts.py
cargo fmt --all -- --check
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml `
  checked_tree_cleanup_ -- --test-threads=1
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml `
  activation_recovery -- --test-threads=1
```

The focused filter covers bounded normal cleanup, entry/depth/logical-byte/
aggregate-encoded-path-payload
limits, inventory-to-removal type changes, explicit non-recursive deletion,
Unix nested-link rejection, and authenticated recovery evidence preservation.
Then run the complete locked Rust, Flutter, protocol, packaging-source, and
definitive verifier suites. A valid complete report must contain exactly
`302/302` steps and the `update-service bounded non-following tree cleanup
regressions` step.

Recorded post-freeze local evidence on 2026-08-30:

- Source contracts pass `705/705`; format and `git diff --check` pass.
- Windows `checked_tree_cleanup_` passed `7/7`; the two `cfg(unix)` primitive
  and recovery fixtures require hosted Ubuntu execution.
- Activation recovery passes `30/30`; update service passes `4 + 247`.
- Strict locked Clippy, both locked workspace suites, and locked all-target/
  all-feature release build pass.
- Flutter analysis and `852/852` tests pass; protocol suites pass
  `14/14 + 6/6`.
- Definitive verifier passes `302/302` with zero skips/errors and Defender/EICAR
  integration disabled in 694 seconds. The 231,383-byte report SHA-256 is
  `326f4755e9d86e972e64a02da317d9ac6daa82ca118a0b34c34a7ceee6073829`.
- Windows PowerShell 5.1 and PowerShell 7 accept the authentic report and reject
  all `24/24` checkpoint-2274 adversarial host/mutation cases.
- Final read-only audit passes 13 modified plus one added path, zero deletions,
  nine unchanged lockfiles, zero product process/pending/temp residue, and the
  exact protected-vault invariant.

Final review superseded that report for current-head credit: basename-only
accounting did not bound the full stored path payload. The repair counts full
aggregate encoded paths under the same 16 MiB cap and adds
`checked_tree_cleanup_path_payload_limit_fails_before_mutation`. Post-repair
format/diff, Source `705/705`, Windows cleanup `8/8`, recovery `30/30`, update
service `4 + 248`, strict locked Clippy, both locked workspaces, locked release,
Flutter `852/852`, and protocols `14/14 + 6/6` pass. Final-source definitive
verification passes exact `302/302` in `669.6s`, with no failed, skipped, or
non-null-error steps and Defender/EICAR opt-in disabled. The 231,397-byte report
SHA-256 is
`7daf28a3904c16a356550afb44a0b7233699b371f3c4d119239ef44979c3bc63`.
Windows PowerShell 5.1 and PowerShell 7 accept the authentic report and reject
all `24/24` adversarial host/mutation cases. Final read-only audit passes the
exact 13 modified plus one added path set, zero deletions, nine unchanged
lockfiles, zero product process/pending/temp residue, and the exact protected-
vault invariant. Hosted Unix, CI/package, merge, destination, and closure
evidence remain pending.

Initial exact-head CI `33306480962` passed, but its raw Ubuntu log contained
neither new `cfg(unix)` test name: the Unix job filtered only the existing
recovery-runtime set. The scripted workflow repair adds a dedicated `Test
bounded cleanup Unix link safety` step with two fully qualified `--exact`
commands, and the existing checkpoint-2274 Source contract pins that route.
The preceding definitive report is therefore pre-workflow-repair evidence.
The first post-freeze Source run failed visibly because the older Unix-job
contract still required 13 Cargo invocations. Updating it to exact 15 and the
fail-fast shell count to five makes Source pass `705/705`; cleanup `8/8`,
recovery `30/30`, update service `4 + 248`, format, and diff checks pass.
Final-source definitive verification passes exact `302/302` in `665.5s` with
zero failed/skipped/non-null-error steps and Defender/EICAR opt-in disabled.
The 231,401-byte report SHA-256 is
`73f63eef30abbb2e1109ce112224128dc87717e9c6ba4363eb8d3842beb49552`.
Both hosts accept the authentic report and reject all `24/24` adversarial
cases. Final audit passes 14 modified plus one added path, zero deletions, nine
unchanged locks, zero product process/pending/temp residue, and the protected-
vault invariant.

Final implementation head `c91519af3e03e8254e6dc215d9528f70a80fc2f5`
passes all six jobs in Avorax CI run `33307588267`. Raw Ubuntu job
`99246758706` evidence shows each fully qualified Unix cleanup/recovery test as
`running 1 test`, named `ok`, and `1 passed; 0 failed`. Desktop Packages run
`33307588380` passes package contracts, all four platform jobs, and
consolidation. Its job log requires six platform files, creates seven checksums,
and creates a CycloneDX 1.6 lockfile SBOM with 569 components; publication is
skipped. GitHub metadata binds consolidated artifact `9731114476` and all four
platform evidence bundles to the implementation head. No artifact was
downloaded, extracted, or executed during review. Evidence-head hosted reruns,
merge, destination, and closure testing remain pending.

### Checkpoint 2274 closure evidence

Evidence-head and merged-main fixed Ubuntu 24.04 jobs each execute both
dedicated Unix cleanup fixtures by fully qualified name with `--exact`; each
fixture passes exact non-empty `1/1`. Both CI matrices pass all six jobs. Both
desktop package matrices pass with publication skipped and bounded review
proves six release files, seven checksums, and CycloneDX 1.6 with 569
components. From the synchronized destination root, the credited commands are:

```powershell
python -B tools\testing\run-python-source-contracts.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked --no-fail-fast -- --test-threads=1
cargo build --workspace --release --all-targets --all-features --locked
Push-Location apps\zentor_client
flutter analyze
flutter test
Pop-Location
Push-Location packages\zentor_protocol
dart analyze
dart test
Pop-Location
Push-Location packages\avorax_protocol
dart analyze
dart test
Pop-Location
```

Source passes `705/705`; both Rust workspace variants have zero failures and
21 documented isolated child-fixture ignores; strict lint and release pass;
Flutter passes `852/852`; protocol tests pass `14/14 + 6/6`.

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File tools\testing\verify-small-threat-mvp.ps1 `
  -RepoRoot . `
  -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2274-destination-bounded-non-following-tree-cleanup-report.json
```

The verifier passes exact `302/302` in 668 seconds with no failed/skipped
steps, no non-null step errors, and Defender/EICAR opt-in false. The 222,657-
byte report SHA-256 is
`c4a95e939462465ce62fe2f6a0a68409906d520870c1c3a8f53ae531a591e0e1`.
PowerShell 5.1 and 7 accept both authentic cases and reject twelve mutations per
host, exact `24/24`, with no unexpected path-only content rejection. Final
destination audit verifies 15 exact blobs, nine unchanged locks, 28 backups,
zero product process/pending/temp residue, and the exact protected vault.

## Checkpoint 2275 Atomic Existing-File Replacement

No checkpoint-2275 command below ran during the scripting phase. The complete
implementation, benign/adversarial tests, hosted routes, verifier/validator
contracts, and docs were frozen first.

Focused commands:

```powershell
cargo test --locked --manifest-path core\avorax_platform_security\Cargo.toml atomic_existing_file_replacement_ -- --test-threads=1
cargo test --locked --manifest-path core\avorax_platform_security\Cargo.toml windows_atomic_replacement_failure_ -- --test-threads=1
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml staged_activation_atomic_replace_ -- --test-threads=1
cargo test --locked --manifest-path core\avorax_update_service\Cargo.toml staged_activation_rejects_ -- --test-threads=1
& 'C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' tools\testing\run-python-source-contracts.py
```

Quality and broad regression commands:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast -- --test-threads=1
cargo test --workspace --all-targets --all-features --locked --no-fail-fast -- --test-threads=1
cargo build --workspace --release --all-targets --all-features --locked
Push-Location apps\zentor_client
flutter analyze
flutter test
Pop-Location
Push-Location packages\zentor_protocol
dart analyze
dart test
Pop-Location
Push-Location packages\avorax_protocol
dart analyze
dart test
Pop-Location
```

The exact 302-step no-skip/no-Defender verifier must contain
`update-service staged file activation atomic replacement regressions` and the
full-suite report must pass both Windows PowerShell 5.1 and PowerShell 7
validators. Exact hosted Ubuntu 24.04 and macOS 15 jobs must each execute the
platform-security and update-service replacement fixtures by fully qualified
name with `--exact`; the Windows Rust job must run the complete locked platform
suite. A zero-test filter is not credit.

Focused results after freeze:

```text
Source contracts: 706/706 passed (two complete runs after two stale historical scope strings were repaired)
Atomic replacement: 3/3 passed (initial 2/3 exposed Windows source-handle sharing violation)
Windows failed-call recovery: 5/5 passed
Update staged atomic replacement: 6/6 passed
Update staged rejection: 2/2 passed
Platform strict Clippy: passed
Update-service strict Clippy: passed
Rustfmt, verifier/validator parse, git diff --check: passed
```

The production repair snapshots the verified Windows staged-source file ID,
closes the source handle required by the unshared `ReplaceFileW` open, and
rebinds the active name to that ID after activation.

Full local results:

```text
Strict locked workspace Clippy: passed
Locked workspace tests: passed
Locked all-target/all-feature tests: 1801 executed, 21 intentional ignores, 0 failed
Locked all-target/all-feature release build: passed
Flutter: analyze passed; 852/852 tests passed
Zentor protocol: analyze passed; 14/14 tests passed
Avorax protocol: analyze passed; 6/6 tests passed
Definitive verifier: 302/302 passed in 720.3s; 0 failed/skipped/error steps; Defender/EICAR opt-in false
Report: 232230 bytes; SHA-256 8cdec8f3d30f279a0faad434cd3238235e9fa7000526dcafc0919b2e36148867
Dual-host report validation: 2/2 authentic accepts; 28/28 adversarial rejects across 14 unique mutations
Adversarial result: 26716 bytes; SHA-256 a47ed3f1d7f2c0f75a1d69900748e03ccd2d9a2b82a56caa12300bc3e3428571
```

These results are superseded for final-source credit. A harmless isolated
Win32 probe proved that `ReplaceFileW` overwrites an already-existing API backup
path. The repaired source reserves an adjacent no-overwrite hard-link backup,
passes a null API backup parameter, preserves candidate collisions, and adds
`windows_atomic_replacement_failure_backup_reservation_preserves_competing_candidate`.
The same focused filter also runs
`windows_atomic_replacement_failure_backup_reservation_rejects_exhausted_candidates`.
After the repair batch freezes, repaired-source focused results pass Source
`706/706`, replacement `3/3`, reservation/recovery `7/7`, update activation
`6/6`, update rejection `2/2`, strict platform/update Clippy, formatting, all
four PowerShell parsers, and diff checks. Verifier, adversarial, and audit
commands still require rerun.

Complete repaired-source local results:

```text
Strict locked workspace Clippy: passed
Both locked workspace test variants: passed
Locked all-target/all-feature tests: 1803 executed, 21 intentional ignores, 0 failed
Locked all-target/all-feature release build: passed
Flutter: analyze passed; 852/852 tests passed
Zentor protocol: analyze passed; 14/14 tests passed
Avorax protocol: analyze passed; 6/6 tests passed
Tracked dependency locks: 9; changed: 0
```

The definitive verifier, new adversarial report validation, and final audit
still require rerun on this repaired source.

The first rerun stopped after 297 passing steps because Defender classified
the generated, malware-fixture-bearing Native unit-test harness as inactive
`Trojan:Win32/Wacatac.C!ml` before the late false-positive tests could start.
Do not add a Defender exclusion. The scripted repair routes those benign checks
through a dedicated integration target that links the production library but
does not compile the Native unit-test fixture corpus:

```powershell
cargo test --manifest-path core\zentor_native_engine\Cargo.toml --locked --test benign_false_positive_gate -- --test-threads=1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-false-positive-gate.ps1 -RepoRoot . -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe
& 'C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools\testing\run-python-source-contracts.py
```

After these focused commands pass, repeat the complete broad regression and
exact 302-step verifier above. The authentic report must be accepted by both
PowerShell hosts; all 34 host/mutation cases across 17 unique mutations must be
rejected. This harness change does not waive any Native unit-test suite or
production false-positive-rate requirement.

Focused post-freeze result: formatting/parsers/diff pass, Source `707/707`,
strict integration-target Clippy passes, the dedicated target passes `3/3`,
the full false-positive gate passes, and the no-malware-binaries gate passes.
Read-only Defender history shows zero detections for the dedicated target.
Broad and exact-302 reruns are still required.

The broad rerun now passes. Exact all-target/all-feature Rust totals are 1,806
executed with 21 intentional Native child-fixture ignores and zero failures;
strict Clippy, the second locked workspace variant, locked release build,
Flutter `852/852`, protocols `14/14 + 6/6`, and nine unchanged lockfiles pass.
Only the regenerated exact-302, adversarial, and final-audit stages remain in
the local closure sequence.

The regenerated definitive verifier now passes exact `302/302` in `708.4s`.
Its 232,732-byte report SHA-256 is
`13998e76443539d9eac4d9c38940a82d26011cc490c801d16de23df4f8edd3f0`.
Both validator hosts accept it and reject `34/34` adversarial cases across 17
unique mutations; result SHA-256 is
`3ea4610cdb1e89df351a454efbee340ab7395ee3ce2faac802ab390bf9655c9a`.
Final local audit was the next required step before commit/hosted evidence.

Final audit now passes 16 modified plus two added paths, zero deletions, nine
unchanged locks, zero process/pending/temp residue, and the exact protected
vault. Its 2,114-byte JSON SHA-256 is
`98627e5c9dc3de32c885212e2770edb49eb28ec1734af6b55bfc4f37fd57f1c2`.
Hosted and destination verification remain separate requirements.

Hosted Linux/macOS runtime, exact-head package, PR/merge, destination-sync, and
destination regression evidence remain pending.

Only harmless temporary ASCII fixtures are permitted and none is executed.
Tests must not install/start services or drivers, change Defender, mutate the
protected vault, download artifacts, publish a release, or claim package-wide
transactionality.

## Checkpoint 2276 Quarantine Metadata Atomic Replacement

Checkpoint 2276 scripts the complete implementation, fixture, workflow,
verifier, validator, source-contract, and documentation batch before testing.
No checkpoint 2276 test ran during that scripting phase.

Focused execution after freeze:

```powershell
cargo fmt --all -- --check
& 'C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools\testing\run-python-source-contracts.py
cargo test --locked --manifest-path core\zentor_local_core\Cargo.toml quarantine_metadata_atomic_replace_ -- --test-threads=1
cargo test --locked --workspace quarantine_metadata_ -- --test-threads=1
cargo clippy --locked --manifest-path core\zentor_local_core\Cargo.toml --all-targets --all-features -- -D warnings
cargo clippy --locked --manifest-path core\avorax_platform_security\Cargo.toml --all-targets --all-features -- -D warnings
```

PowerShell 5.1 and PowerShell 7 must parse both verifier scripts. The complete
post-focus sequence must rerun locked workspace Clippy/tests, all-target/all-
feature tests and release, Flutter analysis/tests, both Dart protocol packages,
security gates, the exact 302-step no-Defender verifier, dual-host authentic and
adversarial report validation, lockfile/diff/process/residue review, and the
read-only protected-vault audit.

The focused fixtures contain harmless temporary ASCII, are never executed, and
must touch only isolated temporary directories. No live malware or EICAR is
permitted for checkpoint 2276.

Post-freeze execution passes Source `708/708`, new replacement `3/3`, workspace
metadata `21/21`, Local Core quarantine `143/143`, Guard quarantine `51/51`,
platform `28/28`, strict lint, formatting, and both parser hosts. Both complete
locked Rust variants pass with 1,809 executed tests, 21 intentional ignores,
and zero failures; release, Flutter `852/852`, and protocols `14/14 + 6/6` pass.

The definitive verifier passes exact `302/302` in `677.8s`, with Defender/EICAR
opt-in false and no skipped Rust or Flutter suite. Report SHA-256 is
`62d917fadc40772e5db7dd14a6da17497db1e90d65224417fead7b74cfe0f32c`.
PowerShell 5.1 and 7 accept the authentic report and reject `52/52` hostile
cases across 26 mutations. The final local path/lock/process/residue/vault audit
passes. Hosted and destination execution remain separate required evidence.

First exact-head macOS execution failed `2/3` only because the authenticated-
pair fixture used the runner's `/var`-symlink temporary root; production link-
ancestor rejection worked as designed. The scripted repair uses
`tempdir_in(std::env::current_dir())` for that fixture only and leaves production
path policy unchanged. Focused, broad affected, exact verifier/audit, and hosted
evidence must be regenerated on the repaired head.

The repaired rerun passes focus `3/3`, Source `708/708`, strict lint, formatting,
and the complete locked all-target/all-feature Rust suite with 1,809 executed,
21 intentional ignores, and zero failures. The regenerated exact verifier
passes `302/302` in `667.1s`; report SHA-256 is
`1736eddd87c9ee03a0d1a2860ea5760b3fdb8ecf6a90ba7960018660e3a8c024`.
Dual-host validation again rejects `52/52` hostile cases and the repaired final
audit passes. Exact-head hosted evidence remains required.

Hosted repaired-head evidence now passes Avorax CI `33328100995`, including
real macOS and Ubuntu metadata replacement runtime, plus package push/PR
`33328099560` and `33328101027` across Windows, Linux, and both macOS
architectures. Both publication jobs are skipped. Evidence-head and destination
reruns remain separate requirements.

## Checkpoint 2277 Quarantine Metadata Update Recovery

Checkpoint 2277 scripts production, harmless fixtures, CI, verifier, validator,
source contracts, and documentation before execution. No checkpoint 2277 test
ran during that scripting phase.

Focused commands after the scripting freeze:

```powershell
cargo fmt --all -- --check
& 'C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools\testing\run-python-source-contracts.py
cargo test --locked --manifest-path core\avorax_platform_security\Cargo.toml tests::quarantine_metadata_update_recovery_artifact_names_are_bounded_and_recognized -- --exact --test-threads=1
cargo test --locked --manifest-path core\zentor_local_core\Cargo.toml quarantine_metadata_update_recovery_ -- --test-threads=1
cargo test --locked --workspace quarantine_metadata_ -- --test-threads=1
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

The complete sequence then requires both locked Rust workspace variants,
release, Flutter/protocol analysis and tests, security regressions, exact
`303/303` no-skip/no-Defender verification, dual-host authentic/adversarial
validation, hosted exact-head evidence, normal PR integration, guarded
destination synchronization, and final lock/process/residue/vault review.

Post-freeze local execution now passes Source `709/709`, recovery `13/13`,
workspace metadata `35/35`, Local Core quarantine `156/156`, strict workspace
Clippy, both complete locked Rust variants with `1,823` executed tests and 21
intentional ignores, locked release, Flutter analysis and `852/852`, and
protocol analysis/tests `14/14 + 6/6`. The definitive verifier passes exact
`303/303` in `680.4s`, with no skips/errors and Defender/EICAR opt-in false.
PS5/PS7 accept the authentic report and reject all `62/62` adversarial cases
across 31 mutations. Exact implementation head `2e106e0` passes Avorax CI
`33337128172` and Desktop Packages push/PR `33337101095`/`33337128179`, with
actual Ubuntu/macOS recovery, all six package files, seven checksums, a
569-component lockfile SBOM, and publication skipped. Evidence-head and
destination execution remain separate required evidence.

Closure execution now passes evidence head `f335ffc6`, PR `#163`, merge
`89c0449`, merged-main CI `33339046998`, and Desktop Packages `33339046993`.
The latter passes all six platform release files, seven checksums, a
569-component lockfile SBOM, and an explicitly skipped publication job.
Guarded destination synchronization applies exact 16 modified plus one added
path, zero deletions, and 32 backups.

Destination focused commands pass Source `709/709`, platform `29/29`, recovery
`13/13`, metadata `35/35`, Local Core quarantine `156/156`, strict workspace
Clippy, and rustfmt. Exact no-skip/no-Defender verification passes `303/303` in
`715.3s`; report SHA-256 is
`b89ad35ff09da20987cd56f54e4e50c1ae4469c53111d63babe910e0fa3b35c7`.
Both PowerShell hosts accept the authentic report and reject `62/62` hostile
reports across 31 mutations; adversarial SHA-256 is
`e6220274b406e634be381a735c9f0702dc1a818d89f8ba8060a7af11a6830ae2`.
Final audit SHA-256 is
`55b061e65b555eafea39ffd54d6f8d08a6d3f45893e200fb37bbcd4e2d98cb1d`;
all 17 blobs, nine locks, process/residue controls, and the protected vault
pass. Checkpoint 2277 is closed; the complete antivirus goal remains active.

Fixtures use harmless isolated ASCII only and are never executed. They must not
touch the protected vault, install/start services or drivers, alter Defender,
download artifacts, or publish. Journal recovery proves bounded rollback of the
metadata pair only; it does not make restore/delete payload movement atomic.

## Checkpoint 2278 Restore/Delete Recovery

Checkpoint 2278 scripts the missing action-level recovery boundary. The focused
post-freeze commands are:

```powershell
cargo test --locked --manifest-path core/avorax_platform_security/Cargo.toml persistent_file_identity_accepts_same_file_and_rejects_replacement -- --test-threads=1
cargo test --locked --manifest-path core/avorax_platform_security/Cargo.toml quarantine_action_recovery_artifact_names_are_bounded_and_recognized -- --test-threads=1
cargo test --locked --manifest-path core/zentor_local_core/Cargo.toml quarantine_lifecycle_action_recovery_ -- --test-threads=1
```

Then run Local Core quarantine/full suites, both locked workspace variants,
strict Clippy, release build, Flutter/protocol, Source `710`, exact definitive
`304/304`, dual-host report validation/adversarial mutation, and the documented
security/dependency/branding gates. No checkpoint-2278 test ran during the
scripting phase; no result is claimed yet. Fixtures are harmless temporary
ASCII and are never executed. The real protected vault, Defender, installed
components, services/drivers, release, and publication remain out of scope.

Post-freeze local execution passes platform `31/31`, action recovery `15/15`,
Local Core quarantine `157/157`, Local Core `614/614`, strict workspace Clippy,
both locked workspace variants, all-feature release, Source `710/710`, Flutter
analysis and `852/852`, and protocol analysis/tests `14/14 + 6/6`. Branding,
product-copy, no-malware-binaries, dependency, UI inventory, and package-source
gates pass. The definitive verifier passes exact `304/304` in `705.3s`, with
Rust and Flutter enabled and Defender/EICAR opt-in false. PowerShell 5.1 and 7
accept the authentic report and reject all `34/34` hostile cases across 17
mutations. Exact implementation `6abbffb3` passes PR `#165` CI `33346196118`
and Desktop Packages PR/push `33346196123`/`33346170948`. All six CI jobs and
Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMG, package contracts, and
consolidation pass; publication is skipped. Consolidated artifact `9742414827`
is 133,133,600 bytes with hosted digest
`f60e09788925a30cfd724176f42eaec088e5a5398b2cd3d4ed729e24bdc10662`.
Only hosted metadata/logs were inspected. Merge, merged-main, guarded sync, and
destination execution remain separate requirements.

Checkpoint-2278 closure now passes evidence-head CI/packages, PR `#165`, merge
`1683a13`, and merged-main CI `33348691591` / packages `33348691613` with
publication skipped. Guarded destination synchronization applies exact 16
modified plus one added path, zero deletions, and 32 backups.

Destination Source `710/710`, rustfmt, platform `1/1 + 1/1`, action recovery
`15/15`, and strict workspace Clippy pass. Exact no-skip/no-Defender verification
passes `304/304` in `760.9s`; report SHA-256 is
`e93040e010e60cd9c77f7750964e836e4aee42a93d76259737e98b30b3c01d3b`.
PowerShell 5.1 and 7 accept it and reject all `34/34` hostile cases across 17
mutations. Final audit SHA-256 is
`86ad411e3709408a5e29837e3ad1ee69c97c59c5e829908090e3fe4fe5c9d06a`;
17/17 blobs, 9/9 locks, 32 backups, process/residue controls, and the protected
vault pass. Checkpoint 2278 is closed; the complete antivirus goal remains active.

## Checkpoint 2279 RestoreReserved Test Plan

The complete checkpoint-2279 batch was scripted before execution. No
checkpoint-2279 test ran during the scripting phase. Harmless Rust fixtures now
cover empty unbound reservation cleanup, hard-link rejection, identity-bound
empty/partial/same-size-hash-mismatched cleanup, completed-copy promotion,
identity substitution, early destination rejection, and non-adjacent phase
rejection. They create only temporary benign text files and never execute them.

After freeze, run the focused action filter, Source contract 711, Local Core and
platform suites, strict locked workspace lint/tests/release, Flutter `852`, both
protocol suites, security/dependency/package gates, and the no-skip/no-Defender
304-step verifier. Validate its authentic report and adversarial mutations on
Windows PowerShell 5.1 and PowerShell 7. CI must rerun the existing action filter
on Ubuntu and macOS. The vault must remain exactly 16,072 files, zero
directories, 4,522,733 bytes, one key, and zero pending before and after.

The expected scope is bounded `Prepared -> RestoreReserved -> RestoreStaged`
replay, not a power-loss-proof transaction, secure erase, installed-service E2E,
driver/pre-execution blocking, Defender replacement, or production accuracy.

Post-freeze local execution passes Source `711/711`, identity `1/1`, action
recovery `25/25`, quarantine `167/167`, Local Core `624/624`, strict Clippy,
both locked workspace variants (`1,850` executed, 21 intentional ignores),
all-target/all-feature release, Flutter `852/852`, protocols `14/14 + 6/6`, and
the UI/package/security/dependency gates. Exact no-skip/no-Defender verification
passes `304/304` in `673.5s`; both PowerShell hosts accept report SHA-256
`e5792c4caf7b77c8462536a0407d74f956983e68b95ab2439d02dba83ea94552`
and reject `34/34` hostile results across 17 mutations. Hosted Ubuntu/macOS,
exact-head packages, PR/merge, guarded synchronization, destination, and closure
evidence remains required.

Implementation-head hosted evidence now passes exact commit `c4c21e5` on PR
`#167`: Avorax CI `33355915264` passes all six jobs, and Desktop Packages
`33355915194` passes contracts, Windows MSI/setup EXE, Linux DEB/tar, both
macOS DMGs, and consolidation with publication skipped. Hosted logs record six
platform files, seven checksums, a 569-component CycloneDX lockfile SBOM, and
eight uploaded evidence files. Consolidated artifact `9745412188` is
133,166,414 bytes with digest
`ea7c9393afa4d3db7cfb124e4226e7ae02bdb44d202c62d697e464bbf48d6a97`.
Only logs and metadata were inspected; integration and destination execution
remain separate required evidence.

Checkpoint-2279 closure passes evidence-head CI/packages, PR `#167`, normal
merge `ad168225`, and merged-main CI `33358161556` / packages `33358161554`.
Publication is skipped and no hosted artifact was downloaded. Guarded sync
applies exact 14 modified plus one added file, zero deletions, and 28 backups.

The synchronized destination commands include:

```powershell
python -B tools/testing/run-python-source-contracts.py
cargo fmt --all -- --check
cargo test --locked --manifest-path core/avorax_platform_security/Cargo.toml persistent_file_identity_accepts_same_file_and_rejects_replacement -- --test-threads=1
cargo test --locked --manifest-path core/zentor_local_core/Cargo.toml quarantine_lifecycle_action_recovery_ -- --test-threads=1
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/testing/verify-small-threat-mvp.ps1 -ReportPath .workflow/ultracode/avorax-hardening/results/checkpoint-2279-destination-report.json
powershell -NoProfile -ExecutionPolicy Bypass -File tools/testing/validate-small-threat-mvp-report.ps1 -ReportPath .workflow/ultracode/avorax-hardening/results/checkpoint-2279-destination-report.json -RequireFullSuite
```

The concrete verifier invocation supplied absolute non-reparse Python, Cargo,
Flutter, Dart, PowerShell 5.1, and PowerShell 7 paths and the compact documented
test profile; Defender was not changed. Results are Source `711/711`, format,
identity `1/1`, action recovery `25/25`, strict Clippy, and exact verifier
`304/304` in `655.2s`, zero failed/skipped/error steps. Report SHA-256 is
`08b7bc67121af02c85ead8fa1cad9bedac7ac816b8aabd4487c3b5338fe34dce`.
Both hosts accept it and reject `34/34` hostile results across 17 mutations.
Final audit SHA-256
`d18946098975dbc22bcd4f9f0e94ee3ec3819a81ed96636ae5e4ac19298ff659`
proves 15 exact blobs, nine unchanged locks, 28 backups, no residue/processes,
and the unchanged protected vault. Checkpoint 2279 is closed; whole-goal tests
and documented technical limits remain active.

## Checkpoint 2280 Restore Handle Tests

Checkpoint 2280 adds only harmless temporary ASCII filesystem fixtures. The
platform suite preserves an existing path, verifies Windows read sharing plus
write/rename/delete denial for a live reservation, verifies mutation is possible
again after fixture handles close, and checks Unix owner-only/no-follow creation.
Local Core has a source-level regression requiring the shared helper before
identity capture. Source contract 712 binds implementation, existing
Windows/Ubuntu/macOS full-platform test coverage, exact-304 verifier scope,
validator limitations, documentation, and zero dependency delta.

No checkpoint-2280 test ran during the scripting phase. Run focused platform and
Local Core checks first, then full platform/quarantine/workspace tests, strict
Clippy, release, Flutter/protocol, exact no-skip/no-Defender verification, both
validator hosts, all hostile mutations, hosted CI/packages, and guarded
destination verification. Never use the protected 16,072-file, zero-pending
vault as a fixture.

Post-freeze results are Source `712/712`, platform restore-stage/full `2/2 +
33/33`, exact Local Core wiring `1/1`, quarantine `182/182`, Local Core
`625/625`, all locked workspace variants, strict Clippy, all-target/all-feature
release, Flutter analysis plus `852/852`, and protocol `14/14 + 6/6`. The exact
no-skip/no-Defender verifier passes `304/304` in `706.4s`; report SHA-256 is
`49701948f989f942902fbffad5a1221ae34f26b3811c18427b2aab1dbe6a6bcb`.
Both report hosts accept it and reject all `34/34` hostile cases; adversarial
SHA-256 is
`1235e51aa65ecf7718a37ab56dc5a8513aff6aa68efc7da6def6f7aeedc0952d`.
Hosted and destination execution remain required.
