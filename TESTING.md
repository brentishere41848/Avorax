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

Tests never execute candidate content and did not mutate the protected
production vault. The result remains user-mode/path-based and does not prove
atomic final path mutation, installed service/UI E2E, driver/kernel mediation,
pre-execution blocking, secure erase, production detection quality, or Defender
replacement.
