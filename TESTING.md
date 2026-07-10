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

Some service/driver/update gates may require elevation or a signed installed driver. If they cannot run, document the blocker in `RUN_LOG.md` and do not claim the gated capability as verified.

Current Windows limitation: `cargo test --manifest-path core/avorax_update_service/Cargo.toml` and `--bin avorax_update_service` can fail before running tests with Windows error 740 because the update-service test binaries inherit a require-administrator manifest. In a non-elevated shell, use `cargo check --manifest-path core/avorax_update_service/Cargo.toml --bin avorax_update_service` plus `uv run pytest tests/test_custom_driver_contract.py -q`, or rerun the Rust unit tests from an elevated developer shell. The static contract test also checks that update apply attempts rollback restoration and service restart on payload-copy failure; elevated integration tests are still needed for real service stop/start/apply paths.
