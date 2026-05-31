# Avorax Anti-Virus Status

## Current Phase

Avorax installer engine-deployment repair and `v0.2.9` release preparation after `v0.2.8`.

## Current Commit

- Current checkpoint commit: this commit; run `git log -1 --oneline` for the exact SHA after checkout.
- Base commit before this checkpoint: `765ba30`
- Current tag: none detected in this environment

## Phase Progress

- Phase 0: in progress / partially complete. Audit documents now exist under `docs/audit/`, and the repository has a root Rust workspace for the documented baseline command.
- Phase 1: in progress. Active product-copy gates were tightened for product-facing UI, docs, package, and installer paths.
- Phases 2-19: not marked complete in this checkpoint; existing engine/service implementations and tests provide partial coverage, but remaining phase work must continue in order.

## Completed Items In This Checkpoint

- Added repository-level `Cargo.toml` workspace covering the active Rust crates.
- Added `docs/audit/repo-audit.md`, `docs/audit/active-components.md`, and `docs/audit/known-blockers.md`.
- Updated `PLANS.md` to list Phases 0 through 19 and the current priority.
- Updated `AGENTS.md` with active string category rules and release gate expectations without introducing blocked product language into active files.
- Strengthened `tools/security/zentor-product-copy-gate.ps1` to scan broader active product-facing paths and additional unsupported claim categories while avoiding self-matching literal claim phrases.
- Made `tools/branding/branding-check.sh` directly executable for local Unix-like validation.
- Updated the Windows MSI packaging script to find Rust binaries produced under the root Cargo workspace target directory.
- Added native trust helpers for Microsoft signature checks, Avorax-owned paths, Avorax installer artifacts, and publisher trust without blindly trusting unsigned system-folder files.
- Suppressed Avorax installer/MSI/internal artifacts from weak heuristic findings unless a confirmed signature or known-bad hash matches.
- Raised weak-signal heuristic thresholds so Downloads, Temp, setup/MSI names, unsigned/unknown publisher, and installer-like names remain observations/likely-clean unless stronger independent evidence exists.
- Hidden native `Observation` verdicts from normal scan threat results.
- Changed scan-result UX so low/medium heuristic-only findings show `Review suggested` or `Observation`, not `Detected`.
- Limited default `Quarantine` and `Delete permanently` buttons to confirmed/probable high-confidence results.
- Reworked the Protection screen explanation and checklist so `Driver Self-Test Required` states explain the missing guard/driver/self-test components and make Cloud disabled explicitly optional.
- Reworked the Device tab into `Device & Protection Health` and removed the unprofessional `Flutter local core active` wording.
- Extended false-positive gates and tests for Avorax installer EXE, Avorax MSI, setup.exe in Downloads, Avorax internal files, normal Downloads EXEs, and native installer trust.
- Added safe GitHub malware-repository metadata and hash-only import tools under `tools/zentor_intel/`.
- Added disabled-by-default external source config for Pyran1 malware repositories in `assets/zentor_native/threat_intel/sources.example.json`.
- Added empty safe `.zsig` packs for GitHub hash-only known-bad and lab known-bad indicators.
- Added `tools/security/zentor-no-malware-binaries-gate.ps1` and `.sh`, wired into the Windows release gate.
- Added docs for safe external malware-intel handling, metadata-only mode, hash-only mode, and disabled lab mode.
- Added native engine tests for GitHub hash-only known-bad SHA-256 confirmation and policy quarantine.
- Rebranded active product-facing UI, docs, installer metadata, CI labels, release artifact names, gates, and safe validation assets from the old product name to Avorax.
- Changed active product naming to Avorax Anti-Virus, Avorax Security, Avorax Native Engine, Avorax Core Service, and Avorax Guard Service.
- Added Avorax build-time configuration names while retaining internal legacy `ZENTOR_*` fallbacks where needed for compatibility.
- Removed placeholder protected-app registry entries that looked like unrelated product-domain examples.
- Replaced the vague partial-protection status label with `Driver Self-Test Required` and changed verified-ready UI copy to avoid unsupported absolute protection claims.
- Hardened Guard Service post-launch response so disabled/observe-only modes do not stop or quarantine, and automatic stop/quarantine is limited to confirmed local known-bad/test-threat/native confirmed verdicts.
- Switched new quarantine payload filenames to `.avoraxq` across the local core, native engine, and Guard Service while keeping legacy quarantine records readable.
- Added Avorax environment-variable aliases and default data/event/quarantine directories for new runtime data, with legacy `ZENTOR_*` fallbacks preserved for existing preview installs.
- Added Avorax publisher trust and Avorax-owned runtime/quarantine path handling to the Guard driver verdict path so Lockdown Mode can allow verified Avorax-signed components and avoid misclassifying Avorax quarantine/runtime files.
- Changed Guard Service detection engine identifiers for known-bad hash and native confirmed verdicts to Avorax-branded values in new quarantine records/events.
- Tightened application-control quarantine policy so probable/high-risk review items are monitored in Block Confirmed and Monitor Only modes, blocked for user approval in Lockdown Mode, and not automatically quarantined or labeled as malware unless the evidence is confirmed.
- Updated protection-mode copy so Block Confirmed Threats describes automatic stop/quarantine for confirmed threats only.
- Restricted legacy "auto quarantine all detections" scan/action compatibility paths so they still quarantine only confirmed threats; probable, suspicious, high-confidence, and heuristic detections remain review-only unless a user manually chooses quarantine.
- Added explicit Avorax Guard Service mode parsing through `AVORAX_GUARD_MODE` / `AVORAX_PROTECTION_MODE`, so background post-launch stop/quarantine honors disabled and monitor-only deployments instead of hardcoding blocking mode.
- Added shared Guard mode config handoff: Flutter writes protection-mode changes through local-core `configure_guard_mode`, local core persists normalized mode JSON, and Guard Service reads that config when no environment override is present.
- Hardened Windows MSI/EXE packaging so the MSI payload now requires the Flutter app, local core helper, Guard Service, Avorax Native Engine packs, AI model assets, trust/test/threat assets, Windows driver tooling, protection self-tests, branding/security/performance/ZNE release gates, safe simulator tools, safe threat-intel tooling, complete docs, and an installed `install-manifest.json`.
- Updated Windows release artifact naming in CI from the old artifact label to `avorax-windows-installers-<version>`.
- Tightened installer release packaging again so missing `zentor_local_core.exe` or `zentor_guard_service.exe` is a hard build failure by default. `-AllowIncompletePayload` is limited to local diagnostics, and normal MSI/EXE builds install the same complete payload through the MSI chain.
- Updated the Flutter GitHub release updater defaults and Windows release build defines so Avorax checks `brentishere41848/Avorax` releases by default.
- Added an installer audit report for the previous `Engine Unavailable` path.
- Updated the Avorax Native Engine config and local core asset discovery so installed layouts under `C:\Program Files\Avorax\engine` are preferred over repository-only asset paths.
- Added Avorax Core Service service-mode support so the MSI can install and start `avorax_core_service` honestly instead of only packaging a stdio helper.
- Changed Guard Service service naming to `avorax_guard_service` while keeping legacy helper names packaged for compatibility.
- Updated the MSI payload to install `avorax_core_service.exe`, `avorax_guard_service.exe`, `engine\config`, Avorax `.asig`, `.arule`, `.amodel`, `.atrust` aliases, and a release self-trust manifest.
- Added ProgramData creation for Avorax config, logs, events, quarantine, scans, cache, reports, and migration data.
- Added `tools\windows\avorax-installed-smoke-test.ps1` to verify installed app files, engine assets, ProgramData, services, install report, and Core health.
- Updated release-gate staging checks so missing installed engine files or smoke-test tooling fail the release gate.
- Updated the scan UI fallback so engine-unavailable states show concrete diagnostics and do not imply files are clean.
- Added an explicit local-core `EngineAssetLocator` with installed-path priority, debug-only repo fallback, checked-path diagnostics, and a focused unit test.
- Extended Flutter local-core health parsing and Scan diagnostics with Core Service status and engine paths checked.
- Added `tools\windows\avorax-installer-stage-test.ps1` and wired it into the Windows release gate so release checks fail when the MSI/EXE stage or required Avorax payload is missing.
- Changed MSI-created ProgramData quarantine casing to `Quarantine` to match runtime quarantine paths and the installed smoke test.
- Updated MSI service control generation so Avorax Core Service and Avorax Guard Service are started during install and repair, not only first install.
- Tightened the installer stage test to require native ML source/alias packs and generated WiX service controls that start both services.
- Fixed Scan diagnostics so development native ML models show as present instead of missing, and stale engine-unavailable scan cards are cleared once health reports the engine available.
- Added a functional Start Core Service action in the app that asks Windows to start `avorax_core_service` with administrator approval.
- Reworked update flow so Avorax selects the MSI release asset, downloads it to a local update cache, and starts the Windows MSI update from inside the app instead of opening the EXE installer or release page.

## Blockers

- Cargo/Rust is not installed or not on `PATH` in this Windows checkout, so Rust and false-positive gates must run in CI or a provisioned Rust environment.
- Flutter is not installed or not on `PATH` in this Windows checkout.
- Dart is not installed or not on `PATH` in this Windows checkout.
- No signed Windows driver has been built, installed, run, or self-tested in this environment.
- Production ML dataset, independent validation, and production-ready model metadata remain unavailable.

## Tests Passed

- `powershell -ExecutionPolicy Bypass -File tools\branding\branding-check.ps1`
- `powershell -ExecutionPolicy Bypass -File tools\security\zentor-product-copy-gate.ps1`
- `powershell -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1`
- PowerShell parser check for `installer\windows\build-msi.ps1`, `tools\windows\zentor-release-gate.ps1`, and `tools\windows\avorax-installer-stage-test.ps1`
- `git diff --check`
- Active-string search for old product copy, old three-letter engine aliases, vague partial-protection label, unrelated product-domain copy, and fake protection claims.
- Active quarantine-extension search confirming new runtime writes use `.avoraxq` and old quarantine extensions only remain in migration/readback paths.
- `python tools\zentor_intel\import_github_malware_metadata.py --config assets\zentor_native\threat_intel\sources.example.json --output $env:TEMP\zentor_metadata.jsonl`
- `python tools\zentor_intel\import_github_hashes_only.py ...` with a safe temporary SHA-256 fixture
- `python tools\zentor_intel\build_known_bad_from_github.py ...` with a safe temporary SHA-256 fixture
- `python tools\zentor_intel\validate_indicator_pack.py --input $env:TEMP\zentor_github_known_bad.zsig`
- Lab-download rejection smoke tests for missing env/flag and repository-local output folder.

## Tests Failing Or Blocked

- GitHub Actions release run `26709325568` for `v0.2.3` failed because `build-msi.ps1` did not look in the root workspace `target\release` directory for `zentor_local_core.exe`; the script has been updated to support that output path.
- `cargo test --workspace` is blocked in this Windows checkout because `cargo` is not installed or not on `PATH`.
- `cargo test --manifest-path core\zentor_guard_service\Cargo.toml` is blocked in this Windows checkout because `cargo` is not installed or not on `PATH`.
- `cargo fmt --manifest-path core\zentor_native_engine\Cargo.toml` is blocked because `cargo` is not installed or not on `PATH`.
- `cargo fmt --manifest-path core\zentor_local_core\Cargo.toml` is blocked because `cargo` is not installed or not on `PATH`.
- `powershell -ExecutionPolicy Bypass -File tools\security\zentor-false-positive-gate.ps1` is blocked because it requires `cargo`.
- `flutter analyze` and `flutter test` are blocked because Flutter is not installed.
- `dart format ...` and `dart test` are blocked because Dart is not installed.
- `flutter test apps\zentor_client\test\update_service_test.dart` is blocked because Flutter is not installed, but the test expectation was updated to require MSI update asset selection.
- `powershell -ExecutionPolicy Bypass -File tools\windows\avorax-installer-stage-test.ps1` is blocked until installer packaging generates `dist\windows-msi\stage`; the script correctly fails when the stage is absent.
- Windows driver validation is blocked by missing Windows, WDK/EWDK, signing, installation, and administrator self-test environment.

## Remaining Work

- Run Rust, Flutter, Dart, false-positive, protection, performance, release, no-malware-binaries, and installer gates in a provisioned environment with Cargo, Flutter, Dart, WiX, and driver tooling available.
- Keep iterating on false-positive policy using signed-publisher validation and real build artifact hash metadata when those are available.
- Continue Phase 2+ implementation in order, without marking driver or production ML features complete until their mandatory validation gates pass.

## Exact Next Step

Commit and push the Avorax installer engine-deployment repair, then let CI build the `v0.2.9` MSI/EXE and inspect any release-workflow failures.

## Handoff

This checkpoint rebrands active product-facing surfaces to Avorax and tightens Guard response policy for confirmed threats. It does not clone malware repos, download malware, execute samples, or ship samples. PowerShell branding, product-copy, and no-malware-binaries gates pass locally. Rust, false-positive, Flutter, Dart, and driver gates remain environment-blocked here and must run in CI or a provisioned environment.

## Final Limitations

Avorax must not claim kernel-level or pre-execution protection until the signed driver path is built, installed, running, and self-tested. No anti-virus can guarantee complete protection.
