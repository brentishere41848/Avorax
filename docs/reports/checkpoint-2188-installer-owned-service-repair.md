# Checkpoint 2188 Installer-Owned Service Repair

Date: 2026-08-20

## Objective

The desktop client exposed a service-repair action that could elevate a service
registration command assembled from a constructor or environment executable
override. A same-user process could therefore propose an untrusted executable
for `New-Service` or `Set-Service`; accepting the UAC prompt would cross the
privilege boundary with attacker-controlled path input.

This checkpoint removes service registration and reconfiguration from the
unprivileged Flutter application. Installation repair is now explicitly owned
by a verified official MSI/EXE installer. The existing-service start action is
kept narrow and can only query or start the fixed `avorax_core_service` name.

## Change

`LocalCoreClient.repairInstallation()` now returns one stable fail-closed
blocker and never resolves an executable, starts a process, or elevates:

```text
In-app service registration is disabled. Installation repair is owned by the
Avorax MSI/EXE installer; reinstall Avorax using a verified official installer
package.
```

The old repair executable resolvers, development registration exception,
`New-Service`, `Set-Service`, and elevated repair command were removed. The
remaining elevated helper is reachable only from `startCoreService()`, uses the
fixed service name, and no longer supplies `-ExecutionPolicy Bypass` to either
PowerShell process.

The Scan screen presents repair state honestly:

- the diagnostic states that installer repair is required and in-app service
  registration is disabled;
- the control remains visible for inventory and accessibility, but is rendered
  as disabled `Repair unavailable` with the exact blocker in its tooltip;
- there is no callback or confirmation dialog and therefore no fake success;
- the controller retains a defense-in-depth method for stale callers, but both
  confirmed and unconfirmed requests log `installation_repair_blocked` and
  never log `installation_repair_requested`.

The UI inventory keeps the stable `Scan / Repair installation` control ID while
classifying its backing action as `No callback`. Threat-model, blocker, control
matrix, UI, verifier-scope, and source-contract documentation now use the same
boundary.

## Rust Test Isolation Repair

The first post-change Rust workspace run exposed a pre-existing test isolation
race. Native Engine tests changed `AVORAX_QUARANTINE_DIR` in the shared process
while a parallel configuration test read it, producing one honest failure.

All eight Native Engine tests that require environment overrides now rerun their
exact test case in a bounded child test process. The parent process never calls
`set_var` or `remove_var`, each child inherits only its explicit override, and
normal parallel engine/configuration tests cannot observe the temporary value.
This changes test code only; production configuration validation remains
fail-closed.

## Local Verification

```powershell
flutter test test\local_core_ipc_diagnostics_test.dart test\app_visual_policy_test.dart test\scan_screen_test.dart test\offline_scan_test.dart
# 380 passed; 0 failed

flutter test
# 838 passed; 0 failed

flutter analyze
# No issues found

dart format --output=none --set-exit-if-changed lib test
# 84 files; 0 changed

python tools\testing\run-python-source-contracts.py
# 625 passed; 0 failed

cargo test -p zentor_native_engine --lib --locked
# 435 passed; 0 failed; 0 ignored

cargo test --workspace --locked
# 1,458 passed; 0 failed; 0 ignored

cargo clippy -p zentor_native_engine --all-targets --locked -- -D warnings
# passed; 0 warnings

cargo fmt --all -- --check
# passed

python tools\testing\validate-client-ui-inventory.py
# 11 routes; 9 desktop destinations; 4 mobile destinations;
# 61 source-accounted controls; passed
```

The final central verifier command is:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot . -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .verification\checkpoint-2188-small-threat-mvp-final-report.json
```

The final report spans `2026-08-20T06:09:11.1498909Z` through
`2026-08-20T06:18:06.6204968Z`, has status `passed`, contains exactly `219`
steps with status `passed`, records no step below `0.1s`, reports `535.4s`
overall, and has an empty error field. The verifier's built-in
`-RequireFullSuite` validator passed in `1.6s`; a separate invocation of the
same validator also passed with `steps: 219` and `require_full_suite: True`.

## Hosted Verification

Exact implementation head
`b67e787a0db0aa08ab82ae7ecc26f975399d4628` passed Avorax CI run
`32339319834`. All five jobs completed successfully:

| Job | Job ID | Result |
|---|---:|---|
| Rust local core and guard | `96335040453` | Passed |
| Flutter client and protocol | `96335040657` | Passed |
| Branding and copy gate | `96335040703` | Passed |
| Unix quarantine permission runtime | `96335040757` | Passed |
| Security, protection, and performance gates | `96335040818` | Passed |

Desktop Packages push run `32339252987` and pull-request run `32339319827`
also passed on that exact head. Each independently passed package contracts,
Windows x64 MSI/EXE build and extraction verification, Linux x64 DEB/tar,
macOS arm64 and x64 DMGs, and consolidation requiring six release artifacts
with checksums and a lockfile SBOM. The push run package job IDs were
`96334840140`, `96334877357`, `96334877378`, `96334877397`, `96334877414`,
and `96337149167`; the pull-request run package job IDs were `96335040484`,
`96335067167`, `96335067180`, `96335067208`, `96335067257`, and
`96338411636`. Prerelease publication was intentionally skipped in both runs.
No package was installed or published by this checkpoint.

## Failed And Superseded Attempts

- The first four-file Flutter run had one test-only finder failure because a
  diagnostic chip combined its label and value. The finder was corrected before
  the affected suite passed `380/380`.
- The first Python contract run retained one old repair-label assertion. The
  first complete affected Flutter run then exposed one stale
  `escapedExecutable` source assertion. Both test expectations were corrected
  before the complete suites passed.
- `python -m pytest` was attempted with both the AppData and bundled Python
  runtimes. Neither runtime has `pytest`; no package was installed. The
  repository's dependency-free runner passed `625/625` and is the counted
  result.
- The first central verifier reached the UI inventory gate and failed because
  the stable control ID had been renamed. Restoring the stable ID then exposed
  that the inventory validator itself still required the old callback. The
  validator was changed to require the disabled markers and no callback.
- A subsequent central run passed `219/219` in `523.4s`, but it predates the
  Rust test-isolation repair and is retained only as superseded evidence.
- The first full Rust workspace run found the real environment race:
  `config::tests::installed_engine_dir_uses_regular_directory` failed while a
  parallel test temporarily supplied a relative `AVORAX_QUARANTINE_DIR`.
  Child-process isolation was added; Native Engine `435/435` and workspace
  `1,458/1,458` then passed.
- The first strict Clippy run on that helper rejected test modules placed before
  public exports. The modules were moved to the end of the production surface;
  strict Clippy and focused child-process tests were rerun successfully.
- The next complete central run executed every one of its `219` content steps,
  but the independent validator rejected step 210 because a host wall-clock
  adjustment produced a `-0.5s` duration. `Invoke-Step` and overall elapsed
  reporting now use monotonic .NET `Stopwatch` instances, and a source contract
  rejects reintroduction of wall-clock subtraction. The rejected report is not
  counted as success.

No failed or superseded invocation is counted as final success.

## Existing Vault Check

Read-only inventory after focused, full, and central verification remains:

```text
C:\ProgramData\Avorax\Quarantine
16,072 files; 0 directories; 4,522,733 bytes
5,357 .avoraxq payloads
5,357 JSON records
5,357 JSON auth sidecars
1 metadata key
0 .pending journals; 0 .pending.auth sidecars
```

No existing quarantine artifact was changed or deleted.

## Dependency And Diff Review

No manifest or lockfile changed. The repair boundary removes command-generation
code and adds no package, license, build script, network request, service,
driver, scheduled task, or machine-wide component. The child-process test
helper uses only `std::process::Command` and the Rust test harness.

Generated `.verification` evidence remains untracked and is excluded from
publication.

## Classification

| Classification | Control | Evidence and boundary |
|---|---|---|
| Verified locally | In-app registration is unreachable | Direct runtime test with an untrusted executable override returns the exact blocker and launches no process; source contracts reject repair resolvers, registration commands, and elevated repair wiring. |
| Verified locally | Scan repair control is honest | Widget and inventory tests require a disabled control, exact tooltip, no callback, no confirmation dialog, and stable control ID. |
| Verified locally | Controller defense in depth | Confirmed and unconfirmed stale calls emit `installation_repair_blocked`; requested/success events and engine rechecks are absent. |
| Verified locally | Existing-service start boundary | Only fixed `avorax_core_service` query/start behavior remains; no service creation, executable-path registration, or `ExecutionPolicy Bypass` is used by the helper. |
| Verified locally | Test environment isolation | Native Engine `435/435`, workspace `1,458/1,458`, strict Clippy, and child-process environment regressions pass without parent-process environment mutation. |
| Verified locally | Full regression and safety gates | Flutter `838/838`, affected UI `380/380`, source contracts `625/625`, analyzer, formatting, UI inventory, and the final central verifier/report validator pass. |
| Partial / blocked | Installed service repair E2E | Requires a disposable elevated Windows host plus a verified MSI/EXE repair package; the app cannot perform or claim this operation. |
| Partial | Existing installed-service start | The command boundary is tested, but this checkpoint does not install or start a real machine service. UAC rejection and service-manager errors remain visible. |
| Disabled | In-app service install/reconfigure | Permanently disabled by design; official installer reinstall/repair is the only documented route. |
| Technically limited | Protection scope | This privilege-boundary change does not improve detection rates or prove persistent monitoring, kernel interception, pre-execution blocking, secure erase, or Defender replacement. |

No live malware, standard EICAR file, Defender exclusion, service/driver start or
installation, package installation, machine-wide setting, secure-erase action,
existing-vault mutation, or project-file deletion was used. All runtime
fixtures were benign and isolated.
