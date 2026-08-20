# Checkpoint 2191 Native System-Root Process Skip

Date: 2026-08-20

## Objective

Checkpoint 2190 made Windows process enumeration native and bounded. Review of
the next policy layer found that Guard still inferred `X:\Windows` from each
observed process path before deciding whether to skip inspection. An executable
at `D:\Windows\System32\payload.exe` could therefore receive the Windows-system
skip even when the operating system's shared Windows directory was on `C:`.

This checkpoint removes observed-path and environment control over that root.
It does not broaden Avorax's claim beyond best-effort post-launch user-mode
observation.

## Change

The new Windows-only `windows_system.rs` module:

- calls `GetSystemWindowsDirectoryW` directly through the existing locked
  `windows-sys` dependency;
- allocates one 32,768-code-unit UTF-16 buffer initialized to a non-NUL
  sentinel, so termination must be written by the API;
- treats an API return of zero as an operating-system error;
- rejects a returned length at or beyond the buffer bound;
- rejects embedded NUL code units and missing termination; and
- converts only the returned prefix to an operating-system path.

Production Guard then:

- requires the result to be an absolute rooted local Windows disk path;
- rejects a symlink/reparse target and every existing linked/reparse ancestor;
- creates one immutable `ProcessSkipPolicy` when finite or persistent process
  watching starts;
- compares observed process paths only with that policy's root;
- preserves the existing skip for the actual root's `System32`, `SysWOW64`, and
  `Explorer.exe`;
- does not skip other-drive, `Windows.old`, traversal, or user-profile
  lookalikes; and
- resolves the checked `taskkill.exe` helper from the same native root and
  validates its complete ancestor chain.

The dead `powershell.exe` branch in Guard's main process-stop helper was removed;
that helper is now explicitly allowlisted to `taskkill.exe`. Guard driver-health
and driver-IPC modules have distinct helper implementations and are unchanged.
Native Engine Authenticode and quarantine helpers are also outside this
checkpoint.

No dependency version changed. `windows-sys` remains locked at `0.61.2`; its
enabled feature set adds `Win32_System_SystemInformation`. `Cargo.lock` is
unchanged.

## Security Boundary

The shared Windows directory supplied by the operating system is inside the
trusted computing base. Guard fails visibly if it cannot obtain and validate
that directory; there is no fallback to `SystemRoot`, `WINDIR`, hard-coded
`C:\Windows`, or the observed executable's drive.

The policy still skips all paths beneath the actual `System32` and `SysWOW64`
directories plus the actual `Explorer.exe`. This is a broad path exclusion, not
publisher verification or proof that every file in those locations is benign.
Replacing it safely requires a separate identity/publisher design and
production false-positive testing.

Process polling remains post-launch. It can miss a process that starts and
exits between snapshots, protected processes can deny image queries, and
same-path PID reuse can be indistinguishable. The signed-driver path is not
installed or claimed by this checkpoint.

## Focused Verification

```powershell
cargo test --locked -p zentor_guard_service process_skip -- --test-threads=1
# 3 passed; 0 failed

cargo test --locked -p zentor_guard_service windows_system_directory -- --test-threads=1
# 3 passed; 0 failed

cargo test --locked -p zentor_guard_service process_watch -- --test-threads=1
# 1 passed; 0 failed

cargo test --locked -p zentor_guard_service process_collection -- --test-threads=1
# 14 passed; 0 failed

cargo test --locked -p zentor_guard_service -- --test-threads=1
# 244 passed; 0 failed; 0 ignored

cargo test --workspace --locked -- --test-threads=1
# 1,476 passed; 0 failed; 0 ignored

cargo clippy --locked -p zentor_guard_service --all-targets -- -D warnings
# passed; 0 warnings

cargo fmt --all -- --check
# passed

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py
# python source-contract run passed: 626 tests

cargo build --release --locked -p zentor_guard_service
# passed
```

Both modified PowerShell verification scripts parse successfully.
`git diff --check` passes, and an explicit `Cargo.lock` diff check is empty.

## Adversarial Runtime Evidence

The release Guard received the same bounded two-snapshot command for three
fresh child processes:

```powershell
$payload = '{"command":"watch_processes","poll_interval_ms":100,"max_iterations":1,"protection_mode":"observeOnly"}'
$payload | .\target\release\zentor_guard_service.exe
```

The middle child alone received:

```text
SystemRoot=Q:\Avorax-Lookalike-Windows
WINDIR=Q:\Avorax-Lookalike-Windows
```

| Run | Environment | Elapsed | Exit | Response | Gaps | Stderr |
| --- | --- | ---: | ---: | --- | ---: | --- |
| 1 | Normal | 82.2 ms | 0 | `ok:false`, `watchCompletedWithCoverageGaps` | 280 | Empty |
| 2 | Spoofed child | 74.2 ms | 0 | `ok:false`, `watchCompletedWithCoverageGaps` | 280 | Empty |
| 3 | Normal | 73.6 ms | 0 | `ok:false`, `watchCompletedWithCoverageGaps` | 280 | Empty |

The gap count is a live two-snapshot occurrence count, not unique processes,
malware, or threats. The expected first limitation remained protected-process
access denial. No process was stopped or quarantined.

## Central Verification

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot . -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .verification\checkpoint-2191-small-threat-mvp-final-report.json
```

The definitive report spans `2026-08-20T11:48:39.5771068Z` through
`2026-08-20T11:57:45.1272217Z`. It records status `passed`, exactly `220/220`
passed steps, zero failures, an empty error, and `545.5s` elapsed. The built-in
independent validator with `-RequireFullSuite` passes in `1.6s`.

The required scope now states that Guard Windows process skips and taskkill
discovery use the bounded native system Windows directory and reject
environment or other-drive lookalikes. Standard EICAR/Defender integration is
opt-in and was not run. Safe simulators, isolated temporary data, scan,
quarantine, restore, delete, allowlist, cancellation, watcher, process,
signed-update, tamper, UI inventory, Flutter, source, branding, no-malware,
false-positive, protection, performance, and dependency gates all pass.

## Existing Vault Check

Read-only inventory after focused, full, release, adversarial, and central
verification is unchanged:

```text
C:\ProgramData\Avorax\Quarantine
16,072 files; 0 directories; 4,522,733 bytes
5,357 .avoraxq payloads
5,357 JSON records
5,357 auth sidecars
1 .metadata_auth_key
0 pending journals or sidecars
```

No existing quarantine artifact was changed or deleted.

## Failed And Superseded Attempts

- The first source-contract run correctly found two assertions that still
  described environment-root and observed-drive behavior. The production
  change and contracts were aligned before the final `626/626` run.
- The first strict Guard Clippy run found one needless `return` and three
  needless borrows. Those local style issues were corrected before the final
  warning-free check.
- The first spoofed-environment child command accidentally invoked a stale
  debug executable and returned `action:error`. After an explicit debug rebuild,
  the identical command passed; final evidence uses a fresh release rebuild.
- `python -m unittest tests.test_custom_driver_contract` discovered zero tests
  because the file contains pytest-style functions. No dependency was
  installed; the repository's dependency-free runner is the counted
  `626/626` result.
- An optional workspace-wide strict Clippy invocation reached three existing
  `services/api` style lints (`enum_variant_names` and
  `items_after_test_module`). This is not counted as success. The changed Guard
  crate passes strict Clippy, the API compiles, and all `1,476` workspace tests
  pass.
- Earlier release timing runs before the final parser termination check and a
  first result parser that looked for a nonexistent JSON gap field are
  superseded by the final three-run table above.

## Hosted Evidence

Exact implementation/local-evidence head
`67e067d2d74d7561c4a48269284702ca50f1b1a1` passes Avorax CI run
`32366912857`. Its five jobs pass:

- Rust/local-core/Guard/update/API `96418298360`;
- branding/copy `96418298483`;
- security/protection/performance `96418298492`;
- Flutter/protocol `96418298532`; and
- native Unix quarantine/Guard routing `96418298685`.

Desktop Packages push run `32366882138` and pull-request run `32366913124`
both pass package contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS
x64/arm64 DMGs, and consolidated checksum/lockfile-SBOM evidence.
Consolidation jobs `96422164489` and `96422683427` pass. Publish jobs
`96422235471` and `96422771716` are intentionally skipped. No package was
installed or released.

Documentation evidence head
`7a48c013a126e9bd68fa705fa7295f6027e29fec` passes Avorax CI
`32368675449` and Desktop Packages PR run `32368675439`; consolidation
`96427640105` passes and publish `96427739316` is skipped. PR `#43` merged as
`d35ed9e9081a0ffb246a6350688bd833bfa6fe9d`. Merged-main CI
`32369958558` and Desktop Packages `32369958304` pass; consolidation
`96431254827` passes and publish `96431345741` is skipped.

## Classification

| Classification | Control | Evidence and boundary |
| --- | --- | --- |
| Verified locally | Native Windows directory parser | Bounded FFI result handling, malformed-result fixtures, and real Windows runtime pass. |
| Verified locally | Process-skip root selection | Actual-root paths retain policy; other-drive and path lookalikes do not select their own skip root. |
| Verified locally | Guard taskkill path | Native root, full ancestor checks, allowlisted leaf, and bounded runner source/runtime contracts pass. |
| Verified locally | Shared regression | Guard, workspace, source contracts, release build, central verifier, and report validator pass. |
| Verified hosted and merged | Hosted and packaged regression | Implementation `67e067d2d74d7561c4a48269284702ca50f1b1a1`, evidence `7a48c013a126e9bd68fa705fa7295f6027e29fec`, and merged main `d35ed9e9081a0ffb246a6350688bd833bfa6fe9d` pass CI and Windows/Linux/macOS package construction plus checksum/SBOM consolidation; publish is skipped. |
| Partial / blocked | Installed LocalSystem behavior | Installed service identity, visibility, ACLs, event logging, lifetime, shutdown, and UI mediation need a disposable elevated host. |
| Technically limited | Real Windows system-directory skip | Actual-root `System32`, `SysWOW64`, and `Explorer.exe` remain broadly path-excluded. |
| Technically limited | User-mode timing and visibility | Polling is post-launch, misses some short-lived processes, and cannot query every protected image. |
| Superseded follow-up | Other helper-root implementations | Checkpoint 2192 moves Guard driver-health and driver-IPC roots to the shared native resolver. Native Engine Authenticode/quarantine helpers remain separate. |

No live malware, downloaded malware repository, standard EICAR file, Defender
exclusion, service/driver operation, installer execution, machine-wide change,
secure-erase claim, network sample, or release was used. Generated
`.verification` evidence remains untracked.
