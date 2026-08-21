# Checkpoint 2194: Native Engine Windows Roots

Date: 2026-08-21

## Scope And Ownership

This checkpoint removes mutable environment input from Native Engine Windows
system-root decisions. It does not add a second production quarantine engine.
Native Engine remains detection-only in production; Local Core exclusively owns
quarantine, authenticated metadata, recovery, rescan, restore, and deletion.
The legacy Native quarantine store is private `#[cfg(test)]` compatibility code.

No live malware was downloaded, executed, unpacked, or retained. Standard
Defender/EICAR integration was intentionally skipped to avoid repeated Defender
alerts; only safe simulators and benign fixtures were used. No Defender setting,
service, driver, machine-wide dependency, package installation, publication, or
release changed.

## Finding

Native Engine Authenticode helper discovery and local Microsoft system-path
trust used independently validated `SystemRoot`/`WINDIR` candidates. Candidate
validation rejected malformed paths, but mutable process environment still
selected the root. The test-only legacy Native quarantine store also invoked
`icacls.exe` and used mutable `USERNAME`/`USERDOMAIN` values to construct ACLs.

## Implementation

The new Windows-only `windows_system` module:

1. calls `GetSystemWindowsDirectoryW` with one 32,768-code-unit buffer;
2. initializes unused space with a non-NUL sentinel and validates API result,
   returned length, embedded NULs, and API-written termination;
3. requires a rooted local-drive path containing only normal components;
4. rejects symbolic-link/reparse ancestors and targets and verifies expected
   directory or regular-file types;
5. accepts only bounded fixed System32 helper components; and
6. caches one immutable success or error per process.

Authenticode discovery now selects only checked
`System32\WindowsPowerShell\v1.0\powershell.exe`. The existing helper runner
keeps closed stdin, a 30-second deadline, and 64 KiB output bounds. Local
Microsoft artifact trust requires both checked system location and valid
Microsoft Authenticode; location alone never creates a clean verdict.

The test-only legacy quarantine store delegates Windows private-directory
hardening to `avorax_platform_security`. That implementation derives the
current token SID, applies a protected exact DACL, and reads it back for exact
verification. It does not launch `icacls.exe` or consume account-name
environment variables.

## Dependency And Lock Evidence

- `windows-sys` remains pinned at root-workspace version `0.61.2`, with the
  required Foundation and SystemInformation feature gates.
- `avorax_platform_security` is an internal Windows target dev-dependency used
  only by the disabled legacy-store tests.
- The standalone Native Engine lock was regenerated offline in an isolated
  temporary directory: 89 packages/88 registry checksums became 72/70.
- Every one of those 70 exact registry package versions already appears in the
  root workspace lock.
- Standalone `cargo check --all-targets --locked --offline` passes.

## Local Verification

Commands were run from the repository root with the installed pinned toolchain:

```powershell
cargo test --manifest-path core\zentor_native_engine\Cargo.toml native_windows -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml authenticode_ -- --test-threads=1
cargo test --manifest-path core\avorax_platform_security\Cargo.toml windows_ -- --test-threads=1
cargo test --manifest-path core\zentor_native_engine\Cargo.toml --all-targets
cargo clippy --manifest-path core\zentor_native_engine\Cargo.toml --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --quiet
Push-Location apps\zentor_client
flutter test
Pop-Location
python -B tools\testing\run-python-source-contracts.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .verification\checkpoint-2194-small-threat-mvp-definitive-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -RepoRoot (Get-Location).Path -ReportPath .verification\checkpoint-2194-small-threat-mvp-definitive-report.json -RequireFullSuite
```

Results:

- Native Windows-root focused regressions: `10/10`;
- Authenticode unsigned/Microsoft-signed runtime probes: `2/2`;
- shared platform Windows ACL/SID regressions: `4/4`;
- Native Engine: 442 library plus 6 binary tests;
- locked Rust workspace: `1,486/1,486`;
- Flutter client: `838/838`;
- Python source contracts: `626/626`;
- strict Native Clippy, rustfmt, PowerShell parsers, standalone offline all-target
  check, and `git diff --check`: passed;
- definitive central report: `223/223`, zero failed/skipped steps and empty
  error, from `2026-08-21T14:40:21.946741Z` through
  `2026-08-21T14:49:04.2857232Z`, `522.3s`;
- independent full-report validator: passed in `1.5s`.

Before standalone-lock regeneration, the stale checkpoint-2193 dependency
evidence was rejected because its Native standalone package count was 89 while
the current dependency graph expected 72. The lock was then regenerated
offline and all exact versions cross-checked against the root lock; no failure
was relabeled as success.

Read-only ProgramData quarantine inventory after verification remains 16,072
files, zero directories, 4,522,733 bytes, 5,357 complete
payload/metadata/auth sets, one metadata-auth key, and zero pending files. No
vault content was modified or deleted.

## Hosted Status

Implementation commits `7cdf7caf5fa0c0e0d66fb66dc9fa397128b74dcb` and
`1dee3e25d5131d9b999cce7580e5df0f59a82f47` are on draft PR `#46`.
Exact implementation-head Avorax CI `32493387468` passes:

| Job | ID | Result |
| --- | ---: | --- |
| Branding and copy gate | `96806051765` | passed |
| Flutter client and protocol | `96806052867` | passed |
| Rust local core and guard | `96806052318` | passed |
| Security, protection, and performance gates | `96806052162` | passed |
| Unix quarantine permission runtime | `96806051980` | passed |

Exact implementation-head Desktop Packages push run `32493383509` passes:

| Job | ID | Result |
| --- | ---: | --- |
| Package contracts | `96806167159` | passed |
| Windows x64 MSI and EXE | `96806215905` | passed |
| Linux x64 DEB and tar | `96806215950` | passed |
| macOS arm64 DMG | `96806216089` | passed |
| macOS x64 DMG | `96806215919` | passed |
| Consolidate and checksum | `96810781054` | passed |
| Publish desktop beta prerelease | `96810863387` | skipped |

Exact implementation-head Desktop Packages PR run `32493387522` passes:

| Job | ID | Result |
| --- | ---: | --- |
| Package contracts | `96806163063` | passed |
| Windows x64 MSI and EXE | `96806225004` | passed |
| Linux x64 DEB and tar | `96806225056` | passed |
| macOS arm64 DMG | `96806224915` | passed |
| macOS x64 DMG | `96806224968` | passed |
| Consolidate and checksum | `96810450806` | passed |
| Publish desktop beta prerelease | `96810546778` | skipped |

No package was installed, published, or released.

## Classification

- **Verified:** bounded OS-root parser/resolver, environment-spoof rejection,
  fixed PowerShell discovery, Microsoft path-plus-Authenticode trust, shared
  token-SID DACL compatibility tests, dependency/lock evidence, all local
  regressions, central report, and exact implementation-head CI/packages.
- **Partial:** documentation/evidence-head and merged-main hosted checks,
  installed package click-through, installed LocalSystem helper execution, and
  protected helper ACL attack E2E.
- **Disabled / blocked:** production Native quarantine mutation, 32-bit Windows,
  production code signing, signed-driver IPC, and pre-execution enforcement.
- **Technically limited:** metadata validation and later process launch are not
  atomic; Windows and its protected system tree remain trusted. User-mode
  monitoring can miss short-lived activity and does not replace Defender or
  provide kernel blocking.
