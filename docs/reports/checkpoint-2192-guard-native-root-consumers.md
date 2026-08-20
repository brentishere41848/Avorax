# Checkpoint 2192 Guard Native Root Consumers

## Scope

Checkpoint 2192 consolidates the remaining Guard Service consumers that could
derive a Windows system path or system-path trust decision from mutable
`SystemRoot` or `WINDIR` process-environment values. It changes no detection
threshold, quarantine record, service registration, driver state, Defender
setting, installer, dependency version, or release.

The affected controls are:

- driver-health discovery for `sc.exe`, `fltmc.exe`, `bcdedit.exe`, and Windows
  PowerShell;
- driver-IPC fail-open recognition for the real `System32` and `SysWOW64`
  trees;
- the existing process-skip root and `taskkill.exe` discovery, which now use
  the same checked module instead of duplicating its validation.

Native Engine Authenticode and quarantine helper discovery remain separate and
are not claimed fixed by this checkpoint.

## Security Change

`windows_system.rs` remains the only Guard module that calls
`GetSystemWindowsDirectoryW`. In addition to its bounded 32,768 UTF-16 parser,
it now exposes checked operations that:

1. require a rooted local drive returned by Windows;
2. reject non-normal lexical components;
3. inspect every existing ancestor and the final target without following
   links;
4. reject symbolic links and Windows reparse points;
5. require the Windows root to be a directory and a selected helper to be a
   regular file;
6. accept only 1-8 relative helper components, each at most 128 characters and
   restricted to ASCII alphanumeric, dot, hyphen, or underscore characters.

Driver health retains its component-specific executable allowlist. PowerShell
is fixed beneath `System32\WindowsPowerShell\v1.0`; the other three tools are
fixed directly beneath `System32`. The existing bounded 30-second command
runner, closed stdin, capped diagnostics, and kill/reap error reporting are
unchanged.

Driver IPC no longer creates trusted Windows-directory candidates from
environment variables. It obtains one checked native directory once and caches
the immutable success or error for the Guard process lifetime, avoiding Win32
and ancestor metadata work on every event. Resolver failure propagates through
verdict evaluation instead of becoming an empty or silently substituted trust
root. Native driver-port handling converts that visible evaluation error to its
existing reason-bearing fail-open verdict, avoiding an unexplained
operating-system lockout. Direct command callers receive an explicit error.

## Threat Model

The closed attack is root selection through inherited or deliberately changed
`SystemRoot`/`WINDIR` values. Such values can no longer redirect Guard to launch
a lookalike system helper or grant a lookalike tree the driver-IPC system-path
exception.

Windows, the Win32 ABI definitions in locked `windows-sys 0.61.2`, filesystem
metadata, the process token, and Windows protection of the real system tree
remain in the trusted computing base. Metadata validation followed by process
creation is not an atomic handle-based launch, so a privileged actor capable of
replacing protected system paths remains outside this user-mode guarantee.

The driver-IPC exception for the real `System32` and `SysWOW64` trees is still
broad and path-based. It prevents recursive operating-system blocking but is
not Authenticode verification and does not prove every resident file benign.
Production-signed driver IPC, installed LocalSystem behavior, helper ACLs, and
pre-execution enforcement still require a disposable elevated Windows host.

## Verification

The following commands passed from the repository root:

```powershell
cargo test --locked -p zentor_guard_service windows_system -- --test-threads=1
cargo test --locked -p zentor_guard_service -- --test-threads=1
cargo test --locked --workspace -- --test-threads=1
cargo clippy --locked -p zentor_guard_service --all-targets --all-features -- -D warnings
cargo build --locked --release -p zentor_guard_service
C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -B tools\testing\run-python-source-contracts.py
```

Results:

- native Windows-root filter: `5/5`;
- complete Guard Service: `247/247`;
- complete locked Rust workspace: `1,479/1,479` across 11 test targets;
- Python source contracts: `626/626`;
- strict Guard Clippy, Guard rustfmt, release build, and both modified
  PowerShell parser checks: passed;
- central small-threat verifier: `221/221`, zero failed or skipped steps and an
  empty error, from `2026-08-20T13:48:37.5422686Z` through
  `2026-08-20T14:00:19.886874Z` (`702.3s`);
- independent full-report validator: passed in `2.0s`;
- stale checkpoint-2191 report: rejected as expected because it lacked
  `guard-service native Windows root regressions`.

The central report is local untracked evidence at
`.verification/checkpoint-2192-small-threat-mvp-definitive-report.json`. Standard
EICAR/Defender integration remained opt-in and was skipped; safe simulators and
benign fixtures were used. One preliminary inline PowerShell parser wrapper had
a quoting error around `$file:`; the corrected wrapper parsed both scripts and
no product parser or test failed.

Read-only post-verification inventory of `C:\ProgramData\Avorax\Quarantine`
remains exactly 16,072 files, zero directories, 4,522,733 bytes, 5,357 complete
`.avoraxq`/`.json`/`.auth` sets, one `.metadata_auth_key`, and zero pending
files. No vault content was changed or deleted.

## Hosted Evidence

Implementation commit `f6a40cc200764d0925bbcc3032a74e87be21b232` is
published on draft PR `#44`. Exact-head Avorax CI run `32378264705` passed its
security/protection/performance, Flutter/protocol, Rust local-core/Guard, Unix
quarantine-permission, and branding/copy jobs.

Desktop Packages push run `32378112753` and PR run `32378264725` passed package
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMGs, and
consolidated checksum evidence. Consolidation jobs `96458306800` and
`96459611854` passed. Publish jobs `96458410803` and `96459718001` were
intentionally skipped. This is build evidence, not installed-package or
runtime protection evidence.

## Classification

- **Verified:** native root parsing, component validation, local-drive and
  reparse checks, Guard tool allowlists, environment-spoof resistance, visible
  resolver errors, complete local Rust/source/full-suite regression, and
  release compilation, plus exact implementation-head CI and desktop package
  construction.
- **Partial:** live driver-health commands are covered by bounded runner and
  path tests, but an installed service/driver command lifecycle was not run.
- **Blocked:** production-signed driver install/load/unload/rollback,
  authenticated installed driver IPC, LocalSystem ACL/lifetime evidence, and
  genuine pre-execution blocking.
- **Technically limited:** user-mode metadata-to-launch time-of-check/time-of-use
  exposure and broad actual-system-tree fail-open/process-skip policy.

No package was installed, published, or released.
