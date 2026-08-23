# Checkpoint 2206: Authenticode Sanitized Launch Context

## Status

Verified locally. Implementation, benign regression fixtures, source
contracts, definitive verifier/validator changes, audit records, and this
report were scripted as one batch before test execution. Historical sequencing
record: No checkpoint-2206 passing result is claimed before execution.

## Objective

The one-shot Windows Authenticode helper previously passed null environment and
current-directory pointers to `CreateProcessAsUserW`. Windows therefore copied
the complete caller environment and caller current directory into the child.
Those ambient values are unnecessary for Avorax's direct handle-based trust
flow and can influence library/configuration discovery in future code.

Checkpoint 2206 supplies an explicit bounded Unicode environment containing
exactly `SystemRoot` and `WINDIR`. Both values come from the existing checked
native `GetSystemWindowsDirectoryW` path, never from process environment state.
It also supplies the checked, non-reparse native `System32` directory as the
child current directory and sets `CREATE_UNICODE_ENVIRONMENT`.

There is no fallback to inherited environment or current-directory state.
Root resolution, directory validation, UTF-16 construction, process creation,
or child launch failure remains diagnostic and cannot become Microsoft
publisher trust.

## Security Contract

- Environment names are fixed to `SystemRoot` and `WINDIR`, in deterministic
  order, with a double-NUL-terminated UTF-16 block.
- Values are one normalized absolute local drive path with no parent traversal,
  UNC/device prefix, embedded NUL, or oversized encoding.
- The current directory is the existing bounded, checked, non-reparse native
  `System32` directory and is passed explicitly as NUL-terminated UTF-16.
- `CreateProcessAsUserW` receives `CREATE_UNICODE_ENVIRONMENT`; neither launch
  pointer is null.
- Existing absolute image path, strict command tokens, exact three-handle
  inheritance, suspended creation, Job assignment, restricted primary token,
  write-restricted request/output thread tokens, nonce/hash binding, timeouts,
  and fail-visible cleanup remain unchanged.

Microsoft documents that null `lpEnvironment` and `lpCurrentDirectory` inherit
caller state, and that a Unicode block requires `CREATE_UNICODE_ENVIRONMENT`:
[CreateProcessAsUserW](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).

## Verified Evidence

| Control | Evidence | Classification |
| --- | --- | --- |
| Exact environment encoding | Pure regression checks ordering, exact entries, double terminator, local-path policy, traversal/UNC/verbatim-device/NUL rejection | Verified locally |
| Real child environment | Ignored child fixture requires exactly two environment entries and native-root values | Verified locally |
| Real child current directory | The same child requires its current directory to equal checked native `System32` | Verified locally |
| Trust compatibility | Embedded Edge and catalog-backed WindowsPowerShell release smoke passed through Local Core and Guard; unsigned and wrong-hash cases remained rejected | Verified locally |
| Central evidence | Dedicated verifier step raises the exact report count from 235 to 236; validator requires the step and exact scope | Verified locally |
| Dependency boundary | Existing pinned `windows-sys 0.61.2` bindings and existing Windows-root module only; Cargo and Flutter lockfiles are unchanged | Verified locally |

Focused evidence passed: sanitized launch `2/2`, restricted-process `2/2`,
write-restricted-token `2/2`, complete Authenticode `33/33` with four isolated
child fixtures intentionally ignored, strict Native Clippy, source contracts
`635/635`, locked Local Core/Guard release builds, and embedded/catalog
two-host release smoke. Candidate fixtures were never executed.

Both locked workspace variants, strict Native/Local/Guard lint, Flutter
analyzer and `838/838`, source contracts `635/635`, package/source gates, and
the definitive verifier passed. The final report contains exactly `236/236`
passed steps from `2026-08-23T08:50:36Z` through `2026-08-23T08:58:18Z`
(`461.7s`). Built-in and independent strict validation passed. Controlled
stale-count, missing-step, and missing-scope reports were rejected and removed.

The final local report is
`.workflow/ultracode/avorax-hardening/results/2206-small-threat-mvp-sanitized-launch-final-report.json`.
Exact-head hosted checks, PR integration, merged-main checks, and
preconditioned original-tree synchronization remain pending.

## Limits

This removes ambient parent environment and current-directory input; it does
not create identity isolation. The child keeps the parent SID, integrity level,
desktop/window station, and ordinary read access. Same-process code can mutate
its own environment, call `RevertToSelf`, and access objects allowed by its
tokens. The environment contains Windows-root values because the Windows trust
stack is the supported provider. This is not AppContainer, a separate desktop,
authenticated cross-identity IPC, or a guarantee that Windows components never
consult other per-user state such as registry profile data.

Job commit limits still do not bound physical working set or I/O bytes;
WinTrust/catalog still execute under the privilege-stripped primary token for
documented compatibility. Writable mappings, post-verdict mutation, installed
LocalSystem E2E, production signing, signed-driver IPC, pre-execution blocking,
Defender replacement, and production detection-rate evidence remain partial,
blocked, or technically limited.

## Safety

Tests use ignored benign Rust child fixtures, installed read-only Microsoft
binaries, and temporary benign text only. Candidate fixtures are never
executed. No live malware, download, install, service/driver start, Defender
change, release, publication, or protected-quarantine mutation is permitted.
