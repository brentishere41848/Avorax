# Checkpoint 2185 Native Unix Quarantine Runtime CI

Date: 2026-08-20

## Objective

Checkpoint 2184 implemented one shared cross-platform quarantine permission
engine, but its Unix-only mode, ownership, and descriptor-identity tests had not
executed on a native hosted Unix runner. Successful Linux package compilation
was not treated as runtime proof.

## Change

Avorax CI now includes a dedicated `Unix quarantine permission runtime` job on
`ubuntu-24.04`. It uses pinned Rust `1.96.1`, locked workspace dependencies,
fail-fast Bash mode, and a 30-minute job timeout. It does not install system
packages or invoke service, driver, malware, network-feed, or machine-wide
operations.

The job is scoped to nine checkpoint-specific tests:

- five tests from `avorax_platform_security`, including the three Unix-only
  owner/mode and path-replacement cases;
- Local Core's Unix artifact-mode and legacy-mode-repair tests;
- Guard's Unix artifact-mode and authenticated-read mode-repair tests.

A dependency-free Python source contract requires the exact runner, pinned
actions, timeout, toolchain, five `cargo test --locked` invocations, exact test
filters, and serial test execution. It rejects `continue-on-error`, swallowed
shell failure, package installation, and ad hoc network commands in this job.

## Local Verification

```powershell
git diff --check
# passed

python -B tools\testing\run-python-source-contracts.py
# 621 passed; 0 failed

cargo test --locked --manifest-path core\avorax_platform_security\Cargo.toml -- --test-threads=1
# Windows host: 6 passed; 0 failed

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\branding\branding-check.ps1
# passed

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-product-copy-gate.ps1
# passed

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1 -RepoRoot . -PythonPath C:\Users\Brent\AppData\Local\Python\pythoncore-3.14-64\python.exe
# passed
```

The first no-malware-gate invocation used the WindowsApps Python alias and was
rejected because that path traverses a reparse point. That command is not
counted as success. The concrete interpreter path reported by `sys.executable`
was then validated and the gate passed.

## Hosted Classification

| Classification | Control | Evidence and boundary |
|---|---|---|
| Verified locally | Workflow and fail-closed source contract | Source contracts pass `621/621`; Windows platform tests pass `6/6`; diff and safety gates pass. |
| Partial, hosted pending | Native Unix permission runtime | The Ubuntu job has not yet executed on the checkpoint branch. No Unix runtime success is inferred from workflow text, cross-compilation, or package builds. |
| Unchanged partial | Installed Windows quarantine | LocalSystem ownership, DPAPI, unprivileged UI/service mediation, repair/upgrade, and package install/uninstall need a disposable elevated Windows host. |
| Technically limited | Filesystem and principal boundary | Same-UID/SID processes, administrators/root, alternate hard links, and path-based ancestor races remain documented limits. Permissions do not encrypt or securely erase payloads and do not prove pre-execution blocking. |

No live malware, standard EICAR string, Defender exclusion, package install,
service/driver operation, machine-wide component, project-file deletion, or
existing quarantine deletion was used.
