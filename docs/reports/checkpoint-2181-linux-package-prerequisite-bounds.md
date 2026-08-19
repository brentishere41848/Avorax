# Checkpoint 2181 Linux Package Prerequisite Bounds

Date: 2026-08-19

## Finding

The duplicate pull-request Desktop Packages run for checkpoint 2180 did not
reach Avorax project code on Linux. Two separate GitHub-hosted Ubuntu attempts
remained in the native prerequisite `apt-get update` or install step until they
were deliberately cancelled. The exact-commit branch run completed the same
Linux package job successfully, so this was not recorded as a scanner or Linux
package test failure. The unbounded prerequisite commands were still an
operational reliability gap.

## Repair

The Linux package job now invokes
`tools/packaging/install-linux-build-prerequisites.sh`. The helper:

- validates timeout, attempt, and delay configuration as canonical bounded
  integers;
- rejects any combined per-operation retry budget above 1,200 seconds;
- gives each `apt-get` process a 300-second default timeout and a 15-second
  termination grace;
- permits three bounded command attempts with five seconds between attempts;
- configures two APT acquisition retries and 30-second HTTP, HTTPS, and package
  lock timeouts;
- reports timeout versus other exit codes explicitly; and
- returns the final non-zero status after retry exhaustion.

The default worst-case budget is 955 seconds for `apt-get update` and another
955 seconds for install. The workflow's existing 100-minute whole-job timeout
remains an independent outer bound.

## Verification

Passed locally without running `apt-get`, installing packages, or changing the
host:

```powershell
C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m unittest discover -s tests -p test_packaging_tools.py -v
# 23 tests passed; 3 Windows symlink tests skipped as designed.

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py
# 617 tests passed.

& 'C:\Program Files\Git\bin\bash.exe' -n tools/packaging/install-linux-build-prerequisites.sh
# Passed.
```

Function-level harmless command doubles also proved that a synthetic exit 124
is retried before success, timeout value `008` is rejected with exit 2, and a
1,830-second combined configuration is rejected with exit 2. A persistent
synthetic exit 42 was attempted exactly twice, never reached the install
operation, and propagated exit 42 after retry exhaustion. The test doubles
replace `sudo`, `timeout`, `apt-get`, and `sleep`; no native package command is
executed. `git diff --check` passes.

GitHub package contracts and the Linux x64 DEB/tar job are required to pass on
the published checkpoint before merge. Their exact run IDs are retained in the
pull-request checks and final checkpoint comment.

## Scope And Remaining Risk

This change improves CI cancellation, retry, and failure reporting only. It
does not alter detection engines, runtime privileges, package contents, or the
readiness estimates in checkpoint 2180. A GitHub package mirror can still fail;
it must now fail visibly inside a finite budget instead of appearing to hang.
Installed Linux package smoke, production signing, installed Windows
service/ACL/DPAPI E2E, signed-driver proof, and production detection calibration
remain partial or blocked as previously documented. No threat-model trust
boundary changes were introduced.
