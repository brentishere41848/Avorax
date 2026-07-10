# Protection Self-Test

Avorax protection self-test is a Windows development validation workflow. It uses EICAR and harmless test binaries only. It does not use real malware.

## One-Command Workflow

Run this from the repository root on a disposable Windows driver-development VM:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-protection-selftest.ps1 -BuildDriver -InstallDriver -ConfirmDriverInstall -CargoPath C:\Path\To\cargo.exe
```

The self-test refuses ambient Cargo lookup. Pass `-CargoPath` or set `CARGO` to an absolute local Cargo executable path.
Driver installation is separately confirmation-gated. If `-InstallDriver` is supplied, `-ConfirmDriverInstall` must also be supplied or the wrapper stops before invoking driver install scripts.

The workflow writes:

```text
dist\windows-driver-validation\selftest_report.json
```

## What It Verifies

- Guard self-test handler can answer in the launched Guard process. This is process/handler evidence only; installed Windows service evidence still comes from service-control probes and driver validation reports.
- Minifilter driver is installed and running.
- Driver-service communication is available.
- EICAR/safe EICAR simulator returns a confirmed block verdict.
- Harmless known-bad test executable returns a block verdict by test hash.
- Post-launch verdict fallback remains available only when the safe block, allow, and review fixtures all return the expected Guard verdicts; it must not be hardcoded as passed.
- Local AI model status is reported honestly.

If the driver is missing or not running, the report must fail and Avorax must show post-launch fallback instead of pre-execution blocking.

Legacy `guard_service.running` and `guard_service.ipc_ok` report fields are compatibility evidence only. `running` is derived from the visible Guard self-test handler step, and `ipc_ok` is derived from handler availability plus computed post-launch verdict fallback evidence; neither field proves an installed Windows service by itself.

The legacy `guard_service.verdict_cache_ok` report field remains `false` until a real Guard verdict-cache implementation and self-test exist. It must not be used as proof of protection or cache health.

## Test Signing

Avorax does not enable TESTSIGNING automatically. For a development VM only:

```powershell
# If Secure Boot is enabled, disable it in UEFI firmware first.
powershell -ExecutionPolicy Bypass -File tools\windows\avorax-enable-test-signing.ps1 -ConfirmTestSigningChange
shutdown /r /t 0
```

If enabling TESTSIGNING reports that the value is protected by Secure Boot policy, run the elevated helper `tools\windows\avorax-open-firmware-settings.ps1 -ConfirmFirmwareReboot`, disable Secure Boot in firmware, boot Windows again, then rerun the TESTSIGNING helper and reboot. This is only for development/test machines; production drivers require Microsoft signing.

Disable it after testing:

```powershell
bcdedit /set testsigning off
shutdown /r /t 0
```

Production driver distribution requires Microsoft driver signing.
