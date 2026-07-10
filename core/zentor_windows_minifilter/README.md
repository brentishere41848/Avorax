# Avorax Windows Minifilter

This project is the Windows pre-execution/on-access blocking path for Avorax.

Current state:

- The repository contains a WDK minifilter project in `driver/` with `FltRegisterFilter`, pre-create/section synchronization callbacks, and a Filter Manager communication port named `\ZentorAvFilterPort`.
- Guard Service verdict handling is implemented in Rust and tested with harmless known-bad/EICAR fixtures.
- The production installer does not claim the driver is active unless Windows reports the signed driver/service is installed and running.
- Development builds require WDK, test signing, and a disposable VM.

Purpose:

- Intercept file create/open/section synchronization operations relevant to executable launch and risky writes.
- Send scan requests to the visible Avorax Guard Service.
- Deny access only when a confirmed malicious verdict is returned within policy timeout.
- Fail open for critical system paths in normal mode.

## Development Commands

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-driver.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\install-test-driver.ps1 -ConfirmDriverInstall
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-test-driver.ps1 -ConfirmDriverUninstall
```

`install-test-driver.ps1` requires Administrator rights, explicit `-ConfirmDriverInstall`, and Windows TESTSIGNING to already be enabled. It does not enable TESTSIGNING automatically. `uninstall-test-driver.ps1` requires explicit `-ConfirmDriverUninstall`.

If MSBuild, Visual Studio C++ tools, or the Windows Driver Kit are missing, `build-driver.ps1` fails with a clear setup error.

Non-goals:

- No stealth.
- No hidden persistence.
- No process/file hiding.
- No kernel patching.
- No disabling Windows Defender or other security tools.
