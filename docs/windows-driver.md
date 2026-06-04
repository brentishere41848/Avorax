# Windows Driver

True Windows pre-execution/on-access blocking requires a signed kernel minifilter and process guard path.

Current implementation:

- User-mode Avorax Guard Service can stop confirmed threats after launch.
- `core/zentor_windows_minifilter` contains a WDK minifilter project with Filter Manager communication-port code and conservative deny policy hooks.
- `core/zentor_windows_process_guard` contains a process notification driver project that establishes the callback path but does not claim deny/blocking until a verified signed-driver cache is implemented.
- The UI must show `Driver Missing` or `Post-launch blocking active` unless a signed driver is installed and verified running.

Driver requirements:

- Use documented Microsoft Filter Manager and process notification APIs.
- Communicate with the visible Avorax Guard Service.
- Avoid recursive scanning of Avorax quarantine and Avorax binaries.
- Fail open for critical system paths in normal mode.
- Never hide files, processes, services, registry keys, or telemetry.
- Never disable Windows Defender or other security products.

Development install scripts live in `core/zentor_windows_minifilter/scripts`. They require Administrator rights and Windows TESTSIGNING to already be enabled in a development VM. Avorax does not enable TESTSIGNING automatically from the driver installer. Packaged development builds include `tools\windows\avorax-enable-test-signing.ps1` as a separate explicit elevated helper; running it still requires a reboot before `ZentorAvFilter` can load.

When the guard health probe finds `ZentorAvFilter` installed but not loaded, it attempts `fltmc load ZentorAvFilter` only if Windows TESTSIGNING is already enabled. If TESTSIGNING is off, self-test reports `testSigningRequired`/`rebootRequired` instead of pretending pre-execution blocking is available. If Secure Boot is enabled, Windows blocks `bcdedit /set testsigning on`; the dev/test minifilter cannot load until Secure Boot is disabled in UEFI firmware, TESTSIGNING is enabled from an elevated terminal, and the machine reboots. Production builds require a Microsoft-signed driver instead of disabling Secure Boot.

Validation workflow:

```powershell
# Development VM only, elevated PowerShell:
powershell -ExecutionPolicy Bypass -File tools\windows\avorax-enable-test-signing.ps1
shutdown /r /t 0

# After reboot, elevated PowerShell:
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-protection-selftest.ps1 -BuildDriver -InstallDriver
```

In v0.1.13, Lockdown Mode adds unknown-app block verdicts to the Guard policy. The UI may only show pre-execution Lockdown blocking when the self-test confirms:

- Driver loaded.
- Driver IPC OK.
- Known-bad executable blocked before launch.
- Unknown unsigned executable blocked before launch in Lockdown.
- Known-good executable allowed.
- Exact-hash approval allows the same unknown executable.

The workflow writes `dist\windows-driver-validation\selftest_report.json`. Driver-enabled release gates must fail if this report is missing or failing.
