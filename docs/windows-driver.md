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

Driver setup/build evidence must come from checked local tool paths. The setup and build scripts resolve MSBuild and WDK tools from local Visual Studio/Windows Kits installation paths, validate project/tool/artifact paths as regular non-reparse files, and write setup/build reports atomically under the repository validation output tree. Ambient PATH discovery is not trusted release evidence for driver builds. The setup report records Secure Boot probe failures as bounded `secure_boot_probe_error` evidence and TESTSIGNING probe failures as bounded `test_signing_probe_error` evidence, failing visibly instead of reporting those boot-security states as disabled when they cannot be verified.

Development helpers that can inspect or change TESTSIGNING use the shared checked System32 resolver. That resolver validates `SystemRoot`/`WINDIR` as local Windows drive roots and fails visibly instead of silently substituting `C:\Windows`; the live remediation helper uses the same no-fallback root policy, and the explicit TESTSIGNING/live helpers capture bounded command diagnostics before any requested boot-state change or task creation.

Development test-certificate and signing scripts are not production signing. They validate certificate names and thumbprints, write reports atomically under the repository validation output tree, sign only checked repository driver artifacts, and timestamp through HTTPS. Production kernel-driver distribution still requires Microsoft Hardware Dev Center signing.

The process-guard signing wrapper is a launch boundary. It validates its shared signing script, report path, and build-output directory under the repository before delegating to the common hardened signing implementation.

Development certificate creation mutates the current-user certificate store and is therefore confirmation-gated. `create-test-cert.ps1` refuses to create or export a development certificate unless `-ConfirmCreateTestCertificate` is supplied.

Development install scripts live in `core/zentor_windows_minifilter/scripts`. They require Administrator rights and Windows TESTSIGNING to already be enabled in a development VM. Avorax does not enable TESTSIGNING automatically from the driver installer. Packaged development builds include `tools\windows\avorax-enable-test-signing.ps1` as a separate explicit elevated helper; it now refuses to change boot configuration unless `-ConfirmTestSigningChange` is supplied, and running it still requires a reboot before `ZentorAvFilter` can load.

Development install, uninstall, and self-test validation reports are repository-contained evidence. The minifilter and process-guard validation scripts require report paths under the repository, write reports atomically, validate setup reports before trust, and reject outside Guard Service self-test executable paths before launch. The minifilter self-test stages its command JSON atomically and launches the checked Guard Service directly with redirected stdin/stdout/stderr and a finite timeout instead of through a shell pipeline. Driver uninstall and self-test reports capture bounded command diagnostics, and uninstall reports cannot claim success when unload/delete commands fail.

The protection self-test wrapper does not forward driver-install confirmation automatically. Supplying `-InstallDriver` is not enough; `-ConfirmDriverInstall` is also required before the wrapper delegates to driver install scripts.

If the minifilter self-test times out, it attempts to kill the Guard Service process and records whether that cleanup succeeded or failed in the structured failure report.

Driver log collection is also development evidence. `collect-driver-logs.ps1` writes only under the repository, stages its text report atomically, bounds command and event-log output, and records command exit codes plus event-log errors rather than treating missing driver/service evidence as a clean pass.

The live remediation helper `tools\windows\avorax-fix-driver-live.ps1` is also development-VM-only. It refuses to enable TESTSIGNING without `-ConfirmTestSigningChange` and refuses to create the SYSTEM post-reboot driver-load scheduled task unless `-ConfirmPostRebootTask` is supplied. Its remediation reports and generated post-reboot script are staged atomically, and the post-reboot SYSTEM script revalidates embedded System32 tools and the optional install helper before launch.

Live remediation logs are bounded diagnostic evidence. The helper records command exit codes, atomically updates `latest.log`, marks truncation when the retained log exceeds its bound, and bounds generated post-reboot install/load/filter/service output before writing `post-reboot.json`. A source scan after the branding gate diagnostics pass found no remaining PowerShell `2>$null` hits in active `tools`, `core`, `installer`, or `.github` scripts.

When the guard health probe finds `ZentorAvFilter` installed but not loaded, it attempts `fltmc load ZentorAvFilter` only if Windows TESTSIGNING is already enabled. If TESTSIGNING is off, self-test reports `testSigningRequired`/`rebootRequired` instead of pretending pre-execution blocking is available. If Secure Boot is enabled, Windows blocks `bcdedit /set testsigning on`; the dev/test minifilter cannot load until Secure Boot is disabled in UEFI firmware, TESTSIGNING is enabled from an elevated terminal, and the machine reboots. Production builds require a Microsoft-signed driver instead of disabling Secure Boot.

Validation workflow:

```powershell
# Development VM only, elevated PowerShell:
powershell -ExecutionPolicy Bypass -File tools\windows\avorax-enable-test-signing.ps1 -ConfirmTestSigningChange
shutdown /r /t 0

# After reboot, elevated PowerShell:
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-protection-selftest.ps1 -BuildDriver -InstallDriver -ConfirmDriverInstall -CargoPath C:\Path\To\cargo.exe
```

The protection self-test requires an explicit checked Cargo executable through `-CargoPath` or `CARGO`; it refuses ambient PATH lookup.

In v0.1.13, Lockdown Mode adds unknown-app block verdicts to the Guard policy. The UI may only show pre-execution Lockdown blocking when the self-test confirms:

- Driver loaded.
- Driver IPC OK.
- Known-bad executable blocked before launch.
- Unknown unsigned executable blocked before launch in Lockdown.
- Known-good executable allowed.
- Exact-hash approval allows the same unknown executable.

The workflow writes `dist\windows-driver-validation\selftest_report.json`. Driver-enabled release gates must fail if this report is missing or failing.
