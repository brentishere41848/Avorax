# Pasus Windows Minifilter

This project is the Windows pre-execution/on-access blocking path for Pasus.

Current state:

- The repository contains the driver architecture, message contract, INF skeleton, and callback design.
- The production installer does not claim the driver is active unless Windows reports the signed driver/service is installed and running.
- Development builds require WDK, test signing, and a disposable VM.

Purpose:

- Intercept file create/open/section synchronization operations relevant to executable launch and risky writes.
- Send scan requests to the visible Pasus Guard Service.
- Deny access only when a confirmed malicious verdict is returned within policy timeout.
- Fail open for critical system paths in normal mode.

Non-goals:

- No stealth.
- No hidden persistence.
- No process/file hiding.
- No kernel patching.
- No disabling Windows Defender or other security tools.
