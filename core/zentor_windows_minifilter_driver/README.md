# Avorax Windows Minifilter Driver Architecture

Avorax v1 does not implement or ship a kernel driver.

True on-access and pre-execution blocking on Windows requires a separately built and properly signed file-system minifilter driver. That future driver must:

- Be signed through the proper Microsoft driver-signing flow.
- Communicate with the visible user-mode Avorax Guard Service.
- Use safe scanner timeouts and explicit fail-open/fail-closed policy.
- Never hide processes, files, services, registry keys, or telemetry.
- Never implement rootkit behavior.
- Expose user-visible configuration and audit logs.

This directory intentionally contains architecture documentation only.
