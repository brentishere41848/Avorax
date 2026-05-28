# Pasus Architecture

Pasus is split into visible UI, local protection services, and platform-specific blocking layers.

- Flutter UI: status, scans, quarantine, settings, events.
- `pasus_local_core`: offline scanner powered by Pasus Native Engine, native signatures, native rules, native ML runtime, risk scoring, quarantine, allowlist, recovery primitives.
- `app_control`: prevention-first execution policy for Balanced, Lockdown, Developer, and Monitor profiles. It separates "unknown app blocked" from "malware detected".
- `pasus_guard_service`: background user-mode real-time guard. It can monitor process starts, stop confirmed threats after launch, and quarantine files.
- Windows minifilter/process guard: required for true pre-execution/on-access blocking. The project path exists, but production activation requires WDK build, testing, and signing.
- macOS Endpoint Security and Linux fanotify: planned platform blocking paths with honest fallback states.

Cloud is optional and must never block local scanning, quarantine, or recovery.

v0.1.13 adds Lockdown policy and validation gates. The policy can decide to block unknown apps, but true pre-execution enforcement still requires the Windows driver path to be installed, running, connected to Guard Service, and passing self-test.
