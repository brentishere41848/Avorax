# Pasus Architecture

Pasus is split into visible UI, local protection services, and platform-specific blocking layers.

- Flutter UI: status, scans, quarantine, settings, events.
- `pasus_local_core`: offline scanner, ClamAV integration, YARA rules, local AI runtime, risk scoring, quarantine, allowlist, recovery primitives.
- `pasus_guard_service`: background user-mode real-time guard. It can monitor process starts, stop confirmed threats after launch, and quarantine files.
- Windows minifilter/process guard: required for true pre-execution/on-access blocking. The project path exists, but production activation requires WDK build, testing, and signing.
- macOS Endpoint Security and Linux fanotify: planned platform blocking paths with honest fallback states.

Cloud is optional and must never block local scanning, quarantine, or recovery.
