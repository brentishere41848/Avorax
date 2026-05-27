# Pasus Guard Service

Pasus Guard Service is the user-mode real-time protection helper.

Windows v1 behavior is best-effort post-launch protection:

- Receives or observes process start events.
- Provides a `watch_processes` command that monitors newly observed processes in user mode.
- Checks known malicious hashes and confirmed local signatures.
- Uses bundled/local ClamAV when available for confirmed signature checks.
- Stops confirmed threat processes where the OS allows it.
- Moves confirmed threat executables to local quarantine.
- Writes visible events for the UI.

Pasus Guard does not stop or disable other antivirus products. It does not claim kernel-level or true pre-execution blocking. Full on-access blocking requires a future signed minifilter driver.
