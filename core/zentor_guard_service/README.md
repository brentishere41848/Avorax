# Avorax Guard Service

Avorax Guard Service is the user-mode real-time protection helper.

Windows v1 behavior is best-effort post-launch protection:

- Receives or observes process start events.
- Provides a `watch_processes` command that monitors newly observed processes in user mode.
- Checks known malicious hashes and Avorax Native Engine verdicts.
- Uses ANE native signatures, native rules, native ML, and native risk fusion as the default decision source.
- Keeps ClamAV/YARA only as optional compatibility features (`compat_clamav`, `compat_yara`) and does not require them.
- Stops confirmed threat processes where the OS allows it.
- Moves confirmed threat executables to local quarantine.
- Writes visible events for the UI.

Avorax Guard does not stop or disable other antivirus products. It does not claim kernel-level or true pre-execution blocking. Full on-access blocking requires a future signed minifilter driver.
