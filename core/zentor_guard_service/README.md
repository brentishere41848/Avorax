# Avorax Guard Service

Avorax Guard Service is the user-mode real-time protection helper.

Windows v1 behavior is best-effort post-launch protection:

- Receives or observes process start events.
- Provides a `watch_processes` command that monitors newly observed processes in user mode.
- Enumerates Windows processes with bounded native Toolhelp/image-query APIs and
  Linux processes through bounded procfs reads. Access, path, record, budget,
  and empty-snapshot gaps remain visible and prevent a clean finite-watch result.
- Resolves the shared Windows directory with bounded native Win32 APIs for the
  process-skip policy and checked `taskkill.exe` discovery. Environment-spoofed
  and other-drive `Windows\System32` lookalikes are not skipped.
- Checks known malicious hashes and Avorax Native Engine verdicts.
- Uses ANE native signatures, native rules, native ML, and native risk fusion as the default decision source.
- Keeps ClamAV/YARA only as optional compatibility features (`compat_clamav`, `compat_yara`) and does not require them.
- Stops confirmed threat processes where the OS allows it.
- Moves confirmed threat executables to local quarantine.
- Writes visible events for the UI.

Avorax Guard does not stop or disable other antivirus products. It does not claim kernel-level or true pre-execution blocking. Full on-access blocking requires a future signed minifilter driver.

Process enumeration is disabled on unsupported non-Windows/non-Linux platforms.
Polling can miss processes that start and exit between snapshots, and protected
processes can deny image queries. These limits are reported as partial coverage,
not as a clean scan or a threat count.

The current process policy still skips images beneath the real Windows
`System32` and `SysWOW64` directories plus the real `Explorer.exe`. This broad
path exclusion is a technical limitation, not publisher verification or proof
that every file in those directories is benign.
