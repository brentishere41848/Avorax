# Windows Driver

True Windows pre-execution/on-access blocking requires a signed kernel minifilter and process guard path.

Current implementation:

- User-mode Pasus Guard Service can stop confirmed threats after launch.
- Driver project skeletons are present in `core/pasus_windows_minifilter` and `core/pasus_windows_process_guard`.
- The UI must show `Driver Missing` or `Post-launch blocking active` unless a signed driver is installed and verified running.

Driver requirements:

- Use documented Microsoft Filter Manager and process notification APIs.
- Communicate with the visible Pasus Guard Service.
- Avoid recursive scanning of Pasus quarantine and Pasus binaries.
- Fail open for critical system paths in normal mode.
- Never hide files, processes, services, registry keys, or telemetry.
- Never disable Windows Defender or other security products.
