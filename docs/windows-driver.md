# Windows Driver

True Windows pre-execution/on-access blocking requires a signed kernel minifilter and process guard path.

Current implementation:

- User-mode Pasus Guard Service can stop confirmed threats after launch.
- `core/pasus_windows_minifilter` contains a WDK minifilter project with Filter Manager communication-port code and conservative deny policy hooks.
- `core/pasus_windows_process_guard` contains a process notification driver project that establishes the callback path but does not claim deny/blocking until a verified signed-driver cache is implemented.
- The UI must show `Driver Missing` or `Post-launch blocking active` unless a signed driver is installed and verified running.

Driver requirements:

- Use documented Microsoft Filter Manager and process notification APIs.
- Communicate with the visible Pasus Guard Service.
- Avoid recursive scanning of Pasus quarantine and Pasus binaries.
- Fail open for critical system paths in normal mode.
- Never hide files, processes, services, registry keys, or telemetry.
- Never disable Windows Defender or other security products.

Development install scripts live in `core/pasus_windows_minifilter/scripts`. They require Administrator rights and Windows TESTSIGNING to already be enabled in a development VM. Pasus does not enable TESTSIGNING automatically.
