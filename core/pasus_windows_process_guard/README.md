# Pasus Windows Process Guard

This project is the Windows process creation protection path.

Current state:

- Architecture and driver skeleton are present.
- Production UI must show `Post-launch blocking active` unless this driver is installed, signed, running, and returning pre-execution deny verdicts.

Design:

- Use the documented process creation callback architecture.
- Ask Pasus Guard Service for cached verdicts on executable paths/hashes.
- Deny or stop only confirmed malicious verdicts.
- Fall back to user-mode termination when pre-execution denial is not available.

Safety boundaries:

- No hidden processes.
- No kernel patching.
- No disabling other antivirus tools.
- No stealth persistence.
