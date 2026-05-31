# Avorax Windows Guard Driver Architecture

Avorax v1 does not ship a kernel driver.

Future Windows on-access blocking requires a separate signed minifilter driver build path:

- Signed Microsoft-compliant minifilter driver.
- Visible user-mode Avorax Guard service.
- Driver asks user-mode scanner for allow/deny decisions.
- Safe timeout policy with explicit fail-open/fail-closed configuration.
- No stealth behavior, no rootkit behavior, no hidden persistence.
- Full audit logging for block decisions.

The current Flutter/Rust product uses visible user-mode protection and does not claim full pre-execution blocking.
