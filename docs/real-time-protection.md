# Real-Time Protection

Pasus has two protection modes:

- Pre-execution blocking: only when a platform blocking driver/extension is installed, signed/approved, running, and returning deny verdicts before execution.
- Post-launch fallback: user-mode Guard watches process starts and stops/quarantines confirmed threats as quickly as the OS allows.

Current Windows release uses the post-launch fallback unless the minifilter driver is separately built, installed, running, connected to Pasus Guard Service, and passing the protection self-test.

The first driver-backed goal is known-threat pre-execution blocking, not broad unknown-file blocking. Unknown files are allowed and monitored unless local policy returns a confirmed/high-confidence malicious verdict.

Auto-stop/quarantine is allowed only for confirmed threats:

- Known bad hash.
- Confirmed local signature such as EICAR test.
- Confirmed ClamAV signature.
- Confirmed high-confidence YARA known-malware rule.

Suspicious or low-confidence results are review-only.

When the user-mode Guard stops a process, it writes the same quarantine metadata shape used by manual scans so the file appears in the Pasus Quarantine UI and can be restored or deleted with confirmation. Medium-confidence YARA/script rules are monitored and logged for review; they do not stop or quarantine a process by themselves.
