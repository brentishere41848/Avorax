# Real-Time Protection

Pasus has two protection modes:

- Pre-execution blocking: only when a platform blocking driver/extension is installed, signed/approved, running, and returning deny verdicts before execution.
- Post-launch fallback: user-mode Guard watches process starts and stops/quarantines confirmed threats as quickly as the OS allows.

Current Windows release uses the post-launch fallback unless the driver path is separately built and installed.

Auto-stop/quarantine is allowed only for confirmed threats:

- Known bad hash.
- Confirmed local signature such as EICAR test.
- Confirmed ClamAV signature.
- Confirmed high-confidence YARA known-malware rule.

Suspicious or low-confidence results are review-only.
