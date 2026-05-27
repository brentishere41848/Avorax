# Real-Time Protection

Pasus has two enforcement layers:

- Pre-execution blocking: only when a platform blocking driver/extension is installed, signed/approved, running, and returning deny verdicts before execution.
- Post-launch fallback: user-mode Guard watches process starts and stops/quarantines confirmed threats as quickly as the OS allows.

Current Windows release uses the post-launch fallback unless the minifilter driver is separately built, installed, running, connected to Pasus Guard Service, and passing the protection self-test.

v0.1.13 adds prevention profiles:

- Balanced Protection: confirmed threats block, suspicious items review, unknown apps allow-and-monitor.
- Block Confirmed Threats: confirmed and high-confidence probable threats block.
- Lockdown Protection: unknown apps block until trusted or approved.
- Developer Mode: unknown developer tools are monitored/reviewed instead of broadly blocked.

When the driver path is active, Lockdown decisions can be enforced before launch. Without the driver, Pasus must say "post-launch fallback only".

Auto-stop/quarantine is allowed only for confirmed threats:

- Known bad hash.
- Confirmed local signature such as EICAR test.
- Confirmed ClamAV signature.
- Confirmed high-confidence YARA known-malware rule.

Suspicious or low-confidence results are review-only.

When the user-mode Guard stops a process, it writes the same quarantine metadata shape used by manual scans so the file appears in the Pasus Quarantine UI and can be restored or deleted with confirmation. Medium-confidence YARA/script rules are monitored and logged for review; they do not stop or quarantine a process by themselves.

Lockdown unknown-app blocking is not malware detection. It should not quarantine by default and must not call normal unknown software a virus.
