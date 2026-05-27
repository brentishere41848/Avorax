# Lab Readiness

Pasus release gates are aligned around the categories used by independent endpoint security testing:

- Protection: EICAR, known-bad safe fixtures, YARA/signature verdicts, Guard decisions, and driver self-test.
- Performance: decision latency, scan throughput, idle overhead, and UI responsiveness.
- Usability: false positives on benign fixtures and clear user-facing wording.
- Remediation: quarantine metadata, restore confirmation, and recovery vault tests.
- Ransomware: safe simulator in a temporary directory, affected file tracking, and recovery honesty.

Current v0.1.13 status:

- Balanced and Lockdown policy are implemented.
- Lockdown unknown-app blocking policy is test-covered.
- True pre-execution enforcement still requires an installed/running Windows driver and passing self-test.
- Local AI is a development model and cannot auto-quarantine by itself.

Pasus should not replace Microsoft Defender until independent validation and production signing are complete.
