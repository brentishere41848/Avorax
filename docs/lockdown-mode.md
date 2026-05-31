# Lockdown Mode

Avorax Lockdown Mode is prevention-first application control.

Balanced mode behaves like a normal antivirus profile: confirmed threats are blocked/quarantined, suspicious items are reviewed, and unknown apps are allowed with monitoring.

Lockdown Mode is stricter:

- Unknown unsigned executables are blocked until approved.
- Known-good exact hashes are allowed.
- User-approved exact hashes are allowed.
- Trusted signed publishers can be allowed by policy.
- Avorax and critical system paths use fail-open safety policy.
- Unknown app blocks are not labeled as malware.

Correct wording:

- "Blocked unknown app"
- "Reason: Lockdown Mode allows only trusted or approved apps."

Incorrect wording:

- "Virus detected" for an unknown app.
- "Trojan found" without signature, AI/category, or behavior evidence.

Without a running driver and passing self-test, Lockdown cannot claim true pre-execution blocking. The Guard still applies post-launch fallback where possible and the UI must say so.
