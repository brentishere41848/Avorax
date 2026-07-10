# Application Control

Application control evaluates execution requests before the malware verdict is finalized.

Trust levels:

- `systemTrusted`
- `trustedPublisher`
- `knownGoodHash`
- `userApproved`
- `allowlisted`
- `unknown`
- `suspicious`
- `knownBad`
- `confirmedMalware`

Decision outputs:

- `allow`
- `block`
- `quarantine`
- `allowAndMonitor`
- `askUser`
- `timeoutAllow`
- `timeoutBlock`

Policy rules:

- Known bad hashes, EICAR/test signatures, confirmed native signatures, and high-confidence native rules are block eligible.
- Known-good hashes, exact user approvals, and trusted signed publishers are allow eligible.
- Trusted-publisher configuration is fail-visible: empty or NUL-containing configured publisher names are rejected instead of silently dropped. Observed malformed publisher evidence remains `unknown`.
- Normal `.exe` files, developer tools, VPN installers, CLI tools, and consumer launchers are not malware simply because they are unknown or unsigned.
- Lockdown may block unknown apps as unknown, not as confirmed threats.
- Folder/root allowlisting is restricted. Avorax must not allowlist `C:\`, `C:\Windows`, `C:\Program Files`, `/`, `/System`, `/usr`, `/bin`, `/sbin`, or `/etc`.

The known-good database in v0.1.13 is intentionally small and development-oriented. It is not a global reputation database.
