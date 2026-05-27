# False Positives

Pasus must minimize false positives.

The following are not malware by themselves:

- `.exe` in Downloads.
- Unsigned executable.
- Unknown publisher.
- VPN installer.
- CLI tool.
- Developer tool.
- Game launcher.

Balanced mode must not auto-quarantine benign fixtures.

Lockdown Mode may block unknown apps, but the UI must say "unknown app" and explain that the block is due to trust policy, not malware detection.

False-positive controls:

- Keep or ignore.
- Mark false positive.
- Mark trusted app.
- Always allow exact hash.
- Allowlist file/folder with warnings and root-path restrictions.

False-positive labels are stored locally for export and immediate local suppression. The production app does not silently retrain itself from one user's labels.
