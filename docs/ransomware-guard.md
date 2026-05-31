# Ransomware Guard

Ransomware Guard is behavior-based protection for suspicious mass file activity.

Signals:

- Rapid modifications across many folders.
- Mass renames or extension changes.
- Entropy increase after writes.
- Ransom-note-like files.
- Backup/snapshot tampering.

Response:

- Stop the responsible process where possible.
- Quarantine the executable when identified.
- Record an incident.
- Start recovery from Recovery Vault or OS snapshots when available.

Avorax must not claim files are recovered unless restore actually succeeds.

The Avorax Native Engine keeps a short per-process activity window. Multiple smaller file-change events can combine into one ransomware decision, which helps avoid overreacting to one normal write while still catching rapid modification patterns.
