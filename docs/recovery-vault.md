# Recovery Vault

Recovery Vault stores local protected copies for selected user folders before risky modifications where possible.

Supported behavior:

- Offline local backups only.
- No upload.
- Opaque local vault copy names.
- Regular-file backups only.
- Vault containment and link/reparse rejection for restore paths.
- Size and SHA-256 verification during backup and staged restore.
- Size limit required before broader automatic backup coverage.
- Incident restore from known vault copies.

If no vault copy, OS snapshot, backup, or decryption key exists, Avorax must show:

> Avorax stopped the threat, but these files cannot always be restored without a backup, snapshot, or decryption key.
