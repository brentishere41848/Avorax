# Recovery Vault

Recovery Vault stores local protected copies for selected user folders before risky modifications where possible.

Supported behavior:

- Offline local backups only.
- No upload.
- Size limit required.
- Incident restore from known vault copies.

If no vault copy, OS snapshot, backup, or decryption key exists, Pasus must show:

> Pasus stopped the threat, but these files cannot always be restored without a backup, snapshot, or decryption key.
