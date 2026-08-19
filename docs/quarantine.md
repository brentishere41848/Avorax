# Quarantine

When scan mode allows quarantine and Avorax finds a confirmed infected file, Avorax automatically quarantines it. Detect-only scans never quarantine or delete files.

The same quarantine store is used by manual scans and Avorax Guard. If the Guard stops a confirmed threat after launch, it moves the executable into this store and writes a JSON record with the action taken.

## Behavior

Avorax:

- Moves the file into the Avorax quarantine folder.
- Renames it to an opaque random ID with a `.avoraxq` extension.
- Removes executable permissions where supported.
- Stores a strict JSON metadata record plus an authenticated sidecar.
- Shows a local event in the app.
- Reports detection metadata to Avorax Cloud if the cloud is online.

Avorax does not permanently delete infected files automatically.

## Storage

Default quarantine locations:

- Windows: `%ProgramData%/Avorax/Quarantine` or user app data fallback.
- macOS: `~/Library/Application Support/Avorax/Quarantine`.
- Linux: `~/.local/share/avorax/quarantine`.

## Metadata

Each record includes:

- `quarantine_id`
- `original_path`
- `quarantine_path`
- `sha256`
- `file_size`
- `detection_name`
- `engine`
- `quarantined_at`
- `status`
- optional `user_note`

Local Core and Guard Service use the same versioned quarantine metadata
contract. New sidecars contain `hmac-sha256:` followed by a 32-byte
HMAC-SHA-256 tag encoded as lowercase hexadecimal. The authentication key is
generated from the operating-system random source. On Windows the key file is
DPAPI-protected and plaintext key files are rejected. The quarantine ID must
also match the metadata filename, unknown JSON fields are rejected, and Guard
process-action evidence is validated before Local Core may list, restore, or
delete the record.

Unsigned records are not treated as trusted legacy data. A record with no auth
sidecar fails visibly. A valid older v1 Local Core or Guard prefix-hash sidecar
may be migrated to the shared HMAC format only after its existing tag, strict
schema, identifier, paths, fields, source, action, and execution claims all
validate. Malformed or unknown-field records are not migrated.

HMAC authenticates metadata; it does not encrypt the quarantined payload. On
Windows DPAPI uses the security context that created the key. The installed
Core/Guard services run as LocalSystem, but installed service/UI cross-account
access, ACL, DPAPI recovery, and upgrade behavior still require a disposable
elevated-host E2E pass before production release.

## Restore, Delete, And Allowlist

Restoring requires explicit confirmation. If a restored file is still detected, the UI must warn the user. Deleting permanently is always a user action.

Users can also keep a file quarantined, restore/keep it, delete it permanently, or add it to the allowlist. Allowlisted files are skipped from automatic quarantine but still produce visible local events when relevant.

Permanent delete removes the isolated payload after integrity and path checks;
it is not a secure-erase promise, especially on SSDs.
