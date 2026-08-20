# Quarantine

When scan mode allows quarantine and Avorax finds a confirmed infected file, Avorax automatically quarantines it. Detect-only scans never quarantine or delete files.

The same quarantine store is used by manual scans and Avorax Guard. If the Guard stops a confirmed threat after launch, it moves the executable into this store and writes a JSON record with the action taken.

## Behavior

Avorax:

- Moves the file into the Avorax quarantine folder.
- Renames it to an opaque random ID with a `.avoraxq` extension.
- Enforces exact owner-only Unix modes or an exact protected Windows DACL and denies Windows file execution.
- Stores a strict JSON metadata record plus an authenticated sidecar.
- Shows a local event in the app.
- Reports detection metadata to Avorax Cloud if the cloud is online.

Avorax does not permanently delete infected files automatically.

## Storage

Default quarantine locations:

- Windows: `%ProgramData%/Avorax/Quarantine` or user app data fallback.
- macOS: `~/Library/Application Support/Avorax/Quarantine`.
- Linux: `~/.local/share/avorax/quarantine`.

Explicit `AVORAX_*QUARANTINE_DIR` or legacy `ZENTOR_*QUARANTINE_DIR` overrides
must be absolute local paths without parent traversal and must end in a
dedicated directory named `Quarantine` (case-insensitive). Avorax will not apply
vault ACLs or modes to an arbitrary existing directory.

Before permission changes, Local Core and Guard enumerate a maximum of `65,536`
directory entries. Every entry must be a non-link regular file with a recognized
opaque payload, strict metadata, authentication sidecar, metadata key, or staged
write name. Unknown names, directories, links/reparse points, enumeration
failure, or an excessive entry count fail visibly before permission mutation.
This name/shape preflight does not authenticate records; HMAC and schema/path
validation remain mandatory before lifecycle use.

Local Core and Guard use the shared `avorax_platform_security` boundary. On
Unix, Avorax opens and verifies the directory or file, compares device/inode
identity, transfers differing ownership through the opened descriptor to the
effective process UID/GID, applies exact directory mode `0700` and file mode
`0600`, then rechecks path identity, ownership, object kind, and mode. This
applies to payloads, staged/final metadata, auth sidecars, and key files. An
ownership transfer that the process is not permitted to perform fails closed.
Existing vault-path ancestors are checked before and after directory creation;
symbolic-link or Windows reparse-point ancestors are rejected.

Local Core test builds use a thread-local temporary `Quarantine` directory by
default. Runtime scan/quarantine tests therefore do not write to an installed
or developer machine's ProgramData vault; explicit failure fixtures use a
scoped thread-local override.

These ancestor checks are path-based and reduce redirection risk, but they are
not a fully handle-relative `openat2` or NT object-tree transaction. A principal
that can concurrently replace trusted vault ancestors remains inside the
platform trusted computing base.

On Windows, Avorax obtains the current identity from `OpenProcessToken` and
`GetTokenInformation`; `USERNAME` and `USERDOMAIN` are not security inputs. It
opens the target with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects reparse points and
wrong object kinds, rejects NUL-containing or oversized paths before the Windows
API call, writes a protected exact DACL with `SetSecurityInfo`, and
sets the object owner to the process-token SID. It reads owner and DACL back with
`GetSecurityInfo` and compares both. For files, the already-opened data handle
and the ACL handle must report the same volume serial and file ID; a replaced
path fails before data is read or written. Directory access is limited to SYSTEM,
Administrators, and the actual process-token SID. Quarantined files add an
Everyone deny ACE for the exact `FILE_EXECUTE` right while retaining
read/recovery access for those principals. Restore staging intentionally does
not carry the quarantine owner/execute-deny policy into the destination; it
inherits the destination directory policy and is integrity-checked before
atomic activation.

If permission or authenticated-metadata finalization fails after a payload has
already moved into the vault, cleanup removes only partial metadata and auth
sidecars. It never deletes the only payload copy. The command fails visibly and
reports the retained opaque payload path, which may require an administrator to
inspect or recover before the record can be exposed through normal listing.

Existing bounded metadata, auth-sidecar, and key reads apply these permissions
before content is consumed. Once an existing record has passed authentication,
schema validation, and vault-path validation, Local Core also hardens its
present payload. This provides an access-time upgrade path for older valid
records without trusting or migrating unsigned content.

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
Core/Guard services run as LocalSystem. Exact DACL behavior is covered with
isolated process-token runtime tests, but installed service/UI cross-account
access, LocalSystem DPAPI recovery, repair, and upgrade behavior still require a
disposable elevated-host E2E pass before production release. In the portable
user-mode beta, another process running under the same SID/UID shares the vault
principal; permission hardening alone is not process isolation.

Quarantine removes and secures the detected path; it does not enumerate all
hard links to the same file across a volume. A pre-existing alternate hard link
can therefore remain accessible and must be detected as its own path. Avorax
does not report that case as volume-wide neutralization.

## Restore, Delete, And Allowlist

Restoring requires explicit confirmation. If a restored file is still detected, the UI must warn the user. Deleting permanently is always a user action.

Users can also keep a file quarantined, restore/keep it, delete it permanently, or add it to the allowlist. Allowlisted files are skipped from automatic quarantine but still produce visible local events when relevant.

Permanent delete removes the isolated payload after integrity and path checks;
it is not a secure-erase promise, especially on SSDs.
