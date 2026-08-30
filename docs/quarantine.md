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
write/finalization-journal name. Finalization journals use `<id>.pending` and
`<id>.pending.auth`; UUID-staged variants are also recognized. Unknown names,
directories, links/reparse points, enumeration
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

Before moving a source, Local Core and Guard write a strict authenticated
finalization journal. The authentication sidecar is persisted first and the
`.pending` file is the commit marker. Its record contains the already validated
ID, original path, opaque payload path, SHA-256, size, detection evidence, and
action claims. Journal authentication uses a separate HMAC domain from final
record authentication. The writer reads the committed journal back, verifies
its exact bytes and HMAC, acquires an exclusive file lock, and keeps that lock
through source movement, final-record verification, and journal cleanup.

If permission or authenticated-metadata finalization fails after a payload has
already moved into the vault, cleanup removes only partial final metadata and
auth sidecars. It never deletes the only payload copy or its authenticated
journal. The command fails visibly and reports the retained opaque payload path.

Local Core performs bounded recovery before normal quarantine listing:

- Recovery must first acquire the same journal lock without waiting. If Local
  Core or Guard is still finalizing that ID, listing fails visibly and leaves
  the source, payload, journal, and sidecars untouched. A crashed writer releases
  the operating-system lock automatically.
- An authenticated journal plus an intact payload and absent original source is
  hardened, size/hash checked, finalized into a current HMAC record, read back,
  and only then has its journal removed.
- A journal with no payload is removed only when the original source is still a
  regular single-link file with the exact recorded size and SHA-256 and no
  cooperating writer still holds the journal lock.
- A matching authenticated final record and intact payload permits cleanup of a
  stale journal or a journal-auth sidecar left by interrupted cleanup.
- Partial final metadata may be replaced only after journal authentication and
  payload integrity succeed.
- Tampered/unsigned/unknown-field journals, filename/ID mismatches, conflicting
  final records, changed payloads, missing sources, excessive vault entries, or
  a state containing both original source and isolated payload fail visibly and
  preserve evidence for operator review.

An orphan journal-auth sidecar with no related state may be removed because no
move was committed. With related state it is removed only after a current final
record and its status-appropriate payload state verify. Recovery never treats a
duplicate source/payload state as completed quarantine and never promises that
same-principal or administrator filesystem races are impossible. The lock
coordinates Avorax Local Core and Guard; it is not a security boundary against a
same-principal or administrator/root process that ignores advisory locks or can
mutate the vault directly.

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

Finalization journals use wrapper format
`avorax-quarantine-finalization-journal-v1` and HMAC domain
`avorax-quarantine-finalization-journal-v1\0`. Final records continue to use
their distinct `avorax-quarantine-record-v2\0` domain. Local Core and Guard use
the same compatible journal schema so Local Core can finish a Guard-created
post-launch quarantine after an interrupted metadata write.

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

Quarantine accepts a source only when the operating-system link count read from
an opened file handle is exactly one. Local Core and Guard check before the
move, check the still-open copy source again before removing it, and reject a
moved or copied vault payload before permission changes or record finalization
if its link count is no longer one. Existing vault entries are subject to the
same rule before permission repair. A pre-existing multi-linked source fails
visibly and remains in place; Avorax does not create a quarantine record for it.

This policy does not enumerate or remove every directory entry for a file
across a volume. A same-principal or administrator/root process may also race a
new hard link between the final count check and a path mutation. Post-move
payload validation catches a link visible before record finalization, but the
complete operation is not a filesystem transaction. Alternate paths must still
be scanned as separate targets, and Avorax does not claim volume-wide
neutralization.

## Scan-Verdict Content Binding

Checkpoint 2260 binds automatic quarantine to the exact SHA-256 returned by the
Native Engine verdict. Local Core no longer replaces that evidence with a fresh
current-path hash. Before vault creation or mutation, the quarantine store
requires a valid infected result, an exact selected-path match, matching bytes
read from the already-opened single-link source, and matching Unix device/inode
or Windows volume/file-index identity for the selected path. If the file changed
or was replaced, Avorax leaves it in place, creates no finalized record, reports
the failure, and requires a rescan.

Guard Service already required its process-observation SHA-256 to match before
post-launch quarantine. Checkpoint 2260 makes Guard hash the already-opened
single-link source, delays vault creation until that match succeeds, and applies
the same open-handle/path identity check before move and copy-source removal.

Checkpoint 2261 distinguishes two explicit manual actions. `Quarantine` on a
visible scan-result row carries that row's exact non-empty SHA-256 and rejects
empty, malformed, or changed evidence with a visible rescan-required error
before vault mutation. The separate
confirmed `Quarantine file` picker has no prior verdict, deliberately omits the
hash, takes a fresh bounded current-file snapshot, and then crosses the same
store boundary. Flutter requires matching original-path evidence for either
success and matching SHA-256 evidence for a threat-row success. Copy fallback
verifies the copied payload SHA-256 and rechecks source identity before removing
the source. Final payload hashing and the authenticated recovery journal still
protect failures after a move.

These checks are user-mode and path-based, not a filesystem transaction. A
privileged writer may still race the last identity check and path mutation on
some filesystems. Such a failure is not reported as successful quarantine;
post-move mismatch remains visible or recovery-journaled. This is not kernel
mediation, pre-execution blocking, administrator/SYSTEM isolation, or a claim
that Avorax replaces Defender. Checkpoint 2261 is closed through exact local
and destination `289/289`, normal PR integration, merged-main CI/package
evidence, guarded 18-path zero-delete synchronization, all eight exact
lockfiles, and an unchanged protected vault. Installed UI-to-service
click-through and atomic kernel path mediation remain outside this proof;
changed evidence requires an explicit rescan.

## Restore, Delete, And Allowlist

Restoring requires explicit confirmation. If a restored file is still detected, the UI must warn the user. Deleting permanently is always a user action.

Users can also keep a file quarantined, restore/keep it, delete it permanently, or add it to the allowlist. Allowlisted files are skipped from automatic quarantine but still produce visible local events when relevant.

Permanent delete removes the isolated payload after integrity and path checks;
it is not a secure-erase promise, especially on SSDs.

## Checkpoint 2276 Metadata Replacement

Existing Local Core quarantine status records and authentication sidecars now
activate through shared existing-file atomic replacement. The previous
validated-file removal before no-replace activation is gone, so an ordinary
failure cannot expose a deliberate destination-name absence. New metadata still
uses atomic no-replace activation and collision-preserving failure.

Atomicity is per file. JSON plus HMAC is not a transaction: interruption between
the two replacements can produce a mismatched pair, which authenticated reads
reject and manual recovery may need to resolve. Windows ambiguous failure may
preserve `.avorax-replace-backup`; same-volume hard links and truthful local
filesystem behavior are required. Checkpoint 2276 does not prove secure erasure,
kernel mediation, pre-execution blocking, or Defender replacement.

Local verification passes all three new harmless replacement fixtures, all 21
workspace metadata tests, Local Core quarantine `143/143`, and definitive
`302/302`. Dual-host validation rejects all 52 hostile reports across 26
mutations. Hosted Unix/macOS and synchronized-destination runtime evidence
remain required.
