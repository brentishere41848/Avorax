# Avorax Local Core

Avorax Local Core is the Rust desktop helper for selected-path malware scanning, quarantine metadata, allowlist validation, and future selected-path watching.

It communicates with Flutter through stdin/stdout JSON commands. It does not bind to the network.

## Commands

- `health`
- `scan_file`
- `scan_folder`
- `quick_scan_selected_paths`
- `full_scan`
- `cancel_scan`
- `quarantine_file`
- `restore_quarantine_item`
- `delete_quarantine_item`
- `list_quarantine`
- `add_allowlist_entry`
- `remove_allowlist_entry`
- `list_allowlist`
- `start_watch`
- `stop_watch`

Every scan command requires a canonical lowercase hyphenated UUID in `job_id`.
The caller must retain that ID and send it with `cancel_scan`. Local Core echoes
the ID in progress/cancel evidence and observes only the bounded strict JSON
token for that exact job. Job IDs are same-user capabilities, not
cross-identity authentication or pre-execution blocking.

## ClamAV

The scanner provider tries `ZENTOR_CLAMAV_CLAMSCAN`, `clamdscan`, `clamscan`, and a bundled `ClamAV\clamscan.exe` next to `zentor_local_core.exe`. If no local ClamAV engine exists, it returns `EngineUnavailable`. It never reports clean unless a real engine scan completes.

The Windows MSI bundles the ClamAV runtime beside the app. Signature database updates are explicit; if ClamAV cannot load a local database, the scan returns an error instead of a fake clean result.

## Quarantine

Infected files are moved to the Avorax quarantine folder, renamed with `.avoraxq`, stripped of executable bits where supported, and paired with JSON metadata. Legacy quarantine records remain readable.

`quarantine_file` accepts an optional bounded `sha256`; when present it must
be non-empty. A confirmed action from a scan-result row must send that row's
exact SHA-256; changed or mismatched
content fails before vault mutation and requires a rescan. A separately
confirmed manual file-picker request omits `sha256` because it has no prior
verdict and takes a fresh bounded snapshot of the selected current file.

Checkpoint 2262 hardens manual trust mutation IPC. `add_allowlist_entry` now
requires `confirmed=true`; callers with a visible scan verdict may also provide
that row's bounded `sha256`, which must match the freshly hashed regular file
before the entry is persisted. A standalone confirmed add without earlier
verdict evidence intentionally takes a fresh current-file hash.

`label_detection` requires `confirmed=true`, an exact bounded `sha256`, and a
supported user label. Local Core hashes before and after static-feature
extraction and persists nothing if the file differs from the scan verdict or
changes during collection. Success includes compact `evidence` containing the
persisted label ID, file SHA-256, user label, previous verdict, and local store
path. This checkpoint 2262 contract is same-user stale-verdict defense; it is
not cross-identity authorization, a kernel file lease, or pre-execution
blocking.

## Tests

```powershell
cargo test
```

## Checkpoint 2263 Restore Activation

Restore still verifies authenticated metadata, payload SHA-256, destination
absence, and path ancestors before staging. Final activation now uses the
shared atomic no-replace platform boundary: Windows `MoveFileExW` without
replace flags, Linux/Android `RENAME_NOREPLACE`, and Apple `RENAME_EXCL`.
A competing destination is preserved and failure remains visible; unsupported
platforms do not fall back to replacement-capable rename. Checkpoint 2263 does
not remove the documented privileged path-ancestor race or add kernel/driver
enforcement.

## Checkpoint 2264 Quarantine Ingestion

Quarantine ingestion in Local Core and Guard now calls the same shared atomic
no-replace platform boundary before the existing exclusive verified copy
fallback. A destination created after preflight is preserved; if atomic rename
and fallback both fail, both causes remain in the visible error. Cross-filesystem
or unsupported atomic rename can still use the safe exclusive-copy path.

The Native direct-quarantine compatibility implementation receives the same
repair but remains disabled in production. Local Core and Guard remain active
mutation owners. Final-name atomicity does not create an immutable source lease,
cross-identity authorization, kernel mediation, or pre-execution blocking.
Checkpoint 2264 focused collision, broader quarantine, strict changed-crate
lint, locked workspace, release-build, and safe-smoke evidence passes locally.
The definitive verifier passes exact `292/292`; hosted and synchronized-
destination evidence remains pending.
