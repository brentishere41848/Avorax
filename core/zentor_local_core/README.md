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

## Tests

```powershell
cargo test
```
