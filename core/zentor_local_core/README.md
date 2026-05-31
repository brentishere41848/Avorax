# Avorax Local Core

Avorax Local Core is the Rust desktop helper for selected-path malware scanning, quarantine metadata, allowlist validation, and future selected-path watching.

It communicates with Flutter through stdin/stdout JSON commands. It does not bind to the network.

## Commands

- `health`
- `scan_file`
- `scan_folder`
- `quick_scan_selected_paths`
- `quarantine_file`
- `restore_quarantine_item`
- `delete_quarantine_item`
- `list_quarantine`
- `add_allowlist_entry`
- `remove_allowlist_entry`
- `list_allowlist`
- `start_watch`
- `stop_watch`

## ClamAV

The scanner provider tries `ZENTOR_CLAMAV_CLAMSCAN`, `clamdscan`, `clamscan`, and a bundled `ClamAV\clamscan.exe` next to `zentor_local_core.exe`. If no local ClamAV engine exists, it returns `EngineUnavailable`. It never reports clean unless a real engine scan completes.

The Windows MSI bundles the ClamAV runtime beside the app. Signature database updates are explicit; if ClamAV cannot load a local database, the scan returns an error instead of a fake clean result.

## Quarantine

Infected files are moved to the Avorax quarantine folder, renamed with `.zentorq`, stripped of executable bits where supported, and paired with JSON metadata.

## Tests

```powershell
cargo test
```
