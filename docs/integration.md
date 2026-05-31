# Avorax Integration

## Local Development

1. Configure Avorax Cloud with `--dart-define` values or use the defaults.
2. Run the Flutter app.
3. Avorax silently calls `GET /v1/health`.
4. Use Quick Scan, Full Scan, or Custom Scan on desktop.
5. Choose Detect only or Auto quarantine mode.
6. Review threats and quarantine, restore/keep, delete, or allowlist explicitly.
7. Use Application Control only when a supported app needs verification.

Users do not paste API settings during first launch. Developer overrides are hidden in `Settings > Advanced`.

## API Expectations

The client uses:

- `GET /v1/health`
- `POST /v1/protection-runs`
- `POST /v1/protection-runs/{protection_run_id}/heartbeat`
- `POST /v1/protection-runs/{protection_run_id}/end`
- `POST /v1/detections`
- `POST /v1/quarantine`

If the API is unreachable or returns an error, the client shows that failure and does not fake success.

## Local Core

Desktop malware scanning requires the Rust local core and Avorax Native Engine assets under `assets/zentor_native`. ClamAV and YARA compatibility paths are optional and disabled by default. For development builds, set `ZENTOR_LOCAL_CORE` to a release folder that contains `zentor_local_core.exe` and the native assets.
