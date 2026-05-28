# Pasus Integration

## Local Development

1. Configure Pasus Cloud with `--dart-define` values or use the defaults.
2. Run the Flutter app.
3. Pasus silently calls `GET /v1/health`.
4. Use Quick Scan, Full Scan, or Custom Scan on desktop.
5. Choose Detect only or Auto quarantine mode.
6. Review threats and quarantine, restore/keep, delete, or allowlist explicitly.
7. Use Gaming Protection only when a supported game needs verification.

Users do not paste API settings during first launch. Developer overrides are hidden in `Settings > Advanced`.

## API Expectations

The client uses:

- `GET /v1/health`
- `POST /v1/sessions`
- `POST /v1/sessions/{session_id}/heartbeat`
- `POST /v1/sessions/{session_id}/end`
- `POST /v1/detections`
- `POST /v1/quarantine`

If the API is unreachable or returns an error, the client shows that failure and does not fake success.

## Local Core

Desktop malware scanning requires the Rust local core and Pasus Native Engine assets under `assets/pasus_native`. ClamAV and YARA compatibility paths are optional and disabled by default. For development builds, set `PASUS_LOCAL_CORE` to a release folder that contains `pasus_local_core.exe` and the native assets.
