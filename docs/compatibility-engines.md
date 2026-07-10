# Compatibility Engines

Avorax Native Engine is the primary engine.

ClamAV and YARA are no longer primary detection layers. Existing code may remain behind compatibility paths for development or comparison, but compatibility engines are disabled by default and must not be required for:

- Quick Scan
- Full Scan
- Custom Scan
- EICAR detection
- quarantine
- Guard verdicts
- real-time protection decisions

The UI must present compatibility engines only in advanced settings if they are enabled explicitly.

Guard Service compatibility code is compiled behind explicit Cargo features:

- `compat_clamav`
- `compat_yara`

Default Guard builds do not call these engines in the process-start or driver-verdict path. ANE native verdicts are evaluated first and are sufficient for EICAR/test-threat decisions.

When local-core ClamAV compatibility is enabled for development, the scanner must be either configured with an absolute local `ZENTOR_CLAMAV_CLAMSCAN` path or bundled beside the running local-core executable. Ambient `PATH` lookup and current-working-directory scanner discovery are not trusted.

Guard ClamAV compatibility follows the same rule when the `compat_clamav` feature is explicitly enabled: configured scanners must be absolute local paths and bundled scanners must be executable-relative, not discovered from `PATH` or the current working directory.
