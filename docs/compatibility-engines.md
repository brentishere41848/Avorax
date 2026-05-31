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
