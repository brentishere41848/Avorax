# Compatibility Engines

Pasus Native Engine is the primary engine.

ClamAV and YARA are no longer primary detection layers. Existing code may remain behind compatibility paths for development or comparison, but compatibility engines are disabled by default and must not be required for:

- Quick Scan
- Full Scan
- Custom Scan
- EICAR detection
- quarantine
- Guard verdicts
- real-time protection decisions

The UI must present compatibility engines only in advanced settings if they are enabled explicitly.
