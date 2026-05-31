# Avorax Client UI

Avorax is a native Flutter Material 3 app. The runtime UI is not a website, browser, WebView, iframe, or embedded dashboard.

## First Screen

The app opens to Home, not an API setup form. Home shows:

- Cloud status pill.
- Protection status pill.
- Run Quick Scan action.
- Run Full Scan action.
- Enable Protection action.
- Compact cards for Real-time protection, Malware engine, Last scan, Quarantine, Updates, and recovery status.
- Updates are based on real GitHub Release metadata. Avorax shows update available, up to date, checking, or check failed, and never installs silently.
- Recent activity from real local events only.

If Avorax Cloud is unavailable, the UI shows `Cloud Offline` without a red blocking setup form.

## Navigation

Desktop uses a left sidebar:

- Home
- Scan
- Protection
- Quarantine
- Allowlist
- Device
- Security Events
- Settings

Mobile uses bottom navigation:

- Home
- Scan
- Quarantine
- Settings

## Empty States

Production runtime must never show fake users, fake detections, fake charts, or fake scan results. Empty states are explicit:

- No scan results.
- No threats found.
- No quarantined files.
- No activity yet.
- Update check failed.

Device protection must not depend on any unrelated product mode.
