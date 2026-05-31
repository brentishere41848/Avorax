# Avorax Privacy

Avorax v1 is visible and user-controlled.

Avorax may:

- Run Quick Scan against common high-risk locations.
- Run Full Scan against accessible local drives or home filesystem areas.
- Run Custom Scan against a user-selected file or folder.
- Calculate hashes for scanned files and selected files or application manifests.
- Use Avorax Cloud for optional status and detection reporting when available.
- Automatically quarantine confirmed infected files when the selected scan mode allows it.
- Store local security events visibly in the app.
- Store explicit false-positive or malicious feedback labels locally when the user submits them.
- Run local AI/static feature extraction offline when a real local model is installed.

Avorax does not:

- Hide scanning activity from the user.
- Permanently delete files automatically.
- Steal credentials.
- Read browser cookies.
- Hide from the user.
- Silently install kernel drivers. Windows driver protection is optional, user-visible, and requires explicit installation.
- Disable other security tools.
- Claim full-system antivirus behavior on mobile.
- Claim 100% malware detection.
- Upload files for AI analysis in v1.
- Retrain itself silently from one user's labels.

Training labels include file hash, file name, path category, static extracted features, previous verdict, user label, optional note, app version, and model version. Raw full paths are not required for training labels unless a future export flow asks for explicit user consent.

Mobile platforms show unavailable states for desktop-style quarantine because Android and iOS sandboxing prevents full-device scanning by a normal app.
