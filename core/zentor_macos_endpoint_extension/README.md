# Zentor macOS Endpoint Security Extension

Zentor macOS real-time blocking requires Endpoint Security entitlement and user approval.

Current state:

- Architecture validation state only; no Endpoint Security extension is installed by this repository yet.
- If entitlement or approval is missing, Zentor must show `macOS real-time blocking unavailable`.
- Zentor must fall back to manual scan/quarantine without fake blocking claims.
