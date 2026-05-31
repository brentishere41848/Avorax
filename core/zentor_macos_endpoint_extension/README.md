# Avorax macOS Endpoint Security Extension

Avorax macOS real-time blocking requires Endpoint Security entitlement and user approval.

Current state:

- Architecture validation state only; no Endpoint Security extension is installed by this repository yet.
- If entitlement or approval is missing, Avorax must show `macOS real-time blocking unavailable`.
- Avorax must fall back to manual scan/quarantine without fake blocking claims.
