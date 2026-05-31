# Avorax In-App Updates

Avorax uses MSI/EXE installers for first install, repair, uninstall, recovery, and offline/manual installation. Normal updates are installed inside Avorax using signed `.aup` packages.

## Package Format

`.aup` means Avorax Update Package. It is a ZIP archive with:

- `manifest.json`
- `manifest.sig`
- `payload/`

The manifest declares product, version, channel, components, rollback support, payload hashes, package hash, signature algorithm, and public key id.

## Security Rules

- Avorax must not install unsigned update packages.
- Avorax must not execute downloaded EXE installers for normal updates.
- Avorax must reject driver updates in `.aup` packages until a separate explicit driver update workflow exists.
- Private signing keys must not be committed.
- The public verification key can be compiled into `avorax_update_service` with `AVORAX_UPDATE_PUBLIC_KEY_HEX` or provided by the environment under the same name.
- Production builds must reject dev-signed packages unless explicitly configured as dev builds.

## Update Flow

1. App reads the configured `update-feed.json`.
2. App downloads the referenced `.aup` package.
3. Avorax Update Service verifies manifest signature and package metadata.
4. Avorax Update Service stages payload files.
5. Avorax Update Service snapshots rollback files.
6. Services are stopped, files are replaced, and services are restarted.
7. `C:\ProgramData\Avorax\updates\logs\update_report.json` records the result.

## Development Package Build

Build the normal Windows stage first, then run:

```powershell
$env:AVORAX_UPDATE_SIGNER = "C:\path\to\sign-manifest.ps1"
$env:AVORAX_UPDATE_PUBLIC_KEY_ID = "avorax-prod-ed25519"
powershell -ExecutionPolicy Bypass -File tools\update\avorax-build-update-package.ps1 -Version 0.2.12
```

The builder refuses to produce an unsigned `.aup`.

## Recovery

If an in-app update fails and rollback cannot recover the install, use the Avorax MSI/EXE repair flow.
