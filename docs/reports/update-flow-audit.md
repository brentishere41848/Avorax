# Avorax Update Flow Audit

## Current Update Behavior Before This Change

The Flutter client checked GitHub Releases through `apps/zentor_client/lib/core/updates/update_service.dart`. Earlier preview builds selected `.exe` or `.msi` release assets and opened or started an installer-oriented update path.

That was not a real in-app update system. It reused first-install/repair installer artifacts for normal updates and could put the user back into setup wizard behavior.

## Current Installer Behavior

Windows MSI/EXE packaging is built by `installer/windows/build-msi.ps1` and `.github/workflows/release-windows.yml`. Release artifacts are named:

- `Avorax-AntiVirus-<version>-x64.msi`
- `Avorax-AntiVirus-<version>-x64-setup.exe`

These artifacts remain valid for first install, repair, uninstall, recovery, and offline/manual installs.

## Version Source

The Flutter app version comes from build defines:

- `AVORAX_APP_VERSION`
- `ZENTOR_APP_VERSION` compatibility fallback

The fallback in `apps/zentor_client/lib/core/config/build_config.dart` is development-only and must not be used to fake release state.

## Release Artifact Source

GitHub Actions currently publishes MSI/EXE release assets. Normal in-app updates now require a signed `.aup` package referenced by `update-feed.json`; MSI/EXE assets are no longer a normal update target.

## Code Paths Replaced

- `apps/zentor_client/lib/core/updates/update_service.dart`: replaced GitHub installer asset selection with update-feed and `.aup` package handling.
- `apps/zentor_client/lib/app/app_state.dart`: replaced external installer launch flow with download, verify, and apply states.
- `apps/zentor_client/lib/features/settings/settings_screen.dart`: update copy now explains signed in-app packages.
- `apps/zentor_client/lib/features/update/`: added dedicated update UI.

## New Update Architecture

- `core/avorax_update_service/`: local privileged updater service and command-line verification/apply entry points.
- `.aup`: ZIP-based Avorax Update Package containing `manifest.json`, `manifest.sig`, and `payload/`.
- `update-feed.json`: signed-package feed consumed by the app.
- `tools/update/avorax-build-update-package.ps1`: build helper that refuses to create unsigned packages.

## Remaining Limitations

Update Service self-update still needs a short-lived helper process before production use. Driver updates are explicitly rejected by the update manifest verifier and must go through a separate driver workflow.
