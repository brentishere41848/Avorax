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

Normal `.aup` engine payloads are restricted to runtime pack files under `payload/engine/signatures`, `payload/engine/rules`, `payload/engine/ml`, and `payload/engine/trust`. The builder may prune known installer-stage-only engine source children such as `engine/config`, `engine/test_corpus`, and `engine/threat_intel`, but any other engine child is a build failure until a separate explicit workflow exists. Supported engine runtime component source directories and destination paths are revalidated before recursive staging. Empty supported engine runtime directories fail the build, and engine component manifest flags are derived from counted staged runtime files rather than directory presence.

Normal `.aup` app and service file staging treats both sides of each copy as untrusted filesystem evidence. Top-level app payload files and allowlisted service binaries are revalidated as regular non-reparse files at copy time, their destination paths are checked before copy, and raw inline destination copies are covered by source-contract regressions.

Normal `.aup` recursive app and engine staging revalidates source trees immediately before `Copy-Item -Recurse`, reducing the gap between earlier tree inspection and recursive copy activation.

Normal `.aup` engine component staging resolves supported runtime component paths from the checked engine source root, and runtime-file counts use the checked component directory before recursive copy.

Normal `.aup` app component evidence uses the shared no-reparse payload-file helper when counting staged app files, aligning app manifest flags with the docs and engine component evidence paths.

Normal `.aup` top-level app staging revalidates the payload root immediately before file and directory enumeration, reducing the gap between initial root inspection and app payload staging.

Normal `.aup` docs file staging follows the same copy boundary: Markdown docs files are enumerated through the shared no-reparse payload-file helper, revalidated as regular non-reparse files at copy time, destination file paths are checked before copy, and unsupported docs content still fails before package creation.

Normal `.aup` docs payload staging enumerates Markdown files from the checked docs source root and derives staging-relative paths from that same checked root.

The shared normal `.aup` payload-file enumeration helper revalidates source trees immediately before recursive file enumeration, so app/docs/engine component evidence and docs staging do not rely solely on earlier tree inspection.

Normal `.aup` payload hashing enumerates staged payload files through the shared no-reparse payload-file helper before revalidating each file immediately before SHA-256 hashing.

Normal `.aup` package artifact activation revalidates the final package path, temporary zip path, and backup path before creating or replacing the archive. The final package file is revalidated before hashing so the generated update feed is tied to a checked regular file.

Normal `.aup` package activation uses the checked temporary package returned by `Require-File` for final `File.Replace` and `File.Move`, so the activated archive comes from the same regular-file evidence accepted after ZIP creation.
Normal `.aup` package artifact creation and activation use post-validation full paths for temporary zip creation, final package target activation, backup path activation, cleanup, and final package validation.

Normal `.aup` zip creation revalidates every work-tree source file immediately before `CreateEntryFromFile`, so archive entries are written from checked regular files rather than trusting earlier enumeration state.

Normal `.aup` zip creation also rejects builder work-tree entries outside `manifest.json`, `manifest.sig`, and `payload/...` immediately before writing the archive, matching the signed package verifier's accepted archive surface.

Signed `.aup` archive validation also requires exactly one `manifest.json` and exactly one `manifest.sig` before manifest reads, signature reads, payload hash scans, or extraction loops proceed.

Signed `.aup` payload validation rejects archives with zero payload files before payload hashing or extraction can report success.

Signed `.aup` archive validation rejects restricted payload roots such as `payload/tools/`, `payload/migrations/`, and driver payload roots even when they appear only as ZIP directory entries.

Signed `.aup` archive validation rejects raw ZIP entry names containing NUL/control characters or excessive length before allowlist and payload path checks.

Signed `.aup` payload extraction revalidates the target parent chain against the canonical staging destination immediately before activating each extracted file, closing the gap between earlier directory creation checks and final rename.

Signed `.aup` payload extraction also revalidates the target parent chain after the final non-following target-absence check and before `rename`, so activation does not rely on parent evidence gathered before target preflight.

Update staged-file activation revalidates the target parent chain against the operation boundary after any existing target removal and immediately before the final rename, so service/docs/app/engine apply copies and staged writes do not rely only on earlier parent checks.

Update staged-file copies revalidate source metadata before open, compare the opened file handle against pre- and post-open source metadata, and reject non-regular or oversized sources before any payload bytes are copied.

Update apply payload-section enumerators revalidate the section root as a directory/non-reparse path immediately before walking or reading entries for app, service, engine, and docs payloads, making a staging-root replacement between presence checks and enumeration fail visibly.

Update apply revalidates the canonical install root as an existing directory/non-reparse path after canonicalization and again immediately before payload-section activation, so the app/service/engine/docs apply phase does not rely solely on the early install-root check.

Rollback restore revalidates its canonical install root as an existing directory/non-reparse path after canonicalization and again immediately before copying snapshot items back into the install directory.

Rollback snapshot resolution revalidates both the canonical rollback root and the canonical snapshot directory as existing directory/non-reparse paths before restore reads snapshot contents.

Rollback latest-snapshot discovery enumerates snapshot entries from a canonical revalidated rollback root before selecting a safe snapshot name for restore.

Update apply failure paths report staging cleanup results in structured update reports and include cleanup failures in returned error context so cleanup faults are visible even when callers only capture command failure text.

Normal `.aup` zip creation revalidates the full work tree immediately before archive enumeration, then still revalidates each individual source file before `CreateEntryFromFile`.

Normal `.aup` zip creation enumerates work-tree files and derives archive entry names from the checked work directory returned by `Require-Directory`, keeping archive path evidence tied to the revalidated root.

Normal `.aup` manifest signing revalidates the `manifest.sig` output path before invoking the external signer, passes a checked manifest file and post-validation signature output path to the signer, and revalidates the produced signature as a regular file before package creation continues.

Normal `.aup` feed generation derives `package_url` from the checked final package file name, avoiding drift between the activated artifact and the feed reference.

Normal `.aup` feed output revalidates the feed path before atomic write and reports the checked final feed file path after write.

Normal `.aup` package output reports the checked final package file path after package activation rather than the pre-validation package path variable.

Flutter update-service subprocess timeouts now request termination and then perform a bounded post-kill exit observation. Timeout diagnostics report whether termination was requested, whether the timed-out process exited within the reap window, or whether exit observation failed, alongside bounded stdout/stderr.

Normal `.aup` metadata generation captures one UTC ISO timestamp and reuses it for signed manifest `release_date` and feed `published_at`, keeping package metadata and feed metadata aligned.

Normal `.aup` payload hashing revalidates each staged payload file immediately before SHA-256 hashing and hashes the checked payload path.
Normal `.aup` payload hashing enumerates staged files and derives manifest payload-hash keys from the checked payload root returned by `Require-Directory`.
Normal `.aup` app component evidence enumerates staged app payload files from the checked app root returned by `Require-Directory`.
Normal `.aup` Core/Guard service component evidence resolves staged service executables from the checked services root returned by `Require-Directory`.
Normal `.aup` engine component evidence resolves runtime component roots from the checked staged engine root returned by `Require-Directory`.
Normal `.aup` docs component evidence enumerates staged docs payload files from the checked docs root returned by `Require-Directory`.

Normal `.aup` shared item validation normalizes paths after no-reparse path validation and uses the post-validation full path for `Get-Item` and fail-visible file/directory diagnostics.
Normal `.aup` stale regular-file cleanup validates paths for reparse traversal and normalizes to the post-validation full path before existence checks and checked removal.
Normal `.aup` existing directory cleanup validates paths for reparse traversal and normalizes to the post-validation full path before existence checks, tree revalidation, and recursive removal.
Normal `.aup` component regular-file probes validate paths for reparse traversal and normalize to the post-validation full path before existence checks and checked file evidence.
Normal `.aup` component directory probes validate paths for reparse traversal and normalize to the post-validation full path before existence checks and checked directory evidence.
Normal `.aup` shared no-reparse tree validation enumerates the checked directory returned by `Require-Directory`, so recursive reparse checks do not fall back to the pre-validation input path string.
Normal `.aup` payload file enumeration validates and enumerates the checked payload directory returned by `Require-Directory`, so recursive file listing does not fall back to the pre-validation input path string.
Normal `.aup` engine unknown/pruned child policy validates and enumerates the checked engine directory returned by `Require-Directory`, so child policy decisions do not fall back to the pre-validation input path string.
Normal `.aup` docs Markdown staging revalidates the checked docs directory returned by `Require-Directory` and derives relative paths from that checked root.
Normal `.aup` top-level app file staging revalidates and enumerates the checked payload root returned by `Require-Directory`.
Normal `.aup` top-level app directory staging revalidates and enumerates the checked payload root returned by `Require-Directory`.
Normal `.aup` service payload staging resolves service executable candidates under the checked payload root returned by `Require-Directory`.

Normal `.aup` checked directory creation validates the requested path, normalizes it to a full path, and then uses that post-validation full path for directory creation and final directory validation.

Normal `.aup` atomic JSON/feed writes revalidate generated temporary and backup paths before writing or activation, and stale random-name collisions are cleaned through checked regular-file removal before a new temporary file is written.
Normal `.aup` raw UTF-8 writes normalize their input to a full path before `WriteAllText`, keeping the final write target aligned with the checked atomic temp path.
Normal `.aup` atomic JSON/feed temporary and backup paths are normalized after validation and those post-validation full paths are used for stale cleanup, write, final temp validation, backup activation, and final cleanup.
Normal `.aup` stale temporary and backup file cleanup removes the checked file path returned by `Require-File`, so cleanup does not fall back to the pre-validation input path string.

Normal `.aup` atomic JSON/feed activation uses the checked temporary file path returned by `Require-File` for `File.Replace` and `File.Move`, so activation does not fall back to the pre-validation temp path string.

Normal `.aup` work-directory cleanup removes the checked directory path returned by `Require-Directory` after tree revalidation, so recursive cleanup does not fall back to the pre-validation input path string.

Normal `.aup` docs payloads are restricted to Markdown files under `payload/docs`. The verifier, builder, and applier reject scripts, binaries, and unsupported docs paths; the applier stages accepted docs files individually instead of activating the entire staged docs tree. The builder derives `components.docs` from counted staged docs files, not directory presence.
Normal `.aup` docs staging revalidates the docs source tree immediately before Markdown file copy staging, then still revalidates each Markdown source file and destination path before copying.

Normal `.aup` app payloads are also preflighted because `payload/app` maps to the install root. The verifier, builder, and applier reject app payloads that would write into restricted install-root surfaces (`engine`, `docs`, `tools`, `driver`, `driver-tools`, or `migrations`) or direct managed service/updater executable names.

The builder derives `components.app` from any staged app payload file, not only from `Avorax.exe`, so resource/DLL-only app updates remain verifiable and self-consistent.
Top-level app payload files are revalidated through the checked regular-file helper at copy time before entering the staged `payload/app` tree.
App payload directories are also revalidated as directories, and their destination paths are checked before recursive staging.

Normal `.aup` service component evidence comes from explicit staged service payload file checks for `avorax_core_service.exe` and `avorax_guard_service.exe`; service component flags are not inferred from arbitrary service directory state.
Normal `.aup` service payload staging revalidates the payload root immediately before staging the allowlisted Core and Guard service binaries, then still revalidates each service source file and destination path before copying.

Normal `.aup` engine child policy enumeration revalidates the engine source tree immediately before checking known runtime components, pruned installer-only children, and unsupported engine children.

## Remaining Limitations

Update Service self-update still needs a short-lived helper process before production use. Driver updates are explicitly rejected by the update manifest verifier and must go through a separate driver workflow.
