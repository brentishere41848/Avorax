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

1. App reads the configured `update-feed.json` from the GitHub release feed by default. If the trusted GitHub `/releases/latest/download/update-feed.json` route returns 404, dev-channel builds query the GitHub releases API for the newest release asset named `update-feed.json` and load that asset instead. Other feed failures still fail honestly.
2. The Updates page displays the version, channel, package name, release notes, and rollback availability.
3. The user clicks the in-app install button; Avorax downloads only the referenced signed `.aup` package.
4. The app verifies the downloaded package hash before invoking the update service.
5. Avorax Update Service verifies manifest signature and package metadata through its installed service/CLI entry points; no separate authenticated IPC listener is exposed or claimed in this preview build.
6. Avorax Update Service rechecks the verified package SHA-256 on the opened package file before payload extraction, then stages payload files from that same file handle. Staging preparation or extraction failures before service-stop write `update_report.json` with `applied: false`, `rollback: null`, a visible failure field, and staging cleanup evidence.
7. Avorax Update Service snapshots rollback files. Snapshot creation failures before service-stop write `update_report.json` with `snapshot_error`, `applied: false`, `rollback: null`, staging cleanup evidence, no service stop/start attempt, and best-effort cleanup of any partial rollback snapshot.
8. Services are stopped, files are replaced, and services are restarted.
9. Avorax cleans the extracted staging payload after successful apply/restart, failed service-stop reports include restart-after-stop-failure and staging-cleanup evidence, and failed apply/restart reports include staging-cleanup evidence after rollback handling. If cleanup fails after an applied update, the report records `applied: true` with `ok: false` and a staging-cleanup error instead of claiming full success.
10. The app reports `Ready to restart` after apply/rollback finishes; `C:\ProgramData\Avorax\updates\logs\update_report.json` records the result.

Current release-binary verification includes signed package verify/tamper,
fail-before-activation, snapshot-failure, fake-service success, stop-failure
rollback/staging, and direct rollback smokes. The fake-service success smoke uses
a temporary process-local `SystemRoot\System32\sc.exe` and does not claim real
installed Windows service stop/start or installed update E2E.

## Development Package Build

Build the normal Windows stage first, then run:

```powershell
$env:AVORAX_UPDATE_SIGNER = "C:\path\to\sign-manifest.ps1"
$env:AVORAX_UPDATE_PUBLIC_KEY_ID = "avorax-prod-ed25519"
powershell -ExecutionPolicy Bypass -File tools\update\avorax-build-update-package.ps1 -Version 0.2.12
```

The builder refuses to produce an unsigned `.aup`.

### Definitions-only hash updates

`tools/update/avorax-build-hash-intel-update.ps1` composes the local reviewed-hash importer with the normal signed update builder. It stages exactly one strict known-bad SHA-256 pack under `engine/signatures`; the resulting manifest declares `native_engine_assets` and `signatures` while app, service, rules, ML, trust, docs, updater, and driver components remain false. The normal builder creates empty component-evidence directories explicitly, so a valid signature-only payload does not depend on unrelated app or docs files.

The wrapper requires repository-relative source metadata, hash-feed and output paths, an absolute checked Python executable, explicit category/version/channel values, and a configured signer. It bounds child execution and output, rejects reparse-backed paths, rechecks that staging contains exactly one regular signature pack, and removes its checked temporary tree on success or failure. It never performs network acquisition. Production release automation must obtain and review a canonical SHA-256-only feed separately, protect the production signing key, publish both `.aup` and `update-feed.json` over authenticated HTTPS, and retain rollback evidence.

For dev-channel signing with the bundled Python helper, set the signer to an absolute Python executable plus the helper path and opt in to the development key explicitly:

```powershell
$env:AVORAX_ALLOW_DEV_UPDATE_SIGNING = "1"
$env:AVORAX_UPDATE_SIGNER = "C:\path\to\python.exe tools\update\avorax-dev-sign-manifest.py"
powershell -ExecutionPolicy Bypass -File tools\update\avorax-build-update-package.ps1 -Version 0.2.12 -Channel dev
```

Production signing must provide `AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX` from a protected signing environment instead of relying on the built-in development key. The dev signer validates Ed25519 key shape, signs only bounded absolute local regular manifest files, rejects link/reparse-backed paths, and writes the signature as a new exclusive output file instead of following or overwriting an existing output path.
The Rust production signer binary applies the same release-host expectations: manifest and signature paths must be absolute local paths, manifest input is bounded, signer arguments are exact, link/reparse paths are rejected, and `manifest.sig` is created exclusively rather than overwritten. The Rust update key generator also treats arguments strictly: no arguments generates a seed/public key pair, `--help` prints usage without key material, and any other or trailing argument fails visibly.
The verifier parses the manifest from the same bounded `manifest.json` bytes that are checked against `manifest.sig`, so channel/version/component policy is tied to the signed manifest content. `manifest.sig` must decode to exactly one 64-byte Ed25519 signature.
The shared Dart manifest model treats supplied manifest fields as untrusted typed data: malformed string, integer, boolean, or `payload_hashes` fields fail visibly instead of being defaulted or stringified, while missing compatibility fields retain their documented defaults before verifier policy validates a production package.

`PayloadRoot` and `OutputDir` must be repository-relative paths without traversal segments. `Version`, `Channel`, and `AVORAX_UPDATE_PUBLIC_KEY_ID` must be safe tokens. `AVORAX_UPDATE_SIGNER` must start with an absolute local signer path; quote the signer path when it contains spaces. The builder treats payload and output paths as untrusted filesystem evidence: payload trees must not contain reparse points; direct child payload staging, payload hashing, and package zipping must fail visibly if reparse-backed entries are encountered; payload hashing enumerates staged files and derives manifest hash keys from the checked payload root returned by `Require-Directory`; staged payload files are revalidated immediately before SHA-256 hashing; shared item validation uses post-validation full paths for `Get-Item` and diagnostics; shared no-reparse tree enumeration uses the checked directory returned by `Require-Directory`; payload file enumeration uses the checked payload directory returned by `Require-Directory`; component regular-file and directory probes validate and normalize before existence checks; stale regular-file cleanup validates and normalizes before existence checks; existing directory cleanup validates and normalizes before existence checks and recursive removal; the package work tree is revalidated immediately before archive enumeration, and ZIP work-file enumeration plus entry-name derivation use the checked work directory returned by `Require-Directory`; zip entries are limited to `manifest.json`, `manifest.sig`, and `payload/...` and are created only from source files revalidated immediately before zipping; existing cleanup/feed/package targets must be regular files or directories as appropriate; checked directory creation uses the post-validation full path for directory creation and final validation; existing work-directory cleanup removes the checked directory returned by `Require-Directory`; stale temporary and backup file cleanup removes the checked file returned by `Require-File`; manifest and feed writes are atomically staged with generated temporary and backup paths revalidated before write/activation; raw UTF-8 writes normalize to a full path before `WriteAllText`; atomic JSON/feed temporary and backup file operations use post-validation full paths, and final activation uses the checked temporary file returned by `Require-File`; manifest signing passes a checked manifest file and post-validation signature output path to the signer, and produced signatures are revalidated as regular files; final package, temporary zip, and backup artifact paths are revalidated before package activation, package/temp/backup file operations use post-validation full paths, and final package activation uses the checked temporary package returned by `Require-File`; the generated feed `package_url` is derived from the checked final package file name; feed output paths are revalidated before atomic write; success output reports checked package and feed files; signed manifest `release_date` and feed `published_at` share one captured UTC timestamp; and driver payloads are still excluded from normal `.aup` packages. Normal `app` payloads must not target restricted install-root surfaces such as `engine`, `docs`, `tools`, `driver`, `driver-tools`, or `migrations`, and must not carry managed service/updater executable names. Top-level app file and directory staging enumerate the checked payload root returned by `Require-Directory`; top-level app payload files are revalidated as regular non-reparse files and destination paths are checked at copy time; app payload directories are revalidated as directories and destination paths are checked before recursive staging, then the source tree is revalidated again immediately before recursive copy. The shared payload-file helper revalidates source trees immediately before recursive file enumeration. The manifest `components.app` value is derived from counted staged app payload files under the checked staged app root returned by `Require-Directory`, so app resource/DLL updates do not produce self-invalid manifests. Normal service payloads are limited to the staged Core and Guard service executables; service executable discovery uses the checked payload root returned by `Require-Directory`; service source files and destination paths are revalidated before staging, and service component flags are derived from explicit staged service file checks under the checked staged services root returned by `Require-Directory`. Normal engine payloads are limited to runtime pack files under `engine\signatures`, `engine\rules`, `engine\ml`, and `engine\trust`; supported engine runtime component paths are resolved from the checked engine source root returned by `Require-Directory`, runtime file counts use checked component directories, component source directories and destination paths are revalidated before recursive staging, then the source tree is revalidated again immediately before recursive copy; engine unknown/pruned child policy enumerates the checked engine directory returned by `Require-Directory`; empty runtime component directories fail the build and engine component manifest flags are derived from counted staged runtime files under the checked staged engine root returned by `Require-Directory`. Installer-stage-only `engine\config`, `engine\test_corpus`, and `engine\threat_intel` are deliberately not included in normal `.aup` packages, and unknown engine source children fail the build. Normal docs payloads are limited to Markdown files under `docs`; Markdown docs payload enumeration uses the shared no-reparse payload-file helper on the checked docs source root returned by `Require-Directory`, docs Markdown staging revalidates that checked docs source root before relative-path derivation, Markdown relative paths are derived from that checked docs directory, scripts, binaries, and unsupported docs paths are not normal update content and require a separate explicit workflow. The manifest `components.docs` value is derived from counted staged docs payload files under the checked staged docs root returned by `Require-Directory`. PowerShell signer scripts are allowed when they create a regular `manifest.sig`; native signer commands still fail on non-zero exit codes.

## Recovery

If an in-app update fails and rollback cannot recover the install, use the Avorax MSI/EXE repair flow.
