# Avorax Anti-Virus

[![Avorax CI](https://github.com/brentishere41848/Avorax/actions/workflows/ci.yml/badge.svg)](https://github.com/brentishere41848/Avorax/actions/workflows/ci.yml)
[![Desktop packages](https://github.com/brentishere41848/Avorax/actions/workflows/desktop-packages.yml/badge.svg)](https://github.com/brentishere41848/Avorax/actions/workflows/desktop-packages.yml)

Avorax is a privacy-first desktop anti-malware client with a Flutter interface
and a Rust detection core. Quick, Full, and Custom scans work locally without an
account or cloud service. The core combines exact hashes, native signatures,
deterministic rules, bounded static analysis, archive inspection, conservative
heuristics, trust data, and an explainable verdict aggregator.

Avorax is currently a **desktop beta**, not a finished replacement for a
production antivirus.

> **Safety warning**
>
> Do not use Avorax Desktop Beta as the only antivirus on a device. It can
> detect common local threats covered by its current rules and signatures, but
> it can miss advanced, novel, targeted, polymorphic, fileless, kernel-level, or
> large-scale malware and ransomware. Keep Microsoft Defender or another
> supported antivirus enabled. No antivirus can guarantee 100% detection.

## Download

Use only assets from the official
[Avorax Releases](https://github.com/brentishere41848/Avorax/releases) page and
verify the published SHA-256 checksums before opening them.

| Platform | Artifact | Architecture | Beta signing status |
| --- | --- | --- | --- |
| Windows | `Avorax-AntiVirus-VERSION-x64-setup.exe` | x64 | Unsigned |
| Windows | `Avorax-AntiVirus-VERSION-x64.msi` | x64 | Unsigned |
| Linux | `Avorax-AntiVirus-VERSION-linux-x64.deb` | x64 | Unsigned local package |
| Linux | `Avorax-AntiVirus-VERSION-linux-x64.tar.gz` | x64 | Unsigned portable bundle |
| macOS | `Avorax-AntiVirus-VERSION-macos-arm64.dmg` | Apple Silicon | Ad-hoc signed, not notarized |
| macOS | `Avorax-AntiVirus-VERSION-macos-x64.dmg` | Intel | Ad-hoc signed, not notarized |

An artifact is not considered verified merely because its filename exists.
Release evidence must include native build logs, package extraction or read-only
mount verification, packaged-core smoke results, signing status, and SHA-256.
See [installer verification](docs/reports/cross-platform-installer-verification.md).

## What Works

- Offline Quick, Full, and Custom scans on Windows, Linux, and macOS.
- Detect-only and confirmed-threat auto-quarantine scan modes.
- Exact-hash and native signature matching.
- Deterministic local rules and bounded static file analysis.
- PE, script, document-carrier, and bounded ZIP-family archive inspection.
- Conservative heuristic scoring with allowlists, exclusions, and trust data.
- Explainable clean, unknown, suspicious, probable, and confirmed verdicts.
- Scan progress, cancellation, structured local events, status, and history.
- Quarantine listing, integrity checks, restore, and explicit permanent delete.
- Best-effort app-lifetime file watch/poll and process observation.
- Optional cloud status/reporting paths; local scanning does not require them.
- Signed `.aup` verification/apply architecture on Windows when a valid signed
  release feed and Update Service are configured.

## What Does Not Work Yet

- No guaranteed detection or independent antivirus certification.
- No production-ready AI protection. The bundled model is explicitly marked
  `production_ready=false` and cannot auto-quarantine by itself.
- No production-signed Windows driver and no verified kernel/pre-execution
  blocking.
- No macOS Endpoint Security extension or pre-execution blocking.
- No installed Linux fanotify service or kernel enforcement.
- No persistent Linux/macOS background service or startup entry.
- No automatic binary apply/rollback on Linux or macOS; the UI shows manual
  package reinstall instead of a dead update control.
- No full-device antivirus claim on Android or iOS.
- No promise of ransomware decryption without a backup, snapshot, vault copy,
  or key.

## Platform Capabilities

| Capability | Windows installer | Linux packages | macOS DMG |
| --- | --- | --- | --- |
| Manual scans | Included | Included | Included |
| Quarantine/restore/delete | Included | Included | Included |
| Allowlist/exclusions/logs | Included | Included | Included |
| App-lifetime user-mode observation | Best effort | Best effort | Best effort |
| Persistent helper | Visible Windows services | None | None |
| Pre-execution blocking | Disabled without signed driver | Disabled | Disabled |
| In-app package apply/rollback | Windows signed-package path | Manual reinstall | Manual reinstall |
| Production code signing | Not in public beta | Not in public beta | Not in public beta |

"Best effort" means post-write or post-launch user-mode observation. It is not a
claim that Avorax can inspect or block every filesystem or process event.

## Install

### Windows

Choose one:

- The setup EXE is the normal interactive installer.
- The MSI is useful for direct Windows Installer testing and managed deployment.

Administrator consent is required because the installer writes under Program
Files and ProgramData and registers visible Core, Guard, and demand-start Update
services. The beta does not install a driver unless a separate, complete signed
driver package is explicitly required at build time; the public beta workflow
does not include one.

Windows SmartScreen can warn because the beta is unsigned. Do not disable
SmartScreen or Defender. Proceed only when the file came from the official
release and its SHA-256 matches.

### Linux

Install the DEB:

```bash
sha256sum Avorax-AntiVirus-VERSION-linux-x64.deb
sudo apt install ./Avorax-AntiVirus-VERSION-linux-x64.deb
avorax
```

Run Avorax as the normal desktop user, not root.

For a non-installed bundle:

```bash
tar -xzf Avorax-AntiVirus-VERSION-linux-x64.tar.gz
./Avorax/Avorax
```

### macOS

Download the DMG matching the Mac architecture, verify it, open it, and move
`Avorax.app` to Applications:

```bash
shasum -a 256 Avorax-AntiVirus-VERSION-macos-arm64.dmg
```

The beta is not Apple-notarized. Gatekeeper can reject it. Use Finder's normal
Open confirmation or System Settings > Privacy & Security only after verifying
the source and checksum. Never disable Gatekeeper globally.

Avorax does not grant itself Full Disk Access. macOS privacy controls can make
protected paths unavailable; those paths must be reported as skipped or denied,
not falsely clean.

Detailed install, removal, payload, and signing notes are in
[docs/installers.md](docs/installers.md).

## First Scan

1. Leave the existing supported antivirus enabled.
2. Open Avorax and check that Avorax Native Engine reports available.
3. Keep the first run in **Detect only** mode.
4. Run a Quick Scan.
5. Review confirmed, probable, suspicious, skipped, and error counts.
6. Enable confirmed-only auto-quarantine only after reviewing the result.

Quick Scan targets high-risk user-writable and startup locations with bounded
depth and risky file types. Full Scan walks accessible local roots and reports
permission failures and skipped paths. Custom Scan touches only the selected
file or folder.

## Safe Validation

Never download or execute live malware to test Avorax. Use EICAR only when the
host antivirus permits it, or use the repository's harmless exact-hash smoke.
Microsoft Defender may intercept EICAR before Avorax sees it; that is expected
and is not a reason to disable Defender.

Cross-platform packaged-core verification:

```bash
python tools/packaging/smoke_local_core.py \
  --core /path/to/avorax_core_service \
  --engine-root /path/to/package-root \
  --report package-core-smoke.json
```

The smoke creates only temporary harmless bytes and an isolated exact-hash rule.
It verifies engine health, detect-only behavior, quarantine, listing, and
byte-preserving restore. It writes no EICAR string, uses no live malware,
requires no network, and makes no machine-wide change.

## Detection Pipeline

Avorax Native Engine (ANE) is the primary local scanner:

1. **Input controls** validate paths, file kind, exclusions, limits, and
   cancellation.
2. **Content reader** computes a full-file SHA-256 with streaming I/O and keeps
   only a bounded analysis sample.
3. **Signatures** match curated exact hashes, strings, bytes, scripts, and PE
   indicators.
4. **Rules** evaluate deterministic local rule packs with bounded reads.
5. **Static analyzers** inspect file type, PE metadata, scripts, carrier
   documents, entropy, suspicious strings, and bounded archive entries.
6. **Trust controls** apply known-good data, explicit allowlists, and exclusions.
7. **Verdict fusion** combines independent evidence into an explainable result
   and conservative action policy.

Weak signals do not become malware labels by themselves. An unsigned developer
tool, unknown CLI binary, VPN installer, or normal executable in Downloads is
not automatically called a virus. Suspicious and heuristic findings remain
review-only unless stronger confirmed evidence exists.

Resource boundaries include file-size/sample limits, archive entry/size/depth
limits, path and command bounds, scan cancellation, bounded diagnostics, and
cache controls. Errors remain visible; engine failure must not be converted into
a clean verdict.

## Quarantine

Confirmed threats can be moved to a controlled quarantine directory with an
opaque ID and `.avoraxq` extension. Avorax removes executable bits where
supported, records hashes and action metadata, authenticates metadata, checks
payload integrity before restore, rejects unsafe destinations and traversal,
and never permanently deletes automatically.

On Windows, the metadata authentication key is DPAPI-protected. This does not
mean every quarantine payload is encrypted on every platform. Avorax does not
promise secure erasure, especially on SSDs.

Restore and permanent delete always require explicit user action. Restore
refuses silent overwrite conflicts.

## Real-Time Protection

The beta's default protection is user-mode and post-event:

- The app can run bounded file watch/poll sessions while its controller is
  active.
- Process snapshots and Guard policy can identify confirmed known threats and
  attempt post-launch response where the OS permits.
- Suspicious or low-confidence observations are logged for review, not silently
  quarantined.

True Windows pre-execution blocking requires a signed, installed, running
driver with authenticated IPC and a passing self-test. macOS requires an
approved Endpoint Security extension. Linux enforcement requires an explicitly
installed and permissioned fanotify path. None is included in the desktop beta.

## App Updates

Release checks use the configured official GitHub release feed over HTTPS.
Network metadata and packages are untrusted until bounded, parsed, hashed, and
signature-verified.

Windows app updates use signed `.aup` packages with a
verification/apply/rollback architecture. It is usable only when release
signing keys, feed metadata, package signatures, and the installed Update
Service are correctly configured. Raw downloaded EXE installers are not the
normal in-app update target.

On a correctly provisioned Windows release, `Download, verify, install`
streams the package to a reserved temporary file, verifies the feed SHA-256,
and asks the Update Service to verify the signed manifest/package metadata
before staging it. A successful apply reaches `Ready to restart`; rollback is
available only when the service reports a complete validated snapshot.

MSI/EXE installers remain first-install, repair, recovery, offline, and manual-install paths.
The client must not execute downloaded EXE installers for normal updates.
Release automation must publish a versioned `update-feed.json` and signed `.aup` package before the Windows in-app path is considered operational.
This unsigned beta fails closed if those signing materials or service evidence
are absent.

Linux and macOS can check for a newer release but intentionally disable package
apply and rollback. Install the matching new DEB/tar/DMG manually.

## Privacy

Local scans, quarantine, allowlists, settings, logs, and results do not require
an account or cloud service. Avorax does not upload file contents for AI
analysis, read browser cookies, collect credentials, hide scanning activity, or
disable other security products.

Optional cloud features are explicit. Diagnostic exports exclude file contents
and quarantine payloads and redact common credential-shaped values, but exports
can still contain local paths and errors and should be reviewed before sharing.
See [privacy](docs/privacy.md) and [security model](SECURITY_MODEL.md).

## Desktop Local Core

```text
Flutter desktop UI
  -> bounded JSON over local stdin/stdout
Rust Local Core
  -> scan jobs, cancellation, quarantine, allowlist, logs
Avorax Native Engine
  -> signatures + rules + static analysis + heuristics + trust + verdicts

Rust Guard helper
  -> best-effort user-mode file/process observation and policy

Windows Update Service
  -> signed .aup verification, staging, apply, rollback
```

The local core does not bind a network port. The UI is a control/display
surface, not the security boundary.

## Repository

```text
apps/zentor_client/             Flutter desktop client
packages/zentor_protocol/       Shared Dart protocol/state models
core/zentor_native_engine/      Primary Rust detection engine
core/zentor_local_core/         Local scanner/quarantine IPC surface
core/zentor_guard_service/      User-mode Guard and driver-facing policy
core/avorax_update_service/     Signed update verifier/apply service
assets/zentor_native/           Signatures, rules, trust, model, safe fixtures
installer/windows/              WiX MSI and setup EXE
installer/linux/                DEB and portable tar builder
installer/macos/                Native DMG builder
tools/packaging/                Package manifest and harmless lifecycle smoke
docs/                           Architecture, safety, audits, operations
```

Historical internal `zentor_*` names remain in paths and protocol identifiers.
Product-facing behavior and documentation use Avorax.

## Build From Source

Clone:

```bash
git clone https://github.com/brentishere41848/Avorax.git
cd Avorax
```

Core checks:

```bash
cargo test --workspace --locked -- --test-threads=1
cd apps/zentor_client
flutter pub get
flutter analyze
flutter test
```

Desktop builds must run natively on the target OS:

```bash
flutter build windows --release
flutter build linux --release
flutter build macos --release
```

Windows additionally needs Visual Studio Desktop development with C++, CMake,
a Windows SDK, a .NET SDK, and the pinned WiX tool manifest. Linux needs the
Flutter GTK/CMake/Ninja build prerequisites. macOS needs Xcode and its command
line tools.

Build installers:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 `
  -Version 0.1.15 `
  -RequireLocalCore `
  -AllowDevelopmentModel `
  -DotnetPath C:\Path\To\dotnet.exe `
  -CargoPath C:\Path\To\cargo.exe `
  -FlutterPath C:\Path\To\flutter.bat
```

```bash
bash installer/linux/build-linux.sh --version 0.1.15
bash installer/macos/build-macos.sh --version 0.1.15
```

The cross-platform workflow is
[desktop-packages.yml](.github/workflows/desktop-packages.yml). It builds on
native Windows, Linux, Apple Silicon macOS, and Intel macOS runners.

## Verification

Start with:

```bash
python -m unittest discover -s tests -p "test_packaging_tools.py" -v
cargo test --workspace --locked -- --test-threads=1
```

Then run the platform package builder. A successful build must include staged
and extracted/mounted payload evidence, packaged-core smoke reports, integrity
manifests, signing/notarization status, and SHA-256 values.

Current verification and blockers:

- [Testing](TESTING.md)
- [Installer operations](docs/installers.md)
- [Installer verification report](docs/reports/cross-platform-installer-verification.md)
- [Engine/control matrix](docs/audit/engine-control-matrix.md)
- [Known blockers](docs/audit/known-blockers.md)
- [Threat model](docs/audit/threat-model.md)

## Security and Safety

Do not submit live malware to this repository. Security tests may use EICAR,
harmless known-bad hashes, inert feature fixtures, and bounded simulators in
isolated temporary directories only.

For a vulnerability, prefer GitHub's private security reporting for this
repository when available. Do not publish exploit details, signing keys,
credentials, quarantine contents, or sensitive local logs in a public issue.

## License

No repository-wide open-source license is currently declared. Public source
availability is not, by itself, a grant of permission to reuse or redistribute
the code. Third-party dependency license evidence is tracked in
[docs/dependency-license-inventory.md](docs/dependency-license-inventory.md);
final release artifacts still require a complete SBOM and license review.
