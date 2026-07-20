# Avorax Desktop Installers

This document defines what each Avorax desktop package contains, how it is
built, and what its verification does and does not prove.

## Beta boundary

Avorax Desktop Beta is not a replacement for Microsoft Defender or another
supported antivirus. The current public packages are development releases:

- Windows MSI and EXE packages are not Authenticode-signed.
- macOS DMGs are ad-hoc signed, not Developer ID signed or notarized.
- Linux DEB and tar packages are not signed by a package repository.
- No package contains a production-signed Windows driver, Linux kernel module,
  or macOS Endpoint Security extension.
- No package may claim pre-execution blocking.

Verify release SHA-256 checksums before use. An integrity manifest shipped
inside a package detects accidental or post-build file changes, but an unsigned
manifest does not authenticate publisher identity.

## Package matrix

| Platform | Artifacts | Architectures | Privileged components | Update apply |
| --- | --- | --- | --- | --- |
| Windows | MSI and WiX Burn setup EXE | x64 | Visible Core, Guard, and demand-start Update Windows services; no driver in the beta build | Signed `.aup` path is present, but usable only with a correctly signed/configured feed |
| Linux | DEB and portable tar.gz | x64 | None; no service, startup entry, setuid file, or kernel module | Release check only; install a new package manually |
| macOS | DMG containing `Avorax.app` | Apple Silicon and Intel | None; no daemon, login item, privileged helper, or Endpoint Security extension | Release check only; install a new DMG manually |

All desktop packages include the Flutter UI, the Rust local core, the Rust Guard
helper, Avorax Native Engine signatures/rules/trust/model assets, the beta
notice, privacy/limitation documentation, and an integrity inventory.

## Capability matrix

`Verified` here means the package builder exercises the staged or
extracted/mounted payload. It does not mean independent antivirus certification.

| Capability | Windows MSI/EXE | Linux DEB/tar | macOS DMG |
| --- | --- | --- | --- |
| Quick, Full, Custom scans | Included | Included | Included |
| Detect-only mode | Included | Included | Included |
| Confirmed-only quarantine | Included | Included | Included |
| List and restore quarantine | Included | Included | Included |
| Local allowlist, exclusions, logs | Included | Included | Included |
| App-lifetime file watch/poll | Best-effort user mode | Best-effort user mode | Best-effort user mode |
| Process observation | Best-effort user mode | Snapshot/user-mode limits | Snapshot/user-mode limits |
| Persistent background service | Visible Windows services | Disabled | Disabled |
| Kernel/pre-execution blocking | Disabled; no signed driver | Disabled | Disabled |
| Production AI auto-quarantine | Disabled; model metadata says development | Disabled | Disabled |
| In-app binary apply/rollback | Windows-only signed `.aup` path | Disabled, manual reinstall | Disabled, manual reinstall |

## Package verification

### Common scanner smoke

`tools/packaging/smoke_local_core.py` starts the package's actual local-core
binary directly without a shell and verifies:

1. Packaged native engine health and self-test.
2. Positive signature and rule counts.
3. Detect-only handling of harmless exact-hash fixture bytes.
4. Confirmed-only quarantine to an opaque `.avoraxq` path.
5. Quarantine listing.
6. Restore with the original bytes preserved.

The smoke uses an isolated temporary data/quarantine root. It does not write
EICAR, use live malware, access the network, install services, change machine
settings, or claim UI/driver/pre-execution proof.

### Windows

`installer/windows/build-msi.ps1` builds the Flutter app and Rust services,
stages assets, generates a release file-hash inventory, then builds:

```text
dist/Avorax-AntiVirus-VERSION-x64.msi
dist/Avorax-AntiVirus-VERSION-x64-setup.exe
```

The release workflow checks the staged payload, runs the packaged local-core
smoke, records `Get-AuthenticodeSignature` output, and administratively extracts
the MSI into an isolated directory. It does not perform a normal MSI install or
register services during CI.

The same non-installing MSI verification can be reproduced on Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\packaging\verify-windows-msi.ps1 `
  -MsiPath .\dist\Avorax-AntiVirus-0.1.15-x64.msi `
  -PythonPath (Get-Command python -CommandType Application).Source
```

The verifier uses a short, opaque directory below `RUNNER_TEMP` or `TEMP`,
checks the real `msiexec` exit code, rejects reparse points, validates required
payloads, runs the benign packaged-core smoke, writes structured evidence, and
removes only its own verified temporary directory. Windows Installer can return
error 1304/1603 when an administrative extraction target makes a payload path
longer than the legacy path limit; pass `-TemporaryBasePath` with a shorter
local directory when the verifier rejects an overlong temporary root.

### Linux

```bash
bash installer/linux/build-linux.sh --version 0.1.15
```

The builder verifies ELF dependencies with `ldd`, rejects setuid/setgid files,
creates and verifies `install-manifest.json`, runs the common scanner smoke,
builds DEB/tar artifacts, extracts the DEB without installing it, and repeats
manifest/scanner verification from the extracted payload.

### macOS

```bash
bash installer/macos/build-macos.sh --version 0.1.15
```

The builder adds the Rust helpers and engine assets to `Avorax.app`, applies an
ad-hoc signature, runs strict `codesign` verification, confirms the release app
does not carry the App Sandbox entitlement, runs the common scanner smoke,
creates and verifies the DMG, mounts it read-only, and repeats signature,
manifest, and scanner verification from the mounted image.

The release build is intentionally outside the App Sandbox so it can scan
user-readable selected paths. macOS TCC protections still apply. Avorax does not
grant itself Full Disk Access or install an Endpoint Security extension.

## Install and remove

### Windows

Run either the setup EXE or MSI from the official release after checksum
verification. Administrator consent is required because the package writes to
Program Files/ProgramData and registers visible Windows services.

Remove Avorax from Windows Settings > Apps. The MSI removes installed binaries,
shortcuts, and registered services. Review or remove retained user/security data
separately only after confirming no quarantine item is still needed.

### Linux

Install the DEB:

```bash
sudo apt install ./Avorax-AntiVirus-0.1.15-linux-x64.deb
```

Run `avorax` as the normal desktop user. Do not run the application as root.

Remove the package:

```bash
sudo apt remove avorax-antivirus
```

The portable tarball can be extracted and run without package installation.

### macOS

Open the matching architecture DMG and drag `Avorax.app` to Applications. The
beta is not notarized, so Gatekeeper can reject it. Use Finder's normal Open
confirmation or System Settings > Privacy & Security only after verifying the
checksum and source. Do not disable Gatekeeper globally.

Remove the app from Applications. User data and quarantine are not silently
deleted with the app.

## Data locations

| Platform | Default local data |
| --- | --- |
| Windows | `%ProgramData%\Avorax` with user-data fallback where required |
| Linux | `~/.local/share/avorax` |
| macOS | user application-support data resolved by the client/core |

Quarantine payloads use opaque `.avoraxq` names and executable bits are removed
where supported. Metadata is authenticated. On Windows, the metadata
authentication key is protected with DPAPI. Quarantine payload contents are not
promised to be encrypted on every platform, and Avorax does not promise secure
erasure on SSDs.

## Production signing prerequisites

Production distribution remains blocked until the release owner supplies and
operationally protects:

- An Authenticode certificate and timestamping policy for Windows MSI/EXE and
  executable signing.
- Apple Developer ID Application credentials plus notarization/stapling
  credentials for both macOS architectures.
- A Linux repository/package-signing key and publishing policy.
- Production update signing keys stored outside the repository.
- For kernel/pre-execution claims, separately signed/approved platform
  components and passing installed self-tests.

No signing key or private credential belongs in source control.
