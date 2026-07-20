# Cross-Platform Installer Verification

Date: 2026-07-20

Product version: `0.1.15`

Release tag: `v0.1.15-beta.3`

Release commit: `c3fc4f1d18bbd0a7c8f38aae1d1d051b8308515a`

Release workflow: [Desktop Packages run 29761712577](https://github.com/brentishere41848/Avorax/actions/runs/29761712577)

Release: [Avorax Desktop Beta v0.1.15-beta.3](https://github.com/brentishere41848/Avorax/releases/tag/v0.1.15-beta.3)

This report supersedes the `v0.1.15-beta.1` package report. All native package
jobs, checksum consolidation, and prerelease publication passed. The public tag
points to the merged verifier commit above. Package proof is deliberately kept
separate from installed UI, service, signing, and production-protection claims.

## Result Classification

### Verified

- The public prerelease contains seven packages/evidence files plus
  `SHA256SUMS.txt`; all seven checksum entries match GitHub's SHA-256 asset
  metadata, and the checksum file itself matches its GitHub digest.
- Windows MSI verification uses a short opaque temporary root, performs a real
  `msiexec /a` administrative extraction, validates the extracted payload, and
  runs the harmless packaged-core lifecycle smoke without installing Avorax.
- Linux DEB/tar and both macOS DMGs are built and checked on native GitHub-hosted
  runners. Their extracted or mounted packaged cores pass the same bounded
  harmless lifecycle smoke.
- Harmless exact-hash fixtures prove detect-only scanning, confirmed-only
  quarantine, listing, integrity-preserving restore, and source restoration.
- No verification downloads or executes live malware, writes the standard EICAR
  string, alters Microsoft Defender, installs a service/driver, or weakens host
  security.

### Partial

- Administrative extraction or mounting proves package contents and local-core
  behavior, but is not a normal installed GUI click-through test.
- Best-effort user-mode file/process observation is source- and fixture-tested;
  persistent installed-host protection is not established.
- The lockfile CycloneDX report is source-level dependency evidence. It is not a
  complete final-binary SBOM, vulnerability attestation, or independent license
  approval.

### Disabled Or Blocked

- Windows Authenticode production signing requires an approved certificate and
  protected signing workflow. The Windows beta artifacts are `NotSigned`.
- macOS distribution signing and notarization require an Apple Developer
  identity and protected notarization credentials. The DMGs use ad-hoc signing
  and are not notarized.
- The bundled ML model is disabled for production verdict authority because its
  metadata reports `production_ready=false`.
- Driver-backed and pre-execution blocking remain unavailable without a
  reviewed, signed, installed driver and isolated elevated verification.

### Technically Limited

- This experimental beta is not a replacement for Microsoft Defender or another
  supported antivirus. Keep Defender enabled.
- No evidence here proves kernel blocking, macOS Endpoint Security, Linux
  fanotify permission blocking, tamper resistance, or enterprise policy.
- Windows service registration/start/stop, installed quarantine ACLs, and
  packaged UI restore-conflict flows were not exercised because machine-wide
  installation was not approved for this verification.
- Secure erasure is not claimed, including on SSDs.

## Source And Verifier Evidence

| Check | Command or evidence | Result |
| --- | --- | --- |
| PowerShell verifier parse | PowerShell parser API against `tools/packaging/verify-windows-msi.ps1` | Passed: no parser errors |
| Packaging tests | `python -m unittest discover -s tests -p test_packaging_tools.py -v` | Passed: 22 tests; 3 expected Windows symlink cases skipped |
| Python source contracts | `python tools/testing/run-python-source-contracts.py` | Passed: 615 tests |
| Product-copy gate | `powershell -ExecutionPolicy Bypass -File tools/security/zentor-product-copy-gate.ps1` | Passed |
| No-malware-binary gate | `powershell -ExecutionPolicy Bypass -File tools/security/zentor-no-malware-binaries-gate.ps1 -RepoRoot . -PythonPath <python>` | Passed |
| PR #28 CI | General CI and Desktop Packages workflows at the merged source commit | Passed |
| Actual MSI positive case | `verify-windows-msi.ps1 -MsiPath <downloaded-msi> -CoreSmokeScript tools/packaging/smoke_local_core.py -PythonPath <python> -ReportPath <isolated-report>` | Passed: 283 files, 79,136,091 extracted bytes, longest relative path 185 characters; harmless lifecycle passed; extraction root removed |
| Excessive temp-root case | Same verifier with a base path exceeding its 120-character limit | Failed visibly before extraction with the configured length diagnostic |
| Missing smoke evidence case | Same verifier with a benign fake interpreter that exits zero without creating a smoke report | Failed visibly; no success report; temporary root cleaned |

An initial manual administrative extraction under the long checkout path failed
with Windows Installer exit `1603` and log error `1304`; the attempted output
path was 273 characters. The same MSI extracted successfully under a short
opaque `%TEMP%` path. The reusable verifier now enforces that short-root policy,
caps the MSI at 512 MiB and the payload at 10,000 files/2 GiB, rejects reparse
entries, hashes the MSI before and after extraction, validates required payloads,
and performs guarded cleanup. This is a verifier-host path constraint, not
evidence that the MSI was corrupt.

## Native Package Matrix

| Package | Classification | Native evidence and limitation |
| --- | --- | --- |
| Windows x64 MSI | Verified package | Built; staged smoke passed; bounded `msiexec /a` extraction and extracted-core smoke passed; manifest/hash passed; `NotSigned`; no machine install |
| Windows x64 setup EXE | Verified package | WiX Burn bundle built; layout/payload/hash checks passed; `NotSigned`; no machine install or service start |
| Linux x64 DEB | Verified package | Built on Linux; no setuid/setgid payload; extracted manifest and packaged-core lifecycle passed |
| Linux x64 tar.gz | Verified package | Built on Linux; independently extracted; manifest and packaged-core lifecycle passed |
| macOS Apple Silicon DMG | Verified package | Built on macOS; arm64 core, DMG integrity, mounted manifest, and lifecycle passed; ad-hoc/not notarized |
| macOS Intel DMG | Verified package | Built on macOS; x64 core, DMG integrity, mounted manifest, and lifecycle passed; ad-hoc/not notarized |
| Lockfile CycloneDX JSON | Verified source inventory artifact | Included in checksums; remains partial dependency evidence rather than final-binary provenance |

## Public Artifact Hashes

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `Avorax-AntiVirus-0.1.15-linux-x64.deb` | 14,310,776 | `77392580ccb77ada1bc7d504309349019617ff4fa81872ea92018fc94d0e7eef` |
| `Avorax-AntiVirus-0.1.15-linux-x64.tar.gz` | 18,510,964 | `10ca5837538c347ea8f3149758a2475b7f277db33cbca8bdedbcea67bbcc7e7f` |
| `Avorax-AntiVirus-0.1.15-lockfile.cdx.json` | 550,170 | `ae4006e90b35c85be93b6d28ea4958c5ab63ef8eb71dfb08138a89457796e739` |
| `Avorax-AntiVirus-0.1.15-macos-arm64.dmg` | 31,621,644 | `7c1c7f1337c1f80b8ccf71a2744f7577bd0d12578dbbc354fc2b40519da62faa` |
| `Avorax-AntiVirus-0.1.15-macos-x64.dmg` | 33,152,856 | `023dc2a92af10ac3cc4fd934b17c226915e5044aa70d180c5f10d93488b4c7a1` |
| `Avorax-AntiVirus-0.1.15-x64-setup.exe` | 18,669,617 | `75013acff6c0133899a285c71b377d0337c394d06f8675475a8ac123a85f8c99` |
| `Avorax-AntiVirus-0.1.15-x64.msi` | 17,762,272 | `108822168cbc8e2844ac308bc3076680a0cb96614fc42dc52cdf3c7498d09d4e` |
| `SHA256SUMS.txt` | 731 | `3f44099b77cad3be3d26739239eda0f7bbc1369d5e8c5bded2dc51550f3e4e50` |

Independent post-publication comparison reported
`CHECKSUM_ENTRIES=7 ASSETS=8 ALL_MATCH=true`. This proves the public package
bytes agree with the release checksum inventory and GitHub's digest metadata;
it is not publisher-signature evidence.

## Native Workflow Results

| Job | Result |
| --- | --- |
| Package contracts | Success (11s) |
| Linux x64 DEB/tar | Success (5m00s) |
| Windows x64 MSI/EXE | Success (13m37s) |
| macOS arm64 DMG | Success (9m52s) |
| macOS x64 DMG | Success (14m55s) |
| Consolidate/checksum | Success (15s) |
| Publish prerelease | Success (15s) |

## Release Gate

The artifacts are published only as an explicitly labeled experimental
prerelease, so GitHub does not mark them as the latest stable release. The
release retains the beta disclaimer, checksum file, unsigned/not-notarized
warnings, and instruction to keep Microsoft Defender enabled. A production
release remains blocked on protected signing/notarization, installed elevated
service/UI verification, complete dependency approval, and any separately
reviewed driver path.
