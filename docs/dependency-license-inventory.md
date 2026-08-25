# Dependency and License Inventory

Date: 2026-08-20

This inventory records dependency pinning and license evidence that affects Avorax release readiness. It is source-derived evidence for the current checkout. The desktop release workflow now emits a deterministic CycloneDX lockfile component inventory, but that inventory is explicitly incomplete and is not a substitute for final-binary dependency resolution plus complete license review on a provisioned release host.

A full SBOM generated from the exact final artifacts, together with a complete license and copyright review, is required on the provisioned release host before production release approval. The source-level inventory in this repository cannot satisfy that gate by itself.

`tools/security/avorax-dependency-evidence.ps1` verifies the source-level dependency evidence without launching ambient package managers. In release mode it fails on missing required lockfiles; use `-AllowKnownBlockers` only for partial local evidence reports that must not be treated as release approval. Reports with allowed blockers and remaining release blockers set `partial=true`.

Checkpoint 2131 expands the generated dependency evidence JSON with `lockfile_summaries` and `license_inventory`. The summaries are derived from bounded local reads of Cargo, pub, and Python lockfiles and record package counts plus checksum/SHA-256/exact-pin counts. The license inventory is intentionally `source_level_partial`: it points to this document, confirms no machine-wide dependency installation and no network access are required by the gate, and keeps `full_release_sbom_required=true` until a provisioned release host generates complete SBOM/license output from final artifacts.

Checkpoint 2157 adds `tools/packaging/create_dependency_sbom.py`. The dependency-free generator performs bounded UTF-8 reads of regular non-link Cargo, pub, and Python lockfiles; rejects malformed structure, missing hosted pub.dev SHA-256 evidence, duplicate pub fields, changed inputs, links/reparse paths, conflicting hashes, and unsafe output targets; deduplicates package URLs while retaining every source lockfile; and writes deterministic CycloneDX 1.6 JSON atomically. With the checkpoint 2184 internal platform-security workspace member, the current repository produces `570` unique components. Two independent local runs produced SHA-256 `D04315EEB9326F73D0C327D18B5D143DBDFAFBFB8110A215197C7B3589DB0BBE`. The generator and dependency evidence gate pass; final release artifacts still require schema validation and complete license review on the provisioned release host.

The generated metadata deliberately states `avorax:license-review-status=partial`, `avorax:final-binary-resolution=false`, and `compositions.aggregate=incomplete`. The cross-platform workflow includes the `.cdx.json` beside the six native artifacts and includes it in `SHA256SUMS.txt`. This closes the missing reproducible lockfile inventory, not the production license/SBOM blocker.

## Python ML Tooling

`ml/requirements.txt` is used only for offline development model export and schema validation. `ml/requirements.lock.txt` pins the direct and transitive packages used by the Windows/Python 3.12 verification environment. These packages must not be installed machine-wide by Avorax and are not required for runtime scanning.

The current Codex validation shell has bundled Python available at `C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`; it reports Python `3.12.13` and pip `26.0.1`. No packages were installed into this checkout or machine-wide during this pass. PyPI JSON metadata for the pinned direct versions was queried over HTTPS on 2026-06-25. A disposable temp venv installed the direct requirements once, then `ml/requirements.lock.txt` was verified in a second disposable temp venv with `pip install --no-deps` plus import/version checks; both temp roots were removed.

| Package | Version | Purpose | License evidence | Verification status |
| --- | ---: | --- | --- | --- |
| `onnx` | `1.22.0` | Export/check ONNX development models from `ml/export_onnx.py`. | PyPI and installed wheel metadata report `License-Expression: Apache-2.0`; `requires_python >=3.10`. | Metadata verified; disposable Windows/Python 3.12 venv install/import smoke passed. |
| `numpy` | `2.2.6` | Build deterministic model tensors for export. | PyPI and installed wheel classifiers include `License :: OSI Approved :: BSD License`; metadata license field includes bundled-library notices. | Metadata verified; disposable Windows/Python 3.12 venv install/import smoke passed. SBOM/license review must inspect the exact release wheel because bundled notices can vary by platform. |
| `jsonschema` | `4.26.0` | Validate ML label/schema data. | PyPI and installed wheel metadata report `License-Expression: MIT`; `requires_python >=3.10`. | Metadata verified; disposable Windows/Python 3.12 venv install/import smoke passed. |

## Lockfile Coverage

Dependency lockfiles are release inputs. Existing lockfiles must be reviewed during SBOM generation; missing lockfiles must be generated by the package manager on a provisioned build host, not handwritten.

| Component | Manifest | Lockfile | Current status |
| --- | --- | --- | --- |
| Root Rust workspace | `Cargo.toml` | `Cargo.lock` | Present; Cargo-generated workspace lock contains 364 Cargo package entries and includes the update-service and shared platform-security workspace members. |
| Native engine | `core/zentor_native_engine/Cargo.toml` | `core/zentor_native_engine/Cargo.lock` | Present; source count check found 89 Cargo package entries. |
| Local core | `core/zentor_local_core/Cargo.toml` | `core/zentor_local_core/Cargo.lock` | Present; source count check found 188 Cargo package entries. |
| Guard service | `core/zentor_guard_service/Cargo.toml` | `core/zentor_guard_service/Cargo.lock` | Present; source count check found 102 Cargo package entries. |
| Update service | `core/avorax_update_service/Cargo.toml` | `Cargo.lock` | Present through the root Rust workspace lockfile; `cargo generate-lockfile --manifest-path core\avorax_update_service\Cargo.toml` updates the workspace `Cargo.lock` and does not create a package-local lockfile for this workspace member. |
| API service | `services/api/Cargo.toml` | `services/api/Cargo.lock` | Present; source count check found 266 Cargo package entries. |
| Flutter client | `apps/zentor_client/pubspec.yaml` | `apps/zentor_client/pubspec.lock` | Present; source count check found 96 Dart package entries. |
| Zentor protocol package | `packages/zentor_protocol/pubspec.yaml` | `packages/zentor_protocol/pubspec.lock` | Present; source count check found 48 Dart package entries. |
| Avorax protocol package | `packages/avorax_protocol/pubspec.yaml` | `packages/avorax_protocol/pubspec.lock` | Present; source count check found 47 Dart package entries. |
| Python ML tooling | `ml/requirements.txt` | `ml/requirements.lock.txt` | Present; direct requirements and transitive verification lock are exact-pinned, and disposable venv install/import smoke passed for Windows/Python 3.12. |
| Android Gradle plugins | `apps/zentor_client/android/settings.gradle.kts`, `apps/zentor_client/android/build.gradle.kts` | Gradle dependency lockfile | Plugin versions are pinned in source (`dev.flutter.flutter-plugin-loader` `1.0.0`, Android Gradle plugin `9.0.1`, Kotlin plugin `2.3.20`), and checkpoint 1555 enables Gradle dependency locking for all Android subprojects. No generated Gradle dependency lockfile is present yet; Android publishing is outside the Windows antivirus release path and must generate/review this lockfile on an Android-capable host before any Android release. |
| Android Gradle wrapper | `apps/zentor_client/android/gradle/wrapper/gradle-wrapper.properties` | Wrapper distribution hash | Wrapper distribution URL is pinned to Gradle `9.1.0-all`; `distributionSha256Sum` is pinned to `b84e04fa845fecba48551f425957641074fcc00a88a84d2aae5808743b35fc85` from the official Gradle distribution hash endpoint. |
| Archived legacy website | `archive/*_website_old/package.json` | `archive/*_website_old/package-lock.json` | Present but archived/private and outside Avorax runtime/release scope. If reactivated, it needs a separate npm install/audit/license pass. |

Checkpoint 2131 source-level lockfile summary counts from `.workflow/ultracode/avorax-hardening/results/2131-dependency-license-evidence.json`:

| Ecosystem | Lockfile | Package count | Integrity count | Integrity evidence |
| --- | --- | ---: | ---: | --- |
| Cargo | `Cargo.lock` | 364 | 358 | Cargo registry checksum entries. |
| Cargo | `core/zentor_native_engine/Cargo.lock` | 89 | 88 | Cargo registry checksum entries. |
| Cargo | `core/zentor_local_core/Cargo.lock` | 188 | 186 | Cargo registry checksum entries. |
| Cargo | `core/zentor_guard_service/Cargo.lock` | 102 | 100 | Cargo registry checksum entries. |
| Cargo | `services/api/Cargo.lock` | 266 | 265 | Cargo registry checksum entries. |
| pub | `apps/zentor_client/pubspec.lock` | 96 | 91 | pub.dev SHA-256 entries. |
| pub | `packages/zentor_protocol/pubspec.lock` | 48 | 48 | pub.dev SHA-256 entries. |
| pub | `packages/avorax_protocol/pubspec.lock` | 47 | 47 | pub.dev SHA-256 entries. |
| Python | `ml/requirements.lock.txt` | 10 | 10 | Exact version pins. |

## Rust Runtime Deflate Helper

Checkpoint 2064 adds direct `flate2 = "1.1"` use to Avorax Native Engine for bounded raw-deflate decoding of small OOXML `.rels` relationship bodies only. It is not a general archive extractor and must not extract files to disk. The root workspace `Cargo.lock` pins `flate2` `1.1.9`, `miniz_oxide` `0.8.9`, `crc32fast` `1.5.0`, and `adler2` `2.0.1`; dependency evidence passed after the manifest change.

License fields were checked from the locally cached crate manifests in `C:\Users\Brent\.cargo\registry\src`: `flate2` reports `MIT OR Apache-2.0`, `miniz_oxide` reports `MIT OR Zlib OR Apache-2.0`, `crc32fast` reports `MIT OR Apache-2.0`, and `adler2` reports `0BSD OR MIT OR Apache-2.0`. A release host still needs complete SBOM/license output from the final lockfile set before release-candidate tagging.

## Quarantine Authentication Dependencies

Checkpoint 2182 makes `hmac = "0.12"` and `getrandom = "0.3"` direct Local Core
and Guard dependencies. Both packages were already present transitively in the
root `Cargo.lock`; the manifest change makes the quarantine security contract
explicit without introducing a new lockfile package.

The lockfile pins `hmac` `0.12.1` and `getrandom` `0.3.4`. Locally cached crate
metadata reports `MIT OR Apache-2.0` for both. `hmac` provides the reviewed
RustCrypto HMAC construction over the existing SHA-256 implementation;
`getrandom` obtains the 32-byte metadata key from the operating-system random
source. Final-artifact SBOM generation and complete license/copyright review
remain production release requirements.

## Shared Platform Security Crate

Checkpoint 2184 adds the internal workspace crate
`core/avorax_platform_security`. Local Core and Guard both depend on it by local
path so Unix ownership/mode enforcement and Windows process-token/DACL
verification have one implementation. The crate adds no new registry package:
it uses existing workspace dependencies `anyhow`, `libc`, `windows-sys 0.61.2`,
and test-only `tempfile`. Their versions and checksums were already pinned in
`Cargo.lock` and remain subject to the existing final-artifact SBOM and
license-review gate.

Locked metadata verification reports `anyhow 1.0.103`, `libc 0.2.186`,
`windows-sys 0.61.2`, and `tempfile 3.27.0`; each declares
`MIT OR Apache-2.0`. This is source-manifest license evidence for reused
dependencies, not a substitute for final-binary copyright/notices review.

## GitHub Actions Supply Chain

All third-party workflow actions are pinned to exact 40-character commit SHAs.
The artifact and release actions use versions whose checked `action.yml` declares
the Node 24 runtime, avoiding GitHub's deprecated Node 20 compatibility forcing.
Release tags, commit SHAs, runtime declarations, and repository license metadata
were queried from the action publishers through the GitHub API on 2026-07-10.

| Action | Pinned release / commit | Runtime / license evidence |
| --- | --- | --- |
| `actions/checkout` | v5 / `93cb6efe18208431cddfb8368fd83d5badbf9bfd` | Exact existing desktop-package pin; MIT |
| `actions/setup-python` | v6 / `ece7cb06caefa5fff74198d8649806c4678c61a1` | Exact existing desktop-package pin; MIT |
| `actions/setup-dotnet` | v5.4.0 / `26b0ec14cb23fa6904739307f278c14f94c95bf1` | `action.yml` declares `node24`; MIT |
| `actions/upload-artifact` | v7.0.1 / `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | `action.yml` declares `node24`; MIT |
| `actions/download-artifact` | v8.0.1 / `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | `action.yml` declares `node24`; MIT |
| `dtolnay/rust-toolchain` | `fa04a1451ff1842e2626ccb99004d0195b455a88` | Exact existing desktop-package pin; MIT |
| `subosito/flutter-action` | v2 / `1a449444c387b1966244ae4d4f8c696479add0b2` | Exact existing desktop-package pin; MIT |
| `softprops/action-gh-release` | v3.0.1 / `718ea10b132b3b2eba29c1007bb80653f286566b` | `action.yml` declares `node24`; MIT |

`tests/test_packaging_tools.py` rejects mutable external action refs and requires
the reviewed commit pins above. It also requires every pinned Rust toolchain
action to receive the exact `1.96.1` toolchain (directly or through the reviewed
desktop-package environment), because a commit ref does not inherit the former
`@stable` ref name as an input. Local actions referenced through `./` remain
repository-owned workflow code and are excluded from that external-action rule.

## Current Blockers

- Cargo/rustfmt are available on this Windows validation host. `cargo generate-lockfile --manifest-path core\avorax_update_service\Cargo.toml` succeeded and updated the root workspace `Cargo.lock`; `cargo test --workspace --no-run` passed after lockfile refresh.
- Flutter/Dart are available on this Windows validation host. The Flutter client and both Dart protocol packages have current local format/analyze/test evidence in checkpoints 1546, 1548, and 1549.
- Android SDK/Gradle execution is not available in this validation shell; `flutter doctor -v` reports the Android SDK is missing. Release readiness still needs Gradle dependency-lock generation/review on an Android-capable build host, using the source-enabled dependency locking rather than a handwritten lockfile.
- npm is not installed or not on `PATH`; this is not a release blocker while the archived legacy website stays out of runtime scope.
- Python package metadata plus disposable Windows/Python 3.12 install/import smoke tests have passed, including a `--no-deps` install from `ml/requirements.lock.txt`. A release host still needs to regenerate/review the lock for the target Python/platform as needed and capture complete license/SBOM output.
- Cross-platform package CI now generates and checksums a CycloneDX 1.6 inventory from the current Rust, Dart, and Python lockfiles. Release-candidate approval still requires final-binary dependency resolution, complete license/copyright review, and Android Gradle lock evidence before any Android release.
- `tools/security/avorax-dependency-evidence.ps1` treats Android Gradle lock evidence as non-blocking for the Windows antivirus release path while still reporting its presence/absence. Root Rust and update-service workspace lock evidence are present through `Cargo.lock`.

## Native WinTrust Feature Surface

Checkpoint 2195 adds no registry package and does not change a dependency
version. Native Engine continues to use pinned `windows-sys 0.61.2`; its Windows
target feature set now exposes the existing Foundation, FileSystem,
Cryptography/Catalog/SIP, and WinTrust declarations needed for direct
handle-based Authenticode verification. Locally cached crate metadata records
`windows-sys` as `MIT OR Apache-2.0`.

Both lockfiles remained byte-unchanged and the complete dependency-evidence
gate passed during checkpoint 2195 local verification. Feature-level source
inventory is not a final binary SBOM, license notice set, or copyright review;
those remain release-host requirements.

## Native Catalog API Surface

Checkpoint 2196 adds no dependency, package, feature, or lockfile change. The
bounded catalog fallback uses the Catalog and WinTrust declarations already
enabled for pinned `windows-sys 0.61.2`, whose reviewed registry license remains
`MIT OR Apache-2.0`. It introduces no parser, network, certificate-store, or
shell dependency. Final-artifact SBOM, notices, and copyright review remain
release gates; a source-level unchanged-lock statement does not replace them.

Both lockfiles remained byte-unchanged in the checkpoint diff. The definitive
dependency-evidence step and the complete locked Rust workspace passed locally;
hosted package SBOM evidence passed on implementation head, evidence head, and
merged main with publication skipped.

## Native Secondary Signature API Surface

Checkpoint 2197 adds no dependency, package, Cargo feature, executable helper,
parser, network client, or lockfile change. It uses
`WINTRUST_SIGNATURE_SETTINGS`, `WSS_GET_SECONDARY_SIG_COUNT`, and
`WSS_VERIFY_SPECIFIC` from the WinTrust declarations already enabled through
pinned `windows-sys 0.61.2`. The reviewed registry license remains
`MIT OR Apache-2.0`.

Both lockfiles remain unchanged in the diff. Strict Native Clippy, both complete
locked workspace variants, the definitive dependency-evidence gate, and the
226-step local verifier passed. Exact implementation-head package push/PR runs
`32591426228`/`32591435262` passed lockfile SBOM generation and artifact
consolidation with publication skipped. Evidence-head and merged-main package
proof plus final release-artifact license/notice review remain pending; source
API reuse is not final-binary license or notice evidence.

## Native Authenticode Isolation API Surface

Checkpoint 2198 adds no package, registry dependency, network client, parser
crate, executable artifact, or dependency version. It extends the existing
pinned `windows-sys 0.61.2` feature surface with
`Win32_System_JobObjects` and `Win32_System_Threading` for Job lifetime control,
process termination, and bounded wait/poll behavior. The reviewed registry
license remains `MIT OR Apache-2.0`. Existing pinned `serde`, `serde_json`, and
`uuid` workspace dependencies provide strict protocol serialization and UUID-v4
nonce validation; no new lockfile entry is intended.

The isolation endpoint is compiled into existing Local Core and Guard binaries,
so it introduces no separately distributed helper that could drift from the
host package. This reduces artifact inventory but makes the exact current
executable and its installed ACLs part of the trusted boundary. The child uses
the parent's token; no sandbox or privilege-separation dependency is claimed.

Local lockfile stability, exact feature resolution, dependency/license gates,
strict lint, complete locked workspace variants, and the definitive `229/229`
verifier pass for checkpoint 2198. No dependency version or lockfile entry was
added. Implementation-head package runs `32597113497`/`32597124404` generate the
lockfile CycloneDX SBOM and checksum it with all six platform artifacts; both
pass with publication skipped. Evidence-head and merged-main package proof plus
final-artifact license, notice, and copyright review remain pending;
source-level reuse does not replace that review.

## Native Authenticode File Identity API Surface

Checkpoint 2199 adds no crate, package, registry dependency, network client,
executable artifact, or dependency version. It reuses the pinned
`windows-sys 0.61.2` `Win32_Storage_FileSystem` feature already present for
`GetFileInformationByHandle`, `GetFileInformationByHandleEx`,
`BY_HANDLE_FILE_INFORMATION`, `FILE_BASIC_INFO`, `FILE_STANDARD_INFO`, and
`FILE_ID_INFO`. No Cargo feature or lockfile entry is intended to change.

The standard library's stable Windows metadata surface does not expose volume/
file identity on stable Rust, so the existing pinned raw Win32 binding is used
instead of adding a parser or wrapper crate. All structures are fixed-size,
stack-allocated, queried only for an already open bounded regular non-reparse
handle, and compared without network or package-manager access.

Lockfile stability, exact API feature resolution, strict lint, both complete
locked workspace variants, and the dependency/license evidence gate pass
locally. No lockfile changed. Implementation-head package push/PR runs
`32601253745`/`32601266989` pass lockfile CycloneDX SBOM generation and
six-artifact checksum consolidation with publication skipped. Evidence-head
package run `32602128573` and merged-main package run `32602820702` also pass
with publication skipped.
Source-level API reuse remains distinct from final-binary license, notice, and
copyright review.

## Native Secondary Catalog Signature API Surface

Checkpoint 2200 adds no crate, package, registry dependency, Cargo feature,
network client, helper executable, or dependency version. It reuses
`WINTRUST_SIGNATURE_SETTINGS`, `WSS_GET_SECONDARY_SIG_COUNT`, and
`WSS_VERIFY_SPECIFIC` already exposed by pinned `windows-sys 0.61.2` for the
embedded-signature work. The catalog member continues to use existing WinTrust
and Catalog declarations. The reviewed registry license remains
`MIT OR Apache-2.0`.

Microsoft's structure documentation describes exact requested/verified indexes
and the returned secondary count; the existing catalog-member structure
documents the open member handle and calculated member hash. These API
contracts justify the implementation surface, but they do not replace runtime
provider evidence. Positive secondary-catalog acceptance is therefore marked
partial until a controlled benign multi-signed catalog fixture exists.

Both Cargo lockfiles remain byte-unchanged. Lockfile stability, strict Native/
Local/Guard Clippy, both complete locked workspace variants, dependency
evidence, package-builder source contracts, and the definitive `231/231`
verifier pass locally. No dependency version, feature, or lockfile entry was
added. Hosted package SBOM generation and final-artifact license, notice, and
copyright review remain distinct from local source checks. Implementation-head
package push/PR runs `32605424354`/`32605433783` pass lockfile CycloneDX SBOM
generation, six-artifact checksum consolidation, and package evidence upload
with publication skipped. Evidence-head package run `32606194213` and merged-
main package run `32606989456` also pass every platform and consolidation with
publication skipped.

## Authenticode Helper Job Resource API Surface

Checkpoint 2201 adds no crate, package, registry dependency, Cargo feature,
network client, helper executable, or dependency version. It reuses
`SetInformationJobObject`, `QueryInformationJobObject`, and extended Job-limit
constants already exposed by pinned `windows-sys 0.61.2` through the existing
`Win32_System_JobObjects` and `Win32_System_Threading` features. The reviewed
registry license remains `MIT OR Apache-2.0`; no lockfile change is intended.

Microsoft's Job structures distinguish committed-memory ceilings from working
set and user-mode CPU from elapsed or kernel time. The code therefore records
exact commit/user-CPU/process limits and retains the separate parent wall-clock
timeout rather than introducing a new wrapper dependency or broader claim.
I/O rate/byte control and restricted-token process creation are not added.

Source contracts `629/629`, strict Native/Local/Guard Clippy, both complete
locked workspace variants, dependency and package-source gates, release
Local Core/Guard builds, and the definitive `232/232` verifier pass locally.
Both Cargo lockfiles remain byte-unchanged. No dependency version, feature, or
lockfile entry was added. Exact implementation-head Desktop Packages push/PR
runs `32609010416`/`32609018053` pass lockfile CycloneDX SBOM generation,
six-artifact consolidation/checksums, and all platform package jobs with
publication skipped. Final-artifact license, notice, and copyright review
remains distinct from that generated lockfile evidence.

## Risk-Fusion PUP Token Boundary

Checkpoint 2202 adds no crate, package, registry dependency, Cargo feature,
network client, model, rule pack, or executable. The implementation uses Rust
standard-library `str::split` and ASCII-alphanumeric classification inside the
existing Native Engine risk-fusion module. No lockfile change is intended.

The change narrows one category keyword from arbitrary substring matching to a
bounded token. It does not alter evidence weights, verdict thresholds, action
policy, signature/rule content, or external data handling. Source contracts,
strict lint, complete locked workspaces, dependency gates, definitive verifier,
and final artifact review pass locally: source contracts `631/631`, both locked
workspace variants, strict Native/Local/Guard Clippy, dependency/package-source
gates, and definitive `232/232` validation pass. Both Cargo lockfiles remain
byte-unchanged. Hosted checkpoint-2202 package SBOM and final-artifact review
remain pending.

## Authenticode Restricted Thread Token API Surface

Checkpoint 2203 adds no crate, package, registry dependency, Cargo feature,
network client, helper executable, or dependency version. It reuses the pinned
`windows-sys 0.61.2` `Win32_Security` and `Win32_System_Threading` features
already required by the Native Engine. The reviewed registry license remains
`MIT OR Apache-2.0`; no lockfile change is intended.

The added API surface is limited to `OpenProcessToken`, `DuplicateTokenEx`,
`CreateRestrictedToken`, `SetThreadToken`, `OpenThreadToken`,
`GetTokenInformation`, `LookupPrivilegeValueW`, and `RevertToSelf`. Microsoft
documents `DISABLE_MAX_PRIVILEGE` as disabling every privilege except
`SeChangeNotifyPrivilege`; runtime code still reads back and bounds the actual
enabled privilege evidence instead of trusting the flag alone. No token-wrapper
or sandbox dependency is introduced.

Source contracts `632/632`, exact dependency resolution, unchanged Cargo and
Flutter lockfiles, strict Native/Local/Guard lint, both complete locked
workspaces, the dependency gate, and package-source contracts pass locally.
The definitive verifier passes `233/233`. Implementation-head package push/PR
runs `32616060448`/`32616072173` pass six-artifact consolidation, checksums,
lockfile SBOM generation, and package evidence on Windows, Linux, and macOS.
Evidence-head and merged-main final-artifact review remain pending;
source-level API reuse is not final-binary license, notice, or copyright
evidence.

## Authenticode Sanitized Launch API Surface

Checkpoint 2206 adds no crate, package, Cargo feature, or lockfile change. It
reuses pinned `windows-sys 0.61.2`, the existing
`CREATE_UNICODE_ENVIRONMENT` binding, and the existing Native Engine checked
Windows-root functions. The environment contains exactly `SystemRoot` and
`WINDIR`; no environment-building, sandbox, path, parser, IPC, registry, or
test dependency is introduced.

Microsoft documents that `CreateProcessAsUserW` inherits the caller environment
and current directory for null pointers and requires
`CREATE_UNICODE_ENVIRONMENT` for a Unicode block. Avorax constructs and owns the
bounded UTF-16 block and current-directory buffer until process creation
returns. Exact dependency resolution, unchanged locks, runtime compatibility,
strict lint, complete suites, dependency evidence, package SBOM, and central
236-step verification pass locally for checkpoint 2206; exact-head hosted and
merged-main package evidence remain pending.

Exact implementation head `80599a1` passes Desktop Packages push/PR runs
`32629820137`/`32629832031`. Both runs pass Windows x64 MSI/EXE, Linux x64
DEB/tar, macOS arm64/x64 DMG, consolidation, checksums, and lockfile SBOM
generation with publication skipped. Evidence-head and merged-main
final-artifact review remain pending; no dependency or lockfile changed.

## Authenticode Process Mitigation API Surface

Checkpoint 2207 adds no crate, package, Cargo feature, or lockfile change. It
reuses pinned `windows-sys 0.61.2` Threading bindings for
`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`, `UpdateProcThreadAttribute`,
`GetProcessMitigationPolicy`, and the signature/dynamic-code/extension-point/
image-load/strict-handle policy selectors. The reviewed crate license remains
`MIT OR Apache-2.0`.

`windows-sys 0.61.2` does not generate the documented process-creation
mitigation bit constants, so the Native Engine defines only the seven reviewed
Microsoft values locally: strict handle checks, extension-point disable,
dynamic-code prohibition, Microsoft-signed-only loading, no remote images, no
low-label images, and System32 preference. Pure exact-word/source contracts and
real child read-back pass locally. No dynamic loader, mitigation crate,
sandbox library, registry dependency, network client, or helper executable is
added. Both lockfiles are unchanged; strict lint, locked release hosts and
workspaces, source contracts `636/636`, and exact `237/237` verification pass.
Hosted package/SBOM evidence remains pending for checkpoint 2207.

## Checkpoint 2208 Low-Integrity Token API Reuse

Checkpoint 2208 adds no crate, package, Cargo feature, or lockfile change. It
reuses pinned `windows-sys 0.61.2` bindings already enabled through
`Win32_Security` and `Win32_System_SystemServices`: `SetTokenInformation`,
`TokenIntegrityLevel`, `TOKEN_MANDATORY_LABEL`, `TOKEN_ADJUST_DEFAULT`,
`CreateWellKnownSid`, `WinLowLabelSid`, `SE_GROUP_INTEGRITY`, and
`SE_GROUP_INTEGRITY_ENABLED`. The reviewed crate license remains
`MIT OR Apache-2.0`.

These APIs implement and read back Windows Mandatory Integrity Control on an
existing restricted token. They add no helper binary, parser, network client,
registry component, build script, transitive package, notice, or license. This
source-level reuse does not replace hosted package lockfile-SBOM evidence or
final production artifact license review. The pre-execution design claimed no
checkpoint-2208 package or SBOM success before its exact-head hosted runs.

Local dependency evidence now passes without a Cargo or Flutter lockfile
change: rustfmt, strict Native/Local Core/Guard Clippy, both locked workspace
test variants, locked Local Core/Guard release builds, release Authenticode
smoke, Flutter analyze and `838/838`, source contracts `637/637`, and the
definitive verifier/validators `238/238` in `429.7s`. At local-batch completion,
hosted package/SBOM output and final-artifact license/notice review remained
pending; this local API-reuse proof does not substitute for them.

Exact implementation head `c7ff9b7` passes package push/PR runs
`32638895902`/`32638907670`. Both runs pass package contracts, Windows x64
MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG, six-artifact consolidation,
checksums, and lockfile SBOM generation with publication skipped.
Evidence-head and merged-main final-artifact review remain pending; no
dependency or lockfile changed.

Final review strengthened the existing four-byte strict-handle policy
read-back to require both invalid-handle exception and permanent-enforcement
flags. This adds no API, feature, dependency, package, or lockfile change; the
amended local verification and exact `237/237` rerun pass. Exact implementation
head `a9d930a` passes package push/PR runs `32634021590`/`32634032975` with
Windows MSI/EXE, Linux DEB/tar, both macOS DMGs, six-artifact consolidation,
checksums, and lockfile SBOM. Publication was skipped; evidence-head and
merged-main package evidence remain pending.

## Authenticode Restricted Process Token API Surface

Checkpoint 2204 adds no crate, package, registry dependency, network client,
helper executable, or dependency version. It adds only the
`Win32_System_Pipes` feature to the existing pinned `windows-sys 0.61.2`
dependency so the Native Engine can call `CreatePipe`. The reviewed crate
license remains `MIT OR Apache-2.0`; no lockfile change is intended.

The process boundary also uses existing `Win32_Security`,
`Win32_System_Threading`, and `Win32_System_JobObjects` APIs:
`CreateRestrictedToken`, `CreateProcessAsUserW`,
`InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute` with
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, `DeleteProcThreadAttributeList`,
`ResumeThread`, `TerminateProcess`, and bounded wait/exit-code calls. No shell,
PATH lookup, network process, token helper, or third-party IPC dependency is
introduced.

The restricted primary token behavior is implemented entirely through those
pinned Windows bindings; it does not introduce a token, sandbox, or IPC crate.

Exact dependency resolution, unchanged Cargo/Flutter lockfiles, strict lint,
complete locked workspaces, release host builds/smoke, source contracts, the
dependency gate, and central `234/234` verifier are locally verified.
Implementation-head package push/PR runs `32620187506`/`32620196066` pass
six-artifact consolidation, checksums, lockfile SBOM generation, and package
evidence on Windows, Linux, and macOS. Evidence-head packages `32620868963` and
merged-main packages `32621422056` pass the same final-artifact review with
publication skipped; source-level API reuse is not final-binary license,
notice, or copyright evidence.

## Authenticode Write-Restricted Token API Surface

Checkpoint 2205 adds no crate, package, registry dependency, network client,
helper executable, or dependency version. It adds only the `Win32_System_SystemServices` feature to pinned `windows-sys 0.61.2` so the
Native Engine uses the generated `SE_GROUP_MANDATORY`,
`SE_GROUP_ENABLED_BY_DEFAULT`, and `SE_GROUP_ENABLED` constants instead of
local numeric copies. The reviewed crate license remains `MIT OR Apache-2.0`;
no Cargo or Flutter lockfile change is intended.

The additional API/constants are `CreateWellKnownSid`, `WinRestrictedCodeSid`,
`WRITE_RESTRICTED`, `TokenRestrictedSids`, `IsValidSid`, `GetLengthSid`,
`SECURITY_MAX_SID_SIZE`, `TOKEN_GROUPS`, and `SID_AND_ATTRIBUTES`. They create
one well-known restricting SID and read back bounded native token evidence. No
SID, token, sandbox, parser, IPC, or test dependency is introduced.

The implementation relies on Microsoft's documented `WRITE_RESTRICTED`
semantics: restricting SIDs participate only in write-access evaluation. The
flag is applied to the `SecurityImpersonation` token used before stdin/request
parsing, not the primary process token: the primary-token prototype stopped in
the Windows loader with `0xC0000142`. It covers request parsing/read-only
candidate preparation and is reapplied for response output. WinTrust/catalog
run under the privilege-stripped primary token because the Windows trust stack
returned error `127` while write restriction remained active. Local
focused checks, strict Native/Local/Guard Clippy, both locked workspace
variants, dependency evidence, locked release builds, two-host smoke, and the
exact `235/235` definitive verifier pass without a lockfile change.
Implementation-head package push/PR runs `32624842967`/`32624862058` pass
six-artifact consolidation, checksums, lockfile SBOM generation, and package
evidence on Windows, Linux, and macOS with publication skipped. Evidence head
`ffda3a6` and merged-main packages `32626673323` pass the same final-artifact
review; source-level API reuse is not final-binary license, notice, or
copyright evidence.

## Authenticode Mandatory Policy API Surface

Checkpoint 2209 adds no crate, package, Cargo feature, helper executable,
network client, dependency version, or lockfile change. It reuses
`TokenMandatoryPolicy`, `TOKEN_MANDATORY_POLICY`,
`TOKEN_MANDATORY_POLICY_NO_WRITE_UP`,
`TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN`, and
`TOKEN_MANDATORY_POLICY_VALID_MASK` from the existing pinned
`windows-sys 0.61.2` `Win32_Security` feature. The reviewed crate license
remains `MIT OR Apache-2.0`.

Fixed-size `GetTokenInformation(TokenMandatoryPolicy)` runs inside the existing
native helper token boundary. The initial unprivileged
`SetTokenInformation(TokenMandatoryPolicy)` attempt failed with error 1314 and
is not retained. No parser, sandbox, policy, IPC, test, registry, shell, or
service dependency is introduced. Both locked workspace variants, strict
Native/Local/Guard lint, dependency/source gates, locked release builds,
source contracts `639/639`, and the definitive `239/239` verifier pass locally.
Cargo and Flutter lockfiles remain byte-unchanged. Hosted package and final-
artifact license evidence remain pending; local API reuse is not that evidence.

The Defender-safe verifier-binary remediation adds no dependency, feature, or
lockfile change. It uses `std::sync::OnceLock`, a fixed 68-byte XOR-encoded
array, and the existing Native signature API. Local Core removes its duplicate
standard EICAR literal and reuses the Native matcher; no codec, parser, package,
network, scanner, or license surface is added.

The no-malware-binaries gate and complete verifier pass after this change. The
Python source contract runtime-joins marker fragments so an ordinary bytecode
cache does not reintroduce the contiguous marker. This adds no Python package
or lockfile entry.

Exact implementation head `7034957` passes Desktop Packages push/PR runs
`32645042925`/`32645055436`. Both runs generate and upload the lockfile
CycloneDX SBOM with all six native package artifacts and checksums; no release
publication job was triggered. Evidence-head, merged-main, and final-artifact
license/notice review remain separate requirements.

Evidence head `7fd8734` passes package run `32646010931`; merge `d07220c`
passes merged-main package run `32646774820`. Both require all six artifacts,
checksums, lockfile CycloneDX SBOM, and evidence upload; beta publication is
skipped. Original-tree synchronization and destination locked tests preserve
the unchanged Cargo/Flutter lockfiles. Complete final-artifact license, notice,
copyright, and binary-resolution review remains a release-host requirement.

## Authenticode Token Virtualization/UIAccess API Surface

Checkpoint 2210 adds no crate, package, Cargo feature, or lockfile change. It
reuses `TokenVirtualizationAllowed`, `TokenVirtualizationEnabled`,
`TokenUIAccess`, and fixed-size `GetTokenInformation` from the already enabled
`Win32_Security` surface in pinned `windows-sys 0.61.2`. The reviewed crate
license remains `MIT OR Apache-2.0`.

No token setter, sandbox crate, UI automation package, parser, helper binary,
service, registry dependency, network client, or test dependency is introduced.
The central verifier gains one Rust test invocation and the Python source suite
gains one contract only. Cargo and Flutter lockfiles are intended to remain
byte-identical.

Local formatting, focused Windows execution, both locked workspaces, strict
Native/Local/Guard lint, release builds/two-host trust smoke, source contracts
`640/640`, dependency/no-malware gates, Flutter `838/838`, and exact `240/240`
verification pass. Cargo and Flutter lockfiles are unchanged. Exact-head hosted
CI `32649764260` and package push/PR `32649749634`/`32649764310` pass at
implementation `c744fa9`; both package runs require all six artifacts, checksums,
lockfile SBOM, dependency/license evidence, and evidence upload, with publication
skipped. Evidence-head/merged-main package evidence and complete final-artifact
license/notice review remain pending; source-level API reuse is not final-binary
license, notice, or copyright evidence.

Evidence head `8228daf` passes CI `32650692083` and packages `32650692145`;
merge `425e663` passes exact merged-main CI `32651609367` and packages
`32651609388`. All six artifacts, dependency/license evidence, checksums,
lockfile SBOM, and administrative MSI extraction pass, with publication
skipped. Destination Cargo and Flutter lockfiles match the merge exactly.
Complete final-artifact license, notice, and copyright review remains a
release-host requirement.

## Authenticode Job UI-Restriction API Surface

Checkpoint 2211 adds no crate, package, Cargo feature, or lockfile change. It
reuses `JobObjectBasicUIRestrictions`, `JOBOBJECT_BASIC_UI_RESTRICTIONS`,
`SetInformationJobObject`, `QueryInformationJobObject`,
`JOB_OBJECT_UILIMIT_HANDLES`, `JOB_OBJECT_UILIMIT_READCLIPBOARD`,
`JOB_OBJECT_UILIMIT_WRITECLIPBOARD`, `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS`,
`JOB_OBJECT_UILIMIT_DISPLAYSETTINGS`, `JOB_OBJECT_UILIMIT_GLOBALATOMS`,
`JOB_OBJECT_UILIMIT_DESKTOP`, and `JOB_OBJECT_UILIMIT_EXITWINDOWS` from the
already enabled `Win32_System_JobObjects` surface in pinned
`windows-sys 0.61.2` (`MIT OR Apache-2.0`).

No sandbox crate, UI automation package, parser, helper binary, service,
registry dependency, network client, or test dependency is introduced. The
verifier adds one Rust filter and the source-contract suite adds one contract.
Cargo and Flutter lockfiles remain byte-identical. Final signed-artifact notice
review remains pending. Job UI limits are not a private desktop or window
station and do not change identity or ordinary filesystem/registry/network read
access.

Local focused/complete Native checks, both locked workspaces, strict
Native/Local/Guard lint, release Local Core/Guard builds and trust smoke,
Flutter `838/838`, source contracts `641/641`, no-malware/dependency gates, and
exact `241/241` verification pass. Cargo and Flutter lockfiles remain exact.
Complete final signed-artifact license, notice, and copyright review remains
pending.

Exact implementation head `024d63fb4268a2a1a8094b1cc61c0ddbe4335ff4`
passes Desktop Packages push run `32655130037` and pull-request run
`32655155628`. Both verify package contracts, pinned dependency/license
evidence, Windows MSI/setup EXE, Linux DEB/tar, macOS x64/arm64 DMGs,
administrative MSI extraction without installation, six-artifact checksums,
lockfile SBOM, and artifact upload. The prerelease publication job is skipped in
both runs. Final signed-artifact license, notice, and copyright review remains a
release approval requirement.

Evidence head `9378955` passes CI `32655933103` and packages `32655933112`;
merge `33cafa5` passes merged-main CI `32656681010` and packages `32656681007`.
All six artifacts, dependency/license evidence, checksums, lockfile SBOM, and
administrative MSI extraction pass, with publication skipped. Destination Cargo
and Flutter lockfiles match the merge exactly. Complete signed final-artifact
license, notice, and copyright review remains a release approval requirement.

## Checkpoint 2212 Windows Desktop API Feature Review

Checkpoint 2212 adds no package and changes no version. The existing pinned
`windows-sys 0.61.2` dependency enables `Win32_Graphics_Gdi` and
`Win32_System_StationsAndDesktops` so Native Engine can call `CreateDesktopW`,
`CloseDesktop`, `GetUserObjectInformationW`, `GetThreadDesktop`, and related
constants. These are feature-gated bindings to Windows system APIs in the current
process window station; no native DLL, runtime, machine-wide component, network
content, or executable fixture is added. Cargo lockfile identity should remain
unchanged and will be verified after scripting.

`CloseDesktop` success is explicitly checked after confirmed helper exit; the RAII
drop path is retained only as failure-path best effort. This changes no dependency
or license conclusion.

Desktop creation temporarily uses existing `Win32_Security`/thread-token bindings to
duplicate and read back a low-integrity `SecurityImpersonation` token from the exact
child primary token and then require `RevertToSelf`. This adds no dependency. The
first medium-integrity-created desktop failed the benign child at `0xC0000142`; the
repair does not add a permissive DACL or fallback desktop.

The boundary retains the station security descriptor and station-wide
clipboard/global atoms. It does not change identity/profile/registry/filesystem or
network read access, and per-helper desktop heap consumption remains an operational
limit. Existing MIT/Apache-2.0 `windows-sys` licensing remains recorded; final signed
artifact notices and license review remain a release prerequisite.

Local dependency and no-malware gates, strict Native/Local Core/Guard lint, locked
release builds, both trust smokes, both locked workspaces, Flutter `838/838`, source
contracts `642/642`, and definitive `242/242` verification pass. No package version
or lockfile entry changed. Cargo and Flutter lockfiles remain exact at Git blobs
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d` and
`51fa085a41168aa1deadace8b5395614db43649e`. Hosted package/SBOM evidence and
complete final-artifact license, notice, and copyright review remain pending.

Exact implementation head `2612b7af77700a47558a638b017f3b5dac9fd0ce`
passes Desktop Packages push/PR runs `32660604610`/`32660616617`. Both runs pass
dependency/license evidence, all six native artifacts, Windows administrative MSI
extraction without installation, checksums, lockfile CycloneDX SBOM, and artifact
upload. Prerelease publication is skipped. Evidence-head/merged-main package
evidence and complete signed final-artifact review remain pending.

## Checkpoint 2213 Windows Console/Pipe API Feature Review

Checkpoint 2213 adds no crate, package, or lockfile change. It enables only the
`Win32_System_Console` feature on the existing pinned `windows-sys 0.61.2`
dependency so Native Engine can call `GetStdHandle` and use the documented
`STD_INPUT_HANDLE`, `STD_OUTPUT_HANDLE`, and `STD_ERROR_HANDLE` selectors. Existing
Foundation, FileSystem, and Pipes features provide `GetHandleInformation`,
`GetFileType`, `FILE_TYPE_PIPE`, `GetNamedPipeInfo`, `PIPE_SERVER_END`, and
`HANDLE_FLAG_INHERIT`.

These are feature-gated bindings to Windows system APIs. No native DLL, runtime,
network content, machine-wide component, executable fixture, or new license is
introduced. Existing MIT/Apache-2.0 `windows-sys` licensing remains recorded.
The dependency set and lockfile entries remain unchanged in the checkpoint diff.
Root Cargo, Native Cargo, and Git-filtered Flutter lockfiles remain exact at blobs
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`.

The feature proves exact parent/child API return-role binding, queries server/read
endpoint mode where Windows permits it, verifies startup-to-`GetStdHandle` identity,
and clears inheritance. It does not turn anonymous pipes
or the nonce into cross-identity authentication or encryption, prevent same-user
handle duplication, or isolate the named-kernel-object namespace. Final signed-
artifact notices and complete license/copyright review remain release prerequisites.

Strict Native/Local Core/Guard lint, locked release Local Core/Guard builds, both
release-host trust smokes, both locked workspaces, source contracts `643/643`,
Flutter analyze and `838/838`, and no-malware pass. The first strict Clippy run
rejected a field-reassigned default initializer; the corrected complete initializer
passes. Dependency evidence and the definitive `243/243` verifier/validator pass;
five malformed report copies are rejected.

Exact implementation head `f0f4c3b82dcb30b6851b26db7a88ab2b6e9a4af8`
passes Desktop Packages push/PR runs `32665646920`/`32665658257`. Both pass all
six native artifacts, Windows administrative MSI extraction without installation,
checksums, a 569-component lockfile CycloneDX SBOM, dependency/license evidence,
and artifact upload. Prerelease publication is skipped. Evidence-head/merged-main
package evidence and complete signed final-artifact license, notice, and copyright
review remain pending.

## Checkpoint 2214 Windows Job Membership API Review

Checkpoint 2214 adds no crate, package, feature, or lockfile change. Existing
`windows-sys 0.61.2` features `Win32_System_JobObjects` and
`Win32_System_Threading` already expose `IsProcessInJob`,
`QueryInformationJobObject`, `JobObjectBasicProcessIdList`,
`JOBOBJECT_BASIC_PROCESS_ID_LIST`, `GetProcessId`, and `GetCurrentProcessId`.
These are bindings to Windows `Kernel32.dll`; no DLL, runtime, machine-wide
component, network content, or executable candidate fixture is added.

Microsoft documents that a non-null Job handle makes `IsProcessInJob` test that
specific Job, while a null Job handle tests membership in any Job. It also documents
the variable process-ID list and count semantics. The implementation uses the
existing active-process limit of one, a one-entry structure, exact returned byte
count, and exact PID/handle identity before resuming the suspended child.

This evidence is point-in-time. The child null-Job query cannot identify the unnamed
parent Job and neither `IsProcessInJob` nor `JOBOBJECT_BASIC_PROCESS_ID_LIST`
authenticates IPC or changes process identity. Existing MIT/Apache-2.0
`windows-sys` licensing is unchanged. Complete signed final-artifact notice,
license, and copyright review remains a release prerequisite.

No checkpoint-2214 package, crate, feature, or lockfile change was required. In the
later execution phase, locked standard/all-feature workspaces, strict Native/Local
Core/Guard lint, locked release Local Core/Guard builds, the two-host trust smoke,
no-malware and dependency-evidence gates, source contracts `644/644`, and exact
root Cargo, Native Cargo, and Git-filtered Flutter lockfile blobs pass. The
definitive verifier passes `244/244` in `464.3s`. Exact implementation `6c3bad3`
passes package push/PR runs `32670175754`/`32670186350`, including dependency and
license evidence, six native artifacts, checksums, lockfile SBOM, and Windows
administrative MSI extraction without installation. Publication is skipped.
Evidence head `3014c44` and merged main `cbf6203` subsequently pass CI/package
runs `32671137010`/`32671137068` and `32672025315`/`32672025303`. Destination
dependency evidence reports `ok=true` and `partial=false`; exact lockfile blobs are
unchanged. This closes checkpoint integration, not the complete signed final-
artifact license, notice, copyright, or binary-resolution release prerequisite.
Complete signed final-artifact license, notice, copyright, and binary-resolution
review remains pending. No passing result is claimed from source presence alone.

## Checkpoint 2215 Windows Pipe Process-ID API Review

Checkpoint 2215 adds no crate, package, feature, or lockfile change. Existing
`windows-sys 0.61.2` feature `Win32_System_Pipes` already exposes
`GetNamedPipeClientProcessId` and `GetNamedPipeServerProcessId`, while the existing
`Win32_System_Threading` feature exposes `GetCurrentProcessId`. These are bindings
to Windows `Kernel32.dll`; no DLL, runtime, machine-wide component, network
content, executable candidate fixture, or dependency is added.

The API roles match the existing `CreatePipe` contract: child stdin inherits the
server/read endpoint and therefore queries its client creator; child stdout and
stderr inherit client/write endpoints and query their server creator. Because both
anonymous-pipe endpoints are created and connected in the parent before inheritance,
the evidence identifies that parent creator. It does not identify the inheriting
child back to the parent, prevent same-user handle duplication, or provide secret,
encrypted, durable, or cross-identity IPC.

Focused runtime, complete Authenticode, strict lint, release builds/two-host smoke,
both locked workspace variants, Flutter, no-malware, and dependency evidence pass.
Source contracts pass `645/645`, definitive verification passes `245/245`, and
the exact root Cargo, Native Cargo, and Git-filtered Flutter lockfile blobs remain
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. No checkpoint-2215 passing result is
claimed before execution; these results come from the later execution phase.
Exact implementation `cf9055b` passes Desktop Packages push/PR runs
`32675035927`/`32675048000`. Each run verifies dependency/license evidence,
requires all six native artifacts, creates checksums and the lockfile SBOM, and
uploads five unexpired artifact bundles bound to the exact SHA. Publication is
skipped. Complete signed final-artifact license/notice and binary-resolution
review remains pending.

Evidence head `79e865c` and merged main `c298c3a` pass Desktop Packages runs
`32675987151` and `32676733940`. Each requires six native artifacts, dependency/
license evidence, checksums, lockfile SBOM, administrative MSI extraction, and
five exact-SHA artifact bundles; publication is skipped. Destination root Cargo,
Native Cargo, and Git-filtered Flutter lock blobs remain exactly
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Complete signed final-artifact
license/notice and binary-resolution review remains pending.
## Checkpoint 2216 dependency delta

The Authenticode parent-child handshake adds two `windows-sys` feature gates but
no new crate or package: `Win32_Security_Authorization` supplies bounded Windows
security-descriptor/SID conversion and `Win32_System_IO` supplies overlapped I/O
cancellation/completion APIs. The repository remains on pinned `windows-sys
0.61.2`; its existing MIT OR Apache-2.0 license classification is unchanged.
No network dependency, executable payload, machine-wide component, or lockfile
version update is introduced. Runtime and exact-lock evidence now pass: source
contracts `646/646`, verifier/validator `246/246`, both locked workspace variants,
and exact lock hashes `7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`.

Exact implementation `472b478c10dad6683ea867616f21c3636fe446de`
passes Avorax CI `32680555167` and Desktop Packages push/PR
`32680536082`/`32680555166`. Both package events pass dependency/license
evidence, all six native artifacts, checksums, lockfile SBOM, and administrative
MSI extraction without installation; prerelease publication is skipped.

The parent-child handshake is same-user process binding, not encrypted
cross-identity IPC, AppContainer, installed LocalSystem, driver, or pre-execution
evidence. `GetNamedPipeClientProcessId` and `GetNamedPipeServerProcessId` are used
only as live process-binding evidence and do not expand publisher trust.

Integration evidence `b1c5b4e`, PR `#68`, merge `e883c187`, merged-main CI
`32682998536`, and packages `32682998541` pass. The package matrix again verifies
all six native artifacts, dependency/license evidence, checksums, lockfile SBOM,
and administrative MSI extraction with publication skipped. Exact 13-path
destination synchronization, both locked workspace variants, destination verifier
`246/246`, and unchanged lock hashes pass. No dependency, package, or license
classification changed; complete signed final-artifact notice and binary-resolution
review remains a release-host requirement.

## Checkpoint 2217 dependency delta

Checkpoint 2217 adds no crate, package, feature, or lockfile change. Existing
pinned `windows-sys 0.61.2` feature `Win32_Security_Authorization` already supplies
`GetSecurityInfo`, `SE_KERNEL_OBJECT`, and security-descriptor conversion; existing
`Win32_Security` supplies `DACL_SECURITY_INFORMATION`,
`LABEL_SECURITY_INFORMATION`, `GetSecurityDescriptorControl`, and
`SE_DACL_PROTECTED`. Existing MIT OR Apache-2.0 licensing is unchanged.

The runtime query uses existing named-pipe `READ_CONTROL` and intentionally avoids
the full SACL, `ACCESS_SYSTEM_SECURITY`, `SeSecurityPrivilege`, network content,
new DLLs, executable candidate fixtures, machine-wide components, and privilege
expansion. This point-in-time ACL/MIC read-back is not encrypted cross-identity
IPC, AppContainer/LPAC, installed LocalSystem, production signing, a driver, or
pre-execution protection. Dependency evidence, strict locked workspaces, and the
complete local verifier pass. Root Cargo, Native Cargo, and Flutter lock hashes
remain `7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Exact implementation package runs
`32687664061` and `32687717444` pass dependency/license evidence and consolidation;
the downloaded push artifact has a CycloneDX 1.6 lockfile SBOM with `569`
components and all seven checksum rows match. Publication is skipped.

Evidence `5fe8dd2`, PR `#69`, merge `3fe2b87`, evidence-head package run
`32689308533`, and merged-main package run `32690610424` complete checkpoint-
2217 integration without changing any dependency or lockfile. Exact 12-path
destination synchronization and the destination dependency gate pass; the three
recorded lock blobs remain unchanged. Complete signed final-artifact notice and
binary-resolution review remains a production-release requirement.

## Checkpoint 2218 dependency delta

Checkpoint 2218 adds no crate, package, feature, or lockfile change. The existing
pinned `windows-sys 0.61.2` `Win32_Storage_FileSystem` feature supplies
`READ_CONTROL` and `GENERIC_WRITE`/`CreateFileW`; existing `Win32_Security` and
`Win32_Security_Authorization` features supply current process-token SID and
bounded `GetSecurityInfo` DACL/mandatory-label read-back. Existing MIT OR
Apache-2.0 licensing is unchanged.

The child requests no `WRITE_DAC`, `WRITE_OWNER`, full-SACL access,
`ACCESS_SYSTEM_SECURITY`, or `SeSecurityPrivilege`. It adds no network content,
DLL, executable candidate fixture, machine-wide component, AppContainer,
installed LocalSystem, driver, or pre-execution behavior. Source dependency
evidence and both locked workspace variants pass. Root Cargo, Native Cargo, and
filtered Flutter lock blobs remain `7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Evidence `eb11c81`, PR `#70`, merge
`1e453005`, evidence/merged-main CI and Desktop Packages, exact 12-path
destination synchronization, destination dependency gates, and the same exact
lock blobs close checkpoint 2218 without a dependency or license delta.
Complete signed final-artifact notice and binary-resolution review remains a
production-release requirement.

## Checkpoint 2219 dependency delta

Checkpoint 2219 adds no crate, package, feature, or lockfile change. The existing
pinned `windows-sys 0.61.2` features already supply `GENERIC_READ`,
`GENERIC_WRITE`, `FILE_GENERIC_*`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, SDDL
conversion, `GetSecurityInfo`, and `MapGenericMask`. Existing MIT OR Apache-2.0
licensing is unchanged.

The protected handshake DACL keeps SYSTEM normalized full control and reduces
the current-user ACE to normalized generic read plus generic write. Exact
point-in-time endpoint read-backs reject broader or narrower masks. The creator's
token default owner is not independently read back; if the current user owns the
pipe, Windows supplies implicit `READ_CONTROL` and `WRITE_DAC`. This is not
encrypted/authenticated cross-identity IPC, AppContainer/LPAC, installed
LocalSystem, driver enforcement, or pre-execution protection. No new network
content, executable fixture, machine-wide component, or license obligation is
introduced. Runtime, lock, hosted, and destination evidence remain pending until
the scripted batch is executed.

Local dependency and license evidence now passes, as do source contracts
`649/649`, both locked workspaces, strict lint, exact verifier/validator
`249/249`, and unchanged root Cargo, Native Cargo, and Flutter lock blobs. No
dependency or license classification changed. Exact implementation `5171fb4e`
passes package push/PR `32702466511`/`32702550182`: all six native package
artifacts, seven independently rechecked checksum rows, dependency/license
evidence, administrative MSI extraction, and a CycloneDX 1.6 lockfile SBOM with
`569` components pass. Publication is skipped. Evidence-head, merge, and
destination evidence remain pending; complete signed final-artifact notice and
binary-resolution review remains a production-release requirement.

Evidence `be122479`, PR `#71`, merge `e6caf818`, evidence-head package run
`32704723183`, and merged-main package run `32706023644` complete checkpoint
2219 integration without changing a dependency or lockfile. Exact 12-path
destination synchronization and destination dependency evidence pass; root
Cargo, Native Cargo, and Flutter lock blobs remain unchanged. Complete signed
final-artifact notice and binary-resolution review remains a production-release
requirement.

## Checkpoint 2220 dependency delta

Checkpoint 2220 adds no crate, package, feature, or lockfile change. Existing
`windows-sys 0.61.2` features supply `OWNER_SECURITY_INFORMATION`, SDDL `OW`,
SID validation/string conversion, `CreateNamedPipeW`, `CreateFileW`,
`READ_CONTROL`, `WRITE_DAC`, and `ERROR_ACCESS_DENIED`; existing MIT OR
Apache-2.0 licensing is unchanged.

The descriptor sets and reads back the current process-token owner and adds
Owner Rights `S-1-3-4` with only `READ_CONTROL`. Runtime evidence is deliberately
pending until the complete scripting batch is closed. This point-in-time
same-user control is not encrypted cross-identity IPC, AppContainer/LPAC,
installed LocalSystem, production signing, driver enforcement, or pre-execution
protection. No network content, executable fixture, machine-wide component,
privilege enablement, or new license obligation is introduced.

Corrected source contracts `650/650`, both locked workspace variants,
locked/offline Native all-target checking, strict Native/Local Core/Guard lint,
release Local Core/Guard builds, benign two-host trust smoke, and Flutter
`838/838` pass without a dependency or lockfile edit. Exact lock hashes and the
dependency evidence gate remain to be rechecked with the definitive verifier;
hosted and integration evidence remain pending.

The definitive dependency gate and full verifier now pass exact `250/250` in
`452.7s`; nine malformed reports are rejected. Root Cargo, Native Cargo, and
Flutter lock blobs remain exactly `7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. No dependency or license
classification changed. Hosted and integration evidence remain pending.

Exact implementation SHA `6f90f9234375ceb22107aba426401e38838ec9b8`
passes Desktop Packages push/PR runs `32712856310`/`32712875850`. Both runs
build all six native artifacts and pass dependency/license evidence,
administrative MSI extraction without installation, consolidation, checksums,
and lockfile SBOM generation; prerelease publication is skipped. Independent
inspection of the push artifact recomputed all seven SHA-256 rows and confirmed
CycloneDX 1.6 with 569 components. No dependency or lockfile changed.
Evidence-head/merged-main package proof and complete signed final-artifact
license, notice, copyright, and binary-resolution review remain pending.

Evidence head `a99b03a` passes package run `32715458329`; merged main
`2bd8956` passes package run `32716511838`. Both require all six native
artifacts, dependency/license evidence, checksums, a 569-component CycloneDX
1.6 lockfile SBOM, and consolidation, while publication is skipped. Guarded
destination sync and full destination verification preserve all three exact
lock blobs. This closes checkpoint package integration only; complete signed
final-artifact license, notice, copyright, and binary-resolution review remains
a production-release prerequisite.

## Checkpoint 2221 - Named-pipe client-token binding

The `ImpersonateNamedPipeClient`, exact `SecurityImpersonation` token
readback, and fail-visible `RevertToSelf` path use the already pinned
`windows-sys` Win32 Pipes, Security, Threading, and FileSystem features. This
adds no crate, package, feature, or lockfile change. Source contracts `651/651`
and the exact `251/251` verifier plus embedded/standalone strict validators pass.
The control remains same-user and does not provide
cross-identity IPC, AppContainer/LPAC, signing, driver, or pre-execution proof;
complete signed final-artifact license and notice review remains blocked on a
production release host.

Focused and full local execution preserves exact root Cargo, Native Cargo, and
Flutter lock blobs `7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Locked/offline Native check, both
locked root workspaces, strict Rust lint, Flutter analyze, and Flutter `838/838`
pass. Flutter reported 33 newer versions outside current constraints but no
upgrade or lock change occurred. Definitive local verification passes in
`487.9s`. Exact implementation-head package push/PR runs contain matching
CycloneDX 1.6 lockfile SBOMs with 569 components and seven verified SHA-256
rows. Publication is skipped; complete signed final-artifact license review
remains pending.

Evidence-head and merged-main package workflows also pass with publication
skipped. The merged-main consolidated bundle retains seven matching SHA-256
rows and the CycloneDX 1.6/569-component lockfile SBOM. The three destination
lock blobs match merge `c4d9975`; no dependency or machine-wide component was
installed. Complete signed final-artifact license and notice review remains a
production-release prerequisite.

## Checkpoint 2222 - Client logon-session binding

Checkpoint 2222 reuses the pinned `windows-sys` Security token definitions for
`TOKEN_STATISTICS`, `TokenStatistics`, and `TokenSessionId`. It adds no crate,
package, feature, or lockfile change. `AuthenticationId` and `TokenSessionId`
are compared only as local Windows token evidence; no network, rule, signature,
or executable dependency is introduced.

Source contract 652, exact verifier step 252, strict validation, and
implementation-head CI/package evidence pass. The same-user
cross-logon-session control remains distinct from cross-identity IPC,
AppContainer/LPAC, production signing, driver, and pre-execution proof.
Complete signed final-artifact license, notice, copyright, and binary-
resolution review remains a production-release prerequisite.

Checkpoint 2223's `TokenStatistics.TokenId`/`ModifiedId` stability boundary,
same-session and cross-identity limitations, pre-execution disclaimer, Rust
regressions, source contract 653, verifier step 253, and validator assertions
use the already pinned `windows-sys` surface and repository tooling. The batch
adds no crate, package, feature, or lockfile change. Runtime, exact-head,
package, merge, synchronization, and destination evidence remain pending; the
complete signed final-artifact license and binary-resolution review remains a
production-release prerequisite.

Local checkpoint-2223 verification passes both locked workspace variants,
standalone locked/offline Native, dependency evidence, exact verifier
`253/253`, and all three unchanged lock blobs. The `TokenId`/`ModifiedId`
implementation therefore adds no dependency or license delta. Exact-head and
merged package SBOM/checksum proof remain pending; same-session, cross-identity,
and pre-execution limitations remain unchanged.

Full local execution preserves exact root Cargo, Native Cargo, and Flutter lock
blobs `7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Both locked Rust workspaces,
strict lint, Flutter analyze, and Flutter `838/838` pass. Flutter reports 33
newer versions outside current constraints, but no dependency or lock change
occurs. Definitive and implementation-head final-artifact evidence pass;
evidence-head and merged-main evidence remain pending.

Definitive local verification passes `252/252` in `507.8s`, including the
dependency evidence gate and unchanged lockfile checks. No dependency or
machine-wide component is installed. Complete signed final-artifact license
review remains pending.

Exact implementation-head package PR/push runs `32732523189`/`32732497575`
pass on SHA `0a24ac25fcdedf1ef50af8acb9b71499caf9ac69`; the push result is
failed-job-only attempt 2 after a documented transient arm64 `hdiutil` resource
failure. Independently inspected consolidated bundles each contain all six
platform artifacts, seven matching SHA-256 rows, and a CycloneDX 1.6 lockfile
SBOM with 569 components. Publication is skipped and no dependency or lockfile
changes. Evidence-head/merged-main package proof and complete signed final-
artifact license, notice, copyright, and binary-resolution review remain
pending.

Evidence-head package run `32735762385` and merged-main package run
`32737920822` pass on `2f02714` and `e644d77`. Both require all six native
artifacts, dependency/license evidence, checksums, a CycloneDX 1.6 lockfile
SBOM with 569 components, and consolidation, while publication is skipped.
Guarded destination synchronization and full destination verification preserve
all three exact lock blobs. This closes checkpoint package integration only;
complete signed final-artifact license, notice, copyright, and binary-
resolution review remains a production-release prerequisite.

Checkpoint 2223 exact implementation `561ac536a55257b05f9c04ada55756d1ab676749`
passes CI `32744796324` and package PR/push `32744796274`/`32744754697` with no
dependency or lockfile change. Independent checks over both untouched
consolidated ZIP streams verify all six platform files, all seven manifest
SHA-256 values, and CycloneDX 1.6 lockfile SBOMs with 569 components.
Publication is skipped. Defender removed locally extracted MSI/EXE copies but
was not weakened; stream verification used the retained original ZIP entries.
Evidence-head/merged-main proof and complete signed final-artifact license,
notice, copyright, and binary-resolution review remain pending.

Checkpoint 2223 evidence `6223ad2`, merge `252a9ade`, evidence-head package run
`32748118314`, and merged-main package run `32750490746` pass after one retained
transient arm64 `hdiutil` failure and an unchanged failed-job-only retry. Both
final bundles require all six platform artifacts, seven matching SHA-256 rows,
and CycloneDX 1.6 lockfile SBOMs with 569 components; publication is skipped.
Guarded destination synchronization and full verification preserve all three
exact lock blobs. This closes checkpoint package integration only; complete
signed final-artifact license, notice, copyright, and binary-resolution review
remains a production-release prerequisite.

Checkpoint 2224 launch-primary token stability uses only the already pinned
`windows-sys` `TOKEN_STATISTICS`/process APIs and existing repository test and
verification tooling. The implementation captures and rechecks `TokenId` and
`ModifiedId` on the same parent-held token handle around process creation and
authenticated handshake; no new binary, script host, network source, or
runtime component is introduced. This batch adds no crate, package, feature,
or lockfile change.

Local verification passes both locked workspaces, strict lint, standalone
locked/offline Native, Flutter lock enforcement/analyze/`838`, source contracts
`654/654`, dependency evidence, and exact verifier `254/254`. All three lock
blobs remain unchanged. Implementation/evidence/merged-main package evidence,
normal merge, guarded synchronization, and destination proof now pass. Exact
evidence `42d8c7c`, merge `243bc84`, evidence-head package run `32760087347`,
and merged-main package run `32761688853` preserve all six platform artifacts,
seven matching checksums, and the CycloneDX 1.6/569-component lockfile SBOM;
publication is skipped. The control does not
prove the child process token remains identical or expand cross-identity,
AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution
guarantees. Complete signed final-artifact license, notice, copyright, and
binary-resolution review remains a production-release prerequisite.

Checkpoint 2225 child process-token binding uses only the already pinned
`windows-sys` duplex named-pipe, `OpenProcessToken`, `TOKEN_QUERY`,
`TOKEN_STATISTICS`, overlapped I/O, wait, and cancellation APIs. Exact
child `TokenId`/`ModifiedId` stability comparison, existing bounded token-
profile queries, and one-byte ACK flow control introduce no crate, package,
feature, binary, script host, network source, or runtime component. This batch
adds no crate, package, feature, or lockfile change.

The first focused runtime showed a distinct child versus launch-primary
`TokenId` on this Windows host; exact cross-object equality is technically
unavailable and not claimed. The repair reuses already linked token APIs to
bind identity/restricted profile and the child token's own stability. Focused,
full local, exact `255/255` verifier, and independent report validation pass;
all three monitored lock blobs remain exact. This point-in-time control does not add cross-
identity authentication, encryption, AppContainer/LPAC, installed LocalSystem,
signed-driver, or pre-execution guarantees. Complete signed final-artifact
license, notice, copyright, and binary-resolution review remains a production-
release prerequisite.

Checkpoint 2225 evidence `d1a1e14`, merge `5792c22`, evidence/merged-main
package runs `32771093928`/`32773257841`, guarded destination synchronization,
and destination `255/255` verification preserve the exact three lock blobs.
Both package bundles retain six platform artifacts, seven matching checksums,
and CycloneDX 1.6/569-component SBOMs; publication is skipped. No dependency or
machine-wide component was installed.

Checkpoint 2226 post-response token stability reuses the already pinned
`windows-sys` named-pipe, process-token, wait, overlapped I/O, and cancellation
APIs plus existing `std` flush support. Retaining the handshake/process/launch-
token handles through response flush, exchanging exact response-ready/final ACK
bytes, and rechecking `TokenId`/`ModifiedId` adds no crate, package, feature,
binary, script host, network source, runtime component, or lockfile change. This
batch adds no crate, package, feature, or lockfile change.

The control remains point-in-time and does not cryptographically bind response
bytes, provide cross-identity IPC, AppContainer/LPAC, installed LocalSystem,
signed-driver, or pre-execution guarantees. Source contract 656 passes
`656/656`; strict locked/offline/all-feature dependency checks pass; and the
Cargo and Flutter lockfiles remain unchanged. Verifier step 256 passes inside
exact `256/256` definitive evidence; the three lock blobs remain exact. Complete
signed final-artifact license,
notice, copyright, and binary-resolution review remains a production-release
prerequisite.

Checkpoint 2226 implementation-head package runs `32780474053` and
`32780511318` generate versioned CycloneDX 1.6 lockfile SBOMs with 569
components. Untouched consolidated artifacts `9539926286`/`9540008859` pass
seven-checksum and exact-SBOM in-stream validation; publication is skipped.
This is dependency evidence, not complete final binary/license approval.

Checkpoint 2226 evidence `bacf1cc`, merge `bab872d`, evidence/merged-main
package runs `32782113878`/`32784751652`, guarded destination synchronization,
and destination `256/256` verification preserve the exact three lock blobs.
The evidence run's first macOS arm64 attempt failed on a hosted Flutter
toolcache architecture mismatch and is uncredited; its unchanged failed-job-
only retry passed. Untouched package artifacts `9540950441`/`9541445838` retain
six platform files, seven matching checksums, and CycloneDX 1.6/569-component
SBOMs; publication is skipped. No dependency, lockfile, or machine-wide
component changed. Complete signed final-artifact license, notice, copyright,
and binary-resolution review remains a production-release prerequisite.

Checkpoint 2227 response-client reauthentication reuses the already pinned
`windows-sys` `GetProcessId`, `GetNamedPipeClientProcessId`,
`ImpersonateNamedPipeClient`, token-information, and revert APIs plus existing
repository testing and verification tooling. The exact process/pipe PID binding,
fresh token-profile validation, and source/verifier/validator contracts add no
crate, package, feature, binary, script host, network source, runtime component,
or lockfile change. Both locked workspaces, strict affected-crate Clippy,
standalone Native locked/offline checking, locked release builds, and Flutter
analysis/`838` pass locally. Definitive exact `257/257` passes and the root
Cargo, Native Cargo, and Flutter lock blobs remain respectively
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. The control
does not add encryption, cross-identity IPC, AppContainer/LPAC, installed
LocalSystem, signing, signed-driver, or pre-execution guarantees. Complete signed
final-artifact license, notice, copyright, and binary-resolution review remains
a production-release prerequisite.

Checkpoint 2227 exact implementation `cef0d28` passes package push/PR runs
`32791317044`/`32791340840`. Untouched consolidated artifacts
`9543648381`/`9543559227` each contain six platform files, seven matching
SHA-256 rows, and a CycloneDX 1.6 lockfile SBOM with 569 components under exact
in-stream validation; publication is skipped. This is dependency evidence, not
complete signed final-artifact license or binary approval.

Checkpoint 2227 evidence `c63fb71`, normal merge `9304681`, evidence/merged-main
package runs `32792981950`/`32794437034`, exact guarded synchronization, and
destination `257/257` verification preserve the exact three lock blobs.
Untouched package artifacts `9544267760`/`9544647451` retain six platform
files, seven matching checksums, and CycloneDX 1.6/569-component SBOMs under
stream-only validation; publication is skipped. No dependency, lockfile, or
machine-wide component changed. Complete signed final-artifact license, notice,
copyright, and binary-resolution review remains a production-release
prerequisite.

Checkpoint 2228 response hash binding reuses the Native Engine's already pinned
`sha2` 0.10 dependency to hash a fixed domain, exact response length, and exact
stdout bytes. The fixed 41-byte pipe frame and existing 16 KiB response ceiling
add no crate, package, feature, or lockfile change, runtime component, script
host, network source, or machine-wide installation. Source contract 658 and
verifier/validator step 258 are scripted before execution. This SHA-256 is
unkeyed same-user content-integrity evidence, not a secret MAC, encryption,
cross-identity authentication, AppContainer/LPAC, installed LocalSystem,
signed-driver, or pre-execution proof. Full local, hosted, package, integration,
synchronization, and destination evidence subsequently passed at merge
`ab43569`; complete signed final-artifact license/binary review remains pending.

Checkpoint 2229 adds Native Engine direct dependency `hmac = "0.12"` to replace
the checkpoint-2228 unkeyed response digest with domain-separated HMAC-SHA-256
under the exact per-launch handshake token. Workspace `Cargo.lock` already pins
RustCrypto `hmac` `0.12.1` through Local Core and Guard; locally cached metadata
already records `MIT OR Apache-2.0`. The dependency uses the existing `sha2`
0.10 implementation and adds no network service, executable, script host,
machine-wide component, or candidate-content execution. Offline lock resolution
and exact review are complete. Root adds only the Native `hmac` edge and hashes
to `bc43621213d9bede816a6e062146996116fb92fc`. Standalone Native adds `hmac`
`0.12.1`, `subtle` `2.6.1`, the enabled `digest` subtle edge, and the Native
edge without package version updates; it hashes to
`1d9d96a172c258a584066a9adbb5a10a8feff97d`. Flutter remains exact at
`51fa085a41168aa1deadace8b5395614db43649e`. The key is carried in child environment/memory
and same-user IPC, so HMAC is not encryption, durable secret storage, cross-
identity authentication, AppContainer/LPAC, installed LocalSystem, signed-
driver, or pre-execution proof. Complete signed final-artifact license, notice,
copyright, and binary-resolution review remains a release prerequisite. No
checkpoint-2229 passing result was claimed during scripting. Focused and full
local runtime checks, exact `259/259` verification, strict report validation,
and dependency evidence now pass. Exact implementation `eaa4ba3` passes package
push/PR runs `32812914763`/`32812956466`; untouched artifacts `9550661340`/
`9550842112` each pass exact six-platform-file, seven-checksum, and CycloneDX
1.6/569-component in-stream validation, while publication is skipped. Evidence-
head/integration checks and complete signed final-artifact review remain
pending.

Checkpoint 2229 evidence `f0c72e1`, normal merge `36d67798`,
evidence/merged-main package runs `32815352955`/`32816491027`, guarded
destination synchronization, and destination `259/259` verification preserve
the exact root/Native/Flutter lock blobs. Untouched artifacts `9551544695`/
`9551887494` retain six platform files, seven matching checksums, and
CycloneDX 1.6/569-component SBOMs under stream-only validation; publication is
skipped. Complete signed final-artifact license, notice, copyright, and binary
review remains a production-release prerequisite.

Checkpoint 2230 changes only the native Authenticode launch-key transport and
its local tests, verifier/validator contracts, and documentation. It adds no
crate, package, feature, lockfile edge, executable, network source, service,
driver, installer, machine-wide component, or candidate-content execution. The
existing HMAC-SHA-256 dependency and pinned root/standalone Native/Flutter lock
graphs are intended to remain exact; lock verification is pending execution.
The key is removed from the child environment but remains in parent/child memory
and crosses authenticated same-user IPC, so this is not encryption,
cross-identity authentication, AppContainer/LPAC, installed LocalSystem,
signed-driver, or pre-execution proof. No checkpoint-2230 passing result is
claimed during scripting; focused/full, definitive, hosted, merge, destination,
and final dependency evidence remain pending.

Post-scripting local execution confirms no lock delta. Git blobs remain exact at
root `bc43621213d9bede816a6e062146996116fb92fc`, standalone Native
`1d9d96a172c258a584066a9adbb5a10a8feff97d`, and Flutter
`51fa085a41168aa1deadace8b5395614db43649e`. Locked/offline resolution, both
workspace modes, affected strict Clippy, release builds, Flutter analyze, and
Flutter `838/838` pass. Hosted package/SBOM and final signed-artifact review
remain pending; no publication is authorized.

Definitive local verification also passes exact `260/260` and its dependency
evidence gate while preserving all three lock blobs. The package source-contract
suite passes 21 tests and explicitly skips three Windows symlink-positive cases
that require optional privileges; no dependency is installed to force those
fixtures. Hosted package/SBOM and complete signed final-artifact review remain
release prerequisites.

Checkpoint 2231 replaces the public fixed handshake ACK with HMAC-SHA-256 key
confirmation using the already pinned `hmac 0.12.1` and `sha2 0.10.9` crates,
the existing canonical UUID key, and existing pipe/process evidence. It adds no
crate, package, feature, or lockfile change, executable, script host, network
source, service, driver, or license obligation. The handshake and response MACs
reuse one per-launch key under distinct fixed domains; this is documented as
same-user point-in-time possession evidence, not encryption, cross-identity
authentication, durable secret storage, signed-driver, or pre-execution proof.
No checkpoint-2231 dependency or lock result is claimed before execution.

Checkpoint 2232 adds `zeroize 1.9.0` as an exact Windows-only direct dependency
of Native Engine. The RustCrypto crate is licensed `Apache-2.0 OR MIT`, requires
Rust 1.85 or newer, and provides the established `Zeroizing<T>` RAII wrapper and
`Zeroize` trait used to scrub Avorax-owned Authenticode launch-key strings and
the bounded child pipe-read buffer on drop. The root lock already contains
`zeroize 1.9.0` transitively; checkpoint 2232 adds only the Native package edge
there. Offline Cargo resolution adds the exact package and Native edge to the
standalone lock without any other package change. The resulting SHA-256 values
are root `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
standalone Native
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and unchanged Flutter
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.

The dependency adds no executable, script host, network client, service, driver,
installer, machine-wide component, or candidate-content execution. Best-effort
zeroization does not guarantee compiler/HMAC/allocator/OS copy removal, process-
dump or paging cleanup, forensic secure erasure, live-memory secrecy, durable
secret storage, cross-identity isolation, signed-driver behavior, or
pre-execution enforcement. Complete signed final-artifact license, notice,
copyright, and binary-resolution review remains a production-release
prerequisite. No checkpoint-2232 passing result is claimed during scripting.

Local dependency evidence now passes source contracts `662/662`, standalone
Native `--locked --offline --all-targets --all-features`, strict Native/Local/
Guard Clippy, both locked workspace variants, three locked release builds, and
the definitive dependency gate inside the exact `262/262` verifier. Root,
standalone Native, and Flutter lock blobs are
`80a97940019c722f29e6852504b430cf97ca906e`,
`876c6627fe0584976778ad26e88149e9e2c51be1`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Exact implementation-head package
runs `32850194350` and `32850233494` build all six Windows/Linux/macOS release
files and consolidate a CycloneDX 1.6 lockfile SBOM with exactly 569 components.
Both downloaded consolidated ZIP digests match GitHub and pass bounded in-stream
inventory, checksum, and SBOM validation without extraction or execution.
Evidence-head package run `32852690969` and merged-main package run
`32854130974` repeat all six platform files, exact checksum coverage, and the
569-component CycloneDX 1.6 SBOM. Their consolidated artifacts match GitHub
digests and pass non-extracting validation. Publication is skipped. Final
signed-artifact license/notice review remains a production-release prerequisite.

Checkpoint 2233 changes only Authenticode launch-key ownership and validation.
It replaces Avorax-owned `Zeroizing<String>` values with the existing
`zeroize 1.9.0` wrapper over one fixed shape, `Zeroizing<[u8; 37]>`, where the
last byte is a zero overflow guard. It reuses the already direct Windows-only
`zeroize = "=1.9.0"`, `uuid`, `hmac`, and `sha2` dependencies and adds no crate,
package, feature, or lockfile change. Their existing licenses and pins remain
unchanged.

The ownership change adds no executable, script host, network source, service,
driver, installer, machine-wide component, candidate-content execution, release,
or publication. A fixed buffer narrows `String` allocation/copy/formatting
surface but does not guarantee cleanup of UUID/HMAC internals, compiler
temporaries, stack/register spills, allocator/OS/pipe copies, dumps, paging, or
forensic remnants; it is not secure erasure, cross-identity isolation,
signed-driver behavior, or pre-execution enforcement. No checkpoint-2233
dependency, lock, build, or test result is claimed during scripting. Exact
source contract 663, exact 263-step dependency/verifier evidence, hosted SBOM,
and final signed-artifact license/notice review remain execution or production
prerequisites.

Checkpoint-2233 local dependency evidence now passes source `663/663`, locked
offline Native resolution, strict Native/Local/Guard Clippy, both locked root
workspace test modes, Local/Guard/Update release builds, and Flutter
`838/838`. Root, standalone Native, and Flutter locks have no diff; Flutter raw
SHA-256 remains `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`
and blob `51fa085a41168aa1deadace8b5395614db43649e`. The implementation continues to
reuse `zeroize 1.9.0` for `Zeroizing<[u8; 37]>` with one overflow guard and adds
no owned launch-key `String`, crate, package, feature, license, or lock change.
Exact 263-step, hosted SBOM/package, and final signed-artifact review remain
pending and no pre-execution or secure-erasure dependency claim is made.

The definitive local dependency gate now passes inside exact `263/263` in
`461.4s`; embedded and independent PS5.1 validators plus `8/8` report mutations
pass. All three locks remain exact and no new dependency/license edge exists.
An optional PS7 strict-validator attempt is not credited because host JSON
timestamp conversion violates the validator's string schema; that tooling-host
limit adds no package and does not change the existing `zeroize 1.9.0`,
`Zeroizing<[u8; 37]>`, overflow guard, removed owned `String`, or
pre-execution/secure-erasure boundaries. Hosted SBOM/package and final
signed-artifact review remain pending.

Checkpoint-2233 exact implementation-head package evidence now passes in push
run `32865302082` and PR run `32865480497` for exact `00e9f3c`. Both runs build
all six Windows/Linux/macOS release files, generate the pinned lockfile
CycloneDX 1.6 SBOM with exactly 569 components, checksum all seven targets, and
skip publication. Untouched consolidated artifacts `9570689038` and
`9570466353` match GitHub/download SHA-256 and pass bounded in-stream inventory,
checksum, and SBOM validation without extraction or execution. This is package
and source-lock evidence, not final signed-binary license/notice/copyright
approval; evidence-head and merged-main package evidence plus final production
artifact review remain pending. No dependency or lock changed.

Checkpoint-2233 evidence head `646000b` and merged main `7467bfd` pass package
runs `32868120588` and `32870805371`. Consolidated artifacts `9571887670` and
`9572796463` match GitHub SHA-256 and pass bounded non-extracting six-platform-
file, seven-checksum, and CycloneDX 1.6/569-component review; publication is
skipped. Destination locked/offline, strict lint, release, full verifier
dependency gate, and source `663/663` checks pass. Root, Native, and Flutter
lock SHA-256 values remain exact at
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
No dependency or lock changed. Final signed-binary license, notice, copyright,
and production release approval remain separate prerequisites.
