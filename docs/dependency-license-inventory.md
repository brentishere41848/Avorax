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
