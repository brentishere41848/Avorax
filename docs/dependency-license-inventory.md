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

Evidence-head and merged-main package artifacts each retain exact CycloneDX 1.6
inventory with 569 unique components and seven matching checksums. No lock,
dependency, source, or license delta occurred. Checkpoint 2254 dependency
evidence is closed; production notices, signing/notarization, legal approval,
and release approval remain separate prerequisites.

Implementation-head package consolidation produces the existing CycloneDX 1.6
lockfile SBOM with exactly 569 components and 569 unique references. The
untouched consolidated artifact passes all seven checksums without extraction,
and publication is skipped. Evidence-head and merged-main hosted SBOM evidence,
production signing/notarization, legal approval, and release approval remain
pending.

## Checkpoint 2252 Dependency Scope

Static structured-indicator cancellation reuses Rust slices, UTF-8 character
indices, checked/saturating arithmetic, the existing shared search module, and
the already locked `anyhow` error boundary. It adds no dependency, feature,
build script, downloaded or network source, package source, license obligation,
or lockfile change.

Tests use only benign in-memory ASCII/UTF-8, reserved `.invalid` references,
and injected callback errors. They never download, unpack, retain, execute, or
write candidate content and do not create a live EICAR file. Exact verifier
step 281 and Source contract 682 are scripted; no checkpoint-2252 test has run
during this scripting phase. Root Cargo, Native Cargo, and Flutter lock SHA-256
values are expected to remain respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`;
verification remains pending. Final-binary SBOM resolution, production
signing/notarization, legal approval, installed-service stress, and release
approval remain separate prerequisites.


Definitive exact `278/278` and dual-host validation pass without dependency or
lockfile change. Hosted package lockfile-SBOM evidence remains pending; this
checkpoint still adds no dependency, feature, package source, or license
classification.

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

Checkpoint 2234 adds no dependency, feature, or lockfile change. Its PowerShell
7 and Windows PowerShell 5.1 JSON compatibility repair uses the built-in
`ConvertFrom-Json` cmdlet and feature-detects the native `DateKind` parameter.
The definitive verifier remains exactly 263 steps; source contract 664 covers
the parser and distinct-host wiring. Existing dependency licenses, lock hashes,
and final signed-binary notice/copyright review requirements are unchanged.

Checkpoint-2234 local dependency evidence passes inside exact verifier
`263/263` in `469.9s`; source contracts pass `664/664`, both strict Windows
PowerShell 5.1/PowerShell 7 validators pass, and root/Native/Flutter lockfiles
remain unchanged. No package upgrade was accepted. Hosted push/PR package runs
`32878368995`/`32878421335` pass and their consolidated artifacts contain the
expected CycloneDX 1.6 lockfile SBOM with exactly 569 components. Final signed-
artifact license review remains pending.

Checkpoint-2234 evidence and merged-main package runs also pass without package
or lock change. Their consolidated CycloneDX 1.6 SBOM evidence remains exactly
569 components and passes bounded in-stream validation. Destination lock hashes
match the recorded root/Native/Flutter values. This closes checkpoint package
dependency evidence, while final signed-artifact notice/copyright approval
remains a separate release prerequisite.

## Checkpoint 2235 Dependency Scope

Bounded Native/Local risk fusion uses Rust standard-library arithmetic,
ordering, UTF-8 boundary, and collection APIs already available in the locked
toolchain. Tests use existing crate test support. Verifier, validator, source
contract, and documentation changes use existing repository tooling. This
checkpoint adds no dependency, feature, downloaded model/rule, package source,
license obligation, or lockfile change. No network content or candidate file is
introduced or executed.

Local execution confirms no lockfile diff. Root, Native, and Flutter SHA-256
remain `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Source `665/665`, both locked workspaces, Flutter, and changed-crate strict
Clippy pass. Final hosted package/SBOM evidence remains pending.

Definitive exact `264/264` and its dependency evidence gate pass without a
lockfile diff. Hosted exact-head package and CycloneDX review remains pending.

Hosted checkpoint-2235 push/PR package runs `32891914251`/`32892108020` pass
without dependency or lock change. Their consolidated artifacts contain the
expected CycloneDX 1.6 lockfile SBOM with exactly 569 components and pass
bounded in-stream validation. Final signed-artifact notice/copyright approval
remains a separate release prerequisite.

Checkpoint-2235 evidence-head and merged-main package runs `32894004858` and
`32896343565` pass with publication skipped. Artifacts `9581295219` and
`9582201337` match GitHub SHA-256 and pass bounded non-extracting six-platform-
file, seven-checksum, and CycloneDX 1.6/569-component validation. Destination
source, locked workspaces, exact verifier dependency gate, and all three lock
hash checks pass without dependency, feature, license, or lockfile change.
Final production signed-artifact notice/copyright approval remains separate.

## Checkpoint 2236 Dependency Scope

Bounded process behavior uses Rust standard-library path, byte-window, UTF-8
boundary, saturating arithmetic, and collection APIs plus repository `anyhow`
and existing verdict/provider types. It adds no dependency, feature, downloaded
model/rule, package source, license obligation, or lockfile change. Tests use the
existing Native test support and harmless text/known-bad fixtures; no candidate
is executed. Source contract 666 and exact verifier cardinality 265 bind this
scope. Lock, package/SBOM, and final signed-artifact review remain pending.

Local execution confirms all three lockfile SHA-256 values remain exact after
focused and broad tests. No dependency was installed to replace missing optional
pytest; the repository's dependency-free source-contract runner passed
`666/666`. Hosted package/SBOM and final signed-artifact review remain pending.

Exact implementation-head package push/PR runs `32904862805`/`32904894580`
produce two independently consolidated artifacts. Non-extracting validation
confirms each contains one CycloneDX 1.6 lockfile inventory with exactly 569
components and seven matching checksums beside six platform files. This remains
lockfile-derived partial dependency evidence, not final-binary license resolution,
production signing, or legal approval.

Evidence-head packages `32906638195` and merged-main packages `32907874963`
also pass all builders and consolidation with publication skipped. Their
consolidated artifacts `9585362967` and `9585995999` pass the same bounded,
non-extracting six-platform/seven-checksum/CycloneDX 1.6/569-component review.
Destination source contracts `666/666`, both locked workspace modes, strict
Native lint, Flutter analyze/`838/838`, exact 265-step dependency gate, and exact
lock hashes pass. No dependency, feature, lockfile, machine-wide component,
release, or publication changed. Final-binary license resolution, production
signing, and legal approval remain separate prerequisites.

## Checkpoint 2237 Dependency Scope

Process observation Native wiring reuses the existing Local Core dependency on
`zentor_native_engine`, existing `anyhow`/serde types, Flutter/Dart standard
libraries, and repository PowerShell/Python verification tools. It adds no
dependency, feature, downloaded model/rule, package source, license obligation,
or lockfile change. Benign tests create only text or temporary ordinary files
and never execute candidate content. Source contract 667 and exact verifier
cardinality 266 bind this scope. Lock, package/SBOM, hosted, and final signed-
artifact license evidence remain pending; no checkpoint-2237 passing result is
claimed during scripting.

Local execution confirms all three lockfile SHA-256 values remain exact. Strict
component lint, both locked workspace modes, Flutter analyze/`838/838`, source
contracts `667/667`, and the exact `266/266` dependency/report gate pass. No
dependency, feature, package source, license classification, or lockfile changed.
Hosted package/CycloneDX and complete signed final-binary license/notice review
remain pending and are not inferred from this local result.

Exact implementation-head package push/PR runs `32915865035`/`32915881182`
produce consolidated artifacts `9588536075`/`9588657829`. Non-extracting
in-stream review confirms each has six platform files, seven matching checksums,
and one CycloneDX 1.6 lockfile SBOM with 569 components; publication is skipped.
This is lockfile-derived partial dependency evidence, not production signing,
final-binary license resolution, or legal approval.

Evidence-head packages `32917698337` and merged-main packages `32918786960`
also pass every builder and consolidation with publication skipped. Their
consolidated artifacts `9589047438` and `9589474251` pass bounded non-extracting
six-platform/seven-checksum/CycloneDX 1.6/569-component review. Destination
source contracts `667/667`, both locked workspace modes, strict Native/Local
lint, Flutter analyze/`838/838`, exact 266-step dependency gate, and exact lock
hashes pass. No dependency, feature, lockfile, machine-wide component, release,
or publication changed. Final-binary license resolution, production signing,
and legal approval remain separate prerequisites.

## Checkpoint 2238 Dependency Scope

Protection-loop generation binding uses Dart integer state, existing timer and
Future control flow, current Flutter test doubles, and repository PowerShell/
Python verification tools. It adds no dependency, feature, downloaded content,
package source, license obligation, or lockfile change. Benign tests use only
temporary empty directories, manual timers, and in-memory response/error
fixtures; they create or execute no candidate content.

Source contracts pass `668/668` and the exact `267/267` verifier dependency gate
passes locally. Root, Native, and Flutter lock SHA-256 values remain exactly
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
No dependency, feature, package source, license classification, or lockfile
changed. Implementation-head hosted package/SBOM evidence follows; evidence-
head and merged-main package evidence remains pending. Final-binary license
resolution, production signing, and legal approval remain separate prerequisites.

Exact implementation-head package runs `32923527726`/`32923573229` produce
consolidated artifacts `9591053604`/`9590999961`. Bounded in-stream review
without extraction confirms six platform release files, seven matching
checksums, and CycloneDX 1.6 lockfile SBOM evidence with 569 components in each;
publication is skipped. This remains lockfile-derived partial dependency
evidence, not final-binary license resolution, production signing, or legal
approval.

Evidence-head packages `32924928368` and merged-main packages `32926037103`
also pass every builder and consolidation with publication skipped. Their
consolidated artifacts `9591498177` and `9591881748` pass bounded non-extracting
six-platform/seven-checksum/CycloneDX 1.6/569-component review. Destination
source contracts `668/668`, Flutter analyze/`840/840`, the exact 267-step
dependency gate, and exact lock hashes pass. No dependency, feature, lockfile,
machine-wide component, release, or publication changed. Final-binary license
resolution, production signing, and legal approval remain separate
prerequisites.

## Checkpoint 2239 Dependency Scope

Scan cancellation generation/outcome binding uses existing Dart integers,
`Completer<bool>`, process objects, test timers, and repository Flutter/
PowerShell/Python tooling. The Local Core process lease is a private Dart value
around the existing `dart:io` `Process`; it adds no dependency, feature,
downloaded content, package source, license obligation, or lockfile change.

Benign tests use temporary directories, in-memory reports/errors, manual timers,
and a bounded Dart subprocess fixture that reads only its JSON test command and
never scans or executes candidate content. Exact 268-step and source contract
669 coverage are scripted but not yet run. Final-binary license resolution,
production signing, and legal approval remain separate prerequisites.

## Checkpoint 2240 Dependency Scope

Scan-job cancellation binding uses the already locked Dart `uuid` package,
Rust `uuid`/Serde/Chrono crates, `dart:io`, and repository PowerShell/Python
tooling. It adds no dependency, feature, downloaded content, package source,
license obligation, or lockfile change.

Benign tests use temporary data roots, JSON command fixtures, and dormant Dart
subprocesses. They do not scan or execute candidate content. Exact 269-step and
source contract 670 coverage are scripted but not yet run. Final-binary license
resolution, production signing, and legal approval remain separate
prerequisites.

## Checkpoint 2241 Dependency Scope

Cooperative in-engine cancellation uses only Rust standard-library error/
callback types, the already locked `anyhow` dependency, existing Local Core
UUID-token parsing, and repository PowerShell/Python verification tools. It
adds no dependency, feature, downloaded content, package source, license
obligation, or lockfile change.

Benign regressions use temporary ordinary text files, sparse zero-filled files,
in-memory byte fixtures, and isolated temporary data roots. They never execute
candidate content and never touch the installed quarantine vault. Exact
270-step and source contract 671 coverage were scripted before testing. Final-
binary license resolution, production signing, and legal approval remain
separate prerequisites; no checkpoint-2241 passing result was claimed during
scripting.

Local verification confirms root, Native, and Flutter lock SHA-256 values remain
exactly `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Source contracts `671/671`, the locked workspace release build, Flutter
`847/847`, and strict Native/Local lint pass. The definitive report passes exact
`270/270` in `462.7s` with dual validator acceptance and adversarial
missing-step/scope rejection. No dependency, feature, package source, license
classification, or lockfile changed. Hosted SBOM/package evidence is now
verified at implementation head: both consolidated artifacts contain one
CycloneDX 1.6 lockfile SBOM with exactly 569 components and seven matching
checksum targets. This remains lockfile evidence, not a final-binary SBOM or
legal approval.

Evidence-head and merged-main packages preserve the same exact CycloneDX 1.6,
569-component, seven-checksum contract. Their consolidated ZIP downloads match
GitHub SHA-256 and pass bounded in-stream validation without extraction or
execution. Destination lock hashes remain exact. Checkpoint 2241 introduces no
dependency, feature, package source, license classification, or lockfile
change; final-binary SBOM resolution and legal approval remain separate.

## Checkpoint 2246 Native Provider Cancellation Dependency Scope

Checkpoint 2246 uses Rust standard-library slices, strings, checked arithmetic,
callbacks and existing `anyhow` error propagation. It adds no dependency, feature,
downloaded content, package source, license classification, or lockfile change.
The root Cargo, Native Cargo, and Flutter lock hashes remain exactly unchanged:
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.

Benign tests use ordinary bytes, the decoded EICAR test marker already present
in the safety suite, and isolated temporary empty custom-pack fixtures. They do
not download, retain, unpack, or execute malware and do not access the protected
ProgramData vault. Source contract `676/676`, locked workspace tests, locked
release build, and exact verifier `275/275` pass locally without a manifest or
lock delta. Final-binary SBOM,
production signing/notarization, model/rule accuracy evidence, legal approval,
and release approval remain separate prerequisites.

## Checkpoint 2245 Non-Archive Static Cancellation Delta

Checkpoint 2245 adds no dependency, feature, build script, downloaded content,
package source, license classification, license obligation, or lockfile change.
It uses Rust standard-library iterators/counters/callbacks and the already locked
`anyhow` error contract. Existing dependency pins and license evidence remain
authoritative.

Benign tests use ordinary strings and synthetic PE bytes in memory; they do not
download, unpack, retain, or execute malware and do not touch the protected
quarantine vault. Exact verifier step 274 and Source contract 675 are scripted,
but no checkpoint-2245 test has run during this scripting phase. Final-binary
SBOM resolution, production signing, release-host packaging, and legal approval
remain separate prerequisites.

Local focused, analyzer, strict Native lint, complete Native, and exact Source
contract `675/675` evidence pass without modifying any dependency manifest or
lockfile. At that stage definitive verifier 274 and hosted SBOM/package evidence
remained pending; no dependency or license conclusion is expanded by the local
tests.

Local Core `546/546`, Flutter analyze and `847/847`, strict Local Core lint, and
the locked workspace release build pass with no manifest or lockfile diff.
Protected-vault preflight is unchanged. Hosted package/SBOM and final-binary
license evidence remain pending.

Definitive local verification now passes exact `274/274` under the locked
dependency graph; both independent PowerShell report validators pass and reject
the two malformed evidence copies. No dependency manifest or lockfile changed.
Hosted package/SBOM and final-binary license evidence remain pending.

Implementation-head push and PR package matrices now pass. The downloaded PR
consolidated artifact matches GitHub's SHA-256 and contains exact CycloneDX 1.6
lockfile evidence with `569` components; all seven checksum rows match their
streamed entries. No entry was extracted or executed, and both publication jobs
are skipped. Legal approval, production signing/notarization, and final release
approval remain separate and partial.




## Checkpoint 2244 Static Archive Analysis Cancellation Delta

Checkpoint 2244 adds no dependency, feature, build script, downloaded content,
or lockfile change. It reuses `anyhow`, `flate2`, and existing Rust callback
contracts already present in the Native engine. Their pinned versions and
license evidence are unchanged. Verification cardinality advances to 273 and
source contract 674; no new third-party license review is required.

Local verification confirms all three lock hashes remain exact, source contract
`674/674` passes, and no dependency file is modified. Definitive verification
passes exact `273/273` in `531.1s` with dual validator acceptance and
adversarial missing-step/scope rejection. The three lock hashes remain exact
afterward. Hosted package evidence at local-evidence head `2518612` and hosted
head `3237d49e3df2d6355968882cddf57f0c171e3827` passes with publication
skipped. Consolidated artifacts `9613011717` and `9614177410` each pass bounded
non-extracting exact eight-entry/seven-checksum validation and contain one
CycloneDX 1.6 lockfile SBOM with 569 components. No dependency, feature,
package source, license classification, or lockfile changed; this remains
lockfile evidence rather than final-binary SBOM resolution or legal approval.

Evidence head `0b566a4ce45e9818db840b09156fbf4a2d0b25f0` and merged main
`c0cd92f7f10e6205ad209435c24367f54f8cd8b0` preserve that dependency
contract. Main package artifact `9616123602` passes bounded non-extracting exact
8-root/6-platform/7-checksum validation with CycloneDX 1.6 and 569 lockfile
components. Guarded destination verification preserves exact root, Native, and
Flutter lock SHA-256 values. Checkpoint 2244 is closed with no dependency,
feature, package source, license classification, or lockfile change; final-binary
SBOM resolution, production signing, and legal approval remain separate.

## Checkpoint 2245 Dependency Closure

Evidence head `195d3c847b4e0ce993329bd0e7b142d1b6c0b785` and merged main
`48cf932ff23211961386cbf220d05026821322c7` preserve the checkpoint's
zero-dependency delta. Evidence-head artifact `9620713611` and merged-main
artifact `9621531773` match their downloaded SHA-256 values and pass bounded
non-extracting exact 8-root/6-platform/7-checksum validation with CycloneDX 1.6
and 569 lockfile components. Publication is skipped.

Destination verification preserves exact SHA-256 values for root `Cargo.lock`,
Native `Cargo.lock`, and Flutter `pubspec.lock`:

- `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`;
- `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`;
- `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.

Source contracts `675/675`, locked release build, and destination definitive
`274/274` pass. Checkpoint 2245 adds no dependency, feature, package source,
license classification, or lockfile change. CycloneDX output remains lockfile
evidence rather than final-binary SBOM resolution; production signing,
notarization, legal approval, and final release approval remain separate.

## Checkpoint 2243 Dependency Scope

Parallel Authenticode helper lifecycle hardening uses Rust standard-library
threads, channels, barriers, process status and I/O plus the already locked
`anyhow`, `hmac`, `sha2`, `uuid`, `windows-sys`, and `zeroize` dependencies. It
adds no dependency, feature, downloaded content, package source, license
obligation, or lockfile change.

Benign tests launch only the current Native test executable under the existing
restricted helper boundary. They exchange fixed text markers, never scan or
execute candidate content, and never touch the installed quarantine vault.
Exact verifier step 272 and source contract 673 are scripted before execution;
no checkpoint-2243 passing result is claimed during scripting. Final-binary
license resolution, production signing, installed-service stress, and legal
approval remain separate prerequisites.

Local Source `679/679`, packaging source contracts, locked workspace tests,
locked release build, and strict lint now pass. Root Cargo, Native Cargo, and
Flutter lock SHA-256 values remain respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
No dependency, feature, package source, license classification, or lockfile has
changed. Hosted lockfile SBOM/package evidence and final-binary resolution remain
pending.

Local verification confirms source contracts `673/673`, strict Native/Local
lint, locked workspace release build, and unchanged root/Native/Flutter lock
SHA-256 values. Flutter `847/847` and analyzer pass. No dependency, feature,
package source, license classification, or lockfile changed; exact verifier 272
and hosted SBOM/package evidence remain pending.

## Checkpoint 2242 Dependency Scope

Cooperative archive traversal/inflate cancellation uses Rust standard-library
callbacks and I/O, the already locked `anyhow` and `flate2` dependencies, and
existing repository verification tools. It adds no dependency, feature,
downloaded content, package source, license obligation, or lockfile change.

Benign tests construct ordinary stored/deflated text fixtures in memory and do
not extract or execute candidate content. Exact verifier step 271 and source
contract 672 were scripted before execution. They now pass exact `271/271` and
`672/672`; locked release build and all three unchanged lock hashes pass. Final-
binary license resolution, production signing, and legal approval remain
separate prerequisites; no checkpoint-2242 passing result was claimed during
scripting. Implementation-head hosted package evidence now confirms both
consolidated artifacts contain one CycloneDX 1.6 lockfile SBOM with exactly 569
components and seven matching checksum targets. This remains lockfile evidence,
not a final-binary SBOM, legal approval, or production-signing proof.

Evidence-head and merged-main packages preserve the same exact CycloneDX 1.6,
569-component, seven-checksum contract. Their consolidated ZIP downloads match
GitHub SHA-256 and pass bounded in-stream validation without extraction or
execution. Destination lock hashes remain exact. Checkpoint 2242 introduces no
dependency, feature, package source, license classification, or lockfile
change; final-binary SBOM resolution and legal approval remain separate.

## Checkpoint 2247 Dependency Scope

Provider text-normalization cancellation uses only Rust standard-library UTF-8,
string, vector, iterator, and checked-arithmetic facilities plus the already
locked `anyhow` error boundary. It adds no dependency, Cargo feature, downloaded
content, package source, license obligation, or lockfile change.

Tests use ordinary benign text and explicitly malformed byte arrays in memory;
they never download, unpack, retain, or execute candidate content and do not use
a live EICAR file. Exact verifier step 276 and Source contract 677 were scripted
before execution and now pass in exact `276/276` and `677/677` runs. Root Cargo,
Native Cargo, and Flutter lock SHA-256 values remain respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Final-binary SBOM resolution, production signing/notarization, legal approval,
installed-service stress, and release approval remain separate.

## Checkpoint 2248 Dependency Scope

Static analyzer text-normalization cancellation reuses Rust standard-library
string/UTF-8 facilities, the existing shared helper, and the already locked
`anyhow` error boundary. It adds no dependency, feature, build script,
downloaded or network source, package source, license obligation, or lockfile
change.

Tests use ordinary benign in-memory text/byte arrays and injected callback
errors. They never download, unpack, retain, or execute candidate content and
do not create a live EICAR file. Exact verifier step 277 and Source contract 678
are scripted; no checkpoint-2248 test has run during this scripting phase.
Local Source `678/678`, locked workspace tests, locked release build, and exact
`277/277` definitive verification now pass. Root Cargo, Native Cargo, and
Flutter lock SHA-256 values remain respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Hosted lockfile SBOM evidence remains pending. Final-binary SBOM resolution,
production signing/notarization, legal approval, installed-service stress, and
release approval remain separate prerequisites.

## Checkpoint 2256 Dependency Delta

Checkpoint 2256 file discovery cancellation and bounds add no dependency,
feature, package source, license class, downloaded runtime, machine-wide
component, or lockfile change. The implementation reuses existing `anyhow`,
`walkdir`, `uuid`, Rust standard-library filesystem APIs, and the existing Local
Core cancellation-token contract.

The scripted verification surface is Source contract 686 and definitive step
285 (`local-core file-discovery cancellation and bounds regressions`). No
Checkpoint 2256 test, dependency re-resolution, package download, artifact
extraction, installation, or execution has occurred during this scripting
phase. Existing final-binary notice/license, production signing/notarization,
enterprise deployment, and release-approval blockers are unchanged.

Focused Checkpoint 2256 verification passed without dependency resolution or
lockfile edits: Source `686/686`, file discovery `5/5`, and Local Core `551/551`.
The dependency delta remains empty; definitive step 285, hosted package/SBOM,
and final-binary legal evidence remain pending.

Broad and definitive Checkpoint 2256 verification also passes both locked
workspace variants, strict Local Core Clippy, the locked all-features release
build, Flutter/Dart regressions, and exact `285/285` without a dependency,
feature, package source, license class, or lockfile change. Root Cargo, Native
Cargo, and Flutter lock SHA-256 values remain respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Hosted package/SBOM evidence and final-binary legal/notice resolution remain
pending; no publication is authorized.

Hosted implementation-head package/SBOM evidence now passes on exact
`75a962003a6efc7ff3be6090ed0500448a547787` in PR/push runs `33128336642` and
`33128313733`, with publication skipped. Consolidated artifacts `9669595520`
and `9669627890` match GitHub SHA-256 metadata and each passes exact seven-target
checksum plus CycloneDX 1.6 review with 569 components and 569 unique refs. This
does not change dependencies, lockfiles, licenses, or installation state and is
not final-binary legal/notice approval, production signing/notarization,
enterprise deployment approval, or release approval. Evidence-head and
merged-main package/SBOM evidence remain pending.

Evidence-head package run `33129647055` and merged-main package run
`33130685232` pass all platform, contract, and consolidation jobs with
publication skipped. Consolidated artifacts `9670029088` and `9670342529` have
independently matched SHA-256 values
`ffd05933f6206f112036d26cc1a75218e4e3529f6d0cb8aa6be7f44b3f89853c` and
`f54bfc35b3645e128ffa294505d76f2d5689e353673f49f23c23d4deef8c10df`.
Both bounded reviews verify all seven checksums and CycloneDX 1.6 with 569
components and 569 unique references. Destination exact `285/285` and all
three unchanged lock hashes pass. Checkpoint 2256 adds no dependency, feature,
package source, license class, downloaded runtime, or machine-wide component.
Final-binary legal/notice resolution, production signing/notarization,
installed-service stress, enterprise deployment approval, and release approval
remain separate prerequisites.

## Checkpoint 2255 Dependency Delta

Checkpoint 2255 changes only first-party Rust PE resource cancellation wiring,
benign tests, verifier/validator contracts, Source contract 685, and documents.
It adds no dependency, feature, package source, license class, downloaded
runtime, machine-wide component, or lockfile change. Definitive verifier step
284 and later hosted package/SBOM evidence remain unverified in this scripting
phase; final signed-binary legal/notice review remains a release prerequisite.

Local dependency evidence now passes exact verifier step 284, both locked
workspace variants, offline Native resolution, the locked release build, and
strict linting. The root Cargo, Native Cargo, and Flutter lock hashes remain
`7c7c8aa...`, `7f4393c...`, and `4de1969...`; no lockfile change occurred.
Checkpoint 2255 adds no dependency or license obligation. Hosted package/SBOM,
signed-final-binary notice, notarization/signing, and release approval remain open.

Exact implementation `67f2d26` now passes PR CI `33117139169` and Desktop
Packages `33117139213`/`33117116754`. Each package run builds all six platform
artifacts, produces seven matching checksum targets and a CycloneDX 1.6
lockfile SBOM with 569 components/unique refs, and skips publication. Untouched
consolidated artifacts `9665343047`/`9665714554` match GitHub digests and pass
bounded non-extracting validation. Evidence-head/merged-main package proof and
complete signed final-artifact license, notice, copyright, binary-resolution,
signing/notarization, and release approval remain open; no dependency or lock
changed.

Evidence-head and merged-main package artifacts each retain exact CycloneDX 1.6
inventory with 569 unique components and seven matching checksums. No lock,
dependency, source, or license delta occurred. Checkpoint 2255 dependency
evidence is closed; production notices, signing/notarization, legal approval,
and release approval remain separate prerequisites.

## Checkpoint 2254 ZIP EOCD Cancellation Dependency Delta

Checkpoint 2254 adds no dependency, feature, package source, downloaded
artifact, runtime installation, or license obligation. It reuses Rust slices,
checked/saturating arithmetic, the existing `anyhow::Result` callback boundary,
and already locked Native Engine dependencies. There is no lockfile change.

The checkpoint's verifier step 283 and Source contract 684 are scripted but not
yet executed. Focused through destination verification remains required; final
binary notices, production signing/notarization, release approval, installed
service stress, and enterprise deployment approval remain separate work.

Broad locked tests, locked/offline Native check, locked release build, and
strict Clippy pass without lockfile mutation. Root Cargo, Native Cargo, and
Flutter lock SHA-256 values remain exact at their checkpoint-2253 baselines.
No new dependency or license review is introduced; hosted SBOM evidence remains
pending.

## Checkpoint 2249 Dependency Scope

ZIP entry-name normalization cancellation reuses Rust standard-library
`Option`/`Result`, slices, strings, closures, and checked arithmetic plus the
existing shared helper and already locked `anyhow` error boundary. It adds no
dependency, feature, build script, downloaded or network source, package source,
license obligation, or lockfile change.

Tests use only ordinary benign in-memory ZIP byte fixtures and injected callback
errors. They never download, unpack, retain, or execute candidate content and do
not create a live EICAR file. Exact verifier step 278 and Source contract 679 are
scripted; no checkpoint-2249 test has run during this scripting phase. Root
Cargo, Native Cargo, and Flutter lock SHA-256 values are expected to remain
respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`;
verification remains pending. Final-binary SBOM resolution, production
signing/notarization, legal approval, installed-service stress, and release
approval remain separate prerequisites.

Local focused/full and definitive exact `279/279` verification pass without a
dependency or lockfile change. Root Cargo, Native Cargo, and Flutter lock hashes
remain exact at the values above. Hosted package/SBOM evidence remains pending;
production signing/notarization, legal approval, installed-service stress, and
release approval remain separate prerequisites.

Local Source `680/680`, focused and full suites, locked workspace tests, locked
release build, and strict lint now pass. The three expected lock SHA-256 values
remain exact after Flutter analysis/tests and all Rust work; no lockfile change
or dependency upgrade occurred. Definitive step 279 and hosted SBOM/package
evidence remain pending.


## Checkpoint 2250 Dependency Scope

Static term-search cancellation reuses Rust slices, iterators, checked and
saturating arithmetic, the existing shared search module, and the already locked
`anyhow` error boundary. It adds no dependency, feature, build script, downloaded
or network source, package source, license obligation, or lockfile change.

Tests use only ordinary benign in-memory text/byte arrays and injected callback
errors. They never download, unpack, retain, execute, or write candidate content
and do not create a live EICAR file. Exact verifier step 279 and Source contract
680 are scripted; no checkpoint-2250 test has run during this scripting phase.
Root Cargo, Native Cargo, and Flutter lock SHA-256 values are expected to remain
respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`;
verification remains pending. Final-binary SBOM resolution, production
signing/notarization, legal approval, installed-service stress, and release
approval remain separate prerequisites.

## Checkpoint 2251 Dependency Scope

Static reference-search cancellation reuses Rust slices, strings, iterators,
UTF-8 boundary checks, checked/saturating arithmetic, the existing shared
search module, and the already locked `anyhow` error boundary. It adds no
dependency, feature, build script, downloaded or network source, package
source, license obligation, or lockfile change.

Tests use only ordinary benign in-memory text/byte arrays and injected callback
errors. They never download, unpack, retain, execute, or write candidate
content and do not create a live EICAR file. Exact verifier step 280 and Source
contract 681 are scripted; no checkpoint-2251 test has run during this
scripting phase. Root Cargo, Native Cargo, and Flutter lock SHA-256 values are
expected to remain respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`;
verification remains pending. Final-binary SBOM resolution, production
signing/notarization, legal approval, installed-service stress, and release
approval remain separate prerequisites.

Local Source `681/681`, focused/full suites, both locked workspace variants,
standalone locked/offline Native, locked release workspace, strict lint,
Flutter/Dart, and exact lock hashes now pass. No dependency, feature, package
source, license obligation, or lockfile change occurred. Definitive step 280
and hosted SBOM/package evidence remain pending.

Definitive local verification now passes exact `280/280` with zero failures,
and dual-validator plus adversarial missing-step/missing-scope report checks
pass. The root Cargo, Native Cargo, and Flutter lock SHA-256 values remain
exactly the three values recorded above after the definitive run. No dependency,
feature, package source, license obligation, lockfile, download, or machine-wide
installation change occurred. Hosted exact-head package/SBOM evidence remains
pending.

## Checkpoint 2252 Local Dependency Verification

Source `682/682`, focused/full tests, all locked workspace variants, standalone
locked/offline Native, locked release workspace, strict lint, Flutter analyze
and tests, and Dart protocol tests pass. No dependency, feature, build script,
package source, license obligation, download, or lockfile change occurred. Root
Cargo, Native Cargo, and Flutter lock SHA-256 values remain exactly
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Definitive step 281 and hosted package/SBOM evidence remain pending; final-
binary SBOM resolution, production signing/notarization, legal approval,
installed-service stress, and release approval remain separate prerequisites.

Definitive exact `281/281`, dual-validator acceptance, and adversarial missing-
step/missing-scope rejection now pass. Root Cargo, Native Cargo, and Flutter
lock hashes remain exact after the run. `CARGO_PROFILE_TEST_DEBUG=0` and
`CARGO_INCREMENTAL=0` changed only generated test-binary metadata after active
Defender removed one debug test binary; they add no dependency, feature,
package source, license, lockfile, release setting, Defender exclusion, or
machine-wide installation. Hosted package/SBOM evidence remains pending.

Hosted branch package evidence now passes on exact implementation `09d84239`
in run `33069608149`, with publication skipped. Consolidated artifact
`9645762246` has exact GitHub/download SHA-256
`cd1bbb28059d1be2a64f181e399a8869e7598c8568aafafdd37ac96784d9a7ca`.
Bounded non-extracting review verifies all seven checksums and a CycloneDX 1.6
lockfile SBOM containing 569 unique component references. This is generated
package evidence, not final-binary legal approval, production signing,
notarization, installed-service stress, enterprise deployment approval, or a
published release. PR and merged-main package/SBOM evidence remain pending.

PR `#113` exact-head package run `33071437817` and merged-main package run
`33073230873` now pass all six platform packages, contracts, and consolidation,
with publication skipped. Consolidated artifacts `9646509990` and `9647242232`
have independently matched SHA-256 values
`03a806c44b179a2c0660037c0d9b26a9c98e2aed3eb3e79af7813fefb9329e56` and
`abd7069509543b8a50f631a94964b82679a1faeb20a2840acdce6ce03262b620`.
Both bounded reviews verify all seven checksums and CycloneDX 1.6 with 569
components and 569 unique references. Destination exact `281/281` and all
three unchanged lock hashes pass. Checkpoint 2252 adds no dependency, feature,
package source, license class, lockfile, or downloaded runtime content.
Final-binary legal/notice resolution, production signing/notarization,
installed-service stress, enterprise deployment approval, and release approval
remain separate prerequisites.

## Checkpoint 2253 Dependency Scope

Failed-step report hardening reuses Windows PowerShell 5.1, the existing checked
PowerShell 7 and Python executables, .NET `Process`, JSON, stopwatch, path, GUID,
and file APIs, plus the repository's existing security-gate helpers. It adds no
dependency, feature, build script, package source, license obligation, network
source, downloaded runtime content, or lockfile change.

The focused smoke intentionally supplies the already checked Python executable
as the Cargo path so the first Cargo-style invocation fails immediately. It
creates no candidate fixture, EICAR content, archive, executable, service,
driver, or Defender exclusion and executes no untrusted content. Exact verifier
step 282 and Source contract 683 are scripted; no checkpoint-2253 test has run
during this scripting phase. The three expected lock hashes remain unchanged
in source and require post-execution confirmation.

Focused dual-parser, Source `683/683`, and failed-step smoke execution passes
without a dependency or lockfile change. Root Cargo, Native Cargo, and Flutter
lock SHA-256 values remain exactly `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Full and hosted package/SBOM evidence remain pending.

Broad local verification also passes the locked all-features workspace,
standalone Native locked/offline check, locked release workspace, strict
Native/Local/Guard Clippy, Flutter analyze and `847/847`, and Dart `14/14`.
The three lock hashes remain unchanged. Checkpoint 2253 still adds no dependency,
feature, build script, package source, license obligation, downloaded runtime,
or machine-wide component. Definitive step 282 and hosted package/SBOM evidence
remain pending.

Definitive exact `282/282`, independent PS5/PS7 acceptance, and missing-step /
missing-scope rejection now pass. Root Cargo, Native Cargo, and Flutter lock
SHA-256 values remain exactly
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
The direct pytest-module miss caused no installation; the dependency-free
Source runner passes `683/683`. Hosted package/SBOM evidence remains pending.

Implementation-head hosted package evidence now passes at exact commit
`3fc1fb0907cc194211064784f9ba95cc34f32732` in Desktop Packages run
`33091417691`, with publication skipped. Consolidated artifact `9655292568`
matches GitHub's 132,050,923-byte SHA-256
`6079a51cdf15760aa6f8c0fd8d1bab821f1075f3050f566292753cd340225e49`.
Bounded non-extracting review verifies six platform packages, all seven
checksum targets, and CycloneDX 1.6 with exactly 569 components and 569 unique
references. No dependency, feature, source, lockfile, license classification,
or runtime installation changed. Evidence-head and merged-main package/SBOM
evidence plus complete signed final-binary license/notice review remain
required.

Evidence-head package run `33093775519` and merged-main package run
`33095665829` pass all platform, contract, and consolidation jobs with
publication skipped. Consolidated artifacts `9656100498` and `9656858505`
have independently matched SHA-256 values
`36756f9dbb1aad926231e4a27008f3c30f985506eb43e23d625d5b926c88c1c5` and
`e1631fbb11088c624309351326a311408ebacb8a71cb2b824906be0e3ba9b8d0`.
Both bounded reviews verify all seven checksums and CycloneDX 1.6 with 569
components and 569 unique references. Destination exact `282/282` and all
three unchanged lock hashes pass. Checkpoint 2253 adds no dependency, feature,
package source, license class, lockfile, downloaded runtime, or machine-wide
component. Final-binary legal/notice resolution, production signing/
notarization, installed-service stress, enterprise deployment approval, and
release approval remain separate prerequisites.

## Checkpoint 2257 Dependency Delta

Checkpoint 2257 file discovery path-memory bounds and cancellable priority
bucketing add no dependency, feature, package source, license class, downloaded
runtime, machine-wide component, or lockfile change. The implementation reuses
Rust standard-library `OsStr` encoding, checked integer arithmetic, `Vec`, and
the existing `anyhow`, `walkdir`, and Local Core cancellation contracts.

Source contract 687 and definitive verifier step 286 / exact `286/286` were
scripted before testing. No Checkpoint 2257 dependency re-resolution, new
package download, artifact extraction, installation, or candidate execution
occurred. Existing final-binary license/notice resolution, production signing/
notarization, installed-service stress, enterprise deployment approval, and
release approval remain separate prerequisites.

Focused Checkpoint 2257 verification passes Source `687/687`, all five new
memory regressions, Local Core `556/556`, strict Clippy, and formatting without
dependency resolution, package download, or lockfile change. Broad locked
workspace/build, hosted package/SBOM, and final-binary legal evidence remain
pending; no publication is authorized.

Both locked Rust workspace variants and the locked all-feature release build
pass. Flutter `847/847`, Dart `14/14` plus `6/6`, and analyzers pass after
routine resolution of the already pinned dependency graphs; all lockfiles
remain byte-unchanged. Checkpoint 2257 still adds no dependency, feature,
package source, license class, or lockfile change. Definitive `286/286` passes
in `643.3s`; the three lock hashes remain exact. Hosted package/SBOM evidence
and final-binary legal evidence remain pending.

Checkpoint 2257 hosted implementation-head package workflows pass for Windows,
Linux, macOS arm64, and macOS x64 with publication skipped. Both consolidated
artifacts pass non-extracting checksum and CycloneDX 1.6 review with 569 unique
lockfile component references. This is hosted source-lock inventory evidence,
not final-binary license/notice provenance, production signing/notarization, or
release approval; those remain pending.

Evidence-head and merged-main package workflows also pass with publication
skipped. Their consolidated artifacts independently pass all seven checksums and
CycloneDX 1.6/569-unique-ref review. Destination lock hashes remain exact after
guarded synchronization and definitive `286/286`. Checkpoint 2257 adds no
dependency or lockfile and is closed; final-binary legal/notice provenance,
production signing/notarization, and release approval remain separate.

Checkpoint 2258 adds no dependency, feature, package source, license class, or
lockfile change. Discovery deadlines use `std::time::{Duration, Instant}`;
checked work accounting and report propagation use the existing standard
library, `walkdir`, `anyhow`, and Local Core types. Existing root, Native, and
Flutter lockfiles must remain byte-exact through focused, definitive, hosted,
and destination verification. Verifier step 287 and Source contract 688 are
scripted. This dependency statement is not final-binary license/notice
provenance or release approval.

Final-source locked standard/all-feature workspace tests and the locked
all-feature release build pass after the elapsed-check repair. All lockfiles
remain unchanged; the dependency and license statement above is unchanged.
A later definitive `287/287` and independent dual-host report validation passed
without dependency or lockfile mutation but is superseded by the final
cancellation/progress honesty repair. The repair also uses only existing Local
Core/std types. Final-source, hosted, and destination lock evidence remain
pending.
Repaired-source locked standard/all-feature tests, locked all-feature release
build, and definitive `287/287` pass with all three lock hashes unchanged.
That report is superseded by a zero-byte progress repair using only existing
Local Core/std types. Final-source locked standard/all-feature tests, locked
all-feature release build, and exact `287/287` definitive verification pass
without dependency or lockfile mutation. Hosted and destination lock evidence
remain pending.

Implementation-head CI and both package matrices pass on exact `709e8a9`.
Consolidated artifacts `9677471939`/`9677431721` each contain the expected
CycloneDX 1.6 lockfile SBOM with 569 non-empty unique component references and
pass all seven checksums under bounded non-extracting review; publication is
skipped. Evidence-head, merged-main, and destination package/SBOM evidence remain
pending, as do final-binary legal/notice provenance and release approval.

Evidence-head and merged-main package workflows pass with publication skipped.
Artifacts `9677952419` and `9678412188` independently pass all seven checksums
and CycloneDX 1.6/569-unique-ref bounded non-extracting review. Destination root,
Native, and Flutter locks remain exact after guarded `14/14` synchronization and
definitive `287/287`. Checkpoint 2258 adds no dependency or lockfile change and
is closed; final-binary legal/notice provenance, production signing/
notarization, enterprise approval, and release approval remain separate.

## Checkpoint 2260 Dependency Delta

Checkpoint 2260 adds no dependency, package source, feature, license class,
downloaded runtime, machine-wide component, or lockfile change. Exact Native
verdict SHA-256 propagation and rescan-required quarantine rejection reuse
existing `sha2` hashing, Rust file handles/metadata, the already-pinned
`windows-sys` `GetFileInformationByHandle` API, Unix device/inode metadata, and
existing bounded quarantine copy, journal, HMAC, and permission code.
The same primitives cover Local Core and Guard Service; no second platform API
or Guard-only package is introduced.

Six harmless temporary-file regressions and Source contract 690 add no fixture
binary and execute no candidate content. Final-binary legal/notice provenance,
production signing/notarization, enterprise deployment approval, and release
approval remain separate. No package was downloaded, installed, released, or
published during the Checkpoint 2260 scripting phase.

Checkpoint 2259 adds no dependency, feature, package source, license class,
downloaded runtime, machine-wide component, or lockfile change. The shared 1 GiB
standard-read ceiling and cancellation-first in-target elapsed classification
reuse Rust standard-library arithmetic/time types and existing Native/Local Core
callbacks and errors. Four harmless regressions use small text bytes and pure
size-policy values; no 1 GiB fixture is allocated and no candidate is executed.
Verifier step 288 and Source contract 689 were scripted before testing. Both
locked workspaces, the locked release build, exact `288/288`, and all local
focused/broad checks pass with root, Native, and Flutter lock SHA-256 values
unchanged. No new package source, dependency, feature, license class, artifact
extraction, candidate execution, installation, or publication was introduced.
Existing final-binary license/notice provenance, production signing/
notarization, enterprise deployment approval, and release approval remain
unresolved and separate from this checkpoint.

Checkpoint 2259 implementation-head CI and both package workflows pass on exact
`97e16e7`, with publication skipped. Consolidated artifacts `9681909119` and
`9681997334` each contain the expected CycloneDX 1.6 lockfile SBOM with 569
non-empty unique component references and pass all seven checksums under bounded
non-extracting review. This is hosted source-lock inventory evidence, not final-
binary legal/notice provenance, production signing/notarization, enterprise
deployment approval, or release approval. Evidence-head, merged-main, and
destination package/SBOM evidence remain pending.

Evidence-head and merged-main package workflows pass with publication skipped.
Artifacts `9682604225` and `9683155445` independently pass all seven checksums
and CycloneDX 1.6/569-unique-ref bounded non-extracting review. Destination root,
Native, and Flutter locks remain exact after guarded `13/13` synchronization and
definitive `288/288`. Checkpoint 2259 adds no dependency or lockfile change and
is closed; final-binary legal/notice provenance, production signing/
notarization, enterprise approval, and release approval remain separate.

## Checkpoint 2261 Dependency Delta

Checkpoint 2261 adds no dependency, feature, package source, license class,
downloaded runtime, machine-wide component, or lockfile change. Manual
scan-result quarantine reuses the existing strict JSON `sha256` command field,
`ThreatResult.sha256`, Local Core non-empty text validation and bounds,
quarantine-store SHA-256 and
open-handle identity checks, and Flutter action-evidence parser. The separate
file-picker action keeps its existing fresh snapshot path.

Four Local Core and three Flutter harmless temporary-fixture regressions add no
binary fixture and execute no candidate content. Verifier step 289, exact-289
validation, Source contract `691/691`, both locked workspace suites, the locked
all-feature release build, Flutter/protocol suites, and definitive `289/289`
pass locally. Root Cargo, standalone Native Cargo, and Flutter lock SHA-256
values remain respectively
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
No tracked lockfile changed. Final-binary legal/notice provenance, production
signing/notarization, enterprise deployment approval, and release approval
remain separate. No package was downloaded, installed, released, or published
during scripting; verification resolved only the already pinned project graph
and installed no machine-wide component.

Exact implementation-head Desktop dispatch `33187853083`, PR `33187857457`,
and push `33187798963` attempt 2 pass dependency/SBOM and complete package gates;
push attempt 1 is retained as concurrency-cancelled rather than a pass. All
publication jobs were skipped. Consolidated artifacts `9693158463`,
`9693163466`, and `9693831394` each pass bounded in-stream review with one
CycloneDX 1.6 lockfile SBOM containing exactly 569 components, six platform
files, and seven independently matching checksum rows. No archive entry was
extracted or executed.

Evidence-head Desktop PR/dispatch artifacts `9694473804`/`9694729048` and
merged-main artifact `9695496543` passed the same bounded non-extracting
8-entry/6-platform/7-checksum/CycloneDX 1.6/569-component validation.
Publication remained skipped. Guarded synchronization changed no lockfile;
independent destination audit passed all eight exact lock hashes before and
after destination exact `289/289`. Checkpoint 2261 is closed without a
dependency or license delta. Final-binary legal/notice provenance, production
signing/notarization, enterprise deployment approval, and release approval
remain separate.

## Checkpoint 2262 Dependency Delta

Checkpoint 2262 adds no dependency, package source, binary fixture, license
class, downloaded artifact, or lockfile change. It uses existing Rust `sha2`,
Serde, UUID, filesystem, bounded static-feature, allowlist, and training-label
code plus existing Dart/Flutter JSON/path validation. The new PowerShell smoke
uses only .NET process, JSON, SHA-256, and temporary-filesystem APIs already
used by repository verification.

All new test bytes are harmless temporary ASCII fixtures, never candidate
executables, and never executed. No live malware or EICAR is included. No
network content, machine-wide component, service/driver registration, Defender
change, release, or publication is required. Locked workspace/release builds,
the local dependency gate, and all source/client/protocol regressions pass with
no tracked lockfile change. Evidence/head and merged-main package/SBOM review,
guarded synchronization, both destination locked workspaces, all-feature
release, the destination dependency gate, and an independent all-eight-lockfile
audit pass. The protected-vault invariant remains read-only. Checkpoint 2262 is
closed; the complete antivirus-hardening goal remains active.

Implementation-head package runs `33206952538` and `33206972034` pass all four
platform builds and consolidation with publication skipped. Their consolidated
artifacts `9700500463` and `9700448185` pass exact checksum inventory and
CycloneDX 1.6 / 569-component review as bounded ZIP streams without extraction.
Evidence-head artifact `9700940590` and merged-main artifact `9701360508` pass
the same bounded 8/6/7/CycloneDX-1.6/569 review; publication is skipped. No
package was extracted, installed, executed, released, or published. Final
signed-binary legal/notice provenance, production signing/notarization,
enterprise deployment approval, and release approval remain separate; this
evidence does not authorize publication.

## Checkpoint 2263 Dependency Delta

Checkpoint 2263 adds no dependency, package source, binary fixture, license
class, network fetch, or lockfile change. Atomic restore no-replace support uses
the already pinned `windows-sys` and `libc` dependencies of
`avorax_platform_security`; Windows, Linux/Android, and Apple calls are selected
only by target configuration. Unsupported targets return a visible error.

Both locked workspace tests, all-feature locked release build, the local
dependency gate, Source `693/693`, and definitive `291/291` passed after the
scripted batch froze. No tracked lockfile changed. Hosted package/SBOM, merge,
and destination evidence remains pending. No package is authorized for
extraction, installation, execution, release, or publication. The complete
antivirus-hardening goal remains active.

Implementation-head package runs `33218432833` and `33218470623` pass all
platform builds, dependency/license evidence, checksum consolidation, and
CycloneDX generation at exact SHA
`db43c763cd2094f467983b5fe9262c847dcf2a2b`; publication skips. Consolidated
artifacts `9704536389` and `9704698986` pass exact bounded
8-root/6-package/7-checksum/CycloneDX-1.6/569-component stream review without
extraction or execution. PR `#135` merges as
`ed0484a605c7f5cc7a62d8c2dd8459ee969cec57`. Closure-head, merged-main,
synchronization, and destination dependency evidence remains pending.

The checkpoint-2263 pending dependency status above is superseded. Merged-main
package run `33221330616` and artifact `9705654475` pass exact-head bounded
8/6/7/CycloneDX-1.6/569 review with publication skipped; guarded synchronization
changes no lockfile, and destination locked builds/tests plus all-eight-lock
audit pass. Checkpoint 2263 is closed without a dependency or license delta.

## Checkpoint 2264 Dependency Delta

Checkpoint 2264 adds no dependency, package source, binary fixture, license
class, network fetch, or lockfile change. Local Core, Guard, and Native Engine
already pin the workspace `avorax_platform_security` crate; the change reuses
its checkpoint-2263 OS no-replace boundary and each owner's existing standard
filesystem, `anyhow`, and hashing facilities.

All scripted fixtures are harmless temporary ASCII and are never executed. No
live malware or EICAR, network content, machine-wide component, Defender
change, service/driver registration, release, or publication is involved.
Both locked workspace suites and the locked all-feature release build pass.
No lockfile is present in the tracked diff. The definitive dependency gate
passes inside exact-292 verification. Evidence-head and merged-main package
runs pass with publication skipped. Consolidated artifacts `9707407539` and
`9707575076` independently pass all seven checksums and CycloneDX 1.6 / 569-
component bounded stream review without extraction or execution. Guarded
synchronization changes no lockfile; destination locked builds/tests and the
all-eight-lockfile audit pass. Checkpoint 2264 is closed without a dependency
or license delta. Final signed-binary notice provenance, production signing/
notarization, enterprise deployment, and release approval remain separate.

## Checkpoint 2265 Dependency Delta

Checkpoint 2265 adds no dependency, changes no pinned version, introduces no
network fetch or executable fixture, changes no license obligation, and requires
no lockfile change. Local Core, Guard, and Native Engine already depend on the
workspace `avorax_platform_security` crate and reuse its established OS
no-replace primitive plus existing standard-library, `anyhow`, UUID, temporary-
directory, and test facilities.

All scripted collision fixtures contain harmless temporary ASCII and are never
executed. No live malware or EICAR, network content, Defender change,
machine-wide component, service/driver registration, protected-vault mutation,
release, or publication is involved. No checkpoint-2265 test ran during the
scripting phase. After batch freeze, both locked workspace suites, locked
all-feature release, the definitive dependency gate inside exact `293/293`, and
an explicit zero-lockfile-diff audit pass locally.

Implementation-head package runs `33233673950` and `33233682629` pass all
platform builds, dependency/license evidence, checksum consolidation, and
CycloneDX generation at exact commit `e4a1bb8`; publication skips. Consolidated
artifacts `9709386808` and `9709458957` pass bounded non-extracting exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component review. Evidence-head
and merged-main package runs also pass with publication skipped. Artifacts
`9709672772`, `9709640926`, and `9709853653` pass the same bounded review
without extraction or execution. Guarded synchronization changes no lockfile;
destination locked tests/builds, the dependency gate, and 8/8 active lockfile
blob comparisons pass. Checkpoint 2265 is closed with no dependency, license,
or network-surface delta. Production signing/notarization, final notice
provenance, enterprise deployment, and release approval remain separate.

## Checkpoint 2271 Dependency Delta

Checkpoint 2271 adds no dependency and requires no lockfile change. The new
fixed `macos-15` workflow route reuses pinned `actions/checkout`, pinned
`dtolnay/rust-toolchain`, Rust `1.96.1`, the existing workspace lock, update-
service crate, shared platform-security crate, and standard-library Unix
permission APIs. No manifest, third-party package, version, source, feature,
runtime download, network content, registry, or license class changes.

Source contract 702, verifier step 299, and the adversarial report harness add
only repository test/evidence logic. Native hosted CI, complete locked tests/
builds, package checksum/SBOM review, eight-lock audit, integration, destination
sync, and closure remain pending until the post-freeze phase. No checkpoint-
2271 test ran during scripting. No live malware, EICAR, Defender change,
installation, service/driver start, release, publication, or protected-vault
mutation occurs. The exact 16,072-file vault has zero pending; complete
antivirus hardening remains active.

Checkpoint 2271 implementation-head CI and package push/PR runs now pass with
publication skipped. Both consolidated artifacts pass bounded in-stream exact
8-root/6-platform/7-checksum/CycloneDX-1.6/569-component validation without
extraction or execution. Eight active lockfiles remain unchanged, and the
commit-bound local audit passes. This confirms zero dependency, lockfile,
runtime-download, network-content, or license-class delta for the checkpoint;
production signing/notarization, final notice provenance, deployment approval,
evidence-head, merge, destination, and closure remain separate.

## Checkpoint 2271 Dependency Closure

Checkpoint 2271 adds no dependency, changes no manifest or lockfile, and adds no
registry, package source, feature, runtime fetch, license class, or notice
obligation. It reuses existing Rust standard-library Unix permission APIs and
the already pinned CI toolchain/actions.

Evidence-head package run `33285885795` and merged-main package run
`33286399375` pass with publication skipped. Consolidated artifacts
`9724549078` and `9724693557` pass bounded in-stream exact
8-root/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components;
neither is extracted or executed. Guarded synchronization, both destination
locked workspaces, locked all-feature release, the dependency gate, and final
8/8 active-lockfile audit pass. The checkpoint dependency and license delta is
exactly zero. Android runtime/build, production signing/notarization, final
notice provenance, enterprise deployment, and release approval remain
separate.

## Checkpoint 2272 Dependency Delta

Checkpoint 2272 adds no dependency and requires no lockfile change. Windows
write-through uses the already enabled `windows-sys` file-system feature. Unix
directory identity and synchronization use Rust standard-library APIs plus the
already pinned `libc` dependency used by the no-replace rename implementation.
No manifest, package version, source, feature, runtime download, network
content, registry, notice obligation, or license class changes.

The additional platform/update fixtures, Source contract, exact 300-step
verifier contract, report-validator scope, and audit documents are repository-
local evidence only. No checkpoint-2272 test ran during scripting; locked
build/test, the dependency gate inside exact `300/300`, and read-only comparison
of all nine tracked lockfiles pass post-freeze. Implementation-head package
push/PR runs `33291944899`/`33291974128` pass dependency/license evidence,
six platform files, seven checksums, and CycloneDX 1.6 with the unchanged 569-
component inventory; publication is skipped. Both consolidated artifacts pass
bounded non-extracting review. Integration, destination, and closure evidence
remain pending with a zero dependency/license delta. No live malware, EICAR,
Defender change, installation, service/driver start, release, publication, or
protected-vault mutation occurs. The exact 16,072-file vault has zero pending;
complete antivirus hardening remains active.

## Checkpoint 2272 Dependency Closure

Checkpoint 2272 adds no dependency, changes no manifest or lockfile, and adds
no registry, package source, feature, runtime fetch, license class, or notice
obligation. It reuses existing Rust standard-library synchronization APIs and
already pinned Windows bindings, toolchains, and actions.

Evidence-head package run `33292650535` and merged-main package run
`33293330096` pass with publication skipped. Consolidated artifacts
`9726612614` and `9726836596` pass bounded in-stream exact
8-entry/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components;
neither is extracted or executed. Guarded synchronization, both destination
locked workspaces, locked all-feature release, dependency gate, and final `9/9`
active-lockfile audit pass. The checkpoint dependency/license delta is exactly
zero. Production signing/notarization, final notice provenance, enterprise
deployment, and release approval remain separate.

## Checkpoint 2270 Dependency Delta

Checkpoint 2270 adds no dependency and requires no lockfile change. The Unix
mode fixtures use only Rust standard-library `PermissionsExt`, the existing
update-service crate, the already pinned internal platform-security crate, and
the existing fixed Ubuntu 24.04 GitHub Actions toolchain. No package, version,
registry, source, feature, network runtime, or license class changes.

No checkpoint-2270 test ran during the scripting phase. Locked builds/tests,
exact-298 dependency gate, hosted package/SBOM comparison, synchronization,
and destination eight-lock audit remain pending. No live malware, EICAR,
fixture execution, Defender change, install, service/driver start, release,
publication, or protected-vault mutation is involved. The vault remains 16,072
files with zero pending, and the complete antivirus-hardening goal remains
active.

Evidence-head/merged-main package runs `33279985653`/`33280845849` pass all
six platform outputs, checksum consolidation, and the lockfile-derived
CycloneDX 1.6 SBOM with 569 components; publication is skipped. Both artifacts
pass bounded in-stream review without extraction or execution. Guarded sync,
both destination locked workspace variants, locked release, dependency gate,
and final eight-lock audit pass with all lockfiles exact. Checkpoint 2270 closes
with zero manifest, lockfile, package, version, registry source, feature,
runtime fetch, dependency, notice-obligation, or license-class delta. Final
signed-artifact notice provenance and production release approval remain
separate.

## Checkpoint 2269 Dependency Delta

Checkpoint 2269 adds direct update-service dependency edges to already locked
`hmac 0.12.1` and `zeroize 1.9.0`. Both exact registry package versions,
checksums, transitive graphs, and existing MIT/Apache-2.0-compatible license
classes were already present in the root lock/SBOM graph. The root lockfile
changes only the `avorax_update_service` dependency list; there is no new
package version, registry source, checksum, runtime download, executable tool,
or network endpoint.

The platform-security crate enables `Win32_Security_Cryptography` and
`Win32_System_Memory` on its existing pinned `windows-sys 0.61.2` dependency;
this adds no package or license class. DPAPI and `LocalFree` are operating-
system APIs, not bundled third-party binaries. No machine-wide component is
installed.

No checkpoint-2269 test ran during the scripting phase. Both locked workspaces
and the locked all-feature release build now pass locally. Exact-297 dependency
gate also passes. Exact implementation head `d44b5c65` passes package push/PR
runs `33271310749`/`33271345821`; untouched consolidated artifacts
`9720317057`/`9720376440` pass bounded in-stream exact 8-root/6-platform/
7-checksum and CycloneDX 1.6/569-component review without extraction or
execution. Publication is skipped. Evidence-head, integration, destination
lock comparison, and closure were pending at implementation head. Evidence
`a933d451` and normal PR `#147` merge `dfcec4fa` pass evidence-head and merged-
main CI/packages. Consolidated artifacts `9720745014`/`9720920236` retain exact
8-root/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components
under bounded review without extraction or execution; publication skips.
Guarded synchronization and destination locked tests/builds pass with all eight
active lockfiles exact: only root `Cargo.lock` contains the intended direct
edges and the other seven are unchanged from the base. This closes checkpoint-
2269 dependency evidence, not final signed-artifact notice/copyright approval.
All fixtures are harmless temporary data; no live malware, network download,
Defender change, protected-vault mutation, release, or publication is involved.
The vault remains 16,072 files with zero pending, and the complete antivirus-
hardening goal remains active.

Checkpoint 2268 definitive local verification passes exact `296/296` in
`673.5s`, including the dependency evidence gate, with report SHA-256
`8b87d0aa72cd0ee51d0c2b6ff9d1ac87dbb392ad19298b4a704a94b2f0f8970c`.
Both PowerShell hosts accept it and reject all `14/14` adversarial report cases.
The three active lock hashes remain exact and no lockfile is modified. Hosted,
integration, guarded-sync, destination, and closure evidence remain pending;
checkpoint 2268 still adds no dependency, license class, network surface, or
notice obligation.

Checkpoint 2268 implementation-head package push/PR runs
`33253626820`/`33253639896` pass exact commit `821d17666`, including dependency/
license evidence, lockfile CycloneDX generation, and checksums; publication is
skipped. Consolidated artifacts `9715355338`/`9715311146` pass bounded non-
extracting/non-executing exact 8/6/7/CycloneDX-1.6/569 review. No manifest,
lockfile, dependency source/version/feature, network runtime, license class, or
notice obligation changes.

## Checkpoint 2268 Dependency Delta

Checkpoint 2268 adds no dependency and requires no lockfile change. The update
service already has an exact internal path dependency on
`avorax_platform_security`; the directory wrapper reuses its existing pinned
Windows `windows-sys`, Linux/Android `libc`, and Apple `libc` OS calls. No crate,
version, registry, source, feature, network runtime, build script, binary blob,
license class, or notice obligation changes.

The six new Rust fixtures use existing `tempfile` development support and inert
ASCII marker bytes only. They never execute fixtures and do not use live
malware, EICAR, a network download, Defender changes, machine-wide components,
service/driver registration, protected-vault mutation, release, or publication.
No checkpoint-2268 test ran during the scripting phase. Locked dependency/build
gates, exact-296 verification, hosted checksum/SBOM review, integration,
synchronization, destination eight-lock audit, and closure remain pending. The
vault remains 16,072 files with zero pending, and the complete antivirus-
hardening goal remains active.

The strict Clippy 1.96 compatibility repair adds three source attributes only;
it changes no manifest, lockfile, dependency, version, feature, serialized API
value, runtime component, license, or notice obligation.

Local locked tests, strict lint, and all-feature release pass with zero tracked
lockfile delta. Flutter resolved only versions already constrained by the
checked-in lockfiles into its user cache; no manifest, dependency, feature,
license class, machine-wide component, or publication changed. Hosted checksum/
SBOM and final eight-lock audits remain pending.

Evidence-head package run `33254651121` and merged-main package run
`33255233172` pass at exact commits `635ccc21` and `99891d10`; publication
skips. Consolidated artifacts `9715575145` and `9715798339` retain exact
8-root/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components
under bounded review without extraction or execution. Guarded synchronization
and destination locked tests/builds pass with all eight active lockfiles exact.
Final audit confirms zero manifest, lockfile, third-party dependency, registry,
source, feature, network-runtime, license-class, or notice-obligation delta.
Checkpoint 2268 is closed; cross-platform runtime, production signing/
notarization, final notice provenance, enterprise deployment, and release
approval remain separate.

## Checkpoint 2266 Dependency Delta

Checkpoint 2266 adds one internal workspace dependency from
`avorax_update_service` to the existing pinned `avorax_platform_security`
crate. The root Cargo.lock records that dependency edge. There is no new
third-party crate, version, registry, package source, feature, downloaded
runtime, or license class; the shared crate already uses the pinned `anyhow`,
`libc`, and `windows-sys` graph documented by prior checkpoints.

The three scripted tests use only temporary harmless ASCII bytes and never
execute candidate content. No live malware, EICAR, network download, Defender
change, machine-wide component, service/driver registration, protected-vault
mutation, release, or publication is introduced. No checkpoint-2266 test ran
during the scripting phase. Locked dependency/build gates, exact-294 verifier,
hosted SBOM/package review, integration, synchronization, and destination
8-lock audit remain pending. The protected vault remains 16,072 files with zero
pending, and the complete antivirus-hardening goal remains active.

After batch freeze, both locked workspace suites, the locked all-feature
release build, strict update-service lint, and all local broad regressions pass.
The two unavailable-`pytest` invocations caused no installation or dependency
change; the dependency-free Source runner passes `697/697`. Git status retains
no manifest or lockfile delta. Exact-295 dependency gate, hosted SBOM/package,
integration, synchronization, destination eight-lock audit, and closure remain
pending; the third-party and license delta remains zero.

After batch freeze, both locked workspace test variants and the locked all-
feature release build pass with the root lockfile's single internal dependency
edge. Full update service `209/209`, strict lint, Source `696/696`, Flutter
`852/852`, and protocols `14/14 + 6/6` also pass. Exact-294 dependency-gate,
hosted SBOM/package, merge, synchronization, destination, and final 8-lock audit
evidence remain pending; no new third-party or license claim is promoted early.

The definitive dependency gate inside exact `294/294` now passes. Final local
audit confirms only one added root-lock dependency line for the existing
internal workspace crate and byte-normalized equality for the other seven
active lockfiles. Hosted SBOM/package, merge, synchronization, destination, and
closure evidence remains pending; the third-party and license delta stays zero.

Implementation-head package push/PR runs `33239451192`/`33239461879` pass
dependency/license evidence, six platform assets, checksums, and CycloneDX 1.6
with 569 components at exact commit `36325846`; publication skips. Both
consolidated artifacts pass bounded non-extracting review. The SBOM retains the
same third-party inventory; evidence-head, merge, merged-main, synchronization,
destination, and closure dependency evidence remains pending.

Evidence-head and merged-main package workflows pass checksums and CycloneDX
1.6 with the same 569-component inventory; bounded artifact inspection performs
no extraction or execution. Guarded synchronization and destination locked
tests/builds pass, and final audit confirms the one intended internal root-lock
edge plus byte-normalized equality for the other seven active lockfiles.
Checkpoint 2266 is closed with no new third-party package, version, source,
runtime fetch, or license class. Android runtime/build, production signing/
notarization, final notice provenance, enterprise deployment, and release
approval remain separate.

## Checkpoint 2267 Dependency Delta

Checkpoint 2267 adds no dependency and requires no lockfile change. The update
service already depends on the existing internal `avorax_platform_security`
crate introduced and pinned in checkpoint 2266; this repair reuses that exact
workspace API. No third-party crate, version, registry, source, feature,
downloaded runtime, network surface, or license class changes.

The five update-service tests and one platform test use only temporary harmless
ASCII bytes and never
execute candidate content. No live malware, EICAR, network download, Defender
change, machine-wide component, service/driver registration, protected-vault
mutation, release, or publication is introduced. No checkpoint-2267 test ran
during the scripting phase. Locked dependency/build gates, exact-295 verifier,
hosted checksum/SBOM review, integration, synchronization, destination 8-lock
audit, and closure remain pending. The vault remains 16,072 files with zero
pending, and the complete antivirus-hardening goal remains active.

The long-path repair following the failed first definitive run adds only
standard-library UTF-16/path handling around the existing pinned `windows-sys`
`MoveFileExW` API. It adds no dependency and no lockfile change. No package was
installed when both optional `pytest` invocations found the module absent.
Platform/update long-path fixtures, Source contract 698, and report contracts
are scripted; no repair test ran during repair scripting. Locked reruns, exact-
295 dependency evidence, hosted SBOM, integration, destination eight-lock
audit, and closure remain pending with zero third-party/license delta.

Post-repair locked workspace tests, locked all-feature release, strict lint,
the definitive dependency gate inside exact `295/295`, and byte comparison of
all eight active lockfiles pass. The package-builder long-path repair continues
to use only standard-library path conversion and the already pinned
`windows-sys` API. No dependency was installed and no manifest, lockfile,
third-party version, source, feature, runtime fetch, or license class changed.
Hosted SBOM/package, integration, synchronization, destination, and closure
evidence remains pending with the dependency and license delta at zero.

Implementation-head package push/PR runs `33247093108`/`33247109041` pass
dependency/license evidence, six platform assets, checksums, and CycloneDX 1.6
with 569 components at exact commit `6e06ac51`; publication skips. Both
consolidated artifacts pass bounded non-extracting review. The SBOM retains the
same third-party inventory; evidence-head, merge, merged-main, synchronization,
destination, and closure dependency evidence remains pending.

Evidence-head package run `33248103915` and merged-main package run
`33248770099` pass at exact commits `2770e5a5` and `7079debe`; publication
skips. Consolidated artifacts `9713666252` and `9713854005` retain exact
8-root/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components
under bounded review without extraction or execution. Guarded synchronization
and destination locked tests/builds pass with all eight active lockfiles exact.
Final audit confirms zero manifest, lockfile, dependency, registry, source,
feature, network-runtime, or license-class delta. Checkpoint 2267 is closed;
Android runtime/build, production signing/notarization, final notice
provenance, enterprise deployment, and release approval remain separate.

## Checkpoint 2273 Dependency Delta

Checkpoint 2273 adds no dependency and requires no lockfile change. Typed
cleanup state, bounded inventory, no-replace moves, HMAC journal verification,
path checks, and temporary-directory tests reuse the Rust standard library plus
the already pinned internal `avorax_platform_security`, `anyhow`, `serde`,
`hmac`, and `sha2` surfaces. No manifest, registry source, version, feature,
network runtime, binary fixture, or license class is added.

No checkpoint-2273 test ran during the scripting phase. Post-freeze locked
build/test, strict Clippy, release, dependency evidence, and no-malware-binaries
gates pass; all nine tracked lockfiles are unchanged. Hosted final-artifact
SBOM/package, integration, destination, and closure evidence remains pending.
No live malware, Defender change, install, service/driver start, release,
publication, or protected-vault mutation occurs. Checkpoint fixtures contain no
EICAR; the inherited verifier's safe text/simulator fixtures run without
Defender integration. The protected vault remains 16,072 files with zero
pending, and the complete antivirus-hardening goal remains active.

Implementation-head package push/PR runs `33298848017`/`33298892093` pass
dependency/license evidence, six platform files, seven checksums, and
CycloneDX 1.6 with the unchanged 569-component inventory; publication is
skipped. Consolidated artifacts `9728478108`/`9728452926` pass bounded review
without extraction or execution. All nine tracked lockfiles remain unchanged,
so the dependency and license delta is still zero. Evidence-head, merge,
destination, and closure evidence remains pending; Android runtime/build,
production signing/notarization, final notice provenance, enterprise
deployment, and release approval remain separate.

## Checkpoint 2273 Dependency Closure

Checkpoint 2273 adds no dependency, changes no manifest or lockfile, and adds
no registry, package source, feature, runtime fetch, license class, or notice
obligation. It reuses existing standard-library filesystem operations, pinned
HMAC/hash support, platform-security helpers, toolchains, and actions.

Evidence-head package run `33299903309` and merged-main package run
`33300730155` pass with publication skipped. Consolidated artifacts
`9728821306` and `9728990794` pass bounded in-stream exact
8-entry/6-platform/7-checksum inventory and CycloneDX 1.6 with 569 components;
neither is extracted or executed. Guarded synchronization, both destination
locked workspaces, locked all-feature release, dependency gate, and final `9/9`
active-lockfile audit pass. The checkpoint dependency/license delta is exactly
zero. Production signing/notarization, final notice provenance, enterprise
deployment, and release approval remain separate.

## Checkpoint 2274 Dependency Delta

Checkpoint 2274 adds no dependency and requires no manifest or lockfile change.
It replaces a standard-library recursive deletion call with existing
standard-library metadata, directory-enumeration, regular-file, and empty-
directory operations plus existing Avorax path/reparse checks. No package
source, feature flag, runtime download, registry dependency, license class, or
notice obligation is added.

Initial post-freeze local strict locked Clippy, both locked workspace variants, locked
all-target/all-feature release, dependency evidence inside exact `302/302`, and
read-only lockfile review pass. All nine tracked lockfiles are unchanged and no
manifest, package, version, source, feature, runtime fetch, dependency, notice,
or license class was added. Final review changed only standard-library path-
payload accounting and added no dependency. Post-repair strict locked Clippy,
both locked workspaces, locked release, and unchanged nine-lock review pass;
final-source definitive verification passes exact `302/302` in `669.6s` and
final read-only audit confirms all nine tracked lockfiles remain unchanged.
The later hosted-coverage repair changes only CI/test/docs and adds no
dependency or lockfile change. Final-source Source `705/705`, exact `302/302`,
dependency gate, and final nine-lock audit pass. Implementation-head Desktop
Packages run `33307588380` passes all platform jobs and consolidation. It
requires six platform files, generates seven checksums, creates CycloneDX 1.6
with 569 lockfile components, and skips publication. GitHub metadata binds all
five artifact bundles to `c91519af`; no bundle was downloaded, extracted, or
executed during review. Evidence-head and merged-main package/SBOM comparison,
destination, and closure evidence remain pending. No live malware,
install, Defender change,
service/driver start, publication, release, or protected-vault mutation is part
of this review; the exact 16,072-file vault remains at zero pending.

Checkpoint 2270 post-freeze strict locked Clippy, both locked workspace test
variants, locked all-target/all-feature release, the dependency gate inside
exact `298/298`, and read-only lockfile-diff checks pass. No manifest or
lockfile changed and no package, version, registry source, feature, runtime
fetch, dependency, notice obligation, or license class was added. Hosted
package/SBOM comparison, integration, destination eight-lock audit, and
closure remain pending.

Implementation-head Desktop Packages push/PR runs `33279152023` and
`33279187604` pass dependency/license evidence, six platform assets, seven
checksums, and CycloneDX 1.6 with 569 components; publication skips. Untouched
consolidated artifacts `9722589339`/`9722639285` pass bounded in-stream review
without extraction or execution. No manifest, lockfile, dependency, version,
source, feature, runtime fetch, notice obligation, or license class changed.
Evidence-head, merged-main, destination eight-lock audit, and closure remain.
