# Checkpoint 2264 - Quarantine Ingest No-Replace

Status: **Definitively verified locally; hosted integration pending**

Checkpoint 2264 prevents quarantine ingestion from replacing an opaque payload
that appears after destination preflight. It changes no detector, verdict
threshold, allowlist, exclusion, update trust rule, service state, or Defender
configuration.

## Risk

Local Core, Guard, and the disabled Native compatibility quarantine path first
checked that the opaque destination was absent and then called ordinary
filesystem rename. On Unix, ordinary rename may replace a destination created
between those operations. That could destroy an existing vault artifact before
the exclusive copy fallback had a chance to reject it.

## Scripted Implementation

- All three ingest paths call
  `avorax_platform_security::rename_file_no_replace` for final-name movement.
- Windows uses zero-flag `MoveFileExW`; Linux/Android use
  `renameat2(RENAME_NOREPLACE)`; Apple targets use
  `renamex_np(RENAME_EXCL)` through the checkpoint-2263 shared boundary.
- A cross-filesystem, unsupported-primitive, or other atomic-rename failure
  enters the existing exclusive `create_new` copy path. That fallback retains
  bounded hashing, source identity/link checks where production owners already
  enforce them, destination verification, and source removal only after
  verification.
- If both strategies fail, the returned error retains both the atomic rename
  error and exclusive verified copy error. A collision is not converted into
  success.
- Local Core and Guard remain the active production mutation owners. Native
  direct quarantine remains disabled compatibility code, but its dormant path
  receives the same destination-safety repair so it is not unsafe if reused.

## Scripted Verification

- Three harmless runtime fixtures create distinct source and competing
  destination bytes, call the exact movement helper, require rejection, and
  prove both files remain byte-for-byte unchanged.
- The definitive verifier adds `quarantine ingest atomic no-replace
  regressions` using workspace filter `quarantine_ingest_no_replace`.
- Full-suite validation requires exactly `292` steps, the named step, two
  verified-scope claims, and three technical-limit claims.
- Source contracts forbid the old direct ingest rename in each production
  range and pin helper wiring, fallback diagnostics, fixtures, verifier,
  validator, documentation, dependency, and safety claims.

No checkpoint-2264 test ran during the scripting phase. Execution began only
after the complete batch was frozen. Focused and broad local results are
recorded below; definitive, adversarial, hosted, merge, and synchronized-
destination evidence remains pending.

## Local Verification

- `cargo fmt --all -- --check` passed after rustfmt-only correction of the new
  Local Core closure. PowerShell 7 and Windows PowerShell 5.1 parsed the
  verifier, validator, and adversarial validator script (`3/3` each).
- Source contracts pass exact `694/694`.
- The first focused compile failed visibly because all three calls omitted the
  required owner label on `rename_file_no_replace`; the implementation was
  repaired with fixed Local/Guard/Native labels. The corrected focused filter
  passes `3/3`.
- The broader `quarantine` filter passes Platform `8/8`, API `3/3`, Guard
  `50/50`, Local Core `139/139`, and Native `38/38`.
- Strict all-feature Clippy passes for the three changed crates. The broader
  workspace Clippy command is not claimed as passing: untouched `services/api`
  is rejected by Rust 1.96 for `items_after_test_module` in `main.rs` and
  `routes.rs`, and `enum_variant_names` in `models.rs`.
- Both `cargo test --locked --workspace -- --test-threads=1` and its
  `--all-features` variant pass. `cargo build --locked --workspace --release
  --all-features` also passes.
- The safe temporary quarantine/restore smoke passes and preserves its
  deliberately competing destination. Flutter analysis reports no issues and
  Flutter passes `852/852`; Zentor protocol analysis plus `14/14` and Avorax
  protocol analysis plus `6/6` pass.
- The no-skip/no-Defender definitive verifier passes exact `292/292`, zero
  failed/skipped, in `659.4s`. Its 217,855-byte report SHA-256 is
  `1c2ecc9ab68b9baf0b1da1240dc524759b18484df5aaeb29a4c973315c3a3d18`.
- Integrated and independent Windows PowerShell 5.1 and PowerShell 7 validators
  accept the authentic report. Both hosts reject each missing required ingest
  step, verified scope, and technical-limit scope mutation (`6/6` rejections).
  The retained adversarial result SHA-256 is
  `f48d9038b494bb4dc6b107747e7f9d7470e1a6b9db79e9525197ee80bbd2fe3d`.
- Final local state audit finds zero Avorax/Zentor processes, no retained safe
  smoke root, no lockfile diff, and the exact protected-vault invariant stated
  below.

The initial PowerShell 5.1 parser wrapper also failed before parsing because
the outer PowerShell command expanded inner variables. Corrected quoting then
passed `3/3`; this was a harness invocation failure, not a product pass.

## Hosted Implementation-Head Evidence

- Exact implementation commit
  `2d1148ebd90bdc017f45040539f2d78e90475984` is the head of PR `#137`.
  Avorax CI PR run `33226157011` passes all five jobs, including Unix runtime,
  Rust/Flutter/protocol, security, dependency, false-positive, and performance
  gates.
- Desktop Packages push/PR runs `33226139023` and `33226157015` pass package
  contracts, Windows MSI/setup EXE, Linux DEB/tar, macOS x64/arm64 DMGs,
  consolidation, checksums, and lockfile SBOM. Both publication jobs are
  skipped.
- Consolidated artifacts `9707188077` and `9707168993` are 132,300,566 and
  132,339,432 bytes with SHA-256 values
  `3df7955dd5367cb47428edd089227d31f4bb325189ac3207a7329076932d05fd`
  and
  `892d559c95ca57b6ef0a372d110a6f253120a20ddbd1159d320624ae87dde099`.
  Bounded stream inspection, without extraction or execution, passes exact
  eight root entries, six platform files, seven checksum targets, and a
  CycloneDX 1.6 SBOM with 569 components for both bundles. Retained validation
  result SHA-256 is
  `576bc69c42d9e788fab4d47f8ea2c01d5157b0ce81dbeaff14f422a74ad669e5`.

Evidence-head CI/packages, merge, merged-main, guarded synchronization, and
destination verification remain pending.

## Verification Matrix

| Control / engine responsibility | Current state | Required evidence |
| --- | --- | --- |
| Local Core quarantine ingest | **Definitively verified locally** | Collision fixture, broader quarantine filter, strict changed-crate lint, safe quarantine smoke, both locked workspaces, and exact-292 verifier pass; hosted evidence remains. |
| Guard quarantine ingest | **Definitively verified locally** | Collision fixture, broader Guard quarantine tests, strict changed-crate lint, workspace regressions, release build, and exact-292 verifier pass; hosted Windows evidence remains. |
| Native compatibility quarantine ingest | **Disabled / definitively verified locally** | Collision fixture, Native quarantine/default/all-feature coverage, strict lint, release build, and exact-292 verifier pass. The feature remains disabled in production; hosted cross-target evidence remains. |
| Existing exclusive verified copy fallback | **Locally re-verified** | Existing hash/link/identity/exclusive-create coverage, broader filters, locked workspaces, and safe smoke pass. |
| Error reporting | **Definitively verified locally** | All three collision tests expose both atomic rename and fallback contexts while preserving source and destination bytes; exact validator scope is adversarially guarded. |
| Signature/hash/local-rule/YARA/static/PE/archive/heuristic/ML/Authenticode/process/verdict engines | **Unchanged / definitive local regression green** | Both locked workspace variants, release build, Flutter/protocol suites, and exact-292 verifier pass; hosted evidence remains. |
| Cross-filesystem or unsupported atomic rename | **Safest viable fallback** | Exclusive verified copy may succeed; otherwise both errors remain visible. |
| Ancestor/source races against privileged actors | **Technically limited** | Final-name no-replace is atomic, but user-mode path/ancestor/source checks are point-in-time. |

## Safety And Limits

Fixtures contain ordinary harmless ASCII and are never executed. No live
malware or EICAR is downloaded, unpacked, retained, or run. Defender is not
changed or weakened. No machine-wide component is installed, no service or
driver is started, and no package, release, or publication is authorized.

Final-name no-replace does not provide a kernel-held immutable source lease or
a handle-relative transaction over every ancestor. Administrators, SYSTEM/root,
hostile filesystems, and kernel compromise remain outside this user-mode
guarantee. It is not pre-execution blocking or Defender replacement.

The protected production vault remains read-only and must retain **16,072
files, 0 directories, 4,522,733 bytes**, with 5,357 each `.avoraxq`, `.json`,
and `.auth`, one `.metadata_auth_key`, and zero pending files. `.verification/`
remains untracked and must never be staged or deleted.

## Dependency Delta

Checkpoint 2264 adds no dependency, package source, binary fixture, license
class, network fetch, or lockfile change. It reuses the pinned
`avorax_platform_security` dependency already present in all three crates.
Locked builds pass and no lockfile appears in the tracked diff. Hosted SBOM and
synchronized-destination reviews remain pending.

The complete antivirus-hardening goal remains active. Completion of checkpoint
2264 must not be represented as completion of the whole antivirus project.
