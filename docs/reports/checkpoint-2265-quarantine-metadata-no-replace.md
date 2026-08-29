# Checkpoint 2265 - Quarantine Metadata No-Replace Activation

Date: 2026-08-29

Status: **Verified locally and at implementation head; integration pending**

## Risk

Local Core, Guard, and the disabled Native quarantine compatibility path staged
metadata in exclusive temporary files, checked that the final name was absent,
and then used ordinary `fs::rename`. On Unix, that final rename can replace a
competing journal, metadata record, or authentication sidecar created after the
absence check. Local Core's intentional status/recovery replacement also had a
remove-to-activation interval in which a new competing object could be replaced.

## Scripted Implementation

- Local Core new journal, record, and authentication-sidecar activation now
  calls the shared operating-system no-replace primitive.
- Local Core status/recovery replacement still removes the validated prior file,
  then uses the same no-replace activation. A destination appearing in that gap
  is preserved and causes a visible failure.
- Guard uses the same no-replace boundary for new quarantine metadata.
- Native's disabled compatibility metadata writer uses the same boundary, while
  production mutation ownership remains with Local Core and Guard.
- Unsupported operating systems fail visibly through the shared helper instead
  of falling back to replacement-capable rename.

## Scripted Verification

- Three harmless Rust collision fixtures exercise the exact Local Core, Guard,
  and Native metadata activation wrappers. They require both staged fixture
  bytes and competing destination bytes to remain unchanged and require the
  no-replace error to remain visible.
- The focused workspace filter is
  `cargo test --workspace quarantine_metadata_no_replace -- --test-threads=1`.
- The Python source contract accounts for all three owners, the Local Core
  remove-before-no-replace order, absence of ordinary final activation rename,
  verifier/validator coupling, audit coverage, safety, and dependencies.
- The definitive verifier gains one required step. The exact full-suite schema
  advances from 292 to 293 steps and rejects missing scope or limitation text.

No checkpoint-2265 test ran during the scripting phase. Focused and broader
execution, exact-293 definitive verification, hosted evidence, integration, and
guarded destination synchronization remain pending until the scripting batch is
complete.

## Local Verification

After the complete scripting batch froze, formatting and source contracts pass
at `695/695`. The focused metadata collision filter passes `3/3`; broader
quarantine coverage passes Platform `8/8`, API `3/3`, Guard `51/51`, Local Core
`140/140`, and Native `39/39`. Strict all-feature Clippy passes for the three
changed crates. Both locked workspace suites, the locked all-feature release
build, safe quarantine/restore smoke, Flutter analysis and `852/852` tests, and
protocol analysis/tests `14/14 + 6/6` pass.

The no-skip/no-Defender definitive verifier passes exact `293/293` with zero
failed or skipped steps in `659.4s`. Its 219,352-byte report has SHA-256
`d526b2548ed90a62fd7e6a23b4383d393bbe878ce4488d5073fcbce8c5bf3a94`.
Independent PowerShell 5.1 and PowerShell 7 validation accepts the authentic
report. Eight content mutations are each rejected by both hosts (`16/16`);
the adversarial result SHA-256 is
`69a633727adf7f33b5b0f2215ca9c49fed84f6f7cd95b73ba4d35b99c98ca4d1`.

Final local audit finds no tracked lockfile change, product process, or retained
checkpoint smoke root. The protected vault read-only inventory remains exact.
Hosted exact-head CI/packages, normal PR integration, guarded destination
synchronization, and a complete destination rerun remain pending.

## Hosted Implementation-Head Evidence

Implementation commit `e4a1bb81dda30b9b9d4377a8f1f43e1f968c8713` is
the first head of PR `#139`. Avorax CI run `33233682635` passes all five jobs.
Desktop Packages push run `33233673950` and PR run `33233682629` each pass
package contracts plus Windows x64 MSI/EXE, Linux x64 DEB/tar, and macOS arm64/
x64 DMG builds. Their publication jobs are skipped.

Consolidated artifacts `9709386808` and `9709458957` are 132,317,128 and
132,858,881 bytes with SHA-256 values
`9ddc8d0251921b8e6dfd19289cad0ff70268f0f13e7f67c1fd748e5f51ac8401`
and
`0adf6846efcb82dfd06ee9d3e80b97b102223737252e175c6ba405e74c424a4e`.
Both pass bounded non-extracting, non-executing review with exact 8 root
entries, 6 platform files, 7 checksum targets, and CycloneDX 1.6 / 569
components. Evidence-head reruns, normal merge, merged-main evidence, guarded
destination synchronization, and destination verification remain pending.

## Verification Matrix

| Control / engine | Scripted state | Required execution evidence |
| --- | --- | --- |
| Local Core new metadata activation | Locally verified | Focused collision, broad quarantine, workspaces, release, and definitive verifier pass |
| Local Core status/recovery replacement | Locally verified; technically limited | Recovery/status regressions, collision, and source contract pass; remove gap remains |
| Guard new metadata activation | Locally verified | Focused collision, Guard regressions, workspaces, release, and definitive verifier pass |
| Native compatibility metadata activation | Regression verified; production-disabled | Focused collision, Native regressions, workspaces, release, and definitive verifier pass |
| Competing destination preservation | Locally verified | All three harmless fixtures preserve staged and destination bytes with visible error |
| Verifier/report schema | Verified locally at exact 293 | Both hosts accept authentic evidence and reject all 16 mutation/host cases |
| Hosted/package evidence | Implementation head verified; integration pending | CI plus push/PR packages pass at `e4a1bb8`; evidence-head and merged-main reruns remain |
| Original-tree synchronization | Pending | Guarded exact-path, zero-delete sync and destination rerun |

## Safety And Limits

No live malware is used, downloaded, unpacked, retained, or executed. Fixtures
contain harmless ASCII only and are never executed. Defender is not weakened;
no machine-wide install, service/driver start, direct-main push, release, or
publication is authorized.

No operation in this checkpoint targets `C:\ProgramData\Avorax\Quarantine`.
Its protected invariant remains 16,072 files, zero directories, 4,522,733
bytes, 5,357 each `.avoraxq`, `.json`, and `.auth`, one
`.metadata_auth_key`, and zero pending files.

No-replace is per final destination name. Journal, record, and authentication
sidecar files are separate non-transactional files. Local Core replacement has
a deliberate remove-to-activation gap. Authenticated recovery can detect and
repair incomplete state but cannot make the set atomic. Path and ancestor checks
remain point-in-time user-mode checks and do not defend against administrators,
SYSTEM/root, hostile filesystems, or kernel compromise. This is not
pre-execution blocking, kernel mediation, or a Defender-replacement claim.

Checkpoint 2265 is one bounded hardening checkpoint. The complete
antivirus-hardening goal remains active after this checkpoint.

## Dependency Delta

Checkpoint 2265 adds no dependency, changes no dependency class or network
surface, and requires no lockfile change. All three crates already depend on the
workspace `avorax_platform_security` helper established by earlier checkpoints.
License obligations and pinned dependency versions are unchanged.
