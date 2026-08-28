# Checkpoint 2261 - Manual Threat Quarantine Hash Binding

Date: 2026-08-28 (Europe/Brussels)

Status: **Locally verified; hosted and integration evidence pending**

## Risk

Checkpoint 2260 bound automatic quarantine to the exact Native verdict SHA-256,
but the later user-confirmed `Quarantine` action on a visible scan-result row
still sent only path, threat name, and engine. Local Core therefore took a new
current-path hash and could quarantine replacement bytes under stale threat
metadata. The Flutter client also accepted any structurally valid quarantined
record without proving that its original path and SHA-256 matched the request.

This did not bypass confirmation or vault integrity, but it left a destructive
time-of-check/time-of-use gap between a displayed detection and the user's
later action. A changed file must be rescanned, not silently treated as the
earlier detected object.

## Implemented Boundary

- `LocalCoreClient.quarantineThreat` sends the exact `ThreatResult.sha256` in
  the existing strict `quarantine_file` command.
- Local Core requires non-empty text when optional `sha256` evidence is
  present, bounds it to 71 characters, rejects NUL, and passes it into
  `quarantine_selected_file` instead of taking a new path snapshot.
- The existing quarantine store remains the authority for semantic SHA-256
  validation, exact selected/result path equality, same-open-handle hashing,
  single-link policy, open-handle/path identity, copy verification, permissions,
  authenticated metadata, and recovery. Invalid or changed evidence fails
  before vault creation or mutation and requires a rescan.
- Flutter action-success validation now requires a matching original path for
  every new quarantine action and a matching normalized SHA-256 for a
  scan-result threat action. Mismatched success evidence becomes a visible
  failure, so controller state and audit history cannot claim quarantine.
- The separate confirmed `Quarantine file` picker deliberately omits `sha256`.
  It has no prior scan verdict to bind and keeps the existing fresh bounded
  current-file snapshot before crossing the same quarantine-store boundary.

## Verification Evidence

Four benign Local Core regressions share the
`manual_threat_quarantine_binding_` prefix:

1. changed bytes are rejected and preserved without vault creation;
2. matching scan SHA-256 is accepted through real command handling;
3. hash-less confirmed file-picker semantics retain a fresh snapshot;
4. empty, whitespace-only, oversized, NUL-bearing, and semantically malformed
   hashes fail before store mutation.

Flutter IPC regressions prove the scan-result SHA-256 is sent, the standalone
picker omits it, and path/hash-mismatched success records are rejected. All
fixtures are harmless temporary text bytes and are never executed.

The central verifier adds exact step 289,
`local-core manual threat quarantine hash-binding regressions`. The existing
`Flutter manual quarantine IPC tests` step executes the client regressions.
Full-suite validation now requires exactly `289` steps, the dedicated step, and
all four new verified-scope claims. Source contract 691 pins Core/API wiring,
client request and response binding, benign tests, verifier/validator
cardinality and scope, documentation, and dependency honesty.

No checkpoint-2261 test ran during the scripting phase. After the complete
source, test, verifier, validator, and documentation batch was frozen, local
execution produced this evidence:

- Initial focused Local Core execution compiled all four tests; two passed and
  two exposed test-only expectations that omitted the existing `sha256:` record
  prefix. The assertions were corrected without changing production behavior,
  and the rerun passed `4/4`. Flutter manual-quarantine IPC passed `3/3` on its
  first run.
- Initial source contracts passed `689/691`; the two failures were stale
  checkpoint-2260 call-shape and checkpoint-2261 README-marker expectations.
  Those contract assertions were corrected and Source passed `691/691`.
- Broader Local Core quarantine coverage passed `137/137`, complete Flutter
  Local Core IPC diagnostics passed `94/94`, offline scan/quarantine controller
  coverage passed `27/27`, and strict Local Core Clippy passed for all targets
  with all features.
- Locked default and all-feature workspace tests passed. Major crate totals are
  Platform `11/11`, Local Core `572/572`, Native Engine `640/640` plus 21
  intentional isolated-child fixture ignores, and Native signature compiler
  `6/6`. The locked all-feature release workspace build also passed.
- Flutter analyze reported no issues and the complete client suite passed
  `849/849`. Zentor protocol passed `14/14`; Avorax protocol analyze reported no
  issues and its tests passed `6/6`.
- The definitive no-skip/no-Defender verifier passed exactly `289/289` with zero
  failed or skipped steps in `659.6s`, from
  `2026-08-28T15:38:15.7925192Z` through
  `2026-08-28T15:49:15.4412261Z`. Its 213,157-byte report is
  `.workflow/ultracode/avorax-hardening/results/2261-small-threat-mvp-manual-threat-quarantine-hash-binding-report.json`
  with SHA-256
  `0074fd8b38a7edf01c132b4ac3ec0d6a8428ad738ebaaf09c985b4ccb59274a8`.
- Both the verifier-integrated and independent `-RequireFullSuite` validators
  accepted the authentic report under Windows PowerShell 5.1 and PowerShell 7.
  Both hosts rejected a copy missing the required checkpoint scope and a copy
  missing the required step, four expected exit-code-1 rejections. The retained
  untracked result is under
  `.verification/checkpoint-2261-validator-adversarial-20260828-175230-69ba14f94c574e85a94d2d0f721ec6e2/results.json`
  with SHA-256
  `52572e56b14600e371427faa9cf58023ae30ee6bacbc077e943dc8d01f4ebd58`.
- The protected production vault remained exact after verification: 16,072
  files, zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`, `.json`, and
  `.auth`, one `.metadata_auth_key`, and zero pending files.

The first two adversarial-copy preparation commands intentionally stopped
before validation because their raw JSON anchor did not account for escaped
apostrophes; they changed no tracked source and left two empty unique untracked
evidence directories. The corrected raw prefix mutation produced the four
expected validator rejections above.

Hosted exact-head CI/packages, PR/merge, guarded synchronization, and
destination verification remain pending. This checkpoint is locally verified,
not closed, and the complete antivirus-hardening goal remains active.

## Verification Classification

- **Verified locally:** exact threat-row request hash, bounded Local Core IPC,
  store-level hash/path binding, visible client response mismatch rejection,
  standalone fresh-snapshot distinction, benign regressions, full local suites,
  and strict report validation.
- **Partial:** packaged installed UI-to-Local-Core click-through, installed
  cross-identity service behavior, hosted exact-head workflows, integration,
  and destination evidence are not yet complete for this checkpoint.
- **Disabled / blocked:** no checkpoint-2261 control is silently disabled.
  Signed driver/kernel mediation, production signing and calibration, and a
  Defender-replacement claim remain broader blocked product prerequisites.
- **Technically limited:** final path identity check plus rename/removal remains
  a user-mode, non-atomic filesystem sequence and cannot defeat administrators,
  SYSTEM, or kernel compromise.

## Responsibility And Limits

This checkpoint adds no detection engine and changes no hash/signature, native
rule, YARA compatibility, static/PE/archive, heuristic, ML, Authenticode,
allowlist, exclusion, process-observation, or verdict-fusion responsibility. It
binds one explicit response action to evidence already produced by those
engines.

The operation remains user-mode and path-based. It cannot make the last path
identity check and rename/removal one atomic cross-platform filesystem
transaction or defeat administrators, SYSTEM, or kernel compromise. Existing
post-move hashing and authenticated recovery keep detected failure visible.

Exact response-path comparison is an internal IPC consistency check, not a
filesystem identity claim. Local Core returns the original request path while
the store separately enforces open-handle identity. The standalone file-picker
action is not a malware verdict: it quarantines the current selected regular
single-link file only after explicit confirmation and a fresh bounded snapshot.

This is not installed UI/service E2E, kernel mediation, pre-execution blocking,
secure erasure, production detection-rate evidence, or Defender replacement.

## Safety And Dependencies

Checkpoint 2261 adds no dependency, package source, license class, downloaded
runtime, machine-wide component, or lockfile change. It reuses the existing
SHA-256 field, strict JSON IPC, quarantine store, Flutter protocol model, and
bounded temporary-fixture tests.

No live malware, Defender change, machine-wide install, service/driver start,
candidate execution, release, publication, or protected production-vault
mutation occurred. Checkpoint-focused fixtures used harmless temporary bytes;
the definitive suite used only its permitted isolated EICAR test-string smokes
and benign fixtures. `.verification` remains untracked and unstaged. The
complete antivirus-hardening goal remains active.
