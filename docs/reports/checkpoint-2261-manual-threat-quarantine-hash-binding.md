# Checkpoint 2261 - Manual Threat Quarantine Hash Binding

Date: 2026-08-28 (Europe/Brussels)

Status: **Closed; implementation integrated and destination verified**

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

## Hosted Implementation-Head Evidence

Implementation commit
`0f223dacf412876f3c0da27b3207fc23aa605741` is the exact head of PR `#131`.
Hosted evidence at that head is:

- Avorax CI pull-request run `33187857398` passed all five jobs: security,
  protection, and performance gates; Rust Local Core and Guard; branding and
  copy; Unix quarantine permissions; and Flutter client/protocol.
- Desktop Packages workflow-dispatch run `33187853083` and pull-request run
  `33187857457` passed package contracts, Windows x64 MSI/setup EXE, Linux x64
  DEB/tar, macOS x64/arm64 DMGs, and consolidation/checksum jobs.
- Automatic Desktop Packages push run `33187798963` attempt 1 was cancelled by
  the workflow's `cancel-in-progress` concurrency group when the explicit
  dispatch started. This is retained as cancelled evidence, not reported as a
  pass. The same exact push event and head passed as attempt 2, including all
  platform, MSI administrative-extraction, dependency/SBOM, and consolidation
  jobs.
- `Publish desktop beta prerelease` was skipped in the dispatch, PR, and
  successful push attempt. No package or release was published.
- Consolidated artifacts `9693158463` (dispatch, 132,214,694 bytes),
  `9693163466` (PR, 132,198,418 bytes), and `9693831394` (push attempt 2,
  132,269,927 bytes) have exact outer SHA-256 values respectively
  `ac42a24680f72996ffe29ba3c4b45542a028eb74a096917f7f6b0693dc1c086c`,
  `445195d629f5a06af300bd369784f98cae45f1f7b75bf522326988d47a5b24a6`,
  and
  `87958194aa4103cd42ff4b436e4471487e3e3d04fd3393329f98bb5507f6ff37`.
- Bounded in-stream review under untracked `.verification` passed for all three
  untouched ZIP streams: exactly eight safe root entries, six platform release
  files, seven independently matching SHA-256 rows, and one CycloneDX 1.6
  lockfile SBOM with 569 components per bundle. Nothing was extracted,
  installed, or executed. The three-artifact result SHA-256 is
  `b87c19f39bc9e75fb42c5caf4c02fccb7cc28a12108d5262ad8e22a931a5f3a5`.

## Evidence-Head And Integration Evidence

Evidence commit `b66aaed3388139c19ff76385bf5ec5cc06adf219` passed
Avorax CI run `33191586704`, Desktop Packages PR run `33191586726`, and
Desktop Packages dispatch run `33191612118`. Publication was skipped.
Consolidated artifacts `9694473804` (PR, 132,227,078 bytes, SHA-256
`0fd7ea2cb25c0cf0bbc8dd1c214f4473ec139e64bfa1638b8dd120d2b7fb9799`)
and `9694729048` (dispatch, 132,717,251 bytes, SHA-256
`f5293bece97c4399ee0b40f1b185e2924d3e0fa77565183b5b2e717642b6350c`)
both passed non-extracting 8-root-entry, 6-platform-file, 7-checksum,
CycloneDX 1.6/569-component validation. The retained validation result SHA-256
is `4aeeb7626e6ad0887c8814b6cbe875b401faecb93c0bbd6327f1c1ed906bf421`.

PR `#131` merged normally as
`1877bbabaeb1fd6e6169d1ca3f92a9438185b3d4`, with exact parents
`aff5ca943856c02cce51ef39c952c41de89b6ac7` and
`b66aaed3388139c19ff76385bf5ec5cc06adf219`. Merged-main Avorax CI
`33194037678` and Desktop Packages `33194037671` passed; publication was
skipped. Merged artifact `9695496543` is 132,207,174 bytes with SHA-256
`97fe2aacffd4da4bb403b7a335c4de083404542ee218937c7a563b32d622b570`
and passed the same bounded non-extracting validation. Its retained validation
result SHA-256 is
`aba548de268cff08b47574b9c25c4258c74c359c2832ea72af30f1cb44d8d352`.

## Guarded Synchronization And Destination Evidence

Read-only preflight proved all 18 merge paths were at the exact old base or
absent, with zero product processes and the exact protected-vault invariant.
The first synchronization attempt stopped before activation because its
untracked nested backup path exceeded the Windows path-length limit. It left
three owned pending sidecars and no changed product file; those exact sidecars
were removed, the evidence backup was retained, and no protected-vault path was
touched. A shortened flat backup layout then passed guarded synchronization:
18 paths, 17 modified, one added, zero deleted. The apply report SHA-256 is
`2d98a915ccab5f074ac529dd89b49bac890aa9a61334e6d8b0dc69988ea92182`.
Independent post-sync evidence passed 18/18 raw and normalized path matches,
8/8 lockfiles, zero residue, zero product processes, and the exact vault. Its
report SHA-256 is
`a011021674318dd58a081b5adc1b6e3361a5a4fad1fd40025f4d2ff1cf81b1a7`.

The first broad destination `cargo test --locked --workspace` orchestration is
not credited as a pass: after Platform `11/11` and Local Core `572/572`,
Microsoft Defender removed the generated Native test harness and Cargo failed
with Windows error 225. Read-only Defender evidence classified that generated
binary as `Trojan:Win32/Wacatac.C!ml`, severity 5, inactive, and
`DidThreatExecute=False`; Defender also blocked the suite's permitted temporary
EICAR file. Defender was not weakened and nothing was restored or allowlisted.

Equivalent unchanged-target coverage was then run without hiding the failure:

- isolated Native default and all-feature runs each passed `640/640`, with 21
  intentional child-fixture ignores; Native compiler passed `6/6`;
- the locked workspace excluding Native passed Platform `11/11` and Local Core
  `572/572`; its all-feature variant passed, and the locked all-feature release
  workspace build passed;
- Flutter analyze reported no issues and all `849/849` tests passed; Zentor
  protocol passed `14/14`, while Avorax protocol analyzed cleanly and passed
  `6/6`;
- the definitive destination verifier, with no skip or Defender switch, passed
  exact `289/289`, zero failed/skipped, in `651.5s` from
  `2026-08-28T17:59:47.8947923Z` through
  `2026-08-28T18:10:39.4388652Z`. Its 204,507-byte report is
  `.workflow/ultracode/avorax-hardening/results/2261-destination-small-threat-mvp-manual-threat-quarantine-hash-binding-report.json`
  with SHA-256
  `4b7f531dd61c0c7c00496ad331061d50161c9a6487f6b7ecd1046bb5e8bdcf25`;
- integrated and independently rerun Windows PowerShell 5.1 and PowerShell 7
  `-RequireFullSuite` validators accepted that destination report.

The final independent read-only audit again passed all 18 synchronized path
hashes, all eight lockfile hashes, zero synchronization sidecars, zero product
processes, and the protected vault at 16,072 files, zero directories,
4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
`.metadata_auth_key`, and zero pending. Checkpoint 2261 is closed. The complete
antivirus-hardening goal remains active.

## Verification Classification

- **Verified:** exact threat-row request hash, bounded Local Core IPC,
  store-level hash/path binding, visible client response mismatch rejection,
  standalone fresh-snapshot distinction, benign regressions, local and
  destination full-suite evidence, normal PR integration, merged-main CI and
  package evidence, and guarded zero-delete synchronization.
- **Partial:** packaged installed UI-to-Local-Core click-through and installed
  cross-identity service behavior remain outside this source/runtime proof.
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
