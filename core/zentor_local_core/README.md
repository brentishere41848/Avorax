# Avorax Local Core

Avorax Local Core is the Rust desktop helper for selected-path malware scanning, quarantine metadata, allowlist validation, and future selected-path watching.

It communicates with Flutter through stdin/stdout JSON commands. It does not bind to the network.

## Commands

- `health`
- `scan_file`
- `scan_folder`
- `quick_scan_selected_paths`
- `full_scan`
- `cancel_scan`
- `quarantine_file`
- `restore_quarantine_item`
- `delete_quarantine_item`
- `list_quarantine`
- `add_allowlist_entry`
- `remove_allowlist_entry`
- `list_allowlist`
- `start_watch`
- `stop_watch`

Every scan command requires a canonical lowercase hyphenated UUID in `job_id`.
The caller must retain that ID and send it with `cancel_scan`. Local Core echoes
the ID in progress/cancel evidence and observes only the bounded strict JSON
token for that exact job. Job IDs are same-user capabilities, not
cross-identity authentication or pre-execution blocking.

## ClamAV

The scanner provider tries `ZENTOR_CLAMAV_CLAMSCAN`, `clamdscan`, `clamscan`, and a bundled `ClamAV\clamscan.exe` next to `zentor_local_core.exe`. If no local ClamAV engine exists, it returns `EngineUnavailable`. It never reports clean unless a real engine scan completes.

The Windows MSI bundles the ClamAV runtime beside the app. Signature database updates are explicit; if ClamAV cannot load a local database, the scan returns an error instead of a fake clean result.

## Quarantine

Infected files are moved to the Avorax quarantine folder, renamed with `.avoraxq`, stripped of executable bits where supported, and paired with JSON metadata. Legacy quarantine records remain readable.

`quarantine_file` accepts an optional bounded `sha256`; when present it must
be non-empty. A confirmed action from a scan-result row must send that row's
exact SHA-256; changed or mismatched
content fails before vault mutation and requires a rescan. A separately
confirmed manual file-picker request omits `sha256` because it has no prior
verdict and takes a fresh bounded snapshot of the selected current file.

Checkpoint 2262 hardens manual trust mutation IPC. `add_allowlist_entry` now
requires `confirmed=true`; callers with a visible scan verdict may also provide
that row's bounded `sha256`, which must match the freshly hashed regular file
before the entry is persisted. A standalone confirmed add without earlier
verdict evidence intentionally takes a fresh current-file hash.

`label_detection` requires `confirmed=true`, an exact bounded `sha256`, and a
supported user label. Local Core hashes before and after static-feature
extraction and persists nothing if the file differs from the scan verdict or
changes during collection. Success includes compact `evidence` containing the
persisted label ID, file SHA-256, user label, previous verdict, and local store
path. This checkpoint 2262 contract is same-user stale-verdict defense; it is
not cross-identity authorization, a kernel file lease, or pre-execution
blocking.

## Tests

```powershell
cargo test
```

## Checkpoint 2263 Restore Activation

Restore still verifies authenticated metadata, payload SHA-256, destination
absence, and path ancestors before staging. Final activation now uses the
shared atomic no-replace platform boundary: Windows `MoveFileExW` without
replace flags, Linux/Android `RENAME_NOREPLACE`, and Apple `RENAME_EXCL`.
A competing destination is preserved and failure remains visible; unsupported
platforms do not fall back to replacement-capable rename. Checkpoint 2263 does
not remove the documented privileged path-ancestor race or add kernel/driver
enforcement.

## Checkpoint 2264 Quarantine Ingestion

Quarantine ingestion in Local Core and Guard now calls the same shared atomic
no-replace platform boundary before the existing exclusive verified copy
fallback. A destination created after preflight is preserved; if atomic rename
and fallback both fail, both causes remain in the visible error. Cross-filesystem
or unsupported atomic rename can still use the safe exclusive-copy path.

The Native direct-quarantine compatibility implementation receives the same
repair but remains disabled in production. Local Core and Guard remain active
mutation owners. Final-name atomicity does not create an immutable source lease,
cross-identity authorization, kernel mediation, or pre-execution blocking.
Checkpoint 2264 focused collision, broader quarantine, strict changed-crate
lint, locked workspace, release-build, and safe-smoke evidence passes locally.
The definitive verifier passes exact `292/292`; hosted and synchronized-
destination evidence remains pending.

## Checkpoint 2265 Quarantine Metadata Activation

Local Core now activates new quarantine finalization journals, metadata records,
and authentication sidecars with the shared operating-system atomic no-replace
primitive. Status and authenticated-recovery updates keep deliberate replacement
semantics: the validated old file is removed before the staged file is activated
with no-replace. A competing destination appearing during that gap is preserved
and causes a visible failure instead of being overwritten.

Guard uses the same boundary, and Native compatibility code receives matching
regression coverage while remaining disabled. Atomicity covers one final name;
the journal, record, and authentication sidecar are not a multi-file transaction.
Checkpoint 2265 code, harmless collision tests, exact-293 verifier/validator,
source contract, and documentation are scripted. No checkpoint-2265 test ran
during the scripting phase. After the batch froze, focused `3/3`, broader
quarantine, strict changed-crate lint, both locked workspaces, release, safe
smoke, UI/protocol regressions, Source `695/695`, and exact definitive
`293/293` pass locally. Hosted and synchronized-destination evidence remains
pending. Implementation-head CI and cross-platform package builds now pass at
`e4a1bb8` with publication skipped; evidence-head, merge, merged-main, and
synchronized-destination proof remain open.

## Checkpoint 2276 Existing Metadata Replacement

Checkpoint 2276 supersedes the checkpoint 2265 remove-before-activate behavior
for existing Local Core status and authenticated-recovery metadata. Existing
JSON records and HMAC sidecars are privately staged and passed to the shared
operating-system atomic existing-file replacement primitive without first
removing the destination name. New journals, records, sidecars, and the metadata
key still use atomic no-replace activation.

The record and HMAC sidecar are replaced independently, not transactionally. A
failure between them remains visible because authenticated reads reject a
mismatched pair and manual recovery may be required. Windows can retain an
adjacent `.avorax-replace-backup` after an ambiguous failure and backup
reservation requires same-volume hard links. Post-freeze local evidence passes
the new `3/3`, workspace metadata `21/21`, complete quarantine `143/143`, strict
lint, both locked workspace variants, and definitive `302/302`. Hosted and
synchronized-destination evidence remains pending; no broader mutation
authority, pre-execution, driver, Defender-replacement, or detection-accuracy
claim is made.

Repaired implementation head `0be467e` passes hosted macOS and Ubuntu runtime,
all six CI jobs, and both cross-platform package workflows with publication
skipped. Evidence-head, merge, and synchronized-destination proof remain open.

## Checkpoint 2277 Authenticated Metadata Update Recovery

Existing JSON/HMAC status updates now prepare one strict bounded
`{id}.update.pending` envelope authenticated under a dedicated HMAC domain. It
binds exact previous and proposed bytes before mutation. Successful updates
verify the proposed pair before removing the journal; while the journal exists,
recovery rolls any exact previous/proposed combination back to the previous
authenticated pair.

Missing or unknown pair bytes, journal tampering, malformed/oversized content,
links, conflicts, or active locks fail visibly and preserve evidence. Competing
updates cannot overwrite the journal and immutable threat evidence cannot be
changed through this path. Checkpoint 2277 was fully scripted before tests and
now passes focused, broad, full-workspace, release, and definitive local
verification. This is rollback recovery rather than two-file atomicity; payload/status
coordination for restore/delete remains outside this checkpoint.

Checkpoint 2277 is now closed through evidence-head and merged-main
Windows/Ubuntu/macOS CI, all desktop package targets, guarded exact 17-path
zero-delete synchronization, destination focused checks and `303/303`, dual-
host hostile-report rejection, and final blob/lock/process/residue/vault audit.
The restore/delete payload-status crash boundary remains open.

## Checkpoint 2278 Authenticated Action Recovery

Restore and delete now reserve one bounded `{id}.action.pending` intent before
their first lifecycle mutation. Its dedicated-domain HMAC binds exact old/new
metadata, action/phase, controlled adjacent restore staging, and, once staged,
the platform file identity. Delete drives any exact old/new JSON/HMAC pair
forward and removes a verified remaining payload. Prepared restore abandons
only an untouched intent; restore-staged accepts exactly one identity-, hash-,
size-, and single-link-matched staging file or destination, then resumes
no-replace activation, terminal metadata, payload cleanup, and final checks.

Malformed, oversized, linked, active, conflicting, unknown, tampered,
duplicate, missing, or identity-mismatched evidence fails visibly and remains
for review. No checkpoint-2278 test ran during the scripting phase. Focused
action recovery passes `15/15`, complete Local Core `614/614`, definitive
verification `304/304`, and dual-host adversarial rejection `34/34` locally;
hosted, integration, and destination evidence is pending.
The phase journal is not a power-loss-proof multi-file transaction, and a crash
after unbound staging but before identity authentication intentionally needs
manual review. This adds no secure-erasure, driver/pre-execution, Defender-
replacement, installed-identity, production-accuracy, or whole-product claim.

Checkpoint 2278 closure passes exact-head and merged-main Windows/Linux/macOS
CI, guarded destination synchronization, destination action recovery `15/15`,
Source `710/710`, strict Clippy, definitive `304/304`, and `34/34` hostile
validator rejection. The final audit confirms 17 exact merge blobs, nine
unchanged locks, 32 backups, zero residue, and the unchanged vault. These results
verify bounded action replay; the documented power-loss, privileged-actor,
driver, Defender, installed-identity, and production-accuracy limits remain.

Checkpoint 2279 inserts authenticated `RestoreReserved` between prepared intent
and completed staging. Local Core creates and hardens an exclusive empty stage,
captures its stable file identity, writes that identity to the HMAC action
journal, and only then copies payload bytes through the same open handle under
the 1 GiB cap. Recovery discards exact identity-bound incomplete or invalid
copies while retaining the quarantine payload, promotes an exact completed copy,
and rejects phase skips, identity changes, hard links, or early destinations.
Prepared recovery may remove only an exact empty ordinary single-link controlled
stage; ambiguous unbound bytes remain for manual review. No checkpoint-2279 test
ran during the scripting phase. Source contract 711 and exact verifier step 304
are scripted; installed identity, power-loss-proof transactionality, secure
erase, driver/pre-execution, Defender replacement, and production accuracy
remain outside this user-mode boundary.

After freeze, action recovery passes `25/25`, quarantine passes `167/167`, the
complete crate passes `624/624`, strict Clippy passes, and the exact verifier
passes `304/304`. This is local user-mode crash-recovery evidence only; hosted
cross-platform, installed identity, and the limits above remain unchanged.
