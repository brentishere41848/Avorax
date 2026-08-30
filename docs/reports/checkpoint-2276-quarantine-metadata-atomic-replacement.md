# Checkpoint 2276 - Quarantine Metadata Atomic Replacement

Date: 2026-08-30

Status: Locally verified; hosted integration pending

## Purpose

Checkpoint 2276 removes the Local Core quarantine metadata remove-before-
activate interval. Existing status records and authenticated-recovery records
now stage privately and call the shared operating-system existing-file atomic
replacement primitive. New finalization journals, records, authentication
sidecars, and metadata keys retain their atomic no-replace activation path.

No checkpoint-2276 test ran during the scripting phase. Production code, benign
tests, hosted workflow coverage, verifier and validator contracts, source
contracts, operational documentation, threat model, control matrix, blocker
record, and dependency statement were completed before execution began.

## Before And After

Before this checkpoint, Local Core validated an existing JSON record or HMAC
sidecar, removed it, and then activated staged bytes with no-replace. Process
interruption or an ordinary activation error after removal could leave that
name absent.

After this checkpoint, replacement stages and syncs a private adjacent regular
file, repeats parent and link checks, and calls
`avorax_platform_security::replace_existing_file_atomically`. The destination
is never deliberately removed first. Missing destinations and replacement
errors fail visibly; staged cleanup failures retain their full error context.

## Control And Engine Matrix

| Control or engine | Checkpoint 2276 classification | Responsibility and evidence state |
| --- | --- | --- |
| Local Core new metadata creation | Unchanged / verified | Uses atomic no-replace for new journals, JSON records, HMAC sidecars, and the metadata key. |
| Local Core existing JSON replacement | Locally verified | Uses shared existing-file atomic replacement without a pre-delete. |
| Local Core existing HMAC sidecar replacement | Locally verified | Uses the same primitive independently and preserves fail-visible errors. |
| Authenticated JSON plus HMAC pair | Technically limited | Two independent file operations, not one filesystem transaction. A failure between them can produce a mismatched pair that fails authenticated reads and may require manual recovery. |
| Quarantine ingest, rescan, restore, and delete | Unchanged / locally regressed | Existing hash binding, authenticated metadata, journal recovery, no-replace restore, and mutation authorization remain in force. |
| Guard Service quarantine owner | Unchanged | New Guard metadata remains no-replace; this checkpoint does not transfer mutation ownership. |
| Native compatibility quarantine | Disabled / unchanged | Direct Native mutation remains disabled compatibility code. |
| Hash/signature, local rules, static/PE, archive, heuristic, ML, process, and verdict engines | Unchanged | This checkpoint changes persistence availability only and makes no detection-accuracy claim. |
| Allowlists, exclusions, caching, scans, realtime observation, schedules, history, logs, settings, notifications, and UI controls | Unchanged | Existing contracts remain accounted for by the repository control matrix and full verifier. |
| Driver and pre-execution enforcement | Technically limited / unchanged | No driver was installed or started; no kernel or pre-execution claim is added. |
| Microsoft Defender relationship | Technically limited / unchanged | Avorax does not disable, bypass, or replace Defender in this checkpoint. |

## Scripted Benign Test Matrix

| Test | Expected contract |
| --- | --- |
| Existing regular metadata file | Old benign bytes are replaced by staged benign bytes with no temporary or backup residue after success. |
| Missing existing destination | Replacement fails visibly, destination stays absent, and temporary residue is cleaned. |
| Authenticated record pair | Existing JSON and HMAC sidecar both change; the final pair verifies as HMAC-SHA256 v2. |
| Source contract | New-file writes stay no-replace, existing writes call the shared atomic replacement helper, and the obsolete remove helper is absent. |
| Hosted Unix/macOS runtime | Linux and macOS jobs execute the Local Core replacement filter with shell failure propagation. |
| Definitive verifier | The renamed broadened metadata step runs within the exact 302-step suite; the validator requires both verified and limited scope text. |

Fixtures contain harmless temporary ASCII only. They are never executed and do
not contain live malware or EICAR. No live malware is permitted or retained.
Tests may mutate only isolated temporary
directories.

## Limits And Failure Behavior

- Quarantine metadata atomic activation protects only one final destination-name operation at a time.
- The record and authentication sidecar remain separate non-transactional files. Authenticated reads reject a mismatched pair; recovery may require manual review.
- On Windows, an ambiguous failed `ReplaceFileW` operation may preserve an adjacent `.avorax-replace-backup`; backup reservation requires same-volume hard-link support.
- Path and ancestor checks remain point-in-time user-mode checks. They do not defeat administrators, SYSTEM/root, hostile filesystems or storage, or kernel compromise.
- Atomic replacement does not prove durable deletion, secure erasure, package-wide transactionality, installed service identity, driver mediation, pre-execution blocking, signing, deployment, or production detection accuracy.

## Local Verification

Post-freeze focused checks pass Source `708/708`, the three new Local Core
fixtures, all 21 workspace `quarantine_metadata_` tests, Local Core quarantine
`143/143`, Guard quarantine `51/51`, platform `28/28`, strict changed-crate
Clippy, formatting, both verifier/validator parsers, and diff checks. The first
format check required formatting only. Early source-contract runs exposed four
stale historical/count/wording contracts, then one historical marker and one
accidentally broadened marker; each failed visibly, was repaired, and the final
complete source run passed.

Broad local verification passes strict locked workspace Clippy, both complete
locked Rust workspace variants with 1,809 executed tests, 21 intentional child-
fixture ignores, and zero failures, the locked all-target/all-feature release
build, Flutter analysis and `852/852`, Zentor protocol `14/14`, and Avorax
protocol `6/6`. All nine dependency lockfiles remain unchanged.

The definitive repaired-source no-skip/no-Defender verifier passes exact
`302/302` in `667.1s`.
Its 233,119-byte report SHA-256 is
`1736eddd87c9ee03a0d1a2860ea5760b3fdb8ecf6a90ba7960018660e3a8c024`.
PowerShell 5.1 and 7 both accept the authentic report and reject all `52/52`
hostile cases across 26 unique mutations. The 57,480-byte adversarial result
SHA-256 is
`c6d91cdf381b8055b1a0d0204dd1dc430234b2b1aa55385bcd514bae826cb4c0`.

The final local audit passes 15 modified plus one added path, zero deletions,
nine unchanged lockfiles, zero staged `.verification` paths, zero product
processes, pending files, or temporary roots, and the exact protected vault.
Its repaired-source 3,086-byte JSON SHA-256 is
`a8c307c729835c02bdbbc2e8bfa3bacca560b01a546ce3db2f8184bcd67d0552`.
Hosted exact-head CI/package evidence, normal PR integration, guarded
destination synchronization, and destination verification remain required.

The first exact-head hosted macOS run failed visibly in the authenticated-pair
fixture because macOS temporary storage reached `/var` through the `/private/var`
symlink while production quarantine correctly rejects every linked ancestor.
The repair does not relax production validation: only that test now creates its
owned temporary directory inside the non-linked CI checkout, and Source 708
requires that route. Post-repair local and exact-head hosted evidence must be
regenerated before integration credit.

Post-repair focused checks pass `3/3`, Source `708/708`, strict Clippy,
formatting, and diff checks. The complete locked all-target/all-feature Rust
suite passes with 1,809 executed tests, 21 intentional child-fixture ignores,
and zero failures. The regenerated definitive, adversarial, and final-audit
evidence above is authoritative for the repaired source; exact-head hosted
evidence is the next required phase.

## Exact-Head Hosted Evidence

Repaired implementation head `0be467e61cf775fc4812b804ee6ac00fcf0e2bbf`
passes Avorax CI `33328100995` with all six jobs successful. The macOS 15 arm64
runtime executes the repaired authenticated-pair fixture successfully; Ubuntu,
Rust, Flutter/protocol, security/performance, and branding/copy jobs also pass.

Desktop Packages push `33328099560` and PR `33328101027` each pass package
contracts, Windows MSI/setup EXE, Linux DEB/tar, macOS x64/arm64 DMGs, and
consolidation; each publication job is explicitly skipped. Consolidated
artifacts `9737011004` and `9737035093` are 132,853,231 and 132,852,641 bytes
with hosted SHA-256 digests
`3db64ce970f7ba198015f23bc10a4b49c8d2302d67864f46ae57ab9071954742`
and
`89181b15a1aa498e22e824fca33fcb513abe14a4f5b2190b538996fbfaf72a0e`.
No artifact was downloaded, extracted, installed, or executed. Evidence-head
checks, normal merge, guarded destination synchronization, and destination
verification remain required before checkpoint closure.

The protected vault baseline remains read-only: 16,072 files, zero directories,
4,522,733 bytes, 5,357 each `.avoraxq`, `.json`, and `.auth`, one
`.metadata_auth_key`, and zero pending. This checkpoint must not mutate it.

No machine-wide component was installed, no service or driver was started, no
Defender setting was weakened, no artifact was downloaded or executed, no
release was published, and no direct-main push occurred. The complete
antivirus-hardening goal remains active after checkpoint 2276.
