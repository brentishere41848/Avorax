# Checkpoint 2277: Quarantine Metadata Update Recovery

## Status

Implementation, harmless runtime fixtures, cross-platform workflow wiring,
definitive verifier/validator contracts, source contracts, and documentation are
scripted. No checkpoint-2277 test ran during the scripting phase. Focused and
full local verification started only after this complete batch was frozen and
now passes. Hosted, integration, and destination evidence remains required.

The complete antivirus-hardening goal remains active. This checkpoint does not
claim production-complete malware prevention, Defender replacement, kernel or
pre-execution blocking, secure erasure, installed-service validation, or a
two-file atomic transaction.

## Problem

Checkpoint 2276 removed Local Core's existing-file remove-before-activate gap,
but the quarantine JSON record and its HMAC sidecar still activate as two
independent files. Termination between those replacements can expose one old
file and one proposed file. Authenticated reads reject that mismatch, but there
was no bounded automatic recovery evidence for the intended update.

## Scripted Design

Local Core now prepares one `{id}.update.pending` JSON envelope before replacing
either existing metadata file. The envelope:

- has a versioned, strict `deny_unknown_fields` schema;
- is bounded to 1 MiB before allocation/read completion;
- carries the exact previous and proposed JSON bytes;
- carries the exact previous and proposed HMAC-sidecar bytes;
- binds all body fields with a domain-separated HMAC using the existing private
  metadata-authentication key;
- uses UUID-adjacent exclusive staging plus atomic no-replace activation;
- is re-read under an exclusive lock and authenticated before mutation;
- preserves a final journal that fails post-write byte or semantic validation;
- retains the exclusive journal lock through successful journal removal;
- rejects changes to immutable threat evidence through the update path.

Journal presence means the proposed metadata update is not committed. A normal
update verifies the previous pair, atomically replaces the JSON file, confirms
the expected intermediate JSON/HMAC state, atomically replaces the HMAC file,
verifies the proposed authenticated pair, and only then removes the journal.
An in-process failure attempts the same authenticated rollback before returning
the original error. A second update cannot overwrite an active journal.

## Recovery Matrix

Recovery authenticates the journal before trusting its embedded versions. It
then accepts only these exact current pair states:

| Current JSON | Current HMAC | Recovery action |
| --- | --- | --- |
| previous | previous | verify previous pair and remove journal |
| proposed | previous | replace JSON with previous bytes, verify, remove journal |
| previous | proposed | replace HMAC with previous bytes, verify, remove journal |
| proposed | proposed | roll both files back to previous bytes, verify, remove journal |

The proposed/proposed state is rolled back because journal presence means
`replace_record` never committed the update to its caller. Missing JSON or HMAC,
unknown current bytes, a conflicting finalization journal, malformed or
oversized JSON, an unknown field, an invalid ID/path, invalid embedded record
semantics, a changed immutable field, a symlink/reparse point, hard-link
ambiguity, an active lock, or HMAC tampering fails visibly without guessing or
deleting the journal evidence.

## Scripted Harmless Fixtures

All fixtures use isolated temporary directories and inert ASCII bytes. Nothing
is executed. The Local Core filter covers:

- rollback from all four exact previous/proposed pair combinations;
- tampered journal authentication;
- a differently serialized but semantically unchanged authenticated record;
- writer-side preservation of an authenticated but semantically invalid journal;
- unknown JSON bytes and unknown HMAC bytes;
- a missing pair member;
- an oversized journal;
- Unix linked-journal rejection without touching the external target;
- an active journal lock blocking concurrent list/recovery;
- an existing journal blocking a competing update;
- immutable threat-evidence mutation rejection.

The platform-security fixture admits only bounded
`{id}.update.pending[.tmp-{token}]` names and rejects empty IDs, sidecar-like
lookalikes, empty staging tokens, dotted IDs, and separator-bearing names.
Ubuntu and macOS CI run both the exact platform artifact-name fixture and the
Local Core recovery filter with single-threaded, fail-fast commands. The Windows
Rust job already runs the complete locked platform and Local Core suites.

## Verifier Contract

The definitive no-skip/no-Defender verifier adds exact step 303:

```text
quarantine metadata update recovery regressions
```

The report validator requires exactly `303` ordered steps, the new step, and
the verified and technically-limited scope strings. Source contracts account
for production ordering, schema/HMAC/path bounds, the state matrix, all harmless
fixtures, both hosted jobs, current verifier count, documentation, and the zero
dependency delta.

## Local Verification After Freeze

Focused execution passes formatting, dependency-free Source `709/709`, the
platform artifact-name fixture, Local Core recovery `13/13`, workspace metadata
`35/35`, Local Core quarantine `156/156`, strict workspace Clippy, and both
PowerShell parser hosts. Both complete locked Rust variants pass with `1,823`
executed tests, zero failures, and 21 intentional isolated child-fixture
ignores. The locked all-target/all-feature release build, Flutter analysis and
`852/852`, Zentor protocol `14/14`, and Avorax protocol `6/6` pass.

The no-skip/no-Defender verifier passes exact `303/303` in `680.4s`, with zero
failed, skipped, or error-bearing steps and both Rust and Flutter enabled. Its
234,669-byte report SHA-256 is
`2dc118bcb78cbc1b1e7b1573ee368088868fb8085e2e9ed64e8363fa530a213c`.
PowerShell 5.1 and 7 accept the authentic report and reject all `62/62`
adversarial cases across 31 unique mutations. The 57,277-byte adversarial
result SHA-256 is
`4d97b5ab0676a14b56fca5a60ff36e4915ddc4233663226dd948c621610cd6e2`.
The final 2,201-byte local audit passes the exact 17-path diff, nine unchanged
lockfiles, zero process/pending/temp residue, and protected-vault invariant; its
SHA-256 is
`7c1cac6557848e5bd5fb9c80eeecf7b2e4c7378116e2fa4ec1274b35d38e5190`.

Hosted evidence still must be tied to an exact pushed commit. Package workflows may
build but publication must remain skipped. Artifacts are metadata-inspected
only; they are not downloaded, executed, installed, released, or published.
Integration uses a normal reviewed PR merge, followed by guarded destination
synchronization with exact blob preconditions, backups, zero deletes, and
read-only vault verification.

## Safety Invariants

- No live malware is downloaded, created, unpacked, executed, or retained.
- Checkpoint fixtures use no EICAR text and only harmless isolated bytes.
- No service or driver is installed or started.
- Microsoft Defender and Windows security remain enabled and unchanged.
- `.verification` remains untracked and is never staged or deleted.
- `C:\ProgramData\Avorax\Quarantine` remains read-only to this work.
- The protected vault baseline remains 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending artifacts.

## Honest Limits

The journal provides authenticated bounded rollback semantics while its file is
present. JSON and HMAC remain separate non-transactional files. This is not a
general transaction manager and does not make restore/delete payload movement
atomic with status metadata. A crash outside metadata-pair replacement may
still leave a duplicated restored file or payload/status cleanup requiring a
separate recovery design or manual review.

Journal unlink durability, directory-entry persistence, and atomic rename or
replacement depend on truthful local filesystem and storage behavior. Windows
can preserve `.avorax-replace-backup` after an ambiguous failure and backup
reservation requires same-volume hard-link support. Path, ancestor, open-file,
and journal-lock checks are point-in-time user-mode evidence; administrators,
SYSTEM/root, hostile filesystems/storage, and kernel compromise remain outside
the guarantee. Unknown or missing state is deliberately preserved for manual
review rather than guessed.

## Dependency Delta

Checkpoint 2277 adds no dependency and requires no lockfile change. It reuses
existing `serde`, `serde_json`, `hmac`, `sha2`, UUID staging, file-locking, and
shared platform-security primitives already licensed and pinned by the
repository.
