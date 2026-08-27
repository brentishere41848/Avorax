# Checkpoint 2255: PE Resource Section Cancellation

Status: **Closed**

## Objective

Checkpoint 2255 makes PE resource RVA-to-file-offset mapping cooperatively
cancellable. A syntactically admitted PE can declare a `u16` section count, so
the prior linear PE resource section rescan could inspect up to 65,535 validated
section records without consulting the scan job's cancellation callback.

## Implementation

- `resource_directory_entry_count_with_cancellation` receives the exact
  static-analysis callback before resource-directory handling.
- `rva_to_file_offset_with_cancellation` checkpoints before its first candidate,
  before every next at-most-4,096 PE resource section entries, and once after an
  exhausted mapping search.
- Callback errors propagate unchanged through `parse_pe_with_cancellation`.
  They cannot become a zero resource count, an unmapped-RVA fallback, later
  PE/string evidence, `StaticAnalysis`, or a published file verdict.
- Existing resource count, truncation, overflow, and unmapped-RVA behavior is
  retained. The parser does not execute or load the benign PE-shaped fixtures.

## Scripted Tests

Three benign in-memory regressions cover interruption at the second section
chunk, unchanged valid resource-count semantics, and exact parser-level error
propagation before later analysis. The focused filter is
`pe_resource_section_cancellation_`.

Verifier step 284 is `native-engine PE resource-section cancellation
regressions`. The report validator requires the step, both verified-scope
sentences, both technical-limit sentences, and exact 284-step cardinality.
Source contract 685 binds the implementation, tests, verifier, validator, and
audit documents.

## Responsibility

The PE resource analyzer maps the declared resource directory into validated
in-sample section data and validates/counts its top-level entries. It does not
execute resources, establish publisher reputation, block processes, quarantine
files, or independently publish a verdict.

## Limits

Cancellation is cooperative, not preemptive. One at-most-4,096-section mapping
chunk may complete before the next checkpoint. The PE header's `u16` section
count and the already validated in-sample section table bound work; they are not
wall-clock deadlines. This checkpoint does not add kernel mediation,
pre-execution blocking, or a Microsoft Defender replacement claim.

## Safety And Dependencies

Only benign in-memory PE-shaped byte arrays are scripted. No live malware is
downloaded, unpacked, retained, or executed. Checkpoint 2255 adds no dependency,
feature, package source, license class, runtime installation, or lockfile change.

No checkpoint-2255 test has run during this scripting phase. Verification must
start only after this complete implementation, test, contract, and documentation
batch is scripted.

## Focused Local Evidence

After the scripting boundary, the exact checkpoint filter passes `3/3` and the
complete PE resource filter passes `6/6`. Source contracts pass exact `685/685`.
Windows PowerShell 5.1 and PowerShell 7 each parse verifier and validator `2/2`;
workspace formatting and `git diff --check` pass.

Two `python -m pytest` attempts did not execute tests because neither discovered
Python runtime included pytest. The documented dependency-free runner was used
without installing anything and passed first the 674 custom contracts and then
the required default 685-contract suite. An initial dual-host parser wrapper did
not forward its path argument and is uncredited; the corrected absolute-path
wrapper passes under both hosts.

## Broad Local Evidence

Both `cargo test --workspace --locked -- --test-threads=1` and its
`--all-features` variant pass. Platform Security passes `9/9`, updater `203/203`,
Local Core `546/546`, Native Engine `638` with 21 documented isolated child
fixtures ignored, and the signature compiler `6/6`. Flutter analysis is clean
and Flutter passes `847/847`; Zentor protocol passes `14/14` and Avorax protocol
passes `6/6`, with clean Dart analysis.

The first Avorax protocol analysis did not execute valid analysis because its
worktree-local `.dart_tool` package configuration was absent. CI-equivalent
`dart pub get` restored only project-local resolution; the rerun passes and no
lockfile changed. Workspace formatting, Native locked/offline check, strict
Native/Local/Guard Clippy with `-D warnings`, and full locked release workspace
build all pass.

The root Cargo, Native Cargo, and Flutter lock SHA-256 values remain
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.

## Definitive Local Evidence

The from-start verifier passes exact `284/284`, zero failed/skipped steps, and
zero non-null step errors in `695.9s`, from
`2026-08-27T20:56:32.9276713Z` through
`2026-08-27T21:08:08.9069723Z`. The 204,626-byte schema-2 report is
`.workflow/ultracode/avorax-hardening/results/checkpoint-2255-small-threat-mvp-verification-report.json`
with SHA-256
`ff8411143e5437e15266c87e789c02d3d5c151a701543651aab3f7e297de7d3b`.
It contains exactly one checkpoint step, starts with `local-core safe simulator
scan reporting`, ends with `Dependency evidence gate`, runs Rust and Flutter,
and leaves the optional Defender/EICAR host probe disabled.

Built-in and separate independent PS5/PS7 full-suite validators accept the
report. PS5 rejects a 283-step copy missing the checkpoint step, and PS7 rejects
a separate 284-step copy missing the PE resource verified scope. A combined
mutation/cleanup wrapper and a later native cleanup wrapper were policy-rejected
before execution and are uncredited. Split create/reject steps passed; the two
exact regular files were deleted through the file-edit tool and their verified
empty owned directory was removed non-recursively, leaving zero residue.

Post-verification checks find zero Avorax/Zentor processes and preserve the
protected vault at exactly 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
unknown or reparse entries. Checkpoint 2255 is **verified locally**. Hosted
exact-head evidence, normal integration, guarded destination synchronization,
and destination verification remain open; the full antivirus goal stays active.

## Hosted Implementation-Head Evidence

Exact implementation commit `67f2d26c73c56087f6e602b299803326f1bbd7b5`
passes PR `#119` Avorax CI run `33117139169`. Rust Local Core/Guard/update/API,
Flutter/protocol, security/protection/performance, Unix quarantine-permission,
and branding/copy jobs all succeed. PR Desktop Packages run `33117139213` and
push run `33117116754` pass package contracts, Windows x64 MSI/EXE, Linux x64
DEB/tar, macOS arm64/x64 DMG, and consolidation. Prerelease publication is
explicitly skipped and no release is created.

GitHub reports PR consolidated artifact `9665343047` as 132,103,528 bytes with
SHA-256 `a21eda3625a88c2abfdda9b9ef440bd34c337eb74e398fab707828e473fa9c1e`.
The independently downloaded untouched ZIP matches both values. Push artifact
`9665714554` is 132,138,884 bytes and independently matches GitHub SHA-256
`2251c3834f63054493a6749d731397a3d1a63cedab4fc1159fd573654fbf0f6c`.
Bounded non-extracting review of both archives verifies exactly eight safe root
entries, six platform packages, seven matching checksum targets, and one
CycloneDX 1.6 lockfile SBOM with 569 components and 569 unique non-empty
`bom-ref` values. It finds zero unsafe, duplicate, encrypted, or link entries.

No artifact was extracted, installed, or executed. The exact temporary ZIPs
and their empty owned directories were removed; one policy-rejected cleanup
command did not execute and is uncredited, after which checked .NET exact-file
cleanup succeeded. `.verification` and the protected vault remained untouched.
Evidence-head CI/packages, normal PR integration, merged-main evidence, guarded
destination synchronization, and destination verification remain required.
The complete antivirus-hardening goal remains active.

## Hosted Integration And Package Evidence

Evidence commit `72112939726259d46c85937d282890957ad7b7c2` passes
PR `#119` exact-head CI run `33119480645` and Desktop Packages run
`33119480624`. All CI jobs and package contracts, Windows, Linux, both macOS,
and consolidation jobs pass; publication is skipped. Consolidated artifact
`9666268817` is 132,098,189 bytes and its untouched download matches SHA-256
`22ae2a11015c514912db39a6983cd2c736ba62f4cd54aacb35a6c1cf843ac787`.
Bounded non-extracting review passes exact 8-root/6-package/7-checksum and
CycloneDX-1.6/569-unique-component validation.

PR `#119` merged normally as
`d1e2b0a34bf866a09c9029e2f88502203d76fda9`. Merged-main CI run
`33120649064` and Desktop Packages run `33120649123` pass on that exact merge;
publication is skipped. Main artifact `9666709785` is 132,096,338 bytes and
its untouched download matches SHA-256
`4a8d41e2db3a964e36e39c3357cbebbed8967856e0048e43c27f65bfa0978c6c`.
The same bounded review passes exact 8/6/7/CycloneDX-1.6/569 inventory with
zero unsafe, duplicate, encrypted, or link entries. No artifact was extracted,
executed, installed, released, or published; exact owned temporary data was
removed.

## Guarded Destination Synchronization

The exact delta from checkpoint-2254 closure
`59d7640ca9b262bf412328606824c2eeea36e093` to merge
`d1e2b0a34bf866a09c9029e2f88502203d76fda9` contains 12 modified, one added,
and zero deleted paths. A strict read-only byte preflight stopped before writes
because nine old destination files had mixed CRLF/LF bytes rather than Git's
fully filtered CRLF output. Normalized comparison proved all nine content-exact
to the old commit; three other files were byte-exact and the added path absent.

All 13 merge-filtered payloads were then written to exclusive same-directory
staging files, byte-verified, and activated through explicit same-directory
backups with terminating errors and reverse-order rollback. Independent review
passes `13/13` target-byte equality, 12 modified plus one added and zero
deleted, with zero staging or backup residue. No unrelated destination file was
changed.

## Destination Verification

Destination focused checks pass PS5/PS7 parser `2/2` each, formatting, Source
`685/685`, and PE resource cancellation `3/3`. With bounded test-profile
settings, the no-skip/no-Defender from-start destination verifier passes exact
`284/284`, zero failed/skipped steps and zero non-null step errors, in `667.7s`
from `2026-08-27T22:23:02.6592399Z` through
`2026-08-27T22:34:10.4152839Z`. Its 195,968-byte schema-2 report is
`.workflow/ultracode/avorax-hardening/results/checkpoint-2255-destination-small-threat-mvp-verification-report.json`
with SHA-256
`853db9a32a3e18f1b8704d9965bf60ab56f52f89f2c280a828278ac73cfade58`.
It records exactly one checkpoint step, starts with `local-core safe simulator
scan reporting`, ends with `Dependency evidence gate`, runs Rust and Flutter,
and leaves the optional Defender/EICAR host probe disabled. Built-in and
separate independent PS5/PS7 full-suite validators pass.

Final audit passes all `13/13` destination blobs, the three exact lock hashes,
zero Avorax/Zentor processes, zero synchronization residue, and the protected-
vault invariant: 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one metadata key, and zero unknown, pending, temp,
or reparse entries. `.verification` was never staged or deleted.

Checkpoint 2255 is closed through focused, broad, adversarial, hosted,
merged-main, synchronized, and destination evidence. Cooperative cancellation
is not a deadline or preemptive stop. Installed cross-identity service/IPC,
production calibration/signing, signed-driver/kernel mediation, pre-execution
blocking, and Defender replacement remain limited, blocked, or unclaimed. The
complete antivirus-hardening goal remains active.
