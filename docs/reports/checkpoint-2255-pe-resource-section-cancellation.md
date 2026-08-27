# Checkpoint 2255: PE Resource Section Cancellation

Status: **Scripted, unverified**

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
