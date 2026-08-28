# Checkpoint 2257: File Discovery Memory Bounds

Status: **Verified locally through definitive regression**

## Objective

Checkpoint 2257 closes the two explicit Local Core discovery gaps left by
Checkpoint 2256: aggregate stored path payload had no byte ceiling, and final
priority sorting could not observe cancellation while it was running.

## Implementation

- Quick scans retain their 5,000-file cap and add an 8 MiB encoded path-payload
  cap. Full and custom scans retain their 250,000-file cap and add a 128 MiB
  encoded path-payload cap.
- Every accepted path is counted with `OsStr::as_encoded_bytes` and checked
  addition before the `PathBuf` is retained. Limit exhaustion or arithmetic
  overflow stops discovery, records a bounded incomplete-scan diagnostic, and
  contributes to `CompletedWithErrors`; undiscovered entries cannot be clean.
- The old stable `sort_by_key` is replaced by stable priority buckets. Each
  path is classified once, within-priority order is preserved, and the exact
  job callback runs before every at-most-128-path bucket and after completion.
- Cancellation during priority bucketing reassembles all classified and
  unclassified paths so the cancelled report can count every discovered path
  as unscanned. An arbitrary callback error propagates before Native Engine
  initialization or scan-result publication.

## Scripted Tests And Contracts

Five benign `file_discovery_memory_` regressions cover fail-visible path-byte
exhaustion, checked-add overflow, stable priority order, cancellation with
complete path retention, and arbitrary callback-error propagation. Fixtures
are ordinary text or in-memory path values and are never executed.

Definitive verifier step 286 is `local-core file-discovery path-memory and
priority cancellation regressions`. The independent report validator requires
that step, exact `286/286` cardinality, the new verified boundaries, and the
remaining technical limits. Source contract 687 binds production source,
tests, verifier, validator, and every checkpoint audit document.

## Limits

The 8 MiB and 128 MiB limits bound only aggregate encoded payload bytes of
retained paths. They exclude `Vec`, `PathBuf`, and allocator overhead and do not
bound directory enumeration, metadata I/O, elapsed time, kernel work, or file
content bytes. Priority bucketing transiently owns the source path vector and
destination bucket allocations.

Cancellation remains cooperative. One entered operating-system directory or
metadata operation, one at-most-128-entry discovery chunk, or one at-most-128-
path priority-classification chunk can complete before the next callback. This
checkpoint adds no installed service, driver, kernel mediation, pre-execution
block, or Microsoft Defender replacement claim.

## Safety And Dependencies

Only benign fixtures are scripted. No live malware is downloaded, unpacked,
retained, or executed. Checkpoint 2257 adds no dependency, feature, package
source, license class, runtime installation, machine-wide component, or
lockfile change.

No checkpoint-2257 test ran during the scripting phase. The complete source,
test, verifier, validator, contract, and documentation batch was scripted first;
focused and broad checks began only after that boundary. Local definitive and
adversarial evidence now pass. Hosted exact-head evidence, normal integration,
guarded destination synchronization, and destination verification remain
required before checkpoint closure. The complete antivirus-hardening goal
remains active.

## Broad Local Evidence

Standard and all-feature Rust workspace tests pass with `--locked`; Native
Engine reports 638 passed and 21 intentionally ignored isolated child fixtures
in each variant, while Local Core reports `556/556`. The locked all-feature
release workspace build passes.

Flutter passes `847/847` and analyzes cleanly. Zentor and Avorax Dart protocol
suites pass `14/14` and `6/6`, with both analyzers clean. Routine Flutter/Dart
resolution leaves every lockfile unchanged. Hosted, integration, guarded-sync,
and destination evidence remain open; the complete antivirus-hardening goal
remains active.

## Definitive Local Evidence

The definitive verifier passes exact `286/286` with zero failed or error steps
in `643.3s`. Defender/EICAR host integration remained disabled by default; the
suite used only the repository's benign fixtures and safe EICAR handling. The
canonical 207,098-byte report has SHA-256
`b989a2cc9d0d42a0a7404e6d778c97617ad449af8ddef520c6b732d3ce3d1833`.

Independent strict validation accepts that report under both Windows
PowerShell 5.1 and PowerShell 7. Three structured adversarial copies were then
created: 285 steps, missing checkpoint verified scope, and missing checkpoint
technical-limit scope. Both hosts rejected all three with exit code 1; all
owned mutation files were removed and residue is zero.

Root Cargo, Native Cargo, and Flutter lockfiles retain SHA-256
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
The final read-only state check again found zero product processes and the exact
protected-vault invariant. `.verification` remained untracked and untouched.

## Hosted Implementation-Head Evidence

Exact implementation commit `c3e24b3c976febc732b04338f6bd8142a88411a4`
passes PR `#123` Avorax CI run `33136854819`, PR Desktop Packages run
`33136854871`, and push Desktop Packages run `33136852044`. All five CI jobs,
both package-contract jobs, all eight platform build jobs, and both
consolidation jobs pass. Both prerelease-publication jobs are intentionally
skipped.

The untouched push consolidated artifact `9672583268` is 132,204,612 bytes
with SHA-256
`24f342d72764884ebdf260cd7830e77c6d6f13f209d864220603cd0379d2ac00`.
The untouched PR artifact `9672658548` is 132,126,515 bytes with SHA-256
`290c18f8812003886c977195f96670e66ec8ae6af96aaed2b51c578cb6918e51`.
Both local downloads match GitHub artifact metadata exactly.

Bounded, non-extracting review of each artifact passes exactly eight safe root
entries, six packages, seven matching checksum targets, CycloneDX 1.6, and 569
non-empty unique component references, with zero duplicate, unsafe, encrypted,
directory, or link entries. No package was extracted, installed, or executed.
The exact owned review directory and both downloaded ZIPs were removed non-
recursively, leaving zero residue.

Hosted implementation-head evidence is complete. Exact evidence-head hosted
runs, normal PR merge, merged-main evidence, guarded destination
synchronization, and destination verification remain open. `.verification` and
the protected vault remain untouched; the complete antivirus-hardening goal
remains active.

## Focused Local Evidence

After the scripting boundary, PS5 and PS7 each parse verifier and validator
`2/2`. The initial rustfmt check reported four mechanical line-wrap differences;
`cargo fmt --all` applied only those changes and the repeat check plus
`git diff --check` pass. Source contracts pass exact `687/687`.

The new filter passes `5/5`; the overlapping discovery, walker, Full Scan, and
scan-cancellation filters pass `10/10`, `15/15`, `3/3`, and `8/8`. Full Local
Core passes `556/556` in `43.97s`, and strict all-target/all-feature Local Core
Clippy passes with warnings denied.

Read-only state checks find zero Avorax/Zentor processes and preserve the vault
at exactly 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
`.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero unknown, pending,
temporary, or reparse entries. `.verification` remains untracked and untouched.
Checkpoint 2257 is **verified locally through definitive regression**. Hosted
evidence, integration, guarded synchronization, and destination proof remain
open; the complete antivirus-hardening goal remains active.
