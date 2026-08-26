# Checkpoint 2237 - Process Observation Native Wiring

## Objective

Connect the existing app-lifetime process snapshot telemetry to the Native
file-plus-behavior process-start API without fabricating Guard telemetry,
executing candidate content, or claiming process blocking. Keep observation,
file I/O, diagnostics, findings, and verifier cardinality bounded and explicit.

## Scripted Implementation

- Windows Flutter collection already obtains at most 256 CIM rows with PID,
  parent PID, executable path, and command line. Flutter retains a 2,048-scalar
  head/tail command sample and Local Core retains at most 4,096 scalars.
- `ProcessStartEvent` now carries `command_line_truncated`. Native rejects a
  truncation claim without command evidence and preserves caller-reported
  omission when producing zero-weight limited-inspection evidence.
- Local Core submits only valid, nonzero-PID, non-allowlisted observations with
  command evidence and an exact security-sensitive executable identity. It
  attempts at most 16 Native file-plus-behavior reviews per snapshot.
- Process-start executable reads have a separate hard 16 MiB total-I/O limit.
  Metadata over the limit fails before opening; growth over the limit fails
  during hashing. Ordinary explicit file scans retain full-file hash behavior.
- The Native engine is initialized lazily on the first eligible observation.
  Attempted, completed, failed, and limit-skipped reviews are counted.
  Diagnostics are control-sanitized, capped at 16 entries and 4,096 characters,
  returned over IPC, parsed by Flutter, and routed through the existing visible
  process-snapshot failure event/state path.
- Native results merge into the bounded 64-finding snapshot set. Behavior-only
  review can surface suspicious evidence; probable/confirmed file evidence is
  labeled honestly. Trusted publisher/file evidence cannot erase a positive
  observed behavior review score, but behavior still cannot trigger mutation.
  Raw command lines are never copied into finding reasons.
- Local Core ignores Native action recommendations. It does not stop, kill,
  block, quarantine, restore, delete, or execute a process/file. This is
  post-start review only.

## Scripted Coverage

Rust fixtures cover upstream truncation preservation, relevant/exact executable
selection, zero PID and inconsistent telemetry rejection, exact 16-review and
16-diagnostic limits, exact allowlist bypass before file I/O, fail-visible
analyzer errors, bounded reason merging, and absence of process mutation.
Sparse benign metadata fixtures cover the process executable I/O limit without
allocating or reading a large payload.
Flutter IPC coverage binds the four Native counters and diagnostics. The
release Local Core smoke adds benign Native-only security-tamper command text
against the existing Windows PowerShell executable; it never executes the
fixture and requires 4/4 Native reviews, zero failed/limited/diagnostics, five
total review findings, and zero Native attempts for an exact allowlist.

The definitive verifier adds mandatory step `local-core Native process
observation wiring regressions`. Its strict validator requires exactly 266
steps and the new scope clauses. Source contract 667 binds Native, Local Core,
Flutter, release smoke, verifier/validator, documentation, no-mutation scope,
and unchanged dependencies/locks.

No checkpoint-2237 passing result is claimed during scripting. No live malware,
candidate execution, Defender change, machine-wide install, service/driver
start, dependency, feature, lockfile, release, publication, or protected-vault
mutation is involved.

## Local Verification

- PowerShell 5.1 and 7 parse all three changed repository scripts. Rustfmt,
  Dart format for all three changed Dart files, `git diff --check`, strict
  Native/Local Clippy, and Flutter analyze pass.
- Focused Native behavior passes `22/22`; Local Core Native review passes
  `3/3`; the complete Flutter IPC diagnostics file passes `88/88`. The release
  smoke observes 267 bounded rows, skips 13, reports exactly five findings,
  completes `4/4` Native reviews with zero failures/limits/diagnostics, bypasses
  an exact allowlist with zero Native attempts, and rejects unknown input.
- Complete Native passes `542/542` with 19 deliberate helper-child entrypoints
  ignored plus compiler `6/6`; Local Core passes `540/540`; Guard passes
  `248/248` default and `249/249` all-features. Both locked workspace modes
  pass. Flutter passes `838/838`, and source contracts pass `667/667`.
- The exact no-skip/no-Defender verifier passes `266/266` with zero failed or
  skipped steps in `472.7s`. Its SHA-256 is
  `2b8a58df72bd7905aee0aa01a42d69614853f4c54e17ddc7cc85046bb54983d4`.
  Distinct checked PowerShell 5.1 and 7 validators accept it; eight isolated
  mutations under both hosts reject `16/16`.
- The three dependency locks retain SHA-256
  `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
  `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
  and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
  The protected vault remains exactly 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each payload/JSON/auth, one key, and zero pending,
  other, or reparse entries.

## Pending Integration

Exact implementation `0e10cae3b2ac8260f3911c4f103b46c1cd6e5af0` is
PR `#89`'s head. Avorax CI `32915881353` passes all five jobs. Desktop
Packages push/PR runs `32915865035`/`32915881182` pass contracts, Windows
MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMG, consolidation, checksums, and
lockfile SBOM; publication jobs `98022943808`/`98024063933` are skipped.
Consolidated artifacts `9588536075` (131,805,755 bytes, SHA-256
`9f08245b75984af40ef769d5ce706e443a1052fe1853529eaa4df5812d26d31d`)
and `9588657829` (131,802,266 bytes, SHA-256
`38a8e5f47aa21c93c3e854bb28238f7c8ead9ae1ecbe0f12a71072fb01ecef7d`)
match GitHub digests. Bounded in-stream review without extraction or execution
passes exact eight entries, six platform files, seven matching checksum rows,
and CycloneDX 1.6 with 569 components.

Evidence-head hosted checks, normal PR merge, guarded zero-delete
synchronization, and destination re-verification remain pending. Implementation-
head proof does not substitute for those phases.

## Limits

This remains a caller-supplied app-lifetime snapshot every two minutes, not an
installed durable service/driver event stream. Processes may start and exit
between snapshots; inaccessible/raced executable reads become visible failures.
Only exact command hosts/utilities with available command evidence enter Native
review, and observations after the first 16 are explicitly limited. Head/tail
sampling can miss middle arguments. Guard still lacks trusted command-line
telemetry and is not falsely marked connected. Parent PID is not verified parent
image identity, so lineage remains disabled. No process stop, quarantine,
pre-execution, kernel, signed-driver, or production-calibration claim is made.
