# Checkpoint 2256: File Discovery Cancellation And Bounds

Status: **Verified locally; hosted and integration evidence pending**

## Objective

Checkpoint 2256 bounds Local Core quick, full, and custom scan discovery and
makes that discovery observe the exact scan job's cancellation token. The old
path collected the complete full/custom file list before its first cancellation
probe, which could delay a requested stop and grow memory on large trees.

## Implementation

- `collect_accessible_files_with_options_and_cancellation` propagates a
  fallible exact job-bound callback before each root, before root metadata,
  before every at-most-128 `WalkDir` entries, after each completed root, and
  before and after priority sorting.
- Cancellation during discovery returns a cancelled report and scans none of
  the paths already discovered. A malformed, oversized, mismatched, or otherwise
  unreadable token remains an error with discovery context; it cannot become a
  clean, completed, or ordinary-cancel result.
- Quick discovery retains its 5,000-file cap. Full and custom discovery now use
  an explicit 250,000-file cap. A reached cap records a bounded incomplete-scan
  diagnostic and forces `CompletedWithErrors`; undiscovered entries are neither
  counted nor reported clean.
- A valid cancellation token is removed on the cancelled-report path. A corrupt
  token that aborts discovery is retained for fail-visible diagnosis.

## Scripted Tests And Contracts

Three benign walker regressions cover cancellation before the next 128-entry
chunk, exact callback-error propagation, and a fail-visible small file limit.
Two isolated Local Core regressions cover a pre-requested cancellation report
and malformed-token failure before Native Engine initialization. No fixture is
executed.

Verifier step 285 is `local-core file-discovery cancellation and bounds
regressions`, filtered by `file_discovery_`. The report validator requires that
step, exact 285-step cardinality, three verified-scope claims, and two technical
limits. Source contract 686 binds implementation, tests, verifier, validator,
and all checkpoint audit documents.

## Limits

Filesystem cancellation is cooperative, not preemptive. One operating-system
directory read or metadata call and one at-most-128-entry chunk can finish before
the next callback. The final priority sort is bounded by the file-count cap but
does not observe cancellation while sorting.

The 250,000 limit bounds stored path count, not aggregate path-string bytes,
filesystem I/O, elapsed time, or kernel work. Discovery estimates count only
enumerated paths. This checkpoint adds no installed service, driver, kernel
mediation, pre-execution block, or Microsoft Defender replacement claim.

## Safety And Dependencies

Only ordinary benign text fixtures are scripted. No live malware is downloaded,
unpacked, retained, or executed. Checkpoint 2256 adds no dependency, feature,
package source, license class, runtime installation, or lockfile change.

No checkpoint-2256 test has run during this scripting phase. Focused checks,
full local regression, Source contract 686, definitive exact `285/285`, hostile
report validation, hosted exact-head evidence, integration, guarded destination
synchronization, and destination verification remain required before closure.

## Focused Local Evidence

After the scripting boundary, PS5 and PS7 each parse verifier and validator
`2/2`. Workspace formatting and `git diff --check` pass. Source contract 686
passes as part of exact `686/686`. The checkpoint filter passes `5/5`; adjacent
walker, full-scan, and cancellation filters pass `10/10`, `3/3`, and `8/8`.

The first full Local Core run passed `550/551`; one source-order regression used
an obsolete exact indentation marker after the new discovery scope. It was
repaired to locate the successful verdict branch and prove no `files_scanned`
increment occurs before it. The focused regression then passed `1/1`, and the
complete Local Core rerun passed `551/551` in `38.24s`.

The initial pre-format checks also correctly rejected one missing Rust
`let-else` semicolon and four rustfmt-only line layouts, while the first Source
686 run rejected one missing exact documentation phrase. None is credited as a
pass; all were repaired before the passing reruns.

## Broad And Definitive Local Evidence

Both locked workspace variants pass serially, including the standard and
`--all-features` graphs. Strict Local Core Clippy with `-D warnings`, the locked
all-features release workspace build, Flutter `847/847`, Zentor protocol
`14/14`, Avorax protocol `6/6`, and both Dart analyzers pass. The three lockfile
SHA-256 values remain exactly
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.

The definitive verifier passes exact `285/285`, zero failed steps, and zero
non-null errors in `629.9s`. Independent PS5 and PS7 validators accept the
206,090-byte report with SHA-256
`74681a86670805ffeb23b9903a7f5cd70a0c008b91bbe7aff7ab256228b23f33`.
Both hosts reject a 284-step missing-step mutation and a separate missing-scope
mutation with exit code 1; all owned mutation files are removed and no
checkpoint validator residue remains.

An earlier standalone validation after the separate release build correctly
rejected the superseded report because its recorded Local Core binary hash no
longer matched the rebuilt executable. That rejection and two incorrectly
quoted inline parser commands are uncredited. The complete verifier regenerated
all binary-bound evidence, and literal-script PS5/PS7 parser `2/2` plus
standalone full-suite validation then passed against the final report above.

Final read-only checks find zero Avorax/Zentor processes and preserve the
protected vault at exactly 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
unknown, pending, temporary, or reparse entries. `.verification` remains
untracked and untouched. Checkpoint 2256 is **verified locally**. Hosted
exact-head CI/packages, normal integration, guarded destination synchronization,
and destination verification remain open; the complete antivirus-hardening goal
remains active.
