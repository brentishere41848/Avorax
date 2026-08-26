# Checkpoint 2245: Non-Archive Static Analysis Cancellation

## Scripting Status

No checkpoint-2245 test has run during this scripting phase. Implementation,
benign regression tests, verifier step 274, strict report-validator scope, Source
contract 675, and audit documentation were deliberately completed before any
formatter, parser, compiler, linter, or test command, as requested. Passing
evidence must be added only after the scripted batch is reviewed and executed.

## Problem And Responsibility

The shared Native static-analysis callback previously reached archive analysis,
but non-archive entropy, string indicators, PE inspection, and script analysis
could finish long bounded substeps before observing cancellation. String URL and
network-path extraction also retained a reference vector proportional to the
number of matches. That was bounded by the existing 64 MiB input sample cap but
unnecessarily increased latency and memory pressure.

Checkpoint 2245 gives every affected analyzer a real, narrow responsibility:

| Analyzer/control | Scripted responsibility | Status before execution |
|---|---|---|
| Shared static orchestrator | Check before/after phases, stream 4096-byte entropy aggregation, and propagate callback errors before `StaticAnalysis` construction | Scripted / unverified |
| Entropy engine | Check every at-most-64-KiB byte chunk and at completion | Scripted / unverified |
| String URL/network-path engine | Stream saturated counts without URL/path reference vectors; check every 1024 references | Scripted / unverified |
| String IP/term/UTF-16 engine | Stream IPv4 candidates, check term passes, decode UTF-16 without a temporary unit vector, and check every 64 Ki decoded characters plus markers | Scripted / unverified |
| PE section engine | Check each section and use fallible chunked section entropy | Scripted / unverified |
| PE import engine | Check each import-category term pass | Scripted / unverified |
| PE debug-path engine | Search in overlapping at-most-64-KiB chunks so boundary-spanning `.pdb` markers remain visible | Scripted / unverified |
| PowerShell analyzer | Check lowercase, indicator, count, and obfuscation term passes | Scripted / unverified |
| JavaScript analyzer | Check lowercase and every indicator/count term pass | Scripted / unverified |
| Batch analyzer | Check lowercase and every obfuscation/indicator/count term pass | Scripted / unverified |
| VBS analyzer | Check lowercase and every indicator/count term pass | Scripted / unverified |
| Compatibility wrappers | Preserve infallible existing call sites and exact analyzer outputs | Scripted / unverified |
| Native verdict boundary | Use one job-bound `static analysis progress` callback and propagate arbitrary errors before completion/verdict publication | Scripted / unverified |

The reputation provider remains disabled without an authenticated,
privacy-reviewed backend. Browser-data, credential/network, persistence-write,
and parent-image-lineage behavior engines remain disabled without trusted
correlated telemetry. Checkpoint 2245 neither enables them nor changes their
documented blockers. Synchronous rule/ML and Windows trust operations are also
outside this checkpoint.

## Benign Regression And Verification Contracts

All new Rust tests use ordinary text or synthetic PE bytes and never execute a
candidate. The `non_archive_static_cancellation` filter covers callback-error
propagation in entropy, shared orchestration, strings, IPv4 traversal, scripts,
PE sections/imports/debug traversal, engine wiring, and exact wrapper parity.
Verifier step 274 runs that filter serially. The report validator requires exact
`274` cardinality, the named step, the verified scope, and both technical-limit
statements. Source contract 675 inventories source wiring, removal of obsolete
URL/path vectors, tests, verifier/validator text, and all checkpoint documents.

After scripting review, the intended evidence order is focused Rust checks,
adjacent analyzer regressions, Source contract `675/675`, full Native/Local/
Flutter regression and strict quality gates, then definitive exact `274/274`
verification with both independent validators and adversarial missing-step and
missing-scope copies. Hosted exact-head, merge, package, guarded synchronization,
and destination evidence remain required before closure.

## Honest Technical Limits

Cancellation is cooperative rather than preemptive. One already-running UTF-8
or UTF-16 lossy/lowercase normalization, one term search, one bounded parser
call, or one operating-system/filesystem/rule/ML/trust operation can complete
before the next checkpoint. Non-archive content remains capped by the existing
64 MiB sample limit; this checkpoint does not claim constant memory, hard task
termination, installed-service ownership, kernel mediation, driver blocking, or
pre-execution prevention.

## Safety And Dependency Delta

Checkpoint 2245 adds no dependency, feature, downloaded content, package source,
license obligation, build script, or lockfile change. It uses Rust callbacks,
iterators, saturated counters, and the already locked `anyhow` dependency. No
live malware, external malware repository, Defender weakening, machine-wide
installation, service/driver action, candidate execution, quarantine-vault
mutation, publication, or release action is part of this checkpoint.

## Local Evidence To Date

After the scripting phase closed, formatting, diff integrity, PowerShell 5.1
parsing, and strict Native all-target/all-feature Clippy passed. The first
focused run compiled and passed `14/15`; its sole failure was a source test
matching its own forbidden-function string literal. The marker was split so it
cannot self-match, and the exact rerun passed `15/15`. All analyzer tests pass
`99/99`, and the complete dependency-free source-contract runner passes exact
`675/675`.

The first complete serial Native run passed `569` tests before Defender blocked
five late benign test-process starts with Windows error 225. No Defender setting
was changed. All five blocked tests passed in isolated low-process-pressure
reruns, and the required complete rerun then passed Native library `574`, with
`21` documented child-fixture ignores, plus signature compiler `6/6`. This clean
complete rerun is the credited Native evidence; the error-225 run is retained as
host-interference evidence.

Local Core now passes `546/546`; Flutter analyze reports no issues and Flutter
tests pass `847/847`; strict Local Core Clippy and the locked optimized workspace
release build pass. No dependency manifest or lockfile is modified. The
protected vault preflight remains exact at 16,072 files, zero directories,
4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one metadata key, zero
pending entries, and zero reparse points. Definitive `274/274` and all hosted/
integration/destination proof were pending at this local regression stage.

## Definitive Local Evidence

The definitive verifier passes exact `274/274` from
`2026-08-26T18:47:12.5110894Z` through `2026-08-26T18:56:12.2995212Z` in
`539.7s`. Defender EICAR integration remains disabled by default, while no Rust
or Flutter verifier step is skipped. The report SHA-256 is
`bf1e079ee669281b69a040a27ff7eef894aa00d72c394a72e2907aaf678f2c07`.

The embedded validator and independent Windows PowerShell 5.1 and PowerShell 7
validators accept the exact report. Both independent hosts reject a `273`-step
copy missing verifier step 274 and a `274`-step copy missing the required entropy
scope; all four expected-negative invocations exit `1`. The adversarial copies
remain isolated under `.verification` and the accepted report was not modified.

Hosted exact-head CI/package evidence, normal PR integration, guarded
synchronization, destination regression, and destination definitive evidence
remain required before checkpoint closure. No release or publication occurred.

## Implementation-Head Hosted Evidence

Implementation head `6a8c136aff321b9c8dac53547b5e988376603091` passes all five
Avorax CI jobs in run `33003081719`. Desktop Packages push run `33003036684`
and PR run `33003081759` both pass package contracts, Windows MSI/EXE, Linux
DEB/tar, macOS arm64/x64 DMGs, and consolidation. Publication jobs
`98293891452` and `98294578577` are skipped.

The PR consolidated artifact `9619955244` is `132023565` bytes and its
downloaded SHA-256 matches GitHub's digest exactly at
`54a8e214df6976ed9b97859dd90470ca7c6be285dac75e86558e6096272aacd9`.
Bounded in-stream validation passes exact 8-root/6-platform/7-checksum and
CycloneDX 1.6/569-component evidence without extraction or execution. The
independent push artifact `9619876133` is `131952443` bytes with GitHub digest
`c008386d54e85bf115b4bda9a1e9d146734bcf4d102c23fec536666c51595d0a`.

PR `#98` remains open. The documentation-only evidence commit, its exact-head
checks, normal merge, merged-main checks/packages, guarded synchronization, and
destination verification remain required. No release or publication occurred.

## Integration And Destination Closure

The preceding open-PR statement records an earlier evidence stage and is now
superseded. Exact evidence head
`195d3c847b4e0ce993329bd0e7b142d1b6c0b785` passes CI `33004923358` and
Desktop Packages `33004923305`; publication job `98301296963` is skipped.
Artifact `9620713611` is `131962495` bytes, matches SHA-256
`621ea64b26f312bc79132f49869e6b3f5356ea0b3230d7e9475507ed62c16ab4`,
and passes bounded non-extracting exact 8-root/6-platform/7-checksum plus
CycloneDX 1.6/569-component validation.

PR `#98` merged normally as
`48cf932ff23211961386cbf220d05026821322c7`. Its exact parents are main
`0f75e8ed883d1fadf5314ce57aafcacae7ab924f` and evidence head
`195d3c847b4e0ce993329bd0e7b142d1b6c0b785`. Merged-main CI
`33006604149` and Desktop Packages `33006604143` pass; publication job
`98308496311` is skipped. Artifact `9621531773` is `131928321` bytes,
matches SHA-256
`a06528a864f1f4a97fb6eaae56b0d92ec021fd44e193f0915ca3892708052110`,
and passes the same bounded validation. No release, direct-main push, package
execution, or installation occurred.

Guarded synchronization to `C:\Users\Brent\Documents\Avorax-main` passes
preflight, atomic apply, and independent Git-attribute-aware verification for
all `22/22` paths with zero deletes and zero staging residue. Post-test
canonical comparison again passes `22/22`.

Destination results are:

- focused non-archive cancellation `15/15`;
- analyzer regressions `99/99` and Source contracts `675/675`;
- Native library `574` passed and `21` documented fixture tests ignored, plus
  signature compiler `6/6`;
- Local Core `546/546`;
- Flutter analyzer with no issues and Flutter `847/847`;
- Native/Local rustfmt and strict all-target/all-feature Clippy;
- explicit Windows PowerShell 5.1 and PowerShell 7 parser checks; and
- `cargo build --workspace --release --locked`.

The exact destination verifier command was:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot . -ReportPath .verification\checkpoint-2245-destination-full-report.json
```

It passes `274/274` from `2026-08-26T20:15:03.174601Z` through
`2026-08-26T20:23:25.6774898Z` in `502.5s`, with Defender/EICAR opt-in off and
no Rust or Flutter skip. Embedded and separately invoked PS5/PS7 validators
accept the report. SHA-256 is
`3b56da92cf01d0a3191ea0fbea19fde82fd45fc14b7e6aaeee5cda9b3e08e342`.
The nested package-source command passed its mandatory verifier step while
documenting three skipped Windows symlink fixtures that require optional
symlink privilege.

All three lock hashes and the protected 16,072-file quarantine invariant remain
exact. Checkpoint 2245 is closed. Cancellation remains cooperative, all
documented disabled engines remain disabled, and the complete antivirus
hardening goal remains active.
