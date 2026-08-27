# Checkpoint 2253 Failed-Step Verification Reporting

Date: 2026-08-27 (Europe/Brussels)

## Problem

The small-threat MVP verifier already wrote a top-level `status=failed` report
and rethrew errors. However, each caller used
`$results.Add((Invoke-Step ...))`. A command failure threw before `Invoke-Step`
returned, so the failed command itself was absent from `steps`. The checkpoint-
2252 Defender-blocked destination attempt demonstrated this observability gap:
34 prior steps were recorded and the exact failing step was not.

This did not turn failure into success, but it weakened diagnosis and made the
structured report less complete than the console error.

## Scripted Implementation

- `Invoke-Step` now captures a bounded diagnostic, command, elapsed time,
  `status=failed`, and `error` before rethrowing. The outer failure path appends
  that one pending result before serializing the failed report.
- Successful steps now carry `status=passed` and JSON `error=null` explicitly.
- Report schema version 2 adds top-level `failure_kind`: `step` when the last
  invoked step failed, `orchestration` when failure occurred outside an invoked
  step, and JSON null for a passed report.
- The validator requires nonnegative elapsed times, exact passed/failed error
  semantics, one terminal failed step for `failure_kind=step`, no failed step
  for `failure_kind=orchestration`, and an exact match between terminal-step and
  top-level error diagnostics.
- Full-suite cardinality is now exact `282`, including the new failed-step
  report smoke, while `Dependency evidence gate` remains the terminal success
  step.

## Scripted Safe Test

`run-small-threat-mvp-failed-step-report-smoke.ps1` launches a nested verifier
with the checked Python executable intentionally supplied as `-CargoPath`.
Python rejects the first Cargo argument immediately; no candidate fixture is
created or executed. The smoke requires one exact terminal failed step and then
requires distinct Windows PowerShell 5.1 and PowerShell 7 validators to accept
the authentic report and reject three report-only mutations:

1. the failed step changed to passed;
2. a passed record placed after the failed step;
3. the failed-step error changed to JSON null.

All reports live in a GUID-owned repository temporary directory. Cleanup
removes only four exact regular files and deletes the directory only after
proving it is empty and non-reparse. There is no recursive delete.

## Verification State

| Surface | State | Required evidence |
|---|---|---|
| Failed invoked-step capture | Verified locally (focused) | Intentional first-step failure records one exact terminal failed row |
| Schema v2 dual-host validator | Verified locally (focused) | PS5 and PS7 accept the authentic report and reject all six mutations |
| Full verifier integration | Verified locally | Exact `282/282` definitive report with zero non-passing steps |
| Source and documentation contract | Verified locally | Exact Source contract `683/683` |
| Hosted/integrated/destination state | Verified | Evidence-head and merged-main CI/packages, normal merge, guarded sync, and destination rerun pass |

No checkpoint-2253 test has run during this scripting phase. Nothing in this
checkpoint changes detection, quarantine, update, service, driver, Defender,
or release behavior. It does not install software, create EICAR, use malware,
start a service/driver, weaken Windows security, publish, or release anything.

## Planned Commands

After the complete scripting batch, run parser and source-contract checks,
then the dedicated smoke, focused validator mutations, full local regression,
and the definitive verifier with exact `282/282` dual-host validation. Only
after local evidence passes may exact-head hosted evidence, review, integration,
guarded synchronization, and destination verification proceed.

Checkpoint 2253 is active. The complete antivirus-hardening goal remains active
and is not implied complete by this verifier-only checkpoint.

## Focused Execution Progress

The first real source-contract run passed exact `683/683`. The first smoke
attempt then stopped fail-visibly before validator invocation because its local
loop variable used PowerShell's read-only automatic `$Host` name. Renaming only
that loop variable to `$validatorHost` repairs the script source. The failed
attempt is uncredited; parser, Source, and smoke reruns remain required.

The corrected focused rerun passes PS5 and PS7 parsing for all three scripts,
Source exact `683/683`, and the dedicated smoke. The authentic nested failure
records exactly one terminal `failed` step; both hosts accept it and reject all
six status, terminal-order, and missing-error mutation cases. Locks and the
read-only protected vault remain exact. Full regression, definitive `282/282`,
hosted, integration, guarded-sync, and destination evidence remain pending.

## Broad Local Execution Progress

The complete post-scripting local regression passes: Rust formatting, Flutter
analyze, Dart protocol `14/14`, Flutter `847/847`, Local Core `546/546`, Native
632 active tests plus compiler `6/6` with 21 documented child fixtures ignored,
and the locked all-features workspace. Standalone Native locked/offline check,
the locked release workspace build, and strict Native, Local Core, and Guard
Clippy with `-D warnings` also pass. Test-only Rust debug, incremental,
codegen-unit, and strip controls bound generated artifacts without changing a
product dependency or release profile. Definitive exact `282/282`, hosted,
integration, guarded-sync, and destination evidence remain pending.

## Definitive Local Evidence

The from-start Windows PowerShell verifier passes exact `282/282`, zero
non-passing steps, in `768.6s` from `2026-08-27T15:44:17.8230206Z` through
`2026-08-27T15:57:06.4775118Z`. The schema-v2 report has
`failure_kind=null`, 282 passed-step `error=null` values, exactly one
`Small-threat MVP failed-step report smoke`, and terminal `Dependency evidence
gate`. The 202,348-byte report SHA-256 is
`3ad67ee7b7d6aed00b4aafece608a61b664aff1949dd67c2a0b04ff1a592894d`.

Independent PS5 and PS7 full-suite validation accepts that report. Both hosts
reject a 281-step copy missing the new smoke and a separate 282-step copy
missing the required schema-v2 verification scope. The two exact regular-file
copies were removed and no temporary-test entry remains. An initial direct
`python -m pytest` command was uncredited because that checked interpreter does
not contain the optional pytest module; the repository's dependency-free
runner then passed exact `683/683` without installation.

The three lock hashes and protected-vault invariant remain exact, with no
product process residue. Checkpoint 2253 is **verified locally**. Hosted
exact-head CI/packages, normal integration, guarded synchronization, and
destination verification remain pending. The complete antivirus-hardening goal
remains active.

## Hosted Implementation-Head Evidence

Exact implementation commit `3fc1fb0907cc194211064784f9ba95cc34f32732`
passes PR `#115` CI run `33091441105`: branding, security/protection/
performance, Flutter/protocol, Rust Local Core/Guard, and Unix quarantine
permission jobs all succeed. Manually dispatched Desktop Packages run
`33091417691` is bound to the same exact head with version `0.1.15`, tag input
`v0.1.15-beta.1`, and `publish_prerelease=false`. Package contracts, Windows
MSI/EXE, Linux DEB/tar, both macOS DMGs, and consolidation succeed; the
publication job is explicitly skipped and no release is created.

GitHub reports consolidated artifact `9655292568`,
`avorax-desktop-release-0.1.15`, as 132,050,923 bytes with digest
`sha256:6079a51cdf15760aa6f8c0fd8d1bab821f1075f3050f566292753cd340225e49`.
The independently downloaded untouched ZIP has that exact size and SHA-256.
A bounded non-extracting review verifies exactly eight safe root entries, six
platform packages, seven matching checksum targets, and one CycloneDX 1.6
lockfile SBOM with 569 components and 569 unique references. It finds zero
unsafe, duplicate, encrypted, or link entries. No artifact content is
installed, extracted, or executed; the exact temporary ZIP and its empty owned
directory are removed afterward.

This closes implementation-head hosted evidence only. Evidence-head CI and
packages, normal PR integration, merged-main CI/packages, guarded destination
synchronization, and destination verification remain required. The complete
antivirus-hardening goal remains active.

## Hosted Integration And Package Evidence

Evidence commit `09e5a9caf64925029316aeb6054306eb872866fb` passes PR
`#115` exact-head CI run `33093781090` and Desktop Packages run `33093775519`.
All five CI jobs and package contract, Windows, Linux, both macOS, and
consolidation jobs pass; publication is skipped. Consolidated artifact
`9656100498` is 132,067,452 bytes and its untouched download matches GitHub
SHA-256 `36756f9dbb1aad926231e4a27008f3c30f985506eb43e23d625d5b926c88c1c5`.
Bounded non-extracting review passes exact 8-root/6-package/7-checksum and
CycloneDX 1.6/569-unique-component validation.

PR `#115` merged normally as
`61311d967168a3cac5cecafce7b1c1c4fcf974f3`. Merged-main CI run
`33095648643` and Desktop Packages run `33095665829` pass on that exact merge;
publication is skipped. Main artifact `9656858505` is 132,060,157 bytes and its
untouched download matches GitHub SHA-256
`e1631fbb11088c624309351326a311408ebacb8a71cb2b824906be0e3ba9b8d0`.
The same bounded review passes exact 8/6/7/CycloneDX-1.6/569 inventory with
zero unsafe, duplicate, encrypted, or link entries. Exact temporary archives
and their empty owned directories were removed without extraction, execution,
installation, release, or publication.

## Guarded Destination Synchronization

The exact delta from prior closure
`4ad5a96dfe9af786713c19aee6324e73efc68e3d` to merge
`61311d967168a3cac5cecafce7b1c1c4fcf974f3` contains ten modified, two added,
and zero deleted paths. Read-only preflight required every existing destination
file to match the old or new Git-clean blob, required both additions to be
absent or already exact, and rejected links, non-files, unsafe containment, and
unexpected statuses. All ten existing files matched the old blobs and both new
paths were absent.

All 12 source blobs were staged to separate same-directory regular temporary
files, verified against the merge blobs, atomically activated, and verified
again. Exact cleanup removed only any still-owned staging files. Independent
post-sync comparison passes `12/12`, with zero mismatches and zero deletes; no
unrelated destination file changed.

## Destination Verification

The first focused invocation selected the WindowsApps Python reparse shim and
the smoke rejected it before testing. That attempt is uncredited and no
security rule changed. The corrected complete focused rerun uses the checked
regular Python host and passes PS5/PS7 parsers `3/3`, Source `683/683`, and the
failed-step smoke with one authentic failure plus six adversarial rejections.

With test-only `CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_TEST_CODEGEN_UNITS=1`, and
`CARGO_PROFILE_TEST_STRIP=symbols`, the from-start destination verifier passes
exact `282/282`, zero non-passing steps, in `578.3s` from
`2026-08-27T17:17:22.5186220Z` through
`2026-08-27T17:27:00.8349357Z`. Its 193,682-byte schema-v2 report is
`.workflow/ultracode/avorax-hardening/results/checkpoint-2253-small-threat-mvp-verification-report-destination.json`
with SHA-256
`bb4d1bda31c67c40c8b4139463234fda0bed87577c70ad7a68f215ea3b1b6fe8`.
It records `failure_kind=null`, 282 passed steps with JSON-null errors, the
expected first step, and terminal `Dependency evidence gate`. Independent PS5
and PS7 full-suite validators pass.

An initial post-run blob summary called `git diff` from the non-Git destination
and produced an invalid zero-path summary; it is uncredited. The corrected
audit runs Git from the authoritative worktree, asserts cardinality 12, and
passes all `12/12` destination blobs. The three recorded lock hashes, zero
product processes, and zero temporary-test entries are exact. The protected
vault was audited read-only and remains 16,072 files, zero directories,
4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one metadata key, and
zero pending/temp/reparse entries. `.verification` was never staged or deleted.

Checkpoint 2253 is closed through local, hosted, merged-main, synchronized, and
destination evidence. This reporting change does not expand antivirus
detection or installed protection. Same-user repository evidence, process or
power-loss serialization, installed cross-identity service/IPC, production
calibration/signing, signed-driver/kernel mediation, pre-execution blocking,
and Defender replacement remain technically limited, blocked, or unclaimed.
The complete antivirus-hardening goal remains active.
