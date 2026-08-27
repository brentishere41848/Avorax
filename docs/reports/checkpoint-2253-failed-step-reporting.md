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
| Hosted/integrated/destination state | Pending | Exact-head CI/package evidence, normal merge, guarded sync, destination rerun |

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
