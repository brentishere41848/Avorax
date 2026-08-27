# Checkpoint 2248: Static Text Normalization Cancellation

## Status

Implementation-first source, benign regression, verifier, validator, Source
contract 678, and documentation scripting is complete. No checkpoint-2248 test
has run during this scripting phase; execution began only after that batch was
frozen. Local, hosted exact-head, normal integration, merged-main, guarded-sync,
and destination evidence now pass. Checkpoint 2248 is closed, while the
complete antivirus hardening goal remains active.

## Objective

Remove the remaining whole-sample cancellation interval in non-archive string,
script, and PE-import text normalization. Make bounded OOXML relationship and
archive `autorun.inf` inspection propagate the exact callback and prevent a
callback error from leaving partial archive evidence. Preserve existing lossy
UTF-8 replacement, ASCII-only lowercase, matching, explanation, and verdict
semantics.

## Scripted Implementation

- String-indicator extraction and PE-import categorization use the existing
  shared lossy-UTF-8/ASCII-lowercase helper. Script normalization delegates to
  that same helper. It checks the exact scan-job callback before every
  at-most-64-KiB input chunk and after the final chunk.
- OOXML relationship bodies pass their callback through normalization and
  indicator extraction. The relationship counters change only after every
  fallible operation succeeds.
- Archive `autorun.inf` bodies use callback-aware indicator extraction and
  publish their command count only after complete success.
- Arbitrary callback errors remain `Err` values. The analyzer and outer engine
  retain their existing fail-visible boundary, so partial static evidence is
  not converted into a clean or successful file verdict.

## Scripted Evidence

- Three benign multi-chunk tests cancel string, script, and PE-import
  normalization before an analysis result can be returned.
- Two benign archive tests inject arbitrary callback failures and require zero
  OOXML or autorun evidence afterward.
- Mandatory verifier step `native-engine static text-normalization cancellation
  regressions` selects the exact `static_text_normalization_` prefix.
- Strict validation requires exactly 277 passing, non-skipped steps and pins the
  verified and technically limited scope. Source contract 678 pins production
  wiring, fixtures, verifier, validator, this report, and every audit document.

## Local Execution Evidence

- The dependency-free Source runner first executed `678` contracts and rejected
  one historical checkpoint-2245 assertion that still required the superseded
  whole-normalization limit. The assertion was moved to the new exact bounded
  limit; the complete rerun passes `678/678`. Two earlier optional-`pytest`
  commands performed no collection because neither available Python runtime
  includes that optional module; no package was installed.
- Dedicated static normalization passes `5/5`; adjacent non-archive static
  cancellation `15/15`, archive cancellation `4/4`, provider normalization
  `7/7`, string `39/39`, script `5/5`, PE-import `2/2`, and ZIP `38/38` filters
  pass.
- Complete Native Engine passes `605` active tests with `21` documented child
  fixtures ignored plus compiler `6/6`. Local Core passes `546/546`; Flutter
  analyze reports no issues and Flutter passes `847/847`. Strict Native and
  Local Core Clippy, formatting, the locked workspace, and locked release
  workspace build pass.
- Definitive verification passes exact `277/277`, zero failed and zero skipped,
  from `2026-08-27T01:13:48.5351313Z` through
  `2026-08-27T01:21:59.2036339Z` in `490.6s`. Embedded and independently
  invoked Windows PowerShell 5.1 and PowerShell 7 validators pass. Report
  SHA-256 is
  `ed446a13be9e87f3c8cef0e04583e8f928f1744276825f40e61fa2304c8ba69a`.
  Both hosts reject separate missing-step and missing-scope reports with exit
  code `1`.
- An initial definitive invocation supplied a nonexistent conventional
  PowerShell 7 path and stopped in tool preflight before tests or report output.
  The corrected invocation used the existing bundled PowerShell 7 executable.
- Root Cargo, Native Cargo, and Flutter lock hashes remain exact. Read-only vault
  inventory remains 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
  payload/metadata/auth, one key, zero pending files, and zero reparse points.

## Hosted And Integration Evidence

- Exact implementation head `eb9b2f1f529cca328e0e45d2a6e358ff02cd24cc`
  passes Desktop Packages push run `33030242047`, Avorax CI PR run
  `33030430576`, and Desktop Packages PR run `33030430739`. All required jobs
  pass and both publication jobs are explicitly skipped.
- Untouched push artifact `9630413284` is 132,090,416 bytes with SHA-256
  `826e997289b6bc3e97a97b266d9ac5675d8cf7e98db28cdff1002eeaf5dfb77f`;
  untouched PR artifact `9630373063` is 132,089,765 bytes with SHA-256
  `f76940dafd898568afde51e59822aa0fa6018bad467037c69dd5b8518b2a138e`.
  Bounded in-stream validation without extraction or execution proves exact
  eight-root-entry, six-platform-file, seven-checksum, CycloneDX 1.6, and
  569-component inventories in both.
- PR `#105` merges normally as
  `43b4fe3441d20d9b6e39c69162ea384d96f16081`, with exact parents
  `01b0701422bd8f620be5df5ee9f56a0ea5d0754b` and
  `eb9b2f1f529cca328e0e45d2a6e358ff02cd24cc`. Merged-main Avorax CI
  `33031710247` and Desktop Packages `33031710233` pass; publication is skipped.
  Main artifact `9630807301` is 132,268,653 bytes with SHA-256
  `84acca2a4860e4946dd1f7fbb6ac88b211ce7081293bdb572930c5210cc224dc`
  and passes the same non-extracting 8/6/7/CycloneDX-1.6/569 validation.

## Destination Evidence

- Guarded synchronization from base
  `01b0701422bd8f620be5df5ee9f56a0ea5d0754b` to merge
  `43b4fe3441d20d9b6e39c69162ea384d96f16081` passes audit, apply, and an
  independent Git-attribute-aware target comparison for exact `15/15` paths,
  with one addition, zero deletes, zero mismatches, and zero staging residue.
- In `C:\Users\Brent\Documents\Avorax-main`, Source contracts pass `678/678`,
  dedicated static normalization passes `5/5`, and workspace formatting passes.
  Definitive verification passes exact `277/277`, zero failed and zero skipped,
  from `2026-08-27T02:20:01.494236Z` through
  `2026-08-27T02:28:57.7621101Z` in `536.2s`. Embedded and independently
  invoked Windows PowerShell 5.1 and PowerShell 7 validators accept report
  SHA-256 `c110ed4a994978550a536e9e984459296dba8a5bad59b93423792a64bc9e2e17`.
- All three dependency locks remain exact. The protected quarantine remains
  read-only and exact at 16,072 files, zero directories, 4,522,733 bytes, 5,357
  each payload/metadata/auth, one metadata key, zero pending/temp files, and
  zero reparse points. No artifact was extracted or executed, no release was
  published, and no machine-wide component was installed.

Checkpoint 2248 is closed. Static text cancellation remains cooperative and
bounded, ZIP entry-name normalization remains technically limited, and disabled
correlation-dependent providers retain their blockers. The complete antivirus
hardening goal remains active.

## Safety

Fixtures are ordinary in-memory text and byte arrays. They are never written as
candidate executables, unpacked, or executed. This checkpoint downloads no
malware, creates no live EICAR file, changes no Defender setting, and does not
install or start a service, driver, installer, or machine-wide component. The
protected `C:\ProgramData\Avorax\Quarantine` vault remains read-only.

## Limits And Honest Claims

Cancellation remains cooperative. One active at-most-64-KiB static text
normalization chunk, one UTF-16 decode interval, one term search, or an entered
filesystem/system operation can finish before the next callback. ZIP entry-name
normalization remains one header-bounded interval of at most 65,535 bytes.
Ordinary file input remains capped at 64 MiB; OOXML relationship and autorun
bodies remain capped at 64 KiB and 16 KiB.

This work is not hard preemption, constant-memory analysis, installed
cross-identity service ownership, driver/kernel mediation, production detection
accuracy, pre-execution blocking, or Defender replacement. Windows trust stays
partial/technically limited, and reputation and correlation-dependent providers
remain disabled with their documented prerequisites.

## Required Verification Sequence

1. Freeze the complete checkpoint-2248 scripting batch before any test.
2. Run formatting, parser checks, Source contract 678, the five focused
   normalization regressions, and adjacent analyzer/provider regressions.
3. Run complete Native, Local Core, Flutter, locked workspace, strict affected
   lint, release-build, dependency, safety, and clean-diff checks.
4. Run the definitive verifier and require exact `277/277`, zero failures and
   zero skips. Validate with independent Windows PowerShell 5.1 and PowerShell 7
   and prove missing-step/scope reports are rejected.
5. Obtain exact-head hosted CI/package evidence with publication skipped, merge
   through a normal PR, verify merged main, guarded-sync with zero deletes, and
   repeat focused and definitive destination verification before closure.
