# Checkpoint 2248: Static Text Normalization Cancellation

## Status

Implementation-first source, benign regression, verifier, validator, Source
contract 678, and documentation scripting is complete. No checkpoint-2248 test
has run during this scripting phase. Exact verifier step 277 is scripted but is
now locally verified. Hosted, integration, guarded-synchronization, and
destination evidence remain pending, so Checkpoint 2248 and the complete
antivirus hardening goal remain active.

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
  Hosted exact-head, PR/merge, package, guarded synchronization, and destination
  proof remain checkpoint-closure prerequisites.

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
