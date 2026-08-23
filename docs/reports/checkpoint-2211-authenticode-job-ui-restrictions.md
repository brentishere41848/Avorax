# Checkpoint 2211: Authenticode Job UI Restrictions

Date: 2026-08-23 (Europe/Brussels)

## Objective

Reduce the one-shot Windows Authenticode helper's access to shared desktop/UI
resources that are unnecessary for hash-bound Microsoft publisher trust, while
preserving the existing suspended-create, fully configured Job assignment, and
fail-visible trust boundary.

## Scripted Implementation

- `KillOnCloseJob::create` configures `JobObjectBasicUIRestrictions` in addition
  to the existing exact CPU/process/commit/kill-on-close limits.
- The required exact flags are `JOB_OBJECT_UILIMIT_HANDLES`,
  `JOB_OBJECT_UILIMIT_READCLIPBOARD`, `JOB_OBJECT_UILIMIT_WRITECLIPBOARD`,
  `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS`, `JOB_OBJECT_UILIMIT_DISPLAYSETTINGS`,
  `JOB_OBJECT_UILIMIT_GLOBALATOMS`, `JOB_OBJECT_UILIMIT_DESKTOP`, and
  `JOB_OBJECT_UILIMIT_EXITWINDOWS`.
- `QueryInformationJobObject(JobObjectBasicUIRestrictions)` must return the
  exact structure byte count and exact flag set before the Job can be returned
  for process assignment.
- Configuration, query, returned-size or exact-flag comparison, suspended-
  process assignment, or resume failure is diagnostic and cannot become
  publisher trust. No partial, weaker-flag, or unrestricted-process retry exists.

The helper remains created suspended, assigned to the configured one-process
Job, and resumed only after assignment. Therefore the Job UI policy is in force
before helper code can parse stdin or inspect a candidate.

## Scripted Benign Evidence

- A real Windows Job regression queries and exactly validates the configured
  `JOBOBJECT_BASIC_UI_RESTRICTIONS` value.
- A pure adversarial regression proves all eight flags compose the exact policy,
  then rejects a wrong returned size, every individually missing flag, and one
  unknown extra flag.
- Existing release Local Core/Guard smoke is retained to exercise actual helper
  startup plus embedded/catalog Microsoft trust compatibility without executing
  any candidate fixture.
- The central verifier adds `native-engine Authenticode helper Job
  UI-restriction regressions`, raising the strict full-suite count from `240` to
  `241`. The independent validator requires the exact step, returned-size and
  flag verified scope, and technical-limit scope.
- The Python source-contract suite accounts for implementation ordering, API and
  flag inventory, tests, verifier, validator, and all audit documents.

No checkpoint-2211 passing result is claimed before execution. The complete
implementation/test/verifier/documentation batch was scripted first, as
requested.

## Verification Matrix

| Control | Evidence | Current classification |
| --- | --- | --- |
| Exact Job UI policy | Real query/read-back plus missing/unknown flag and wrong-size rejection | Verified locally `2/2` |
| Fail-visible setup | Set/query/returned-size/flag/assignment/resume errors have no trust fallback | Verified in source and regressions |
| Trust compatibility | Release two-host embedded/catalog/hash-binding smoke | Verified locally |
| Central evidence | Dedicated step, exact `241` count, strict scope validation | Verified locally `241/241` |
| Dependency boundary | Existing pinned `windows-sys 0.61.2` JobObjects APIs only | Verified locally; hosted package evidence pending |

## Local Verification

- PowerShell parser checks, rustfmt, and diff checks pass. The dedicated Job UI
  filter passes `2/2`; adjacent Job-resource and token-safety filters pass
  `1/1` and `2/2`. Complete Authenticode passes `43` with `8` intentional
  child-fixture ignores.
- Strict Native, Local Core, and Guard Clippy pass. Locked release Local Core
  and Guard builds plus the two-host embedded/catalog/hash-binding/no-execution
  smoke pass with the UI-restricted Job active.
- Both locked Rust workspace variants pass. Native reports `479` passed with
  `8` intentional ignores and the signature compiler adds `6/6` in each.
- Flutter analyze reports no issues and Flutter passes `838/838`. The
  dependency-free source-contract runner passes `641/641`; no-malware and
  dependency-evidence gates pass.
- Final diff review found that the first passing run checked query success and
  exact flags but not the returned structure byte count. That run is not
  retained as final evidence. Exact returned-size validation and a wrong-size
  adversarial regression were added before the affected focused/full reruns.
- A subsequent evidence review found that retry 2 exercised returned-size
  rejection but did not require returned-size wording in the central report
  scope. The verifier, validator, and source contract now enforce it, so retry 2
  is not retained as final evidence.
- The corrected definitive report
  `.verification/checkpoint-2211-small-threat-mvp-definitive-retry3-report.json`
  passes exactly `241/241`, with zero failed or skipped, from
  `2026-08-23T17:21:41.5398675Z` through
  `2026-08-23T17:28:55.6483598Z` (`434.1s`). Separate full-suite validation
  accepts it.
- Fresh controlled reports derived from that final report with `240` steps, a
  renamed required step, removed verified scope, removed technical-limit scope,
  or a skipped required step are all rejected. They remain only under
  `.verification/`.
- Cargo and Flutter lockfiles remain exact. The protected vault remains exactly
  `16,072` files, zero directories, `4,522,733` bytes, `5,357` each
  `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.

Hosted exact-head checks, normal PR merge, merged-main checks, guarded
original-tree synchronization, and destination verification remain pending and
are not claimed.

## Honest Boundary

The controls restrict foreign USER handles, clipboard reads/writes, system
parameters, display settings, global atoms, desktop creation/switching, and
`ExitWindows` for processes in the Job. `JOB_OBJECT_UILIMIT_DESKTOP` does not
create a private desktop or window station. These controls do not change user
identity, credentials, profile or registry namespace; remove filesystem,
registry, network, or ordinary read access; constrain named kernel objects; or
isolate already mapped image/non-image data.

This is not AppContainer/LPAC, authenticated cross-identity IPC, installed
LocalSystem evidence, a signed driver, kernel interception, pre-execution
blocking, Defender replacement, or production detection-rate evidence.

No candidate fixture is executed. No live malware, network retrieval,
installation, service/driver start, Defender change, release, publication, or
protected-quarantine mutation is permitted.

## Dependency Contract

Checkpoint 2211 adds no crate, package, Cargo feature, or lockfile change. It
uses the existing pinned `windows-sys 0.61.2` `Win32_System_JobObjects` surface,
licensed `MIT OR Apache-2.0`. Final artifact license and notice review remains a
separate release-host requirement.
