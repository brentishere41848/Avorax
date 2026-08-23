# Checkpoint 2201: Authenticode Helper Job Limits

## Objective

Bound committed memory, user-mode CPU, and process fan-out for release
Authenticode verification so a malformed candidate or Windows trust provider
cannot consume those resources without an explicit operating-system ceiling.

## Scripted Boundary

The existing unnamed kill-on-close Windows Job now receives one exact extended
limit structure before the child receives candidate input:

- 12 seconds of per-process user-mode CPU time;
- one active process;
- 1 GiB of committed memory per process;
- 1 GiB of committed memory for the whole Job;
- kill-on-last-Job-handle-close; and
- unhandled-exception dialog suppression.

After `SetInformationJobObject`, Avorax calls `QueryInformationJobObject` and
requires every flag and value to match exactly. Create, set, query, mismatch,
assignment, timeout, kill, and reap failures remain diagnostic and cannot
supply Microsoft trust. The parent starts writing the strict nonce/hash request
only after the Job was configured, read back, and assigned.

Reviewed Windows contracts:

- [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [`JOBOBJECT_BASIC_LIMIT_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information)
- [`JOBOBJECT_EXTENDED_LIMIT_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)
- [`QueryInformationJobObject`](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject)

## Verification Design

- A focused Windows test creates a real Job and validates the operating
  system's returned flags and values.
- The same benign test mutates the returned flag set, CPU limit, active-process
  count, per-process commit limit, and whole-Job commit limit; every mismatch
  must fail with its own diagnostic.
- The central verifier adds a dedicated Job-resource step. The independent
  validator requires exactly 232 steps, the new step, the verified boundary,
  and the technical-limit language.
- Python source contracts pin constants, API calls, fail-visible diagnostics,
  verifier wiring, report count, and honest limitations.

## Honest Limitations

Windows Job commit limits bound committed virtual memory, not physical working
set. The CPU limit counts per-process user-mode execution and excludes kernel
execution. This checkpoint does not add an I/O-byte/rate ceiling. The trusted
current executable starts before assignment but blocks on stdin; untrusted
candidate processing starts only after successful Job assignment. The helper
still uses the parent's security token, so this is resource/lifetime isolation,
not a restricted-token sandbox or authenticated cross-token service boundary.

Installed LocalSystem/service/UI E2E, production package signing and key
custody, driver IPC, kernel/pre-execution enforcement, Defender replacement,
and production detection/false-positive rates remain separate limitations or
blockers. No fixture is executed, and no live malware is used.

## Execution Evidence

Per the requested sequencing rule, implementation, benign tests, verifier,
validator, source contracts, and documentation were completed before the first
checkpoint-2201 test execution.

Local results after that complete scripting phase:

- real Windows Job read-back and adversarial mismatch filter: `1/1` passed;
- release helper isolation: `5/5`; complete Authenticode module: `25/25`;
- Native Engine: `459` library and `6` binary tests passed;
- both complete locked workspace variants and strict Native/Local/Guard Clippy
  passed;
- release Local Core and Guard builds plus two-host helper smoke passed;
- Flutter analyze reported no issues and the suite passed `838/838`;
- Python source contracts passed `629/629`; rustfmt, PowerShell parsing,
  dependency, package-source, security, unchanged-lockfile, and diff gates
  passed; and
- the definitive report ran from `2026-08-23T00:42:57.2282152Z` to
  `2026-08-23T00:50:18.2720889Z`, passing exactly `232/232` steps in `441s`.
  Its built-in validator and a separate strict validator passed. An adversarial
  copy missing only the new Job step failed as required with expected 232,
  found 231.

The protected quarantine vault remained exactly 16,072 files, zero
directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
metadata key, and zero pending files. Exact-head hosted CI/packages, merge, and
safe original-tree synchronization remain pending. No release, publication,
installation, service/driver start, Defender change, fixture execution, or
quarantine mutation occurred.
