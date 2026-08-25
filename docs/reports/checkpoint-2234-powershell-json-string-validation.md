# Checkpoint 2234 - PowerShell JSON String Validation

## Objective

Remove the verifier-host discrepancy exposed by checkpoint 2233 without
weakening strict report types. PowerShell 7.5 and later may coerce ISO-8601 JSON
strings to `DateTime` during `ConvertFrom-Json`; Windows PowerShell 5.1 leaves
them as strings. The report contract requires timestamp properties to remain
JSON strings before explicit invariant-culture ISO-8601 parsing.

## Scripted implementation

- `ConvertFrom-AvoraxGateJsonPreservingStrings` uses the native `DateKind`
  parameter with exact `String` behavior when that parameter exists and keeps
  the compatible Windows PowerShell 5.1 call shape otherwise.
- All nine bounded JSON readers in the strict small-threat report validator use
  that helper. Strict object, property, scalar type, timestamp, path, scope,
  generated-report, status, and exact 263-step checks remain unchanged.
- The definitive verifier resolves checked regular-file paths for distinct
  Windows PowerShell 5.1 and PowerShell 7 executables, then requires the exact
  generated report to pass the same validator under both hosts.
- Source contract 664 accounts for helper dispatch, all nine readers, distinct
  checked hosts, exact scope wording, documentation, and unchanged step count.

## Scripted adversarial coverage

Existing strict report validation still rejects non-string timestamps,
malformed JSON, missing or extra schema fields, unsafe paths, false success,
incorrect step counts, and inconsistent nested evidence. Checkpoint execution
will additionally run the same benign prior exact report through both hosts and
then run the existing isolated malformed-report suite. No candidate file or
malware fixture is executed.

## Evidence state

No checkpoint-2234 passing result is claimed during scripting. After the full
batch was scripted, Windows PowerShell 5.1 and PowerShell 7 parser checks passed,
the focused valid 263-step checkpoint-2233 report passed under both hosts, and
numeric/object timestamp plus malformed JSON fixtures were rejected `4/4`.
Source contracts pass `664/664`.

Broad local regression passes Native `517/517` with 19 intentional isolated
child-fixture ignores plus signature compiler `6/6`, Local `536/536`, Guard
`248/248 + 249/249`, Flutter analyze, and Flutter `838/838`. A combined root
workspace run passed platform security, update service, API, and Local Core,
then Defender blocked its separate Native test executable with OS error 225.
That combined run is fail-visible and uncredited; the exact standalone Native
suite above passed without changing Defender.

The definitive report passes exact `263/263`, with zero failed verifier steps,
`include_defender_eicar=false`, `skip_rust=false`, and `skip_flutter=false`, in
`469.9s`. Its post-report strict validator passes first under Windows PowerShell
5.1 and then under PowerShell 7. Eight full-suite mutations per host covering
timestamp type confusion, status/options, cardinality, required dual-host scope,
and failed-step evidence are rejected `16/16`. Hosted, integration,
synchronization, and destination evidence remain pending.

## Limits

This repairs evidence parsing only. It does not expand antivirus detection,
quarantine, installed-service, signing, driver, or pre-execution capability.
Both PowerShell hosts remain trusted verification prerequisites. The change
adds no dependency, feature, or lockfile change.
