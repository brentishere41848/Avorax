# Flutter Core Service Health Verification

Date: 2026-07-17

Checkpoint: 2163

## Scope

This checkpoint connects the Flutter desktop client to the native, read-only
Windows Core Service health probe. It does not move scan, quarantine, allowlist,
update, or service-control mutations across the privileged service boundary.

## Verified

- Flutter launches the local-core executable with exactly one additional
  read-only mode argument: `--service-ipc-health`.
- Probe stdin is closed; stdout is limited to 16 KiB; stderr is bounded; a
  ten-second outer timeout terminates and reaps a stalled child process.
- The parser requires the exact protocol-v1 schema and validates local named
  pipe transport, no network exposure, health-only scope, both authentication
  flags, nonzero equal server/service PIDs, service readiness, consistent
  `ok`/engine readiness, definition-count limits, and bounded limitations.
- Protection and Settings render the service boundary independently from stdio
  scan health. Missing or degraded Windows service evidence cannot produce the
  full `Protected` state.
- Support-bundle diagnostics record the same bounded boundary status, protocol,
  transport, scope, authentication, PID-match, readiness, counts, limitations,
  and diagnostic evidence without adding file contents or payloads.
- Benign Dart subprocess fixtures verify a valid response, the exact read-only
  argument, oversized-output failure, timeout cleanup, and visible diagnostics.
- No live malware, malware repository, service installation, driver operation,
  Defender change, or machine-wide mutation was used.

## Partial

- The native helper performs SCM/pipe PID authentication, while Dart validates
  the helper's strict report. Dart does not independently query SCM or verify
  the helper's Authenticode signature.
- Installed Windows UI to installed Core Service behavior, pipe/service ACLs,
  service recovery, and package installation remain outside this checkpoint.
- The broad scan/quarantine stdio route remains per-process and unprivileged;
  service command mediation is not implemented.

## Disabled Or Blocked

- Every service mutation command remains disabled at the named-pipe boundary.
- External malware sample repositories remain metadata-only and disabled. They
  are not downloaded and cannot become active blocking definitions without a
  reviewed canonical SHA-256-only feed and signed versioned activation.
- Production publisher signing and installed trusted-helper proof are blocked
  on protected signing credentials and release-host validation.

## Technical Limits

- User-mode health and monitoring do not prove pre-execution blocking.
- Kernel enforcement requires a reviewed, built, signed, installed, and tested
  driver plus authenticated service/driver IPC.
- A compromised trusted helper process can fabricate its own report; executable
  ACL, publisher, package, and host integrity remain part of the trust boundary.
- Secure erasure on SSDs is not claimed.

## Commands And Results

```text
dart format <changed Dart files>
PASS: all changed Dart files formatted.

flutter test test/local_core_ipc_diagnostics_test.dart test/settings_native_status_test.dart
PASS: 74 tests before adding the Windows subprocess cases.

flutter test test/local_core_ipc_diagnostics_test.dart
PASS: 78 tests, including strict parser, real benign subprocess, oversized
output, timeout termination/reaping, timeout-bound enforcement, control-text
normalization, and existing IPC regressions.

flutter test test/offline_scan_test.dart --plain-name "Windows full protection"
PASS: 2 tests; unavailable boundary remains partial, ready authenticated
boundary permits full protection with ready engine and running driver evidence.

flutter test test/offline_scan_test.dart
PASS: 185 tests.

flutter test test/settings_native_status_test.dart
PASS within the combined focused run; service boundary row rendered.

flutter analyze
PASS: No issues found (29.8s).

flutter test --reporter compact
PASS: 821 tests. An initial full run passed 820 tests and found one stale
source-policy assertion for the old driver-plus-engine condition; the assertion
was updated to require the new service boundary, passed alone, and the complete
suite then passed.

flutter test test/local_event_test.dart
PASS: 44 tests after service-boundary support-bundle evidence was added.
```

Final repository-wide source contracts, diff checks, and CI results are recorded
in the pull request evidence for this checkpoint.
