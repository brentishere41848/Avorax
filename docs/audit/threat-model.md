# Avorax Threat Model

Date: 2026-07-08

This document records the defensive threat model for the current small-threat
MVP. It is intentionally conservative: a feature is trusted only when the
repository has executable proof and the verification report names the proof.

## Protected Assets

- User files scanned through local-core quick/full/custom scan commands.
- Quarantine payloads and authenticated metadata.
- User trust decisions such as allowlist entries, protected roots, and trusted
  process paths.
- Local status, history, logs, and support-bundle evidence.
- Definition, rule, model, trust, and update-package assets.

## Trust Boundaries

- Flutter UI to local-core IPC over stdio is local process IPC, not a network
  trust boundary.
- Release local-core JSON responses are untrusted until parsed, schema-checked,
  and surfaced with visible errors.
- Engine assets, update packages, allowlist files, quarantine stores, and
  status reports are treated as local input and must be bounded, validated, and
  fail visible.
- User-mode watcher and process-observation paths are best-effort only. They do
  not claim pre-execution blocking, kernel coverage, or persistent service
  monitoring.
- Signed driver and elevated service behavior are outside the verified MVP until
  installed service/driver IPC, signing, and recovery evidence exists.

## Current Defensive Controls

- Detection uses local signatures, local rule/static analysis, bounded archive
  analysis, heuristics, trust-store checks, and explainable verdict evidence.
- Local scan wrappers count release-binary progress events for Quick/Full scan
  paths, prove explicit folder auto-quarantine keeps benign neighbors in place,
  support detect-only `-FailOnThreat` failure semantics for automation, and fail
  visible on unsafe targets, repo-escaping report paths, and unexpected
  non-progress stdout.
- Cancel-scan wrappers require explicit isolated or installed runtime selection,
  create a validated cooperative cancel token, and do not claim process kill,
  service, persistent monitoring, or kernel/pre-execution behavior.
- Quarantine operations require authenticated metadata/integrity checks,
  confirmation-gated manual quarantine of explicit file targets, detect-only
  rescan of stored `.avoraxq` payloads, and confirmation for restore/delete
  wrappers.
- Allowlist mutation wrappers require explicit confirmation and file-scoped
  evidence.
- Status/health wrappers classify readiness as `ready`, `degraded`, or
  `unavailable`; `-RequireReady` fails visible on degraded status.
- Update verification uses signed manifests/packages and failure-safe activation
  and rollback fixtures.
- Verification uses benign fixtures, EICAR only where explicitly allowed, and
  no live malware.

## Key Abuse Cases

| Abuse case | Current mitigation | Remaining limitation |
| --- | --- | --- |
| Malformed scan/archive input hides errors | Bounded file walkers, archive limits, fail-visible parser and release smokes | Not every archive format is supported |
| Long local scans appear stuck or fake-complete | Local scan wrapper progress smoke requires release-binary progress events and report counts | Installed UI progress click-through and external cancellation E2E remain partial |
| Automation treats a threat result as success or a folder action removes benign files | `-FailOnThreat` returns visible failure while preserving detect-only behavior; explicit folder auto-quarantine smoke proves the known-bad fixture is removed and the benign fixture remains | Installed UI/service folder scan click-through remains partial |
| Bad scan input creates fake reports or writes evidence outside the repo | Local scan wrapper path-guard smoke proves missing targets, wrong target kind, and repo-escaping report paths fail visibly before scan-report creation | Installed UI/service filesystem picker E2E remains partial |
| Cancel control writes to an unintended runtime or claims hard blocking | Cancel wrapper requires `-DataRoot` or explicit `-UseInstalledDataRoot`, validates the `cancel-active-scan` token path, documents cooperative-token limits, and has path/report guard proof that rejected input writes neither a report nor an outside-path cancel token | Installed UI/service cross-process cancellation E2E remains partial |
| User trusts a malicious path accidentally | Confirmation-gated allowlist wrapper, target validation, no broad-root wrapper support, and path/report guard proof for unconfirmed mutation and repo-escaping report rejection | Folder/hash wrapper support remains partial |
| Quarantine restore writes unsafe data/path | Quarantine metadata/payload tamper smokes, restore/delete confirmation | Installed UI/service E2E remains partial |
| Manual quarantine is used on the wrong file or becomes a silent destructive control | Manual quarantine wrapper requires a concrete non-reparse leaf file, bounded labels, and `-ConfirmAction`; Flutter manual quarantine requires confirmation before file picker access, refuses busy states, and sends explicit `quarantine_file` labels; smokes prove confirmed quarantine creates a real `.avoraxq` payload through release local-core | Installed packaged file-picker click-through and service-mediated manual quarantine remain partial |
| Bad quarantine input creates fake reports or unsafe mutation | Quarantine wrapper path-guard smoke proves missing manual targets, directory targets, invalid quarantine IDs, and repo-escaping report paths fail visibly before report creation or quarantine mutation | Installed UI/service filesystem picker and service-mediated quarantine E2E remain partial |
| Quarantine rescan mutates or executes isolated payloads | Rescan wrapper rejects confirmation, scans only existing `.avoraxq` payloads in detect-only mode, and records no restore/delete safety flags | Installed service/UI rescan click-through remains partial |
| A later informational scan event hides a security warning in the shell notification area | Shell notification selection now ranks recent local events by severity, so `error` and `warning` events win over newer informational events, with newest-event tie-breaking at the same severity | This is in-app local-event notification evidence only; Windows toast delivery and installed packaged UI click-through remain partial |
| Timed-out helper commands leave child processes running | Flutter timeout paths now use bounded Windows process-tree cleanup for Avorax-spawned children and tests assert injected hung Dart fixtures exit | Installed desktop/service subprocess E2E and OS service supervision remain partial |
| Bad watch input creates fake reports or watches broad roots | Watch wrapper path-guard smoke proves missing paths, missing roots, file roots, broad filesystem roots, and repo-escaping report paths fail visibly before watch polling or report creation | Installed service/background monitoring E2E and scheduled startup remain partial |
| Status UI or installed smoke claims health from misleading output | Health IPC diagnostics, `avorax-status.ps1`, `-RequireReady`, path/report guards, and a bounded installed-smoke parser requiring exactly one typed JSON health response plus canonical binary/ready-engine checks | Actual installed service/driver proof remains blocked on release-host prerequisites |
| Installed smoke reports protection without exercising file lifecycle postconditions | Installed lifecycle probe uses harmless exact-hash fixtures and fails unless scan quarantine removes the source, list returns the record, restore reproduces the original SHA-256 and removes the payload, and confirmed delete leaves source/payload absent; its generated report is independently schema-validated | Release-binary execution and installed-smoke wiring are verified; actual installed service mediation and packaged UI click-through remain blocked |
| Portable package is modified, path-traverses on extraction, or claims installed protection | Builder hashes every packaged file after ready/lifecycle proof; archive smoke applies entry/count/size/total/ratio/path/duplicate limits, rejects manifest tampering, and reruns status/lifecycle from a fresh extraction; package/docs deny service, persistence, Defender replacement, and pre-execution claims | Local ZIP is unsigned and manual/finite user-mode only; transport authenticity and installed protection are not claimed |
| User-mode watcher is mistaken for kernel protection | Watch wrappers and UI copy record no-service/no-kernel/no-pre-execution limits | Persistent background monitoring remains partial |
| Network/update content is trusted blindly | Signed package verifier, tamper/restricted-payload/rollback smokes | Production signer ceremony and deployment approval remain blocked |

## Checkpoint 2153 Portable Beta Threat-Model Note

The interim portable beta treats its own bundle and ZIP as untrusted local
input. The builder packages only the canonical executable and required runtime
engine areas, verifies ready local stdio/no-network health and the harmless
quarantine lifecycle, then records every file size and SHA-256. The independent
archive smoke rejects traversal, case-insensitive duplicates, oversized or
over-compressed entries, manifest hash tampering, unmanifested files, reparse
paths, and runtime/lifecycle regressions after fresh extraction. Cleanup is
restricted to checked GUID-named temporary roots. The archive is unsigned and
therefore is not a trusted distribution channel; it must not be represented as
an installed service, persistent monitor, Defender replacement, driver, or
pre-execution blocker.

## Checkpoint 2151 Structured Installed Health Threat-Model Note

The installed smoke no longer treats a raw `"ok":true` substring as proof that
the installed core is healthy. A shared bounded probe now requires exactly one
structured JSON response, typed health fields, local stdio/no-network status,
and visible failure for malformed, ambiguous, or rejected output. Installed
verification additionally checks the canonical core/alias hashes and requires
available/ready engine state, loaded signature and rule packs, and native
self-test success. A safe release-binary smoke proves the parser and launch
boundary, but it does not claim an installed service or packaged UI on this
host; those remain blocked by documented build-host prerequisites.

## Checkpoint 2152 Installed Core Lifecycle Threat-Model Note

Installed validation now requires observable file-lifecycle postconditions, not
only a healthy process response. The lifecycle probe uses two harmless ASCII
fixtures with a temporary exact-hash signature, isolated data/quarantine/engine
roots, and the production local scan/quarantine wrappers. It verifies source
removal and a quarantine-root-contained `.avoraxq` payload, list consistency,
confirmed restore with the original SHA-256 and payload removal, and a separate
confirmed delete with source/payload absence. Cleanup is restricted to a
GUID-named direct child of the checked Windows temp root. The resulting report
explicitly denies Defender exclusions, machine-wide changes, service/driver
installation, installed service mediation, secure erase, and pre-execution
blocking. This closes a future installed-smoke fake-success gap, but the current
host still lacks packaged installation/service/UI evidence.

## Checkpoint 2150 Status/Allowlist/Cancel Path Guard Threat-Model Note

Status, allowlist, and cooperative scan cancellation now have release-binary
negative-input evidence. Missing engine roots, unconfirmed allowlist mutations,
missing or conflicting cancel data-root choices, and report paths outside the
repository fail visibly without creating requested negative reports. The cancel
outside-report case additionally proves that no `cancel-active-scan` token is
written after report-path rejection. These checks prevent invalid controls from
being represented as successful actions or producing evidence outside the
repository. They do not prove installed service mediation, packaged UI
click-through, persistent monitoring, scheduled startup, driver operation, or
pre-execution blocking.

## Checkpoint 2149 Watch Path/Report Guard Threat-Model Note

The finite watch-scan wrapper now has release-binary smoke evidence that unsafe
inputs fail before local-core watch polling or report creation. The smoke proves
missing `-Path`, missing watched roots, file paths used as roots, broad
filesystem roots, and absolute report paths outside the repository all fail
visibly and write no requested negative reports. This keeps finite user-mode
watch validation from becoming broad-root surveillance or fake success evidence.
The proof does not claim installed background service monitoring, scheduled
startup, Defender changes, kernel/pre-execution blocking, or live malware
behavior.

## Checkpoint 2148 Timeout Process-Tree Cleanup Threat-Model Note

Timeout handling for Flutter-spawned Windows helpers now treats leaked child
processes as a security and reliability risk rather than accepting a parent-only
kill as sufficient. App detection, platform probing, local-core IPC, Guard
self-test, cancel IPC, and elevated PowerShell timeout paths attempt bounded
cleanup with the checked local `taskkill.exe /PID <pid> /T /F` for the specific
Avorax-spawned child process, then fall back to existing kill/reap diagnostics
if that cleanup fails. Runtime tests inject sleeping Dart fixtures and assert
those processes exit after timeout. The finite watcher smoke was also hardened
against startup races so event proof is not accidentally converted into
baseline-only evidence. This does not claim installed service supervision,
persistent monitoring, Defender changes, kernel/pre-execution blocking, or live
malware behavior.

## Checkpoint 2147 Quarantine Path/Report Guard Threat-Model Note

The quarantine wrapper now has release-binary smoke evidence that unsafe
destructive inputs are rejected before local-core mutation or report creation.
The smoke proves missing manual quarantine targets, directory targets, invalid
quarantine IDs, and absolute report paths outside the repository all fail
visibly and do not write the requested reports. This keeps local automation from
mistaking invalid quarantine commands for successful actions and keeps evidence
repo-contained. The proof does not claim installed service mediation, packaged
UI click-through, secure deletion, or pre-execution blocking.

## Checkpoint 2143 Manual Quarantine UI Threat-Model Note

The Quarantine tab now treats manual file quarantine as a destructive user
intent flow instead of an inert surface. The UI requires confirmation before the
file picker opens, then the controller rechecks scan, configuration, update, and
quarantine mutation busy states before local-core IPC. Canceled picker results
clear target-selection state without quarantine, picker errors become visible
state/audit failures, and successful selections send `quarantine_file` with
explicit `path`, `threat_name=Manual quarantine`, and
`engine=avorax-ui-manual-quarantine`. Widget/controller/IPC tests and the full
small-threat verifier now cover those guards; installed packaged file-picker
click-through and service-mediated quarantine remain partial.

## Checkpoint 2144 Shell Notification Priority Threat-Model Note

The shell notification area now treats security events as higher priority than
ordinary informational completion events. `ZentorShell` scans the recent local
event window, selects `error` before `warning` before info events, and only uses
newer timestamps as a tie-breaker within the same priority. Widget tests cover a
`threat_detected` warning remaining visible when a newer `scan_completed` info
event exists, plus newest warning selection when priority matches. This does not
claim OS toast delivery, persistent notification history beyond the local event
log, or installed packaged click-through coverage.

## Checkpoint 2142 Manual Quarantine Threat-Model Note

The quarantine wrapper treats manual quarantine input as destructive local user
intent. `Quarantine` requires an existing non-reparse target file and explicit
`-ConfirmAction`; it rejects quarantine IDs for that action so the command
cannot ambiguously mutate an existing record. Threat and engine labels are
trimmed, non-empty, NUL-free, and bounded before IPC. The release-binary smoke
proves missing confirmation fails without removing the source, while confirmed
manual quarantine creates a real quarantined record, preserves the supplied
labels, removes the source into an opaque `.avoraxq` payload, and records no
live malware, no standard EICAR string, no Defender exclusion, no service
install, no pre-execution claim, and no secure-erase claim.

## Checkpoint 2141 Cancel-Scan Threat-Model Note

The cancel-scan wrapper treats cancellation as a cooperative token request. It
will not silently use the installed data directory: callers must provide an
isolated `-DataRoot` or explicitly select `-UseInstalledDataRoot`. The wrapper
validates the release local-core response, requires an absolute
`cancel-active-scan` token path, verifies isolated tokens stay under
`DataRoot\runtime`, and reports no service installation, external process kill,
persistent monitoring, or pre-execution/kernel blocking claim. Local-core
regression tests cover scan-loop observation of cancellation; installed
UI/service cross-process cancellation remains partial.

## Checkpoint 2140 Local Scan Progress Threat-Model Note

The local scan wrapper treats release local-core stdout as untrusted JSON lines.
Progress lines are counted only when they parse as progress events; other JSON
responses are kept as scan responses, and malformed stdout fails visible. The
checkpoint 2140 smoke proves a detect-only Quick scan over a harmless exact-hash
fixture records progress events, detects the fixture, quarantines nothing, and
keeps the source file in place.

## Checkpoint 2145 Local Scan Folder/Fail-On-Threat Threat-Model Note

The local scan wrapper now has release-binary smoke evidence for the two
automation-sensitive edges around user-facing scans. Explicit `Folder` scanning
with confirmed quarantine scans a folder containing one harmless known-bad
fixture and one benign neighbor, quarantines only the known-bad fixture, and
leaves the benign file in place. `-FailOnThreat` keeps the default detect-only
behavior, writes a report, preserves the source file, and returns visible
failure semantics so scripts do not treat a threat result as success.

## Checkpoint 2146 Local Scan Path/Report Guard Threat-Model Note

The local scan wrapper now has release-binary smoke evidence that unsafe input
is rejected before scan execution or report creation. The smoke proves a missing
target, a `File` scan pointed at a folder, and an absolute report path outside
the repository all fail visibly and do not write the requested report. This
keeps automation from mistaking invalid input for clean scans and keeps wrapper
evidence repo-contained.

## Checkpoint 2139 Quarantine Rescan Threat-Model Note

The quarantine wrapper treats quarantine records and stored payload paths as
untrusted local input. `Rescan` requires an existing quarantined record, resolves
only an absolute `.avoraxq` payload under the checked quarantine root, rejects
reparse payloads, and invokes local-core in `detectOnly` mode. The smoke evidence
proves the rescan reports a threat without creating a new quarantine, restoring
the original path, deleting the payload, executing content, or weakening
Microsoft Defender.

## Checkpoint 2138 Status Threat-Model Note

The status wrapper treats local-core health output as untrusted IPC until the
required fields are present. It writes a report only after shape validation,
classifies incomplete health as `degraded`, and keeps readiness failure visible
through `-RequireReady`. The smoke evidence deliberately observes `driver_status
= missing`, inactive monitors, and failed native self-test prerequisites rather
than converting those limitations into a green protection claim.

## Out Of Scope Until Proven

- Live malware testing.
- Pre-execution blocking without signed installed driver evidence.
- Kernel realtime blocking without driver IPC and signing evidence.
- Secure deletion guarantees, especially on SSDs.
- Production ML protection claims without production metadata, model review, and
  false-positive-rate evidence.
- Machine-wide installs, Defender exclusions, or Windows security weakening
  without explicit approval and isolated verification.

## Cross-Platform Package Boundary

The desktop packages are untrusted-input containers until their manifests and
hashes pass. Native CI therefore verifies staged payloads, then verifies the
actual administrative extraction, archive extraction, or mounted DMG payload
before running the bounded local-core lifecycle smoke. The smoke creates only an
isolated harmless exact-hash fixture, never executes it, and proves detect-only,
confirmed quarantine, list, and integrity-preserving restore. It does not start
a service, install a driver, alter Microsoft Defender, use network content, or
claim pre-execution blocking.

The Windows beta has no Authenticode publisher identity. The macOS beta uses an
ad-hoc signature and is not notarized, so Gatekeeper rejection is expected and
recorded instead of suppressed. These artifacts are acceptable only as an
explicit experimental prerelease with hashes and warnings. Production release
remains blocked on protected signing credentials, installed-host privilege/IPC
verification, platform distribution approval, and a complete dependency review.

Linux/macOS update mutation controls remain unavailable because the signed
`.aup` activation implementation is Windows-specific. The UI exposes manual
reinstall guidance on those platforms, avoiding a dead control or false update
success. Network update content remains untrusted and must never be activated
without the existing signed-manifest/package verification path.

## External Sample Repository Boundary

The registered GitHub sample repositories are discovery/attribution surfaces,
not definition authorities. Avorax may request bounded repository and recursive
tree metadata, but it must not request blob contents, clone repositories, fetch
archives/releases, execute samples, or derive active signatures by handling
sample bytes. Git blob SHA, path, filename, extension, and inferred family are
low-confidence observations and have `auto_quarantine_allowed=false`.

Only reviewed SHA-256 rows from a hash-only feed may become confirmed exact-hash
signatures, and public network content must still pass a versioned signed Avorax
definition package before activation. Until such a feed exists, automatic
blocking attributed to these repositories is disabled and Microsoft Defender
must remain enabled.

## Checkpoint 2155 Failure-Visibility Boundary

Local verification tooling is part of the release trust boundary: a missing
helper, failed artifact enumeration, or failed dependency wildcard enumeration
must not be converted into empty or successful evidence. Expected absence is
handled narrowly, while unexpected PowerShell errors stop the verifier. macOS
DMG verification may retry only the exact short-lived `hdiutil` resource-busy
diagnostic, at most three times; malformed or persistently unavailable images
still fail and cannot reach mount, manifest, signing, or packaged-core proof.

## Checkpoint 2156 Native Cleanup Boundary

Host tool absence is an expected discovery outcome, but it must flow into the
existing checked executable failure instead of being hidden. A signed macOS app
without readable entitlement evidence cannot be classified as suitable for the
scanner package, because an unnoticed sandbox entitlement would make filesystem
protection claims misleading. Emergency DMG detach is also security-relevant
cleanup: failure is reported and can fail an otherwise successful build, while
an existing build failure remains the primary nonzero status.
