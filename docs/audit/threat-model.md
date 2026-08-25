# Avorax Threat Model

Date: 2026-07-18

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
- Windows Core Service exposes a separate local named-pipe v1 boundary. Windows
  authenticates the client token, remote clients are rejected, and the current
  command allowlist contains only read-only `health`; Flutter does not yet use
  this boundary for scan or mutation commands.
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
| Missing or invalid file modification time hides a same-size rewrite from the finite watcher | Modification time is optional evidence; query/pre-epoch failures are bounded diagnostics, unknown timestamps are never inserted into baseline or unchanged caches, and the candidate is conservatively rescanned under existing limits | This remains post-write finite polling; persistent notification/service and pre-execution coverage are not provided |
| Suspicious process arguments are hidden after a long benign command prefix | Flutter and Local Core retain bounded command-line head and tail evidence, propagate source truncation explicitly, inspect retained tail flags, and conservatively mark truncated security-sensitive commands for review | Omitted middle text cannot be reconstructed; this is snapshot-only review and does not stop or quarantine processes |
| Status UI or installed smoke claims health from misleading output | Health IPC diagnostics, `avorax-status.ps1`, `-RequireReady`, path/report guards, and a bounded installed-smoke parser requiring exactly one typed JSON health response plus canonical binary/ready-engine checks | Actual installed service/driver proof remains blocked on release-host prerequisites |
| Installed smoke reports protection without exercising file lifecycle postconditions | Installed lifecycle probe uses harmless exact-hash fixtures and fails unless scan quarantine removes the source, list returns the record, restore reproduces the original SHA-256 and removes the payload, and confirmed delete leaves source/payload absent; its generated report is independently schema-validated | Release-binary execution and installed-smoke wiring are verified; actual installed service mediation and packaged UI click-through remain blocked |
| Portable package is modified, path-traverses on extraction, or claims installed protection | Builder hashes every packaged file after ready/lifecycle proof; archive smoke applies entry/count/size/total/ratio/path/duplicate limits, rejects manifest tampering, and reruns status/lifecycle from a fresh extraction; package/docs deny service, persistence, Defender replacement, and pre-execution claims | Local ZIP is unsigned and manual/finite user-mode only; transport authenticity and installed protection are not claimed |
| A process chooses a lookalike `X:\Windows\System32` path to evade Guard polling inspection | Guard creates one immutable skip policy from bounded `GetSystemWindowsDirectoryW` output; other-drive, `Windows.old`, traversal, and user-profile lookalikes do not receive the Windows-system skip | The actual Windows `System32`/`SysWOW64` and `Explorer.exe` exclusion remains broad and path-based; polling is post-launch and can miss short-lived processes |
| User-mode watcher is mistaken for kernel protection | Watch wrappers and UI copy record no-service/no-kernel/no-pre-execution limits | Persistent background monitoring remains partial |
| Network/update content is trusted blindly | Signed package verifier, tamper/restricted-payload/rollback smokes | Production signer ceremony and deployment approval remain blocked |

## Checkpoint 2171 Watch-Timestamp Threat-Model Note

The finite watcher no longer converts failed or pre-Unix-epoch modification
timestamps to zero. Zero was ambiguous with a real epoch value and could make a
same-size rewrite appear unchanged after baseline caching. Timestamp evidence is
now optional: only a valid timestamp may enter the baseline or unchanged-file
cache. An unavailable timestamp produces a bounded visible scan diagnostic and
the candidate is rescanned rather than trusted as unchanged. Rechecks remain
bounded by the existing 10-second duration, 512-file pass, depth-eight, and
32-event maxima. This improves post-write observation only; it does not add a
persistent service, OS notification subscription, kernel blocking, or
pre-execution protection.

**Local execution:** Focused real-child and adversarial masks, complete
Authenticode, both locked workspaces, strict lint, release trust smoke, Flutter
`838/838`, source contracts `649/649`, safety/dependency gates, and exact
verifier/validator `249/249` in `470.3s` pass. Eight malformed reports are
rejected. Hosted, merge, synchronization, and destination evidence remain
pending; the ownership and cross-identity limitations above remain unchanged.

## Checkpoint 2172 Process Command Truncation Threat-Model Note

The Windows process snapshot path no longer discards every command-line
character after a fixed prefix. Flutter retains a bounded head and tail sample
and reports whether the middle was omitted. Local Core independently bounds
direct input, evaluates suspicious flags in either retained end, and sends a
truncated script host or network-capable utility to review at the default
threshold. This closes a simple benign-prefix evasion without pretending that
omitted text was inspected. The result remains a user-mode point-in-time
`suspiciousProcess` finding only; it does not terminate, quarantine, persistently
monitor, or block execution.

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

## Checkpoint 2193 DMG Verification Threat-Model Note

A just-created DMG is not trusted merely because `hdiutil create` returned
success. Merged-main evidence showed `hdiutil verify` can race the hosted
macOS disk-image helper and return `Resource temporarily unavailable` before
the image settles. The builder now performs a fixed settle and retries only
that exact transient response within a 33-second total settle/backoff bound.
All other verification errors fail immediately, and exhausting the transient
budget returns the real failure status. The mounted manifest, payload,
signature, entitlement, Gatekeeper, checksum, and lifecycle checks remain
mandatory. This change improves package-build availability; it does not make an
ad-hoc signature a Developer ID signature, provide notarization, install the
package, or establish runtime antivirus protection.

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

## Checkpoint 2157 Dependency Inventory Boundary

Lockfiles and their checksums are untrusted build inputs until bounded parsing
and consistency checks pass. The release inventory rejects linked/reparse or
changing inputs, malformed lock structures, non-exact Python requirements,
hosted pub packages without pub.dev SHA-256 evidence, conflicting hashes,
duplicate fields, excessive component counts, and unsafe output targets. The
result is deterministic, atomically activated, independently schema-valid, and
covered by the release checksum file. It describes reviewed lockfile contents,
not reachability in final binaries, license compatibility, vulnerability status,
or signed provenance; those distinctions remain machine-readable in the BOM.

## Checkpoint 2158 Service Status Boundary

Windows Service Control Manager status is security evidence and must not turn an
unexpected monitoring failure into a clean stop. The Guard Service now exposes a
bounded pending-start state, restricts accepted controls to the running state,
and reports monitor failure with a nonzero service-specific exit code. If final
status reporting also fails, both failures remain in the fatal diagnostic. This
does not authenticate UI-to-service commands or prove installed service recovery:
the current Flutter/local-core boundary remains per-process stdio, and privileged
service IPC, service ACLs, restart policy, driver signing, and elevated-host E2E
remain required before claiming persistent or pre-execution protection.

## Checkpoint 2159 Service Query Boundary

Service status text is locale-dependent, and a failed helper process can emit
attacker-influenced or misleading diagnostics. Local Core and Guard therefore
no longer infer `missing`, `off`, `running`, or `stopped` from `sc.exe` output.
They use typed Service Control Manager status with least query privilege and a
fixed service-name allowlist. Only numeric error `1060` means absent; access
denial, malformed names, and other API failures stay unknown with diagnostics.
This reduces parsing and child-process attack surface but is observation only:
it does not authenticate commands to a privileged service, validate installed
service ACL/recovery configuration, start or stop services, or prove persistence
or pre-execution blocking.

## Checkpoint 2160 Core Service Startup Boundary

A service that reports running before its detection engine is ready, or exits
during warmup without a failing SCM status, can create false protection health.
Core Service now enters a bounded pending state first and becomes running only
after native-engine warmup. Warmup and runtime failures produce a nonzero
service-specific stop status, while failure to publish that status is retained
alongside the primary error. This proves state mapping and failure preservation,
not installed service supervision: recovery actions, ACLs, privileged IPC,
restart behavior, and elevated-host lifecycle remain outside the verified scope.

## Checkpoint 2161 Authenticated Core Service IPC Boundary

Running Local Core's broad stdio command handler as `LocalSystem` would turn
file-system and quarantine commands into an unsafe confused-deputy boundary.
Core Service therefore exposes a separate Windows named pipe with an explicit
SYSTEM/Administrators/Authenticated Users ACL, `PIPE_REJECT_REMOTE_CLIENTS`, and
exclusive first-instance creation. The server reads at most one 16 KiB message,
obtains the local client PID, impersonates the client, opens its query token,
and must successfully `RevertToSelf` before parsing or answering. Revert failure
terminates the IPC worker and becomes a failing service runtime result.

Protocol v1 rejects unknown fields, invalid versions, malformed JSON, empty or
oversized request IDs, and every command except read-only `health`. The health
response omits installation and data paths and states `healthOnly`, no network
exposure, non-production ML status, and the user-mode limitations. A real local
pipe fixture verifies client PID/token authentication, first-instance collision
failure, malformed input, mutation denial, 16 KiB enforcement, recovery after
oversized input, worker liveness, and bounded shutdown. This does not authorize
mutations, connect Flutter to the service, validate the installed service ACL or
recovery policy, or prove persistent/pre-execution protection.

## Checkpoint 2162 Pipe Server Authentication Boundary

An explicit pipe ACL and exclusive first-instance flag do not by themselves let
an unprivileged client prove which process answered. The native health client
therefore reads the running Core Service PID from typed SCM status, opens only
the fixed local pipe, obtains the pipe server PID from the connected handle, and
requires both identities to match. It queries SCM again after receiving the
response; a stopped/restarted service, zero PID, mismatched server, or changed
PID fails closed. The service name remains allowlisted and the SCM/service access
rights remain `CONNECT` and `QUERY_STATUS` only.

The client uses overlapped named-pipe reads and writes with finite waits,
`CancelIoEx`, and completed-operation reaping so a same-name stalled server
cannot hang the caller. It accepts one bounded strict protocol-v1 health response
whose request ID and authenticated client PID match, whose scope remains
`healthOnly`, and whose transport remains local and non-networked. Counts and
limitation text are bounded, contradictory data/error fields and unknown JSON
fields are rejected, and no mutation command can be selected. This authenticates
the read-only native probe in local fixtures; it does not defend against code
already executing inside the trusted service process, authorize privileged
mutations, prove installed service ACL/recovery configuration, connect Flutter,
or provide kernel/pre-execution enforcement.

## Checkpoint 2163 Flutter Service-Evidence Boundary

The Flutter client previously combined broad per-process stdio engine health
with a textual service-state field. A running status did not prove that the UI
had reached the registered Core Service or that the named-pipe server matched
the Service Control Manager process. Flutter now invokes the native helper only
in `--service-ipc-health` mode and treats its single JSON document as untrusted
until strict schema and semantic validation pass. The client bounds stdout to
16 KiB, bounds diagnostics, closes stdin, applies a ten-second outer timeout,
and terminates and reaps a stalled helper. Unknown/missing fields, wrong
protocol/transport/scope, network exposure, false authentication, zero or
mismatched service/server PIDs, contradictory `ok` and engine readiness,
excessive counts, and malformed limitations fail closed with visible detail.

The service-boundary result is stored separately from stdio scan readiness and
is shown in Protection and Settings. On Windows, full protection additionally
requires a ready authenticated boundary; unavailable or degraded evidence can
only produce partial protection. This does not independently authenticate the
native helper binary from Dart. A writable, replaced, or untrusted helper could
fabricate JSON, so installed executable ACLs, trusted publisher signing, package
authenticity, and installed service/pipe lifecycle remain required TCB and E2E
evidence. The service API remains health-only, and no mutation, persistence,
kernel enforcement, or pre-execution claim is added.

## Checkpoint 2164 Signed Hash-Intelligence Boundary

External malware repository trees are attacker-controlled metadata and do not
provide canonical file SHA-256 evidence. Treating Git blob identifiers, paths,
filenames, extensions, or repository labels as confirmed malware would allow a
third party to induce false positives and destructive quarantine. Avorax keeps
those sources disabled and metadata-only. It never downloads sample bytes to
manufacture hashes for this workflow.

The reviewed-hash boundary now requires a non-empty pack whose every active row
is a unique lowercase SHA-256 exact hash with confirmed confidence, critical
severity, a production threat category, global file scope, empty context, and
`quarantine_if_policy_allows`. Compilation and validation occur in unique local
temporary files; only a validated regular pack atomically replaces the target.
Failure cleanup revalidates temporary files, and an existing known-good pack is
preserved when validation fails.

The definitions-only package wrapper accepts checked local metadata and hashes,
uses bounded local child processes, rejects reparse-backed paths, requires one
and only one staged pack, and delegates signing, payload hashes, archive policy,
atomic staging, and rollback to the normal `.aup` verifier/applier. This reduces
schema, partial-write, path, and unsigned-update risk but does not prove source
truth, production key custody, release-host integrity, HTTPS publication, or an
installed service apply/rollback. Those remain release-process and installed-E2E
boundaries. The benign smoke verifies package construction and `--verify` only;
it does not apply definitions, install services, disable Defender, use malware,
or claim pre-execution blocking.

## Checkpoint 2165 Reviewed Feed Provenance Boundary

Source JSON and hash text remain untrusted even when supplied locally. Ambiguous
objects could previously hide misspelled or ignored fields, and permissive URL
text could misrepresent HTTP, credential-bearing, or fragment-qualified origins.
The hash importer now selects one exact metadata schema, validates the registry
template shape, requires safe HTTPS provenance when a URL is present, caps active
rows, and rejects canonical duplicates before atomic output.

This prevents configuration confusion and resource amplification, but a valid
URL and schema are not authenticity evidence. The importer does not contact the
URL, validate publisher control, or infer that a hash is malicious. Feed review,
false-positive ownership, signing-key custody, and authenticated publication
remain separate trusted release-process responsibilities.

## Checkpoint 2166 Engine Definition Revocation Boundary

Per-file overwrite left files that were absent from a new signed engine
component in place. For malware definitions this meant a false-positive or
revoked pack could remain active indefinitely even after a valid update. Engine
subcomponents now activate through a checked sibling directory: copy and
validation finish first, the existing component moves to a unique backup, the
staged component is renamed into place, and activation failure restores the
backup. Successful activation removes the backup; later apply failures still
use the normal pre-apply rollback snapshot.

The release smoke proves this behavior with benign text fixtures, temporary
install/data roots, and a fake service-control executable under a temporary
`SystemRoot`. It does not establish real installed ACLs, production signing-key
custody, actual service lifecycle behavior, or kernel/pre-execution blocking.

## Checkpoint 2173 Process Snapshot Response Integrity

Local Core process snapshot output crosses a subprocess IPC trust boundary.
Missing responses, explicit rejection, malformed required fields, or malformed
finding rows can remove evidence that would otherwise require review. Treating
such a response as a clean snapshot would create false success and could hide a
suspicious process from the event history.

The Flutter controller now requires both `report.ok` and an empty diagnostics
list before it may emit evaluated or suspicious success evidence. Rejection and
incomplete parsing instead produce a bounded warning and a `limited` active-loop
state. Existing valid findings in an incomplete response are not acted upon,
because their surrounding response cannot be trusted; the failure remains
visible for operator review.

This is fail-closed status handling, not process blocking. The app still uses
bounded point-in-time user-mode snapshots and does not terminate, quarantine,
or prevent process execution. Persistent service observation, authenticated
mutation IPC, signed-driver enforcement, and installed-host E2E remain separate
boundaries.

## Checkpoint 2174 Watch-Poll Response Consistency

A watch-poll response contains two related state claims: the watcher plan and
the finite poll summary. A compromised, malformed, or version-incompatible
subprocess could return `ok=true` while marking only one of those states active,
or use a mode that does not match the activity flag. Accepting that combination
as clean would create false monitoring evidence.

The IPC parser and controller now independently require equal watcher/poll
activity. Active evidence additionally requires `userModeBestEffort`, at least
one watched path, and `finiteUserModePolling`; inactive evidence requires a
stopped/off watcher and stopped poll. Contradictions become bounded warning
events and a `limited` loop state, never `watch_poll_loop_clean`.

This consistency check does not improve observation timing or provide process
or filesystem blocking. Watch-poll remains finite post-write user-mode polling
while the app is running. Persistent service monitoring, OS notifications,
kernel enforcement, and pre-execution blocking remain separate boundaries.

## Checkpoint 2175 Mutation Response Evidence

Local Core mutation responses cross a subprocess IPC boundary after actions that
change quarantine, allowlist, feedback, or protection configuration state. A
bare `ok=true`, a stale record, or a record for another identifier could make
the UI announce success even though the requested change was not demonstrated.
That false state is especially dangerous for quarantine and restore because the
operator may make later decisions based on a file location that was never
proved.

Flutter now validates action-specific success evidence before returning a
successful result. Quarantine-family records use the same strict parser as list
responses and must carry the expected status; identifier-bearing operations
must echo the requested identifier. Allowlist rows must be valid and have the
expected active state. Label and configuration writes must return a bounded
absolute local path. Any success response containing an error field also fails
closed.

This verifies response completeness, not independent post-write durability or
machine-wide service mutation. The native stores retain their existing atomic,
integrity, path, and ACL controls. Installed authenticated mutation IPC remains
disabled, and service/driver installation and pre-execution enforcement remain
separate boundaries.

## Checkpoint 2176 Protection Self-Test Response Integrity

Guard self-test output crosses a subprocess boundary and can be malformed,
truncated, version-incompatible, or contradictory. Previously the desktop
client ignored the process exit code, selected the final output line, accepted
partial JSON, and then classified the returned text by searching for failure
words. A failed or forged response without those words could therefore appear
as a clean result and receive success styling.

The client now requires zero exit, empty stderr, one bounded JSON line, the
exact Guard event envelope, exact self-test report and nested status schemas,
UTC timestamps within five minutes of each other, bounded control-free text,
one to 64 unique exact step objects, and agreement among every step, report
`passed`, `overall_result`, and outer `ok`. All other responses fail closed.
The controller and UI consume a typed boolean instead of reinterpreting text.

This gate does not authenticate a replacement executable by publisher and does
not establish installed service or driver state by itself. Installed binary
ACL/publisher validation, service lifecycle E2E, production driver signing, and
pre-execution enforcement remain separate controls and blockers.

## Checkpoint 2177 Windows MSI Verification Boundary

The Windows MSI is untrusted input even when it was produced by the release
workflow. Administrative extraction now runs only below a short opaque
temporary root after the MSI is bounded, opened as a regular non-reparse file,
and hashed. The verifier rejects excessive file count or aggregate bytes,
reparse entries, missing required payloads, manifest or lifecycle failure, and
any MSI mutation between the pre- and post-extraction hashes. Cleanup is limited
to the exact generated child of the configured temporary base and rejects
reparse paths.

A long-checkout extraction produced Windows Installer `1603`/`1304` at a
273-character output path; the same package passed under the bounded short root.
This prevents a host-path limitation from being reported as corrupt package
evidence or silently skipped. The verifier proves administrative extraction and
harmless packaged-core behavior only. It does not install Avorax, start a
service, establish installed ACLs, authenticate an unsigned publisher, or prove
driver/pre-execution enforcement.

## Checkpoint 2178 Explicit Driver Activation Boundary

A normal MSI/EXE install must never change kernel-driver state or Windows trust
stores merely because candidate driver files happen to be present in the build
tree. Driver package content is therefore inert: the MSI contains no deferred
driver custom action. The separate elevated helper requires the operator to pass
`-ConfirmDriverInstall` before resolving or invoking any driver-management tool.
The package verifier independently opens the built MSI database and rejects any
`CustomAction` table before extraction or packaged-core execution.

The helper may inspect a bundled certificate as package evidence but never calls
`certutil -addstore`, never imports into `Root` or `TrustedPublisher`, and never
enables TESTSIGNING. Windows remains the signature/catalog enforcement boundary
for the explicit `pnputil` request. This does not establish production driver
signing, installed driver health, rollback/uninstall behavior, or pre-execution
blocking; those still require approved signing and a disposable elevated host.

## Checkpoint 2179 Diagnostic Category Isolation

Risk-fusion explanations can contain untrusted filenames, paths, probe errors,
and command diagnostics. Substring-based category inference over those neutral
rows is unsafe and nondeterministic: a random `.tmpupTeBo` path in publisher
trust diagnostics contains `pup` and previously overrode positive Office macro
evidence to `PotentiallyUnwantedApp`.

Category inference now excludes evidence whose weight is zero. The diagnostic
is still retained and bounded in the verdict explanation, but only positive
detection evidence may assign a threat family. A regression fixture preserves
the exact path-shaped collision and requires `MaliciousMacro` from the real
macro signal. This does not turn diagnostics into detections or increase an
automatic-action score.

## Checkpoint 2180 Dependency Evidence And Readiness Boundary

Dependency and verification reports are security inputs because release gates
may use them to approve binaries. Platform line endings caused the Python exact
requirement regex to report zero packages and zero integrity entries while the
generator still exited successfully. If only the generator result were trusted,
incomplete dependency evidence could be mistaken for release readiness.

Generation and validation now share a bounded regex counter that normalizes
line endings and times out after two seconds. Missing source files, zero package
counts, and zero integrity counts are release blockers. CI runs the generator,
and the full report validator independently recomputes the counts from current
lockfiles. The dependency document also states explicitly that source-level
inventory does not replace a full SBOM and license review of final artifacts.

Authenticode helper module discovery is also a security input. The unfiltered
workspace suite showed that an ambient `PSModulePath` could make the checked
WindowsPowerShell 5.1 process autoload an incompatible PowerShell 7 Security
module. The probe now derives the built-in Security manifest from the checked
`System32\WindowsPowerShell\v1.0` executable, rejects linked/reparse module
paths, replaces the child `PSModulePath`, explicitly imports that manifest, and
uses module-qualified cmdlets. A hostile or broken parent module path therefore
cannot silently change publisher-trust evidence; module failures remain
visible and fail closed.

This closes the false-evidence path, not the production supply-chain boundary.
Compromised package registries, build-host compromise, signer-key theft,
final-binary transitive dependencies, license obligations, and release artifact
substitution still require pinned inputs, isolated release hosts, signed
artifacts, key custody, final-artifact SBOM review, and operational monitoring.

The consolidated readiness review does not promote partial engines. User-mode
watching remains app-lifetime and post-write; process snapshots remain
observational; development ML and cloud reputation remain non-production;
YARA/ClamAV are optional compatibility paths; and pre-execution claims remain
blocked until a signed installed driver passes approved elevated E2E testing.

## Checkpoint 2182 Quarantine Metadata And Cross-Engine Integrity

Quarantine metadata is a security decision input. An attacker who can remove an
auth sidecar, alter a restore path, add ambiguous fields, rename a record, or
make Guard and Local Core disagree could hide a quarantined item or influence a
later restore/delete decision. A custom keyed digest is also an unnecessary
cryptographic construction when a reviewed HMAC implementation is available.

Local Core and Guard now write one domain-separated HMAC-SHA-256 format with a
32-byte operating-system-random key. Windows key files must be DPAPI-protected;
plaintext is rejected. Missing sidecars, malformed tags, unknown fields,
filename/ID mismatches, unsafe paths, and contradictory source/action/process
claims fail closed. Local Core may migrate exact authenticated v1 Local Core or
Guard tags only after the complete record validates, and verifies the unchanged
record again after replacing the sidecar. Unsigned records are never migrated.

The cross-engine contract now accepts only the Guard actions the current Guard
actually writes and preserves historical process evidence through a Local Core
restore. It still rejects Guard pre-execution claims because the current Guard
path is post-launch user mode. This prevents the interoperability repair from
weakening claim honesty.

Residual boundaries remain. HMAC does not encrypt payload bytes. DPAPI is bound
to the creating Windows security context; installed LocalSystem service access,
ACL recovery, upgrade/repair, unprivileged UI mediation, and service mutation
IPC require disposable elevated-host E2E. An administrator or compromised
LocalSystem process remains inside the trusted computing base, and secure erase
is not claimed.

## Checkpoint 2183 Single Quarantine Mutation Owner

Two product components must not move files into one quarantine root under
incompatible metadata, authentication, restore, and security-context contracts.
The Native Engine previously exposed direct and scan-policy quarantine through
an unauthenticated record writer while Local Core and Guard used the shared HMAC
lifecycle. A confirmed native verdict could therefore create an item the normal
Recovery Vault could not safely authenticate or restore.

The Native Engine is now limited to detection and explainable verdicts.
Mutating scan modes are rejected before file reads or root walking, and direct
native quarantine rejects before I/O. Its old store and action policy compile
only for private tests. `DetectOnly` and `LockdownReview` remain functional, and
the product path continues to route confirmed lifecycle actions through Local
Core's authenticated quarantine implementation.

This intentionally disables a duplicate unsafe capability; it does not reduce
the existing Local Core quick, full, custom, watcher, manual quarantine, restore,
or delete paths. Installed service identity, DPAPI/ACL behavior, UI mediation,
and package click-through remain partial. The boundary is user mode and makes no
driver, pre-execution, secure-erase, or production detection-rate claim.

## Checkpoint 2184 Quarantine Permission Identity And Verification

Quarantine permissions are a security boundary, so mutable `USERNAME` and
`USERDOMAIN` values cannot identify the principal that receives vault access.
An inherited or retained explicit ACL can also leave access broader than the
command that attempted to harden it, while a moved Unix file can retain its old
mode. Treating a successful external ACL process exit as proof would not verify
the resulting object.

Local Core and Guard now delegate to one platform-security crate. Windows reads
the user SID from the current process token, opens the exact object without
following a reparse point, rejects NUL-containing or oversized paths before the
Windows API call, applies a protected DACL through handle APIs, and
sets ownership to that token SID. It reads owner and DACL back, compares the
owner SID and exact ACE sequence, and fails closed on mismatch. File hardening
also compares the already-opened data handle with the ACL handle by volume
serial and file ID, so a path replacement between those opens fails visibly.
Quarantine files
deny the specific `FILE_EXECUTE` right to Everyone; directory and recovery
access remains with SYSTEM, Administrators, and the process-token SID. Cleanup
failures are combined with the original failure instead of being discarded. No
external `icacls` command or environment-derived account name remains in either
production quarantine path.

Unix hardening compares the opened handle's device/inode identity with the path,
transfers differing ownership through the descriptor to the effective process
UID/GID, sets exact directory/file modes `0700`/`0600`, and rechecks identity,
ownership, kind, and mode afterward. A forbidden ownership transfer fails
closed. Local Core separates quarantine copies from restore staging so the
Windows execute-deny ACL is not carried to a restored destination; payload
integrity and destination checks still run before atomic activation.

Local Core and Guard check every existing vault-path ancestor before and after
directory creation. A symbolic-link or Windows reparse-point ancestor fails
closed, preventing a configured path from being redirected between the trusted
name and a different filesystem location.

An absolute override can still be dangerous if it names an unrelated existing
directory and Avorax then replaces that directory's ACL or modes. Explicit
quarantine overrides therefore require the final component `Quarantine`, and a
bounded preflight accepts at most 65,536 recognized non-link regular vault
artifacts before any permission mutation. Unknown names, wrong object kinds,
links/reparse points, and enumeration errors fail visibly. This is a directory
ownership/shape guard, not record authenticity: HMAC, strict schema, identifier,
path, and integrity checks remain required before list/restore/delete use.

Regression tests previously reached the normal ProgramData fallback. Local Core
test builds now select a thread-local temporary vault by default, with a scoped
override only for deterministic failure cases. A complete Local Core run was
observed to leave the real vault's entry count and byte total unchanged. No
existing user vault content was deleted as part of this repair.

Upgrade handling is fail closed. Metadata, auth-sidecar, and key readers harden
existing files before reading them. Local Core hardens an existing payload only
after the associated record is authenticated, parsed, validated, and confirmed
to resolve inside the vault. Unsigned or untracked files are not promoted into
valid quarantine records.

A finalization failure after payload movement is not converted into implicit
deletion. Before mutation, Local Core and Guard persist a strict journal plus a
domain-separated HMAC sidecar. They clean only incomplete final metadata/auth
artifacts, retain the sole opaque payload and authenticated journal, and return
a visible error containing its vault path. If a copy fallback reports failure
but leaves a destination artifact, or destination absence cannot be proved, the
journal is retained rather than incorrectly classified as unused.

After the `.pending` commit marker is written, its writer reads back and
authenticates the exact persisted bytes, acquires an exclusive operating-system
file lock, and holds it until finalization or fail-visible return. Recovery uses
the same non-blocking lock. An active Local Core or Guard transaction therefore
cannot be mistaken for an abandoned pre-move journal; a crashed process releases
the lock automatically. The lock coordinates cooperating Avorax processes and
does not elevate same-principal or administrator/root filesystem mutation out of
the trusted computing base.

Local Core's list boundary performs a bounded 65,536-entry recovery pass. It
authenticates and strictly parses each journal, binds filename/record ID and the
expected opaque payload path, checks record claims, verifies payload size/hash
and single-link hardening, writes and re-verifies current final metadata, and
then removes the journal. A pre-move journal may be discarded only after the
recovery lock is held, no payload/final metadata exists, and the original source
still has the recorded size, hash, regular-file kind, and one link. A stale
journal or orphan journal auth sidecar may be cleaned after the complete final record and
status-appropriate payload state authenticate. Tampering, unknown fields,
missing authentication, record conflicts, changed payloads, partial related
state, or both source and payload fail visibly without deleting evidence.

This recovery closes the checkpoint-2184 untracked-payload listing gap for
authenticated journals; it is not a general salvage tool for historical
unsigned payloads. Recovery runs on Local Core list access, so an installed
Guard-only process does not independently finalize journals until Local Core is
invoked. Installed LocalSystem/DPAPI/UI mediation and crash-at-every-instruction
package E2E still require a disposable elevated Windows host.

Residual boundaries remain. Unit and integration tests exercise the current
Windows process identity and temporary filesystem, while Linux CI supplies the
Unix branch evidence. Installed LocalSystem service ownership, DPAPI key access,
cross-account UI mediation, repair/upgrade, and package lifecycle still require
a disposable elevated Windows host. Administrators and LocalSystem remain in
the trusted computing base. In user-mode operation, other processes with the
same SID/UID also share the vault principal and remain trusted until an isolated
service plus authenticated IPC is deployed and verified. This does not encrypt
payloads, guarantee secure erase, add kernel interception, or prove
pre-execution blocking.

Vault-ancestor validation is a pre/post path check, not a fully handle-relative
`openat2` or NT object-tree transaction. A principal able to mutate trusted
ancestors concurrently remains in the trusted computing base; this checkpoint
does not claim protection from such an administrator/root race.

Hard links have a bounded fail-visible policy. Local Core and Guard require an
opened source handle to report exactly one filesystem link before quarantine,
recheck the opened source before copy-fallback removal, and require the vault
payload to remain single-linked before permission mutation and authenticated
record finalization. Vault-shape preflight also rejects hard-linked entries.
Windows reads `nNumberOfLinks` with `GetFileInformationByHandle`; Unix reads
`nlink` from descriptor metadata. A pre-existing alternate hard link therefore
causes the action to fail without moving the source or creating a record.

This is not volume-wide enumeration or an atomic hard-link transaction. A
same-SID/UID or administrator/root-capable process can still race a new link
between the final handle check and rename/removal, and moving or deleting one
path cannot identify arbitrary aliases elsewhere on the volume. Destination
postflight catches aliases visible before finalization, but Avorax must still
describe quarantine as path-specific rather than volume-wide neutralization.

## Checkpoint 2188 Installer-Owned Service Repair Boundary

The former Flutter repair path crossed a privilege boundary that the desktop
client could not authenticate safely. A same-user process could supply a Local
Core executable override through constructor or process environment state and
then rely on a user accepting the UAC prompt before elevated `New-Service` or
service reconfiguration consumed that path. UAC remained an explicit boundary,
but the desktop client had no signed-installer provenance contract for the
selected executable.

Checkpoint 2188 removes direct service creation and reconfiguration from the
Flutter client. Repair no longer reads executable overrides, resolves a repair
binary, builds `New-Service`/`Set-Service` commands, or launches elevated repair
PowerShell. The Scan surface permanently disables the repair button, displays
that installer repair is required, and exposes the same bounded blocker in a
tooltip. Direct client and controller calls fail closed and emit
`installation_repair_blocked`; there is no `installation_repair_requested`
success event. The remaining elevated helper does not use PowerShell execution-
policy bypass and is reachable only by the separately confirmed fixed-name
`Get-Service`/`Start-Service` flow for an already registered service.

Service installation and repair are now owned by a verified official MSI/EXE
package. End-to-end proof still requires a disposable elevated Windows host,
production code signing, installed-path and ACL inspection, service identity
validation, repair/rollback tests, and package provenance checks. Starting the
fixed existing service remains only partially verified until that host test is
performed. Administrators and the Windows service control manager remain in the
trusted computing base. This change does not install a service or driver and
does not add or claim pre-execution blocking.

## Checkpoint 2189 Process Enumeration Evidence Boundary

Process observation has two independent failure surfaces: collecting a process
image and inspecting an image after collection. The Guard already reported
metadata/hash/native/compat inspection failures, but Windows rows with no
`ExecutablePath` and individual Linux procfs failures could be omitted before
inspection. A finite no-threat result could therefore overstate the set of
processes actually observed.

Every collection now carries a saturating gap count and one bounded diagnostic.
Finite completion is non-clean when that count is non-zero. Persistent service
mode writes one structured limitation event, suppresses duplicate warnings
while the condition remains active, and rearms only after three clear polls.
Failure to persist the warning remains fatal. This makes incomplete evidence
visible without generating an unbounded event stream.

A collection with zero observable executable images and no prior gap records
its own limitation. Guard should observe at least its own running image, so an
empty but syntactically valid helper envelope or procfs directory is not
accepted as proof that all observable processes were clean.

Windows uses a strict bounded CIM envelope and treats missing non-kernel image
paths plus invalid/uninspectable returned paths as gaps. Linux bounds procfs PID
records, reports malformed/inaccessible entries, and treats a missing procfs
root as an error. `NotFound` while resolving a PID is treated as normal churn or
an image-less process because the process may have exited; a resolved target
that is unavailable while the PID directory remains present is a gap. On
unsupported platforms process enumeration is explicitly disabled.

The watcher retains only the previous bounded PID/path map. This fixes
unbounded lifetime PID accumulation and detects changed-image PID reuse after a
snapshot transition. Polling still cannot distinguish every same-path PID reuse
or observe a process that starts and exits between polls. Permissions can also
prevent a user-mode collector from reading protected process images. These are
technical limits, not clean evidence; stronger timing claims require a verified
signed driver or an approved authenticated operating-system event source.

Exact implementation head `d8ff525c362003a5396258ad8ffaeb51741b9387`
passes Avorax CI `32350190743`. Its pinned Ubuntu job `96367469456` runs the
exact locked native `process_collection` filter and passes `8/8`, including
malformed-image, empty-root, and unavailable-root procfs fixtures. Desktop
Packages push run `32350121197` and PR run `32350190448` both pass Windows,
Linux, macOS arm64/x64, and consolidated checksum/lockfile-SBOM jobs. Those
builds exercise packaging without installing or publishing any package.

The current path remains best-effort post-launch user mode. It does not stop an
image before execution, replace Defender, establish a production detection
rate, or prove installed LocalSystem visibility, event-log ACLs, shutdown, UI
mediation, and performance. Those installed checks require a disposable
elevated Windows host.

## Checkpoint 2190 Native Windows Process Collector Boundary

Launching WindowsPowerShell and CIM on every process snapshot added a helper
process, script encoding, JSON serialization/parsing, external command output,
and startup latency to a 750 ms polling loop. Checkpoint 2190 removes that
Windows collection path. Guard now calls the documented Toolhelp and process
image APIs through the locked `windows-sys` crate, without ambient tool lookup,
script execution, network input, or helper output parsing.

The native FFI boundary is isolated in one Windows-only module. It requests
only `PROCESS_QUERY_LIMITED_INFORMATION`, checks every Win32 result before use,
reads `GetLastError` immediately after failures, validates returned character
counts, and owns each successful handle until RAII cleanup. Memory is bounded by
one 32,768-code-unit image buffer and at most 65,536 PID records. A two-second
budget is checked between image queries; record and time exhaustion become
coverage gaps rather than truncation disguised as complete evidence.

Process churn and unavailable evidence are intentionally different. An
`ERROR_INVALID_PARAMETER` for a non-kernel PID is treated as a process that
exited between snapshot and query. Access denial, image query failure,
unexpected snapshot termination, unsafe/missing image paths, and all resource
limits are incomplete coverage. PIDs 0 and 4 are the only explicit kernel
exclusions. A zero-row result still becomes a gap because the running Guard
should observe itself.

The operating system, `windows-sys` ABI definitions, and the process token are
inside this collector's trusted computing base. The collector does not elevate,
open processes for mutation, inject code, suspend or terminate a process, or
alter Windows security. Process termination remains a separate policy action
using the existing checked bounded command runner after a confirmed verdict.

Protected processes can deny limited queries. A process can start and exit
between polls, one native call cannot be cancelled mid-call, and same-path PID
reuse can remain indistinguishable. The two-second budget is therefore a
between-call work bound, not a hard kernel-call deadline. These conditions
produce partial evidence and never a complete-coverage claim. Stronger timing
or visibility claims require an approved OS event source or a production-signed
installed driver with authenticated IPC and dedicated validation.

The final non-elevated release watch returned `ok:false` with 290 gap
occurrences across two snapshots and first detail `Access is denied`. That is
expected user-mode limitation evidence, not 290 threats. The collector is much
faster than the removed helper on this host, but it remains post-launch
observation and does not replace Defender or establish pre-execution blocking.

## Checkpoint 2191 Native System-Root Skip Boundary

The old Windows skip function inferred `X:\Windows` from the drive letter of
the untrusted observed image path. That let an image under an otherwise
lookalike `D:\Windows\System32` select the root against which its own exclusion
was evaluated. The path still had to be an observable regular file, but the
policy decision used attacker-influenced location text.

Guard now asks Windows for the shared system Windows directory once when the
watcher starts. The FFI parser is bounded to 32,768 UTF-16 code units,
initializes unused buffer space with a non-NUL sentinel, and rejects failed,
zero, oversized, embedded-NUL, or non-API-terminated results. The
returned path must be an absolute rooted local disk path whose existing
ancestors and final directory are non-reparse. Failure to construct this policy
aborts watcher startup visibly; it does not fall back to `SystemRoot`, `WINDIR`,
`C:\Windows`, or the observed process drive.

The normalized process path is compared only with that immutable root.
Deterministic tests prove actual-root `System32`, `SysWOW64`, and `Explorer.exe`
retain the current behavior while other-drive, `Windows.old`, parent-traversal,
and user-profile lookalikes remain inspectable. A Windows runtime test obtains
the real root and rejects the equivalent path on another drive. A release child
with `SystemRoot` and `WINDIR` spoofed to
`Q:\Avorax-Lookalike-Windows` produces the same fail-visible coverage result as
normal children.

This closes root selection by an observed path or mutable environment; it does
not prove every file under the actual Windows system directories is trusted.
Those broad exclusions remain in the current polling policy to avoid expensive
and noisy repeated inspection of core operating-system processes. Replacing
them requires a separately tested identity/publisher policy and production
false-positive evidence. Protected-process access denial, between-poll starts,
installed LocalSystem behavior, and macOS support also remain limited or
blocked. No driver, service, Defender setting, pre-execution claim, or package
installation is involved.

At checkpoint 2191, Guard driver-health/driver-IPC code and Native Engine
Authenticode/quarantine helper discovery retained separate validated
environment-root implementations. Checkpoint 2192 addresses the two Guard
consumers; checkpoint 2194 supersedes the Native Engine follow-up.

## Checkpoint 2192 Guard Native Root Consumer Boundary

Checkpoint 2192 removes mutable `SystemRoot`/`WINDIR` input from the remaining
Guard driver-health and driver-IPC system-root decisions. Driver health now
resolves only allowlisted `sc.exe`, `fltmc.exe`, `bcdedit.exe`, and Windows
PowerShell components beneath the checked directory returned by
`GetSystemWindowsDirectoryW`. Driver IPC derives its actual `System32` and
`SysWOW64` fail-open roots from the same checked result. The existing process
skip and `taskkill.exe` paths also delegate to this shared validation.

The resolver bounds the Win32 output parser and relative component count/size,
requires a rooted local drive with normal components, and rejects symbolic-link
or reparse-point ancestors and final targets. Component allowlists remain at
the caller so adding an arbitrary helper name does not silently expand command
execution. Environment-spoof tests prove `Q:\SpoofedWindows` cannot replace the
actual root.

Driver IPC caches one immutable checked root result for the Guard process
lifetime, avoiding repeated native and ancestor metadata work on every event.
Root-resolution errors are cached and propagated into verdict evaluation. The
native port then uses its existing reason-bearing fail-open error verdict, which
avoids a silent trust substitution and avoids unexplained system lockout. This
availability choice does not label a file clean or malicious and is not a
pre-execution protection claim.

The operating system, locked `windows-sys` ABI, process token, and protection of
the real Windows tree remain trusted. Metadata inspection followed by command
creation is not an atomic handle-based launch. A privileged actor able to
replace protected system paths, or compromise Windows itself, is outside this
user-mode boundary. Actual-root `System32`/`SysWOW64` fail-open and process-skip
coverage remains broad and path-based rather than publisher-based.

Native Engine helper-root follow-up is superseded by checkpoint 2194. Installed
LocalSystem behavior, live helper ACLs, signed-driver IPC, driver lifecycle,
and true pre-execution enforcement remain partial or blocked. No service,
driver, Defender setting, package installation, or release is changed by
checkpoint 2192.

## Checkpoint 2194 Native Engine Windows Root Boundary

Before checkpoint 2194, Native Engine independently validated candidates from
mutable `SystemRoot` and `WINDIR` for Authenticode PowerShell discovery and
system-path trust. That validation rejected obvious malformed candidates, but
the process environment still selected the root. Its retained legacy
quarantine compatibility store also used `icacls.exe` and account-name
environment variables in Windows-only tests.

Native Engine now obtains one process-stable result from
`GetSystemWindowsDirectoryW`. The parser uses a sentinel-filled 32,768-unit
UTF-16 buffer and rejects API failure, zero or excessive length, embedded NUL,
and missing API-written termination. The path must be a rooted local drive with
normal components; existing ancestors and targets must not be symbolic links or
Windows reparse points. Only bounded fixed components can select the checked
PowerShell file or `System32`/`SysWOW64` directories. Root resolution errors are
cached and remain explicit; there is no environment or `C:\Windows` fallback.

System location is only one conjunct in local Microsoft artifact trust. A file
must also pass Microsoft Authenticode verification. Therefore an arbitrary file
placed beneath a familiar directory is not automatically classified clean.
PowerShell remains an external helper with closed stdin, a 30-second deadline,
and 64 KiB output cap. Metadata checks and later process creation are not an
atomic handle-based launch; replacing the helper with direct native
`WinVerifyTrust` remains possible future hardening.

The Native Engine quarantine store is private `#[cfg(test)]` compatibility
code, not an active mutation engine. Production Native Engine remains
detection-only and Local Core exclusively owns quarantine, authenticated
metadata, recovery, rescan, restore, and deletion. Tests now call the shared
platform-security implementation, which derives the current process token SID,
applies a protected exact Windows DACL, and verifies it without `icacls.exe` or
account-name environment input.

Windows, the Win32 ABI, process token, and protection of the actual system tree
remain trusted. Missing `SysWOW64`, including on unsupported 32-bit Windows,
fails conservatively; the current Windows package job covers x64 only. Installed
LocalSystem behavior, protected helper ACL attack testing, production signing,
signed-driver IPC, and pre-execution enforcement remain partial or blocked.
This checkpoint changes no service, driver, Defender setting, package install,
publication, or release and makes no Defender-replacement or kernel-blocking
claim.

## Checkpoint 2195 Direct Authenticode Boundary

Checkpoint 2195 removes the external PowerShell, module-discovery, script,
JSON, and command-output surfaces from Native Engine publisher verification.
The candidate is opened as an absolute bounded regular non-reparse file without
write/delete sharing, and `WinVerifyTrust` receives that handle. The trust call
is noninteractive and cache-only, so it does not retrieve network content.
WinTrust state is closed for success and failure paths, and cleanup errors are
not swallowed.

A valid chain alone does not establish Microsoft identity. The primary signer
leaf must contain both exact `Microsoft Corporation` organization and an exact
allowlisted Microsoft common name. Subject lookalikes, unsigned files, invalid
signatures, and malformed files do not supply publisher trust. Revocation,
policy, provider, I/O, cleanup, and unknown failures remain visible diagnostics
and contribute zero trust weight rather than becoming clean results.

The scan engine previously computes a full SHA-256 before publisher trust. It
now passes that digest into the native verifier. After a valid Microsoft signer
is established, the verifier rewinds the same open handle, rereads at most 512
MiB using a 128 KiB buffer, compares pre/post metadata, and requires the digest
to match. The limit is checked before WinTrust and during every read, bounding
a file that grows through a handle opened before Avorax acquired its handle.

This reduces but does not eliminate user-mode TOCTOU. An already open writable
or memory-mapped handle can still mutate bytes, and a file can change after a
verdict before another application executes it. `WinVerifyTrust` itself cannot
be hard-cancelled in-process; cache-only behavior prevents online stalls but is
not a kernel-call deadline. Catalog-only and secondary signatures are not
evaluated, so valid Microsoft files relying on those forms may conservatively
receive no trust or a diagnostic. Stronger execution-time guarantees require a
separately validated signed driver or an OS execution-control boundary.

Windows trust stores, cryptographic providers, the Win32 ABI, and protection of
their state remain in the trusted computing base. Native Engine stays
detection-only and Local Core stays the authenticated quarantine owner. No
service, driver, Defender setting, package install, publication, release,
execution authorization, Defender replacement, pre-execution, or detection-rate
claim is introduced.

## Checkpoint 2196 Catalog Authenticode Boundary

Checkpoint 2196 adds a bounded catalog fallback only after primary embedded
verification returns a definitive untrusted result. An inconclusive embedded
policy, revocation, provider, I/O, or cleanup failure remains visible and does
not get hidden by a second trust path.

The fallback acquires a SHA-256 catalog administrator context, calculates the
catalog member hash from the same already-open regular non-reparse file handle,
and enumerates at most 16 matching system catalogs. Returned catalog paths are
treated as untrusted fixed-buffer data: they must have one bounded NUL-terminated
value, no trailing data, and an absolute local-drive path. UNC/network catalog
paths are rejected. Every candidate is evaluated through noninteractive,
cache-only `WinVerifyTrust`; the same exact Microsoft leaf organization/common
name policy applies. A valid catalog and matching hash alone are insufficient if
the verified signer is not Microsoft.

The normal return path explicitly releases the current catalog context and the
administrator context. Release failures replace a would-be verdict with a
diagnostic, and a verification error plus cleanup error preserves both. A valid
catalog verdict on the scan path still requires the second bounded same-handle
SHA-256 read to equal the bytes already scanned.

Catalog enumeration improves legitimate Windows-file trust and false-positive
resistance, but it does not authorize execution. Secondary embedded signatures
remain unevaluated. In-process WinTrust/catalog calls have no hard cancellation,
and an earlier writable or memory-mapped handle plus post-verdict mutation remain
user-mode TOCTOU limits. Windows catalog registration, trust stores,
cryptographic providers, the Win32 ABI, and protected catalog state remain in
the trusted computing base. No service, driver, Defender setting, installation,
publication, release, pre-execution, or detection-rate claim is added.

Local verification covers `10/10` catalog/direct boundary cases, a real benign
catalog-backed WindowsPowerShell fixture that demonstrably fails the embedded
path before catalog success, plus correct and incorrect scan hashes,
the complete Native Engine and workspace suites, all Flutter tests, source
contracts, and the definitive `225/225` verifier. This is implementation and
regression evidence, not installed execution-control or production-accuracy
evidence.

## Checkpoint 2197 Secondary Embedded Authenticode Boundary

Multi-signed PE files can carry a primary embedded Authenticode signature plus
secondary signatures. Treating only index zero as authoritative can withhold
legitimate Microsoft publisher trust when another valid publisher occupies the
primary slot. Conversely, accepting a secondary by name alone, trusting an
unchecked index, retaining stale provider state, or iterating an attacker-
controlled count without a cap could turn false-positive reduction into a trust
bypass or resource-exhaustion surface.

The verifier therefore asks WinTrust for the secondary count while explicitly
verifying index zero. Before every call the output index is initialized to a
sentinel. For primary index zero, the current Windows provider leaves that
output untouched, so only zero or the sentinel is accepted; every secondary
must report the exact requested index. The state is closed and reset before each
later index. The primary plus all reported secondaries may total no more than 16, and the count
must remain unchanged throughout one file decision. Overflow, count drift,
unexpected index, policy/API/I/O failure, signer parsing failure, content-hash
mismatch, and cleanup failure are visible errors and supply no clean trust.

Only a signature already accepted by Windows policy is inspected for publisher
identity. Avorax still requires its exact Microsoft organization/common-name
pair, and scan-path acceptance still rereads the same bounded handle and
matches the SHA-256 computed by the detection engine. A valid non-Microsoft
primary may lead to an ordered bounded secondary search. Invalid secondaries are
ignored; inconclusive secondaries abort. A definitively invalid primary cannot
be rescued by secondaries and instead retains only the separate catalog
fallback. This conservative rule avoids using a damaged primary container as a
gateway to publisher trust.

The benign runtime fixture is selected from at most 64 direct Edge application
entries and eight fixed Microsoft DLL names, rejects reparse entries, and is
read only. It is never executed. Missing host fixture evidence is a visible
blocker. Secondary catalog signatures are not evaluated. Windows trust stores,
cryptographic providers, protected Edge installation state, and WinTrust's
selected-signature semantics remain trusted boundaries. In-call cancellation,
memory-mapped mutation, post-verdict mutation, execution authorization,
pre-execution blocking, Defender replacement, and detection-rate claims remain
outside this checkpoint.

## Checkpoint 2198 WinTrust Process-Isolation Boundary

One native `WinVerifyTrust` invocation has no in-call cancellation API. Running
that call in a long-lived Local Core or Guard process can exceed the caller's
scan deadline even though network retrieval is disabled. Abruptly killing the
service or abandoning an in-process thread would create wider state, lifetime,
and cleanup risks. Checkpoint 2198 therefore scripts a release-only child-
process lifetime boundary while preserving the direct verifier as the sole
verdict implementation.

The parent resolves its exact current executable, requires an absolute local-
drive path and bounded regular non-reparse file, opens it with read sharing only,
and keeps that handle alive through child execution and response validation. It
starts the same image with one exact hidden argument, no shell, no ambient PATH
lookup, no network operation, and no visible window. The child is assigned to a
Windows Job configured to kill all members when its last handle closes. The
parent imposes a 15-second decision deadline and a separate two-second reap
deadline. Spawn, assignment, input, pipe, timeout, kill, reap, and cleanup
failures remain diagnostics and cannot become a trusted publisher verdict.
The deadline starts after synchronous Windows process creation and Job
assignment. The process-creation call itself is not cancellable through this
design and remains an operating-system boundary.

The protocol accepts exactly one bounded schema-v1 JSON request containing a
random UUID-v4 nonce, one bounded UTF-16 path, and an optional expected SHA-256.
The response must match schema and nonce exactly and is accepted only when the
child exits successfully, emits one bounded response, and reports either the
real direct verifier verdict or a bounded error. Extra fields, malformed JSON,
wrong nonce, wrong digest, excess data, invalid path shape, or contradictory
status/verdict fields fail visibly. Standard error is retained only as bounded
diagnostic evidence. The helper never executes the inspected fixture.

This boundary contains duration and process failure, not privilege. The child
uses the same token as its Local Core or Guard parent, so it is neither a
restricted-token sandbox nor authenticated cross-privilege IPC. The operating
system loader, Windows Job/process/pipe semantics, current executable and its
installed ACLs, WinTrust providers, trust stores, and protected catalog state
remain trusted. A retained read handle cannot revoke a writable or memory-
mapped handle opened earlier, prevent post-verdict mutation, authorize later
execution, or provide pre-execution blocking.

Secondary catalog signatures remain conservatively unsupported. The reviewed
Windows contract documents selected secondary signatures for file trust; it
does not provide enough evidence to reuse those index assumptions for catalog
trust. Checkpoint 2198 does not weaken this limitation, Defender, Windows
security, or the existing conjunction of valid Windows policy, exact Microsoft
leaf identity, and scanned-content SHA-256 binding. The documented local batch
passes focused, full, release-smoke, and definitive verification (`229/229` in
`433s`). Exact-head, merge, merged-main, and synchronized-tree evidence also
passes with publication skipped. No installed, sandbox, production-signing, or
pre-execution claim is made.

## Checkpoint 2199 Mandatory Hash And Handle-Identity Boundary

A path-only publisher verdict can be misused by a future caller that has not
bound trust to bytes already scanned. A nullable helper digest also creates two
security contracts for one endpoint. Checkpoint 2199 removes the
unused path-only Microsoft/publisher helper and requires one exact 64-hex
SHA-256 through public trust, direct WinTrust, helper JSON, embedded signatures,
catalog fallback, and release smoke. Missing, null, malformed, or mismatched
digests fail visibly. The scan engine already computes and supplies the full-
file digest; no extra ambient path trust is introduced.

The no-write/delete-sharing candidate handle is captured before WinTrust and
retained across the verdict. Before and after the complete embedded/catalog/hash
operation, the verifier queries volume/file ID, legacy file index, creation,
write, and change times, attributes, allocation and end size, link count,
delete-pending, and directory state. It cross-checks independent legacy and
extended volume, creation/write time, size, link-count, and attribute values.
Any API failure, internal inconsistency, or before/after drift replaces the
verdict with a bounded
diagnostic. If trust and identity checks both fail, both diagnostics survive.
Last-access time is deliberately excluded because verification reads may update
it and create false mutation reports.

Benign adversarial tests open only temporary text fixtures. They prove a
pre-existing writer prevents the verifier's restrictive open, repeated handle
snapshots are stable, creating a real hardlink changes link-count evidence and
is rejected, and identity errors cannot become trust or hide a verification
error. Installed Edge and Windows PowerShell fixtures remain read-only and are
never executed.

This is detection of common in-verification drift, not atomic execution control.
A writable mapping created before the verifier opens its handle can still alter
pages; digest and metadata checks may detect that activity but cannot revoke the
mapping. Mutation after the verdict remains possible. Filesystems that cannot
supply required identity information fail conservatively. Same-token helper
privilege, secondary catalog signatures, production signing, installed service/
UI behavior, driver IPC, pre-execution blocking, Defender replacement, and
production detection-rate claims remain outside this checkpoint. The completed
local verifier/validator passes `230/230` in `504.6s`. Exact implementation-head
and evidence-head CI/packages pass with publication skipped. PR `#51` merges as
`264e4551aa930f75d325ebd3df4522bd4f244941`; merged-main CI/packages and exact
16-file synchronized-tree checks pass. The protected vault remains unchanged.

## Checkpoint 2200 Secondary Catalog Signature Boundary

A catalog file may itself contain a primary and secondary Authenticode
signature. Accepting only its primary can withhold legitimate Microsoft trust;
accepting a secondary by name or assumed position could instead create a trust
bypass. The Windows `WINTRUST_SIGNATURE_SETTINGS` contract exposes requested
index, returned verified index, and secondary count. Checkpoint 2200 applies
that contract to the existing `WTD_CHOICE_CATALOG` verification while retaining
the already open catalog-member handle and calculated SHA-256 evidence.

The primary request uses index zero plus count retrieval. A successful primary
must report zero or retain the initialized provider-untouched sentinel; every
secondary must report exactly its requested index. The count must remain stable
across calls, total signatures are capped at 16, and each state is closed before
the next request. A definitively invalid primary is never rescued. A valid
other-publisher primary may search bounded secondaries, but only a WinTrust-
valid exact-Microsoft leaf with the mandatory scanned-member SHA-256 can return
publisher trust. Errors, count drift, wrong indexes, limits, hash mismatch, and
state/catalog cleanup failures remain diagnostic.

The controlled evidence is deliberately split. Deterministic benign unit data
proves aggregation and failure semantics. A read-only installed
WindowsPowerShell member proves real catalog-provider compatibility and hash
binding, but its primary path does not prove positive acceptance of a real
secondary catalog signature. No controlled benign multi-signed system catalog
is available in the repository or guaranteed on this host, so that positive
route remains partial. The code remains fail-closed at that boundary; no trust
is synthesized from the unit fixture.

Windows trust stores, cryptographic providers, catalog registration, protected
catalog state, and WinTrust selected-signature semantics remain trusted.
Memory-mapped and post-verdict mutation, same-token helper privilege,
production signing, installed service/UI behavior, signed-driver IPC,
pre-execution blocking, Defender replacement, and production detection-rate
claims remain outside this checkpoint. No candidate fixture is executed.

Local evidence passes the secondary-catalog filter `2/2`, the complete
Authenticode module `24/24`, Native Engine `458 + 6`, both locked workspace
variants, release helper smoke on Local Core and Guard, Flutter `838/838`,
source contracts `628/628`, and all strict safety/dependency gates. The
definitive verifier and independent validator pass `231/231` in `424.1s`; stale
`230`-step evidence is rejected. This verifies bounded fail-closed selection and
primary catalog compatibility, not a positive real secondary signature.

## Checkpoint 2201 Authenticode Helper Resource Boundary

The release helper's parent-enforced 15-second wall timeout bounds elapsed
verification time, but it did not independently cap committed memory,
user-mode CPU, or process fan-out. A malformed candidate or a defective trust
provider could therefore consume substantial host resources before the parent
deadline. Checkpoint 2201 configures the existing unnamed Windows Job before
the strict request is written.

The Job requires kill-on-close, unhandled-exception dialog suppression, 12
seconds of per-process user-mode CPU, one active process, 1 GiB per-process
commit, and 1 GiB whole-Job commit. Avorax reads the structure back through
`QueryInformationJobObject` and requires exact flags and values. Create, set,
query, value mismatch, assignment, timeout, kill, or reap failure remains a
diagnostic and cannot become Microsoft trust. The exact current executable
blocks reading stdin until the parent has configured, validated, and assigned
the Job, so untrusted candidate handling begins after the limits apply.

This is resource and lifetime containment, not a security-token sandbox. Job
commit limits are not physical working-set or I/O-byte limits, and user CPU
does not include kernel execution. The short process/runtime startup before
assignment remains inside the trusted-current-executable boundary. The helper
retains the parent's token, while Windows Job/process semantics and WinTrust
remain trusted. Installed-service identity, authenticated cross-token IPC,
production signing, driver/pre-execution enforcement, Defender replacement,
and production accuracy are not established. No live malware or executable
fixture is used.

Local evidence passes the real Job read-back/mismatch filter `1/1`, helper
isolation `5/5`, the complete Authenticode module `25/25`, Native Engine
`459 + 6`, both locked workspace variants, release Local Core/Guard builds and
helper smoke, Flutter `838/838`, source contracts `629/629`, and strict safety,
dependency, formatting, and lint gates. The definitive report and independent
validator pass exactly `232/232` in `441s`; a report missing only the new Job
step is rejected at 231. This verifies the configured user-mode resource
boundary on this Windows host, not restricted-token isolation, kernel
interception, installed-service behavior, or production protection efficacy.

## Checkpoint 2202 Evidence-Text Category Boundary

Risk-fusion category inference joins positive-weight evidence identifiers,
titles, and details. Details intentionally explain archive members and paths,
but those untrusted strings must not masquerade as a category marker. Merged-
main CI `32610442133` proved the previous unbounded `pup` substring check could
read randomized temporary path `.tmpuPoV59` as PUP and override the otherwise
correct downloader/script category. The threat verdict remained
`ProbableMalware`; this was an explainability and deterministic-testing defect,
not a clean-verdict bypass.

Checkpoint 2202 requires `pup` as a complete token separated by non-ASCII-
alphanumeric boundaries. This preserves identifiers such as `pup_indicator`
while rejecting incidental fragments inside a longer path component. A direct
negative/positive unit regression, the existing complete risk-fusion verifier
step, strict validator scope checks, and source contracts are scripted. This
does not claim a semantic malware-family classifier: other category rules
remain keyword heuristics, and production category/false-positive accuracy
still needs corpus evidence. No file or fixture is executed.

The first default-parallel locked workspace run also showed that Local Core
asset-locator tests could temporarily expose an intentionally invalid engine
root to unrelated scan tests. Checkpoint 2202 moves the explicit installed-dir
and relative-root env cases into exact child-test processes. This is test
isolation, not a production configuration fallback: relative roots remain
rejected and production discovery code is unchanged.

Local evidence passes the direct boundary `1/1`, risk fusion `7/7`, the
triggering archive regression 25 repeats, asset isolation `4/4`, three parallel
Local Core suites at `535/535`, Native `460 + 6`, both locked workspaces,
strict lint/format/security/dependency gates, Flutter/analyzer, and exact
`232/232` definitive plus independent validation in `517.3s`. Stale same-count
evidence without the new scope is rejected. This proves deterministic behavior
for the bounded PUP case and test isolation on this host, not production family
classification accuracy.

## Checkpoint 2203 Authenticode Helper Thread-Privilege Boundary

The isolated Authenticode helper previously inherited every enabled privilege
of its parent. That is most consequential when Guard or Core runs as
LocalSystem: candidate parsing and Windows trust-provider work do not require
backup, restore, debug, ownership, service, or other administrative privileges.
A malformed candidate or defective provider should therefore run with a smaller
effective token even though the one-shot process and Job already bound lifetime
and resources.

Before opening the requested path, the helper duplicates its process token as a
`SecurityImpersonation` token and calls `CreateRestrictedToken` with
`DISABLE_MAX_PRIVILEGE`. It validates the returned token type and impersonation
level, reads at most 64 KiB and 256 `TokenPrivileges` entries, and permits only
the documented `SeChangeNotifyPrivilege` exception to remain enabled. It then
assigns the token to the current thread and repeats the same validation on the
effective read-back token. `IsTokenRestricted` is not evidence here because the
Windows API checks only restricting SIDs, while this design intentionally keeps
the parent's SIDs for file and trust-store compatibility.

All setup/read-back failures prevent candidate verification. Normal success and
verification-error paths call `RevertToSelf`; a revert failure is combined with
the operation diagnostic and cannot return trust. Benign tests exercise actual
token application/reversion and synthetic unexpected-enabled-privilege
rejection. Release smoke must still prove embedded and catalog Microsoft trust,
unsigned rejection, and wrong-hash failure on Local Core and Guard without
executing fixtures.

This narrows enabled thread privileges, not the process security boundary. The
helper retains the parent process token, SID, integrity level, desktop,
environment, and ordinary ACL access. Native code in the same process could
technically revert impersonation. AppContainer/restricted-process isolation,
separate desktop, authenticated cross-token IPC, installed LocalSystem E2E,
production signing, driver/pre-execution enforcement, Defender replacement,
and production accuracy remain partial, blocked, or technically limited.

Local evidence passes the actual restricted-token and sensitive-privilege tests
`2/2`, complete Authenticode tests `27/27`, Native Engine `462 + 6`, both locked
workspace variants, Flutter `838/838`, source contracts `632/632`, release
Local Core/Guard helper smoke, strict gates, and the exact `233/233` verifier in
`473.5s`. The strict validator also rejects stale 232-step and missing-scope
reports. This verifies the configured thread-privilege boundary on this host;
hosted exact-head, installed LocalSystem, and stronger process sandbox evidence
remain pending.

## Checkpoint 2204 Authenticode Helper Restricted-Process Boundary

The release helper no longer starts with the Local Core or Guard process token.
The parent derives a restricted primary token with
`CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, validates exact primary type and
bounded enabled privileges, and passes it to `CreateProcessAsUserW`. The child
starts suspended. `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` permits exactly three
validated stdin/stdout/stderr handles; parent pipe ends are explicitly
non-inheritable.

The parent assigns the already configured one-process, CPU, commit, crash-UI,
and kill-on-close Job before `ResumeThread`. Assignment or resume failure
terminates and reaps the suspended process. Before request parsing, the child
reads back its process token and requires exact primary type plus only enabled
`SeChangeNotifyPrivilege`. The restricted thread token remains defense in depth
for candidate open, WinTrust, catalog, signer, and content-hash work. There is no
unrestricted-process fallback, and any token, pipe, attribute-list, launch, Job,
resume, read-back, timeout, termination, reap, protocol, or verification error
cannot become publisher trust.

This is not an AppContainer or cross-identity sandbox. The restricted primary
token retains the parent SID, integrity level, environment, desktop, and
ordinary SID-based access because restricting SIDs are not added. Windows token,
process, pipe, Job, loader, trust-provider, and protected-catalog semantics stay
in the trusted computing base. Installed LocalSystem behavior remains planned
evidence, while production signing, driver enforcement, pre-execution blocking,
Defender replacement, and production accuracy remain separate blockers.

Checkpoint-2204 focused, full Native/workspace, strict lint, release-build,
two-host smoke, analyzer, protocol, Flutter, source-contract, central-gate, and
exact `234/234` verifier/validator claims are locally verified. Stale,
missing-step, and missing-scope evidence is rejected. Evidence `930342f`, PR
`#56`, merge `a5f982a`, merged-main CI/packages, exact 12-file synchronization,
destination checks, and the protected-vault audit pass with publication
skipped. Tests use only ignored benign Rust child fixtures, installed read-only
Microsoft binaries, and temporary benign text; candidates are never executed.

## Checkpoint 2205 Authenticode Helper Write-Restriction Boundary

Checkpoint 2205 reduces ordinary write authority without turning publisher
verification into a broad sandbox claim. The process keeps checkpoint 2204's
`DISABLE_MAX_PRIVILEGE` primary token, checked before process creation and
again in the child. Before stdin or request parsing, release helper code calls
`CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED` and
exactly one zero-attribute `WinRestrictedCodeSid` input, installs that
`SecurityImpersonation` token on the current thread, and reads it back. Strict
request parsing plus read-only candidate open, size bound, and identity snapshot
run under that token. The helper reverts it fail-visibly before WinTrust,
catalog, signer, and content-hash work under the privilege-stripped primary
token. A newly created/read-back restricted token then protects response
serialization and stdout.

`TokenRestrictedSids` evidence is byte-bounded and count-bounded. The parser
checks count arithmetic, returned-buffer ranges for each SID pointer, structural
validity, SID length through `SECURITY_MAX_SID_SIZE`, and exact well-known SID
bytes. Read-back requires exact `SE_GROUP_MANDATORY`,
`SE_GROUP_ENABLED_BY_DEFAULT`, and `SE_GROUP_ENABLED` attributes; zero is the
creation input rather than the returned token representation. Missing,
duplicate, malformed, unexpectedly attributed, or wrong SID evidence cannot
become Microsoft publisher trust. Privilege validation still allows only
enabled `SeChangeNotifyPrivilege`; token setup or read-back failure prevents
publisher trust.

The intended security property is narrow and explainable. `WRITE_RESTRICTED`
causes the restricting SID to participate only in write-access checks. A benign
child regression must retain read/hash access to an ordinary user-owned
temporary file while its write-open request receives access denied and the
bytes remain unchanged. Existing inherited stdio handles and securable objects
whose ACLs satisfy both the normal and restricting access checks are not claimed
inaccessible.

Applying the same write-restricted SID to the primary token was tested first,
but the child stopped before user code with `0xC0000142`
(`STATUS_DLL_INIT_FAILED`). The implementation does not hide that compatibility
failure behind a launch retry or weaker fallback. It instead retains the
already verified privilege-stripped primary token and narrows the code that
handles untrusted requests with the write-restricted thread token.

The first release-host smoke with thread restriction held across the Windows
trust APIs also failed: embedded Edge verification fell through and SHA-256
catalog hashing returned Windows error `127`. Treating that as unsigned would
break valid Microsoft publisher trust; retrying after a failed call would hide
the security boundary. The final design therefore scopes write restriction
around Avorax-controlled input/candidate preparation and output while running
the trusted Windows trust/catalog phase once under the privilege-stripped
primary token.

The helper still retains parent SID, integrity, environment, desktop, and
ordinary read access. The primary token is privilege-stripped but not
write-restricted, and same-process native code can technically call
`RevertToSelf`. This is not AppContainer, identity isolation, environment
sanitization, a separate desktop, or authenticated cross-identity IPC.
Installed LocalSystem behavior, writable mappings/post-verdict mutation,
production signing, driver enforcement, pre-execution blocking, Defender
replacement, and production accuracy remain separate limitations or blockers.
Preliminary focused runs established the canonical SID attributes and exposed
the primary-token loader incompatibility; the first release smoke then exposed
trust-stack error `127`. The repaired final-design
implementation/test/verifier/documentation batch is scripted before its next
test run. Final-design focused evidence now passes: write restriction `2/2`,
complete Authenticode `31/31` plus three intentional child-fixture ignores,
strict Native Clippy, source contracts `634/634`, locked release builds, and
two-host embedded/catalog/hash-binding smoke. Both locked workspace variants,
strict Native/Local/Guard Clippy, Flutter analyze and `838/838`, source
contracts `634/634`, and the definitive verifier plus independent validator
pass exactly `235/235` in `470.1s`. Controlled stale-count, missing-step, and
missing-scope reports are rejected. The protected-vault read-only audit remains
exact. Implementation head `a5597d2` passes CI `32624862111` and package
push/PR `32624842967`/`32624862058`, including all six artifacts, checksums,
and lockfile SBOM with publication skipped. Evidence-head, merge, merged-main,
and synchronization evidence subsequently closed through evidence `ffda3a6`,
PR `#57`, merge `757432b`, green merged-main CI/packages, exact 13-path original-
tree synchronization, and an unchanged protected vault.

## Checkpoint 2206 Sanitized Authenticode Launch Context

The checkpoint-2205 child still inherited the caller's complete environment and
current directory because `CreateProcessAsUserW` received null pointers for
both. Checkpoint 2206 removes those mutable launch inputs. The parent passes a
double-NUL-terminated Unicode block containing only `SystemRoot` and `WINDIR`,
derived from the checked native Windows root, sets
`CREATE_UNICODE_ENVIRONMENT`, and supplies the checked non-reparse native
`System32` directory as `lpCurrentDirectory`. Construction or validation
failure has no inherited fallback and cannot supply Microsoft publisher trust.

This reduces configuration/search-path attack surface but is not an identity
sandbox. The child retains parent SID, integrity, desktop/window station, and
ordinary read access. It can mutate its own environment after startup, and
Windows trust components remain in the trusted computing base. AppContainer,
profile/registry isolation, separate-desktop isolation, installed LocalSystem
E2E, and authenticated cross-identity IPC are not claimed. Benign focused and
real-child fixtures pass, embedded/catalog two-host release smoke remains
compatible, both locked workspace variants and strict lint pass, Flutter passes
`838/838`, and source contracts pass `635/635`. Relative, traversal, UNC,
verbatim-device, and embedded-NUL launch paths are rejected. The definitive
report and strict validator pass exactly `236/236` in `461.7s`; controlled stale-count,
missing-step, and missing-scope reports are rejected. Exact-head hosted,
merged-main, and installed LocalSystem evidence remain separate. Exact
implementation head `80599a1` passes CI `32629832036` and package push/PR
`32629820137`/`32629832031`, including all six desktop artifacts, checksums,
and lockfile SBOM with publication skipped.

## Checkpoint 2207 Authenticode Process Mitigation Policy

The one-shot helper already has a privilege-stripped primary token,
write-restricted request/output threads, exact handle inheritance, Job limits,
and sanitized launch state, but checkpoint 2206 did not set process-creation
exploit/image policy. Checkpoint 2207 adds a mandatory
`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` value enabling strict handle checks,
extension-point disable, dynamic-code prohibition, Microsoft-signed-only image
loading, remote/low-label image rejection, and System32 image preference.

The policy value has stable storage through attribute-list deletion. Before
stdin or request parsing, the child reads back binary-signature, dynamic-code,
extension-point, image-load, and strict-handle groups. Missing Microsoft-only,
store-only substitution, any missing required image bit, query failure, or
attribute failure cannot supply trust, and there is no weaker retry.

This reduces post-start executable-image and extension-point attack surface; it
does not constrain the already mapped helper image or non-image data. It does
not change identity/integrity, isolate profile/registry/desktop/read access,
prevent same-process `RevertToSelf`, or create AppContainer/authenticated IPC.
Microsoft-signed-only loading can be incompatible with non-Microsoft trust
providers or injected security modules. The real benign child read-back,
focused mitigation tests `2/2`, complete Authenticode `35/35`, both release
hosts, locked workspaces, strict lint, Flutter `838/838`, source contracts
`636/636`, and definitive verifier/validators `237/237` in `462.1s` pass.
Hosted exact-head/merge evidence, installed enterprise integrations, and
LocalSystem execution remain unverified.

Final review hardened strict-handle read-back to require both invalid-handle
exception and permanent-enforcement flags, rejecting temporary debugger-induced
evidence. The stricter fixture passes `2/2`; complete Authenticode, strict lint,
source contracts, release smoke, and the fresh definitive `237/237` rerun pass.
Exact implementation head `a9d930a` passes CI `32634033002` and package
push/PR `32634021590`/`32634032975`, including all six artifacts, checksums,
and lockfile SBOM with publication skipped. Evidence-head, merge, merged-main,
installed enterprise, and LocalSystem evidence remain separate.

## Checkpoint 2208 Low-Integrity Authenticode Helper

The remaining high-value helper boundary is the primary token used for loader
and trust-provider compatibility. A same-user helper running at medium, high,
or system integrity could use its parent SID to modify ordinary objects even
after privilege removal. Checkpoint 2208 scripts Windows Mandatory Integrity Control
for that process: `SetTokenInformation(TokenIntegrityLevel)` assigns
exact `WinLowLabelSid` after `DISABLE_MAX_PRIVILEGE`, parent read-back occurs
before `CreateProcessAsUserW`, and child read-back occurs before stdin or any
untrusted request processing. Missing, malformed, differently attributed, or
non-low integrity evidence prevents trust; there is no weaker retry.

MIC's default no-write-up evaluation occurs before DACL evaluation. The benign
regression therefore creates an ordinary medium-integrity text object, starts
the real restricted helper child, explicitly calls `RevertToSelf`, retains
read/hash access, and requires write-open denial plus unchanged bytes. This
addresses same-process escape from the write-restricted impersonation token:
reversion reaches only the low-integrity primary token.

This boundary does not change identity, credentials, profile/registry
namespace, desktop/window station, or normal read rights. It does not prevent
writes to objects deliberately labelled for low-integrity mutation and does not
constrain existing mappings or post-verdict mutation. Mandatory Integrity
Control with `WinLowLabelSid` is not AppContainer/LPAC, authenticated IPC,
installed LocalSystem proof, kernel interception, driver enforcement, or
pre-execution blocking.

Local evidence passes the focused low-integrity and adjacent token/launch
filters, complete Authenticode `37/37` with six intentional child-fixture
ignores, strict Native/Local/Guard lint, both locked workspace variants,
release embedded/catalog/hash-binding smoke, Flutter `838/838`, and source
contracts `637/637`. The corrected definitive verifier and built-in plus
independent validators pass exactly `238/238` in `429.7s`; controlled
237-step, missing-step, missing-verified-scope, and missing-technical-limit
reports are rejected. Evidence-head, merge, merged-main, installed LocalSystem,
AppContainer, driver, and pre-execution evidence remain separate.

Exact implementation head `c7ff9b7` passes Avorax CI `32638907677` and
Desktop Packages push/PR `32638895902`/`32638907670`. Both package runs pass
Windows MSI/EXE, Linux DEB/tar, both macOS DMGs, six-artifact consolidation,
checksums, and lockfile SBOM; publication is skipped. Evidence-head, merge,
merged-main, installed enterprise, and LocalSystem evidence remain separate.

Checkpoint 2208 integration is closed through evidence `fa7574f`, PR `#60`,
merge `1076ac3`, exact merged-main CI `32640506209`, packages `32640506192`,
guarded 12-path original-tree synchronization, destination runtime checks, and
an unchanged protected-vault invariant. This closes the implementation and
integration evidence only; the identity/profile/registry/desktop/read,
AppContainer, installed LocalSystem, driver, and pre-execution limitations
above remain unchanged.

## Checkpoint 2209 Mandatory No-Write-Up Token Policy

Checkpoint 2208 verified the helper's exact Low Mandatory SID, but Windows also
stores a mandatory integrity policy in `TOKEN_MANDATORY_POLICY`. A low SID must
not be reported as enforced no-write-up when that separate policy is off.
Checkpoint 2209 therefore requires the LSA-created policy inherited through
`CreateRestrictedToken` to contain `TOKEN_MANDATORY_POLICY_NO_WRITE_UP`. Full
parent read-back occurs before `CreateProcessAsUserW`, and the child repeats it
before stdin or untrusted request processing. An attempted direct
`SetTokenInformation(TokenMandatoryPolicy)` call failed with
`ERROR_PRIVILEGE_NOT_HELD` (1314); it was removed rather than granting the
helper another privilege.

The evidence parser requires no-write-up and rejects every bit outside
`TOKEN_MANDATORY_POLICY_VALID_MASK`. It accepts the documented optional
`TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN` bit only when no-write-up is also
present. Pure off/new-process-only/unknown-bit cases and a real benign child are
verified. Both locked workspace variants, strict lint, release trust smoke,
Flutter analyze and `838/838`, source contracts `639/639`, and the definitive
verifier/validators pass exactly `239/239` in `433.2s`. Five malformed reports
are rejected. Hosted and installed evidence remain separate.

This makes no-write-up policy explicit but does not set no-read-up or
no-execute-up and does not change identity, credentials, profile/registry,
desktop/window station, ordinary reads, or explicitly low-writable objects. It
is not AppContainer/LPAC, private-desktop isolation, authenticated cross-user
IPC, installed LocalSystem proof, driver enforcement, or pre-execution
blocking.

The first definitive checkpoint-2209 verifier exposed a host-interaction risk:
an exact compile-time EICAR marker made the otherwise benign Native test
executable a Defender target, causing OS error 225 after 38 steps. Defender
must not be weakened to accommodate tests. Native therefore stores only a
bounded XOR-encoded vector, decodes it once in memory, and shares the matcher
with Local Core. Both test executables reject static exact-marker inclusion.
This preserves EICAR detection but does not claim that an opt-in standard EICAR
file will bypass, replace, or outrun Defender.

The initial Defender failure remains explicit. A later retry also failed at
step 233 when an agent-created Python bytecode cache contained the contract's
compile-time-joined marker; the no-malware gate detected it. The cache was
removed, the contract now runtime-joins fragments, and the complete retry plus
the binary gate pass. No Defender exclusion or setting change was made.

Checkpoint 2209 integration is closed through evidence `7fd8734`, PR `#61`,
merge `d07220c`, exact merged-main CI `32646774829`, packages `32646774820`,
guarded 18-path original-tree synchronization, destination focused/full
checks, and an unchanged protected-vault invariant. This closes the mandatory-
policy and verifier-binary integration evidence only; identity, read, profile,
registry, desktop, AppContainer, installed LocalSystem, signed-driver,
pre-execution, and production-accuracy limitations remain unchanged.

## Checkpoint 2210 Token Virtualization and UIAccess Boundary

**Threat:** A helper token that permits or enables legacy virtualization can
observe redirected/merged per-user registry state or redirect eligible writes,
making actual behavior differ from the documented low-integrity boundary. A
token with UIAccess can interact across UI privilege-isolation boundaries that
ordinary desktop processes cannot cross.

**Redesigned control:** The prepared primary token and actual child token must
return a canonical Boolean for `TokenVirtualizationAllowed` and exact zero for
`TokenVirtualizationEnabled` and `TokenUIAccess` through fixed-size
`GetTokenInformation` queries before launch or stdin. Any noncanonical,
enabled, query, size, or inherited-state mismatch is fail-visible and cannot
become trust. There is no capability setter, privilege addition, or weaker
launch retry.

**Evidence state:** Pure cases reject enabled state and malformed non-Boolean
capability evidence; a benign isolated child validates real process state. The
first compiled child exposed `TokenVirtualizationAllowed=1`, so the original
all-zero capability policy failed and was corrected; it is not success. The
repaired filter passes `2/2`, all adjacent filters and complete Authenticode
pass, source contracts pass `640/640`, and strict lint, locked workspaces,
release-host smoke, Flutter, no-malware, and dependency gates pass. The
definitive verifier and independent validator pass `240/240` in `458s`; five
malformed reports are rejected. Exact implementation `c744fa9` passes hosted CI
`32649764260` and package push/PR `32649749634`/`32649764310`, with six
artifacts, checksums, lockfile SBOM, and publication skipped. Evidence-head,
merged-main, and installed evidence remained pending at that implementation
stage. Evidence `8228daf`, PR `#62`, merge `425e663`, exact merged-main CI
`32651609367`, packages `32651609388`, 12-path guarded synchronization, and
destination contracts/token/Authenticode/no-malware/lint/release/smoke/full-
workspace checks now pass. Lockfiles and the protected vault remain exact;
installed LocalSystem evidence remains pending.

**Residual risk:** `TokenVirtualizationAllowed` may remain one because it is an
inherited capability. Trusted helper code has no enable path, but the
capability is not removed. The flags do not isolate identity, profile, registry
namespace, desktop/window station, ordinary reads, inherited standard handles,
already mapped code/data, or post-verdict mutation. They are not AppContainer,
LPAC, private-desktop isolation, authenticated cross-user IPC, installed
LocalSystem evidence, kernel interception, driver enforcement, or pre-execution
blocking.

## Checkpoint 2211 Job UI Resource Boundary

**Threat:** Even with low integrity and UIAccess disabled, a same-desktop helper
can attempt selected USER-handle, clipboard, global-atom, desktop-switch, display,
system-parameter, or shutdown operations that are irrelevant to hash-bound
publisher verification and enlarge the impact of a parser or trust-stack flaw.

**Scripted control:** Before the helper is assigned or resumed, its Job is
configured through `JobObjectBasicUIRestrictions` with exact
`JOB_OBJECT_UILIMIT_HANDLES`, `JOB_OBJECT_UILIMIT_READCLIPBOARD`,
`JOB_OBJECT_UILIMIT_WRITECLIPBOARD`, `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS`,
`JOB_OBJECT_UILIMIT_DISPLAYSETTINGS`, `JOB_OBJECT_UILIMIT_GLOBALATOMS`,
`JOB_OBJECT_UILIMIT_DESKTOP`, and `JOB_OBJECT_UILIMIT_EXITWINDOWS`. Exact
parent read-back of the exact returned structure size and exact flags is
mandatory. Configuration, query, returned-size, exact-flag, assignment, or
resume failure cannot become trust and has no weaker retry.

**Evidence state:** Two benign Windows regressions pass `2/2`; complete
Authenticode passes `43` with `8` ignored and release Local Core/Guard trust
smoke remains compatible. Both locked workspaces, strict Native/Local/Guard
lint, Flutter analyze and `838/838`, source contracts `641/641`, and
no-malware/dependency gates pass. Final review found missing returned-size
validation, then found that retry 2 did not require returned-size wording in the
central scope; neither earlier passing run is final evidence. After both repairs
and full affected reruns, corrected retry 3 and its independent validator pass
`241/241` in `434.1s`; five fresh malformed reports are rejected.
Exact implementation `024d63f` passes CI `32655155577` plus Desktop Packages
push/PR `32655130037`/`32655155628`, including all six platform artifacts,
checksums, lockfile SBOM, administrative MSI extraction, and skipped
publication. Evidence-head, merge, destination, and installed evidence remains
pending.

**Residual risk:** Job UI limits constrain documented shared UI operations but
do not create a private desktop or window station, change SID/profile, remove
filesystem/registry/network/read access, constrain named kernel objects, or
isolate already mapped code/data. They are not AppContainer/LPAC, authenticated
cross-identity IPC, installed LocalSystem proof, driver enforcement, kernel
interception, or pre-execution blocking.

**Integration closure:** Evidence head `9378955`, PR `#63`, merge `33cafa5`,
merged-main CI `32656681010`, packages `32656681007`, exact 12-path guarded
synchronization, destination source/focused/full/release checks, exact lockfiles,
and the unchanged vault pass. Publication was skipped. This closes the Job UI
checkpoint, not the residual isolation risks or the complete antivirus goal.

## Checkpoint 2212: Private Authenticode Desktop

**Threat addressed:** A one-shot trust helper attached to the caller's interactive
desktop can share windows, hooks, menus, and desktop objects with unrelated GUI
processes. Job UI restrictions reduce operations but do not establish a separate
desktop namespace.

**Scripted control:** Before process creation, the parent creates a unique bounded
desktop with `CreateDesktopW` in the current process window station while temporarily
using a read-back-verified low-integrity `SecurityImpersonation` token derived from
the exact child primary token. Successful `RevertToSelf` is mandatory. The parent
reads back the exact name/byte count and non-inheritable zero-hook flags, passes the
exact name via `STARTUPINFOEXW.lpDesktop`, and retains the handle through child exit.
After confirmed child exit, `CloseDesktop` success is checked and failure remains
diagnostic; RAII is retained as a failure-path fallback.
Before token validation or stdin, the child compares startup state with
`GetThreadDesktop(GetCurrentThreadId())`. Any failure remains diagnostic and cannot
become publisher trust. Private-desktop tests pass `2/2`, complete Authenticode
passes `45` with `9` intentional ignores, and both locked workspaces report Native
`481` passed/`9` ignored plus compiler `6/6`. Strict lint/release/two-host smoke,
Flutter analyze and `838/838`, source contracts `642/642`, no-malware, dependency,
exact-lockfile, and protected-vault checks pass. The definitive report and independent
validator pass `242/242` in `473.5s` after final review found and repaired unchecked
`CloseDesktop` result handling; five malformed reports are rejected. Hosted,
integration, destination, and installed evidence remain pending. Exact
implementation `2612b7a` passes CI `32660616609` and package push/PR
`32660604610`/`32660616617`, including all six artifacts, checksums, lockfile
SBOM, administrative MSI extraction, and skipped publication.

The first parent-integrity desktop attempt failed visibly at loader status
`0xC0000142`. The repair does not introduce a permissive DACL or a default-desktop
fallback.

**Residual risk:** The desktop inherits the current window station's security
descriptor. It does not isolate the station-wide clipboard or global atom table,
SID/profile/registry/filesystem/network/read access, named kernel objects, or desktop
heap accounting. It is not AppContainer/LPAC, authenticated cross-identity IPC,
installed LocalSystem proof, driver interception, or pre-execution blocking.

## Checkpoint 2213: Authenticode Standard-Handle Binding

**Threat addressed:** Restricting process inheritance to three numeric handles is
not by itself child-side proof that the C runtime's `stdin`, `stdout`, and `stderr`
still identify three distinct anonymous pipes with the intended direction. Leaving
their inheritance flags set also needlessly exposes them to any attempted descendant.

**Scripted control:** Every parent `CreatePipe` endpoint is queried through
`GetFileType` and `GetHandleInformation` before process creation.
`GetNamedPipeInfo` verifies server/read endpoints; exact API return-role assignment
binds child stdin to read and stdout/stderr to writes without relying on an
unsupported write-handle attribute query. Parent endpoints must have zero flags and
child endpoints exactly `HANDLE_FLAG_INHERIT`. Before private-desktop, token, mitigation, or stdin
processing, the child requires exact `STARTF_USESTDHANDLES`, exact `GetStdHandle`
identity against startup state, three valid distinct `FILE_TYPE_PIPE` handles,
queried stdin server/read mode, stdout/stderr identity bound to parent-created write
handles, and exact initial inheritance flags. It then clears
`HANDLE_FLAG_INHERIT` on all three and requires exact-zero read-back. Any handle
query, type, direction binding, identity, duplicate, initial-flag, mutation, or read-back
failure is diagnostic and cannot become publisher trust.

A benign real-child fixture, adversarial pure evidence, verifier step 243, strict
independent report validation, source contracts, and audit documentation were all
scripted before test execution. No checkpoint-2213 passing result was claimed before
execution. Focused `2/2`, complete Authenticode `47` passed/`10` ignored, source
contracts `643/643`, strict lint/release/two-host smoke, both locked workspaces,
Flutter `838/838`, and no-malware pass. The definitive verifier/validator pass
`243/243` in `469.2s`; five controlled malformed reports are rejected, exact
lockfiles and the protected-vault invariant pass. Exact implementation `f0f4c3b`
passes CI `32665658235` and package push/PR `32665646920`/`32665658257`, with six
artifacts, checksums, lockfile SBOM, administrative MSI extraction, and skipped
publication. Evidence-head/integration, destination, installed, and complete final-
artifact license evidence remain pending. Candidate fixtures are never executed.

**Residual risk:** Exact standard-handle binding narrows inherited helper IPC only.
Anonymous pipes and the nonce do not provide cross-identity authentication or
encryption, prevent same-user handle duplication, or isolate the named-kernel-object
namespace. The boundary is not AppContainer, installed LocalSystem evidence, driver
interception, or pre-execution blocking.

## Checkpoint 2214 Job Membership and Process Identity

**Threat:** A successful `AssignProcessToJobObject` call alone does not read back
that the intended process handle and `PROCESS_INFORMATION` refer to the same live
helper, that the helper is a member of the exact Job, or that it is the Job's sole
member before execution resumes. The child also previously assumed parent
assignment without checking whether it actually runs under a Job before trust work.

**Scripted control:** After assignment and before `ResumeThread`, the parent requires
nonzero matching `PROCESS_INFORMATION.dwProcessId` and `GetProcessId` identities,
exact-Job `IsProcessInJob`, and an exact-size
`JOBOBJECT_BASIC_PROCESS_ID_LIST` containing exactly one assigned/listed process
whose sole PID is the helper. Identity, exact-membership, query, returned-size,
count, or PID failure terminates and reaps the still-suspended helper. As its first
in-process action, the child requires nonzero `GetCurrentProcessId` and successful
null-Job `IsProcessInJob` evidence before standard handles, private desktop, token,
mitigation, stdin, request, or candidate processing. No weaker retry exists.

A benign real child, pure adversarial evidence, verifier step 244, independent
exact-count/scope validation, source contract 644, and audit documentation are
scripted before execution. No checkpoint-2214 passing result is claimed before
execution. Candidate fixtures are never executed.

The later execution phase passes the focused real-child/adversarial checks `2/2`,
complete Authenticode `49` passed/`11` intentional ignored, both locked workspace
variants with Native `485`/`11` and compiler `6/6`, source contracts `644/644`,
strict lint/release/two-host trust smoke, Flutter analyze and `838/838`, no-malware,
dependency, exact-lockfile, and protected-vault gates. The definitive verifier and
independent validator pass exactly `244/244` in `464.3s`; six adversarial report
mutations are rejected. At this local-evidence point, hosted and integration
evidence remained pending; the later hosted result is recorded immediately below.

Exact implementation `6c3bad3` later passes Avorax CI `32670186345` and Desktop
Packages push/PR runs `32670175754`/`32670186350`. The package runs pass six native
artifacts, checksums, lockfile SBOM, dependency/license evidence, and Windows
administrative MSI extraction without installation; publication is skipped.
Evidence head `3014c44` passes CI `32671137010` and packages `32671137068`; PR
`#66` merges normally as `cbf6203`; merged-main CI `32672025315` and packages
`32672025303` pass. Exact 12-path synchronization and destination runtime, lint,
workspace, Flutter, safety, dependency, lockfile, and vault checks pass. This closes
checkpoint integration evidence without changing the residual boundary below.

**Residual risk:** Parent exact-Job and PID-list read-back is point-in-time process
confinement. The child passes a null Job handle, so its `IsProcessInJob` evidence
proves membership only in some Job, not independently in the unnamed parent Job.
The parent keeps the process handle alive, but PID state is not an authenticated IPC
identity. Job membership neither authenticates/encrypts pipes nor changes SID,
profile, registry, filesystem, network, or ordinary read access. It is not
AppContainer/LPAC, installed LocalSystem, driver, or pre-execution evidence.

## Checkpoint 2215 Anonymous-Pipe Parent-Creator Binding

**Threat:** Exact inherited handle identity and direction do not independently
prove which process created the connected opposite endpoint. Unchecked peer-owner
state must not reach publisher-trust request parsing.

**Verified local control:** The parent places canonical nonzero `GetCurrentProcessId`
evidence in the exact sanitized launch environment. After standard-handle type,
direction, startup identity, and inheritance checks, the child requires
`GetNamedPipeClientProcessId` on its inherited stdin server/read handle and
`GetNamedPipeServerProcessId` on inherited stdout/stderr client/write handles to
all equal that parent PID and differ from child PID. Missing, malformed, zero,
self, API-failed, or mismatched evidence is diagnostic before private desktop,
token, mitigation, stdin, request, candidate, or WinTrust work.

A real benign isolated child and malformed/mismatched adversarial evidence pass
`2/2`; source contracts pass `645/645`; complete Authenticode passes `59` with
`12` intentional ignores; both locked workspaces report Native `487`/`12` plus
compiler `6/6`; and verifier/validator pass exactly `245/245` in `469.4s`. Seven
fresh malformed reports are rejected. No checkpoint-2215 passing result is claimed
before execution; these results come from the later execution phase. Candidate
fixtures are not executed. Hosted and integration evidence remain pending.

**Residual risk:** Anonymous `CreatePipe` endpoints are both created and connected
in the parent before inheritance. The process-ID APIs bind the child's inherited
handles to that parent creator; they do not report the later inheriting child back
to the parent. The environment PID is an expectation rather than a secret. This
does not prevent same-user handle duplication and is not encrypted, durable, or
authenticated cross-identity IPC. AppContainer, installed LocalSystem, driver, and
pre-execution limitations remain unchanged.
## Checkpoint 2216: Authenticode parent-child handshake

Checkpoint 2215's anonymous pipes prove the exact parent creator to the child but
cannot prove the inheriting child back to the parent. Checkpoint 2216 scripts a
separate random local named-pipe handshake before trust work. The child requires
`GetNamedPipeServerProcessId` to equal the canonical parent PID; the parent
requires `GetNamedPipeClientProcessId` to equal the exact live launched child PID.
The distinct random token must match exactly. A current-user/SYSTEM DACL,
low-integrity mandatory label, remote rejection, one-instance policy, bounded
overlapped I/O, cancellation settlement, and terminate/reap behavior reduce
substitution, namespace guessing, hangs, and unsafe in-flight cleanup.

Residual risk remains explicit: this is same-user process binding, not encrypted
or durable cross-identity IPC. It does not defeat privileged same-user memory or
process access, trusted code already inside either process, or kernel compromise.
It is not AppContainer/LPAC, installed LocalSystem, production signing, driver
interception, or pre-execution evidence. No checkpoint-2216 passing result is
claimed before execution.

Local execution now passes focused mutual-PID/adversarial runtime, complete
Authenticode, release two-host trust smoke, source contracts `646/646`, and exact
verifier/validator `246/246`; seven malformed reports are rejected. Exact
implementation `472b478c10dad6683ea867616f21c3636fe446de` also passes hosted CI
`32680555167` and package push/PR `32680536082`/`32680555166`, with publication
skipped. Merge, merged-main, synchronization, and destination evidence remain
pending.

**Integration closure:** Evidence `b1c5b4e`, PR `#68`, merge `e883c187`,
merged-main CI `32682998536`, packages `32682998541`, exact 13-path guarded
synchronization, destination source/runtime/lint/release/full-workspace/Flutter
checks, and destination verifier/validator `246/246` in `489.4s` pass. Lockfiles
and the protected vault remain exact and publication was skipped. This closes the
checkpoint integration, not the same-user/cross-identity, AppContainer,
installed-service, driver, pre-execution, or complete-antivirus limitations.

## Checkpoint 2217: applied handshake-pipe security

**Threat:** Passing intended SDDL into `CreateNamedPipeW` is not runtime evidence
that the endpoint received the exact protected DACL and low-integrity label.

**Verified control:** Immediately after endpoint validation and before any event,
connect, process creation, or helper launch, the parent calls `GetSecurityInfo`
with `SE_KERNEL_OBJECT` and exactly `DACL_SECURITY_INFORMATION |
LABEL_SECURITY_INFORMATION`. Both components require existing `READ_CONTROL`.
Bounded structured ACL/ACE evidence, with generic pipe/file masks normalized by
`MapGenericMask`, must exactly prove ordered SYSTEM and current-user full-control
ACEs, `SE_DACL_PROTECTED`, and one low-integrity no-write-up mandatory label. Any
API, ACL bound/count, ACE type/size/flag/mask/SID, principal, policy, or label
mismatch fails visibly with no weaker retry.

**Least privilege and residual risk:** The check intentionally does not query the
full SACL, request `ACCESS_SYSTEM_SECURITY`, or enable `SeSecurityPrivilege`;
`LABEL_SECURITY_INFORMATION` exposes only mandatory-label evidence. Read-back is
point-in-time and cannot defeat privileged same-user mutation/inspection, trusted
in-process code, SYSTEM, or kernel compromise. It is not encrypted cross-identity
IPC, AppContainer/LPAC, installed LocalSystem, production signing, a driver, or
pre-execution protection. Focused and adjacent runtime tests, complete
Authenticode, strict lint, locked workspaces, release smoke, source contracts, and
the exact `247/247` definitive verifier pass locally. Exact implementation
`a518e93` passes hosted CI `32687717433` and package push/PR
`32687664061`/`32687717444`. Evidence `5fe8dd2`, PR `#69`, merge `3fe2b87`,
evidence-head and merged-main CI/packages, exact 12-path synchronization,
destination Authenticode `62/13`, and destination verifier/validator `247/247`
complete integration. The residual risks above remain unchanged.

## Checkpoint 2218: child-opened handshake-pipe security

**Threat:** Parent read-back immediately after server creation does not by itself
prove that the later low-integrity child observes the same exact protected DACL
and mandatory label on its opened client endpoint before token exchange.

**Verified and integrated control:** The child requests exactly
`GENERIC_WRITE | READ_CONTROL`, validates the client endpoint and exact parent
server PID, resolves its current process-token SID, then performs the same bounded
`GetSecurityInfo(SE_KERNEL_OBJECT)` DACL and mandatory-label read-back before
`WriteFile`. Any access, SID, query, descriptor, ACL/ACE, policy, label, or order
failure is diagnostic and cannot reach token exchange or publisher trust. No
write-only or weaker retry exists. Real child `1/1`, Authenticode `63/13`, source
contracts `648/648`, strict lint, locked workspaces, release smoke, Flutter
`838/838`, and safety/dependency gates pass. Verifier/validator passes `248/248`
in `470.1s`; eight malformed reports are rejected. Evidence `eb11c81`, PR `#70`,
merge `1e453005`, evidence/merged-main CI and packages, exact 12-path sync,
destination full workspaces/lint/release/trust-smoke/Flutter checks, and destination
verifier `248/248` in `484.1s` pass. Locks and the protected vault remain exact;
publication is skipped.

**Residual risk:** This narrows creation-to-connect descriptor drift but remains a
point-in-time same-user control. It does not defeat privileged same-user or trusted
in-process mutation/inspection, SYSTEM, process-memory access, or kernel compromise;
provide encryption or cross-identity authentication; create AppContainer/LPAC;
prove installed LocalSystem or production signing; add driver enforcement; or
provide pre-execution protection.

## Checkpoint 2219: least-privilege handshake-pipe DACL

**Threat:** The earlier protected DACL gave both SYSTEM and the current user full
control even though the protocol needs only parent read and child write plus
descriptor read-back. Extra execute/delete/owner-management rights enlarge the
same-user attack surface without improving Authenticode trust evidence.

**Locally and exact-head hosted verified control:** The exact DACL grants SYSTEM normalized full control and
the current user normalized generic read plus generic write. Both endpoint
read-backs normalize generic pipe/file masks and reject current-user full-control,
read-only, write-only, execute, delete, `WRITE_DAC`, `WRITE_OWNER`, or any other
mismatch before token exchange or publisher trust. The real child fixture and
adversarial benign masks, exact verifier step 249, validator clauses, and source
contract 649 pass. Exact implementation `5171fb4e` passes CI `32702550130` and
package push/PR `32702466511`/`32702550182`, including all six packages, seven
checksums, the 569-component lockfile SBOM, and administrative MSI extraction;
publication is skipped. Evidence `be122479`, PR `#71`, merge `e6caf818`,
evidence/merged-main CI and packages, exact 12-path synchronization, destination
full workspaces/lint/release/trust-smoke/Flutter checks, and destination
verifier/validator `249/249` in `486.9s` complete integration.

**Residual risk:** The pipe creator's token default owner is not changed or
independently read back. If the current user owns the named pipe, Windows
ownership supplies implicit `READ_CONTROL` and `WRITE_DAC` independently of the
narrower ACE. Parent and child checks remain point-in-time evidence and cannot
prevent same-user descriptor mutation between checks. This does not provide
encryption, authenticated cross-identity IPC, AppContainer/LPAC, installed
LocalSystem, production signing, driver enforcement, or pre-execution protection.

## Checkpoint 2220: handshake-pipe Owner Rights

**Threat:** A narrower current-user ACE alone did not remove the owner's
automatic `WRITE_DAC`, allowing same-user descriptor management independently of
the visible ACE contract.

**Scripted control, verification pending:** The creation descriptor explicitly
sets the current process-token user SID as owner and adds ordered Owner Rights
`S-1-3-4` with only `READ_CONTROL`. Both endpoint checks request and validate
the exact owner alongside protected DACL and mandatory-label evidence. Microsoft
documents that an applied Owner Rights ACE suppresses implicit owner
`READ_CONTROL` and `WRITE_DAC`. A benign local random-pipe test must prove a
same-user `WRITE_DAC`-only reopen returns `ERROR_ACCESS_DENIED`; adversarial
owner/SID/mask/flag/order evidence must fail before trust. Verifier step 250,
exact validation, and source contract 650 are scripted, not yet passed.

**Residual risk:** The current-user ACE intentionally retains protocol
read/write. Existing handles, trusted same-user code, privileged ownership
changes, injection, duplication, and descriptor mutation between point-in-time
checks remain in scope, as do SYSTEM/administrator/kernel compromise. This is
not encryption, cross-identity IPC, AppContainer/LPAC, installed LocalSystem,
production signing, driver enforcement, or pre-execution protection.

**Corrected local evidence:** The exact same-user `WRITE_DAC` denial passes
`1/1`; all four handshake security filters and Authenticode `57/13` pass. Native
`493/13`, compiler `6/6`, Local Core `536/536`, Guard `248/249`, strict lint,
both locked workspaces, release/two-host embedded/catalog/hash-binding smoke,
source contracts `650/650`, Flutter analyze, and Flutter `838/838` pass. The
definitive report, malformed validation, lock/vault, hosted, integration,
synchronization, and destination evidence remain pending.

**Definitive local evidence:** Exact verifier/validator `250/250` passes in
`452.7s`, and nine malformed reports are rejected. Root Cargo, Native Cargo,
Flutter lock blobs, and the read-only protected-vault invariant remain exact.
This closes local evidence only; hosted, integration, synchronization, and
destination checks remain pending, and the point-in-time/cross-identity/
pre-execution limitations remain unchanged.

**Implementation-head hosted evidence:** Exact SHA
`6f90f9234375ceb22107aba426401e38838ec9b8` passes all five CI jobs in run
`32712875828` and package push/PR runs `32712856310`/`32712875850`. The push
artifact has six release files, seven independently matching SHA-256 rows, and
a CycloneDX 1.6 lockfile SBOM with 569 components. Both publication jobs are
skipped. This confirms build and hosted regression behavior; it does not expand
the control beyond the same-user, point-in-time boundary described above.
Evidence-head, merge, merged-main, synchronization, and destination checks
remain pending.

**Integration and destination evidence:** Evidence `a99b03a` and merged main
`2bd8956` pass exact-head and merged-main CI/packages; package publication is
skipped. Guarded synchronization leaves 12/12 exact destination blobs and no
staging files. Full destination Rust/Flutter checks pass, and the destination
report validates exact `250/250`, zero failed/skipped, in `494.3s`. Three lock
blobs and the protected-vault invariant remain exact. This closes checkpoint
integration without changing the residual same-user, point-in-time,
cross-identity, privileged-adversary, or pre-execution boundaries.

### Authenticode handshake client token (checkpoint 2221)

The child now opens its dedicated handshake endpoint with explicit
`SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`. After the one bounded token
message is read, the parent calls `ImpersonateNamedPipeClient`, validates exact
`SecurityImpersonation`, launch user SID, low-integrity/no-write-up state,
privilege stripping, zero restricting SIDs, virtualization and UIAccess state,
then requires `RevertToSelf` and no remaining thread token. Any failure stops
publisher trust. Focused runtime, adversarial, full regression, and exact
`251/251` definitive verifier evidence pass locally.

The boundary remains same-user and message-scoped. It does not resist a
privileged same-user injector or handle duplicator, encrypt the pipe, change
identity/logon session, implement cross-identity service IPC, create
AppContainer/LPAC, or demonstrate driver/pre-execution protection. Those limits
remain explicit even when checkpoint verification succeeds.

### Authenticode client logon session (checkpoint 2222)

Before creating the dedicated pipe, the parent now captures the exact
low-integrity, privilege-stripped launch token's user SID,
`TokenStatistics.AuthenticationId`, and `TokenSessionId`; the user SID must
also equal the pipe owner. After the bounded client message is read and
impersonated, the connected thread token must match both authentication-LUID
halves and the exact session ID. Empty expected authentication IDs, fixed-size
query failure, authentication-ID drift, session-ID drift, or failed cleanup
cannot become publisher trust. These controls and their benign/adversarial
tests are scripted; execution evidence is pending.

This narrows the same-user cross-logon-session substitution threat but is only
point-in-time evidence. It does not prove token uniqueness, stop privileged
same-logon-session injection or handle duplication, encrypt the channel,
change identity, authenticate cross-identity service IPC, provide
AppContainer/LPAC, or establish signed-driver/pre-execution enforcement.

Focused and full local evidence now passes: source contracts `652/652`, exact
logon-session `2/2`, Authenticode `69/13`, Native `497/13` plus compiler `6/6`,
Local Core `536/536`, Guard `248/249`, both locked workspaces, strict lint, and
Flutter `838/838`. Locks and the read-only protected vault remain exact.
Definitive, hosted, integration, synchronization, and destination proof remain
pending, so the residual threat classification is unchanged.

Definitive local verification now passes exact `252/252` in `507.8s`, including
the exact logon-session target. Both strict validators pass and nine malformed
reports are rejected. This strengthens evidence for the implemented boundary;
it does not alter the same-session, cross-identity, AppContainer/LPAC, driver,
or pre-execution limitations above.

### Authenticode client token stability window (checkpoint 2223)

After successful named-pipe impersonation, the parent now snapshots exact
`TokenStatistics.TokenId` and `ModifiedId` before querying privileges, type,
level, SID, logon session, restricted SIDs, integrity, mandatory policy,
virtualization, and UIAccess. It queries both identifiers again only after all
property checks pass. Empty initial token identity, exact-size query failure,
token-instance drift, or token-modification drift fails visibly and cannot
become publisher trust; `RevertToSelf` remains mandatory on every path.

This narrows token replacement or mutation during the successful validation
window. It intentionally does not compare the impersonation `TokenId` with the
launch primary token because they are distinct token-object instances. It does
not detect mutation wholly before or after the window, prevent same-session
injection or handle duplication, encrypt the channel, authenticate cross-
identity service IPC, provide AppContainer/LPAC, or demonstrate signed-driver/
pre-execution enforcement. Scripting is complete; runtime and hosted evidence
remain pending.

Local runtime evidence now passes the isolated real handshake and adversarial
drift cases `2/2`, Authenticode `71/13`, Native `499/13`, both locked
workspaces, strict lint, Flutter `838/838`, and definitive exact `253/253` in
`492.9s`. Nine malformed reports are rejected. This verifies the implemented
window on this host; it does not alter the same-session, cross-identity,
AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution
residual threats. Hosted and destination evidence remain pending.

Exact implementation `561ac536a55257b05f9c04ada55756d1ab676749`
passes CI `32744796324` and both package runs `32744796274`/`32744754697`.
Independent checks over each untouched consolidated ZIP verify all six
platform artifacts, seven exact SHA-256 rows, and a CycloneDX 1.6 lockfile SBOM
with 569 components; publication is skipped. Defender removed the Windows
files only from ordinary local extraction, was not weakened, and the incomplete
extracted directories are not treated as complete evidence. Hosted proof does
not expand the point-window boundary or any residual threat above. Evidence-
head, merged-main, synchronization, and destination evidence remain pending.

Evidence `6223ad2`, PR `#75`, merge `252a9ade`, exact evidence-head and
merged-main CI/packages, guarded 12-path synchronization, full destination
Rust/Flutter checks, and destination verifier/validator `253/253` in `484.8s`
close checkpoint integration. The retained first evidence-head arm64 attempt
failed only on bounded `hdiutil verify` resource-busy retries after the build,
payload, signing, smoke, and DMG creation checks passed; failed-job-only attempt
2 passed unchanged. This strengthens deployment evidence but does not expand
the token-stability window or any identity, isolation, driver, or pre-execution
boundary above. Publication was skipped and no package was installed.

### Authenticode launch-primary token stability (checkpoint 2224)

Before exposing the handshake pipe, the parent now snapshots exact
`TokenStatistics.TokenId` and `ModifiedId` from the same parent-held low-
integrity, privilege-stripped token handle later passed to
`CreateProcessAsUserW`. The same handle is queried after successful process
creation while the child is suspended and after exact child-process, connected-
client-token, and random-token handshake authentication. Empty initial token
identity, exact-size query failure, token-instance drift, or modified-context
drift fails visibly; post-creation failure terminates and reaps the helper.

This narrows persistent launch-token replacement or mutation across the launch
window. It is not proof that the child process token remains identical after
creation and does not bind the distinct launch-primary and impersonation token
objects. Transient mutation between snapshots, mutation after final read-back,
same-session injection, privileged handle duplication, and process injection
remain possible within the user-mode threat boundary. Cross-identity
authenticated IPC, AppContainer/LPAC, installed LocalSystem isolation, signed-
driver enforcement, and demonstrated pre-execution protection remain separate
technical or external prerequisites.

Code, regressions, source contract 654, exact verifier step 254, report
validation, and documentation were scripted before execution. Local evidence
now passes target `2/2`, complete Authenticode `65/13`, Native `501/13`, both
locked workspaces, strict lint, Flutter `838/838`, and exact definitive
`254/254` in `489.6s`; nine malformed reports are rejected. This verifies the
implemented point-in-time boundary on this host but does not change the child-
token, transient-mutation, identity, injection, isolation, driver, or pre-
execution residual threats.

Implementation `c831149`, evidence `42d8c7c`, PR `#76`, merge `243bc84`, exact
evidence-head and merged-main CI/packages, guarded 12-path synchronization,
full destination Rust/Flutter checks, and destination verifier/validator
`254/254` in `494.5s` close checkpoint 2224 integration. Publication was
skipped; locks and the protected vault remain exact. This closure does not
expand the point-in-time identity, isolation, driver, or pre-execution boundary.

### Authenticode child process-token binding (checkpoint 2225)

The handshake pipe is now duplex. After writing the random launch token, the
child waits for an exact one-byte ACK and cannot continue into token/request/
candidate work. Parent `OpenProcessToken(process, TOKEN_QUERY)` first queries
the token attached to the exact `PROCESS_INFORMATION` child while suspended,
then reopens it after exact child PID, connected-client-token, nonce, and
launch-token authentication while the child waits for ACK. Both queries require
primary type, the launch user SID and AuthenticationId/session, stripped
privileges, zero restricting SIDs, low integrity/no-write-up, canonical
virtualization, disabled UIAccess, and nonempty `TokenStatistics.TokenId`. The
second query must exactly match the child token's own `TokenId`/`ModifiedId`
captured while suspended before ACK or publisher trust.

The first focused runtime proved that `CreateProcessAsUserW` produced a distinct
child token `TokenId` from the supplied launch-primary token on this host. Exact
cross-object `TokenId` equality is technically unavailable and is not claimed;
the viable control binds launch identity/security properties and then proves
the child token object is stable across the ACK-gated window. This closes the
simple child-exit race and detects persistent wrong-profile attachment or child
token replacement/modification at two point-in-time boundaries. It does not
bind the distinct named-pipe impersonation token object to either primary token,
prevent replacement or mutation after ACK, detect every transient between
snapshots, or prevent same-session process injection and privileged handle
duplication. ACK is bounded flow control, not a secret, encryption, or cross-
identity authentication. AppContainer/LPAC, installed LocalSystem isolation,
production signing, signed-driver enforcement, and demonstrated pre-execution
protection remain separate.

Production code, benign/adversarial regressions, source contract 655, verifier
step 255, strict report assertions, and documentation were scripted before
execution. The first focused run compiled; the adversarial test passed and the
production-path test rejected the infeasible launch/child `TokenId` equality
with successful cleanup. That failure is retained and not counted as a pass;
the repaired focused path passes `2/2`, complete Authenticode passes `52/52`,
and definitive verification passes exact `255/255` in `521.1s` with both strict
validators and nine malformed-report rejections. Evidence `d1a1e14`, PR `#77`,
merge `5792c22`, exact evidence/merged-main CI and package checks, guarded 12-
path synchronization, full destination Rust/Flutter checks, and exact
destination verifier/validator `255/255` in `476.3s` close checkpoint 2225.
Publication was skipped; locks and the protected vault remain exact.

### Authenticode post-response token stability (checkpoint 2226)

**Threat:** Checkpoint 2225 proves launch and exact child process-token state at
suspended creation and authenticated handshake, but the helper could still
experience persistent token replacement or modification after initial ACK while
performing trust work or writing its response.

**Verified and integrated control:** The same duplex channel now remains
open through candidate trust and response flush. After writing and flushing
bounded stdout, the child sends an exact response-ready marker and blocks for a
distinct final ACK. Before that ACK, the parent queries the same launch
`TokenId`/`ModifiedId`, reopens the exact live child token with `TOKEN_QUERY`,
repeats its complete launch identity/restricted profile, and requires the
captured child `TokenId`/`ModifiedId` to remain exact. Bounded overlapped I/O,
process-exit waits, cancellation settlement, terminate/reap, private-desktop,
and worker diagnostics remain fail-visible without a weaker retry. Source
contract 656 and exact verifier step 256 were scripted before execution.
Post-response regressions pass `3/3`, complete Authenticode passes `55/55`,
Native passes `506/15` plus compiler `6/6`, both locked workspaces and strict
lint/offline checks pass, and Flutter passes `838/838`. Definitive verifier and
strict validation pass exact `256/256` in `459.6s`; ten malformed reports are
rejected. Evidence `bacf1cc`, PR `#78`, normal merge `bab872d`, exact evidence-
head and merged-main CI/packages, exact 12-path guarded synchronization, full
destination Rust/Flutter checks, and destination verifier/validator `256/256`
in `438.4s` close checkpoint 2226 integration. The initial arm64 hosted attempt
and support-wrapper failures remain uncredited; publication was skipped and
locks and the protected vault remain exact.

**Residual risk:** This third snapshot narrows persistent drift through flushed
response production but remains point-in-time. It does not cryptographically
bind response bytes to token snapshots, bind the distinct named-pipe
impersonation token object, catch every transient between snapshots, prevent
mutation after final ACK or privileged same-session injection/handle
duplication, encrypt IPC, create cross-identity authentication or AppContainer/
LPAC, prove installed LocalSystem, or demonstrate signed-driver/pre-execution
enforcement. Response-ready and final ACK are flow control, not secrets.

### Authenticode response client reauthentication (checkpoint 2227)

**Threat:** Checkpoint 2226 keeps the exact pipe and child alive through flushed
response production and rechecks launch/child primary tokens, but it does not
repeat connected pipe-client process or impersonation-token authentication at
the response-ready boundary. Persistent client security-context drift after the
initial handshake could therefore escape the later primary-token snapshots.

**Verified and integrated control:** After exact ready-marker validation and
before launch/child token read-back and final ACK, parent binds the client PID
queried from the retained pipe instance to the PID queried from the exact
retained child process handle. It then freshly impersonates that same connection
and repeats exact SecurityImpersonation type/level, launch SID,
AuthenticationId/session, privilege stripping, zero restricting SIDs, low
integrity/no-write-up, virtualization/UIAccess safety, and within-validation
`TokenId`/`ModifiedId` stability. Successful `RevertToSelf` and an empty parent
thread token remain mandatory. Any query, binding, impersonation, profile,
stability, revert, later read-back, or final-ACK failure enters bounded cleanup
and cannot become trust. Source contract 657 and verifier step 257 are scripted.
Focused regressions pass `2/2`, complete Authenticode passes `72/15`, Native
passes `508/15` plus compiler `6/6`, affected crates and both locked workspaces
pass, and Flutter passes `838/838`. Definitive verifier/validator passes exact
`257/257` in `453.2s`, and 12 malformed reports are rejected. Exact
implementation `cef0d28`, evidence `c63fb71`, PR `#79`, normal merge
`9304681`, evidence-head and merged-main CI/packages, exact 12-path guarded
synchronization, full destination Rust/Flutter checks, and destination verifier/
validator `257/257` in `434s` pass. Publication is skipped, locks and the
protected vault remain exact, and this closure does not expand the point-in-time
boundary.

**Residual risk:** This repeats the connected identity/profile at a second point
in time; it is not cross-snapshot token-object equality. Windows may create a
distinct impersonation token object for each call, so that equality is
unavailable and not claimed. Response/ready/ACK bytes remain unencrypted and not
cryptographically token-bound. Transients between checks, post-ACK mutation,
privileged same-session injection/handle duplication, compromised parent/kernel,
cross-identity IPC, AppContainer/LPAC, installed LocalSystem, signed-driver, and
pre-execution threats remain outside this control.

### Authenticode response hash binding (checkpoint 2228)

**Threat:** The response-ready boundary reauthenticates the connected child and
rechecks primary tokens, but its one-byte marker does not describe the exact
stdout bytes later parsed as a verdict. Mutation of the anonymous stdout stream
after flush could therefore leave process/token evidence intact while changing
the response consumed by the parent.

**Scripted control, execution pending:** The response writer retains the exact
bounded JSON plus newline. Child hashes a fixed domain, exact unsigned 64-bit
little-endian length, and every response byte, sends an exact 41-byte marker,
length, and SHA-256 frame on the retained pipe, and waits for ACK. Parent
requires exact frame size and 1..16,384-byte length before fresh connected-client
reauthentication and launch/child token read-back. After exit it compares exact
collected stdout length/digest before strict JSON parsing or publisher trust.
Malformed, truncated, extended, out-of-range, length-mismatch, or digest-mismatch
evidence is fail-visible. Three Rust regressions, source contract 658, verifier
step 258, strict validator scope, and all audit records are scripted before any
execution.

**Residual risk:** The unkeyed SHA-256 digest gains its sender association from
the existing same-user pipe process/token validation. It is content-integrity
evidence, not a secret MAC, encryption, cross-identity message authentication,
or durable token-object identity. A privileged same-session attacker able to
inject the helper, duplicate handles, or change both stdout and frame before the
authenticated snapshot remains in scope. It does not supply AppContainer/LPAC,
installed LocalSystem, production signing, signed-driver, or demonstrated
pre-execution enforcement.

### Authenticode per-launch response MAC (checkpoint 2229)

**Threat:** Checkpoint 2228 detected stdout changes after its frame was formed,
but an unkeyed digest did not require knowledge held by this launch. An actor
able to alter both the anonymous stdout stream and digest frame before the
authenticated snapshot could preserve internal consistency.

**Locally verified control:** The already authenticated canonical
random launch UUID becomes the exact 36-byte HMAC key. The child retains that
key after handshake authentication and computes domain-separated HMAC-SHA-256
over the exact unsigned little-endian response length and all bounded stdout
bytes. The parent retains its independently generated per-launch key, accepts
only the fixed 41-byte frame and canonical 1..16,384-byte length, completes the
existing process/client/token checks, and after exit uses constant-time MAC
verification before strict JSON parsing or publisher trust. Wrong length,
mutated bytes, modified MAC, malformed frame, and a benign child using a wrong
launch key are fail-visible. Source contract 659, complete Authenticode and
workspace regression, verifier step 259, exact `259/259` strict verification,
and controlled malformed-report rejection pass locally. Exact implementation
head `eaa4ba3` also passes all five CI jobs in `32812956518` and complete
Desktop Packages push/PR runs `32812914763`/`32812956466`. Publication is
skipped; both untouched consolidated artifacts pass exact six-platform-file,
seven-checksum, and CycloneDX 1.6/569-component in-stream validation without
extraction or execution. Evidence-head, integration, and destination evidence
remain pending.

**Integration closure:** Evidence `f0c72e1`, PR `#81`, normal merge
`36d67798`, evidence-head and merged-main CI/packages, exact 23-path
synchronization, destination focused/full Rust and Flutter checks, and exact
`259/259` verification in `473s` pass. Publication is skipped; artifact
validation never extracts or executes candidate installers. Locks and the
protected vault remain exact. This closes checkpoint integration without
expanding the same-user technical boundary below.

Definitive execution also exposed a Windows PowerShell 5.1 boundary error:
redirected stdin could prepend a UTF-8 BOM to otherwise strict JSON. The release
Authenticode harness, six user wrappers, and driver-self-test harness now choose
BOM-less UTF-8 only around process/stdin creation and restore the prior encoding
in `finally`. Product parsers still reject BOM-prefixed input; this changes the
trusted producer wiring rather than broadening accepted syntax.

**Residual risk:** The launch token is not durable secret storage. It is carried
in the child's sanitized environment and over a same-user pipe, so same-user
process-memory or environment read access, privileged process injection, or
handle duplication may recover it or modify both stdout and HMAC before
authentication. HMAC-SHA-256 does not encrypt IPC, authenticate another Windows
identity, bind durable token objects, or establish AppContainer/LPAC, installed
LocalSystem, signed-driver, or pre-execution enforcement.

## Checkpoint 2230 - Pipe-Delivered Launch-Key Boundary

**Control:** The parent withholds the canonical random launch/MAC
key until a connected handshake client is bound to the exact retained child
process, its same-user logon-session impersonation token and restricted profile
are authenticated, and launch/child token stability is revalidated. Only that
retained pipe receives the exact key. The child verifies exact parent PID and
the applied pipe DACL/mandatory label before a bounded canonical UUID read,
derives the response MAC key, and emits the exact ACK. The parent validates that
ACK and repeats stability checks before candidate trust work can proceed.

The sanitized environment now carries only the canonical pipe name, parent PID,
and checked native `SystemRoot`/`WINDIR`; it carries no launch token or response
MAC key. Malformed, oversized, truncated, non-UTF-8, noncanonical, duplicate
pipe/key UUID, missing ACK, partial I/O, timeout, cancellation, PID, pipe-security,
or token evidence is fail-visible and cannot become publisher trust. Benign
fixture, source contract 660, and exact 260-step verification coverage are
implemented and verified.

**Residual risk:** Removing environment inheritance narrows passive disclosure;
it does not create durable secrecy. The key remains in parent/child memory and
crosses authenticated same-user IPC. Process-memory access, sufficiently
privileged injection, pipe-handle duplication or observation, compromised
endpoints, administrator/SYSTEM, or kernel compromise may recover it or modify
both response and MAC. This is not encryption, cross-identity authentication,
AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution
enforcement.

**Local evidence:** After scripting completed, source contracts `660/660`, the
new real benign child, adjacent identity/token/MAC targets, complete Native,
Local Core, Guard, both workspace modes, strict lint/offline/release checks,
PS7/PS5 Authenticode smoke, Flutter analyze, and `838/838` UI tests passed.
Definitive, hosted, integration, synchronization, and destination evidence now
passes without changing the residual technical limits below.

Definitive local execution now passes exact `260/260` in `459.9s`, including
the new key-delivery regression in `0.2s`; strict PS5 validation passes and
`16/16` adversarial report mutations are rejected. Evidence `4b03b0e`, PR `#82`,
merge `9690c84`, hosted/merged-main CI/packages, exact 12-path synchronization,
and destination `260/260` in `448.1s` also pass. This evidence does not change
the same-user memory/pipe, cross-identity, driver, or pre-execution limits above.

## Checkpoint 2231 - Authenticode Launch-Key Confirmation HMAC

**Threat:** The checkpoint-2230 fixed one-byte ACK proved protocol ordering but
did not cryptographically prove that the connected child received the exact
per-launch key. A process able to reach the already authenticated same-user
pipe could emit that public byte without possessing the key.

**Control:** The fixed ACK is removed. After exact parent PID, child
PID, pipe security, connected-client token, launch-token, and child-token checks,
the child reads the canonical 36-byte key and computes domain-separated
HMAC-SHA-256 over the exact little-endian canonical pipe-name byte length, every
canonical pipe-name byte, and the exact little-endian parent and child PIDs.
The parent reads at most 33 bytes, requires exactly 32, and uses constant-time
verification under its retained key and exact retained context before repeating
launch/child token stability and allowing request or candidate work. Empty,
truncated, extended, mutated, wrong-key, wrong-pipe, wrong-PID, zero-PID, and
equal-PID evidence is fail-visible. A real restricted benign wrong-key child is
scripted to terminate and reap through existing bounded cleanup. No live malware
or candidate fixture is executed.

**Residual risk:** Handshake key confirmation and response MAC binding use the
same per-launch key with distinct fixed HMAC-SHA-256 domains. This is
point-in-time possession evidence from the already PID/token-bound same-user
pipe, not encryption, cross-identity authentication, durable secret storage,
durable token-object identity, AppContainer/LPAC, installed LocalSystem,
signed-driver, or pre-execution enforcement. Same-user memory read, sufficiently
privileged injection, pipe observation, and handle duplication can still expose
the key or subvert an endpoint.

**Evidence:** Focused HMAC `2/2`, complete Native `515/515` plus compiler `6/6`,
Local `536/536`, Guard `248/248 + 249/249`, both locked workspaces, strict lint,
release smoke, Flutter `838/838`, and source `661/661` pass. Local and destination
verifier/validator evidence passes exact `261/261` in `466.4s` and `452.7s`, with
`8/8` malformed-report rejections at each stage. Evidence `0f49c76`, PR `#83`,
normal merge `b678027`, hosted/merged-main CI/packages, guarded synchronization,
exact locks, and the protected-vault invariant pass; publication is skipped.

## Checkpoint 2232 - Authenticode Launch-Key Best-Effort Zeroization

**Threat:** Checkpoint 2231 retained the random per-launch HMAC key in ordinary
owned `String` values and created a separate raw 36-byte derived-key array. Drop,
error, cancellation, or unwind released those allocations without an explicit
best-effort scrub, increasing the chance that stale key bytes remained readable
in Avorax-owned memory after the protocol ended.

**Control:** The Windows-only Native Authenticode path pins `zeroize 1.9.0` and
uses `Zeroizing<String>` for the parent handshake, authenticated response
evidence, pending child handshake, and completed child handshake. The bounded
37-byte child pipe-read buffer uses `Zeroizing<[u8; 37]>`. Canonical UUID
validation now returns a borrowed key slice instead of copying the key into a
raw array. Key-bearing structs do not derive `Debug`. RAII covers normal drop,
early return, and unwind; a pure benign regression explicitly scrubs both owned
forms and requires prior handshake-HMAC and response-MAC evidence to fail.

**Residual risk:** This is best-effort cleanup of Avorax-owned buffers only. It
does not prove erasure of compiler temporaries, HMAC internals, allocator or OS
copies, process dumps, paging, or forensic remnants and does not stop same-user
or privileged reads while the key is live. It is not secure erasure, encryption,
durable secret storage, cross-identity authentication, AppContainer/LPAC,
installed LocalSystem, signed-driver, or pre-execution enforcement.

**Local evidence:** Focused zeroization passes `1/1`; Native passes `516/516`
with 19 intentional ignored child entrypoints plus compiler `6/6`; Local passes
`536/536`; Guard passes `248/248 + 249/249`; both locked workspaces, strict lint,
offline/release/two-host trust smoke, Flutter analyze and `838/838`, and source
contracts `662/662` pass. The exact no-skip/no-Defender verifier and both strict
validators pass `262/262` in `459.7s`, and `8/8` malformed reports are rejected.
Locks and the protected-vault invariant remain exact. Exact implementation
`eac61e6` passes all five CI jobs and both Windows/Linux/macOS package runs;
their consolidated artifacts pass exact digest and in-stream inventory/SBOM
validation with publication skipped. Evidence-head, integration,
synchronization, and destination proof remain pending. No candidate content or
live malware is used.

**Integration evidence:** Evidence `183d1d6`, normal PR `#84` merge `6de2a8f`,
evidence-head and merged-main CI/packages, skipped publication, and exact
non-extracting package digest/inventory/SBOM validation pass. Guarded mixed
merged-main/checkpoint-2231-closure preconditions synchronize exact 15 paths.
Destination full Rust/Flutter/build evidence passes, as do exact `262/262` in
`555.3s`, both strict validators, and `8/8` adversarial report rejections. Locks,
processes, sync residue, and the protected-vault invariant remain exact.
Checkpoint 2232 is closed; the complete antivirus goal remains active and all
owned-buffer-only technical limits above remain unchanged.

## Checkpoint 2233 - Authenticode Fixed Launch-Key Buffer

**Threat:** Checkpoint 2232 scrubbed Avorax-owned key storage, but four protocol
states still used displayable, heap-owning `String` values and the child copied
the just-read key into another owned `String`. That enlarged the number and
kind of Avorax-owned key representations and left formatting/capacity behavior
that the fixed 36-byte protocol does not need.

**Control:** Every key owner now uses the same
`AuthenticodeLaunchKey = Zeroizing<[u8; 37]>`. The first 36 bytes contain the
canonical lowercase random RFC-4122-v4 UUID; the last byte is a zero overflow
guard. The parent encodes directly into the buffer and writes exactly 36 bytes.
The child reads at most 37, requires exactly 36 bytes and an unchanged guard,
validates guard, ASCII shape, UTF-8, UUID variant, and version, and moves the
same buffer through pending/completed state without `to_owned()`. HMAC routines
borrow only the validated prefix. Key-bearing structs do not derive `Debug`.

**Adversarial model:** benign pure regressions cover generated length/form,
nonzero key material, guard mutation, explicit all-zero scrub, and post-scrub
canonical rejection. Existing malformed UUID, wrong key, handshake HMAC, and
response HMAC tests remain mandatory. The verifier adds a distinct fixed-buffer
target and the independent validator requires exactly 263 steps plus the new
verified and technically limited scope. Eight scripted report mutations remove
or corrupt those claims and must be rejected after definitive evidence exists.

**Residual risk:** This reduces owned copies and displayable `String` exposure;
it is not secure erasure. UUID/HMAC internals, compiler temporaries, stack or
register spills, allocator/OS/pipe copies, process dumps, paging, forensic
remnants, and live same-user or privileged memory reads remain outside this
user-mode control. It is not encryption, cross-identity authentication,
AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution
enforcement.

**Evidence state:** implementation, benign tests, source contract 663, verifier,
validator, adversarial script, and documentation were completed before
execution. No checkpoint-2233 passing result is claimed during scripting. No
candidate content, live malware, Defender change, machine-wide install, service,
driver, release, publication, dependency, or lockfile change is involved.

**Broad local evidence:** parsers, format, source `663/663`, fixed-buffer `1/1`,
zeroization `1/1`, key confirmation `2/2`, pipe delivery `1/1`, complete
Authenticode `81/81` with 19 intentional ignores, Native `517/517` plus compiler
`6/6`, Local `536/536`, Guard `248/248 + 249/249`, both locked workspaces,
strict lint, offline Native, release builds, corrected absolute-path PS7/PS5.1
smoke, Flutter analyze, and Flutter `838/838` pass. All lockfiles remain exact.
The `Zeroizing<[u8; 37]>` overflow guard and absent owned child `String` copy are
locally evidenced; definitive 263-step, hosted, integration, synchronization,
and destination proof remain pending. This does not expand pre-execution claims.

**Definitive local evidence:** the verifier passes exact `263/263` from
`2026-08-25T15:09:40.0697976Z` to `2026-08-25T15:17:21.5029589Z` in `461.4s`;
the fixed-buffer step takes `0.2s`. Embedded/independent PS5.1 validation and
`8/8` adversarial rejections pass. Locks and protected-vault invariants remain
exact. An optional PS7 validator host auto-converts ISO strings to `DateTime`
and fails visibly before evidence evaluation; it is not credited. PS7/PS5.1
release smokes both pass, and this tooling limit changes neither the
`Zeroizing<[u8; 37]>` overflow-guard/removed `String` control nor its
secure-erasure, cross-identity, signed-driver, and pre-execution limits.

**Exact implementation-head hosted evidence:** exact `00e9f3c` passes all
required jobs in CI `32865480443` and package push/PR runs
`32865302082`/`32865480497`. Publication is skipped. Consolidated artifacts
`9570689038`/`9570466353` match GitHub SHA-256 and, without extraction or
execution, pass exact eight-root-entry, six-release-file, seven-checksum, and
CycloneDX 1.6/569-component validation. This verifies hosted build/package
compatibility at the implementation head; it does not strengthen the stated
memory, cross-identity, signed-driver, installed-host, or pre-execution model.
Evidence-head, merge, synchronization, and destination proof remain pending.

**Integration evidence:** evidence `646000b`, normal PR `#85` merge `7467bfd`,
evidence-head and merged-main CI/packages, skipped publication, and exact
non-extracting package digest/inventory/SBOM review pass. Guarded 12-path
destination synchronization is followed by complete Rust/Flutter/lint/build/
smoke evidence, corrected exact `263/263` verification in `454.1s`, both strict
validators, and `8/8` destination adversarial rejections. One WindowsApps
Python-alias invocation stopped safely and is not credited. Locks, stage,
processes, and protected-vault invariants remain exact. This closes checkpoint
2233 integration without changing any live-memory, cross-identity, installed-
service, signed-driver, secure-erasure, or pre-execution boundary above.

## Checkpoint 2234 - Verification JSON Host Consistency

PowerShell 7 can convert ISO-looking JSON strings into `DateTime` objects before
the strict validator sees them. Accepting those objects would weaken the JSON
type contract, while rejecting the host leaves one verification path unusable.
The shared gate parser now requests native `DateKind=String` when available and
uses the unchanged Windows PowerShell 5.1 parser shape otherwise. The validator
then performs its existing explicit invariant-culture ISO-8601 parse.

All nine bounded top-level and generated-report readers use this boundary. The
definitive verifier requires the exact 263-step report to pass the same strict
validator under distinct checked Windows PowerShell 5.1 and PowerShell 7
executables. Malformed JSON, type confusion, unsafe paths, inconsistent status,
scope drift, and wrong step counts still fail visibly. Scripted evidence is not
execution evidence; checkpoint-2234 focused, full, adversarial, hosted,
integration, destination, and protected-vault checks remain pending.

Local execution confirms that preserving strings does not weaken rejection:
both hosts accept the same exact 263-step report; numeric/object timestamp,
malformed JSON, false status/options, stale cardinality, removed host scope, and
failed-step mutations reject, including `16/16` full-suite host/mutation pairs.
The definitive run passes `263/263` in `469.9s`. A combined root-workspace test
binary is separately blocked by Defender with OS error 225 and is not counted;
the standalone Native `517/517 + 6/6` route passes and Defender remains enabled.
Exact implementation `708e939` passes hosted CI `32878421258` and package
push/PR runs `32878368995`/`32878421335`. Both publication jobs are skipped;
both consolidated ZIPs match GitHub digests and pass bounded non-extracting
8-entry/6-release/7-checksum/CycloneDX 1.6/569-component validation. This
supports the verifier-host repair and package reproducibility only. Integration,
destination, and external platform limits are unchanged.

Evidence head `a5cf1c5`, normal merge `c969351`, merged-main CI/packages,
skipped publication, and bounded package review pass. Guarded 11-path
destination synchronization and exact `263/263` destination verification in
`468.9s` pass under both strict hosts; `16/16` adversarial reports reject. This
closes the JSON-host evidence inconsistency without changing the threat model:
PowerShell hosts remain trusted verifier prerequisites, and no detection,
installed service, signing, driver, kernel, or pre-execution boundary expands.

## Checkpoint 2235 Risk-Fusion Boundary

**Threat:** malformed or unexpectedly numerous engine evidence can overflow a
score accumulator, panic a debug scanner, wrap a release score, split a UTF-8
character during display truncation, use negative diagnostics to satisfy Local
quality/source gates, hide decisive evidence after the report cap, or omit the
TrustStore engine that actually changed policy.

**Scripted control:** Native accumulation uses saturating `i64` arithmetic and
clamps at 0..100. Local accumulation saturates at 100 and quality/source counts
ignore non-positive reasons. Native output stably retains highest absolute
decision weight, bounds each text field and explanation at valid UTF-8 byte
boundaries, discloses omitted item count, and collects engine provenance after
synthetic trust evidence. All complete evidence remains available to verdict
and category decisions before report shaping.

**Residual risk:** weighted evidence and ordering remain policy choices, not a
calibrated probability. An attacker may still craft files near thresholds, and
bounded reports omit lower-magnitude context. Analysts, signed definition/rule
updates, broader benign/malicious corpora, production false-positive metrics,
and installed workflow tests remain required. No driver, kernel, signing,
cross-identity, or pre-execution boundary changes.

**Evidence state:** all checkpoint-2235 implementation, pure regressions,
verifier/validator changes, source contract 665, and documentation are scripted
before execution. No passing result is claimed yet.

Focused extreme-weight, multibyte, decisive-evidence, provenance, and negative-
diagnostic tests now pass, as do broad engine/workspace/Flutter regressions,
source `665/665`, changed-crate strict Clippy, parser, lock, and vault checks.
This supplies local runtime evidence for the scripted control without changing
the residual calibration, installed-service, driver, or pre-execution risks.
Definitive and integration evidence remains pending.

Definitive local evidence now passes exact `264/264` in `503.5s`, dual-host
strict validation, and `16/16` adversarial report rejections. This verifies the
bounded-fusion regression and evidence contract locally; it does not change the
residual calibration, installed-service, signed-driver, or pre-execution model.
Hosted and destination evidence remains pending.

Exact implementation `8fa9630` passes hosted CI `32892108074` and package
push/PR runs `32891914251`/`32892108020`. Both publication jobs are skipped;
both consolidated ZIPs match GitHub digests and pass bounded non-extracting
8-entry/6-release/7-checksum/CycloneDX 1.6/569-component validation. This
supports the bounded-fusion implementation and package reproducibility only.
Calibration, installed-service, destination, signed-driver, and pre-execution
limits are unchanged.
