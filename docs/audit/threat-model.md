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
local verifier/validator passes `230/230` in `504.6s`; hosted exact-head, merge,
and synchronized-tree evidence remains pending.
