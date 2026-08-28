# Avorax Engine and Control Matrix

Date: 2026-06-25

This matrix accounts for Avorax custom engines, compatibility engines,
protection surfaces, update controls, and supporting trust controls. It is
source-derived from `core/`, `assets/zentor_native/`, `apps/zentor_client/lib`,
and the operational docs. It separates source-accounted evidence from runtime
verification. Current Windows-host Rust/Flutter/Dart toolchains have runtime
evidence where exact checkpoint commands are named; driver, installer, and
installed-service E2E status remains partial unless another report names an
exact passing command.

Checkpoint 1649 reconciles the blocker register with checkpoints 1647 and 1648:
the local-core root/config/migration/service-status/ACL/ClamAV/YARA/AI/native
asset fixtures, Guard self-test/post-launch/hash-read/ClamAV fixtures, native
trust/AuthentiCode fixtures, and signature-compiler source/output fixtures now
have focused runtime evidence where the blocker register names those counts.
Filters that matched `0 tests`, Guard quarantine ACL, non-Windows service-mode,
installed UI/service E2E, live Authenticode, and signed-driver proof remain
partial or blocked.

Checkpoint 1650 adds focused runtime evidence for the remaining trust-root policy
gap around Guard fail-open and local-core passthrough roots: Guard `driver_ipc`
passed (`49`), local-core `app_control` passed (`47`), local-core `trust_store`
passed (`10`), and Guard `driver_health` passed (`16`). Installed signed-driver,
driver-health, and service E2E remain partial.

Checkpoint 1651 adds Flutter controller runtime evidence for allowlist refresh
busy-state and duplicate-refresh queueing: `offline_scan_test.dart` passed
(`97`) including the focused allowlist refresh busy-state test. Installed UI
click/layout E2E remains partial.

Checkpoint 1652 adds matching Flutter controller runtime evidence for quarantine
refresh busy-state and duplicate-refresh queueing: `offline_scan_test.dart`
passed (`98`) including the focused quarantine refresh busy-state test.
Installed UI click/layout E2E remains partial.

Checkpoint 1653 adds Flutter controller runtime evidence for protection self-test
single-flight behavior: `offline_scan_test.dart` passed (`99`) including the
focused duplicate self-test suppression test. Installed UI click/layout and
signed-driver self-test E2E remain partial.

Checkpoint 2114 adds Flutter controller/runtime evidence for app-lifetime finite
watch-poll scanning. `LocalCoreClient.watchPollScan` now parses bounded
`watch_poll_scan` IPC results, `ZentorController` starts a one-minute app timer
only when best-effort watcher roots are active, each tick runs a bounded
4-second/200 ms/8-event local-core poll, and failures/threats/clean outcomes are
reported through state and local events. The Protection UI shows the finite
scan-loop status while keeping post-write/no-service/no-kernel-blocking
limitations visible. Focused Flutter watch-poll IPC/controller tests, analyzer,
source-contracts, and the full small-threat MVP verifier passed (`191` steps in
`498.2s`). Installed service/background monitoring, OS filesystem notification,
and signed-driver/pre-execution E2E remain partial or blocked.

Checkpoint 2115 adds no-EICAR release local-core validation evidence for hosts
where Microsoft Defender intercepts the standard EICAR string before Avorax can
scan it. `tools/testing/run-no-eicar-local-core-harmless-threat-smoke.ps1` wraps
the existing release safe exact-hash smoke, writes a JSON report, and records
that it used no live malware, no standard EICAR file/string, no Defender
exclusion, no network access, and no machine-wide changes. Focused validation
passed against `target/release/zentor_local_core.exe` in `1.4s`, and the full
small-threat MVP verifier/report-validator passed (`192` steps in `500.6s`) for
`.workflow/ultracode/avorax-hardening/results/2115-small-threat-mvp-full-report.json`,
including the new no-EICAR step (`1.7s`). This proves detect-only reporting,
confirmed-only quarantine, `.avoraxq` payload evidence, quarantine listing, and
restore for harmless fixture bytes. Installed UI,
installed service, packaged Windows build, and driver/pre-execution proof remain
partial or blocked.

Checkpoint 2116 promotes the no-EICAR harmless-threat JSON into the main
small-threat MVP generated-report matrix as
`generated_reports.no_eicar_harmless_threat`. The full-suite report validator now
parses that generated report and requires the expected schema, repository,
underlying release safe-hash smoke path, verified flow, limitations, and safety
flags. The full verifier/report-validator passed (`192` steps in `499.0s`) for
`.workflow/ultracode/avorax-hardening/results/2116-small-threat-mvp-full-report.json`;
a negative copied report with `fixture_policy.defender_exclusion_required=true`
failed with `no-EICAR harmless-threat generated report
fixture_policy.defender_exclusion_required must be JSON boolean False.` This
hardens evidence honesty only; installed UI/service/package/driver proof remains
partial or blocked.

Checkpoint 2117 adds safe diagnostic support-bundle export evidence for the
Flutter client. `LocalEventRepository.exportSupportBundle` writes
`avorax-support-bundle.json` through the same bounded atomic export path as event
logs, and records privacy flags for no file contents, no quarantine payloads, no
credentials, no live malware, possible local paths/errors in event details, and
manual review before sharing. `ZentorController.exportSupportBundle` requires
explicit confirmation, rejects overlapping exports, exposes a busy state, logs
confirmation-required/busy/success/failure events, and surfaces failures instead
of swallowing them. Logs and Settings expose confirmed buttons with disabled busy
states. Focused Flutter tests passed (`120`), analyzer passed, source-contracts
passed (`559`), product-copy/no-malware gates passed, report validation passed,
and the Flutter/no-Rust
small-threat MVP verifier passed (`62` steps in `243.2s`) for
`.workflow/ultracode/avorax-hardening/results/2117-small-threat-mvp-flutter-support-bundle-report.json`.
This is local diagnostic-export and widget/controller proof only; installed
packaged click-through, production support intake, service behavior, and
driver/pre-execution proof remain partial or blocked.

Checkpoint 2118 promotes support-bundle export coverage into a first-class
small-threat MVP verifier and report-validator requirement. The verifier now
runs `Flutter support-bundle export tests` against Logs, Settings, and local
event repository/controller coverage with `--plain-name support bundle`; the
report validator rejects passed reports that did not skip Flutter if that step
or the `support-bundle export confirmation/busy/privacy guards` scope text is
missing. Source-contracts passed (`559`), focused support-bundle tests passed
(`8`), the old 2117 report failed validation as expected for the missing step,
and the Flutter/no-Rust small-threat MVP verifier passed (`63` steps in
`336.9s`) for
`.workflow/ultracode/avorax-hardening/results/2118-small-threat-mvp-flutter-support-bundle-required-report.json`.
This hardens diagnostic-export evidence only; installed packaged UI,
production support intake, service behavior, and driver/pre-execution proof
remain partial or blocked.

Checkpoint 2119 hardens support-bundle privacy by redacting credential-like
diagnostics and event details before writing the JSON bundle. The repository now
recursively sanitizes support-bundle diagnostics/events, redacts sensitive keys
and common token shapes, and records `credential_redaction_applied=true` plus
`redacted_value_marker=[redacted]` in privacy metadata while leaving normal
local event history and normal log export unchanged for local audit. Focused
support-bundle tests passed (`9`), local-event tests passed (`43`), analyzer
passed, source-contracts passed (`560`), and the Flutter/no-Rust small-threat
MVP verifier passed (`63` steps in `299.2s`) for
`.workflow/ultracode/avorax-hardening/results/2119-small-threat-mvp-support-bundle-redaction-report.json`.
This is bounded pattern/key redaction for diagnostic exports only; it does not
prove installed packaged UI, production support intake, service behavior, or a
complete guarantee that every possible secret format is removed.

Checkpoint 2120 extends the credential-redaction boundary from support bundles
to normal shareable event-log export. `LocalEventRepository.export` now writes
sanitized event JSON through `_redactShareableExportValue`, and
`exportSupportBundle` uses the same helper family for diagnostics/events, while
raw in-app local event history remains unchanged for local audit. The verifier
now requires `Flutter shareable export credential-redaction tests`, and the
report validator rejects passed non-skip-Flutter reports missing that step or
the `shareable log/support-bundle credential-redaction guards` scope text.
Focused tests passed (`2` redaction tests, `44` local-event tests), analyzer
passed, source-contracts passed (`560`), the old 2119 report failed validation
as expected, and the Flutter/no-Rust small-threat MVP verifier passed (`64`
steps in `300.3s`) for
`.workflow/ultracode/avorax-hardening/results/2120-small-threat-mvp-shareable-log-redaction-report.json`.
This is bounded pattern/key redaction for shareable JSON exports only; exported
paths/errors can still require user review, and installed packaged click-through
and production support-intake E2E remain partial.

Checkpoint 2121 broadens shareable export credential redaction for common web
and diagnostic secret forms. The repository now redacts Basic/Digest/Negotiate/
NTLM authorization values, Cookie/Set-Cookie headers, session/access/refresh
token assignments, cookie/session map keys, and URL userinfo before writing
normal log exports or support bundles. Runtime tests prove those values are
absent from exported JSON while raw local history remains unchanged for audit.
The verifier scope now requires `Basic-auth/cookie/session/URL-userinfo
shareable export redaction guards`, and the report validator rejects older 2120
reports missing that scope. Focused tests passed (`2` redaction tests, `44`
local-event tests), analyzer passed, source-contracts passed (`560`), the old
2120 report failed validation as expected, and the Flutter/no-Rust small-threat
MVP verifier passed (`64` steps in `376.6s`) for
`.workflow/ultracode/avorax-hardening/results/2121-small-threat-mvp-expanded-export-redaction-report.json`.
This remains bounded pattern/key redaction for shareable JSON exports only; it
does not prove installed packaged UI, production support intake, or complete
coverage of every proprietary secret format.

Checkpoint 1980 extends the protection self-test single-flight guard to public
Flutter busy-state drift. Direct `runProtectionSelfTest` calls now reject when
`state.protectionSelfTestInFlight` or `state.protectionOperationInFlight` are
already busy, emit `protection_self_test_busy`, and make no Local Core self-test
IPC. Focused Flutter tests, source-contracts, analyzer, the negative
report-validator scope fixture, and the full small-threat MVP verifier passed
(`99` steps in `205.9s`). This remains Flutter controller/runtime proof, not
installed Guard/local-core service E2E or signed-driver self-test proof.

Checkpoint 1654 adds Flutter widget/runtime evidence for protection self-test
busy-state UI: `settings_accessibility_test.dart` passed (`3`) including the
focused Protection/Settings self-test button relabel/disable test. Installed
desktop click/layout E2E remains partial.

Checkpoint 1655 adds Flutter widget/runtime evidence for protection-operation
busy UI disabling: `settings_accessibility_test.dart` passed (`4`) including
Home start, Protection start/stop, and Protection/Settings self-test disabled
states while `protectionOperationInFlight=true`. Home stop and installed desktop
click/layout E2E remain partial.

Checkpoint 1656 adds Flutter controller runtime evidence for protection
start/stop single-flight behavior: `offline_scan_test.dart` passed (`100`)
including the focused overlapping start/stop suppression test. Installed
service/driver E2E remains partial.

Checkpoint 1981 extends protection start/stop single-flight coverage to public
Flutter busy-state drift and self-test overlap. Direct `startProtection` and
`stopProtection` calls now reject when public operation or self-test busy state
is already active, emit `protection_action_busy`, and make no Guard
mode/watch/stop-watch Local Core IPC. Focused Flutter tests, source-contracts,
analyzer, the negative report-validator scope fixture, and the full
small-threat MVP verifier passed (`99` steps in `207.6s`). This remains Flutter
controller/runtime proof, not installed Guard/local-core service E2E or
signed-driver/pre-execution proof.

Checkpoint 1982 aligns Home and Protection start/stop UI with the controller
guard by disabling those controls when public `protectionSelfTestInFlight` is
true, even if `loading` is not set. Focused widget tests, the full
`settings_accessibility_test.dart` suite, source-contracts, analyzer, the
negative report-validator scope fixture, and the full small-threat MVP verifier
passed (`99` steps in `202.8s`). This remains Flutter widget/runtime proof, not
installed desktop click-through or service/driver proof.

Checkpoint 1983 blocks security settings changes during protection-operation or
self-test busy states. The shared `_beginSecuritySettingsAction` rejects
protection mode, ransomware guard, and scheduled quick-scan settings changes
before Guard/ransomware IPC or schedule persistence, while Settings disables the
matching controls during protection-operation/self-test busy state. Focused
controller/widget tests, source-contracts, analyzer, the negative
report-validator scope fixture, and the full small-threat MVP verifier passed
(`99` steps in `201.4s`). This remains Flutter controller/widget proof, not
installed service/driver E2E proof.

Checkpoint 1984 blocks configuration reset during protection-operation or
self-test busy states. `resetConfiguration` now rejects before reset-in-flight,
protection stop, or config persistence when public/private protection busy flags
are active, while duplicate reset still has precedence and Settings disables the
reset button during protection-operation/self-test busy state. Focused
controller/widget tests, source-contracts, analyzer, the negative
report-validator scope fixture, and the full small-threat MVP verifier passed
(`99` steps in `218.3s`). This remains Flutter controller/widget proof, not
installed desktop/service/driver proof.

Checkpoint 1985 blocks scan starts during security-settings writes or
configuration reset. Quick/full/custom scans and quarantine original rescan now
reject before target planning, auto-action confirmation, OS picker launch,
rescan-request logging, scan-start state, or Local Core scan IPC, and
`_scanPaths` retains the same fallback guard. Home, Scan, and Protection scan
controls disable during those config-busy states. Focused controller/widget
tests, source-contracts, analyzer, the negative report-validator scope fixture,
and the full small-threat MVP verifier passed (`99` steps in `251s`). This
remains Flutter controller/widget proof, not installed OS picker,
local-core/service, or driver proof.

Checkpoint 1986 blocks manual trust and quarantine mutations across
configuration-sensitive work. Quarantine, restore, delete, allowlist add/remove,
and detection-feedback controller paths reject security-settings writes and
configuration reset before Local Core IPC, while Settings reset/security controls
reject or disable during security-settings, reset, quarantine, allowlist, and
feedback busy states. Scan-result, Quarantine, and Allowlist mutation controls
also disable during settings/reset busy states. Focused controller/widget tests,
source-contracts, analyzer, the negative report-validator scope fixture, and the
full small-threat MVP verifier passed locally. This remains Flutter
controller/widget proof, not installed local-core/service, OS picker, or driver
proof.

Checkpoint 1987 closes the matching direct-controller gap for Scan
`Keep / Ignore`. `ignoreThreat` now rejects security-settings writes and
configuration reset before setting `threatIgnoreActionInFlight`, logging
`threat_ignored`, or mutating the current scan row to ignored. Focused
controller/source tests, source-contracts, analyzer, the negative
report-validator scope fixture, and the full small-threat MVP verifier passed
(`101` steps in `225.3s`). This remains Flutter controller proof, not installed
desktop click-through or local-core/service proof.

Checkpoint 1988 blocks configuration-sensitive Settings mutations during scan
work. `_beginSecuritySettingsAction` and `resetConfiguration` now reject scan
start, running scan, custom target selection, and scan-cancel busy states before
Guard/ransomware IPC, schedule persistence, reset in-flight state, protection
stop, or config reset persistence. Settings disables the protection mode,
ransomware guard, scheduled quick-scan, and reset controls during the same scan
busy states. Focused controller/UI/source tests, source-contracts, analyzer, the
negative report-validator scope fixture, and the full small-threat MVP verifier
passed (`102` steps in `284.6s`). This remains Flutter controller/widget/runtime
proof, not installed desktop click-through, OS picker, local-core/service, or
driver proof.

Checkpoint 1989 blocks in-app update install/rollback during active security
work. `installUpdateInApp` and `rollbackUpdateInApp` now reject active
protection, scan, configuration reset/security settings, quarantine, allowlist,
and detection-feedback work before package download/verify/install or
update-service rollback. Home, Settings, and Updates disable update mutation
buttons during the same active-work states while leaving update checks available.
Focused controller/UI/source tests, source-contracts, analyzer, and the full
small-threat MVP verifier passed (`102` steps in `248.2s`). This remains Flutter
controller/widget/runtime coverage plus existing update-service fixture coverage;
installed updater-service E2E and release-host update/rollback E2E remain
partial.

Checkpoint 1990 blocks protection start/stop and protection self-test while
update package work is mutating local update state. `startProtection`,
`stopProtection`, and `runProtectionSelfTest` now reject update
download/verify/install/rollback statuses before Guard mode, watcher,
stop-watch, or self-test IPC. Home, Protection, and Settings disable the same
protection controls during that update package work, while ordinary update
checks remain outside this mutation guard. Focused controller/UI tests,
analyzer, source-contracts, the negative missing-scope report-validator fixture,
and the full small-threat MVP verifier passed (`102` steps in `250.7s`). This
remains Flutter controller/widget/runtime coverage; installed desktop
click-through E2E, installed updater-service apply/rollback E2E, installed
Guard/local-core service behavior, signed-driver/pre-execution blocking, and
release-host update/rollback E2E remain partial, blocked, or technically
limited.

Checkpoint 1991 blocks scan starts while update package work is mutating local
update state. Quick, Full, Custom File, Custom Folder, Quarantine original
rescan, and scheduled quick scan now reject or skip update download/verify/
install/rollback states before scan auto-action confirmation, OS picker handoff,
scan-start state, quarantine-rescan audit events, or Local Core scan IPC. Home,
Protection, Scan, and Quarantine disable matching scan controls during update
package work while ordinary update checks remain outside this mutation guard.
Focused controller/UI tests, analyzer, source-contracts, the negative
missing-scope report-validator fixture, and the full small-threat MVP verifier
passed (`103` steps in `428.5s`). This remains Flutter controller/widget/runtime
coverage; installed desktop click-through E2E, installed updater-service
apply/rollback E2E, installed local-core/service behavior, signed-driver/
pre-execution blocking, and release-host update/rollback E2E remain partial,
blocked, or technically limited.

Checkpoint 1992 blocks Settings security mutations and configuration reset while
update package work is mutating local update state. Protection mode changes,
ransomware guard settings, scheduled quick-scan settings, and configuration
reset now reject update download/verify/install/rollback states before Guard or
ransomware IPC, schedule persistence, reset in-flight state, protection stop, or
config reset persistence. Settings disables the same security-settings and reset
controls during update package work while ordinary update checks remain outside
this mutation guard. Focused controller/UI tests, analyzer, source-contracts,
the negative missing-scope report-validator fixture, and the full small-threat
MVP verifier passed (`104` steps in `355.1s`). This remains Flutter
controller/widget/runtime coverage; installed desktop click-through E2E,
installed updater-service apply/rollback E2E, installed Guard/local-core service
behavior, signed-driver/pre-execution blocking, and release-host update/rollback
E2E remain partial, blocked, or technically limited.

Checkpoint 1993 blocks manual trust/disposition mutations while update package
work is mutating local update state. Scan-result quarantine, Keep/Ignore,
false-positive feedback, malicious feedback, Add to allowlist, Quarantine
restore/delete, and Allowlist remove now reject update download/verify/install/
rollback states before local-core IPC or scan-row mutation. Scan, Quarantine,
and Allowlist UI mutation controls disable during update package work; read-only
refreshes remain available. Focused controller/UI tests, analyzer,
source-contracts, the negative missing-scope report-validator fixture, and the
full small-threat MVP verifier passed (`108` steps in `252.3s`). This remains
Flutter controller/widget/runtime coverage; installed desktop click-through E2E,
installed updater-service apply/rollback E2E, installed local-core/service
behavior, signed-driver/pre-execution blocking, and release-host update/rollback
E2E remain partial, blocked, or technically limited.

Checkpoint 1994 blocks Protected Apps scan-scope/config mutations while update
package work is mutating local update state. Add file/app, Add folder, detected
app row selection, and Calculate build hash now reject update download/verify/
install/rollback states before OS picker handoff, hash reads, config
persistence, or scan-scope mutation. Protected Apps UI disables the same
mutation controls during update package work; read-only app detection rescan
remains separate. Focused controller/UI tests, analyzer, source-contracts, the
negative missing-scope report-validator fixture, and the full small-threat MVP
verifier passed (`110` steps in `288.4s`). This remains Flutter
controller/widget/runtime coverage; installed OS picker/hash filesystem E2E,
installed updater-service apply/rollback E2E, installed local-core/service
behavior, signed-driver/pre-execution blocking, and release-host update/rollback
E2E remain partial, blocked, or technically limited.

Checkpoint 1995 expands update install/rollback active-work guards to cover the
remaining mutating controller states. In-app install and rollback now reject
service recovery, developer-cloud override, and Protected Apps actions before
package download/verify/install or update-service rollback. Home, Settings, and
Updates use the same shared active-work helper, so update mutation buttons are
disabled during those states while read-only update checks remain available.
Focused controller/UI tests, analyzer, source-contracts, the negative
missing-scope report-validator fixture, and the full small-threat MVP verifier
passed (`112` steps in `283.0s`). This remains Flutter controller/widget/runtime
coverage; installed updater-service apply/rollback E2E, installed service repair
E2E, installed Protected Apps OS picker/hash E2E, signed-driver/pre-execution
blocking, and release-host update/rollback E2E remain partial, blocked, or
technically limited.

Checkpoint 1996 adds the reciprocal service recovery update-mutation guard.
Start Core Service, Open install report, and Repair installation now reject
update package download/verify/install/rollback states before Local Core IPC.
The Scan engine-unavailable recovery controls use the shared update-mutation
helper, so they are disabled while package work is active and continue to allow
ordinary update checks. Focused controller/UI tests, analyzer, source-contracts,
the negative missing-scope report-validator fixture, and the full small-threat
MVP verifier passed (`113` steps in `288.6s`). This remains Flutter
controller/widget/runtime coverage; installed updater-service apply/rollback
E2E, installed service repair E2E, installed Explorer/report E2E, signed-driver/
pre-execution blocking, and release-host update/rollback E2E remain partial,
blocked, or technically limited.

Checkpoint 1997 adds the developer override update-mutation guard. Save
developer override and Disable developer override now reject update package
download/verify/install/rollback states before config persistence or cloud
health checks. Settings developer override fields, switch, and mutation button
use the existing update-mutation busy state, so they are disabled during package
work while ordinary update checks remain available. Focused controller/UI tests,
analyzer, source-contracts, the negative missing-scope report-validator fixture,
and the full small-threat MVP verifier passed (`114` steps in `291.0s`). This
remains Flutter controller/widget/runtime coverage; installed updater-service
apply/rollback E2E, live backend developer override E2E, signed-driver/pre-
execution blocking, and release-host update/rollback E2E remain partial,
blocked, or technically limited.

Checkpoint 1998 records local build evidence without installing machine-wide
components or weakening Windows settings. `cargo build --workspace --release`
passed and produced `target\release\zentor_local_core.exe`,
`target\release\zentor_guard_service.exe`, and
`target\release\avorax_update_service.exe`. `flutter build windows --debug`
did not produce `Avorax.exe`; Flutter reported that plugin builds require
Windows symlink support. `flutter doctor -v` showed Visual Studio missing the
Desktop C++/CMake components required for Windows desktop builds. The non-
mutating release prerequisite check wrote
`.workflow\ultracode\avorax-hardening\results\1998-release-prereq-check.json`
with `ok=false`, Rust service binaries passing, and blockers for missing .NET
SDK inventory, missing Flutter release `Avorax.exe`, missing installer stage,
unavailable symlink support, and missing Visual Studio Desktop C++ components.
This verifies Rust release binaries only; Flutter Windows app build, installer
stage/MSI/EXE build, installed service repair E2E, and installed UI E2E remain
blocked by host prerequisites until Developer Mode/symlink support, Visual
Studio Desktop C++ components, and a usable .NET SDK are available on an
approved build host.

Checkpoint 1999 proves the release local-core binary can execute the core safe
hash scan/quarantine/restore flow without `cargo run`, live malware,
machine-wide installation, or Windows security setting changes. The new
`tools\testing\run-release-local-core-smoke.ps1` creates a temporary
process-local engine directory, writes a safe exact-hash test pack for the
benign `harmless-known-bad-fixture`, sets `AVORAX_ENGINE_DIR` only for the
child process, drives `target\release\zentor_local_core.exe` through stdin JSON,
and verifies detect-only detection, confirmed auto-quarantine to an opaque
`.avoraxq` payload, quarantine metadata listing, and confirmed restore of the
original bytes. The small-threat MVP verifier now performs a reproducible
`cargo build --release --manifest-path core\zentor_local_core\Cargo.toml`
before the release-binary smoke, and the full-suite report validator requires
the new step and verified scope. Source-contracts passed (`515`), the full
self-validating verifier passed (`116` steps in `703.5s`), and a negative
in-repo report fixture missing `release local-core binary safe hash fixture
scan/quarantine smoke` failed with the expected scope diagnostic. This is
release local-core binary proof only; packaged desktop click-through E2E,
installed local-core/service behavior, installed update/rollback, installed
realtime watcher behavior, signed-driver/pre-execution blocking, release-host
SBOM/license output, production false-positive-rate evidence, Flutter Windows
app build, and installer stage remain partial, blocked, or technically limited.

Checkpoint 2000 proves the release local-core binary fails safe when local
signature definitions are present but fail integrity verification. The new
`tools\testing\run-release-local-core-definition-failsafe-smoke.ps1` creates a
temporary process-local engine directory selected through `AVORAX_ENGINE_DIR`,
writes a syntactically valid `avorax_core.asig` for the benign
`harmless-known-bad-fixture` with an intentionally wrong `pack_sha256`, and
scans through `target\release\zentor_local_core.exe` in
`autoQuarantineConfirmedOnly` mode. The expected and verified behavior is
`engineUnavailable`, `signature pack hash mismatch`, zero files scanned, zero
threats, at least one skipped file, source fixture left in place, and no
`.avoraxq` payload. The full-suite verifier and report validator now require
`release local-core binary invalid signature-pack fail-safe smoke`.
Source-contracts passed (`516`), the full self-validating verifier passed
(`117` steps in `495.2s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release local-core
local-definition fail-safe proof only; network definition download, signed
update activation, installed updater-service rollback, installed service
behavior, packaged desktop E2E, signed-driver/pre-execution blocking,
release-host SBOM/license output, production false-positive-rate evidence,
Flutter Windows app build, and installer stage remain partial, blocked, or
technically limited.

Checkpoint 2001 proves the release local-core binary also fails safe when local
rule definitions are present but fail integrity verification. The new
`tools\testing\run-release-local-core-rule-failsafe-smoke.ps1` creates a
temporary process-local engine directory selected through `AVORAX_ENGINE_DIR`,
writes a syntactically valid `avorax_core.arule` with a benign
`contains_ascii` condition for `harmless-known-bad-fixture` and an
intentionally wrong `pack_sha256`, and scans through
`target\release\zentor_local_core.exe` in `autoQuarantineConfirmedOnly` mode.
The expected and verified behavior is `engineUnavailable`,
`rule pack hash mismatch`, zero files scanned, zero threats, at least one
skipped file, source fixture left in place, and no `.avoraxq` payload. The
full-suite verifier and report validator now require
`release local-core binary invalid rule-pack fail-safe smoke`.
Source-contracts passed (`517`), the full self-validating verifier passed
(`118` steps in `275.4s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release local-core local-rule
fail-safe proof only; network definition download, signed update activation,
installed updater-service rollback, installed service behavior, packaged
desktop E2E, signed-driver/pre-execution blocking, release-host SBOM/license
output, production false-positive-rate evidence, Flutter Windows app build,
and installer stage remain partial, blocked, or technically limited.

Checkpoint 2002 refreshes Windows release-host readiness after user-local
Flutter/Dart/Rust/Git paths became available. The non-mutating host-only
prerequisite check wrote
`.workflow\ultracode\avorax-hardening\results\2002-release-prereq-hostonly.json`
with `ok=false`, `27` checks, `3` errors, and `0` warnings. The remaining
blockers are concrete host prerequisites: `C:\Program Files\dotnet\dotnet.exe`
exists but has no SDK inventory, Windows symlink support/Developer Mode remains
unavailable for Flutter plugin builds, and Flutter doctor still reports missing
Visual Studio Desktop C++ components. This does not affect the passing
small-threat MVP verifier, but Windows desktop `Avorax.exe`, installer
stage/MSI/EXE, installed UI/service E2E, signed-driver/pre-execution blocking,
and release-host production evidence remain partial, blocked, or technically
limited until those prerequisites are supplied on an approved build host.

Checkpoint 2003 proves the release local-core binary also fails safe when a
local native ML model asset is present but fails strict validation. The new
`tools\testing\run-release-local-core-model-failsafe-smoke.ps1` creates a
temporary process-local engine directory selected through `AVORAX_ENGINE_DIR`,
writes `engine\ml\avorax_native_model.amodel` as syntactically valid model JSON
with an intentionally empty `model_version`, and scans a benign
`harmless-known-bad-fixture` through `target\release\zentor_local_core.exe` in
`autoQuarantineConfirmedOnly` mode. The expected and verified behavior is
`engineUnavailable`, `invalid native model`, `model_version must not be empty`,
zero files scanned, zero threats, at least one skipped file, source fixture
left in place, and no `.avoraxq` payload. The full-suite verifier and report
validator now require
`release local-core binary invalid native-model fail-safe smoke`.
Source-contracts passed (`518`), the full self-validating verifier passed
(`119` steps in `375.9s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release local-core
local-native-model fail-safe proof only; production ML quality, network
definition download, signed update activation, installed updater-service
rollback, installed service behavior, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2004 proves the release local-core binary also fails safe when local
native trust-store assets are present but fail strict hash validation. The new
`tools\testing\run-release-local-core-trust-failsafe-smoke.ps1` runs two
temporary process-local `AVORAX_ENGINE_DIR` scenarios: malformed
`engine\trust\avorax_known_good.atrust` and malformed
`engine\trust\zentor_known_bad_test.ztrust` with a valid empty known-good store.
Both scenarios scan a benign `harmless-known-bad-fixture` through
`target\release\zentor_local_core.exe` in `autoQuarantineConfirmedOnly` mode.
The expected and verified behavior is `engineUnavailable`, the matching
malformed native known-good or known-bad SHA-256 diagnostic, zero files scanned,
zero threats, at least one skipped file, source fixture left in place, and no
`.avoraxq` payload. The full-suite verifier and report validator now require
`release local-core binary invalid native trust-store fail-safe smoke`.
Source-contracts passed (`519`), the full self-validating verifier passed
(`120` steps in `355.3s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release local-core
local-native-trust-store fail-safe proof only; production trust-intel quality,
network definition download, signed update activation, installed updater-service
rollback, installed service behavior, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2005 proves the release local-core binary fails closed when user
allowlist data is present but malformed. The new
`tools\testing\run-release-local-core-allowlist-failsafe-smoke.ps1` writes a
corrupt process-local `ZENTOR_ALLOWLIST_FILE` containing
`corrupt-release-allowlist-entry` with `not-a-sha256`, while the temporary
`AVORAX_ENGINE_DIR` contains a safe exact-hash signature pack for the benign
`harmless-known-bad-fixture`. The expected and verified behavior is
`threatsFound`, one scanned file, one confirmed threat, one quarantined file,
one `.avoraxq` payload, visible `allowlist unavailable` plus malformed
allowlist SHA-256 diagnostics, source fixture removal after quarantine,
successful `list_quarantine`, and confirmed restore with exact byte match. The
full-suite verifier and report validator now require
`release local-core binary corrupt allowlist fail-closed smoke`.
Source-contracts passed (`520`), the full self-validating verifier passed
(`121` steps in `343.5s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release local-core
user-allowlist fail-closed proof only; installed desktop E2E, installed service
behavior, network definition update activation, production trust-intel quality,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2006 proves the release local-core binary rejects quarantine
metadata and payload tampering before restore/delete can mutate user paths or
remove quarantined payloads. The new
`tools\testing\run-release-local-core-quarantine-tamper-smoke.ps1` creates two
temporary process-local scenarios using a safe exact-hash signature pack for the
benign `harmless-known-bad-fixture`. In the metadata-auth scenario, the `.json`
metadata record is modified while `.json.auth` remains unchanged; the expected
and verified behavior is `list_quarantine`, `restore_quarantine_item`, and
`delete_quarantine_item` all fail with `quarantine metadata authentication
failed`, while the `.avoraxq` payload remains in place. In the payload-hash
scenario, the `.avoraxq` bytes are replaced with same-length benign bytes; the
authenticated metadata still lists, but restore and delete both fail with
`quarantine payload hash mismatch`, do not recreate the source path, and do not
remove the tampered payload. The full-suite verifier and report validator now
require `release local-core binary quarantine metadata/payload tamper fail-safe
smoke`. Source-contracts passed (`521`), the full self-validating verifier
passed (`122` steps in `458s`), and a negative in-repo report fixture missing
that scope failed with the expected diagnostic. This is release local-core
quarantine tamper proof only; installed desktop E2E, installed service
behavior, network definition update activation, production trust-intel quality,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2007 proves the release update-service verifier accepts a benign
stable-channel Ed25519-signed `.aup` package and rejects manifest or payload
tampering without package activation, rollback, service control, network
download, or machine-wide install behavior. The new
`tools\testing\run-release-update-service-verify-smoke.ps1` creates temporary
process-local signing key material with `avorax_generate_update_key.exe`, signs
a benign manifest/payload package with `avorax_sign_manifest.exe`, and verifies
it through `target\release\avorax_update_service.exe --verify` using a
temporary trusted public key in `AVORAX_UPDATE_PUBLIC_KEY_HEX`. The expected and
verified behavior is a valid package succeeds and writes an OK
`updates\logs\update_cli_status.json` record, a manifest modified after signing
fails with `manifest signature verification failed`, and a payload modified
after signing fails with
`payload hash mismatch for payload/app/AvoraxSmoke.txt`; both failure cases
also write failed CLI status evidence under a temporary `AVORAX_DATA_DIR`. The
full-suite verifier and report validator now require
`release update-service signed package verify/tamper smoke` and build the
release update-service binaries before running it. Source-contracts passed
(`522`), the full self-validating verifier passed (`124` steps in `352.4s`),
and a negative in-repo report fixture missing that scope failed with the
expected diagnostic. This is release update-service package verification proof
only; network definition download, signed update activation, installed
updater-service apply/rollback E2E, service stop/start behavior, packaged
desktop E2E, signed-driver/pre-execution blocking, release-host SBOM/license
output, production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2008 proves the normal `.aup` package builder can produce a benign
stable-channel signed package and update feed that the built release
update-service verifier accepts. The new
`tools\testing\run-release-update-package-builder-smoke.ps1` drives the real
`tools\update\avorax-build-update-package.ps1` with a temporary benign app
payload, `engine\signatures\avorax_builder_smoke.asig`,
`docs\builder-smoke.md`, process-local key material from
`avorax_generate_update_key.exe`, and `avorax_sign_manifest.exe` through
`AVORAX_UPDATE_SIGNER`. The expected and verified behavior is that
`Avorax-AntiVirus-0.3.0.aup` and `update-feed.json` are produced, the feed
`package_url` references the package file, the feed `package_sha256` matches the
actual package bytes, and `target\release\avorax_update_service.exe --verify`
accepts the package with app, engine-signatures, docs component evidence and
matching payload hashes. The smoke does not call update apply, rollback,
service control, network download, or machine-wide install paths. The
full-suite verifier and report validator now require
`release update-package builder signed verify smoke`. Source-contracts passed
(`523`), the full self-validating verifier passed (`125` steps in `289.3s`),
and a negative in-repo report fixture missing that scope failed with the
expected diagnostic. This is release package-builder/verifier proof only;
network definition download, signed update activation, installed updater-service
apply/rollback E2E, service stop/start behavior, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2009 fixes and proves normal `.aup` package-builder restricted
payload fail-safe behavior. `tools\update\avorax-build-update-package.ps1` now
rejects source `driver` and `driver-tools` directories with visible diagnostics
instead of silently skipping them; driver changes must ship through MSI/EXE or
an explicit signed-driver workflow. The new
`tools\testing\run-release-update-package-builder-failsafe-smoke.ps1` runs the
real builder against seven benign negative fixtures: `tools-root`,
`migrations-root`, `driver-root`, `driver-tools-root`,
`unsupported-engine-child`, `docs-non-markdown`, and `missing-engine`. The
expected and verified behavior is that each scenario exits non-zero with the
matching diagnostic and produces no `.aup` package or `update-feed.json`. The
full-suite verifier and report validator now require
`release update-package builder restricted-payload fail-safe smoke`.
Source-contracts passed (`524`), the full self-validating verifier passed
(`126` steps in `290.1s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is package-builder
restricted-payload fail-safe proof only; network definition download, signed
update activation, installed updater-service apply/rollback E2E, service
stop/start behavior, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2026 hardens normal `.aup` package-builder managed executable
fail-safe behavior. `tools\update\avorax-build-update-package.ps1` now rejects
source `avorax_update_service.exe` before staging, because the updater cannot
overwrite itself through a normal in-app update, and rejects top-level
directories named like managed service/updater executables before they can be
copied under `payload/app`. The release builder fail-safe smoke now runs ten
benign negative fixtures, adding `update-service-root` and
`managed-service-directory`; each exits non-zero with a visible diagnostic and
produces no `.aup` package or `update-feed.json`. The positive signed-builder
smoke still accepts benign app, Core/Guard service, engine signature, and docs
payloads. Source-contracts passed (`535`), the focused fail-safe and
signed-verify smokes passed, and the full small-threat MVP verifier plus report
validator passed (`135` steps in `312.8s`). This is package-builder proof only;
installed service stop/start behavior, installed update apply/rollback E2E,
network definition download, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2027 extends the release `.aup` package-builder fail-safe smoke with
an `empty-docs` benign negative fixture. The fixture creates a valid minimal
engine signature payload plus an empty `docs` directory; the real builder exits
non-zero with `Payload docs source contains no Markdown files for a normal .aup
update.` and produces no `.aup` package or `update-feed.json`. The positive
signed-builder smoke still accepts benign app, Core/Guard service, engine
signature, and Markdown docs payloads. Source-contracts passed (`535`), the
focused fail-safe and signed-verify smokes passed, and the full small-threat
MVP verifier plus report validator passed (`135` steps in `349.6s`). This is
package-builder docs component evidence only; installed service stop/start
behavior, installed update apply/rollback E2E, network definition download,
packaged desktop E2E, signed-driver/pre-execution blocking, release-host
SBOM/license output, production false-positive-rate evidence, Flutter Windows
app build, and installer stage remain partial, blocked, or technically limited.

Checkpoint 2028 adds Rust runtime coverage for the normal `.aup` update applier
docs payload guard. The new
`copy_docs_payload_section_rejects_empty_docs_directory` fixture creates an
empty staged `docs` section, calls the docs payload activation helper, verifies
the visible `docs update payload contains no Markdown files` failure, and
confirms the install docs destination was not created. Focused update-service
verification passed: rustfmt, the single fixture (`1 passed`), `docs_payload`
(`5 passed`), and `update_applier` (`31 passed`). Source-contracts passed
(`535`), and the full small-threat MVP verifier plus report validator passed
(`135` steps in `427.3s`). This is package/applier docs payload evidence only;
installed service stop/start behavior, installed update apply/rollback E2E,
network definition download, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2029 adds Rust runtime coverage for the normal `.aup` update applier
app payload guard. `copy_app_payload_section` now requires a present staged
`app` section to contain at least one regular file before activation, while
still allowing missing `app` sections for engine/service/docs-only updates. The
new `copy_app_payload_section_rejects_empty_app_directory` fixture creates a
directory-only staged `app` section, verifies the visible
`app update payload contains no regular files` failure, and confirms the install
destination was not created. Focused update-service verification passed:
rustfmt, the new app fixture (`1 passed`), the existing restricted-app fixture
(`1 passed`), and `update_applier` (`32 passed`). Source-contracts passed
(`535`), and the full small-threat MVP verifier plus report validator passed
(`135` steps in `405.3s`). This is update-applier app payload evidence only;
installed service stop/start behavior, installed update apply/rollback E2E,
network definition download, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2030 adds explicit Rust runtime fixtures for existing normal `.aup`
update applier guards that reject empty staged `services` and `engine` payload
sections. `copy_service_payload_section_rejects_empty_services_directory`
verifies an empty staged `services` section fails with
`service update payload contains no supported service files` before creating the
install destination. `copy_engine_payload_section_rejects_empty_engine_directory`
verifies an empty staged `engine` section fails with
`engine update payload contains no supported runtime subdirectories` before
creating the install engine destination. Focused update-service verification
passed: rustfmt, both focused fixtures (`1 passed` each), and `update_applier`
(`34 passed`). Source-contracts passed (`535`), and the full small-threat MVP
verifier plus report validator passed (`135` steps in `349.3s`). This is
update-applier service/engine payload evidence only; installed service
stop/start behavior, installed update apply/rollback E2E, network definition
download, packaged desktop E2E, signed-driver/pre-execution blocking,
release-host SBOM/license output, production false-positive-rate evidence,
Flutter Windows app build, and installer stage remain partial, blocked, or
technically limited.

Checkpoint 2031 makes signed normal `.aup` package verification fail visibly
when manifest component flags claim an update without a matching signed payload
hash. `verify_payload_matches_manifest` now calls
`ensure_manifest_components_have_payload_hashes` and requires declared `app`,
`core_service`, `guard_service`, `native_engine_assets`, `signatures`, `rules`,
`ml`, `trust_packs`, and `docs` components to be backed by matching payload hash
entries. New Rust fixtures reject declared app, Core service, native engine
asset, engine subcomponent, and docs components without payload hashes. Focused
update-service verification passed: rustfmt, the `declared_` filter (`8`
tests), and the full update-service crate (`197` tests). Source-contracts
passed (`536`), and the full small-threat MVP verifier plus report validator
passed (`135` steps in `359.7s`). This is signed package verification evidence
only; installed service stop/start behavior, installed update apply/rollback
E2E, network definition download, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2032 hardens the normal signed `.aup` apply path against package
replacement between verification and payload extraction. `UpdatePackage` now
offers `extract_payload_to_verified_hash`, which validates the expected SHA-256,
hashes the opened package file, rejects a mismatch with
`update package changed after verification`, rewinds that same file handle, and
extracts from it. `apply_package_with_service_control` now calls that helper
with `verified.package_sha256` after `UpdateVerifier::verify_package`, so the
top-level apply path no longer uses direct extraction after verification. Focused
update-service verification passed: rustfmt, the changed-package extraction
fixture (`1` test), the apply-ordering fixture (`1` test), warning-free release
build, and the full update-service crate (`199` tests). Source-contracts passed
(`537`), and the full small-threat MVP verifier plus report validator passed
(`135` steps in `391.5s`). This is local signed package apply-path hardening
evidence only; installed service stop/start behavior, installed update
apply/rollback E2E, network definition download, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2033 hardens pre-activation failure handling in the same normal
signed `.aup` apply path. `apply_package_with_service_control` no longer creates
the staging directory before verified-hash extraction. Stale staging cleanup
failures and verified extraction failures now flow through
`report_pre_activation_failure`, producing `update_report.json` with
`applied: false`, `rollback: null`, an explicit `staging_prepare_error` or
`extract_error`, and staging cleanup evidence before any service stop/start is
attempted. The new runtime fixture
`apply_package_reports_pre_activation_staging_prepare_failure_without_stopping_services`
proves a stale non-directory staging path fails visibly, records no service
calls, writes the report, and leaves the install tree unchanged. Focused
update-service verification passed: rustfmt, the pre-activation staging failure
fixture (`1` test), the verified-extract ordering fixture (`1` test), release
build, and the full update-service crate (`200` tests). Source-contracts passed
(`537`), and the full small-threat MVP verifier plus report validator passed
(`135` steps in `343.8s`). This is local signed package apply-path hardening
evidence only; installed service stop/start behavior, installed update
apply/rollback E2E, network definition download, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2034 extends pre-activation failure handling to rollback snapshot
creation. After verified payload staging, `apply_package_with_service_control`
now routes `create_snapshot` failures through `report_pre_activation_failure`
with `snapshot_error`, `applied: false`, `rollback: null`, and staging cleanup
evidence before any service stop/start is attempted. `create_snapshot` now copies
required rollback items through `copy_snapshot_items` and removes the partial
snapshot if a later required item fails. The new runtime fixture
`apply_package_reports_pre_activation_snapshot_failure_and_cleans_staging` proves
a missing install `engine` directory fails visibly, records no service calls,
writes `update_report.json`, cleans staging and the partial rollback snapshot,
and leaves the install tree unchanged. The rollback fixture
`create_snapshot_rejects_missing_required_component` also proves no partial
snapshot remains. Focused update-service verification passed: rustfmt, the
rollback snapshot cleanup fixture (`1` test), the apply snapshot failure fixture
(`1` test), release build, and the full update-service crate (`201` tests).
Source-contracts passed (`537`), and the full small-threat MVP verifier plus
report validator passed (`135` steps in `377.6s`). This is local signed package
apply-path hardening evidence only; installed service stop/start behavior,
installed update apply/rollback E2E, network definition download, packaged
desktop E2E, signed-driver/pre-execution blocking, release-host SBOM/license
output, production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2035 adds release-CLI proof for checkpoint 2034's snapshot failure
path. `tools\testing\run-release-update-service-apply-snapshot-failure-smoke.ps1`
builds a benign signed app-only `.aup`, prepares a temporary install tree with
old app/Core/Guard files but no required rollback `engine` directory, and runs
`target\release\avorax_update_service.exe --apply`. The verified behavior is a
non-zero pre-service-stop failure with the missing-engine snapshot diagnostic,
`update_report.json` containing `snapshot_error`, `applied: false`,
`rollback: null`, and successful staging cleanup, no partial
`updates\rollback\0.5.0` snapshot, no service-control diagnostic, unchanged
install files, and failed `update_cli_status.json` evidence for `command=--apply`.
The full-suite verifier and report validator now require
`release update-service apply snapshot-failure fail-safe smoke`.
Source-contracts passed (`538`), the focused release smoke passed, and the full
small-threat MVP verifier plus report validator passed (`136` steps in
`375.6s`). This is release update-service pre-service-stop failure evidence only;
installed service stop/start behavior, successful installed update apply/rollback
E2E, network definition download, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2036 adds release-CLI proof for the normal signed `.aup` apply
success path without touching real Windows services. The new
`tools\testing\run-release-update-service-apply-success-fake-service-smoke.ps1`
smoke builds a benign signed package with app, Core service, Guard service,
engine signature/rule/ML/trust, and docs payloads, prepares a temporary install
tree with old app/service/engine/docs files, and runs the release
`target\release\avorax_update_service.exe --apply` binary. Service-control is
isolated by copying `C:\Program Files\Git\usr\bin\true.exe` to a temporary fake
`SystemRoot\System32\sc.exe` and adjusting only the child process environment.
The verified behavior is successful release CLI exit, activated
app/service/engine/docs payloads, rollback snapshot evidence for old
app/Core/Guard/engine files, successful staging cleanup, `update_report.json`
with `ok: true` and `applied: true`, successful `update_cli_status.json`
evidence for `command=--apply`, and no service-control diagnostic. The
full-suite verifier and report validator now require
`release update-service apply success fake-service smoke`. Source-contracts
passed (`539`), the focused release smoke passed, and the full small-threat MVP
verifier plus report validator passed (`137` steps in `410.9s`). This is release
fake-service success-path evidence only; real installed service stop/start
behavior, successful installed update apply/rollback E2E, network definition
download, packaged desktop E2E, signed-driver/pre-execution blocking,
release-host SBOM/license output, production false-positive-rate evidence,
Flutter Windows app build, and installer stage remain partial, blocked, or
technically limited.

Checkpoint 2037 refreshes Windows release-host prerequisite evidence after
Flutter, Dart, Cargo, rustfmt, and Git became available on Brent's machine.
`flutter doctor -v` now verifies Flutter `3.44.4`, Dart `3.12.2`, Windows
desktop device discovery, and Visual Studio Community 2022 presence, but reports
missing Visual Studio Desktop C++ build components. Direct
`flutter build windows --debug --no-pub` still fails before build because
Flutter plugin builds require Windows symlink support. The host-only release
prereq check was rerun with explicit dotnet/cargo/flutter paths and wrote
`.workflow\ultracode\avorax-hardening\results\2037-release-prereq-host-refresh.json`
with `ok: false` and exactly three current blockers: no .NET SDK at
`C:\Program Files\dotnet\dotnet.exe`, unavailable Windows symlink support, and
missing Visual Studio Desktop C++ components. This supersedes the old
missing-Flutter/Dart/Rust/Git blocker text for this host, but Windows
`Avorax.exe` build, installer stage/MSI/setup artifacts, packaged desktop
click-through E2E, installed service/UI E2E, installed update/rollback E2E,
signed-driver/pre-execution blocking, full release-host SBOM/license output, and
production false-positive-rate evidence remain partial, blocked, or technically
limited.

Checkpoint 2038 adds dark-theme contrast regression coverage for the shared
Flutter UI palette. `ZentorColors.secondaryAccent` changes from `0xFF6C5CFF` to
`0xFF8E82FF` because the older secondary purple fell below AA contrast on app
surface backgrounds. `app_visual_policy_test.dart` now computes contrast ratios
for text, accent, success, warning, and danger colors against `background`,
`surface`, and `elevatedSurface`, requiring `>= 4.5`. Focused visual policy
tests passed (`59`), Flutter analyze passed, Dart format passed after
formatting, and source-contracts passed (`539`). This improves the shared visual
accessibility guard only; keyboard traversal audits, per-feature screen-reader
coverage, localization-ready text extraction, packaged desktop visual/click E2E,
and installed UI/service E2E remain partial or open.

Checkpoint 2025 extends the release `.aup` package-builder signed-verify smoke
with benign `avorax_core_service.exe` and `avorax_guard_service.exe` payload
fixtures. The real builder stages them under `payload/services`, the release
update-service verifier accepts the signed package, the verified manifest
declares `components.core_service` and `components.guard_service`, service
payload hashes are present for `services/avorax_core_service.exe` and
`services/avorax_guard_service.exe`, and updater/driver-tool flags remain
false. The fixtures are packaged and verified only; they are not executed or
installed. Source-contracts passed (`535`), the focused builder signed-verify
smoke passed, and the full small-threat MVP verifier plus report validator
passed (`135` steps in `312.2s`). This is package-builder service component
evidence only; installed service stop/start behavior, installed update
apply/rollback E2E, network definition download, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2024 extends the same release `.aup` package-builder fail-safe
smoke to eight benign negative fixtures by adding `empty-engine-component`.
The new fixture creates `engine\signatures` without runtime files and verifies
that the real builder exits non-zero with `Normal .aup update package engine
component 'engine\signatures' contains no runtime files`, while producing no
`.aup` package and no `update-feed.json`. This pairs with the existing signed
builder smoke that verifies `native_engine_assets` and `signatures` manifest
flags from an actual staged signature file. Source-contracts passed (`535`),
the focused fail-safe smoke passed, and the full small-threat MVP verifier plus
report validator passed (`135` steps in `454.7s`). This is package-builder
component-evidence/fail-safe proof only; network definition download, signed
update activation, installed updater-service apply/rollback E2E, service
stop/start behavior, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2010 proves the release update-service `--apply` path rejects a
tampered signed package before update activation begins. The new
`tools\testing\run-release-update-service-apply-tamper-smoke.ps1` creates
temporary process-local Ed25519 signing key material, signs a benign
stable-channel package with `avorax_sign_manifest.exe`, modifies
`manifest.json` after signing, and then runs
`target\release\avorax_update_service.exe --apply` against a temporary install
directory and temporary `AVORAX_DATA_DIR`. The expected and verified behavior
is a non-zero `--apply` exit with `manifest signature verification failed`, no
`updates\staging`, no `updates\rollback`, no
`updates\logs\update_report.json`, an empty temporary install directory, and a
failed `updates\logs\update_cli_status.json` record for `command=--apply`. The
full-suite verifier and report validator now require
`release update-service apply tamper fail-before-activation smoke`.
Source-contracts passed (`525`), the full self-validating verifier passed
(`127` steps in `292.3s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release update-service
fail-before-activation proof only; successful signed update activation,
installed updater-service apply/rollback E2E, service stop/start behavior,
network definition download, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2011 proves the release update-service `--apply` path handles a late
service-stop failure safely after signed package verification, staging
extraction, and rollback snapshot creation. The new
`tools\testing\run-release-update-service-apply-stop-failure-smoke.ps1` creates
temporary process-local Ed25519 signing key material, signs a benign
stable-channel package with `avorax_sign_manifest.exe`, prepares a temporary
install directory with rollback-required app, service, and engine files, and
runs `target\release\avorax_update_service.exe --apply` with a
child-process-only fake `SystemRoot`/`WINDIR`. That fake Windows root forces
service-control tool preflight to fail before any real service-control command
can run. The expected and verified behavior is a non-zero `--apply` exit with
`update apply aborted because services did not stop`, package-specific staging
cleanup, rollback snapshot preservation under `updates\rollback\0.5.0`,
unchanged install files with no app payload copied, failed
`updates\logs\update_report.json` evidence including
`restart_after_stop_failure_ok=false` and `staging_cleanup_ok=true`, and failed
`updates\logs\update_cli_status.json` evidence for `command=--apply`. The
full-suite verifier and report validator now require
`release update-service apply stop-failure rollback/staging smoke`.
Source-contracts passed (`526`), the full self-validating verifier passed
(`128` steps in `289.1s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release update-service
late-failure handling proof only; successful signed update activation,
installed updater-service apply/rollback E2E, real service stop/start behavior,
network definition download, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2012 proves the release update-service `--rollback` path restores a
local rollback snapshot into a temporary install directory without service
control, network access, installer behavior, or machine-wide changes. The new
`tools\testing\run-release-update-service-rollback-smoke.ps1` creates a
temporary `AVORAX_DATA_DIR`, writes a rollback snapshot under
`updates\rollback\0.5.0`, writes different current app, service, and engine
files into a temporary install directory, and runs
`target\release\avorax_update_service.exe --rollback <install_dir>`. The
expected and verified behavior is successful exit, restored `Avorax.exe`,
`avorax_core_service.exe`, `avorax_guard_service.exe`, restored snapshot engine
content, removal of a pre-rollback engine signature, snapshot preservation,
successful `updates\logs\update_cli_status.json` evidence for
`command=--rollback`, and no direct-rollback
`updates\logs\update_report.json`. The full-suite verifier and report
validator now require `release update-service rollback restore smoke`.
Source-contracts passed (`527`), the full self-validating verifier passed
(`129` steps in `294.1s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release update-service
direct rollback restore proof only; successful signed update activation,
installed updater-service apply/rollback E2E, real service stop/start behavior,
network definition download, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2013 proves the release update-service `--rollback` path fails
visibly and leaves the install directory unchanged when no local rollback
snapshot exists. The new
`tools\testing\run-release-update-service-rollback-failsafe-smoke.ps1` creates a
temporary install directory containing current `Avorax.exe`,
`avorax_core_service.exe`, `avorax_guard_service.exe`, and
`engine\signatures\current.asig`, points `AVORAX_DATA_DIR` at a temporary data
root, intentionally creates no `updates\rollback` snapshot, and runs
`target\release\avorax_update_service.exe --rollback <install_dir>`. The
expected and verified behavior is non-zero exit with
`No Avorax rollback snapshot is available.`, unchanged install files, no created
rollback root, no `updates\logs\update_report.json`, and failed
`updates\logs\update_cli_status.json` evidence for `command=--rollback` with the
missing-snapshot diagnostic. The full-suite verifier and report validator now
require `release update-service rollback missing-snapshot fail-safe smoke`.
Source-contracts passed (`528`), the full self-validating verifier passed
(`130` steps in `290.8s`), and a negative in-repo report fixture missing that
scope failed with the expected diagnostic. This is release update-service direct
rollback missing-snapshot fail-safe proof only; successful signed update
activation, installed updater-service apply/rollback E2E, real service
stop/start behavior, network definition download, packaged desktop E2E,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2014 fixes and proves the release update-service `--rollback` path
rejects an incomplete local rollback snapshot before mutating the install
directory. `core\avorax_update_service\src\rollback.rs` now runs
`preflight_restore_snapshot(&snapshot, &install_dir)?` before the first restore
copy, validating required snapshot items and destination boundaries up front.
The new
`tools\testing\run-release-update-service-rollback-partial-snapshot-smoke.ps1`
creates a temporary install directory containing current `Avorax.exe`,
`avorax_core_service.exe`, `avorax_guard_service.exe`, and
`engine\signatures\current.asig`, creates a partial
`updates\rollback\0.5.0` snapshot containing only `Avorax.exe` and an engine
signature, points `AVORAX_DATA_DIR` at a temporary data root, and runs
`target\release\avorax_update_service.exe --rollback <install_dir>`. The
expected and verified behavior is non-zero exit with
`rollback snapshot missing required file avorax_core_service.exe`, unchanged
install files, no copied partial snapshot signature, preserved partial snapshot
fixtures, no `updates\logs\update_report.json`, and failed
`updates\logs\update_cli_status.json` evidence for `command=--rollback` with the
partial-snapshot diagnostic. The full-suite verifier and report validator now
require `release update-service rollback partial-snapshot fail-safe smoke`.
The full update-service Rust suite passed (`180` tests), source-contracts passed
(`530`), the full self-validating verifier passed (`131` steps in `295.8s`),
and a negative in-repo report fixture missing that scope failed with the
expected diagnostic. This is release update-service direct rollback
partial-snapshot fail-safe proof only; fully atomic nested-directory restore for
every possible mid-copy filesystem failure, successful signed update activation,
installed updater-service apply/rollback E2E, real service stop/start behavior,
network definition download, packaged desktop E2E, signed-driver/pre-execution
blocking, release-host SBOM/license output, production false-positive-rate
evidence, Flutter Windows app build, and installer stage remain partial,
blocked, or technically limited.

Checkpoint 2015 fixes and proves the release update-service `--rollback` path
rejects wrong-kind restore destinations before mutating the install directory.
`core\avorax_update_service\src\rollback.rs` now preflights file targets as
regular files or absent and directory targets as directories or absent, then
repeats those checks immediately before restore activation. The new
`tools\testing\run-release-update-service-rollback-destination-kind-smoke.ps1`
runs two complete-snapshot scenarios against the built release binary: one where
`avorax_core_service.exe` is a directory and one where `engine` is a file. The
expected and verified behavior is non-zero exit with
`rollback destination target is not a regular file` or
`rollback destination target is not a directory`, unchanged install files, no
copied rollback engine signature, no `updates\logs\update_report.json`, and
failed `updates\logs\update_cli_status.json` evidence for `command=--rollback`
with the destination-kind diagnostic. The full-suite verifier and report
validator now require
`release update-service rollback destination-kind fail-safe smoke`. The full
update-service Rust suite passed (`182` tests), source-contracts passed (`531`),
the full self-validating verifier passed (`132` steps in `296.8s`), and a
negative in-repo report fixture missing that scope failed with the expected
diagnostic. This is release update-service direct rollback destination-kind
fail-safe proof only; fully atomic nested-directory restore for every possible
mid-copy filesystem failure, successful signed update activation, installed
updater-service apply/rollback E2E, real service stop/start behavior, network
definition download, packaged desktop E2E, signed-driver/pre-execution blocking,
release-host SBOM/license output, production false-positive-rate evidence,
Flutter Windows app build, and installer stage remain partial, blocked, or
technically limited.

Checkpoint 2016 fixes and proves the release update-service `--rollback` path
restores the `engine` directory through a staged sibling directory and backup
activation instead of direct delete/copy. `core\avorax_update_service\src\rollback.rs`
now copies rollback snapshot directories to a checked sibling staging path,
moves any existing destination to a checked backup path, renames staging into
place, restores the backup on activation failure where possible, and reports
cleanup failures instead of swallowing them. The new
`tools\testing\run-release-update-service-rollback-staged-engine-smoke.ps1`
runs against the built release binary with a complete snapshot containing
`engine\signatures\rollback.asig` and `engine\models\rollback.model` plus a
current install tree containing obsolete engine files. The expected and
verified behavior is successful exit, restored app/service files, restored
snapshot engine files, removal of pre-rollback engine files, no leftover
`.engine.*.avorax-dir` staging or backup directories, preserved snapshot files,
successful `updates\logs\update_cli_status.json` evidence for
`command=--rollback`, and no direct-rollback `updates\logs\update_report.json`.
The full-suite verifier and report validator now require
`release update-service rollback staged-engine restore smoke`. The full
update-service Rust suite passed (`185` tests), source-contracts passed (`533`),
and the full self-validating verifier passed (`133` steps in `297.6s`). This is
release update-service direct rollback staged-directory restore proof only;
successful signed update activation, installed updater-service apply/rollback
E2E, real service stop/start behavior, network definition download, packaged
desktop E2E, signed-driver/pre-execution blocking, release-host SBOM/license
output, production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 2017 adds runtime proof for the normal update payload activation
layer that can be safely tested without installing or faking Windows services.
`core\avorax_update_service\src\update_applier.rs` now includes
`apply_payload_sections_copies_allowlisted_payloads_to_install_subtrees`, which
creates benign staged app, service, engine-signatures, engine-rules, engine-ml,
engine-trust, docs, tools, and migrations payloads. The test verifies
`apply_payload_sections` copies each allowlisted payload into the expected
install subtree while staged `tools` and `migrations` payloads remain
unactivated. This deliberately does not claim full release `--apply` success:
the top-level `--apply` path still requires real service stop/start behavior
that remains partial on this host without installing Windows services. The
focused payload-section test passed, the full update-service Rust suite passed
(`186` tests), source-contracts passed (`533`), and the full self-validating
verifier passed (`133` steps in `301.3s`) with report validation. Installed
updater-service apply/rollback E2E, real service stop/start behavior, successful
signed update activation through the top-level release `--apply` path, network
definition download, packaged desktop E2E, signed-driver/pre-execution blocking,
release-host SBOM/license output, production false-positive-rate evidence,
Flutter Windows app build, and installer stage remain partial, blocked, or
technically limited.

Checkpoint 2018 adds private service-control injection for update-service apply
orchestration tests while keeping production `apply_package` backed by
`WindowsUpdateServiceControl` and the real Windows stop/start helpers.
`apply_package_with_service_control` lets crate tests prove top-level signed
package apply behavior without installing services or faking release CLI
success. The success fixture verifies signed package verification/extraction,
rollback snapshot creation, injected stop/start order, allowlisted app/service/
engine/docs payload activation, successful `update_report`, and staging cleanup.
The restart-failure fixture injects a synthetic start error and verifies rollback
restore, failed report fields, rollback restart reporting, and restored old
app/service/engine files. Focused orchestration tests passed (`2`), the full
update-service Rust suite passed (`188` tests), source-contracts passed (`534`),
and the full self-validating verifier plus report validator passed (`133` steps
in `309.3s`). This is unit/integration orchestration proof only; installed
updater-service apply/rollback E2E, real service stop/start success on this
host, network definition download, packaged desktop E2E, signed-driver/
pre-execution blocking, release-host SBOM/license output, production
false-positive-rate evidence, Flutter Windows app build, and installer stage
remain partial, blocked, or technically limited.

Checkpoint 2019 introduces `FileSelectionService` for Flutter file/folder picker
handoffs so `ZentorController` no longer calls `file_selector` directly.
Production still uses the real `file_selector.openFile()` and
`file_selector.getDirectoryPath()` inside the adapter, while tests inject a fake
picker service. New Custom File/Folder widget tests prove detect-only picker
success sends the selected file/folder path to Local Core once with
`ScanKind.custom`; controller tests prove picker cancel clears
`scanTargetSelectionInFlight` without scanning or logging failure, and picker
failure produces normalized visible `scan_folder_picker_failed` evidence without
control characters. The small-threat verifier/report validator now require
`Flutter custom picker adapter tests` and `custom picker adapter success/cancel/
failure tests`. Focused adapter tests passed (`10` in the combined verifier
filter), Flutter analyzer passed, source-contracts passed (`535`), and the full
self-validating verifier plus report validator passed (`134` steps in
`526.7s`). This improves widget/controller/runtime evidence for custom scan
picker flows only; installed OS picker click-through E2E, packaged desktop E2E,
installed local-core/service behavior, signed-driver/pre-execution blocking,
release-host SBOM/license output, production false-positive-rate evidence,
Flutter Windows app build, and installer stage remain partial, blocked, or
technically limited.

Checkpoint 2020 extends `FileSelectionService` picker adapter evidence to the
Protected Apps Add file/app and Add folder controls. Protected Apps widget tests
now inject a fake picker service through `ZentorController`, proving confirmed
file selection saves the selected file identity/path/source, adds that file to
scan scope, records `protected_app_added_manually`, and shows saved feedback;
confirmed folder selection saves the selected folder and scan scope; and folder
picker failure records normalized `manual_protected_app_folder_failed` evidence
without control characters or a false saved state. The small-threat verifier and
report validator now require `Flutter Protected Apps picker adapter tests` and
`Protected Apps picker adapter success/failure tests`. Focused Protected Apps
picker tests passed (`7`), Flutter analyzer passed, source-contracts passed
(`535`), and the full self-validating verifier plus report validator passed
(`135` steps in `563.1s`). This improves widget/controller/runtime evidence for
Protected Apps picker handoffs only; installed OS picker click-through E2E,
packaged desktop E2E, installed local-core/service behavior, signed-driver/
pre-execution blocking, release-host SBOM/license output, production
false-positive-rate evidence, Flutter Windows app build, and installer stage
remain partial, blocked, or technically limited.

Checkpoint 2021 completes the Add file/app picker edge-case evidence for
Protected Apps. A confirmed Add file/app dialog whose picker returns `null` now
has widget proof that the file picker is called once, no protected-app config is
saved, scan scope remains unchanged, no false failure or manual-add event is
recorded, and the visible outcome is `No protected app selection was saved.` A
second test injects a file picker exception containing control characters and
proves `manual_protected_app_file_failed` is recorded as protection/error
evidence, the visible/audit diagnostic is normalized, and no false saved state or
scan-scope mutation occurs. Source contracts now guard both fixtures. Focused
Protected Apps picker tests passed (`9`), Flutter analyzer passed,
source-contracts passed (`535`), and the full self-validating verifier plus
report validator passed (`135` steps in `452.1s`). This remains
widget/controller/runtime evidence; installed OS picker click-through E2E,
packaged desktop E2E, installed local-core/service behavior, signed-driver/
pre-execution blocking, release-host SBOM/license output, production
false-positive-rate evidence, Flutter Windows app build, and installer stage
remain partial, blocked, or technically limited.

Checkpoint 2022 completes the remaining Custom Scan picker edge-case evidence.
`offline_scan_test.dart` now proves a Custom File picker exception records
normalized `scan_file_picker_failed` scan/error evidence, sets
`ScanStatus.failed`, clears `scanTargetSelectionInFlight`, makes zero Local Core
scan IPC calls, and strips control characters from visible/audit diagnostics. It
also proves Custom Folder picker cancel clears target-selection state, makes zero
Local Core scan IPC calls, leaves no user-visible error, and records no false
`scan_folder_picker_failed` event. Source contracts now guard both fixtures.
Focused custom picker adapter tests passed (`12`), Flutter analyzer passed,
source-contracts passed (`535`), and the full self-validating verifier plus
report validator passed (`135` steps in `477s`). This improves
widget/controller/runtime evidence for custom scan picker handoffs only;
installed OS picker click-through E2E, packaged desktop E2E, installed
local-core/service behavior, signed-driver/pre-execution blocking, release-host
SBOM/license output, production false-positive-rate evidence, Flutter Windows
app build, and installer stage remain partial, blocked, or technically limited.

Checkpoint 2023 completes the remaining Protected Apps Add folder picker cancel
evidence. A confirmed Add folder dialog whose folder picker returns `null` now
has widget proof that the directory picker is called once, no protected-app
config is saved, scan scope remains unchanged, no false folder-failure or
manual-add event is recorded, and the visible outcome is
`No protected app selection was saved.` Focused Protected Apps picker tests
passed (`10`), Flutter analyzer passed, source-contracts passed (`535`), and
the full self-validating verifier plus report validator passed (`135` steps in
`611.8s`). This remains widget/controller/runtime evidence; installed OS picker
click-through E2E, packaged desktop E2E, installed local-core/service behavior,
signed-driver/pre-execution blocking, release-host SBOM/license output,
production false-positive-rate evidence, Flutter Windows app build, and
installer stage remain partial, blocked, or technically limited.

Checkpoint 1657 refreshes Flutter controller runtime evidence for update event
metadata: `update_controller_test.dart` passed (`32`) including update check,
availability, install, rollback, and failure category/severity coverage.
Installed updater service and release-package E2E remain partial.

Checkpoint 1658 adds Flutter controller runtime evidence for scheduled scan,
protection self-test, and heartbeat event metadata: `offline_scan_test.dart`
passed (`101`) including scheduled quick-scan settings/start metadata and the
focused self-test/heartbeat success/failure metadata test. Installed
app-lifetime scheduling, UI event-flow E2E, and live cloud backend smoke remain
partial.

Checkpoint 1767 hardens scheduled quick-scan activation: the in-app timer is
created before schedule config persistence, pending timers are cancelled on
failure, startup timer activation failures are logged, and a failing timer
factory cannot leave Settings claiming an enabled schedule. `offline_scan_test.dart`
passed (`103`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. This remains an app-lifetime scheduler,
not a Windows scheduled task or background service.

Checkpoint 1977 hardens scheduled quick-scan concurrency around custom target
selection. App-lifetime timer fires now log `scheduled_quick_scan_skipped`
instead of `scheduled_quick_scan_started` when a custom file/folder picker is
already active, Home/Scan/Protection quick-scan controls treat target selection
as scan-busy, and scan action-mode changes are rejected during target selection
with warning evidence. Focused Flutter tests, source-contracts, analyzer, the
negative report-validator scope fixture, and the full small-threat MVP verifier
passed (`98` steps in `191.2s`). This is still app-lifetime Flutter
controller/UI proof, not Windows Scheduled Task/background-service scheduling
or installed desktop click-through E2E.

Checkpoint 1769 hardens signed `.aup` payload extraction activation: the update
package activator rechecks the extraction target parent chain after the
non-following target-absence check and immediately before `rename`, preserving
canonical staging-boundary evidence through final activation. The focused
activation regression passed, full `avorax_update_service` tests passed (`176`),
and `cargo fmt --all -- --check` passed. Installed update-service/package E2E
remains partial.

Checkpoint 1770 hardens Flutter update-service timeout reporting: `_runUpdater`
now reports kill request status and then performs a bounded post-kill process
exit observation, surfacing non-exit or observation failure in the same bounded
diagnostic text. `update_service_test.dart` passed (`108`), `flutter analyze`
passed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Hung real updater process fixtures and installed update E2E remain
partial.

Checkpoint 1771 hardens Flutter local-core subprocess timeout reporting:
scan IPC, Guard self-test, cancel IPC, and elevated PowerShell timeout paths
now report kill request status plus bounded post-kill exit observation.
`local_core_ipc_diagnostics_test.dart` passed (`59`) with a hung local-core
child fixture for scan IPC, `flutter analyze` passed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Hung Guard/cancel/elevated
PowerShell runtime fixtures and installed process E2E remain partial.

Checkpoint 1772 hardens the remaining Flutter platform/app process timeout
reporting: platform-info PowerShell and app-detection process-list commands now
report kill request status plus bounded post-kill exit observation, and timed-out
stdout/stderr collection is bounded so diagnostics cannot hang after cleanup.
`platform_info_service_test.dart` passed (`17`), `app_detector_test.dart` passed
(`8`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Hung process runtime fixtures for these
specific helpers and installed desktop E2E remain partial.

Checkpoint 1773 adds benign hung-process runtime fixtures for the platform/app
timeout paths covered in checkpoint 1772. The production helpers still resolve
PowerShell/tasklist/ps through checked local paths and retain the default 8s
command timeout plus 5s post-kill reap timeout; tests inject a sleeping Dart
child and short test-only timeouts to verify the timeout, kill request, bounded
post-kill exit observation, and bounded diagnostic collection behavior.
`platform_info_service_test.dart` passed (`19`), `app_detector_test.dart` passed
(`9`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed desktop/service subprocess E2E
remains partial.

Checkpoint 1774 adds matching benign hung-process runtime fixtures for the
remaining Flutter local-core subprocess helpers: Guard self-test, cancel IPC,
and elevated PowerShell via the public service-start route. Local-core process
launches now support test-only process starters and timeout overrides while
retaining production executable validation and default timeouts; elevated
PowerShell timeout diagnostics also bound post-timeout stdout/stderr collection.
`local_core_ipc_diagnostics_test.dart` passed (`62`), `flutter analyze` passed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed desktop/service subprocess E2E remains partial.

Checkpoint 1775 runtime-verifies Flutter cached update-package hash-input size
bounds: the update service keeps the production 512 MiB package limit by
default, exposes a positive test-only package-size limit, and rejects an
oversized managed-cache `.aup` during `verifyDownloadedPackage` before SHA-256
streaming or updater launch. `update_service_test.dart` passed (`109`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed signed update apply/rollback E2E
remains partial.

Checkpoint 1776 runtime-verifies selected-file hash race and growth guards:
`HashService` keeps the production 512 MiB selected-file limit by default,
supports a positive test-only limit, rejects a selected path that changes after
stat and before hashing, and rejects a file that grows over the limit during
chunked SHA-256 streaming. `hash_service_test.dart` passed (`6`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Symlink/junction execution remains
host-limited where link creation is unavailable.

Checkpoint 1777 runtime-verifies scan metric no-evidence labels in the Flutter
widget tree: report-backed scan metric cards render `No report` without
`lastScanReport`, live progress facts render `Pending` without a progress
snapshot, and explicit `0`/`0s` labels are absent where no evidence exists.
`scan_screen_test.dart` passed (`2`), `flutter analyze` passed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed desktop click/layout E2E remains partial.

Checkpoint 1778 runtime-verifies Flutter cloud health streamed-response limits:
cloud health rejects responses that exceed the JSON byte cap while streaming,
even without `Content-Length`, and stalled cloud response streams fail through
bounded offline diagnostics using a short test-only timeout while preserving the
production 256 KiB/10 second defaults. `api_client_test.dart` passed (`40`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Live backend/cloud smoke remains partial.

Checkpoint 1779 hardens Flutter controller UI diagnostics by moving app-state
diagnostics from the broader update-check cap to an explicit 2048-character UI
cap. Runtime fixtures verify quarantine and allowlist refresh failures normalize
control/NUL-rich local-core exceptions and bound both visible `errorMessage`
text and local-event `details`. `offline_scan_test.dart` passed (`105`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed UI click-through remains
partial.

Checkpoint 1780 runtime-verifies Home/Protection/Settings native pack-count
labels: zero signature/rule counts stay `Unknown` while native-engine readiness
is unproven, and explicit zero loaded counts appear only with
`nativeEngineStatus == ready`. `settings_accessibility_test.dart` passed (`13`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed desktop visual E2E remains
partial.

Checkpoint 1781 runtime-verifies native-engine status labels across Home,
Device, Protection, and Settings: `ready`, `error`, `unavailable`, unknown
values, and `lastEngineError` diagnostic override all render as explicit,
evidence-backed labels instead of raw IPC strings or unavailable fallbacks.
`settings_accessibility_test.dart` passed (`15`), `flutter analyze` passed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed desktop visual E2E remains partial.

Checkpoint 1782 runtime-verifies Device Guard/driver and service-evidence
labels: unknown Guard/driver evidence stays `Unknown` instead of `Missing` or
`Not running`, and partially missing service-state maps render
`unknown; service evidence missing` rather than fabricated not-installed
evidence. `settings_accessibility_test.dart` passed (`17`), `flutter analyze`
passed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Installed desktop visual/service E2E remains partial.

Checkpoint 1783 runtime-verifies Scan and Protection Core Service status labels:
Scan engine-unavailable diagnostic chips and Protection checklist rows render
`unknown`, `unsupported`, `error`, and truly unrecognized Core Service statuses
as distinct evidence-backed labels. `scan_screen_test.dart` plus
`settings_accessibility_test.dart` passed together (`21`), `flutter analyze`
passed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Installed desktop visual/service E2E remains partial.

Checkpoint 1784 runtime-verifies native ML and Local AI status labels across
Home, Device, Protection, Settings, and Scan. The widget fixtures cover
`loaded`, `developmentModel`, `modelMissing`, `error`, unrecognized fallback
labels, and Protection's `AiModelStatus` checklist labels, preventing stale
production/active aliases from reappearing as UI evidence. `scan_screen_test.dart`
plus `settings_accessibility_test.dart` passed together (`24`), `flutter analyze`
passed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Installed desktop visual/service E2E remains partial.

Checkpoint 1785 runtime-verifies Settings AI feature-schema display honesty:
`unavailable` and blank schema evidence render as `Unavailable`, valid schema
metadata renders verbatim, and fabricated `1.0.0`/`zne-features-v1` defaults are
absent from the Settings widget. `settings_accessibility_test.dart` passed
(`21`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed Local Core health/UI E2E remains
partial.

Checkpoint 1786 runtime-verifies the Protection Native Engine checklist
unavailable label. A focused widget fixture renders
`nativeEngineStatus='unavailable'` through the Protection checklist path,
confirms `Unavailable` is visible, and confirms the unavailable state does not
collapse into generic `Error`. `settings_accessibility_test.dart` passed (`22`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed desktop visual/service E2E
remains partial.

Checkpoint 1787 runtime-verifies Home threat-status evidence. A focused widget
fixture confirms Home does not render `Threats found` or `Review threats`
without a scan report or with a clean zero-threat report, and renders both only
when `lastScanReport.threatsFound > 0`. `settings_accessibility_test.dart`
passed (`23`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed scan/UI E2E remains partial.

Checkpoint 1788 hardens watcher active-without-paths diagnostics. Active
watcher IPC responses with valid empty watched paths now surface the diagnostic
through both `RealtimeWatcherState.error` and `limitations`, allowing
protection-start limitation evidence to remain visible. Malformed watched-path
evidence is still reported as malformed paths and is not relabeled as
active-without-paths. The focused `local_core_ipc_diagnostics_test.dart`
watcher-state filter passed (`5`), `flutter analyze` passed, source-contracts
passed (`481`), and no-malware/product-copy gates passed. Installed watcher E2E
remains partial.

Checkpoint 1789 runtime-verifies Settings malware-engine health busy UI.
`malwareEngineHealthCheckInFlight=true` relabels the Settings engine refresh
control to `Checking engine`, disables the button, and hides the idle
`Check engine` action. `settings_accessibility_test.dart` passed (`24`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed Settings click/layout E2E
remains partial.

Checkpoint 1790 runtime-verifies Protected Apps autodetection busy UI.
`appDetectionInFlight=true` relabels the Protected Apps `Rescan` control to
`Rescanning`, disables the button, and hides the idle `Rescan` action while
automatic detection remains supported. `settings_accessibility_test.dart`
passed (`25`), `flutter analyze` passed, and source-contracts passed (`481`).
No-malware/product-copy gates are rerun in the checkpoint 1790 result artifact.
Installed Protected Apps click/layout E2E remains partial.

Checkpoint 1791 runtime-verifies Scan target-selection busy UI.
`scanTargetSelectionInFlight=true` disables Quick Scan, Full Scan, Custom File,
and Custom Folder controls so an in-flight custom target picker blocks all
scan-start actions. `scan_screen_test.dart` passed (`5`), `flutter analyze`
passed, and source-contracts passed (`481`). No-malware/product-copy gates are
rerun in the checkpoint 1791 result artifact. Installed OS-picker and Scan
click/layout E2E remain partial.

Checkpoint 1792 runtime-verifies Quarantine action busy UI.
`quarantineActionInFlight=true` disables Quarantine `Refresh`, `Restore / Keep`,
and `Delete permanently` controls for a quarantined record, preventing
overlapping restore/delete/refresh actions while mutation work is pending.
`quarantine_screen_test.dart` passed (`1`), `flutter analyze` passed, and
source-contracts passed (`481`). No-malware/product-copy gates are rerun in the
checkpoint 1792 result artifact. Installed Quarantine click/layout E2E remains
partial.

Checkpoint 1793 runtime-verifies Allowlist action busy UI.
`allowlistActionInFlight=true` disables Allowlist `Refresh` and `Remove`
controls for an active allowlist entry, preventing overlapping trust-entry
refresh/remove actions while mutation work is pending. `allowlist_screen_test.dart`
passed (`1`), `flutter analyze` passed, and source-contracts passed (`481`).
No-malware/product-copy gates are rerun in the checkpoint 1793 result artifact.
Installed Allowlist click/layout E2E remains partial.

Checkpoint 1794 runtime-verifies Scan threat feedback and ignore busy UI.
`detectionFeedbackInFlight=true` disables `Mark false positive` and
`Mark malicious`, and `threatIgnoreActionInFlight=true` disables
`Keep / Ignore` for a review threat. The threat-card details `ExpansionTile`
now has its own transparent `Material` so Flutter does not hide ListTile
ink/background effects inside the decorated threat card. `scan_screen_test.dart`
passed (`6`), `flutter analyze` passed, and source-contracts passed (`481`).
No-malware/product-copy gates are rerun in the checkpoint 1794 result artifact.
Installed Scan-result click/layout E2E remains partial.

Checkpoint 1795 runtime-verifies Settings security-settings busy UI.
`securitySettingsActionInFlight=true` disables the Protection mode dropdown,
ransomware protected folders and trusted-process text fields, Save ransomware
protection settings button, scheduled quick-scan switch, and scan interval
dropdown. `settings_accessibility_test.dart` passed (`26`), `flutter analyze`
passed, and source-contracts passed (`481`). No-malware/product-copy gates are
rerun in the checkpoint 1795 result artifact. Installed Settings click/layout
E2E remains partial.

Checkpoint 1796 runtime-verifies Scan service-recovery busy UI.
`serviceActionInFlight=true` disables Start Core Service, Open install report,
and Repair installation controls in engine-unavailable diagnostics.
`scan_screen_test.dart` passed (`7`), `flutter analyze` passed, and
source-contracts passed (`481`). No-malware/product-copy gates are rerun in the
checkpoint 1796 result artifact. Installed Scan diagnostics/service-control E2E
remains partial.

Checkpoint 1797 runtime-verifies Settings configuration-reset busy UI.
`configurationResetInFlight=true` disables the Reset configuration control,
preventing duplicate reset attempts while protection-stop/reset cleanup is
pending. `settings_accessibility_test.dart` passed (`27`), `flutter analyze`
passed, and source-contracts passed (`481`). No-malware/product-copy gates are
rerun in the checkpoint 1797 result artifact. Installed Settings reset E2E
remains partial.

Checkpoint 1798 runtime-verifies Protected Apps action busy UI.
`protectedAppActionInFlight=true` disables Add file or app, Add folder,
Calculate build hash, and detected-app row selection while protected-app
mutation/hash work is pending. `settings_accessibility_test.dart` passed (`28`),
`flutter analyze` passed, and source-contracts passed (`481`). No-malware/product-copy
gates are rerun in the checkpoint 1798 result artifact. Installed Protected Apps
click/layout E2E remains partial.

Checkpoint 1799 runtime-verifies quarantine restore/delete path-text bounds.
A long quarantine `originalPath` containing NUL, newline, and tab control
characters is normalized and bounded in unconfirmed restore/delete confirmation
events before any local-core restore/delete IPC is made. Both confirmation
events remain `quarantine`/`warning`, retain truncation evidence, and local-core
restore/delete call counters remain zero. `offline_scan_test.dart` passed
(`106`) including the focused path-text fixture, `flutter analyze` passed, and
source-contracts passed (`481`). No-malware/product-copy gates are rerun in the
checkpoint 1799 result artifact. Installed Quarantine restore/delete click/E2E
remains partial.

Checkpoint 1800 runtime-verifies optimistic quarantine status/action
consistency. Successful restore/delete paths with a failed follow-up quarantine
refresh now assert that the stale local UI row updates both `status` and
`actionTaken` to `restored` or `deleted`, preventing restored/deleted rows from
retaining stale `quarantined` action evidence while waiting for the next
successful refresh. The focused restore/delete fixtures passed,
`offline_scan_test.dart` passed (`106`), `flutter analyze` passed, and
source-contracts passed (`481`). No-malware/product-copy gates are rerun in the
checkpoint 1800 result artifact. Installed Quarantine restore/delete click/E2E
remains partial.

Checkpoint 1801 refreshes Flutter dead scan-status wrapper runtime evidence.
The focused `local_core_ipc_diagnostics_test.dart` fixture `scan report and
progress parsers bound string IPC fields` passed on the current host and
confirms the active parser still uses `ScanStatus? _scanStatusOrNull` while the
unused `ScanStatus _scanStatus(` wrapper remains absent. `dart format` reported
no changes, `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed.

Checkpoint 1802 broadens Flutter protection-readiness event runtime coverage.
Startup controller fixtures now verify app-detection start, empty process
snapshot, no-supported-app detection, malware-engine available-with-diagnostics,
app-detection failure, and malware-health failure events use the `protection`
category with the expected info/warning/error severities and visible failure or
diagnostic details. `offline_scan_test.dart` passed (`108`), `flutter analyze`
passed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Installed Protected Apps/Settings click-through E2E remains partial.

Checkpoint 1803 runtime-verifies Flutter update cache staging/activation failure
safety. A local `.aup` source that exceeds a test-only package limit fails during
staging, does not return a fake downloaded package path, preserves the existing
cached `.aup` contents, and leaves no temporary `.part` package files behind.
`update_service_test.dart` passed (`110`), `flutter analyze` passed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed update-service/package E2E remains partial.

Checkpoint 1804 runtime-verifies Flutter realtime watcher path-probe limitations.
An injected filesystem probe fixture makes UI-side inspection of a NUL-rich watch
path fail before Local Core validation; the controller keeps the original watch
path in the Local Core call, records a normalized limitation without embedded NUL
bytes, and surfaces the warning through realtime watcher state/error text instead
of reporting unqualified success. `offline_scan_test.dart` passed (`109`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed Local Core watcher/service E2E
remains partial.

Checkpoint 1805 runtime-verifies Flutter protection-start exception
normalization. A control/NUL-rich Guard IPC exception thrown during
`startProtection` is bounded and normalized before both visible `errorMessage`
and the `protection_start_failed` audit event, leaves protection in explicit
error state, clears loading/busy state, and does not attempt watcher startup
after the failed Guard-mode IPC call. `offline_scan_test.dart` passed (`110`),
`flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed service/driver E2E remains
partial.

Checkpoint 1806 runtime-verifies Flutter scan-cancel exception normalization. A
control/NUL-rich cancel IPC exception during an active quick scan is bounded and
normalized before visible `errorMessage` and the `scan_cancel_failed` audit
event; the cancel-in-flight state clears, the scan remains running after failed
cancellation, and the eventual clean scan report is not converted to a cancelled
result. `offline_scan_test.dart` passed (`111`), `flutter analyze` passed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed scan/UI/local-core E2E remains partial.

Checkpoint 1807 runtime-verifies Flutter cloud health exception normalization. A
control/NUL-rich exception thrown by the cloud health client is bounded and
normalized before visible `errorMessage` and the `cloud_offline` audit event;
the cloud health busy flag clears, Cloud status becomes offline, and the event
stays categorized as `settings`/`warning`. `offline_scan_test.dart` passed
(`112`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed Settings UI and live backend
smoke remain partial.

Checkpoint 1808 runtime-verifies Flutter configuration reset exception
normalization. A control/NUL-rich exception thrown by the config repository
during confirmed reset is bounded and normalized before visible `errorMessage`
and the `configuration_reset_failed` audit event; the reset returns false,
`configurationResetInFlight` clears, and existing developer override/scheduled
scan settings remain unchanged instead of silently reverting to defaults.
`offline_scan_test.dart` passed (`113`), `flutter analyze` passed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed Settings reset click-through remains partial.

Checkpoint 1809 runtime-verifies Flutter protection self-test exception
normalization. A control/NUL-rich exception thrown by self-test IPC is bounded
and normalized before visible `errorMessage`, self-test result text, and the
`protection_self_test_failed` audit event; exactly one self-test IPC call is
made, loading and self-test busy state clear, and no PASS/fake success text is
shown. `offline_scan_test.dart` passed (`114`), `flutter analyze` passed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed Guard/self-test E2E remains partial.

Checkpoint 1810 runtime-verifies Flutter false-positive feedback exception
normalization. A control/NUL-rich exception thrown by detection-label IPC is
bounded and normalized before visible `errorMessage` and the
`false_positive_label_failed` audit event; exactly one feedback IPC call is
made, `detectionFeedbackInFlight` clears, and the threat remains detected
instead of being marked ignored/suppressed. `offline_scan_test.dart` passed
(`115`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed Scan-result click-through E2E
remains partial.

Checkpoint 1811 runtime-verifies Flutter malicious feedback exception
normalization. A control/NUL-rich exception thrown by detection-label IPC is
bounded and normalized before visible `errorMessage` and the
`malicious_label_failed` audit event; exactly one feedback IPC call is made,
`detectionFeedbackInFlight` clears, and the threat remains detected with the
original `review` recommendation instead of being escalated to quarantine.
`offline_scan_test.dart` passed (`116`), `flutter analyze` passed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed Scan-result click-through E2E remains partial.

Checkpoint 1812 runtime-verifies Flutter allowlist-add exception normalization.
A control/NUL-rich exception thrown by allowlist add IPC is bounded and
normalized before visible `errorMessage` and the `allowlist_entry_add_failed`
audit event; exactly one add IPC call is made, `allowlistActionInFlight` clears,
and the threat remains detected with the original `review` recommendation
instead of being marked allowlisted/trusted. `offline_scan_test.dart` passed
(`117`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed Scan-result/Allowlist
click-through E2E remains partial.

Checkpoint 1813 runtime-verifies Flutter allowlist-remove exception
normalization. A control/NUL-rich exception thrown by allowlist remove IPC is
bounded and normalized before visible `errorMessage` and the
`allowlist_entry_remove_failed` audit event; exactly one remove IPC call is
made, `allowlistActionInFlight` clears, and the allowlist row remains active
instead of falsely showing normal policy has resumed. `offline_scan_test.dart`
passed (`118`), `flutter analyze` passed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed Allowlist click-through E2E
remains partial.

Checkpoint 1814 runtime-verifies Flutter manual quarantine exception
normalization. The existing quarantine IPC exception fixture now uses a
control/NUL-rich diagnostic and proves the thrown error is bounded and
normalized before visible `errorMessage` and the `quarantine_failed` audit
event; exactly one quarantine IPC call is made, `quarantineActionInFlight`
clears, and the threat remains detected instead of falsely marked quarantined.
`offline_scan_test.dart` passed (`118`), `flutter analyze` passed after
retrying with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed Scan-result/Quarantine
click-through E2E remains partial.

Checkpoint 1815 runtime-verifies Flutter quarantine restore exception
normalization. The existing restore IPC exception fixture now uses a
control/NUL-rich diagnostic and proves the thrown error is bounded and
normalized before visible `errorMessage` and the `quarantine_restore_failed`
audit event; exactly one restore IPC call is made, `quarantineActionInFlight`
clears, and the quarantine row remains `quarantined` instead of falsely marked
restored. `offline_scan_test.dart` passed (`118`), `flutter analyze` passed
with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed.
Installed Quarantine restore click-through E2E remains partial.

Checkpoint 1816 runtime-verifies Flutter quarantine delete exception
normalization. A new delete IPC exception fixture uses a control/NUL-rich
diagnostic and proves the thrown error is bounded and normalized before visible
`errorMessage` and the `quarantine_delete_failed` audit event; exactly one
delete IPC call is made, `quarantineActionInFlight` clears, and the quarantine
row remains `quarantined` instead of falsely marked deleted. `offline_scan_test.dart`
passed (`119`), `flutter analyze` passed with analytics suppressed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed Quarantine delete click-through E2E remains partial.

Checkpoint 1817 runtime-verifies Quarantine restore/delete dialog click-through
at the Flutter widget layer. `quarantine_screen_test.dart` now opens the
Restore / Keep and Delete permanently dialogs, proves Cancel does not call
local-core, and proves confirm routes the expected quarantine ID through the
controller to restore/delete IPC. `quarantine_screen_test.dart` passed (`5`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Packaged desktop
click-through with installed local-core remains partial.

Checkpoint 1818 runtime-verifies Scan-result manual Quarantine dialog
click-through at the Flutter widget layer. `scan_screen_test.dart` now renders
a confirmed benign EICAR-style detection, opens the Quarantine confirmation
dialog, proves Cancel does not call local-core, and proves confirm routes the
expected threat ID through quarantine IPC. `scan_screen_test.dart` passed (`9`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Packaged desktop
Scan-result click-through with installed local-core remains partial.

Checkpoint 1819 runtime-verifies Scan-result Add to allowlist dialog
click-through at the Flutter widget layer. `scan_screen_test.dart` now opens the
Add to allowlist confirmation dialog for a review detection, proves Cancel does
not call local-core, and proves confirm routes the expected path through
allowlist IPC. `scan_screen_test.dart` passed (`11`), `flutter analyze` passed
with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Packaged desktop Scan-result allowlist
click-through with installed local-core remains partial.

Checkpoint 1820 runtime-verifies Scan-result Mark false positive dialog
click-through at the Flutter widget layer. `scan_screen_test.dart` now opens the
Mark false positive confirmation dialog for a review detection, proves Cancel
does not call local-core, and proves confirm routes the expected threat ID with
the `falsePositive` label through detection-label IPC. `scan_screen_test.dart`
passed (`13`), `flutter analyze` passed with analytics suppressed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Packaged desktop Scan-result feedback click-through with installed local-core
remains partial.

Checkpoint 1821 runtime-verifies Scan-result Mark malicious dialog
click-through at the Flutter widget layer. `scan_screen_test.dart` now opens the
Mark malicious confirmation dialog for a review detection, proves Cancel does
not call local-core, and proves confirm routes the expected threat ID with the
`confirmedMalicious` label through detection-label IPC without claiming
quarantine or deletion. `scan_screen_test.dart` passed (`15`), `flutter analyze`
passed with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Packaged desktop Scan-result feedback
click-through with installed local-core remains partial.

Checkpoint 1822 runtime-verifies Scan-result Keep / Ignore dialog
click-through at the Flutter widget layer. `scan_screen_test.dart` now opens the
Keep and ignore confirmation dialog for a review detection, proves Cancel keeps
the threat detected, and proves confirm marks the threat ignored while clearing
the ignore busy state. `scan_screen_test.dart` passed (`17`), `flutter analyze`
passed with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Packaged desktop Scan-result ignore
click-through remains partial.

Checkpoint 1823 runtime-verifies Quick Scan automatic-quarantine confirmation
at the Flutter widget layer. `scan_screen_test.dart` now uses fake quick-scan
targets and fake local-core scan IPC, opens the automatic-quarantine scan
confirmation dialog, proves Cancel does not scan, and proves Confirm starts
exactly one quick scan with `autoQuarantineConfirmedOnly` against the expected
fixture path. `scan_screen_test.dart` passed (`19`), `flutter analyze` passed
with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Packaged desktop scan-start click-through
with installed local-core remains partial.

Checkpoint 1824 runtime-verifies Full Scan automatic-quarantine confirmation at
the Flutter widget layer. `scan_screen_test.dart` now uses a fake full-scan root
and fake local-core scan IPC, opens the automatic-quarantine scan confirmation
dialog, proves Cancel does not scan, and proves Confirm starts exactly one full
scan with `autoQuarantineConfirmedOnly` against the expected fixture root.
`scan_screen_test.dart` passed (`21`), `flutter analyze` passed with analytics
suppressed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Packaged desktop scan-start click-through with installed local-core
remains partial.

Checkpoint 1825 runtime-verifies Quick Scan detect-only start behavior at the
Flutter widget layer. `scan_screen_test.dart` now uses fake quick-scan targets
and fake local-core scan IPC, proves detect-only Quick Scan does not show the
automatic-quarantine confirmation dialog, and proves it starts exactly one quick
scan with `ScanActionMode.detectOnly`. `scan_screen_test.dart` passed (`22`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Packaged desktop scan-start
click-through with installed local-core remains partial.

Checkpoint 1826 runtime-verifies Full Scan detect-only start behavior at the
Flutter widget layer. `scan_screen_test.dart` now uses a fake full-scan root and
fake local-core scan IPC, proves detect-only Full Scan does not show the
automatic-quarantine confirmation dialog, and proves it starts exactly one full
scan with `ScanActionMode.detectOnly`. `scan_screen_test.dart` passed (`23`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Packaged desktop scan-start
click-through with installed local-core remains partial.

Checkpoint 1827 runtime-verifies Custom File and Custom Folder
automatic-quarantine cancel behavior at the Flutter widget layer.
`scan_screen_test.dart` opens the automatic-quarantine confirmation from both
custom scan controls and proves Cancel closes the dialog without calling
local-core scan IPC before any picker/scan handoff. `scan_screen_test.dart`
passed (`25`), `flutter analyze` passed with analytics suppressed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed OS-picker and packaged desktop click-through E2E remain partial.

Checkpoint 1828 runtime-verifies Scan-tab start-busy UI gating at the Flutter
widget layer. `scan_screen_test.dart` sets `scanStartInFlight=true` and proves
the scan action-mode segmented control plus Quick Scan, Full Scan, Custom File,
and Custom Folder start controls are disabled while scan startup is in flight.
`scan_screen_test.dart` passed (`26`), `flutter analyze` passed with analytics
suppressed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Packaged desktop scan-start click-through remains partial.

Checkpoint 1829 runtime-verifies Scan-tab running-scan UI gating at the Flutter
widget layer. `scan_screen_test.dart` sets `scanStatus=running` and proves the
scan action-mode segmented control plus Quick Scan, Full Scan, Custom File, and
Custom Folder start controls are disabled while a scan is already running.
`scan_screen_test.dart` passed (`27`), `flutter analyze` passed with analytics
suppressed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Packaged desktop scan-start click-through remains partial.

Checkpoint 1830 runtime-verifies Home and Protection scan shortcut busy gating
at the Flutter widget layer. `settings_accessibility_test.dart` renders Home
and Protection with `scanStartInFlight=true` and `scanStatus=running`, proving
Home Run Quick Scan/Run Full Scan and Protection Run Quick Scan are disabled in
both states. `settings_accessibility_test.dart` passed (`29`), `flutter analyze`
passed with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Packaged desktop scan-start click-through
remains partial.

Checkpoint 1831 runtime-verifies Home and Protection scan shortcut action-mode
isolation at the Flutter widget/controller/local-core fixture layer.
`settings_accessibility_test.dart` renders Home and Protection while Scan-tab
state is `autoQuarantineConfirmedOnly`, clicks Home Run Quick Scan, Home Run
Full Scan, and Protection Run Quick Scan, and proves each local-core scan IPC
uses `ScanActionMode.detectOnly` with the expected shortcut target path.
`settings_accessibility_test.dart` passed (`30`), `flutter analyze` passed with
analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Packaged desktop scan-start click-through
remains partial.

Checkpoint 1832 runtime-verifies Scan-tab cancellation busy gating at the
Flutter widget layer. `scan_screen_test.dart` renders a running scan with
`scanCancelInFlight=true` and proves the visible Cancel control is disabled
while cancellation IPC is already in flight. `scan_screen_test.dart` passed
(`28`), `flutter analyze` passed with analytics suppressed, source-contracts
passed (`481`), and no-malware/product-copy gates passed. Installed local-core
cancel click-through E2E remains partial.

Checkpoint 1833 runtime-verifies Scan-tab service-recovery confirmation
click-through at the Flutter widget/controller/local-core fixture layer.
`scan_screen_test.dart` opens Start Core Service, Open install report, and
Repair installation confirmation dialogs from engine-unavailable diagnostics,
proves Start cancel does not call local-core, and proves each confirm routes
exactly one call to the intended local-core service/report/repair IPC stub.
`scan_screen_test.dart` passed (`32`), `flutter analyze` passed with analytics
suppressed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Installed Windows service/Explorer/repair E2E remains partial.

Checkpoint 1834 runtime-verifies remaining Scan-tab service-recovery cancel
no-op behavior at the Flutter widget/controller/local-core fixture layer.
`scan_screen_test.dart` opens Open install report and Repair installation
confirmation dialogs from engine-unavailable diagnostics and proves Cancel
closes each dialog without calling the matching local-core IPC stub.
`scan_screen_test.dart` passed (`34`), `flutter analyze` passed with analytics
suppressed, source-contracts passed (`481`), and no-malware/product-copy gates
passed. Installed Windows service/Explorer/repair E2E remains partial.

Checkpoint 1835 runtime-verifies Home Stop Protection busy-state gating at the
Flutter widget layer. `settings_accessibility_test.dart` now resets the local
ProviderScope between protection busy-state renders, renders Home with
`ProtectionStatus.protected` and `protectionOperationInFlight=true`, and proves
the Home Stop Protection control is visible but disabled while a protection
action is already in flight. `settings_accessibility_test.dart` passed (`30`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Installed desktop
click/layout E2E remains partial.

Checkpoint 1836 runtime-verifies Home Enable/Stop Protection confirmation
click-through at the Flutter widget/controller/local-core fixture layer.
`settings_accessibility_test.dart` opens Home Enable Protection and Stop
Protection confirmations, proves Cancel does not call Guard/watch IPC stubs,
proves Enable confirm routes one Guard-mode call with `ProtectionMode.balanced`
and no watcher call when no watch roots are configured, and proves Stop confirm
routes one Guard-mode `ProtectionMode.off` call plus one watcher-stop call.
`settings_accessibility_test.dart` passed (`34`), `flutter analyze` passed with
analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed desktop service/driver
click-through E2E remains partial.

Checkpoint 1837 runtime-verifies Protection-tab Enable/Stop Protection
confirmation click-through at the Flutter widget/controller/local-core fixture
layer. `settings_accessibility_test.dart` opens Protection Enable Protection
and Stop Protection confirmations, proves Cancel does not call Guard/watch IPC
stubs, proves Enable confirm routes one Guard-mode call with
`ProtectionMode.balanced` and no watcher call when no watch roots are
configured, and proves Stop confirm routes one Guard-mode `ProtectionMode.off`
call plus one watcher-stop call. `settings_accessibility_test.dart` passed
(`38`), `flutter analyze` passed with analytics suppressed, source-contracts
passed (`481`), and no-malware/product-copy gates passed. Installed desktop
service/driver click-through E2E remains partial.

Checkpoint 1838 runtime-verifies Protection and Settings protection self-test
click-through at the Flutter widget/controller/local-core fixture layer.
`settings_accessibility_test.dart` clicks Protection `Run protection self-test`
and Settings `Run Protection Self-Test`, proves each routes exactly one call to
the local-core self-test stub, and proves the fixture result is rendered.
`settings_accessibility_test.dart` passed (`40`), `flutter analyze` passed with
analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed desktop PowerShell/driver
self-test E2E remains partial.

Checkpoint 1839 runtime-verifies Settings security confirmation click-through
at the Flutter widget/controller/local-core fixture layer. The Settings
Protection mode dialog Cancel path makes no Guard-mode IPC call and preserves
the current profile; Confirm routes one Guard-mode call and persists Lockdown.
The ransomware guard settings dialog Cancel path makes no core policy call and
preserves empty policy lists; Confirm routes one ransomware guard policy call,
persists the protected-root/trusted-process lists, and shows the success
snackbar. The scheduled quick-scan switch Cancel path preserves a disabled
schedule; Confirm persists the app-lifetime detect-only schedule at the current
interval. `settings_accessibility_test.dart` passed (`46`), `flutter analyze`
passed with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed desktop service/local-core
policy E2E and true background/Windows scheduled-task behavior remain partial
or technically limited as documented.

Checkpoint 1840 runtime-verifies Settings reset-configuration confirmation
click-through at the Flutter widget/controller fixture layer. The Reset
configuration dialog Cancel path preserves a non-default protection profile,
scheduled quick-scan state, interval, and developer cloud override settings and
does not show the success snackbar. The Confirm path restores default
configuration, disables the app-lifetime scheduled quick scan, returns
protection status to idle, disables cloud status, and shows the success
snackbar. `settings_accessibility_test.dart` passed (`48`), `flutter analyze`
passed with analytics suppressed, source-contracts passed (`481`), and
no-malware/product-copy gates passed. Installed desktop Settings reset E2E and
active-service/driver stop-before-reset E2E remain partial.

Checkpoint 1841 runtime-verifies Settings log-export confirmation
click-through at the Flutter widget/controller/event-repository fixture layer.
The Export logs dialog Cancel path makes zero export calls and shows no success
or failure snackbar. The Confirm path routes exactly one event-repository
export call, shows the bounded exported-path success snackbar, and records a
`logs_exported` event through controller state. `settings_accessibility_test.dart`
passed (`50`), `flutter analyze` passed with analytics suppressed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed desktop filesystem export E2E and export-path safety remain covered
separately or partial as documented.

Checkpoint 1842 runtime-verifies Updates-tab install and rollback confirmation
click-through at the Flutter widget/controller/update-service fixture layer.
The Download/verify/install dialog Cancel path makes zero update-service calls
and preserves `UpdateStatus.updateAvailable`; Confirm routes exactly one
download, verify, and install service sequence and transitions to
`UpdateStatus.readyToRestart` with install-started/ready events. The Rollback
dialog Cancel path makes zero rollback calls and preserves
`UpdateStatus.updateAvailable`; Confirm routes exactly one rollback service
call and transitions to `UpdateStatus.readyToRestart` with
rollback-started/ready events. `update_ui_test.dart` passed (`8`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Installed updater service,
elevation, package application, and rollback filesystem E2E remain partial.

Checkpoint 1843 runtime-verifies Allowlist remove confirmation click-through at
the Flutter widget/controller/local-core fixture layer. The Allowlist Remove
dialog Cancel path makes zero local-core trust-store calls, preserves the active
entry, and keeps the row visible. The Confirm path routes exactly one
`removeAllowlistEntry` local-core call for the selected entry ID, marks the row
inactive in controller state after refresh, records `allowlist_entry_removed`,
and renders the empty-state UI. `allowlist_screen_test.dart` passed (`3`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Installed local-core
trust-store E2E remains partial.

Checkpoint 1844 runtime-verifies Protected Apps build-hash confirmation
click-through at the Flutter widget/controller/hash-service fixture layer. The
dialog Cancel path makes zero hash-service calls, preserves empty build-hash
evidence, and shows no success snackbar. The Confirm path routes exactly one
hash call to the selected benign fixture path, saves the returned SHA-256,
sets the app verification status to verified, records `file_hash_calculated`,
and shows `Build hash calculated.`. The Protected Apps row now constrains and
ellipsizes long trailing evidence so SHA-256 text cannot consume the whole
`ListTile` width. `protected_apps_screen_test.dart` passed (`2`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Installed filesystem/hash
E2E remains partial.

Checkpoint 1845 runtime-verifies Protected Apps detected-row selection
click-through at the Flutter widget/controller/config-repository fixture layer.
The Select dialog Cancel path preserves the existing manual app, does not add
the detected path to scan scope, records no `protected_app_selected` event, and
shows no success snackbar. The Confirm path saves the detected app identity,
source, and path, adds that path to scan scope, sets app-detection status to
detected, records `protected_app_selected`, and shows
`Protected app selected.`. The row is scrolled into view in the widget test, and
`_AppRow` now wraps `ListTile` in a transparent `Material` so row ink/hit
feedback is not hidden by the panel decoration. `protected_apps_screen_test.dart`
passed (`4`), `flutter analyze` passed with analytics suppressed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed Protected Apps desktop E2E remains partial.

Checkpoint 1846 runtime-verifies the Updates-tab `Check for updates` control at
the Flutter widget/controller/update-service fixture layer. The enabled path
routes exactly one update-service `checkForUpdate` call, transitions state to
`UpdateStatus.updateAvailable`, stores update metadata for version `0.2.16`,
renders `Status: Update available`, and records `update_check_started` plus
`update_available` events. The busy path renders the button as `Checking`,
keeps it disabled, and makes zero update-service calls. `update_ui_test.dart`
passed (`10`), `flutter analyze` passed with analytics suppressed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed update-service/network/package E2E remains partial.

Checkpoint 1847 runtime-verifies the Settings `Check for updates` control at
the Flutter widget/controller/update-service fixture layer. The enabled path
scrolls the Settings update button into view, routes exactly one update-service
`checkForUpdate` call, transitions state to `UpdateStatus.updateAvailable`,
stores update metadata for version `0.2.16`, renders the Settings update status
as available, and records `update_check_started` plus `update_available` events.
The busy path renders the Settings button as `Checking`, disables it, hides the
idle label, and makes zero update-service calls. `settings_accessibility_test.dart`
passed (`52`), `flutter analyze` passed with analytics suppressed,
source-contracts passed (`481`), and no-malware/product-copy gates passed.
Installed update-service/network/package E2E remains partial.

Checkpoint 1848 runtime-verifies the Settings `Download, verify, install`
control at the Flutter widget/controller/update-service fixture layer. The
dialog Cancel path makes zero update-service calls, preserves
`UpdateStatus.updateAvailable`, and records no `update_install_started` event.
The Confirm path scrolls the Settings install button into view, routes exactly
one download/verify/install service sequence, transitions to
`UpdateStatus.readyToRestart`, and records `update_install_started` plus
`update_install_ready` events. `settings_accessibility_test.dart` passed (`54`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Installed updater-service,
elevation, and package-apply E2E remain partial.

Checkpoint 1849 runtime-verifies the Settings `Test Cloud Connection` control at
the Flutter widget/controller/API-client fixture layer. The enabled path scrolls
the Settings cloud button into view, routes exactly one API health-check call,
transitions cloud status to online, clears the public in-flight flag, and records
`cloud_health_check_started` plus `cloud_online` events. The busy path renders
the Settings button as `Checking Cloud`, disables it, hides the idle label, and
makes zero API health-check calls. `settings_accessibility_test.dart` passed
(`56`), `flutter analyze` passed with analytics suppressed, source-contracts
passed (`481`), and no-malware/product-copy gates passed. Live cloud/backend E2E
remains partial.

Checkpoint 1850 reconciles the UI control inventory with existing checkpoint
1838 runtime evidence for the Protection and Settings self-test controls. The
client UI matrix now marks Protection `Run protection self-test` and Settings
`Run Protection Self-Test` as widget/runtime verified in checkpoint 1838 instead
of source-accounted only. Current verification reran
`settings_accessibility_test.dart` (`56`), `flutter analyze`, source-contracts
(`481`), and no-malware/product-copy gates. Installed PowerShell/driver
self-test E2E remains partial.

Checkpoint 1851 runtime-verifies Allowlist Refresh click-through at the Flutter
widget/controller/local-core fixture layer. The Allowlist screen startup refresh
routes one `listAllowlist` call and populates the active row; clicking Refresh
routes exactly one additional `listAllowlist` call, preserves the row, and
clears `allowlistRefreshInFlight`. `allowlist_screen_test.dart` passed (`4`),
`flutter analyze` passed with analytics suppressed, source-contracts passed
(`481`), and no-malware/product-copy gates passed. Installed local-core
trust-store E2E remains partial.

Checkpoint 1852 reconciles the UI control inventory with existing checkpoint
1817 runtime evidence for Quarantine restore/delete controls. The client UI
matrix now marks Quarantine `Restore / Keep` and `Delete permanently` as
widget/runtime verified in checkpoint 1817 instead of source-accounted only.
Current verification reran `quarantine_screen_test.dart` (`5`),
`flutter analyze`, source-contracts (`481`), and no-malware/product-copy gates.
Installed local-core quarantine restore/delete E2E remains partial.

Checkpoint 1853 reconciles the UI control inventory with existing checkpoint
1822 runtime evidence for Scan-result Keep / Ignore. The client UI matrix now
marks `Keep / Ignore` as widget/runtime verified in checkpoint 1822 instead of
source-accounted only. Current verification reran `scan_screen_test.dart` (`34`),
`flutter analyze`, source-contracts (`481`), and no-malware/product-copy gates.
Installed Scan-result click/layout E2E remains partial.

Checkpoint 1854 reconciles the UI control inventory with existing checkpoints
1818-1821 runtime evidence for Scan-result Quarantine, Add to allowlist, Mark
false positive, and Mark malicious. The client UI matrix now marks those actions
as widget/runtime verified instead of source-accounted only. Current verification
reran `scan_screen_test.dart` (`34`), `flutter analyze`, source-contracts
(`481`), and no-malware/product-copy gates. Installed Scan-result/local-core E2E
remains partial.

Checkpoint 1855 reconciles the UI control inventory with existing checkpoints
1833-1834 runtime evidence for Scan Start Core Service, Open install report, and
Repair installation. The client UI matrix now marks those service-recovery
actions as widget/runtime verified instead of source-accounted only. Current
verification reran `scan_screen_test.dart` (`34`), `flutter analyze`,
source-contracts (`481`), and no-malware/product-copy gates. Elevated Windows
service, Explorer shell-launch, and repair E2E remain partial.

Checkpoint 1856 reconciles the UI control inventory with existing checkpoints
1830-1831 runtime evidence for Protection Run Quick Scan. The client UI matrix
now marks the Protection shortcut as widget/runtime verified instead of
source-accounted only. Current verification reran `settings_accessibility_test.dart`
(`56`), `flutter analyze`, source-contracts (`481`), and no-malware/product-copy
gates. Packaged desktop click-through E2E remains partial.

Checkpoint 1857 runtime-verifies Protected Apps Add file or app and Add folder
confirmation boundaries at the Flutter widget/controller fixture layer.
`protected_apps_screen_test.dart` opens both dialogs, proves Cancel does not save
protected-app configuration or scan scope, and proves confirmed unsupported
platform paths report visible no-save outcomes without opening OS picker success
flows. The client UI matrix now marks these controls widget/runtime verified for
cancel and unsupported-confirm behavior. Current verification reran
`protected_apps_screen_test.dart` (`8`), `flutter analyze`, source-contracts
(`481`), and no-malware/product-copy gates. OS picker success E2E remains
partial.

Checkpoint 1858 reconciles the UI control inventory with existing checkpoint
1790 runtime evidence for Protected Apps Rescan busy-state behavior. The client
UI matrix now marks Rescan as widget/runtime busy-state verified instead of
source-accounted only. Current verification reran `settings_accessibility_test.dart`
(`56`), `flutter analyze`, source-contracts (`481`), and no-malware/product-copy
gates. Detection click-through E2E remains partial.

Checkpoint 1859 reconciles the UI control inventory with existing checkpoints
1677-1680 runtime evidence for Settings Developer options, API endpoint, Project
ID, Public Client Key, Save developer override, and Disable developer override.
The client UI matrix now marks these controls widget/runtime verified instead of
source-accounted only. Current verification reran `settings_accessibility_test.dart`
(`56`), `flutter analyze`, source-contracts (`481`), and no-malware/product-copy
gates. Live backend and packaged Settings E2E remain partial.

Checkpoint 1860 reconciles the UI control inventory with existing checkpoint
1839 runtime evidence for Settings ransomware protected folders, ransomware
trusted processes, and scan interval controls. The client UI matrix now marks
the ransomware text fields and scan interval dropdown widget/runtime verified
instead of source-accounted only. Current verification reran
`settings_accessibility_test.dart` (`56`), `flutter analyze`, source-contracts
(`481`), and no-malware/product-copy gates. Installed local-core/service E2E and
true background scheduling remain partial or technically limited.

Checkpoint 1861 runtime-verifies Scan Retry engine/service status click-through
at the Flutter widget/controller/local-core fixture layer. `scan_screen_test.dart`
opens engine-unavailable diagnostics, clicks Retry, proves exactly one
local-core health summary call, confirms ready engine state is applied, and
confirms the health-check busy flag clears. The client UI matrix now marks Scan
Retry widget/runtime verified instead of source-accounted only. Current
verification reran `scan_screen_test.dart` (`35`), `flutter analyze`,
source-contracts (`481`), and no-malware/product-copy gates. Installed
local-core health IPC E2E remains partial.

Checkpoint 1862 runtime-verifies Onboarding Continue and Privacy details
navigation at the Flutter widget/router fixture layer. `onboarding_screen_test.dart`
starts on `/onboarding`, clicks Continue, proves onboarding state is persisted
and Home renders, then separately clicks Privacy details and proves Privacy
renders without marking onboarding complete. The client UI matrix now marks
these Onboarding controls widget/runtime verified instead of source-accounted
only. Current verification ran `onboarding_screen_test.dart` (`2`),
`flutter analyze`, source-contracts (`481`), and no-malware/product-copy gates.
Packaged navigation E2E remains partial.

Checkpoint 1863 runtime-verifies Home View all security events navigation at
the Flutter widget/router fixture layer. `home_navigation_test.dart` starts on
`/home`, clicks View all, and proves the Logs screen renders local-event history
without invoking destructive behavior. The client UI matrix now marks this Home
control widget/runtime verified instead of source-accounted only. Current
verification ran `home_navigation_test.dart` (`1`), `flutter analyze`,
source-contracts (`481`), and no-malware/product-copy gates. Packaged navigation
E2E remains partial.

Checkpoint 1864 runtime-verifies the client route matrix at the Flutter
widget/router fixture layer. `route_matrix_test.dart` uses the real
`ZentorShell`, desktop sidebar, mobile bottom navigation, and `GoRouter`
routes with marker pages to prove `/home`, `/scan`, `/protection`,
`/quarantine`, `/allowlist`, `/logs`, `/device`, `/updates`, and `/settings`
are reachable from desktop navigation, that Settings can route to `/privacy`,
and that the mobile bottom navigation exposes only Home, Scan, Quarantine, and
Settings. The checkpoint also bounds compact Home metric-card text and the
Security Events header to avoid overflow in constrained panes. Current
verification ran `route_matrix_test.dart` (`3`), `flutter analyze`,
source-contracts (`483`), and no-malware/product-copy gates. Packaged Windows
navigation E2E remains partial.

Checkpoint 1865 runtime-verifies the Privacy policy point list at the Flutter
widget layer. `privacy_screen_test.dart` renders `PrivacyScreen`, verifies the
eleven visible policy points, and asserts the no credential theft, no browser
cookie reading, no hiding, no silent kernel-driver install, and no automatic
permanent deletion claims are visible. The checkpoint also makes the Privacy
screen independently scrollable so direct renders and smaller containers do not
overflow while keeping shell/onboarding navigation working. Current
verification ran `privacy_screen_test.dart`, `onboarding_screen_test.dart`, and
`route_matrix_test.dart` (`6`), `flutter analyze`, source-contracts (`484`),
and no-malware/product-copy gates. Packaged navigation/layout E2E remains
partial.

Checkpoint 1866 runtime-verifies the Security Events Export logs control at the
Flutter widget/controller fixture layer. `logs_screen_test.dart` renders
`LogsScreen`, proves Cancel leaves export calls at zero, proves Confirm calls
`controller.exportLogs(confirmed: true)` once and shows the exported path
snackbar, and proves the button is disabled with the `Exporting logs` label
while `logExportInFlight` is true. Existing controller and Settings tests still
cover bounded export-path/failure handling and shared single-flight behavior;
current verification ran `logs_screen_test.dart` (`3`), `flutter analyze`,
source-contracts (`484`), and no-malware/product-copy gates. Installed
filesystem/export E2E remains partial.

Checkpoint 1867 runtime-verifies the Device and protection health cards at the
Flutter widget/provider fixture layer. `device_screen_test.dart` injects a
bounded `DeviceIntegritySummary` and app state, then proves the System,
Hardware, App version, Privacy, Avorax Services, Avorax Native Engine,
Real-time Protection, and Permissions cards render real platform/protection
evidence including native signature/rule counts, native ML production readiness,
driver status, service states, privacy posture, and current-user evidence. The
same test also verifies platform-info errors are control/NUL-normalized before
display. Current verification ran `device_screen_test.dart` (`2`),
`flutter analyze`, source-contracts (`485`), and no-malware/product-copy gates.
Live platform-info host E2E remains partial.

Checkpoint 1868 runtime-verifies the Settings native-engine status rows at the
Flutter widget/state fixture layer. `settings_native_status_test.dart` injects
app-state evidence and proves Settings renders engine availability, native
status, IPC mode, network exposure, native/AI self-tests, ProgramData and
install/engine roots, checked engine paths, asset directories, native
signature/rule counts, compatibility-engine status, reputation detail, Local AI
status, native ML model/schema/production-readiness, and visible service/guard
driver status rows. Current verification ran `settings_native_status_test.dart`
(`1`), `flutter analyze`, source-contracts (`485`), and no-malware/product-copy
gates. Installed local-core health E2E remains partial.

Checkpoint 1869 re-verifies the full Flutter client regression surface after
the UI route/control/status matrix runtime pass. Full `apps/zentor_client`
tests pass with `--concurrency=1` and with the default parallel runner, focused
hash-service and update-controller regressions pass, `flutter analyze` reports
no issues, source-contracts pass (`485`), and no-malware/product-copy gates
pass. The checkpoint also removes a stale update-controller source-marker
expectation and replaces a disk-heavy oversized-file hash fixture with a small
test-only bounded-limit fixture. Packaged desktop click-through, service/update
E2E, and signed-driver validation remain partial.

Checkpoint 1870 hardens Windows release-prerequisite evidence handling:
`tools/windows/avorax-release-prereq-check.ps1` now requires `-ReportPath` to
resolve inside the repository before atomic JSON evidence is written. A negative
outside-temp-path fixture failed visibly without creating the outside report,
normal host-only evidence still writes inside `.workflow`, source-contracts
passed (`485`), and no-malware/product-copy gates passed. Current host-only
release blockers remain no .NET SDK inventory, unavailable symlink support, and
missing Visual Studio Desktop C++ components.

Checkpoint 1871 hardens installer-stage and installed-smoke manifest path
validation: both `tools/windows/avorax-installer-stage-test.ps1` and
`tools/windows/avorax-installed-smoke-test.ps1` reject leading, trailing, and
doubled separators after slash normalization before duplicate-path and
staged/installed hash evidence is trusted. A runtime helper fixture verifies the
boundary in both scripts, source-contracts passed (`486`), and no-malware/product
copy gates passed. Full packaged installer and installed-service E2E remain
partial.

Checkpoint 1872 hardens update-package build path scoping:
`tools/update/avorax-build-update-package.ps1` now rejects `PayloadRoot` and
`OutputDir` values that resolve to the repository root itself, preventing
accidental whole-repository payload enumeration or root-level update output. A
negative `-PayloadRoot .` runtime fixture failed before signer/package output and
left the requested output directory absent, source-contracts passed (`487`), and
no-malware/product-copy gates passed. Signed package build/apply E2E remains
partial.

Checkpoint 1873 hardens update-service staging ID derivation:
`core/avorax_update_service/src/update_applier.rs` now rejects the exact signed
manifest package id `.` before joining it to the ProgramData staging root.
Focused update package id tests passed (`2`), full `avorax_update_service` tests
passed (`176`), `cargo fmt --all -- --check` passed, source-contracts passed
(`487`), and no-malware/product-copy gates passed. Installed update apply and
rollback E2E remain partial.

Checkpoint 1874 hardens update-service rollback snapshot name derivation:
`core/avorax_update_service/src/rollback.rs` now rejects the exact rollback
snapshot version `.` before joining it to the rollback root. Focused rollback
snapshot version tests passed (`1`), full `avorax_update_service` tests passed
(`176`), `cargo fmt --all -- --check` passed, source-contracts passed (`487`),
and no-malware/product-copy gates passed. Installed rollback E2E remains
partial.

Checkpoint 1875 hardens update manifest safe-token validation:
`core/avorax_update_service/src/update_manifest.rs` now rejects the exact token
`.` for manifest fields such as `package_id`, `public_key_id`, and migration
step IDs. Focused update-manifest tests passed (`8`), full
`avorax_update_service` tests passed (`177`), `cargo fmt --all -- --check`
passed, source-contracts passed (`487`), and no-malware/product-copy gates
passed. Installed update apply and rollback E2E remain partial.

Checkpoint 1876 hardens update-service log name validation:
`core/avorax_update_service/src/logging.rs` now rejects the exact update log name
`.` before joining it to the update log directory. Focused update log name tests
passed (`1`), full `avorax_update_service` tests passed (`177`),
`cargo fmt --all -- --check` passed, source-contracts passed (`487`), and
no-malware/product-copy gates passed. Installed service log-write E2E remains
partial.

Checkpoint 1877 hardens driver signing build-output scope:
`core/zentor_windows_minifilter/scripts/sign-test-driver.ps1` and
`core/zentor_windows_process_guard/scripts/sign-test-driver.ps1` now reject
`BuildOutputDir` values that resolve to the repository root itself. Negative
runtime fixtures for both scripts failed before setup/signing with no report file
created, source-contracts passed (`488`), and no-malware/product-copy gates
passed. Real driver signing remains blocked by host signing/WDK prerequisites.

Checkpoint 1878 hardens development driver certificate export scope:
`core/zentor_windows_minifilter/scripts/create-test-cert.ps1` now rejects
`CertOutputDir` values that resolve to the repository root itself. A negative
runtime fixture failed before certificate creation with no report file and no
root `ZentorDriverTest.cer` export, source-contracts passed (`489`), and
no-malware/product-copy gates passed. Real certificate creation remains gated by
`-ConfirmCreateTestCertificate`.

Checkpoint 1879 hardens protection self-test report scope:
`tools/windows/zentor-protection-selftest.ps1` now rejects `ReportPath` values
that resolve to the repository root itself. A negative runtime fixture failed
with the new report-path error before Cargo/build/self-test work, source-
contracts passed (`489`), and no-malware/product-copy gates passed. Real driver
protection self-test remains blocked by host driver prerequisites.

Checkpoint 1880 hardens driver self-test report scopes:
`core/zentor_windows_minifilter/scripts/run-driver-self-test.ps1` and
`core/zentor_windows_process_guard/scripts/run-process-guard-self-test.ps1` now
reject `ReportPath` values that resolve to the repository root itself before
creating report directories, launching Guard Service, querying `sc.exe`, or
writing catch-block reports. Negative runtime fixtures for both scripts failed
with the new report-path errors, source-contracts passed (`490`), and
no-malware/product-copy gates passed. Real driver self-tests remain blocked by
host driver prerequisites.

Checkpoint 1881 hardens driver install/uninstall report scopes:
minifilter and process-guard install/uninstall wrappers now reject `ReportPath`
values that resolve to the repository root itself before report directory
creation, setup checks, INF validation, driver commands, or catch-block report
writes. Negative runtime fixtures for all four scripts failed with the new
report-path errors, source-contracts passed (`490`), and no-malware/product-copy
gates passed. Real driver install/uninstall remains gated by confirmation and
host prerequisites.

Checkpoint 1882 hardens driver log output scope:
`core/zentor_windows_minifilter/scripts/collect-driver-logs.ps1` now rejects
`OutputPath` values that resolve to the repository root itself before `fltmc.exe`,
`sc.exe`, Event Log reads, or output-file writes can start. A negative runtime
fixture failed with the new output-path error, source-contracts passed (`490`),
and no-malware/product-copy gates passed. Real log collection remains partial
until an installed driver host is available.

Checkpoint 1883 hardens driver setup/build report scopes:
`core/zentor_windows_minifilter/scripts/setup-dev-env-check.ps1`,
`core/zentor_windows_minifilter/scripts/build-driver.ps1`, and
`core/zentor_windows_process_guard/scripts/build-driver.ps1` now reject
`ReportPath` values that resolve to the repository root itself before tool
discovery, setup delegation, MSBuild/linker work, or catch-block report writes.
Negative runtime fixtures for all three scripts failed with the new report-path
errors, source-contracts passed (`491`), and no-malware/product-copy gates
passed. Real driver setup/build remains blocked by host prerequisites.

Checkpoint 1884 hardens the ZNE release-gate report scope:
`tools/zne/zne-release-gate.ps1` now rejects `-ReportPath` values that resolve
to the repository root itself before Cargo path validation, required artifact
checks, native-engine builds, or release-gate tests. A negative runtime fixture
failed with the new report-path error while using a deliberately nonexistent
Cargo path, source-contracts passed (`492`), and no-malware/product-copy gates
passed. Full ZNE/release approval remains blocked by host and packaging
prerequisites.

Checkpoint 1885 hardens the Windows installer stage-test scope:
`tools/windows/avorax-installer-stage-test.ps1` now rejects `-StagePath` values
that resolve to the repository root itself or outside the repository before
payload checks, manifest reads, hash comparisons, installer artifact
enumeration, or WiX source scans. A negative runtime fixture failed with the
new stage-path error, source-contracts passed (`493`), and
no-malware/product-copy gates passed. Full installer stage/package approval
remains blocked by missing Windows stage artifacts and installed E2E evidence.

Checkpoint 1886 hardens installed-smoke evidence boundaries:
`tools/windows/avorax-installed-smoke-test.ps1` now rejects explicit
`-InstallPath` and `-ProgramDataPath` values that resolve inside the repository
before installed payload checks, release-manifest reads, hash comparisons,
ProgramData checks, service inspection, or core health probing. A negative
runtime fixture failed with the new install-path error, source-contracts passed
(`494`), and no-malware/product-copy gates passed. Full installed E2E remains
blocked until installer artifacts are built and installed on a suitable host.

Checkpoint 1887 hardens the Windows release-gate self-test report boundary:
`tools/windows/zentor-release-gate.ps1` now resolves `-SelfTestReport` relative
to the repository and rejects values that resolve to the repository root itself
or outside the repository before Cargo/Python/.NET/Flutter validation or any
release sub-gate work. A negative runtime fixture failed with the new
self-test-report path error while using deliberately nonexistent tool paths,
source-contracts passed (`495`), and no-malware/product-copy gates passed. Full
release approval remains blocked by package/install E2E and signed-driver
evidence.

Checkpoint 1888 hardens MSI builder driver-package scope:
`installer/windows/build-msi.ps1` now resolves explicit `-DriverPackageDir`
values relative to the repository and rejects paths that resolve to the
repository root itself or outside the repository before .NET/Flutter/Cargo
validation, app staging, driver package traversal, or installer packaging. A
negative runtime fixture failed with the new driver-package path error while
using deliberately nonexistent tool paths, source-contracts passed (`496`), and
no-malware/product-copy gates passed. Full MSI/setup approval remains blocked by
Windows packaging, installed E2E, and signed-driver evidence.

Checkpoint 1889 hardens MSI builder required-driver validation: when
`-RequireDriverPackage` is set, `installer/windows/build-msi.ps1` now verifies
the signed minifilter driver package directory, rejects reparse trees, and
requires `ZentorAvFilter.sys`, `ZentorAvFilter.inf`, and a `.cat` catalog before
.NET/Flutter/Cargo validation, app staging, driver package copying, or installer
packaging. A negative runtime fixture failed with an explicit
missing-driver-package error while using deliberately nonexistent tool paths,
source-contracts passed (`497`), and no-malware/product-copy gates passed. Full
MSI/setup approval remains blocked by Windows packaging, installed E2E, and
signed-driver evidence.

Checkpoint 1890 hardens the generated elevated driver-install helper report
scope: the `avorax-install-driver.ps1` generated by
`installer/windows/build-msi.ps1` now rejects explicit `-ReportPath` values
outside Avorax ProgramData reports, or the reports directory itself, before
driver INF inspection, System32 tool lookup, certificate import, `bcdedit`,
`pnputil`, `sc`, or `fltmc` work. A temporary extracted-helper negative fixture
failed with the new ProgramData report-path error, source-contracts passed
(`498`), and no-malware/product-copy gates passed. Real driver install evidence
remains blocked by signed-driver/host prerequisites.

Checkpoint 1891 hardens the generated elevated driver-install helper INF scope:
the `avorax-install-driver.ps1` generated by `installer/windows/build-msi.ps1`
now rejects explicit `-DriverInf` values outside the installed Avorax driver
package directory and requires the leaf name `ZentorAvFilter.inf` before report
writing, System32 tool lookup, certificate import, `bcdedit`, `pnputil`, `sc`,
or `fltmc` work. A temporary extracted-helper negative fixture failed with the
new driver-INF path error, source-contracts passed (`499`), and
no-malware/product-copy gates passed. Real driver install evidence remains
blocked by signed-driver/host prerequisites.

Checkpoint 1892 hardens generated elevated driver-install helper root evidence:
the `avorax-install-driver.ps1` generated by `installer/windows/build-msi.ps1`
now requires the installed Avorax driver package directory to exist as a
non-reparse directory before deriving the default `ZentorAvFilter.inf`; missing
installed driver package evidence fails with an explicit blocker instead of a
raw `Get-Item` error or blind path join. A temporary extracted-helper negative
fixture failed with the new missing-driver-package-root error before
report/system-tool/driver work, source-contracts passed (`499`), and
no-malware/product-copy gates passed. Real driver install evidence remains
blocked by signed-driver/host prerequisites.

Checkpoint 1659 adds Flutter local-core IPC runtime evidence for malformed final
scan-report fields: `local_core_ipc_diagnostics_test.dart` passed (`43`)
including malformed status/kind/action-mode, required/optional numeric counters,
current path, and message diagnostics. This verifies explicit scan-error
evidence before compatibility fallback values are displayed.

Checkpoint 1660 adds Flutter local-core IPC runtime evidence for required threat
row evidence: `local_core_ipc_diagnostics_test.dart` passed (`44`) including
malformed threat label, engine, timestamp, size, enum, and reason-summary
fixtures. Malformed rows are dropped with explicit scan-error evidence instead
of displaying fabricated threat labels, engines, timestamps, zero sizes, enum
defaults, or generic reason text.

Checkpoint 1661 adds Flutter local-core IPC runtime evidence for quarantine
record required evidence: `local_core_ipc_diagnostics_test.dart` passed (`45`)
including malformed quarantine record ID, timestamp, status, execution booleans,
file size, detection/engine labels, paths, source, and action fixtures. The
list parser fails visibly instead of returning fallback quarantine rows.

Checkpoint 1662 adds Flutter local-core IPC runtime evidence for allowlist entry
required evidence: `local_core_ipc_diagnostics_test.dart` passed (`46`)
including malformed allowlist ID, type, active state, timestamp, reason,
creator, file SHA/path, and hash SHA/path fixtures. The list parser fails
visibly instead of returning fallback trust rows.

Checkpoint 1663 adds Flutter local-core IPC runtime evidence for risk-score
required evidence: `local_core_ipc_diagnostics_test.dart` passed (`47`)
including missing/malformed risk score, verdict, confidence, recommended action,
risk reasons, and risk engines. Threat rows with invalid top-level risk evidence
are dropped, while malformed risk reasons are omitted without default reason
metadata.

Checkpoint 1664 adds Flutter Guard self-test runtime evidence:
`local_core_ipc_diagnostics_test.dart` passed (`48`) including malformed
self-test step rows. The self-test formatter now has fixture coverage for
non-object rows, malformed names, missing names, malformed reasons, malformed
pass flags, and valid passing rows producing explicit PASS/FAIL evidence.

## Detection Pipeline

| Engine/control | Primary source | Real responsibility | Status | Verification or blocker |
| --- | --- | --- | --- | --- |
| Avorax Native Engine (ANE) orchestrator | `core/zentor_native_engine/src/engine.rs`, `config.rs`, `detection_provider.rs`, `verdict/`, `analyzers/`, `scan/content_reader.rs` | Primary offline non-mutating detection and verdict source for signatures, rules, static analysis, ML, heuristics, trust stores, controlled engine asset configuration, and sampled-content actual-size evidence | Detection runtime verified; native mutation disabled; installed E2E partial | Engine docs and assets are present; checkpoint 1616 verifies native sampled-content actual-size evidence and large-file full-hash/sample-limit behavior with focused Cargo filters (`1 passed; 0 failed` each); checkpoint 1617 clears targeted analyzer/parser rustfmt drift, removes native test unused-import warnings, verifies extension/ZIP/PE parser fixtures with eleven focused Cargo filters (`1 passed; 0 failed` each), and proves broad native-engine tests pass (`284 passed; 0 failed` lib tests plus `6 passed; 0 failed` signature-compiler tests); native engine default-root hardening source-accounted in checkpoint 809; native engine env-root NUL/parent-traversal rejection source-accounted in checkpoint 1209; native scan-summary error detail bounds source-accounted in checkpoint 1115; checkpoint 2183 verifies all current `435 + 6` native tests and makes Local Core the only supported production quarantine lifecycle owner |
| Native signature matcher | `core/zentor_native_engine/src/signatures/`, `core/zentor_native_engine/src/bin/zentor-signature-compiler.rs`, `assets/zentor_native/signatures/` | Exact hashes, byte/string/signature packs, EICAR test signature, family indicators, pack compilation, strict signature-pack schemas, strict signature-compiler CLI parsing, bounded pack reads, and metadata/hash verification | Runtime fixture verified; safe EICAR only | No live malware retained; checkpoint 1640 verifies native `signature_pack` (`16`) plus representative bundled `.zsig` validator runs (`zentor_core.zsig`, `zentor_realworld_hashes.zsig`) and native-engine rustfmt. Earlier evidence remains: signature compiler source/output hardening source-accounted in checkpoint 858; native signature/rule pack actual-byte read limits source-accounted in checkpoint 1271; signature compiler source actual-byte read limits source-accounted in checkpoint 1279; indicator-pack validator shape validation source/fixture/asset-accounted in checkpoint 998; signature compiler output-parent default honesty source-accounted in checkpoint 1020; signature compiler CLI strictness verified in checkpoint 1560 |
| Checkpoint 1619 native trust/signature fixtures | `core/zentor_native_engine/src/trust/microsoft_trust.rs`, `core/zentor_native_engine/src/bin/zentor-signature-compiler.rs`, `core/zentor_native_engine/src/tests/mod.rs` | Focused runtime coverage for structured Authenticode JSON Microsoft trust decisions, Authenticode candidate path guarding, removed placeholder native update export, bounded signature-compiler source reads, and threat-intel generated-signature wiring | Runtime fixture verified; symlink partial | Checkpoint 1619 verifies five Authenticode JSON trust fixtures, `authenticode_candidate_rejects_directory`, `microsoft_signature_path_guard_uses_non_following_inspection`, `native_engine_does_not_export_placeholder_updates_namespace`, `signature_compiler_rejects_oversized_source_before_parse`, and `threat_intel_hash_pack_signature_matches_without_dead_context` with focused Cargo filters (`1 passed; 0 failed` each for matching tests); `authenticode_candidate_rejects_symbolic_link` is Unix-gated and reports `0 tests` on Windows; no live malware used |
| Checkpoint 2082 native Authenticode target-path invocation | `core/zentor_native_engine/src/trust/microsoft_trust.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Runtime proof that native Microsoft publisher-trust inspection can invoke checked WindowsPowerShell with `-EncodedCommand` and a target path without positional-argument ambiguity | Runtime fixture verified for unsigned file; live signed publisher E2E and replacement-race proof remain partial | Checkpoint 2082 replaces the old `.arg(path.as_os_str())` target handoff after `-EncodedCommand` with process-only `AVORAX_AUTHENTICODE_TARGET_PATH`, read by the encoded helper before `Get-AuthenticodeSignature -LiteralPath $target`. The checked local PowerShell path, UTF-16LE encoded helper, bounded stdout/stderr runner, timeout, and fail-visible diagnostics are preserved. Runtime proof `authenticode_probe_accepts_unsigned_file_without_encoded_command_argument_error` verifies an unsigned temporary `.exe` returns `false` instead of the host PowerShell error `Cannot process command because a command is already specified with -Command or -EncodedCommand.` Native `trust` passed (`56`), local-core `quick_scan_reports` passed (`32`), source-contracts passed (`541`), and the full small-threat MVP verifier/report-validator passed (`148` steps in `344.9s`) for `.workflow\ultracode\avorax-hardening\results\2082-small-threat-mvp-full-report.json`. This does not grant trust to unsigned files, does not use ambient `PATH`, does not run live malware, and does not prove signed-publisher policy behavior beyond existing parser fixtures and this unsigned-file invocation regression. |
| Checkpoint 2083 native Authenticode Microsoft-signed probe | `core/zentor_native_engine/src/trust/microsoft_trust.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Positive runtime proof that the checked WindowsPowerShell binary is accepted as Microsoft-signed through the same safe Authenticode helper path used by publisher-trust inspection | Runtime fixture verified for Microsoft-signed Windows binary; broader signed-publisher policy E2E and replacement-race proof remain partial | Checkpoint 2083 adds `authenticode_probe_accepts_microsoft_signed_windows_powershell_binary`, resolving the checked local WindowsPowerShell helper and requiring `microsoft_signature_verdict` to return `true`. The existing unsigned-file runtime regression still returns `false`, so the positive Microsoft-signed proof does not weaken fail-closed unsigned behavior. The small-threat MVP verifier and report validator now require both regressions under `Windows Authenticode unsigned-file and Microsoft-signed probe regressions`. Native rustfmt passed, source-contracts passed (`541`), `authenticode_probe_accepts` passed (`2`), `authenticode_probe` passed (`4`), native `trust` passed (`57`), local-core `quick_scan_reports` passed (`32`), and the full small-threat MVP verifier/report-validator passed (`149` steps in `351.9s`) for `.workflow\ultracode\avorax-hardening\results\2083-small-threat-mvp-full-report.json`. No live malware, ambient `PATH`, machine-wide install, or pre-execution blocking claim is involved. |
| Checkpoint 1620 native hash/signature/rule fixtures | `core/zentor_native_engine/src/trust/`, `core/zentor_native_engine/src/signatures/`, `core/zentor_native_engine/src/rules/`, `core/zentor_native_engine/src/tests/mod.rs` | Focused runtime coverage for exact/malformed native hash trust, signature hash validation, suppression-store hash validation, rule compiler validation, rule-pack integrity validation, and rule VM diagnostics | Runtime fixture verified; broader installed/E2E partial | Checkpoint 1620 verifies fifteen native hash/signature/suppression focused Cargo filters (`1 passed; 0 failed` each), `rule_compiler` (`13 passed; 0 failed`), `rule_pack_validation` (`6 passed; 0 failed`), `rule_vm_reports` (`2 passed; 0 failed`), and `compiler_outputs_pack_metadata_and_hash` (`1 passed; 0 failed`); no live malware used |
| Checkpoint 1621 native pack tooling fixtures | `tools/zentor_intel/`, `assets/zentor_native/signatures/`, `assets/zentor_native/rules/`, `core/zentor_native_engine/src/signatures/`, `core/zentor_native_engine/src/rules/` | Python tooling and Rust runtime agree on sorted-key canonical `pack_sha256` validation for native signature/rule packs, required-context checks, pack path/loader checks, and bundled non-EICAR pack coverage | Runtime/tooling verified; installed E2E partial | Checkpoint 1621 validates all bundled signature packs and rule packs with `validate_indicator_pack.py`; native focused Cargo filters pass: `repo_native_packs_detect_more_than_eicar` (`1 passed`), `signature_pack_loads_and_counts_builtin` (`1 passed`), `rule_pack_loads` (`1 passed`), `pack_loader` (`6 passed`), `pack_hash` (`2 passed`), `rule_pack` (`17 passed`), and `required_context` (`3 passed`); no live malware used |
| Checkpoint 1622 error/defaulting and size-bound fixtures | `core/zentor_guard_service/src/`, `core/zentor_local_core/src/`, `core/zentor_native_engine/src/` | Focused runtime coverage for fail-visible corrupt/oversized trust stores, YARA/rule metadata, training labels, guard-mode config, known-bad caches, quarantine metadata, AI/native ML metadata, scan-walker errors, and app-control/native trust hash validation | Runtime fixture verified; warning debt and installed E2E partial | Checkpoint 1622 verifies Guard process/cache/config/serialization/direct-start/AI metadata filters, local-core app-control/YARA/AI/allowlist/ransomware/training-label/hash-validation filters, and native trust-store/allowlist/user-approval/false-positive/pack-reader/scan-walker/ML filters. Local-core and Guard warning debt remains visible; native signature-compiler bin reports `0 tests` for library-only filters while matching library tests pass; no live malware used |
| Checkpoint 1626 native exact-hash trust-store fixtures | `core/zentor_native_engine/src/trust/store_io.rs`, `known_good.rs`, `known_bad.rs` | Focused runtime coverage for native known-good/known-bad exact-hash trust stores, including bounded reads, malformed hash rejection, unknown-field rejection, missing-file empty compatibility, and non-following presence checks | Runtime fixture verified; replacement/symlink partial | Checkpoint 1626 verifies `trust_store` (`3 passed`), `known_good` (`6 passed`), and `known_bad` (`10 passed`) focused Cargo filters, plus native-engine rustfmt check. Windows-host execution does not cover Unix-only symlink tests and does not prove replacement-race behavior; no live malware used |
| Checkpoint 1623/1631/2037 Flutter host runtime refresh | `apps/zentor_client/lib`, `apps/zentor_client/test`, `packages/zentor_protocol`, `tests/test_custom_driver_contract.py`, `tools/windows/avorax-release-prereq-check.ps1` | Current-host verification for Flutter UI/controller/update/settings/protocol contracts after Flutter/Dart became available, including analyzer cleanliness, full widget/controller test coverage, protocol model tests, formatting, source-contract drift cleanup, and current Windows release-host blocker evidence | Runtime verified; Windows desktop artifact blocked | Checkpoint 1623 verifies `flutter analyze` (`No issues found`), `flutter test --reporter compact` (`464 passed`), protocol `dart analyze` (`No issues found`), protocol `dart test --reporter compact` (`8 passed`), Flutter/protocol `dart format --set-exit-if-changed lib test` (`0 changed` after formatting), Python source-contracts (`481 tests`), and `py_compile`. Checkpoint 1631 refreshes the installed Flutter path (`C:\Users\Brent\develop\flutter\bin`), `flutter pub get`, `flutter analyze` (`No issues found`), and full `flutter test --reporter compact` (`All tests passed`, final counter `+464`) with process-local Git PATH setup. Checkpoint 2037 supersedes old missing-toolchain blockers for this host: Flutter `3.44.4`, Dart `3.12.2`, Cargo, rustfmt, and Git are available, while Windows `Avorax.exe` build remains blocked by unavailable symlink support/Developer Mode, missing Visual Studio Desktop C++ components, and no installed .NET SDK at the explicit dotnet path. No installed desktop UI/E2E or driver/service claim is made. |
| Checkpoint 1624 update-service runtime suite | `core/avorax_update_service/src/`, `core/avorax_update_service/Cargo.toml` | Local Rust runtime coverage for signed `.aup` manifest/signature shape, package path safety, payload hash/path/entry limits, duplicate payload handling, extraction/activation revalidation, rollback validation, service-control command bounds, CLI strictness, and update applier payload allowlists | Runtime fixture verified; production update E2E blocked | Checkpoint 1624 verifies `cargo test --manifest-path core\avorax_update_service\Cargo.toml -- --test-threads=1`: update key generator `4 passed`, sign-manifest bin `0 tests`, update-service main tests `176 passed`; `cargo fmt --manifest-path core\avorax_update_service\Cargo.toml -- --check` passes after formatting, and Python source-contracts pass with `481 tests`. Production signer ceremony, installed update-service operation, real signed release package staging, MSI integration, and installed Avorax update/rollback E2E remain unverified |
| Checkpoint 1957 update-service signed package verifier | `core/avorax_update_service/src/update_verifier.rs`, `core/avorax_update_service/src/update_package.rs`, `tools/testing/verify-small-threat-mvp.ps1`, `tests/test_custom_driver_contract.py` | Runtime proof that the update verifier accepts a benign Ed25519-signed `.aup` manifest/payload pair and rejects manifest-signature or payload-hash tampering, plus one-command MVP coverage for update-service manifest/package/rollback/apply fixtures | Runtime fixture verified; production update E2E blocked | Checkpoint 1957 adds signed `.aup` verifier tests: `signed_update_package_verifies_manifest_signature_and_payload_hashes`, `signed_update_package_rejects_tampered_manifest_signature`, and `signed_update_package_rejects_tampered_payload_hash`. Focused `update_verifier` passes (`12`), full update-service crate passes (`180`), source-contracts pass (`513`), rustfmt check passes, and the expanded small-threat MVP verifier passes in `229.7s` with `update-service signed package/update regressions`. This does not prove production signer ceremony, installed update-service operation, signed release package staging, MSI integration, or installed update/rollback E2E |
| Checkpoint 1632 Guard Service runtime suite | `core/zentor_guard_service/src/`, `core/zentor_guard_service/Cargo.toml` | Guard-mode config, quarantine metadata/auth/path/fallback behavior, driver IPC fail-open/trust boundaries, known-bad cache bounds, driver-health classification, self-test hash/model metadata bounds, and optional ClamAV/YARA compatibility feature fixtures | Runtime fixture verified; installed service/driver E2E blocked | Checkpoint 1632 verifies Guard focused filters: `guard_mode` (`17 passed`), `quarantine` (`32 passed`), `driver_ipc` (`49 passed`), `known_bad` (`16 passed`), `self_test` (`16 passed`), and `driver_health` (`16 passed`); full Guard crate (`212 passed`), `--features compat_yara` (`213 passed`), and `--features compat_clamav` (`212 passed`) passed; Guard rustfmt, Python source-contracts (`481 tests`), and `compileall tools ml` passed. This does not prove installed Windows service operation, signed-driver IPC, elevated service control, or pre-execution blocking |
| Checkpoint 1956 Guard Service MVP verifier coverage | `tools/testing/verify-small-threat-mvp.ps1`, `core/zentor_guard_service/src/`, `tests/test_custom_driver_contract.py` | One-command small-threat MVP verifier coverage for Guard mode config, known-bad cache, quarantine metadata, driver IPC boundary, driver-health probes, self-test, process observation, and process skip fixtures | Runtime fixture verified; installed service/driver E2E blocked | Checkpoint 1956 wires Guard filters into the MVP verifier and verifies `guard_mode` (`17`), `known_bad` (`16`), `quarantine` (`32`), `driver_ipc` (`49`), `driver_health` (`16`), `self_test` (`16`), `process_watch` (`1`), and `process_skip` (`1`). Python source-contracts passed (`512`), and the expanded small-threat MVP verifier passed in `183.3s`. This is fixture coverage only and does not prove installed Windows service operation, signed-driver IPC, elevated service control, or pre-execution blocking |
| Checkpoint 1959/2048 non-driver protection gate MVP coverage | `tools/testing/verify-small-threat-mvp.ps1`, `tools/testing/validate-small-threat-mvp-report.ps1`, `tools/security/zentor-protection-gate.ps1`, `tests/test_custom_driver_contract.py`, `.workflow/ultracode/avorax-hardening/results/small-threat-mvp-protection-selftest.json` | One-command small-threat MVP verifier coverage for the protection gate using a synthetic non-driver self-test fixture, explicit Cargo path, no driver-feature release claim, and full-suite validation that generated protection evidence does not imply signed-driver or pre-execution blocking | Gate verified; signed-driver/pre-execution blocked | Checkpoint 1959 writes a bounded synthetic report with `driver.running=false`, `pre_execution_blocking_available=false`, and `unknown_unsigned_lockdown_blocked_before_launch=false`, then runs `zentor-protection-gate.ps1` without `-DriverFeatureEnabled`. Checkpoint 2048 makes the full-suite report validator parse and verify the generated protection self-test fixture, exact driver false fields, non-driver policy/verdict test booleans, and no signed-driver/pre-execution disclaimer; a negative fixture with `driver.pre_execution_blocking_available=true` failed with `protection self-test generated report driver.pre_execution_blocking_available must be JSON boolean False.` Source-contracts passed (`540`), PowerShell parser checks passed, and the full small-threat MVP verifier plus report validator passed with `139` steps in `305.1s` for `.workflow\ultracode\avorax-hardening\results\2048-small-threat-mvp-full-report.json`. This verifies policy/verdict gate wiring and report honesty only; it does not prove installed Guard Service operation, signed-driver IPC, kernel blocking, or pre-execution blocking |
| Checkpoint 1960 branding gate MVP coverage | `tools/testing/verify-small-threat-mvp.ps1`, `tools/branding/branding-check.ps1`, `tests/test_custom_driver_contract.py` | One-command small-threat MVP verifier coverage for active-source product/branding drift before product-copy and security gates | Gate verified; packaged release validation partial | Checkpoint 1960 wires `Branding gate` into the MVP verifier with `tools\branding\branding-check.ps1 -Root <repo>`. Standalone branding check passed, the focused no-Rust/no-Flutter verifier pass completed in `15.5s`, `Branding gate` passed in `1.6s`, source-contracts passed (`513`), and the full expanded small-threat MVP verifier passed in `192.6s`. This verifies active source/doc branding terms only; packaged installer/assets and release-host branding validation remain separate |
| Checkpoint 1961 small-threat MVP JSON report | `tools/testing/verify-small-threat-mvp.ps1`, `tools/security/avorax-security-gate-tools.ps1`, `tests/test_custom_driver_contract.py`, `.workflow/ultracode/avorax-hardening/results/small-threat-mvp-verification-report.json` | Structured reproducible verifier evidence with status, exact commands, timings, tool paths, options, generated reports, verification scope, partial surfaces, and technical limits | Runtime verified; E2E blockers remain | Checkpoint 1961 adds `-ReportPath`, rejects report paths outside the repository, writes the report atomically through `Write-AvoraxGateJsonFileAtomic`, records `passed`/`failed` status without swallowing failures, and preserves the same scope/limit text printed to console. Focused no-Rust/no-Flutter verifier passed in `15.7s`; the full expanded verifier passed in `191.9s`; JSON sanity confirmed `status=passed`, `98` steps, no Rust/Flutter skips, and generated report links; out-of-repo report path rejection passed; and source-contracts passed (`513`). This report is verification evidence only and does not prove installed service/UI/driver/release-host blockers |
| Checkpoint 1962 small-threat MVP report validator | `tools/testing/validate-small-threat-mvp-report.ps1`, `tests/test_custom_driver_contract.py`, `.workflow/ultracode/avorax-hardening/results/small-threat-mvp-verification-report.json` | Independent validation for structured verifier reports: schema, status, timestamps, booleans, tool paths, generated report paths, step evidence, scope text, and error semantics | Validator verified; protection proof unchanged | Checkpoint 1962 adds a local-only report validator and source-contract coverage. It passed against the existing full MVP report with `-RequireFullSuite` (`status=passed`, `98` steps), rejected `passed` with no steps, rejected `failed` with no error, rejected an out-of-repo report path, and source-contracts passed (`514`). This hardens evidence hygiene only and does not prove installed UI/service/driver/release-host behavior |
| Checkpoint 1963 self-validating small-threat MVP verifier | `tools/testing/verify-small-threat-mvp.ps1`, `tools/testing/validate-small-threat-mvp-report.ps1`, `tests/test_custom_driver_contract.py`, `.workflow/ultracode/avorax-hardening/results/1963-small-threat-mvp-full-report.json` | The one-command verifier validates its just-written success report before accepting the run | Self-validation verified; protection proof unchanged | Checkpoint 1963 makes `verify-small-threat-mvp.ps1` call `validate-small-threat-mvp-report.ps1` after writing a success report. Full non-Defender/non-skip runs pass `-RequireFullSuite`; skip or optional-Defender runs use structural validation only. Focused skip verification passed in `15.9s`; the full verifier passed in `192.8s` with `98` steps; post-write full-suite validation passed in `0.5s`; and source-contracts passed (`514`). If validation fails, the verifier falls through the existing failure-report path instead of leaving malformed success evidence. This improves failure honesty but does not prove installed UI/service/driver/release-host behavior |
| Checkpoint 1964 allowlist smoke fail-visible quarantine check | `tools/testing/run-safe-allowlist-smoke.ps1`, `tests/test_custom_driver_contract.py` | Safe allowlist smoke refuses to hide quarantine-payload enumeration failures | Smoke verified; protection proof unchanged | Checkpoint 1964 changes quarantine-payload enumeration from `-ErrorAction SilentlyContinue` to `-ErrorAction Stop` and adds a source-contract guard. The safe allowlist smoke passed with an allowlisted simulator and `Quarantined files: 0`; source-contracts passed (`514`); and targeted `rg` over active tool/driver PowerShell scripts found no `SilentlyContinue` matches. This hardens test failure visibility only and does not prove installed UI/service/driver/release-host behavior |
| Checkpoint 1965 process snapshot explicit observations | `core/zentor_local_core/src/main.rs`, `core/zentor_local_core/src/protection/process_monitor.rs`, `tests/test_custom_driver_contract.py`, `.workflow/ultracode/avorax-hardening/results/1965-small-threat-mvp-full-report.json` | Local-core process snapshot IPC refuses missing observation payloads instead of treating them as successful empty evidence | Runtime verified; active loop remains partial | Checkpoint 1965 changes `evaluate_process_snapshot` to require `process_observations`, while still allowing explicitly empty observation arrays. Focused local-core `process_snapshot` tests passed (`4`), including `process_snapshot_ipc_requires_explicit_observations`; local-core rustfmt check passed; source-contracts passed (`514`); focused self-validating verifier passed in `15.9s`; and the full verifier passed in `196.4s` with `98` steps plus post-write full-suite report validation in `0.5s`. This prevents missing IPC payloads from becoming fake empty success evidence but does not prove an installed active process-monitoring loop |
| Checkpoint 1633 workspace/security gate refresh | `Cargo.toml`, `packages/`, `tools/security/`, `tools/perf/`, `tools/branding/`, `tools/windows/` | Broad non-installer workspace and release-gate confidence for Rust workspace tests, Dart protocol packages, branding/product-copy/no-malware/dependency/false-positive/protection/performance gates, and fail-visible release prerequisite checks | Runtime/gate verified; release blockers remain | Checkpoint 1633 verifies protocol format/analyze/test (`zentor_protocol` 8 tests, `avorax_protocol` 6 tests), `cargo test --workspace --no-run`, `cargo test --workspace -- --test-threads=1` (update key `4`, update service `176`, API `40`, Guard `212`, local-core `411`, native engine `284`, signature compiler `6`), branding/product-copy/no-malware/false-positive/protection/performance gates, and dependency evidence with known Android lockfile blocker. Release prerequisite check with explicit dotnet/cargo/flutter paths fails only on real blockers: missing Android Gradle lockfile, missing Windows release `Avorax.exe`, missing installer stage, unavailable symlink support, missing Android SDK, and missing Visual Studio Desktop C++ components. Protection gate uses synthetic non-driver evidence and does not prove signed-driver IPC/pre-execution blocking |
| Checkpoint 1639 command/config/service runtime | `core/zentor_guard_service/src/`, `core/zentor_local_core/src/` | Focused runtime coverage for Guard mode config strictness, Guard fatal-log staging, Secure Boot probe command encoding, local-core command strict schema, Core/Guard service-status classification, and local-core fatal-log staging | Runtime fixture verified; installed service E2E partial | Checkpoint 1639 verifies Guard filters `guard_mode` (`17`), `guard_fatal` (`1`), `secure_boot` (`2`), local-core filters `core_command` (`4`), `service_status` (`10`), `core_fatal` (`1`), plus Guard/local-core rustfmt. Windows service environment, elevated service-control, installed IPC, and live Secure Boot probe E2E remain partial. |
| Checkpoint 1641 trust/quarantine/API runtime | `core/zentor_local_core/src/app_control/`, `core/zentor_local_core/src/quarantine/`, `core/zentor_native_engine/src/trust/`, `services/api/src/` | Focused runtime coverage for local app-control passthrough/trust-store roots, native repo/quarantine trust roots, local quarantine text/path/staging/copy/finalization details, and API CORS/routes/project/auth/body/error source-contract fixtures | Runtime fixture verified; installed/browser/database E2E partial | Checkpoint 1641 verifies local-core `trust_store` (`10`), `app_control` (`47`), `original_restore_path_text` (`1`), `quarantine_payload_path_text` (`1`), `list_rejects_metadata_with_unsafe_restore_or_payload_paths` (`1`), `quarantine_metadata_staged` (`3`), `copy_fallback` (`7`), `quarantine_finalization` (`1`), `quarantine_metadata_text_reader` (`1`), and `quarantine_root` (`1`); native-engine `quarantine_trust` (`3`) and `repo_root` (`2`); API `cors` (`1`), `route` (`32`), `project` (`6`), `auth` (`2`), `body` (`1`), and `error` (`1`). Browser preflight, database-backed API smoke, installed local-core/UI E2E, platform-gated reparse/race behavior, and VCS status remain partial |
| Checkpoint 1642 Guard process/root runtime | `core/zentor_guard_service/src/`, `core/zentor_native_engine/src/config.rs`, `core/zentor_local_core/src/main.rs` | Focused runtime coverage for Guard process-watch error accounting, process-skip path normalization, driver-health bounded probes/root validation, Guard quarantine/native asset/ClamAV compatibility roots, native engine/quarantine roots, and local watcher/status behavior | Runtime fixture verified; installed service/driver E2E partial | Checkpoint 1642 verifies Guard filters `process_watch` (`1`), `process_skip` (`1`), `driver_health` (`16`), `quarantine_root` (`2`), `guard_native_asset` (`2`), `native_asset` (`4`), and `clamav` (`2`); native-engine filters `native_engine_root` (`1`) and `native_quarantine_root` (`4`); local-core `watch` (`10`). Non-Windows service-mode filters matched `0 tests` on this Windows host and are not counted as proof. Installed Guard service operation, signed-driver IPC, elevated service control, live process-observation E2E, platform-gated race/reparse behavior, and VCS status remain partial |
| Checkpoint 1643 Flutter update/quarantine runtime | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/lib/core/local_core/local_core_client.dart`, `apps/zentor_client/lib/core/network/zentor_api_client.dart`, `apps/zentor_client/lib/app/app_state.dart` | Focused Flutter runtime coverage for update URI trust gates, local update feed/package validation, GitHub HTTPS trust reuse, quarantine IPC record evidence, cloud quarantine preflight/upload evidence, and update controller busy/diagnostic flows | Runtime fixture verified; installed UI/service/backend E2E partial | Checkpoint 1643 verifies `update_service_test.dart` (`106`), `local_core_ipc_diagnostics_test.dart` (`42`), `api_client_test.dart` (`38`), and `update_controller_test.dart` (`32`) with `All tests passed!`. Installed Windows UI click/layout, installed local-core/service/driver E2E, database-backed API smoke, and symlink/junction race fixtures remain partial |
| Checkpoint 1644 native policy/parser runtime | `core/zentor_native_engine/src/` | Focused native runtime coverage for dead placeholder removal, PE resource parsing, script unsupported-type failures, ML unknown-feature handling, process/risk/signature/rule policy mappings, threat-intel defaults/normalization, and quick/full scan root source contracts | Runtime fixture verified; platform E2E partial | Checkpoint 1644 verifies full native-engine tests (`284` lib, `6` bin), native-engine rustfmt, and focused filters for publisher stub absence (`1`), PE resources (`3`), updates placeholder namespace absence (`1`), script unsupported types (`1`), unknown ML features (`3`), process-start action mapping (`1`), risk-fusion action mapping (`1`), signature action-policy rejection (`1`), rule match weighting (`1`), threat-intel confidence (`1`), quick/full scan root contracts (`1` each), and indicator normalization (`2`). The symlink/permission quick-scan filter matched `0 tests` on Windows and is not counted; installed native-engine/UI, Windows/POSIX env, permission, symlink/junction, and live Authenticode E2E remain partial |
| Checkpoint 1645 API cloud contract runtime | `services/api/src/` | Focused API compile/runtime source-marker coverage for cloud request schemas, quarantine metadata evidence, event/session/detection/ban/device transaction and acknowledgement boundaries, timestamp bounds, device/project boundaries, fail-closed project creation, and unused audit-helper removal | Runtime source-marker verified; database smoke partial | Checkpoint 1645 verifies API rustfmt, full API tests (`40`), and focused filters for quarantine metadata evidence/payload/ack, event empty-batch/ack, session expiry/device/transaction/ack, active-session writes, heartbeat active-update/event ack, timestamp bounds, detection transaction/ack/empty aggregate, ban device/project/ack, device-risk boundary, device-registration transaction/audit ack, project fail-closed behavior, and unused audit-helper absence. Live database-backed route smoke, failure-injection transaction tests, browser CORS preflight, and deployment startup smoke remain partial |
| Checkpoint 1646/2038 Flutter UI/controller runtime | `apps/zentor_client/lib/`, `apps/zentor_client/test/` | Focused Flutter runtime coverage for status/protection honesty, watcher copy, scan/protection/service event severity, local event category/severity constraints, scan policy boundaries, detect-only shortcuts, self-test visible results, config recovery warnings, and shared dark-theme contrast regression coverage | Runtime fixture verified; installed UI/service E2E partial | Checkpoint 1646 verifies `app_visual_policy_test.dart` (`57`), `offline_scan_test.dart` (`96`), `local_event_test.dart` (`35`), `protection_status_test.dart` (`1`), and `config_validation_test.dart` (`22`). Checkpoint 2038 updates `secondaryAccent` to an AA-readable value on dark surfaces and verifies text/status/accent color contrast against background, surface, and elevated-surface colors with focused `app_visual_policy_test.dart` (`59`), Flutter analyze, Dart format, and source-contracts (`539`). Installed Windows UI click/layout/screenshot E2E, installed local-core/service/driver E2E, keyboard traversal audits, per-feature screen-reader coverage, localization-ready text extraction, and kernel pre-execution proof remain partial or open. |
| Checkpoint 1647 local/Guard/native root runtime | `core/zentor_local_core/src/`, `core/zentor_guard_service/src/`, `core/zentor_native_engine/src/` | Focused runtime coverage for local ProgramData/config/migration/service-status/ACL roots, local ClamAV/YARA/AI/native-asset fixtures, Guard self-test/post-launch/hash-read/ClamAV fixtures, native trust-root/AuthentiCode/Microsoft-trust fixtures, and signature-compiler source/output hardening | Runtime fixture verified; platform/installed E2E partial | Checkpoint 1647 verifies local-core filters `local_core_program_data_root` (`3`), `config_root` (`1`), `migration` (`11`), `service_status` (`10`), `acl` (`2`), `clamav` (`11`), `yara` (`19`), `ai_model` (`1`), and `engine_asset_locator` (`4`); Guard filters `self_test` (`16`), `post_launch` (`3`), `hash_read` (`1`), and `clamav` (`2`); native-engine filters `trust_root` (`3`) and `microsoft` (`18`); and signature-compiler bin filter `signature_compiler` (`6`). Filters that matched `0 tests` (`runtime_root`, `native_asset`, Guard/local service-mode, Guard ACL) are not counted. Existing local-core/Guard warning debt, installed UI/service/native E2E, signed-driver IPC, live Authenticode, and non-Windows service-mode fixtures remain partial |
| Checkpoint 1648 Rust warning-debt cleanup | `core/zentor_local_core/src/`, `core/zentor_guard_service/src/` | Maintainability cleanup for warning-heavy local-core/Guard test builds while preserving compatibility-provider and wire-schema boundaries | Runtime verified; protection claims unchanged | Checkpoint 1648 removes unused local-core imports, fixes an unused heuristic metadata binding, and scopes `allow(dead_code)`/`allow(unused_imports)` to intentional compatibility/development helpers and ignored external trust-injection fields. Focused tests pass for local-core ProgramData (`3`), ClamAV (`11`), YARA (`19`), app-control (`47`), and Guard self-test (`16`); full local-core (`411`) and Guard (`212`) suites pass with no warnings in captured output; local-core/Guard rustfmt, Python source-contracts (`481`), and no-malware gate pass. Installed UI/service/driver E2E, signed-driver IPC, kernel pre-execution blocking, live Authenticode, and release packaging remain partial |
| Native rule VM | `core/zentor_native_engine/src/rules/`, `assets/zentor_native/rules/` | Avorax-owned local rule matching for ransomware, infostealer, persistence, miner/PUP, and script-downloader indicators with strict rule-pack schemas and bounded pack reads | Runtime fixture verified; installed E2E partial | Checkpoint 1640 verifies native `rule_pack` (`17`), `rule_compiler` (`13`), representative bundled `.zrule` validator runs (`zentor_rules.zrule`, `zentor_script_threats.zrule`), and native-engine rustfmt. Earlier evidence remains: native signature/rule pack actual-byte read limits source-accounted in checkpoint 1271; indicator-pack validator shape validation source/fixture/asset-accounted in checkpoint 998; rule compiler explicit version source/fixture-accounted in checkpoint 1005. Installed native-engine/UI E2E remains partial |
| Static file analyzers | `core/zentor_native_engine/src/analyzers/` | Bounded metadata/content analysis for file type, entropy, strings, PE, ELF, Mach-O, scripts, PE resources/certificates, imports, overlays, and ZIP archives | Runtime fixture verified; broader partial | Checkpoint 1617 verifies file-type missing-extension default honesty and PE resource parser fixtures, including certificate/resource directory evidence and no dead zero stub, with focused Cargo filters (`1 passed; 0 failed` each); malformed-file coverage beyond these fixtures remains partial |
| Archive scanner | `core/zentor_native_engine/src/scan/archive_scanner.rs`, `analyzers/archives/zip.rs` | Bounded archive inspection without executing payloads | Runtime fixture verified; broader partial | Checkpoint 1617 verifies ZIP relative-path allowance, empty-entry rejection, truncated-header rejection, and explicit empty-suffix handling with focused Cargo filters (`1 passed; 0 failed` each); no archive payload execution is performed |
| Checkpoint 1620 native ZIP archive fixtures | `core/zentor_native_engine/src/analyzers/archives/zip.rs`, `core/zentor_native_engine/src/tests/mod.rs` | Focused runtime coverage for ZIP path-safety, malformed/truncated ZIP metadata handling, and explicit suffix/default branches | Runtime fixture verified; broader archive-format partial | Checkpoint 1620 verifies `cargo test --manifest-path core\zentor_native_engine\Cargo.toml archive` with `10 passed; 0 failed` for lib tests; the signature-compiler bin reports `0 tests` for this library-only filter; no archive payload execution is performed |
| Native heuristic scoring | `core/zentor_native_engine/src/heuristics/`, `core/zentor_native_engine/src/ml/feature_extractor.rs` | Combine weak local signals into conservative suspicious/probable verdict evidence and extract bounded static feature evidence | Runtime partial | Checkpoint 1617 verifies missing-extension feature extraction uses an explicit non-executable branch (`1 passed; 0 failed`); broader heuristic false-positive/runtime calibration remains partial |
| Native ML runtime | `core/zentor_native_engine/src/ml/`, `assets/zentor_native/ml/`, `ml_native/`, `tools/zne/zne-release-gate.ps1`, `tools/zne/zne-release-gate.sh` | Pure Rust `.zmodel` feature scoring and explanations plus schema-aware native model train/evaluate/export, bounded model reads, bounded release-gate metadata, atomically activated ZNE report evidence, and UI production-ready metadata display | Runtime fixture verified; development model only | Bundled model is development-only unless metadata is production-ready; production dataset validation is blocked. Checkpoint 1625 verifies focused native ML Cargo filters: `native_model` (`19 passed`) covers strict schema, malformed schema, bounded `.zmodel` reads, directory rejection, oversized model rejection, unknown/non-finite/unbounded feature handling, explicit unloaded production-ready false branch, and invalid metadata; `ml` (`23 passed`) adds feature extractor/vector fail-closed fixtures; native-engine rustfmt check passes after formatting drift cleanup. Earlier tooling evidence remains: static-model metadata validator hardening source-accounted in checkpoint 823; native evaluator hardening source-accounted in checkpoint 824; native train/export hardening source-accounted in checkpoint 825; ZNE metadata JSON parsing hardening source-accounted in checkpoint 829; ZNE report activation hardening source-accounted in checkpoint 843; evaluator report-output hardening source/fixture-accounted in checkpoint 849; native feature-builder output hardening source/fixture-accounted in checkpoint 850; shared native ML output helper source/fixture-accounted in checkpoint 851; shell ZNE metadata/report parity source-accounted in checkpoint 857; Python temp-cleanup visibility source-accounted in checkpoint 861; Flutter Settings feature-schema display honesty source-accounted in checkpoint 1073; PowerShell ZNE bounded handle reader source/fixture-accounted in checkpoint 1008; release source-text bounded handle reader source-accounted in checkpoint 1014; ZNE PowerShell command diagnostic bounds source-accounted in checkpoint 1101; Flutter native ML production-ready boolean parsing/display source-accounted in checkpoint 1127 |
| Risk fusion and action policy | `core/zentor_native_engine/src/verdict/`, `core/zentor_local_core/src/risk/`, `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/test/offline_scan_test.dart` | Explainable aggregation of signature, rule, heuristic, ML, trust, and policy signals into verdict/action recommendations plus review-only user action handling for non-confirmed detections | Runtime partial | Runtime aggregator tests need Cargo; UI shows review-only states for non-confirmed detections; Flutter nested risk-score diagnostics source-accounted in checkpoint 892; Flutter threat-row risk-score evidence fail-closed source-accounted in checkpoint 1043; Flutter risk-reason row fallback cleanup source-accounted in checkpoint 1044; Flutter threat-ignore single-flight source-accounted in checkpoint 1163 and runtime-verified in checkpoint 1584 with `flutter test test\offline_scan_test.dart --reporter compact` (`95 passed`), including duplicate ignore rejection during pending audit write without a second ignored event or premature hidden detection; Flutter threat-ignore busy-state UI source-accounted in checkpoint 1175 and controller busy flag runtime-verified in checkpoint 1584; native/local verdict aggregator runtime fixtures and installed Scan UI click/layout E2E remain partial |
| Local-core scan orchestration | `core/zentor_local_core/src/main.rs`, `core/zentor_local_core/src/api/`, `scanner/`, `protection/guard_service.rs`, `apps/zentor_client/lib/core/local_core/local_core_client.dart`, `apps/zentor_client/lib/features/scan/scan_screen.dart` | Quick/full/custom scan dispatch, progress, cancellation, report generation, skipped/error accounting, bounded manual-action/threat hash evidence, bounded startup-migration hash evidence, health/status diagnostics including unsupported-platform Guard status, runtime-root/config validation, native asset discovery, startup migration validation, install-report path validation, checked Core/Guard executable discovery, strict local-core IPC command handling, fail-visible unsupported-platform Core Service mode, and honest engine-unavailable diagnostics | Runtime verified for crate fixtures; installed E2E partial | Checkpoint 1631 refreshes local-core runtime evidence with `scan` (`83 passed`), `quarantine` (`86 passed`), `report` (`29 passed`), full local-core crate tests (`411 passed`), and local-core rustfmt. Installed local-core process/UI E2E remains partial. Earlier focused evidence remains: local-core IPC command size and bounded line-reader fixtures runtime-verified in checkpoint 1605 with `cargo test --manifest-path core\zentor_local_core\Cargo.toml oversized_json_before -- --test-threads=1` (`2 passed`) and `cargo test --manifest-path core\zentor_local_core\Cargo.toml core_command_reader -- --test-threads=1` (`1 passed`); local-core IPC path bounds runtime-verified in checkpoint 1606 with `cargo test --manifest-path core\zentor_local_core\Cargo.toml ipc_path -- --test-threads=1` (`3 passed`); local-core IPC text bounds runtime-verified in checkpoint 1607; progress serialization runtime-verified in checkpoint 1608; feature/hash bounded I/O runtime-verified in checkpoint 1609; local scan-target metadata path-safety and scan-error accounting partially runtime-verified in checkpoint 1610, with Unix-only symlink fixture still technically limited on this Windows host; local publisher exact-match and passthrough exact-root trust runtime-verified in checkpoint 1611; Flutter UI/controller coverage refreshed in checkpoint 1631 through full `flutter test --reporter compact` (`All tests passed`, final counter `+464`). The remaining source-accounted diagnostics, status labels, runtime-root guards, and UI state checks listed in prior matrix revisions are covered by named historical checkpoints but still require installed service/UI E2E before product-level claims |
| Checkpoint 1618 local scan cancellation runtime fixture | `core/zentor_local_core/src/main.rs` | Focused runtime coverage that local-core scan cancellation/time-budget exits report queued unscanned files as skipped, preserve failed-native-inspection accounting, and avoid silently continuing through the full queue | Runtime fixture verified; installed E2E partial | Checkpoint 1618 verifies `scan_paths_honors_cancel_request_between_files`, `full_scan_time_budget_exit_reports_unscanned_remainder`, `scan_paths_does_not_count_failed_native_inspections_as_scanned`, `scan_cancellation_reports_unscanned_remainder`, and `scan_cancellation_token_uses_staged_write_without_temp_leftover` with focused Cargo filters (`1 passed; 0 failed` each); installed scan UI/local-core process E2E remains partial |
| Rust workspace compile/runtime gate | `Cargo.toml`, `core/zentor_native_engine/`, `core/zentor_local_core/`, `core/avorax_update_service/`, `core/zentor_guard_service/`, `services/api/` | Workspace-level compile/test-executable gate for native engine, local/update/guard services, and API crates | Compile and runtime tests verified | Checkpoints 1547 and 1562 prove `cargo test --workspace --no-run` and `cargo test --workspace -- --test-threads=1` pass on the current host with existing warnings only; checkpoint 1617 refreshes the native-engine crate with broad `cargo test --manifest-path core\zentor_native_engine\Cargo.toml -- --test-threads=1` (`284 passed; 0 failed` lib tests, `6 passed; 0 failed` signature-compiler tests) and no warnings after cleanup; release/installer artifact gates remain separate host-prerequisite blockers |
| Flutter local-core action/watcher/cancel/list/health IPC boundary | `apps/zentor_client/lib/core/local_core/local_core_client.dart`, `apps/zentor_client/test/local_core_ipc_diagnostics_test.dart`, `tests/test_custom_driver_contract.py` | IPC action-result parsing for quarantine, allowlist, detection feedback, Guard mode, and ransomware-guard configuration actions plus start/stop watcher, cancel-scan, quarantine-list, allowlist-list, and health-response protocol validation | Runtime fixture verified; installed E2E partial | Action responses now fail visibly when `ok:true` is accompanied by bounded IPC protocol warnings in checkpoint 1517; start/stop watcher responses do the same in checkpoint 1518; cancel responses do the same in checkpoint 1519; quarantine/allowlist list responses do the same in checkpoint 1520 before records become UI evidence; health responses surface collected protocol warnings through `lastError` in checkpoint 1521; checkpoint 1643 refreshes `flutter test test\local_core_ipc_diagnostics_test.dart --reporter compact` (`42 passed`), including quarantine IPC source/action/process evidence rejection for malformed actionable record/list rows before UI/action use; checkpoints 1666-1668 add runtime fixtures for action, watcher, quarantine-list, cancel, and health `ok:true` protocol-warning responses, with `local_core_ipc_diagnostics_test.dart` passing (`53`). Installed local-core IPC E2E remains partial |
| Scan diagnostics UI | `apps/zentor_client/lib/features/scan/scan_screen.dart`, `apps/zentor_client/lib/app/app_state.dart` | Engine-unavailable diagnostics and scanbanner messages for Core Service, engine directory, definition packs, ML model, ProgramData, paths checked, and bounded last-error evidence | Runtime fixture verified; visual/E2E partial | Checkpoint 1783 runtime-verifies Scan Core Service status chips for `unknown`, `unsupported`, `error`, and unrecognized fallback labels with `scan_screen_test.dart`; checkpoint 1784 runtime-verifies Scan ML model chips for loaded, development, missing, error, and fallback native ML evidence; Core Service status labels align with local-core health statuses in checkpoint 1059, local-core `unsupported` status is parser/label aligned in checkpoint 1062, Core Service engine-unavailable messages preserve distinct status evidence in checkpoint 1061, service/report action single-flight is source-accounted in checkpoint 1156 and controller-runtime-verified in checkpoint 1583, service busy-state UI is source-accounted in checkpoint 1173 with controller busy flag runtime-verified in checkpoint 1583, engine path/asset-pack honesty is source-accounted in checkpoints 814, 1052, and 1056, Scan last-error diagnostic trimming is source-accounted in checkpoint 1538, Scan pack-status diagnostic fallback guarding is source-accounted in checkpoint 1539, and checkpoint 1563 verifies focused Flutter UI fixture coverage through `flutter test test\app_visual_policy_test.dart --reporter compact` (`57 passed`); installed Windows visual/screenshot E2E remains partial |
| Flutter UI diagnostic boundary | `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/lib/features/settings/settings_screen.dart`, `apps/zentor_client/lib/features/device/device_screen.dart`, `apps/zentor_client/lib/shared/widgets/zentor_shell.dart`, `apps/zentor_client/test/navigation_accessibility_test.dart`, `apps/zentor_client/test/config_validation_test.dart`, `apps/zentor_client/test/local_event_test.dart`, `apps/zentor_client/test/settings_accessibility_test.dart`, `apps/zentor_client/test/update_controller_test.dart`, `apps/zentor_client/test/update_service_test.dart`, `tests/test_custom_driver_contract.py` | Shared controller and feature-level error formatters for visible UI state, local-event details, Settings export-log errors, Device platform-provider failures, config recovery warnings, update failures, and shell notification summaries across scan, update, quarantine, allowlist, protection, cloud, app detection, settings, onboarding, and startup tasks | Runtime fixture partial | Checkpoint 1311 source-verifies `_boundedUiDiagnostic` bounds and control/NUL-normalizes exception text before controller catch blocks emit UI/audit evidence; checkpoint 1315 source-verifies `_boundedSettingsDiagnostic` and `_boundedDeviceDiagnostic` apply the same control/NUL normalization before feature-level UI evidence is emitted; checkpoint 1316 source-verifies `_notificationText` control/NUL-normalizes local-event notification summaries before display; checkpoint 1566 verifies the shell notification text runtime fixture with control/NUL details rendered as normalized one-line UI text in `flutter test test\navigation_accessibility_test.dart --reporter compact` (`4 passed`); checkpoint 1567 verifies config-recovery warning/error propagation at startup through `flutter test test\config_validation_test.dart --reporter compact` (`21 passed`); checkpoint 1568 verifies update-check failure diagnostics with control/NUL text are normalized before `updateError`, `errorMessage`, and `update_check_failed` event evidence through `flutter test test\update_controller_test.dart --reporter compact` (`28 passed`); checkpoint 1569 verifies Device platform-provider failures with control/NUL text render as normalized visible UI text through `flutter test test\settings_accessibility_test.dart --reporter compact` (`2 passed`); checkpoint 1570 verifies Settings log-export controller failures with control/NUL text are normalized before visible `errorMessage` and `logs_export_failed` audit details through `flutter test test\local_event_test.dart --reporter compact` (`35 passed`); checkpoint 1681 verifies the Settings log-export dialog failure path shows a failure snackbar without success text, keeps the normalized visible controller error, and emits `logs_export_failed` as `settings`/`error` through `flutter test test\settings_accessibility_test.dart --reporter compact` (`9 passed`); checkpoint 1571 verifies update download failures with control/NUL text are normalized before visible `updateError`/`errorMessage` and `update_install_failed` event details through `flutter test test\update_controller_test.dart --reporter compact` (`29 passed`); checkpoint 1572 verifies update verify/install/rollback failures with control/NUL text are normalized before visible UI state and failure-event details through `flutter test test\update_controller_test.dart --reporter compact` (`30 passed`); checkpoint 1573 verifies `ZentorUpdateService.downloadUpdatePackage` combined original/cleanup diagnostics are bounded and control/NUL-normalized when temp cleanup fails through `flutter test test\update_service_test.dart --reporter compact` (`84 passed`); checkpoint 1574 verifies `verifyDownloadedPackage` rejects non-file cached package paths with bounded probe diagnostics before updater launch through `flutter test test\update_service_test.dart --reporter compact` (`85 passed`); remaining broader controller diagnostic paths and installed update package apply/rollback fixtures still need focused runtime fixtures |
| Flutter startup background-task boundary | `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/test/config_validation_test.dart`, `tests/test_custom_driver_contract.py` | Startup app detection, malware-engine health refresh, quarantine refresh, silent update checks, saved protection restore, and config-recovery warning propagation through bounded visible/audit boundaries so unexpected async failures do not become detached silent failures | Runtime fixture partial | Checkpoint 1300 source-verifies `_runStartupTask` catches startup task failures, bounds diagnostics, records error-severity audit events, sets visible UI error state, and replaces the prior direct startup invocations; checkpoint 1567 verifies startup config-recovery warning propagation with visible `errorMessage` and `configuration_recovered` event evidence; remaining detached-future failure paths still need focused runtime fixtures |
| Flutter scan-start controller guard | `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/lib/features/home/home_screen.dart`, `apps/zentor_client/lib/features/scan/scan_screen.dart`, `apps/zentor_client/lib/features/protection/protection_screen.dart`, `apps/zentor_client/lib/features/quarantine/quarantine_screen.dart`, `docs/client-ui.md` | Controller-level single-flight guard for manual and scheduled scan starts before local-core scan IPC launch plus visible scan-start busy gating, custom target-picker de-duplication before OS picker launch, visible target-selection busy gating, custom picker scan-busy rejection before OS picker launch, scheduled-scan target-selection skip evidence, direct quick/full/quarantine-rescan target-selection race rejection, scan action-mode mutation blocking while scans start/run or target selection is active, and detect-only Home/Protection/quarantine original-rescan paths without scan-action selectors | Runtime fixture verified; UI/E2E partial | Scan-start guard source-accounted in checkpoint 1142; scan-start busy-state UI source-accounted in checkpoint 1182; scan-start engine-diagnostic limitation audit handling source-accounted in checkpoint 1525; scheduled quick-scan engine-diagnostic start-event severity source-accounted in checkpoint 1526; custom scan target-selection single-flight source-accounted in checkpoint 1162; custom target-selection busy-state UI source-accounted in checkpoint 1180; scan action-mode policy blocking source-accounted in checkpoint 1165; Home/Protection detect-only shortcut behavior source-accounted in checkpoint 1167; checkpoint 1564 verifies duplicate scan-start suppression and scan-start state through `flutter test test\offline_scan_test.dart --reporter compact`; checkpoint 1977 verifies scheduled timer fires skip with warning evidence during target selection, Scan/Home/Protection target-selection busy UI gating, and scan action-mode target-selection blocking; checkpoint 1978 verifies direct quick/full scan and quarantine original-rescan calls log `scan_start_ignored` and make no Local Core scan IPC while target selection is active, and adds verifier/report-validator scope for `scan concurrency target-selection controller guards`; checkpoint 1979 verifies Custom File/Folder controller calls log `scan_target_selection_busy`, keep `scanTargetSelectionInFlight=false`, and do not open picker handoff or scan IPC while a scan is starting or running, and adds verifier/report-validator scope for `custom-picker scan-busy controller guards`; installed UI/E2E scan-control verification remains partial |
| Flutter Home native-engine diagnostic metric | `apps/zentor_client/lib/features/home/home_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Home native-engine metric value/detail use current engine diagnostic evidence instead of status-only ready copy | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1527; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Device native-engine diagnostic metric | `apps/zentor_client/lib/features/device/device_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Device native-engine metric value/detail use current engine diagnostic evidence instead of status-only ready copy | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1528; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Settings native-status diagnostic row | `apps/zentor_client/lib/features/settings/settings_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Settings native-status value uses current engine diagnostic evidence instead of status-only ready copy | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1529; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Protection native-engine diagnostic status | `apps/zentor_client/lib/features/protection/protection_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Protection native-engine metric and checklist status values use current engine diagnostic evidence instead of status-only ready copy | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1530; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Home native-rule diagnostic count | `apps/zentor_client/lib/features/home/home_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Home native-rule count metric preserves real count evidence but does not use ready-status fallback while engine diagnostics are visible | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1531; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Protection native pack/count diagnostic labels | `apps/zentor_client/lib/features/protection/protection_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Protection native signature/rule count labels preserve real count evidence but do not use ready-status fallback while engine diagnostics are visible | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1532; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Settings native packaged-count diagnostic labels | `apps/zentor_client/lib/features/settings/settings_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Settings native signature/rule count labels preserve real count evidence but do not use ready-status fallback while engine diagnostics are visible | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1533; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Protection quarantine readiness diagnostic label | `apps/zentor_client/lib/features/protection/protection_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Protection quarantine readiness does not report available while current engine diagnostics are visible | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1534; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Protection native-engine diagnostic detail order | `apps/zentor_client/lib/features/protection/protection_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Protection native-engine detail copy reports current engine diagnostics before ready scanner reassurance | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1535; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Device native-engine diagnostic detail normalization | `apps/zentor_client/lib/features/device/device_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Device native-engine detail displays trimmed current engine diagnostic evidence instead of raw last-error text | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1536; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter Settings engine-diagnostic row normalization | `apps/zentor_client/lib/features/settings/settings_screen.dart`, `apps/zentor_client/test/app_visual_policy_test.dart`, `tests/test_custom_driver_contract.py` | Settings engine-diagnostic row displays trimmed current engine diagnostic evidence instead of raw last-error text | Runtime fixture verified; visual/E2E partial | Source-accounted in checkpoint 1537; checkpoint 1563 verifies the Flutter widget/runtime fixture through `app_visual_policy_test.dart`; installed Windows visual/screenshot E2E remains partial |
| Flutter scheduled quick-scan timer boundary | `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/test/offline_scan_test.dart`, `tests/test_custom_driver_contract.py` | Periodic quick-scan callbacks launch through a bounded scan error/audit boundary, skip visibly while another scan or target selection is active, and avoid detached timer future failures | Runtime fixture verified; installed UI/E2E partial | Checkpoint 1301 source-verifies `Timer.periodic` uses `_runScheduledQuickScanSafely`, catches unexpected failures, bounds diagnostics, records scan error events, and sets visible UI error state; checkpoint 1565 adds an injectable timer factory that defaults to `Timer.periodic` and verifies a scheduled timer fire launches a detect-only quick scan with `scheduled_quick_scan_started` event evidence in `flutter test test\offline_scan_test.dart --reporter compact`; checkpoint 1658 verifies scheduled quick-scan settings/start category and severity at runtime in `offline_scan_test.dart` (`101`); checkpoint 1977 verifies a scheduled timer fire during active custom target selection logs `scheduled_quick_scan_skipped` with `Scan target selection is already in progress.`, makes no Local Core scan call, and does not log `scheduled_quick_scan_started`; installed app-lifetime scheduling UI/E2E remains partial |
| Flutter empty scan-target guard | `apps/zentor_client/lib/app/app_state.dart`, `tests/test_custom_driver_contract.py` | Central scan orchestration rejects empty target lists with a visible completed-with-errors scan report before reading `paths.first` or marking scan start in flight | Runtime fixture verified | Checkpoint 1302 source-verifies the empty-target guard, warning event, visible scan report, current-path clearing, and pre-`paths.first` ordering; checkpoint 1564 verifies the empty full-scan target fixture returns a completed-with-errors report, records `scan_targets_unavailable`, and does not call local-core scan IPC |
| Flutter scan-cancel controller guard | `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/lib/features/scan/scan_screen.dart`, `docs/client-ui.md` | Controller-level in-flight guard for scan cancellation before local-core cancel IPC launch plus visible cancel-control busy gating and explicit scan-category audit metadata | Runtime fixture verified; UI/E2E partial | Source-accounted in checkpoint 1144; busy-state UI source-accounted in checkpoint 1179; checkpoint 1564 adds and verifies a duplicate cancel runtime fixture where a second cancellation during pending cancel IPC is ignored visibly and does not call local core twice; checkpoint 1672 verifies ignored, duplicate, clean, fallback, and failed cancellation events carry `scan` category with warning/info/error severity in `offline_scan_test.dart` (`101`); installed UI/E2E cancel-control verification remains partial |
| Local file walker and scan scope | `core/zentor_local_core/src/scanner/file_walker.rs`, `scan_scope.rs`; `core/zentor_native_engine/src/scan/`; `apps/zentor_client/lib/core/scanning/scan_target_service.dart` | Scope selection, traversal limits, metadata checks, risky-file filtering, skipped path reporting including non-regular entries, visible quick-scan root probe failures, and UI quick/full/custom/protected-app scan target suggestions | Runtime partial; MVP verifier covered for current-host file-walker and native planner regressions | Checkpoint 1947 adds local-core `file_walker` (`7` passed) and native-engine `native_file_walker` (`3` passed) Cargo filters to `tools\testing\verify-small-threat-mvp.ps1`, covering quick/full walk behavior, non-following metadata guards, non-regular skip/error reporting guards, metadata-error honesty, and bounded/omitted walk-error details on this Windows host. Checkpoint 1948 adds native scan env-root validation (`3` passed), quick-scan root planning (`3` passed), and full-scan root planning (`1` passed) to the same verifier, covering relative/empty/parent-traversal env-root rejection, checked env-root use, non-following quick-root presence checks, quick-root inspection diagnostics, duplicate-free quick-root planning, and no current-directory/dot fallback for native full scans. Checkpoint 2051 expands Quick Scan risky-carrier selection for PowerShell module/data/type XML, JavaScript module variants, registry/URL/SCF/CHM, Office add-in/query, and OneNote package carriers; ANE now classifies `.ps1xml`, `.hta`, and `.wsf` into script-style analysis paths, and the full small-threat MVP verifier/report validator requires native file-type classifier regressions (`140` steps in `332.5s`). Checkpoint 2052 adds local-core Quick Scan runtime proof that inert `.hta` and `.wsf` script-host carriers in `Downloads` become review-only `SuspiciousDownloader` probable-malware detections with encoded-script and download-execute evidence, while confirmed-only auto-quarantine leaves the files in place; the full small-threat MVP verifier/report validator passed (`140` steps in `321s`). Checkpoint 2053 adds static registry/shortcut carrier indicators and review-only heuristics for `.reg` autorun plus remote/script-host evidence and `.url`/`.scf` remote executable/script URLs, with local-core Quick Scan proof for inert `autorun.reg` and `support.url` review detections, a native ordinary-web-link negative fixture, and full small-threat MVP verifier/report-validator evidence (`140` steps in `328.1s`). Checkpoint 2054 adds review-only `.iqy`/`.slk` Office query/spreadsheet carrier heuristics for remote executable/script URL or script-host evidence, with local-core Quick Scan proof for inert `remote-query.iqy` and `spreadsheet-link.slk` review detections, a native ordinary data-query negative fixture, and full small-threat MVP verifier/report-validator evidence (`140` steps in `325.3s`). Checkpoint 2055 adds review-only `.chm`/`.one`/`.onepkg` help/OneNote carrier heuristics for remote executable/script URL evidence or script-host plus downloader/execution terms, with local-core Quick Scan proof for inert `support.chm` and `meeting.onepkg` review detections, a native ordinary help-link negative fixture, and full small-threat MVP verifier/report-validator evidence (`140` steps in `308.3s`). Checkpoint 2056 adds review-only `.xlam`/`.xll` Office add-in carrier heuristics for remote executable/script URL evidence or script-host plus downloader/execution terms, with local-core Quick Scan proof for inert `addin-loader.xlam` and `report-addin.xll` review detections, a native ordinary add-in link negative fixture, and full small-threat MVP verifier/report-validator evidence (`140` steps in `350s`). Checkpoint 2057 adds local-core Quick Scan runtime proof that `.psm1`, `.psd1`, and `.ps1xml` PowerShell carrier files selected under `Downloads` route through script-style analysis and become review-only `SuspiciousDownloader` detections with encoded-script and download-execute evidence; the full small-threat MVP verifier/report-validator passed (`140` steps in `299.3s`). Checkpoint 2058 adds local-core Quick Scan runtime proof that `.jse`, `.mjs`, and `.cjs` JavaScript carrier files selected under `Downloads` route through script-style analysis and become review-only `SuspiciousDownloader` detections with encoded-script and download-execute evidence; the full small-threat MVP verifier/report-validator passed (`140` steps in `300.5s`). Checkpoint 2059 adds local-core Quick Scan runtime proof that `.bat`, `.cmd`, `.vbs`, and `.vbe` carriers selected under `Downloads` route through script-style analysis and become review-only `SuspiciousDownloader` detections with download-execute evidence plus encoded-script evidence for VBS/VBE; the full small-threat MVP verifier/report-validator passed (`140` steps in `302.2s`). Checkpoint 2060 adds UTF-16LE string-indicator extraction plus `.lnk` shortcut-carrier evidence under `shortcut_remote_executable_launch`, with native positive/negative `.lnk` fixtures and local-core Quick Scan proof for inert `support-link.lnk`; the full small-threat MVP verifier/report-validator passed (`140` steps in `318.1s`). Checkpoint 2061 adds `remote_network_executable_path_count` for UNC and remote `file://` executable/script references, negative fixtures for ordinary UNC documents and local `file:///` executable URLs, and local-core Quick Scan proof for inert `support-share.lnk`; the full small-threat MVP verifier/report-validator passed (`140` steps in `317.4s`). Platform-specific symlink/reparse/permission E2E remains partial where an approved host fixture is required. Flutter scan-target env validation source-accounted in checkpoint 803; Flutter scan-target env parent-traversal rejection source-accounted in checkpoint 1303; Flutter scan-target env NUL rejection source-accounted in checkpoint 1304; Flutter scan-target planning limitation evidence source-accounted in checkpoint 1078 and runtime/source-marker verified in checkpoint 1690 with `flutter test test\scan_target_service_test.dart test\offline_scan_test.dart --reporter compact` (`109 passed`), including uninspectable scan targets/watch paths kept visible for core validation and scan routing reporting target probe failures before IPC; Flutter scan-target probe diagnostic control/NUL normalization source-accounted in checkpoint 1313; protected-app action single-flight source-accounted in checkpoint 1157 and runtime-verified in checkpoint 1585 with `flutter test test\offline_scan_test.dart --reporter compact` (`96 passed`), including overlapping protected-app selection blocked during pending hash work; custom scan target-selection single-flight source-accounted in checkpoint 1162 |
| Local AI ONNX compatibility model | `core/zentor_local_core/src/ai/`, `ml/static_ml_schema.py`, `ml/build_features.py`, `ml/train_model.py`, `ml/evaluate_model.py`, `ml/export_onnx.py`, `assets/models/` | Offline advisory static model for local-core compatibility path plus fail-closed feature, training-summary, release metadata validation, strict model-metadata/threshold schemas, runtime metadata semantic validation, bounded actual-byte metadata reads, bounded ONNX output handling, health status visibility, and export evidence | Runtime fixture verified; development model only | Model is development-only and must not auto-quarantine by itself; checkpoint 1951 adds local-core `static_feature` (`7 passed`) to the small-threat MVP verifier for current-host static feature extraction proof. Checkpoint 1629 verifies local-core `model_metadata` (`7 passed`), `model_runner` (`13 passed`), and `static_feature` (`7 passed`) focused Cargo filters, covering strict metadata schemas, finite/ordered thresholds, required production metric evidence, packaged metadata parsing, development-model inactive state, env-path rejection, bounded metadata reads, directory rejection before metadata read, deterministic local output, explicit unknown top-category branch, non-following static-feature target metadata, bounded sample reads, and filename/extension default honesty. Checkpoint 1630 verifies `onnx_runtime_category_scores_stay_unit_bounded`, `local_ai_threat_builder_rejects_unsupported_labels`, and `local_ai_threat_builder_rejects_non_file_targets` focused Cargo filters (`1 passed; 0 failed` each) plus local-core rustfmt. Local-core warning debt remains visible; production dataset validation, replacement-race/symlink fixtures, and installed UI/E2E remain partial. Earlier source/tooling evidence remains: model root validation checkpoint 801, static evaluator checkpoint 823, static ONNX exporter checkpoint 826, feature-build/train tooling checkpoint 827, evaluator output checkpoint 849, static ML shared output helper checkpoint 852, Flutter AI health/status display checkpoints 890/1065/1133, local ONNX category-score bounds checkpoint 918, and local AI threat-label validation checkpoint 1117 |
| Local heuristic provider | `core/zentor_local_core/src/scanner/heuristic_provider.rs` | Compatibility/review heuristic signal provider with bounded sample reads and conservative heuristic-only auto-action policy helper | Runtime fixture verified; installed E2E partial | Checkpoint 1951 adds local-core `heuristic` (`19 passed`) to the small-threat MVP verifier, covering the current focused local heuristic fixture set for conservative auto-action gating, bounded script/entropy samples, non-following target inspection, and filename/default branch honesty. Checkpoint 1630 verifies `heuristic_auto_quarantine_requires_probable_verdict_and_independent_sources`, `obfuscated_script_detection_uses_bounded_sample`, and `entropy_detection_uses_bounded_sample` focused Cargo filters (`1 passed; 0 failed` each) plus local-core rustfmt; heuristic auto-quarantine policy bounds source-accounted in checkpoint 1119; heuristic sample chunk limits source-accounted in checkpoint 1283; existing local-core warning debt and installed UI/service E2E remain partial |
| Native/local product-path trust | `core/zentor_native_engine/src/trust/zentor_trust.rs`, `core/zentor_native_engine/src/engine.rs`, `core/zentor_native_engine/src/trust/publisher_trust.rs`, `core/zentor_local_core/src/scanner/heuristic_provider.rs` | Exact-root product artifact trust, repo-marker/product-trust diagnostics, publisher trust probe error evidence, quarantine trust root validation, and local heuristic suppression for legitimate product paths without trusting lookalike roots or installer-shaped filenames alone | Runtime fixture verified; installed E2E partial | Checkpoint 1614 verifies native exact-root trust, repo lookalike rejection, no false-default prefix checks, installer-name-only no-trust behavior, local heuristic Avorax installer/MSI no-trust behavior, and product-path trust error propagation with ten focused Cargo filters (`1 passed; 0 failed` each); checkpoint 1615 verifies repo-marker directory checks, repo-marker error honesty, Microsoft publisher trust probe error evidence, and quarantine trust root validation with six focused Cargo filters (`1 passed; 0 failed` each); `repo_marker_dirs_reject_symbolic_links` is Unix-gated and reports `0 tests` on Windows; targeted `rustfmt --check` passed for the involved native/local trust files; broad native-engine rustfmt still has existing out-of-scope formatting drift |
| Local YARA-style provider | `core/zentor_local_core/src/scanner/yara_provider.rs` | Local compatibility rule path for YARA-like development rules with bounded actual-byte runtime rule reads and bounded chunked sample prefixes | Disabled/compatibility by default; runtime fixtures verified | Not required for quick/full/custom scan, EICAR, quarantine, or Guard verdicts; checkpoint 1630 verifies `yara_rule_parser_requires_explicit_metadata`, `yara_provider_reads_only_bounded_sample`, and `yara_rule_reader_is_metadata_and_actual_byte_bounded` focused Cargo filters (`1 passed; 0 failed` each) plus local-core rustfmt; default rule root hardening source-accounted in checkpoint 800; local provider status label alignment with Flutter health allowed set source-accounted in checkpoint 1124; installed service/UI E2E remains partial |
| Checkpoint 1619 YARA/hash runtime fixtures | `core/zentor_local_core/src/scanner/yara_provider.rs`, `core/zentor_guard_service/src/main.rs`, `core/zentor_guard_service/src/driver_ipc.rs` | Focused runtime coverage for bounded local YARA sample reads, bounded Guard service/driver YARA rule reads, Guard/driver YARA path safety, and streaming Guard SHA-256 file hashing | Runtime fixture verified; symlink partial; installed E2E partial | Checkpoint 1619 verifies `yara_provider_reads_only_bounded_sample`, Guard/driver missing-file and directory rejection fixtures, Guard/driver oversized YARA rule rejection fixtures, and `guard_sha256_file_streams_full_file` with focused Cargo filters (`1 passed; 0 failed` each); Guard/driver YARA symlink fixtures are Unix-gated and report `0 tests` on Windows; installed Guard/local-core service E2E remains partial |
| Checkpoint 1620 local/Guard hash and compatibility fixtures | `core/zentor_local_core/src/app_control/`, `core/zentor_local_core/src/scanner/`, `core/zentor_guard_service/src/` | Focused runtime coverage for local app-control hash stores/policies, config staged writes, bounded heuristic/static/YARA/ClamAV samples, local ClamAV streaming/bounded behavior, and Guard hash trust/quarantine/IPC paths | Runtime fixture verified; warning debt and installed E2E partial | Checkpoint 1620 verifies local-core `app_control` (`47 passed; 0 failed`), `config_writer` (`4 passed; 0 failed`), `bounded_sample` (`5 passed; 0 failed`), `clamav` (`11 passed; 0 failed`), and Guard `hash` (`32 passed; 0 failed`) with focused Cargo filters. Existing local-core and Guard compile warning debt remains visible; installed service/driver E2E remains partial |
| ClamAV/YARA compatibility providers | `core/zentor_local_core/src/scanner/clamav_provider.rs`, `core/zentor_local_core/src/scanner/yara_provider.rs`, `core/zentor_guard_service/src/main.rs`, `core/zentor_guard_service/src/driver_ipc.rs` | Optional compatibility scanners/rules for development/comparison only with bounded command output, bounded local samples, bounded actual-byte YARA rule reads, and bounded local ClamAV scan hashing | Disabled/guarded by default; local runtime fixtures verified | Requires explicit configured/bundled absolute scanner or controlled executable/debug-marker rule roots; no ambient PATH/current-dir discovery; checkpoint 1630 verifies local-core `clamav` (`11 passed; 0 failed`) and `bounded_sample` (`5 passed; 0 failed`) focused Cargo filters plus local-core rustfmt; local/Guard ClamAV configured scanner NUL/parent-traversal rejection source-accounted in checkpoint 1217; Guard native/YARA asset-root hardening source-accounted in checkpoint 807; Guard YARA malformed string diagnostics source-accounted in checkpoint 906; Guard YARA confidence diagnostics source-accounted in checkpoint 907; local/Guard ClamAV command-output drain-with-retain-bounds source-accounted in checkpoint 1281; local/Guard/driver YARA sample chunk limits source-accounted in checkpoint 1283; local ClamAV signature sample chunk limits source-accounted in checkpoint 1284; local ClamAV infected-exit fallback evidence source-accounted in checkpoint 1111; local YARA metadata fail-closed parsing source-accounted in checkpoint 1116; local/Guard/driver YARA rule actual-byte read limits source-accounted in checkpoint 1278; local ClamAV UUID temp-fixture names source-accounted in checkpoint 1122; local ClamAV hash byte limits source-accounted in checkpoint 1261; installed Guard/local-core service E2E remains partial |
| Reputation provider | `core/zentor_local_core/src/scanner/reputation_provider.rs`, `apps/zentor_client/lib/core/local_core/local_core_client.dart`, Flutter Protection/Settings UI | Explicitly disabled no-op reputation surface that reports `unavailable` with a health reason, contributes no scan evidence until a real bounded backend exists, and remains visible in local health/UI | Disabled/blocked | No local/cloud reputation backend is configured; disabled no-op honesty source-accounted in checkpoint 1120; Flutter reputation health/state/Protection/Settings visibility source-accounted in checkpoint 1126; runtime backend work needs Cargo, Flutter/Dart runtime verification, and a real trust/reputation design |

## Trust, Allowlist, and Feedback Controls

| Engine/control | Primary source | Real responsibility | Status | Verification or blocker |
| --- | --- | --- | --- | --- |
| Native known-good and known-bad trust stores | `core/zentor_native_engine/src/trust/`, `assets/zentor_native/trust/` | Exact-hash trust and known-bad evidence with bounded actual-byte store reads and strict hash-list schemas | Runtime fixture verified; replacement/symlink partial | Checkpoint 1953 adds native-engine `trust_store` (`3 passed`), `known_good` (`6 passed`), and `known_bad` (`10 passed`) to the small-threat MVP verifier. Checkpoint 1626 verifies the same native trust-store bounded-reader, known-good, and known-bad focused Cargo filters, including strict unknown-field rejection, malformed hash rejection, oversized-store rejection, missing-store empty compatibility, and non-following presence markers. Replacement-race and Unix-only symlink fixtures remain platform-limited on this Windows host |
| Local app-control trust stores | `core/zentor_local_core/src/app_control/` | Known-good, known-bad, user approvals, publisher trust, policy decisions, strict trust-store schemas, bounded actual-byte store reads, validated passthrough roots, and script subpolicy profile propagation for local app control | Runtime fixture verified; warning debt and race/symlink partial | Checkpoint 1952 adds local-core `app_control` (`47 passed`) and `trust_store` (`10 passed`) to the small-threat MVP verifier. Checkpoint 1627 verifies the same local app-control focused Cargo filters, covering strict known-good/known-bad schemas, malformed hash branches, oversized store rejection, bounded store reads, exact passthrough root checks, script policy propagation, publisher trust validation, user-approval hash handling, and default asset-root hardening; `cargo fmt --manifest-path core\zentor_local_core\Cargo.toml -- --check` passes. Existing local-core warning debt remains visible; replacement-race and Unix-only symlink fixtures remain platform-limited. Earlier source evidence remains: local passthrough trust-root validation checkpoint 796, env-root NUL/parent-traversal rejection checkpoint 1211, default trust-store root hardening checkpoint 799, trusted-publisher config diagnostics checkpoint 903, Off-mode panic-route removal checkpoint 1192, script policy mode propagation checkpoint 1193, and passthrough lexical path matching checkpoint 1197 |
| User allowlist | `core/zentor_local_core/src/allowlist/`, `core/zentor_native_engine/src/trust/allowlist.rs`, `apps/zentor_client/lib/features/allowlist/allowlist_screen.dart` | User-controlled exclusions; never silently added; root and malformed-path entries fail closed; persisted entry schemas reject ignored trust controls; local trust-store path overrides are absolute local paths only; persisted allowlist reads and file/app/executable trust hashing are byte-bounded; overlapping add/remove trust mutations are blocked while local-core IPC is pending | Runtime fixture verified; installed UI/race/symlink partial | Checkpoint 1954 adds local-core `allowlist` (`37 passed`) and native-engine `allowlist` (`6 passed`) to the small-threat MVP verifier. Checkpoint 1628 verifies local-core `allowlist` focused Cargo coverage for strict persisted schemas, unsafe root blocking, traversal-safe folder matching, env-path rejection, oversized persisted-store rejection, bounded store reads, selected-file hash byte limits, directory rejection before hashing, staged writes, cleanup-error reporting, ID validation, explicit hash/path matching, malformed persisted hash rejection, and local-core confirmation/list error fixtures. Checkpoint 1629 verifies native `allowlist` focused Cargo filter (`6 passed`) covering broad-root rejection, exact hash matching, malformed-hash fail-closed behavior, component-aware path matching, and sibling-prefix rejection. Flutter allowlist mutation single-flight is runtime-verified in checkpoint 1577 (`88 passed`); local allowlist staged persistence is partially runtime-verified in checkpoint 1618. Replacement-race, Unix-only symlink, and installed Allowlist/Scan UI click-layout E2E remain partial |
| Checkpoint 1618 local allowlist runtime fixtures | `core/zentor_local_core/src/allowlist/allowlist_store.rs` | Focused runtime coverage for rejecting unsafe allowlist roots, staged allowlist persistence, and deactivation preserving entry history | Runtime fixture verified; installed E2E partial | Checkpoint 1618 verifies `blocks_unsafe_root_paths`, `save_uses_staged_write_without_temp_leftover`, and `deactivate_marks_entry_inactive_without_deleting_history` with focused Cargo filters (`1 passed; 0 failed` each); installed Allowlist UI E2E remains partial |
| Flutter app configuration repository | `apps/zentor_client/lib/core/config/config_repository.dart`, `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/lib/features/onboarding/onboarding_screen.dart` | Persist local security policy, cloud endpoints, onboarding state, scan scope, scheduling, and protection settings without reporting success after rejected storage writes, invalid enabled developer cloud overrides, reset side-effect cleanup failures, or overlapping reset operations | Runtime partial | Config validation and controller source coverage present; persistence acknowledgement source-accounted in checkpoint 870; developer cloud override validation source-accounted in checkpoint 1147, controller runtime-verified in checkpoint 1675 with `flutter test test\offline_scan_test.dart --reporter compact` (`102 passed`) including invalid enabled override rejection before config mutation or follow-up cloud health check, repository runtime-verified in checkpoint 1676 with `flutter test test\config_validation_test.dart --reporter compact` (`23 passed`) including invalid enabled override rejection before persisted JSON overwrite, Settings save-widget runtime-verified in checkpoint 1677 with `flutter test test\settings_accessibility_test.dart --reporter compact` (`5 passed`) including switch/text-field/dialog confirmation, fake health follow-up, success snackbar, controller state, and persisted JSON, Settings invalid-save widget runtime-verified in checkpoint 1678 with `settings_accessibility_test.dart` (`6 passed`) including visible failure message, unchanged state, no persisted JSON, no cloud health call, and no success snackbar, Settings disable widget runtime-verified in checkpoint 1679 with `settings_accessibility_test.dart` (`7 passed`) including disable dialog, build-config restoration, persisted disabled JSON, follow-up fake health call, and disabled snackbar, and Settings in-flight disabled controls runtime-verified in checkpoint 1680 with `settings_accessibility_test.dart` (`8 passed`) including disabled switch, endpoint/project/key fields, and save button while `developerCloudOverrideInFlight=true`; cloud config control/NUL rejection source-accounted in checkpoint 1321; raw cloud/protected-app config control-text validation source-accounted in checkpoint 1323; runtime Settings path-list control/NUL rejection source-accounted in checkpoint 1324 and runtime-verified in checkpoint 1575 with `flutter test test\config_validation_test.dart --reporter compact` (`22 passed`), including no core policy write and no persisted success after a control-character path; reset protection-stop/scheduler cleanup source-accounted in checkpoint 1148 and partially runtime-verified in checkpoint 1581 with `flutter test test\offline_scan_test.dart --reporter compact` (`92 passed`), including active-protection stop before reset defaults are applied; reset single-flight source-accounted in checkpoint 1149 and runtime-verified in checkpoint 1581, including duplicate reset rejection during pending Guard-mode IPC with no overlapping watcher stop; reset busy-state UI source-accounted in checkpoint 1176 and controller busy flag runtime-verified in checkpoint 1581; security settings single-flight source-accounted in checkpoint 1155 and runtime-verified in checkpoint 1579 with `flutter test test\offline_scan_test.dart --reporter compact` (`90 passed`), including no overlapping ransomware-guard IPC during pending Guard-mode IPC; security settings busy-state UI source-accounted in checkpoint 1168 and controller busy flag runtime-verified in checkpoint 1579; protected-app action single-flight source-accounted in checkpoint 1157 and runtime-verified in checkpoint 1585 with `flutter test test\offline_scan_test.dart --reporter compact` (`96 passed`), including overlapping protected-app selection rejection during pending build-hash work; protected-app action busy-state UI source-accounted in checkpoint 1178 and controller busy flag runtime-verified in checkpoint 1585; developer cloud override single-flight source-accounted in checkpoint 1160 and runtime-verified in checkpoints 1580/1675 with `offline_scan_test.dart`, including duplicate-save rejection during pending cloud health-check work and invalid-save rejection before health checks; developer cloud override busy-state UI source-accounted in checkpoint 1177 and runtime-verified in checkpoints 1580/1680; onboarding completion single-flight source-accounted in checkpoint 1161 and runtime-verified in checkpoint 1582 with `flutter test test\offline_scan_test.dart --reporter compact` (`93 passed`), including duplicate completion rejection during pending config persistence with one save; onboarding completion busy-state UI source-accounted in checkpoint 1184 and controller busy flag runtime-verified in checkpoint 1582; config-recovery diagnostic control/NUL normalization source-accounted in checkpoint 1314 and runtime-verified in checkpoint 1567; remaining installed reset/onboarding/protected-app/UI interaction and packaged E2E are partial |
| Optional cloud API client | `apps/zentor_client/lib/core/network/zentor_api_client.dart`, `services/api/` | Optional health, protection-run, heartbeat, detection-report, event, quarantine-metadata, risk, and ban telemetry/control with local preflight validation, transactional device registration/audit persistence, route-local acknowledged audit persistence with no unused audit helper, device-registration audit insert acknowledgement, quarantine metadata final payload-size validation and insert acknowledgement, security-event insert acknowledgement, detection-report insert acknowledgement, protection-run creation insert acknowledgement, ban creation insert acknowledgement, heartbeat event insert acknowledgement, end-session audit insert acknowledgement, bounded protection-run expiry, bounded client evidence timestamps, active/unexpired session write enforcement, heartbeat update acknowledgement, transactional session creation/end and heartbeat update/event persistence, device/project-scoped session, risk, and ban handling, transactional ban/audit persistence, explicit quarantine evidence upload/API persistence, strict top-level API request/event schemas, non-empty event batches and detection reports, validate-before-insert and transactional event batching, transactional detection-report/audit persistence, bounded JSON/diagnostics, explicit acknowledgement checks, streamed response-size bounds, and no cloud dependency for primary scanning | Source-accounted; runtime partial | Cloud is optional and disabled without real config; backend tests need Cargo/API smoke; Flutter cloud acknowledgement parse diagnostics source-accounted in checkpoint 900; Flutter cloud response streamed-size bounds source-accounted in checkpoint 1251; Flutter cloud diagnostics control/NUL normalization source-accounted in checkpoint 1317; Flutter cloud response status/error control/NUL normalization source-accounted in checkpoint 1320; Flutter cloud outbound metadata control/NUL rejection source-accounted in checkpoint 1321; Flutter cloud raw payload control-text rejection source-accounted in checkpoint 1323; cloud quarantine metadata preflight source-accounted in checkpoint 1381; cloud quarantine evidence persistence source-accounted in checkpoint 1382; cloud quarantine strict API schema source-accounted in checkpoint 1383; cloud API request strict schemas source-accounted in checkpoint 1384; cloud security-event wrapper strict schema source-accounted in checkpoint 1385; cloud security-event empty-batch rejection source-accounted in checkpoint 1386; cloud protection-run expiry bounds source-accounted in checkpoint 1387; cloud session write active/expiry enforcement source-accounted in checkpoint 1388; cloud ban device/project boundary source-accounted in checkpoint 1389; cloud device-risk project boundary source-accounted in checkpoint 1390; cloud protection-run device/project boundary source-accounted in checkpoint 1391; cloud detection-report empty aggregate rejection source-accounted in checkpoint 1392; cloud event batch validate-before-insert source-accounted in checkpoint 1393; cloud heartbeat active-update acknowledgement source-accounted in checkpoint 1394; cloud evidence timestamp bounds source-accounted in checkpoint 1395; cloud event batch transactionality source-accounted in checkpoint 1396; cloud detection-report transactionality source-accounted in checkpoint 1397; cloud heartbeat transactionality source-accounted in checkpoint 1398; cloud protection-run creation transactionality source-accounted in checkpoint 1399; cloud ban creation transactionality source-accounted in checkpoint 1400; cloud end-session transactionality source-accounted in checkpoint 1401; cloud device registration transactionality source-accounted in checkpoint 1402; cloud quarantine metadata payload-size validation source-accounted in checkpoint 1403; cloud quarantine metadata insert acknowledgement source-accounted in checkpoint 1404; cloud security-event insert acknowledgement source-accounted in checkpoint 1405; cloud detection-report insert acknowledgement source-accounted in checkpoint 1406; cloud protection-run creation insert acknowledgement source-accounted in checkpoint 1407; cloud ban creation insert acknowledgement source-accounted in checkpoint 1408; cloud device-registration audit insert acknowledgement source-accounted in checkpoint 1409; cloud heartbeat event insert acknowledgement source-accounted in checkpoint 1410; cloud end-session audit insert acknowledgement source-accounted in checkpoint 1411; cloud unused audit helper removal source-accounted in checkpoint 1412; Flutter heartbeat single-flight/fail-visible exception handling source-accounted in checkpoint 1143 and heartbeat success/failure event metadata runtime-verified in checkpoint 1658; Flutter manual cloud health-check single-flight/fail-visible handling source-accounted in checkpoint 1145; Flutter developer cloud override single-flight source-accounted in checkpoint 1160 and runtime-verified in checkpoint 1580 for duplicate override saves during pending cloud health-check work; Flutter cloud health busy-path visibility source-accounted in checkpoint 1166; Flutter cloud health busy-state UI source-accounted in checkpoint 1188 |
| False-positive and malicious feedback | `core/zentor_local_core/src/ai/training_labels.rs`, `risk/false_positive_policy.rs`, Flutter scan UI | Local JSONL training labels and future suppression/training evidence with validated absolute local storage roots, strict label/static-feature schemas, bounded actual-byte store reads, and duplicate user-feedback suppression while label IPC is pending | Runtime fixture verified; installed UI/race/symlink partial | Does not silently retrain or upload. Checkpoint 1954 adds local-core `training_label` (`21 passed`) to the small-threat MVP verifier. Checkpoint 1628 verifies the same focused Cargo coverage for false-positive suppression/revocation, malformed/missing/oversized store handling, strict top-level and nested feature schemas, unsafe ID rejection, relative/parent-traversal root rejection, no relative fallback, staged writes, cleanup-error reporting, actual-byte read bounds, and explicit empty latest-label branch. Flutter detection-feedback single-flight is runtime-verified in checkpoint 1576 (`87 passed`), including no duplicate `labelDetection` call during pending label IPC; installed Scan UI click/layout E2E, replacement-race, and Unix-only symlink fixtures remain partial |
| Publisher and product trust | `core/zentor_local_core/src/app_control/publisher_trust.rs`, `core/zentor_native_engine/src/trust/publisher_trust.rs`, `core/zentor_native_engine/src/trust/microsoft_trust.rs`, `core/zentor_native_engine/src/trust/zentor_trust.rs` | Authenticode/publisher evidence for exact trusted-publisher allow decisions and native Microsoft/Avorax local-artifact trust evidence with validated product/quarantine/repo roots | Runtime fixture verified; live Authenticode E2E partial | Checkpoint 1629 verifies native `zentor` (`12 passed`), `trust_root` (`3 passed`), and `microsoft` (`18 passed`) focused Cargo filters, covering exact product roots, quarantine root env validation, repo lookalike rejection, non-following repo marker checks, installer-name-only no-trust behavior, checked Microsoft system roots, component-boundary matching, bounded Authenticode command output, non-following candidate path inspection, and malformed Authenticode JSON fail-closed parsing. Local publisher exact-match is runtime-verified in checkpoint 1611. Live Authenticode verification with real Windows trust stores, signed binaries, and installed E2E remains partial; Unix-only repo symlink fixtures remain platform-limited |
| Threat-intel import and pack builder | `core/zentor_native_engine/src/threat_intel/`, `tools/zentor_intel/`, `assets/zentor_native/threat_intel/` | Safe import of hash/indicator intelligence into Avorax-owned packs with bounded local/network input parsing, strict indicator/source schemas, atomic pack output, and real-world coverage hygiene gates | Runtime fixture verified; network importer partial | Uses text indicators/metadata only; no live malware download or retention; checkpoint 1640 verifies native `threat_intel` (`12`) and representative pack-validator runs. Earlier evidence remains: shared intel input/output hardening source-accounted in checkpoint 832, helper rollout source-accounted in checkpoint 833, real-world coverage gate safe-enumeration/source-order hardening source-accounted in checkpoint 835, shared helper UUID-temp/reparse hardening source/fixture-accounted in checkpoint 855, Python temp-cleanup visibility source/fixture-accounted in checkpoint 861, GitHub API/source-config/manual IOC/hash-feed/developer hash metadata validations source/fixture-accounted in checkpoints 984-1006, and real-world wrapper subprocess/temp-output hardening source/fixture-accounted in checkpoints 999/1108. Live network importer and release-host E2E remain partial |
| Threat-intel hash category allowlist | `tools/zentor_intel/github_intel_common.py`, `tools/zentor_intel/import_hash_feed.py`, `tools/zentor_intel/import_github_hashes_only.py`, `tools/testing/run-threat-intel-category-smoke.ps1` | Requires hash-only imports to map explicit category metadata through the shared supported-category allowlist before JSONL output, preventing arbitrary or misspelled category text from becoming active definition metadata | Runtime fixture verified | Checkpoint 2039 adds `required_category(...)` and routes hash-feed plus developer hash-only imports through it. Harmless fake-hash smoke verifies `suspicious-script` normalizes to `suspiciousScript`, `rootkit_indicator` normalizes to `rootkitIndicator`, and invalid categories fail visibly for both importers. Python `py_compile` passed for changed threat-intel modules and source-contracts passed (`540`). Live network feed import and installed definition-update E2E remain partial. |
| Threat-intel pack category allowlist | `tools/zentor_intel/import_malware_report_iocs.py`, `tools/zentor_intel/compile_zentor_signatures.py`, `tools/zentor_intel/build_known_bad_from_github.py`, `tools/zentor_intel/compile_zentor_rules.py`, `tools/zentor_intel/validate_indicator_pack.py`, `tools/testing/run-threat-intel-category-smoke.ps1` | Extends supported-category enforcement to manual IOC import, signature compilation, known-bad pack output, rule pack output, and signature/rule pack validation so arbitrary categories cannot be written into or accepted from active definition packs | Runtime fixture verified | Checkpoint 2040 adds `optional_category(...)` for report-level category inheritance and routes compilers/validators through `required_category(...)`. Expanded harmless fake-hash/fake-string smoke verifies manual IOC `credential-theft-indicator` -> `credentialTheftIndicator`, signature compiler `exploit-dropper` -> `exploitDropper`, known-bad `security_tamper_indicator` -> `securityTamperIndicator`, rule compiler `persistence-indicator` -> `persistenceIndicator`, and invalid-category fail-visible behavior for import, compile, validate, known-bad, and rule flows. Python `py_compile` passed for changed threat-intel modules/contracts and source-contracts passed (`540`). Live network feed import, production feed operations, installed definition-update E2E, and driver-level pre-execution proof remain partial. |
| Threat-intel pack canonical category spelling | `tools/zentor_intel/github_intel_common.py`, `tools/zentor_intel/validate_indicator_pack.py`, `tools/testing/run-threat-intel-category-smoke.ps1` | Requires already-built `.zsig` and `.zrule` packs to contain canonical engine threat-category spelling, so validation cannot pass for alias text the native engine schema would reject | Runtime fixture verified | Checkpoint 2041 adds `required_canonical_category(...)` and uses it for signature/rule pack validation. Expanded harmless fake-string smoke verifies canonical compiled packs validate while non-canonical but supported aliases such as `exploit-dropper` in a signature pack and `persistence-indicator` in a rule pack fail visibly. Python `py_compile` passed for changed category/validator/contracts and source-contracts passed (`540`). Live network feed import, production feed operations, installed definition-update E2E, and driver-level pre-execution proof remain partial. |
| Threat-intel pack enum metadata allowlists | `tools/zentor_intel/github_intel_common.py`, `tools/zentor_intel/import_malware_report_iocs.py`, `tools/zentor_intel/compile_zentor_signatures.py`, `tools/zentor_intel/validate_indicator_pack.py`, `tools/testing/run-threat-intel-category-smoke.ps1` | Validates signature/rule enum-like metadata against supported native-engine vocabularies and normalizes action-policy aliases before output, preventing validator success for packs the native engine or compiler policy would reject | Runtime fixture verified | Checkpoint 2042 adds action-policy normalization (`review` -> `review_only`, `observation_only` -> `observe`) and validator allowlists for confidence, severity, signature type, action policy, file type filters, rule verdict/action, condition type, and PE import categories. Expanded harmless fake-pack smoke verifies invalid values fail visibly, source-contracts passed (`540`), and all bundled Avorax `.zsig`/`.zrule` packs validate with the stricter gate (`14`). Live network feed import, production feed operations, installed definition-update E2E, and driver-level pre-execution proof remain partial. |
| Threat-intel pack metadata verifier integration | `tools/testing/verify-small-threat-mvp.ps1`, `tools/testing/validate-small-threat-mvp-report.ps1`, `tools/testing/run-threat-intel-category-smoke.ps1`, `tests/test_custom_driver_contract.py` | Keeps the category/canonical-category/enum metadata smoke in the one-command small-threat MVP suite and rejects full-suite reports that omit that definition-chain coverage | Verifier integration verified | Checkpoint 2043 adds `Threat-intel pack metadata smoke` to the full verifier, adds `threat-intel pack metadata smoke` to the verified scope, and makes `validate-small-threat-mvp-report.ps1 -RequireFullSuite` require both. Focused smoke passed, source-contracts passed (`540`), PowerShell parser checks passed, and the full small-threat MVP verifier plus report validator passed with `138` steps in `.workflow\ultracode\avorax-hardening\results\2043-small-threat-mvp-full-report.json`. This is safe metadata-only verifier coverage; live network feed import, production feed operations, installed definition-update E2E, and driver-level pre-execution proof remain partial. |
| Bundled signature/rule pack verifier integration | `tools/testing/run-bundled-pack-validation.ps1`, `tools/testing/verify-small-threat-mvp.ps1`, `tools/testing/validate-small-threat-mvp-report.ps1`, `tools/zentor_intel/validate_indicator_pack.py`, `assets/zentor_native/signatures/`, `assets/zentor_native/rules/` | Validates every bundled active signature/rule pack through the Python pack validator as part of the one-command small-threat MVP suite, requires the expected shipped small-threat pack inventory so ransomware, infostealer, miner/PUP, persistence, or script-threat coverage cannot disappear while the report still claims full coverage, emits a required generated JSON inventory report with per-pack evidence, and content-validates that generated report during full-suite report validation | Verifier integration verified | Checkpoint 2044 adds `Bundled signature/rule pack validation` to the full verifier, adds `bundled signature/rule pack validation` to the verified scope, and makes the full-suite report validator require both. Checkpoint 2045 strengthens the script with expected-inventory checks for `8` signature packs and `6` rule packs; a temporary fixture missing `zentor_persistence.zrule` failed visibly with `Missing expected bundled rule pack: zentor_persistence.zrule`. Checkpoint 2046 adds `-ReportPath`, writes `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-bundled-pack-inventory.json`, and requires `generated_reports.bundled_pack_inventory` in full-suite reports. Checkpoint 2047 makes the report validator parse and verify that generated inventory's schema, status, repository, validator path, expected lists, counts, row count, duplicate-free rows, repository-relative paths, current byte sizes, extensions, expected directories, and validator-output evidence; a negative missing-row inventory failed with `bundled pack inventory report packs count must match total_pack_count: 13 vs 14`. Source-contracts passed (`540`), PowerShell parser checks passed, and the full small-threat MVP verifier plus report validator passed with `139` steps in `308.4s` for `.workflow\ultracode\avorax-hardening\results\2047-small-threat-mvp-full-report.json`. This is safe local pack validation/report evidence only; live network feed import, production feed operations, installed definition-update E2E, and driver-level pre-execution proof remain partial. |

## Protection and Monitoring Surfaces

| Engine/control | Primary source | Real responsibility | Status | Verification or blocker |
| --- | --- | --- | --- | --- |
| Protection dashboard UI | `apps/zentor_client/lib/features/protection/protection_screen.dart`, `apps/zentor_client/lib/app/app_state.dart` | Protection readiness checklist, Guard/driver state display, start/stop/self-test controls, and limited/protected-state copy gated by engine and driver evidence | Runtime fixture verified; visual/E2E partial | Checkpoint 1563 verifies focused Flutter fixture coverage in `app_visual_policy_test.dart` for protection labels, confirmations, protected-state evidence, self-test panels, and controller events; Core Service checklist status labels align with local-core health statuses in checkpoint 1060, local-core `unsupported` Core Service status is parser/label aligned in checkpoint 1062, watcher-mode labels align with local-core `stopped`/`userModeBestEffort` in checkpoint 1066, active watcher diagnostics/limitations drive limited-start warning evidence in checkpoint 1067, Quarantine readiness is no longer hardcoded Ready in checkpoint 1069, Native Engine unavailable checklist evidence is explicit in checkpoint 1070, Native Engine metric labels are status-aware in checkpoints 1071-1072, protection start/stop single-flight source-accounted in checkpoint 1150, protection start/stop busy-state UI source-accounted in checkpoint 1170, protection self-test single-flight source-accounted in checkpoint 1151, protection self-test busy-state UI source-accounted in checkpoint 1169, with driver/Guard/native-ML honesty source-accounted in checkpoints 1054-1056, driver-status unknown fallback source-accounted in checkpoint 1063, and Guard-status unknown fallback source-accounted in checkpoint 1064; installed Windows visual/screenshot E2E remains partial |
| Guard Service | `core/zentor_guard_service/src/` | Background/post-launch monitoring, strict stdin command schema, driver-facing verdict service, known-good/known-bad caches, bounded known-bad cache reads, bounded guard-mode config reads, bounded process/quarantine SHA-256 evidence, process stop/reporting, strict guard-mode policy parsing, fail-visible unsupported-platform service mode, driver-health/self-test probe diagnostics including unsupported-platform reporting, explicit handler-vs-installed-service wording, bounded self-test hash evidence, bounded actual-byte AI metadata self-test evidence, computed post-launch fallback evidence, guard-mode-derived health fallback availability, evidence-derived legacy self-test service fields, disabled unverified verdict-cache evidence, controlled native/YARA asset discovery, and AI metadata self-test evidence | Source-accounted; runtime partial | Guard installed service smoke still needs a Windows service fixture; Guard stdin command size and bounded line-reader fixtures runtime-verified in checkpoint 1605 with `cargo test --manifest-path core\zentor_guard_service\Cargo.toml oversized_json_before -- --test-threads=1` (`2 passed`) and `cargo test --manifest-path core\zentor_guard_service\Cargo.toml guard_command_reader -- --test-threads=1` (`1 passed`); Guard IPC field bounds runtime-verified in checkpoint 1606 with `rejects_oversized` (`11 passed`), `rejects_nul` (`1 passed`), `command_known_bad_hashes_reject_excessive_entries` (`1 passed`), and `external_driver_scan_ignores_caller_supplied` (`3 passed`); driver-health helper nonzero exit reporting source-accounted in checkpoint 785; Guard driver-health System32 tool-root parent-traversal rejection source-accounted in checkpoint 1204; Guard driver-health bounded timeout command runner source-accounted in checkpoint 1285; Guard driver-health cleanup-failure visibility source-accounted in checkpoint 1298; Guard config/event/quarantine env-root parent-traversal rejection source-accounted in checkpoint 1216; Guard config/quarantine metadata text read byte limits source-accounted in checkpoint 1270; Guard driver-health non-Windows unsupported-platform reporting source-accounted in checkpoint 941; Guard service-mode unsupported-platform behavior source-accounted in checkpoint 943; Guard self-test handler evidence wording source-accounted in checkpoint 944; Guard self-test fallback evidence source-accounted in checkpoint 945; Guard self-test verdict-cache disabled evidence source-accounted in checkpoint 946; Guard health fallback availability source-accounted in checkpoint 951; Guard self-test legacy status evidence source-accounted in checkpoint 952; known-bad default root hardening source-accounted in checkpoint 798; native/YARA asset-root hardening source-accounted in checkpoint 807; self-test AI metadata root hardening source-accounted in checkpoint 811; Guard self-test AI metadata actual-byte read limits source-accounted in checkpoint 1275; Guard fatal-log staged activation source-accounted in checkpoint 856; Guard self-test fixture creation source-accounted in checkpoint 859; guard-mode JSON schema/value strictness source-accounted in checkpoint 909; stdin command strict-schema hardening source-accounted in checkpoint 910; known-bad cache strict-schema hardening source-accounted in checkpoint 913; Guard known-bad cache actual-byte read limits source-accounted in checkpoint 1274; Guard process hash-cache identity source-accounted in checkpoint 1110; Guard process command bounded runner source-accounted in checkpoint 1286; Guard process/quarantine hash byte limits source-accounted in checkpoint 1262; Guard self-test hash byte limits source-accounted in checkpoint 1263; Guard process-observer skip lexical path matching source-accounted in checkpoint 1201; Guard System32 tool-root parent-traversal rejection source-accounted in checkpoint 1203 |
| Guard trusted-publisher exact-match | `core/zentor_guard_service/src/driver_ipc.rs`, `core/zentor_guard_service/src/main.rs` | Requires canonical exact trusted-publisher matches for Guard driver verdict allow decisions and ignores caller-supplied trusted-publisher metadata in external driver scan commands | Runtime fixture verified; installed E2E partial | Checkpoint 1612 verifies `trusted_publisher_requires_exact_canonical_name`, `driver_request_trusted_publisher_allows_in_lockdown`, `driver_request_avorax_publisher_allows_in_lockdown`, and `external_driver_scan_ignores_caller_supplied_trusted_publisher` with focused Cargo filters (`1 passed; 0 failed` each); `rustfmt --check core\zentor_guard_service\src\main.rs core\zentor_guard_service\src\driver_ipc.rs` passed; installed Guard/driver E2E remains partial |
| Guard fail-open exact-root | `core/zentor_guard_service/src/driver_ipc.rs` | Requires exact configured/conventional Windows runtime, product, and quarantine roots before fail-open verdicts can become `SystemTrusted`; lookalike paths do not inherit allow status | Runtime fixture verified; installed E2E partial | Checkpoint 1613 verifies `fail_open_paths_require_exact_runtime_roots`, `lookalike_runtime_paths_do_not_allow_in_lockdown`, and `driver_fails_open_for_avorax_runtime_paths` with focused Cargo filters (`1 passed; 0 failed` each); `rustfmt --check core\zentor_guard_service\src\main.rs core\zentor_guard_service\src\driver_ipc.rs` passed; live driver/pre-execution E2E remains blocked on signed driver and approved elevated VM |
| Guard finite process-watch limitations | `core/zentor_guard_service/src/main.rs`, `tests/test_custom_driver_contract.py`, `tools/testing/verify-small-threat-mvp.ps1` | Counts metadata/hash/native/compat inspection failures plus Windows/Linux process-enumeration coverage gaps and prevents either class from becoming a clean finite-watch result | Windows runtime, source contract, and native hosted Linux verified; installed service E2E partial | Checkpoint 2189 supersedes the old source-only blocker. Inspection-only failures retain `watchCompletedWithInspectionErrors`; collection gaps return `watchCompletedWithCoverageGaps`, and combined failures use a distinct action. Zero-row snapshots create a gap rather than clean success. Deterministic completion tests, real Windows command-channel evidence, Guard `234/234`, checkpoint filter `8/8`, workspace `1,466/1,466`, and source contracts `626/626` pass. Avorax CI `32350190743`, job `96367469456`, executes the exact locked native Ubuntu filter and passes `8/8`; installed LocalSystem service E2E remains pending. |
| Guard driver IPC and driver port | `core/zentor_guard_service/src/driver_ipc.rs`, `driver_port.rs` | Translate driver/process requests into bounded native verdict replies, strict nested scan-request schemas, bounded local SHA-256 evidence, and driver-facing compatibility rule evidence | Source-accounted; pre-execution blocked | Requires built/signed driver and approved elevated VM for live verification; driver IPC temp fail-open root removal source-accounted in checkpoint 797; driver IPC native/YARA asset-root hardening source-accounted in checkpoint 807; driver trusted-publisher config diagnostics source-accounted in checkpoint 905; nested scan-request strict-schema hardening source-accounted in checkpoint 912; Guard driver local hash byte limits source-accounted in checkpoint 1252; driver IPC YARA sample chunk limits source-accounted in checkpoint 1283; Guard fail-open lexical path matching source-accounted in checkpoint 1198; Guard fail-open env-root NUL/parent-traversal rejection source-accounted in checkpoint 1220 |
| Pre-execution policy | `core/zentor_guard_service/src/preexecution_policy.rs` | Policy model for driver-assisted blocking when driver is installed and self-tested | Technically limited | UI/docs must not claim active pre-execution blocking without self-test evidence |
| User-mode realtime watcher | `core/zentor_local_core/src/watcher/`, `protection/file_monitor.rs`, Flutter Protection UI | Best-effort folder monitoring while app/local core is active | Partial/limited | Not kernel pre-execution blocking; full watcher tests need installed local-core; Flutter watcher-mode parser/label alignment source-accounted in checkpoint 1066; active watcher diagnostics/limitations event honesty source-accounted in checkpoint 1067; active-without-paths diagnostics source-accounted in checkpoint 1068; Flutter local watch-path probe diagnostics source-accounted in checkpoint 1077; local-core empty/all-invalid watch plans report stopped mode plus explicit no-path limitations in checkpoint 1515 |
| Local Core native self-test health evidence | `core/zentor_local_core/src/main.rs`, `apps/zentor_client/lib/core/local_core/local_core_client.dart`, `apps/zentor_client/lib/app/app_state.dart` | Native engine self-test status/error reporting for Protection and Settings readiness evidence | Source-accounted; runtime partial | Local Core now derives `native_self_test` and `native_self_test_error` together so self-test execution errors retain context instead of becoming a bare false in checkpoint 1516; Flutter parser/state/display wiring source-accounted in checkpoint 1130; Cargo/rustfmt and Flutter/Dart runtime verification remain blocked |
| Process monitor and behavior monitor | `core/zentor_local_core/src/protection/process_monitor.rs`, `behavior_monitor.rs`, `core/zentor_local_core/src/api/mod.rs`, `core/zentor_native_engine/src/behavior/`, `apps/zentor_client/lib/core/local_core/local_core_client.dart`, `apps/zentor_client/lib/core/apps/app_detector.dart`, `apps/zentor_client/lib/features/protected_apps/protected_apps_screen.dart` | Suspicious process/activity observation, bounded snapshot scoring, behavior scoring, and protected-app UI detection suggestions; local-core health separates capability from active status and Flutter surfaces monitor evidence | Snapshot evaluator, IPC, Flutter client, bounded app-detector observation extraction, controller event submission, Protected Apps event-evidence UI, app-lifetime controller loop, routine event dedupe, loop-start failure visibility, loop state/UI visibility, active-loop Protected Apps evidence, newest-evidence timestamp selection, visible UTC evidence timestamp, verifier-scope wording, and report-validator scope enforcement runtime/source verified; installed service/driver loop blocked | Must remain visible and bounded; local process/behavior monitor health reports `notActive` with explicit reasons until an installed polling/observation service or driver exists, source-accounted in checkpoint 1123 and refreshed in checkpoint 1761 to clarify snapshot-only capability; checkpoint 1761 adds runtime-verified local-core process snapshot evaluation with strict schemas, bounded inventory/text/findings, exact normalized allowlists, parent-traversal rejection, and explainable suspicious-process findings for encoded/hidden script hosts, remote-transfer tool arguments, and unsigned user-writable process images (`process_monitor` passed with `5`); checkpoint 1762 wires the evaluator into strict Local Core IPC as `evaluate_process_snapshot`, verifies suspicious snapshot reporting, exact allowlisting, nested unknown-field rejection, and no active-loop claim (`process_snapshot` passed with `3`; full local-core passed with `418`); checkpoint 1763 adds Flutter client models/parser support, accepts `userModeSnapshot` health capability, and verifies process snapshot IPC parsing/protocol warnings with `local_core_ipc_diagnostics_test.dart` (`59`) plus `flutter analyze`; checkpoint 1764 extends AppDetector to produce bounded `ProcessObservation` snapshots from checked `tasklist.exe`/`ps` output with PID parsing, text normalization, parent-traversal rejection, inventory limits, and no ambient PATH lookup (`app_detector_test.dart` passed with `8`); checkpoint 1765 submits protected-app detection snapshots to Local Core from `ZentorController`, records `process_snapshot_evaluated`/`process_snapshot_suspicious`/`process_snapshot_failed` local events with bounded evidence, and verifies the suspicious-event path (`local_event_test.dart` passed with `40`; combined Flutter suite passed with `107`; `flutter analyze` passed); checkpoint 1766 surfaces process snapshot local events on Protected Apps with explicit evaluated/suspicious/empty/failed labels and bounded detail text (`app_visual_policy_test.dart` + `local_event_test.dart` passed with `98`; broader process-snapshot Flutter suite passed with `165`; `flutter analyze` passed); checkpoint 1967 adds a two-minute app-lifetime controller loop while protection is active, with no immediate host read, single-flight evaluation, visible empty/evaluated/suspicious/failed events, and stop/dispose cancellation verified by focused Flutter tests; checkpoint 1968 deduplicates identical routine process snapshot loop info events without skipping timer evaluations or warning/failure evidence; checkpoint 1969 surfaces process snapshot timer-start failures in both `protection_start_limited` and visible `state.errorMessage`; checkpoint 1970 adds `processSnapshotLoopStatus`/reason state updates for active, attention, limited, and off loop states and surfaces those details in the Protection `Process monitors` card; checkpoint 1972 extends the Protected Apps evidence panel to the `process_snapshot_loop_*` active-protection event family with rendered widget coverage for loop-suspicious details; checkpoint 1973 makes the Protected Apps evidence helper choose the newest matching process snapshot/app-lifetime loop event by `createdAt` so stale evidence is not selected from noncanonical event order; checkpoint 1974 renders the selected event's UTC timestamp in the panel so recency is visible to users and tests; checkpoint 1975 makes the small-threat verifier's generated scope text explicitly name Protected Apps process-evidence newest ordering and UTC timestamp visibility; checkpoint 1976 makes full-suite report validation fail if that scope is missing; Flutter health/state/Protection UI monitor evidence wiring source-accounted in checkpoint 1125; installed service/driver process loop, installed Protected Apps UI click/layout E2E, kernel enforcement, and driver-backed enforcement remain partial/blocked |
| Ransomware guard | `core/zentor_local_core/src/protection/ransomware_guard.rs`, `core/zentor_local_core/src/main.rs`, `core/zentor_native_engine/src/behavior/ransomware_guard.rs`, `docs/ransomware-guard.md`, `tools/simulators/zentor-benign-ransomware-simulator/` | Activity-window ransomware detection, protected-root/trusted-process policy, persisted local policy validation, bounded actual-byte policy reads, recovery-aware warning/stop decisions, and benign temp-only simulator validation | Runtime fixture verified for local policy/config; installed E2E partial | Settings changes are confirmation-gated; checkpoint 1949 adds the local-core `ransomware_guard` filter (`21` passed) to `tools\testing\verify-small-threat-mvp.ps1`, covering benign protected-root activity detection, traversal-outside-root rejection, trusted-process suppression boundaries, trusted-process collapsed path equivalence, persisted config strict schema/value validation, directory/symlink/path-safety markers, staged writes, oversized config rejection before parse, and metadata/actual-byte bounded config reads. Benign simulator root-safety hardening source/fixture-accounted in checkpoint 853; simulator exclusive fixture writes source/fixture-accounted in checkpoint 860; Flutter security settings single-flight source-accounted in checkpoint 1155 and runtime-verified in checkpoint 1579 for overlapping settings writes; security settings busy-state UI source-accounted in checkpoint 1168 and controller busy flag runtime-verified in checkpoint 1579; installed watcher/service E2E and live-ransomware validation remain partial or disabled |
| Recovery Vault | `core/zentor_local_core/src/protection/recovery_manager.rs`, `docs/recovery-vault.md` | Protected backup/restore support for recovery scenarios with exclusive byte-bounded vault/restore copies, bounded integrity hashing, and visible partial cleanup | Source-accounted; runtime partial | Does not claim decryption without backups/keys; full restore fixtures need Cargo; Recovery Vault copy byte limits and partial cleanup source-accounted in checkpoint 1258; Recovery Vault hash byte limits source-accounted in checkpoint 1267 |
| Windows minifilter validation path | `core/zentor_windows_minifilter/`, `core/zentor_windows_minifilter_driver/`, `tools/windows/avorax-fix-driver-live.ps1`, `tools/windows/avorax-enable-test-signing.ps1`, `tools/security/zentor-protection-gate.ps1` | Driver development, install, self-test, signing, guarded live remediation, TESTSIGNING helper instructions, protection gate evidence, bounded setup-report consumption, bounded self-test subprocess output, and validation scripts | Blocked/guarded | Requires WDK/VS, signing, explicit confirmation, and approved elevated VM; live remediation report/helper default-root hardening source-accounted in checkpoint 817; TESTSIGNING helper instruction hardening source-accounted in checkpoint 819; protection self-test JSON parsing hardening source-accounted in checkpoint 829; driver setup-report JSON hardening source-accounted in checkpoint 841; minifilter self-test output/JSON hardening source-accounted in checkpoint 842; PowerShell JSON helper normalization source-accounted in checkpoint 845; PowerShell `File.Replace` backup compatibility source-accounted in checkpoint 848; Flutter protection self-test step diagnostics source-accounted in checkpoint 896 and runtime-verified for Guard self-test parser fixtures in checkpoint 1664; protection-gate bounded handle reader source/fixture-accounted in checkpoint 1007; System32/setup-report bounded handle reader source/fixture-accounted in checkpoint 1011; TESTSIGNING helper bcdedit diagnostic bounds source-accounted in checkpoint 1085; live remediation top-level bcdedit/schtasks diagnostic bounds source-accounted in checkpoint 1086; firmware reboot shutdown diagnostic bounds source-accounted in checkpoint 1087; setup-dev TESTSIGNING bcdedit diagnostic bounds source-accounted in checkpoint 1089; driver log collection command diagnostic bounds source-accounted in checkpoint 1090; generated post-reboot remediation command diagnostic bounds source-accounted in checkpoint 1091; live remediation final-error diagnostic bounds source-accounted in checkpoint 1092; driver install/uninstall final-error report bounds source-accounted in checkpoint 1093; driver build/sign/cert/self-test final-error report bounds source-accounted in checkpoint 1094; driver build MSBuild/link diagnostic bounds source-accounted in checkpoint 1095; setup-dev vswhere discovery diagnostic bounds source-accounted in checkpoint 1096; protection self-test wrapper child-command diagnostic bounds source-accounted in checkpoint 1097; protection-gate Cargo command diagnostic bounds source-accounted in checkpoint 1100; minifilter setup-delegation command diagnostic bounds source-accounted in checkpoint 1106 |
| Windows process guard validation path | `core/zentor_windows_process_guard/`, `core/zentor_windows_guard_driver/` | Process guard driver development, bounded setup-report consumption, and validation path | Blocked/guarded | Same elevated driver-development blockers as minifilter; process-guard setup-report JSON hardening source-accounted in checkpoint 841; PowerShell JSON helper normalization source-accounted in checkpoint 845; PowerShell `File.Replace` backup compatibility source-accounted in checkpoint 848; System32/setup-report bounded handle reader source/fixture-accounted in checkpoint 1011; process-guard wrapper delegation command diagnostic bounds source-accounted in checkpoint 1107 |
| AMSI/fanotify/macOS extension paths | `core/zentor_amsi_provider/`, `core/zentor_linux_fanotify_guard/`, `core/zentor_macos_endpoint_extension/` | Platform-specific validation/development paths | Partial/development | Not release claims without platform-specific build/signing validation |

## Quarantine, Updates, and Evidence Controls

| Engine/control | Primary source | Real responsibility | Status | Verification or blocker |
| --- | --- | --- | --- | --- |
| Flutter selected-file hash service | `apps/zentor_client/lib/core/security/hash_service.dart`, `apps/zentor_client/test/hash_service_test.dart`, `apps/zentor_client/test/offline_scan_test.dart` | Hash selected protected-app files as local verification evidence while rejecting links, folders, oversized files, and post-stat type changes; stream SHA-256 input without buffering whole files | Runtime partial | Checkpoint 1249 adds source-marker coverage for `maxSelectedHashFileBytes`, pre-read and actual-read size checks, post-stat type revalidation, and streaming chunked SHA-256; checkpoint 1585 runtime-verifies controller behavior around a pending selected-file hash so overlapping protected-app selection is rejected and the original app path receives the final hash; checkpoint 1589 runtime-verifies selected directory rejection and oversized selected-file rejection before streaming/progress callbacks with `flutter test test\hash_service_test.dart --reporter compact` (`4 passed`) and full `flutter test --reporter compact` (`443 passed`); replacement-race and symlink/junction fixtures remain partial until a provisioned filesystem host is available |
| Flutter update package hash input bounds | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Reject oversized staged/cached `.aup` hash inputs and revalidate regular-file status before SHA-256 streaming in download, verify, and install flows | Source-accounted; runtime partial | Checkpoint 1248 adds source-marker coverage for `_rejectOversizedPackage(await file.length(), 'update package hash input')` and post-size regular-file revalidation; checkpoint 1551 passes the full Flutter client test suite |
| Flutter update network timeouts | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Bound update HTTP request send time and remote metadata/package/redirect stream read idle time so update workflows cannot hang indefinitely on stalled peers | Source-accounted; runtime partial | Checkpoint 1247 adds source-marker coverage for `updateNetworkRequestTimeout`, `updateNetworkReadTimeout`, request `.timeout(...)`, and remote stream `.timeout(...)`; Flutter/Dart timeout fixture runtime tests remain blocked until a provisioned host is available |
| Flutter subprocess timeout cleanup evidence | `apps/zentor_client/lib/core/local_core/local_core_client.dart`, `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/lib/core/platform/platform_info_service.dart`, `apps/zentor_client/lib/core/apps/app_detector.dart`, related Flutter tests | Visible timeout cleanup evidence for local-core scan IPC, Guard self-test IPC, cancel IPC, elevated PowerShell, update-service child processes, platform PowerShell probes, and protected-app process enumeration | Source-accounted; runtime partial | Checkpoint 1290 source-accounts local-core scan IPC timeout kill-result evidence; checkpoint 1291 source-accounts updater timeout kill-result evidence; checkpoint 1318 source-accounts updater stdout/stderr control/NUL normalization before timeout/nonzero-exit diagnostics; checkpoint 1292 source-accounts Guard self-test, cancel IPC, elevated PowerShell, platform PowerShell, and app-detection process-list timeout kill-result evidence; Flutter/Dart runtime timeout fixtures remain blocked until a provisioned host is available |
| Flutter Windows helper root validation | `apps/zentor_client/lib/core/local_core/local_core_client.dart`, `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/lib/core/platform/platform_info_service.dart`, `apps/zentor_client/lib/core/apps/app_detector.dart`, `tests/test_custom_driver_contract.py` | Resolve WindowsPowerShell, `tasklist.exe`, Explorer, and elevation helper paths from checked `SystemRoot`/`WINDIR` roots without ambient PATH lookup, silent `C:\Windows` fallback, NUL roots, or parent-traversing roots | Source-accounted; runtime partial | Checkpoint 1305 source-verifies NUL and parent-traversal rejection before Flutter helper command-path construction; Windows runtime fixtures remain blocked until Flutter/Dart and a Windows smoke host are available |
| Flutter update redirect body bounds | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Follow only explicitly allowed update redirects while bounding any redirect response body drained before the next hop | Source-accounted; runtime partial | Checkpoint 1246 adds source-marker coverage for `maxUpdateRedirectBodyBytes`, `_drainBoundedRedirectBody`, and removal of unbounded `drain<void>()`; Flutter/Dart redirect fixture runtime tests remain blocked until a provisioned host is available |
| Flutter local update package copy revalidation | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Revalidate local `.aup` source paths after bounded streaming and before staged package hash/cache activation | Source-accounted; runtime partial | Checkpoint 1245 adds source-marker coverage for post-stream `_requireRegularFile(source.path, 'local update package source')`; Flutter/Dart race-fixture runtime tests remain blocked until a provisioned host is available |
| Update package payload actual-byte limits | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Enforce per-entry and aggregate payload byte limits against bytes actually read during payload hashing and extraction, not only ZIP-declared uncompressed sizes | Source-accounted; runtime partial | Checkpoint 1244 adds source-marker coverage for `sha256_reader_limited`, `copy_reader_limited`, aggregate extraction byte tracking, and removal of direct `std::io::copy` from payload extraction; Cargo/rustfmt and malformed ZIP fixture execution remain blocked until a provisioned Rust host is available |
| Update package payload activation parent-chain revalidation | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Revalidates the target parent chain against the canonical extraction destination immediately before renaming each extracted payload temp file into place | Source-accounted; runtime partial | Cargo/rustfmt extraction race/reparse fixture execution blocked in this shell; parent-chain activation revalidation source-accounted in checkpoint 1505 |
| Update staged-file activation parent-chain revalidation | `core/avorax_update_service/src/path_safety.rs`, `tests/test_custom_driver_contract.py` | Revalidates the target parent chain against the operation boundary after target removal and immediately before renaming staged temp files into place | Source-accounted; runtime partial | Cargo/rustfmt staged activation race/reparse fixture execution blocked in this shell; staged activation parent-chain revalidation source-accounted in checkpoint 1506 |
| Update staged-file source-open revalidation | `core/avorax_update_service/src/path_safety.rs`, `tests/test_custom_driver_contract.py` | Revalidates staged copy sources as regular bounded files before open, compares opened handle metadata against pre/post-open source metadata, and fails closed before copying bytes if the source changes | Source-accounted; runtime partial | Cargo/rustfmt source replacement race fixture execution blocked in this shell; staged source-open revalidation source-accounted in checkpoint 1507 |
| Update apply payload-section pre-enumeration revalidation | `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Revalidates app, service, engine, and docs payload-section roots as directory/non-reparse paths immediately before enumeration | Source-accounted; runtime partial | Cargo/rustfmt staging-root replacement race fixture execution blocked in this shell; payload-section pre-enumeration revalidation source-accounted in checkpoint 1508 |
| Update apply install-root pre-activation revalidation | `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Revalidates the canonical install root as an existing directory/non-reparse path after canonicalization and immediately before payload-section activation | Source-accounted; runtime partial | Cargo/rustfmt install-root replacement race fixture execution blocked in this shell; install-root pre-activation revalidation source-accounted in checkpoint 1509 |
| Rollback install-root pre-restore revalidation | `core/avorax_update_service/src/rollback.rs`, `tests/test_custom_driver_contract.py` | Revalidates the canonical rollback restore install root as an existing directory/non-reparse path after canonicalization and immediately before copying snapshot items | Source-accounted; runtime partial | Cargo/rustfmt rollback install-root replacement race fixture execution blocked in this shell; rollback install-root pre-restore revalidation source-accounted in checkpoint 1510 |
| Rollback snapshot canonical-root revalidation | `core/avorax_update_service/src/rollback.rs`, `tests/test_custom_driver_contract.py` | Revalidates canonical rollback root and canonical snapshot directories as existing directory/non-reparse paths before restore reads snapshot contents | Source-accounted; runtime partial | Cargo/rustfmt rollback root/snapshot replacement race fixture execution blocked in this shell; canonical snapshot revalidation source-accounted in checkpoint 1511 |
| Rollback latest-snapshot root enumeration | `core/avorax_update_service/src/rollback.rs`, `tests/test_custom_driver_contract.py` | Enumerates latest rollback snapshots from a canonical revalidated rollback root before selecting safe snapshot entries | Source-accounted; runtime partial | Cargo/rustfmt rollback-root replacement race fixture execution blocked in this shell; latest-snapshot root enumeration source-accounted in checkpoint 1512 |
| Update failure-path staging cleanup context | `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Includes staging cleanup failures in returned update-apply error context as well as structured update reports across stop/apply/rollback/restart failure paths | Source-accounted; runtime partial | Cargo/rustfmt failure-path cleanup fixture execution blocked in this shell; cleanup context propagation source-accounted in checkpoint 1513 |
| Signed `.aup` non-empty payload validation | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Rejects archives with zero payload files before payload hashing or extraction can report success | Source-accounted; runtime partial | Cargo/rustfmt empty-payload archive fixture execution blocked in this shell; non-empty payload validation source-accounted in checkpoint 1502 |
| Flutter local update-feed file bounds | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Bound local `file:` update-feed JSON reads while streaming and recheck regular-file status around the read before parser use | Source-accounted; runtime partial | Checkpoint 1243 adds source-marker coverage for `_readBoundedUtf8File`, `file.openRead()`, accumulated byte checks, and removal of the local feed `readAsString()` path; checkpoint 1551 passes the full Flutter client test suite |
| Flutter update metadata response bounds | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Bound remote update-feed and GitHub release fallback JSON response bodies while streaming, before constructing buffered `http.Response` objects for existing parser code | Runtime fixture verified; installed E2E partial | Checkpoint 1242 adds source-marker coverage for bounded chunk accumulation and removal of `http.Response.fromStream`; oversized remote update-feed metadata without `Content-Length` is runtime-verified in checkpoint 1592 with `flutter test test\update_service_test.dart --reporter compact` (`89 passed`) and full `flutter test --reporter compact` (`447 passed`); oversized GitHub releases metadata without `Content-Length` is runtime-verified in checkpoint 1593 with focused `90 passed` and full `448 passed`; stalled remote update-feed response timeout is runtime-verified in checkpoint 1594 with focused `92 passed` and full `450 passed`; stalled GitHub releases metadata response timeout is runtime-verified in checkpoint 1595 with focused `94 passed` and full `452 passed`; stalled package-download stream timeout is runtime-verified in checkpoint 1597 with focused `96 passed` and full `454 passed`; installed Windows update-flow E2E remains partial |
| Flutter update network timeout diagnostics | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart`, `tests/test_custom_driver_contract.py` | Keeps update network request/read timeouts finite by default, validates injected timeout overrides as positive, and reports stalled request/stream failures with labeled diagnostics instead of raw swallowed exceptions | Runtime fixture verified; installed E2E partial | Checkpoints 1594, 1595, 1596, and 1597 runtime-verify stalled update-feed/GitHub metadata sends and response streams, stalled redirect response bodies, and stalled package-download streams with `flutter test test\update_service_test.dart --reporter compact` (`96 passed`) and full `flutter test --reporter compact` (`454 passed`); source-contracts verify positive timeout validation, production 30-second defaults, request/read timeout use on feed/GitHub/redirect/package streams, and labeled timeout conversion; installed Windows update-flow E2E remains partial |
| Flutter local update package containment | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Keep local `file:` update packages under the local update-feed directory by checking lexical containment during feed parsing and canonical containment again before copying an existing local `.aup` into the update cache | Source-accounted; runtime partial | Checkpoint 1241 adds source-marker coverage for `resolveSymbolicLinksSync()`-based canonical feed/package containment before local package copy; checkpoint 1551 passes the full Flutter client test suite, but Windows symlink/junction fixtures still need a symlink-capable validation host |
| Local quarantine | `core/zentor_local_core/src/quarantine/`, `apps/zentor_client/lib/features/quarantine/quarantine_screen.dart` | Isolate detected files under opaque IDs, authenticated metadata, restore/delete review, validated absolute quarantine roots, bounded metadata reads, bounded ACL helper diagnostics, bounded integrity hashing, exclusive final metadata/auth/key activation, UUID staged metadata temp names, owner-aware staged temp cleanup, restore/delete status preflight, restore/delete action metadata consistency, status/action metadata validation, execution-claim metadata validation, source/evidence metadata validation, Flutter IPC source/action/process-ID evidence validation, explicit shared protocol evidence fields, optimistic UI status/action consistency, cloud upload evidence preflight, cloud evidence payload/API persistence, strict cloud quarantine API schema, delete payload-integrity preflight, restore/delete status ordering around payload cleanup, restore metadata-failure cleanup, restore parent revalidation, checked restore/delete payload cleanup, bounded exclusive payload copy fallback with visible partial/source-delete/verification cleanup, cleanup of untracked payload/metadata/auth artifacts on post-move finalization failure, and overlapping restore/delete suppression while local-core IPC is pending | Runtime fixture verified; installed E2E partial | Checkpoint 1955 adds local-core `quarantine` (`88 passed`) to the small-threat MVP verifier. Checkpoint 1636 verifies local-core `metadata_validation` (`6`), `list_rejects_metadata` (`3`), `restore` (`21`), `delete` (`9`), broad `quarantine` (`86`), and local-core rustfmt. Checkpoint 1768 adds `remove_checked_quarantine_payload` so restore post-status cleanup and delete payload removal revalidate the payload as a non-following regular quarantine file immediately before removal; local-core `quarantine` passed (`87`), full local-core passed (`419`), `cargo fmt --all -- --check` passed, and source-contracts passed (`481`). This covers local metadata/path/field/status/action/execution/source validation, restore/delete preflight and ordering, delete integrity, restore cleanup, parent revalidation, fallback copy/hash cleanup, finalization cleanup, staged metadata exclusivity/parent/UUID/ownership, current `.avoraxq` payload policy, and checked cleanup removal. No secure-erase promise; installed local-core service, Flutter click-layout, full installed scan/quarantine/restore/delete E2E, and platform-gated ACL/reparse behavior remain partial. |
| Native quarantine | `core/zentor_native_engine/src/quarantine/`, `core/zentor_native_engine/src/config.rs` | Native quarantine records and store behavior for engine-level workflows with validated absolute local quarantine roots, bounded Windows ACL hardening, bounded integrity hashing, bounded metadata fields and bytes, bounded metadata parent checks, exclusive final metadata activation, owner-aware staged metadata cleanup, bounded record paths, POSIX executable-bit stripping, bounded exclusive payload copy fallback with visible partial/source-delete/verification cleanup, and cleanup of untracked payloads on post-move finalization failure | Runtime fixture verified; installed E2E partial | Checkpoint 1955 adds native-engine `quarantine_trust` (`3 passed`) to the small-threat MVP verifier for current-host quarantine trust-root coverage. Checkpoints 1634 and 1638 verify focused native quarantine filters (`native_quarantine_record` `2`, `native_quarantine_copy_fallback` `5`, `native_quarantine_metadata` `6`, `native_quarantine_finalization` `1`, `native_quarantine` `26`, broad `quarantine` `38`) plus native-engine rustfmt, covering runtime-root/trust-root, metadata/path/hash/byte limits, fallback copy cleanup, root checks, executable-bit stripping, finalization cleanup, and staged metadata safety. Installed native-engine/UI/service E2E, replacement-race, symlink/junction, and real Windows ACL enforcement remain partial/platform-gated. |
| Guard quarantine | `core/zentor_guard_service/src/main.rs` quarantine paths | Quarantine confirmed detections observed by guard workflows with bounded metadata/auth reads, bounded metadata fields, bounded record paths, bounded ACL helper diagnostics, bounded source/destination hash verification, write-time metadata-auth verification, exclusive final metadata/auth/key activation, UUID staged metadata temp names, owner-aware staged temp cleanup, bounded exclusive payload copy fallback with visible partial/source-delete/verification cleanup, and cleanup of untracked payload/metadata/auth artifacts on post-move finalization failure | Runtime fixture verified; installed service E2E partial | Checkpoint 1637 verifies Guard Service `guard_quarantine_record` (`7`), `guard_quarantine_copy_fallback` (`7`), `guard_quarantine_staged` (`3`), `guard_quarantine_finalization` (`1`), broad `quarantine` (`32`), and Guard rustfmt. This covers Guard metadata field/path validation, expected-hash preflight, copy-fallback cleanup, finalization cleanup, staged metadata/auth/key final exclusivity, parent revalidation, UUID temp naming, and temp ownership. Installed Guard service operation, signed-driver IPC, pre-execution blocking, and platform-gated ACL/reparse behavior remain partial. |
| Checkpoint 1618 quarantine runtime fixtures | `core/zentor_local_core/src/quarantine/quarantine_store.rs`, `core/zentor_guard_service/src/main.rs` | Focused runtime coverage for local/Guard quarantine auth, DPAPI key storage, Windows reparse constants, ACL current-account lookup, staged local metadata writes, metadata parse-error reporting, legacy metadata compatibility, and copy-fallback hash-mismatch source preservation | Runtime fixture verified; installed E2E partial | Checkpoint 1618 verifies local copy-fallback hash-mismatch source preservation, staged metadata write cleanup, staged-write link-hardening umbrella coverage, corrupt metadata context, legacy no-auth-sidecar readability, local tampering visible reporting, Guard tamper detection, local/Guard Windows reparse constants, local/Guard DPAPI metadata-key storage, and local/Guard ACL current-account lookup with focused Cargo filters (`1 passed; 0 failed` each); old local linked-temp/skipped-tamper filters report `0 tests`; Guard symlink-source fixture is Unix-gated and reports `0 tests` on Windows; installed quarantine UI/service E2E remains partial |
| Checkpoint 1619 quarantine symlink technical limits | `core/zentor_local_core/src/quarantine/quarantine_store.rs`, `core/zentor_guard_service/src/main.rs` | Explicit accounting for base-directory symlink and metadata-key symlink rejection fixtures that require Unix symlink semantics | Technically limited on Windows host | Checkpoint 1619 confirms `quarantine_rejects_symbolic_link_base_directory`, `guard_quarantine_rejects_symbolic_link_base_directory`, `linked_metadata_key_is_rejected`, and `guard_linked_metadata_key_is_rejected` are `#[cfg(unix)]` symlink fixtures and report `0 tests` on this Windows host; source/accounting remains present, runtime proof needs a Unix-capable fixture host |
| Structured local events/logs and shared client protocol | `apps/zentor_client/lib/core/logging/`, `apps/zentor_client/lib/core/platform/platform_info_service.dart`, `apps/zentor_client/lib/features/logs/logs_screen.dart`, `apps/zentor_client/lib/features/settings/settings_screen.dart`, `apps/zentor_client/lib/features/device/device_screen.dart`, `packages/zentor_protocol/`, `core/zentor_native_engine/src/telemetry/` | Visible local evidence, device/platform status, history, export, audit records, and shared config/event parsing with strict metadata validation | Shared protocol runtime verified; UI runtime partial | Log export confirmation and path safety source-accounted; Windows platform-info JSON diagnostics source-accounted in checkpoint 897; Windows service-state JSON diagnostics source-accounted in checkpoint 898; platform-info environment fallback text bounds source-accounted in checkpoint 1308; Device Native Engine status labels source-accounted in checkpoint 1072; local-event export exclusive temp reservation source-accounted in checkpoint 862; local-event export reserved-writer source-accounted in checkpoint 867; local-event export body-size rejection source-accounted in checkpoint 1329; local-event export success-path text bounds source-accounted in checkpoint 1330; local-event export cleanup failure reporting and unsafe temporary cleanup-target rejection are runtime-verified in checkpoint 1685 with `local_event_test.dart` (`37 passed`); local-event host-key safe segment source-accounted in checkpoint 1331; local-event write/clear rejected-acknowledgement failures are runtime-verified in checkpoint 1691 with `local_event_test.dart` plus `config_validation_test.dart` (`64 passed`); local-event decode recovery details and malformed-row recovery details are runtime-verified in checkpoint 1689 with `local_event_test.dart` (`37 passed`); local-event persisted JSON size, newest-200 retention, and persisted timestamp bounds are runtime-verified in checkpoint 1692 with `local_event_test.dart` (`39 passed`); local-event recovery diagnostic control/NUL normalization source-accounted in checkpoint 1310; local-event category/severity invalid-value rejection and missing optional fallback are runtime-verified in checkpoint 1671; local-event write-time category/severity rejection source-accounted in checkpoint 1250; shared-protocol local-event raw control/NUL text rejection is runtime-verified in checkpoint 1671; Flutter repository local-event raw control/NUL text rejection source-accounted in checkpoint 1326; Flutter repository persisted local-event oversized text rejection source-accounted in checkpoint 1327; Flutter repository persisted local-event row-count cap source-accounted in checkpoint 1328; shared config string-list blank-entry rejection is runtime-verified in checkpoint 1673; shared config string-list control/NUL rejection is runtime-verified in checkpoint 1673; raw shared config and protected-app control-text rejection is runtime-verified in checkpoint 1673; protected-app profile blank-value rejection is runtime-verified in checkpoint 1673; shared settings event category alignment is runtime-verified in checkpoint 1671; Flutter config save/reset rejected-acknowledgement failures are runtime-verified in checkpoint 1691; Flutter log-export single-flight and public busy flag release are runtime-verified in checkpoint 1674; Flutter Settings log-export failure UI is runtime-verified in checkpoint 1681 with `settings_accessibility_test.dart` (`9 passed`); Flutter Settings log-export busy button UI is runtime-verified in checkpoint 1682 with `settings_accessibility_test.dart` (`10 passed`); Flutter Logs log-export busy button UI is runtime-verified in checkpoint 1683 with `settings_accessibility_test.dart` (`11 passed`); packages/zentor_protocol format/test verified in checkpoint 1673 with 11 Dart tests passed; broader installed Flutter UI/E2E fixtures remain partial |
| Update service and package verifier | `core/avorax_update_service/`, `apps/zentor_client/lib/core/updates/update_service.dart`, `packages/avorax_protocol/`, `docs/in-app-updates.md`, `tools/update/avorax-build-update-package.ps1` | Versioned signed `.aup` packages, typed manifest/package verification, atomic activation, rollback through installed service/CLI entry points, UI update-launch plumbing, local file-feed trust validation, executable-derived install-target resolution, checked updater executable discovery, checked CLI install-dir handling, fail-visible top-level CLI command handling, strict trailing CLI argument handling, guarded optional CLI positionals, compatible optional CLI flag parsing, strict update key-generator arguments, bounded CLI status and console reporting, bounded service-control names and command execution, fail-visible unsupported-platform service control, fail-visible unsupported-platform service mode, bounded service-error reports, fail-visible update-package component evidence, fail-visible update-package reparse handling across staging/hash/zip enumeration, strict signed-manifest schemas, bounded signed payload-hash maps, strict shared Dart manifest parsing, strict Flutter update-feed/package-entry parsing, bounded update staging IDs, staged file copy byte limits, and validated update log/staging/rollback runtime roots; downloads remain Flutter-owned and no dead service-side downloader placeholder is exposed | Source-accounted; runtime partial | Full signed package apply/rollback needs Rust and provisioned Windows host; native update placeholders removed in checkpoints 781-783; update-service runtime-root validation source-accounted in checkpoint 793; update-service env-root NUL/parent-traversal rejection source-accounted in checkpoint 1210; Flutter updater executable resolver hardening source-accounted in checkpoint 806; Flutter updater install-root hardening source-accounted in checkpoint 813; update-service CLI install-dir hardening source-accounted in checkpoints 815 and 1221; update apply/rollback install-dir canonicalizer hardening source-accounted in checkpoint 1223; rollback latest-snapshot entry reparse rejection source-accounted in checkpoint 1224; rollback recursive copy-entry reparse rejection source-accounted in checkpoint 1225; rollback recursive copy canonical-root revalidation source-accounted in checkpoint 1235; update destination copy-entry reparse rejection source-accounted in checkpoint 1227; update destination canonical-root revalidation source-accounted in checkpoint 1234; update package extraction canonical-root revalidation source-accounted in checkpoint 1236; shared staged activation temp/target revalidation source-accounted in checkpoint 1228; update staged/extraction temp cleanup validation source-accounted in checkpoint 1229; update staged file copy byte limits source-accounted in checkpoint 1256; update package file-size bounds source-accounted in checkpoint 1238; update package archive-entry count bounds source-accounted in checkpoint 1239; update package manifest/signature actual-byte ZIP-entry reads source-accounted in checkpoint 1282; update package post-open path revalidation source-accounted in checkpoint 1230; update package opener metadata consistency source-accounted in checkpoint 1231; update package direct path-hash helper removal source-accounted in checkpoint 1232; update package duplicate payload entry rejection source-accounted in checkpoint 1233; update payload-hash manifest duplicate normalized path rejection source-accounted in checkpoint 1237; update CLI status bounds source-accounted in checkpoint 928; update service-control name bounds source-accounted in checkpoint 929; update service-control System32 tool-root parent-traversal rejection source-accounted in checkpoint 1206; update service-control unsupported-platform behavior source-accounted in checkpoint 938; update service-control bounded command execution source-accounted in checkpoint 1289; update service-mode unsupported-platform behavior source-accounted in checkpoint 939; update service-error report bounds source-accounted in checkpoint 930; update dead downloader-module removal source-accounted in checkpoint 931; update CLI trailing-argument strictness source-accounted in checkpoint 932; update CLI console diagnostic bounds source-accounted in checkpoint 933; update CLI positional flag guard source-accounted in checkpoint 934; update CLI unknown-command strictness source-accounted in checkpoint 935; update CLI optional flag parsing source-accounted in checkpoint 936; update key-generator CLI strictness source-accounted in checkpoint 937; Flutter executable-parent validation source-accounted in checkpoint 816; update-package path text validation source-accounted in checkpoint 1222; update-package payload activation revalidation source-accounted in checkpoint 1226; update-package component predicate hardening source-accounted in checkpoint 822; update-package reparse enumeration hardening source-accounted in checkpoint 836; Dart update-manifest typed-field diagnostics source-accounted in checkpoint 899 and format/analyze/test verified in checkpoint 1549; Dart update-manifest strict-field hardening source-accounted in checkpoint 924 and format/analyze/test verified in checkpoint 1549; Flutter update-feed strict-field hardening source-accounted in checkpoint 925; Flutter remote package streamed-write hardening source-accounted in checkpoint 1240; update-service signed-manifest strict-schema hardening source/builder-accounted in checkpoint 923; update-service payload-hash manifest bounds source-accounted in checkpoint 926; update staging-id bounds source-accounted in checkpoint 927; update-package signer command diagnostic bounds source-accounted in checkpoint 1104; Rust update signer manifest read bounds source-accounted in checkpoint 1259; Flutter update rollback support label honesty source-accounted in checkpoints 1074 and 1076; Flutter update-cache exclusive temp reservation source-accounted in checkpoint 862; Flutter update-cache backup activation source-accounted in checkpoint 863; Flutter update staged-write helper source-accounted in checkpoint 865; Flutter update action single-flight source-accounted in checkpoint 1146; Flutter update operation busy-state UI source-accounted in checkpoint 1186; Flutter update installed-version failure reporting is runtime-verified in checkpoint 1684 with `update_service_test.dart` (`107 passed`); Flutter updater timeout kill-result evidence source-accounted in checkpoint 1291; Flutter update-service diagnostic control/NUL normalization source-accounted in checkpoint 1312; Flutter updater subprocess stdout/stderr diagnostic control/NUL normalization source-accounted in checkpoint 1318; Flutter local file-feed trust source-accounted in checkpoint 1413 |
| Checkpoint 1618 update traversal/runtime-root fixtures | `core/avorax_update_service/src/logging.rs`, `core/avorax_update_service/src/update_applier.rs`, `core/avorax_update_service/src/rollback.rs` | Focused runtime coverage for update ProgramData runtime roots, update package IDs, rollback snapshot versions, and restore containment rejecting traversal/out-of-root inputs | Runtime fixture verified; installed E2E partial | Checkpoint 1618 verifies `update_program_data_root_rejects_relative_override`, `update_program_data_root_has_no_temp_fallback`, `update_package_id_rejects_traversal`, `snapshot_version_rejects_traversal`, and `restore_rejects_snapshot_outside_rollback_root` with focused Cargo filters (`1 passed; 0 failed` for the matching lib tests); package binaries report `0 tests` for those lib filters before the matching lib tests run; full signed update apply/rollback E2E remains partial |
| Flutter update action single-flight guard | `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/test/update_controller_test.dart`, `apps/zentor_client/lib/features/settings/settings_screen.dart`, `apps/zentor_client/lib/features/updates/updates_screen.dart`, `apps/zentor_client/lib/features/home/home_screen.dart` | Prevents overlapping update check/install/rollback actions, keeps package download/verify/install work from starting behind a pending update check, emits visible update/warning busy evidence, and exposes `updateOperationInFlight` so update controls can disable while work is pending | Runtime partial | Controller path runtime-verified in checkpoint 1586 with `flutter test test\update_controller_test.dart --reporter compact` (`31 passed`) and refreshed in checkpoint 1694 with `flutter test test\update_controller_test.dart test\update_ui_test.dart --reporter compact` (`35 passed`): pending and duplicate update actions block overlapping check/install/rollback work, leave package/rollback calls unstarted, keep/clear busy state correctly, emit `update_action_busy`, and Settings/Update source-marker/widget fixtures cover update-control/rollback gating; installed Home/Settings/Updates click/layout E2E remains partial |
| Flutter update event metadata | `apps/zentor_client/lib/app/app_state.dart`, `apps/zentor_client/test/update_controller_test.dart` | Ensures update checks, package install, rollback, confirmation-required, busy, unavailable, and failure outcomes write structured local history with explicit `update` category and correct info/warning/error severity | Runtime partial | Controller path runtime-verified in checkpoint 1587 with `flutter test test\update_controller_test.dart --reporter compact` (`32 passed`) and refreshed in checkpoint 1694 with `flutter test test\update_controller_test.dart test\update_ui_test.dart --reporter compact` (`35 passed`): check start is update/info, availability/install/rollback progress and confirmation-required/unavailable/busy outcomes are update/warning, and check/install/rollback failures are update/error with bounded diagnostics; installed UI event-flow E2E remains partial |
| Flutter update rollback support UI | `apps/zentor_client/lib/features/update/update_screen.dart`, `apps/zentor_client/lib/features/update/widgets/update_status_rows.dart`, `apps/zentor_client/lib/features/update/update_state.dart`, `apps/zentor_client/test/update_ui_test.dart` | Keeps rollback support labels honest so missing metadata remains unknown, explicit unsupported packages show unavailable, and rollback cannot be launched unless package metadata explicitly supports it | Runtime partial | Flutter widget path runtime-verified in checkpoint 1588 with `flutter test test\update_ui_test.dart --reporter compact` (`3 passed`) and full `flutter test --reporter compact` (`441 passed`): status rows render Unknown/Unavailable/Available from null/false/true metadata, and the Updates rollback button is disabled for null/false while enabled for true; installed Settings/Updates click-layout E2E and real rollback on installed Windows remain partial |
| Flutter local update-feed streaming bounds | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Reads local `file:` update feeds through chunked byte-limit enforcement so oversized untrusted feed metadata fails before JSON parsing or package selection | Runtime partial | Oversized local feed runtime-verified in checkpoint 1590 with `flutter test test\update_service_test.dart --reporter compact` (`86 passed`) and full `flutter test --reporter compact` (`444 passed`): a `maxUpdateFeedBytes + 1` local feed returns a failed update check containing the local feed metadata-limit diagnostic and performs no HTTP request; growing-file race fixtures remain partial until a provisioned filesystem race host is available |
| Update local file-feed URI authority guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Rejects local `file:` update feed URI authorities before filesystem path conversion so `file://host/...`-style authorities cannot be treated as local feed sources | Runtime fixture verified; installed E2E partial | Checkpoint 1643 verifies this through `flutter test test\update_service_test.dart --reporter compact` (`106 passed`), including file-feed authority guard coverage; installed update-flow E2E remains partial |
| Update local package file-URI trust guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Rejects local `file:` update package URI authorities, unsafe path conversion, non-local absolute paths, and parent traversal before local feed-directory containment is evaluated | Runtime fixture verified; race/E2E partial | Checkpoint 1643 verifies this through `flutter test test\update_service_test.dart --reporter compact` (`106 passed`), including local package path authority/traversal/containment checks before package use. Windows symlink/junction race fixtures and installed update-flow E2E remain partial |
| Update HTTPS URI authority trust guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Requires HTTPS update feed and package URIs to include a URI authority, a non-empty host, and no embedded userinfo credentials before they are accepted as trusted update sources | Runtime fixture verified; installed E2E partial | Checkpoint 1643 verifies this through `flutter test test\update_service_test.dart --reporter compact` (`106 passed`), including HTTPS host/authority/userinfo trust gates before feed/package acceptance; installed update-flow E2E remains partial |
| GitHub update HTTPS trust reuse guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Applies the shared trusted HTTPS URI predicate before GitHub latest-download feed matching, release asset selection, and release-asset redirect acceptance host/path allowlists | Runtime fixture verified; installed E2E partial | Checkpoint 1643 verifies this through `flutter test test\update_service_test.dart --reporter compact` (`106 passed`), including shared HTTPS trust reuse for GitHub feed, release asset, and redirect paths; installed update-flow E2E remains partial |
| Update URI text control-character guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Rejects raw control/NUL characters in configured update feed URLs, feed package URLs, and GitHub release feed asset URLs before URI parsing | Runtime fixture verified; installed E2E partial | Update URI text hygiene source-accounted in checkpoint 1418; GitHub fallback `browser_download_url` NUL rejection is runtime-verified in checkpoint 1599 with focused `98 passed` and full `456 passed`; configured update feed URL and feed package URL NUL rejection are runtime-verified in checkpoint 1600 with `flutter test test\update_service_test.dart --reporter compact` (`100 passed`) and full `flutter test --reporter compact` (`458 passed`), failing before URI parsing and without raw NUL text in diagnostics; installed Windows update-flow E2E remains partial |
| Update required metadata control-character guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Rejects raw control/NUL characters in required update feed/package metadata strings and required GitHub release strings before comparison, parsing, or URL handling | Runtime partial | Required metadata hygiene source-accounted in checkpoint 1419; checkpoint 1601 runtime-verifies feed `product`, feed `latest_version`, and package `package_sha256` NUL rejection with `flutter test test\update_service_test.dart --reporter compact` (`103 passed`) and full `flutter test --reporter compact` (`461 passed`), failing before product comparison/version parsing/SHA validation with normalized diagnostics; broader GitHub release required-field fixtures and installed Windows update-flow E2E remain partial |
| Update optional metadata control-character guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Rejects raw control/NUL characters in optional update metadata token/date strings before channel/minimum-version comparison or published-at date parsing | Runtime fixture verified; installed E2E partial | Optional metadata hygiene source-accounted in checkpoint 1420; checkpoint 1601 runtime-verifies feed `channel`, feed `minimum_supported_version`, and package `published_at` NUL rejection with focused `103 passed` and full `461 passed`, failing before channel comparison/version comparison/date parsing with normalized diagnostics; installed Windows update-flow E2E remains partial |
| Update feed product-field boundary | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Parses the feed `product` value through the required metadata string boundary before Avorax product matching so malformed product evidence fails closed | Runtime fixture verified; installed E2E partial | Product-field boundary source-accounted in checkpoint 1421; checkpoint 1601 runtime-verifies NUL-bearing feed `product` rejection before Avorax product comparison with focused `103 passed` and full `461 passed`; installed Windows update-flow E2E remains partial |
| Update release-notes free-text guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Rejects NUL, DEL, and non-display C0 control characters in bounded release-notes text while allowing tabs and line breaks for normal multiline notes | Runtime fixture verified; installed E2E partial | Release-notes free-text hygiene source-accounted in checkpoint 1422; checkpoint 1601 runtime-verifies multiline/tab release notes remain accepted while NUL-bearing release notes fail with normalized unsupported-control diagnostics using focused `103 passed` and full `461 passed`; installed Windows update-flow E2E remains partial |
| GitHub update asset-name boundary | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Routes GitHub release asset path names through the safe update asset-name boundary before fallback or redirect matching trusts them | Runtime fixture verified; installed E2E partial | GitHub asset-name boundary source-accounted in checkpoint 1423; checkpoint 1602 runtime-verifies the redirect path refuses malformed release-assets paths before following redirected asset evidence with focused `105 passed` and full `463 passed`; checkpoint 1603 runtime-verifies unsafe decoded GitHub fallback asset names such as `nested%5Cupdate-feed.json` are rejected before feed download selection with focused `106 passed` and full `464 passed`; installed Windows update-flow E2E remains partial |
| GitHub update redirect Location text guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Rejects raw control/NUL characters in bounded GitHub update redirect Location header text before URI resolution and redirect allowlist evaluation | Runtime fixture verified; installed E2E partial | Redirect Location text hygiene source-accounted in checkpoint 1424; checkpoint 1602 runtime-verifies NUL-bearing redirect `Location` rejection before URI resolution with `flutter test test\update_service_test.dart --reporter compact` (`105 passed`) and full `flutter test --reporter compact` (`463 passed`), with normalized diagnostics; installed Windows update-flow E2E remains partial |
| GitHub release-assets redirect path-shape guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Requires the final `release-assets.githubusercontent.com` redirect hop to use a `github-production-release-asset` path with at least three non-empty, non-dot segments before package verification can proceed | Runtime fixture verified; installed E2E partial | Release-assets path-shape hygiene source-accounted in checkpoint 1425; checkpoint 1602 runtime-verifies malformed release-assets redirect paths are rejected before follow with focused `105 passed` and full `463 passed`; installed Windows update-flow E2E remains partial |
| GitHub update redirect raw Location guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Applies length and control/NUL checks to the untrimmed redirect Location header value before whitespace trimming or URI resolution | Runtime fixture verified; installed E2E partial | Raw Location hygiene source-accounted in checkpoint 1426; checkpoint 1602 runtime-verifies untrimmed NUL-bearing redirect `Location` rejection before trimming or URI resolution with focused `105 passed` and full `463 passed`; installed Windows update-flow E2E remains partial |
| Update Content-Length raw header guard | `apps/zentor_client/lib/core/updates/update_service.dart`, `apps/zentor_client/test/update_service_test.dart` | Applies length and control/NUL checks to present feed/package/GitHub metadata `Content-Length` header values before whitespace trimming or numeric parsing | Runtime fixture verified; installed E2E partial | Source-accounted in checkpoint 1427; remote update-feed and update-package malformed header paths runtime-verified in checkpoint 1591 with `flutter test test\update_service_test.dart --reporter compact` (`88 passed`) and full `flutter test --reporter compact` (`446 passed`): NUL-bearing `Content-Length` values fail with normalized invalid-header diagnostics before feed parsing or package writes; GitHub releases metadata malformed header path is runtime-verified in checkpoint 1598 with focused `97 passed` and full `455 passed`, failing before GitHub metadata parsing or fallback feed asset selection; installed Windows update-flow E2E remains partial |
| Signed `.aup` archive entry allowlist | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Rejects archive entries outside `manifest.json`, `manifest.sig`, and safe `payload/...` paths before manifest reads or payload limit scans | Runtime fixture verified | Source-accounted in checkpoint 1428; checkpoint 1604 runtime-verifies `read_manifest_rejects_unexpected_archive_entry`, `read_manifest_rejects_restricted_payload_directory_entry`, and `package_archive_entries_are_allowlisted_before_archive_reads` through `cargo test --manifest-path core\avorax_update_service\Cargo.toml read_manifest -- --test-threads=1` (`10 passed`) plus focused source fixture (`1 passed`); `rustfmt --check core\avorax_update_service\src\update_package.rs` passed |
| Checkpoint 1621 update-service package/path fixtures | `core/avorax_update_service/src/` | Focused runtime coverage for signed update hash/version validation, package extraction staging, path-safety rechecks, staged file activation/cleanup, rollback snapshot selection/completeness, service-control bounds, manifest operational flags, payload allowlists, subcomponent consistency, oversized manifest/signature entries, release-notes/migration URL/string validation, and current-version policy validation | Runtime fixture verified; symlink partial; installed E2E partial | Checkpoint 1621 verifies update-service filters: `malformed` (`5 passed`), `package_extraction` (`2 passed`), `path_safety` (`11 passed`), staged-copy/temp/log/path/rollback focused filters (`1 passed` each), `update_applier` (`27 passed`), `service_control` (`4 passed`), `oversized` (`3 passed`), `driver_payload` (`1 passed`), `manifest_payload` (`13 passed`), `subcomponent` (`5 passed`), and manifest flag/string/version/current-policy filters (`1 passed` each). Symlink-oriented filters `symbolic_link`, `checked_recursive_remove`, and `checked_create_dir_rejects_symbolic_link_ancestor` report `0 tests` on this Windows host |
| Signed `.aup` archive entry-name text guard | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Rejects raw ZIP entry names containing NUL/control characters or excessive length before allowlist and payload path checks | Runtime fixture verified | Source-accounted in checkpoint 1504; checkpoint 1604 runtime-verifies `read_manifest_rejects_control_character_archive_entry_name` through `cargo test --manifest-path core\avorax_update_service\Cargo.toml read_manifest -- --test-threads=1` (`10 passed`); `rustfmt --check core\avorax_update_service\src\update_package.rs` passed |
| Signed `.aup` restricted payload directory-entry rejection | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Rejects restricted payload roots such as tools, migrations, and driver payloads even when represented only as ZIP directory entries | Runtime fixture verified | Source-accounted in checkpoint 1503; checkpoint 1604 runtime-verifies `read_manifest_rejects_restricted_payload_directory_entry` through `cargo test --manifest-path core\avorax_update_service\Cargo.toml read_manifest -- --test-threads=1` (`10 passed`); `rustfmt --check core\avorax_update_service\src\update_package.rs` passed |
| Signed `.aup` manifest/signature entry cardinality | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Requires exactly one `manifest.json` and exactly one `manifest.sig` before manifest reads, signature reads, payload hash scans, or extraction loops proceed | Runtime fixture verified | Source-accounted in checkpoints 1499, 1500, and 1501; checkpoint 1604 runtime-verifies duplicate/missing manifest/signature fixtures via `cargo test --manifest-path core\avorax_update_service\Cargo.toml read_manifest -- --test-threads=1` (`10 passed`); `rustfmt --check core\avorax_update_service\src\update_package.rs` passed |
| Signed manifest scalar raw-text guard | `core/avorax_update_service/src/update_manifest.rs`, `tests/test_custom_driver_contract.py` | Rejects raw control characters and surrounding whitespace in signed manifest scalar fields before trimmed parsing or policy comparison | Runtime fixture verified | Checkpoint 1634 verified `manifest_scalar` and `update_manifest` Cargo filters plus update-service rustfmt. |
| Signed manifest payload-hash value guard | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Rejects raw control characters and surrounding whitespace in signed manifest `payload_hashes` values before archive open or payload comparison | Runtime fixture verified | Checkpoint 1634 verified `payload_hash` and `read_manifest` Cargo filters plus update-service rustfmt. |
| Signed manifest payload-hash path-key guard | `core/avorax_update_service/src/update_package.rs`, `tests/test_custom_driver_contract.py` | Rejects raw control characters and surrounding whitespace in signed manifest `payload_hashes` path keys before path normalization, duplicate detection, or archive open | Runtime fixture verified | Checkpoint 1634 verified `payload_hash` and `read_manifest` Cargo filters plus update-service rustfmt. |
| Normal `.aup` tooling payload policy | `core/avorax_update_service/src/update_package.rs`, `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Rejects `tools/` payload roots in normal signed `.aup` packages and refuses package-builder source/leaked `tools/` payload paths until an explicit tooling workflow exists | Rust runtime verified; builder partial | Checkpoint 1635 verified signed `tools/` payload rejection with `tools_payload`, `manifest_payload_verification`, and update-service rustfmt. Package-builder runtime fixtures for source/leaked tooling payload refusal remain partial. |
| Normal `.aup` tooling activation removal | `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Removes normal update apply activation for `staging/tools`, leaving no install-copy route for tooling payloads in the normal `.aup` apply path | Runtime fixture verified | Checkpoint 1635 verified `normal_update` update-applier fixtures plus update-service rustfmt. |
| Normal `.aup` migration workflow disabling | `core/avorax_update_service/src/update_manifest.rs`, `core/avorax_update_service/src/update_package.rs`, `core/avorax_update_service/src/update_applier.rs`, `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Rejects signed migration steps, rejects `migrations/` payload roots, refuses builder source/leaked migration payloads, and removes normal apply activation for `staging/migrations` until an explicit migration workflow exists | Rust runtime verified; builder partial | Checkpoint 1635 verified signed manifest/payload-root/applier behavior with `migration`, `normal_update`, `manifest_payload_verification`, and update-service rustfmt. Package-builder runtime fixtures for migration payload refusal remain partial. |
| Normal `.aup` app payload restricted targets | `core/avorax_update_service/src/update_package.rs`, `core/avorax_update_service/src/update_applier.rs`, `tools/update/avorax-build-update-package.ps1`, `tools/testing/run-release-update-package-builder-failsafe-smoke.ps1`, `tests/test_custom_driver_contract.py` | Prevents `payload/app` from bypassing specialized update sections by rejecting restricted install-root children and managed service/updater executable names before manifest authorization, package signing, or app tree activation | Runtime fixture verified; installed E2E partial | Checkpoint 2026 runtime-verifies builder refusal for source `avorax_update_service.exe` and top-level managed service/updater executable directories that would otherwise be staged through app payload paths. Checkpoint 2029 verifies the applier app payload guard remains active while adding non-empty app-section enforcement. Installed update apply E2E remains partial. |
| Normal `.aup` app payload non-empty activation | `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Rejects a present staged `app` section when it contains no regular files, so normal update apply cannot report success for a no-op app payload; missing app sections remain allowed for engine/service/docs-only updates | Runtime fixture verified; installed E2E partial | Checkpoint 2029 adds `copy_app_payload_section_rejects_empty_app_directory`, proving a directory-only staged app payload fails visibly with `app update payload contains no regular files` before creating the install destination. Installed update apply E2E remains partial. |
| Normal `.aup` manifest component/payload consistency | `core/avorax_update_service/src/update_package.rs`, `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Requires every declared normal update component flag to have a matching signed payload hash before verification succeeds, preventing manifests from claiming app, service, engine, or docs updates that the package does not carry | Runtime fixture verified; installed E2E partial | Checkpoint 2031 adds `ensure_manifest_components_have_payload_hashes` and fixtures for declared app, Core service, native engine assets, engine subcomponents, and docs without payload hashes. The restart-failure apply fixture now carries docs payload so declared docs evidence is honest. Installed update apply E2E remains partial. |
| Normal `.aup` verified-hash extraction | `core/avorax_update_service/src/update_package.rs`, `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Rechecks the verified package SHA-256 on the same opened file handle used for extraction before normal update apply stages payloads, reducing package-replacement risk between verification and extraction | Runtime fixture verified; installed E2E partial | Checkpoint 2032 adds `extract_payload_to_verified_hash`, proves a changed package fails with `update package changed after verification` before staging exists, and pins `apply_package_with_service_control` to the verified-hash helper after `UpdateVerifier::verify_package`. Installed update apply E2E remains partial. |
| Normal `.aup` pre-activation failure reporting | `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Reports and cleans up staging preparation or verified extraction failures before rollback/service-stop, with `applied: false`, `rollback: null`, explicit failure fields, and no service-control calls | Runtime fixture verified; installed E2E partial | Checkpoint 2033 adds `report_pre_activation_failure` and proves stale non-directory staging fails visibly with `staging_prepare_error`, writes `update_report.json`, records staging cleanup evidence, keeps service calls empty, and leaves the install tree unchanged. Installed update apply E2E remains partial. |
| Normal `.aup` rollback snapshot failure reporting | `core/avorax_update_service/src/update_applier.rs`, `core/avorax_update_service/src/rollback.rs`, `tools/testing/run-release-update-service-apply-snapshot-failure-smoke.ps1`, `tests/test_custom_driver_contract.py` | Reports rollback snapshot creation failures before service-stop with `snapshot_error`, cleans staging, removes partial rollback snapshots, and records no service-control calls | Runtime and release-smoke verified; installed E2E partial | Checkpoint 2034 routes `create_snapshot` failures through `report_pre_activation_failure`, proves a missing install `engine` directory writes `update_report.json`, leaves the install tree unchanged, cleans staging, and removes the partial rollback snapshot. Checkpoint 2035 verifies the same pre-service-stop failure path through the release `avorax_update_service.exe --apply` smoke with a benign signed `.aup`, no service-control diagnostic, unchanged install files, staging cleanup, no partial rollback snapshot, and CLI status evidence. Successful installed update apply E2E remains partial. |
| Normal `.aup` release apply success fake-service smoke | `tools/testing/run-release-update-service-apply-success-fake-service-smoke.ps1`, `tools/testing/verify-small-threat-mvp.ps1`, `tools/testing/validate-small-threat-mvp-report.ps1`, `tests/test_custom_driver_contract.py` | Proves the release `avorax_update_service.exe --apply` success path with a benign signed package, activated app/Core/Guard/engine/docs payloads, rollback snapshot evidence, staging cleanup, success report/status output, and process-local fake service-control isolation | Release-smoke verified; installed E2E partial | Checkpoint 2036 copies Git `true.exe` into a temporary fake `SystemRoot\System32\sc.exe`, sets that environment only for the child process, and verifies successful release apply behavior without touching real Windows services. This is fake-service release evidence only; real installed service stop/start and installed update apply/rollback E2E remain partial. |
| Normal `.aup` app component evidence | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Declares `components.app` when any staged app payload file exists, keeping app resource/DLL updates self-consistent with verifier payload-root policy | Source-accounted; runtime partial | Builder runtime fixture execution is blocked in this shell; app component evidence source-accounted in checkpoint 1441 |
| Normal `.aup` app file staging revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates top-level app payload source files and destination paths before staging into `payload/app` | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; app file copy revalidation source-accounted in checkpoints 1445 and 1448 |
| Normal `.aup` app directory staging revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates app payload source directories and destination paths before recursive staging into `payload/app` | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; app directory copy revalidation source-accounted in checkpoint 1446 |
| Normal `.aup` engine component evidence | `tools/update/avorax-build-update-package.ps1`, `tools/testing/run-release-update-package-builder-smoke.ps1`, `tools/testing/run-release-update-package-builder-failsafe-smoke.ps1`, `tests/test_custom_driver_contract.py` | Requires supported normal engine component directories to contain runtime files and derives engine component manifest flags from counted staged runtime files instead of directory presence | Runtime fixture verified | Checkpoint 2008 release builder signed verify smoke proves `native_engine_assets` and `signatures` manifest flags from an actual staged `engine/signatures` runtime file; checkpoint 2024 extends the fail-safe smoke with `empty-engine-component`, proving empty `engine\signatures` fails visibly and produces no `.aup` or `update-feed.json`. Race/reparse staging fixtures remain covered separately by the staging revalidation rows. |
| Normal `.aup` engine component staging revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates supported engine runtime component source directories and destination paths before recursive staging into `payload/engine` | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; engine component copy revalidation source-accounted in checkpoint 1447 |
| Normal `.aup` service payload allowlist | `core/avorax_update_service/src/update_package.rs`, `tools/update/avorax-build-update-package.ps1`, `tools/testing/run-release-update-package-builder-smoke.ps1`, `tools/testing/run-release-update-package-builder-failsafe-smoke.ps1`, `tests/test_custom_driver_contract.py` | Restricts normal service payloads to direct `services/avorax_core_service.exe` and `services/avorax_guard_service.exe` files with matching signed manifest components | Runtime fixture verified; installed E2E partial | Checkpoint 1635 verified signed unknown/nested service payload fixtures with `service_payload`, broad `service`, `manifest_payload_verification`, and update-service rustfmt; checkpoint 2025 verifies builder staging and manifest hashes for benign direct Core/Guard service payloads; checkpoint 2026 verifies builder refusal for updater self-update payloads and managed executable directories. Installed service stop/start and apply E2E remain partial. |
| Normal `.aup` service component evidence | `tools/update/avorax-build-update-package.ps1`, `tools/testing/run-release-update-package-builder-smoke.ps1`, `tests/test_custom_driver_contract.py` | Derives Core and Guard service component flags from explicit staged service payload file checks, keeping service manifest evidence aligned with allowlisted service staging | Runtime fixture verified | Checkpoint 2025 release builder signed verify smoke proves benign `avorax_core_service.exe` and `avorax_guard_service.exe` payloads are staged under `payload/services`, declare `components.core_service` and `components.guard_service`, carry matching service payload hashes, and do not declare updater or driver-tool updates. Installed service stop/start and apply E2E remain covered separately as partial/blocked. |
| Normal `.aup` service file staging revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates allowlisted service source files and destination paths before staging into `payload/services` | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; service file copy revalidation source-accounted in checkpoint 1448 |
| Normal `.aup` service activation allowlist | `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Prevents normal apply from copying `staging/services` wholesale; validates and stages only `avorax_core_service.exe` and `avorax_guard_service.exe` service binaries through bounded atomic file activation | Runtime fixture verified; installed E2E partial | Checkpoint 2030 adds `copy_service_payload_section_rejects_empty_services_directory`, proving an empty staged `services` section fails visibly with `service update payload contains no supported service files` before creating the install destination. Installed service stop/start and apply E2E remain partial. |
| Normal `.aup` engine payload allowlist | `core/avorax_update_service/src/update_package.rs`, `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Restricts normal engine payloads to files under `engine/signatures`, `engine/rules`, `engine/ml`, and `engine/trust`; keeps `native_engine_assets` from authorizing unknown or direct engine-root payloads | Source-accounted; runtime partial | Cargo/rustfmt signed unknown-subdir/direct-subcomponent fixtures and builder runtime fixtures are blocked in this shell; normal engine payload allowlist source-accounted in checkpoint 1436 |
| Normal `.aup` engine checked component staging | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Resolves supported engine runtime component paths from the checked engine source root and counts runtime files from checked component directories before recursive staging | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; checked engine component staging source-accounted in checkpoint 1497 |
| Normal `.aup` engine activation allowlist | `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Prevents normal apply from copying `staging/engine` wholesale; enumerates, validates, and copies only `signatures`, `rules`, `ml`, and `trust` component directories to canonical engine destinations | Runtime fixture verified; installed E2E partial | Checkpoint 2030 adds `copy_engine_payload_section_rejects_empty_engine_directory`, proving an empty staged `engine` section fails visibly with `engine update payload contains no supported runtime subdirectories` before creating the install engine destination. Installed update apply E2E remains partial. |
| Normal `.aup` docs payload Markdown-only | `core/avorax_update_service/src/update_package.rs`, `core/avorax_update_service/src/update_applier.rs`, `tools/update/avorax-build-update-package.ps1`, `tools/testing/run-release-update-package-builder-failsafe-smoke.ps1`, `tests/test_custom_driver_contract.py` | Restricts normal docs payloads to Markdown files under `docs`; builder rejects non-Markdown docs and leaked unsupported docs paths, and applier validates/stages docs files instead of copying `staging/docs` wholesale | Runtime fixture verified; installed E2E partial | Update-service runtime verifies signed non-Markdown docs rejection and applier non-Markdown docs rejection; checkpoint 2027 verifies builder empty-docs fail-safe; checkpoint 2028 verifies applier empty staged-docs fail-safe and that no install docs destination is created. Installed update apply E2E remains partial. |
| Normal `.aup` docs component evidence | `tools/update/avorax-build-update-package.ps1`, `tools/testing/run-release-update-package-builder-smoke.ps1`, `tools/testing/run-release-update-package-builder-failsafe-smoke.ps1`, `core/avorax_update_service/src/update_applier.rs`, `tests/test_custom_driver_contract.py` | Declares `components.docs` from counted staged docs payload files instead of docs directory presence, keeping docs manifest evidence aligned with Markdown-only payload staging | Runtime fixture verified | Checkpoint 2008 release builder signed verify smoke proves `components.docs` from an actual staged Markdown docs payload; checkpoint 2027 adds `empty-docs`, proving an empty docs source fails visibly and produces no `.aup` or `update-feed.json`; checkpoint 2028 proves an empty staged docs section is rejected by the applier before install docs creation. Race/reparse docs staging fixtures remain covered separately by docs staging revalidation rows. |
| Normal `.aup` docs file staging revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates Markdown docs source files and destination paths before staging into `payload/docs` | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; docs file copy revalidation source-accounted in checkpoint 1449 |
| Normal `.aup` docs checked source staging | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Enumerates Markdown docs files from the checked docs source root and derives staging-relative paths from that same checked root | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; docs checked source staging source-accounted in checkpoint 1498 |
| Normal `.aup` package artifact path revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates final package, temporary zip, and backup paths before package creation/activation, then revalidates the final package file before hashing it for the update feed | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; package artifact path revalidation source-accounted in checkpoint 1450 |
| Normal `.aup` zip-entry source revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates each work-tree source file immediately before `CreateEntryFromFile` and writes zip entries from the checked source path | Source-accounted; runtime partial | Builder race/reparse fixture execution is blocked in this shell; zip-entry source revalidation source-accounted in checkpoint 1451 |
| Normal `.aup` archive checked work root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Enumerates ZIP work files and derives archive entry names from the checked work directory returned by `Require-Directory` | Source-accounted; runtime partial | Archive work-root race/reparse fixture execution is blocked in this shell; checked archive work root source-accounted in checkpoint 1496 |
| Normal `.aup` zip-entry allowlist | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Rejects builder work-tree archive entries outside `manifest.json`, `manifest.sig`, and `payload/...` immediately before writing zip entries | Source-accounted; runtime partial | Builder runtime/race fixture execution is blocked in this shell; zip-entry allowlist source-accounted in checkpoint 1452 |
| Normal `.aup` signature output revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates the `manifest.sig` output path before invoking the signer and revalidates the produced signature as a regular file before package creation continues | Source-accounted; runtime partial | Signer race/reparse fixture execution is blocked in this shell; signature output revalidation source-accounted in checkpoint 1453 |
| Normal `.aup` feed package URL derivation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Derives generated feed `package_url` from the checked final package file name instead of repeating a second hardcoded artifact name | Source-accounted; runtime partial | Feed/package fixture execution is blocked in this shell; package URL derivation source-accounted in checkpoint 1454 |
| Normal `.aup` feed output revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates the feed path before atomic write, retains the checked final feed file, and reports the checked feed path in success output | Source-accounted; runtime partial | Feed-output fixture execution is blocked in this shell; feed output revalidation source-accounted in checkpoint 1455 |
| Normal `.aup` package output reporting | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Reports the checked final package file path from `Require-File` in builder success output | Source-accounted; runtime partial | Package-output fixture execution is blocked in this shell; package output reporting source-accounted in checkpoint 1456 |
| Normal `.aup` metadata timestamp consistency | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Uses one captured UTC ISO timestamp for signed manifest `release_date` and generated feed `published_at` | Source-accounted; runtime partial | Feed/package metadata fixture execution is blocked in this shell; timestamp consistency source-accounted in checkpoint 1457 |
| Normal `.aup` payload hash source revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates each staged payload file immediately before SHA-256 hashing and hashes the checked payload path | Source-accounted; runtime partial | Payload-hash race/reparse fixture execution is blocked in this shell; payload hash source revalidation source-accounted in checkpoint 1458 |
| Normal `.aup` atomic writer temp path revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates generated temporary and backup paths before atomic JSON/feed writes and cleans stale random-name collisions through checked regular-file removal | Source-accounted; runtime partial | Atomic-writer collision/reparse fixture execution is blocked in this shell; temp/backup path revalidation source-accounted in checkpoint 1459 |
| Normal `.aup` atomic writer checked-temp activation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Uses the checked temporary file returned by `Require-File` for atomic JSON/feed `File.Replace` and `File.Move` activation | Source-accounted; runtime partial | Atomic-writer activation race/reparse fixture execution is blocked in this shell; checked-temp activation source-accounted in checkpoint 1460 |
| Normal `.aup` package checked-temp activation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Uses the checked temporary package returned by `Require-File` for final `.aup` `File.Replace` and `File.Move` activation | Source-accounted; runtime partial | Package activation race/reparse fixture execution is blocked in this shell; checked-temp package activation source-accounted in checkpoint 1461 |
| Normal `.aup` recursive staging pre-copy revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates app and supported engine source trees immediately before recursive `Copy-Item` staging | Source-accounted; runtime partial | Recursive-copy race/reparse fixture execution is blocked in this shell; pre-copy tree revalidation source-accounted in checkpoint 1462 |
| Normal `.aup` app component no-reparse evidence | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Counts staged app payload files through the shared no-reparse payload-file helper before setting `components.app` | Source-accounted; runtime partial | App component fixture execution is blocked in this shell; app component no-reparse evidence source-accounted in checkpoint 1463 |
| Normal `.aup` docs staging no-reparse enumeration | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Enumerates docs payload files through the shared no-reparse payload-file helper before Markdown policy checks and staging | Source-accounted; runtime partial | Docs staging fixture execution is blocked in this shell; docs staging no-reparse enumeration source-accounted in checkpoint 1464 |
| Normal `.aup` shared payload-file helper pre-enumeration revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates payload source trees immediately before recursive file enumeration in the shared helper used by app/docs/engine evidence and docs staging | Source-accounted; runtime partial | Payload helper race/reparse fixture execution is blocked in this shell; shared helper pre-enumeration revalidation source-accounted in checkpoint 1465 |
| Normal `.aup` payload hash helper enumeration | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Enumerates staged payload files for hashing through the shared no-reparse payload-file helper before per-file hash revalidation | Source-accounted; runtime partial | Payload-hash helper enumeration fixture execution is blocked in this shell; payload hash helper enumeration source-accounted in checkpoint 1466 |
| Normal `.aup` top-level app staging pre-enumeration revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates the payload root immediately before top-level app file and directory staging enumeration | Source-accounted; runtime partial | Top-level app staging race/reparse fixture execution is blocked in this shell; pre-enumeration root revalidation source-accounted in checkpoint 1467 |
| Normal `.aup` zip work-tree pre-enumeration revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates the package work tree immediately before archive file enumeration and before per-file zip source revalidation | Source-accounted; runtime partial | Zip work-tree race/reparse fixture execution is blocked in this shell; work-tree pre-enumeration revalidation source-accounted in checkpoint 1468 |
| Normal `.aup` service payload pre-staging revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates the payload root immediately before allowlisted service binary staging and before per-file service source/destination validation | Source-accounted; runtime partial | Service payload race/reparse fixture execution is blocked in this shell; service payload pre-staging root revalidation source-accounted in checkpoint 1469 |
| Normal `.aup` engine child policy pre-enumeration revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates the engine source tree immediately before unknown/pruned child policy enumeration | Source-accounted; runtime partial | Engine child policy race/reparse fixture execution is blocked in this shell; engine child policy pre-enumeration revalidation source-accounted in checkpoint 1470 |
| Normal `.aup` docs pre-copy revalidation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates the docs source tree immediately before Markdown file copy staging and before per-file source/destination validation | Source-accounted; runtime partial | Docs copy race/reparse fixture execution is blocked in this shell; docs pre-copy revalidation source-accounted in checkpoint 1471 |
| Normal `.aup` work-directory cleanup checked path | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Removes the checked directory returned by `Require-Directory` after work-tree revalidation instead of the pre-validation input path string | Source-accounted; runtime partial | Work-directory cleanup race/reparse fixture execution is blocked in this shell; checked cleanup path source-accounted in checkpoint 1472 |
| Normal `.aup` temp/backup file cleanup checked path | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Removes the checked file returned by `Require-File` for stale temporary and backup cleanup instead of the pre-validation input path string | Source-accounted; runtime partial | Temp/backup file cleanup race/reparse fixture execution is blocked in this shell; checked file cleanup path source-accounted in checkpoint 1473 |
| Normal `.aup` checked directory creation path | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Uses the post-validation full path for directory creation and final directory validation | Source-accounted; runtime partial | Directory creation race/reparse fixture execution is blocked in this shell; checked directory creation path source-accounted in checkpoint 1474 |
| Normal `.aup` package artifact full-path activation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Uses post-validation full paths for temporary zip creation, package target activation, backup activation, cleanup, and final package validation | Source-accounted; runtime partial | Package artifact race/reparse fixture execution is blocked in this shell; package artifact full-path activation source-accounted in checkpoint 1475 |
| Normal `.aup` atomic writer temp/backup full-path activation | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Uses post-validation full paths for atomic JSON/feed temp writes, temp validation, backup activation, stale cleanup, and final cleanup | Source-accounted; runtime partial | Atomic writer temp/backup race/reparse fixture execution is blocked in this shell; atomic writer temp/backup full-path activation source-accounted in checkpoint 1476 |
| Normal `.aup` raw UTF-8 full-path write target | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Normalizes raw UTF-8 write helper input to a full path before `WriteAllText` | Source-accounted; runtime partial | Raw UTF-8 write race/reparse fixture execution is blocked in this shell; raw UTF-8 full-path write target source-accounted in checkpoint 1477 |
| Normal `.aup` manifest signer checked paths | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Passes a checked manifest file and post-validation signature output path to the external signer before revalidating produced signature output | Source-accounted; runtime partial | Manifest signer race/reparse fixture execution is blocked in this shell; manifest signer checked paths source-accounted in checkpoint 1478 |
| Normal `.aup` shared item validation full-path lookup | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Uses post-validation full paths for shared `Get-Item` lookup and item-kind diagnostics in `Require-Item` | Source-accounted; runtime partial | Shared item validation race/reparse fixture execution is blocked in this shell; shared item full-path lookup source-accounted in checkpoint 1479 |
| Normal `.aup` stale regular-file cleanup full-path existence check | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Validates cleanup paths for reparse traversal and uses post-validation full paths for existence checks and checked removal | Source-accounted; runtime partial | Cleanup race/reparse fixture execution is blocked in this shell; cleanup full-path existence check source-accounted in checkpoint 1480 |
| Normal `.aup` existing directory cleanup full-path existence check | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Validates cleanup directories for reparse traversal and uses post-validation full paths for existence checks, tree revalidation, and recursive removal | Source-accounted; runtime partial | Directory cleanup race/reparse fixture execution is blocked in this shell; directory cleanup full-path existence check source-accounted in checkpoint 1481 |
| Normal `.aup` component regular-file probe full-path existence check | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Validates component file probes for reparse traversal and uses post-validation full paths for existence checks and checked file evidence | Source-accounted; runtime partial | Component file probe race/reparse fixture execution is blocked in this shell; component file probe full-path existence check source-accounted in checkpoint 1482 |
| Normal `.aup` component directory probe full-path existence check | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Validates component directory probes for reparse traversal and uses post-validation full paths for existence checks and checked directory evidence | Source-accounted; runtime partial | Component directory probe race/reparse fixture execution is blocked in this shell; component directory probe full-path existence check source-accounted in checkpoint 1483 |
| Normal `.aup` shared no-reparse tree checked enumeration | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Enumerates the checked directory returned by `Require-Directory` during recursive reparse validation | Source-accounted; runtime partial | Recursive tree race/reparse fixture execution is blocked in this shell; checked tree enumeration source-accounted in checkpoint 1484 |
| Normal `.aup` payload file checked enumeration | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Enumerates payload files from the checked payload directory returned by `Require-Directory` | Source-accounted; runtime partial | Payload file enumeration race/reparse fixture execution is blocked in this shell; checked payload file enumeration source-accounted in checkpoint 1485 |
| Normal `.aup` engine child policy checked enumeration | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Enumerates unknown/pruned engine source children from the checked engine directory returned by `Require-Directory` | Source-accounted; runtime partial | Engine child policy race/reparse fixture execution is blocked in this shell; checked engine child enumeration source-accounted in checkpoint 1486 |
| Normal `.aup` docs Markdown checked staging root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates the checked docs directory returned by `Require-Directory` and derives Markdown relative paths from that checked root | Source-accounted; runtime partial | Docs staging race/reparse fixture execution is blocked in this shell; checked docs staging root source-accounted in checkpoint 1487 |
| Normal `.aup` top-level app file checked staging root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates and enumerates top-level app files from the checked payload root returned by `Require-Directory` | Source-accounted; runtime partial | Top-level app file staging race/reparse fixture execution is blocked in this shell; checked app file staging root source-accounted in checkpoint 1488 |
| Normal `.aup` top-level app directory checked staging root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Revalidates and enumerates top-level app directories from the checked payload root returned by `Require-Directory` | Source-accounted; runtime partial | Top-level app directory staging race/reparse fixture execution is blocked in this shell; checked app directory staging root source-accounted in checkpoint 1489 |
| Normal `.aup` service payload checked staging root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Resolves service executable candidates from the checked payload root returned by `Require-Directory` | Source-accounted; runtime partial | Service staging race/reparse fixture execution is blocked in this shell; checked service staging root source-accounted in checkpoint 1490 |
| Normal `.aup` payload hash checked root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Enumerates staged payload hash inputs and derives manifest payload-hash keys from the checked payload root returned by `Require-Directory` | Source-accounted; runtime partial | Payload hash root race/reparse fixture execution is blocked in this shell; checked payload hash root source-accounted in checkpoint 1491 |
| Normal `.aup` app component checked evidence root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Derives manifest `components.app` evidence from the checked staged app root returned by `Require-Directory` | Source-accounted; runtime partial | App component evidence race/reparse fixture execution is blocked in this shell; checked app component evidence root source-accounted in checkpoint 1492 |
| Normal `.aup` service component checked evidence root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Derives Core/Guard service manifest flags from the checked staged services root returned by `Require-Directory` | Source-accounted; runtime partial | Service component evidence race/reparse fixture execution is blocked in this shell; checked service component evidence root source-accounted in checkpoint 1493 |
| Normal `.aup` engine component checked evidence root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Derives runtime engine manifest flags from the checked staged engine root returned by `Require-Directory` | Source-accounted; runtime partial | Engine component evidence race/reparse fixture execution is blocked in this shell; checked engine component evidence root source-accounted in checkpoint 1494 |
| Normal `.aup` docs component checked evidence root | `tools/update/avorax-build-update-package.ps1`, `tests/test_custom_driver_contract.py` | Derives manifest `components.docs` evidence from the checked staged docs root returned by `Require-Directory` | Source-accounted; runtime partial | Docs component evidence race/reparse fixture execution is blocked in this shell; checked docs component evidence root source-accounted in checkpoint 1495 |
| Windows installer/release gates | `installer/windows/`, `.github/workflows/release-windows.yml`, `.github/workflows/ci.yml`, `tools/windows/`, `tools/branding/`, `tools/security/zentor-product-copy-gate.ps1`, `tools/security/zentor-no-malware-binaries-gate.ps1`, `tools/security/zentor-no-malware-binaries-gate.sh`, `tools/security/avorax-dependency-evidence.ps1`, `tools/perf/zentor-performance-gate.ps1`, `tools/perf/avorax-benchmark.py`, `tools/update/avorax-build-update-package.ps1` | MSI/EXE packaging, staged release/update evidence, installed smoke/release/performance gates with checked installed-layout roots, dependency evidence, static install-report evidence, bounded release/product-copy JSON/text parsing, fail-visible branding search diagnostics, bytecode-free no-malware binary hygiene scanning, bounded optional compatibility-runtime download handling, benchmark evidence, and Burn launch targets without fixed machine-wide install roots | Source-accounted; runtime partial | Full release build requires explicit dotnet/cargo/flutter paths and packaged fixtures; installed smoke-test default-root hardening source-accounted in checkpoint 818; MSI helper/report path hardening source-accounted in checkpoint 820; Burn LaunchTarget/LaunchWorkingFolder substitution source-accounted in checkpoint 821; malformed stage/release/smoke JSON evidence hardening source-accounted in checkpoint 828; MSI/workflow AI metadata JSON parsing source-accounted in checkpoint 830; product-copy gate bounded scan hardening source-accounted in checkpoint 831; PowerShell no-malware bytecode suppression source-accounted in checkpoint 837; shell no-malware bytecode suppression source-accounted in checkpoint 838; ClamAV download timeout/size handling source-accounted in checkpoint 840; dependency-evidence report activation source-accounted in checkpoint 844; PowerShell JSON helper normalization source-accounted in checkpoint 845; performance report activation source-accounted in checkpoint 846; workflow generated evidence atomic-write hardening source-accounted in checkpoint 847; update-package atomic activation and `File.Replace` backup compatibility source-accounted in checkpoint 848; benchmark report activation source/fixture-accounted in checkpoint 854; Python temp-cleanup visibility source/fixture-accounted in checkpoint 861; benchmark corpus exclusive-write source/fixture-accounted in checkpoint 864; benchmark exclusive-copy source/fixture-accounted in checkpoint 866; benchmark copy-cleanup combined diagnostics source/fixture-accounted in checkpoint 979; benchmark error diagnostic bounds source/fixture-accounted in checkpoint 980; benchmark subprocess output bounds source/fixture-accounted in checkpoint 982; Windows release-gate bounded handle reader source/fixture-accounted in checkpoint 1009; stage/smoke manifest bounded handle reader source/fixture-accounted in checkpoint 1010; MSI builder bounded handle reader source-accounted in checkpoint 1012; product-copy bounded handle reader source/gate-accounted in checkpoint 1013; release source-text bounded handle reader source-accounted in checkpoint 1014; branding stderr bounded handle reader source/gate-accounted in checkpoint 1015; no-malware CLI scan-root validation source/fixture-accounted in checkpoint 1016; shell no-malware wrapper path validation source-accounted in checkpoint 1017; shell branding stderr visibility source-accounted in checkpoint 1018; PowerShell no-malware env-restore visibility source/gate-accounted in checkpoint 1019; false-positive/performance gate diagnostic bounds source-accounted in checkpoint 1080; protection/release/stage/smoke gate diagnostic bounds source-accounted in checkpoint 1081; installed smoke Core health subprocess bounds source-accounted in checkpoint 1082; release workflow AI metadata bounded handle reader source-accounted in checkpoint 1083; shared System32 command diagnostic subprocess bounds source-accounted in checkpoint 1084; MSI driver-install command diagnostic bounds source-accounted in checkpoint 1088; shared security-gate command diagnostic helper source-accounted in checkpoint 1098; top-level release-gate command diagnostic bounds source-accounted in checkpoint 1099; false-positive/protection/performance subgate command diagnostic bounds source-accounted in checkpoint 1100; MSI builder Flutter/Cargo/dotnet command diagnostic bounds source-accounted in checkpoint 1102; PowerShell no-malware verifier command diagnostic bounds source/gate-accounted in checkpoint 1103; PowerShell branding ripgrep command diagnostic bounds source/gate-accounted in checkpoint 1105; shared security-gate sanitized child environment source/gate-accounted in checkpoint 1118; release dependency-evidence artifact upload fail-visible source-accounted in checkpoint 1191 |

| Python release subprocess timeout cleanup | `tools/perf/avorax-benchmark.py`, `tools/zentor_intel/build_realworld_detection_pack.py`, `tests/test_custom_driver_contract.py` | Bound post-timeout cleanup for benchmark and real-world detection-pack helper subprocesses so release evidence cannot hide kill/reap failures or wait indefinitely after timeout | Source-accounted; runtime partial | Checkpoint 1293 source-verifies bounded cleanup diagnostics, finite `process.wait(timeout=5)`, and fallback return codes; live release-host timeout fixtures remain blocked until a provisioned Python release host is available |
| PowerShell gate stop cleanup | `tools/security/avorax-security-gate-tools.ps1`, `tools/windows/avorax-system32-tools.ps1`, `tools/windows/zentor-protection-selftest.ps1`, `tests/test_custom_driver_contract.py` | Ensure release/security/System32/protection-selftest helpers fail visibly when timeout or output-limit cleanup kills a child that still does not exit within the bounded post-kill wait | Source-accounted; runtime partial | Checkpoint 1294 source-verifies finite post-kill waits, visible unreaped-child diagnostics, and no old `[void]$Process.WaitForExit(5000)` swallow path; full release/driver-host timeout fixtures remain blocked |
| Live remediation post-reboot stop cleanup | `tools/windows/avorax-fix-driver-live.ps1`, `tests/test_custom_driver_contract.py` | Ensure the generated elevated post-reboot remediation script reports unreaped child processes after timeout/output-limit cleanup instead of treating them as successfully stopped | Blocked/guarded | Checkpoint 1295 source-verifies the generated runner uses a finite post-kill wait and visible unreaped-child diagnostic; elevated remediation execution remains blocked without an approved Windows development VM |
| Live remediation log reader bounds | `tools/windows/avorax-fix-driver-live.ps1`, `tests/test_custom_driver_contract.py` | Keep `latest.log` append evidence bounded by reading existing log content through a checked handle/tail reader before atomic log activation | Blocked/guarded | Checkpoint 1299 source-verifies bounded handle/tail log reads and absence of `ReadAllText`; elevated remediation execution remains blocked |
| UEFI firmware reboot helper diagnostics | `tools/windows/avorax-open-firmware-settings.ps1`, `tools/windows/avorax-system32-tools.ps1`, `tests/test_custom_driver_contract.py` | Keep the explicitly confirmed firmware reboot helper on checked System32 execution while bounding Secure Boot query warning diagnostics | Blocked/guarded | Checkpoint 1296 source-verifies bounded Secure Boot query warnings; the helper is not executed locally because it can reboot the machine into firmware settings |
| Historical quarantine ACL subprocess boundary | `core/avorax_platform_security/src/lib.rs`, `core/zentor_local_core/src/quarantine/quarantine_store.rs`, `core/zentor_guard_service/src/main.rs`, `tests/test_custom_driver_contract.py` | Keep the retired Local Core/Guard `icacls.exe` runner unreachable and use one in-process handle-based owner/DACL verifier | Superseded and disabled; replacement runtime verified locally | Checkpoint 2184 removes both ACL subprocess paths, mutable account-name resolution, command timeout handling, and stderr parsing from production quarantine code. Source contracts require those surfaces to remain absent. The replacement process-token SID, exact protected DACL, same-file handle identity, and readback path has Windows runtime coverage; installed LocalSystem E2E remains partial. |

Checkpoint 1893 hardens the generated elevated driver-install helper System32 root handling:
the `avorax-install-driver.ps1` generated by `installer/windows/build-msi.ps1` now requires `SystemRoot`/`WINDIR` candidates for `certutil.exe`, `bcdedit.exe`, `pnputil.exe`, `sc.exe`, and `fltmc.exe` to be local Windows drive paths that pass no-reparse ancestor validation, accumulates rejected-root diagnostics, and includes the missing `Remove-SafeRegularFileIfPresent` cleanup helper for checked report backup deletion. Source-contracts passed (`500`), `build-msi.ps1` parser check passed, and no-malware/product-copy gates passed. Real driver install evidence remains blocked by signed-driver/host prerequisites.

Checkpoint 1894 hardens live driver remediation System32 root handling:
`tools/windows/avorax-fix-driver-live.ps1` now requires `SystemRoot`/`WINDIR` candidates for `bcdedit.exe`, `fltmc.exe`, `sc.exe`, `schtasks.exe`, and `powershell.exe` to be local Windows drive paths that pass no-reparse ancestor validation before deriving elevated tool paths, accumulates rejected-root diagnostics, and preserves final candidate regular-file/non-reparse checks. Source-contracts passed (`501`), `avorax-fix-driver-live.ps1` parser check passed, and no-malware/product-copy gates passed. Live remediation execution remains blocked by elevated VM/signed-driver/explicit-confirmation prerequisites.

Checkpoint 1895 hardens the shared System32 helper:
`tools/windows/avorax-system32-tools.ps1`, used by installer, firmware, test-signing, minifilter, and process-guard scripts, now requires `SystemRoot`/`WINDIR` candidates to be local Windows drive paths that pass no-reparse ancestor validation before deriving System32 tool paths. Rejected roots are reported with bounded diagnostics, and final tool candidates remain allowlisted/non-reparse regular files. Source-contracts passed (`502`), representative PowerShell parser checks passed, and no-malware/product-copy gates passed. Machine-wide execution evidence remains blocked by explicit-approval/elevated-VM/signed-driver prerequisites.

Checkpoint 1896 records a small-threat MVP improvement:
local-core scans now surface Windows anti-malware virus/PUA file-access blocks (`ERROR_VIRUS_INFECTED`/`225` and `ERROR_VIRUS_DELETED`/`226`) as confirmed detections instead of generic scan errors, while explicitly avoiding any Avorax quarantine claim when the operating system blocked content access. Runtime coverage verifies the standard EICAR safe test string through local-core scan reporting, the safe EICAR simulator auto-quarantine path, and explicit OS-block mapping. Focused EICAR tests passed (`5`), the OS-block mapping test passed (`1`), `cargo fmt --check` passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This supports immediate small/simple threat reporting, not live-malware, pre-execution driver-blocking, or production-E2E completion claims.

Checkpoint 1897 records known-bad hash MVP coverage:
local-core now has end-to-end runtime evidence that benign fixture content `harmless-known-bad-fixture`, matched through the native known-bad trust store, is reported as a confirmed threat with `known_bad_hash` evidence and auto-quarantined under `AutoQuarantineConfirmedOnly`. Focused known-bad test passed (`1`), EICAR/local-signature focused tests passed (`5`), `cargo fmt --check` passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This verifies the simple known-bad pipeline with a benign fixture only, not live-malware, unknown-malware, pre-execution driver-blocking, or production-E2E claims.

Checkpoint 1898 records Quick Scan known-bad `.bin` MVP coverage:
Quick Scan now treats `.bin` payloads as risky candidates while still skipping plain documents, and local-core runtime coverage proves a benign known-bad `.bin` fixture in `Downloads` is found by Quick Scan and auto-quarantined under `AutoQuarantineConfirmedOnly`. Quick-walk filter test passed (`1`), Quick Scan known-bad `.bin` test passed (`1`), known-bad Custom Scan test passed (`1`), EICAR/local-signature focused tests passed (`5`), `cargo fmt --check` passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This is benign-fixture small-threat MVP evidence, not live-malware, unknown-malware, pre-execution driver-blocking, or production-E2E evidence.

Checkpoint 1899 records Quick Scan archive-review MVP coverage:
local-core runtime coverage proves Quick Scan reports a benign ZIP fixture in `Downloads` containing a nested executable-looking entry (`invoice.exe`) for review, while preserving conservative behavior by not auto-quarantining archive-only evidence under `AutoQuarantineConfirmedOnly`. Quick Scan ZIP review test passed (`1`), Quick Scan known-bad `.bin` test passed (`1`), EICAR/local-signature focused tests passed (`5`), `cargo fmt --check` passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This is benign archive-header review evidence, not nested extraction, live-malware, pre-execution blocking, or production-E2E evidence.

Checkpoint 1900 records Quick Scan script/dropper review MVP coverage:
local-core runtime coverage proves Quick Scan reports a benign PowerShell script fixture in `Downloads` containing encoded-command, download, and execution indicators. The script is surfaced as probable/high review evidence with native signature/rule reasons and is not auto-quarantined under `AutoQuarantineConfirmedOnly`. Quick Scan encoded-downloader script test passed (`1`), Quick Scan ZIP review test passed (`1`), Quick Scan known-bad `.bin` test passed (`1`), EICAR/local-signature focused tests passed (`5`), `cargo fmt --check` passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This is inert script review evidence, not live-malware, script execution blocking, pre-execution blocking, or production-E2E evidence.

Checkpoint 1901 records Quick Scan ransomware-note review MVP coverage:
local-core runtime coverage proves Quick Scan reports an inert PowerShell fixture in `Downloads` containing ransom-note language plus `vssadmin delete shadows` indicators. The script is surfaced as ransomware review/probable evidence with native signature/rule reasons and is not auto-quarantined under `AutoQuarantineConfirmedOnly`. Quick Scan ransomware-note/backup-delete script test passed (`1`), encoded-downloader script test passed (`1`), ZIP review test passed (`1`), known-bad `.bin` test passed (`1`), EICAR/local-signature focused tests passed (`5`), `cargo fmt --check` passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This is inert review evidence, not live ransomware, behavior blocking, rollback, pre-execution blocking, or production-E2E evidence.

Checkpoint 1902 records Quick Scan infostealer/miner/persistence review MVP coverage:
local-core runtime coverage proves Quick Scan reports inert fixtures in `Downloads` for infostealer indicators (`collector.js` with browser credential, wallet, archive staging, and localhost POST terms), miner/PUP indicators (`miner-config.ps1` with `stratum+tcp` and scheduled-task terms), and multiple persistence indicators (`startup-task.ps1` with scheduled-task plus service terms). Local-core now preserves native threat categories such as infostealer, suspicious downloader/script, credential-theft, persistence, rootkit/security-tamper indicators, and related rule/YARA metadata categories instead of collapsing them to `Unknown`. Native engine now emits conservative review-only `script_persistence_multiple_indicators` evidence for scripts with multiple persistence indicators, and category inference no longer lets path text such as `Downloads` override explicit persistence evidence. Quick Scan review regressions passed (`6`), native indicator regressions passed (`9`), individual infostealer/miner/persistence Quick Scan tests passed (`3`), both rustfmt checks passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This is inert review evidence, not live malware, process blocking, pre-execution blocking, installed-service/UI E2E behavior, or production false-positive-rate evidence.

Checkpoint 1903 records Flutter small-threat category surfacing:
the shared Dart `ThreatCategory` protocol enum now accepts and labels the local-core/native small-threat categories from checkpoint 1902, including infostealer, suspicious downloader/script, credential-theft, persistence, rootkit/security-tamper indicators, and related categories. The Scan tab now renders the category as a visible threat chip, and widget coverage proves infostealer, miner, and persistence review detections show their category labels while not exposing the manual Quarantine action for medium-confidence suspicious review-only evidence. Local-core IPC runtime coverage proves an `infostealer` scan-report threat parses into `ThreatCategory.infostealer` instead of being dropped as malformed. `zentor_protocol` analyze passed, protocol tests passed (`12`), `zentor_client` Flutter analyze passed, Scan-tab widget tests passed (`36`), local-core scan-report IPC tests passed (`12`), source-contracts passed (`502`), and no-malware/product-copy gates passed. This is UI/IPC surfacing evidence for inert fixtures, not live malware, process blocking, pre-execution blocking, installed-service/UI E2E behavior, or production false-positive-rate evidence.

Checkpoint 1904 records Flutter small-threat scan-event summary coverage:
`threat_detected` and `scan_completed` local events now use a bounded scan summary with scan status, kind, action mode, file/threat/suspicious/quarantine counts, optional coverage message, and compact threat summaries by category, verdict, and status. Runtime controller coverage proves an inert Quick Scan with infostealer, miner, and persistence review threats records event details containing `Potential infostealer`, `Potential miner`, `Persistence indicator`, `Review suggested x3`, `Detected x3`, and `quarantined=0`. The scan-event source contract now requires `_scanEventDetails(report, coverageWarning: scanErrorMessage)` for completion events and verifies category/verdict/status summary markers. Offline scan/controller tests passed (`26`), local-event tests passed (`20`), Flutter analyze passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This is bounded UI local-event/history evidence for inert fixtures, not live malware, process blocking, pre-execution blocking, installed-service/UI E2E behavior, production false-positive-rate evidence, or tamper-proof audit logging.

Checkpoint 1905 records Flutter quarantine lifecycle confirmed-flow coverage:
controller runtime coverage now proves confirmed restore/delete quarantine lifecycle behavior for existing quarantine records: local-core restore/delete IPC is called exactly once, stale UI rows update to `restored` and `deleted` when refresh fails, `actionTaken` matches each new status, and `quarantine_restore_requested`, `quarantine_item_restored`, `quarantine_item_deleted`, and `quarantine_refresh_failed` events are recorded with quarantine/warning metadata. Quarantine screen widget coverage still proves restore/delete dialogs cancel without IPC and confirm with IPC. Focused Rust quarantine-store tests prove restore confirmation and overwrite prevention, delete confirmation and store-boundary behavior, and restore/delete active-quarantine status preflight. Focused lifecycle test passed (`1`), quarantine-related offline/controller tests passed (`17`), Quarantine screen widget tests passed (`5`), Flutter analyze passed, focused Rust quarantine tests passed (`3`), rustfmt passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This is fake-IPC UI/controller plus isolated backend-fixture evidence, not installed-service E2E behavior, live malware handling, process blocking, pre-execution blocking, secure erase, or production false-positive-rate evidence.

Checkpoint 1906 records Flutter quarantine original-rescan coverage:
quarantine rows whose status is no longer active `quarantined` now expose a `Scan original path` action. The controller runs this as a detect-only custom scan through existing scan orchestration, target preflight, progress, event, and report handling. Active quarantine rows hide the UI action, and direct controller calls for active quarantined records log `quarantine_rescan_unavailable` without scan IPC so opaque quarantine payloads remain isolated. Focused rescan controller tests passed (`2`), Quarantine screen widget tests passed (`7`), quarantine-related offline/controller tests passed (`19`), Flutter analyze passed, source-contracts passed (`502`), and no-malware/product-copy gates passed. This is fake-IPC Flutter/controller/UI evidence, not installed-service E2E behavior, active quarantine payload scanning, live malware handling, process blocking, pre-execution blocking, secure erase, or production false-positive-rate evidence.

Checkpoint 1907 records a focused small-threat MVP verification entrypoint:
`tools\testing\verify-small-threat-mvp.ps1` now gives the small-threat control set a reproducible local validation command. The script runs local-core EICAR/OS-block tests, Quick Scan small-threat regressions, native indicator regressions, Dart protocol tests, Flutter Scan/quarantine tests, Flutter analyze, Python source contracts, product-copy, and no-malware binary gates while avoiding live malware, admin install, machine-wide changes, network downloads, and archive unpacking. The end-to-end verifier passed in `29.8s`, source-contracts passed (`503`), the script parser check passed, and Git status remains blocked because the folder is not a Git repository. This verifies the current small-threat MVP sweep only; installed service/UI E2E, process blocking, pre-execution driver behavior, signed-driver validation, live-malware validation, and production false-positive-rate evidence remain blocked/limited.

Checkpoint 1908 records scan action-mode label hardening:
the legacy `autoQuarantineAllDetections` protocol value remains accepted for saved config/IPC compatibility, but visible protocol/UI/docs text now labels it `Legacy confirmed-only quarantine` / `Legacy confirmed-only` instead of `Review non-confirmed`. This keeps the Scan tab from implying that probable, suspicious, or heuristic review-only findings are automatically quarantined. Protocol tests passed (`13`), the focused Scan-tab widget regression passed (`1`), the small-threat MVP verifier passed end-to-end in `28.5s`, and Git status remains blocked because the folder is not a Git repository. This is control-label honesty hardening only; installed service/UI E2E, process blocking, pre-execution driver behavior, signed-driver validation, live-malware validation, and production false-positive-rate evidence remain blocked/limited.

Checkpoint 1909 records review-only scan-result notice hardening:
suspicious/unknown or low/medium-confidence scan result rows that are not eligible for default quarantine now show a visible notice that Avorax will not automatically quarantine the file and that the user should inspect it before choosing an action. Confirmed/probable high-confidence rows retain the quarantine action path. The focused Scan-tab widget regression passed (`1`), Flutter analyze passed, the small-threat MVP verifier passed end-to-end in `27.9s`, source-contracts passed (`503`), product-copy/no-malware gates passed, and Git status remains blocked because the folder is not a Git repository. This is scan-result honesty hardening only; installed service/UI E2E, process blocking, pre-execution driver behavior, signed-driver validation, live-malware validation, and production false-positive-rate evidence remain blocked/limited.

Checkpoint 1910 records malicious-feedback current-row honesty hardening:
Scan result `Mark malicious` still saves a local malicious feedback label for future detection decisions, but it no longer changes the current scan row into a quarantine recommendation. The confirmation dialog now explicitly states that the action is feedback-only and does not quarantine, delete, execute, or change the current file. Focused Scan widget tests passed (`2`), focused malicious-feedback controller/source tests passed (`4`), the visual policy source-marker test passed (`1`), Flutter analyze passed, the small-threat MVP verifier passed end-to-end in `28.1s`, source-contracts passed (`503`), product-copy/no-malware gates passed, and Git status remains blocked because the folder is not a Git repository. This is feedback-action honesty hardening only; installed service/UI E2E, process blocking, pre-execution driver behavior, signed-driver validation, live-malware validation, and production false-positive-rate evidence remain blocked/limited.

Checkpoint 1911 records small-threat verifier feedback coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the focused `offline_scan_test.dart --plain-name "malicious feedback"` controller coverage, so checkpoint 1910's feedback-only behavior is part of the reproducible small-threat MVP sweep. The verifier script parser check passed, source-contracts passed (`503`), the expanded small-threat MVP verifier passed end-to-end in `31.6s`, product-copy/no-malware gates passed, and Git status remains blocked because the folder is not a Git repository. This is verifier coverage hardening only; installed service/UI E2E, process blocking, pre-execution driver behavior, signed-driver validation, live-malware validation, and production false-positive-rate evidence remain blocked/limited.

Checkpoint 1912 records feedback success-event traceability:
successful false-positive and malicious feedback local events now include the full detection path and explicit current-row/action context. False-positive success records that the row was ignored by the user and future detections may be suppressed; malicious-feedback success records that the current row is unchanged and no quarantine, delete, or execution occurred. Focused false-positive feedback tests passed (`4`), focused malicious feedback tests passed (`4`), Flutter analyze passed, the expanded small-threat MVP verifier passed end-to-end in `31.2s`, source-contracts passed (`503`), product-copy/no-malware gates passed, and Git status remains blocked because the folder is not a Git repository. This is audit/history traceability hardening only; installed service/UI E2E, process blocking, pre-execution driver behavior, signed-driver validation, live-malware validation, and production false-positive-rate evidence remain blocked/limited.

Checkpoint 1913 records small-threat verifier false-positive coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the focused `offline_scan_test.dart --plain-name "false-positive feedback"` controller coverage in addition to the malicious-feedback filter, so checkpoint 1912's success-event traceability is part of the reproducible small-threat MVP sweep for both feedback paths. The verifier script parser check passed, source-contracts passed (`503`), the expanded small-threat MVP verifier passed end-to-end in `34.5s`, product-copy/no-malware gates passed, and Git status remains blocked because the folder is not a Git repository. This is verifier coverage hardening only; installed service/UI E2E, process blocking, pre-execution driver behavior, signed-driver validation, live-malware validation, and production false-positive-rate evidence remain blocked/limited.

Checkpoint 1914 records a safe EICAR smoke-test command:
`tools\testing\run-safe-eicar-smoke.ps1` creates a temporary `ZENTOR-SAFE-EICAR-SIMULATOR-FILE`, scans it through local-core IPC in detect-only mode, verifies a confirmed test threat is reported, and removes the temporary fixture. `docs\testing-eicar.md` documents the non-admin command and its safety boundary. The smoke test passed with `Status: threatsFound`, `Threats: 1`, and `Action mode: detectOnly`; source-contracts passed (`504`); the expanded small-threat MVP verifier passed end-to-end in `34.4s`; product-copy/no-malware gates passed; and Git status remains blocked because the folder is not a Git repository. This is safe local smoke-test evidence only; installed service/UI E2E, process blocking, pre-execution driver behavior, signed-driver validation, live-malware validation, and production false-positive-rate evidence remain blocked/limited.

Checkpoint 1915 records a local-core quarantine runtime crash fix and reversible smoke test:
the local quarantine SHA-256 helper now keeps its 1 MiB read buffer on the heap instead of the Windows main-thread stack, fixing a reproducible `STATUS_STACK_OVERFLOW` in the real `quarantine_file` IPC path before payload movement. `tools\testing\run-safe-quarantine-restore-smoke.ps1` now creates a temporary harmless `ZENTOR-SAFE-EICAR-SIMULATOR-FILE`, uses a process-local `AVORAX_QUARANTINE_DIR`, scans with `autoQuarantineConfirmedOnly`, verifies the confirmed simulator is quarantined as `.avoraxq`, lists the record, restores it with explicit confirmation, verifies restored bytes, and removes the temporary root. The smoke test passed with `Status: threatsFound`, `Threats: 1`, `Action mode: autoQuarantineConfirmedOnly`, and `Restore status: restored`; focused quarantine-related Rust tests passed (`88`); rustfmt passed; source-contracts passed (`505`). This is safe simulator quarantine/restore evidence only; it is not live-malware handling, installed-service E2E, pre-execution blocking, secure erase, or production false-positive-rate evidence.

Checkpoint 1916 records auto-quarantine threat-row evidence:
local-core scan reports now attach optional `quarantine_id`, `quarantine_path`, and `quarantine_action_taken` to threat rows when a confirmed detection is actually moved into quarantine. The shared Dart protocol and Flutter local-core parser preserve that evidence without requiring it for older reports. The safe quarantine/restore smoke now verifies the scan row carries the created quarantine record id/path/action before listing and restoring the record. Focused Rust EICAR auto-quarantine evidence passed (`1`), Dart protocol tests passed (`14`), focused Flutter scan-report quarantine-evidence IPC passed (`1`), the safe quarantine/restore smoke passed, source-contracts passed (`505`), product-copy/no-malware gates passed, and the expanded small-threat MVP verifier passed in `39.3s`. This improves local scan/quarantine traceability for safe simulator detections; it does not prove installed-service E2E, live-malware handling, pre-execution blocking, signed-driver behavior, or production false-positive-rate evidence.

Checkpoint 1917 records quarantine evidence surfacing in the Flutter Scan UI
and local event/history layer:
quarantined scan rows now show an isolated-quarantine notice with the created
record id and payload path evidence, scan completion/detection events include
compact quarantine record summaries, and `file_quarantined` events include
bounded record id/path/action evidence. Focused Flutter controller event
coverage passed (`1`), focused Scan-tab widget coverage passed (`1`), Flutter
analyzer passed, and the expanded small-threat MVP verifier passed in `37.6s`.
This is UI/history traceability for safe simulator quarantine evidence only; it
does not prove installed-service E2E, live-malware handling, process blocking,
pre-execution blocking, signed-driver behavior, or production false-positive
rate evidence.

Checkpoint 1918 records expanded small-threat MVP verifier smoke coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes
`tools\testing\run-safe-eicar-smoke.ps1` before the quarantine/restore smoke, so
the one-command sweep proves both safe detect-only reporting and safe
auto-quarantine/restore behavior. The standalone detect-only smoke passed with
`Status: threatsFound`, `Threats: 1`, and `Action mode: detectOnly`;
source-contracts passed (`505`); and the expanded small-threat MVP verifier
passed in `38.4s`, including the new `safe EICAR detect-only smoke` block. This
is verifier coverage hardening only; it does not prove installed-service E2E,
live-malware handling, process blocking, pre-execution blocking, signed-driver
behavior, production false-positive-rate evidence, or secure erase.

Checkpoint 1919 records safe quarantine delete smoke coverage:
`tools\testing\run-safe-quarantine-delete-smoke.ps1` creates a temporary safe
EICAR simulator fixture, uses a process-local `AVORAX_QUARANTINE_DIR`, scans
with `autoQuarantineConfirmedOnly`, verifies the simulator payload was moved
into `.avoraxq` quarantine storage, deletes the quarantine item with explicit
confirmation, verifies the payload is gone, and verifies deleted metadata
remains listed. The standalone delete smoke passed with `Status: threatsFound`,
`Threats: 1`, `Action mode: autoQuarantineConfirmedOnly`, and
`Delete status: deleted`; source-contracts passed (`506`); and the expanded
small-threat MVP verifier passed in `40.5s`, including the new
`safe EICAR quarantine delete smoke` block. This is isolated temporary-data
quarantine delete verification only; it is not secure erase and does not prove
installed-service E2E, live-malware handling, process blocking, pre-execution
blocking, signed-driver behavior, or production false-positive-rate evidence.

Checkpoint 1920 records safe allowlist smoke coverage and two local-core fixes:
`tools\testing\run-safe-allowlist-smoke.ps1` creates a temporary safe EICAR
simulator fixture, uses process-local `ZENTOR_ALLOWLIST_FILE` and
`AVORAX_QUARANTINE_DIR` stores, adds the file to the allowlist, scans with
`autoQuarantineConfirmedOnly`, and verifies the detection is reported as
`allowlisted` with `quarantined_files=0` and no `.avoraxq` payload. This smoke
found that file allowlist hashing could overflow the Windows local-core
main-thread stack due to a 1 MiB stack buffer, and that stored
`sha256:<hash>` allowlist entries did not match bare scan threat hashes. The
hash buffer now uses heap allocation and hash comparison strips the optional
`sha256:` prefix before matching. The standalone allowlist smoke passed with
`Status: threatsFound`, `Threats: 1`, `Threat status: allowlisted`, and
`Quarantined files: 0`; focused local-core allowlist tests passed (`37`);
source-contracts passed (`508`); and the expanded small-threat MVP verifier
passed in `41.6s`, including the new `safe EICAR allowlist smoke` block. This
is safe simulator allowlist verification only; it does not prove production
false-positive rates, installed-service E2E, live-malware handling, process
blocking, pre-execution blocking, or signed-driver behavior.

Checkpoint 1921 records safe allowlist removal lifecycle coverage:
`tools\testing\run-safe-allowlist-removal-smoke.ps1` creates a temporary safe
EICAR simulator fixture, uses process-local `ZENTOR_ALLOWLIST_FILE` and
`AVORAX_QUARANTINE_DIR` stores, adds the file to the allowlist, verifies an
allowlisted scan does not quarantine it, deactivates the entry through
`remove_allowlist_entry` with explicit confirmation, verifies inactive history
remains listed, and verifies the same simulator is auto-quarantined after
removal. The standalone removal smoke passed with
`Initial threat status: allowlisted`, `Removed entry active: False`,
`Post-removal threat status: quarantined`, and
`Post-removal quarantined files: 1`; focused local-core allowlist tests passed
(`37`); source-contracts passed (`509`); and the expanded small-threat MVP
verifier passed in `44.5s`, including the new
`safe EICAR allowlist removal smoke` block. This is safe simulator allowlist
lifecycle verification only; it does not prove production false-positive rates,
installed-service E2E, live-malware handling, process blocking, pre-execution
blocking, signed-driver behavior, or secure erase.

Checkpoint 1922 records safe manual quarantine IPC coverage:
`tools\testing\run-safe-manual-quarantine-smoke.ps1` creates a temporary benign
fixture, uses a process-local `AVORAX_QUARANTINE_DIR`, calls `quarantine_file`
with explicit manual detection and engine evidence, verifies the source is moved
into `.avoraxq` quarantine storage, restores the item with explicit
confirmation, and verifies the original bytes are restored. The standalone
manual quarantine smoke passed with `Quarantine status: quarantined` and
`Restore status: restored`; focused local-core quarantine tests passed (`88`);
source-contracts passed (`510`); and the expanded small-threat MVP verifier
passed in `45.7s`, including the new `safe manual quarantine restore smoke`
block. This is temporary benign manual quarantine/restore verification only; it
does not prove live-malware handling, installed-service E2E, pre-execution
blocking, signed-driver behavior, production false-positive-rate evidence, or
secure erase.

Checkpoint 1923 records safe manual quarantine/delete IPC coverage:
`tools\testing\run-safe-manual-quarantine-delete-smoke.ps1` creates a temporary
benign fixture, uses a process-local `AVORAX_QUARANTINE_DIR`, calls
`quarantine_file` with explicit manual detection and engine evidence, verifies
the source is moved into `.avoraxq` quarantine storage, deletes the item with
explicit confirmation, verifies the quarantine payload is gone, and verifies the
source fixture was not restored during delete. The standalone manual delete
smoke passed with `Quarantine status: quarantined` and
`Delete status: deleted`; focused local-core quarantine tests passed (`88`);
source-contracts passed (`511`); and the expanded small-threat MVP verifier
passed in `46.9s`, including the new `safe manual quarantine delete smoke`
block. This is temporary benign manual quarantine/delete verification only; it
does not prove live-malware handling, installed-service E2E, pre-execution
blocking, signed-driver behavior, production false-positive-rate evidence,
secure erase, or installed UI E2E.

Checkpoint 1924 records safe custom-folder scan coverage:
`tools\testing\run-safe-folder-scan-smoke.ps1` creates a temporary folder with
one benign fixture and one safe EICAR simulator fixture, uses a process-local
`AVORAX_QUARANTINE_DIR`, runs `scan_folder` with
`autoQuarantineConfirmedOnly`, verifies both files are scanned, verifies the
benign fixture remains in place, verifies only the simulator is quarantined, and
verifies quarantine id/path evidence is returned. The standalone folder smoke
passed with `Status: threatsFound`, `Files scanned: 2`, `Threats: 1`, and
`Quarantined files: 1`; focused local-core scan tests passed (`90`);
source-contracts passed (`512`); and the expanded small-threat MVP verifier
passed in `48.2s`, including the new `safe custom-folder scan smoke` block.
This is safe custom-folder scan verification only; it does not prove
live-malware handling, installed-service/UI E2E, pre-execution blocking,
signed-driver behavior, production false-positive-rate evidence, or secure
erase.

Checkpoint 1925 records small-threat verifier cancellation coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the local-core
`scan_cancellation` regression filter. The focused regressions verify that scan
cancellation reports unscanned remainder, uses non-following exclusive staged
cancellation token writes, and leaves no temporary token behind. Focused
cancellation tests passed (`3`), source-contracts passed (`512`), and the
expanded small-threat MVP verifier passed in `49.4s`, including the new
`local-core scan cancellation regressions` block. An attempted quick
selected-path process smoke timed out on this host and was removed rather than
left as a flaky/hanging verifier step. This is local-core cancellation
regression coverage only; it does not prove installed UI cancellation E2E,
live-malware handling, pre-execution blocking, signed-driver behavior, or
production false-positive-rate evidence.

Checkpoint 1926 records small-threat verifier full-scan boundedness coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the local-core
`full_scan` regression filter. The focused regressions verify missing or
inaccessible scan roots are reported as skipped and full-scan time-budget exits
report an unscanned remainder instead of silently claiming completion. Focused
full-scan tests passed (`2`), source-contracts passed (`512`), and the expanded
small-threat MVP verifier passed in `48.9s`, including the new
`local-core full-scan boundedness regressions` block. This is local-core
boundedness regression coverage only; it does not prove installed UI/service
E2E, live-malware handling, pre-execution blocking, signed-driver behavior, or
production false-positive-rate evidence.

Checkpoint 1927 records small-threat verifier local-event/log-export coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the Flutter
`local_event_test.dart` and `logs_screen_test.dart` suites. These focused tests
cover local security event persistence, host-scoped history keys, malformed and
oversized history recovery, bounded event fields, staged/non-following log
export writes, export cleanup diagnostics, controller export failure reporting,
duplicate export blocking, and Security Events export dialog behavior. Focused
local-event tests passed (`40`), focused logs-screen export tests passed (`3`),
source-contracts passed (`512`), and the expanded small-threat MVP verifier
passed in `55.7s`, including `Flutter local-event audit tests` and
`Flutter logs screen export tests`. This is Flutter controller/widget audit-log
coverage only; it does not prove packaged desktop click-through E2E,
installed-service logging E2E, live-malware handling, pre-execution blocking,
signed-driver behavior, or production false-positive-rate evidence.

Checkpoint 1928 records small-threat verifier scheduled quick-scan coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes Flutter focused
scheduled quick-scan controller/source, Settings UI confirmation, and config
validation filters. These tests cover explicit confirmation before saving a
schedule, detect-only timer execution, audited skip behavior while another scan
is running, timer creation failure rollback, interval bounds, config round-trip,
and Settings copy/dialog behavior that states the schedule only runs while the
app is open and does not install a Windows Scheduled Task. Focused scheduled
controller/source tests passed (`7`), focused Settings scheduled-scan tests
passed (`2`), focused scheduled config tests passed (`2`), source-contracts
passed (`512`), and the expanded small-threat MVP verifier passed in `66.8s`,
including the three scheduled quick-scan blocks. This is Flutter
controller/widget/config coverage for app-lifetime scheduling only; it does not
prove packaged desktop click-through E2E, Windows Scheduled Task/service
scheduling, live-malware handling, pre-execution blocking, signed-driver
behavior, or production false-positive-rate evidence.

Checkpoint 1929 records small-threat verifier scan-target planning coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes
`Flutter scan-target planning tests`. The focused planner suite verifies quick
scan selection for common user-risk folders, Windows Startup without broad Start
Menu scanning, Linux autostart/local-bin persistence paths without broad
`.config` scanning, full-scan accessible root selection, rejection of relative
and UNC environment roots, and retention of uninspectable paths for local-core
validation instead of silently dropping them. Focused scan-target tests passed
(`7`), source-contracts passed (`512`), and the expanded small-threat MVP
verifier passed in `69.6s`, including the new scan-target planning block. This
is Flutter scan-target planner coverage only; it does not prove packaged desktop
click-through E2E, installed local-core launch E2E, live-malware handling,
pre-execution blocking, signed-driver behavior, or production
false-positive-rate evidence.

Checkpoint 1930 records small-threat verifier scope-matrix coverage:
`tools\testing\verify-small-threat-mvp.ps1` now prints a `Verification scope`
section after a successful run. The output explicitly separates verified MVP
behavior from partial evidence and technical limits, including no live-malware
handling, no pre-execution blocking claim without a signed installed driver, no
Windows Scheduled Task/background-service scheduling claim, no secure-erase
claim, and no enterprise update/deployment approval claim. Source-contracts
passed (`512`), and the expanded small-threat MVP verifier passed in `69.4s`
with the Verified/Partial/Technically limited scope output. This is verifier
honesty/readiness reporting only; it does not add installed E2E, live-malware,
driver/pre-execution, secure-erase, Windows Scheduled Task, or enterprise
deployment evidence.

Checkpoint 1931 records small-threat verifier realtime watcher coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes local-core realtime
watcher regressions plus Flutter watcher IPC diagnostics and controller tests.
The focused Rust watcher fixtures cover non-following path checks,
stopped/no-path honesty, debounce/stable-size behavior, monitor-only review
semantics, duplicate-cache behavior, and start-watch IPC path limits. The
Flutter IPC fixtures cover malformed watcher responses, protocol-warning
fail-visible behavior, bounded watcher fields, malformed list/active
diagnostics, and active-without-path diagnostics. The Flutter controller fixtures
cover confirmed best-effort watcher start, stop/clear behavior, unconfirmed
start/stop no-ops, and uninspectable path limitations carried visibly for local
Core validation. Focused local-core watcher tests passed (`10`), focused Flutter
watcher IPC tests passed (`7`), focused Flutter watcher controller tests passed
(`6`), source-contracts passed (`512`), and the expanded small-threat MVP
verifier passed in `75.8s`, including the realtime watcher blocks and updated
scope matrix. This is best-effort user-mode watcher fixture coverage only; it
does not prove installed watcher E2E, kernel realtime blocking, live-malware
handling, pre-execution blocking, signed-driver behavior, or production
false-positive-rate evidence.

Checkpoint 1932 records small-threat verifier health/self-test readiness
coverage: `tools\testing\verify-small-threat-mvp.ps1` now includes local-core
health self-test regressions, native-engine self-test regressions, Flutter health
IPC diagnostics, and Flutter protection self-test controller tests. The focused
local-core fixtures cover native self-test error context and failed prerequisite
naming; the native-engine fixtures cover EICAR self-test detection and
missing-pack self-test failure; the Flutter health IPC fixtures cover
malformed/protocol-warning/list diagnostics and self-test error fields; and the
Flutter controller fixtures cover duplicate protection self-test blocking,
bounded exception diagnostics, and scheduled scan self-test/heartbeat metadata.
Focused local-core health self-test tests passed (`2`), focused native-engine
self-test tests passed (`2`), focused Flutter health IPC tests passed (`7`),
focused Flutter protection self-test controller tests passed (`3`),
source-contracts passed (`512`), and the expanded small-threat MVP verifier
passed in `82.3s`, including the health/self-test blocks and updated scope
matrix. This is local fixture/controller readiness coverage only; it does not
prove installed service/driver self-test E2E, live-malware handling,
pre-execution blocking, signed-driver behavior, or production false-positive-rate
evidence.

Checkpoint 1933/2049 records small-threat verifier dependency-evidence coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the dependency evidence
gate and writes `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-dependency-evidence.json`.
The gate reads source-level evidence only: exact-pinned Python requirement files,
required Rust/Dart lockfiles, non-Windows Android Gradle lock status, Gradle
wrapper URL/hash pinning, and archived website lockfile presence. It does not
install packages or launch package managers. The focused dependency evidence
gate passed, source-contracts passed (`512`), and the expanded small-threat MVP
verifier passed in `82.5s`, including the dependency gate and updated scope
matrix. Checkpoint 2049 makes the full-suite report validator parse that generated
dependency evidence and require the exact Python pins, exact lockfile matrix,
current manifest/lockfile presence, pinned Gradle wrapper URL/hash,
`allow_known_blockers=false`, `ok=true`, `partial=false`, and empty release
blockers. A negative copied report with the required Local Core lockfile row set
to `lockfile_present=false` failed with `dependency evidence generated report
lockfile check 3 lockfile_present must be JSON boolean True.` Source-contracts
passed (`540`), and the full small-threat MVP verifier plus report validator
passed with `139` steps in `302.6s` for
`.workflow\ultracode\avorax-hardening\results\2049-small-threat-mvp-full-report.json`.
This is source-level dependency/lockfile evidence only; it does not
replace a full release-host SBOM/license report, Android Gradle lock generation,
machine-wide dependency installation, installed E2E, live-malware handling,
pre-execution blocking, signed-driver behavior, or production false-positive-rate
evidence.

Checkpoint 1934/2050 records small-threat verifier performance/resource coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the safe synthetic
performance/resource gate. The verifier invokes
`tools\perf\zentor-performance-gate.ps1` with explicit checked Cargo and Python
paths, and the gate runs only harmless synthetic fixtures plus existing unit
decision paths. The standalone performance gate passed and wrote
`dist\performance\performance_gate_report.json` plus
`dist\performance\benchmark_report.json`; the benchmark report covered synthetic
traversal/hash (`64` files, `4096` bytes each), native signature-match
wall-clock, Guard known-good decision wall-clock, and synthetic update-copy
simulation. The parser check passed, source-contracts passed (`512`), and the
expanded small-threat MVP verifier passed in `86.5s`, including the new
performance/resource block and updated scope matrix. Checkpoint 2050 wires those
generated performance reports into `generated_reports.performance_gate` and
`generated_reports.performance_benchmark`, then makes the full-suite report
validator parse their contents. It now requires the gate threshold/status values,
the unit-path plus WDK VM latency-test limitation, the benchmark synthetic-only
fixture policy, matching repository root, exactly four metrics, the `64` by
`4096` harmless corpus, passing native signature and Guard command metrics, and
the non-elevated update-copy simulation disclaimer. The old 2049 report failed
because `performance_gate` was missing, and a copied benchmark report with
`safe_fixture_policy='real malware samples'` failed with `performance benchmark
generated report safe_fixture_policy mismatch`. Source-contracts passed (`540`),
and the full small-threat MVP verifier plus report validator passed with `139`
steps in `308.6s` for
`.workflow\ultracode\avorax-hardening\results\2050-small-threat-mvp-full-report.json`.
This is bounded synthetic user-mode development evidence only; it does not prove
release-host performance baselines, installed service/UI E2E, live-malware
handling, kernel realtime blocking, driver latency, pre-execution blocking,
signed-driver behavior, or production false-positive-rate evidence.

Checkpoint 1935 records Windows desktop build-readiness recheck evidence:
`flutter doctor -v` confirms the installed Flutter 3.44.4 toolchain and Windows
desktop device discovery on this host, while still reporting missing Visual
Studio Desktop C++ components. The Android SDK is also missing but remains out
of scope for the Windows antivirus release path. Host-only
`tools\windows\avorax-release-prereq-check.ps1` wrote
`dist\release-prereq\host_only_1935.json` with `ok=false`, `24` checks, and
exactly three real host errors: explicit .NET SDK path missing/no SDK inventory,
unavailable Windows symlink support/Developer Mode, and missing Visual Studio
Desktop C++ components. A direct `flutter build windows --debug --no-pub`
attempt failed immediately with Flutter's plugin symlink-support prerequisite,
and `dotnet --list-sdks` confirmed `C:\Program Files\dotnet\dotnet.exe` has no
SDKs installed. This is current blocker evidence only; Windows `Avorax.exe`,
installer stage/MSI/setup artifacts, installed service/UI E2E, signed-driver
validation, and pre-execution blocking remain unverified.

Checkpoint 1936 records repair-installation privilege-boundary hardening:
the Flutter local-core service repair action no longer uses development
`target\release` local-core candidates when registering or repairing the Windows
Core Service. `repairInstallation()` now resolves only installed or explicit
service executables, canonicalizes the checked executable path before service
registration policy checks, and refuses to register a development checkout
executable as a Windows service. Runtime coverage proves a repository
`target\release\zentor_local_core.exe` is rejected before elevated PowerShell can
launch; source markers prove the installed-only resolver excludes
`_developmentExecutableCandidates(...)`. Verification passed with full
`local_core_ipc_diagnostics_test.dart` (`66`), focused service action tests
(`4`), Flutter analyzer, source-contracts (`512`), and the expanded
small-threat MVP verifier in `86.9s`. This hardens a visible repair control and
privilege boundary; it does not prove installed service/UI E2E, real installer
repair, signed-driver behavior, or pre-execution blocking.

Checkpoint 1937 records small-threat verifier repair-boundary coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes
`Flutter repair-installation boundary tests`, running the focused
`local_core_ipc_diagnostics_test.dart --plain-name "repair installation"` block
inside the one-command MVP sweep. The verifier scope now classifies the
repair-installation development-checkout boundary as verified and installed
service repair E2E as partial. Source-contracts assert the verifier step and
scope text. Focused parser check passed, focused repair boundary tests passed
(`2`), source-contracts passed (`512`), and the expanded small-threat MVP
verifier passed in `90.7s`. This is verifier coverage hardening only; it does
not prove installed service repair E2E, installed UI/service operation,
machine-wide service changes, signed-driver behavior, or pre-execution blocking.

Checkpoint 1938 records in-app update-service boundary hardening:
Flutter update verification, install, and rollback now require an installed-only
Avorax Update Service executable and refuse development checkout
`target\release\avorax_update_service.exe` candidates before elevated updater
work. Runtime rollback coverage proves a development updater is rejected in the
current checkout, and source-marker coverage proves destructive update operations
call the installed-only resolver with development candidates disabled.
`tools\testing\verify-small-threat-mvp.ps1` now includes `Flutter update-service
boundary tests` and classifies installed update/rollback E2E as partial. Full
`update_service_test.dart` passed (`112`), update controller/UI tests passed,
`flutter analyze` reported no issues, Python source-contracts passed (`512`),
and the expanded small-threat MVP verifier passed end-to-end in `94.1s`.
`git status --short` remains unavailable because this checkout has no `.git`
directory. This is update privilege-boundary hardening only; it does not prove
installed update/rollback E2E, signed package deployment on a release host,
driver behavior, pre-execution blocking, or live-malware handling.

Checkpoint 1939 records small-threat verifier Defender-noise reduction:
the default `tools\testing\verify-small-threat-mvp.ps1` run no longer creates
the standard EICAR file that Microsoft Defender reports as `DOS/EICAR_Test_File`.
Default verification uses Avorax's internal `ZENTOR-SAFE-EICAR-SIMULATOR-FILE`
runtime fixture for scan/quarantine proof, keeps Windows anti-malware
blocked-read mapping covered with a unit fixture, and makes the real standard
EICAR host integration path explicit via `-IncludeDefenderEicar`. The same
checkpoint adds `Flutter update controller/UI tests` to the one-command verifier
so update confirmation, busy-state guards, failure-honesty, and rollback controls
remain covered. Focused safe simulator and Windows anti-malware mapping tests
passed (`1` each), focused update controller/UI tests passed, source-contracts
passed (`512`), the Rust/security-only verifier path passed in `26.6s`, and the
full small-threat MVP verifier passed end-to-end in `107.3s` with the new opt-in
EICAR notice. `git status --short` remains unavailable because this checkout has
no `.git` directory. This keeps Avorax default detection proof while reducing
Defender alert noise; it does not prove installed update E2E, installed service
E2E, driver behavior, pre-execution blocking, or live-malware handling.

Checkpoint 1940 records protection start failure-honesty hardening:
Flutter `startProtection()` no longer reports `ProtectionStatus.partiallyProtected`
or persists `realtimeProtectionEnabled=true` when Guard mode configuration fails
and the user-mode watcher is also inactive. In that no-active-local-layer case,
the controller logs `protection_start_failed`, sets `ProtectionStatus.error`,
keeps the fresh-start preference disabled, and surfaces bounded Guard/watcher
diagnostics. The fake local-core test helper now supports ordered Guard mode
results so start-success/stop-failure flows remain precise, and the small-threat
MVP verifier now includes `Flutter protection start-stop controller tests`.
Focused `flutter test test\offline_scan_test.dart --plain-name "start
protection"` passed (`7`), focused `--plain-name "protection"` passed (`22`),
`flutter analyze` reported no issues, Python source-contracts passed (`512`),
and the full small-threat MVP verifier passed end-to-end in `112.5s`. `git
status --short` remains unavailable because this checkout has no `.git`
directory. This hardens visible protection-control honesty and regression
coverage only; it does not prove installed service/driver E2E, kernel blocking,
pre-execution blocking, or live-malware handling.

Checkpoint 1941 records ransomware guard settings verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes focused Flutter
ransomware guard controller, Settings UI, and config-validation tests. The
one-command MVP sweep proves confirmation/cancel behavior, overlapping
security-settings busy guards, local-core policy failure visibility, persisted
policy shape, and numeric/config bounds remain covered for the visible
ransomware guard controls. Focused controller tests passed (`4`), focused
Settings UI tests passed (`2`), focused config-validation tests passed (`3`),
Python source-contracts passed (`512`), and the expanded small-threat MVP
verifier passed end-to-end in `121.8s` with all steps green. `git status
--short` remains unavailable because this checkout has no `.git` directory.
This is verifier coverage hardening only; it does not prove packaged desktop
click-through E2E, installed service/driver E2E, kernel blocking, pre-execution
blocking, or live-malware handling.

Checkpoint 1942 records route and product-policy verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes focused Flutter
route/navigation matrix tests plus the product-policy/no-fake-control sweep.
The one-command MVP sweep now covers desktop/mobile route exposure, navigation
semantics, notification normalization, visible confirmation gates, dead-control
guards, honest scan/protection/update copy, categorized controller event-source
guards, and product claim boundaries. The product-policy source assertion for
scan completion details was refreshed to check
`_scanEventDetails(report, coverageWarning: scanErrorMessage)` and the helper's
`coverageWarning ?? report.message` fallback. Focused route/navigation tests
passed (`7`), focused product-policy tests passed (`58`), Python
source-contracts passed (`512`), and the expanded small-threat MVP verifier
passed end-to-end in `127.8s` with all steps green. `git status --short`
remains unavailable because this checkout has no `.git` directory. This is
source/widget verifier coverage hardening only; packaged desktop click-through
E2E, installed service/driver E2E, OS picker E2E, pre-execution blocking, and
live-malware handling remain partial or technically limited.

Checkpoint 1943 records startup, onboarding, privacy, and native-status
verifier coverage: `tools\testing\verify-small-threat-mvp.ps1` now includes a
focused Flutter startup/onboarding/native-status step. The one-command MVP sweep
proves startup avoids API-form/required-field regressions, Home security-events
navigation reaches Logs, onboarding completion persists setup and routes Home,
privacy route coverage remains present, and Settings native-engine status rows
render real app-state evidence instead of invented readiness. Focused Flutter
tests passed (`6`), Python source-contracts passed (`512`), and the expanded
small-threat MVP verifier passed end-to-end in `131.2s` with all steps green.
`git status --short` remains unavailable because this checkout has no `.git`
directory. This is source/widget verifier coverage hardening only; packaged
desktop click-through E2E, installed service/driver E2E, OS picker E2E,
pre-execution blocking, and live-malware handling remain partial or technically
limited.

Checkpoint 1944 records visible-surface and local helper/cloud-boundary verifier
coverage: `tools\testing\verify-small-threat-mvp.ps1` now includes focused
Flutter visible-surface guard tests for Allowlist, Device, Protected Apps, and
protection-status UI, plus focused helper/cloud-boundary tests for selected-file
hashing, app/process detection, platform-info collection, and optional cloud API
boundary handling. The one-command MVP sweep now proves these existing controls
and helpers remain covered alongside scan/quarantine/protection/update flows.
Focused visible-surface tests passed (`15`), focused helper/cloud-boundary tests
passed (`65`), Python source-contracts passed (`512`), and the expanded
small-threat MVP verifier passed end-to-end in `137.6s` with all steps green.
`git status --short` remains unavailable because this checkout has no `.git`
directory. This is source/widget/helper verifier coverage hardening only;
packaged desktop click-through E2E, installed service/driver E2E, live
backend/cloud E2E, OS picker E2E, pre-execution blocking, and live-malware
handling remain partial or technically limited.

Checkpoint 1945 records suspicious-process snapshot verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes local-core process
monitor snapshot regressions, local-core process snapshot IPC regressions,
Flutter process snapshot IPC tests, and Flutter process snapshot event tests.
The one-command MVP sweep now proves snapshot-only suspicious-process
observation stays bounded and honest, including exact allowlist handling, parent
traversal rejection, strict IPC schemas, protocol-warning visibility, health
capability/status labels, and local event evidence for evaluated/suspicious
process snapshots. Focused process-monitor tests passed (`5`), focused
process-snapshot IPC tests passed (`3`), focused Flutter process IPC tests
passed (`6`), focused Flutter process event tests passed (`1`), Python
source-contracts passed (`512`), and the expanded small-threat MVP verifier
passed end-to-end in `145.9s` with all steps green. `git status --short`
remains unavailable because this checkout has no `.git` directory. This is
snapshot-observation verifier coverage only; installed process observation loop
E2E, installed service/driver E2E, active polling-loop claims, pre-execution
blocking, and live-malware handling remain partial or technically limited.

Checkpoint 1946 records native detection-pipeline verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes focused native-engine
signature, rule, static/archive, script, family-indicator, false-positive, and
risk-fusion regressions. The one-command MVP sweep now proves native EICAR
signature detection, packaged signatures beyond EICAR, rule-pack loading, ZIP
traversal/archive analyzer evidence, large-file full-hash/sample-limit behavior,
encoded PowerShell rule verdicts, ransomware/infostealer family indicator
fusion, downloader verdict fusion, normal executable false-positive
suppression, and bounded risk-fusion explanation/action mapping. Focused
native-engine checks passed locally (`1` each except family indicator fusion
`2` and risk fusion `3`), Python source-contracts passed (`512`), and the
expanded small-threat MVP verifier passed end-to-end in `175.2s` with all steps
green. `git status --short` remains unavailable because this checkout has no
`.git` directory. This is offline native detection-pipeline verifier coverage;
production false-positive-rate evidence, live-malware validation, installed
service/driver E2E, and pre-execution blocking remain partial or technically
limited.

Checkpoint 1947 records file-walker verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes local-core
`file_walker` and native-engine `native_file_walker` regressions. The
one-command MVP sweep covers quick/full local walk behavior, non-following
metadata guards, non-regular skip/error reporting guards, metadata-error
honesty, and bounded/omitted local/native walk-error details. Focused local-core
file-walker tests passed (`7`), native file-walker tests passed (`3`), Python
source-contracts passed (`512`), and the expanded small-threat MVP verifier
passed end-to-end in `176.2s`. This is current-host scanner skip/error honesty
proof; platform-specific symlink/reparse E2E, installed service/UI E2E,
live-malware handling, and pre-execution blocking remain partial or technically
limited.

Checkpoint 1948 records native scan-root planner verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes native scan env-root
validation, quick-scan root planning, and full-scan root planning regressions.
The one-command MVP sweep covers relative/empty/parent-traversal env-root
rejection, checked env-root use, non-following quick-root presence checks,
quick-root inspection diagnostics, duplicate-free quick-root planning, and no
current-directory/dot fallback for native full scans. Focused native
`quick_scan_plan` passed (`3`), `full_scan_planner` passed (`1`), and
`native_scan_env_roots` passed (`3`), Python source-contracts passed (`512`),
and the expanded small-threat MVP verifier passed end-to-end in `177.8s`. This
is current-host native planner coverage only; symlink/reparse/permission fixture
E2E, installed scan-root E2E, live-malware handling, and pre-execution blocking
remain partial or technically limited.

Checkpoint 1949 records local ransomware guard runtime verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the local-core
`ransomware_guard` Cargo filter. The one-command MVP sweep covers benign
protected-root activity detection, traversal-outside-root rejection,
trusted-process suppression boundaries, trusted-process collapsed path
equivalence, persisted config strict schema/value validation,
directory/symlink/path-safety markers, staged writes, oversized config rejection
before parse, and metadata/actual-byte bounded config reads. Focused
`ransomware_guard` passed (`21`), Python source-contracts passed (`512`), and
the expanded small-threat MVP verifier passed end-to-end in `171.2s`. This is
local fixture coverage only; installed watcher/service E2E, live-ransomware
validation, kernel blocking, and pre-execution blocking remain partial,
disabled, or technically limited.

Checkpoint 1950 records local YARA/ClamAV compatibility verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes local-core `yara` and
`clamav` Cargo filters. The one-command MVP sweep covers local YARA embedded
fallback behavior, default rule-root safety, explicit metadata requirements,
malformed pattern rejection, non-following scan/rule paths, directory/oversized
rule rejection, bounded sample reads, metadata/actual-byte bounded rule reads,
confirmed-vs-review verdicts, normal-text false-positive guard, and
unreadable-target error reporting. It also covers local ClamAV compatibility
path discovery without ambient PATH lookup, configured scanner path validation,
bounded command output, bounded hash/sample reads, local EICAR signature
scanning, infected-exit detection naming, and fail-visible local signature
errors. Focused `yara` passed (`19`), `clamav` passed (`11`), Python
source-contracts passed (`512`), and the expanded small-threat MVP verifier
passed end-to-end in `172.1s`. This is optional compatibility/local-rule
fixture coverage only; primary scans still do not depend on ClamAV/YARA,
configured/bundled scanner E2E remains partial, and live-malware validation
remains disabled.

Checkpoint 1951 records local heuristic/static-feature verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes local-core `heuristic`
and `static_feature` Cargo filters. The one-command MVP sweep covers
conservative heuristic auto-action gating, bounded script/entropy heuristic
samples, non-following target inspection, filename/default branch-honesty
fixtures, bounded static-feature sample reads, directory/non-file rejection,
and static filename/extension/default branch-honesty fixtures. Focused
`heuristic` passed (`19`), `static_feature` passed (`7`), Python
source-contracts passed (`512`), and the expanded small-threat MVP verifier
passed end-to-end in `174s`. This is local fixture coverage only; production
false-positive-rate evidence, production ML activation, replacement-race and
platform-specific symlink/reparse fixtures, installed local-core/UI E2E, and
live-malware validation remain partial, blocked, or disabled.

Checkpoint 1952 records local app-control/trust-store verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes local-core
`app_control` and `trust_store` Cargo filters. The one-command MVP sweep covers
known-good, known-bad, user-approval, publisher-trust, script-subpolicy, exact
passthrough-root, strict schema, malformed-hash, bounded-read, and fail-closed
policy fixtures for the local app-control compatibility layer. Focused
`app_control` passed (`47`), `trust_store` passed (`10`), Python
source-contracts passed (`512`), and the expanded small-threat MVP verifier
passed end-to-end in `174.7s`. This is local fixture coverage only;
replacement-race/symlink fixtures, live Authenticode E2E, installed
local-core/UI/service E2E, signed-driver behavior, and pre-execution blocking
remain partial, blocked, or technically limited.

Checkpoint 1953 records native exact-hash trust-store verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes native-engine
`trust_store`, `known_good`, and `known_bad` Cargo filters. The one-command MVP
sweep covers native known-good/known-bad exact-hash trust-store strict schema,
malformed-hash rejection, oversized-store rejection, bounded actual-byte reads,
missing-store empty compatibility, and non-following presence markers. Focused
`trust_store` passed (`3`), `known_good` passed (`6`), `known_bad` passed
(`10`), Python source-contracts passed (`512`), and the expanded small-threat
MVP verifier passed end-to-end in `175s`. This is native fixture coverage only;
replacement-race and Unix-only symlink fixtures, installed native asset layout
E2E, live-malware validation, signed-driver behavior, and pre-execution
blocking remain partial, blocked, or technically limited.

Checkpoint 1954 records allowlist and feedback-store verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes local-core `allowlist`,
native-engine `allowlist`, and local-core `training_label` Cargo filters. The
one-command MVP sweep covers unsafe-root rejection, traversal-safe matching,
strict persisted schemas, bounded store/hash reads, staged writes, malformed
persisted hash rejection, native exact-hash/component-aware matching,
false-positive suppression/revocation, strict label/static-feature schemas,
and feedback store fail-closed behavior. Focused local-core `allowlist` passed
(`37`), native-engine `allowlist` passed (`6`), local-core `training_label`
passed (`21`), Python source-contracts passed (`512`), and the expanded
small-threat MVP verifier passed end-to-end in `175.8s`. This is fixture and
controller-level coverage only; replacement-race/symlink fixtures, installed
Scan/Allowlist UI click-layout E2E, live-malware validation, signed-driver
behavior, and pre-execution blocking remain partial, blocked, or technically
limited.

Checkpoint 1955 records local/native quarantine verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes local-core
`quarantine` and native-engine `quarantine_trust` Cargo filters. The
one-command MVP sweep covers local authenticated metadata visibility,
path/text/field validation, staged metadata/auth/key writes, payload/hash
integrity, restore/delete status ordering, cleanup/finalization behavior, and
native quarantine trust-root boundaries at the fixture layer. Focused
local-core `quarantine` passed (`88`), native-engine `quarantine_trust` passed
(`3`), Python source-contracts passed (`512`), and the expanded small-threat
MVP verifier passed end-to-end in `184.4s`. Safe EICAR/manual quarantine
restore/delete smokes also passed in the same run. This is fixture/controller
coverage only; installed local-core/service/UI E2E, platform-gated
ACL/reparse/race behavior, live-malware validation, signed-driver behavior,
pre-execution blocking, and secure-erase claims remain partial, blocked,
technically limited, or not claimed.

Checkpoint 1956 records Guard Service fixture verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes Guard Service
`guard_mode`, `known_bad`, `quarantine`, `driver_ipc`, `driver_health`,
`self_test`, `process_watch`, and `process_skip` Cargo filters. The
one-command MVP sweep covers Guard mode config strictness, known-bad cache
bounds, quarantine metadata/auth behavior, driver IPC fail-open/trust
boundaries, driver-health classification, self-test fixture bounds, process
observation error accounting, and process-skip normalization without claiming
pre-execution blocking. Focused Guard filters passed: `guard_mode` (`17`),
`known_bad` (`16`), `quarantine` (`32`), `driver_ipc` (`49`),
`driver_health` (`16`), `self_test` (`16`), `process_watch` (`1`), and
`process_skip` (`1`). Python source-contracts passed (`512`), and the
expanded small-threat MVP verifier passed end-to-end in `183.3s`. This is
Guard fixture coverage only; installed Guard Service operation, signed-driver
IPC, elevated service control, kernel blocking, pre-execution blocking, and
live-malware handling remain partial, blocked, disabled, or technically
limited.

Checkpoint 1957 records update-service signed package verifier coverage:
`core\avorax_update_service\src\update_verifier.rs` now has runtime fixtures for
a benign Ed25519-signed `.aup` manifest/payload pair, tampered manifest
signature rejection, and tampered payload-hash rejection. The one-command MVP
sweep now includes `update-service signed package/update regressions`, running
the full update-service crate so manifest schema, package archive/path/hash
bounds, update verifier policy, apply staging, rollback, service-control, and
CLI strictness stay in the MVP proof. Focused `update_verifier` passed (`12`),
the full update-service crate passed (`180`), rustfmt check passed, Python
source-contracts passed (`513`), and the expanded small-threat MVP verifier
passed end-to-end in `229.7s`. This is local benign fixture coverage only;
production signer ceremony, installed update-service operation, signed release
package staging, MSI integration, installed update/rollback E2E, live-malware
handling, and enterprise deployment approval remain partial, blocked, disabled,
or technically limited.

Checkpoint 1958 records false-positive gate verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes the
`False-positive gate`, running `tools\security\zentor-false-positive-gate.ps1`
with explicit `-RepoRoot` and `-CargoPath`. The gate checks the benign fixture
corpus and focused local-core/native-engine/Guard regressions for normal
installer-like files, Avorax installer/MSI suppression, setup.exe weak-signal
handling, internal-file heuristic suppression, unknown-app Lockdown/Balanced
label honesty, and native normal executable false-positive suppression. The
standalone gate passed, source-contracts passed (`513`), and the expanded
small-threat MVP verifier passed end-to-end in `189.8s`, including
`False-positive gate` (`7s`). This is benign fixture gate coverage only;
installed UI/service/driver E2E, release-host false-positive baselines, and
production false-positive-rate evidence remain partial or unverified.

Checkpoint 1959 records non-driver protection gate verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now writes
`.workflow\ultracode\avorax-hardening\results\small-threat-mvp-protection-selftest.json`
as a synthetic non-driver report and then runs
`tools\security\zentor-protection-gate.ps1` as
`Protection gate without driver feature claim`. The fixture marks driver
communication/running/pre-execution availability false and sets
`unknown_unsigned_lockdown_blocked_before_launch=false`; the verifier does not
pass `-DriverFeatureEnabled`. The no-Rust/no-Flutter verifier pass completed in
`14.6s`, the protection gate itself passed in `1.3s`, source-contracts passed
(`513`), and the full expanded small-threat MVP verifier passed end-to-end in
`197s`. This is policy/verdict gate wiring evidence only; installed Guard
Service operation, signed-driver IPC, kernel blocking, pre-execution blocking,
and production driver validation remain blocked or technically limited.

Checkpoint 1960 records branding gate verifier coverage:
`tools\testing\verify-small-threat-mvp.ps1` now includes `Branding gate`,
running `tools\branding\branding-check.ps1 -Root <repo>` before product-copy
and security gates. The standalone branding check passed, the no-Rust/no-Flutter
focused verifier pass completed in `15.5s`, `Branding gate` passed in `1.6s`,
source-contracts passed (`513`), and the full expanded small-threat MVP
verifier passed in `192.6s`. This keeps active source/doc product and
old gaming-branding drift in the repeatable small-threat MVP sweep; packaged
installer/assets and release-host branding validation remain partial.

Checkpoint 1961 records structured small-threat MVP verifier report evidence:
`tools\testing\verify-small-threat-mvp.ps1` now accepts `-ReportPath`, defaults
to `.workflow\ultracode\avorax-hardening\results\small-threat-mvp-verification-report.json`,
requires the resolved path to stay under the repository root, and writes the
JSON report through `Write-AvoraxGateJsonFileAtomic`. The report includes
schema version, `passed`/`failed` status, tool paths, options, generated report
paths, step commands/timings, verification scope, partial items, technical
limits, and bounded failure diagnostics. Focused verifier execution passed in
`15.7s`; the full expanded verifier passed in `191.9s`; JSON sanity confirmed
`status=passed`, `98` steps, no Rust/Flutter skips, and generated report links;
an out-of-repo `-ReportPath` was rejected; and source-contracts passed (`513`).
The report is evidence for the verifier run, not installed
service/UI/driver/release-host proof.

Checkpoint 1962 adds independent validation for the structured small-threat MVP
report: `tools\testing\validate-small-threat-mvp-report.ps1` resolves the report
path under the repository, reads it with `Read-AvoraxGateTextFileBounded`, checks
schema version, `passed`/`failed` status, ISO timestamps, option booleans, tool
path fields, generated report paths, passed-step evidence, verification scope,
and error semantics. With `-RequireFullSuite`, it additionally requires a passed
full-suite report with no Rust/Flutter skips, at least `80` steps, the expected
first/last steps, and the branding/false-positive/protection/performance/
dependency gates. Runtime validation passed against the full `1961` report
(`98` steps), and negative fixtures rejected `passed` with no steps, `failed`
with no error, and an out-of-repo report path. This validates evidence shape
only; it does not add installed service/UI/driver/release-host proof.

Checkpoint 1963 wires that validator into the one-command small-threat MVP
verifier. After `verify-small-threat-mvp.ps1` writes a success report, it runs
`validate-small-threat-mvp-report.ps1` against the same report path. Full
non-Defender/non-skip verifier runs use `-RequireFullSuite`; fast skip runs and
optional Defender/EICAR runs use structural validation so they are not mistaken
for full-suite release evidence. Runtime verification passed: the focused skip
verifier completed in `15.9s`, the full verifier completed in `192.8s` with
`98` steps, and the post-write full-suite validator passed in `0.5s`. A
malformed success report now turns the run into a visible verifier failure
through the existing failure-report path.

Checkpoint 1964 tightens the safe allowlist smoke evidence path. The smoke
test already verifies that a safe simulator can be allowlisted without being
auto-quarantined; its final quarantine-payload check now uses
`Get-ChildItem -ErrorAction Stop` instead of `SilentlyContinue`, so a traversal
or permission failure in the quarantine root is visible. Runtime verification
passed the allowlist smoke with `Threat status: allowlisted` and
`Quarantined files: 0`; source-contracts passed (`514`); and the targeted
PowerShell tool/script scan found no remaining `SilentlyContinue` matches.

Checkpoint 1965 tightens process snapshot IPC evidence. A request for
`evaluate_process_snapshot` now requires the caller to include
`process_observations`; omitting the field returns `ok=false` with a bounded
error instead of fabricating an empty successful snapshot. Explicitly empty
observation arrays remain valid evidence that the caller collected no processes.
The focused local-core `process_snapshot` filter passed (`4`), and the full
small-threat MVP verifier passed in `196.4s` with report validation. This keeps
the snapshot-only limitation honest and does not claim an installed polling
loop.

Checkpoint 1966 strengthens Windows process snapshot collection for the Flutter
client. The active Windows AppDetector path now launches checked local
`WindowsPowerShell\v1.0\powershell.exe` with an encoded `Get-CimInstance
Win32_Process -ErrorAction Stop` script, does not use an app-detector
execution-policy override, parses compressed JSON, and preserves `pid`,
`parent_pid`, `image_path`, and optional `command_line` evidence in
`ProcessObservation`. The previous `tasklist.exe` CSV path is no longer the
active client implementation. Focused app-detector tests passed (`10`), Flutter
analyzer passed, source-contracts passed (`514`), and the full small-threat MVP
verifier passed in `194.7s` with report validation. This improves snapshot
evidence for suspicious-process rules but still does not claim an installed
polling loop, signed-driver IPC, or pre-execution process blocking.

Checkpoint 1967 adds an app-lifetime best-effort process snapshot loop in the
Flutter controller. After protection starts successfully, the controller
schedules a two-minute injectable timer, avoids an immediate host process read,
uses a single-flight guard, submits bounded observations to Local Core, logs
empty/evaluated/suspicious/failed process snapshot events, and cancels the loop
on protection stop or controller disposal. Focused protection tests passed
(`26`), app visual policy tests passed (`58`), process snapshot event/IPC tests
passed (`1`/`6`), analyzer passed, source-contracts passed (`514`), and the full
small-threat MVP verifier passed in `187s` with report validation. This is
app-lifetime user-mode observation only; installed service/driver observation,
kernel enforcement, and pre-execution process blocking remain unclaimed.

Checkpoint 1968 bounds routine event-history churn from that app-lifetime
process snapshot loop. The controller now deduplicates identical routine
`process_snapshot_loop_empty` and `process_snapshot_loop_evaluated` info events
while still running every timer evaluation and still recording suspicious,
failed, and busy outcomes. The dedupe key resets on protection loop start/stop
and warning outcomes so recovery remains visible. Focused protection tests
passed (`27`), app visual policy tests passed (`58`), process snapshot event
tests passed (`1`), analyzer passed, source-contracts passed (`514`), and the
full small-threat MVP verifier passed in `187.8s` with report validation. This
improves bounded local event history only; it does not add installed
service/driver process observation or pre-execution blocking.

Checkpoint 1969 makes app-lifetime process snapshot loop start failures visible
in the Flutter state as well as in local events. If the injected process snapshot
timer cannot be created, `startProtection` still records
`protection_start_limited` and now also includes the bounded
`Process observation loop did not start` diagnostic in `state.errorMessage`.
Focused protection tests passed (`28`), app visual policy tests passed (`58`),
analyzer passed, source-contracts passed (`514`), and the full small-threat MVP
verifier passed in `189.5s` with report validation. This improves failure
visibility only; it does not add an installed service/driver process observer or
pre-execution blocking.

Checkpoint 1970 makes the app-lifetime process snapshot loop visible as current
state instead of event-history-only evidence. `ZentorState` now tracks
`processSnapshotLoopStatus` and `processSnapshotLoopStatusReason`, start
protection records `active` or `limited`, timer ticks record `active` or
`attention`, failures/busy outcomes record `limited`, stop records `off`, and
the Protection `Process monitors` detail shows the loop label plus bounded
diagnostics. Focused protection tests passed (`28`), app visual policy tests
passed (`58`), analyzer passed, source-contracts passed (`514`), and the full
small-threat MVP verifier passed in `189.9s` with report validation. This
improves app-lifetime loop status visibility only; installed service/driver
process observation and pre-execution blocking remain blocked.

Checkpoint 1971 aligns the small-threat MVP verifier scope with that state/UI
proof. `tools/testing/verify-small-threat-mvp.ps1` now includes
`state/UI visibility` in the verified app-lifetime process snapshot loop scope,
and `tests/test_custom_driver_contract.py` guards that wording. Source-contracts
passed (`514`), the focused no-Rust/no-Flutter verifier passed in `15.9s` with
report validation, and the full verifier passed in `188.7s` with `98` steps plus
full-suite report validation. This improves report evidence wording only; it
does not add installed service/driver process observation or pre-execution
blocking.

Checkpoint 1972 extends Protected Apps process snapshot evidence to the
active-protection loop event types. The panel now accepts
`process_snapshot_loop_evaluated`, `process_snapshot_loop_suspicious`,
`process_snapshot_loop_empty`, and `process_snapshot_loop_failed`, labels them
with the same bounded evaluated/suspicious/empty/failed vocabulary, and updates
empty-state copy to mention app detection or active protection. Focused
Protected Apps widget tests passed (`9`) including rendered loop-suspicious
details, app visual policy tests passed (`58`), analyzer passed,
source-contracts passed (`514`), and the full verifier passed in `189.4s` with
`98` steps plus report validation. This improves visible user-mode process
evidence only; it does not add installed service/driver process observation or
pre-execution blocking.

Checkpoint 1973 makes the Protected Apps latest process evidence selection
timestamp-driven. `_latestProcessSnapshotEvent` now scans every app-detection and
active-protection snapshot event and chooses the event with the newest
`createdAt`, so stale evidence cannot win merely because a repository/import/test
list is not newest-first. Focused Protected Apps widget tests passed (`10`),
including an out-of-order older app-detection/newer active-protection fixture;
app visual policy tests passed (`58`), analyzer passed, source-contracts passed
(`514`), and the full verifier passed in `191.2s` with `98` steps plus report
validation. This improves evidence ordering only; it does not add installed
service/driver process observation or pre-execution blocking.

Checkpoint 1974 surfaces process evidence recency on Protected Apps. When a
snapshot or app-lifetime loop event is shown, the panel now includes
`Evidence time (UTC): <timestamp>` using the selected event's `createdAt`, and
the newest-event widget regression verifies the newer loop-failure timestamp is
visible. Focused Protected Apps widget tests passed (`10`), app visual policy
tests passed (`58`), analyzer passed, source-contracts passed (`514`), and the
full verifier passed in `192.1s` with `98` steps plus report validation. This
improves recency visibility only; it does not add installed service/driver
process observation or pre-execution blocking.

Checkpoint 1975 aligns generated verifier scope with the Protected Apps process
evidence proof from checkpoints 1973-1974. The small-threat MVP report now
explicitly lists `Protected Apps process-evidence newest ordering plus UTC
timestamp visibility`, and a Python source-contract assertion guards that
wording. Source-contracts passed (`514`), the focused no-Rust/no-Flutter
verifier passed in `15.5s`, and the full verifier passed in `191.6s` with `98`
steps plus report validation. This improves report honesty only; it does not add
installed service/driver process observation or pre-execution blocking.

Checkpoint 1976 makes the full-suite report validator enforce that same
Protected Apps process-evidence scope. `validate-small-threat-mvp-report.ps1`
now rejects `-RequireFullSuite` reports whose `verification_scope.verified` text
does not include `Protected Apps process-evidence newest ordering plus UTC
timestamp visibility`. Runtime validation passed for the existing full report,
a temporary negative report with that phrase removed failed with the expected
scope diagnostic, source-contracts passed (`514`), and the full verifier passed
in `191.7s` with `98` steps plus report validation. This improves verifier
evidence integrity only; it does not add installed service/driver process
observation or pre-execution blocking.

Checkpoint 1977 makes app-lifetime scheduled quick scans respect active custom
target selection before claiming a start. `_runScheduledQuickScan` now uses a
busy-reason helper, logs `scheduled_quick_scan_skipped` with `Scan target
selection is already in progress.`, makes no Local Core scan call, and does not
emit `scheduled_quick_scan_started` while target selection is active. Home,
Scan, and Protection scan shortcuts treat target selection as scan-busy, and
`setScanActionMode` rejects mode changes during target selection with scan
warning evidence. Runtime verification passed for the focused Flutter
regressions, the scheduled quick-scan subset (`8`), Scan screen tests (`38`),
app visual policy tests (`58`), analyzer, source-contracts (`514`), a negative
missing-scope report-validator fixture, and the full self-validating
small-threat MVP verifier (`98` steps in `191.2s`). This is app-lifetime
Flutter controller/UI proof only; it does not add Windows Scheduled Task or
background-service scheduling, installed desktop click-through E2E, installed
service behavior, or pre-execution blocking.

Checkpoint 1978 closes the remaining direct Flutter controller target-selection
race for scan starts. `runQuickScan`, `runFullScan`, and
`rescanQuarantineOriginal` now check target-selection state before scan mode
confirmation, target planning, rescan audit events, or Local Core scan IPC.
When blocked, they log `scan_start_ignored` as a scan warning, set the visible
error `Scan target selection is already in progress.`, and leave Local Core
scan call counts at zero. The client UI inventory now also accounts for the
Quarantine `Scan original path` control. Runtime verification passed for the
focused scan-concurrency tests (`2`), source-marker test (`1`), broader
offline scan subset (`34`), quarantine subset (`21`), Flutter analyzer,
source-contracts (`514`), a negative report-validator fixture missing
`scan concurrency target-selection controller guards`, and the full
self-validating small-threat MVP verifier (`99` steps in `193.8s`). This is
Flutter controller/runtime proof only; it does not add installed desktop
click-through E2E, installed local-core/service behavior, signed-driver or
pre-execution blocking proof, or production false-positive-rate evidence.

Checkpoint 1979 blocks Custom File/Folder target selection before OS picker
handoff while a scan is starting or running. `_beginScanTargetSelection` now
uses `_scanTargetSelectionBusyReason()` so active target selection, scan-start
in-flight, and running scans all reject with `scan_target_selection_busy`
warning evidence before `openFile()` or `getDirectoryPath()` can run. Runtime
verification passed for the focused scan-concurrency tests (`4`), custom
target-selection source-marker test (`1`), broader offline scan subset (`37`),
Flutter analyzer, source-contracts (`514`), a negative report-validator fixture
missing `custom-picker scan-busy controller guards`, and the full
self-validating small-threat MVP verifier (`99` steps in `207.2s`). This is
Flutter controller/runtime proof only; it does not add installed OS picker
click-through E2E, installed local-core/service behavior, signed-driver or
pre-execution blocking proof, or production false-positive-rate evidence.

## Checkpoint 2131 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Source-level dependency/license evidence gate | `tools/security/avorax-dependency-evidence.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `docs/dependency-license-inventory.md`; `tests/test_custom_driver_contract.py` | Verify required lockfiles, exact Python pins, pinned Gradle wrapper hash, source-level lockfile package/integrity counts, and documented license-inventory metadata without installing dependencies, using ambient package managers, or claiming release-host SBOM completeness | Source-level dependency/license evidence verified; complete release-host SBOM/license output from final artifacts remains partial/required | Checkpoint 2131 adds `lockfile_summaries` and `license_inventory` to dependency evidence reports. The validator recomputes Cargo/pub/Python package and checksum/SHA/exact-pin counts from current lockfiles and rejects full-suite reports missing the license-inventory schema. Parser checks, dependency evidence generation, source-contracts (`567`), stricter full-suite validation of `.workflow\ultracode\avorax-hardening\results\2130-small-threat-mvp-ransomware-guard-activity-report.json`, and negative validation for missing `license_inventory` passed. This is source-level evidence only; it does not generate a complete CycloneDX/SPDX SBOM, install packages, query live registries, inspect final signed installer artifacts, or replace release-host license review. |

## Checkpoint 2130 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Release local-core ransomware guard config/activity smoke | `core/zentor_local_core/src/api/mod.rs`; `core/zentor_local_core/src/main.rs`; `core/zentor_local_core/src/protection/ransomware_guard.rs`; `tools/testing/run-release-local-core-ransomware-guard-config-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` can evaluate bounded, caller-supplied ransomware activity observations against persisted protected-root and trusted-process policy, explain protected activity signals, ignore outside-root activity, suppress trusted non-critical activity, preserve critical ransom-note/backup-tamper override behavior, and reject malformed or unbounded IPC without claiming a persistent monitor or pre-execution blocker | Release-binary caller-supplied activity fixture verified; installed UI/service E2E, real filesystem change collection, response/blocking policy for live endpoint ransomware behavior, signed-driver pre-execution behavior, and production false-positive policy remain partial or blocked | Checkpoint 2130 expands `run-release-local-core-ransomware-guard-config-smoke.ps1` and renames the full-suite step to `release local-core binary ransomware guard config/activity smoke`. Local Core now exposes strict `evaluate_ransomware_activity` IPC with denied unknown fields, required activity payloads, path-text validation, score/range checks, modified-path entry limits, renamed-file and time-window bounds, persisted config loading, and explicit limitations: `caller-supplied-activity-observations-only`, `post-write-detection-only`, `no-persistent-service-monitor`, and `no-kernel-pre-execution-blocking`. Focused `ransomware_activity` tests (`3`), focused `ransomware_guard` tests (`21`), release smoke, negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`203` steps in `978.1s`) for `.workflow\ultracode\avorax-hardening\results\2130-small-threat-mvp-ransomware-guard-activity-report.json`, including the config/activity release smoke (`2.3s`). This is safe release-binary runtime policy evaluation for benign caller-supplied observations only; it does not simulate encryption, monitor/block real filesystem writes, install/start a Windows service, run a persistent watcher, weaken Defender, use live malware, prove installed UI/service E2E, or claim pre-execution blocking. |

## Checkpoint 2129 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Release local-core ransomware guard config smoke | `core/zentor_local_core/src/protection/ransomware_guard.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/run-release-local-core-ransomware-guard-config-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` can list default ransomware-guard config, persist validated protected roots and trusted-process allowlists through isolated config state, preserve the last good config when unsafe roots are rejected, and fail visibly for invalid or schema-unknown persisted configuration | Release-binary configuration fixture verified; installed UI/service E2E, real filesystem monitoring/blocking, signed-driver pre-execution behavior, and production false-positive policy remain partial or blocked | Checkpoint 2129 adds `run-release-local-core-ransomware-guard-config-smoke.ps1`. The smoke runs the built `target/release/zentor_local_core.exe` directly through JSON IPC with isolated data, legacy-data, and `AVORAX_RANSOMWARE_GUARD_CONFIG` roots; verifies default empty `list_ransomware_guard_config`, `configure_ransomware_guard` trimming/deduplication, trusted-process allowlist cleanup, staged-write cleanup with no leftover `*.tmp-*` files, `source=avorax_local_core`, round-trip listing, broad `C:/` protected-root rejection without overwriting the last good config, fail-visible invalid persisted paths, and strict rejection of an unknown persisted `enabled` field. Parser checks, focused local-core `ransomware_guard` tests (`21`), release build, focused release smoke, source-contracts (`567`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`203` steps in `627.6s`) for `.workflow\ultracode\avorax-hardening\results\2129-small-threat-mvp-release-ransomware-guard-config-report.json`, including the new release ransomware-guard config smoke (`1s`). This is safe release-binary configuration evidence only; it does not simulate encryption, monitor or block real filesystem writes, install/start a Windows service, run a persistent watcher, weaken Defender, use live malware, prove installed UI/service E2E, or claim pre-execution blocking. |

## Checkpoint 2128 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Release local-core process snapshot observation smoke | `core/zentor_local_core/src/protection/process_monitor.rs`; `core/zentor_local_core/src/api/mod.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/run-release-local-core-process-snapshot-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` evaluates bounded, caller-supplied process observations as snapshot-only review evidence, explains suspicious script-host and unsigned user-writable remote-transfer indicators, honors exact allowlists, accounts for skipped malformed/over-limit observations, and rejects malformed IPC without claiming an active service loop or pre-execution blocking | Release-binary mocked snapshot fixture verified; installed process-observation service/driver loop, real OS process inventory collection, response policy for live endpoint processes, and signed-driver pre-execution blocking remain partial or blocked | Checkpoint 2128 adds `run-release-local-core-process-snapshot-smoke.ps1`. The smoke runs the built `target/release/zentor_local_core.exe` directly through JSON IPC with isolated data and legacy-data roots; sends only inert mocked process observations; verifies `notActive`/`userModeSnapshot` snapshot-only status, `263` observed processes, `8` skipped malformed/over-limit observations, two `suspiciousProcess` findings with encoded/hidden script-host and unsigned user-writable remote-transfer reasons, exact normalized allowlist suppression to zero findings, a visible missing-`process_observations` JSON error, and non-zero failure for an unknown nested `auto_quarantine` field. Parser checks, focused local-core `process_snapshot` tests (`4`), release build, focused release smoke, source-contracts (`566`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`202` steps in `781.8s`) for `.workflow\ultracode\avorax-hardening\results\2128-small-threat-mvp-release-process-snapshot-report.json`, including the new release process snapshot smoke (`1s`). This is safe mocked release-binary snapshot evidence only; it does not enumerate real host processes, start/stop/kill/block processes, install/start a Windows service, run a persistent polling loop, weaken Defender, use live malware, prove installed UI/service E2E, or claim pre-execution blocking. |

## Checkpoint 2062 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Release local-core Full Scan PE-carrier smoke | `tools/testing/run-release-local-core-full-scan-pe-carrier-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs Full Scan traversal, signature verdict reporting, and confirmed-only quarantine for benign `.dll`, `.sys`, `.scr`, and `.bin` carrier fixtures without using installed services or machine-wide state | Release-binary fixture verified; installed UI/service E2E partial; real PE loader behavior, production false-positive measurement, and pre-execution blocking remain limited | Checkpoint 2098 adds `run-release-local-core-full-scan-pe-carrier-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a temporary self-hashed exact-hash signature pack for harmless `zentor-safe-release-fullscan-fixture` bytes; creates `.dll`, `.sys`, `.scr`, `.bin`, and benign `.txt` fixtures; invokes JSON `full_scan` with `scan_kind=full` and `AutoQuarantineConfirmedOnly`; then verifies `5` scanned files, `4` signature threats, `4` quarantines, `.avoraxq` payloads, quarantine records, removal of only matching carrier sources, and preservation of the benign file. The full verifier and report validator now require `release local-core binary full-scan PE carrier safe hash fixture smoke`, and the old 2097 report fails validation because it lacks that step. Focused release build/smoke passed, source-contracts passed (`542`), and the full small-threat MVP verifier/report-validator passed (`174` steps in `511.1s`) for `.workflow\ultracode\avorax-hardening\results\2098-small-threat-mvp-full-report.json`. This is safe release-binary scan/quarantine evidence only; it does not execute DLLs, load drivers, run screensavers, execute payloads, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan CPL/MSU smoke | `tools/testing/run-release-local-core-quick-scan-cpl-msu-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal, signature verdict reporting, and confirmed-only quarantine for benign `.cpl` and `.msu` carrier fixtures without using installed services or machine-wide state | Release-binary fixture verified; installed UI/service E2E partial; real CPL/MSU runtime behavior, production false-positive measurement, and pre-execution blocking remain limited | Checkpoint 2099 adds `run-release-local-core-quick-scan-cpl-msu-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a temporary self-hashed exact-hash signature pack for harmless `zentor-safe-release-quickscan-cpl-msu-fixture` bytes; creates `.cpl`, `.msu`, and benign `.txt` fixtures under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `2` scanned files, `2` signature threats, `2` quarantines, `.avoraxq` payloads, quarantine records, removal of only matching carrier sources, and preservation of the benign file. The full verifier and report validator now require `release local-core binary quick-scan CPL/MSU safe hash fixture smoke`, and the old 2098 report fails validation because it lacks that step. Focused release build/smoke passed, source-contracts passed (`543`), and the full small-threat MVP verifier/report-validator passed (`175` steps in `495.7s`) for `.workflow\ultracode\avorax-hardening\results\2099-small-threat-mvp-full-report.json`. This is safe release-binary Quick Scan/quarantine evidence only; it does not open Control Panel applets, invoke `control.exe`/`rundll32`, invoke `wusa`, DISM, Windows Update, or installers, extract MSU/CAB payloads, install packages, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan script carrier review smoke | `tools/testing/run-release-local-core-quick-scan-script-carrier-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal and reports benign `.ps1`, `.jse`, `.cmd`, `.vbs`, `.hta`, and `.wsf` script-carrier markers as review-only heuristic findings without executing scripts or quarantining them in confirmed-only mode | Release-binary fixture verified; installed UI/service E2E partial; broader benign script false-positive rates, script-host runtime behavior, and pre-execution blocking remain limited | Checkpoint 2109 adds `run-release-local-core-quick-scan-script-carrier-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates isolated engine subdirectories without signature/rule packs; writes benign inert script-carrier fixtures with static encoded-script and/or download-execute markers under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `6` scanned script carriers, `6` review-only heuristic findings with `encoded_script_command` and/or `download_execute_script` evidence, zero scan errors, zero quarantined files, empty quarantine records, source-carrier preservation, and benign-file preservation. The full verifier and report validator now require `release local-core binary quick-scan script carrier review smoke`, and the old 2108 report fails validation because it lacks that step. Focused smoke, PowerShell parser checks, and source-contracts passed (`554`), and the full small-threat MVP verifier/report-validator passed (`185` steps in `475.9s`) for `.workflow\ultracode\avorax-hardening\results\2109-small-threat-mvp-full-report.json`. This is safe release-binary script-carrier review evidence only; it does not execute PowerShell, JavaScript, CMD/BAT, VBS/VBE, HTA, WSF, WSH, Node, browsers, or any script host, resolve or download URLs, auto-quarantine review-only findings in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan family script review smoke | `tools/testing/run-release-local-core-quick-scan-family-script-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` loads the bundled native assets through normal repo-root discovery and reports benign ransomware/infostealer/miner/persistence script family markers as review-only findings without executing scripts or quarantining them in confirmed-only mode | Release-binary fixture verified; installed UI/service E2E partial; broader benign family-script false-positive rates, script-host/runtime behavior, production response policy, and pre-execution blocking remain limited | Checkpoint 2110 adds `run-release-local-core-quick-scan-family-script-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, and allowlist roots; sets `AVORAX_ENGINE_DIR` to the repo root so the release binary loads bundled `assets/zentor_native` `signatures`, `rules`, `ml`, and `trust` assets; writes a valid empty allowlist JSON array; writes benign inert `.ps1`/`.js` family-script fixtures under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `4` scanned family-script carriers, `4` review-only findings with categories `ransomware`, `infostealer`, `miner`, and `persistenceIndicator`, bundled rule evidence `ZNE-RULE-RANSOM-BACKUP-DELETE-NOTE`, `ZNE-RULE-INFOSTEALER-CREDS-ARCHIVE-NETWORK`, `ZNE-RULE-MINER-POOL-PERSISTENCE`, and `ZNE-RULE-PERSISTENCE-RUNKEY-SCRIPT`, zero scan errors, zero quarantined files, empty quarantine records, source-carrier preservation, and benign-file preservation. The full verifier and report validator now require `release local-core binary quick-scan family script review smoke`, and the old 2109 report fails validation because it lacks that step. Focused smoke, PowerShell parser checks, and source-contracts passed (`555`), and the full small-threat MVP verifier/report-validator passed (`186` steps in `844.6s`) for `.workflow\ultracode\avorax-hardening\results\2110-small-threat-mvp-full-report.json`. This is safe release-binary family-script review evidence only; it does not execute PowerShell, JavaScript, CMD/BAT, WSH, service-control commands, scheduled tasks, miners, credential tooling, browsers, or any script host, inspect real credentials or wallets, delete backups, resolve or download URLs, auto-quarantine review-only findings in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan AppInstaller carrier review smoke | `tools/testing/run-release-local-core-quick-scan-appinstaller-carrier-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal and reports a benign `.appinstaller` manifest with a remote `.msixbundle` package URL as a review-only heuristic finding without invoking App Installer, downloading the package, or quarantining it in confirmed-only mode | Release-binary fixture verified; installed UI/service E2E partial; live App Installer handler behavior, package trust prompts/capabilities, remote reputation, and pre-execution blocking remain limited | Checkpoint 2123 adds `run-release-local-core-quick-scan-appinstaller-carrier-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates benign inert `support.appinstaller` with `https://example.invalid/packages/support.msixbundle` and benign `docs.appinstaller` with a non-package document link under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `2` scanned fixtures, one review-only `SuspiciousDownloader` heuristic finding with `windows_appinstaller_remote_package_launch` evidence, no finding for `docs.appinstaller`, zero scan errors, zero quarantined files, empty quarantine records, and source-fixture preservation. The full verifier and report validator now require `release local-core binary quick-scan AppInstaller carrier review smoke`; the negative 2123 report without that step fails validation. Parser checks, focused release build/smoke, and source-contracts passed (`561`), and the full small-threat MVP verifier/report-validator passed (`197` steps in `624.3s`) for `.workflow\ultracode\avorax-hardening\results\2123-small-threat-mvp-release-appinstaller-report.json`. This is safe release-binary static AppInstaller manifest review evidence only; it does not invoke App Installer, install/register APPX/MSIX packages, resolve or download URLs, evaluate package trust prompts/capabilities as execution proof, auto-quarantine review-only findings in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan launch/installer carrier review smoke | `tools/testing/run-release-local-core-quick-scan-launch-installer-carrier-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal and reports benign ClickOnce, Java Web Start/JNLP, Windows scriptlet/SCT/WSC, and Windows Installer custom-action carriers as review-only heuristic findings without invoking handlers, downloading payloads, or quarantining them in confirmed-only mode | Release-binary fixture verified; installed UI/service E2E partial; live ClickOnce/JNLP/scriptlet/MSI/MSP handler behavior, trust prompts, remote reputation, and pre-execution blocking remain limited | Checkpoint 2124 adds `run-release-local-core-quick-scan-launch-installer-carrier-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates inert benign `support.application`, `support.appref-ms`, `support.jnlp`, `loader.sct`, `component.wsc`, `support-installer.msi`, and `support-patch.msp` carrier fixtures plus a benign text note under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `7` scanned carrier fixtures, `7` review-only `SuspiciousDownloader` heuristic findings with `clickonce_remote_deployment_launch`, `java_web_start_remote_archive_launch`, `windows_scriptlet_remote_script_launch`, and `windows_installer_custom_action_remote_launch` evidence, zero scan errors, zero quarantined files, empty quarantine records, and source-fixture preservation. The full verifier and report validator now require `release local-core binary quick-scan launch/installer carrier review smoke`; the negative 2124 report without that step fails validation. Parser checks, focused release build/smoke, and source-contracts passed (`562`), and the full small-threat MVP verifier/report-validator passed (`198` steps in `677.9s`) for `.workflow\ultracode\avorax-hardening\results\2124-small-threat-mvp-release-launch-installer-report.json`. This is safe release-binary static carrier review evidence only; it does not launch ClickOnce, Java Web Start, WSH/scriptlet handlers, Windows Installer, or App Installer, install/register applications/packages/COM components, resolve or download URLs, auto-quarantine review-only findings in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan document/web carrier review smoke | `tools/testing/run-release-local-core-quick-scan-document-web-carrier-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal and reports benign autorun INF, EML attachment, Office query/macro, OOXML macro relationship, RTF/PDF active-content, HTML/SVG web-document, CHM/OneNote, and Office add-in carriers as review-only heuristic findings without opening applications, invoking handlers, downloading payloads, or quarantining them in confirmed-only mode | Release-binary fixture verified; installed UI/service E2E partial; live document/application handler behavior, parser semantic completeness, remote reputation, and pre-execution blocking remain limited | Checkpoint 2125 adds `run-release-local-core-quick-scan-document-web-carrier-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates `22` inert benign carrier fixtures plus a benign note under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `22` scanned carriers, `22` review-only heuristic findings with `autorun_inf_executable_launch`, `email_executable_attachment`, `office_query_remote_script_launch`, `office_macro_auto_run_remote_launch`, `ooxml_macro_external_remote_relationship`, `rtf_external_object_remote_launch`, `pdf_active_content_remote_launch`, `web_document_active_content_remote_launch`, `help_note_remote_script_launch`, and `office_addin_remote_script_launch` evidence, zero scan errors, zero quarantined files, empty quarantine records, and source-fixture preservation. The full verifier and report validator now require `release local-core binary quick-scan document/web carrier review smoke`; the negative 2125 report without that step fails validation. Parser checks, focused release build/smoke, and source-contracts passed (`563`), and the full small-threat MVP verifier/report-validator passed (`199` steps in `658s`) for `.workflow\ultracode\avorax-hardening\results\2125-small-threat-mvp-release-document-web-report.json`. This is safe release-binary static carrier review evidence only; it does not open Office/PDF/HTML/CHM/OneNote content in an application, execute macros/scripts, invoke URL/file handlers, resolve or download URLs, auto-quarantine review-only findings in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan persistence/shortcut carrier review smoke | `tools/testing/run-release-local-core-quick-scan-persistence-shortcut-carrier-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal and reports benign registry autorun, URL/LNK shortcut, UNC shortcut, and disk-image autorun carriers as review-only heuristic findings without importing registry files, invoking handlers, mounting images, downloading payloads, or quarantining them in confirmed-only mode | Release-binary fixture verified; installed UI/service E2E partial; live registry import/URL/LNK/disk-image handler behavior, shortcut/ISO semantic completeness, remote reputation, and pre-execution blocking remain limited | Checkpoint 2126 adds `run-release-local-core-quick-scan-persistence-shortcut-carrier-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates inert benign `autorun.reg`, `support.url`, UTF-16LE `support-link.lnk`, UTF-16LE `support-share.lnk`, `support-media.iso`, plus a benign note under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `5` scanned carrier fixtures, `5` review-only heuristic findings with `registry_autorun_remote_launch`, `shortcut_remote_executable_launch`, and `disk_image_autorun_executable` evidence, zero scan errors, zero quarantined files, empty quarantine records, and source-fixture preservation. The full verifier and report validator now require `release local-core binary quick-scan persistence/shortcut carrier review smoke`; the negative 2126 report without that step fails full-suite validation. Parser checks, focused release build/smoke, and source-contracts passed (`564`), and the full small-threat MVP verifier/report-validator passed (`200` steps in `659.1s`) for `.workflow\ultracode\avorax-hardening\results\2126-small-threat-mvp-release-persistence-shortcut-report.json`. This is safe release-binary static carrier review evidence only; it does not import registry files, invoke URL/file handlers, resolve shortcut targets, mount disk images, execute autorun commands, resolve or download URLs, auto-quarantine review-only findings in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan ZIP carrier review smoke | `tools/testing/run-release-local-core-quick-scan-zip-carrier-review-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal and reports benign ZIP nested executable, deceptive nested executable, autorun bundle, autorun.inf command, and shortcut executable bundle carriers as review-only heuristic findings without extracting archives, executing entries, invoking handlers, or quarantining them in confirmed-only mode | Release-binary fixture verified; installed UI/service E2E partial; live archive handler behavior, broader archive parser semantic completeness, encrypted/unsupported archive edge rates beyond existing fail-visible checks, remote reputation, and pre-execution blocking remain limited | Checkpoint 2127 adds `run-release-local-core-quick-scan-zip-carrier-review-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates inert benign `invoice-archive.zip`, `documents-archive.zip`, `media-autoplay.zip`, `launcher-autoplay.zip`, and `shortcut-bundle.zip` fixtures plus a benign note under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `5` scanned ZIP carrier fixtures, `5` review-only heuristic findings with `archive_suspicious_executable`, `archive_autorun_executable_bundle`, `archive_autorun_inf_executable_command`, and `archive_shortcut_executable_bundle` evidence, zero scan errors, zero quarantined files, empty quarantine records, and source-fixture preservation. The full verifier and report validator now require `release local-core binary quick-scan ZIP carrier review smoke`; the negative 2127 report without that step fails full-suite validation. Parser checks, focused release build/smoke, focused local-core ZIP carrier tests, and source-contracts passed (`565`), and the full small-threat MVP verifier/report-validator passed (`201` steps in `648.8s`) for `.workflow\ultracode\avorax-hardening\results\2127-small-threat-mvp-release-zip-carrier-report.json`. This is safe release-binary static ZIP carrier review evidence only; it does not extract archive contents to disk, execute archive entries, invoke shell/archive handlers, install packages, auto-quarantine review-only findings in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan ZIP archive-entry smoke | `tools/testing/run-release-local-core-quick-scan-zip-entry-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal, bounded in-memory ZIP entry signature evidence, and confirmed-only outer-archive quarantine for a benign ZIP entry fixture without using installed services or machine-wide state | Release-binary fixture verified; installed UI/service E2E partial; encrypted/oversized/unsupported archive edge rates, production false-positive measurement, and pre-execution blocking remain limited | Checkpoint 2100 adds `run-release-local-core-quick-scan-zip-entry-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; writes a temporary self-hashed exact-hash signature pack for harmless `zentor-safe-release-zip-entry-fixture` bytes; creates `safe-release-archive.zip` with `payload/safe-release-entry.txt` plus a benign `.txt` file under a temporary `Downloads` folder; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies one scanned ZIP carrier, one confirmed `Archived entry signature` threat with the safe signature id and no-extract/no-execute evidence, zero scan errors, one outer ZIP quarantine, a `.avoraxq` payload, a quarantine record, removal of only the matching ZIP source, and preservation of the benign file. The full verifier and report validator now require `release local-core binary quick-scan ZIP archive-entry safe hash fixture smoke`, and the old 2099 report fails validation because it lacks that step. Focused smoke passed, source-contracts passed (`544`), and the full small-threat MVP verifier/report-validator passed (`176` steps in `399.7s`) for `.workflow\ultracode\avorax-hardening\results\2100-small-threat-mvp-full-report.json`. This is safe release-binary archive-entry scan/quarantine evidence only; it does not extract ZIP contents to disk, execute archive entries, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan nested ZIP archive-entry smoke | `tools/testing/run-release-local-core-quick-scan-nested-zip-entry-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal, bounded recursive in-memory ZIP entry signature evidence, and confirmed-only outer-archive quarantine when the matching benign fixture exists only inside an inner ZIP | Release-binary fixture verified; installed UI/service E2E partial; encrypted/oversized/unsupported/deeper nested archive edge rates, production false-positive measurement, and pre-execution blocking remain limited | Checkpoint 2101 adds `run-release-local-core-quick-scan-nested-zip-entry-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; writes a temporary self-hashed exact-hash signature pack for harmless `zentor-safe-release-nested-zip-entry-fixture` bytes; creates `safe-release-nested-archive.zip` containing `archives/inner-safe.zip`, with the matching bytes inside the inner archive at `payload/safe-release-nested-entry.txt`; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies one scanned outer ZIP carrier, one confirmed `Archived entry signature` threat with the nested safe signature id and no-extract/no-execute evidence, zero scan errors, one outer ZIP quarantine, a `.avoraxq` payload, a quarantine record, removal of only the matching outer ZIP source, and preservation of the benign file. The full verifier and report validator now require `release local-core binary quick-scan nested ZIP archive-entry safe hash fixture smoke`, and the old 2100 report fails validation because it lacks that step. Focused smoke passed, source-contracts passed (`545`), and the full small-threat MVP verifier/report-validator passed (`177` steps in `428s`) for `.workflow\ultracode\avorax-hardening\results\2101-small-threat-mvp-full-report.json`. This is safe release-binary nested archive-entry scan/quarantine evidence only; it does not extract ZIP contents to disk, execute archive entries, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan package archive-entry smoke | `tools/testing/run-release-local-core-quick-scan-package-archive-entry-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal, bounded in-memory ZIP-framed package entry signature evidence, bounded APPX/MSIX bundle recursion, and confirmed-only outer-carrier quarantine for benign package fixtures without using installed services or machine-wide state | Release-binary fixture verified; installed UI/service E2E partial; encrypted/oversized/unsupported package edge rates, production false-positive measurement, package install/register semantics, and pre-execution blocking remain limited | Checkpoint 2102 adds `run-release-local-core-quick-scan-package-archive-entry-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; writes a temporary self-hashed exact-hash signature pack for harmless `zentor-safe-release-package-archive-entry-fixture` bytes; creates benign `.jar`, `.apk`, `.xpi`, `.vsix`, `.nupkg`, `.appx`, `.msix`, `.appxbundle`, and `.msixbundle` carriers under a temporary `Downloads` folder; nests APPX/MSIX bytes inside the bundle carriers; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `9` scanned package carriers, `9` confirmed `Archived entry signature` threats with the safe package signature id and no-extract/no-execute evidence, zero scan errors, `9` outer-carrier quarantines, `.avoraxq` payloads, quarantine records, removal of only matching carrier sources, and preservation of the benign file. The full verifier and report validator now require `release local-core binary quick-scan package archive-entry safe hash fixture smoke`, and the old 2101 report fails validation because it lacks that step. Focused smoke passed, source-contracts passed (`546`), and the full small-threat MVP verifier/report-validator passed (`178` steps in `429.4s`) for `.workflow\ultracode\avorax-hardening\results\2102-small-threat-mvp-full-report.json`. This is safe release-binary package archive-entry scan/quarantine evidence only; it does not extract package contents to disk, install or register APK/browser/editor/Windows packages, execute package contents, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan unsafe archive path review smoke | `tools/testing/run-release-local-core-quick-scan-unsafe-archive-path-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` performs selected-path Quick Scan traversal and reports ZIP-framed archive path traversal or absolute entry names as review-only unsafe archive path evidence without extracting, executing, or quarantining review-only carriers | Release-binary fixture verified; installed UI/service E2E partial; encrypted/oversized/unsupported archive edge rates, production false-positive measurement, package install/register semantics, and pre-execution blocking remain limited | Checkpoint 2103 adds `run-release-local-core-quick-scan-unsafe-archive-path-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates isolated engine subdirectories without a signature pack; creates benign `.zip`, `.jar`, `.appx`, and `.appxbundle` carriers containing parent-traversal, Windows drive-root, root-backslash, or nested package traversal entry names; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `4` scanned unsafe archive carriers, `4` review-only heuristic findings with `archive_zip_slip` and fail-visible `archive_content_scan_limited` evidence, zero scan errors, zero quarantined files, empty quarantine records, source-carrier preservation, and benign-file preservation. The full verifier and report validator now require `release local-core binary quick-scan unsafe archive path review smoke`, and the old 2102 report fails validation because it lacks that step. Focused smoke passed, source-contracts passed (`547`), and the full small-threat MVP verifier/report-validator passed (`179` steps in `662.3s`) for `.workflow\ultracode\avorax-hardening\results\2103-small-threat-mvp-full-report.json`. This is safe release-binary unsafe archive path review evidence only; it does not extract archive contents to disk, execute archive entries, auto-quarantine review-only findings in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan archive limit fail-visible smoke | `core/zentor_local_core/src/main.rs`; `tools/testing/run-release-local-core-quick-scan-archive-limit-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` reports oversized ZIP-framed archive content as fail-visible incomplete analysis instead of clean success, without extracting, executing, or quarantining unscanned carriers | Release-binary fixture verified; installed UI/service E2E partial; encrypted/unsupported archive edge rates, production false-positive measurement, package install/register semantics, and pre-execution blocking remain limited | Checkpoint 2104 surfaces otherwise non-threat `archive_content_scan_limited` evidence in local-core as skipped files and bounded scan errors, then adds `run-release-local-core-quick-scan-archive-limit-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates isolated engine subdirectories without a signature pack; creates benign oversized `.zip`, `.jar`, `.appx`, and `.appxbundle` carriers with `1 MiB + 1` entry content; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `completedWithErrors`, at least `4` scanned carriers, at least `4` skipped files, carrier-specific scan errors with `archive_content_scan_limited` and the limit explanation, zero threats, zero quarantined files, empty quarantine records, and source-carrier preservation. The full verifier and report validator now require `release local-core binary quick-scan archive limit fail-visible smoke`, and the old 2103 report fails validation because it lacks that step. Focused rustfmt/local regression/release build/smoke passed, source-contracts passed (`549`), and the full small-threat MVP verifier/report-validator passed (`180` steps in `580.8s`) for `.workflow\ultracode\avorax-hardening\results\2104-small-threat-mvp-full-report.json`. This is safe release-binary archive limit fail-visible evidence only; it does not extract archive contents to disk, execute archive entries, auto-quarantine unscanned content in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan archive truncation fail-visible smoke | `core/zentor_local_core/src/main.rs`; `tools/testing/run-release-local-core-quick-scan-archive-truncation-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` reports truncated ZIP-framed archive content as fail-visible incomplete analysis instead of clean success, without extracting, executing, repairing, or quarantining unscanned carriers | Release-binary fixture verified; installed UI/service E2E partial; encrypted/unsupported archive edge rates, production false-positive measurement, package install/register semantics, and pre-execution blocking remain limited | Checkpoint 2105 adds `quick_scan_reports_truncated_archive_content_limit_as_not_clean` and `run-release-local-core-quick-scan-archive-truncation-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates isolated engine subdirectories without a signature pack; creates benign truncated `.zip`, `.jar`, `.appx`, and nested `.appxbundle` carriers whose declared entry sizes exceed the available body bytes; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `completedWithErrors`, `4` scanned carriers, at least `4` skipped files, carrier-specific scan errors with `archive_content_scan_limited` and the limit explanation, zero threats, zero quarantined files, empty quarantine records, and source-carrier preservation. The full verifier and report validator now require `release local-core binary quick-scan archive truncation fail-visible smoke`, and the old 2104 report fails validation because it lacks that step. Focused rustfmt/local regression/release build/smoke passed, source-contracts passed (`550`), and the full small-threat MVP verifier/report-validator passed (`181` steps in `531.9s`) for `.workflow\ultracode\avorax-hardening\results\2105-small-threat-mvp-full-report.json`. This is safe release-binary archive truncation fail-visible evidence only; it does not extract archive contents to disk, execute archive entries, auto-quarantine unscanned content in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan archive encryption/unsupported fail-visible smoke | `core/zentor_local_core/src/main.rs`; `tools/testing/run-release-local-core-quick-scan-archive-encryption-unsupported-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` reports encrypted ZIP-framed archive entries and unsupported ZIP compression methods as fail-visible incomplete analysis instead of clean success, without extracting, decrypting, executing, or quarantining unscanned carriers | Release-binary fixture verified; installed UI/service E2E partial; broader benign archive edge rates, production false-positive measurement, package install/register semantics, and pre-execution blocking remain limited | Checkpoint 2106 adds `quick_scan_reports_encrypted_archive_content_limit_as_not_clean`, `quick_scan_reports_unsupported_archive_content_limit_as_not_clean`, and `run-release-local-core-quick-scan-archive-encryption-unsupported-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates isolated engine subdirectories without a signature pack; creates benign encrypted and unsupported-compression `.zip`, `.jar`, `.appx`, and nested `.appxbundle` carriers with ZIP local headers carrying general-purpose flag `0x0001` or compression method `99`; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `completedWithErrors`, `8` scanned carriers, `8` skipped files, carrier-specific scan errors with `archive_content_scan_limited` and the limit explanation, zero threats, zero quarantined files, empty quarantine records, and source-carrier preservation. The full verifier and report validator now require `release local-core binary quick-scan archive encryption/unsupported fail-visible smoke`, and the old 2105 report fails validation because it lacks that step. Focused rustfmt/local regressions/release build/smoke passed, source-contracts passed (`551`), and the full small-threat MVP verifier/report-validator passed (`182` steps in `441s`) for `.workflow\ultracode\avorax-hardening\results\2106-small-threat-mvp-full-report.json`. This is safe release-binary archive encryption/unsupported fail-visible evidence only; it does not decrypt protected content, emulate unsupported compression, extract archive contents to disk, execute archive entries, auto-quarantine unscanned content in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan archive depth fail-visible smoke | `core/zentor_local_core/src/main.rs`; `tools/testing/run-release-local-core-quick-scan-archive-depth-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` reports nested ZIP-framed content beyond the configured archive-depth limit as fail-visible incomplete analysis instead of clean success, without extracting, executing, recursing past the configured depth, or quarantining unscanned carriers | Release-binary fixture verified; installed UI/service E2E partial; broader benign archive edge rates, production false-positive measurement, package install/register semantics, and pre-execution blocking remain limited | Checkpoint 2107 adds `quick_scan_reports_nested_archive_depth_limit_as_not_clean` and `run-release-local-core-quick-scan-archive-depth-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates isolated engine subdirectories without a signature pack; creates benign nested-depth `.zip`, `.jar`, `.appx`, and `.appxbundle` carriers with ZIP entry chains such as `level1.zip -> level2.zip -> level3.zip`; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `completedWithErrors`, `4` scanned carriers, `4` skipped files, carrier-specific scan errors with `archive_content_scan_limited`, `configured archive-depth limit`, and the deeper-content warning, zero threats, zero quarantined files, empty quarantine records, and source-carrier preservation. The first smoke attempt exposed a separate `.appxbundle` package review heuristic when using nested `store.appx`, so the final smoke isolates archive-depth proof with direct ZIP-framed bundle entries. The full verifier and report validator now require `release local-core binary quick-scan archive depth fail-visible smoke`, and the old 2106 report fails validation because it lacks that step. Focused rustfmt/local regression/release build/smoke passed, source-contracts passed (`552`), and the full small-threat MVP verifier/report-validator passed (`183` steps in `438.9s`) for `.workflow\ultracode\avorax-hardening\results\2107-small-threat-mvp-full-report.json`. This is safe release-binary archive depth fail-visible evidence only; it does not recurse past the configured depth, extract archive contents to disk, execute archive entries, auto-quarantine unscanned content in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Release local-core Quick Scan archive count/total fail-visible smoke | `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/run-release-local-core-quick-scan-archive-count-total-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that `target/release/zentor_local_core.exe` reports ZIP-framed archive entry-count and total-content limits as fail-visible incomplete analysis instead of clean success or synthetic threat evidence, without extracting, executing, or quarantining unscanned carriers | Release-binary fixture verified; installed UI/service E2E partial; broader benign archive edge rates, production false-positive measurement, package install/register semantics, and pre-execution blocking remain limited | Checkpoint 2108 adds `quick_scan_reports_archive_entry_count_limit_as_not_clean`, `quick_scan_reports_archive_total_content_limit_as_not_clean`, native `benign_archive_entry_location_observations_do_not_accumulate_into_threat`, and `run-release-local-core-quick-scan-archive-count-total-smoke.ps1`. Native archive-entry heuristic aggregation now skips weak repeated `location_observation` and `filename_observation` evidence so entry count alone cannot turn benign archive metadata into a threat, and local-core maps native `review_or_quarantine_by_policy` recommendations to review action unless stronger confirmed evidence maps to quarantine. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; creates isolated engine subdirectories without a signature pack; creates benign entry-count `.zip`, `.jar`, `.appx`, and `.appxbundle` carriers with `65` stored entries plus total-content carriers with five `900 KiB` stored entries; invokes JSON `quick_scan_selected_paths` with `scan_kind=quick` and `AutoQuarantineConfirmedOnly`; then verifies `completedWithErrors`, `8` scanned carriers, `8` skipped files, carrier-specific scan errors with `archive_content_scan_limited`, zero threats, zero quarantined files, empty quarantine records, and source-carrier preservation. The full verifier and report validator now require `release local-core binary quick-scan archive count/total fail-visible smoke`, and the old 2107 report fails validation because it lacks that step. Focused native/local rustfmt, native/local regressions, release build, smoke, and source-contracts passed (`553`), and the full small-threat MVP verifier/report-validator passed (`184` steps in `497.4s`) for `.workflow\ultracode\avorax-hardening\results\2108-small-threat-mvp-full-report.json`. This is safe release-binary archive count/total fail-visible evidence only; it does not extract archive contents to disk, execute archive entries, auto-quarantine unscanned or review-only content in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Full Scan PE-carrier simulator signature/quarantine coverage | `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Runtime Full Scan proof that `.dll`, `.sys`, `.scr`, and `.bin` safe simulator files are sent through ANE signature detection and normal confirmed-only quarantine, while removing an unused source-only signature-gating helper | Runtime fixture verified; installed E2E partial; real PE loader behavior, production false-positive measurement, and pre-execution blocking remain limited | Checkpoint 2097 removes the unused local-core `should_signature_scan` / `signature_scan_extension` helper and its source-only regression, then adds `full_scan_reports_pe_carrier_safe_simulators_and_quarantines_files`. The proof scans benign `.dll`, `.sys`, `.scr`, and `.bin` fixtures containing only `ZENTOR-SAFE-EICAR-SIMULATOR-FILE`, reports each as confirmed signature evidence, and quarantines each through `AutoQuarantineConfirmedOnly`. The small-threat MVP verifier and report validator now require `local-core full-scan PE carrier simulator quarantine`; the previous 2096 full report fails validation because it lacks that required step. Focused local tests passed, source-contracts passed (`541`), and the full small-threat MVP verifier/report-validator passed (`173` steps in `502.8s`) for `.workflow\ultracode\avorax-hardening\results\2097-small-threat-mvp-full-report.json`. This is safe runtime signature/quarantine proof only; it does not execute DLLs, load drivers, run screensavers, execute payloads, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan risky-carrier priority alignment | `core/zentor_local_core/src/scanner/file_walker.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Keeps already-selected risky candidates early in Quick Scan ordering for `.sys`, `.bin`, `.vbe`, `.wsf`, `.hta`, `.lnk`, and the checkpoint 2095 `.com`/`.pif`/`.cpl`/`.msu` carrier paths, without making extension-only detections | Runtime fixture verified for ordering; installed E2E partial; detection-time improvement on representative hosts and pre-execution blocking remain limited | Checkpoint 2096 aligns Quick Scan priority ordering with risky-file candidate coverage, adds explicit priority assertions for `driver.sys`, `payload.bin`, `support.vbe`, `support-ticket.wsf`, `support-ticket.hta`, and `support-link.lnk`, and reruns the quick-walker risky-file selection guard. Focused local tests passed, source-contracts passed (`541`), and the full small-threat MVP verifier/report-validator passed (`172` steps in `504.4s`) for `.workflow\ultracode\avorax-hardening\results\2096-small-threat-mvp-full-report.json`. This is scan-ordering proof only; it does not create detections by extension, raise verdicts, trigger quarantine, execute scripts/shortcuts/drivers/applications/packages, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan CPL/MSU simulator signature coverage | `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Quick Scan risky-file routing for `.cpl` Control Panel applets and `.msu` Windows Update packages, plus explicit `.com`/`.pif` priority routing | Runtime fixture verified; installed E2E partial; full CPL runtime behavior, MSU/CAB parsing, Windows Update/package installation semantics, and pre-execution blocking remain limited | Checkpoint 2095 adds `.cpl` and `.msu` to local-core Quick Scan risky-file selection and makes `.com`/`.pif` quick-scan priority routing explicit. Local-core proof `quick_scan_reports_cpl_msu_safe_simulators_and_quarantines_files` scans benign `Downloads\safe-simulator-panel.cpl` and `Downloads\safe-simulator-update.msu` files containing only the safe simulator signature string; both are confirmed signature detections and are quarantined by `AutoQuarantineConfirmedOnly`. Checkpoint 2097 removes the stale Full Scan signature-gating helper and adds runtime Full Scan PE-carrier proof. Focused local tests passed, source-contracts passed (`541`), local-core quick-walker proof passed, and the full small-threat MVP verifier/report-validator passed (`172` steps in `520.8s`) for `.workflow\ultracode\avorax-hardening\results\2095-small-threat-mvp-full-report.json`. This is safe signature/routing/quarantine proof only; it does not open Control Panel applets, invoke `control.exe`, `rundll32`, `wusa`, DISM, Windows Update, or installers, extract MSU/CAB payloads, install packages, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan Windows scriptlet/SCT/WSC carrier review coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.sct` scriptlet and `.wsc` Windows Script Component carriers that combine scriptlet/registration/script markers with remote executable/script or script-host downloader evidence | Runtime fixture verified; installed E2E partial; full scriptlet/COM registration semantics, `regsvr32`/`scrobj.dll` runtime behavior, remote scriptlet download/reputation behavior, and pre-execution blocking remain limited | Checkpoint 2094 adds `windows_scriptlet_marker_count`, `windows_scriptlet_remote_script_launch`, `.sct`/`.wsc` VBS-style classification, and Quick Scan risky-carrier selection. Native proof under the `windows_scriptlet` filter passed (`5` tests), covering `.sct` remote-script evidence, `.wsc` script-host downloader evidence, string indicator counting, ordinary scriptlet document-link negative guard, and non-scriptlet remote text negative guard. Local-core proof `quick_scan_reports_windows_scriptlet_carriers_for_review` scans benign `Downloads\loader.sct` and `Downloads\component.wsc` as review-only `SuspiciousDownloader` heuristic detections while `AutoQuarantineConfirmedOnly` leaves both files in place. Focused native/local tests passed, source-contracts passed (`541`), local-core quick-walker proof passed, and the full small-threat MVP verifier/report-validator passed (`171` steps in `507.9s`) for `.workflow\ultracode\avorax-hardening\results\2094-small-threat-mvp-full-report.json`. This is bounded static Windows scriptlet/SCT/WSC carrier review only; it does not invoke `regsvr32`, `rundll32`, WSH, COM registration, scriptlet engines, or `scrobj.dll`, resolve/download remote scriptlets, register COM components, execute script content, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan Java Web Start/JNLP carrier review coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.jnlp` Java Web Start launch descriptors that combine JNLP/Web Start markers with remote Java archive or launcher evidence | Runtime fixture verified; installed E2E partial; Java Web Start runtime behavior, Java signing/trust prompt/sandbox semantics, remote JAR/JNLP download/reputation behavior, and pre-execution blocking remain limited | Checkpoint 2093 adds `java_web_start_marker_count`, `remote_java_web_start_url_count`, `java_web_start_remote_archive_launch`, `.jnlp` text classification, and Quick Scan risky-carrier selection. Native proof under the `java_web_start` filter passed (`6` tests), covering remote JAR evidence, text classification, string indicators, ordinary document-link negative guard, and non-JNLP XML negative guard. Local-core proof `quick_scan_reports_java_web_start_carrier_for_review` scans benign `Downloads\support.jnlp` as a review-only `SuspiciousDownloader` heuristic detection while `AutoQuarantineConfirmedOnly` leaves the file in place. Focused native/local tests passed, source-contracts passed (`541`), local-core quick-walker proof passed, and the full small-threat MVP verifier/report-validator passed (`169` steps in `524.7s`) for `.workflow\ultracode\avorax-hardening\results\2093-small-threat-mvp-full-report.json`. This is bounded static Java Web Start/JNLP carrier review only; it does not start Java, invoke `javaws`, install or cache Web Start applications, resolve/download remote JAR/JNLP URLs, evaluate Java signing/trust prompts or sandbox permissions as execution proof, execute Java code, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan Windows Installer custom-action carrier review coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.msi` Windows Installer packages and `.msp` patch packages that combine installer/package markers, custom-action or QuietExec/deferred metadata, and remote executable/script or script-host downloader evidence | Runtime fixture verified; installed E2E partial; full MSI database/table parsing, installer signature/trust prompt semantics, live install/repair/patch behavior, remote download/reputation behavior, and pre-execution blocking remain limited | Checkpoint 2092 adds `windows_installer_marker_count`, `windows_installer_custom_action_count`, `windows_installer_custom_action_remote_launch`, CFB header context, and `.msp` Quick Scan risky-carrier selection alongside `.msi`. Native proof under the `windows_installer` filter passed (`5` tests), covering `.msi` remote custom-action evidence, `.msp` script-host custom-action evidence, string indicator counting, and ordinary installer/document-link negative guards. Local-core proof `quick_scan_reports_windows_installer_custom_action_carriers_for_review` scans benign `Downloads\support-installer.msi` and `Downloads\support-patch.msp` fixtures as review-only `SuspiciousDownloader` heuristic detections while `AutoQuarantineConfirmedOnly` leaves both files in place. Focused native/local tests passed, source-contracts passed (`541`), local-core quick-walker proof passed, and the full small-threat MVP verifier/report-validator passed (`167` steps in `502.6s`) for `.workflow\ultracode\avorax-hardening\results\2092-small-threat-mvp-full-report.json`. This is bounded static Windows Installer carrier review only; it does not invoke `msiexec`, install/repair/patch packages, extract MSI tables or payloads to disk, execute custom actions, resolve/download remote URLs, evaluate installer signatures/trust prompts as execution proof, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan Windows App Installer/AppInstaller carrier review coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.appinstaller` manifests that combine App Installer manifest markers with remote `.appx`, `.msix`, `.appxbundle`, or `.msixbundle` package URLs | Runtime fixture verified; installed E2E partial; App Installer handler behavior, Windows package trust prompts, package manifest/capability semantics, live install/register/download behavior, remote reputation, and pre-execution blocking remain limited | Checkpoint 2122 adds `windows_appinstaller_marker_count`, `remote_windows_app_package_url_count`, `windows_appinstaller_remote_package_launch`, `.appinstaller` text classification, and Quick Scan risky-carrier selection. Native proof under the `appinstaller` filter passed (`6` tests), covering remote package evidence, text classification, string indicator counting, ordinary document-link negative guard, and non-`.appinstaller` XML negative guard. Local-core proof `quick_scan_reports_windows_appinstaller_carrier_for_review` scans benign `Downloads\support.appinstaller` as a review-only `SuspiciousDownloader` heuristic detection while `AutoQuarantineConfirmedOnly` leaves the carrier and an ordinary document-link `.appinstaller` fixture in place. Focused native/local tests passed, source-contracts passed (`560`), local-core quick-walker proof passed, and the full small-threat MVP verifier/report-validator passed (`196` steps in `695.7s`) for `.workflow\ultracode\avorax-hardening\results\2122-small-threat-mvp-windows-appinstaller-report.json`. This is bounded static App Installer manifest review only; it does not invoke App Installer, install/register APPX/MSIX packages, resolve or download remote URLs, evaluate package trust prompts/capabilities as execution proof, auto-quarantine review-only carriers in confirmed-only mode, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan ClickOnce carrier review coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.application` ClickOnce deployment manifests and `.appref-ms` application references that combine ClickOnce deployment/reference context with a remote application, executable/script URL, or remote executable/script network path | Runtime fixture verified; installed E2E partial; ClickOnce trust prompt/certificate/zone semantics, live installation, remote download/reputation behavior, and pre-execution blocking remain limited | Checkpoint 2091 adds `clickonce_marker_count`, `remote_clickonce_url_count`, `clickonce_remote_deployment_launch`, `.application`/`.appref-ms` text classification, and Quick Scan risky-carrier selection. Native proof under the `clickonce` filter passed (`6` tests), covering `.application` remote executable evidence, `.appref-ms` remote application evidence, text classification, string indicators, and ordinary XML negative guard. Local-core proof `quick_scan_reports_clickonce_carriers_for_review` scans benign `Downloads\support.application` and `Downloads\support.appref-ms` fixtures as review-only `SuspiciousDownloader` heuristic detections while `AutoQuarantineConfirmedOnly` leaves both files in place. Focused native/local tests passed, source-contracts passed (`541`), local-core quick-walker proof passed, and the full small-threat MVP verifier/report-validator passed (`165` steps in `466.2s`) for `.workflow\ultracode\avorax-hardening\results\2091-small-threat-mvp-full-report.json`. This is bounded static ClickOnce carrier review only; it does not launch ClickOnce handlers, install applications, resolve/download remote URLs, evaluate deployment trust prompts/certificates/zones as execution proof, execute deployed binaries, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan OOXML macro-package relationship coverage | `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/analyzers/archives/mod.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for macro-enabled OOXML Office containers with a VBA project entry and an external relationship to a remote executable/script URL or remote network script path | Runtime fixture verified; encrypted/protected/unsupported content fail-visible; ZIP64/multidisk/unsupported parsing partial; installed E2E partial | Checkpoint 2063 adds `ooxml_vba_project_count`, `ooxml_external_relationship_count`, `ooxml_remote_executable_relationship_count`, `ooxml_macro_external_remote_relationship`, native positive/negative archive/scoring fixtures, and local-core Quick Scan proof for inert `invoice-package.docm`, `budget-package.xlsm`, and `briefing-package.pptm`. Checkpoint 2064 adds bounded raw-deflate support for ZIP method `8` `.rels` bodies, `MAX_DEFLATED_RELATIONSHIP_BYTES`, `MAX_INFLATED_RELATIONSHIP_BYTES`, decode-error limit evidence, native positive/limit/error fixtures, direct lock-pinned `flate2` use in ANE, and local-core Quick Scan proof for inert `compressed-invoice.docm`. Checkpoint 2065 adds bounded central-directory/data-descriptor parsing with `MAX_CENTRAL_DIRECTORY_BYTES`, EOCD lookup, ZIP64/multidisk fail-visible limits, matching local-header name/method/data-descriptor-bit guard, native positive/mismatch fixtures, and local-core Quick Scan proof for inert `descriptor-invoice.docm`. Checkpoint 2066 adds `ZIP_GENERAL_PURPOSE_ENCRYPTED`, encrypted relationship skip/limit evidence, central/local encrypted-bit consistency, native encrypted local/central fixtures, and local-core Quick Scan proof that inert `encrypted-invoice.docm` remains clean when encrypted `.rels` bytes contain plaintext-looking remote-script XML. Checkpoint 2067 makes oversized stored, over-limit deflated, and unsupported-compression relationship bodies fail-visible as limit/unsupported evidence, with native limit fixtures and local-core Quick Scan proof that inert `unsupported-compression-invoice.docm` remains clean. Focused native/local tests passed, source-contracts passed (`541`), native `ooxml_` passed (`13`), native `archive` passed (`21`), local-core `quick_scan_reports` passed (`21`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `323.7s`) for `.workflow\ultracode\avorax-hardening\results\2067-small-threat-mvp-full-report.json`. This is bounded OOXML relationship review evidence and false-positive control only; it does not decrypt Office files, support all ZIP compression/encryption methods, ZIP64, multidisk archives, full OLE/VBA streams, Office automation, macro execution, installed UI/service E2E, live malware, or pre-execution blocking. |
| Quick Scan Office macro-carrier coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_native_engine/src/verdict/risk_fusion.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.docm`, `.xlsm`, `.pptm`, `.doc`, `.xls`, and `.ppt` carriers that combine macro auto-run evidence with remote executable/script, remote network script, script-host, or suspicious downloader evidence | Runtime fixture verified; installed E2E partial; full OLE/VBA parsing partial | Checkpoint 2062 adds `macro_auto_run_count`, `office_macro_auto_run_remote_launch`, native positive/negative macro-enabled Office fixtures, macro-category fusion proof, and local-core Quick Scan proof for inert `invoice.docm`, `budget.xlsm`, and `briefing.pptm`. Checkpoint 2068 extends the same conservative review signal to legacy `.doc`, `.xls`, and `.ppt` carrier extensions, adds `is_macro_capable_office_carrier` while keeping `is_macro_enabled_ooxml_office_carrier` for OOXML relationship evidence, routes legacy Office extensions through Quick Scan, and proves inert `invoice-legacy.doc`, `budget-legacy.xls`, and `briefing-legacy.ppt` fixtures are review-detected while confirmed-only auto-quarantine leaves them in place. Focused native/local tests passed, source-contracts passed (`541`), native `office_macro` passed (`5`), local-core `quick_scan_reports` passed (`22`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `327.6s`) for `.workflow\ultracode\avorax-hardening\results\2068-small-threat-mvp-full-report.json`. This is bounded static review evidence only; it does not open Office files, execute VBA/macros, parse full OLE/OpenXML macro projects, prove installed UI/service E2E, test live malware, or claim pre-execution blocking. |
| Quick Scan RTF external-object carrier coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.rtf` carriers that combine RTF object/template/field control words with remote executable/script, remote network script, script-host, or suspicious downloader evidence | Runtime fixture verified; installed E2E partial; embedded OLE/RTF exploit parsing partial | Checkpoint 2069 adds `rtf_external_object_count`, `rtf_external_object_remote_launch`, `.rtf` document classification, `.rtf` Quick Scan routing, native positive fixtures for remote URL and remote network script references, negative fixtures for ordinary RTF web links and non-RTF object words, and local-core Quick Scan proof for inert `invoice-object.rtf` and `support-field.rtf` fixtures. Focused native/local tests passed, source-contracts passed (`541`), native `file_type` passed (`6`), native `scoring` passed (`32`), local-core `quick_scan_reports` passed (`23`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `327.2s`) for `.workflow\ultracode\avorax-hardening\results\2069-small-threat-mvp-full-report.json`. This is bounded static RTF carrier review evidence only; it does not parse embedded OLE payloads, exploit CVEs, open Word/Office, resolve remote references, execute content, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan PDF active-content carrier coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.pdf` carriers that combine PDF active-content markers with remote executable/script, remote network script, script-host, or suspicious downloader evidence | Runtime fixture verified; installed E2E partial; PDF object-stream/embed/exploit parsing partial | Checkpoint 2070 adds `pdf_active_content_count`, `pdf_active_content_remote_launch`, `.pdf` document classification, `.pdf` Quick Scan routing, native positive fixtures for remote URL JavaScript and remote network launch references, negative fixtures for ordinary PDF web links and PDF action words outside PDF files, and local-core Quick Scan proof for inert `invoice-action.pdf` and `support-launch.pdf` fixtures. Focused native/local tests passed, source-contracts passed (`541`), native `file_type` passed (`6`), native `scoring` passed (`36`), local-core `quick_scan_reports` passed (`24`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `331s`) for `.workflow\ultracode\avorax-hardening\results\2070-small-threat-mvp-full-report.json`. This is bounded static PDF carrier review evidence only; it does not parse PDF object streams, decompress embedded payloads, exploit CVEs, render/open PDF files, resolve remote references, execute content, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan HTML/SVG web-document carrier coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.html`, `.htm`, and `.svg` carriers that combine web-document active-content markers with remote executable/script, remote network script, script-host, or suspicious downloader evidence | Runtime fixture verified; installed E2E partial; browser rendering/JS execution/exploit parsing partial | Checkpoint 2071 adds `web_document_active_content_count`, `web_document_active_content_remote_launch`, `.html`/`.htm`/`.svg` document classification, web-document Quick Scan routing, native positive fixtures for HTML script/download and SVG event-handler remote-script references, negative fixtures for ordinary HTML links and active words outside web-document context, and local-core Quick Scan proof for inert `invoice-web.html` and `diagram-loader.svg` fixtures. Focused native/local tests passed, source-contracts passed (`541`), native `file_type` passed (`6`), native `scoring` passed (`40`), local-core `quick_scan_reports` passed (`25`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `335.7s`) for `.workflow\ultracode\avorax-hardening\results\2071-small-threat-mvp-full-report.json`. This is bounded static web-document carrier review evidence only; it does not render/open browsers, execute JavaScript, fetch remote content, parse browser exploit families, inspect browser caches, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan autorun INF carrier coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.inf` autorun carriers that combine a visible `[autorun]` section with executable/script launch commands | Runtime fixture verified; installed E2E partial; removable-media/Windows AutoRun behavior partial | Checkpoint 2072 adds `autorun_inf_executable_command_count`, `autorun_inf_executable_launch`, `.inf` text classification, `.inf` Quick Scan routing, native positive fixtures for local executable and remote network script launch commands, negative fixtures for ordinary driver INF content and autorun document links, file-walker proof that `autorun.inf` is retained by Quick Scan, and local-core Quick Scan proof for inert `autorun.inf` and `media-autorun.inf` fixtures. Focused native/local tests passed, source-contracts passed (`541`), native `file_type` passed (`6`), native `scoring` passed (`44`), local-core `file_walker` passed (`7`), local-core `quick_scan_reports` passed (`26`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `336.4s`) for `.workflow\ultracode\avorax-hardening\results\2072-small-threat-mvp-full-report.json`. This is bounded static autorun INF carrier review evidence only; it does not mount removable media, enable/test Windows AutoRun, execute referenced commands, resolve remote references, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan EML executable-attachment carrier coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/analyzers/file_type.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.eml` carriers that combine MIME email headers, `Content-Disposition: attachment`, and executable/script `filename=` or `name=` metadata | Runtime fixture verified; installed E2E partial; full MIME/attachment decoding/msg parsing partial | Checkpoint 2073 adds `email_executable_attachment_count`, `email_executable_attachment`, `.eml` text classification, `.eml` Quick Scan routing, native positive fixture coverage for executable/script attachment metadata, negative fixtures for ordinary document attachments and attachment words outside email context, and local-core Quick Scan proof for inert `invoice-email.eml`. Focused native/local tests passed, source-contracts passed (`541`), native `file_type` passed (`6`), native `scoring` passed (`47`), local-core `file_walker` passed (`7`), local-core `quick_scan_reports` passed (`27`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `382.5s`) for `.workflow\ultracode\avorax-hardening\results\2073-small-threat-mvp-full-report.json`. This is bounded static email carrier review evidence only; it does not parse Outlook `.msg`/OLE, decode/extract attachments, perform full MIME unfolding/RFC2231 parsing, open mail clients, execute attachments, resolve remote content, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan ZIP deceptive nested executable coverage | `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/analyzers/archives/mod.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for ZIP entries with deceptive executable/script names such as bait names or document/image/email decoy extensions before executable/script suffixes | Runtime fixture verified; installed E2E partial; nested extraction and non-ZIP archive parsing partial | Checkpoint 2074 adds `suspicious_archive_executable_name`, broadens `contains_executable` suffix accounting for common script/installer carriers, keeps `archive_suspicious_executable` gated on suspicious nested names, adds native positive fixtures for `invoice.exe`, `invoice.pdf.exe`, `photo.jpg.scr`, and `readme.txt.js`, adds negative fixtures for ordinary `tools/setup.exe`, and proves local-core Quick Scan reports an inert `documents-archive.zip` fixture while confirmed-only auto-quarantine leaves it in place. Focused native/local tests passed, source-contracts passed (`541`), native `archive` passed (`25`), native `scoring` passed (`49`), local-core `quick_scan_reports` passed (`28`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `342.3s`) for `.workflow\ultracode\avorax-hardening\results\2074-small-threat-mvp-full-report.json`. This is bounded ZIP entry-name review evidence only; it does not extract archives, unpack payloads, execute nested files, inspect encrypted/protected archive contents beyond existing fail-visible limits, parse non-ZIP archive formats, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan disk image autorun carrier coverage | `core/zentor_native_engine/src/analyzers/strings.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for `.iso` and `.img` carriers that combine an ISO/UDF marker, `autorun.inf`, and executable/script launch evidence | Runtime fixture verified; installed E2E partial; full ISO/UDF filesystem parsing and mounting behavior partial | Checkpoint 2075 adds `disk_image_autorun_executable_count`, `disk_image_autorun_executable`, ISO/UDF marker checks for `CD001`, `NSR02`, and `NSR03`, `.iso`/`.img` Quick Scan priority routing, native positive/negative fixtures for executable autorun references versus ordinary text/document links, and local-core Quick Scan proof for an inert `support-media.iso` fixture while confirmed-only auto-quarantine leaves it in place. Focused native/local tests passed, source-contracts passed (`541`), native `scoring` passed (`52`), native `indicator` passed (`10`), local-core `file_walker` passed (`7`), local-core `quick_scan_reports` passed (`29`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `335.4s`) for `.workflow\ultracode\avorax-hardening\results\2075-small-threat-mvp-full-report.json`. This is bounded disk-image marker/string review evidence only; it does not mount disk images, parse full ISO/UDF filesystems, extract or execute payloads, inspect other image formats deeply, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan ZIP autorun executable bundle coverage | `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/analyzers/archives/mod.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for ZIP archives that contain both an `autorun.inf` entry and an executable/script companion entry | Runtime fixture verified; installed E2E partial; archive payload extraction and autorun body parsing partial | Checkpoint 2076 adds `autorun_inf_entry_count`, `autorun_executable_entry_count`, `archive_autorun_executable_bundle`, native positive/negative fixtures for autorun plus executable companion versus autorun plus document-only companion, and local-core Quick Scan proof for an inert `media-autoplay.zip` fixture while confirmed-only auto-quarantine leaves it in place. Focused native/local tests passed, source-contracts passed (`541`), native `archive` passed (`27`), native `scoring` passed (`54`), local-core `quick_scan_reports` passed (`30`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `344s`) for `.workflow\ultracode\avorax-hardening\results\2076-small-threat-mvp-full-report.json`. This is bounded ZIP entry-name review evidence only; it does not extract archives, inspect encrypted/protected archive bodies beyond existing fail-visible limits, parse `autorun.inf` semantics inside the archive as execution proof, execute nested files, parse non-ZIP archive formats, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan ZIP autorun body command coverage | `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/analyzers/archives/mod.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for ZIP archives with a small bounded `autorun.inf` body that launches an executable/script companion entry | Runtime fixture verified; installed E2E partial; archive payload extraction and Windows AutoRun behavior partial | Checkpoint 2077 adds `autorun_inf_executable_command_count`, explicit `16 KiB` stored/deflated/inflated autorun body limits, `bounded_autorun_inf_body`, encrypted autorun-body fail-visible coverage, `archive_autorun_inf_executable_command`, native positive/negative fixtures, and local-core Quick Scan proof for an inert `launcher-autoplay.zip` fixture while confirmed-only auto-quarantine leaves it in place. Focused native/local tests passed, source-contracts passed (`541`), native `archive` passed (`29`), native `scoring` passed (`55`), local-core `quick_scan_reports` passed (`31`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `337.8s`) for `.workflow\ultracode\avorax-hardening\results\2077-small-threat-mvp-full-report.json`. This is bounded ZIP-contained autorun body review evidence only; it does not extract archives, execute nested files, mount media, prove Windows AutoRun behavior, inspect encrypted/protected archive bodies beyond fail-visible limits, parse non-ZIP archive formats, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |

| Quick Scan APPXBUNDLE/MSIXBUNDLE nested package signature coverage | `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching for safe nested APPX/MSIX package entries inside APPXBUNDLE/MSIXBUNDLE carriers using the existing ZIP-framed archive sampler, plus Quick Scan risky-carrier selection for `.appxbundle` and `.msixbundle`, without extracting, installing, registering, or executing package contents | Native and local-core runtime fixture verified; installed E2E partial; APPX/MSIX bundle manifest/resource/capability semantics, Windows package install/registration behavior, package startup-task behavior, encrypted/protected/unsupported archive content, non-ZIP-framed formats, and pre-execution blocking remain limited | Checkpoint 2090 extends archive-entry content scanning and Quick Scan risky selection from ZIP/JAR/APK/XPI/VSIX/NUPKG/APPX/MSIX carriers to `.appxbundle` and `.msixbundle` Windows package bundles. Native proof `eicar_inside_appxbundle_and_msixbundle_nested_packages_is_detected` detects in-memory `store-package.appxbundle::packages/store-package.appx::assets/eicar.txt` and `desktop-package.msixbundle::packages/desktop-package.msix::vfs/programfiles/app/eicar.txt` EICAR payloads without extraction, installation, registration, or execution. Local-core proof `quick_scan_reports_appxbundle_msixbundle_nested_package_safe_simulator` scans benign `Downloads\safe-simulator-store-package.appxbundle` and `Downloads\safe-simulator-desktop-package.msixbundle` fixtures with nested inner package simulator entries and quarantines only the outer bundles because confirmed simulator signature evidence is present. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), focused native/local APPXBUNDLE/MSIXBUNDLE tests passed (`1` each), local-core `file_walker` passed (`7`), native `eicar_inside_` passed (`9`), native `archive` passed (`43`), local-core `quick_scan_reports` passed (`38`), and the full small-threat MVP verifier/report-validator passed (`163` steps in `381.9s`) for `.workflow\ultracode\avorax-hardening\results\2090-small-threat-mvp-full-report.json`. This does not install or register Windows packages or bundles, evaluate package bundle manifest/resource/capability semantics, run package startup tasks or binaries, write inner entries to disk, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan APPX/MSIX archive-entry signature coverage | `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching for safe small APPX/MSIX entries using the existing ZIP-framed archive sampler, plus Quick Scan risky-carrier selection for `.appx` and `.msix`, without extracting, installing, registering, or executing package contents | Native and local-core runtime fixture verified; installed E2E partial; APPX/MSIX manifest/capability semantics, Windows package install/registration behavior, package startup-task behavior, encrypted/protected/unsupported archive content, non-ZIP-framed formats, and pre-execution blocking remain limited | Checkpoint 2089 extends archive-entry content scanning and Quick Scan risky selection from ZIP/JAR/APK/XPI/VSIX/NUPKG carriers to `.appx` and `.msix` Windows app packages. Native proof `eicar_inside_appx_and_msix_entries_is_detected_without_extracting_package` detects in-memory `store-package.appx::assets/eicar.txt` and `desktop-package.msix::vfs/programfiles/app/eicar.txt` EICAR payloads without extraction, installation, registration, or execution. Local-core proof `quick_scan_reports_appx_msix_entry_safe_simulator_and_quarantines_outer_packages` scans benign `Downloads\safe-simulator-store-package.appx` and `Downloads\safe-simulator-desktop-package.msix` fixtures and quarantines only the outer packages because confirmed simulator signature evidence is present. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), focused native/local APPX/MSIX tests passed (`1` each), local-core `file_walker` passed (`7`), native `eicar_inside_` passed (`8`), native `archive` passed (`43`), local-core `quick_scan_reports` passed (`37`), and the full small-threat MVP verifier/report-validator passed (`161` steps in `385.2s`) for `.workflow\ultracode\avorax-hardening\results\2089-small-threat-mvp-full-report.json`. This does not install or register Windows packages, evaluate package manifest/capability semantics, run package startup tasks or binaries, write inner entries to disk, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan NUPKG archive-entry signature coverage | `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching for safe small NUPKG entries using the existing ZIP-framed archive sampler, plus Quick Scan risky-carrier selection for `.nupkg`, without extracting, restoring, installing, or executing package contents | Native and local-core runtime fixture verified; installed E2E partial; NuGet package metadata semantics, package restore/install scripts/build targets, package binary execution behavior, encrypted/protected/unsupported archive content, non-ZIP-framed formats, and pre-execution blocking remain limited | Checkpoint 2088 extends archive-entry content scanning and Quick Scan risky selection from ZIP/JAR/APK/XPI/VSIX carriers to `.nupkg` NuGet packages. Native proof `eicar_inside_nupkg_entry_is_detected_without_extracting_archive` detects an in-memory `library-package.nupkg::contentfiles/any/any/eicar.txt` EICAR payload without extraction, restore, installation, or execution. Local-core proof `quick_scan_reports_nupkg_entry_safe_simulator_and_quarantines_outer_package` scans a benign `Downloads\safe-simulator-library-package.nupkg` fixture with `contentfiles/any/any/safe-eicar.txt` and quarantines only the outer NUPKG because confirmed simulator signature evidence is present. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), focused native/local NUPKG tests passed (`1` each), local-core `file_walker` passed (`7`), native `eicar_inside_` passed (`7`), native `archive` passed (`43`), local-core `quick_scan_reports` passed (`36`), and the full small-threat MVP verifier/report-validator passed (`159` steps in `360.5s`) for `.workflow\ultracode\avorax-hardening\results\2088-small-threat-mvp-full-report.json`. This does not restore NuGet packages, run package install scripts or build targets, execute package binaries, write inner entries to disk, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan VSIX archive-entry signature coverage | `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching for safe small VSIX entries using the existing ZIP-framed archive sampler, plus Quick Scan risky-carrier selection for `.vsix`, without extracting, installing, or executing archive contents | Native and local-core runtime fixture verified; installed E2E partial; VSIX manifest/API semantics, editor extension install behavior, extension JavaScript/native-code behavior, encrypted/protected/unsupported archive content, non-ZIP-framed formats, and pre-execution blocking remain limited | Checkpoint 2087 extends archive-entry content scanning and Quick Scan risky selection from ZIP/JAR/APK/XPI carriers to `.vsix` editor-extension packages. Native proof `eicar_inside_vsix_entry_is_detected_without_extracting_archive` detects an in-memory `editor-extension.vsix::extension/assets/eicar.txt` EICAR payload without extraction, installation, or execution. Local-core proof `quick_scan_reports_vsix_entry_safe_simulator_and_quarantines_outer_package` scans a benign `Downloads\safe-simulator-editor-extension.vsix` fixture with `extension/assets/safe-eicar.txt` and quarantines only the outer VSIX because confirmed simulator signature evidence is present. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), focused native/local VSIX tests passed (`1` each), local-core `file_walker` passed (`7`), native `eicar_inside_` passed (`6`), native `archive` passed (`42`), local-core `quick_scan_reports` passed (`35`), and the full small-threat MVP verifier/report-validator passed (`157` steps in `361.6s`) for `.workflow\ultracode\avorax-hardening\results\2087-small-threat-mvp-full-report.json`. This does not install editor extensions, run extension JavaScript or native extension code, touch editor profiles, write inner entries to disk, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan XPI archive-entry signature coverage | `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching for safe small XPI entries using the existing ZIP-framed archive sampler, plus Quick Scan risky-carrier selection for `.xpi`, without extracting, installing, or executing archive contents | Native and local-core runtime fixture verified; installed E2E partial; browser extension manifest/API semantics, browser install behavior, encrypted/protected/unsupported archive content, non-ZIP-framed formats, and pre-execution blocking remain limited | Checkpoint 2086 extends archive-entry content scanning and Quick Scan risky selection from ZIP/JAR/APK carriers to `.xpi` browser-extension packages. Native proof `eicar_inside_xpi_entry_is_detected_without_extracting_archive` detects an in-memory `browser-extension.xpi::assets/eicar.txt` EICAR payload without extraction, installation, or execution. Local-core proof `quick_scan_reports_xpi_entry_safe_simulator_and_quarantines_outer_package` scans a benign `Downloads\safe-simulator-extension.xpi` fixture with `assets/safe-eicar.txt` and quarantines only the outer XPI because confirmed simulator signature evidence is present. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), focused native/local XPI tests passed (`1` each), local-core `file_walker` passed (`7`), native `eicar_inside_` passed (`5`), native `archive` passed (`41`), local-core `quick_scan_reports` passed (`34`), and the full small-threat MVP verifier/report-validator passed (`155` steps in `348.3s`) for `.workflow\ultracode\avorax-hardening\results\2086-small-threat-mvp-full-report.json`. This does not install browser extensions, run browser extension JavaScript, touch browser profiles, write inner entries to disk, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan APK archive-entry signature coverage | `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/scanner/file_walker.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching for safe small APK entries using the existing ZIP-framed archive sampler, plus Quick Scan risky-carrier selection for `.apk`, without extracting, installing, or executing archive contents | Native and local-core runtime fixture verified; installed E2E partial; Android/Dalvik/package semantics, encrypted/protected/unsupported archive content, non-ZIP-framed formats, and pre-execution blocking remain limited | Checkpoint 2085 extends archive-entry content scanning and Quick Scan risky selection from ZIP/JAR carriers to `.apk` packages. Native proof `eicar_inside_apk_entry_is_detected_without_extracting_archive` detects an in-memory `mobile-package.apk::assets/eicar.txt` EICAR payload without extraction, installation, or execution. Local-core proof `quick_scan_reports_apk_entry_safe_simulator_and_quarantines_outer_package` scans a benign `Downloads\safe-simulator-mobile.apk` fixture with `assets/safe-eicar.txt` and quarantines only the outer APK because confirmed simulator signature evidence is present. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), focused native/local APK tests passed (`1` each), local-core `file_walker` passed (`7`), native `eicar_inside_` passed (`4`), native `archive` passed (`40`), local-core `quick_scan_reports` passed (`33`), and the full small-threat MVP verifier/report-validator passed (`153` steps in `344.2s`) for `.workflow\ultracode\avorax-hardening\results\2085-small-threat-mvp-full-report.json`. This does not install APKs, run Android/Java/Dalvik code, execute class/dex files, write inner entries to disk, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan JAR archive-entry signature coverage | `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching for safe small JAR entries using the existing ZIP-framed archive sampler without extracting or executing archive contents | Native and local-core runtime fixture verified; installed E2E partial; Java execution/class analysis, encrypted/protected/unsupported archive content, non-ZIP-framed formats, and pre-execution blocking remain limited | Checkpoint 2084 extends archive-entry content scanning from `.zip` paths and nested `.zip` entries to `.jar` paths and nested `.jar` entries. Native proof `eicar_inside_jar_entry_is_detected_without_extracting_archive` detects an in-memory `support-library.jar::payload/eicar.txt` EICAR payload without extraction or execution. Local-core proof `jar_entry_safe_simulator_is_detected_and_outer_archive_quarantined` scans a benign `safe-simulator-library.jar` fixture with `payload/safe-eicar.txt` and quarantines only the outer JAR because confirmed simulator signature evidence is present. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), focused native/local JAR tests passed (`1` each), native `archive` passed (`39`), local-core safe simulator archive group passed (`3`), local-core `quick_scan_reports` passed (`32`), and the full small-threat MVP verifier/report-validator passed (`151` steps in `351.1s`) for `.workflow\ultracode\avorax-hardening\results\2084-small-threat-mvp-full-report.json`. This does not run Java, execute class files, write inner entries to disk, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan ZIP archive-entry rule/heuristic coverage | `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded local rule and heuristic evidence for safe sampled ZIP entries without extracting or executing archive contents | Native and local-core runtime fixture verified; installed E2E partial; encrypted/protected/unsupported archive content, non-ZIP formats, production false-positive evidence, and pre-execution blocking remain limited | Checkpoint 2081 renames the archive-entry engine helper to `archive_entry_detection_evidence`, runs sampled entry bytes through normal signature matching, local rule evaluation, and bounded heuristic scoring, and emits `Archived entry rule` plus `Archived entry heuristic` details with the full archive-entry path. Native proof covers an in-memory `script-archive.zip::scripts/dropper.ps1` fixture that produces `ps_encoded_download_exec` rule evidence and `download_execute_script` heuristic evidence without extraction or execution. Local-core proof covers inert `script-rule-archive.zip::scripts/dropper.ps1` evidence for product rule IDs such as `ZNE-RULE-PS-ENCODED-DOWNLOAD-EXEC` and `ZNE-RULE-SCRIPT-DOWNLOADER-002`, plus `encoded_script_command` and `download_execute_script`, while `AutoQuarantineConfirmedOnly` leaves the outer archive in place. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), focused native/local tests passed, native `archive` passed (`38`), and the full small-threat MVP verifier/report-validator passed (`147` steps in `346.8s`) for `.workflow\ultracode\avorax-hardening\results\2081-small-threat-mvp-full-report.json`. This is bounded in-memory ZIP entry static analysis only; it does not write inner entries to disk, execute nested files, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan nested ZIP archive-entry signature coverage | `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching through nested safe ZIP entries up to the configured archive-depth limit without extracting or executing archive contents | Native and local-core runtime fixture verified; installed E2E partial; encrypted/protected/unsupported nested archive content, non-ZIP formats, and pre-execution blocking remain limited | Checkpoint 2080 adds recursive native archive-entry signature evidence for sampled `.zip` entries, uses `max_archive_depth()` (`3`) as the nested ZIP limit, emits `archive_content_scan_limited` at depth exhaustion, includes archive-entry chains in signature evidence, and proves detection with an in-memory deflated nested EICAR ZIP plus local-core proof that inert `nested-safe-simulator-archive.zip` containing `archives/inner-safe.zip::payload/safe-eicar.txt` quarantines the outer archive in confirmed-only mode. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), native nested ZIP embedded-signature test passed (`1`), focused local-core nested archive-entry simulator scan passed (`1`), local-core direct+nested archive simulator scan passed (`2`), native `archive` passed (`37`), and the full small-threat MVP verifier/report-validator passed (`145` steps in `346.3s`) for `.workflow\ultracode\avorax-hardening\results\2080-small-threat-mvp-full-report.json`. This is bounded in-memory nested ZIP signature evidence only; it does not write inner entries to disk, execute nested files, treat encrypted/oversized/unsupported/deeper entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan ZIP archive-entry signature coverage | `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/scan/archive_scanner.rs`; `core/zentor_native_engine/src/engine.rs`; `core/zentor_native_engine/src/tests/mod.rs`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Bounded signature matching for safe small ZIP entries without extracting or executing archive contents | Native and local-core runtime fixture verified; installed E2E partial; encrypted/protected/unsupported archive content, non-ZIP formats, and pre-execution blocking remain limited | Checkpoint 2079 adds `bounded_zip_entry_samples`, explicit `64` entry / `1 MiB` per-entry / `4 MiB` total caps, archive scanner wiring, native engine `archive_entry_signature_evidence`, `archive_content_scan_limited` limit evidence, an in-memory EICAR ZIP detection test, and local-core Quick Scan proof that inert `safe-simulator-archive.zip` containing `payload/safe-eicar.txt` quarantines the outer archive in confirmed-only mode. Rust fmt/check passed for native-engine and local-core, source-contracts passed (`541`), native ZIP content sampling tests passed (`4`), native embedded ZIP signature test passed (`1`), focused local-core archive-entry simulator scan passed (`1`), native `archive` passed (`36`), and the full small-threat MVP verifier/report-validator passed (`143` steps in `340.3s`) for `.workflow\ultracode\avorax-hardening\results\2079-small-threat-mvp-full-report.json`. This is bounded in-memory ZIP entry signature evidence only; it does not write inner entries to disk, execute nested files, treat encrypted/oversized/unsupported entries as clean, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |
| Quick Scan ZIP shortcut executable bundle coverage | `core/zentor_native_engine/src/analyzers/archives/zip.rs`; `core/zentor_native_engine/src/analyzers/archives/mod.rs`; `core/zentor_native_engine/src/heuristics/scoring.rs`; `core/zentor_local_core/src/main.rs`; `tests/test_custom_driver_contract.py` | Review-only static detection for ZIP archives that contain a shortcut carrier entry and an executable/script companion entry | Runtime fixture verified; installed E2E partial; shortcut body parsing and archive payload extraction partial | Checkpoint 2078 adds `shortcut_entry_count`, `archive_shortcut_entry`, `archive_shortcut_executable_bundle`, native positive/negative fixtures for shortcut plus executable companion versus shortcut plus document-only companion, and local-core Quick Scan proof for an inert `shortcut-bundle.zip` fixture while confirmed-only auto-quarantine leaves it in place. Focused native/local tests passed, source-contracts passed (`541`), native `archive` passed (`31`), native `scoring` passed (`57`), local-core `quick_scan_reports` passed (`32`), and the full small-threat MVP verifier/report-validator passed (`140` steps in `333.8s`) for `.workflow\ultracode\avorax-hardening\results\2078-small-threat-mvp-full-report.json`. This is bounded ZIP entry-metadata review evidence only; it does not parse shortcut bodies, resolve shortcut targets, extract archives, execute nested files, inspect encrypted/protected archive content beyond existing fail-visible limits, parse non-ZIP archive formats, test live malware, prove installed UI/service E2E, or claim pre-execution blocking. |

## Checkpoint 2115/2116 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| No-EICAR release local-core harmless-threat validation smoke | `tools/testing/run-no-eicar-local-core-harmless-threat-smoke.ps1`; `tools/testing/run-release-local-core-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py`; `README.md`; `TESTING.md`; `docs/malware-protection.md` | Provide a user-safe local proof that Avorax release local-core can detect, quarantine, list, and restore a confirmed harmless exact-hash fixture without creating the standard EICAR string or weakening Microsoft Defender | Release-binary fixture and generated-report content verified; installed UI/service E2E, packaged Windows build, production false-positive rates, and pre-execution blocking remain partial or blocked | Checkpoint 2115 adds `run-no-eicar-local-core-harmless-threat-smoke.ps1`. The wrapper runs the existing release safe hash fixture smoke against `target/release/zentor_local_core.exe`, writes a repo-contained JSON report, and records `live_malware_used=false`, `standard_eicar_file_created=false`, `standard_eicar_string_written=false`, `defender_exclusion_required=false`, `machine_wide_changes=false`, and `network_access_required=false`. Focused validation passed locally in `1.4s` and wrote `.workflow/ultracode/avorax-hardening/results/2115-no-eicar-harmless-threat-smoke.json`, proving detect-only `threatsFound`, confirmed-only quarantine of harmless exact-hash fixture bytes, `.avoraxq` quarantine payload use, `list_quarantine` record evidence, and restore of the original fixture bytes. Checkpoint 2116 records the generated report in the full MVP JSON as `generated_reports.no_eicar_harmless_threat` and makes the report validator parse the generated report's schema, timestamps, repository, `run-release-local-core-smoke.ps1` path, verified flow, limits, and safety flags. A negative generated report with `defender_exclusion_required=true` failed validation. This is release local-core validation and report-honesty evidence only; it does not prove installed desktop UI click-through, installed service behavior, Windows filesystem notification coverage, signed-driver/pre-execution blocking, or packaged build output. |

Full-suite refresh: `.workflow/ultracode/avorax-hardening/results/2115-small-threat-mvp-full-report.json` passed with `192` steps in `500.6s`, including `release local-core binary no-EICAR harmless threat validation smoke` (`1.7s`) and final report validation.

Full-suite refresh: `.workflow/ultracode/avorax-hardening/results/2116-small-threat-mvp-full-report.json` passed with `192` steps in `499.0s`, including `release local-core binary no-EICAR harmless threat validation smoke` (`1.6s`) and final `-RequireFullSuite` report validation (`1.2s`). The generated no-EICAR report recorded `live_malware_used=false`, `standard_eicar_file_created=false`, `standard_eicar_string_written=false`, `defender_exclusion_required=false`, `machine_wide_changes=false`, and `network_access_required=false`.

## Checkpoint 2113 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Release local-core finite watch-poll scan/quarantine smoke | `core/zentor_local_core/src/main.rs`; `core/zentor_local_core/src/api/mod.rs`; `core/zentor_local_core/src/watcher/mod.rs`; `tools/testing/run-release-local-core-watch-poll-scan-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that a finite user-mode polling command can baseline accessible watch roots, observe a stable file created during the command, run normal scanning, and quarantine a confirmed safe exact-hash fixture while preserving explicit no-service/no-kernel/pre-execution limitations | Finite release-binary polling fixture verified; installed watcher/service E2E and signed-driver pre-execution blocking remain blocked/partial | Checkpoint 2113 adds bounded `watch_poll_scan` IPC with strict `duration_ms`, `poll_interval_ms`, and `max_events` validation plus watch candidate file-count/depth limits. The release smoke runs the built `target/release/zentor_local_core.exe` directly through JSON IPC with isolated data/quarantine/allowlist/engine roots; writes a temporary exact-hash pack for benign `harmless-watch-poll-known-bad-fixture` bytes; creates `created-during-watch.bin` after the finite polling command starts; and verifies `finiteUserModePolling`, `1` event observed, `1` file scanned, `1` threat found, `1` file quarantined, source removal, a listed quarantine record, and a `.avoraxq` payload. Focused parser checks, rustfmt check, local-core watcher Cargo tests (`13`), watch-poll command tests (`2`), release local-core build, focused release watch-poll smoke, source-contracts (`558`), old-report validator rejection, and the full small-threat MVP verifier/report-validator passed (`189` steps in `494.1s`) for `.workflow/ultracode/avorax-hardening/results/2113-small-threat-mvp-full-report.json`, including the new release watch-poll smoke (`4.7s`). This is finite watch-poll release-binary evidence only; it does not run persistent monitoring after command exit, install/start a Windows service, consume OS filesystem notification APIs, provide kernel realtime blocking, prove installed UI/service E2E, test live malware, or claim pre-execution blocking. |

## Checkpoint 2112 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Release local-core watcher honesty smoke | `core/zentor_local_core/src/watcher/mod.rs`; `apps/zentor_client/lib/app/app_state.dart`; `apps/zentor_client/lib/features/protection/protection_screen.dart`; `tools/testing/run-release-local-core-watcher-honesty-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof and UI/source guard that `start_watch` is represented as best-effort watch-root planning with explicit one-shot/no-service/no-kernel limitations, not as installed persistent realtime monitoring or pre-execution blocking | Release-binary fixture verified; installed watcher/service E2E and signed-driver pre-execution blocking remain blocked/partial | Checkpoint 2112 adds `one-shot-watch-plan-only`, `no-persistent-service-monitor`, and `no-kernel-pre-execution-blocking` limitations to local-core watch-plan responses, updates Flutter Protection wording to "watch roots prepared" / "watch plan" copy, and adds `run-release-local-core-watcher-honesty-smoke.ps1`. The smoke runs the built `target/release/zentor_local_core.exe` directly through JSON IPC; creates only temporary benign path fixtures; verifies `start_watch` keeps exactly one accessible directory, ignores a missing path, rejects a non-directory path with `unsafe-or-uninspectable-paths-ignored`, returns `userModeBestEffort` plus the explicit limitation set, verifies empty `start_watch` returns stopped plus `no-watch-paths-requested`, and verifies `stop_watch` returns stopped with no watched paths. Focused PowerShell parser checks, local-core watcher Cargo tests (`10`), Flutter watcher/UI subset (`8`), source-contracts (`557`), release local-core build, old-report validator rejection, and the focused release watcher smoke passed. The full small-threat MVP verifier plus report validator passed (`188` steps in `494.8s`) for `.workflow/ultracode/avorax-hardening/results/2112-small-threat-mvp-full-report.json`, including the new release watcher honesty smoke (`0.6s`). This is watcher honesty and release-binary IPC evidence only; it does not run a persistent watcher process, install or start a Windows service, provide kernel realtime blocking, prove installed UI/service E2E, test live malware, or claim pre-execution blocking. |

## Checkpoint 2111 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Release local-core allowlist confirmed-fixture no-quarantine smoke | `tools/testing/run-release-local-core-allowlist-honored-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Release-binary proof that an explicit user allowlist entry suppresses confirmed-only auto-quarantine for a matching confirmed safe exact-hash detection while keeping the detection visible as allowlisted evidence | Release-binary fixture verified; installed UI/service E2E partial; production false-positive rates and replacement-race/symlink behavior on an installed host remain limited | Checkpoint 2111 adds `run-release-local-core-allowlist-honored-smoke.ps1`. The smoke uses isolated process-local data, legacy-data, quarantine, allowlist, and engine roots; writes a valid empty allowlist JSON array; writes a temporary exact-hash signature pack for benign `harmless-known-bad-allowlisted-fixture` bytes; adds the fixture through local-core JSON `add_allowlist_entry`; verifies `list_allowlist` persisted an active `sha256:<hex>` record; invokes JSON `scan_file` with `scan_kind=custom` and `AutoQuarantineConfirmedOnly`; then verifies `threatsFound`, one scanned file, one allowlisted confirmed detection, `recommended_action=allowlist`, zero scan errors, zero quarantined files, no quarantine ID/path on the threat, unchanged source bytes, empty quarantine records, and no `.avoraxq` payloads. The full verifier and report validator now require `release local-core binary allowlist confirmed-fixture no-quarantine smoke`, and the old 2110 report fails validation because it lacks that step. Focused smoke, PowerShell parser checks, source-contracts passed (`556`), and the full small-threat MVP verifier/report-validator passed (`187` steps in `740.2s`) for `.workflow/ultracode/avorax-hardening/results/2111-small-threat-mvp-full-report.json`, including the new release allowlist honored smoke (`1.7s`). This is safe release-binary allowlist behavior evidence only; it does not use EICAR or live malware, disable or weaken Windows Defender, prove installed UI/service E2E, prove production false-positive rates, or claim pre-execution blocking. |

## Checkpoint 2132 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Client UI inventory source gate | `tools/testing/validate-client-ui-inventory.py`; `docs/client-ui.md`; `apps/zentor_client/lib/app/router.dart`; `apps/zentor_client/lib/shared/widgets/zentor_sidebar.dart`; `apps/zentor_client/lib/shared/widgets/zentor_bottom_nav.dart`; `apps/zentor_client/lib/features/**`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Fail the small-threat MVP verifier when a documented route, navigation item, high-risk button, setting, custom control, verification status, empty state, or technical limitation drifts away from the Flutter source inventory | Source-accounted and full-suite verified; packaged desktop click-through, OS picker/elevation/toast behavior, installed local-core/service E2E, and signed-driver/pre-execution behavior remain partial or blocked | Checkpoint 2132 adds a dependency-free Python gate that verifies `11` router routes, `9` desktop sidebar destinations, `4` mobile bottom-nav destinations, Control Matrix row shape/status fields, required limitation/empty-state markers, and `61` source-accounted controls across Home, Scan, Protection, Quarantine, Allowlist, Security Events, Settings, Updates, Protected Apps, Onboarding, and Privacy. The small-threat MVP verifier runs `Client UI inventory source gate`, and the report validator requires that step plus `client UI tab/button/setting source inventory gate` scope for full-suite reports. Focused validation, parser checks, source-contracts (`568`), and the full small-threat MVP verifier/report-validator passed (`204` steps in `924.7s`) for `.workflow/ultracode/avorax-hardening/results/2132-small-threat-mvp-client-ui-inventory-report.json`; a report with the UI inventory step removed failed validation with `passed full-suite report is missing required step: Client UI inventory source gate`. This proves source/documentation accountability only; it does not click through an installed packaged Windows app, render OS picker/elevation/toast dialogs, prove installed service IPC, use live malware, or claim pre-execution blocking. |

## Checkpoint 2133 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Local scan wrapper release-binary smoke | `tools/windows/avorax-local-scan.ps1`; `tools/testing/run-avorax-local-scan-wrapper-smoke.ps1`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide a safe user-facing local command path for `Quick`, `Full`, `File`, and `Folder` scans over the release local-core binary, with detect-only default, explicit confirmed-quarantine opt-in, repo-contained JSON evidence, bounded path validation, and visible refusal of broad default-root auto-quarantine | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, persistent realtime monitoring, signed-driver pre-execution behavior, and production false-positive rates remain partial or blocked | Checkpoint 2133 adds `tools/windows/avorax-local-scan.ps1`. The wrapper invokes `target/release/zentor_local_core.exe` through redirected JSON stdin/stdout, rejects empty/NUL/oversized/missing/reparse targets, writes reports atomically under the repository, restores process environment overrides, defaults to `detectOnly`, and rejects `-AutoQuarantineConfirmed` without explicit `-Path` targets. The smoke creates only harmless exact-hash fixture bytes plus an isolated temporary `avorax_core.asig` signature pack; proves detect-only reports a threat with `0` quarantines and preserved source file; proves explicit confirmed quarantine removes only the matching harmless fixture; and proves broad Quick auto-quarantine without explicit paths fails visibly. Parser checks, focused wrapper smoke, source-contracts (`570`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`205` steps in `912.8s`) for `.workflow/ultracode/avorax-hardening/results/2133-small-threat-mvp-local-scan-wrapper-report.json`, including `Local scan wrapper release-binary smoke` (`4.1s`). This is safe release-binary local scan/quarantine proof only; it does not install or start services, weaken Defender, use standard EICAR by default, use live malware, provide persistent background monitoring, prove installed UI/service E2E, or claim pre-execution blocking. |

## Checkpoint 2134 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Watch scan wrapper finite release-binary smoke | `tools/windows/avorax-watch-scan.ps1`; `tools/testing/run-avorax-watch-scan-wrapper-smoke.ps1`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide a safe user-facing finite watch-scan command path over release local-core `watch_poll_scan` for explicit directories, with detect-only default, confirmed quarantine opt-in, bounded duration/poll/event limits, broad-root and reparse-point refusal, repo-contained JSON evidence, and explicit no-service/no-kernel/no-pre-execution limitations | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service/background monitoring E2E, scheduled startup, signed-driver pre-execution behavior, and production false-positive rates remain partial or blocked | Checkpoint 2134 adds `tools/windows/avorax-watch-scan.ps1`. The wrapper invokes `target/release/zentor_local_core.exe` through redirected JSON stdin/stdout/stderr, requires at least one explicit watched directory, rejects broad roots and reparse targets, bounds `DurationSeconds` to `1..10`, `PollIntervalMilliseconds` to `50..2000`, and `MaxEvents` to `1..32`, writes reports atomically under the repository, defaults to `detectOnly`, and only quarantines with explicit `-AutoQuarantineConfirmed`. The smoke creates only harmless exact-hash fixture bytes plus an isolated temporary `avorax_core.asig` signature pack; proves finite detect-only watch scanning reports a created fixture with `0` quarantines and preserved source file; proves explicit confirmed quarantine removes only the matching harmless fixture; and proves missing `-Path` fails visibly. Parser checks, focused wrapper smoke, source-contracts (`572`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`206` steps in `638.5s`) for `.workflow/ultracode/avorax-hardening/results/2134-small-threat-mvp-watch-scan-wrapper-report.json`, including `Watch scan wrapper finite release-binary smoke` (`9.9s`). This is finite safe release-binary user-mode polling proof only; it does not install/start a service, weaken Defender, use standard EICAR by default, use live malware, provide persistent background monitoring, prove installed UI/service E2E, or claim pre-execution/kernel blocking. |

## Checkpoint 2135 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Release host prerequisite ready-or-blocked evidence gate | `tools/windows/avorax-release-prereq-check.ps1`; `tools/testing/run-release-prereq-host-evidence.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py`; `.workflow/ultracode/avorax-hardening/results/small-threat-mvp-release-prereq-host.json` | Make Windows release-host readiness a mandatory generated report in the small-threat MVP evidence, while accepting a blocked host only when concrete actionable prereq errors are recorded and release packaging claims remain disabled | Full-suite verifier wiring verified; current host remains blocked for release packaging by missing .NET SDK inventory, unavailable Windows symlink support, and missing Visual Studio Desktop C++ components | Checkpoint 2135 adds `tools/testing/run-release-prereq-host-evidence.ps1` and wires `Release host prerequisite ready-or-blocked evidence` into the verifier before dependency evidence. The wrapper runs the host-only prereq check with explicit local paths, validates `mode=host_only`, repo-contained report activation, required check/status rows, and actionable blocker text, and does not install tools, enable Developer Mode, weaken Defender, change Windows settings, or create release artifacts. The generated report records `ok=false` on this host with `.NET SDK inventory` failed (`dotnet.exe` exists but no SDKs), `Windows symlink support` failed (`Administrator privilege required for this operation.`), and `Visual Studio Desktop C++ components` failed (`Flutter doctor reports missing components`). Parser checks, focused wrapper execution, source-contracts (`573`), a short wiring verifier (`11` steps in `32.5s`), negative report validation, and the full small-threat MVP verifier/report-validator passed (`207` steps in `576.5s`) for `.workflow/ultracode/avorax-hardening/results/2135-small-threat-mvp-release-prereq-host-report.json`, including the prereq evidence step (`9.3s`). This is release-host evidence hygiene only; it does not produce Windows `Avorax.exe`, MSI/installer stage, installed UI/service E2E, signed-driver/pre-execution validation, or full release-host SBOM/license output. |

## Checkpoint 2136 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Quarantine wrapper release-binary smoke | `tools/windows/avorax-quarantine.ps1`; `tools/testing/run-avorax-quarantine-wrapper-smoke.ps1`; `tools/windows/avorax-local-scan.ps1`; `core/zentor_local_core/src/main.rs`; `core/zentor_local_core/src/quarantine/quarantine_store.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide a safe user-facing release-binary command path for quarantine `List`, confirmed `Restore`, and confirmed `Delete`, with local-core IPC, quarantine-ID validation, explicit confirmation, repo-contained JSON evidence, and no secure-erase or pre-execution claims | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, signed-driver pre-execution behavior, production false-positive rates, release packaging, and secure deletion remain partial, blocked, or not claimed | Checkpoint 2136 adds `tools/windows/avorax-quarantine.ps1`. The wrapper resolves `target/release/zentor_local_core.exe`, rejects reparse binaries/roots, validates quarantine IDs before IPC, requires `-ConfirmAction` for restore/delete, invokes `list_quarantine`, `restore_quarantine_item`, and `delete_quarantine_item` through redirected JSON stdin/stdout/stderr, writes atomic repo-contained reports, restores environment overrides, and records safety flags including `secure_erase_claimed=false`. The smoke creates only harmless exact-hash fixture bytes and an isolated temporary signature pack, creates quarantined records via `avorax-local-scan.ps1`, proves list visibility, proves restore without confirmation fails visibly, proves confirmed restore recreates the original bytes, and proves confirmed delete removes the quarantined payload without restoring the original. Parser checks, focused wrapper smoke, source-contracts (`575`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`208` steps in `587.8s`) for `.workflow/ultracode/avorax-hardening/results/2136-small-threat-mvp-quarantine-wrapper-report.json`, including `Quarantine wrapper release-binary smoke` (`3.9s`). This is safe release-binary quarantine management proof only; it does not install/start services, weaken Defender, use standard EICAR by default, use live malware, prove installed UI/service E2E, claim pre-execution/kernel blocking, or promise secure deletion on SSDs. |

## Checkpoint 2137 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Allowlist wrapper release-binary smoke | `tools/windows/avorax-allowlist.ps1`; `tools/testing/run-avorax-allowlist-wrapper-smoke.ps1`; `tools/windows/avorax-local-scan.ps1`; `core/zentor_local_core/src/main.rs`; `core/zentor_local_core/src/allowlist/allowlist_store.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide a safe user-facing release-binary command path for file allowlist `List`, confirmed `Add`, and confirmed `Remove`, with explicit persistence through a checked allowlist file, local-core IPC, confirmation-gated trust changes, repo-contained JSON evidence, and no broad-root/pre-execution claims | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, folder/hash wrapper support, replacement-race/symlink behavior on an installed host, signed-driver pre-execution behavior, and production false-positive rates remain partial or blocked | Checkpoint 2137 adds `tools/windows/avorax-allowlist.ps1`. The wrapper resolves `target/release/zentor_local_core.exe`, validates target files and allowlist IDs before IPC, initializes a repo/temp-scoped allowlist file with an empty JSON array when needed, requires `-ConfirmAction` for add/remove, invokes `list_allowlist`, `add_allowlist_entry`, and `remove_allowlist_entry` through redirected JSON stdin/stdout/stderr, writes atomic repo-contained reports, restores `ZENTOR_ALLOWLIST_FILE`, and records safety flags for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no pre-execution blocking claim, no broad-root allowlist, and no folder/hash wrapper support. The smoke creates only harmless exact-hash fixture bytes and an isolated temporary signature pack, proves add/remove without confirmation fail visibly, proves confirmed add/list persists an active `sha256:<hex>` file allowlist entry, proves a confirmed-only local scan reports the matching fixture as allowlisted with `0` quarantines and preserved source bytes, proves confirmed remove marks the entry inactive, and proves a post-remove confirmed scan quarantines the same harmless fixture. Parser checks, focused wrapper smoke, source-contracts (`577`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`209` steps in `584.4s`) for `.workflow/ultracode/avorax-hardening/results/2137-small-threat-mvp-allowlist-wrapper-report.json`, including `Allowlist wrapper release-binary smoke` (`4s`). This is safe release-binary file-allowlist management proof only; it does not install/start services, weaken Defender, use standard EICAR by default, use live malware, prove installed UI/service E2E, support folder/hash allowlist entries through this wrapper, or claim pre-execution/kernel blocking. |

## Checkpoint 2138 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Status wrapper release-binary smoke | `tools/windows/avorax-status.ps1`; `tools/testing/run-avorax-status-wrapper-smoke.ps1`; `core/zentor_local_core/src/main.rs`; `core/zentor_local_core/src/protection/guard_service.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide a safe user-facing release-binary health/status command path that validates local-core health JSON, records readiness as `ready`, `degraded`, or `unavailable`, exposes concrete blockers, and refuses fake readiness through `-RequireReady` | Release-binary wrapper and full-suite verified; installed service/driver health E2E, persistent monitoring, pre-execution blocking, production ML readiness, and packaged UI click-through remain partial or blocked | Checkpoint 2138 adds `tools/windows/avorax-status.ps1`. The wrapper resolves `target/release/zentor_local_core.exe`, optionally sets a checked `AVORAX_ENGINE_DIR`, invokes local-core `health` through redirected JSON stdin/stdout/stderr, validates required response fields, writes atomic repo-contained reports, restores environment overrides, and records safety flags for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no pre-execution blocking claim, no persistent-monitoring claim, no kernel-driver claim, and no trusted network content. The smoke creates only harmless exact-hash fixture bytes and an isolated temporary signature pack, proves the release binary reports the temp engine as available with `native_signature_count>=1`, records incomplete readiness as `health_state=degraded` instead of ready, keeps `ipc=stdio` and `network_exposed=false`, records `driver_status=missing`, and proves `-RequireReady` fails visibly on the incomplete temp engine. Parser checks, focused wrapper smoke, source-contracts (`579`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`210` steps in `590.4s`) for `.workflow/ultracode/avorax-hardening/results/2138-small-threat-mvp-status-wrapper-report.json`, including `Status wrapper release-binary smoke` (`1.7s`). This is release-binary status/health proof only; it does not install/start/repair services, run a persistent monitor, prove signed-driver IPC, claim pre-execution/kernel blocking, or mark production ML ready. |

## Checkpoint 2139 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Quarantine wrapper rescan/restore/delete release-binary smoke | `tools/windows/avorax-quarantine.ps1`; `tools/testing/run-avorax-quarantine-wrapper-smoke.ps1`; `tools/windows/avorax-local-scan.ps1`; `core/zentor_local_core/src/main.rs`; `core/zentor_local_core/src/quarantine/quarantine_store.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide a safe user-facing release-binary command path for quarantine `List`, detect-only `Rescan`, confirmed `Restore`, and confirmed `Delete`, with quarantine-ID validation, payload path validation, repo-contained JSON evidence, and visible refusal of mutation during rescan | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, signed-driver pre-execution behavior, production false-positive rates, release packaging, and secure deletion remain partial, blocked, or not claimed | Checkpoint 2139 extends `tools/windows/avorax-quarantine.ps1` with `Rescan`. The wrapper rejects `-ConfirmAction` for rescan, requires the selected record to remain `quarantined`, resolves only an existing absolute `.avoraxq` payload, rejects reparse payloads, keeps payloads under the checked quarantine root, invokes local-core `scan_file` with `scan_kind=custom` and `action_mode=detectOnly`, records rescan status/counts/raw scan evidence, and keeps restore/delete confirmation-gated. The smoke creates only harmless exact-hash fixture bytes and an isolated temporary signature pack, proves list `records_count=1`, proves rescan with confirmation fails visibly, proves detect-only rescan reports `threatsFound`, `1` scanned file, at least `1` threat, `0` quarantines, no restore/delete during rescan, and preserved `.avoraxq` payload, then proves confirmed restore and confirmed delete. Parser checks, focused wrapper smoke, source-contracts (`579`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`210` steps in `580.1s`) for `.workflow/ultracode/avorax-hardening/results/2139-small-threat-mvp-quarantine-rescan-wrapper-report.json`, including `Quarantine wrapper release-binary smoke` (`4.9s`). This is safe release-binary quarantine rescan/restore/delete proof only; it does not install/start services, weaken Defender, use standard EICAR by default, use live malware, prove installed UI/service E2E, claim pre-execution/kernel blocking, or promise secure deletion on SSDs. |

## Checkpoint 2140 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Local scan wrapper progress/quarantine release-binary smoke | `tools/windows/avorax-local-scan.ps1`; `tools/testing/run-avorax-local-scan-wrapper-smoke.ps1`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide release-binary proof that the local scan wrapper surfaces progress-event evidence for Quick scans while preserving detect-only defaults, explicit confirmed-quarantine opt-in, repo-contained JSON evidence, and visible refusal of broad default-root auto-quarantine | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, external cancellation E2E, persistent realtime monitoring, signed-driver pre-execution behavior, and production false-positive rates remain partial or blocked | Checkpoint 2140 extends `tools/testing/run-avorax-local-scan-wrapper-smoke.ps1` with a progress proof over `target/release/zentor_local_core.exe`. The smoke uses only harmless exact-hash fixture bytes and an isolated temporary signature pack, runs `avorax-local-scan.ps1 -ScanType Quick -Path <fixture>` in detect-only mode, and verifies `command=quick_scan_selected_paths`, `scan_kind=quick`, `action_mode=detectOnly`, `progress_events>=2`, `files_scanned>=1`, `threats_found>=1`, `quarantined_files=0`, and preserved source bytes. It also keeps the previous detect-only File scan, explicit confirmed quarantine, and negative broad Quick auto-quarantine guard. Parser checks, focused wrapper smoke, source-contracts (`579`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`210` steps in `584.3s`) for `.workflow/ultracode/avorax-hardening/results/2140-small-threat-mvp-local-scan-progress-wrapper-report.json`, including `Local scan wrapper release-binary smoke` (`3.2s`). This is safe release-binary local scan progress/quarantine proof only; it does not install/start services, weaken Defender, use live malware, prove packaged UI/service E2E, prove external cross-process cancellation, provide persistent background monitoring, or claim pre-execution/kernel blocking. |

## Checkpoint 2141 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Cancel scan wrapper release-binary smoke | `tools/windows/avorax-cancel-scan.ps1`; `tools/testing/run-avorax-cancel-scan-wrapper-smoke.ps1`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide a safe user-facing release-binary command path for cooperative scan cancellation, with explicit isolated/installed runtime selection, checked cancel-token path validation, repo-contained JSON evidence, and no service/process-kill/pre-execution claims | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service cross-process cancellation E2E, persistent realtime monitoring, signed-driver pre-execution behavior, and production false-positive rates remain partial or blocked | Checkpoint 2141 adds `tools/windows/avorax-cancel-scan.ps1`. The wrapper resolves `target/release/zentor_local_core.exe`, requires `-DataRoot` for isolated proof or explicit `-UseInstalledDataRoot` for an installed runtime, rejects both together, invokes local-core `cancel_scan` through redirected JSON stdin/stdout/stderr, validates the absolute `cancel-active-scan` token path, proves isolated tokens stay under `DataRoot/runtime`, writes atomic repo-contained reports, restores `AVORAX_DATA_DIR`, and records safety fields for no live malware, no standard EICAR string, no Defender exclusion, no machine-wide component install, no service install, no external process kill, no persistent monitoring, and no pre-execution/kernel blocking claim. The smoke uses an isolated temp data root, proves token creation and negative guards for missing/mutually exclusive data-root selection, and records `cancel-scan-wrapper-request.json`. Parser checks, focused wrapper smoke, source-contracts (`580`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`211` steps in `650.3s`) for `.workflow/ultracode/avorax-hardening/results/2141-small-threat-mvp-cancel-scan-wrapper-report.json`, including `Cancel scan wrapper release-binary smoke` (`1.2s`). This is cooperative cancel-token request proof only; scan-loop observation is covered by local-core cancellation regressions, while installed UI/service cancellation E2E and pre-execution/kernel blocking remain partial or blocked. |

## Checkpoint 2142 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Quarantine wrapper manual/rescan/restore/delete release-binary smoke | `tools/windows/avorax-quarantine.ps1`; `tools/testing/run-avorax-quarantine-wrapper-smoke.ps1`; `tools/windows/avorax-local-scan.ps1`; `core/zentor_local_core/src/main.rs`; `core/zentor_local_core/src/quarantine/quarantine_store.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Provide a safe user-facing release-binary command path for manual quarantine, list, detect-only rescan, confirmed restore, and confirmed delete, with target-path validation, confirmation-gated destructive actions, repo-contained JSON evidence, and no secure-erase or pre-execution claims | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, signed-driver pre-execution behavior, production false-positive rates, release packaging, and secure deletion remain partial, blocked, or not claimed | Checkpoint 2142 extends `tools/windows/avorax-quarantine.ps1` with `Quarantine`. The wrapper requires `-TargetPath` and `-ConfirmAction`, rejects `-QuarantineId` for manual quarantine, validates the target as an existing non-reparse leaf file, bounds `-ThreatName` and `-Engine` text before IPC, invokes local-core `quarantine_file` through redirected JSON stdin/stdout/stderr, writes atomic repo-contained reports, restores environment overrides, and records `manual_quarantine_requires_confirmation=true`. The smoke creates only harmless exact-hash fixture bytes and isolated temporary roots, proves manual quarantine without confirmation fails visibly and preserves the source, proves confirmed manual quarantine records `status=quarantined`, `action_taken=quarantined`, preserved threat/engine labels, source removal, and `.avoraxq` payload creation, then keeps list/rescan/restore/delete coverage. Parser checks, focused wrapper smoke, source-contracts (`580`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`211` steps in `592.3s`) for `.workflow/ultracode/avorax-hardening/results/2142-small-threat-mvp-manual-quarantine-wrapper-report.json`, including `Quarantine wrapper release-binary smoke` (`5.9s`). This is safe release-binary manual quarantine management proof only; it does not install/start services, weaken Defender, use standard EICAR by default, use live malware, prove installed UI/service E2E, claim pre-execution/kernel blocking, or promise secure deletion on SSDs. |
| Manual quarantine UI/controller/IPC guards | `apps/zentor_client/lib/features/quarantine/quarantine_screen.dart`; `apps/zentor_client/lib/app/app_state.dart`; `apps/zentor_client/lib/core/local_core/local_core_client.dart`; `apps/zentor_client/test/quarantine_screen_test.dart`; `apps/zentor_client/test/offline_scan_test.dart`; `apps/zentor_client/test/local_core_ipc_diagnostics_test.dart`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py`; `docs/client-ui.md` | Provide a real Quarantine tab `Quarantine file` control that requires confirmation before file selection, refuses scan/configuration/update/quarantine busy states, sends explicit local-core `quarantine_file` labels, and refreshes quarantine state without fake success | Widget/controller/IPC and full-suite verified; installed packaged filesystem picker click-through, installed service mediation, signed-driver pre-execution behavior, production false-positive rates, release packaging, and secure deletion remain partial, blocked, or not claimed | Checkpoint 2143 adds `Quarantine file` to the Flutter Quarantine tab and `quarantineSelectedFile({bool confirmed = false})` to the controller. The controller refuses unconfirmed requests before opening the picker, refuses unsupported platforms and busy scan/configuration/update/quarantine states, clears target-selection state on picker cancel, surfaces picker/IPC failures, sends `threat_name=Manual quarantine` and `engine=avorax-ui-manual-quarantine` through `LocalCoreClient.quarantineFile`, logs `manual_file_quarantined`, and refreshes quarantine state on success. Widget/controller tests cover cancel/confirm, picker counts, busy/update blocking, normalized errors, and quarantine refresh; IPC diagnostics assert the exact `quarantine_file` payload. Parser checks, focused Flutter tests, source-contracts (`580`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`212` steps in `597.1s`) for `.workflow/ultracode/avorax-hardening/results/2143-small-threat-mvp-manual-quarantine-ui-report.json`, including `Flutter manual quarantine IPC tests` (`3.6s`), `Flutter quarantine controller tests` (`3.8s`), and `Flutter quarantine screen tests` (`5.1s`). This is UI/controller/IPC evidence over the existing release-binary quarantine backend; it does not install/start services, weaken Defender, use live malware, prove installed packaged file-picker click-through, claim pre-execution/kernel blocking, or promise secure deletion on SSDs. |

| Shell notification priority guards | `apps/zentor_client/lib/shared/widgets/zentor_shell.dart`; `apps/zentor_client/test/navigation_accessibility_test.dart`; `apps/zentor_client/test/app_visual_policy_test.dart`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py`; `docs/client-ui.md` | Keep in-app security notifications visible by ranking recent local events as error, warning, then info, with newest-event tie-breaking only inside the same priority | Widget/source and full-suite verified; installed packaged click-through and Windows toast delivery remain partial or not claimed | Checkpoint 2144 changes `ZentorShell` notification selection from newest/first notification event to highest-priority recent event. Focused widget tests cover an older `threat_detected` warning staying visible over a newer `scan_completed` info event, and newest warning selection when priorities tie. Source contracts pin the bounded recent-event window, priority helper, widget fixtures, verifier step, validator step, and verified scope. The full small-threat MVP verifier/report-validator passed with `213` report steps in `606.9s` for `.workflow\ultracode\avorax-hardening\results\2144-small-threat-mvp-shell-notification-priority-report.json`, including `Flutter shell notification priority tests` (`4s`). Negative evidence in `.workflow\ultracode\avorax-hardening\results\2144-shell-notification-priority-negative-validator.txt` proves a report missing that step is rejected. This is in-app local-event notification evidence only; it does not claim OS toast delivery, installed UI automation, persistent service monitoring, pre-execution blocking, or live-malware behavior. |

## Checkpoint 2145 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Local scan wrapper folder/fail-on-threat release-binary smoke | `tools/windows/avorax-local-scan.ps1`; `tools/testing/run-avorax-local-scan-wrapper-smoke.ps1`; `core/zentor_local_core/src/main.rs`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py`; `TESTING.md`; `docs/audit/threat-model.md` | Provide release-binary proof that explicit `Folder` scans can quarantine a known-bad harmless fixture without removing benign neighboring files, and that `-FailOnThreat` returns failure semantics while preserving detect-only behavior and repo-contained JSON evidence | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, external cancellation E2E, persistent realtime monitoring, signed-driver pre-execution behavior, production false-positive rates, and release packaging remain partial or blocked | Checkpoint 2145 extends `tools/testing/run-avorax-local-scan-wrapper-smoke.ps1` with folder and fail-on-threat proof over `target/release/zentor_local_core.exe`. The smoke uses only harmless exact-hash fixture bytes, a benign text fixture, and an isolated temporary signature pack. `local-scan-wrapper-folder-quarantine.json` records `status=threatsFound`, `command=scan_folder`, `scan_kind=custom`, `action_mode=autoQuarantineConfirmedOnly`, `files_scanned=2`, `threats_found=1`, and `quarantined_files=1`, with the threat fixture removed and the benign fixture preserved. `local-scan-wrapper-fail-on-threat.json` records `status=threatsFound`, `action_mode=detectOnly`, `files_scanned=1`, `threats_found=1`, and `quarantined_files=0`, while the wrapper returns a visible failure and keeps the source file. Parser checks, focused wrapper smoke, source-contracts (`580`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`213` steps in `609.7s`) for `.workflow/ultracode/avorax-hardening/results/2145-small-threat-mvp-local-scan-folder-failon-report.json`, including `Local scan wrapper release-binary smoke` (`5.2s`). This is safe release-binary local scan wrapper proof only; it does not install/start services, weaken Defender, use live malware, prove packaged UI/service E2E, provide persistent background monitoring, or claim pre-execution/kernel blocking. |

## Checkpoint 2146 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Local scan wrapper path/report guard release-binary smoke | `tools/windows/avorax-local-scan.ps1`; `tools/testing/run-avorax-local-scan-wrapper-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py`; `TESTING.md`; `docs/audit/threat-model.md` | Provide release-binary proof that invalid wrapper inputs fail visibly before scan execution or report creation, and that wrapper evidence remains repo-contained | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, external cancellation E2E, persistent realtime monitoring, signed-driver pre-execution behavior, production false-positive rates, and release packaging remain partial or blocked | Checkpoint 2146 extends `tools/testing/run-avorax-local-scan-wrapper-smoke.ps1` with path/report guard proof over `target/release/zentor_local_core.exe`. The smoke writes `local-scan-wrapper-path-guards.json` with `status=passed`, three checked cases, and safety fields showing no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, and no pre-execution claim. The checked cases prove missing scan targets fail with `Scan target does not exist` and no scan report, `File` scans pointed at folders fail with `File scan target is not a file` and no scan report, and absolute report paths outside the repository fail with `Avorax local scan report must be inside the repository` and no outside report. Parser checks, focused wrapper smoke, source-contracts (`580`), negative full-suite report validation, standalone report validation, and the full small-threat MVP verifier/report-validator passed (`213` steps in `647.7s`) for `.workflow/ultracode/avorax-hardening/results/2146-small-threat-mvp-local-scan-path-guards-report.json`, including `Local scan wrapper release-binary smoke` (`6.1s`). This is safe release-binary wrapper input-boundary proof only; it does not install/start services, weaken Defender, use live malware, prove packaged UI/service picker E2E, provide persistent background monitoring, or claim pre-execution/kernel blocking. |

## Checkpoint 2147 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Quarantine wrapper path/report guard release-binary smoke | `tools/windows/avorax-quarantine.ps1`; `tools/testing/run-avorax-quarantine-wrapper-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py`; `TESTING.md`; `docs/audit/threat-model.md` | Provide release-binary proof that unsafe quarantine wrapper inputs fail visibly before report creation or quarantine mutation, and that quarantine wrapper evidence remains repo-contained | Release-binary wrapper and full-suite verified; installed packaged UI click-through, installed service E2E, persistent realtime monitoring, signed-driver pre-execution behavior, production false-positive rates, release packaging, and secure deletion remain partial, blocked, or not claimed | Checkpoint 2147 extends `tools/testing/run-avorax-quarantine-wrapper-smoke.ps1` with path/report guard proof over `target/release/zentor_local_core.exe`. The smoke writes `quarantine-wrapper-path-guards.json` with `status=passed`, four checked cases, and safety fields showing no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no pre-execution claim, and no secure-erase claim. The checked cases prove missing manual quarantine targets and directory targets fail with `TargetPath must be an existing file` and no report, invalid quarantine IDs fail with `QuarantineId may contain only ASCII letters` and no report, and absolute report paths outside the repository fail with `Avorax quarantine report must be inside the repository` and no outside report. Parser checks, focused wrapper smoke, source-contracts (`580`), negative full-suite report validation, standalone report validation, and the full small-threat MVP verifier/report-validator passed (`213` steps in `760.7s`) for `.workflow/ultracode/avorax-hardening/results/2147-small-threat-mvp-quarantine-path-guards-report.json`, including `Quarantine wrapper release-binary smoke` (`7.8s`). This is safe release-binary quarantine wrapper input-boundary proof only; it does not install/start services, weaken Defender, use live malware, prove packaged UI/service E2E, provide persistent background monitoring, claim pre-execution/kernel blocking, or promise secure deletion on SSDs. |

## Checkpoint 2148 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Flutter timeout process-tree cleanup guards | `apps/zentor_client/lib/core/apps/app_detector.dart`; `apps/zentor_client/lib/core/platform/platform_info_service.dart`; `apps/zentor_client/lib/core/local_core/local_core_client.dart`; `apps/zentor_client/test/app_detector_test.dart`; `apps/zentor_client/test/platform_info_service_test.dart`; `apps/zentor_client/test/local_core_ipc_diagnostics_test.dart`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Clean up timed-out Avorax-spawned Windows helper process trees with bounded diagnostics so helper children do not remain running silently | Flutter runtime/source and full-suite verified; installed desktop/service subprocess E2E and Windows service supervision remain partial | Checkpoint 2148 adds checked `%SystemRoot%/System32/taskkill.exe` process-tree cleanup with `/PID <pid> /T /F` to app detection, platform PowerShell, local-core IPC, Guard self-test, cancel IPC, and elevated PowerShell timeout paths. Runtime tests inject sleeping Dart children and assert process exit after timeout. Focused timeout tests, full changed Flutter test files, Flutter analyze, parser checks, source-contracts (`580`), a post-run `remaining_timeout_fixture_processes=0` audit, and the full small-threat MVP verifier/report-validator passed (`214` steps in `836.9s`) for `.workflow/ultracode/avorax-hardening/results/2148-small-threat-mvp-timeout-process-tree-report.json`, including `Flutter timeout process-tree cleanup tests` (`6.1s`). Negative validation proves reports missing `Flutter timeout process-tree cleanup guards` are rejected. This is bounded cleanup for Avorax-spawned helper children only; it does not install/start services, weaken Defender, claim persistent monitoring, or claim kernel/pre-execution blocking. |
| Watch-smoke startup race hardening | `tools/testing/run-avorax-watch-scan-wrapper-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tests/test_custom_driver_contract.py`; `TESTING.md`; `docs/audit/threat-model.md` | Keep finite release-binary watcher smoke evidence event-based rather than accidentally baseline-only by allowing watcher startup before harmless fixture creation | Release-binary smoke and full-suite verified; installed background watcher/service E2E remains partial | Checkpoint 2148 changes the focused and verifier watch-smoke runs to `DurationSeconds=8` and waits `2500ms` before writing the harmless fixture. Focused detect and confirmed-quarantine reports record `initial_files_observed=0`, `events_observed=1`, `files_scanned=1`, `threats_found=1`, and expected quarantine counts. The full verifier's `Watch scan wrapper finite release-binary smoke` passed in `18.1s`. This strengthens finite user-mode polling evidence only; it does not claim scheduled startup, persistent service monitoring, kernel blocking, or pre-execution protection. |

## Checkpoint 2149 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Watch wrapper path/report guard release-binary smoke | `tools/windows/avorax-watch-scan.ps1`; `tools/testing/run-avorax-watch-scan-wrapper-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py`; `TESTING.md`; `docs/audit/threat-model.md` | Provide release-binary proof that invalid finite watch inputs fail visibly before watch polling or report creation, and that watch-wrapper evidence remains repo-contained | Release-binary wrapper and full-suite verified; installed background watcher/service E2E, scheduled startup, signed-driver pre-execution behavior, production false-positive rates, and release packaging remain partial or blocked | Checkpoint 2149 extends `tools/testing/run-avorax-watch-scan-wrapper-smoke.ps1` with path/report guard proof over `target/release/zentor_local_core.exe`. The smoke writes `watch-scan-wrapper-path-guards.json` with `status=passed`, five checked cases, and safety fields showing no live malware, no standard EICAR string, no Defender exclusion, no machine-wide changes, no service installation, no persistent-monitoring claim, no pre-execution claim, no kernel-driver requirement, and no broad default watch roots. The checked cases prove missing `-Path`, missing watched roots, file paths used as roots, broad filesystem roots, and absolute report paths outside the repository fail visibly and write no requested negative report. Parser checks, focused wrapper smoke, source-contracts (`580`), negative full-suite report validation, and the full small-threat MVP verifier/report-validator passed (`214` steps in `779.3s`) for `.workflow/ultracode/avorax-hardening/results/2149-small-threat-mvp-watch-path-guards-report.json`, including `Watch scan wrapper finite release-binary smoke` (`19.5s`). This is safe release-binary finite watcher input-boundary proof only; it does not install/start services, weaken Defender, use live malware, prove packaged UI/service E2E, provide persistent background monitoring, claim pre-execution/kernel blocking, or prove scheduled startup. |

## Checkpoint 2150 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Status wrapper path/report guard release-binary smoke | `tools/windows/avorax-status.ps1`; `tools/testing/run-avorax-status-wrapper-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Reject missing engine roots and repo-escaping report paths visibly before local-core health execution/report creation | Release-binary wrapper and full-suite verified; installed service/driver health and packaged UI E2E remain partial or blocked | `status-wrapper-path-guards.json` records two passed guard cases and zero negative reports written. Focused smoke and parser checks, source-contracts (`580`), negative scope validation, and the `214`-step full verifier passed in `1006.1s`; the status wrapper step passed in `2.7s`. This proves a local stdio release-binary boundary only and does not claim installed service, driver, kernel, or pre-execution protection. |
| Allowlist wrapper confirmation/path/report guard release-binary smoke | `tools/windows/avorax-allowlist.ps1`; `tools/testing/run-avorax-allowlist-wrapper-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Require explicit confirmation for add/remove, reject repo-escaping reports, and preserve the real add/list/scan/remove policy lifecycle | Release-binary wrapper and full-suite verified; installed packaged picker/service E2E and broader folder/hash wrapper support remain partial | `allowlist-wrapper-path-guards.json` records three passed guard cases and zero negative reports written. The positive smoke still proves an allowlisted known-bad harmless fixture is preserved, confirmed removal deactivates the entry, and a later confirmed-only scan quarantines it. The full verifier step passed in `6.3s`. No broad-root allowlisting, Defender exclusion, or machine-wide trust mutation is claimed. |
| Cancel-scan wrapper data-root/path/report guard release-binary smoke | `tools/windows/avorax-cancel-scan.ps1`; `tools/testing/run-avorax-cancel-scan-wrapper-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Require explicit isolated/installed data-root selection, reject conflicting roots and repo-escaping reports, and prevent cancellation token creation after rejected input | Release-binary cooperative-token wrapper and full-suite verified; installed UI/service cross-process cancellation E2E remains partial | `cancel-scan-wrapper-path-guards.json` records three passed guard cases, zero negative reports, and zero unexpected cancel tokens. The positive isolated-root case proves `cancel-active-scan` is written only under the selected data root; the full verifier step passed in `2.4s`. This is cooperative user-mode cancellation evidence only; it does not kill external processes or prove kernel/pre-execution blocking. |

## Checkpoint 2151 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Installed core structured health gate | `tools/windows/avorax-core-health-probe.ps1`; `tools/windows/avorax-installed-smoke-test.ps1`; `tools/windows/avorax-installer-stage-test.ps1`; `tools/testing/run-avorax-installed-core-health-probe-smoke.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Prevent fake installed-health success by requiring one bounded typed JSON health response, local stdio/no-network status, canonical/alias binary integrity, available/ready engine state, loaded packs, and a passing native self-test | Parser and release-binary runtime verified; actual staged/installed service and packaged UI E2E blocked by release-host prerequisites | The focused smoke rejects seven cases: non-JSON text containing `"ok":true`, a missing required field, explicit `ok=false`, multiple health responses, `network_exposed=true`, non-stdio IPC, and non-zero exit. It also probes `target/release/zentor_local_core.exe` and writes `installed-core-health-probe.json` while explicitly recording `installed_runtime_claimed=false`. The full small-threat MVP verifier/report-validator passed all `215` report steps in `1027.4s`, including `Installed smoke structured core-health probe tests` in `2.1s`; negative validation proves the step is mandatory. The installed smoke now requires canonical `zentor_local_core.exe`, a matching `avorax_core_service.exe` alias hash, no stderr, positive signature/rule counts, and native self-test success. No service installation, installed-runtime success, driver activation, or pre-execution claim is made on this host. |

## Checkpoint 2152 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Installed-core scan/quarantine/restore/delete lifecycle gate | `tools/windows/avorax-installed-core-lifecycle-probe.ps1`; `tools/windows/avorax-installed-smoke-test.ps1`; `tools/windows/avorax-installer-stage-test.ps1`; `tools/windows/avorax-local-scan.ps1`; `tools/windows/avorax-quarantine.ps1`; `tools/security/avorax-security-gate-tools.ps1`; `tools/testing/verify-small-threat-mvp.ps1`; `tools/testing/validate-small-threat-mvp-report.ps1`; `tests/test_custom_driver_contract.py` | Prevent installed-smoke fake success by requiring the canonical executable to complete a harmless exact-hash scan, `.avoraxq` quarantine, list, SHA-256-verified restore, second quarantine, confirmed delete, and bounded cleanup with independently validated evidence | Release-binary lifecycle runtime, installed-smoke/stage wiring, and full suite verified; actual staged/MSI install, installed service mediation, packaged UI click-through, and signed-driver/pre-execution behavior remain partial or blocked | The focused probe passes against `target/release/zentor_local_core.exe` and records five operation objects: `scan_restore`, `list`, `restore`, `scan_delete`, and `delete`. It proves both scan sources are removed, payload extensions are `.avoraxq`, list finds the first ID, restore reproduces the fixture SHA-256 and removes its payload, delete leaves source and payload absent, IDs are distinct, and the isolated temp root is removed. The report denies live malware, standard EICAR creation/string writes, network need, Defender exclusions, machine-wide changes, service/driver installation, installed service mediation, secure erase, and pre-execution blocking. Source contracts passed (`581`); tampered `restore.payload_removed=false` evidence was rejected; and the full verifier/report-validator passed `216` steps in `1092.7s`, including the lifecycle step in `3.8s` and final validation in `2.2s`. Host packaging remains blocked by no .NET SDK inventory, missing Visual Studio Desktop C++ components, and unavailable Windows symlink support. |

## Checkpoint 2153 Engine-Control Matrix Addendum

| Control / engine | Implementation surface | Intended behavior | Current status | Evidence / limitation |
| --- | --- | --- | --- | --- |
| Portable beta launcher | `tools/windows/avorax-portable-beta.ps1`; existing status/local-scan/watch/quarantine/allowlist wrappers; `docs/portable-beta.md` | Expose real manual scan, finite watch, quarantine, and allowlist actions from a fixed local bundle while containing state/reports and preserving visible failures | Portable runtime and source-contract verified; command-line/manual usability only | Launcher fixes the canonical executable and engine root to the bundle, keeps reports under the selected local data root, bounds watch to ten seconds, requires confirmation for destructive/trust mutations, and rejects degraded status or scan-error reports. It does not install, persist, replace Defender, or claim pre-execution blocking. |
| Portable beta package builder | `tools/windows/build-avorax-portable-beta.ps1`; `tools/windows/avorax-installed-core-lifecycle-probe.ps1`; `tools/security/avorax-security-gate-tools.ps1` | Build a reversible local ZIP from the verified release core and only required runtime engine assets, after ready and lifecycle proof, with a complete hash manifest | Verified for local artifact `0.1.0-beta.1`; distribution authenticity blocked because ZIP is unsigned | Final disclaimer build passed in `5.715s`, recording `39` manifested files, `13` signatures, `9` rules, native self-test, stdio/no-network operation, restore hash equality, payload removal, and delete postconditions. Output ZIP SHA-256 is `a80155373a869576dad6d015c21221a18815bf3318a253a11c19477af128240b`. No machine-wide mutation, service, driver, Defender exclusion, persistence, live malware, or pre-execution claim was made. |
| Portable extracted-archive integrity/adversarial smoke | `tools/testing/run-avorax-portable-beta-smoke.ps1`; `tests/test_custom_driver_contract.py` | Treat the final ZIP as untrusted, enforce bounded safe extraction and exact manifest inventory, then prove the extracted copy still reports ready and completes quarantine restore/delete | Verified for current local ZIP; production signing and installer/UI E2E remain blocked or separate | Final smoke passed in `5.957s` with `40` ZIP entries and `39` manifested files. It limits entries to `512`, each entry to `256 MiB`, total declared expansion to `512 MiB`, and compression ratio to `1000`; it rejects parent traversal, case-insensitive duplicates, excessive compression ratio, and a tampered manifest hash. Extracted status/lifecycle and cleanup passed. Source contracts passed `582` tests. |

## Disabled, Blocked, and Technical Limits

| Area | Classification | Required before claiming more |
| --- | --- | --- |
| Live malware validation | Disabled by policy | Use only EICAR and benign fixtures/mocks; never download, execute, unpack, or retain live malware |
| ClamAV/YARA compatibility | Disabled by default | Explicit feature/config, absolute/bundled scanner paths, and separate validation |
| Production ML | Blocked | Production-ready metadata, independent dataset validation, acceptable false-positive rate, and release review |
| Pre-execution blocking | Blocked/technical | Built and signed driver, installed service, authenticated IPC, approved elevated VM self-test, and UI evidence |
| Full UI/core E2E | Blocked/partial | Flutter/Dart and Cargo/rustfmt unit/runtime suites pass on this host; installed local-core layout, installed Windows UI automation, service validation, and driver validation host remain required |
| Driver install/signing | Blocked/guarded | User approval, development VM, Visual Studio Build Tools/WDK, test/prod signing, explicit confirmation switches |
| Secure deletion | Not claimed | Quarantine delete removes isolated payload after confirmation; Avorax must not promise secure erase on SSDs |

## Source-Accounted Control Summary

- Primary scanning does not depend on cloud, accounts, ClamAV, or YARA.
- Auto-quarantine is limited to confirmed detections or explicit user action; heuristic/development ML findings remain review-oriented.
- Compatibility engines are optional and disabled/guarded by default.
- User allowlist, false-positive, malicious feedback, protection mode, ransomware guard settings, update install/rollback, driver install, and quarantine restore/delete are confirmation-gated.
- Runtime gaps are documented as blockers instead of being represented as working protection.

## Cross-Platform Beta Packaging Addendum

Release workflow [29088539809](https://github.com/brentishere41848/Avorax/actions/runs/29088539809)
passed and published the prerelease at commit
`7b1f8130a652e27d8750954e88b63f3b7f32de2a`.

| Control / engine | Responsibility | Classification | Native evidence / limitation |
| --- | --- | --- | --- |
| Windows MSI package | Install the desktop payload through Windows Installer | Verified package; installed-host behavior partial | Native build, staged smoke, administrative extraction, manifest/hash verification, and extracted local-core lifecycle passed; package is unsigned and no service was installed or started |
| Windows setup EXE | Bootstrap the MSI through WiX Burn | Verified package; installation partial | Native bundle build and hash/signature inventory passed; artifact is unsigned and was not launched on the host |
| Linux DEB package | Install the desktop payload under `/opt/avorax` | Verified package; desktop integration partial | Native build, dependency inventory, no setuid/setgid check, extraction, manifest verification, and local-core lifecycle passed |
| Linux tar package | Provide a portable Linux desktop payload | Verified package | Separate extraction, manifest verification, and local-core lifecycle passed |
| macOS arm64 DMG | Distribute an Apple Silicon app bundle | Verified package; distribution blocked | Native DMG integrity, arm64 core, ad-hoc code signature, mounted manifest, and local-core lifecycle passed; Gatekeeper rejection is expected without Developer ID signing/notarization |
| macOS x64 DMG | Distribute an Intel app bundle | Verified package; distribution blocked | Native DMG integrity, x86_64 core, ad-hoc code signature, mounted manifest, and local-core lifecycle passed; Gatekeeper rejection is expected without Developer ID signing/notarization |
| Package manifest verifier | Detect missing, altered, duplicate, or unexpected payload files | Verified | Staged/extracted/mounted package checks passed on native runners; consolidated hashes were independently recomputed after artifact download |
| Packaged-core smoke | Exercise health, exact-hash detection, quarantine, list, and restore | Verified within bounded scope | Uses an isolated harmless exact-hash fixture only; no live malware, standard EICAR string, network, machine-wide state, service, GUI, or blocking proof |
| Platform update UI | Prevent unsupported update mutation controls | Verified source/UI tests; platform delivery partial | Signed `.aup` controls remain Windows-only; Linux/macOS direct users to manual reinstall instead of exposing a dead install/rollback control |
| Native ML signal | Supply optional static score evidence | Disabled for production verdict authority | Every packaged-core health result reports `native_ml_production_ready=false` |
| Driver/pre-execution engine | Block execution before user-mode launch | Blocked/technical | No package or smoke proves a reviewed signed driver, authenticated installed service IPC, kernel enforcement, or pre-execution blocking |
| OS signing/notarization | Establish trusted publisher and platform distribution acceptance | Blocked | Requires protected Windows signing credentials and Apple Developer ID/notarization credentials; unsigned/ad-hoc status is visible in artifacts and documentation |
| External GitHub sample-repository registry | Record bounded source attribution and tree metadata without handling sample bytes | Verified source policy; disabled by default | Requested repositories are exact HTTPS roots with `mode=metadata_only` and `enabled=false`; regression coverage forbids treating registration as active protection |
| External repository automatic hash blocking | Detect an exact file SHA-256 attributed to an external source | Disabled/blocked | Git tree metadata does not provide trusted file SHA-256 values and the active GitHub known-bad pack is empty; requires reviewed hash-only intel plus signed versioned Avorax package activation |

## Checkpoint 2155 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| PowerShell command and evidence enumeration | Load the checked core-health helper and enumerate update/report evidence without hiding unexpected errors | Runtime/source verified | PowerShell parser checks passed; the core-health smoke rejected seven malformed/error cases and passed real local stdio health; eleven update-builder fail-safe scenarios passed without producing `.aup` or feed output; `591` source contracts and the focused self-validating 11-gate MVP report passed |
| macOS DMG integrity verification retry | Tolerate only a short-lived `hdiutil verify` resource-busy condition after successful DMG creation while preserving fail-closed integrity verification | Source/unit verified; native rerun required | Bash parse and packaging contracts pass. Retry is limited to three attempts with delays of 2 and 4 seconds, and only exact `Resource temporarily unavailable` failures are retried. Any other error fails immediately; native arm64/x64 package CI remains required |

## Checkpoint 2156 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Native package tool discovery | Resolve configured or host Linux/macOS build tools while distinguishing expected absence from unexpected script failure | Source/unit verified; native rerun required | Missing `command -v` results are handled explicitly and still fail the absolute executable validation; no `|| true` remains in either native builder |
| macOS entitlement and emergency mount cleanup | Refuse packaging when entitlement inspection is unavailable and ensure cleanup failures are visible without erasing the original failure status | Source/unit verified; native rerun required | Entitlement inspection is fail-closed; the EXIT trap reports detach failure and preserves prior status. Bash parse, `16` packaging tests, and `591` source contracts pass; Developer ID signing/notarization and installed-host E2E remain blocked |

## Checkpoint 2157 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Lockfile CycloneDX component inventory | Produce deterministic bounded package identity/hash evidence from reviewed Cargo, pub, and Python lockfiles and deliver it beside release artifacts | Runtime/source verified; production SBOM/license review partial | Real generation records `569` deduplicated components; repeated output hashes match; official CycloneDX 1.6 schema validation passes; malformed/missing hash, duplicate field, link output, and checksum regressions pass; workflow-equivalent smoke includes the `.cdx.json` in seven checksum rows. Metadata explicitly records partial license review, false final-binary resolution, and incomplete composition. Final-binary graph, complete license/copyright notices, Android Gradle lock evidence, and artifact signing remain incomplete or blocked |

## Checkpoint 2158 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Windows Guard Service lifecycle status | Report startup, active operation, clean shutdown, and unexpected runtime failure honestly to Service Control Manager without hiding a primary monitor error behind a secondary status error | Windows runtime fixture verified; installed-service E2E partial | `StartPending` has a bounded 30-second wait hint and no accepted controls; `Running` accepts stop/shutdown; clean stop uses `NO_ERROR`; failed monitor operation uses service-specific exit code `1`; combined-error fixtures preserve both runtime and status-reporting diagnostics. Guard rustfmt, two focused tests, the complete Guard suite (`214`), all workspace test-binary compilation, Python source contracts (`592`), and the no-malware-binaries gate pass. Strict Rust 1.96 Clippy remains non-green on `15` pre-existing Guard and `13` dependency native-engine lints outside this diff. No service registration/start/stop, authenticated privileged IPC, signed driver, or pre-execution blocking was exercised. |

## Checkpoint 2159 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Local Core and Guard service-status probe | Query product service presence/state without localized subprocess output, broad SCM rights, arbitrary names, or false missing/off classification on access/probe errors | Windows read-only runtime verified; installed-service E2E partial | Shared `windows-service` helper permits only `avorax_core_service`, `avorax_guard_service`, and `zentor_guard_service`; requests SCM `CONNECT` plus service `QUERY_STATUS`; treats only numeric Windows error `1060` as missing; maps typed `Running`/`Stopped` and conservative pending/paused `Installed`; includes numeric errors in diagnostics. Seven focused tests, the complete local-core suite (`483`), source contracts (`592`), rustfmt, and the no-malware-binaries gate pass. Fresh debug health returns `core_service_status=missing`, `guard_status=off`, null status errors, `ipc=stdio`, and `network_exposed=false`. The host fixture performs read-only queries only; installed start/stop/recovery, service ACL validation, authenticated privileged IPC, and driver behavior remain unverified or blocked. |

## Checkpoint 2160 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Windows Core Service lifecycle status | Expose initialization, active operation, clean stop, and warmup/runtime failure honestly to Service Control Manager | Windows runtime fixture verified; installed-service E2E partial | `StartPending` is reported before native-engine warmup with a bounded 30-second wait hint and no accepted controls; `Running` follows successful warmup only; clean stop uses `NO_ERROR`; warmup/running-status/shutdown-channel failure uses service-specific exit code `1`; combined-error fixtures preserve runtime and final-status diagnostics. Three focused tests, the complete local-core suite (`485`), source contracts (`593`), rustfmt, and the no-malware-binaries gate pass. No service registration/start/stop, installed recovery, service ACL validation, authenticated privileged IPC, driver behavior, or pre-execution blocking was exercised. |

## Checkpoint 2161 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Windows Core Service authenticated IPC v1 | Provide a least-privilege local service boundary without exposing the broad stdio scan/quarantine command handler under `LocalSystem` | Local Windows transport/runtime verified; UI mediation and installed-service E2E partial | `\\.\pipe\AvoraxCoreService.v1` uses explicit SYSTEM/Administrators/Authenticated Users access, exclusive first-instance creation, and remote-client rejection. Requests are one message and 16 KiB maximum; the server validates client PID plus impersonated query token and treats failed identity reversion as fatal. Strict protocol v1 allows only read-only `health`, denies every mutating/unknown command, rejects malformed/unknown-field/version/ID inputs, and returns no filesystem paths. Six focused tests include a real named-pipe client, exclusive-name collision, authenticated PID, malformed request, mutation denial, oversized-message disconnect, recovery, liveness, and stop; the full local-core suite passes (`492`). Flutter remains on per-process stdio, service mutations are disabled, installed service/pipe ACL and recovery are not exercised, and this does not provide persistent monitoring, driver enforcement, or pre-execution blocking. |

## Checkpoint 2162 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Native Core Service health client | Let an unprivileged local caller observe Core Service/engine health without trusting a same-name pipe server or exposing mutation commands | Local Windows transport/runtime verified; Flutter and installed-service E2E partial | `--service-ipc-health` queries the fixed service through typed read-only SCM access, matches the connected pipe server PID before sending, rechecks the unchanged SCM PID after receiving, and rejects zero/missing/stopped/restarted/mismatched identities. Overlapped I/O has bounded waits and cancellation. Strict 16 KiB protocol-v1 parsing validates request ID, client PID, authenticated flag, health-only scope, local/no-network transport, bounded definition counts, explicit bounded limitations, and absence of contradictory or unknown fields; overall `ok` remains false when the authenticated service reports a degraded engine. Twelve focused tests pass, including a real probe, degraded engine, spoofed PID, restart race, stalled response, malformed/oversized input, recovery, and mutation denial. The serialized Local Core suite passes (`498`), source contracts pass (`594`), all workspace test binaries compile, and the no-malware gate passes. The first parallel full run's one PE-carrier fixture failure passed immediately alone and in the serialized suite. Strict Clippy reports only `16` pre-existing lints outside this change. Real host probes for missing service and unknown CLI mode both fail visibly with exit `1`. No service was installed or changed; Flutter consumption, installed pipe/service ACL and recovery E2E, privileged mutations, persistence, signed driver behavior, and pre-execution blocking remain partial, disabled, or blocked. |

## Checkpoint 2163 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Flutter Core Service boundary probe | Surface the native read-only service identity/health result separately from broad per-process stdio scan health and prevent a Windows full-protection label without ready authenticated service evidence | Windows benign-subprocess/parser/controller/UI runtime verified; installed-service E2E partial | Flutter launches only `--service-ipc-health`, closes stdin, limits stdout to 16 KiB, limits stderr diagnostics, applies a ten-second outer timeout with termination/reaping, and strictly rejects missing/unknown fields, protocol/transport/scope changes, network exposure, unauthenticated flags, zero/mismatched PIDs, contradictory `ok`/engine state, invalid counts, and malformed limitations. Protection and Settings expose ready/degraded/unavailable detail. Windows controller tests prove missing evidence remains `Partially Protected` and valid ready evidence permits `Protected` only when the existing engine and driver requirements also pass. The trusted native helper and its installation ACL/signature remain part of the TCB; unsigned package distribution and installed service/pipe ACL/recovery E2E are not proven. |

## Checkpoint 2164 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Reviewed SHA-256 definition pack profile | Permit active known-bad metadata only when a pack is non-empty and every indicator is a unique canonical lowercase SHA-256 exact hash with confirmed confidence, critical severity, a production category, global file scope, and explicit quarantine policy; preserve the previous pack on any failure | Benign metadata-only runtime and adversarial validation verified | `tools/zentor_intel/validate_indicator_pack.py`, `build_realworld_detection_pack.py`, and `tests/test_hash_intel_update.py` reject empty, duplicate, uppercase, partial-hash, confidence, severity, category, scope, context, mask, and policy violations. Validation uses a unique temporary pack and atomic activation. The profile cannot establish third-party source truth; review and false-positive ownership remain maintainer responsibilities. |
| Signed definitions-only update package | Build exactly one reviewed signature pack into an Ed25519-signed `.aup`, declare only signature engine components, verify package/payload hashes and manifest signature through the release Update Service, and clean checked temporary data | Local release-binary verify plus isolated fake-service apply/rollback verified; real installed service E2E partial | `avorax-build-hash-intel-update.ps1` and `run-hash-intel-update-package-smoke.ps1` produce the exact three-entry archive, reject unsafe arguments, verify its signature, apply it in checked temporary install/data roots, prove the previous pack is revoked and snapshotted, then roll back to the previous bytes. Fixtures are benign text and service control is redirected to a temporary fake `System32`; no package is machine-installed and production-key custody is not proven. |
| Requested GitHub malware repositories | Use repository metadata for attribution/review only and activate blocking only from a separately reviewed canonical SHA-256 feed delivered through the signed path | Metadata-only registry and signed local-feed path verified; automatic source ingestion/blocking disabled | The repository APIs provide Git blob/tree metadata, not a reviewed canonical file SHA-256 feed. The listed sources remain `enabled: false`; no samples are cloned or downloaded and `zentor_github_known_bad.zsig` remains empty. |

## Checkpoint 2165 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Reviewed hash-feed provenance parser | Select only an exact direct source object or exact manual registry template; reject ambiguous fields, unsafe URLs, duplicate hashes, and oversized active feeds before atomic JSONL output | Benign metadata-only runtime and adversarial validation verified | `import_hash_feed.py` and `test_hash_intel_update.py` cover direct/template success plus unknown fields, wrong registry shape, HTTP, credentials, fragments, backslashes, and canonical duplicate hashes. The 100,000-row bound is source-enforced. Schema-valid provenance does not prove publisher identity or indicator truth; maintainer review remains required. |

## Checkpoint 2166 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Atomic engine subcomponent activation | Replace each declared engine component as a checked directory unit so removed/revoked definitions cannot remain active; restore the prior component on activation failure and retain the pre-apply rollback snapshot | Rust unit/integration and isolated release-binary apply/rollback verified | `file_replacer::replace_tree_atomically` stages under the install boundary, revalidates path chains and kinds, renames destination to a unique sibling backup, activates by rename, restores on activation failure, and removes the backup after success. The signed hash smoke exposed and regressed the previous merge behavior. Real installed services, ACLs, and production release keys remain partial. |

## Checkpoint 2167 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Strict update-service lint gate | Keep signed-update, rollback, path-safety, CLI, and verifier code free of Rust 1.96 Clippy warnings and prevent silent regression | Local all-target gate verified; CI enforcement source-verified | `cargo clippy --all-targets -- -D warnings` passes without command-line allowances. CI pins Rust 1.96.1, installs Clippy, and runs the same command after updater tests. Two source files retain narrow `items_after_test_module` annotations because source-contract tests intentionally inspect later production helpers; there is no crate-wide lint suppression. This gate improves maintainability but is not installed-host or security-boundary E2E proof. |

## Checkpoint 2168 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Strict Guard Service lint gate | Keep Guard process observation, driver-health, driver IPC, known-bad-cache, DPAPI metadata, and quarantine code free of Rust 1.96 Clippy warnings | Local all-target Guard gate verified; CI enforcement source-verified | `cargo clippy --all-targets --no-deps -- -D warnings` passes with no lint allowances; the complete Guard suite (`214`), source contracts (`608`), rustfmt/diff checks, and no-malware-binaries gate pass. CI pins Rust 1.96.1 and runs the exact command after Guard tests. `--no-deps` deliberately leaves thirteen native-engine dependency lints visible as separate debt; this gate is not installed-service, signed-driver, or pre-execution proof. |

## Checkpoint 2169 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Strict native detection-engine lint gate | Keep bounded archive parsing, static analysis, signatures, rules, trust, ML scaffolding, quarantine, scanning, and explainable verdict aggregation free of Rust 1.96 Clippy warnings | Local all-target native gate verified; CI enforcement source-verified | `cargo clippy --all-targets --no-deps -- -D warnings` passes with no lint allowances. The complete native suite (`433` library plus `6` compiler CLI), dependent Guard suite (`214`), source contracts (`609`), and no-malware-binaries gate pass. CI pins Rust 1.96.1 and runs the exact command. Verdict boundaries and existing ZIP safety limits are retained, but this gate does not measure detection accuracy or prove installed-service, signed-driver, or pre-execution behavior. |

## Checkpoint 2170 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Strict Local Core lint gate | Keep scan orchestration, progress/cancellation, quarantine/restore/delete, allowlist, user-mode watcher, ransomware activity, service health, and UI stdio IPC code free of Rust 1.96 Clippy warnings | Local all-target gate verified; CI enforcement source-verified | `cargo clippy --all-targets --no-deps -- -D warnings` passes without new lint suppression and removes the ransomware argument-count suppression through a named activity record. The complete serialized Local Core suite (`498`) and source contracts (`610`) pass. CI pins Rust 1.96.1 and runs the exact command after tests. Installed Core Service mutation remains disabled, watcher/ransomware observation remains best-effort post-activity user mode, and no signed-driver or pre-execution claim is made. |

## Checkpoint 2171 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Finite watcher timestamp and unchanged-file cache | Never treat unavailable filesystem modification time as proof that same-size content is unchanged; expose the diagnostic and rescan conservatively within fixed limits | Unit, release-binary, and source-contract verified; real metadata-failure host fixture partial | `modified_at_ms` is optional from collection through evaluation. Query/pre-epoch failures produce bounded diagnostics; only valid timestamps enter baseline/unchanged caches; unavailable timestamps yield `timestamp-unavailable-rescan`. The serialized Local Core suite passes (`500`), source contracts pass (`611`), strict Clippy/rustfmt and no-malware gates pass, and a fresh release watch-poll smoke detects/quarantines one harmless exact-hash fixture. A real filesystem timestamp-query failure was not induced, and this remains finite post-write user-mode polling without persistent service, OS notifications, kernel blocking, or pre-execution proof. |

## Checkpoint 2172 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Bounded process command evidence | Preserve inspectable command-line head and tail evidence, propagate source truncation across Flutter IPC, inspect retained suspicious flags, reject inconsistent command evidence, and conservatively route truncated security-sensitive utilities to review | Unit, Flutter runtime, IPC, full-suite, and release-binary fixture verified; installed monitoring E2E partial | Flutter retains 2048 Unicode scalar values, Local Core retains 4096, IPC carries `command_line_truncated`, and all findings remain explainable `suspiciousProcess` review results. Local Core passes `506`, Flutter passes `824`, source contracts pass `611`, and the release smoke verifies `266` synthetic observations with `4` expected findings and `12` bounded/invalid skips. Omitted middle content is not reconstructed; there is no automatic process action, persistent service proof, representative false-positive study, signed-driver enforcement, or pre-execution claim. |

## Checkpoint 2173 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Flutter process snapshot response gate | Prevent rejected, missing, or incompletely parsed Local Core snapshot evidence from becoming a clean evaluation or active process-loop claim | Controller runtime, full Flutter suite, and source-contract verified; installed monitoring E2E partial | The controller checks `report.ok` and requires no parser diagnostics before emitting evaluated/suspicious success. Rejection or incomplete evidence records a bounded warning, marks the active loop `limited`, resets routine dedupe, and emits no evaluated event. Two regressions, Flutter `826`, analyzer, source contracts `612`, and the no-malware gate pass. Benign fakes only were used; persistent service observation, real-host response policy, process action, signed-driver enforcement, and pre-execution behavior remain partial or blocked. |

## Checkpoint 2174 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Watch-poll response consistency gate | Require watcher plan and finite poll summary to agree before the UI may claim active or clean monitoring | IPC subprocess, controller runtime, analyzer, and source-contract verified; installed monitoring E2E partial | Parser and controller independently require matching activity, active watcher mode/path evidence, and activity-appropriate poll mode. Contradictions produce `watch_poll_loop_failed`, reset routine dedupe, and set `limited`; they cannot emit a clean event. Flutter passes `828`, source contracts pass `613`, analyzer and no-malware gates pass. Tests use benign JSON and fake controller data only. Finite polling remains app-lifetime and post-write, with no installed persistent service, OS-notification, kernel, signed-driver, or pre-execution proof. |

## Checkpoint 2175 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Flutter Local Core mutation evidence gate | Prevent a bare, stale, malformed, or contradictory `ok=true` response from becoming quarantine, restore, delete, allowlist, feedback, or protection-configuration success in the UI | Benign IPC subprocess runtime, full Flutter suite, analyzer, and source-contract verified; installed mutation E2E partial | Quarantine-family actions require a strictly parsed record with the expected status and, where applicable, requested ID. Allowlist actions require a strictly parsed entry with the expected active state and removal ID. Label and configuration writes require a bounded absolute local result path; success plus any error field is rejected. Four adversarial response tests and the positive manual-quarantine IPC test pass; Flutter passes `832`, source contracts pass `614`, analyzer and no-malware gates pass. This does not independently prove post-write durability, installed service mutation, signed-driver behavior, or pre-execution blocking. |

## Checkpoint 2176 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Flutter Guard self-test evidence gate | Convert one freshly launched Guard self-test response into a typed, explainable status only after complete response validation | Benign subprocess runtime, controller, UI state, full Flutter suite, analyzer, and source-contract verified; installed Guard/driver E2E partial | Requires zero exit, empty stderr, one bounded JSON line, exact envelope and nested schemas, bounded control-free fields, UTC timestamp consistency, 1-64 unique exact steps, and matching step/report/outer verdicts. Malformed, extra, incomplete, nonzero-exit, stderr, invalid-time, timeout, and contradictory fixtures fail closed; Flutter passes `838`, source contracts pass `615`, analyzer and no-malware gates pass. This does not authenticate publisher identity or prove an installed service, signed minifilter, or pre-execution blocking. |

## Checkpoint 2177 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Windows MSI administrative verifier | Prove the actual MSI can be extracted and its packaged Local Core can complete a harmless lifecycle, while bounding path length, input size, extracted count/bytes, required payloads, reparse exposure, MSI stability, evidence creation, and cleanup | Actual-package runtime, adversarial fixture, unit, source-contract, CI, and public-release verification passed; installed-host E2E partial | `tools/packaging/verify-windows-msi.ps1` passed against an actual workflow MSI with 283 files and 79,136,091 extracted bytes, then removed its opaque temporary root. Excessive-root and missing-smoke-evidence cases fail visibly and clean up. Packaging tests pass `22` with `3` expected Windows symlink skips; source contracts pass `615`; the `v0.1.15-beta.3` Windows native job and all release jobs pass. This is `msiexec /a`, not machine installation, service start, installed ACL proof, Authenticode identity, or driver/pre-execution evidence. |

## Checkpoint 2178 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Explicit Windows driver activation boundary | Keep candidate driver files inert during MSI/EXE installation and require a separate confirmed elevated workflow without implicit trust-store or TESTSIGNING changes | Source contracts, generated-helper fail-closed runtime, actual-MSI database/runtime, packaging unit, safety gates, and native package CI verified; installed driver E2E blocked | `installer/windows/build-msi.ps1` emits no driver-install custom action, records driver activation as not performed, and generates a helper that refuses operation without `-ConfirmDriverInstall`. The helper does not call `certutil -addstore` and does not enable TESTSIGNING. `verify-windows-msi.ps1` opens the actual MSI database and rejects any `CustomAction` table. Local evidence passes `616` source contracts and `22` packaging tests with `3` expected symlink skips; an actual Avorax MSI passed database/extraction/lifecycle checks and an existing cached MSI with a `CustomAction` table was rejected before extraction. Avorax CI run `29765160511` and Desktop Packages runs `29765128390` and `29765160524` pass, including both fresh Windows MSI/EXE jobs. This boundary does not prove production signatures, OS acceptance, load/unload, rollback, service/driver IPC, or pre-execution blocking. |

## Checkpoint 2179 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Native verdict category inference | Infer a stable threat family from positive detection evidence without letting neutral diagnostics alter category or score | Runtime, lint, general CI, and native package CI verified; production-rate evidence technically limited | GitHub run `29766224417` exposed a `.tmpupTeBo` path causing a zero-weight publisher diagnostic to match `pup` and override macro evidence. `RiskFusion` now ignores zero-weight rows only for category inference while retaining them in explanation evidence. The exact regression, formerly failing Local Core test, Native Engine `434 + 6`, Local Core `506`, rustfmt, and both clippy checks pass. Final Avorax CI run `29767214563` and Desktop Packages runs `29767211055` and `29767214589` pass; PR `#30` merged as `f28cad2`. Production false-positive/false-negative rates and live-malware validation remain technically limited and are not claimed. |

## Checkpoint 2180 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Dependency evidence count and release gate | Count exact lockfile package/integrity evidence consistently across LF/CRLF hosts and fail closed on missing or zero summaries | Local runtime, source-contract, CI wiring, full verifier, and report-validator verified | Shared bounded regex counting normalizes line endings and has a two-second timeout. Generator and validator use the same helper, zero/missing summaries are blockers, Python requirements report `10/10`, source contracts pass `617`, and the final full verifier passes `217/217` in `961.5s`. Source-level inventory remains incomplete: a full final-artifact SBOM and license review is still required on a provisioned release host. |
| Windows Authenticode module isolation | Collect publisher-signature evidence through the checked local WindowsPowerShell security module without inheriting ambient module discovery | Local runtime, adversarial environment, source-contract, full Rust, and full verifier verified; packaged signature E2E partial | The full workspace run exposed incompatible module autoload from the parent `PSModulePath`. The probe now derives and non-followingly validates the built-in `Microsoft.PowerShell.Security.psd1` from checked `System32\WindowsPowerShell\v1.0`, overrides the child module root, explicitly imports that manifest, and uses module-qualified cmdlets. Four focused probes pass both normally and with a deliberately invalid parent `PSModulePath`; the full Rust workspace passes `1,408` tests and the final verifier passes `217/217`. Production Avorax Authenticode signing and installed-artifact trust-policy E2E remain blocked/partial. |
| Checkpoint 2180 consolidated custom-engine/UI readiness | Keep every custom engine and existing control classified as verified, partial, disabled/blocked, or technically limited without converting fixture evidence into production claims | Consolidated evidence review verified; production boundaries unchanged | `docs/reports/checkpoint-2180-project-readiness.md` records 19 engine/control rows, 11 routes, 65 documented UI controls/settings, and 61 source-gated high-risk controls. User-mode scan/quarantine/update fixtures are green; development ML and cloud reputation remain non-production/disabled, compatibility YARA/ClamAV remain optional, monitoring remains app-lifetime/post-write, and signed-driver/installed-host proof remains blocked or partial. |

## Checkpoint 2182 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Shared Local Core/Guard quarantine metadata authentication | Authenticate strict metadata, keep Guard-created items available to Local Core lifecycle actions, and fail closed on unsigned, malformed, renamed, or contradictory records | Isolated Rust runtime and adversarial regression verified; installed service/UI E2E partial | New records use shared domain-separated HMAC-SHA-256 with a 32-byte OS-random key. Windows accepts DPAPI-protected key material only. Exact authenticated v1 Local/Guard tags migrate only after complete validation; unsigned and unknown-field records do not migrate. Tests prove tamper rejection, filename/ID binding, Guard source/action validation, and Guard-record list/restore interoperability. HMAC does not encrypt payloads. Installed LocalSystem ACL/DPAPI recovery, UI mediation, repair/upgrade, and authenticated mutation IPC still require a disposable elevated Windows host. |
| Quarantine metadata dependency boundary | Use reviewed explicit crypto/random APIs without silently expanding the runtime dependency set | Lockfile and local license metadata verified; final-artifact SBOM review partial | Direct dependencies pin RustCrypto `hmac` `0.12.1` and `getrandom` `0.3.4`, both already present transitively in `Cargo.lock`; cached metadata reports `MIT OR Apache-2.0`. Final-binary dependency resolution and complete release license/copyright review remain required. |

## Checkpoint 2183 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Avorax Native Engine production orchestrator | Read bounded content, run signatures/rules/static analysis/heuristics/trust/model signals, and return an explainable non-mutating verdict to Local Core | Detection/verdict runtime verified; direct mutation disabled with blocker | `scan_file`, byte self-test scans, and root scans reject native auto-quarantine compatibility modes before file/root I/O. `DetectOnly` and `LockdownReview` remain functional. Production code cannot construct the old native store or action policy. Focused tests pass `3/3`, the complete Native Engine passes `435 + 6`, strict Clippy passes, and Local Core passes `515/515`. Native mutation is disabled because its unauthenticated schema and missing restore/DPAPI contract cannot safely share the Local Core vault. |
| Local Core quarantine lifecycle owner | Convert eligible aggregated verdicts into authenticated quarantine records and own list, rescan, restore, and delete semantics | Existing runtime verified; installed service/UI E2E partial | Local Core continues to invoke the Native Engine with `DetectOnly` and retains the shared HMAC lifecycle. Its full `515`-test suite covers quick/full/custom scan and quarantine/restore/delete paths. Installed LocalSystem ACL/DPAPI behavior, authenticated service mutation, and packaged UI click-through remain partial. |
| Native quarantine compatibility API | Preserve serialized result/action-mode compatibility while refusing unsafe duplicate file mutation | Explicitly disabled with visible blocker | Both auto modes and direct `quarantine` return the bounded Local Core routing error; native `quarantine_record` remains `None`. The old store, extension helper, and action-policy modules are private test-only code. This is not fake success and does not claim kernel or pre-execution enforcement. |
| Checkpoint 2183 GitHub head and package evidence | Verify the exact checkpoint on clean hosted Windows, Linux, macOS arm64, and macOS x64 runners | General CI and cross-platform package jobs verified; installed-host E2E partial | Head `a7e8ca33d02a2513e6a8b8949ef3120cddc1d58a` passes Avorax CI `32291858708`; Desktop Packages push run `32291729128` and PR run `32291858742` both pass package contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, both macOS DMGs, and consolidated checksum/lockfile-SBOM evidence. This does not install the packages or prove elevated service/driver behavior. |

## Checkpoint 2184 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Shared platform quarantine permission engine | Give Local Core and Guard one fail-closed implementation for exact private Unix ownership/modes and exact Windows owner/DACL policy | Windows and native Ubuntu runtime, Local Core/Guard integration, strict lint, source-contract, and central-verifier verified | Windows identity comes from the process token, not mutable account environment variables. Handle-based code bounds/rejects unsafe paths, rejects reparse/wrong-kind targets, binds the data and ACL handles to the same volume/file ID, sets and reads back the owner SID plus exact protected DACL, and denies only `FILE_EXECUTE` to Everyone on payloads. Unix code transfers differing ownership through the opened descriptor to the effective UID/GID, then verifies device/inode identity, ownership, and exact `0700`/`0600` modes. Local Core and Guard reject linked/reparse vault ancestors before and after creation. Explicit overrides require a dedicated `Quarantine` leaf, Windows Guard rejects UNC roots, and a bounded 65,536-entry vault-shape preflight rejects unknown/link/wrong-kind content before permission mutation. Local Core's arbitrary-base constructor is test-only; runtime tests use a thread-local temporary vault and leave ProgramData unchanged. Existing bounded metadata/key reads repair permissions before content reads, and Local Core repairs present authenticated legacy payloads after path validation. Platform `6/6`, Local quarantine `112/112`, Guard quarantine `47/47`, full Local `517/517`, full Guard `223/223`, the Rust workspace `1,435/1,435`, source contracts `620/620`, and the central verifier `219/219` in `618.0s` pass locally. Platform strict Clippy passes for Windows and the Linux target; affected Windows crates pass strict Clippy; Guard Linux all-target compilation passes. Full Local cross-check is blocked only by missing `x86_64-linux-gnu-gcc` for `tract-linalg`. Checkpoint 2185 adds a bounded Ubuntu 24.04 job for all five shared tests plus exact Local Core and Guard permission-routing filters. Initial run `32319783686` exposed a Unix-only test compile error after shared `5/5` and skipped Guard. The explicit-`Option` repair passes source contracts `621/621` and focused Local quarantine `112/112`; replacement run `32320253194`, job `96280869830`, then passed shared `5/5`, Local Core `1+1`, and Guard `1+1`, for native scope `9/9`. |
| Local Core quarantine/restore permission routing | Harden moved/copied payloads and staged metadata/auth/key files while avoiding an execute-deny ACL on restored output | Runtime and source-contract verified; installed service/UI E2E partial | `ExclusiveCopySecurity::Quarantine` applies payload isolation; `Restore` uses exact Unix private staging but intentionally does not apply the Windows quarantine DACL. Integrity, path/link, conflict, parent revalidation, exclusive create, cleanup, and atomic activation controls remain in force. Installed LocalSystem ownership, DPAPI access, and cross-account UI mediation remain partial; portable same-SID/UID processes share the vault principal. |
| Guard quarantine permission routing | Apply the same verified vault permissions to post-launch confirmed-threat quarantine without external ACL processes | Runtime and source-contract verified; persistent installed Guard E2E partial | Guard hardens the base, moved/copied payload, metadata, auth sidecar, and key path through the shared crate. The old `icacls` runner and environment-derived account identity are absent. This remains post-launch user-mode response and does not claim driver or pre-execution blocking. |
| Quarantine finalization payload retention | Prevent a late permission/metadata failure from deleting the only quarantined payload copy | Local Core/Guard runtime and source-contract verified; administrator recovery UI partial | Cleanup after payload movement removes only incomplete metadata/auth artifacts. It retains the opaque payload and returns its vault path in a visible error. The untracked payload is intentionally absent from normal authenticated listing; dedicated recovery tooling remains follow-up work. |
| Platform-security dependency boundary | Reuse pinned platform APIs without adding an unreviewed registry dependency | Lockfile and source-level license evidence verified; final-artifact review partial | The internal `avorax_platform_security` crate uses already pinned `anyhow`, `windows-sys 0.61.2`, and test-only `tempfile`. Root lock evidence is `364` packages / `358` checksums; deterministic CycloneDX generation reports `570` components. A complete final-artifact SBOM and license/copyright review remain required. |
| Quarantine hard-link boundary | Reject known path aliases before quarantine and prevent a linked vault payload from being recorded as isolated | Windows and native Ubuntu runtime plus source contract verified; volume-wide atomicity technically limited | Shared handle-based code requires exactly one link through Windows `GetFileInformationByHandle.nNumberOfLinks` or Unix descriptor `nlink`. Local Core and Guard preflight source handles, recheck copy sources before removal, and postflight payload/vault files before permission mutation or authenticated record finalization. Adversarial Windows fixtures preserve both source names and create no payload/record. Avorax CI `32324715015`, job `96293537585`, passes `16/16` selected native Ubuntu tests on exact implementation head `2613b4131cb31c37e413d7610403fb2d665582e9`. The policy does not enumerate a volume or close same-principal/administrator races between the final check and mutation, so alternate paths remain separate targets and volume-wide neutralization is not claimed. |
| Vault-ancestor race boundary | Keep symlink/reparse protection claims aligned with path-based pre/post validation | Technically limited and documented; handle-relative redesign remains open | Existing ancestors are rejected when linked/reparse and rechecked after creation, but the complete tree is not held through an NT handle-relative or Unix `openat2` transaction. Administrators/root-capable principals able to replace trusted ancestors concurrently remain in the trusted computing base. |

## Checkpoint 2186 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Shared quarantine hard-link inspector | Read link count from the already-opened file object without shelling out or enumerating an unbounded volume | Windows and native Ubuntu runtime plus source contract verified | Windows uses `GetFileInformationByHandle.nNumberOfLinks`; Unix uses descriptor `MetadataExt::nlink`. Counts other than exactly one fail visibly. Platform tests cover direct rejection, hard-linked vault-entry preflight, and rejection before permission hardening. Windows passes `9/9`; hosted Ubuntu passes shared `8/8`; strict Windows and Linux platform Clippy pass. |
| Local Core hard-link action policy | Prevent a known alternate path from being reported as successfully quarantined | Direct/copy Windows and native Ubuntu runtime plus full regression verified | The source handle is checked before move and again immediately before mutation. Copy fallback returns the opened input and rechecks it before source removal. Destination hardening rechecks before HMAC record finalization. Benign fixtures preserve source plus alternate and create no payload or record; full Local Core passes `519/519`, and hosted Ubuntu passes `1+1+2` selected tests. The complete Rust workspace passes `1,442/1,442`, and the central verifier/report validator passes `219/219` in `605.1s`. |
| Guard hard-link action policy | Apply the same fail-visible boundary to post-launch Guard quarantine | Direct/copy Windows and native Ubuntu runtime plus full regression verified | Guard uses the shared handle inspector before each move attempt, on the copy input before removal, and on the payload before record finalization. Benign fixtures preserve both names and create no payload or record; full Guard passes `225/225`, and hosted Ubuntu passes `1+1+2` selected tests. This remains post-launch response and does not claim pre-execution blocking. |
| Unix hard-link runtime job | Execute shared, Local Core, and Guard link-count branches on native Ubuntu | Workflow, source contract, and hosted runtime verified | The existing pinned Ubuntu 24.04 job runs the full shared crate and exact Local Core/Guard permission plus `hard_link` filters across seven locked Cargo invocations. Source contracts pass `622/622`; Avorax CI `32324715015`, job `96293537585`, passes shared `8/8`, Local Core `1+1+2`, and Guard `1+1+2`, totaling `16/16` on exact implementation head `2613b4131cb31c37e413d7610403fb2d665582e9`. |
| Volume-wide hard-link atomicity | Bound claims where filesystem alias creation can race quarantine | Technically limited | Avorax does not enumerate every directory entry on a volume and has no atomic transaction spanning link creation and rename/removal. Same-SID/UID and administrator/root-capable concurrent mutation remains inside the trusted computing boundary. Alternate paths remain independent scan targets; volume-wide neutralization is not claimed. |

## Checkpoint 2187 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Local Core finalization journal writer | Commit authenticated recovery intent before source mutation and retain it whenever a destination artifact exists or absence cannot be proved | Windows runtime, native Ubuntu writer runtime, full regression, lint, and source-contract verified | The strict wrapper is written auth-sidecar first and `.pending` last, uses a domain distinct from final records, contains the prevalidated record, and is read back byte-for-byte plus HMAC verified before the source moves. Its exclusive lock is held through finalization. Move failure with a proven-absent destination cleans the unused journal; an existing or uninspectable destination retains it. Local Core passes `534/534`; hosted Ubuntu job `96312704078` includes the normal writer. Installed LocalSystem E2E remains partial. |
| Guard finalization journal writer | Give Guard post-launch quarantine the same recoverable metadata contract without adding a second lifecycle owner | Windows runtime, native Ubuntu writer runtime, compatibility contract, full regression, and lint verified; installed Guard E2E partial | Guard writes the Local-compatible wrapper before retrying the move, reads back and verifies the HMAC, holds the same exclusive lock, finalizes the shared record, and removes the journal only on success. Post-move or ambiguous destination failure cleans partial final metadata but retains payload/journal for Local Core. Guard passes `226/226`; hosted Ubuntu job `96312704078` includes its journal-lock and normal-writer tests. This does not claim process stop, driver interception, or pre-execution blocking. |
| Finalization concurrency lock | Prevent recovery from classifying a still-active Local Core or Guard transaction as an abandoned pre-move journal | Windows cross-handle and native Ubuntu runtime verified | Both writers retain the operating-system file lock from verified commit through cleanup. Recovery uses non-blocking `try_lock`; a competing active writer produces a visible error and preserves source, journal, auth, and payload state. After the writer releases or crashes, the same recovery succeeds. Avorax CI `32331431435`, job `96312704078`, passes shared `8/8`, Local Core `1+1+2+1+1`, and Guard `1+1+2+1+1`, totaling `20/20` across 11 locked Cargo invocations on exact implementation head `3e361a4d0b1829017603d3644c4866ccb5d3ad6c`. |
| Local Core bounded finalization recovery | Turn authenticated crash evidence into a current final record without deleting the only payload or trusting malformed state | Adversarial runtime and source-contract verified | Recovery scans at most `65,536` vault entries, locks and authenticates before parse/use, enforces strict schema and ID/path binding, validates record claims, size/hash/single-link payload integrity, and re-verifies the written HMAC record before journal cleanup. Tests cover active-writer refusal, isolated-payload completion, abandoned source-intact cleanup, partial metadata replacement, stale journal/orphan-auth cleanup, tampered/missing auth, authenticated unknown fields, filename mismatch, payload mutation, final-record conflict, and duplicate source/payload refusal. Platform passes `9/9`, workspace `1,458/1,458`, source contracts `623/623`, and the central verifier/report validator passes `219/219` in `533.3s`. |
| Ambiguous duplicate-state policy | Avoid claiming quarantine completion when both original path and opaque payload exist | Verified fail-closed; operator resolution partial | Local Core returns an explicit error and preserves both copies plus authenticated journal. It does not guess which copy to delete or promise secure erase. A future operator flow must present independently verified evidence and explicit confirmation before mutation. |
| Historical unsigned payload boundary | Keep journal recovery from silently legitimizing old untracked files | Explicitly unsupported / blocked | Only a current authenticated journal or current authenticated final record can drive automatic cleanup/finalization. Historical opaque payloads without authenticated metadata remain unavailable to normal actions and require deliberate forensic/operator handling. |
| Installed recovery/UI boundary | Prove recovery under LocalSystem DPAPI/ACL ownership and surface outcomes through packaged UI/service mediation | Partial / blocked on disposable elevated Windows host | Current evidence uses isolated user-process temporary vaults. Installed service identity, repair/upgrade interruption, hostile same-principal mutation, notification wording, packaged UI click-through, and package lifecycle have not yet been exercised end to end; no installed success claim is made. |
| Checkpoint package regression | Ensure journal changes still produce complete inspectable desktop package sets without installing them | Hosted Windows/Linux/macOS package builds verified | Desktop Packages push run `32331417805` and PR run `32331431406` pass package contracts, Windows x64 MSI/EXE build and administrative extraction, Linux x64 DEB/tar, macOS arm64/x64 DMGs, six-artifact consolidation, checksums, and lockfile SBOM evidence on implementation head `3e361a4d0b1829017603d3644c4866ccb5d3ad6c`. Prerelease publication was intentionally skipped. This is package-build evidence, not installed lifecycle E2E or production code-signing proof. |

## Checkpoint 2188 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Flutter in-app service registration | Prevent desktop UI state or same-user executable overrides from crossing UAC into service creation/reconfiguration | Explicitly disabled; source, direct-client runtime, controller event, widget, analyzer, and contract verified | `repairInstallation()` returns one installer-owned blocker and does not inspect executable overrides or call elevated PowerShell. Scan exposes no repair callback and renders a permanently disabled `Repair unavailable` control plus an installer-required diagnostic. The controller records `installation_repair_blocked`; the historical requested-success event is absent. |
| Start Core Service | Ask Windows to start only the already registered fixed-name `avorax_core_service` after explicit confirmation | Flutter/runtime verified; installed elevated E2E partial | The remaining PowerShell path uses fixed `Get-Service`/`Start-Service`, contains no service creation/reconfiguration and no execution-policy bypass. A disposable elevated Windows host must still prove installed identity, ACLs, UAC behavior, failure reporting, and service start. |
| Installer-owned repair/install | Install, repair, or reconfigure service binaries only through a provenance-checked official MSI/EXE | Disabled/blocked in app; package-host E2E required | The desktop app directs the user to reinstall from a verified official installer. Production-signed package provenance, installed-path validation, service identity, repair/rollback/uninstall, and ACL proof remain blocked on a disposable elevated Windows host. No installed success is claimed. |

## Checkpoint 2189 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Guard process collection evidence | Bind every process snapshot to bounded coverage-gap evidence rather than returning only visible rows | Windows runtime, deterministic fixtures, full regression, lint, source contract, definitive central verifier, exact-head CI, and native hosted Linux verified | `ProcessCollectionCoverage` saturates its count, keeps one detail capped at 512 characters including any truncation suffix, and every collector caps PID records at `65,536`. A finite watch with any gap returns `ok:false`; collection plus inspection failures remain explainable. A zero-row snapshot creates a gap because Guard should observe at least itself. Guard passes `234/234`, the cross-platform filter `8/8`, workspace `1,466/1,466`, source contracts `626/626`, and the definitive central verifier/report validator `220/220` in `516.5s`. Exact implementation head `d8ff525c362003a5396258ad8ffaeb51741b9387` passes Avorax CI `32350190743`. Earlier pre-final runs remain superseded. |
| Windows CIM process collector | Historical checkpoint 2189 collector for accessible process images and explicit helper coverage | Superseded and removed by checkpoint 2190 | Checkpoint 2189 verified checked System32 WindowsPowerShell, strict bounded `{Processes,CoverageErrors}` parsing, and fail-visible missing paths. Checkpoint 2190 removes this collector, its script encoding, child process, CIM query, and JSON parser from active Windows process enumeration. The native replacement is inventoried below. |
| Linux procfs process collector | Bound procfs enumeration and distinguish normal churn from inaccessible or malformed records | Source, compiled fixture, and native hosted runtime verified | Non-PID entries and `NotFound` read-link churn are skipped explicitly. Directory-entry, non-`NotFound` link, still-live missing-image, image-validation failures, and zero-row snapshots become gaps. Missing procfs fails visibly. Benign temp-procfs tests cover valid, malformed, exited, missing-target, and empty proc roots. Avorax CI `32350190743`, pinned Ubuntu job `96367469456`, passes the exact locked `process_collection` filter `8/8` on implementation head `d8ff525c362003a5396258ad8ffaeb51741b9387`. |
| Persistent collection-warning state | Surface limited observation without unbounded duplicate log growth | Deterministic runtime and production wiring verified; installed event ACL/service lifetime partial | The first limited poll writes `processCollectionCoverageLimited` with `ok:false`; repeated limited polls do not duplicate it. Three consecutive clear polls rearm warning emission. Event-write failure stops the watcher visibly. |
| Bounded PID/path snapshot | Reinspect changed-path PID reuse and prevent lifetime PID memory accumulation | Deterministic runtime and source contract verified | Only the prior snapshot is retained. Exited PIDs disappear; the same PID with a changed path requires inspection. A process that starts and exits between snapshots or same-path PID reuse entirely between polls remains technically unobservable to polling. |
| Unsupported-platform process observation | Prevent absent platform support from becoming empty success | Explicitly disabled | Non-Windows/non-Linux collection returns a stable disabled error. macOS Guard polling is not claimed until a native bounded collector and tests exist. |
| Process-observation timing boundary | Keep process watcher claims aligned with user-mode polling evidence | Technically limited / installed E2E blocked | This is best-effort post-launch observation. It does not prove kernel interception, pre-execution blocking, Defender replacement, or detection rate. Installed LocalSystem visibility, service lifetime/shutdown, event ACLs, performance, and UI mediation need a disposable elevated Windows host. |

## Checkpoint 2190 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Native Windows process collector | Enumerate accessible Windows process images without a per-snapshot PowerShell/CIM child process | Native Windows runtime, deterministic fixtures, strict lint, central verifier, exact-head CI, and Windows package build verified | The isolated Windows-only module uses Toolhelp, `PROCESS_QUERY_LIMITED_INFORMATION`, and `QueryFullProcessImageNameW(PROCESS_NAME_WIN32)`. It checks API results and returned lengths, closes snapshot/process handles through RAII, and returns only candidate PID/path records plus explicit coverage evidence. The collector has no command launch, script, JSON helper, ambient tool lookup, network input, or process mutation. |
| Native process resource bounds | Bound collector memory, PID work, and query-loop time without hiding truncation | Runtime and source contract verified; individual kernel-call deadline technically limited | Each snapshot permits at most `65,536` PID records, reuses one 32,768 UTF-16 code-unit path buffer, and checks a two-second budget between image queries. Zero record/time limits fail before Win32 use. Record or budget exhaustion records gaps; one native call cannot be cancelled mid-call, so the budget is not a hard kernel-call timeout. |
| Windows process churn and gap classifier | Keep exited-PID races separate from unavailable evidence while preventing either from creating fake clean coverage | Deterministic and live runtime verified | PIDs 0/4 are explicit kernel exclusions. `ERROR_INVALID_PARAMETER` is treated as exited-PID churn. Access denial, query failure, early snapshot termination, unsafe/missing/reparse image paths, limits, and zero-row snapshots remain coverage gaps. The final non-elevated release watch returned `ok:false`, `watchCompletedWithCoverageGaps`, and 290 gap occurrences; the count is not threats. |
| Guard process stop diagnostics | Preserve bounded command output while explaining non-zero stop failures | Runtime/source regression verified; installed process-stop policy E2E partial | Existing checked `taskkill.exe`/`kill` command paths and timeout/output bounds are unchanged. Failure detail now prefers bounded stderr, then bounded stdout, then an explicit no-output diagnostic. This does not broaden stop policy or grant collection-time mutation rights. |
| Checkpoint 2190 verification and package regression | Prove the native collector does not regress shared engines, UI, security gates, or desktop package construction | Local, exact evidence-head, and merged-main hosted evidence verified; release/install intentionally absent | Focused collection passes `14/14`, Guard `239/239`, workspace `1,471/1,471`, source contracts `626/626`, and central verification `220/220` in `687.6s`. Implementation `a928aa0297cadeedd002a4e84cf937250de6bf3b` and evidence `9fec6ccbf36d0146e6ac66fe911e48b0449a98a8` are merged by PR `#42` as `f66ea472bff3d6f0b9ff4cb3b0cfcf2f25dee92a`. Evidence-head CI `32358381763`, package push `32358376699`, package PR `32358381728`, merged-main CI `32359532900`, and merged-main packages `32359532935` pass; publish jobs are skipped. `Cargo.lock` is unchanged. |
| Native process-observation timing boundary | Prevent performance improvement from being presented as kernel or pre-execution protection | Technically limited / installed E2E blocked | Final host-local release samples improve from 763-1,150 ms with the removed helper to 66-186 ms natively, but protected processes still deny access and between-poll starts can be missed. macOS enumeration remains disabled. Installed LocalSystem visibility, event ACLs, service lifetime, UI mediation, and stronger timing claims require separate elevated-host or signed-driver evidence. |

## Checkpoint 2191 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Guard native shared-Windows-directory resolver | Obtain one bounded operating-system source of truth for the Windows directory without trusting mutable process environment | Windows runtime, parser fixtures, strict Guard lint, full regression, central verifier, and hosted implementation-head regression verified | The isolated Windows-only module calls `GetSystemWindowsDirectoryW` with one 32,768-code-unit buffer initialized to a non-NUL sentinel. Zero, excessive, embedded-NUL, and non-API-terminated results fail visibly. Production then requires an absolute rooted local disk path and rejects a reparse target or ancestor chain. The operating system and Win32 ABI remain in the trusted computing base. |
| Guard Windows process-skip policy | Prevent an observed executable from choosing the drive/root that grants its own system-process exclusion | Deterministic and native Windows runtime verified locally; policy breadth technically limited | One immutable policy is created at watcher startup from the native shared Windows directory. The actual root's `System32`, `SysWOW64`, and `Explorer.exe` retain the existing skip. `D:\Windows`, `Windows.old`, traversal, and user-profile lookalikes do not skip when they differ from that root. The actual-root directory exclusion is still path-based and broad; it is not Authenticode trust or proof every resident image is benign. |
| Guard taskkill discovery | Resolve the post-verdict Windows process-stop helper from the same native root and reject linked ancestors before execution | Runtime/source regression verified locally; installed process-stop E2E partial | Only `taskkill.exe` remains allowlisted in this helper. Its complete candidate chain and final regular non-reparse file are checked before the existing bounded command runner starts it. This does not broaden stop policy, elevate privileges, or prove process termination on a protected target. |
| Other Windows helper-root implementations | Keep checkpoint scope honest and inventory similar paths that were not silently changed | Guard consumers superseded by checkpoint 2192; Native Engine follow-up superseded by checkpoint 2194 | Checkpoint 2192 moves Guard `driver_health.rs` and `driver_ipc.rs` to its native resolver. Checkpoint 2194 independently moves Native Engine Authenticode helper discovery to its own bounded native resolver and removes account-environment/helper execution from its private test-only legacy quarantine store. |
| Checkpoint 2191 regression evidence | Prove the root change does not regress process observation, scan, quarantine, update, UI, or resource gates | Local, exact-head, pull-request, and merged-main hosted evidence verified; installed behavior pending | Process skip and system-directory filters pass `3/3` each, process watch `1/1`, collection `14/14`, Guard `244/244`, workspace `1,476/1,476`, source contracts `626/626`, strict Guard Clippy, rustfmt, parser checks, and release build. The central report passes `220/220` in `545.5s`; its validator passes in `1.6s`. Implementation `67e067d2d74d7561c4a48269284702ca50f1b1a1` and evidence `7a48c013a126e9bd68fa705fa7295f6027e29fec` are merged by PR `#43` as `d35ed9e9081a0ffb246a6350688bd833bfa6fe9d`. Evidence-head CI `32368675449`, package PR `32368675439`, merged-main CI `32369958558`, and merged-main packages `32369958304` pass; publish is skipped. Three release watches, including a spoofed child environment, return the intended fail-visible coverage result. `Cargo.lock` and the existing ProgramData vault are unchanged. |

## Checkpoint 2192 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Shared Guard checked Windows root | Turn bounded `GetSystemWindowsDirectoryW` output into one validated local-root and fixed-component helper boundary | Native Windows runtime, parser, adversarial component, strict lint, release build, and full regression verified locally | The module requires a rooted local disk with normal components; rejects linked/reparse ancestors and targets; requires the root to be a directory and helpers to be regular files; and caps helper paths at 1-8 components of at most 128 restricted ASCII characters. Windows, the locked Win32 ABI, process token, and protected system-tree ACLs remain trusted. Metadata-to-launch is not atomic. |
| Driver-health System32 tool discovery | Prevent inherited environment values or ambient PATH from selecting service, filter, boot-policy, or Secure Boot helpers | Source/runtime regression and shared-resolver runtime verified; installed command lifecycle partial | Only `sc.exe`, `fltmc.exe`, `bcdedit.exe`, and `WindowsPowerShell\v1.0\powershell.exe` are accepted beneath the native root. The existing closed-stdin, 30-second, bounded-output runner remains. No driver install/load state was changed; live installed helper/ACL behavior needs an elevated disposable host. |
| Driver-IPC system-path fail-open root | Keep system availability without allowing mutable environment to choose which tree receives system trust | Native Windows environment-spoof and verdict regression verified; signed-driver IPC E2E blocked | `System32`/`SysWOW64` candidates come only from one immutable process-lifetime checked native-root result, avoiding repeated Win32/metadata work per event. Resolver errors are cached, propagate, and make the native port emit its existing reason-bearing fail-open error verdict. The actual-root exception remains broad and path-based, not Authenticode proof. |
| Existing process skip and taskkill consumers | Keep checkpoint-2191 behavior on the same shared checked implementation | Runtime/source regression verified; policy breadth technically limited | Process-skip policy and `taskkill.exe` now delegate to the shared module. Other-drive and environment-spoofed lookalikes remain rejected. Actual-root `System32`/`SysWOW64` and Explorer breadth is unchanged. |
| Remaining Native Engine helper roots | Inventory unchecked consolidation scope without overstating Guard coverage | Superseded by checkpoint 2194 | Native Engine Authenticode helper discovery now uses bounded native Windows-directory resolution. The legacy Native quarantine store is test-only and delegates ACL hardening to the shared platform-security crate; Local Core owns production quarantine. |
| Checkpoint 2192 regression evidence | Prove the consolidation does not regress scan, quarantine, update, UI, false-positive, resource, or package-independent release behavior | Local definitive, exact implementation-head, and merged-main CI verified; installed evidence pending | Native-root tests pass `5/5`, Guard `247/247`, workspace `1,479/1,479`, source contracts `626/626`, strict Guard Clippy, parser checks, and release Guard build. The central report passes `221/221` in `702.3s` and its validator in `2.0s`; a stale report without the new step fails validation. Implementation `f6a40cc200764d0925bbcc3032a74e87be21b232` passed CI `32378264705` and package runs `32378112753`/`32378264725`; PR `#44` merged as `71887973206f5287ba50cc8ff6e5eadcf43c678b` and main CI `32381508352` passed. Main package run `32381508319` attempt 1 preserved an arm64 settle failure; attempt 2 passed with publish skipped. Checkpoint 2193 supersedes that reliability follow-up. The ProgramData vault and `Cargo.lock` remain unchanged. |

## Checkpoint 2193 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| macOS DMG settle and transient verifier | Keep a valid newly created image from failing only because hosted `diskimages-helper` still retains it, without weakening integrity verification | Local source-contract/full-suite and exact-head macOS arm64/x64 builds verified | The builder calls `sync`, waits three seconds, and permits five verification attempts. Only exact `Resource temporarily unavailable` output retries with bounded 2/4/8/16-second backoff. Any other nonzero result fails immediately; the fifth transient result returns its real status. Merged-main run `32381508319` attempt 1 preserves three transient failures, while unchanged-code attempt 2 passes. Exact implementation-head push/PR macOS arm64/x64 jobs all pass `Attempt 1/5`. This is availability hardening, not signature, notarization, or antivirus detection proof. |
| Central desktop-package contract gate | Prevent package retry, manifest, extraction, checksum, SBOM, and workflow safety contracts from drifting outside the one-command antivirus regression report | Mandatory verifier step and independent validator verified locally | `Desktop package builder source contracts` runs 24 tests; 21 pass and 3 Windows symlink tests skip explicitly for missing privilege. The full report contains the step and scope, passes `222/222` in `553.8s`, and an older 221-step report is rejected. Native package construction still requires hosted Linux/macOS/Windows runners. |
| Checkpoint 2193 hosted regression | Prove the changed shell path on real macOS arm64/x64 runners and guard all other desktop packages | Exact evidence head and merged main verified; installed behavior pending | Implementation `07e803c42880e7bc556642e206828f4e5c33b815` and evidence `21db1719154a698b339bbc69cae532ae3185a22b` merged through PR `#45` as `ab1233b4f04a6a4b0d5dd4d949a8003dd41169f1`. Evidence-head CI `32485827199`, package PR `32485827196`, merged-main CI `32487488540`, and merged-main packages `32487488604` pass. Consolidation passes and publication is skipped at both heads. No package was installed. |
| Package protection boundary | Keep package reliability separate from installed runtime protection claims | Technically limited / production signing and installed E2E blocked | No package was installed or published. macOS artifacts remain ad-hoc signed and unnotarized; Windows artifacts remain without approved production signing. Package success does not prove installed service lifetime, persistent monitoring, kernel interception, Defender replacement, pre-execution blocking, or detection rate. |

## Checkpoint 2194 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Native Engine Windows-directory resolver | Obtain a bounded, process-stable OS source of truth for Native Engine system helper and local-artifact trust roots | Native Windows runtime/parser, strict lint, full regression, and central verifier verified locally | Calls `GetSystemWindowsDirectoryW` with one 32,768-code-unit sentinel-filled buffer; rejects API failure, invalid length/NUL shape, non-local or relative roots, non-normal components, links, reparse points, and non-directory roots. Both success and error are cached once per process. Windows, the Win32 ABI, and protected system-tree ACLs remain trusted. |
| Native Engine Authenticode helper discovery | Prevent mutable environment or ambient `PATH` from choosing the PowerShell process used by the bounded Authenticode probe | Unsigned and Microsoft-signed runtime probes plus environment-spoof child verified | Only `System32\WindowsPowerShell\v1.0\powershell.exe` beneath the checked root is accepted. The existing runner remains closed-stdin, 30-second bounded, and limited to 64 KiB output. Metadata validation and process creation are not one atomic handle operation; direct native `WinVerifyTrust` remains possible future hardening. |
| Native Engine Microsoft local-artifact trust | Require more than a familiar path before treating a local system artifact as Microsoft-trusted | Runtime and trust-store regressions verified; publisher/OS boundary technically limited | A candidate must be inside the checked actual Windows tree and pass Microsoft Authenticode verification. A `System32` or `SysWOW64` path alone never supplies clean trust. Missing `SysWOW64`, including on unsupported 32-bit Windows, fails conservatively; the current Windows package job covers x64 only. |
| Legacy Native quarantine compatibility store | Retain narrow historical format tests without creating a competing production mutation owner | Explicitly disabled in production; Windows ACL compatibility verified in tests | The module is private `#[cfg(test)]`. It no longer runs `icacls.exe` or reads `USERNAME`/`USERDOMAIN`; it delegates to shared token-SID DACL application and exact verification. Production Native Engine is detection-only and Local Core exclusively owns quarantine, restore, delete, metadata authentication, and recovery. |
| Standalone Native dependency evidence | Keep the independently buildable Native crate pinned, license-auditable, and compatible with the root workspace | Locked offline all-target check and root-lock cross-check verified | Standalone lock shrinks from 89 packages/88 registry checksums to 72/70. All 70 exact registry package versions already occur in the root lock. `windows-sys` stays at `0.61.2`; `avorax_platform_security` is an internal Windows test-only dependency. |
| Checkpoint 2194 regression evidence | Prove root hardening does not regress scan, quarantine, update, UI, packaging contracts, or resource bounds | Definitive local and exact implementation-head CI/packages verified; evidence-head/merge and installed behavior pending | Focused roots pass `10/10`, Authenticode `2/2`, shared Windows ACL/SID `4/4`, Native 448 tests, workspace `1,486/1,486`, Flutter `838/838`, source contracts `626/626`, and central verification `223/223` in `522.3s`. Exact implementation-head CI `32493387468` and package runs `32493383509`/`32493387522` pass all builds and consolidation with publication skipped. ProgramData vault inventory is unchanged. Evidence-head and merged-main runs remain to be recorded before closure. |

## Checkpoint 2195 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Native direct Authenticode verifier | Establish Windows trust without a script, child process, JSON parser, ambient module path, or network retrieval | Focused Windows, full local regression, and central verifier verified | Opens an absolute bounded regular non-reparse file without write/delete sharing and supplies that handle to `WinVerifyTrust`. It requests no UI, cache-only retrieval, whole-chain revocation checks, and explicit verify/close state handling. Definitively absent/invalid signatures return false; policy, revocation, provider, I/O, cleanup, and unknown failures remain diagnostics. Direct boundary tests pass `7/7`; unsigned/malformed tests pass `2/2`. |
| Microsoft signer identity policy | Prevent any valid Authenticode signer or subject-name lookalike from becoming Microsoft publisher trust | Benign installed-binary runtime verified; catalog/secondary support blocked | Primary signer leaf must have exact organization `Microsoft Corporation` and exact common name `Microsoft Corporation`, `Microsoft Windows`, or `Microsoft Windows Publisher`. Both attributes are required after WinTrust validates the signature/chain. Embedded Microsoft Edge positive evidence and catalog-only WindowsPowerShell conservative rejection pass. Catalog signatures and secondary signer enumeration are not implemented. |
| Scanned-content trust binding | Keep a valid Microsoft signature on one set of bytes from supplying trust to a different hash already scanned | Correct/wrong digest and bounded-read runtime verified | The engine passes its full SHA-256 to the trust layer. Only after valid Microsoft signer verification, the same handle is rewound and rehashed with a 128 KiB buffer under a 512 MiB preflight/live ceiling. Digest mismatch or metadata change is a visible diagnostic. A pre-existing writable/memory-mapped handle and post-verdict mutation remain user-mode TOCTOU limitations. |
| Checkpoint 2195 regression evidence | Prove the native replacement preserves scan, trust, UI, package, and safety contracts | Definitive local and exact implementation-head CI/packages verified; evidence-head/merge pending | Native passes `440 + 6`, workspace `1,484/1,484`, Flutter `838/838`, source contracts `626/626`, strict lint/dependency/security gates and a cold locked release build pass. Central verification passes `224/224` in `686.1s`; stale `223` evidence is rejected and the protected vault is unchanged. Implementation `1e6f86a32f80f6cecec737f249d90a858c0fcb39` passes CI `32581595210` and package push/PR `32581579353`/`32581595294` with publication skipped. Evidence-head CI/packages, PR merge, merged-main checks, and original-tree synchronization remain pending. |

## Checkpoint 2196 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Native SHA-256 catalog lookup | Find Windows catalog membership for a definitively non-trusted embedded signature without network retrieval or path-only trust | Focused runtime/adversarial and full local regression verified | Uses the existing open regular non-reparse handle, SHA-256 catalog context, exact 32-byte member hash, uppercase member tag, and at most 16 catalog candidates. Catalog fixed-buffer paths must be one bounded absolute local-drive value. API, path, limit, and cleanup failures are diagnostics. Boundary tests pass `10/10`. |
| Catalog Microsoft signer policy | Add clean publisher weight only when a matching catalog itself passes Windows trust and the verified leaf is exactly Microsoft | Real benign WindowsPowerShell catalog and hash-binding runtime verified locally | Each candidate uses no-UI cache-only `WinVerifyTrust`, whole-chain revocation policy, explicit state close, exact Microsoft organization/common-name policy, and scan-hash binding. Catalog membership by itself is not trusted. The fixture explicitly fails embedded verification before catalog success; fallback/correct/wrong digest tests pass `3/3`. Secondary signatures remain unsupported. |
| Catalog resource lifetime | Prevent successful-looking results when WinTrust/catalog state cannot be released normally | Source/adversarial contracts and strict lint verified locally | Natural enumeration transfers prior catalog context through the Win32 API; early-exit current context and administrator context are explicitly released. Any normal cleanup failure replaces the verdict, and combined verification/cleanup errors preserve both diagnostics. In-call hard cancellation is unavailable. |
| Checkpoint 2196 regression evidence | Prove catalog support reduces false-positive risk without weakening scan, UI, package, or safety contracts | Definitive local, hosted, merge, and synchronized-tree evidence verified | Post-review Native passes `445 + 6`, standard workspace `1,489`, all-features workspace `1,490`, Flutter `838/838`, source contracts `626/626`, and strict lint/format/analyzer/security/dependency gates pass. Final central verification and independent validation pass exactly `225/225` in `577.2s`; stale `224` evidence is rejected and the protected vault is unchanged. Implementation `3eb079cce859b3523dcb22c983ba81628900f9c5` and evidence `e3b4bdddb1a952c70ef7f4c690f7bff4fac963a0` pass exact-head CI/packages and merge through PR `#48` as `6d721d5d683c8ee90ccb40945894012ceda76803`; merged-main CI/packages pass with publication skipped. All 12 explicit files synchronized after old/new preconditions matched and focused destination checks passed. |

## Checkpoint 2197 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Secondary embedded Authenticode enumerator | Reduce false-positive risk for a valid multi-signed file whose primary valid signer is not Microsoft but a bounded secondary valid signer is exactly Microsoft | Local, hosted, merge, and synchronized-tree evidence verified | Uses `WINTRUST_SIGNATURE_SETTINGS` with count plus exact-index flags. Primary index zero accepts only returned zero or the initialized sentinel because the current provider leaves the output untouched; every secondary must report its requested index exactly. It closes and resets WinTrust state after each call, rejects count drift, and caps primary plus secondaries at 16. Each accepted signature independently passes Windows policy, exact Microsoft leaf identity, and scan-hash binding. Secondary suite passes `14/14`. |
| Embedded signature aggregation policy | Prevent an invalid or ambiguous signature from rescuing an unsafe file or hiding a diagnostic | Verified locally with adversarial tests | A valid exact-Microsoft primary returns trust. A valid other-publisher primary may search indices 1 through the reported count. Invalid secondaries contribute no trust. A definitively invalid primary returns non-trust before secondary aggregation, preserving only the separate catalog fallback. Inconclusive status, I/O, count drift, limit, identity-read, hash-binding, or cleanup errors abort visibly. Pure ordering, early success, invalid-primary, no-match, callback-error, cap, and provider-index tests pass. |
| Benign multi-signature fixture | Exercise the real Windows secondary-index API without malware or fixture execution | Verified on current Windows host and hosted Windows regression | Discovery reads at most 64 non-reparse Edge application entries and a fixed eight-name DLL allowlist. The chosen regular non-reparse Microsoft DLL has a valid primary outside the exact allowlist and a later exact-Microsoft secondary; every secondary returns its exact index with stable count and closed/reset state. No candidate is executed or copied. |
| Checkpoint 2197 regression evidence | Bind implementation, runtime fixture, source contracts, full suites, definitive report, hosted packages, merge, and safe sync | Definitive local, hosted, merge, and synchronized-tree evidence verified | Secondary tests pass `14/14`, Native Engine `448 + 6`, Flutter `838/838`, source contracts `626/626`, strict lint and complete Rust workspace variants pass, and the definitive verifier/validator pass exactly `226/226` in `480.8s`. Stale 225-step evidence is rejected and the protected vault is unchanged. Implementation `e4dcb89e9b6fe487713d07283a719ad41317af22` and evidence `137ee29052a10696956256629f8d729ec561ba40` pass exact-head CI/packages and merge through PR `#49` as `736a9f6ccdb6f7512c854aa816361fc322489222`; merged-main CI/packages pass with publication skipped. All 12 explicit files synchronize after exact preconditions match and focused destination checks pass. Release and installation are not claimed. |

## Checkpoint 2198 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Release Authenticode isolation client | Bound an otherwise non-cancellable WinTrust call without weakening the exact Microsoft signer and scanned-content digest policy | Focused, release-smoke, and full local evidence verified | Non-debug builds launch a hidden mode of the exact current executable with no shell, PATH lookup, network, or visible window. A strict nonce-bound schema carries one bounded UTF-16 path and optional expected SHA-256. Request, stdout, stderr, errors, assigned-child wall time, and reap time are bounded. Any spawn, Job assignment, pipe, timeout, kill, reap, exit, parse, schema, nonce, hash, or child error supplies no trust. The synchronous Windows process-creation call itself has no cancellation API. Debug builds retain the direct path for deterministic unit harnesses. |
| Authenticode helper process lifetime | Ensure timeout or parent teardown terminates the isolated WinTrust operation and does not leave an unbounded child | Adversarial timeout tests verified locally | The parent creates a Windows Job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assigns the child, polls to a 15-second deadline, then kills and reaps within a separate two-second bound. Bounded reader workers preserve stdout/stderr diagnostics and have independent receive deadlines. Helper isolation tests pass `4/4`. The child uses the same security token; this is process/time isolation, not privilege separation or a sandbox. Windows process, Job, pipe, and scheduler semantics remain trusted. |
| Current-executable launch boundary | Prevent ambient helper replacement while avoiding a new release artifact | Release host-lock evidence verified locally | The parent resolves its absolute local-drive current executable, opens it as a bounded regular non-reparse file with read sharing only, retains that handle through launch and response validation, and passes one exact hidden argument. Release smoke passes on Local Core and Guard. The running image and its protected installed location remain trusted; this does not prove package signing or eliminate every pre-existing writable/memory-mapped-handle race. |
| Local Core and Guard helper entry points | Expose exactly the isolated verifier and client self-test modes before normal service startup | Release binary smoke verified locally | Each host recognizes exact one-argument modes. Guard also rejects unknown or multiple arguments instead of falling through to service behavior. The helper reads one bounded request from stdin and emits one bounded response. Embedded Edge, catalog-backed Windows PowerShell, unsigned text, and wrong-hash cases pass on both hosts; no fixture is executed, no service is started, and no machine-wide component is installed. |
| Checkpoint 2198 regression evidence | Prove timeout isolation and helper protocol preserve native Authenticode, catalog, secondary, scan, UI, packaging, and safety behavior | Definitive local, hosted, merge, and synchronized-tree evidence verified | Helper tests pass `4/4`, focused Authenticode `26/26`, Native Engine `452 + 6`, both complete locked workspace variants, Flutter `838/838`, source contracts `627/627`, strict lint/format/analyzer/security/dependency gates, release host builds, and benign release smoke pass. The definitive verifier/validator pass exactly `229/229` in `433s`; stale 226-step evidence is rejected and the protected vault is unchanged. Implementation `10668f17e084187014cc4bfa34a6191c47493d7c` and evidence `e14e6dd9d80e77823c1c1db8d968c5f86f598ce0` pass exact-head CI/packages and merge through PR `#50` as `ab6bd8908d679a60515bac0cf3ceb56f3b6f8a45`; merged-main CI/packages pass with publication skipped. All 18 explicit files synchronize after exact preconditions match and focused destination checks pass. |

## Checkpoint 2199 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Mandatory Microsoft trust hash contract | Prevent a path-only or helper-null request from supplying publisher trust for bytes the scanner did not hash | Windows runtime and source-contract verified locally | The public trust API accepts only `path + expected_sha256`. Strict helper schema uses a required `String`; missing, null, malformed, or mismatched SHA-256 fails. The unused path-only publisher helper is removed. Existing scan production already supplies its computed full-file SHA-256. |
| Authenticode open-handle identity snapshot | Detect file-object or mutation-metadata drift across embedded/catalog WinTrust and content binding | Windows runtime and benign adversarial evidence verified locally | Captures Windows volume/file ID, legacy file index, creation/write/change times, attributes, allocation/end size, link count, delete-pending, and directory state before and after the complete trust operation. It cross-checks legacy/extended volume, creation/write time, size, link count, and attributes. Query failure, internal inconsistency, or drift is diagnostic and cannot become trust. Last-access time is excluded because reading may update it. |
| Authenticode sharing and drift regressions | Exercise realistic user-mode mutation boundaries without malware or fixture execution | Windows runtime verified locally; user-mode limits retained | Temporary benign tests prove pre-existing writer denial, stable repeated snapshots, actual hardlink/link-count drift rejection, and combined verification/snapshot diagnostics. The existing no-write/delete-sharing handle and hash reread remain. Writable mappings created before verification and mutation after verdict remain technically limited. |
| Checkpoint 2199 regression evidence | Bind mandatory hash and file identity to all prior scan, trust, UI, package, and safety behavior | Definitive local, hosted, merge, and synchronized-tree evidence verified | Parser/format/source contracts, focused Authenticode tests, strict Clippy, release host builds/smoke, both complete locked Rust variants, Flutter `838/838`, security/dependency gates, and exactly `230/230` verifier steps in `504.6s` pass. Independent validation passes and rejects stale `229`-step evidence. Native passes `456 + 6`, source contracts `627/627`, locks are unchanged, and the protected vault is unchanged. Implementation `d619c0a5ddb627e9d940d12478d5db9589ee5679` and evidence `b000b8dfc9e4e7427380ddbe80dba958d9d16e95` pass exact-head CI/packages; PR `#51` merges as `264e4551aa930f75d325ebd3df4522bd4f244941` and merged-main CI/packages pass with publication skipped. All 16 files synchronize after exact preconditions and focused destination checks pass. |

## Checkpoint 2200 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Secondary catalog Authenticode selector | Permit a valid exact-Microsoft secondary catalog signature to contribute publisher trust without accepting an arbitrary or ambiguous index | Windows unit/runtime and full local evidence verified; positive secondary fixture partial | Each catalog candidate uses `WINTRUST_SIGNATURE_SETTINGS`, requests primary zero plus secondary count, accepts only zero/provider-untouched primary output and exact secondary indexes, rejects count drift, closes state between attempts, and caps total signatures at 16. Invalid primary signatures are never rescued. Every accepted index still requires valid Windows trust, exact Microsoft leaf identity, and member SHA-256 binding. |
| Catalog secondary aggregation regressions | Keep ordering, cap, primary-invalid short circuit, errors, and Microsoft acceptance deterministic | Benign unit/adversarial evidence verified locally | The unit fixture contains verdict values only and executes no candidate. The focused filter passes `2/2` and proves decision logic, but is not cryptographic or installed-secondary-provider evidence. Error and over-limit paths remain visible and cannot return trust. |
| Catalog provider compatibility and hash binding | Prove signature settings do not break real system-catalog verification and retain exact scanned-content binding | Installed primary-catalog evidence verified; actual secondary acceptance technically partial | A checked WindowsPowerShell file is opened read-only and never executed. Correct hash passes through its real catalog and wrong hash fails. No controlled benign system catalog with a known Microsoft secondary is available, so positive secondary-catalog acceptance is not called fully verified. |
| Checkpoint 2200 regression evidence | Bind the new selection path to prior scan, trust, helper, UI, package, and safety behavior | Definitive local, hosted, merge, and synchronized-tree evidence verified | Authenticode passes `24/24`, Native Engine `458 + 6`, both locked workspaces, release host smoke, Flutter `838/838`, source contracts `628/628`, strict lint/format/security/dependency gates, and exactly `231/231` verifier steps in `424.1s` pass. Independent validation passes and rejects stale `230`-step evidence. Implementation `882f24d45c13b60b952cfacb94d3eee2563fb0f8` and evidence `e863332dec8a646909ba1945aca32875288df76c` pass exact-head CI/packages. PR `#52` merges as `baa39ac316c58b010cb7805785a1fef47c4f0c19`; merged-main CI/packages and the exact 13-file sync plus focused destination checks pass with publication skipped. Verification also exposed and fixed a parallel test-environment race and an unassigned validator scope variable. The protected vault is unchanged. |

## Checkpoint 2201 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Authenticode helper Job resource policy | Bound committed memory, user-mode CPU, process count, crash UI, and parent-loss lifetime before untrusted candidate verification | Windows runtime and full local evidence verified | Requests kill-on-close, no unhandled-exception dialog, 12 seconds per-process user CPU, one active process, 1 GiB per-process commit, and 1 GiB whole-Job commit. `SetInformationJobObject` and exact `QueryInformationJobObject` read-back are mandatory before request input. API or value mismatch supplies no trust. |
| Job-limit adversarial regression | Prove Windows accepted the real policy and future drift cannot silently weaken it | Benign runtime and mandatory verifier evidence verified | Creates a real unnamed Job, checks returned flags/values, then proves altered flags, CPU, active-process, per-process commit, and whole-Job commit evidence fails visibly. The focused filter passes `1/1`; dedicated verifier step 232 and exact report validation pass. A report missing only this step is rejected at 231. |
| Job resource-limit interpretation | Prevent resource limits from becoming a sandbox or total-resource claim | Explicitly technically limited | Commit is not physical working set or I/O bytes; user CPU excludes kernel time. Trusted host startup precedes assignment but blocks on stdin. The helper retains its parent's token. No restricted-token, installed service identity, driver enforcement, pre-execution blocking, or Defender replacement is claimed. |
| Checkpoint 2201 regression evidence | Bind helper limits to all prior trust, scan, UI, package, and safety behavior | Definitive local and exact implementation-head hosted evidence verified; evidence-head/merge/sync pending | Job limits pass `1/1`, helper isolation `5/5`, Authenticode `25/25`, Native Engine `459 + 6`, both locked workspaces, release builds/smoke, Flutter `838/838`, source contracts `629/629`, and strict lint/format/security/dependency gates pass. The definitive and independent validators accept exactly `232/232` in `441s`; a 231-step copy is rejected. Implementation `c8673c134c79f2931e9206b424b2d016a19e1cbd` passes CI `32609018123` and package push/PR `32609010416`/`32609018053`, including every platform, consolidation, checksums, and lockfile SBOM with publication skipped. Locks and the protected vault are unchanged. Evidence-head checks, merge, and original-tree synchronization remain pending. |

## Checkpoint 2202 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Native Engine PUP category token boundary | Prevent arbitrary path fragments from changing an explainable verdict category while retaining explicit PUP evidence | Focused/full runtime and central verifier verified locally | `pup` must be one exact ASCII-alphanumeric-delimited token. The exact merged-main failure path `.tmpuPoV59` retains `SuspiciousDownloader`; explicit `pup_indicator` remains `PotentiallyUnwantedApp`. Direct boundary passes `1/1`, risk fusion `7/7`, and the triggering archive test passes 25 repeats. Verdict score, evidence, and action policy are unchanged. |
| Risk-fusion report contract | Keep the existing complete risk-fusion verifier step and new boundary text mandatory without inflating the suite | Definitive and adversarial validation verified locally | The independent validator requires `native-engine risk fusion regressions` and both token/path scope statements while retaining exactly 232 steps. The final report passes `232/232` in `517.3s`; stale 2201 evidence with the same count but missing scope is rejected. |
| Local Core asset-locator env regression isolation | Keep negative/override configuration tests from contaminating parallel scans | Child-test and repeated parallel full-suite evidence verified | Explicit engine-dir and relative engine-root cases set env only on exact child-test processes. Isolation passes `4/4`, Local Core passes three parallel `535/535` runs, and both locked workspaces pass. Production discovery is unchanged and invalid roots remain rejected. |
| Checkpoint 2202 regression evidence | Repair the exact merged-main failure before any original-tree synchronization | Definitive local evidence verified; hosted/merge/sync pending | Native `460 + 6`, both locked workspaces, strict lint/format, Flutter/analyzer, release smokes, security/dependency/package gates, source contracts `631/631`, and definitive `232/232` pass. Locks and protected vault are unchanged. Exact-head hosted checks, follow-up merge, green merged-main evidence, and sync remain pending. |

## Checkpoint 2203 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2202 integration closure | Close the prior hosted, merge, and safe-sync evidence gap without altering product behavior | Verified | Evidence head `dee97b4`, PR `#54`, merge `4e24e47`, merged-main CI `32613299479`, packages `32613299509`, exact 15-file sync, destination focused checks, release helper smoke, and protected-vault invariant pass. Publication was skipped. |
| Authenticode privilege-stripped thread token | Remove unnecessary enabled privileges from candidate WinTrust work before the candidate path is opened | Verified locally | The one-shot helper derives a `SecurityImpersonation` token with `DISABLE_MAX_PRIVILEGE`, requires exact token type/level, applies it to the current thread, and reads it back. Only `SeChangeNotifyPrivilege` may remain enabled. Any API, type, level, bound, privilege, assignment, read-back, or normal revert failure cannot supply trust. Real-token apply/read-back/revert evidence passes. |
| Restricted-token privilege evidence parser | Prevent a malformed or unexpectedly large token response from becoming least-privilege evidence | Verified locally | `TokenPrivileges` is capped at 64 KiB and 256 entries, length/count arithmetic is checked, and an adversarial enabled non-traverse LUID is rejected. `IsTokenRestricted` is not used because it checks restricting SIDs rather than privilege-only restriction. |
| Helper token cleanup | Restore the helper thread token after success or verification failure | Verified locally | Normal paths call `RevertToSelf` and combine verification plus cleanup diagnostics. Drop supplies best-effort unwind cleanup. The helper is one-shot and no revert failure can return a trust verdict. Success/error/repeat regressions pass. |
| Checkpoint 2203 regression evidence | Bind privilege reduction to all prior Authenticode, scan, UI, package, and safety behavior | Verified, hosted, merged, and synchronized | Focused token `2/2`, complete Authenticode `27/27`, Native `462 + 6`, locked workspace variants, Flutter `838/838`, source contracts `632/632`, release helper smoke, strict gates, and exact `233/233` verifier/validator pass. Stale-count and missing-scope reports are rejected. Implementation `710e38a`, evidence `1a9703d`, PR `#55`, merge `b70298a`, merged-main CI/packages, exact original-tree synchronization, destination checks, and vault audit pass with publication skipped. |
| Residual helper privilege boundary | Prevent a thread-token reduction from being described as a process sandbox | Technically limited | The process keeps its parent token, SID, integrity level, desktop, environment, and access rights; same-process native code can technically revert impersonation. No AppContainer, restricted process token, separate desktop, authenticated cross-token IPC, installed LocalSystem E2E, or pre-execution protection is claimed. |

## Checkpoint 2204 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2203 integration closure | Close hosted, merge, and safe original-tree evidence for the restricted thread token | Verified | Evidence head `1a9703d`, PR `#55`, merge `b70298a`, merged-main CI `32617710173`, packages `32617710182`, exact 12-file sync, destination contracts/token/AuthentiCode/release-smoke checks, and protected-vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |
| Authenticode restricted primary process token | Prevent helper native code from reverting to a process token with unnecessary enabled privileges | Windows runtime and focused regression verified locally | Parent creates and validates a `DISABLE_MAX_PRIVILEGE` primary token and uses `CreateProcessAsUserW`. Child validates exact primary type and bounded privileges before request parsing. Only enabled `SeChangeNotifyPrivilege` is allowed; no unrestricted fallback exists. Real child read-back passes through debug tests and both release hosts. |
| Exact helper handle inheritance | Prevent ambient inheritable handles from crossing into the trust helper | Source, adversarial contract, and release runtime verified locally | Parent pipe ends are non-inheritable. `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` names exactly three distinct valid child stdin/stdout/stderr handles. Invalid or duplicate lists fail before process creation. |
| Suspended Job-before-code boundary | Ensure no helper instruction or candidate processing runs outside configured Job limits | Runtime, timeout, and cleanup regression verified locally | Process starts with `CREATE_SUSPENDED`; exact Job assignment precedes `ResumeThread`. Assignment/resume failure terminates and reaps the suspended child. Existing wall, CPU, commit, process-count, crash-UI, and kill-on-close limits remain mandatory. |
| Restricted-process benign regressions | Prove real child token read-back, strict command/handle validation, timeout termination, and release host compatibility | Verified, hosted, merged, and synchronized | Ignored Rust child fixtures never inspect or execute malware. Process tests pass `2/2`, helper `9/9`, Authenticode `29/29` plus two ignored child fixtures, Native `464 + 6`, release Local Core/Guard smoke, both locked workspaces, Flutter `838/838`, contracts `633/633`, and exact verifier/validator `234/234` pass. Implementation `a0272a3`, evidence `930342f`, PR `#56`, merge `a5f982a`, merged-main CI/packages, exact 12-file original-tree synchronization, destination checks, and vault audit pass with publication skipped. |
| Residual restricted-process boundary | Prevent restricted privileges from becoming an AppContainer or identity-isolation claim | Technically limited | The restricted primary token retains parent SID, integrity, environment, desktop, and ordinary SID-based access. No restricting SIDs, AppContainer, separate desktop, cross-identity IPC, installed LocalSystem E2E, driver enforcement, or pre-execution claim is made. |

## Checkpoint 2205 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2204 integration closure | Close hosted, merge, merged-main, and safe original-tree evidence for restricted helper process creation | Verified | Evidence `930342f`, PR `#56`, merge `a5f982a`, merged-main CI `32621422088`, packages `32621422056`, exact 12-file sync, destination contracts/process/AuthentiCode/lint/release-smoke checks, and protected-vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |
| Authenticode write-restricted request/candidate boundary | Reduce ordinary helper write authority while retaining cache-only Windows trust compatibility | Verified locally and at implementation head | The helper keeps checkpoint 2204's `DISABLE_MAX_PRIVILEGE` primary process token. Before stdin, release code applies a read-back-verified `SecurityImpersonation` token created with `DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED` and exactly one zero-attribute `WinRestrictedCodeSid`; strict request parsing and read-only candidate open/snapshot run under it. Revert is fail-visible before WinTrust/catalog, and a fresh restricted token protects response serialization/output. Complete Authenticode passes `31/31`; both locked workspaces, strict Native/Local/Guard Clippy, Flutter `838/838`, contracts `634/634`, and exact verifier/validator `235/235` pass. Implementation `a5597d2` passes CI `32624862111` and packages `32624842967`/`32624862058`, with publication skipped. |
| Restricted-SID evidence parser | Prevent absent, duplicate, malformed, out-of-buffer, oversized, unexpectedly attributed, or wrong SID evidence from satisfying the boundary | Verified locally | `TokenRestrictedSids` is capped at 64 KiB and 16 entries; count arithmetic, SID pointer range, structural validity, length, exact mandatory/default-enabled/enabled attributes, and exact well-known SID bytes are checked. Any failure prevents publisher trust. Exact policy tests pass; stale-count, missing-step, and missing-scope central reports are rejected. |
| Write-denial/read-continuity regression | Prove the supported write boundary without malware or broad filesystem claims | Verified locally | An isolated ignored child reads/hashes a benign ordinary user-owned temporary file but receives `PermissionDenied` when requesting write access; the parent verifies unchanged bytes. The dedicated filter passes `2/2`; no fixture is executed. |
| Primary write-restricted-token compatibility | Avoid hiding a Windows loader failure behind a weaker launch path | Blocked for this design | Applying the same restricting SID to the primary token caused the child to terminate before user code with `0xC0000142` (`STATUS_DLL_INIT_FAILED`). Avorax keeps the already verified privilege-stripped primary token and applies write restriction to request parsing/candidate preparation plus response output; no launch retry or unrestricted fallback was added. |
| WinTrust write-restriction compatibility | Preserve valid embedded/catalog Microsoft verification without silently bypassing a failed trust call | Technically limited, compatibility verified locally | The first release smoke returned Windows error `127` when WinTrust/catalog remained under the write-restricted thread. The final design reverts fail-visibly and runs only the Windows trust/catalog phase under the privilege-stripped primary token, then reapplies restriction for output. Locked release Local Core/Guard two-host smoke passes embedded/catalog trust, unsigned rejection, and wrong-hash failure. |
| Residual write-restriction boundary | Prevent a write-restricted SID from becoming a full sandbox claim | Technically limited | The impersonation token retains parent SID, integrity, environment, desktop, and ordinary read access. `WRITE_RESTRICTED` checks restricting SIDs only for write access; inherited handle rights and ACLs satisfying both access checks can remain usable. The primary process token is privilege-stripped but not write-restricted, same-process code can technically call `RevertToSelf`, and WinTrust/catalog intentionally use that primary token. No AppContainer, identity isolation, installed LocalSystem E2E, driver enforcement, or pre-execution claim is made. |

## Checkpoint 2206 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2205 integration closure | Close evidence-head, merge, merged-main, and safe original-tree synchronization for write restriction | Verified | Evidence `ffda3a6`, PR `#57`, merge `757432b`, merged-main CI `32626673331`, packages `32626673323`, exact 13-file sync, destination focused/release-smoke checks, and protected-vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |
| Authenticode helper sanitized environment | Remove mutable caller environment input from the one-shot publisher-trust child | Verified locally | Parent builds a bounded Unicode block with exactly `SystemRoot` and `WINDIR`, both from the checked native Windows root, and sets `CREATE_UNICODE_ENVIRONMENT`. No `PATH`, temp, profile, tool, or Avorax override is inherited; no inherited-environment fallback exists. The real child and complete release-host trust checks pass. |
| Authenticode helper explicit current directory | Remove caller current-directory influence from child startup and future relative lookups | Verified locally | Parent supplies the checked, non-reparse native `System32` directory. Relative, parent-traversing, UNC/device, NUL, or oversized directory encoding fails before process creation. Pure and real-child regressions pass. |
| Sanitized-launch adversarial/child evidence | Prove encoding and real process state without executing a candidate | Verified locally and at implementation head | Pure tests cover exact ordering/termination and relative, traversal, UNC, verbatim-device, and NUL paths. An ignored benign child requires exactly two environment entries, exact native-root values, and checked `System32` current directory. The focused filter passes `2/2`; exact verifier/validator `236/236` passes in `461.7s`, and stale-count/missing-step/missing-scope copies are rejected. Implementation `80599a1` passes CI `32629832036` and package push/PR `32629820137`/`32629832031`, with all six artifacts and publication skipped. |
| Residual launch boundary | Keep environment reduction distinct from a sandbox claim | Technically limited | The helper retains parent SID, integrity, desktop/window station, and ordinary read access. Same-process code can mutate its own environment. This is not AppContainer, profile/registry isolation, a separate desktop, or authenticated cross-identity IPC. |

## Checkpoint 2207 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2206 integration closure | Close evidence-head, merge, merged-main, and safe original-tree synchronization for sanitized launch state | Verified | Evidence `5bbe6bd`, PR `#58`, merge `8e9b672`, merged-main CI `32631277590`, packages `32631277605`, exact 12-path sync, destination focused/release-smoke checks, and vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |
| Authenticode helper immutable process mitigation attribute | Prevent avoidable executable-image injection and legacy extension surfaces in the one-shot trust child | Verified locally | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` enables strict handle checks, extension-point disable, dynamic-code prohibition, Microsoft-signed-only binary loading, no remote images, no low-label images, and System32 image preference. It is a second mandatory creation attribute with stable boxed storage and no weaker retry. Strict lint, release builds, and source contracts `636/636` pass. |
| Child mitigation read-back | Prevent a requested but absent/partial policy from being described as active | Verified locally | Before stdin, the child queries signature, dynamic-code, extension-point, image-load, and strict-handle policy groups. Strict-handle evidence requires both invalid-handle exception and permanent-enforcement flags; temporary debugger-induced evidence is rejected. The stricter real-child fixture passes on Windows. |
| Process-mitigation benign regression | Prove real process state and exact pure evidence rejection without executing a candidate | Verified locally and at implementation head | Pure and real-child mitigation tests pass `2/2`; complete Authenticode passes `35/35` with five intentional ignores. The final definitive verifier/validators pass `237/237` in `462.1s`; controlled stale-count, missing-step, missing-verified-scope, and missing-limit-scope reports are rejected. Implementation `a9d930a` passes CI `32634033002` and package push/PR `32634021590`/`32634032975`, with six artifacts/checksums/SBOM and publication skipped. |
| Residual mitigation boundary | Keep image/extension mitigations distinct from identity or content isolation | Technically limited | The policy does not constrain the already mapped helper image or non-image data and does not isolate identity, profile, registry, desktop, or read access. Microsoft-signed-only loading may reject third-party providers/injected security modules; no weaker retry exists. This is not AppContainer, installed LocalSystem E2E, driver enforcement, or pre-execution blocking. |

## Checkpoint 2208 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2207 integration closure | Close evidence-head, normal merge, exact merged-main checks, safe original-tree synchronization, and destination verification | Verified | Evidence `b36b6eb`, PR `#59`, merge `c1d7e969`, merged-main CI `32636058192`, packages `32636058140`, exact 12-path synchronization, destination contracts `636/636`, focused/complete Authenticode, strict lint, release builds, two-host trust smoke, and unchanged protected-vault invariant. Six artifacts/checksums/SBOM passed; publication was skipped. |
| Authenticode helper Low Mandatory primary token | Apply Windows Mandatory Integrity Control/no-write-up across loader, WinTrust, catalog, hash, and response phases | Verified locally and at implementation head | Parent uses `SetTokenInformation(TokenIntegrityLevel)` with exact `WinLowLabelSid` after `DISABLE_MAX_PRIVILEGE`, then validates it before `CreateProcessAsUserW`. Child repeats bounded exact SID/attribute read-back before stdin. No parent-integrity retry exists. Focused and complete Authenticode tests, strict lint, release builds, both workspace variants, and two-host trust smoke pass. Implementation `c7ff9b7` passes CI `32638907677` and package push/PR `32638895902`/`32638907670`. |
| Low-integrity escape/mutation regression | Prove `RevertToSelf` cannot recover parent integrity and ordinary medium-integrity mutation is denied without losing read/hash behavior | Verified locally and at implementation head | The isolated benign child calls `RevertToSelf`, validates its low-integrity primary token, reads and hashes a temporary text fixture, requires access denied for write-open, and proves unchanged bytes. Candidate fixtures are never executed. The dedicated filter passes `2/2`; exact verifier/validators pass `238/238` in `429.7s`, and four malformed report copies are rejected. Exact-head CI and both six-artifact package/SBOM runs pass with publication skipped. |
| Residual Mandatory Integrity Control boundary | Keep MIC/no-write-up distinct from identity, read, desktop, profile, or AppContainer isolation | Technically limited | Low integrity retains parent SID, profile/registry namespace, desktop, normal read access, and intentional stdio handles. Objects explicitly permitting low-integrity writes remain writable. It is not AppContainer/LPAC, separate desktop, authenticated IPC, installed LocalSystem proof, driver enforcement, or pre-execution blocking. |

## Checkpoint 2209 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2208 integration closure | Close exact evidence-head checks, normal merge, merged-main checks, guarded original-tree synchronization, and destination verification for Low Mandatory Integrity | Verified | Evidence `fa7574f`, PR `#60`, merge `1076ac3`, merged-main CI `32640506209`, packages `32640506192`, exact 12-path synchronization, destination contracts `637/637`, focused/complete Authenticode, strict Native lint, locked release builds, two-host trust smoke, and the unchanged protected-vault invariant passed. Six artifacts/checksums/SBOM passed; publication was skipped. |
| Authenticode helper mandatory no-write-up token policy | Prevent a Low-IL label from being treated as enforced no-write-up when the separate token policy is absent or disabled | Verified locally | Parent requires the LSA-created policy inherited through `CreateRestrictedToken` to contain `TOKEN_MANDATORY_POLICY_NO_WRITE_UP` before process creation; child rechecks it before stdin. Policy `2/2`, adjacent isolation filters, complete Authenticode, strict lint, both workspace variants, release builds, and two-host release smoke pass. An attempted unprivileged setter failed visibly with error 1314 and was removed rather than adding privilege. |
| Mandatory-policy adversarial and real-child evidence | Reject policy off, new-process-minimum-only, unknown bits, missing read-back, or child policy drift | Verified locally and at implementation head | Pure cases accept no-write-up and no-write-up plus optional `TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN`; all weaker/unknown cases fail. The benign child validates the real primary policy before stdin. The definitive verifier/validators pass `239/239` in `433.2s`, five malformed reports are rejected, and implementation `7034957` passes CI `32645055401` plus package push/PR `32645042925`/`32645055436`. |
| Residual mandatory-policy boundary | Keep verified no-write-up distinct from read, execute, identity, profile, registry, desktop, or AppContainer isolation | Technically limited | The policy remains LSA-owned and inherited; unprivileged `SetTokenInformation(TokenMandatoryPolicy)` is not used. It does not set no-read-up/no-execute-up and retains parent SID, profile/registry namespace, desktop/window station, ordinary reads, and explicitly low-writable objects. Private desktop, AppContainer/LPAC, installed LocalSystem, driver, and pre-execution evidence remain separate. |
| Benign verifier executable EICAR representation | Preserve standard EICAR detection without embedding its exact static signature in Native/Local Core test executables | Verified locally | The first definitive verifier failed after 38 steps when Defender removed the Native test executable with OS error 225. A single XOR-encoded 68-byte vector is decoded once at runtime through `OnceLock`; Local Core reuses Native matching, exact Rust literals are absent, both test executables self-scan, the no-malware gate passes, and the complete retry passes `239/239`. Defender remains enabled and unchanged. |
| Checkpoint 2209 integration closure | Close exact-head, merge, merged-main, original-tree synchronization, and destination evidence for mandatory no-write-up policy | Verified | Evidence `7fd8734`, PR `#61`, merge `d07220c`, merged-main CI `32646774829`, packages `32646774820`, exact 18-path sync, destination contracts/focused/full Rust/lint/release/trust-smoke checks, and the protected-vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |

## Checkpoint 2210 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Authenticode helper legacy token-virtualization boundary | Ensure the one-shot trust helper cannot run with active legacy per-user file/registry virtualization | Verified locally | Parent and child fixed-size read-back require canonical `TokenVirtualizationAllowed` and exact-zero `TokenVirtualizationEnabled`; query, size, noncanonical, active, or drift errors cannot become trust. The first child run rejected capability value one; that failed design was corrected to distinguish capability from active state. The repaired focused filter passes `2/2`, adjacent filters pass, and complete Authenticode passes `41` with `8` intentional ignores. |
| Authenticode helper UIAccess boundary | Ensure the trust helper token does not receive UIAccess treatment across UIPI boundaries | Verified locally | Parent and child require exact-zero `TokenUIAccess` before process creation or request parsing. A nonzero or malformed result fails visibly; there is no setter, privilege addition, or weaker retry. Real-child, pure rejection, strict lint, locked workspace, release-host smoke, and full local regression evidence pass. |
| Token virtualization/UIAccess report contract | Prevent stale or scope-incomplete verification reports from claiming the new boundary | Verified locally and at implementation head | The verifier has a dedicated token-safety filter; the independent validator requires exactly 240 steps, exact step presence, verified scope, and technical-limit scope. Source contracts pass `640/640`; the definitive report passes `240/240` in `458s`, and five controlled malformed reports are rejected. Exact implementation `c744fa9` passes CI `32649764260` and package push/PR `32649749634`/`32649764310`, with six artifacts, checksums, lockfile SBOM, and publication skipped. |
| Residual token boundary | Keep inactive virtualization/disabled UIAccess distinct from capability, identity, and resource isolation | Technically limited | `TokenVirtualizationAllowed` may remain one; trusted helper code has no enable path, but capability is not removed. The checks do not create another SID, profile, registry namespace, desktop/window station, or deny ordinary reads/inherited standard handles. AppContainer/LPAC, private desktop, installed LocalSystem, driver enforcement, and pre-execution evidence remain separate. |
| Checkpoint 2210 integration closure | Close exact-head, merge, merged-main, original-tree synchronization, and destination evidence for token virtualization/UIAccess | Verified | Evidence `8228daf`, PR `#62`, merge `425e663`, merged-main CI `32651609367`, packages `32651609388`, exact 12-path sync, destination contracts/token/Authenticode/no-malware/lint/release/trust-smoke/full-workspace checks, exact lockfiles, and the protected-vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |

## Checkpoint 2211 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Authenticode helper Job UI restrictions | Constrain cross-process USER handles, clipboard reads/writes, system parameters, display settings, global atoms, desktop creation/switching, and `ExitWindows` before helper execution | Verified locally | `JobObjectBasicUIRestrictions` is configured with exact `JOB_OBJECT_UILIMIT_HANDLES`, `JOB_OBJECT_UILIMIT_READCLIPBOARD`, `JOB_OBJECT_UILIMIT_WRITECLIPBOARD`, `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS`, `JOB_OBJECT_UILIMIT_DISPLAYSETTINGS`, `JOB_OBJECT_UILIMIT_GLOBALATOMS`, `JOB_OBJECT_UILIMIT_DESKTOP`, and `JOB_OBJECT_UILIMIT_EXITWINDOWS`, then queried with an exact returned-size and flag comparison before assignment/resume. Exact/adversarial read-back passes `2/2`; release Local Core/Guard trust smoke remains compatible. |
| Job UI restriction failure boundary | Prevent partial or unavailable UI restriction configuration from degrading silently | Verified locally | Set/query/returned-size mismatch, exact-flag mismatch, Job assignment, or resume failure remains diagnostic and cannot become publisher trust. There is no unrestricted or weaker-flag retry. Missing/unknown-flag and wrong-size regressions pass. |
| Job UI restriction report contract | Prevent stale verification reports from claiming this boundary | Verified locally and at implementation head | The dedicated filter is mandatory; the independent validator requires its exact step, returned-size and flag verified scope, technical-limit text, and exactly `241` steps. Source contracts pass `641/641`; after final review rejected the earlier runs for missing returned-size implementation and then missing returned-size scope enforcement, corrected retry 3 passes `241/241` in `434.1s`, and five fresh malformed reports are rejected. Exact implementation `024d63f` passes CI `32655155577` and package push/PR `32655130037`/`32655155628`, with six artifacts, checksums, lockfile SBOM, administrative MSI extraction, and publication skipped. |
| Residual UI/resource boundary | Keep Job UI limits distinct from identity, desktop, and object isolation | Technically limited | `JOB_OBJECT_UILIMIT_DESKTOP` blocks desktop creation/switching but does not create a private desktop or window station. Job UI limits do not change SID/profile, remove filesystem/registry/network/read access, constrain named kernel objects, or provide AppContainer, driver, or pre-execution enforcement. |
| Checkpoint 2211 integration closure | Close exact-head, merge, merged-main, original-tree synchronization, and destination evidence for Job UI restrictions | Verified | Evidence `9378955`, PR `#63`, merge `33cafa5`, merged-main CI `32656681010`, packages `32656681007`, exact 12-path sync, destination contracts/Job-UI/Authenticode/lint/release/trust-smoke/no-malware/both-workspace checks, exact lockfiles, and the protected-vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |

## Checkpoint 2212 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Authenticode helper private desktop | Separate helper windows, hooks, menus, and desktop objects from the interactive desktop before trust work | Verified locally and hosted at implementation head | Parent creates a unique bounded `CreateDesktopW` object in the current process window station while temporarily using a read-back-verified low-integrity `SecurityImpersonation` token derived from the exact child primary token, requires successful `RevertToSelf`, reads back exact name/size and non-inheritable zero-hook flags, supplies `STARTUPINFOEXW.lpDesktop`, retains the handle through child exit, and requires checked `CloseDesktop` success afterward. Child exact-binding occurs before token validation or stdin. The first medium-integrity creation attempt failed visibly with loader status `0xC0000142`; no broad DACL or default retry was added. Private-desktop `2/2`, Authenticode `45` passed/`9` ignored, both locked workspaces, CI `32660616609`, and package push/PR `32660604610`/`32660616617` pass. Integration/destination and installed evidence remain pending. |
| Private-desktop fail-visible contract | Prevent missing, malformed, substituted, default, inheritable, or unclosed desktop state from degrading to trust | Verified locally | Real benign child and adversarial name/binding/flag tests pass. Final review found and repaired unchecked `CloseDesktop` result handling before retaining final evidence. Verifier step `242`, exact independent validator requirements, and source contract `642` pass; the definitive retry report is `242/242` in `473.5s`, and five malformed report copies are rejected. No default-desktop fallback exists. |
| Residual desktop/window-station boundary | Keep desktop isolation distinct from identity and a private window station | Technically limited | `CreateDesktopW` remains in the current process window station and inherits its security descriptor. It does not isolate station-wide clipboard/global atoms, SID/profile/registry/filesystem/network/read access, named kernel objects, or desktop heap beyond existing helper lifetime/concurrency bounds. It is not AppContainer, cross-identity IPC, driver, or pre-execution enforcement. |

## Checkpoint 2213 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2212 integration closure | Close exact-head, normal merge, merged-main checks, guarded original-tree synchronization, and destination verification for the private desktop | Verified | Evidence `e73a56d`, PR `#64`, merge `744c492`, merged-main CI `32662681992`, packages `32662682077`, exact 13-path synchronization, destination contracts/private-desktop/Authenticode/lint/release/trust-smoke/no-malware/both-workspace checks, exact Native/root Cargo and Flutter lockfiles, and the protected-vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |
| Authenticode parent pipe endpoint contract | Prove the exact three handles offered for inheritance are anonymous-pipe endpoints with intended roles and flags | Verified locally and hosted at implementation head | Every `CreatePipe` endpoint is queried with `GetFileType` and `GetHandleInformation`. `GetNamedPipeInfo` verifies server/read endpoints; exact API return-role assignment preserves child stdin as read and stdout/stderr as writes without making an unsupported write-handle query. Parent endpoints must have zero flags and child endpoints exactly `HANDLE_FLAG_INHERIT`. Focused, complete Authenticode, strict lint, release, both-workspace, and exact-head CI/package evidence pass. |
| Authenticode child standard-handle binding | Prevent substituted, duplicated, non-pipe, misbound, or recursively inheritable standard handles from reaching trust work | Verified locally and hosted at implementation head | Before private-desktop, token, mitigation, or stdin processing, the child requires exact `STARTF_USESTDHANDLES`, exact `GetStdHandle` identity against startup state, three valid distinct `FILE_TYPE_PIPE` handles, queried stdin server/read mode, stdout/stderr identity bound to parent-created write handles, and exact initial inheritance. It then clears `HANDLE_FLAG_INHERIT` on all three and requires exact-zero read-back. Real-child/adversarial `2/2`, Authenticode `47` passed/`10` ignored, two-host release trust smoke, CI `32665658235`, and package push/PR `32665646920`/`32665658257` pass. Integration/destination and installed evidence remain pending. |
| Standard-handle verifier/report contract | Prevent absent or stale proof from claiming the new boundary | Verified locally and hosted at implementation head | The verifier adds exact step 243 and the independent validator requires exactly `243` steps, exact step presence, parent/child verified scope, fail-visible language, and technical-limit scope. Source contracts pass `643/643`; the definitive report passes `243/243` in `469.2s`, and stale-count, renamed-step, missing-child-scope, missing-limit-scope, and skipped-step copies are rejected. Exact lockfiles, protected-vault invariant, exact-head CI, six artifacts, checksums, lockfile SBOM, and administrative MSI extraction pass; publication is skipped. Evidence-head/integration remains pending. |
| Residual anonymous-pipe boundary | Keep exact inherited IPC binding distinct from authenticated cross-identity IPC | Technically limited | Exact standard-handle binding narrows inherited helper IPC only. Anonymous pipes and the nonce do not provide cross-identity authentication or encryption, prevent same-user handle duplication, or isolate the named-kernel-object namespace. This is not AppContainer, installed LocalSystem, driver, or pre-execution enforcement. |

## Checkpoint 2214 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2213 integration closure | Close exact-head, normal merge, merged-main checks, guarded original-tree synchronization, and destination verification for standard handles | Verified | Evidence `128a56b`, PR `#65`, merge `ce80ce2`, merged-main CI `32667384412`, packages `32667384370`, exact 13-path synchronization, destination contracts/standard-handle/Authenticode/lint/release/trust-smoke/no-malware/both-workspace checks, exact Native/root Cargo and Flutter lockfiles, and the protected-vault invariant pass. Six artifacts/checksums/SBOM passed and publication was skipped. |
| Parent exact Job membership and process identity | Prevent a successful assignment call from being treated as proof that the intended still-suspended helper is the sole member of the intended Job | Verified and integrated | After assignment and before resume, nonzero `PROCESS_INFORMATION.dwProcessId` equals `GetProcessId`; `IsProcessInJob` confirms the exact parent-created Job; `JobObjectBasicProcessIdList` returns exactly `sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)`, one assigned/listed process, and the same sole PID. Failure terminates/reaps the suspended child without retry. Focused real-child/adversarial checks pass `2/2`; complete Authenticode passes `49` with `11` intentional isolated-child ignores. Exact head `6c3bad3`, evidence `3014c44`, PR `#66`, merge `cbf6203`, and merged-main CI `32672025315` pass. |
| Child Job membership gate | Prevent helper trust work when the running child is no longer under any Windows Job | Verified and integrated | As the first child check, nonzero `GetCurrentProcessId` and `IsProcessInJob(GetCurrentProcess(), NULL, ...)` prove membership in some Job before standard handles, desktop, token, mitigation, stdin, request, or candidate processing. API/false results fail visibly. Native Engine passes `485` with `11` intentional ignores in both locked workspace variants; strict lint and release trust smoke pass. Exact-head, evidence-head, merged-main, and destination checks pass. |
| Job membership verifier/report contract | Prevent stale or scope-incomplete evidence from claiming this boundary | Verified and integrated | Verifier step 244 and the independent exact-244 validator require the dedicated filter, parent/child scope, suspended-process cleanup language, and technical limit. Source contracts pass `644/644`; the definitive report passes `244/244` in `464.3s`. Six fresh adversarial report copies are rejected. Flutter `838/838`, no-malware/dependency gates, exact lockfiles, protected-vault invariant, six package artifacts, checksums, lockfile SBOM, administrative MSI extraction, exact 12-path destination synchronization, and destination reruns pass; publication is skipped. |
| Residual Job membership boundary | Keep Job/process read-back distinct from durable identity and authenticated IPC | Technically limited | Exact-parent `IsProcessInJob` plus `JOBOBJECT_BASIC_PROCESS_ID_LIST` is point-in-time process/Job state. The child null-Job query proves only some Job. Neither authenticates pipes, changes identity, provides AppContainer/LPAC or installed LocalSystem proof, or demonstrates driver/pre-execution enforcement. |

## Checkpoint 2215 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Checkpoint 2214 integration closure | Close exact-head, normal merge, merged-main checks, guarded original-tree synchronization, and destination verification for Job membership | Verified | Evidence `3014c44`, PR `#66`, merge `cbf6203`, merged-main CI `32672025315`, packages `32672025303`, exact 12-path synchronization, destination contracts/Job-membership/Authenticode/lint/release/trust-smoke/no-malware/dependency/full-workspace/Flutter checks, exact lockfiles, and the protected-vault invariant pass. Publication was skipped. |
| Authenticode sanitized parent-PID launch evidence | Give the child one bounded expected parent creator identity without ambient environment inheritance | Verified and integrated | Parent nonzero `GetCurrentProcessId` is canonical decimal in `AVORAX_AUTHENTICODE_PARENT_PID`; environment remains exactly three variables. Empty, zero, noncanonical, signed, whitespace, non-ASCII, embedded-NUL, oversized, or out-of-range values fail before trust work. Local, exact-head/evidence-head, merged-main, and destination verification pass through PR `#67` and merge `c298c3a`. |
| Authenticode stdin parent-creator binding | Bind the inherited stdin server/read handle to the exact process that created its client/write peer | Verified and integrated | After standard-handle validation, `GetNamedPipeClientProcessId(stdin)` equals the sanitized nonzero parent PID and differs from child PID. API, zero, self, or mismatch failure is diagnostic before private desktop, token, mitigation, stdin, request, candidate, or trust work. Real-child/adversarial checks pass `2/2`; complete Authenticode passes `59` with `12` intentional ignores locally and after exact destination synchronization. |
| Authenticode stdout/stderr parent-creator binding | Bind both inherited output client/write handles to their exact server/read creator | Verified and integrated | `GetNamedPipeServerProcessId(stdout)` and `GetNamedPipeServerProcessId(stderr)` independently return the exact sanitized parent PID. Source contracts pass `645/645`; verifier/validator pass `245/245`; seven malformed reports are rejected. Evidence-head CI `32675987165`, packages `32675987151`, merged-main CI `32676733841`, packages `32676733940`, exact 12-path synchronization, destination full verifier/workspaces/Flutter/lint/trust-smoke/lock/vault checks, six artifacts/checksums/SBOM, and skipped publication pass. |
| Residual anonymous-pipe peer boundary | Keep creator-PID binding distinct from authenticated two-way peer identity | Technically limited | Anonymous `CreatePipe` endpoints connect in the parent before inheritance. The APIs prove parent creator identity from the child's handles, not inheriting child identity back to the parent. The environment PID is not secret; same-user duplication, encryption, durable/cross-identity authentication, AppContainer, driver, and pre-execution evidence remain absent. |
| Authenticode parent-child handshake | Bind both live helper processes before request/candidate/trust work | Verified locally and at implementation head; merge/destination integration pending | Dedicated random one-instance local named pipe; child `GetNamedPipeServerProcessId` must equal exact parent and parent `GetNamedPipeClientProcessId` must equal exact launched child. Exact v4 token, current-user/SYSTEM DACL, low-integrity label, remote rejection, overlapped timeout/cancel settlement, and fail-visible cleanup pass focused runtime, complete Authenticode, release trust smoke, source contracts `646/646`, verifier/validator `246/246`, hosted CI `32680555167`, and package push/PR `32680536082`/`32680555166`. |
| Authenticode parent-child handshake limitations | Avoid cross-identity, encryption, driver, or pre-execution overclaim | Technically limited | Ephemeral same-user PID/token binding does not defeat privileged same-user process inspection, process-memory access, trusted in-process code, or kernel compromise. It is not AppContainer/LPAC, installed LocalSystem, durable authenticated IPC, a driver, or pre-execution blocking. |

## Checkpoint 2216 Integration Closure

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Authenticode parent-child handshake integration | Close exact-head, normal merge, merged-main, synchronization, and destination evidence | Verified and integrated | Evidence `b1c5b4e`, PR `#68`, merge `e883c187`, merged-main CI `32682998536`, packages `32682998541`, exact 13-path synchronization, destination source/handshake/Authenticode/lint/release/trust-smoke/both-workspace/Flutter checks, and exact `246/246` destination verifier/validator pass. Lockfiles and the protected vault remain exact; publication was skipped. |
| Residual parent-child boundary | Keep integrated same-user process binding distinct from a stronger security boundary | Technically limited | Random token, exact live PIDs, restrictive ACL/MIC, and cancellation settlement do not provide encrypted durable cross-identity IPC, AppContainer/LPAC, installed LocalSystem, driver enforcement, or pre-execution blocking. |

## Checkpoint 2217 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Handshake pipe applied-security read-back | Prevent intended SDDL construction from being treated as proof that Windows applied the exact pipe security boundary | Verified and integrated | Before event/connect/launch, `GetSecurityInfo(SE_KERNEL_OBJECT)` queries exactly `DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION` under existing `READ_CONTROL`; bounded structured ACL/ACE evidence plus `MapGenericMask` must prove `SE_DACL_PROTECTED`, exact ordered SYSTEM/current-user full control, and one low-integrity no-write-up label. Query or mismatch fails visibly. Implementation `a518e93`, evidence `5fe8dd2`, PR `#69`, merge `3fe2b87`, implementation/evidence/merged-main CI and package runs, exact 12-path synchronization, destination Authenticode `62/13`, and verifier/validator `247/247` pass. |
| Least-privilege security query | Avoid expanding UI/helper privileges merely to audit the pipe | Verified locally and hosted at implementation head | The control does not request the full SACL, `ACCESS_SYSTEM_SECURITY`, or `SeSecurityPrivilege`. `LABEL_SECURITY_INFORMATION` returns only mandatory-label evidence. Strict lint, locked workspaces, release builds, two-host benign trust smoke, hosted CI, all six package artifacts, checksums, lockfile SBOM, and administrative MSI extraction pass without a crate/package/feature/lock change; publication is skipped. |
| Residual security-descriptor boundary | Keep point-in-time user-mode read-back distinct from stronger IPC and interception | Technically limited | A privileged same-user actor, injected trusted code, SYSTEM, or kernel compromise remains outside this check. Exact ACL/MIC read-back is not encrypted cross-identity IPC, AppContainer/LPAC, installed LocalSystem, production signing, a driver, or pre-execution blocking. |

## Checkpoint 2218 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Classification | Evidence / limitation |
| --- | --- | --- | --- |
| Handshake client applied-security read-back | Verify the exact descriptor on the child-opened endpoint before launch-token transfer | Verified and integrated | Child uses exactly `GENERIC_WRITE | READ_CONTROL`, validates endpoint and exact parent PID, resolves its process-token SID, and reuses bounded `GetSecurityInfo` DACL/label verification before `WriteFile`. Access, query, SID, descriptor, ACL/ACE, policy, label, or order failure cannot reach trust; no weaker retry exists. Real child `1/1`, Authenticode `63/13`, source contracts `648/648`, strict lint, locked workspaces, release smoke, Flutter `838/838`, verifier/validator `248/248`, evidence `eb11c81`, PR `#70`, merge `1e453005`, evidence/merged-main CI/packages, exact 12-path sync, and destination verifier `248/248` pass; eight malformed reports are rejected. |
| Client query least privilege | Avoid expanding the child to descriptor mutation or broad SACL privileges | Verified and integrated | Only `READ_CONTROL` is added to required `GENERIC_WRITE`. No `WRITE_DAC`, `WRITE_OWNER`, full SACL, `ACCESS_SYSTEM_SECURITY`, `SeSecurityPrivilege`, crate, package, feature, or lock change is introduced. Destination safety/dependency gates, exact lock blobs, protected-vault inventory, full workspaces, lint, release/trust smoke, and Flutter `838/838` pass; publication is skipped. |
| Residual client read-back boundary | Keep dual endpoint evidence distinct from stronger isolation | Technically limited | The check is point-in-time and same-user. It does not defeat privileged same-user/in-process/SYSTEM/kernel mutation or inspection and is not encryption, cross-identity IPC, AppContainer/LPAC, installed LocalSystem, production signing, driver enforcement, or pre-execution blocking. |

## Checkpoint 2219 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode handshake least-privilege DACL | Give each named principal only the pipe rights required by the bounded parent-child token exchange | Verified and integrated | Protected ordered DACL grants SYSTEM normalized full control and the current user normalized generic read plus generic write. Exact parent/client read-back rejects full-control, read-only, write-only, execute, delete, `WRITE_DAC`, `WRITE_OWNER`, or any other mismatched current-user ACE. Real child `1/1`, Authenticode `56/13`, source contracts `649/649`, both locked workspaces, strict lint, release smoke, Flutter `838/838`, exact verifier/validator `249/249`, and eight malformed-report rejections pass. Implementation `5171fb4e`, evidence `be122479`, PR `#71`, merge `e6caf818`, implementation/evidence/merged-main CI and package runs, exact 12-path destination synchronization, destination verifier `249/249` in `486.9s`, locks, and vault pass; publication is skipped. |
| Handshake DACL ownership boundary | State what the narrower current-user ACE cannot guarantee | Technically limited | The creator's token default owner is not changed or independently read back. If the current user owns the pipe, Windows ownership supplies implicit `READ_CONTROL` and `WRITE_DAC`. Dual checks are point-in-time detection, not prevention of same-user descriptor mutation, encrypted/authenticated cross-identity IPC, AppContainer/LPAC, driver enforcement, or pre-execution protection. |

## Checkpoint 2220 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Handshake Owner Rights boundary | Suppress the named-pipe owner's implicit DACL-management authority while preserving exact protocol access | Scripted; verification pending | Descriptor explicitly sets and reads back current process-token owner, then requires ordered `S-1-3-4` Owner Rights with only `READ_CONTROL`. Benign `WRITE_DAC`-only reopen and adversarial owner/SID/mask/flag/order tests, verifier step 250, validator, and source contract 650 are scripted but not yet executed. |
| Owner Rights failure boundary | Prevent missing or malformed owner controls from becoming publisher trust | Scripted; verification pending | Parent and child require exact owner, DACL, and label evidence before token exchange. Missing, reordered, zero, `WRITE_DAC`-augmented, flagged, extra, or wrong-principal evidence has no weaker fallback. |
| Residual owner boundary | Keep narrower owner rights distinct from identity isolation | Technically limited | This remains point-in-time same-user evidence. Protocol read/write, trusted same-user code, existing handles, privileged ownership changes, process injection, handle duplication, SYSTEM/administrators, and kernel compromise are not prevented. It is not encrypted cross-identity IPC, AppContainer/LPAC, installed LocalSystem, driver enforcement, or pre-execution protection. |
| Checkpoint 2220 local runtime evidence | Exercise the production descriptor, real pipe access check, adjacent trust hosts, and regressions before hosted integration | Locally verified | Owner Rights `1/1`, handshake `4/4`, Authenticode `57/13`, Native `493/13`, Local Core `536/536`, Guard `248/249`, source contracts `650/650`, strict lint, both locked workspaces, release/two-host trust smoke, and Flutter `838/838` pass. Hosted, merge, synchronization, and destination evidence remain pending. |
| Checkpoint 2220 definitive report contract | Prevent stale or incomplete evidence from claiming Owner Rights enforcement | Locally verified | Exact `250/250` in `452.7s`, embedded/standalone validation, and nine malformed-report rejections pass. Three lock blobs and the protected-vault invariant remain exact. Hosted, integration, synchronization, and destination evidence remain pending. |
| Checkpoint 2220 implementation-head hosting | Bind CI and package evidence to the exact Owner Rights implementation | Hosted verified | SHA `6f90f9234375ceb22107aba426401e38838ec9b8` passes CI `32712875828` and package push/PR runs `32712856310`/`32712875850`. Six release files, seven matching SHA-256 rows, and CycloneDX 1.6/569-component SBOM evidence pass; publication is skipped. Evidence-head, merge, merged-main, synchronization, and destination evidence remain pending. |
| Checkpoint 2220 integration and destination closure | Require exact-head, merged-main, guarded sync, and independent destination proof | Verified | Evidence `a99b03a` and merge `2bd8956` pass CI/packages; publication is skipped. Twelve destination blobs match the merge, full Rust/Flutter checks pass, and the destination report validates exact `250/250` in `494.3s`. Locks and vault remain exact. Same-user point-in-time and pre-execution limitations remain explicit. |
| Authenticode handshake client-token binding (checkpoint 2221) | Authenticate the connected helper security token before accepting the random launch token | Locally verified | Child requests explicit `SecurityImpersonation` SQOS. After the bounded message read, parent `ImpersonateNamedPipeClient` requires exact launch user, low integrity, no-write-up, privilege stripping, zero restricting SIDs, canonical virtualization/UIAccess state, then proves `RevertToSelf`. Source contract 651 and verifier/validator 251-step evidence pass. This remains same-user message binding, not encrypted/cross-identity IPC, AppContainer/LPAC, driver, or pre-execution enforcement. |
| Checkpoint 2221 local runtime and regression evidence | Prove real client-token binding, adversarial rejection, cleanup, and product compatibility before definitive evidence | Locally verified | Client-token `2/2`, handshake `6/6`, Authenticode `67/13`, Native `495/13`, Local Core `536/536`, Guard `248/249`, both locked workspaces, strict lint, source contracts `651/651`, and Flutter `838/838` pass. Definitive verification passes exact `251/251` in `487.9s`; embedded/standalone validation and nine malformed-report rejections pass. Locks/vault remain exact; hosted/integration/destination evidence remains pending. |
| Checkpoint 2221 implementation-head hosting | Bind hosted CI and package evidence to the exact client-token implementation | Hosted verified | SHA `014e5b98ec703e30b8c59a7d26f6511f1c5aa7ed` passes CI `32722684598` and package push/PR runs `32722662492`/`32722684574`. Windows MSI/EXE, Linux DEB/tar, both macOS DMGs, consolidation, seven checksums, and CycloneDX 1.6/569-component SBOM pass; publication is skipped. Evidence-head, integration, synchronization, and destination proof remain pending. |
| Checkpoint 2221 integration and destination closure | Require exact evidence-head, merged-main, guarded sync, and independent destination proof | Verified | Evidence `b60f500`, merge `c4d9975`, evidence-head and merged-main CI/packages pass with publication skipped. Twelve destination blobs match the merge; focused/full Rust and Flutter checks pass; destination verifier validates exact `251/251` in `463.5s`. Locks and vault remain exact. Same-user, injection/duplication, cross-identity, AppContainer/LPAC, driver, and pre-execution limits remain explicit. |

## Checkpoint 2222 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode launch logon-session capture | Bind expected client identity to the exact launch primary token before exposing the handshake endpoint | Locally and hosted verified | Parent queries launch user SID, `TokenStatistics.AuthenticationId`, and `TokenSessionId` before `CreateNamedPipeW`; launch SID must equal pipe owner and an empty authentication LUID fails. Source contracts `652/652`, benign/adversarial logon-session `2/2`, complete Authenticode `69/13`, Native `497/13` plus compiler `6/6`, exact definitive `252/252`, and implementation-head hosting pass. Integration/destination evidence remains pending. |
| Connected client logon-session validation | Reject a same-user client from a different Windows logon session before publisher trust | Locally and hosted verified | After message read and `ImpersonateNamedPipeClient`, both `AuthenticationId` halves and exact `TokenSessionId` must match. Exact-size query failure or drift is diagnostic; existing fail-visible `RevertToSelf` remains mandatory. Both locked workspaces, Local `536/536`, Guard `248/249`, strict lint, Flutter `838/838`, definitive step 252, and implementation-head hosting pass. Integration/destination evidence remains pending. |
| Residual logon-session boundary | Keep session binding distinct from stronger process and IPC authentication | Technically limited | This narrows same-user cross-logon-session substitution at one message. It does not prove token uniqueness, prevent same-session injection/handle duplication, encrypt IPC, change identity, provide cross-identity authentication or AppContainer/LPAC, or demonstrate driver/pre-execution enforcement. |
| Checkpoint 2222 definitive local evidence | Prevent stale or incomplete evidence from claiming exact launch-session binding | Locally verified | Exact verifier/validator `252/252` passes in `507.8s`; target passes in `0.3s`, embedded/independent strict validation passes, and nine malformed reports are rejected. Defender is opt-in, Rust/Flutter are required, and locks/vault remain exact. Integration/destination evidence remains pending. |
| Checkpoint 2222 implementation-head hosting | Bind CI and package evidence to the exact logon-session implementation | Hosted verified | SHA `0a24ac25fcdedf1ef50af8acb9b71499caf9ac69` passes CI `32732523250` and package PR/push runs `32732523189`/`32732497575`. The push succeeds on attempt 2 after a retained transient arm64 `hdiutil` resource failure. Six release files, seven matching SHA-256 rows, and CycloneDX 1.6/569-component SBOM evidence pass; publication is skipped. Integration and destination proof remain pending. |
| Checkpoint 2222 integration and destination closure | Require exact evidence-head, merged-main, guarded synchronization, and independent destination proof | Verified | Evidence `2f02714`, merge `e644d77`, evidence-head and merged-main CI/packages pass with publication skipped. Twelve destination blobs/raw hashes match the merge/source; focused and full Rust/Flutter checks pass; destination verifier validates exact `252/252` in `496.7s`. Locks and vault remain exact. Same-session, cross-identity, AppContainer/LPAC, installed LocalSystem, driver, and pre-execution limits remain explicit. |
| Authenticode connected-client token stability | Detect token replacement or modification during successful client-token validation | Locally verified | Exact `TokenStatistics.TokenId` and `ModifiedId` are captured before all property checks and queried again afterward. Empty initial ID, fixed-size query failure, token-instance drift, or modified-context drift fails visibly. Source contract 653 and verifier step 253 pass locally. This does not bind the impersonation token object to the launch primary token or prevent same-session injection/handle duplication, cross-identity IPC, AppContainer/LPAC, driver, or pre-execution limits. |
| Checkpoint 2223 definitive local evidence | Prevent stale or incomplete reports from claiming token-stability coverage | Locally verified | Token stability `2/2`, Authenticode `71/13`, Native `499/13` plus compiler `6/6`, source contracts `653/653`, both locked workspaces, strict lint, Flutter `838/838`, and exact verifier/validator `253/253` in `492.9s` pass. Nine malformed reports are rejected. Hosting, integration, and destination evidence remain pending. |
| Checkpoint 2223 implementation-head hosting | Bind hosted CI and multi-platform package evidence to the exact token-stability implementation | Hosted verified | SHA `561ac536a55257b05f9c04ada55756d1ab676749` passes CI `32744796324` and package PR/push runs `32744796274`/`32744754697`. Both untouched consolidated ZIPs independently verify six release files, seven matching SHA-256 rows, and CycloneDX 1.6/569-component SBOM evidence; publication is skipped. Defender removed locally extracted Windows copies, so extracted directories are not used as complete evidence and Defender was not weakened. Integration/destination evidence remains pending. |
| Checkpoint 2223 integration and destination closure | Require exact evidence-head, normal merge, merged-main checks, guarded synchronization, and independent destination proof | Verified | Evidence `6223ad2`, PR `#75`, merge `252a9ade`, evidence/merged-main CI/packages, exact 12-path synchronization, destination focused/full Rust and Flutter, and exact verifier/validator `253/253` in `484.8s` pass. One evidence-head arm64 `hdiutil` resource-busy failure is retained; failed-job-only attempt 2 passed unchanged. Six artifacts/checksums/SBOM, locks, and vault pass; publication is skipped. Same-session, cross-identity, AppContainer/LPAC, installed LocalSystem, driver, and pre-execution limits remain explicit. |

## Checkpoint 2224 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode launch-primary token stability | Detect persistent replacement or mutation of the launch token across process creation and authenticated handshake | Locally verified | Parent captures exact `TokenId`/`ModifiedId` before pipe creation from the same parent-held handle passed to `CreateProcessAsUserW`, then checks that handle after process creation while suspended and after handshake authentication. Empty ID, query failure, four-field drift, or cleanup failure is diagnostic. Target `2/2`, source contracts `654/654`, Authenticode `65/13`, Native `501/13` plus compiler `6/6`, locked workspaces, strict lint, Flutter `838/838`, and exact verifier `254/254` in `489.6s` pass. Hosted/integration/destination evidence remains pending. |
| Launch-token failure cleanup | Prevent unstable post-creation launch evidence from leaving a helper alive or becoming trust | Locally verified | Drift after creation terminates and reaps the suspended or running helper through existing bounded cleanup. The path has no weaker retry and cannot return publisher trust; adversarial four-field and empty-ID cases pass. |
| Residual launch-token boundary | Keep same-handle point-in-time evidence distinct from child-token or identity proof | Technically limited | This does not prove the child process token remains identical, bind the distinct launch-primary and impersonation objects, or prevent transient mutation, same-session injection, handle duplication, or process injection. Cross-identity IPC, AppContainer/LPAC, installed LocalSystem, signed-driver, and pre-execution enforcement remain separate. |
| Checkpoint 2224 definitive local evidence | Prevent stale or incomplete reports from claiming launch-token stability | Locally verified | Exact `254/254`, zero failed/skipped, passes in `489.6s`; target `0.2s`, embedded/independent strict validation, and nine malformed-report rejections pass. Locks/vault remain exact; hosting, integration, synchronization, and destination evidence remain pending. |
| Checkpoint 2224 integration and destination closure | Require exact hosted, normal-merge, synchronization, and independent destination evidence | Verified | Implementation `c831149`, evidence `42d8c7c`, PR `#76`, merge `243bc84`, evidence-head and merged-main CI/packages, guarded 12-path synchronization, full destination Rust/Flutter checks, and exact destination verifier/validator `254/254` in `494.5s` pass. Publication is skipped; locks and the protected vault remain exact. Point-in-time identity/isolation/driver limits remain explicit. |

## Checkpoint 2225 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Suspended child process-token binding | Bind the token initially attached to the exact `PROCESS_INFORMATION` child to the launch identity/restricted profile and capture its object identity | Verified and integrated | Before Job assignment or resume, parent `OpenProcessToken(process, TOKEN_QUERY)` requires primary type, launch user SID and AuthenticationId/session, stripped privileges, zero restricting SIDs, low integrity/no-write-up, canonical virtualization, disabled UIAccess, and nonempty `TokenStatistics.TokenId`; it captures the child token's own `TokenId`/`ModifiedId`. Query/profile failure terminates and reaps the suspended child without retry. Focused production/adversarial tests pass `2/2`. |
| ACK-gated post-auth child process-token binding | Remove the child-exit race and recheck the currently attached process token after handshake authentication | Verified and integrated | The duplex pipe child writes nonce then waits for an exact one-byte ACK. After exact PID, connected-client-token, nonce, and launch-token checks, parent reopens the child token with `TOKEN_QUERY`, repeats the full profile validation, requires exact equality with the captured child `TokenId`/`ModifiedId`, and only then sends ACK through bounded overlapped I/O. Missing/malformed ACK, profile drift, query, timeout, cancellation, or cleanup failure cannot become publisher trust. Complete Authenticode passes `52/52`. |
| Checkpoint 2225 verifier/report contract | Prevent stale or scope-incomplete evidence from claiming child token binding | Verified and integrated | Source contract `655/655`, exact local `255/255` in `521.1s`, exact destination `255/255` in `476.3s`, embedded/independent validation, and nine malformed-report rejections pass. |
| Residual child process-token boundary | Keep two point-in-time process-token snapshots distinct from cross-object identity or durable isolation | Technically limited | The first focused run proved the child has a distinct `TokenId` from the launch primary on this host; exact cross-object equality is unavailable and not claimed. Profile plus child-stability binding does not identify the distinct named-pipe impersonation token object, prevent replacement/mutation after ACK, catch every transient, or stop same-session injection/privileged handle duplication. ACK is not secret/encrypted. Cross-identity IPC, AppContainer/LPAC, installed LocalSystem, signed driver, and pre-execution protection remain absent. |
| Checkpoint 2225 implementation-head hosted evidence | Prove the exact implementation against hosted CI and every desktop package path without publishing | Verified | Exact `311d9a2` passes CI `32769512557` and package push/PR `32769502849`/`32769512526`; Windows MSI/EXE, Linux DEB/tar, macOS arm64/x64 DMG, contracts, and consolidation pass while publication is skipped. Untouched consolidated artifacts `9536055246`/`9536052725` each pass exact eight-entry, seven-checksum, and CycloneDX 1.6/569-component in-stream validation without extraction or execution. |
| Checkpoint 2225 integration and destination closure | Require exact evidence-head, normal merge, merged-main checks, guarded synchronization, and independent destination proof | Verified | Evidence `d1a1e14`, PR `#77`, merge `5792c22`, evidence/merged-main CI and packages, exact 12-path synchronization, destination focused/full Rust and Flutter checks, and exact verifier/validator `255/255` in `476.3s` pass. Evidence/merged artifacts `9536921340`/`9537511908` pass exact six-platform-file, seven-checksum, and CycloneDX 1.6/569-component checks without extraction; publication is skipped. Locks and vault remain exact. |

## Checkpoint 2226 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Retained Authenticode response handshake | Keep the exact verified parent-child channel alive through candidate trust and response flush | Verified and integrated | Child retains its exact client pipe, writes and flushes bounded stdout, sends a distinct exact response-ready marker, and waits for final ACK. Parent retains the server/event/overlapped state, exact process handle, and same parent-held launch token. Early exit, malformed marker, timeout, or unsettled cancellation fails visibly. Post-response regressions pass `3/3`; complete destination Authenticode passes `70/15`. |
| Post-response launch and child token stability | Reject trust output if launch or exact live child token evidence changes during trust/response production | Verified and integrated | Before final ACK, parent repeats same-handle launch `TokenId`/`ModifiedId` stability and exact child `TOKEN_QUERY` launch SID/session, primary/privilege/restricting-SID/low-integrity/no-write-up/virtualization/UIAccess profile plus captured `TokenId`/`ModifiedId`. Query, profile, or drift failure terminates and reaps without retry. Native `506/15` plus compiler `6/6`, Local `536/536`, Guard `248/248`, both locked workspaces, strict lint/offline checks, release/two-host smoke, and Flutter `838/838` pass. |
| Checkpoint 2226 verifier/report contract | Prevent stale evidence from claiming the post-response boundary | Verified and integrated | Benign/adversarial Rust tests, source contract 656, one new mandatory verifier target, exact 256-step validator scope, and docs were scripted before execution. Source contracts pass `656/656`; local verifier/validator passes exact `256/256` in `459.6s`, destination passes `256/256` in `438.4s`, the target passes in `0.3s`, and ten malformed reports are rejected. Locks and vault remain exact. |
| Residual post-response boundary | Keep a third point-in-time snapshot distinct from durable identity/isolation | Technically limited | Response-ready/final ACK flow does not cryptographically bind response bytes to token snapshots, bind the distinct impersonation token object, detect every transient, prevent mutation after final ACK or privileged same-session injection/handle duplication, encrypt IPC, provide cross-identity authentication or AppContainer/LPAC, or prove installed LocalSystem, signed-driver, or pre-execution enforcement. |
| Checkpoint 2226 implementation-head hosted evidence | Prove the exact implementation through hosted CI and every desktop package path without publishing | Verified | Exact `74d7d963` passes CI `32780511368` and package push/PR `32780474053`/`32780511318`; Windows MSI/EXE, Linux DEB/tar, both macOS DMGs, contracts, and consolidation pass while publication is skipped. Untouched artifacts `9539926286`/`9540008859` each pass exact six-platform-file, seven-checksum, and CycloneDX 1.6/569-component in-stream validation without extraction or execution. |
| Checkpoint 2226 integration and destination closure | Require exact evidence-head, normal merge, merged-main checks, guarded synchronization, and independent destination proof | Verified | Evidence `bacf1cc`, PR `#78`, merge `bab872d`, evidence/merged-main CI and packages, exact 12-path synchronization, destination focused/full Rust and Flutter checks, and exact verifier/validator `256/256` in `438.4s` pass. Evidence/merged artifacts `9540950441`/`9541445838` pass exact six-platform-file, seven-checksum, and CycloneDX 1.6/569-component checks without extraction; publication is skipped. Locks and vault remain exact. |

## Checkpoint 2227 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Response-ready connected-client process binding | Prove the still-connected handshake client remains the exact retained child process before final ACK | Verified and integrated | After exact ready-marker validation, parent binds `GetNamedPipeClientProcessId` on the retained pipe instance to `GetProcessId` on the exact retained child handle. Zero/query/mismatch fails into bounded terminate/reap cleanup before launch/child read-back or publisher trust. Focused `2/2`, destination Authenticode `72/15`, Native `508/15`, and exact verifier `257/257` pass. |
| Response-ready client-token reauthentication | Repeat complete connected-client identity and restricted-profile evidence after response production | Verified and integrated | Parent freshly impersonates the same pipe connection and requires SecurityImpersonation, launch SID and AuthenticationId/session, stripped privileges, zero restricting SIDs, low integrity/no-write-up, canonical virtualization, disabled UIAccess, within-check `TokenId`/`ModifiedId` stability, successful `RevertToSelf`, and no remaining thread token. No weaker retry. Focused, full, hosted, merged-main, and destination evidence passes. |
| Checkpoint 2227 verifier/report contract | Prevent stale evidence from claiming response-client reauthentication | Verified and integrated | Source contracts pass `657/657`; local verifier/validators pass exact `257/257` in `453.2s`, destination passes `257/257` in `434s`, and 12 malformed reports are rejected. Stale 256-step evidence cannot satisfy the validator. |
| Residual response-client boundary | Keep repeated point-in-time authentication distinct from durable token identity or isolation | Technically limited | Separate impersonation calls may create distinct token objects, so cross-snapshot `TokenId` equality is unavailable and not claimed. Ready/ACK/response bytes are not cryptographically bound or encrypted. The control does not catch every transient, stop privileged same-session injection/handle duplication, or provide cross-identity IPC, AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution enforcement. |
| Checkpoint 2227 implementation-head hosting | Require exact implementation CI plus complete cross-platform package evidence without publication | Verified | Exact `cef0d28` passes CI `32791340856` and package runs `32791317044`/`32791340840`. Untouched artifacts `9543648381`/`9543559227` each pass exact six-platform-file, seven-checksum, and CycloneDX 1.6/569-component stream validation without extraction or execution; publication is skipped. |
| Checkpoint 2227 integration and destination closure | Require exact evidence-head, normal merge, merged-main checks, guarded synchronization, and independent destination proof | Verified | Evidence `c63fb71`, PR `#79`, merge `9304681`, evidence/merged-main CI and packages, exact 12-path synchronization, destination focused/full Rust and Flutter checks, and exact verifier/validator `257/257` in `434s` pass. Evidence/merged artifacts `9544267760`/`9544647451` pass exact six-platform-file, seven-checksum, and CycloneDX 1.6/569-component checks without extraction; publication is skipped. Locks and vault remain exact. |

## Checkpoint 2228 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode response hash frame | Bind exact flushed stdout length and content to the retained response-ready pipe | Verified, integrated, and superseded by checkpoint 2229 MAC | Child hashes a fixed domain, exact little-endian `u64` length, and all response bytes including newline, then sends exact marker/length/SHA-256 in a fixed 41-byte frame. Checkpoint 2228 passed focused `3/3`, full local and destination regression, exact `258/258` verification, hosted evidence, normal merge `ab43569`, and guarded destination synchronization before checkpoint 2229 replaced the unkeyed digest. |
| Authenticated response-to-stdout comparison | Reject stdout mutation before strict verdict parsing | Verified, integrated, and retained | Parent validates the frame before fresh client reauthentication and primary-token checks, then after helper exit requires exact collected length/digest before constructing output. Same-length mutation and explicit length mismatch passed adversarial coverage; checkpoint 2229 retains the ordering and upgrades the comparison to HMAC-SHA-256. |
| Checkpoint 2228 verifier/report contract | Prevent stale evidence from claiming response hash binding | Verified and integrated | Three Rust regressions, source contract 658, one mandatory verifier target, exact 258-step validator scope, hosted checks, merge, destination verification, and audit closure passed. Stale 257-step evidence is rejected. |
| Residual response hash boundary | Keep content-integrity evidence distinct from secret or cross-identity authentication | Technically limited | SHA-256 is unkeyed and rides the existing same-user authenticated endpoint. It is not a secret MAC, encryption, durable token-object binding, AppContainer/LPAC, installed LocalSystem, driver, or pre-execution proof. A privileged same-session actor able to modify both stdout and frame before authentication remains outside the control. |

## Checkpoint 2229 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode per-launch response MAC | Bind exact flushed stdout to the random launch token already authenticated on the retained pipe | Verified and integrated | Child retains the exact canonical 36-byte random launch-token key and computes domain-separated HMAC-SHA-256 over exact little-endian `u64` length plus every response byte. Parent retains the independently generated key and uses constant-time `verify_slice` before strict JSON or publisher trust. Local, hosted, merged-main, and destination evidence pass; destination Authenticode is `84/17 ignored` and definitive verification is `259/259`. |
| Wrong-key and mutation rejection | Fail visibly when response bytes, length, frame tag, or launch key differ | Verified and integrated | Same-length mutation/length/frame tests exercise MAC semantics. A benign isolated child authenticates with the correct handshake token but frames harmless text under another fixed test UUID; the parent rejects it. Destination focused `3/3 + 1/1`, full Native, hosted, and exact verifier evidence pass. |
| Windows PowerShell redirected JSON stdin | Keep strict JSON commands interoperable with PS5 without accepting BOM-prefixed input | Verified and integrated | Authenticode smoke plus scan/cancel/allowlist/quarantine/watch/status and blocked driver-self-test harnesses select `UTF8Encoding(false)` before process/stdin creation and restore prior encoding in `finally`. Strict product parsers are not weakened. Local/destination parsers, wrappers, release smoke, verifier, and hosted Windows packaging pass. |
| Checkpoint 2229 verifier/report contract | Prevent stale or unkeyed evidence from claiming the MAC boundary | Verified and integrated | Source `659/659`, retained/new targets, local and destination exact `259/259`, both strict validators, 15 malformed-report rejections, evidence/merged-main CI, normal merge `36d67798`, and 23-path destination synchronization pass. Stale 258-step or missing MAC scope cannot satisfy the validator. |
| Checkpoint 2229 package evidence | Prove the exact implementation across every desktop package path without publishing or executing candidate installers | Verified at implementation head | Desktop Packages push/PR `32812914763`/`32812956466` pass all platform jobs and skip publication. Untouched artifacts `9550661340`/`9550842112` pass exact six-platform-file, seven-checksum, and CycloneDX 1.6/569-component stream validation without extraction or execution. |
| Checkpoint 2229 integration and destination closure | Require evidence-head, normal merge, merged-main checks, guarded synchronization, and independent destination proof | Verified | Evidence `f0c72e1`, PR `#81`, merge `36d67798`, evidence/merged-main CI and packages, exact 23-path synchronization, destination focused/full Rust and Flutter checks, and exact verifier/validator `259/259` in `473s` pass. Evidence/merged artifacts pass exact stream checks; publication is skipped, locks and vault remain exact. |
| Residual response MAC boundary | Keep per-launch same-user authentication distinct from key secrecy or stronger isolation | Technically limited | The key is carried in the child's sanitized environment and over the same-user pipe. HMAC-SHA-256 is not encryption, cross-identity authentication, durable token-object binding, AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution enforcement. Same-user process-memory or environment read access, privileged injection, or handle duplication may recover the key or alter both stdout and MAC before authentication. |

## Checkpoint 2230 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode pipe-delivered launch key | Remove the random launch/MAC key from inherited child environment data while preserving exact process, token, pipe-security, response-MAC, cancellation, and diagnostic boundaries | Verified and integrated | Parent verifies the exact connected child PID, same-user logon-session client token, launch token, and child primary-token stability before sending the canonical 36-byte key on the retained duplex pipe. Child verifies exact parent PID and applied pipe security before a bounded canonical-key read. The original fixed ACK is superseded by checkpoint 2231 HMAC-SHA-256 confirmation. Local, hosted, merged-main, and destination evidence pass. |
| Key-free sanitized helper environment | Limit child environment inheritance to values required for exact helper launch | Verified and integrated | The environment builder contains only canonical pipe name, parent PID, and checked native `SystemRoot`/`WINDIR`; no launch token or response MAC key is inherited. The real benign fixture proves absence before and after the production handshake; complete local and destination regressions pass. |
| Checkpoint 2230 verifier/report contract | Prevent stale evidence from claiming pipe-only key delivery | Verified and integrated | Source `660/660`; local `260/260` in `459.9s`; destination `260/260` in `448.1s`; both strict validators and `16/16` malformed-report rejections pass. Evidence `4b03b0e`, PR `#82`, merge `9690c84`, hosted and merged-main CI/packages, and exact 12-path guarded synchronization pass with publication skipped. |
| Residual pipe-delivered key boundary | Keep reduced environment exposure distinct from durable secrecy or stronger isolation | Technically limited | The key remains in parent/child memory and crosses authenticated same-user IPC. Same-user process-memory access, privileged injection, pipe-handle duplication or observation, compromised endpoints, administrator/SYSTEM, or kernel compromise may recover it or alter response and MAC. This is not encryption, cross-identity IPC, durable secret storage, AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution enforcement. |

## Checkpoint 2231 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode launch-key confirmation HMAC | Prove possession of the exact pipe-delivered per-launch key before parent post-handshake token acceptance | Verified and integrated | Child computes domain-separated HMAC-SHA-256 over exact canonical pipe-name length/name and little-endian parent/child PIDs. Parent requires exactly 32 bytes and constant-time verification under its retained key/context before post-confirmation token stability. The fixed one-byte ACK no longer exists in production. Focused local/destination `2/2`, full regression, hosted, merged-main, and destination evidence pass. |
| Key-confirmation adversarial coverage | Reject malformed or context-substituted confirmation and terminate a real wrong-key restricted child | Verified and integrated | Pure benign fixtures cover empty, truncated, extended, mutated, wrong-key, wrong-pipe, wrong-parent-PID, wrong-child-PID, zero-PID, and equal-PID evidence. A separate benign child uses a different fixed test UUID key and fails into bounded terminate/reap cleanup; no candidate content is executed. Both complete Native runs pass `515/515` with 19 intentional child-entrypoint ignores. |
| Checkpoint 2231 verifier/report contract | Prevent stale or scope-incomplete evidence from claiming key possession | Verified and integrated | Source `661/661`; local `261/261` in `466.4s`; destination `261/261` in `452.7s`; embedded/independent strict validation and `8/8` local plus `8/8` destination malformed-report rejections pass. Evidence `0f49c76`, PR `#83`, merge `b678027`, hosted/merged-main CI/packages, and guarded destination synchronization pass with publication skipped. |
| Residual key-confirmation boundary | Keep point-in-time same-user key possession distinct from secret transport or stronger isolation | Technically limited | Handshake confirmation and response MAC reuse the per-launch key with distinct fixed domains. This proves possession by data arriving on the already PID/token-bound same-user pipe at that moment. It is not encryption, cross-identity authentication, durable secret storage or token-object identity, AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution enforcement; memory read, injection, and handle duplication remain outside this user-mode control. |

## Checkpoint 2232 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode launch-key best-effort zeroization | Reduce retention of the per-launch HMAC key in Avorax-owned memory after success, failure, cancellation, or unwind | Verified and integrated | Parent handshake, authenticated response evidence, pending child handshake, and completed child handshake own the canonical key through `Zeroizing<String>`; the bounded 37-byte child pipe-read buffer uses `Zeroizing<[u8; 37]>`. Key bytes are borrowed only after canonical UUID validation, the old raw 36-byte derived-key array is removed, and key-bearing containers do not derive `Debug`. Native `516/516`, strict lint/release checks, exact-head/evidence-head/merged-main CI and packages, normal PR `#84` merge, and exact 15-path destination synchronization pass with publication skipped. |
| Zeroization fail-visible regression | Prove explicit scrubbing destroys the usable key evidence instead of yielding a valid protocol result | Verified and integrated | A benign pure regression explicitly zeroizes the key and read buffer, requires empty/all-zero storage, and requires prior handshake-HMAC and response-MAC evidence to fail. Focused `1/1`, source `662/662`, local `262/262` in `459.7s`, destination `262/262` in `555.3s`, strict validators, and `8/8` local plus `8/8` destination malformed-report rejections pass. No candidate content is read or executed. |
| Residual memory boundary | Keep best-effort owned-buffer cleanup distinct from secret isolation or secure erasure | Technically limited | `zeroize` cannot guarantee removal of compiler temporaries, HMAC internals, allocator/OS copies, paging, process dumps, or forensic remnants, and it cannot stop same-user or privileged memory reads while the key is live. This is not secure erasure, durable secret storage, cross-identity IPC, AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution enforcement. |
| Checkpoint 2232 package evidence | Bind platform package and dependency evidence to exact implementation, evidence, and merged-main heads without publication | Verified and integrated | Exact implementation `eac61e6`, evidence `183d1d6`, and merge `6de2a8f` pass hosted CI/packages. Their consolidated artifacts match GitHub SHA-256 and pass exact in-stream eight-entry, six-platform-file, seven-checksum, and CycloneDX 1.6/569-component validation without extraction or execution. Publication jobs are skipped and no release is created. |

## Checkpoint 2233 Engine-Control Matrix Addendum

| Control / engine | Responsibility | Status | Evidence and limits |
|---|---|---|---|
| Authenticode fixed launch-key ownership | Keep each owned protocol key in one non-displayable, fixed, best-effort-zeroizing shape | Scripted; verification pending | Parent, authenticated response evidence, pending child, and completed child use `AuthenticodeLaunchKey = Zeroizing<[u8; 37]>` instead of `Zeroizing<String>`. The parent encodes directly into bytes 0..36; byte 36 is a zero overflow guard. The wire contract remains exactly 36 bytes. No passing result is claimed before execution. |
| Exact child key transfer and move | Reject truncated/extended delivery and avoid a second owned child key copy | Scripted; verification pending | Child reads at most 37 bytes, requires exactly 36 transferred bytes and an unchanged overflow guard, validates canonical UTF-8/RFC-4122-v4 form, and moves the same buffer through states without `String::to_owned()`. HMAC receives only a borrowed validated prefix. |
| Fixed-buffer fail-visible regressions | Prove generation, guard, transfer shape, canonical validation, and scrub failure behavior with benign data | Scripted; verification pending | New pure regression requires length 37, a zero guard, canonical nonzero 36-byte key, changed-guard rejection, all-zero scrub, and post-scrub rejection. Updated source contract 663 and mandatory exact-263 verifier/report checks are scripted; no fixture is executed as candidate content. |
| Residual fixed-buffer memory boundary | Keep reduced ownership/copy surface distinct from secure erasure or endpoint isolation | Technically limited | Removing owned `String` keys does not erase UUID/HMAC internals, compiler temporaries, stack/register spills, allocator/OS/pipe copies, dumps, paging, or forensic remnants and cannot stop live same-user or privileged reads. This is not encryption, cross-identity IPC, AppContainer/LPAC, installed LocalSystem, signed-driver, or pre-execution enforcement. |

Checkpoint 2233 broad local execution now passes source `663/663`, focused
fixed-buffer `1/1`, complete Authenticode `81/81` with 19 intentional ignores,
Native `517/517 + 6/6`, Local `536/536`, Guard `248/248 + 249/249`, both locked
workspaces, strict lint/offline/release/two-host smoke, and Flutter `838/838`.
The first three rows remain **locally verified; definitive/integration pending**
until exact 263-step, hosted, merge, synchronization, and destination evidence
passes. The `Zeroizing<[u8; 37]>` overflow guard and removed owned `String` copy
do not change the technically limited secure-erasure/pre-execution boundary.

Definitive local status is now **verified**: exact `263/263` passes in `461.4s`,
the mandatory fixed-buffer target passes in `0.2s`, embedded/independent PS5.1
strict validation passes, and `8/8` adversarial reports are rejected. Hosted,
merge, synchronization, and destination integration remain pending. An optional
PS7 report-validator invocation is technically limited by automatic JSON ISO
timestamp-to-`DateTime` conversion; this does not affect the passing PS7/PS5.1
release Authenticode smokes or the `Zeroizing<[u8; 37]>` overflow guard and
removed owned `String` evidence, and makes no pre-execution claim.

Exact implementation-head status is now **hosted verified**: exact `00e9f3c`
passes Avorax CI `32865480443` and Desktop Packages push/PR
`32865302082`/`32865480497`. Both publication jobs are skipped. Consolidated
artifacts `9570689038`/`9570466353` match GitHub SHA-256 and pass bounded
non-extracting exact 8-entry/6-release/7-checksum/CycloneDX 1.6/569-component
validation. Evidence-head, merge, synchronization, and destination integration
remain pending; the fixed-buffer memory and pre-execution limits are unchanged.

Checkpoint 2233 is now **verified and integrated**. Evidence `646000b`, normal
PR `#85` merge `7467bfd`, exact evidence/merged-main CI and packages, skipped
publication, and three stages of non-extracting package digest/inventory/SBOM
review pass. Guarded 12-path destination synchronization and destination full
Rust/Flutter/lint/build/smoke evidence pass. The corrected verifier is exact
`263/263` in `454.1s`; both strict validators and `8/8` destination mutations
pass. The initial WindowsApps Python-alias verifier is fail-visible and
uncredited. Locks and the protected vault remain exact. Fixed-buffer ownership
remains best-effort memory hygiene, not secure erasure or pre-execution proof.

## Checkpoint 2234 Engine-Control Matrix Addendum

| Control or engine | Scripted state | Verification state | Honest limit |
|---|---|---|---|
| Strict verification JSON reader | All nine bounded readers preserve strings with PowerShell 7 `DateKind=String` and retain Windows PowerShell 5.1 compatibility | Source contract 664 and dual-host exact-report execution are scripted; execution pending | Trusted-host evidence parser only; no detection or protection behavior |
| Definitive report validator | Exact schema, scalar types, explicit ISO timestamp parsing, repository containment, generated evidence, status/scope, and 263-step cardinality stay strict | Same report must pass under distinct checked Windows PowerShell 5.1 and PowerShell 7 executables; execution pending | Does not prove installed service, driver, signing, or pre-execution behavior |
| Detection, scan, update, quarantine, realtime, and custom engines | No source or configuration change | Prior evidence remains applicable; checkpoint 2234 adds no new engine claim | Existing partial, blocked, and technical limits remain unchanged |

Local execution now verifies the JSON reader and definitive validator:
PowerShell 5.1/7 focused checks pass, source contracts pass `664/664`, exact
`263/263` passes in `469.9s` under both strict hosts, and `16/16` full-suite
mutations reject. Broad standalone engine and Flutter suites pass. One combined
root-workspace Native executable is blocked by Defender with OS error 225 and is
not credited; the standalone Native suite passes without weakening Defender.
Hosted, integration, synchronization, and destination columns remain pending.

Exact implementation-head hosting is now **verified**: commit `708e939` passes
CI `32878421258` and package push/PR runs `32878368995`/`32878421335`; both
publication jobs are skipped. Consolidated artifacts `9575787747`/`9575480016`
match GitHub SHA-256 and pass bounded non-extracting exact
8-entry/6-release/7-checksum/CycloneDX 1.6/569-component validation. Evidence-
head, merge, synchronization, and destination integration remain pending; no
antivirus-engine or pre-execution claim changes.

Checkpoint 2234 is now **verified and integrated**. Evidence `a5cf1c5`, normal
PR `#86` merge `c969351`, exact evidence/merged-main CI and packages, skipped
publication, and non-extracting package digest/inventory/checksum/SBOM review
pass. Guarded 11-path synchronization and destination source `664/664`, exact
`263/263` in `468.9s`, dual-host strict validation, and `16/16` adversarial
rejections pass. Three package symlink-positive tests remain explicitly skipped
for absent optional Windows symlink privilege. The JSON-host repair remains
verification tooling, not a detection, installed-service, driver, signing, or
pre-execution capability.

## Checkpoint 2235 Engine-Control Matrix Addendum

| Control or engine | Responsibility | Scripted state | Honest limit |
|---|---|---|---|
| Native `RiskFusion` score policy | Aggregate signed signature, rule, heuristic, ML, behavior, reputation, application-control, and trust evidence into a conservative 0..100 verdict | Saturating `i64` accumulation, exact thresholds, and extreme-weight regressions are scripted; verification pending | Weighted policy is not a calibrated malware probability or production false-positive measurement |
| Local Core heuristic risk policy | Aggregate local reasons and gate probable-malware/automatic quarantine on sufficient positive quality and independent positive sources | Saturating 0..100 accumulation plus positive-only quality/source gates and adversarial diagnostics are scripted; verification pending | Heuristic auto-quarantine remains conservative policy and requires broader production calibration and installed E2E |
| Native verdict explainability | Keep decisive evidence and provenance visible while bounding API/UI output | Stable descending absolute-weight selection, exact 32-item limit, 256/256/1,024-byte fields, 2,048-byte UTF-8 explanation, omitted count, and TrustStore provenance are scripted; verification pending | Lower-magnitude evidence can be omitted by design; complete evidence still participates in the verdict but is not all returned |
| Checkpoint 2235 verifier contract | Bind source, focused runtime fixtures, exact report cardinality, scope, docs, and unchanged dependencies | Mandatory Native and Local targets, exact 264-step validator, four scope clauses, and source contract 665 are scripted; execution pending | Does not prove installed UI/service behavior, production calibration, signing, driver, or pre-execution enforcement |

Checkpoint 2235 is now **locally verified** for the first three controls and
the local portion of the verifier contract: Native `10/10` focused and
`520 + 19 ignored + 6`, Local `1/1` focused and `537/537`, Guard
`248/248 + 249/249`, source `665/665`, both locked workspaces, changed-crate
strict Clippy, Flutter analyze/`838/838`, dual-host parsers, locks, and vault
pass. Exact 264-step, hosted, merge, sync, and destination columns remain
pending. Existing API-only workspace Clippy diagnostics are visible and not
credited to this control.

The checkpoint-2235 verifier contract is now **definitively locally verified**:
exact `264/264` in `503.5s`, both strict PowerShell hosts, and `16/16`
stale/target/scope/options/status/step report mutations pass. Hosted,
integration, synchronization, and destination columns remain pending.

Exact implementation-head hosting is now **verified**: commit `8fa9630` passes
CI `32892108074` and package push/PR runs `32891914251`/`32892108020`; both
publication jobs are skipped. Consolidated artifacts `9580216963`/`9580381411`
match GitHub SHA-256 and pass bounded non-extracting exact
8-entry/6-release/7-checksum/CycloneDX 1.6/569-component validation. Evidence-
head, merge, synchronization, and destination integration remain pending; no
antivirus-engine, installed-service, or pre-execution claim changes.

Checkpoint 2235 is now **verified and integrated**. Evidence head `57ce163`,
normal PR `#87` merge `5fc30c9`, exact evidence/merged-main CI and package runs,
skipped publication, and bounded artifact digest/inventory/checksum/SBOM review
pass. Guarded 13-path synchronization and destination focused/full engine,
workspace, Flutter `838/838`, source `665/665`, exact `264/264` in `488.3s`,
dual-host strict validation, and `16/16` adversarial report rejections pass.
The four checkpoint controls are verified at source and destination. Risk
fusion remains weighted policy without production calibration; installed
service, signing, driver, kernel, and pre-execution evidence remain unchanged.

## Checkpoint 2236 Engine-Control Matrix Addendum

| Control or engine | Responsibility | Scripted state | Honest limit |
|---|---|---|---|
| Bounded process event gate | Reject invalid process identity/NUL telemetry before file I/O and inspect only bounded UTF-8-safe command head/tail data | Verified by focused/full/destination and exact 265-step evidence: nonzero PID, embedded-NUL rejection, 16 KiB valid-UTF-8 sample, truncation evidence, and benign/adversarial fixtures | Public explicit API only; app/service process-start wiring and durable monitoring are not established |
| Process script-host observation | Record exact script-host executable identity without treating normal host use as malicious | Verified by focused/full/destination and exact 265-step evidence: exact case-insensitive basename and zero-weight `NativeBehavior` context | Does not parse or execute scripts and does not make host use suspicious by itself |
| Process security-tamper review | Correlate exact command/script host context with distinct bounded tamper command indicators | Verified by focused/full/destination and exact 265-step evidence: context gate, token boundaries, distinct count, saturating score capped at 75, bounded UTF-8 sample, and no raw command disclosure | Post-start review only; no process is stopped, quarantined, or blocked |
| Post-start execution decision | Describe the recommended response without claiming an action that did not occur | Verified: `recommend_stop_and_quarantine` replaces fake `block`; mapping and harmless known-bad paths pass destination regression | Recommendation only; no pre-execution or mutation capability |
| Ransomware high-write component | Share the exact 25-write threshold with the bounded ransomware activity window | Verified in focused/full/destination suites; existing helper is wired into runtime window scoring | Post-write user-mode telemetry; no driver or pre-write interception |
| Browser-data path access provider | Correlate trusted per-process browser-store path access | Explicitly disabled; bounded case-insensitive helper remains testable | Blocked by missing trusted per-process path-access telemetry |
| Infostealer credential/network provider | Correlate credential/wallet reads, staging, and outbound activity | Explicitly disabled; score arithmetic is saturating and bounded | Blocked by missing correlated credential-read/archive/network telemetry |
| Persistence correlation provider | Correlate autorun writes with parent trust/signature state | Explicitly disabled; path and score helpers are bounded and saturating | Blocked by missing trusted registry/file-write and parent-signature telemetry |
| Suspicious child-lineage provider | Correlate verified parent and child image identities | Explicitly disabled; exact allocation-free name classifier remains tested | `ProcessStartEvent` has only parent PID, not verified parent image identity |
| Checkpoint 2236 verifier contract | Bind source, runtime fixtures, exact report cardinality, scope, docs, and unchanged dependencies | Verified locally and at destination: mandatory target once, exact `265/265`, five scope clauses, source contracts `666/666`, two-host validation, adversarial `16/16` | Does not prove installed UI/service, production calibration/signing, driver, kernel, or pre-execution behavior |

No checkpoint-2236 control is marked verified during scripting. Existing process
snapshot and file-activity evidence remains separate and does not silently fill
the disabled telemetry gaps above.

Local execution now verifies the scripted control contracts with focused Native
`19/19`, complete Native `538/538` plus 19 deliberate ignores and compiler
`6/6`, both locked workspace modes, strict lint/format/parser checks, Flutter
analyze and `838/838`, and source contracts `666/666`. The explicit API remains
post-start and unconnected to installed process telemetry; disabled providers
remain disabled. Definitive, hosted, integration, and destination proof is open.

Definitive local verification passes exact `265/265` in `523.1s`, including the
new target in `0.3s`; both strict validators pass and adversarial report variants
reject `16/16`. Hosted, integration, and destination columns remain open, and no
disabled provider or installed/pre-execution capability is promoted by this result.

Checkpoint 2236 integration and destination evidence is now closed. PR `#88`
merged normally; exact-head and merged-main CI/package matrices pass with
publication skipped. Guarded synchronization copied 25 exact blobs, and the
destination passes the broad suites plus exact `265/265` in `490.8s`, both
validators, and adversarial `16/16`. The four missing-telemetry providers above
remain disabled and the installed/durable/pre-execution limitations are unchanged.

## Checkpoint 2237 Process Observation Native Wiring

| Control or engine | Ownership | Scripted state | Evidence or exact limit |
|---|---|---|---|
| App-lifetime process inventory | Flutter `AppDetector`, Local Core process monitor | Locally verified by focused/full/release/exact 266-step evidence | Maximum 256 rows; Flutter 2,048-scalar and Local Core 4,096-scalar head/tail samples; Windows CIM owns PID/parent/path/command, POSIX does not fabricate command data |
| Native script-host observation | `native.behavior.process_script_host` | Enabled, connected, and locally verified through Local Core | Exact command-host identity, zero host-only weight, maximum 16 Native reviews per snapshot |
| Native security-tamper review | `native.behavior.process_security_tamper` | Enabled, connected, and locally verified | File-plus-behavior fusion, caller truncation provenance, positive behavior remains review-visible despite trusted-file offsets, exact 16-review/16-diagnostic limits, hard 16 MiB per-process executable-read limit, post-start review only |
| Process review allowlist | Local Core process monitor | Locally verified before Native candidate/file I/O | Exact normalized path match; no substring/prefix suppression |
| Process review errors | Local Core IPC, Flutter parser/controller | Locally verified fail-visible | attempted/completed/failed/limited counters, max 16 sanitized 4,096-character diagnostics, existing failure event/state path |
| Process action | Local Core | Disabled by design | Native recommendation is ignored; no stop, kill, block, quarantine, delete, restore, or candidate execution |
| Guard commandline behavior wiring | Guard service | Disabled/blocked | Guard enumeration owns PID/path only; trusted bounded commandline transport is absent |
| Parent-child lineage | Native behavior inventory | Disabled/blocked | Parent PID is not verified parent image identity |

The release smoke, source contract `667/667`, complete component/workspace/
Flutter suites, and exact no-skip/no-Defender `266/266` verifier pass locally.
Both strict hosts accept the report and adversarial variants reject `16/16`.
Hosted, integration, synchronization, and destination evidence remains open.

Exact implementation `0e10cae` passes PR `#89` CI and both package trigger
modes. Both consolidated artifact streams pass exact platform/checksum/SBOM
validation and publication is skipped. Evidence-head, merge, synchronization,
and destination evidence remain open; hosted packaging does not expand the
post-start advisory boundary.

Checkpoint 2237 integration and destination evidence is now closed. PR `#89`
merged normally; exact evidence-head and merged-main CI/package matrices pass
with publication skipped. Guarded synchronization copied 24 exact blobs, and
the destination passes broad component/workspace/Flutter/contracts plus exact
`266/266` in `499.0s`, both validators, and adversarial `16/16`. The enabled
process controls above are verified at the destination. Guard commandline and
parent-image providers remain disabled, and installed durable monitoring,
mutation, calibration, driver/kernel, and pre-execution limits are unchanged.

## Checkpoint 2238 Protection Loop Generation Matrix

| Control | Ownership | Scripted state | Exact limit |
|---|---|---|---|
| Process-snapshot lifecycle generation | Flutter `ZentorController` | Locally verified | Exact generation, active timer, mounted controller, and active protection required at timer entry and after each request await |
| Finite watch-poll lifecycle generation | Flutter `ZentorController` | Locally verified | Independent exact generation and current loop-state check for success/error publication |
| Empty watch-path replacement | Flutter watch-poll start | Locally verified | Prior generation/timer/path lease invalidated before empty-path limitation returns |
| Late process success | Flutter controller regression | Locally verified | Suspicious fixture after stop cannot replace `off` state or publish suspicious loop event |
| Late watch-poll error | Flutter controller regression | Locally verified | Exception after stop cannot replace `off` state or publish stale failure event |
| Underlying request cancellation | PowerShell/CIM and Local Core subprocess paths | Not claimed | Existing bounded timeout/reap behavior remains; generation binding rejects publication only |
| Checkpoint 2238 verifier contract | Verifier, validator, source contracts | Locally verified | Mandatory stale-generation target, exact 267 steps, source contract 668 |

Focused and adjacent filters, Flutter `840/840`, source contracts `668/668`, and
the exact `267/267` verifier pass locally. Both strict hosts accept the report
and adversarial variants reject `16/16`. Generation binding narrows asynchronous
UI/controller lifecycle integrity; it does not promote polling to installed
durable monitoring or add mutation/pre-execution capability. Implementation-
head hosted evidence follows; evidence-head, integration, synchronization, and
destination evidence remains open.

Exact implementation `5944e97` passes PR `#90` CI and both package trigger
modes. Both consolidated artifact streams pass bounded platform/checksum/SBOM
validation and publication is skipped. Hosted packaging does not expand the
app-lifetime, publication-only generation boundary; evidence-head, merge,
synchronization, and destination evidence remains open.

Checkpoint 2238 integration and destination evidence is now closed. PR `#90`
merged normally as `2435b31`; exact evidence-head and merged-main CI/package
matrices pass with publication skipped. Guarded synchronization copied 13 exact
blobs and the destination passes focused generation `2/2`, Flutter
analyze/`840/840`, source contracts `668/668`, exact `267/267` in `464.2s`,
both validators, and adversarial `16/16`. The enabled generation controls above
are verified at the destination. Hard cancellation, installed durable
monitoring, mutation, driver/kernel enforcement, and pre-execution blocking
remain unclaimed.

## Checkpoint 2239 Scan Cancellation Ownership Matrix

| Control | Ownership | Scripted state | Exact limit |
|---|---|---|---|
| Scan operation generation | Flutter `ZentorController` | Scripted, not yet verified | Monotonic controller-lifetime integer; exact generation required after awaits and for cleanup/publication |
| Cancellation outcome | Flutter controller | Scripted, not yet verified | One `Completer<bool>` for the exact requested generation; completed report waits for accept/fail outcome |
| Replacement scan starts | Controller and visible scan controls | Scripted, not yet verified | Manual quick/full/custom/rescan, picker, scheduler, Home, Protection, Scan, and Quarantine starts blocked while cancellation is in flight |
| Active scan subprocess | `LocalCoreClient` | Scripted, not yet verified | Exact process lease captured before cancel IPC/delay; only identical owning lease may clear the slot |
| Unrelated Local Core IPC | `LocalCoreClient._call` | Scripted, not yet verified | Non-scan calls own no lease and cannot clear active scan fallback ownership |
| Cross-instance cancel token | Local Core runtime file | Superseded by checkpoint 2240 scripting | Per-job UUID/token binding replaces the shared marker; same-user capability is not cross-identity authentication |
| Checkpoint 2239 verifier contract | Verifier, validator, source contracts | Scripted, not yet verified | Mandatory cancellation ownership target, exact 268 steps, source contract 669 |

No checkpoint-2239 passing result is claimed during scripting. The change
narrows post-start cancellation ownership only; it does not add durable service,
driver/kernel, or pre-execution blocking capability.

## Checkpoint 2240 Scan Job Cancellation Binding Matrix

| Control | Responsibility | State | Evidence target / limit |
| --- | --- | --- | --- |
| Client scan job UUID | Create one canonical random UUID before process start and bind scan IPC plus exact process lease | Scripted, not yet verified | Flutter benign subprocess regression; same-user capability only |
| Local Core job parser/progress | Require canonical UUID on every scan/cancel command and preserve it in progress | Scripted, not yet verified | Rust canonical/missing/malformed command regressions |
| Per-job cancellation token | Exclusive staged write, 1 KiB bound, strict JSON/schema/job validation, non-following path checks | Scripted, not yet verified | Wrong-job, mismatch, malformed, oversized, symlink regressions |
| Cancel wrapper | Require `-JobId`; validate echo, exact leaf/content/root and negative no-output guards | Scripted, not yet verified | Release-binary wrapper smoke with malformed-ID case |
| Checkpoint 2240 verifier contract | Verifier, validator, source contracts | Scripted, not yet verified | Mandatory job-bound cancellation target, exact 269 steps, source contract 670 |

Cancellation remains cooperative user-mode post-start control. Job binding is
not cross-identity authentication, installed service ownership, hard engine
interruption, driver/kernel interception, or pre-execution blocking.

## Checkpoint 2241 Cooperative In-Engine Cancellation Matrix

| Control | Responsibility | Scripted state | Evidence target / limit |
| --- | --- | --- | --- |
| Native cancellation outcome | Distinguish accepted cancellation from token-probe failure | Locally verified | Typed anyhow downcast; neither outcome can become a verdict |
| Content hash/read boundary | Probe exact job state around each at-most-1-MiB read request | Locally verified | Sparse benign fixture cancels before full hash completion |
| Detection-stage boundary | Probe between static, publisher trust, signatures, archive, rules, heuristics, ML, and verdict publication | Locally verified | Benign runtime/source regressions; no partial verdict |
| Archive boundary | Probe around bounded sample collection and before every sampled entry/recursive archive | Locally verified | Existing 64-entry/4-MiB/1-MiB/depth limits remain authoritative |
| Local Core accounting | Interrupted current file plus remainder are unscanned; probe corruption aborts visibly | Locally verified | Exact-job token runtime tests and source accounting contract |
| Checkpoint 2241 verifier contract | Verifier, validator, source contracts | Closed: local, hosted, merged-main, synchronized, and destination verified | Mandatory cooperative-cancellation target, exact 270/270, source contract 671, dual validators, adversarial rejection, exact-head/main CI and packages, 19/19 sync, destination 270/270 |

Checkpoint 2241 does not hard-interrupt an in-progress filesystem read, static
analyzer substep, bounded archive collect/inflate, synchronous rule/ML call, or
Windows trust helper. It remains current-user cooperative cancellation, not
installed cross-identity, driver/kernel, or pre-execution enforcement. No
checkpoint-2241 passing result is claimed during scripting.

Focused cancellation passes `9/9`; complete Native library `568`, Local Core
`546/546`, Flutter `847/847`, source contracts `671/671`, strict component lint,
locked release build, analyzer, formatting, and parser gates pass. The
definitive no-skip/no-Defender report passes exact `270/270` in `462.7s`, both
independent validators pass, and missing-step/scope adversarial reports are
rejected. Evidence head and merged main pass CI/packages and bounded artifact
validation; guarded sync verifies `19/19` paths and destination definitive
passes `270/270` in `517.9s`. Checkpoint 2241 is closed. Workspace-wide strict
Clippy is separately blocked by three
unchanged API-service Rust-1.96 lints; Native/Local strict Clippy is clean.

## Checkpoint 2242 Cooperative Archive Inflate Cancellation Matrix

| Control | Responsibility | Scripted state | Evidence target / limit |
| --- | --- | --- | --- |
| ZIP entry traversal checkpoint | Observe exact job cancellation before each local/central-directory sampled entry | Locally verified | Benign two-entry cancellation regression; no partial returned sample set |
| Stored body checkpoint | Bound cancellation around an at-most-1-MiB stored-body copy | Locally verified | Pre/post callback with unchanged entry/total limits |
| Deflate output checkpoint | Observe cancellation before every at-most-64-KiB output read | Locally verified | Benign multi-chunk deflate regression; existing 1-MiB output cap |
| Scanner typed propagation | Preserve cancellation/probe errors instead of archive-limit evidence | Locally verified | Distinct cancellation and probe-failure adapter regressions; source contract 672 |
| Checkpoint 2242 verifier contract | Require current evidence rather than stale checkpoint-2241 reports | Closed: local, hosted, merged-main, synchronized, and destination verified | Exact 271/271, source contract 672, dual validators, adversarial rejection, exact-head/main CI and packages, 13/13 sync, destination 271/271 |

One already-running decoder read is not hard-interrupted. Static archive
metadata/relationship analysis remains a separate synchronous bounded substep.
During scripting, no checkpoint-2242 passing result was claimed. Local focused,
full, definitive `271/271`, and adversarial validation now pass. Implementation
head, evidence head, and merged main pass CI/packages and bounded artifact
validation. Guarded sync verifies `13/13` paths and destination definitive
passes `271/271` in `507.6s`. Checkpoint 2242 is closed; one uncredited
default-parallel Native handshake race remains the next hardening lead.

## Checkpoint 2243 Parallel Authenticode Helper Lifecycle Matrix

| Control | Responsibility | Scripted state | Evidence target / limit |
| --- | --- | --- | --- |
| Pre-handshake standard-stream draining | Start bounded stdout/stderr readers before authenticated pipe key delivery/confirmation | Locally verified | Early child output cannot create pipe backpressure before handshake; existing 16-KiB stream caps remain |
| Overlapped transfer settlement | Use authoritative completion byte counts for key delivery, key confirmation, response-ready, and ACK | Locally verified | `GetOverlappedResult` is mandatory after pending and synchronous success; exact transfer lengths remain fail-closed |
| Handshake message framing | Preserve protocol-write boundaries between key confirmation and response binding | Locally verified | Local message-type/message-read-mode named pipe; +1 buffers reject true overlength without consuming a following frame |
| Early failure evidence | Preserve bounded child exit status, stdout/stderr, writer and cleanup diagnostics | Locally verified | Benign child emits a marker plus more than an ordinary pipe buffer, exits cleanly before connect, and yields a fail-visible bounded parent error |
| Parallel helper independence | Support concurrent product helper calls without a process-wide serialization lock | Locally verified | Four barrier-released benign helpers each complete unique pipe/process/key authentication and response MAC binding; 20 focused and 20 complete repetitions pass |
| Fail-closed lifecycle | Never retry handshake/output failure and never derive a trust verdict from diagnostic evidence | Locally verified | Initial handshake failure terminates or observes exit, reaps, closes the desktop, joins workers, and returns error |
| Checkpoint 2243 verifier contract | Reject stale checkpoint-2242 evidence | Scripted, execution pending | Exact 272 steps, source contract 673, dual validators, and adversarial missing-step/scope rejection |

No checkpoint-2243 passing result is claimed during scripting. Four local child
fixtures do not prove unbounded load, installed-service identity behavior,
kernel/driver mediation, or pre-execution blocking. Authenticode still requires
valid Windows trust and a verified Microsoft signer; diagnostics never create a
trusted result.

Local focused `2/2`, 20 focused repetitions, complete Authenticode `83`/`21`
with 20 full repetitions, Native `555`/`21` plus compiler `6/6`, Local Core
`546/546`, Flutter `847/847`, source contracts `673/673`, strict lint/build, and
parser/diff gates pass. Definitive 272-step and hosted/integration/destination
evidence remain pending.

## Checkpoint 2244 Static Archive Analysis Cancellation Matrix

| Control / engine | Responsibility | Current state | Evidence / blocker |
|---|---|---|---|
| Native static ZIP metadata analyzer | Inspect bounded local/central metadata and archive names without extraction | Locally verified | Fallible checkpoint before traversal and every entry; maximum 256 entries retained; focused/ZIP/full Native pass |
| OOXML relationship analyzer | Inspect bounded stored/deflated `.rels` bodies for external and remote executable targets | Locally verified | Checkpoints around stored copies and before each at-most-64-KiB inflate output read; benign cancellation and existing detection regressions pass |
| Archive autorun analyzer | Inspect bounded stored/deflated `autorun.inf` bodies for executable commands | Locally verified | Same fallible copy/inflate checkpoint path; callback errors are not archive limits; complete ZIP regressions pass |
| Native scan cancellation bridge | Prevent partial static analysis or verdict publication after cancellation/probe failure | Locally verified | Engine maps `static archive analysis progress` through typed cancellation; source contract and full Native/Local pass |
| Checkpoint 2244 verifier contract | Reject stale checkpoint-2243 evidence | Definitively verified locally | Exact 273/273 in 531.1s, source contract 674, dual validators, and adversarial missing-step/scope rejection pass |

Checkpoint 2244 adds cooperative boundaries only. It does not hard-interrupt an
active decoder read, change detector thresholds or archive limits, add
extraction, or claim kernel/pre-execution blocking. No checkpoint-2244 passing
result is claimed during scripting.

Local evidence passes focused `4/4`, ZIP `36/36`, adjacent cancellation `4/4`,
Native `559`/`21` plus compiler `6/6`, Local Core `546/546`, Flutter `847/847`,
source contracts `674/674`, strict component lint, dual parsers, formatting and
diff checks, and locked release build. Locks and protected vault remain exact;
definitive exact `273/273` and adversarial evidence pass. Report SHA-256 is
`2547454f20895864be9727dd545e0625d39b0b761732032f886c004ff5de2216`;
hosted/integration/destination evidence was pending at that local stage.

The GitHub Actions `major_outage` left uncredited zero-job runs, but recovery
evidence now passes: exact-head CI `32987569318`/`32987888207` and PR packages
`32987888192` are green with publication skipped. Consolidated artifact
`9614177410` passes bounded non-extracting exact 8/6/7/CycloneDX-1.6/569
validation. Evidence-head/merge/main/integration/destination proof was pending
at that recovery stage; the closure matrix below supersedes it.

### Checkpoint 2244 Integration Closure

| Control | Responsibility | Status | Evidence |
|---|---|---|---|
| Static archive cancellation integration | Preserve exact parser/entry/copy/inflate cancellation behavior through hosted, merged, and destination trees | Verified | Evidence head `0b566a4` and merge `c0cd92f`; main CI `32993065989`; main packages `32993065971`; guarded canonical sync `14/14` |
| Static archive cancellation destination verifier | Reproduce the exact no-skip control/engine matrix after guarded synchronization | Verified | Destination `273/273` in `502s`; dual independent validators; report SHA-256 `b5c403d2795bbbd9ff544a6ba431b45c14c2620ec6b99557afb93fed1079a405` |
| Residual synchronous analysis | Keep unclosed cancellation boundaries explicit | Partial / technically limited | One active decoder read, non-archive static analysis, synchronous rule/ML and trust calls remain cooperative/bounded rather than preemptive |

Checkpoint 2244 is closed without expanding user-mode cancellation into a
service, driver, kernel, or pre-execution claim. The whole antivirus goal remains
active.

## Checkpoint 2245 Non-Archive Static Cancellation Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Shared Native static orchestrator | Propagate one job-bound callback through non-archive phases and publish no partial result | Scripted / unverified | 4096-byte entropy loop plus fallible string/PE/script calls; verifier step 274 |
| Entropy | Bound cancellation latency while counting byte frequencies | Scripted / unverified | At-most-64-KiB checkpoints and exact wrapper parity |
| String URLs | Count URL carrier classes without retaining references | Scripted / unverified | Streaming saturated counters; checkpoint every 1024 references |
| String network paths | Count remote executable paths without retaining references | Scripted / unverified | Streaming saturated counter; checkpoint every 1024 references |
| String IPs | Count valid IPv4 candidates without per-candidate vectors | Scripted / unverified | Four-octet iterator; checkpoint every 1024 candidates |
| String term groups | Preserve registry, macro, document, installer, script-host, and suspicious-term evidence | Scripted / unverified | Fallible callback before each complete term search |
| UTF-16 indicator view | Decode without a temporary `Vec<u16>` and retain marker semantics | Scripted / unverified | Streaming decode checkpoint every 64 Ki characters and per marker |
| PE sections | Parse each section and calculate high-entropy evidence | Scripted / unverified | Per-section callback; fallible at-most-64-KiB entropy chunks |
| PE imports | Preserve nine suspicious-import categories | Scripted / unverified | Per-term callbacks; no temporary lowercase term allocation |
| PE debug path | Preserve boundary-spanning `.pdb` detection | Scripted / unverified | Overlapping at-most-64-KiB search chunks |
| PowerShell static analyzer | Explain encoded, obfuscation, download, execution, persistence, and tamper evidence | Scripted / unverified | Fallible normalization and term passes |
| JavaScript static analyzer | Explain encoded, obfuscation, download, execution, and persistence evidence | Scripted / unverified | Fallible normalization and term passes |
| Batch static analyzer | Explain obfuscation, download, execution, persistence, and tamper evidence | Scripted / unverified | Fallible normalization and term passes |
| VBS static analyzer | Explain encoded, obfuscation, download, execution, and persistence evidence | Scripted / unverified | Fallible normalization and term passes |
| Wrapper compatibility | Keep existing infallible internal callers behaviorally unchanged | Scripted / unverified | Exact entropy/string/script/PE parity tests |
| Verdict publication | Fail visibly on arbitrary callback errors | Scripted / unverified | Shared analyzer returns `Err`; completion and verdict remain after fallible call |
| Reputation provider | Remote reputation only after authenticated privacy-reviewed backend exists | Disabled / blocked | No approved authenticated backend; unchanged |
| Browser-data correlation | Correlate trusted per-process browser-data access telemetry | Disabled / blocked | No trusted per-process telemetry; unchanged |
| Credential/network correlation | Correlate credential reads, archive creation, and outbound network activity | Disabled / blocked | No trusted correlated telemetry; unchanged |
| Persistence-write correlation | Correlate registry/file autorun writes with signer/parent identity | Disabled / blocked | No trusted registry/file write plus identity feed; unchanged |
| Parent-image lineage | Attribute verified parent image identity rather than PID alone | Disabled / blocked | No trusted parent-image identity feed; unchanged |
| Rule/ML/trust cancellation | Interrupt synchronous rule, ML, or Windows trust calls | Partial / technically limited | Separate bounded operations; not made preemptive in checkpoint 2245 |

Exact verifier step 274 and Source contract 675 are scripted. No
checkpoint-2245 test has run during this scripting phase, so no matrix row above
is promoted to Verified yet. The 64 MiB sample cap and cooperative user-mode
boundary remain authoritative; no service, driver, kernel, or pre-execution
claim is added.

### Checkpoint 2245 Local Matrix Evidence

The scripted analyzer, compatibility, and verdict-boundary rows above are now
verified locally by focused `15/15`, analyzer `99/99`, Native `574` plus compiler
`6/6`, Source contract `675/675`, strict Native Clippy, formatting, diff, and
PowerShell parsing. The first complete Native attempt's five Defender error-225
blocks are uncredited; isolated reruns and a clean complete rerun pass without
changing Defender. At that stage rows remained pending for exact verifier
`274/274`, hosted, merge, package, guarded synchronization, and destination
evidence.

Local Core `546/546`, Flutter analyze and `847/847`, strict Local Core lint, and
the locked release workspace build also pass. Dependency locks and the exact
16,072-file protected-vault invariant are unchanged. Definitive local
verification now passes exact `274/274` in `539.7s`; embedded and independent
PowerShell 5.1/7 validators accept the exact report, while both independent
hosts reject missing-step and missing-required-scope copies. Hosted, integration,
and destination matrix proof remain pending.

Implementation head `6a8c136aff321b9c8dac53547b5e988376603091` passes all five
hosted CI jobs and independent push/PR package matrices for Windows, Linux, and
both macOS architectures. The PR consolidated artifact passes bounded
non-extracting exact 8/6/7/CycloneDX-1.6/569 validation, and both publication
jobs are skipped. Evidence-head, integration, and destination proof remain
pending; this does not promote any disabled engine or expand user-mode limits.

### Checkpoint 2245 Closure Matrix Evidence

The historical pending statements above are superseded. Evidence-head and
merged-main CI/package matrices pass with publication skipped. PR `#98` merged
normally as `48cf932ff23211961386cbf220d05026821322c7`; both package artifacts
pass matching-digest, bounded non-extracting 8/6/7/CycloneDX-1.6/569 checks.
Guarded and post-test canonical comparisons pass all `22/22` synchronized
paths with zero deletes or residue.

Destination focused `15/15`, analyzers `99/99`, source `675/675`, Native
`574`/`21` plus compiler `6/6`, Local Core `546/546`, Flutter `847/847`, strict
quality gates, locked release build, and definitive `274/274` in `502.5s` all
pass. The implemented analyzer, compatibility-wrapper, and fail-visible verdict
rows are therefore verified for this user-mode boundary. Reputation and the
four correlation-dependent behavior rows remain **Disabled / blocked**;
rule/ML/trust cancellation remains **Partial / technically limited**. No row is
promoted to installed service, kernel, driver, or pre-execution protection.

## Checkpoint 2246 Native Provider Cancellation And Pack-Limit Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Shared provider byte search | Exact and masked byte matching with bounded cancellation latency | Verified | At-most-64-KiB candidate chunks, cross-chunk parity, arbitrary callback failure |
| Native signature provider | Match exact/partial hashes, bytes, ASCII, UTF-16, EICAR, PE/script/archive and required context | Verified | One lowercase sample per provider; fallible per-signature/context/search path |
| Native rule provider | Evaluate validated explainable conditions without repeated sample normalization | Verified | One lowercase sample/path per provider; per-rule, condition and term checkpoints |
| Native ML provider | Score bounded static features with development/production metadata honesty | Verified | Callback per at-most-128 score/contribution weights; compatibility parity |
| Archive-entry provider path | Analyze bounded in-memory entry samples without extraction/execution | Verified | Fallible static/signature/rule callbacks before outer verdict publication; 1 MiB entry cap |
| Signature pack loader | Load local `.zsig` definitions without aggregate resource exhaustion | Verified | Max 32 provider files, 256 inspected entries, 16 MiB total bytes, 4,096 signatures |
| Rule pack loader | Load local `.zrule` definitions without aggregate resource exhaustion | Verified | Max 32 provider files, 256 inspected entries, 16 MiB total bytes, 4,096 rules |
| Provider compatibility wrappers | Preserve existing infallible internal API behavior | Verified | Signature/rule/ML/search wrapper parity fixtures |
| Provider error boundary | Prevent cancellation/probe/overflow/limit failure becoming no-match or clean | Verified | Error propagation before database activation, evidence fusion, or file verdict |
| Windows publisher trust | Validate bounded Microsoft Authenticode identity/hash binding | Partial / technically limited | Existing isolated helper bounds; one active trust call is not hard-interrupted |
| Reputation provider | Remote reputation only after authenticated privacy-reviewed backend exists | Disabled / blocked | No approved authenticated backend; unchanged |
| Browser-data correlation | Correlate trusted per-process browser-data access telemetry | Disabled / blocked | No trusted per-process telemetry; unchanged |
| Credential/network correlation | Correlate credential reads, archive creation, and outbound network activity | Disabled / blocked | No trusted correlated telemetry; unchanged |
| Persistence-write correlation | Correlate registry/file autorun writes with signer/parent identity | Disabled / blocked | No trusted registry/file write plus identity feed; unchanged |
| Parent-image lineage | Attribute verified parent image identity rather than PID alone | Disabled / blocked | No trusted parent-image identity feed; unchanged |

Focused `19/19`, Source `676/676`, full Native/Local/Flutter, locked workspace,
release build, and definitive exact `275/275` local evidence pass. Exact-head,
PR, merged-main, package, guarded `21/21` synchronization, and destination
`275/275` evidence also pass, so implemented rows are **Verified**. Publication
was skipped and artifacts were validated without extraction or execution.
Cancellation is cooperative: one provider
normalization, one search chunk, the bounded ML sort, an entered OS call, or a
Windows trust operation can finish before the next callback. No installed
service, driver, kernel, production-accuracy, or pre-execution claim is added.

Checkpoint 2246 is closed. Windows publisher trust remains **Partial /
technically limited**, and all correlation-dependent rows remain **Disabled /
blocked** with their listed prerequisites. The complete antivirus goal remains
active.

## Checkpoint 2252 Static Structured-Indicator Cancellation Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Structured traversal boundary | Check cancellation during delimiter, trim, candidate, token, and host traversal | Verified | Shared at-most-64-KiB byte or UTF-8-safe character intervals; local/hosted/destination evidence passes |
| Carrier classifier | Recognize RTF, PDF, and web-document carriers before counting active-content terms | Verified | Bounded exact markers and injected carrier-search error fixture pass |
| IPv4 candidate classifier | Count syntactically valid IPv4-looking candidates without reputation lookup | Verified | Chunked candidate traversal, representable-length guard, and error fixture pass |
| URL/query suffix classifier | Classify payload suffix before query or fragment without treating query text as a payload | Verified | Bounded first delimiter and preservation fixture pass |
| Remote path classifier | Validate UNC and remote `file://` host/share shape while excluding device/local forms | Verified | Bounded leading-host traversal and host cancellation fixture pass |
| Autorun classifier | Count executable/script command values only when an autorun section exists | Verified | CRLF, comments, accepted keys, tokens, suffixes, and line/token cancellation fixtures pass |
| Optical-image marker classifier | Recognize bounded ISO/UDF markers and autorun executable references | Verified | Shared exact marker search and injected optical-marker error fixture pass |
| Email attachment classifier | Count lines containing executable/script `filename` or `name` fields in an email carrier | Verified | Streaming semicolon fields, no per-line vector, per-line semantics, and error fixture pass |
| String Indicator publication | Publish no partial aggregate after arbitrary callback failure | Verified | Every new helper is fallible; full Native/Local and destination verifier pass |
| Structured callback latency | Bound cooperative work between callbacks | Partial / technically limited | One admitted structured chunk of at most 64 KiB may finish before cancellation is observed |
| Network/action ownership | Keep the provider deterministic, offline, detection-only, and non-mutating | Verified / unchanged | No URL/path access, execution, blocking, quarantine, or network lookup is added |
| Installed/kernel prevention | Mediate cross-identity or pre-execution events | Disabled / blocked | Requires installed authenticated service boundary and production-signed driver evidence |

Checkpoint 2252 verifier step 281 and Source contract 682 are fully scripted.
No checkpoint-2252 test has run during this scripting phase. Focused/full,
definitive exact `281/281`, hosted, integration, guarded-sync, and destination
evidence remain pending. New rows remain **Scripted / unverified**; existing
verified, partial, technically limited, disabled, and blocked statuses are
unchanged. The complete antivirus-hardening goal remains active.


Closure docs passed PR `#102` exact-head CI and normal merge `146b536`; its
merged-main CI passed. Exact four-path, zero-delete guarded synchronization and
the final destination `275/275` verifier plus independent PS5/PS7 validation
passed. Docs-only path policy started no package workflow; implementation
package evidence remains the already verified six-platform-artifact set.

## Checkpoint 2247 Provider Text Normalization Cancellation Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Shared provider text normalizer | Prepare lossy UTF-8, ASCII-lowercase text with bounded cancellation latency | Verified | `7/7` dedicated and `26/26` provider regressions; at-most-64-KiB new input per callback interval; final callback; arbitrary error propagation |
| UTF-8 boundary compatibility | Preserve one-shot replacement grouping across valid, malformed, and truncated input | Verified | Maximum three-byte carry plus parity fixtures at the exact chunk boundary |
| Native signature provider | Normalize once before signature/context/search evaluation | Verified | Signature `62/62` plus compiler `6/6`; DB, direct matcher, and ASCII wrapper use the same fallible helper |
| Native rule provider | Normalize sample/path once before condition evaluation | Verified | Rule `44/44`; DB and direct VM use shared helper; empty DB retains no-sample fast path |
| Archive-entry provider path | Apply the same bounded normalizer to in-memory sampled entry content | Verified | Archive `71/71`; existing exact-job callback reaches shared signature/rule DB paths before outer verdict |
| Provider error boundary | Prevent cancellation/probe errors from becoming no-match, clean, or partial success | Verified | Arbitrary callback failures abort; partial prepared text remains local and is dropped on `Err` |
| Non-archive static analyzers | Normalize and inspect separate static text views | Partial / technically limited | Separate bounded analyzer work remains cooperative; not changed in checkpoint 2247 |
| Windows publisher trust | Validate bounded Microsoft Authenticode identity/hash binding | Partial / technically limited | Existing isolated helper bounds; one active trust call is not hard-interrupted |
| Reputation provider | Remote reputation only after authenticated privacy-reviewed backend exists | Disabled / blocked | No approved authenticated backend; unchanged |
| Browser/credential/network/persistence/lineage correlation | Require trusted correlated per-process telemetry | Disabled / blocked | Required durable identity-bound telemetry is unavailable; unchanged |

Exact verifier step 276 and Source contract 677 pass in the definitive
`276/276` and Source `677/677` runs. Exact-head/PR/main CI and package matrices
pass with publication skipped; three consolidated artifacts pass bounded
non-extracting 8/6/7/CycloneDX-1.6/569 checks. Guarded synchronization passes
`18/18` with zero deletes, and destination Source `677/677`, focused `7/7`,
formatting, and definitive `276/276` plus dual validators pass. Implemented rows
are therefore **Verified**. The partial and disabled rows remain unchanged. This
is cooperative user-mode post-start analysis, not service, driver, kernel,
production-accuracy, or pre-execution proof. Checkpoint 2247 is closed; the
complete antivirus goal remains active.

## Checkpoint 2248 Static Text Normalization Cancellation Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Shared static text normalizer | Preserve lossy UTF-8 and ASCII-lowercase semantics with bounded callback latency | Verified | At-most-64-KiB chunks plus final callback; local, hosted, merged-main, and destination evidence passes |
| String-indicator analyzer | Extract URL/path/IP/autorun/reference evidence without whole-sample normalization interval | Verified | Callback-aware helper; `39/39` string and multi-chunk cancellation evidence |
| Script analyzer | Normalize script content before bounded term passes | Verified | Shared helper; `5/5` script and cancellation-before-analysis evidence |
| PE-import analyzer | Normalize PE sample before explainable import category counts | Verified | Shared helper; `2/2` import and cancellation-before-categories evidence |
| OOXML relationship analyzer | Count external/remote-executable relationships only after successful body analysis | Verified | Callback through normalization and indicators; zero-evidence error fixture plus ZIP `38/38` |
| Archive autorun analyzer | Count executable autorun commands only after successful body analysis | Verified | Callback-aware indicators; zero-evidence error fixture plus ZIP `38/38` |
| ZIP entry-name normalization | Normalize format-header-bounded names | Partial / technically limited | One cooperative interval, maximum 65,535 bytes |
| UTF-16 and term traversal | Decode/search remaining bounded static views | Partial / technically limited | Existing explicit intervals; not hard preemption |
| Windows publisher trust | Validate bounded Microsoft Authenticode identity/hash binding | Partial / technically limited | Existing isolated helper; one active trust call is not hard-interrupted |
| Reputation and correlated behavior providers | Require authenticated backend or trusted identity-bound telemetry | Disabled / blocked | Existing prerequisites remain unavailable |

Exact verifier step 277 and Source contract 678 are scripted. No
checkpoint-2248 test has run during this scripting phase, so no implemented row
was promoted before execution. Source `678/678`, focused `5/5`, full Native,
Local Core, Flutter, locked workspace/release, and definitive exact `277/277`
local evidence now passes. Exact-head push/PR packages and PR CI, normal PR
`#105`, merged-main CI/packages, bounded non-extracting artifact review, guarded
`15/15` synchronization, destination Source `678/678`, focused `5/5`,
formatting, and definitive `277/277` plus dual validators pass. Implemented rows
are therefore **Verified**; partial and disabled rows remain unchanged. The 64
MiB ordinary sample cap and 64-KiB/16-KiB OOXML relationship/autorun body caps
remain. This is cooperative user-mode normalization, not installed service,
driver, kernel, production-accuracy, pre-execution, or Defender-replacement
evidence. Checkpoint 2248 is closed; the complete antivirus goal remains active.

## Checkpoint 2249 ZIP Entry-Name Normalization Cancellation Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Shared ZIP name normalizer | Preserve lossy UTF-8 and ASCII-lowercase semantics with exact callback propagation | Verified | Shared helper at all four production callsites; focused `4/4`, ZIP `42/42`, hosted, and destination evidence pass |
| Local-header sample collector | Normalize a validated name before collecting bounded in-memory entry bytes | Verified | Callback error fixture aborts before sample publication |
| Local-header static analyzer | Normalize before path, OOXML, autorun, and entry-count evidence | Verified | Callback error fixture aborts before `ArchiveAnalysis` return |
| Central-directory parser | Keep malformed structural fallback separate from fallible normalization | Verified | `Result<Option<...>>`; malformed regressions and callback-error fixture pass |
| Local/central consistency gate | Require matching normalized local and central names before body trust | Verified | Matching/mismatch regressions and callback-error fixture pass |
| ZIP name callback latency | Bound cooperative work between callbacks | Partial / technically limited | One admitted header name, maximum 65,535 bytes, may finish before next callback |
| Archive extraction/execution | Avoid materializing or launching archive content | Verified / unchanged | Existing in-memory bounded inspection; fixtures are benign and never executed |
| Windows publisher trust | Validate bounded Microsoft Authenticode identity/hash binding | Partial / technically limited | Existing isolated helper; one active trust call is not hard-interrupted |
| Reputation/correlated behavior providers | Require authenticated backend or trusted identity-bound telemetry | Disabled / blocked | Existing prerequisites remain unavailable |

Verifier step 278, Source contract 679, Source `679/679`, focused `4/4`, Native
609 active plus compiler `6/6`, Local Core `546/546`, Flutter analyze and
`847/847`, locked build/tests, strict Clippy, safety gates, and definitive local
`278/278` all pass. Exact-head branch, PR, and merged-main CI/package matrices
pass with publication skipped. All three consolidated artifacts pass bounded
non-extracting exact 8/6/7/CycloneDX-1.6/569 validation.

Normal PR `#107`, exact `11/11` zero-delete guarded synchronization, independent
target-blob comparison, destination Source `679/679`, focused `4/4`, formatting,
and definitive `278/278` plus independent PS5/PS7 validation pass. Implemented
rows are therefore **Verified**. Partial and disabled rows remain unchanged.
This is cooperative user-mode post-start analysis, not installed-service,
driver, kernel, production-accuracy, pre-execution, or Defender-replacement
evidence. Checkpoint 2249 is closed; the complete antivirus goal remains active.

## Checkpoint 2250 Static Term-Search Cancellation Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Shared static term counter | Count exact non-overlapping byte terms with bounded callback latency | Verified | At-most-64-KiB candidate chunks; cross-chunk/count/empty-needle fixtures pass in focused `6/6` |
| String Indicator term groups | Produce explainable static category counts | Verified | Shared counter and no-evidence cancellation fixture pass; verifier step 279 and destination evidence pass |
| Script term groups and any-term probe | Count or detect bounded script indicators | Verified | Shared counter/exact search, Source `680/680`, hosted, and destination evidence pass |
| PE-import term groups | Count suspicious imported API categories | Verified | Shared counter and cancellation-before-evidence fixture pass |
| UTF-16 marker probes | Detect decoded executable/document markers | Verified | Shared exact search replaces whole-view `contains`; full compatibility and destination verification pass |
| Static verdict publication | Publish only after all fallible analysis completes | Verified | Callback errors propagate before `StaticAnalysis` and file verdict; full Native/Local and destination verifier pass |
| Structured static traversal | Process bounded line, predicate, and decode work | Partial / technically limited | One separate bounded traversal or UTF-16 interval may complete before callback |
| Windows publisher trust | Validate bounded Microsoft Authenticode identity/hash binding | Partial / technically limited | Existing isolated helper; an entered trust call is not hard-interrupted |
| Reputation/correlated behavior providers | Require authenticated backend or trusted identity-bound telemetry | Disabled / blocked | Existing prerequisites remain unavailable |

Checkpoint 2250 verifier step 279 and Source contract 680 are fully scripted.
No checkpoint-2250 test has run during this scripting phase. Focused, full,
definitive exact `279/279`, hosted, integration, guarded-sync, and destination
search evidence remain pending, so implemented rows remain **Scripted /
unverified**. Existing partial and disabled engine statuses are unchanged. The
whole antivirus hardening goal remains active.

Local focused/adjacent, Source `680/680`, full Native/Local/Flutter, locked
workspace/release, strict Clippy, formatting, parser, lock, and vault checks now
pass. The implementation rows are therefore **Verified locally**. Definitive
exact `279/279`, hosted, integration, guarded-sync, and destination term-search
evidence remain open; partial and disabled rows are unchanged.

Definitive local verification now passes exact `279/279`, zero failed/skipped,
in `649.9s`; independent PS5/PS7 validators accept the report and reject both
required adversarial mutations. Exact implementation `0847f3e`, PR `#109`,
normal merge `a423fb6`, exact-head and merged-main CI/package matrices, and all
three bounded non-extracting artifact reviews pass with publication skipped.
Guarded `14/14` zero-delete synchronization, independent target-blob equality,
destination Source `680/680`, focused `6/6`, formatting, and definitive
`279/279` plus PS5/PS7 acceptance pass. Implemented rows are **Verified**;
partial and disabled rows are unchanged. Checkpoint 2250 is closed, while the
complete antivirus-hardening goal remains active.

## Checkpoint 2256 File Discovery Control Matrix

| Control / engine | Responsibility | Scripted state | Honest limit / blocker |
|---|---|---|---|
| Local Core file walker | Enumerate safe regular scan candidates without following links; retain bounded errors and estimates | **Scripted / unverified** under verifier step 285 and Source contract 686 | Cooperative OS metadata/directory calls; one at-most-128-entry chunk may finish before cancellation |
| Job-bound discovery cancellation | Read the exact scan UUID token before roots, during traversal, after roots, and around sorting; cancel without scanning discovered paths | **Scripted / unverified** | Same-user capability token, not cross-identity service authentication, kernel cancellation, or pre-execution blocking |
| Quick discovery cap | Stop at 5,000 discovered risky files and report incomplete discovery | **Scripted / unverified** | Undiscovered paths are not counted; cap is coverage reduction, never a clean claim |
| Full/custom discovery cap | Stop at 250,000 discovered files and force `CompletedWithErrors` with fail-visible details | **Scripted / unverified** | Bounds path count only, not aggregate path bytes, I/O, elapsed time, or sort latency |
| Native Engine | Scan only completely discovered queued files after discovery succeeds | Existing engine behavior preserved; Checkpoint 2256 integration **unverified** | Not initialized for a pre-discovery cancel; no driver/kernel or Defender-replacement claim |

No Checkpoint 2256 test has run during this scripting phase. Exact `285/285`,
focused/broad, hosted, integration, guarded destination, and destination evidence
remain required.

Focused Checkpoint 2256 evidence promotes the Local Core walker/cancellation/
cap rows to **Verified locally**: new `5/5`, walker `10/10`, full scan `3/3`,
cancellation `8/8`, Source `686/686`, and Local Core `551/551` pass. Exact
verifier `285/285`, hosted, integration, guarded-sync, destination, and all
documented technical/product limits remain open.

Broad and adversarial local evidence now promotes every Checkpoint 2256 row to
**Verified locally**: both locked workspace variants, strict Local Core Clippy,
release build, Flutter/Dart regressions, and exact verifier `285/285` pass;
PS5/PS7 accept the exact report and reject missing-step/missing-scope mutations.
Hosted exact-head, integration, guarded synchronization, and destination proof
remain open. The cooperative, path-byte/I/O, cross-identity, kernel,
pre-execution, and Defender-replacement limits are unchanged.

Exact implementation `75a9620` passes hosted PR CI and both PR/push package
matrices. Bounded non-extracting review passes exact 8/6/7/CycloneDX-1.6/569
for both consolidated artifacts with publication skipped. Checkpoint 2256 rows
remain **Verified locally and on implementation-head CI**; evidence-head,
merged-main, synchronized-destination, and destination evidence remain open.

## Checkpoint 2255 Control Delta

| Control / engine | Responsibility | State | Evidence required |
|---|---|---|---|
| PE resource directory analyzer | Map the declared resource RVA into validated in-sample PE sections and validate/count top-level entries | **Closed / verified for this checkpoint** | Benign focused `3/3`, PE resource `6/6`, Native/full regression, Source contract 685, exact verifier `284/284`, hosted CI/packages, and destination proof |
| PE resource section cancellation | Propagate the exact scan callback before directory handling, each at-most-4,096-entry section chunk, and exhausted search | **Closed / verified for this checkpoint** | Exact callback-error preservation, no later analysis/verdict publication, merged-main and synchronized-destination evidence |

Checkpoint 2255 does not give the PE resource analyzer execution, reputation,
blocking, quarantine, or independent-verdict responsibility. Installed service,
driver/kernel, pre-execution, and Defender-replacement controls are unchanged.

Local evidence includes both locked workspace variants, strict lint/offline/
release gates, Flutter/Dart suites, exact `284/284`, independent PS5/PS7 report
acceptance, and hostile scope/step rejection. Hosted, integration, synchronized
destination, and destination verifier evidence remain open.

Exact implementation `67f2d26` now passes PR `#119` CI and both PR/push package
runs. The two untouched consolidated artifacts pass bounded non-extracting
8-root/6-package/7-checksum/CycloneDX-1.6/569-unique-ref review and publication
is skipped. Evidence-head, integration, merged-main, synchronized-destination,
and destination-verifier evidence remain open.

Evidence-head and merged-main CI/packages, bounded artifact inspection, guarded
`13/13` synchronization, focused destination checks, and definitive destination
`284/284` now pass. The two rows are **Closed / verified for this checkpoint**.
Installed-service, driver/kernel, production calibration, pre-execution, and
Defender-replacement rows remain partial, blocked, limited, or unclaimed.

## Checkpoint 2254 ZIP EOCD Search Cancellation Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Native ZIP EOCD finder | Locate a valid trailing EOCD in the bounded comment window and preserve exact callback errors | Scripted / unverified | Initial plus at-most-4,096-candidate checkpoints scripted; focused tests pending |
| Archive content sampling engine | Reach central-directory entries for bounded nested detection without extraction | Scripted / unverified | Callback failure must precede metadata and sample publication |
| Static archive-analysis engine | Produce bounded ZIP structural/heuristic evidence | Scripted / unverified | Callback failure must precede metadata, evidence, fallback, and verdict publication |
| ZIP compatibility and limits | Preserve valid comments, 65,557-byte search bound, entry caps, and parser behavior | Scripted / unverified | Benign long-comment preservation plus full Native regression pending |
| Definitive verifier/report | Reject stale or scope-incomplete evidence | Scripted / unverified | Mandatory step 283, exact-cardinality validator, and Source contract 684 pending execution |
| Installed service, driver/kernel, Defender replacement | Supply installed authenticated and pre-execution protection evidence | Partial / blocked / technically limited or unclaimed | Checkpoint 2254 does not alter these boundaries |

No checkpoint-2254 test has run during this scripting phase. ZIP EOCD focused,
full, exact `283/283`, hosted, integration, guarded-sync, and destination
evidence remain required before any new row is promoted to verified.

Focused execution now promotes the finder, both consumer, and compatibility
rows to **Verified locally (focused)**: EOCD `3/3`, full ZIP `45/45`, and three
adjacent cancellation filters `4/4` each pass. Source `684/684`, PS5/PS7 parser
`2/2` each, formatting, and diff hygiene pass. The definitive-evidence row
remains **Scripted / unverified** pending broad regression and exact `283/283`;
hosted, integration, sync, and destination evidence remain open.

Broad local regression now passes both locked workspace variants, Native
`635/635` plus compiler `6/6`, Local Core `546/546`, Platform Security `9/9`,
updater `203/203`, Flutter `847/847`, Dart `14/14`, release build, offline
Native check, and strict Native/Local/Guard Clippy. The first four rows are
**Verified locally**; the definitive-evidence row remains **Scripted /
unverified** until exact `283/283` and hostile validator checks pass.

Definitive exact `283/283`, dual-host acceptance, missing-step/missing-scope
rejection, and exact implementation-head CI/packages now pass. The first five
rows are **Verified locally and at implementation head**. Installed service,
driver/kernel, Defender replacement, evidence-head, integration, merged-main,
guarded-sync, and destination rows remain unchanged or open.

Evidence-head and merged-main CI/packages, bounded artifact inspection,
corrected guarded `13/13` synchronization, focused destination checks, and
definitive destination `283/283` now pass. The first five rows are **Closed /
verified for this checkpoint**. Installed-service, driver/kernel, production
calibration, pre-execution, and Defender-replacement rows remain partial,
blocked, technically limited, or unclaimed.

## Checkpoint 2251 Static Reference-Search Cancellation Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Shared exact reference finder | Return the first exact marker offset with bounded callback latency | Verified | At-most-64-KiB candidate chunks; cross-chunk/first-match/empty-needle fixtures and destination evidence pass |
| String Indicator reference terminator | Locate Unicode whitespace or an existing delimiter without splitting UTF-8 | Verified | UTF-8-safe at-most-64-KiB chunks and cross-boundary Unicode fixture pass locally and at destination |
| Embedded URL classifier | Count URL references and classify executable, ClickOnce, Java Web Start, and Windows package suffixes | Verified | Marker/body cancellation fixtures, hosted checks, and exact destination verification pass |
| Remote network-path classifier | Count executable UNC or remote `file://` references while excluding device/local forms | Verified | Marker/body cancellation fixtures pass; existing path predicates and destination behavior remain unchanged |
| String Indicator publication | Return no partial `StringIndicators` after arbitrary callback failure | Verified | Fallible paths propagate before publication; full local/hosted/destination suites pass |
| Static reference callback latency | Bound cooperative work between callbacks | Partial / technically limited | One admitted marker candidate or UTF-8-safe body chunk of at most 64 KiB may finish first |
| Reference execution/network access | Keep static parsing detection-only and offline | Verified / unchanged | Engine only examines bounded in-memory text; it does not open URLs/paths or perform lookup/action |
| Windows publisher trust | Validate bounded Microsoft Authenticode identity/hash binding | Partial / technically limited | Existing isolated helper; one active trust call is not hard-interrupted |
| Reputation/correlated behavior providers | Require authenticated backend or trusted identity-bound telemetry | Disabled / blocked | Existing prerequisites remain unavailable |

Checkpoint 2251 verifier step 280 and Source contract 681 are fully scripted.
No checkpoint-2251 test has run during this scripting phase. Focused, full,
definitive exact `280/280`, hosted, integration, guarded-sync, and destination
evidence remain pending, so new implementation rows remain **Scripted /
unverified**. Existing verified, partial, and disabled engine statuses are
otherwise unchanged. The complete antivirus-hardening goal remains active.

Local focused/adjacent and full compatibility evidence now passes: reference
`8/8`, terms `6/6`, strings `45/45`, cancellation `15/15`, Source `681/681`,
Native 623 active plus compiler `6/6`, Local Core `546/546`, both locked
workspace variants, strict lint, locked/offline and release builds, Flutter
analyze and `847/847`, and Dart `14/14`. New implementation rows are therefore
**Verified locally**. Definitive `280/280`, hosted, integration, guarded-sync,
and destination evidence remain open; partial and disabled rows are unchanged.

Definitive local evidence now passes exact `280/280`, zero failures, in `662.9`
seconds; report SHA-256 is
`17b60115b7a419310646789d4dc8b17b157b3e62ab0f1b2da6ec48d0dbe8b5f4`.
PS5/PS7 accept the exact report and both reject missing-step and missing-scope
adversarial copies. Exact implementation `96a3e73`, PR `#111`, normal merge
`3e58dc15`, exact-head and merged-main CI/package matrices, and bounded artifact
review pass with publication skipped. Guarded `12/12` zero-delete
synchronization, independent raw-blob equality, destination Source `681/681`,
focused `8/8`, formatting, and definitive `280/280` plus independent PS5/PS7
acceptance pass. Implemented rows are **Verified**; partial and disabled rows
are unchanged. Checkpoint 2251 is closed, while the complete antivirus goal
remains active.

Checkpoint 2252 local evidence now passes Source `682/682`, focused structured
`9/9`, all String Indicator `54/54`, adjacent reference `8/8`, Native 632 active
plus compiler `6/6`, Local Core `546/546`, locked workspace/release/offline
checks, strict Native/Local/Guard lint, Flutter analyze and `847/847`, and Dart
`14/14`. The first Native Clippy type-complexity failure was repaired with a
generic callback helper and exact reruns pass. Implemented checkpoint-2252 rows
are therefore **Verified locally**. Exact `281/281`, hosted, integration,
guarded-sync, and destination evidence remain open; all partial/disabled limits
and the complete antivirus-hardening goal remain unchanged and active.

Definitive local evidence promotes the implemented checkpoint-2252 rows to
**Verified locally**: exact `281/281`, zero non-passing steps, in `786.9s`, with
independent PS5/PS7 acceptance of report SHA-256
`039f30500f4a842f7f9785653df8a49b4b01f22963ecb1c340cb7265a2815153`.
Both validators reject missing-step and missing-scope copies. The first run's
Defender `Wacatac.C!ml` block of a generated debug test binary is uncredited;
the exact filter and from-start verifier pass with test-only debug/incremental
metadata disabled and without weakening Defender. Hosted, integration,
guarded-sync, and destination evidence remain open. Partial/disabled rows and
the complete antivirus goal remain unchanged.

Hosted implementation package evidence also passes: exact `09d84239` run
`33069608149`, all build/contract/consolidation jobs green, publication skipped,
and consolidated artifact `9645762246` exact at 132,039,189 bytes and SHA-256
`cd1bbb28059d1be2a64f181e399a8869e7598c8568aafafdd37ac96784d9a7ca`.
Bounded non-extracting 8-root/6-package/7-checksum/CycloneDX-1.6/569-component
review passes. PR/main and destination closure remain open; engine limits and
the complete goal remain unchanged.

Checkpoint 2252 is now closed through evidence `4d8aac4`, PR `#113`, merge
`4370debc`, exact-head and merged-main CI/packages, bounded review of both
consolidated package artifacts, guarded `11/11` zero-delete synchronization,
destination focused checks, and destination definitive `281/281` plus
independent PS5/PS7 validation. The implemented rows are **Verified**. The
structured callback latency row remains **Partial / technically limited**, and
the installed/kernel row remains **Disabled / blocked**. The verifier's
top-level failed-report path is fail-visible, but recording the thrown step in
the `steps` array remains a separate harness-observability hardening item. The
complete antivirus-hardening goal remains active.

## Checkpoint 2253 Failed-Step Reporting Matrix

| Control / engine | Responsibility | Status | Evidence / blocker |
|---|---|---|---|
| Small-threat MVP step runner | Preserve the exact invoked command, bounded error, and elapsed time before rethrow | Verified | Authentic first-step failure and local/destination definitive evidence pass |
| Verification report serializer | Distinguish invoked-step failure from orchestration failure without converting either to success | Verified | Schema-v2 `failure_kind` and exact terminal-error contracts pass |
| Small-threat MVP report validator | Reject missing, multiple, non-terminal, or errorless failed-step evidence and invalid passed-step errors | Verified | PS5/PS7 acceptance and all six report-only mutation rejections pass |
| Full-suite verifier | Include the safe failed-step regression in every definitive run | Verified | Mandatory step 282; local and destination exact `282/282` pass |
| Detection and verdict engines | Continue existing scan, trust, quarantine, and verdict responsibilities unchanged | Verified / unchanged | No engine implementation or threshold changes in checkpoint 2253 |
| Installed service, driver, and Defender replacement | Require installed authenticated IPC, production signing, kernel mediation, and host proof | Disabled / blocked or technically limited | This reporting checkpoint supplies no such proof and makes no protection expansion claim |

No checkpoint-2253 test has run during this scripting phase. The implemented
reporting rows remain unverified until focused, full, definitive, hosted,
integrated, guarded-sync, and destination evidence passes. Source contract 683
and exact verifier cardinality 282 are scripted. The complete antivirus-
hardening goal remains active.

Focused PS5/PS7 parsers, Source `683/683`, and the corrected failed-step smoke
now pass. One authentic nested first-step failure is accepted by both hosts;
both reject all three adversarial report forms, for six rejections total. The
step runner, serializer, and validator rows are therefore **Verified locally
(focused)**. Full-suite verifier step 282 remains **Scripted / unverified**
pending broad regression and definitive exact `282/282`; hosted, integration,
sync, and destination evidence also remain open.

Broad local regression now passes Rustfmt, both complete Rust engines, the
locked all-features workspace, standalone Native locked/offline check, locked
release workspace, strict Native/Local/Guard Clippy, Flutter analyze and
`847/847`, and Dart `14/14`. The full-suite verifier row remains **Scripted /
unverified** until the from-start exact `282/282` report and independent
validation pass. Other implemented reporting rows are **Verified locally**;
product engine and installed/kernel limits remain unchanged.

Definitive local verification promotes the full-suite verifier row to
**Verified locally**: exact `282/282`, zero non-passing, in `768.6s`, with one
new smoke and the dependency gate terminal. Independent PS5/PS7 validators
accept SHA-256
`3ad67ee7b7d6aed00b4aafece608a61b664aff1949dd67c2a0b04ff1a592894d` and
reject both missing-step and missing-scope copies. Hosted, integration,
guarded-sync, and destination evidence remain open. Detection/verdict behavior
is unchanged; installed service, driver/kernel, and Defender-replacement rows
remain partial, disabled, blocked, technically limited, or unclaimed.

Exact implementation head `3fc1fb0907cc194211064784f9ba95cc34f32732`
now passes five-job PR CI `33091441105` and full Desktop Packages run
`33091417691` with publication skipped. Consolidated artifact `9655292568`
matches GitHub's 132,050,923-byte SHA-256 and passes bounded non-extracting
exact 8-root/6-package/7-checksum/CycloneDX-1.6/569-unique-component review.
The reporting controls are therefore **Verified locally and at implementation
head**. Evidence-head, integration, merged-main, guarded-sync, and destination
evidence remain open; no product-engine or protection claim changes.

Checkpoint 2253 is now closed through evidence `09e5a9c`, PR `#115`, merge
`61311d9`, exact-head and merged-main CI/packages, bounded review of all three
consolidated package artifacts, guarded `12/12` zero-delete synchronization,
destination focused checks, and destination exact `282/282` with independent
PS5/PS7 validation. All four reporting rows are **Verified**. Detection and
verdict rows remain unchanged; installed service, cross-identity IPC,
production signing, driver/kernel, pre-execution, and Defender-replacement rows
remain partial, disabled, blocked, technically limited, or unclaimed. The
complete antivirus-hardening goal remains active.
