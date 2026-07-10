# Avorax Integration

## Local Development

1. Configure Avorax Cloud with `--dart-define` values or use the defaults.
2. Run the Flutter app.
3. Avorax silently calls `GET /v1/health`.
4. Use Quick Scan, Full Scan, or Custom Scan on desktop.
5. Choose Detect only or Auto quarantine mode.
6. Review threats and quarantine, restore/keep, delete, or allowlist explicitly.
7. Use Application Control only when a supported app needs verification.

Users do not paste API settings during first launch. Developer overrides are hidden in `Settings > Advanced`.

## API Expectations

The client uses:

- `GET /v1/health`
- `POST /v1/protection-runs`
- `POST /v1/protection-runs/{protection_run_id}/heartbeat`
- `POST /v1/protection-runs/{protection_run_id}/end`
- `POST /v1/detections`
- `POST /v1/quarantine`

If the API is unreachable or returns an error, the client shows that failure and does not fake success.

Protection-run cloud failures use user-facing operation names such as `Protection run creation` and `End protection run` instead of internal camelCase protocol names. Remote response details remain untrusted diagnostics and must still be bounded before display.

Protection-run IDs are bounded cloud action tokens. The client accepts only non-empty `A-Z`, `a-z`, `0-9`, `_`, or `-` values up to the cloud ID limit before storing returned run IDs or constructing heartbeat/end-run URLs.

## Local Core

Desktop malware scanning requires the Rust local core and Avorax Native Engine assets under `assets/zentor_native`. ClamAV and YARA compatibility paths are optional and disabled by default. For development builds, set `ZENTOR_LOCAL_CORE` to a release folder that contains `zentor_local_core.exe` and the native assets.

Desktop local-core and guard-service executable overrides must resolve to direct regular files. The client does not treat symbolic links, reparse-backed paths, directories, or missing files as launchable local-core evidence.

Executable and install-report probes use non-following filesystem metadata. Probe exceptions are reported through the local-core error/diagnostic surfaces instead of being silently collapsed into "not found"; blank environment overrides are ignored after trimming.

Recovery Vault restore and permanent-delete IDs are bounded action-target tokens. The local core rejects empty, whitespace-padded, dotted, path-like, or oversized quarantine IDs before metadata lookup or status/auth-sidecar path construction.

Quarantine list loading applies the same ID policy before records reach IPC/UI action surfaces. Malformed legacy metadata IDs fail the list request with metadata-record context rather than returning dead restore/delete targets.

Allowlist entries and removal requests apply the same bounded action-target ID policy. Malformed allowlist IDs fail before persisted entries can be loaded for removal or before deactivate lookup starts.

Guard quarantine record writes validate bounded non-path IDs before constructing metadata or auth-sidecar filenames. This keeps guard-generated quarantine evidence from accepting malformed IDs as path fragments.

Training-label IDs are bounded audit identifiers. Blank new labels get generated UUIDs during append; persisted malformed IDs fail suppression checks with line context rather than silently acting as false-positive or trusted-app evidence.

Known-good trust records require both a valid SHA-256 and explicit `known_good` trust level before they can grant local trust. Wrong-level records fail store loading.

Local YARA-like rule files fail closed on malformed rule names or string patterns. A rule without valid string patterns cannot make the YARA provider look available while matching nothing.

Guard driver-port worker startup failures are reported instead of panicking. The Windows signed-driver port background worker writes a checked fatal-error diagnostic if thread creation fails, preserving the existing guard fatal-log path.

Guard self-test fixture setup fails with context instead of panicking. The internally generated download-path parent directory is checked before creation so self-test setup failures remain explicit diagnostic errors.

Guard self-test generated hashes are normalized through contextual error propagation. If an internally generated self-test hash is malformed, the self-test fails with an explicit diagnostic instead of panicking or producing empty hash evidence.

Guard hash fixture helpers are isolated to test modules. Production marker scans no longer include test-only `normalize_hash` expectations from guard command and driver IPC test fixtures.

YARA embedded-rule `Default` expectations are isolated to tests. Production YARA loading remains fallible through `from_default_rules() -> Result<Self>`, so runtime rule failures can surface as errors.

Native engine default configuration is fallible only. The panicking `EngineConfig::default()` path was removed; callers must use `try_default()` or an explicit repo root.

Native installed-engine alias selection requires an explicit first candidate. The helper no longer accepts an empty slice and no longer carries a production `expect`; additional aliases are optional candidates after the declared primary asset.

Production marker inventory treats remaining `unsupported` text as explicit security evidence, not loose placeholders. Unsupported driver events, guard modes, rule-pack formats, YARA rule names, native signature filters, action policies, and rule/matcher categories fail closed; native quarantine restore remains a documented technical limit that must direct callers to the local-core Recovery Vault restore flow until fully supported and verified.

Quarantine ACL hardening helpers must not carry placeholder unused-argument suppressors. Local-core and guard quarantine base hardening pass the explicit `_path` argument to `icacls` on Windows, while non-Windows builds make the unused-platform branch visible through the parameter name rather than `let _ = path;`.

Update-check catch diagnostics are bounded before they become update state. `checkForUpdate` catches unexpected exceptions through `_boundedUpdateCheckError('$error')` before returning `UpdateCheckResult.failed`, so malformed local version probes, feed parsing, or transport failures cannot inject unbounded exception text into the Updates UI or audit history.

Update URL parse diagnostics are also bounded. GitHub release redirect `Location` parsing, GitHub fallback feed asset URL parsing, and package URL parsing normalize `FormatException.message` through `_boundedUpdateCheckError` before throwing update-service errors.

Cancel IPC fallback diagnostics are bounded before they reach scan state. If graceful local-core cancellation fails and the Flutter client reports the process-kill fallback status, the original cancel exception is normalized with `_ipcDiagnosticOrNull('$cancelError')` rather than interpolated raw.

Offline ML tooling dependencies are pinned and scoped to development. `ml/requirements.txt` uses exact direct package versions, `ml/requirements.lock.txt` pins the Windows/Python 3.12 transitive verification set, and `docs/dependency-license-inventory.md` records PyPI/installed metadata evidence plus the remaining release-host SBOM/license-output requirement.

Rust and Dart dependency lockfile coverage is inventoried in `docs/dependency-license-inventory.md`. The Flutter client, Dart protocol packages, native engine, local core, guard service, API service, and root Rust workspace have lockfiles; the native update service is covered by the root workspace `Cargo.lock`.

The backend API must fail closed on missing runtime configuration. `DATABASE_URL` and `REDIS_URL` are required, optional development seeding is controlled by `AVORAX_ENABLE_DEV_SEED=true`, and invalid Redis URLs, `.env` parse failures, and migration directory read errors are startup failures rather than hidden fallbacks. Local Compose explicitly enables the dev seed with Avorax project/key values that match the Flutter development defaults.

The backend API does not grant permissive browser CORS by default. Native Avorax clients do not require CORS; any future browser-based admin surface must add a reviewed, explicit origin policy rather than relying on ambient cross-origin access.

The backend API supports the Flutter client's hyphenated protection-run routes and returns `protection_run_id` while retaining legacy `session_id` compatibility. Request bodies are capped, event batches and nested JSON values are bounded, detection reports accept the current aggregate `detections` payload shape, and stored risk-score JSON parse errors are reported instead of being silently collapsed to empty reasons.

Backend bearer tokens are bounded before hashing. The API accepts the documented local dev key shape and generated `pk_avorax_...` keys, but rejects empty, oversized, or non-token authorization values before database lookup work.

Cloud project identifiers in request bodies may be either the authenticated project UUID string or the authenticated project's slug, such as `avorax-default`. The API resolves slugs against the authenticated project row; body project IDs do not authorize cross-project writes.

The backend API router uses Axum 0.7 brace-style dynamic route parameters, for example `/v1/protection-runs/{session_id}/heartbeat`. Old `:param` route syntax must not be reintroduced because it can fail during router construction on current Axum.

Flutter cloud telemetry identifies the client as Avorax. Protection-run creation sends `avorax-client`, and heartbeat visibility payloads use Avorax wording rather than legacy product copy.

Project creation over the backend API is fail-closed. The local dev project/key is created only by explicit startup seed configuration, and production project/key provisioning must stay out of band until an authenticated admin workflow is implemented and verified.

Backend API error responses redact internal failures. Bad request and forbidden responses may include bounded user-actionable text, but database/internal errors return a generic `internal server error` body instead of leaking SQL or infrastructure details.

Flutter scan and protected-app setup controls surface technical blockers as local history evidence. Unsupported platform scanning, full scans with no accessible roots, missing protected-app hash targets, and unavailable path hashing return visible errors/events; scan-start blockers also preserve a scan report where the UI expects one. Picker cancellation remains a user cancellation, not a failed security action.

Confirmed local-core action failures are audit events. Quarantine, feedback, allowlist, restore, and delete flows must log `*_failed` events for explicit `ok: false` local-core results as well as thrown IPC exceptions before surfacing the error in UI state. Quarantine actions use quarantine warning/error category severity; allowlist trust add/remove actions use protection warning/error category severity; false-positive and malicious feedback actions use protection warning/error category severity.
Threat ignore actions use scan warning category severity because they preserve a detected item rather than remediating it.
Scan-cancellation actions use scan category severity: idle requests are warnings, clean cancellation is info, fallback cancellation is warning, and cancellation failures are errors.
Settings-control actions use settings category severity: developer cloud override confirmations/saves/failures, log export confirmations/success/failure, and configuration reset confirmations/success/failure must keep explicit info/warning/error history.
Update progress actions use update category severity: check start/completion are info, while update availability, install start/readiness, and rollback start/readiness are warnings.
Protection-readiness events use protection category severity: protected-app detection and malware-engine health must record info for ready/detected/start outcomes, warnings for disabled/unavailable/none-found outcomes, and errors for failed probes.
Protected-app mutation actions use protection category severity: manual file/folder selection, detected-app selection, manual app add, and build-hash controls must record warning history for confirmations/mutations/unavailable paths and error history for failures.

Local-core stdout IPC decoding is malformed-tolerant. stdout response/progress lines use `Utf8Decoder(allowMalformed: true)` before line splitting so malformed byte sequences are handled through bounded protocol-warning/error paths.

Local-core stdout IPC lines are bounded before JSON parsing. The Flutter client uses `_boundedIpcStdoutLines` so a malformed or malicious local-core stdout line cannot grow without limit before protocol-warning handling.

Local-core action-result and watcher protocol errors are bounded before they reach controller state. The Flutter client uses the shared IPC diagnostic limit for `error` fields from malformed or failed action/watcher responses instead of preserving arbitrary raw response text.

Local subprocess diagnostics are bounded before they reach UI recovery flows. Guard self-test stdout/stderr, scan IPC stderr, and elevated PowerShell stderr/launch failures use bounded UTF-8 collection rather than raw stream joins.

Guard self-test subprocesses are time-bounded. If the self-test does not finish within `_protectionSelfTestTimeout`, the Flutter client kills the child process and surfaces a bounded failure diagnostic.

Protection self-test completion events are classified after reading the result. Results containing fail/not-active evidence use protection warning severity, while clean completions remain protection info events.

Scan-cancel IPC subprocesses are time-bounded. If cancellation IPC does not finish within `_cancelIpcTimeout`, the Flutter client kills the child process and surfaces a bounded cancellation failure diagnostic.

Scan-cancel IPC responses are verified before success is reported. The Flutter client reads bounded stdout/stderr from the cancellation subprocess, rejects non-zero exits, missing/malformed responses, and explicit `ok:false` results, and only treats `ok:true` as a successful cancel request.

Elevated PowerShell helper subprocesses collect both stdout and stderr through bounded IPC readers. Timeout handling kills the PowerShell launcher and reports bounded diagnostics from either stream.

LocalCoreClient exception diagnostics are bounded before reaching UI recovery paths. Protection self-test, install-report open, local-core IPC failures, cancel IPC, and executable probe exceptions normalize details with the shared IPC diagnostic limit.

LocalCoreClient list-response failures are bounded before reaching UI refresh failures. Quarantine and allowlist list errors returned by local-core IPC use the shared diagnostic limit before throwing into controller refresh paths.

Local event export cleanup failures bound both the original export exception and cleanup exception before throwing the combined diagnostic. Log export failures must be visible without allowing unbounded exception text into UI state.

Update diagnostics are bounded before they reach UI state or audit history. Update package cleanup, update check, install, and rollback exception paths normalize and cap failure details before setting `errorMessage`, `updateError`, or local-event `details`. Update failure local events use update category with error severity, and busy/confirmation/unavailable update outcomes use update category with warning severity.

Updater subprocess stdout/stderr diagnostics include truncation markers inside the updater diagnostic limit. The marker is not appended after the buffer reaches the configured maximum.

Combined updater subprocess diagnostics are bounded after stream labels are added. Individually bounded stdout and stderr streams must not be concatenated into an oversized failure message.

Updater subprocess execution is time-bounded. If Avorax Update Service does not exit within `updaterProcessTimeout`, the Flutter client kills the child process and reports bounded stdout/stderr diagnostics instead of waiting indefinitely.

Scan local events are categorized by result severity. Scan failures are scan/error events, while completed scans with skipped or errored coverage are scan/warning events rather than ordinary info completion.

Local-core action diagnostics are bounded before they reach UI state or audit history. Quarantine, feedback, allowlist, restore, and delete failures normalize thrown exceptions and failed local-core result errors before recording `*_failed` events or visible error messages.

Protection and privilege-action diagnostics are bounded before they reach UI state or audit history. Core Service start, install-report open, repair, protection start/stop, and protection self-test failures normalize exception details, and protection start/stop warnings cap Guard-mode and watcher error text. Protection starts with Guard-mode or watcher limitations emit `protection_start_limited` warning evidence instead of a plain success event. Successful protection stops emit protection-categorized local history with local Guard/watch stop details.
Service recovery controls use protection category severity: Core Service start, install-report open, and installation repair confirmation/request events are warnings, and failure events are errors.
Protection-state lifecycle controls use protection category severity: startup restore and profile changes are warnings, clean stop is info, restore-start is warning during saved preference restore or info for a normal start request, and engine-unavailable start failure is error.

Protection settings diagnostics are bounded before they reach UI state or audit history. Protection-profile and ransomware-guard settings changes normalize local-core result errors, primary save exceptions, rollback result errors, and rollback exceptions before recording failure events or visible settings errors.

Scan and settings operation diagnostics are bounded before they reach UI state or audit history. Scheduled scan settings, custom scan pickers, scan cancellation, scan invocation failures, log export, and configuration reset normalize exception details before writing failure events, scan reports, or visible errors.
Custom scan picker failures and quick-scan no-target completions use scan category severity: picker failures are errors, quick-scan no-target completion is warning, and normal scan-start is info.
Scheduled scan and heartbeat lifecycle events use explicit severity: scheduled scan setting changes are scan warnings, scheduled scan starts are scan info, protection self-test starts are protection info, heartbeat success is protection info, and heartbeat failure is protection warning.
Controller local-event calls declare category and severity at the call site. Startup, onboarding, config recovery, local scanner initialization, cloud health, scan, update, protection, quarantine, settings, and heartbeat events must not rely on repository defaults.

Performance benchmark copy cleanup diagnostics preserve both failure causes. If harmless synthetic update-copy benchmarking fails after creating a target and partial-target cleanup also fails, the benchmark raises a combined diagnostic with the original copy error and cleanup error instead of masking the first failure.

Performance benchmark error diagnostics are bounded before report persistence. Timed metric failures and combined copy/cleanup diagnostics use NUL-normalized text capped at the benchmark diagnostic limit with a truncation marker, instead of persisting raw exception strings.

Performance benchmark subprocess output is bounded before report persistence. Benchmark subprocesses drain stdout/stderr through a bounded reader and retain only a capped output tail plus `output_truncated` evidence, rather than collecting full command output in memory.

Source-contract runner failure diagnostics are bounded before console output. The dependency-free Python fallback runner preserves failing test tracebacks but caps them with truncation markers and normalizes NUL/control characters before adding them to validation failure output.

Source-contract evidence reads are bounded. The central Python contract suite reads repository source evidence only after confirming the path stays under the repository, is a regular non-linked file, and is below the source-contract byte limit.

Threat-intel GitHub metadata reads are bounded before JSON parsing. The Python importer rejects malformed, negative, or oversized `Content-Length` values, reads at most the configured response cap plus one sentinel byte, requires UTF-8 text, and accepts only JSON objects before using GitHub API metadata.

Threat-intel GitHub repository metadata is shape-validated before indicator generation. Source URLs must be exact HTTPS `github.com/<owner>/<repo>` repository URLs with safe bounded owner/repo tokens. Default branches must be bounded strings, explicit CLI/source branch refs must be validated and normalized before use, tree responses must carry a boolean truncation flag and bounded list, blob rows must have safe repository-relative POSIX paths plus valid optional SHA/size fields, and branch refs are URL-encoded before tree API requests. Metadata JSONL output revalidates consumed tree rows before writing path, blob-SHA, and size fields. Recursive tree responses marked `truncated` fail closed instead of producing incomplete metadata packs.

Threat-intel source configs are schema-checked before import. A `sources` field must be a list of objects, `enabled` must be boolean when present, top-level source configs must have `url` or `source_url`, and selected GitHub metadata sources without a URL fail visibly. GitHub metadata source entries reject unknown fields, ambiguous `url`/`source_url` pairs, unsupported modes, and malformed labels before output attribution. Disabled example sources still remain inactive unless an operator explicitly passes `--include-disabled`.

Manual malware-report IOC imports are schema-checked before JSONL output. Source names, indicator lists, required indicator type/value fields, and explicit active metadata must be typed, non-empty where required, bounded text without control characters, and fail visibly when malformed. Threat category, confidence, false-positive notes, and action policy must come from the indicator row or explicit report-level inheritance; missing values are not replaced with `unknown`/`medium`/`review` defaults.

SHA-256 hash-feed imports also validate metadata before JSONL output. Source names, optional source URLs/types, malware-family labels, and explicit category output must be typed, bounded text; malformed metadata or missing category metadata fails before confirmed hash indicators are written.

Developer hash-only imports reject non-string JSON hash entries instead of stringifying them. Source names, optional source URLs, and explicit category metadata are typed and bounded before hash-only JSONL output is written; missing category metadata fails before confirmed SHA-256 indicators are emitted.

Generic signature-pack compilation validates active indicator rows before output. Indicator IDs, source names, indicator types, patterns, categories, confidence, action policies, false-positive notes, and pack version metadata must be typed and bounded; missing confidence/action/version metadata no longer falls back to implicit values.

Known-bad signature-pack building has a stricter escalation boundary. Only valid SHA-256 indicators with explicit `confidence: confirmed`, `action_policy: quarantine_if_policy_allows`, category, source, false-positive notes, and pack version metadata become active known-bad signatures; lower-confidence hash metadata is retained as non-active input evidence.

Native rule-pack compilation validates `.zrule` source packs before output. Rule packs must declare supported format/version/rules, rule rows and conditions must use the expected schema, conditions must be non-empty, and `min_condition_matches` must be positive and feasible.

Indicator-pack validation uses the same strict posture for generated and bundled `.zsig`/`.zrule` packs. The validator rejects unknown pack, item, and condition fields; requires object entries and explicit item lists; validates self-hash shape for non-empty packs; and fails on empty rule conditions or impossible condition counts before reporting success.

Generated native rule-pack compilation requires explicit pack version metadata. Missing or empty `--version` fails before `.zrule` output, and canonical self-hashing uses the actual compiled rule list instead of a hidden empty default.

The real-world detection-pack wrapper keeps the hash-only workflow explicit and bounded. It requires category/version metadata, checks the current Python executable and local helper scripts before subprocess launch, captures bounded stdout/stderr with a timeout, writes through a unique temporary JSONL, and removes that temporary file on success or failure.

Platform PowerShell probes collect stdout and stderr through bounded streams rather than unbounded `Process.run` results. Probe timeouts kill the child process, non-zero exits preserve bounded diagnostics, and oversized successful stdout fails visibly before JSON parsing.

Protected-app process enumeration also uses bounded subprocess collection. `tasklist` and `ps` output is read through capped UTF-8 streams, timed out with process kill, and rejected visibly if stdout exceeds the process-list output limit.

Flutter app-state controller exception diagnostics use a shared bounded formatter. Outside `_boundedUiDiagnostic`, controller code must not write raw `'$error'` exception text directly into visible UI state, local-event details, scan reports, or diagnostic records.

Update service diagnostics are bounded before reaching update status or UI recovery paths. Installed-version discovery, GitHub release-feed fallback, and updater file-probe inspection failures normalize exception text with the update diagnostic limit.

Flutter core/UI diagnostics are bounded before reaching visible cards, snackbars, audit history, or recovery reasons. App detection, platform probes, config recovery, local-event maintenance, Settings log export, and Device provider failures normalize runtime exception text before display or persistence.

Truncated Flutter diagnostics and notification previews reserve room for their ellipsis inside the declared maximum length. Helpers that append `...` must slice to `max - 3`, not `max`, so visible bounded text does not exceed its documented cap.
