use std::collections::{HashMap, HashSet};
#[cfg(windows)]
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::ExitStatus;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zentor_native_engine::{
    EngineConfig, ScanActionMode as AneScanActionMode, Verdict as AneVerdict, ZentorNativeEngine,
};

mod driver_health;
mod driver_ipc;
#[cfg(windows)]
mod driver_port;
mod known_bad_cache;
mod known_good_cache;
mod preexecution_policy;
mod self_test;

const SERVICE_NAME: &str = "avorax_guard_service";
#[cfg(windows)]
const GUARD_SERVICE_RUNTIME_FAILURE_EXIT_CODE: u32 = 1;
#[cfg(windows)]
const GUARD_SERVICE_START_WAIT_HINT: Duration = Duration::from_secs(30);
const QUARANTINE_EXTENSION: &str = "avoraxq";
const MAX_GUARD_QUARANTINE_COPY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_GUARD_HASH_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_GUARD_QUARANTINE_METADATA_AUTH_BYTES: u64 = 16 * 1024;
const MAX_GUARD_QUARANTINE_ID_CHARS: usize = 128;
const MAX_GUARD_QUARANTINE_METADATA_LABEL_CHARS: usize = 256;
const MAX_GUARD_QUARANTINE_METADATA_STATE_CHARS: usize = 64;
const MAX_GUARD_QUARANTINE_USER_NOTE_CHARS: usize = 2048;
const MAX_GUARD_QUARANTINE_RECORD_PATH_CHARS: usize = 4096;
const DEFAULT_GUARD_QUARANTINE_DETECTION_NAME: &str = "Guard detection";
const DEFAULT_GUARD_QUARANTINE_ENGINE: &str = "guard-service";
#[cfg(feature = "compat_yara")]
const GUARD_YARA_SAMPLE_LIMIT_BYTES: u64 = 1_048_576;
#[cfg(any(feature = "compat_yara", test))]
const GUARD_YARA_RULE_TEXT_LIMIT_BYTES: u64 = 256 * 1024;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
#[cfg(not(windows))]
const NON_WINDOWS_GUARD_SERVICE_MODE_UNSUPPORTED: &str =
    "Avorax Guard Service Windows service mode is unsupported on this platform";
const MAX_GUARD_MODE_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_GUARD_COMMAND_JSON_BYTES: usize = 256 * 1024;
const MAX_GUARD_IPC_PATH_CHARS: usize = 4096;
const MAX_GUARD_IPC_HASHES: usize = 2048;
const MAX_GUARD_IPC_TEXT_CHARS: usize = 1024;
const MAX_GUARD_IPC_REQUEST_ID_CHARS: usize = 128;
const MAX_WINDOWS_PROCESS_QUERY_BYTES: usize = 1024 * 1024;
const MAX_GUARD_COMMAND_OUTPUT_BYTES: usize = 2048;
const GUARD_PROCESS_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(windows)]
const GUARD_ACL_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(feature = "compat_clamav", test))]
const MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES: usize = 8192;
#[cfg(any(feature = "compat_clamav", test))]
#[allow(dead_code)]
const GUARD_CLAMAV_SCAN_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_GUARD_WATCH_POLL_INTERVAL_MS: u64 = 750;
const MIN_GUARD_WATCH_POLL_INTERVAL_MS: u64 = 100;
const MAX_GUARD_WATCH_POLL_INTERVAL_MS: u64 = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardCommand {
    command: String,
    process_id: Option<u32>,
    process_path: Option<String>,
    known_malicious_hashes: Option<Vec<String>>,
    // Accepted for wire compatibility but intentionally ignored; external callers cannot inject trust.
    #[allow(dead_code)]
    known_good_hashes: Option<Vec<String>>,
    // Accepted for wire compatibility but intentionally ignored; external callers cannot inject trust.
    #[allow(dead_code)]
    user_approved_hashes: Option<Vec<String>>,
    protection_mode: Option<preexecution_policy::DriverProtectionMode>,
    poll_interval_ms: Option<u64>,
    max_iterations: Option<u32>,
    scan_request: Option<driver_ipc::ScanRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardModeConfigFile {
    mode: String,
    updated_at: Option<DateTime<Utc>>,
    source: Option<String>,
}

#[derive(Debug, Serialize)]
struct GuardEvent {
    ok: bool,
    action: String,
    message: String,
    process_id: Option<u32>,
    process_path: Option<String>,
    quarantine_id: Option<String>,
    quarantine_path: Option<String>,
    quarantine_record_path: Option<String>,
    created_at: DateTime<Utc>,
}

struct ProcessInspection {
    hash: String,
    native_match: Option<LocalThreatMatch>,
    compat_match: Option<LocalThreatMatch>,
}

enum ProcessInspectionOutcome {
    Inspected(ProcessInspection),
    ErrorReported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessFileIdentity {
    len: u64,
    modified: SystemTime,
}

#[derive(Clone, Debug)]
struct ProcessHashCacheEntry {
    identity: ProcessFileIdentity,
    hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum QuarantineStatus {
    Quarantined,
    Restored,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuardQuarantineRecord {
    quarantine_id: String,
    original_path: String,
    quarantine_path: String,
    sha256: String,
    file_size: u64,
    detection_name: String,
    engine: String,
    action_taken: String,
    quarantined_at: DateTime<Utc>,
    status: QuarantineStatus,
    user_note: Option<String>,
    source: String,
    blocked_before_execution: bool,
    process_started: bool,
    process_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalThreatConfidence {
    Confirmed,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
struct LocalThreatMatch {
    reason: String,
    engine: String,
    confidence: LocalThreatConfidence,
}

#[cfg(any(feature = "compat_clamav", test))]
#[derive(Debug)]
#[allow(dead_code)]
struct BoundedGuardClamavCommandOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "--service" => return run_service(),
            "--watch" => return run_console_watch(),
            _ => {}
        }
    }

    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    while let Some(line) = read_next_guard_command_line(&mut stdin)? {
        if line.trim().is_empty() {
            continue;
        }
        let command = parse_guard_command_line(&line)?;
        let response = handle(command);
        println!("{}", serde_json::to_string(&response)?);
    }
    Ok(())
}

fn read_next_guard_command_line<R: BufRead>(reader: &mut R) -> anyhow::Result<Option<String>> {
    read_next_bounded_line(reader, MAX_GUARD_COMMAND_JSON_BYTES, "guard command JSON")
}

fn read_next_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
    label: &str,
) -> anyhow::Result<Option<String>> {
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

fn parse_guard_command_line(line: &str) -> anyhow::Result<GuardCommand> {
    if line.len() > MAX_GUARD_COMMAND_JSON_BYTES {
        anyhow::bail!(
            "guard command JSON exceeds maximum size of {} bytes",
            MAX_GUARD_COMMAND_JSON_BYTES
        );
    }
    serde_json::from_str(line).context("failed to parse guard command JSON")
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, windows_service_main);

#[cfg(windows)]
fn run_service() -> anyhow::Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
fn run_service() -> anyhow::Result<()> {
    anyhow::bail!(NON_WINDOWS_GUARD_SERVICE_MODE_UNSUPPORTED)
}

#[cfg(windows)]
fn windows_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_windows_service_loop() {
        report_guard_fatal_error("guard_service_error.log", &format!("{error:#}"));
    }
}

pub(crate) fn report_guard_fatal_error(file_name: &str, detail: &str) {
    if let Err(error) = write_guard_fatal_error_log(file_name, detail) {
        eprintln!("failed to write guard fatal error log {file_name}: {error:#}; original error: {detail}");
    }
}

fn write_guard_fatal_error_log(file_name: &str, detail: &str) -> anyhow::Result<()> {
    if file_name.is_empty() || file_name.contains('/') || file_name.contains('\\') {
        anyhow::bail!("invalid guard fatal error log file name");
    }
    let base = event_log_base()?;
    fs::create_dir_all(&base).with_context(|| {
        format!(
            "failed to create guard fatal log directory {}",
            base.display()
        )
    })?;
    ensure_guard_fatal_log_directory(&base)?;
    let path = base.join(file_name);
    let temp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    write_guard_fatal_log_file_exclusive(
        &temp_path,
        detail.as_bytes(),
        "temporary guard fatal error log",
    )?;
    if let Err(error) = remove_existing_guard_fatal_log_file(&path, "guard fatal error log") {
        cleanup_staged_guard_fatal_log(&temp_path, "temporary guard fatal error log")
            .with_context(|| {
                format!(
                    "failed to clean up temporary guard fatal error log {} after activation preflight failed: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, &path) {
        cleanup_staged_guard_fatal_log(&temp_path, "temporary guard fatal error log")
            .with_context(|| {
                format!(
                    "failed to clean up temporary guard fatal error log {} after activation failed: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to activate guard fatal error log {}",
                path.display()
            )
        });
    }
    Ok(())
}

fn ensure_guard_fatal_log_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect guard fatal log directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link guard fatal log directory");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("refusing to use reparse point guard fatal log directory");
        }
    }
    if !metadata.is_dir() {
        anyhow::bail!(
            "guard fatal log directory is not a directory: {}",
            path.display()
        );
    }
    Ok(())
}

fn remove_existing_guard_fatal_log_file(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing to replace symbolic link {label}");
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    anyhow::bail!("refusing to replace reparse point {label}");
                }
            }
            if !metadata.is_file() {
                anyhow::bail!("refusing to replace non-file {label}");
            }
            fs::remove_file(path)
                .with_context(|| format!("failed to remove existing {label} {}", path.display()))?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn write_guard_fatal_log_file_exclusive(
    path: &Path,
    bytes: &[u8],
    label: &str,
) -> anyhow::Result<()> {
    let mut output = fs::OpenOptions::new()
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

fn cleanup_staged_guard_fatal_log(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {label} {}", path.display()))
        }
    }
}

#[cfg(windows)]
fn run_windows_service_loop() -> anyhow::Result<()> {
    use windows_service::service::{ServiceControl, ServiceExitCode, ServiceState};
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let status_handle =
        service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Err(error) = shutdown_tx.send(()) {
                        report_guard_fatal_error(
                            "guard_service_error.log",
                            &format!("failed to signal guard service shutdown: {error}"),
                        );
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;

    status_handle.set_service_status(guard_service_status(
        ServiceState::StartPending,
        ServiceExitCode::NO_ERROR,
    ))?;

    status_handle.set_service_status(guard_service_status(
        ServiceState::Running,
        ServiceExitCode::NO_ERROR,
    ))?;

    let driver_port_stop = driver_port::start_background_worker();
    let result = watch_processes_until_shutdown(
        &HashSet::new(),
        DEFAULT_GUARD_WATCH_POLL_INTERVAL_MS,
        &shutdown_rx,
    );
    driver_port_stop.store(true, std::sync::atomic::Ordering::Relaxed);

    let stop_status_result = status_handle.set_service_status(guard_service_status(
        ServiceState::Stopped,
        guard_service_stop_exit_code(&result),
    ));
    combine_guard_service_runtime_and_status_results(result, stop_status_result)
}

#[cfg(windows)]
fn guard_service_status(
    state: windows_service::service::ServiceState,
    exit_code: windows_service::service::ServiceExitCode,
) -> windows_service::service::ServiceStatus {
    use windows_service::service::{
        ServiceControlAccept, ServiceState, ServiceStatus, ServiceType,
    };

    let is_start_pending = state == ServiceState::StartPending;
    let controls_accepted = if state == ServiceState::Running {
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
    } else {
        ServiceControlAccept::empty()
    };
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted,
        exit_code,
        checkpoint: u32::from(is_start_pending),
        wait_hint: if is_start_pending {
            GUARD_SERVICE_START_WAIT_HINT
        } else {
            Duration::from_secs(0)
        },
        process_id: None,
    }
}

#[cfg(windows)]
fn guard_service_stop_exit_code(
    runtime_result: &anyhow::Result<()>,
) -> windows_service::service::ServiceExitCode {
    if runtime_result.is_ok() {
        windows_service::service::ServiceExitCode::NO_ERROR
    } else {
        windows_service::service::ServiceExitCode::ServiceSpecific(
            GUARD_SERVICE_RUNTIME_FAILURE_EXIT_CODE,
        )
    }
}

#[cfg(windows)]
fn combine_guard_service_runtime_and_status_results(
    runtime_result: anyhow::Result<()>,
    status_result: windows_service::Result<()>,
) -> anyhow::Result<()> {
    match (runtime_result, status_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(runtime_error), Ok(())) => Err(runtime_error),
        (Ok(()), Err(status_error)) => Err(status_error)
            .context("failed to report stopped Guard Service status to Windows"),
        (Err(runtime_error), Err(status_error)) => anyhow::bail!(
            "Guard Service runtime failed: {runtime_error:#}; additionally failed to report stopped status to Windows: {status_error}"
        ),
    }
}

fn run_console_watch() -> anyhow::Result<()> {
    let (_shutdown_tx, shutdown_rx) = mpsc::channel();
    #[cfg(windows)]
    let _driver_port_stop = driver_port::start_background_worker();
    watch_processes_until_shutdown(
        &HashSet::new(),
        DEFAULT_GUARD_WATCH_POLL_INTERVAL_MS,
        &shutdown_rx,
    )
}

fn handle(command: GuardCommand) -> GuardEvent {
    match command.command.as_str() {
        "health" => {
            let configured_guard_mode = match configured_guard_mode() {
                Ok(mode) => mode,
                Err(error) => {
                    return error_event(None, None, format!("guard mode unavailable: {error:#}"));
                }
            };
            match known_bad_cache::load_known_bad_hashes() {
                Ok(known_bad_hashes) => {
                    let message = match serde_json::to_string(&serde_json::json!({
                        "guard": "ready",
                        "driver": driver_health::DriverHealth::probe(),
                        "policy": preexecution_policy::PreExecutionPolicy::default(),
                        "configured_guard_mode": configured_guard_mode,
                        "known_bad_hashes": known_bad_hashes.len(),
                        "post_launch_fallback": post_launch_fallback_available(&configured_guard_mode),
                    })) {
                        Ok(message) => message,
                        Err(error) => {
                            return error_event(
                                None,
                                None,
                                format!("health serialization failed: {error:#}"),
                            );
                        }
                    };
                    GuardEvent {
                        ok: true,
                        action: "health".to_string(),
                        message,
                        process_id: None,
                        process_path: None,
                        quarantine_path: None,
                        quarantine_id: None,
                        quarantine_record_path: None,
                        created_at: Utc::now(),
                    }
                }
                Err(error) => error_event(
                    None,
                    None,
                    format!("known-bad cache unavailable: {error:#}"),
                ),
            }
        }
        "driver_scan_request" => {
            let Some(mut request) = command.scan_request else {
                return error("scan_request is required");
            };
            sanitize_external_driver_request(&mut request);
            if let Err(error) = validate_guard_scan_request(&request) {
                return error_event(request.process_id, None, error.to_string());
            }
            let request_path = request.file_path.clone();
            let mut hashes = match known_bad_cache::load_known_bad_hashes() {
                Ok(hashes) => hashes,
                Err(error) => {
                    return error_event(
                        request.process_id,
                        Some(request_path),
                        format!("known-bad cache unavailable: {error:#}"),
                    );
                }
            };
            match normalize_command_hashes(command.known_malicious_hashes) {
                Ok(command_hashes) => hashes.extend(command_hashes),
                Err(error) => {
                    return error_event(request.process_id, Some(request_path), error.to_string());
                }
            }
            let mode = match configured_guard_mode() {
                Ok(mode) => mode,
                Err(error) => {
                    return error_event(
                        request.process_id,
                        Some(request_path),
                        format!("guard mode unavailable: {error:#}"),
                    );
                }
            };
            match driver_ipc::evaluate_driver_request(
                &request,
                &driver_ipc::DriverVerdictConfig {
                    known_bad_hashes: hashes,
                    mode,
                    ..Default::default()
                },
            ) {
                Ok(verdict) => {
                    let message = match serde_json::to_string(&verdict) {
                        Ok(message) => message,
                        Err(error) => {
                            return error_event(
                                request.process_id,
                                Some(request_path),
                                format!("driver verdict serialization failed: {error:#}"),
                            );
                        }
                    };
                    GuardEvent {
                        ok: true,
                        action: "driverVerdict".to_string(),
                        message,
                        process_id: request.process_id,
                        process_path: Some(request_path),
                        quarantine_id: None,
                        quarantine_path: None,
                        quarantine_record_path: None,
                        created_at: Utc::now(),
                    }
                }
                Err(error) => {
                    error_event(request.process_id, Some(request_path), error.to_string())
                }
            }
        }
        "driver_self_test" => {
            let mut hashes = match known_bad_cache::load_known_bad_hashes() {
                Ok(hashes) => hashes,
                Err(error) => {
                    return error_event(
                        None,
                        None,
                        format!("known-bad cache unavailable: {error:#}"),
                    );
                }
            };
            match normalize_command_hashes(command.known_malicious_hashes) {
                Ok(command_hashes) => hashes.extend(command_hashes),
                Err(error) => return error_event(None, None, error.to_string()),
            }
            match self_test::run_self_test(hashes) {
                Ok(report) => {
                    let message = match serde_json::to_string(&report) {
                        Ok(message) => message,
                        Err(error) => {
                            return error_event(
                                None,
                                None,
                                format!("driver self-test serialization failed: {error:#}"),
                            );
                        }
                    };
                    GuardEvent {
                        ok: report.passed,
                        action: "driverSelfTest".to_string(),
                        message,
                        process_id: None,
                        process_path: None,
                        quarantine_id: None,
                        quarantine_path: None,
                        quarantine_record_path: None,
                        created_at: Utc::now(),
                    }
                }
                Err(error) => error_event(None, None, error.to_string()),
            }
        }
        "process_started" => {
            let path = match required_guard_ipc_path(command.process_path, "process_path") {
                Ok(path) => path,
                Err(error) => return error_event(None, None, error.to_string()),
            };
            let path_text = path.display().to_string();
            let pid = command.process_id;
            let malicious = match normalize_command_hashes(command.known_malicious_hashes) {
                Ok(hashes) => hashes,
                Err(error) => return error_event(pid, Some(path_text), error.to_string()),
            };
            let protection_mode = match effective_guard_mode(command.protection_mode) {
                Ok(mode) => mode,
                Err(error) => {
                    return error_event(
                        pid,
                        Some(path_text),
                        format!("guard mode unavailable: {error:#}"),
                    )
                }
            };
            match handle_process_started(pid, &path, &malicious, protection_mode) {
                Ok(event) => event,
                Err(error) => error_event(pid, Some(path_text), error.to_string()),
            }
        }
        "watch_processes" => {
            let malicious = match normalize_command_hashes(command.known_malicious_hashes) {
                Ok(hashes) => hashes,
                Err(error) => return error_event(None, None, error.to_string()),
            };
            let protection_mode = match effective_guard_mode(command.protection_mode) {
                Ok(mode) => mode,
                Err(error) => {
                    return error_event(None, None, format!("guard mode unavailable: {error:#}"));
                }
            };
            let poll_interval_ms = match guard_watch_poll_interval_ms(command.poll_interval_ms) {
                Ok(value) => value,
                Err(error) => return error_event(None, None, error.to_string()),
            };
            match watch_processes(
                &malicious,
                poll_interval_ms,
                command.max_iterations,
                protection_mode,
            ) {
                Ok(event) => event,
                Err(error) => error_event(None, None, error.to_string()),
            }
        }
        _ => error("unknown command"),
    }
}

fn guard_watch_poll_interval_ms(raw: Option<u64>) -> anyhow::Result<u64> {
    match raw {
        None => Ok(DEFAULT_GUARD_WATCH_POLL_INTERVAL_MS),
        Some(value) => validate_guard_watch_poll_interval_ms(value),
    }
}

fn validate_guard_watch_poll_interval_ms(value: u64) -> anyhow::Result<u64> {
    if value < MIN_GUARD_WATCH_POLL_INTERVAL_MS {
        anyhow::bail!(
            "guard process watch poll_interval_ms must be at least {} ms",
            MIN_GUARD_WATCH_POLL_INTERVAL_MS
        );
    }
    if value > MAX_GUARD_WATCH_POLL_INTERVAL_MS {
        anyhow::bail!(
            "guard process watch poll_interval_ms must be at most {} ms",
            MAX_GUARD_WATCH_POLL_INTERVAL_MS
        );
    }
    Ok(value)
}

fn sanitize_external_driver_request(request: &mut driver_ipc::ScanRequest) {
    request.normalized_file_path = None;
    request.signature_status = None;
    request.publisher = None;
    request.signature_verified_by = None;
    request.parent_process_path = None;
    request.sha256 = None;
    request.sha256_verified_by = None;
}

fn validate_guard_scan_request(request: &driver_ipc::ScanRequest) -> anyhow::Result<()> {
    validate_guard_ipc_text(
        &request.request_id,
        "scan_request.request_id",
        MAX_GUARD_IPC_REQUEST_ID_CHARS,
        true,
    )?;
    validate_guard_ipc_path_text(&request.file_path, "scan_request.file_path")?;
    validate_optional_guard_ipc_path_text(
        request.normalized_file_path.as_deref(),
        "scan_request.normalized_file_path",
    )?;
    validate_optional_guard_ipc_path_text(
        request.parent_process_path.as_deref(),
        "scan_request.parent_process_path",
    )?;
    validate_optional_guard_ipc_text(
        request.user_sid.as_deref(),
        "scan_request.user_sid",
        MAX_GUARD_IPC_TEXT_CHARS,
    )?;
    Ok(())
}

fn required_guard_ipc_path(raw: Option<String>, field: &str) -> anyhow::Result<PathBuf> {
    let raw = raw.ok_or_else(|| anyhow::anyhow!("{field} is required"))?;
    validate_guard_ipc_path_text(&raw, field)?;
    Ok(PathBuf::from(raw))
}

fn validate_optional_guard_ipc_path_text(raw: Option<&str>, field: &str) -> anyhow::Result<()> {
    if let Some(raw) = raw {
        validate_guard_ipc_path_text(raw, field)?;
    }
    Ok(())
}

fn validate_guard_ipc_path_text(raw: &str, field: &str) -> anyhow::Result<()> {
    validate_guard_ipc_text(raw, field, MAX_GUARD_IPC_PATH_CHARS, true)
}

fn validate_optional_guard_ipc_text(
    raw: Option<&str>,
    field: &str,
    max_chars: usize,
) -> anyhow::Result<()> {
    if let Some(raw) = raw {
        validate_guard_ipc_text(raw, field, max_chars, false)?;
    }
    Ok(())
}

fn validate_guard_ipc_text(
    raw: &str,
    field: &str,
    max_chars: usize,
    require_non_empty: bool,
) -> anyhow::Result<()> {
    if require_non_empty && raw.trim().is_empty() {
        anyhow::bail!("{field} is required");
    }
    if raw.contains('\0') {
        anyhow::bail!("{field} contains a NUL byte");
    }
    if raw.chars().count() > max_chars {
        anyhow::bail!("{field} exceeds maximum length of {max_chars} characters");
    }
    Ok(())
}

fn normalize_command_hashes(values: Option<Vec<String>>) -> anyhow::Result<HashSet<String>> {
    let mut hashes = HashSet::new();
    let Some(values) = values else {
        return Ok(hashes);
    };
    if values.len() > MAX_GUARD_IPC_HASHES {
        anyhow::bail!(
            "known malicious SHA-256 list exceeds maximum of {} entries",
            MAX_GUARD_IPC_HASHES
        );
    }
    for value in values {
        let Some(hash) = normalize_sha256(&value) else {
            anyhow::bail!("invalid known malicious SHA-256 value");
        };
        hashes.insert(format!("sha256:{hash}"));
    }
    Ok(hashes)
}

fn effective_guard_mode(
    requested: Option<preexecution_policy::DriverProtectionMode>,
) -> anyhow::Result<preexecution_policy::DriverProtectionMode> {
    match requested {
        Some(mode) => Ok(mode),
        None => configured_guard_mode(),
    }
}

fn post_launch_fallback_available(mode: &preexecution_policy::DriverProtectionMode) -> bool {
    !matches!(mode, preexecution_policy::DriverProtectionMode::Disabled)
}

fn handle_process_started(
    process_id: Option<u32>,
    process_path: &Path,
    known_malicious_hashes: &HashSet<String>,
    protection_mode: preexecution_policy::DriverProtectionMode,
) -> anyhow::Result<GuardEvent> {
    let hash = sha256_file(process_path)?;
    let native_match = native_threat_match(process_path).with_context(|| {
        format!(
            "process native inspection failed: {}",
            process_path.display()
        )
    })?;
    let compat_match = if native_match.is_none() {
        compat_threat_match(process_path)?
    } else {
        None
    };
    let confirmed_match = if known_malicious_hashes.contains(&hash) {
        Some(LocalThreatMatch {
            reason: "known malicious hash".to_string(),
            engine: "avorax-known-bad-hash".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        })
    } else if let Some(native_match) = native_match {
        Some(native_match)
    } else {
        compat_match
    };

    let Some(threat_match) = confirmed_match else {
        return Ok(GuardEvent {
            ok: true,
            action: "monitored".to_string(),
            message: "Process monitored. No confirmed local threat hash matched.".to_string(),
            process_id,
            process_path: Some(process_path.display().to_string()),
            quarantine_id: None,
            quarantine_path: None,
            quarantine_record_path: None,
            created_at: Utc::now(),
        });
    };

    if matches!(
        protection_mode,
        preexecution_policy::DriverProtectionMode::Disabled
            | preexecution_policy::DriverProtectionMode::ObserveOnly
    ) {
        return Ok(GuardEvent {
            ok: true,
            action: "reviewOnly".to_string(),
            message: format!(
                "Confirmed local threat observed but automatic stop/quarantine is not enabled. Reason: {}. Confidence: {:?}.",
                threat_match.reason, threat_match.confidence
            ),
            process_id,
            process_path: Some(process_path.display().to_string()),
            quarantine_id: None,
            quarantine_path: None,
            quarantine_record_path: None,
            created_at: Utc::now(),
        });
    }

    let stop_requested = if let Some(pid) = process_id {
        stop_process(pid).with_context(|| {
            format!("failed to stop process {pid} before quarantining confirmed threat")
        })?;
        true
    } else {
        false
    };
    let record =
        quarantine_file(process_path, &hash, process_id, &threat_match).with_context(|| {
            if stop_requested {
                "known malicious process stop succeeded but quarantine failed"
            } else {
                "known malicious file matched without process id but quarantine failed"
            }
        })?;
    let (action, message) = if stop_requested {
        (
            "stopRequestedAndQuarantined",
            format!(
                "Avorax sent a process stop request and moved the file to quarantine. Reason: {}. Confidence: {:?}.",
                threat_match.reason,
                threat_match.confidence
            ),
        )
    } else {
        (
            "quarantined",
            format!(
                "Avorax moved the file to quarantine. No process id was supplied, so no process stop was attempted. Reason: {}. Confidence: {:?}.",
                threat_match.reason,
                threat_match.confidence
            ),
        )
    };
    Ok(GuardEvent {
        ok: true,
        action: action.to_string(),
        message,
        process_id,
        process_path: Some(process_path.display().to_string()),
        quarantine_id: Some(record.quarantine_id.clone()),
        quarantine_path: Some(record.quarantine_path.clone()),
        quarantine_record_path: Some(
            checked_quarantine_record_path(&record.quarantine_id)?
                .display()
                .to_string(),
        ),
        created_at: Utc::now(),
    })
}

fn watch_processes(
    known_malicious_hashes: &HashSet<String>,
    poll_interval_ms: u64,
    max_iterations: Option<u32>,
    protection_mode: preexecution_policy::DriverProtectionMode,
) -> anyhow::Result<GuardEvent> {
    let poll_interval_ms = validate_guard_watch_poll_interval_ms(poll_interval_ms)?;
    let mut seen: HashSet<u32> = list_processes()?
        .into_iter()
        .map(|process| process.process_id)
        .collect();
    let mut cache: HashMap<PathBuf, ProcessHashCacheEntry> = HashMap::new();
    let mut iterations = 0u32;
    let mut inspection_errors = 0u64;

    loop {
        iterations = iterations.saturating_add(1);
        for process in list_processes()? {
            if !seen.insert(process.process_id) {
                continue;
            }
            if should_skip_process_path(&process.path) {
                continue;
            }
            let inspection =
                match inspect_new_process(&process.path, Some(process.process_id), &mut cache)? {
                    ProcessInspectionOutcome::Inspected(inspection) => inspection,
                    ProcessInspectionOutcome::ErrorReported => {
                        inspection_errors = inspection_errors.saturating_add(1);
                        continue;
                    }
                };

            if known_malicious_hashes.contains(&inspection.hash)
                || inspection.native_match.is_some()
                || inspection.compat_match.is_some()
            {
                return handle_process_started(
                    Some(process.process_id),
                    &process.path,
                    known_malicious_hashes,
                    protection_mode.clone(),
                );
            }
        }

        if let Some(max_iterations) = max_iterations {
            if iterations >= max_iterations {
                if inspection_errors > 0 {
                    return Ok(GuardEvent {
                        ok: false,
                        action: "watchCompletedWithInspectionErrors".to_string(),
                        message: format!(
                            "Process watch completed with {inspection_errors} process inspection error(s). No confirmed threat process was observed."
                        ),
                        process_id: None,
                        process_path: None,
                        quarantine_id: None,
                        quarantine_path: None,
                        quarantine_record_path: None,
                        created_at: Utc::now(),
                    });
                }
                return Ok(GuardEvent {
                    ok: true,
                    action: "watchCompleted".to_string(),
                    message: "Process watch completed. No confirmed threat process was observed."
                        .to_string(),
                    process_id: None,
                    process_path: None,
                    quarantine_id: None,
                    quarantine_path: None,
                    quarantine_record_path: None,
                    created_at: Utc::now(),
                });
            }
        }
        thread::sleep(Duration::from_millis(poll_interval_ms));
    }
}

fn watch_processes_until_shutdown(
    known_malicious_hashes: &HashSet<String>,
    poll_interval_ms: u64,
    shutdown_rx: &mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    let poll_interval_ms = validate_guard_watch_poll_interval_ms(poll_interval_ms)?;
    let mut seen: HashSet<u32> = list_processes()?
        .into_iter()
        .map(|process| process.process_id)
        .collect();
    let mut cache: HashMap<PathBuf, ProcessHashCacheEntry> = HashMap::new();
    let protection_mode = configured_guard_mode()?;

    loop {
        if shutdown_rx.try_recv().is_ok() {
            return Ok(());
        }

        for process in list_processes()? {
            if !seen.insert(process.process_id) {
                continue;
            }
            if should_skip_process_path(&process.path) {
                continue;
            }

            let inspection =
                match inspect_new_process(&process.path, Some(process.process_id), &mut cache)? {
                    ProcessInspectionOutcome::Inspected(inspection) => inspection,
                    ProcessInspectionOutcome::ErrorReported => continue,
                };

            if known_malicious_hashes.contains(&inspection.hash)
                || inspection.native_match.is_some()
                || inspection.compat_match.is_some()
            {
                match handle_process_started(
                    Some(process.process_id),
                    &process.path,
                    known_malicious_hashes,
                    protection_mode.clone(),
                ) {
                    Ok(event) => {
                        write_guard_event(&event)?;
                    }
                    Err(error) => {
                        write_guard_event(&error_event(
                            Some(process.process_id),
                            Some(process.path.display().to_string()),
                            error.to_string(),
                        ))?;
                    }
                }
            }
        }

        thread::sleep(Duration::from_millis(poll_interval_ms));
    }
}

fn inspect_new_process(
    path: &Path,
    process_id: Option<u32>,
    cache: &mut HashMap<PathBuf, ProcessHashCacheEntry>,
) -> anyhow::Result<ProcessInspectionOutcome> {
    let identity = match process_file_identity(path) {
        Ok(identity) => identity,
        Err(error) => {
            write_process_inspection_error(process_id, path, "metadata", error)?;
            return Ok(ProcessInspectionOutcome::ErrorReported);
        }
    };
    let hash = match cache.get(path) {
        Some(entry) if entry.identity == identity => entry.hash.clone(),
        _ => match sha256_file(path) {
            Ok(hash) => {
                cache.insert(
                    path.to_path_buf(),
                    ProcessHashCacheEntry {
                        identity,
                        hash: hash.clone(),
                    },
                );
                hash
            }
            Err(error) => {
                write_process_inspection_error(process_id, path, "hash", error)?;
                return Ok(ProcessInspectionOutcome::ErrorReported);
            }
        },
    };
    let native_match = match native_threat_match(path) {
        Ok(result) => result,
        Err(error) => {
            write_process_inspection_error(process_id, path, "native", error)?;
            return Ok(ProcessInspectionOutcome::ErrorReported);
        }
    };
    let compat_match = if native_match.is_none() {
        match compat_threat_match(path) {
            Ok(result) => result,
            Err(error) => {
                write_process_inspection_error(process_id, path, "compat", error)?;
                return Ok(ProcessInspectionOutcome::ErrorReported);
            }
        }
    } else {
        None
    };
    Ok(ProcessInspectionOutcome::Inspected(ProcessInspection {
        hash,
        native_match,
        compat_match,
    }))
}

fn process_file_identity(path: &Path) -> anyhow::Result<ProcessFileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect guard process path {}", path.display()))?;
    let file_type = metadata.file_type();
    if !file_type.is_file() || file_type.is_symlink() || is_guard_process_reparse_point(&metadata) {
        anyhow::bail!(
            "guard process path is not a regular non-reparse file: {}",
            path.display()
        );
    }
    let modified = metadata.modified().with_context(|| {
        format!(
            "unable to read modified time for guard process path {}",
            path.display()
        )
    })?;
    Ok(ProcessFileIdentity {
        len: metadata.len(),
        modified,
    })
}

fn write_process_inspection_error(
    process_id: Option<u32>,
    path: &Path,
    stage: &str,
    error: anyhow::Error,
) -> anyhow::Result<()> {
    write_guard_event(&error_event(
        process_id,
        Some(path.display().to_string()),
        format!("process {stage} inspection failed: {error:#}"),
    ))
}

fn configured_guard_mode() -> anyhow::Result<preexecution_policy::DriverProtectionMode> {
    if let Some(mode) = guard_mode_from_env()? {
        return Ok(mode);
    }
    read_guard_mode_config()
}

fn guard_mode_from_env() -> anyhow::Result<Option<preexecution_policy::DriverProtectionMode>> {
    for name in [
        "AVORAX_GUARD_MODE",
        "AVORAX_PROTECTION_MODE",
        "ZENTOR_GUARD_MODE",
    ] {
        match std::env::var(name) {
            Ok(value) => {
                let mode = parse_guard_mode(&value).ok_or_else(|| {
                    anyhow::anyhow!("unsupported guard mode in environment {name}: {value}")
                })?;
                return Ok(Some(mode));
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(error) => {
                anyhow::bail!("invalid guard mode environment {name}: {error}");
            }
        }
    }
    Ok(None)
}

fn read_guard_mode_config() -> anyhow::Result<preexecution_policy::DriverProtectionMode> {
    let path = guard_mode_config_path()?;
    if !guard_config_file_present(&path, "guard mode config")? {
        return Ok(preexecution_policy::DriverProtectionMode::default());
    }
    let text = read_bounded_guard_text(&path, MAX_GUARD_MODE_CONFIG_BYTES, "guard mode config")?;
    if text.trim_start().starts_with('{') {
        let config: GuardModeConfigFile = serde_json::from_str(&text)
            .with_context(|| format!("unable to parse guard mode config {}", path.display()))?;
        return guard_mode_from_config_file(config);
    }
    parse_guard_mode(&text).ok_or_else(|| anyhow::anyhow!("unsupported guard mode in config"))
}

fn guard_mode_from_config_file(
    config: GuardModeConfigFile,
) -> anyhow::Result<preexecution_policy::DriverProtectionMode> {
    let GuardModeConfigFile {
        mode,
        updated_at: _updated_at,
        source,
    } = config;
    validate_guard_mode_config_text(&mode, "guard mode config mode")?;
    if let Some(source) = &source {
        validate_guard_mode_config_text(source, "guard mode config source")?;
        if source.trim().is_empty() {
            anyhow::bail!("guard mode config source is empty");
        }
    }
    parse_guard_mode(&mode)
        .ok_or_else(|| anyhow::anyhow!("unsupported guard mode in config: {mode}"))
}

fn validate_guard_mode_config_text(value: &str, label: &str) -> anyhow::Result<()> {
    if value.contains('\0') {
        anyhow::bail!("{label} contains NUL");
    }
    if value.chars().count() > MAX_GUARD_IPC_TEXT_CHARS {
        anyhow::bail!("{label} exceeds maximum length of {MAX_GUARD_IPC_TEXT_CHARS} characters");
    }
    Ok(())
}

fn read_bounded_guard_text(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<String> {
    let metadata = ensure_regular_guard_config_file(path, label)?;
    read_bounded_guard_utf8_file(path, max_bytes, label, &metadata)
}

fn read_bounded_guard_utf8_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
    metadata: &fs::Metadata,
) -> anyhow::Result<String> {
    if metadata.len() > max_bytes {
        anyhow::bail!(
            "{label} {} exceeds maximum size of {max_bytes} bytes",
            path.display()
        );
    }
    let mut file = fs::File::open(path)
        .with_context(|| format!("unable to read {label} {}", path.display()))?;
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    let mut bytes = Vec::new();
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("unable to read {label} {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("guard text read size overflow"))?;
        if total > max_bytes {
            anyhow::bail!(
                "{label} {} exceeds maximum size of {max_bytes} bytes",
                path.display()
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("{label} {} is not valid UTF-8", path.display()))
        .with_context(|| format!("unable to read {label} {}", path.display()))
}

fn guard_config_file_present(path: &Path, label: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_guard_config_metadata(path, label, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_regular_guard_config_file(path: &Path, label: &str) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    ensure_regular_guard_config_metadata(path, label, &metadata)?;
    Ok(metadata)
}

fn ensure_regular_guard_config_metadata(
    path: &Path,
    label: &str,
    metadata: &fs::Metadata,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to read symbolic link {label} {}", path.display());
    }
    if guard_config_metadata_is_windows_reparse_point(metadata) {
        anyhow::bail!("refusing to read reparse point {label} {}", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn guard_config_metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn guard_config_metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn guard_mode_config_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_guard_env_path("AVORAX_GUARD_MODE_CONFIG")? {
        return Ok(path);
    }
    if let Some(path) = absolute_guard_env_path("ZENTOR_GUARD_MODE_CONFIG")? {
        return Ok(path);
    }
    Ok(guard_config_base()?.join("guard_mode.json"))
}

fn guard_config_base() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_guard_env_path("AVORAX_CONFIG_DIR")? {
        return Ok(path);
    }
    if let Some(path) = absolute_guard_env_path("AVORAX_DATA_DIR")? {
        return Ok(path.join("config"));
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = absolute_guard_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax").join("Config"));
        }
        if let Some(program_data) = absolute_guard_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax").join("Config"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = absolute_guard_env_path("HOME")? {
            return Ok(home
                .join("Library")
                .join("Application Support")
                .join("Avorax")
                .join("Config"));
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = absolute_guard_env_path("HOME")? {
            return Ok(home.join(".local/share/avorax/config"));
        }
    }
    anyhow::bail!("no absolute guard config directory is configured")
}

fn absolute_guard_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => {
            anyhow::bail!("invalid guard config path environment {name}: {error}");
        }
    };
    if value.trim().is_empty() {
        anyhow::bail!("guard config path environment {name} is empty");
    }
    if value.contains('\0') {
        anyhow::bail!("guard config path environment {name} contains NUL");
    }
    if guard_env_path_has_parent_traversal(&value) {
        anyhow::bail!("guard config path environment {name} must not contain parent traversal");
    }
    let path = PathBuf::from(&value);
    if !path.is_absolute() {
        anyhow::bail!("guard config path environment {name} must be absolute: {value}");
    }
    Ok(Some(path))
}

fn guard_env_path_has_parent_traversal(value: &str) -> bool {
    value.replace('\\', "/").split('/').any(|part| part == "..")
}

fn parse_guard_mode(raw: &str) -> Option<preexecution_policy::DriverProtectionMode> {
    let normalized = raw.trim().replace(['-', '_', ' '], "").to_ascii_lowercase();
    match normalized.as_str() {
        "off" | "disabled" => Some(preexecution_policy::DriverProtectionMode::Disabled),
        "observeonly" | "monitoronly" => {
            Some(preexecution_policy::DriverProtectionMode::ObserveOnly)
        }
        "balanced" => Some(preexecution_policy::DriverProtectionMode::Balanced),
        "blockknownbad" => Some(preexecution_policy::DriverProtectionMode::BlockKnownBad),
        "blockconfirmedthreats" | "blockconfirmed" => {
            Some(preexecution_policy::DriverProtectionMode::BlockConfirmedThreats)
        }
        "lockdown" => Some(preexecution_policy::DriverProtectionMode::Lockdown),
        "developermode" | "developer" => {
            Some(preexecution_policy::DriverProtectionMode::DeveloperMode)
        }
        "aggressive" => Some(preexecution_policy::DriverProtectionMode::Aggressive),
        _ => None,
    }
}

fn write_guard_event(event: &GuardEvent) -> anyhow::Result<()> {
    let base = event_log_base()?;
    fs::create_dir_all(&base)?;
    let path = base.join("guard_events.jsonl");
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", serde_json::to_string(event)?)?;
    Ok(())
}

fn event_log_base() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_guard_event_env_path("AVORAX_EVENT_LOG_DIR")? {
        return Ok(path);
    }
    if let Some(path) = absolute_guard_event_env_path("ZENTOR_EVENT_LOG_DIR")? {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = absolute_guard_event_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax").join("Events"));
        }
        if let Some(program_data) = absolute_guard_event_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax").join("Events"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = absolute_guard_event_env_path("HOME")? {
            return Ok(home
                .join("Library")
                .join("Application Support")
                .join("Avorax")
                .join("Events"));
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = absolute_guard_event_env_path("HOME")? {
            return Ok(home.join(".local/share/avorax/events"));
        }
    }
    anyhow::bail!("no absolute guard event log directory is configured")
}

fn absolute_guard_event_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => {
            anyhow::bail!("invalid guard event log path environment {name}: {error}");
        }
    };
    if value.trim().is_empty() {
        anyhow::bail!("guard event log path environment {name} is empty");
    }
    if value.contains('\0') {
        anyhow::bail!("guard event log path environment {name} contains NUL");
    }
    if guard_env_path_has_parent_traversal(&value) {
        anyhow::bail!("guard event log path environment {name} must not contain parent traversal");
    }
    let path = PathBuf::from(&value);
    if !path.is_absolute() {
        anyhow::bail!("guard event log path environment {name} must be absolute: {value}");
    }
    Ok(Some(path))
}

#[derive(Debug)]
struct ObservedProcess {
    process_id: u32,
    path: PathBuf,
}

fn list_processes() -> anyhow::Result<Vec<ObservedProcess>> {
    #[cfg(windows)]
    {
        return list_processes_windows();
    }
    #[cfg(not(windows))]
    {
        return list_processes_procfs();
    }
}

#[cfg(windows)]
fn list_processes_windows() -> anyhow::Result<Vec<ObservedProcess>> {
    let script = "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | Select-Object ProcessId,ExecutablePath | ConvertTo-Json -Compress";
    let powershell = windows_system32_tool("powershell.exe")?;
    let encoded_script = powershell_encoded_command(script);
    let mut command = Command::new(&powershell);
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        &encoded_script,
    ]);
    let output = run_guard_process_command(
        &mut command,
        "Windows process query",
        MAX_WINDOWS_PROCESS_QUERY_BYTES,
        MAX_GUARD_COMMAND_OUTPUT_BYTES,
        GUARD_PROCESS_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Windows process query failed: {}",
            command_output_excerpt(&output.stderr)
        ));
    }
    let stdout = windows_process_query_text(&output.stdout)?;
    parse_windows_process_json(&stdout)
}

#[cfg(windows)]
fn windows_process_query_text(bytes: &[u8]) -> anyhow::Result<String> {
    if bytes.len() > MAX_WINDOWS_PROCESS_QUERY_BYTES {
        anyhow::bail!(
            "Windows process query JSON exceeded {} bytes",
            MAX_WINDOWS_PROCESS_QUERY_BYTES
        );
    }
    Ok(String::from_utf8_lossy(bytes).to_string())
}

#[cfg(windows)]
fn powershell_encoded_command(script: &str) -> String {
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.push((unit & 0xff) as u8);
        bytes.push((unit >> 8) as u8);
    }
    base64_encode(&bytes)
}

#[cfg(windows)]
fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(((bytes.len() + 2) / 3) * 4);
    let mut offset = 0;
    while offset < bytes.len() {
        let first = bytes[offset];
        let second = if offset + 1 < bytes.len() {
            bytes[offset + 1]
        } else {
            0
        };
        let third = if offset + 2 < bytes.len() {
            bytes[offset + 2]
        } else {
            0
        };
        let triple = ((first as u32) << 16) | ((second as u32) << 8) | third as u32;
        encoded.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        encoded.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if offset + 1 < bytes.len() {
            encoded.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
        if offset + 2 < bytes.len() {
            encoded.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
        offset += 3;
    }
    encoded
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum WindowsProcessJson {
    One(WindowsProcessRow),
    Many(Vec<WindowsProcessRow>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsProcessRow {
    process_id: u32,
    executable_path: String,
}

#[cfg(windows)]
fn parse_windows_process_json(json: &str) -> anyhow::Result<Vec<ObservedProcess>> {
    if json.len() > MAX_WINDOWS_PROCESS_QUERY_BYTES {
        anyhow::bail!(
            "Windows process query JSON exceeded {} bytes",
            MAX_WINDOWS_PROCESS_QUERY_BYTES
        );
    }
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: WindowsProcessJson = serde_json::from_str(trimmed)?;
    let rows = match parsed {
        WindowsProcessJson::One(row) => vec![row],
        WindowsProcessJson::Many(rows) => rows,
    };
    let mut processes = Vec::new();
    for row in rows {
        let process = ObservedProcess {
            process_id: row.process_id,
            path: PathBuf::from(row.executable_path),
        };
        if guard_process_path_is_regular_file(&process.path)? {
            processes.push(process);
        }
    }
    Ok(processes)
}

#[cfg(not(windows))]
fn list_processes_procfs() -> anyhow::Result<Vec<ObservedProcess>> {
    let mut processes = Vec::new();
    let proc = Path::new("/proc");
    if !guard_process_directory_is_regular(proc)? {
        return Ok(processes);
    }
    for entry in fs::read_dir(proc)? {
        let Ok(entry) = entry else {
            continue;
        };
        let file_name = entry.file_name();
        let Some(pid) = procfs_pid_from_file_name(&file_name) else {
            continue;
        };
        let Ok(path) = fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        if guard_process_path_is_regular_file(&path)? {
            processes.push(ObservedProcess {
                process_id: pid,
                path,
            });
        }
    }
    Ok(processes)
}

#[cfg(not(windows))]
fn procfs_pid_from_file_name(file_name: &std::ffi::OsStr) -> Option<u32> {
    let raw = file_name.to_string_lossy();
    match raw.parse::<u32>() {
        Ok(pid) => Some(pid),
        Err(_) => None,
    }
}

fn guard_process_path_is_regular_file(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && !is_guard_process_reparse_point(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect guard process path {}", path.display())),
    }
}

#[allow(dead_code)]
fn guard_process_directory_is_regular(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && !is_guard_process_reparse_point(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect guard process directory {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn is_guard_process_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_guard_process_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn stop_process(process_id: u32) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let taskkill = windows_system32_tool("taskkill.exe")?;
        let label = format!("taskkill for process {process_id}");
        let mut command = Command::new(&taskkill);
        command.args(["/PID", &process_id.to_string(), "/F"]);
        let output = run_guard_process_command(
            &mut command,
            &label,
            MAX_GUARD_COMMAND_OUTPUT_BYTES,
            MAX_GUARD_COMMAND_OUTPUT_BYTES,
            GUARD_PROCESS_COMMAND_TIMEOUT,
        )?;
        if !output.status.success() {
            anyhow::bail!(
                "taskkill failed for process {process_id} with status {}; stderr: {}",
                output.status,
                command_output_excerpt(&output.stderr)
            );
        }
    }
    #[cfg(not(windows))]
    {
        let kill = non_windows_process_kill_tool()?;
        let label = format!("kill for process {process_id}");
        let mut command = Command::new(&kill);
        command.args(["-TERM", &process_id.to_string()]);
        let output = run_guard_process_command(
            &mut command,
            &label,
            MAX_GUARD_COMMAND_OUTPUT_BYTES,
            MAX_GUARD_COMMAND_OUTPUT_BYTES,
            GUARD_PROCESS_COMMAND_TIMEOUT,
        )?;
        if !output.status.success() {
            anyhow::bail!(
                "kill failed for process {process_id} with status {}; stderr: {}",
                output.status,
                command_output_excerpt(&output.stderr)
            );
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn non_windows_process_kill_tool() -> anyhow::Result<PathBuf> {
    let mut rejected = Vec::new();
    for candidate in [PathBuf::from("/bin/kill"), PathBuf::from("/usr/bin/kill")] {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    rejected.push(format!("{} is a symbolic link", candidate.display()));
                    continue;
                }
                if metadata.file_type().is_file() {
                    return Ok(candidate);
                }
                rejected.push(format!("{} is not a regular file", candidate.display()));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => rejected.push(format!(
                "unable to inspect {}: {error}",
                candidate.display()
            )),
        }
    }
    if rejected.is_empty() {
        anyhow::bail!("unable to locate a checked process kill tool");
    }
    anyhow::bail!(
        "unable to locate a checked process kill tool: {}",
        rejected.join("; ")
    )
}

fn command_output_excerpt(bytes: &[u8]) -> String {
    let limit = bytes.len().min(MAX_GUARD_COMMAND_OUTPUT_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[..limit]).to_string();
    if bytes.len() > MAX_GUARD_COMMAND_OUTPUT_BYTES {
        text.push_str("...[truncated]");
    }
    text
}

struct GuardProcessCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_guard_process_command(
    command: &mut Command,
    label: &str,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> anyhow::Result<GuardProcessCommandOutput> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to launch {label}"))?;
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("failed to capture {label} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("failed to capture {label} stderr"))?;
    let stdout_reader =
        thread::spawn(move || read_bounded_guard_command_output(stdout, stdout_limit));
    let stderr_reader =
        thread::spawn(move || read_bounded_guard_command_output(stderr, stderr_limit));
    let status = match wait_for_guard_process_child(&mut child, timeout)
        .with_context(|| format!("failed to wait for {label}"))?
    {
        Some(status) => status,
        None => {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let stdout = join_guard_command_output_reader(stdout_reader, label, "stdout")?;
            let stderr = join_guard_command_output_reader(stderr_reader, label, "stderr")?;
            let mut detail = format!("{label} exceeded {} seconds", timeout.as_secs());
            if let Some(error) = kill_error {
                detail.push_str(&format!(
                    "; failed to kill timed-out guard process command: {error}"
                ));
            }
            if let Some(error) = wait_error {
                detail.push_str(&format!(
                    "; failed to reap timed-out guard process command: {error}"
                ));
            }
            let stderr_excerpt = command_output_excerpt(&stderr);
            let stdout_excerpt = command_output_excerpt(&stdout);
            if !stderr_excerpt.is_empty() {
                detail.push_str(&format!("; stderr: {stderr_excerpt}"));
            } else if !stdout_excerpt.is_empty() {
                detail.push_str(&format!("; stdout: {stdout_excerpt}"));
            }
            anyhow::bail!(detail);
        }
    };
    let stdout = join_guard_command_output_reader(stdout_reader, label, "stdout")?;
    let stderr = join_guard_command_output_reader(stderr_reader, label, "stderr")?;
    Ok(GuardProcessCommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_guard_process_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> io::Result<Option<std::process::ExitStatus>> {
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn join_guard_command_output_reader(
    reader: thread::JoinHandle<anyhow::Result<Vec<u8>>>,
    label: &str,
    stream_name: &str,
) -> anyhow::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} {stream_name} reader panicked"))?
}

#[cfg(windows)]
struct BoundedGuardCommandOutput {
    status: ExitStatus,
    stderr: Vec<u8>,
}

#[cfg(windows)]
fn run_guard_acl_command(command: &mut Command) -> anyhow::Result<BoundedGuardCommandOutput> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("failed to launch guard quarantine ACL command")?;
    let stderr = child
        .stderr
        .take()
        .context("failed to capture guard quarantine ACL command stderr")?;
    let stderr_reader = thread::spawn(move || {
        read_bounded_guard_command_output(stderr, MAX_GUARD_COMMAND_OUTPUT_BYTES)
    });
    let status = match wait_for_guard_acl_child(&mut child)? {
        Some(status) => status,
        None => {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let stderr = stderr_reader
                .join()
                .map_err(|_| anyhow::anyhow!("guard quarantine ACL stderr reader panicked"))??;
            let mut detail = format!(
                "guard quarantine ACL command timed out after {} seconds",
                GUARD_ACL_COMMAND_TIMEOUT.as_secs()
            );
            if let Some(error) = kill_error {
                detail.push_str(&format!(
                    "; failed to kill timed-out guard quarantine ACL command: {error}"
                ));
            }
            if let Some(error) = wait_error {
                detail.push_str(&format!(
                    "; failed to reap timed-out guard quarantine ACL command: {error}"
                ));
            }
            let stderr_excerpt = command_output_excerpt(&stderr);
            if !stderr_excerpt.is_empty() {
                detail.push_str(&format!("; stderr: {stderr_excerpt}"));
            }
            anyhow::bail!(detail);
        }
    };
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("guard quarantine ACL stderr reader panicked"))??;
    Ok(BoundedGuardCommandOutput { status, stderr })
}

#[cfg(windows)]
fn wait_for_guard_acl_child(child: &mut std::process::Child) -> anyhow::Result<Option<ExitStatus>> {
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to poll guard quarantine ACL command")?
        {
            return Ok(Some(status));
        }
        if started.elapsed() >= GUARD_ACL_COMMAND_TIMEOUT {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_bounded_guard_command_output<R: Read>(
    reader: R,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    let retain_limit = max_bytes.saturating_add(1);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("failed to read bounded guard command output")?;
        if read == 0 {
            break;
        }
        let remaining = retain_limit.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = read.min(remaining);
            bytes.extend_from_slice(&buffer[..keep]);
        }
    }
    Ok(bytes)
}

fn quarantine_file(
    path: &Path,
    sha256: &str,
    process_id: Option<u32>,
    threat_match: &LocalThreatMatch,
) -> anyhow::Result<GuardQuarantineRecord> {
    let detection_name = guard_quarantine_metadata_label(
        "detection name",
        &threat_match.reason,
        DEFAULT_GUARD_QUARANTINE_DETECTION_NAME,
    );
    let engine = guard_quarantine_metadata_label(
        "engine",
        &threat_match.engine,
        DEFAULT_GUARD_QUARANTINE_ENGINE,
    );
    let expected_sha256 = normalize_sha256(sha256)
        .ok_or_else(|| anyhow::anyhow!("invalid guard quarantine expected sha256"))?;
    let base = quarantine_base()?;
    let original_path = path.display().to_string();
    validate_guard_quarantine_record_path_text("original path", &original_path, false)?;
    let id = Uuid::new_v4().to_string();
    let destination = base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
    let quarantine_path = destination.display().to_string();
    validate_guard_quarantine_record_path_text("payload path", &quarantine_path, true)?;
    ensure_quarantine_base_directory_path(&base)?;
    let metadata = regular_guard_file_metadata(path, "quarantine source")?;
    let source_sha256 = sha256_file(path)?;
    let source_sha256_body = normalize_sha256(&source_sha256).ok_or_else(|| {
        anyhow::anyhow!("guard quarantine source hash helper returned invalid SHA-256")
    })?;
    if source_sha256_body != expected_sha256 {
        anyhow::bail!("quarantine source hash changed before move");
    }
    let file_size = metadata.len();
    let mut last_error: Option<anyhow::Error> = None;
    ensure_quarantine_payload_destination_absent(&destination)?;
    for _ in 0..10 {
        if let Err(error) = regular_guard_file_metadata(path, "quarantine source") {
            last_error = Some(error);
            thread::sleep(Duration::from_millis(150));
            continue;
        }
        ensure_quarantine_payload_destination_absent(&destination)?;
        match fs::rename(path, &destination)
            .or_else(|_| copy_then_remove_verified(path, &destination, &source_sha256))
        {
            Ok(()) => {
                let finalize_result = (|| -> anyhow::Result<GuardQuarantineRecord> {
                    regular_guard_file_metadata(&destination, "guard quarantine destination")?;
                    remove_executable_permissions(&destination)?;
                    let quarantined_sha256 = sha256_file(&destination)?;
                    let quarantined_sha256_body = normalize_sha256(&quarantined_sha256)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "guard quarantine destination hash helper returned invalid SHA-256"
                            )
                        })?;
                    if quarantined_sha256_body != source_sha256_body {
                        return Err(anyhow::anyhow!(
                            "guard quarantine payload hash changed during move"
                        ));
                    }
                    let record = GuardQuarantineRecord {
                        quarantine_id: id.clone(),
                        original_path: original_path.clone(),
                        quarantine_path: quarantine_path.clone(),
                        sha256: quarantined_sha256,
                        file_size,
                        detection_name: detection_name.clone(),
                        engine: engine.clone(),
                        action_taken: if process_id.is_some() {
                            "process_stop_requested_and_file_quarantined"
                        } else {
                            "file_quarantined_without_process_stop"
                        }
                        .to_string(),
                        quarantined_at: Utc::now(),
                        status: QuarantineStatus::Quarantined,
                        user_note: None,
                        source: "guard_service".to_string(),
                        blocked_before_execution: false,
                        process_started: process_id.is_some(),
                        process_id,
                    };
                    write_quarantine_record(&record)?;
                    Ok(record)
                })();
                match finalize_result {
                    Ok(record) => return Ok(record),
                    Err(error) => {
                        cleanup_untracked_guard_quarantine_artifacts(&id, &destination)
                            .with_context(|| {
                                format!(
                                    "failed to clean up untracked guard quarantine artifacts after quarantine finalization failure: {error:#}"
                                )
                            })?;
                        return Err(error);
                    }
                }
            }
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(150));
            }
        }
    }
    match last_error {
        Some(error) => Err(error),
        None => Err(anyhow::anyhow!(
            "guard quarantine failed after retry loop without a recorded cause"
        )),
    }
}

#[allow(dead_code)]
fn reject_symlink_source(path: &Path) -> anyhow::Result<()> {
    reject_link_path(path, "quarantine source")
}

fn regular_guard_file_metadata(path: &Path, label: &str) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label}");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("refusing to use reparse point {label}");
        }
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    Ok(metadata)
}

fn reject_link_path(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label}");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("refusing to use reparse point {label}");
        }
    }
    Ok(())
}

fn copy_then_remove_verified(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> anyhow::Result<()> {
    let expected_sha256 = normalize_sha256(expected_sha256)
        .ok_or_else(|| anyhow::anyhow!("invalid guard quarantine copy expected sha256"))?;
    regular_guard_file_metadata(source, "quarantine source")?;
    ensure_quarantine_payload_destination_absent(destination)?;
    copy_file_exclusive(source, destination)?;
    let destination_hash = match (|| -> anyhow::Result<String> {
        regular_guard_file_metadata(destination, "guard quarantine destination")?;
        let destination_hash = sha256_file(destination)?;
        normalize_sha256(&destination_hash).ok_or_else(|| {
            anyhow::anyhow!("guard quarantine destination hash helper returned invalid SHA-256")
        })
    })() {
        Ok(hash) => hash,
        Err(error) => {
            cleanup_guard_quarantine_partial_file(
                destination,
                "invalid copied guard quarantine destination",
            )
            .with_context(|| {
                format!(
                    "failed to clean up invalid copied guard quarantine destination {} after verification failure: {error:#}",
                    destination.display()
                )
            })?;
            return Err(error).with_context(|| {
                format!(
                    "failed to verify copied guard quarantine destination {}",
                    destination.display()
                )
            });
        }
    };
    if destination_hash != expected_sha256 {
        if let Err(cleanup_error) = fs::remove_file(destination) {
            anyhow::bail!(
                "hash verification failed before deleting original quarantine source; failed to remove invalid guard quarantine destination {}: {cleanup_error}",
                destination.display()
            );
        }
        anyhow::bail!("hash verification failed before deleting original quarantine source");
    }
    if let Err(error) = fs::remove_file(source) {
        cleanup_guard_quarantine_partial_file(destination, "copied guard quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up copied guard quarantine destination {} after source deletion failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to delete original guard quarantine source {}",
                source.display()
            )
        });
    }
    Ok(())
}

fn ensure_quarantine_payload_destination_absent(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing to use symbolic link guard quarantine payload destination");
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    anyhow::bail!(
                        "refusing to use reparse point guard quarantine payload destination"
                    );
                }
            }
            anyhow::bail!(
                "guard quarantine payload destination {} already exists",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect guard quarantine payload destination {}",
                path.display()
            )
        }),
    }
}

fn cleanup_guard_quarantine_partial_file(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {label} {}", path.display()))
        }
    }
}

fn cleanup_untracked_guard_quarantine_artifacts(
    id: &str,
    payload_path: &Path,
) -> anyhow::Result<()> {
    let mut targets = vec![(
        payload_path.to_path_buf(),
        "untracked guard quarantine payload",
    )];
    match checked_quarantine_record_path(id) {
        Ok(metadata_path) => {
            targets.push((
                metadata_path.clone(),
                "untracked guard quarantine metadata record",
            ));
            targets.push((
                metadata_path.with_extension("json.tmp"),
                "untracked guard quarantine metadata temp record",
            ));
            let auth_path = metadata_path.with_extension("json.auth");
            targets.push((
                auth_path.clone(),
                "untracked guard quarantine metadata auth sidecar",
            ));
            targets.push((
                auth_path.with_extension("auth.tmp"),
                "untracked guard quarantine metadata auth temp sidecar",
            ));
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to derive guard quarantine cleanup metadata paths for {id}")
            });
        }
    }
    let mut failures = Vec::new();
    for (path, label) in targets {
        if let Err(error) = cleanup_guard_quarantine_partial_file(&path, label) {
            failures.push(format!("{label} {}: {error:#}", path.display()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "failed to clean up one or more untracked guard quarantine artifacts: {}",
            failures.join("; ")
        ))
    }
}

fn copy_file_exclusive(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let mut input = fs::File::open(source)
        .with_context(|| format!("failed to open quarantine source {}", source.display()))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| {
            format!(
                "failed to create quarantine destination {}",
                destination.display()
            )
        })?;
    if let Err(error) = copy_guard_quarantine_payload_limited(
        &mut input,
        &mut output,
        MAX_GUARD_QUARANTINE_COPY_BYTES,
        source,
    ) {
        drop(output);
        cleanup_guard_quarantine_partial_file(destination, "partial guard quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial guard quarantine destination {} after copy failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to copy quarantine payload {} to {}",
                source.display(),
                destination.display()
            )
        });
    }
    if let Err(error) = output.sync_all() {
        drop(output);
        cleanup_guard_quarantine_partial_file(destination, "partial guard quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial guard quarantine destination {} after sync failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to sync quarantine destination {}",
                destination.display()
            )
        });
    }
    Ok(())
}

fn copy_guard_quarantine_payload_limited<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    limit: u64,
    source: &Path,
) -> anyhow::Result<()> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("guard quarantine payload copy size overflow"))?;
        if total > limit {
            anyhow::bail!(
                "guard quarantine payload {} exceeds the copy size limit",
                source.display()
            );
        }
        output.write_all(&buffer[..read])?;
    }
}

fn write_quarantine_record(record: &GuardQuarantineRecord) -> anyhow::Result<()> {
    validate_guard_quarantine_record(record)?;
    let path = checked_quarantine_record_path(&record.quarantine_id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(record)?;
    write_staged_quarantine_file(&path, raw.as_bytes(), "guard quarantine metadata record")?;
    write_quarantine_record_auth(record, &raw)?;
    ensure_quarantine_record_auth_valid(&path, &raw)?;
    Ok(())
}

fn guard_quarantine_metadata_label(label: &str, value: &str, fallback: &str) -> String {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_GUARD_QUARANTINE_METADATA_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_string();
    if normalized.is_empty()
        || validate_guard_quarantine_metadata_text(
            label,
            &normalized,
            MAX_GUARD_QUARANTINE_METADATA_LABEL_CHARS,
            true,
        )
        .is_err()
    {
        fallback.to_string()
    } else {
        normalized
    }
}

fn validate_guard_quarantine_record(record: &GuardQuarantineRecord) -> anyhow::Result<()> {
    validate_guard_quarantine_id(&record.quarantine_id)?;
    validate_guard_quarantine_record_path_text("original path", &record.original_path, false)
        .with_context(|| "invalid guard quarantine original path")?;
    validate_guard_quarantine_record_path_text("payload path", &record.quarantine_path, true)
        .with_context(|| "invalid guard quarantine payload path")?;
    if normalize_sha256(&record.sha256).is_none() {
        anyhow::bail!("invalid guard quarantine metadata sha256");
    }
    validate_guard_quarantine_metadata_text(
        "detection name",
        &record.detection_name,
        MAX_GUARD_QUARANTINE_METADATA_LABEL_CHARS,
        true,
    )?;
    validate_guard_quarantine_metadata_text(
        "engine",
        &record.engine,
        MAX_GUARD_QUARANTINE_METADATA_LABEL_CHARS,
        true,
    )?;
    validate_guard_quarantine_metadata_text(
        "action taken",
        &record.action_taken,
        MAX_GUARD_QUARANTINE_METADATA_STATE_CHARS,
        true,
    )?;
    validate_guard_quarantine_metadata_text(
        "source",
        &record.source,
        MAX_GUARD_QUARANTINE_METADATA_STATE_CHARS,
        true,
    )?;
    if let Some(note) = &record.user_note {
        validate_guard_quarantine_metadata_text(
            "user note",
            note,
            MAX_GUARD_QUARANTINE_USER_NOTE_CHARS,
            false,
        )?;
    }
    Ok(())
}

fn validate_guard_quarantine_record_path_text(
    label: &str,
    text: &str,
    require_payload_extension: bool,
) -> anyhow::Result<()> {
    if text.trim().is_empty() {
        anyhow::bail!("guard quarantine {label} is empty");
    }
    if text.contains('\0') {
        anyhow::bail!("guard quarantine {label} contains NUL");
    }
    if text.chars().count() > MAX_GUARD_QUARANTINE_RECORD_PATH_CHARS {
        anyhow::bail!(
            "guard quarantine {label} exceeds maximum length of {} characters",
            MAX_GUARD_QUARANTINE_RECORD_PATH_CHARS
        );
    }
    if text.chars().any(|ch| ch.is_control()) {
        anyhow::bail!("guard quarantine {label} contains control characters");
    }
    if guard_quarantine_record_path_has_unsafe_segment(text) {
        anyhow::bail!("unsafe guard quarantine {label}");
    }
    let path = PathBuf::from(text);
    if !path.is_absolute() || path.file_name().is_none() {
        anyhow::bail!("unsafe guard quarantine {label}");
    }
    if require_payload_extension
        && path.extension().and_then(|value| value.to_str()) != Some(QUARANTINE_EXTENSION)
    {
        anyhow::bail!("guard quarantine {label} has unsafe extension");
    }
    Ok(())
}

fn guard_quarantine_record_path_has_unsafe_segment(text: &str) -> bool {
    text.replace('\\', "/")
        .split('/')
        .any(|part| part == "." || part == "..")
}

fn validate_guard_quarantine_metadata_text(
    label: &str,
    value: &str,
    max_chars: usize,
    required: bool,
) -> anyhow::Result<()> {
    if required && value.trim().is_empty() {
        anyhow::bail!("guard quarantine metadata {label} is required");
    }
    if required && value.trim() != value {
        anyhow::bail!("guard quarantine metadata {label} contains leading or trailing whitespace");
    }
    if value.contains('\0') {
        anyhow::bail!("guard quarantine metadata {label} contains NUL");
    }
    if value.chars().count() > max_chars {
        anyhow::bail!(
            "guard quarantine metadata {label} exceeds maximum length of {max_chars} characters"
        );
    }
    if value.chars().any(|ch| ch.is_control()) {
        anyhow::bail!("guard quarantine metadata {label} contains control characters");
    }
    Ok(())
}

fn write_quarantine_record_auth(record: &GuardQuarantineRecord, raw: &str) -> anyhow::Result<()> {
    let path = checked_quarantine_record_path(&record.quarantine_id)?.with_extension("json.auth");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let Some(tag) = quarantine_record_auth_tag(raw, true)? else {
        anyhow::bail!("guard quarantine metadata authentication key unavailable");
    };
    write_staged_quarantine_file(
        &path,
        format!("{tag}\n").as_bytes(),
        "guard quarantine metadata auth sidecar",
    )?;
    Ok(())
}

fn quarantine_record_auth_valid(path: &Path, raw: &str) -> anyhow::Result<bool> {
    let auth_path = path.with_extension("json.auth");
    if !guard_quarantine_metadata_file_present(
        &auth_path,
        "guard quarantine metadata auth sidecar",
    )? {
        return Ok(true);
    }
    let Some(expected) = quarantine_record_auth_tag(raw, false)? else {
        anyhow::bail!(
            "guard quarantine metadata authentication key unavailable for authenticated record {}",
            path.display()
        );
    };
    let actual = read_bounded_guard_quarantine_text(
        &auth_path,
        MAX_GUARD_QUARANTINE_METADATA_AUTH_BYTES,
        "guard quarantine metadata auth sidecar",
    )?
    .trim()
    .to_string();
    Ok(constant_time_eq(expected.as_bytes(), actual.as_bytes()))
}

fn ensure_quarantine_record_auth_valid(path: &Path, raw: &str) -> anyhow::Result<()> {
    if quarantine_record_auth_valid(path, raw)? {
        return Ok(());
    }
    anyhow::bail!(
        "guard quarantine metadata authentication failed for record {}",
        path.display()
    );
}

fn quarantine_record_auth_tag(raw: &str, create_key: bool) -> anyhow::Result<Option<String>> {
    let Some(key) = quarantine_metadata_auth_key(create_key)? else {
        return Ok(None);
    };
    let mut hasher = Sha256::new();
    hasher.update(b"avorax-guard-quarantine-record-v1\0");
    hasher.update(key.as_bytes());
    hasher.update(b"\0");
    hasher.update(raw.as_bytes());
    Ok(Some(format!("sha256:{:x}", hasher.finalize())))
}

fn quarantine_metadata_auth_key(create: bool) -> anyhow::Result<Option<String>> {
    let base = quarantine_base()?;
    let path = base.join(".metadata_auth_key");
    if guard_quarantine_metadata_file_present(
        &path,
        "guard quarantine metadata authentication key",
    )? {
        let raw_key = read_bounded_guard_quarantine_text(
            &path,
            MAX_GUARD_QUARANTINE_METADATA_AUTH_BYTES,
            "guard quarantine metadata authentication key",
        )?;
        let key = decode_metadata_auth_key(&raw_key)?;
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }
    if !create {
        return Ok(None);
    }
    ensure_quarantine_base_directory()?;
    let key = Uuid::new_v4().to_string();
    write_staged_quarantine_file(
        &path,
        encode_metadata_auth_key(&key)?.as_bytes(),
        "guard quarantine metadata authentication key",
    )?;
    Ok(Some(key))
}

fn read_bounded_guard_quarantine_text(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<String> {
    let metadata = ensure_regular_guard_quarantine_metadata_file(path, label)?;
    read_bounded_guard_utf8_file(path, max_bytes, label, &metadata)
}

fn guard_quarantine_metadata_file_present(path: &Path, label: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_guard_quarantine_metadata(&metadata, path, label)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_regular_guard_quarantine_metadata_file(
    path: &Path,
    label: &str,
) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    ensure_regular_guard_quarantine_metadata(&metadata, path, label)?;
    Ok(metadata)
}

fn ensure_regular_guard_quarantine_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    label: &str,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label}");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("refusing to use reparse point {label}");
        }
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    Ok(())
}

fn write_staged_quarantine_file(path: &Path, bytes: &[u8], label: &str) -> anyhow::Result<()> {
    ensure_quarantine_file_parent_directory(path, label)?;
    let temp_path = guard_quarantine_staged_temp_path(path, label)?;
    if let Err(error) = write_file_exclusive(&temp_path, bytes, label) {
        return Err(error);
    }
    if let Err(error) = reject_link_path(&temp_path, label) {
        cleanup_guard_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after temp validation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = ensure_quarantine_file_parent_directory(path, label) {
        cleanup_guard_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after parent preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = ensure_quarantine_file_destination_absent(path, label) {
        cleanup_guard_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after activation preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        cleanup_guard_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after activation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to activate {label} {}", path.display()));
    }
    Ok(())
}

fn guard_quarantine_staged_temp_path(path: &Path, label: &str) -> anyhow::Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no parent {}", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no file name {}", path.display()))?;
    let mut temp_name = file_name.to_os_string();
    temp_name.push(format!(".tmp-{}", Uuid::new_v4()));
    Ok(parent.join(temp_name))
}

fn cleanup_guard_quarantine_staged_file(path: &Path, label: &str) -> anyhow::Result<()> {
    let cleanup_label = format!("temporary {label}");
    cleanup_guard_quarantine_partial_file(path, &cleanup_label)
}

fn ensure_quarantine_file_parent_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no parent {}", path.display()))?;
    let metadata = fs::symlink_metadata(parent).with_context(|| {
        format!(
            "failed to inspect {label} parent directory {}",
            parent.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label} parent directory");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("refusing to use reparse point {label} parent directory");
        }
    }
    if !metadata.file_type().is_dir() {
        anyhow::bail!(
            "{label} parent directory {} is not a directory",
            parent.display()
        );
    }
    Ok(())
}

fn write_file_exclusive(path: &Path, bytes: &[u8], label: &str) -> anyhow::Result<()> {
    let mut output = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(output) => output,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create temporary {label} {}", path.display()));
        }
    };
    if let Err(error) = output.write_all(bytes) {
        drop(output);
        cleanup_guard_quarantine_staged_file(path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after write failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to write temporary {label} {}", path.display()));
    }
    if let Err(error) = output.sync_all() {
        drop(output);
        cleanup_guard_quarantine_staged_file(path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after sync failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to sync temporary {label} {}", path.display()));
    }
    Ok(())
}

#[allow(dead_code)]
fn remove_existing_quarantine_file(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing to replace symbolic link {label}");
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    anyhow::bail!("refusing to replace reparse point {label}");
                }
            }
            if !metadata.is_file() {
                anyhow::bail!("refusing to replace non-file {label}");
            }
            fs::remove_file(path)
                .with_context(|| format!("failed to remove existing {label} {}", path.display()))?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_quarantine_file_destination_absent(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing to replace symbolic link {label}");
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    anyhow::bail!("refusing to replace reparse point {label}");
                }
            }
            if !metadata.file_type().is_file() {
                anyhow::bail!("refusing to replace non-file {label}");
            }
            anyhow::bail!("{label} destination already exists {}", path.display())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn encode_metadata_auth_key(key: &str) -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        let protected = dpapi_protect(key.as_bytes())?;
        return Ok(format!("dpapi:{}\n", hex_encode(&protected)));
    }
    #[cfg(not(windows))]
    {
        Ok(format!("{key}\n"))
    }
}

fn decode_metadata_auth_key(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    #[cfg(windows)]
    {
        if let Some(hex) = trimmed.strip_prefix("dpapi:") {
            let protected = hex_decode(hex)?;
            let clear = dpapi_unprotect(&protected)?;
            return String::from_utf8(clear).map_err(|_| {
                anyhow::anyhow!("protected guard quarantine metadata key is not UTF-8")
            });
        }
    }
    Ok(trimmed.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> anyhow::Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        anyhow::bail!("protected guard quarantine metadata key has invalid hex length");
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    for pair in raw.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(value: u8) -> anyhow::Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => anyhow::bail!("protected guard quarantine metadata key has invalid hex"),
    }
}

#[cfg(windows)]
fn dpapi_protect(clear: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: clear.len() as u32,
        pbData: clear.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            null(),
            null(),
            null_mut(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        anyhow::bail!("CryptProtectData failed for guard quarantine metadata key");
    }
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(protected)
}

#[cfg(windows)]
fn dpapi_unprotect(protected: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null(),
            null_mut(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        anyhow::bail!("CryptUnprotectData failed for guard quarantine metadata key");
    }
    let clear =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(clear)
}

fn quarantine_record_path(id: &str) -> anyhow::Result<PathBuf> {
    Ok(quarantine_base()?.join(format!("{id}.json")))
}

fn checked_quarantine_record_path(id: &str) -> anyhow::Result<PathBuf> {
    validate_guard_quarantine_id(id)?;
    quarantine_record_path(id)
}

fn validate_guard_quarantine_id(id: &str) -> anyhow::Result<()> {
    if id.trim().is_empty() {
        anyhow::bail!("guard quarantine id is required");
    }
    if id.trim() != id {
        anyhow::bail!("guard quarantine id contains leading or trailing whitespace");
    }
    if id.chars().count() > MAX_GUARD_QUARANTINE_ID_CHARS {
        anyhow::bail!("guard quarantine id exceeds maximum length");
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        anyhow::bail!(
            "invalid guard quarantine id; only ASCII letters, digits, hyphen, and underscore are allowed"
        );
    }
    Ok(())
}

fn ensure_quarantine_base_directory() -> anyhow::Result<PathBuf> {
    let base = quarantine_base()?;
    ensure_quarantine_base_directory_path(&base)?;
    Ok(base)
}

fn ensure_quarantine_base_directory_path(base: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(base)?;
    reject_link_path(base, "quarantine base directory")?;
    harden_quarantine_base_acl(base)?;
    Ok(())
}

fn harden_quarantine_base_acl(_path: &Path) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let current_user = current_windows_account()?;
        let current_user_grant = format!("{current_user}:(OI)(CI)F");
        let icacls = windows_system32_tool("icacls.exe")?;
        let mut command = Command::new(&icacls);
        command.arg(_path).args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            &current_user_grant,
        ]);
        let output = run_guard_acl_command(&mut command)?;
        if !output.status.success() {
            anyhow::bail!(
                "failed to harden guard quarantine ACLs: {}",
                command_output_excerpt(&output.stderr)
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_system32_tool(name: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        matches!(name, "icacls.exe" | "powershell.exe" | "taskkill.exe"),
        "unsupported guard Windows System32 tool {name}"
    );
    let system_root = guard_windows_system_root()?;
    let candidate = if name == "powershell.exe" {
        system_root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join(name)
    } else {
        system_root.join("System32").join(name)
    };
    let metadata = fs::symlink_metadata(&candidate).with_context(|| {
        format!(
            "unable to inspect Windows System32 tool {}",
            candidate.display()
        )
    })?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to launch symbolic link Windows System32 tool {}",
        candidate.display()
    );
    anyhow::ensure!(
        !guard_metadata_is_reparse_point(&metadata),
        "refusing to launch reparse point Windows System32 tool {}",
        candidate.display()
    );
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "Windows System32 tool {} is not a regular file",
        candidate.display()
    );
    Ok(candidate)
}

#[cfg(windows)]
fn guard_windows_system_root() -> anyhow::Result<PathBuf> {
    let mut diagnostics = Vec::new();
    for key in ["SystemRoot", "WINDIR"] {
        match std::env::var_os(key) {
            Some(value) => {
                let text = value.to_string_lossy().trim().to_string();
                if text.is_empty() {
                    diagnostics.push(format!("{key} is empty"));
                    continue;
                }
                let normalized_root = match normalize_guard_windows_system_root_text(&text) {
                    Ok(text) => text,
                    Err(error) => {
                        diagnostics.push(format!("{key} is unsafe: {error}"));
                        continue;
                    }
                };
                let path = PathBuf::from(normalized_root);
                if !is_local_windows_drive_path(&path) {
                    diagnostics.push(format!(
                        "{key} must be a local Windows drive path: {}",
                        path.display()
                    ));
                    continue;
                }
                return Ok(path);
            }
            None => diagnostics.push(format!("{key} is not set")),
        }
    }
    anyhow::bail!(
        "Guard Windows System32 tool root is unavailable: {}",
        diagnostics.join("; ")
    );
}

#[cfg(windows)]
fn normalize_guard_windows_system_root_text(value: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !value.contains('\0'),
        "Guard Windows system root contains NUL"
    );
    let normalized = value.trim().replace('/', "\\");
    anyhow::ensure!(
        !normalized.split('\\').any(|part| part == ".."),
        "Guard Windows system root must not contain parent traversal"
    );
    Ok(collapse_guard_windows_system_root_segments(&normalized))
}

#[cfg(windows)]
fn collapse_guard_windows_system_root_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if trimmed.is_empty() {
        return String::new();
    }
    let (prefix, rest, absolute) = split_guard_windows_system_root_prefix(trimmed);
    let mut parts = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            _ => parts.push(part),
        }
    }
    let joined = parts.join("\\");
    match (prefix, absolute, joined.is_empty()) {
        (Some(prefix), true, true) => format!("{prefix}\\"),
        (Some(prefix), true, false) => format!("{prefix}\\{joined}"),
        (None, true, true) => "\\".to_string(),
        (None, true, false) => format!("\\{joined}"),
        (Some(prefix), false, true) => prefix.to_string(),
        (Some(prefix), false, false) => format!("{prefix}{joined}"),
        (None, false, _) => joined,
    }
}

#[cfg(windows)]
fn split_guard_windows_system_root_prefix(path: &str) -> (Option<&str>, &str, bool) {
    if path.len() >= 3 && path.as_bytes()[1] == b':' && path.as_bytes()[2] == b'\\' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with('\\') {
        return (None, path.trim_start_matches('\\'), true);
    }
    (None, path, false)
}

#[cfg(windows)]
fn is_local_windows_drive_path(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(windows)]
fn guard_metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn current_windows_account() -> anyhow::Result<String> {
    let user = std::env::var("USERNAME").map_err(|_| anyhow::anyhow!("USERNAME is not set"))?;
    if user.trim().is_empty() {
        anyhow::bail!("USERNAME is empty");
    }
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.trim().is_empty() => Ok(format!("{domain}\\{user}")),
        _ => Ok(user),
    }
}

fn remove_executable_permissions(_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = regular_guard_file_metadata(_path, "guard quarantine destination")?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() & !0o111);
        fs::set_permissions(_path, permissions)?;
    }
    Ok(())
}

fn quarantine_base() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_guard_quarantine_env_path("AVORAX_GUARD_QUARANTINE_DIR")? {
        return Ok(path);
    }
    if let Some(path) = absolute_guard_quarantine_env_path("AVORAX_QUARANTINE_DIR")? {
        return Ok(path);
    }
    if let Some(path) = absolute_guard_quarantine_env_path("ZENTOR_GUARD_QUARANTINE_DIR")? {
        return Ok(path);
    }
    if let Some(path) = absolute_guard_quarantine_env_path("ZENTOR_QUARANTINE_DIR")? {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = absolute_guard_quarantine_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax").join("Quarantine"));
        }
        if let Some(program_data) = absolute_guard_quarantine_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax").join("Quarantine"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = absolute_guard_quarantine_env_path("HOME")? {
            return Ok(home
                .join("Library")
                .join("Application Support")
                .join("Avorax")
                .join("Quarantine"));
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = absolute_guard_quarantine_env_path("HOME")? {
            return Ok(home.join(".local/share/avorax/quarantine"));
        }
    }
    anyhow::bail!("no absolute guard quarantine directory is configured")
}

fn absolute_guard_quarantine_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => {
            anyhow::bail!("invalid guard quarantine path environment {name}: {error}");
        }
    };
    if value.trim().is_empty() {
        anyhow::bail!("guard quarantine path environment {name} is empty");
    }
    if value.contains('\0') {
        anyhow::bail!("guard quarantine path environment {name} contains NUL");
    }
    if guard_env_path_has_parent_traversal(&value) {
        anyhow::bail!("guard quarantine path environment {name} must not contain parent traversal");
    }
    let path = PathBuf::from(&value);
    if !path.is_absolute() {
        anyhow::bail!("guard quarantine path environment {name} must be absolute: {value}");
    }
    Ok(Some(path))
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let metadata = regular_guard_file_metadata(path, "file to hash")?;
    if metadata.len() > MAX_GUARD_HASH_BYTES {
        anyhow::bail!(
            "file to hash {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_GUARD_HASH_BYTES
        );
    }
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("guard hash size overflow"))?;
        if total > MAX_GUARD_HASH_BYTES {
            anyhow::bail!(
                "file to hash {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_GUARD_HASH_BYTES
            );
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn normalize_sha256(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let raw = sha256_body(trimmed);
    if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(raw.to_lowercase())
    } else {
        None
    }
}

fn sha256_body(trimmed: &str) -> &str {
    match trimmed.strip_prefix("sha256:") {
        Some(raw) => raw,
        None => trimmed,
    }
}

fn native_threat_match(path: &Path) -> anyhow::Result<Option<LocalThreatMatch>> {
    let mut engine =
        ZentorNativeEngine::initialize(EngineConfig::from_repo_root(native_asset_root()?)?)?;
    let verdict = engine.scan_file(path.to_path_buf(), AneScanActionMode::DetectOnly)?;
    let confidence = match verdict.final_verdict.confidence {
        zentor_native_engine::Confidence::Confirmed => LocalThreatConfidence::Confirmed,
        zentor_native_engine::Confidence::High => LocalThreatConfidence::High,
        zentor_native_engine::Confidence::Medium => LocalThreatConfidence::Medium,
        zentor_native_engine::Confidence::Low => LocalThreatConfidence::Low,
    };
    if matches!(
        verdict.final_verdict.verdict,
        AneVerdict::TestThreat | AneVerdict::ConfirmedMalware
    ) && matches!(
        verdict.final_verdict.confidence,
        zentor_native_engine::Confidence::Confirmed
    ) {
        return Ok(Some(LocalThreatMatch {
            reason: verdict.final_verdict.user_visible_explanation,
            engine: "avorax-native-engine".to_string(),
            confidence,
        }));
    }
    Ok(None)
}

fn native_asset_root() -> anyhow::Result<PathBuf> {
    let roots = guard_asset_root_candidates("guard native asset root discovery")?;
    for candidate in &roots {
        if native_asset_marker_dir_is_regular(&candidate.join("assets").join("zentor_native"))? {
            return Ok(candidate.to_path_buf());
        }
    }
    let root = roots.first().ok_or_else(|| {
        anyhow::anyhow!("guard native asset root discovery found no controlled roots")
    })?;
    Ok(root.to_path_buf())
}

fn native_asset_marker_dir_is_regular(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && !is_guard_native_asset_reparse_point(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect guard native asset marker {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn is_guard_native_asset_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_guard_native_asset_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn guard_asset_root_candidates(context: &str) -> anyhow::Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    let exe = std::env::current_exe()
        .with_context(|| format!("{context} failed to resolve current executable"))?;
    let parent = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{context} found no parent for {}", exe.display()))?;
    push_guard_executable_asset_roots(&mut roots, parent)?;

    #[cfg(debug_assertions)]
    {
        let current_dir = std::env::current_dir()
            .with_context(|| format!("{context} failed to read current directory"))?;
        push_debug_guard_asset_roots(&mut roots, &current_dir)?;
    }

    Ok(roots)
}

fn push_guard_executable_asset_roots(
    roots: &mut Vec<PathBuf>,
    parent: &Path,
) -> anyhow::Result<()> {
    for candidate in [
        parent.to_path_buf(),
        parent.join(".."),
        parent.join("..").join(".."),
        parent.join("..").join("..").join(".."),
    ] {
        push_unique_guard_asset_root(roots, &candidate)?;
    }
    Ok(())
}

fn push_unique_guard_asset_root(roots: &mut Vec<PathBuf>, root: &Path) -> anyhow::Result<()> {
    if !guard_asset_root_is_allowed(root) {
        anyhow::bail!(
            "guard asset root {} must be an absolute local path",
            root.display()
        );
    }
    if !roots.iter().any(|existing| existing == root) {
        roots.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(windows)]
fn guard_asset_root_is_allowed(path: &Path) -> bool {
    is_local_windows_drive_path(path)
}

#[cfg(not(windows))]
fn guard_asset_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(debug_assertions)]
fn push_debug_guard_asset_roots(
    roots: &mut Vec<PathBuf>,
    current_dir: &Path,
) -> anyhow::Result<()> {
    for root in current_dir.ancestors() {
        if is_guard_development_root(root)? {
            push_unique_guard_asset_root(roots, root)?;
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn is_guard_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_guard_service")
        .join("Cargo.toml");
    guard_development_marker_file_present(&marker, "guard development marker")
}

#[cfg(debug_assertions)]
fn guard_development_marker_file_present(path: &Path, description: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("{description} {} is a symbolic link", path.display());
            }
            if is_guard_native_asset_reparse_point(&metadata) {
                anyhow::bail!("{description} {} is a reparse point", path.display());
            }
            if !metadata.file_type().is_file() {
                anyhow::bail!("{description} {} is not a regular file", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect {description} {}", path.display())),
    }
}

fn compat_threat_match(_path: &Path) -> anyhow::Result<Option<LocalThreatMatch>> {
    #[cfg(any(feature = "compat_yara", feature = "compat_clamav"))]
    {
        #[cfg(feature = "compat_yara")]
        if let Some(yara_match) = yara_rule_match(_path)? {
            if matches!(yara_match.confidence, LocalThreatConfidence::Confirmed) {
                return Ok(Some(yara_match));
            }
        }
        #[cfg(feature = "compat_clamav")]
        if let Some(signature) = clamav_signature_match(_path)? {
            return Ok(Some(LocalThreatMatch {
                reason: format!("ClamAV compatibility signature: {signature}"),
                engine: "compat-clamav".to_string(),
                confidence: LocalThreatConfidence::Confirmed,
            }));
        }
    }
    Ok(None)
}

#[cfg(feature = "compat_clamav")]
fn clamav_signature_match(path: &Path) -> anyhow::Result<Option<String>> {
    regular_guard_file_metadata(path, "guard ClamAV scan target")?;
    let Some(clamscan) = find_clamscan()? else {
        return Ok(None);
    };
    let mut process = Command::new(&clamscan);
    process.arg("--no-summary").arg(path);
    let BoundedGuardClamavCommandOutput {
        status,
        stdout,
        stderr,
    } = run_guard_clamav_command(&mut process)?;
    let combined = format!("{stdout}{stderr}");
    if status.success() {
        return Ok(None);
    }
    if status.code() != Some(1) {
        anyhow::bail!("guard ClamAV scanner failed with status {status}: {combined}");
    }
    let signature = combined
        .split(':')
        .nth(1)
        .map(|value| value.replace("FOUND", "").trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "ClamAV compatibility detection".to_string());
    Ok(Some(signature))
}

#[cfg(any(feature = "compat_clamav", test))]
#[allow(dead_code)]
fn run_guard_clamav_command(
    process: &mut Command,
) -> anyhow::Result<BoundedGuardClamavCommandOutput> {
    process
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = process
        .spawn()
        .context("failed to start guard ClamAV scanner")?;
    let stdout = child
        .stdout
        .take()
        .context("missing guard ClamAV stdout pipe")?;
    let stderr = child
        .stderr
        .take()
        .context("missing guard ClamAV stderr pipe")?;
    let stdout_reader = spawn_guard_clamav_output_reader(stdout, "stdout");
    let stderr_reader = spawn_guard_clamav_output_reader(stderr, "stderr");
    let status = match wait_for_guard_clamav_child(&mut child, GUARD_CLAMAV_SCAN_TIMEOUT)
        .context("failed to wait for guard ClamAV scanner")?
    {
        Some(status) => status,
        None => {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let stdout = join_guard_clamav_output_reader(stdout_reader, "stdout")?;
            let stderr = join_guard_clamav_output_reader(stderr_reader, "stderr")?;
            let detail = format!("{stdout}{stderr}");
            if let Some(error) = &kill_error {
                if let Some(wait_error) = &wait_error {
                    anyhow::bail!(
                        "guard ClamAV scanner exceeded {} seconds and failed to terminate: {error}; failed to reap timed-out guard ClamAV scanner: {wait_error}; output: {detail}",
                        GUARD_CLAMAV_SCAN_TIMEOUT.as_secs()
                    );
                }
                anyhow::bail!(
                    "guard ClamAV scanner exceeded {} seconds and failed to terminate: {error}; output: {detail}",
                    GUARD_CLAMAV_SCAN_TIMEOUT.as_secs()
                );
            }
            if let Some(error) = wait_error {
                anyhow::bail!(
                    "guard ClamAV scanner exceeded {} seconds and failed to reap timed-out guard ClamAV scanner: {error}; output: {detail}",
                    GUARD_CLAMAV_SCAN_TIMEOUT.as_secs()
                );
            }
            anyhow::bail!(
                "guard ClamAV scanner exceeded {} seconds; output: {detail}",
                GUARD_CLAMAV_SCAN_TIMEOUT.as_secs()
            );
        }
    };
    let stdout = join_guard_clamav_output_reader(stdout_reader, "stdout")?;
    let stderr = join_guard_clamav_output_reader(stderr_reader, "stderr")?;
    Ok(BoundedGuardClamavCommandOutput {
        status,
        stdout,
        stderr,
    })
}

#[cfg(any(feature = "compat_clamav", test))]
#[allow(dead_code)]
fn wait_for_guard_clamav_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> io::Result<Option<std::process::ExitStatus>> {
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(any(feature = "compat_clamav", test))]
#[allow(dead_code)]
fn spawn_guard_clamav_output_reader<R>(
    reader: R,
    label: &'static str,
) -> thread::JoinHandle<anyhow::Result<String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || read_bounded_guard_clamav_output(reader, label))
}

#[cfg(any(feature = "compat_clamav", test))]
fn join_guard_clamav_output_reader(
    handle: thread::JoinHandle<anyhow::Result<String>>,
    label: &str,
) -> anyhow::Result<String> {
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("guard ClamAV {label} reader panicked"))?
}

#[cfg(any(feature = "compat_clamav", test))]
fn read_bounded_guard_clamav_output<R: Read>(reader: R, label: &str) -> anyhow::Result<String> {
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    let retain_limit = MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES.saturating_add(1);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("failed to read guard ClamAV {label}"))?;
        if read == 0 {
            break;
        }
        let remaining = retain_limit.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = read.min(remaining);
            bytes.extend_from_slice(&buffer[..keep]);
        }
    }
    let truncated = bytes.len() > MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES;
    if truncated {
        bytes.truncate(MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES);
    }
    let mut text = String::from_utf8_lossy(&bytes).to_string();
    if truncated {
        text.push_str("...[truncated]");
    }
    Ok(text)
}

#[cfg(feature = "compat_yara")]
fn yara_rule_match(path: &Path) -> anyhow::Result<Option<LocalThreatMatch>> {
    regular_guard_file_metadata(path, "guard YARA scan target")?;
    let rules_path = default_yara_rules_path()?;
    if !guard_yara_rules_file_present(&rules_path)? {
        return Ok(None);
    }
    let rules = read_bounded_guard_yara_rules(&rules_path)?;
    let body = read_bounded_sample(path, GUARD_YARA_SAMPLE_LIMIT_BYTES)?;
    let body_text = String::from_utf8_lossy(&body).to_lowercase();
    let mut best: Option<LocalThreatMatch> = None;
    let mut current_rule = String::new();
    let mut confidence = LocalThreatConfidence::Low;
    let mut description = String::new();

    for line in rules.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            let Some(rule_name) = yara_rule_name(trimmed) else {
                anyhow::bail!("guard YARA rule header is malformed");
            };
            current_rule = rule_name;
            confidence = LocalThreatConfidence::Low;
            description.clear();
        } else if trimmed.starts_with("confidence") {
            if current_rule.is_empty() {
                continue;
            }
            let Some(value) = metadata_value(trimmed, "confidence") else {
                anyhow::bail!("guard YARA rule {current_rule} confidence metadata is malformed");
            };
            confidence = confidence_from_yara(&current_rule, &value)?;
        } else if let Some(value) = metadata_value(trimmed, "description") {
            description = value;
        } else if trimmed.starts_with('$') {
            if current_rule.is_empty() {
                continue;
            }
            let Some((_, value)) = trimmed.split_once('=') else {
                anyhow::bail!("guard YARA rule {current_rule} string declaration is malformed");
            };
            let Some(pattern) = quoted_value(value.trim()) else {
                anyhow::bail!("guard YARA rule {current_rule} string pattern is malformed");
            };
            if body_text.contains(&pattern.to_lowercase()) {
                let candidate = LocalThreatMatch {
                    reason: if description.is_empty() {
                        format!("YARA rule matched: {current_rule}")
                    } else {
                        description.clone()
                    },
                    engine: format!("zentor-yara/{current_rule}"),
                    confidence: confidence.clone(),
                };
                let should_replace_best = match best.as_ref() {
                    Some(existing) => {
                        confidence_rank(&candidate.confidence)
                            > confidence_rank(&existing.confidence)
                    }
                    None => true,
                };
                if should_replace_best {
                    best = Some(candidate);
                }
            }
        }
    }

    Ok(best)
}

#[cfg(feature = "compat_yara")]
fn yara_rule_name(line: &str) -> Option<String> {
    let name = line
        .strip_prefix("rule ")
        .and_then(|value| value.split_whitespace().next())?
        .trim_matches('{');
    if is_yara_rule_identifier(name) {
        Some(name.to_string())
    } else {
        None
    }
}

#[cfg(feature = "compat_yara")]
fn is_yara_rule_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(feature = "compat_yara")]
fn read_bounded_sample(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    regular_guard_file_metadata(path, "guard YARA scan target")?;
    let mut reader = fs::File::open(path)?;
    let mut body = Vec::new();
    let mut remaining = limit;
    let mut buffer = [0_u8; 8192];
    while remaining > 0 {
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
        remaining -= read as u64;
        body.extend_from_slice(&buffer[..read]);
    }
    Ok(body)
}

#[cfg(any(feature = "compat_yara", test))]
fn read_bounded_guard_yara_rules(path: &Path) -> anyhow::Result<String> {
    let metadata = ensure_regular_guard_yara_rules(path)?;
    if metadata.len() > GUARD_YARA_RULE_TEXT_LIMIT_BYTES {
        anyhow::bail!(
            "guard YARA rules {} exceeds maximum size of {} bytes",
            path.display(),
            GUARD_YARA_RULE_TEXT_LIMIT_BYTES
        );
    }
    let mut reader = std::io::BufReader::new(fs::File::open(path)?);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("guard YARA rules {} size overflow", path.display()))?;
        if total > GUARD_YARA_RULE_TEXT_LIMIT_BYTES {
            anyhow::bail!(
                "guard YARA rules {} exceeds maximum size of {} bytes",
                path.display(),
                GUARD_YARA_RULE_TEXT_LIMIT_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("unable to decode guard YARA rules {}", path.display()))
}

#[cfg(any(feature = "compat_yara", test))]
fn guard_yara_rules_file_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect guard YARA rules {}", path.display())),
    }
}

#[cfg(any(feature = "compat_yara", test))]
fn ensure_regular_guard_yara_rules(path: &Path) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect guard YARA rules {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("guard YARA rules {} is a symbolic link", path.display());
    }
    if is_guard_yara_reparse_point(&metadata) {
        anyhow::bail!("guard YARA rules {} is a reparse point", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("guard YARA rules {} is not a regular file", path.display());
    }
    Ok(metadata)
}

#[cfg(all(any(feature = "compat_yara", test), windows))]
fn is_guard_yara_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(any(feature = "compat_yara", test), not(windows)))]
fn is_guard_yara_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(feature = "compat_yara")]
fn default_yara_rules_path() -> anyhow::Result<PathBuf> {
    let roots = guard_asset_root_candidates("guard YARA default-rule discovery")?;
    for root in &roots {
        for candidate in [
            root.join("assets")
                .join("yara")
                .join("zentor_core_rules.yar"),
            root.join("..")
                .join("..")
                .join("assets")
                .join("yara")
                .join("zentor_core_rules.yar"),
        ] {
            if guard_yara_rules_file_present(&candidate)? {
                return Ok(candidate);
            }
        }
    }
    let root = roots.first().ok_or_else(|| {
        anyhow::anyhow!("guard YARA default-rule discovery found no controlled roots")
    })?;
    Ok(root
        .join("assets")
        .join("yara")
        .join("zentor_core_rules.yar"))
}

#[cfg(feature = "compat_yara")]
fn metadata_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} =");
    line.strip_prefix(&prefix)
        .and_then(|value| quoted_value(value.trim()))
}

#[cfg(feature = "compat_yara")]
fn quoted_value(value: &str) -> Option<String> {
    let start = value.find('"')?;
    let rest = &value[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(feature = "compat_yara")]
fn confidence_from_yara(rule_name: &str, value: &str) -> anyhow::Result<LocalThreatConfidence> {
    match value {
        "confirmed" => Ok(LocalThreatConfidence::Confirmed),
        "high" => Ok(LocalThreatConfidence::High),
        "medium" => Ok(LocalThreatConfidence::Medium),
        "low" => Ok(LocalThreatConfidence::Low),
        _ => anyhow::bail!("guard YARA rule {rule_name} confidence metadata is unsupported"),
    }
}

#[cfg(feature = "compat_yara")]
fn confidence_rank(confidence: &LocalThreatConfidence) -> u8 {
    match confidence {
        LocalThreatConfidence::Confirmed => 4,
        LocalThreatConfidence::High => 3,
        LocalThreatConfidence::Medium => 2,
        LocalThreatConfidence::Low => 1,
    }
}

#[cfg(feature = "compat_clamav")]
fn find_clamscan() -> anyhow::Result<Option<PathBuf>> {
    match std::env::var("ZENTOR_CLAMAV_CLAMSCAN") {
        Ok(configured) => {
            if configured.trim().is_empty() {
                anyhow::bail!("configured ClamAV scanner path is empty");
            }
            let configured_text = validate_guard_configured_clamscan_text(&configured)?;
            let path = PathBuf::from(configured_text);
            ensure_regular_guard_clamscan_executable(&path)?;
            return Ok(Some(path));
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(error) => anyhow::bail!("configured ClamAV scanner path is invalid: {error}"),
    }
    let executable_name = if cfg!(windows) {
        "clamscan.exe"
    } else {
        "clamscan"
    };
    let mut roots = Vec::new();
    let current_exe = std::env::current_exe()
        .context("failed to read current executable path for guard ClamAV discovery")?;
    let parent = current_exe
        .parent()
        .context("current executable path has no parent for guard ClamAV discovery")?;
    roots.push(parent.to_path_buf());
    for root in roots {
        for candidate in [
            root.join("ClamAV").join(executable_name),
            root.join(executable_name),
        ] {
            if guard_clamscan_executable_present(&candidate)? {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(None)
}

#[cfg(any(feature = "compat_clamav", test))]
fn validate_guard_configured_clamscan_text(configured: &str) -> anyhow::Result<&str> {
    let text = configured.trim();
    if text.is_empty() {
        anyhow::bail!("configured ClamAV scanner path is empty");
    }
    if text.contains('\0') {
        anyhow::bail!("configured ClamAV scanner path contains NUL");
    }
    if guard_configured_clamscan_has_parent_traversal(text) {
        anyhow::bail!("configured ClamAV scanner path must not contain parent traversal");
    }
    Ok(text)
}

#[cfg(any(feature = "compat_clamav", test))]
fn guard_configured_clamscan_has_parent_traversal(value: &str) -> bool {
    value.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(any(feature = "compat_clamav", test))]
#[allow(dead_code)]
fn guard_clamscan_executable_present(path: &Path) -> anyhow::Result<bool> {
    ensure_guard_clamscan_location(path)?;
    if guard_clamscan_path_present(path)? {
        ensure_regular_guard_clamscan(path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(any(feature = "compat_clamav", test))]
#[allow(dead_code)]
fn ensure_regular_guard_clamscan_executable(path: &Path) -> anyhow::Result<()> {
    ensure_guard_clamscan_location(path)?;
    ensure_regular_guard_clamscan(path)
}

#[cfg(any(feature = "compat_clamav", test))]
#[allow(dead_code)]
fn ensure_guard_clamscan_location(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("ClamAV scanner {} must be an absolute path", path.display());
    }
    if !guard_clamscan_path_is_local(path) {
        anyhow::bail!("ClamAV scanner {} must be on a local path", path.display());
    }
    Ok(())
}

#[cfg(any(feature = "compat_clamav", test))]
fn guard_clamscan_path_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect ClamAV scanner {}", path.display())),
    }
}

#[cfg(any(feature = "compat_clamav", test))]
fn ensure_regular_guard_clamscan(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect ClamAV scanner {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("ClamAV scanner {} is a symbolic link", path.display());
    }
    if is_guard_clamscan_reparse_point(&metadata) {
        anyhow::bail!("ClamAV scanner {} is a reparse point", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("ClamAV scanner {} is not a regular file", path.display());
    }
    Ok(())
}

#[cfg(all(any(feature = "compat_clamav", test), windows))]
#[allow(dead_code)]
fn guard_clamscan_path_is_local(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(all(any(feature = "compat_clamav", test), not(windows)))]
#[allow(dead_code)]
fn guard_clamscan_path_is_local(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(all(any(feature = "compat_clamav", test), windows))]
fn is_guard_clamscan_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(any(feature = "compat_clamav", test), not(windows)))]
fn is_guard_clamscan_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn should_skip_process_path(path: &Path) -> bool {
    let raw = path.display().to_string();
    let windows_path = normalize_observed_windows_process_path(&raw);
    let unix_path = normalize_observed_unix_process_path(&raw);

    should_skip_windows_process_path(&windows_path) || should_skip_unix_process_path(&unix_path)
}

fn should_skip_windows_process_path(path: &str) -> bool {
    let Some(root) = observed_windows_root(path) else {
        return false;
    };
    let system32 = join_observed_process_path(&root, "system32", '\\');
    let syswow64 = join_observed_process_path(&root, "syswow64", '\\');
    let explorer = join_observed_process_path(&root, "explorer.exe", '\\');

    path == explorer
        || observed_process_path_is_equal_or_descendant(path, &system32, '\\')
        || observed_process_path_is_equal_or_descendant(path, &syswow64, '\\')
}

fn observed_windows_root(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    Some(format!("{}:\\windows", bytes[0] as char))
}

fn should_skip_unix_process_path(path: &str) -> bool {
    ["/usr", "/bin", "/sbin", "/system"]
        .iter()
        .any(|root| observed_process_path_is_equal_or_descendant(path, root, '/'))
}

fn normalize_observed_windows_process_path(value: &str) -> String {
    let normalized = value.trim().replace('/', "\\").to_ascii_lowercase();
    collapse_observed_process_path_segments(&normalized, '\\')
}

fn normalize_observed_unix_process_path(value: &str) -> String {
    let normalized = value.trim().replace('\\', "/").to_ascii_lowercase();
    collapse_observed_process_path_segments(&normalized, '/')
}

fn join_observed_process_path(root: &str, child: &str, separator: char) -> String {
    let mut joined = root.trim_end_matches(separator).to_string();
    joined.push(separator);
    joined.push_str(child.trim_matches(separator));
    joined
}

fn collapse_observed_process_path_segments(path: &str, separator: char) -> String {
    let trimmed = path.trim_end_matches(separator);
    if trimmed.is_empty() {
        return String::new();
    }
    let (prefix, rest, absolute) = split_observed_process_path_prefix(trimmed, separator);
    let mut parts = Vec::new();
    for part in rest.split(separator) {
        match part {
            "" | "." => {}
            ".." => {
                if let Some(last) = parts.last() {
                    if *last != ".." {
                        parts.pop();
                        continue;
                    }
                }
                if !absolute {
                    parts.push(part);
                }
            }
            _ => parts.push(part),
        }
    }

    let separator_text = separator.to_string();
    let joined = parts.join(&separator_text);
    match (prefix, absolute, joined.is_empty()) {
        (Some(prefix), true, true) => format!("{prefix}{separator}"),
        (Some(prefix), true, false) => format!("{prefix}{separator}{joined}"),
        (None, true, true) => separator.to_string(),
        (None, true, false) => format!("{separator}{joined}"),
        (Some(prefix), false, true) => prefix.to_string(),
        (Some(prefix), false, false) => format!("{prefix}{joined}"),
        (None, false, _) => joined,
    }
}

fn split_observed_process_path_prefix(path: &str, separator: char) -> (Option<&str>, &str, bool) {
    if separator == '\\'
        && path.len() >= 3
        && path.as_bytes()[1] == b':'
        && path.as_bytes()[2] == b'\\'
    {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with(separator) {
        return (None, path.trim_start_matches(separator), true);
    }
    (None, path, false)
}

fn observed_process_path_is_equal_or_descendant(path: &str, root: &str, separator: char) -> bool {
    let root = root.trim_end_matches(separator);
    !root.is_empty() && (path == root || path.starts_with(&format!("{root}{separator}")))
}

fn error(message: &str) -> GuardEvent {
    error_event(None, None, message.to_string())
}

fn error_event(
    process_id: Option<u32>,
    process_path: Option<String>,
    message: String,
) -> GuardEvent {
    GuardEvent {
        ok: false,
        action: "error".to_string(),
        message,
        process_id,
        process_path,
        quarantine_path: None,
        quarantine_id: None,
        quarantine_record_path: None,
        created_at: Utc::now(),
    }
}

#[cfg(test)]
fn normalized_test_source(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn normalize_hash(value: String) -> String {
        normalize_sha256(&value).expect("internal guard test hash must be a valid SHA-256 value")
    }

    #[cfg(not(windows))]
    #[test]
    fn guard_service_mode_fails_visibly_off_windows() {
        let source = include_str!("main.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let start = source.find("#[cfg(not(windows))]\nfn run_service").unwrap();
        let end = source[start..]
            .find("#[cfg(windows)]\nfn windows_service_main")
            .map(|offset| start + offset)
            .unwrap();
        let service_source = &source[start..end];

        assert!(service_source.contains("NON_WINDOWS_GUARD_SERVICE_MODE_UNSUPPORTED"));
        assert!(service_source.contains("anyhow::bail!"));
        assert!(!service_source.contains("run_console_watch()"));
    }

    #[cfg(windows)]
    #[test]
    fn guard_service_statuses_are_fail_visible_and_state_appropriate() {
        use windows_service::service::{ServiceControlAccept, ServiceExitCode, ServiceState};

        let start_pending =
            guard_service_status(ServiceState::StartPending, ServiceExitCode::NO_ERROR);
        assert_eq!(start_pending.current_state, ServiceState::StartPending);
        assert_eq!(
            start_pending.controls_accepted,
            ServiceControlAccept::empty()
        );
        assert_eq!(start_pending.checkpoint, 1);
        assert_eq!(start_pending.wait_hint, GUARD_SERVICE_START_WAIT_HINT);

        let running = guard_service_status(ServiceState::Running, ServiceExitCode::NO_ERROR);
        assert_eq!(running.current_state, ServiceState::Running);
        assert_eq!(
            running.controls_accepted,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        );
        assert_eq!(running.checkpoint, 0);
        assert_eq!(running.wait_hint, Duration::from_secs(0));

        let clean_result: anyhow::Result<()> = Ok(());
        let failed_result: anyhow::Result<()> = Err(anyhow::anyhow!("watch failed"));
        assert_eq!(
            guard_service_stop_exit_code(&clean_result),
            ServiceExitCode::NO_ERROR
        );
        assert_eq!(
            guard_service_stop_exit_code(&failed_result),
            ServiceExitCode::ServiceSpecific(GUARD_SERVICE_RUNTIME_FAILURE_EXIT_CODE)
        );

        let stopped = guard_service_status(
            ServiceState::Stopped,
            guard_service_stop_exit_code(&failed_result),
        );
        assert_eq!(stopped.current_state, ServiceState::Stopped);
        assert_eq!(stopped.controls_accepted, ServiceControlAccept::empty());
        assert_eq!(
            stopped.exit_code,
            ServiceExitCode::ServiceSpecific(GUARD_SERVICE_RUNTIME_FAILURE_EXIT_CODE)
        );
        assert_eq!(stopped.checkpoint, 0);
        assert_eq!(stopped.wait_hint, Duration::from_secs(0));
    }

    #[cfg(windows)]
    #[test]
    fn guard_service_preserves_runtime_and_status_failures() {
        let runtime_error = combine_guard_service_runtime_and_status_results(
            Err(anyhow::anyhow!("watch failed")),
            Ok(()),
        )
        .unwrap_err()
        .to_string();
        assert!(runtime_error.contains("watch failed"));

        let status_error = combine_guard_service_runtime_and_status_results(
            Ok(()),
            Err(windows_service::Error::Winapi(
                std::io::Error::from_raw_os_error(5),
            )),
        )
        .unwrap_err()
        .to_string();
        assert!(status_error.contains("failed to report stopped Guard Service status"));

        let combined_error = combine_guard_service_runtime_and_status_results(
            Err(anyhow::anyhow!("watch failed")),
            Err(windows_service::Error::Winapi(
                std::io::Error::from_raw_os_error(5),
            )),
        )
        .unwrap_err()
        .to_string();
        assert!(combined_error.contains("watch failed"));
        assert!(combined_error.contains("failed to report stopped status"));
    }

    fn driver_request_for(path: &Path) -> driver_ipc::ScanRequest {
        driver_ipc::ScanRequest {
            request_id: "test-request".to_string(),
            event_type: driver_ipc::DriverEventType::ImageExecuteAttempt,
            file_path: path.display().to_string(),
            normalized_file_path: None,
            process_id: Some(1234),
            parent_process_id: None,
            user_sid: None,
            desired_access: None,
            file_size: None,
            file_attributes: None,
            signature_status: None,
            publisher: None,
            signature_verified_by: None,
            parent_process_path: None,
            sha256: None,
            sha256_verified_by: None,
            timestamp_utc: Utc::now(),
        }
    }

    fn driver_verdict_from_event(event: &GuardEvent) -> driver_ipc::ScanVerdict {
        serde_json::from_str(&event.message).unwrap()
    }

    fn guard_command(command: &str) -> GuardCommand {
        GuardCommand {
            command: command.to_string(),
            process_id: None,
            process_path: None,
            known_malicious_hashes: None,
            known_good_hashes: None,
            user_approved_hashes: None,
            protection_mode: None,
            poll_interval_ms: None,
            max_iterations: None,
            scan_request: None,
        }
    }

    #[test]
    fn mock_process_start_without_known_hash_is_monitored() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        fs::write(&file, b"developer tool").unwrap();
        let result = handle_process_started(
            None,
            &file,
            &HashSet::new(),
            preexecution_policy::DriverProtectionMode::BlockConfirmedThreats,
        )
        .unwrap();
        assert_eq!(result.action, "monitored");
        assert!(file.exists());
    }

    #[test]
    fn known_malicious_hash_is_quarantined() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"known bad fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let result = handle_process_started(
            None,
            &file,
            &HashSet::from([hash]),
            preexecution_policy::DriverProtectionMode::BlockConfirmedThreats,
        )
        .unwrap();
        assert_eq!(result.action, "quarantined");
        assert!(result.message.contains("no process stop was attempted"));
        assert!(!file.exists());
        assert!(result
            .quarantine_path
            .as_ref()
            .unwrap()
            .ends_with(".avoraxq"));
        assert!(Path::new(result.quarantine_path.as_ref().unwrap()).exists());
        let record_path = result.quarantine_record_path.as_ref().unwrap();
        assert!(Path::new(record_path).exists());
        let record: GuardQuarantineRecord =
            serde_json::from_str(&fs::read_to_string(record_path).unwrap()).unwrap();
        assert_eq!(record.status, QuarantineStatus::Quarantined);
        assert_eq!(record.engine, "avorax-known-bad-hash");
        assert_eq!(record.action_taken, "file_quarantined_without_process_stop");
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_normalizes_threat_metadata_before_move() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let file = dir.path().join("bad-label.exe");
        fs::write(&file, b"known bad fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let threat_match = LocalThreatMatch {
            reason: "\nKnown\0Bad\n".to_string(),
            engine: "\n\t\0".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        };

        let record = quarantine_file(&file, &hash, None, &threat_match).unwrap();

        assert_eq!(record.detection_name, "Known Bad");
        assert_eq!(record.engine, DEFAULT_GUARD_QUARANTINE_ENGINE);
        assert!(!record.detection_name.chars().any(|ch| ch.is_control()));
        assert!(!record.engine.chars().any(|ch| ch.is_control()));
        assert!(!file.exists());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_record_metadata_validation_rejects_unsafe_fields() {
        let dir = tempdir().unwrap();
        let mut record = guard_fixture_record(dir.path(), "record");
        record.sha256 = "not-a-sha256".to_string();

        let hash_error = validate_guard_quarantine_record(&record).unwrap_err();
        assert!(hash_error
            .to_string()
            .contains("invalid guard quarantine metadata sha256"));

        record.sha256 = format!("sha256:{}", "f".repeat(64));
        record.detection_name = "Known\nBad".to_string();
        let label_error = validate_guard_quarantine_record(&record).unwrap_err();
        assert!(label_error
            .to_string()
            .contains("guard quarantine metadata detection name contains control characters"));
    }

    #[test]
    fn guard_quarantine_record_path_validation_rejects_unsafe_fields() {
        let dir = tempdir().unwrap();
        let mut record = guard_fixture_record(dir.path(), "record");
        record.original_path = "relative.exe".to_string();

        let original_error = validate_guard_quarantine_record(&record).unwrap_err();
        assert!(original_error
            .to_string()
            .contains("invalid guard quarantine original path"));

        record.original_path = dir.path().join("bad.exe").display().to_string();
        record.quarantine_path = dir
            .path()
            .join("quarantine")
            .join("record.tmp")
            .display()
            .to_string();
        let payload_error = validate_guard_quarantine_record(&record).unwrap_err();
        assert!(payload_error
            .to_string()
            .contains("invalid guard quarantine payload path"));
    }

    #[test]
    fn guard_quarantine_rejects_changed_source_hash() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let file = dir.path().join("changed.exe");
        fs::write(&file, b"original content").unwrap();
        let stale_hash = sha256_file(&file).unwrap();
        fs::write(&file, b"changed content").unwrap();
        let threat_match = LocalThreatMatch {
            reason: "known malicious hash".to_string(),
            engine: "fixture".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        };

        let error = quarantine_file(&file, &stale_hash, None, &threat_match)
            .expect_err("stale hash should not quarantine changed source");

        assert!(error.to_string().contains("source hash changed"));
        assert!(file.exists());
        let quarantine_dir = dir.path().join("quarantine");
        match fs::read_dir(&quarantine_dir) {
            Ok(mut entries) => assert!(entries.next().is_none()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => assert_eq!(
                error.kind(),
                io::ErrorKind::NotFound,
                "unable to inspect rejected quarantine directory {}: {error}",
                quarantine_dir.display(),
            ),
        }
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_rejects_invalid_expected_hash_before_directory_work() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let file = dir.path().join("invalid-expected-hash.exe");
        fs::write(&file, b"known bad fixture").unwrap();
        let threat_match = LocalThreatMatch {
            reason: "known malicious hash".to_string(),
            engine: "fixture".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        };

        let error = quarantine_file(&file, "not-a-sha256", None, &threat_match)
            .expect_err("invalid expected hash should fail before quarantine work");

        assert!(error
            .to_string()
            .contains("invalid guard quarantine expected sha256"));
        assert!(file.exists());
        assert!(!dir.path().join("quarantine").exists());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[cfg(unix)]
    #[test]
    fn guard_quarantine_rejects_symbolic_link_source_before_metadata_follow() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let target = dir.path().join("target.exe");
        let link = dir.path().join("link.exe");
        fs::write(&target, b"known bad fixture").unwrap();
        symlink(&target, &link).unwrap();
        let hash = sha256_file(&target).unwrap();
        let threat_match = LocalThreatMatch {
            reason: "known malicious hash".to_string(),
            engine: "fixture".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        };

        let error = quarantine_file(&link, &hash, None, &threat_match)
            .expect_err("symbolic link source should not be quarantined");

        assert!(error
            .to_string()
            .contains("refusing to use symbolic link quarantine source"));
        assert!(target.exists());
        assert!(link.exists());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_uses_regular_file_guards_around_move() {
        let source = include_str!("main.rs");
        let start = source.find("fn quarantine_file(").unwrap();
        let end = source.find("fn reject_symlink_source").unwrap();
        let quarantine_source = &source[start..end];

        assert!(
            quarantine_source.contains("regular_guard_file_metadata(path, \"quarantine source\")")
        );
        assert!(quarantine_source.contains(
            "regular_guard_file_metadata(&destination, \"guard quarantine destination\")"
        ));
        assert!(!quarantine_source.contains("fs::metadata(path)?"));
        assert!(!quarantine_source.contains("metadata.is_file()"));
    }

    #[test]
    fn guard_quarantine_finalization_failures_clean_untracked_artifacts() {
        let source = include_str!("main.rs");
        let start = source.find("fn quarantine_file(").unwrap();
        let end = source.find("fn reject_symlink_source").unwrap();
        let quarantine_source = &source[start..end];
        let cleanup_start = source
            .find("fn cleanup_untracked_guard_quarantine_artifacts")
            .unwrap();
        let cleanup_end = source.find("fn copy_file_exclusive").unwrap();
        let cleanup_source = &source[cleanup_start..cleanup_end];

        assert!(quarantine_source
            .contains("let finalize_result = (|| -> anyhow::Result<GuardQuarantineRecord>"));
        assert!(quarantine_source
            .contains("cleanup_untracked_guard_quarantine_artifacts(&id, &destination)"));
        assert!(quarantine_source.contains("after quarantine finalization failure"));
        assert!(quarantine_source.contains("return Err(error)"));
        assert!(cleanup_source.contains("\"untracked guard quarantine payload\""));
        assert!(cleanup_source.contains("\"untracked guard quarantine metadata record\""));
        assert!(cleanup_source.contains("\"untracked guard quarantine metadata temp record\""));
        assert!(cleanup_source.contains("\"untracked guard quarantine metadata auth sidecar\""));
        assert!(
            cleanup_source.contains("\"untracked guard quarantine metadata auth temp sidecar\"")
        );
        assert!(cleanup_source
            .contains("failed to clean up one or more untracked guard quarantine artifacts"));
        assert!(cleanup_source.contains("checked_quarantine_record_path(id)"));
        assert!(
            quarantine_source
                .find("fs::rename(path, &destination)")
                .unwrap()
                < quarantine_source
                    .find("let finalize_result = (|| -> anyhow::Result<GuardQuarantineRecord>")
                    .unwrap()
        );
        assert!(
            quarantine_source
                .find("write_quarantine_record(&record)?")
                .unwrap()
                < quarantine_source
                    .find("cleanup_untracked_guard_quarantine_artifacts")
                    .unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn guard_quarantine_rejects_symbolic_link_base_directory() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let real_base = dir.path().join("real-q");
        let link_base = dir.path().join("link-q");
        fs::create_dir_all(&real_base).unwrap();
        symlink(&real_base, &link_base).unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", &link_base);
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"known bad fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let threat_match = LocalThreatMatch {
            reason: "known malicious hash".to_string(),
            engine: "fixture".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        };

        let error = quarantine_file(&file, &hash, None, &threat_match)
            .expect_err("symbolic link quarantine base should be rejected");

        assert!(error
            .to_string()
            .contains("refusing to use symbolic link quarantine base directory"));
        assert!(file.exists());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_point_attribute_constant_is_expected_value() {
        assert_eq!(FILE_ATTRIBUTE_REPARSE_POINT, 0x400);
    }

    #[cfg(windows)]
    #[test]
    fn windows_current_account_for_acl_is_not_empty() {
        assert!(!current_windows_account().unwrap().trim().is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn metadata_key_storage_round_trips_plaintext_off_windows() {
        let encoded = encode_metadata_auth_key("fixture-key").unwrap();
        assert_eq!(encoded, "fixture-key\n");
        assert_eq!(decode_metadata_auth_key(&encoded).unwrap(), "fixture-key");
    }

    #[cfg(windows)]
    #[test]
    fn metadata_key_storage_uses_dpapi_on_windows() {
        let encoded = encode_metadata_auth_key("fixture-key").unwrap();
        assert!(encoded.starts_with("dpapi:"));
        assert_eq!(decode_metadata_auth_key(&encoded).unwrap(), "fixture-key");
    }

    #[test]
    fn guard_quarantine_copy_fallback_keeps_source_on_hash_mismatch() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("destination.avoraxq");
        fs::write(&source, b"known bad fixture").unwrap();
        let wrong_hash = format!("sha256:{}", "0".repeat(64));

        let error = copy_then_remove_verified(&source, &destination, &wrong_hash)
            .expect_err("mismatched copy hash must fail before deleting source");

        assert!(error.to_string().contains("hash verification failed"));
        assert!(source.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn guard_quarantine_copy_fallback_rejects_invalid_expected_hash_before_copy() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("destination.avoraxq");
        fs::write(&source, b"known bad fixture").unwrap();

        let error = copy_then_remove_verified(&source, &destination, "not-a-sha256")
            .expect_err("invalid copy hash must fail before copying payload");

        assert!(error
            .to_string()
            .contains("invalid guard quarantine copy expected sha256"));
        assert!(source.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn guard_quarantine_copy_fallback_accepts_bare_expected_hash() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("destination.avoraxq");
        fs::write(&source, b"known bad fixture").unwrap();
        let hash = sha256_file(&source).unwrap();
        let bare_hash = normalize_sha256(&hash).expect("hash body");

        copy_then_remove_verified(&source, &destination, &bare_hash)
            .expect("bare expected hash should be accepted");

        assert!(!source.exists());
        assert!(destination.exists());
    }

    #[test]
    fn guard_quarantine_copy_fallback_source_delete_failure_cleans_destination() {
        let source = include_str!("main.rs");
        let start = source.find("fn copy_then_remove_verified").unwrap();
        let end = source
            .find("fn ensure_quarantine_payload_destination_absent")
            .unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("if let Err(error) = fs::remove_file(source)"));
        assert!(copy_source.contains(
            "cleanup_guard_quarantine_partial_file(destination, \"copied guard quarantine destination\")"
        ));
        assert!(copy_source.contains("after source deletion failure"));
        assert!(copy_source.contains("failed to delete original guard quarantine source"));
        assert!(
            copy_source
                .find("destination_hash != expected_sha256")
                .unwrap()
                < copy_source
                    .find("if let Err(error) = fs::remove_file(source)")
                    .unwrap()
        );
        assert!(
            copy_source
                .find("if let Err(error) = fs::remove_file(source)")
                .unwrap()
                < copy_source.rfind("Ok(())").unwrap()
        );
    }

    #[test]
    fn guard_quarantine_copy_fallback_verification_failure_cleans_destination() {
        let source = include_str!("main.rs");
        let start = source.find("fn copy_then_remove_verified").unwrap();
        let end = source
            .find("fn ensure_quarantine_payload_destination_absent")
            .unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("let destination_hash = match (|| -> anyhow::Result<String>"));
        assert!(copy_source.contains("invalid copied guard quarantine destination"));
        assert!(copy_source.contains("after verification failure"));
        assert!(copy_source.contains("failed to verify copied guard quarantine destination"));
        assert!(
            copy_source
                .find("copy_file_exclusive(source, destination)?")
                .unwrap()
                < copy_source.find("let destination_hash = match").unwrap()
        );
        assert!(
            copy_source.find("let destination_hash = match").unwrap()
                < copy_source
                    .find("destination_hash != expected_sha256")
                    .unwrap()
        );
    }

    #[test]
    fn guard_quarantine_copy_fallback_rejects_existing_destination() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("destination.avoraxq");
        fs::write(&source, b"known bad fixture").unwrap();
        fs::write(&destination, b"existing payload").unwrap();
        let hash = sha256_file(&source).unwrap();

        let error = copy_then_remove_verified(&source, &destination, &hash)
            .expect_err("existing payload destination must not be overwritten");

        assert!(error
            .to_string()
            .contains("guard quarantine payload destination"));
        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read(&destination).unwrap(), b"existing payload");
        assert!(source.exists());
    }

    #[cfg(unix)]
    #[test]
    fn guard_quarantine_copy_fallback_rejects_linked_destination() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let external = dir.path().join("external-target");
        let destination = dir.path().join("destination.avoraxq");
        fs::write(&source, b"known bad fixture").unwrap();
        fs::write(&external, b"do not overwrite").unwrap();
        std::os::unix::fs::symlink(&external, &destination).unwrap();
        let hash = sha256_file(&source).unwrap();

        let error = copy_then_remove_verified(&source, &destination, &hash)
            .expect_err("linked payload destination must not be followed");

        assert!(error
            .to_string()
            .contains("refusing to use symbolic link guard quarantine payload destination"));
        assert_eq!(fs::read(&external).unwrap(), b"do not overwrite");
        assert!(source.exists());
    }

    #[test]
    fn guard_quarantine_copy_fallback_uses_exclusive_destination_creation() {
        let source = include_str!("main.rs");
        let start = source.find("fn copy_then_remove_verified").unwrap();
        let end = source.find("fn write_quarantine_record").unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("ensure_quarantine_payload_destination_absent(destination)?"));
        assert!(copy_source.contains(".create_new(true)"));
        assert!(copy_source.contains("MAX_GUARD_QUARANTINE_COPY_BYTES"));
        assert!(copy_source.contains("copy_guard_quarantine_payload_limited"));
        assert!(copy_source.contains("let mut buffer = [0_u8; 64 * 1024]"));
        assert!(copy_source.contains("total > limit"));
        assert!(copy_source.contains("output.write_all(&buffer[..read])"));
        assert!(copy_source.contains("cleanup_guard_quarantine_partial_file"));
        assert!(copy_source.contains("after copy failure"));
        assert!(copy_source.contains("after sync failure"));
        assert!(copy_source.contains("output.sync_all()"));
        let old_copy = ["io::", "copy(&mut input, &mut output)"].concat();
        assert!(!copy_source.contains(&old_copy));
        assert!(!copy_source.contains("fs::copy(source, destination)"));
    }

    #[test]
    fn guard_quarantine_retry_errors_are_explicit() {
        let source = include_str!("main.rs");
        let start = source.find("fn quarantine_file(").unwrap();
        let end = source.find("fn reject_symlink_source").unwrap();
        let quarantine_source = &source[start..end];

        assert!(quarantine_source.contains("match last_error"));
        assert!(quarantine_source.contains("Some(error) => Err(error)"));
        assert!(quarantine_source
            .contains("guard quarantine failed after retry loop without a recorded cause"));
        assert!(!quarantine_source.contains("last_error.unwrap_or_else"));
    }

    #[test]
    fn guard_quarantine_record_writes_are_staged() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = GuardQuarantineRecord {
            quarantine_id: "record".to_string(),
            original_path: dir.path().join("bad.exe").display().to_string(),
            quarantine_path: dir
                .path()
                .join("quarantine")
                .join("record.avoraxq")
                .display()
                .to_string(),
            sha256: format!("sha256:{}", "f".repeat(64)),
            file_size: 12,
            detection_name: "Fixture".to_string(),
            engine: "fixture".to_string(),
            action_taken: "process_stop_requested_and_file_quarantined".to_string(),
            quarantined_at: Utc::now(),
            status: QuarantineStatus::Quarantined,
            user_note: None,
            source: "guard_service".to_string(),
            blocked_before_execution: false,
            process_started: true,
            process_id: Some(1234),
        };

        write_quarantine_record(&record).unwrap();

        let base = dir.path().join("quarantine");
        assert!(base.join("record.json").exists());
        assert!(!base.join("record.json.tmp").exists());
        assert!(base.join("record.json.auth").exists());
        assert!(!base.join("record.json.auth.tmp").exists());
        assert!(!base.join(".metadata_auth_key.tmp").exists());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_record_writes_reject_unsafe_ids_before_path_construction() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));

        for unsafe_id in ["", "../record", r"..\record", "bad/id", "bad.id"] {
            let record = guard_fixture_record(dir.path(), unsafe_id);
            let record_error = write_quarantine_record(&record).unwrap_err();
            let record_message = record_error.to_string();
            assert!(
                record_message.contains("guard quarantine id is required")
                    || record_message.contains("invalid guard quarantine id")
            );

            let raw = serde_json::to_string_pretty(&record).unwrap();
            let auth_error = write_quarantine_record_auth(&record, &raw).unwrap_err();
            let auth_message = auth_error.to_string();
            assert!(
                auth_message.contains("guard quarantine id is required")
                    || auth_message.contains("invalid guard quarantine id")
            );
        }

        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_record_id_validation_is_not_dead_control() {
        let source = include_str!("main.rs");
        let record_start = source.find("fn write_quarantine_record(").unwrap();
        let auth_start = source.find("fn write_quarantine_record_auth").unwrap();
        let auth_end = source.find("fn quarantine_record_auth_valid").unwrap();
        let record_source = &source[record_start..auth_start];
        let auth_source = &source[auth_start..auth_end];

        assert!(source.contains("const MAX_GUARD_QUARANTINE_ID_CHARS: usize = 128;"));
        assert!(source.contains("fn validate_guard_quarantine_id"));
        assert!(source.contains("fn checked_quarantine_record_path"));
        assert!(record_source.contains("checked_quarantine_record_path(&record.quarantine_id)?"));
        assert!(auth_source.contains("checked_quarantine_record_path(&record.quarantine_id)?"));
    }

    #[test]
    fn guard_quarantine_base_rejects_relative_override_environment() {
        let _lock = env_lock();
        std::env::remove_var("AVORAX_QUARANTINE_DIR");
        std::env::remove_var("ZENTOR_GUARD_QUARANTINE_DIR");
        std::env::remove_var("ZENTOR_QUARANTINE_DIR");
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", "relative-quarantine");

        let error = quarantine_base().unwrap_err().to_string();

        assert!(error.contains("AVORAX_GUARD_QUARANTINE_DIR must be absolute"));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_base_rejects_parent_traversal_override_environment() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_GUARD_QUARANTINE_DIR");
        let dir = tempdir().unwrap();
        std::env::remove_var("AVORAX_QUARANTINE_DIR");
        std::env::remove_var("ZENTOR_GUARD_QUARANTINE_DIR");
        std::env::remove_var("ZENTOR_QUARANTINE_DIR");
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join(".."));

        let error = quarantine_base().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR"),
        }
        assert!(error.contains("AVORAX_GUARD_QUARANTINE_DIR"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[test]
    fn guard_quarantine_base_path_safety_markers_stay_in_place() {
        let source = include_str!("main.rs");

        assert!(source.contains("fn quarantine_base() -> anyhow::Result<PathBuf>"));
        assert!(source.contains("fn absolute_guard_quarantine_env_path"));
        assert!(source.contains("guard quarantine path environment {name} must be absolute"));
        assert!(source.contains("quarantine_base()?"));
        assert!(!source.contains("PathBuf::from(\".avorax/quarantine\")"));
    }

    #[test]
    fn guard_quarantine_staged_writes_reject_linked_temp_paths_in_source() {
        let source = include_str!("main.rs");
        let write_start = source.find("fn write_quarantine_record(").unwrap();
        let read_start = source
            .find("fn read_bounded_guard_quarantine_text")
            .unwrap();
        let write_sources = &source[write_start..read_start];
        let write_exclusive_pattern = ["fn write_file_", "exclusive"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let sync_pattern = ["output.", "sync_all()"].concat();
        let staged_call_pattern = ["write_file_", "exclusive(&temp_path, bytes, label)"].concat();
        let old_record_write_pattern = ["fs::write(&temp_", "path, &raw)?"].concat();
        let old_auth_write_pattern = ["fs::write(&temp_", "path, format!(\"{tag}\\n\"))?"].concat();
        let old_key_write_pattern = [
            "fs::write(&temp_",
            "path, encode_metadata_auth_key(&key)?)?",
        ]
        .concat();
        let old_final_replace_pattern =
            ["remove_existing_quarantine_file(path", ", label)?"].concat();
        let old_record_temp_pattern = ["with_extension(\"json", ".tmp\")"].concat();
        let old_auth_temp_pattern = ["with_extension(\"auth", ".tmp\")"].concat();
        let old_key_temp_pattern = [".metadata_auth_key", ".tmp"].concat();

        assert!(source.contains("fn write_staged_quarantine_file"));
        assert!(source.contains("fn guard_quarantine_staged_temp_path"));
        assert!(source.contains("let temp_path = guard_quarantine_staged_temp_path(path, label)?"));
        assert!(source.contains("temp_name.push(format!(\".tmp-{}\", Uuid::new_v4()))"));
        assert!(source.contains(&write_exclusive_pattern));
        assert!(source.contains(&create_new_pattern));
        assert!(source.contains(&sync_pattern));
        assert!(source.contains(&staged_call_pattern));
        assert!(source.contains("ensure_quarantine_file_parent_directory(path, label)?"));
        assert!(source.contains("ensure_quarantine_file_parent_directory(path, label)"));
        assert!(source.contains("cleanup_guard_quarantine_staged_file(&temp_path, label)"));
        assert!(source.contains("ensure_quarantine_file_destination_absent(path, label)"));
        assert!(source.contains("let mut output = match fs::OpenOptions::new()"));
        assert!(source.contains("Err(error) => {"));
        assert!(source.contains("after write failure"));
        assert!(source.contains("after sync failure"));
        assert!(source.contains("after temp validation failure"));
        assert!(source.contains("after parent preflight failure"));
        assert!(source.contains("after activation preflight failure"));
        assert!(source.contains("after activation failure"));
        assert!(source.contains("{label} destination already exists"));
        assert!(source.contains("fn ensure_quarantine_file_parent_directory"));
        assert!(source.contains("refusing to replace symbolic link {label}"));
        assert!(source.contains("refusing to replace reparse point {label}"));
        assert!(source.contains("fn ensure_quarantine_file_destination_absent"));
        assert!(!source.contains(&old_record_write_pattern));
        assert!(!source.contains(&old_auth_write_pattern));
        assert!(!source.contains(&old_key_write_pattern));
        assert!(!source.contains(&old_final_replace_pattern));
        assert!(!write_sources.contains(&old_record_temp_pattern));
        assert!(!write_sources.contains(&old_auth_temp_pattern));
        assert!(!write_sources.contains(&old_key_temp_pattern));
    }

    #[test]
    fn guard_quarantine_staged_writes_reject_existing_final_record() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "record");
        let record_path = checked_quarantine_record_path("record").unwrap();
        fs::create_dir_all(record_path.parent().unwrap()).unwrap();
        fs::write(&record_path, b"existing record").unwrap();

        let err = write_quarantine_record(&record).unwrap_err();

        assert!(err
            .to_string()
            .contains("guard quarantine metadata record destination already exists"));
        assert_eq!(fs::read(&record_path).unwrap(), b"existing record");
        assert!(!record_path.with_extension("json.tmp").exists());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_staged_writes_reject_existing_final_auth_sidecar() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "record");
        let raw = serde_json::to_string_pretty(&record).unwrap();
        quarantine_metadata_auth_key(true).unwrap();
        let auth_path = checked_quarantine_record_path("record")
            .unwrap()
            .with_extension("json.auth");
        fs::write(&auth_path, b"existing auth").unwrap();

        let err = write_quarantine_record_auth(&record, &raw).unwrap_err();

        assert!(err
            .to_string()
            .contains("guard quarantine metadata auth sidecar destination already exists"));
        assert_eq!(fs::read(&auth_path).unwrap(), b"existing auth");
        assert!(!auth_path.with_extension("auth.tmp").exists());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[cfg(unix)]
    #[test]
    fn guard_legacy_fixed_record_temp_link_is_not_used_by_uuid_staging() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "record");
        let base = dir.path().join("quarantine");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("external-record"), b"do not overwrite").unwrap();
        symlink(base.join("external-record"), base.join("record.json.tmp")).unwrap();

        write_quarantine_record(&record).unwrap();

        assert_eq!(
            fs::read(base.join("external-record")).unwrap(),
            b"do not overwrite"
        );
        assert!(base.join("record.json").exists());
        assert!(fs::symlink_metadata(base.join("record.json.tmp"))
            .unwrap()
            .file_type()
            .is_symlink());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[cfg(unix)]
    #[test]
    fn guard_legacy_fixed_auth_temp_link_is_not_used_by_uuid_staging() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "record");
        let base = dir.path().join("quarantine");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("external-auth"), b"do not overwrite").unwrap();
        let raw = serde_json::to_string_pretty(&record).unwrap();
        quarantine_metadata_auth_key(true).unwrap();
        symlink(
            base.join("external-auth"),
            base.join("record.json.auth.tmp"),
        )
        .unwrap();

        write_quarantine_record_auth(&record, &raw).unwrap();

        assert_eq!(
            fs::read(base.join("external-auth")).unwrap(),
            b"do not overwrite"
        );
        assert!(base.join("record.json.auth").exists());
        assert!(fs::symlink_metadata(base.join("record.json.auth.tmp"))
            .unwrap()
            .file_type()
            .is_symlink());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[cfg(unix)]
    #[test]
    fn guard_legacy_fixed_metadata_key_temp_link_is_not_used_by_uuid_staging() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let base = dir.path().join("quarantine");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("external-key-temp"), b"do not overwrite").unwrap();
        symlink(
            base.join("external-key-temp"),
            base.join(".metadata_auth_key.tmp"),
        )
        .unwrap();

        let key = quarantine_metadata_auth_key(true).unwrap();

        assert!(!key.trim().is_empty());
        assert_eq!(
            fs::read(base.join("external-key-temp")).unwrap(),
            b"do not overwrite"
        );
        assert!(base.join(".metadata_auth_key").exists());
        assert!(fs::symlink_metadata(base.join(".metadata_auth_key.tmp"))
            .unwrap()
            .file_type()
            .is_symlink());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_record_auth_detects_tampering() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let mut record = guard_fixture_record(dir.path(), "record");

        write_quarantine_record(&record).unwrap();
        let path = quarantine_record_path("record").unwrap();
        assert!(quarantine_record_auth_valid(&path, &fs::read_to_string(&path).unwrap()).unwrap());

        record.engine = "tampered-engine".to_string();
        let tampered_raw = serde_json::to_string_pretty(&record).unwrap();
        fs::write(&path, &tampered_raw).unwrap();

        assert!(!quarantine_record_auth_valid(&path, &tampered_raw).unwrap());
        let err = ensure_quarantine_record_auth_valid(&path, &tampered_raw).unwrap_err();
        assert!(err
            .to_string()
            .contains("guard quarantine metadata authentication failed"));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_oversized_auth_sidecar_is_rejected_before_comparison() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "record");

        write_quarantine_record(&record).unwrap();
        let path = quarantine_record_path("record").unwrap();
        let base = path.parent().unwrap();
        fs::write(
            base.join("record.json.auth"),
            "x".repeat(MAX_GUARD_QUARANTINE_METADATA_AUTH_BYTES as usize + 1),
        )
        .unwrap();
        let raw = serde_json::to_string_pretty(&record).unwrap();

        let err = quarantine_record_auth_valid(&path, &raw).unwrap_err();

        assert!(err
            .to_string()
            .contains("guard quarantine metadata auth sidecar"));
        assert!(err.to_string().contains("exceeds maximum size"));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_oversized_metadata_key_is_rejected_before_decode() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let base = dir.path().join("quarantine");
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", &base);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            base.join(".metadata_auth_key"),
            "x".repeat(MAX_GUARD_QUARANTINE_METADATA_AUTH_BYTES as usize + 1),
        )
        .unwrap();

        let err = quarantine_metadata_auth_key(false).unwrap_err();

        assert!(err
            .to_string()
            .contains("guard quarantine metadata authentication key"));
        assert!(err.to_string().contains("exceeds maximum size"));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_authenticated_record_without_metadata_key_is_reported() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let base = dir.path().join("quarantine");
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", &base);
        fs::create_dir_all(&base).unwrap();
        let record = guard_fixture_record(dir.path(), "record");
        let raw = serde_json::to_string_pretty(&record).unwrap();
        let path = quarantine_record_path("record").unwrap();
        fs::write(&path, &raw).unwrap();
        fs::write(path.with_extension("json.auth"), "sha256:fixture\n").unwrap();

        let err = quarantine_record_auth_valid(&path, &raw).unwrap_err();

        assert!(err
            .to_string()
            .contains("guard quarantine metadata authentication key unavailable"));
        assert!(err.to_string().contains("record.json"));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_legacy_record_without_auth_sidecar_remains_readable() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "legacy");
        let raw = serde_json::to_string_pretty(&record).unwrap();
        let path = quarantine_record_path("legacy").unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &raw).unwrap();

        assert!(quarantine_record_auth_valid(&path, &raw).unwrap());
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[cfg(unix)]
    #[test]
    fn guard_linked_auth_sidecar_is_rejected() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "record");

        write_quarantine_record(&record).unwrap();
        let path = quarantine_record_path("record").unwrap();
        let base = path.parent().unwrap();
        fs::remove_file(base.join("record.json.auth")).unwrap();
        symlink(
            base.join(".metadata_auth_key"),
            base.join("record.json.auth"),
        )
        .unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        let err = quarantine_record_auth_valid(&path, &raw).unwrap_err();

        assert!(err
            .to_string()
            .contains("refusing to use symbolic link guard quarantine metadata auth sidecar"));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[cfg(unix)]
    #[test]
    fn guard_linked_metadata_key_is_rejected() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "record");
        let base = dir.path().join("quarantine");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("external-key"), b"external").unwrap();
        symlink(base.join("external-key"), base.join(".metadata_auth_key")).unwrap();
        let err = write_quarantine_record(&record).unwrap_err();

        assert!(err.to_string().contains(
            "refusing to use symbolic link guard quarantine metadata authentication key"
        ));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_directory_auth_sidecar_is_rejected() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let record = guard_fixture_record(dir.path(), "record");

        write_quarantine_record(&record).unwrap();
        let path = quarantine_record_path("record").unwrap();
        let auth_path = path.with_extension("json.auth");
        fs::remove_file(&auth_path).unwrap();
        fs::create_dir(&auth_path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        let err = quarantine_record_auth_valid(&path, &raw).unwrap_err();

        assert!(err
            .to_string()
            .contains("guard quarantine metadata auth sidecar"));
        assert!(err.to_string().contains("not a regular file"));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_directory_metadata_key_is_rejected() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let base = dir.path().join("quarantine");
        std::env::set_var("AVORAX_GUARD_QUARANTINE_DIR", &base);
        fs::create_dir_all(&base).unwrap();
        fs::create_dir(base.join(".metadata_auth_key")).unwrap();

        let err = quarantine_metadata_auth_key(false).unwrap_err();

        assert!(err
            .to_string()
            .contains("guard quarantine metadata authentication key"));
        assert!(err.to_string().contains("not a regular file"));
        std::env::remove_var("AVORAX_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn guard_quarantine_optional_metadata_presence_is_non_following() {
        let source = include_str!("main.rs");
        let start = source.find("fn quarantine_record_auth_valid").unwrap();
        let end = source.find("fn write_staged_quarantine_file").unwrap();
        let metadata_source = &source[start..end];

        assert!(metadata_source.contains("guard_quarantine_metadata_file_present"));
        assert!(metadata_source.contains("ensure_regular_guard_quarantine_metadata"));
        assert!(metadata_source.contains("fs::symlink_metadata(path)"));
        assert!(metadata_source.contains("metadata.file_type().is_symlink()"));
        assert!(!metadata_source.contains("auth_path.exists()"));
        assert!(!metadata_source.contains("path.exists()"));
    }

    #[test]
    fn guard_quarantine_record_auth_is_verified_after_write() {
        let source = include_str!("main.rs");
        let write_start = source.find("fn write_quarantine_record(").unwrap();
        let write_auth_start = source.find("fn write_quarantine_record_auth").unwrap();
        let write_source = &source[write_start..write_auth_start];
        let auth_start = source.find("fn quarantine_record_auth_valid").unwrap();
        let tag_start = source.find("fn quarantine_record_auth_tag").unwrap();
        let auth_source = &source[auth_start..tag_start];

        assert!(write_source.contains("ensure_quarantine_record_auth_valid(&path, &raw)?"));
        assert!(auth_source.contains("guard quarantine metadata authentication failed"));
        assert!(auth_source.contains(
            "guard quarantine metadata authentication key unavailable for authenticated record"
        ));
        assert!(!auth_source.contains("return Ok(false);"));
    }

    #[test]
    fn watch_processes_completes_without_fake_detection() {
        let result = watch_processes(
            &HashSet::new(),
            100,
            Some(1),
            preexecution_policy::DriverProtectionMode::BlockConfirmedThreats,
        )
        .unwrap();
        assert_eq!(result.action, "watchCompleted");
        assert!(result.ok);
    }

    #[test]
    fn guard_watch_poll_interval_is_explicitly_bounded() {
        assert_eq!(
            guard_watch_poll_interval_ms(None).unwrap(),
            DEFAULT_GUARD_WATCH_POLL_INTERVAL_MS
        );
        assert_eq!(
            guard_watch_poll_interval_ms(Some(MIN_GUARD_WATCH_POLL_INTERVAL_MS)).unwrap(),
            MIN_GUARD_WATCH_POLL_INTERVAL_MS
        );
        assert_eq!(
            guard_watch_poll_interval_ms(Some(MAX_GUARD_WATCH_POLL_INTERVAL_MS)).unwrap(),
            MAX_GUARD_WATCH_POLL_INTERVAL_MS
        );

        let too_low =
            guard_watch_poll_interval_ms(Some(MIN_GUARD_WATCH_POLL_INTERVAL_MS - 1)).unwrap_err();
        assert!(too_low.to_string().contains("poll_interval_ms"));
        assert!(too_low.to_string().contains("at least"));

        let too_high =
            guard_watch_poll_interval_ms(Some(MAX_GUARD_WATCH_POLL_INTERVAL_MS + 1)).unwrap_err();
        assert!(too_high.to_string().contains("poll_interval_ms"));
        assert!(too_high.to_string().contains("at most"));
    }

    #[test]
    fn guard_watch_poll_interval_source_has_no_hidden_default_or_clamp() {
        let source = include_str!("main.rs");
        let helper_start = source.find("fn guard_watch_poll_interval_ms").unwrap();
        let helper_end = source.find("fn sanitize_external_driver_request").unwrap();
        let helper_source = &source[helper_start..helper_end];
        let handle_start = source.find("\"watch_processes\" =>").unwrap();
        let handle_end = source.find("fn guard_watch_poll_interval_ms").unwrap();
        let handle_source = &source[handle_start..handle_end];
        let watch_start = source.find("fn watch_processes(").unwrap();
        let watch_end = source.find("fn inspect_new_process").unwrap();
        let watch_source = &source[watch_start..watch_end];
        let old_default = ["command.poll_interval_ms", ".unwrap_or(750)"].concat();
        let old_sleep_clamp = ["poll_interval_ms", ".max(100)"].concat();

        assert!(helper_source.contains("DEFAULT_GUARD_WATCH_POLL_INTERVAL_MS"));
        assert!(helper_source.contains("MIN_GUARD_WATCH_POLL_INTERVAL_MS"));
        assert!(helper_source.contains("MAX_GUARD_WATCH_POLL_INTERVAL_MS"));
        assert!(handle_source.contains("guard_watch_poll_interval_ms(command.poll_interval_ms)"));
        assert!(watch_source.contains("validate_guard_watch_poll_interval_ms(poll_interval_ms)?"));
        assert!(watch_source.contains("Duration::from_millis(poll_interval_ms)"));
        assert!(!source.contains(&old_default));
        assert!(!watch_source.contains(&old_sleep_clamp));
    }

    #[test]
    fn process_watch_inspection_errors_are_not_suppressed() {
        let source = include_str!("main.rs");
        let watch_start = source.find("fn watch_processes(").unwrap();
        let guard_mode_start = source.find("fn configured_guard_mode(").unwrap();
        let watch_source = &source[watch_start..guard_mode_start];
        let inspect_start = source.find("fn inspect_new_process").unwrap();
        let inspect_end = source.find("fn process_file_identity").unwrap();
        let inspect_source = &source[inspect_start..inspect_end];
        let empty_hash_pattern = ["sha256_file(&process.path)", ".unwrap_or_default()"].concat();
        let native_swallow_pattern =
            ["native_threat_match(&process.path)", ".ok().flatten()"].concat();
        let compat_swallow_pattern =
            ["compat_threat_match(&process.path)", ".ok().flatten()"].concat();

        assert!(source.contains("enum ProcessInspectionOutcome"));
        assert!(source.contains("Inspected(ProcessInspection)"));
        assert!(source.contains("ErrorReported"));
        assert!(watch_source.contains("let mut inspection_errors = 0u64"));
        assert!(watch_source.contains("inspection_errors = inspection_errors.saturating_add(1)"));
        assert!(watch_source.contains("watchCompletedWithInspectionErrors"));
        assert!(watch_source.contains("ok: false"));
        assert!(watch_source.contains("process inspection error(s)"));
        assert!(watch_source.contains("inspect_new_process"));
        assert!(watch_source.contains("inspect_new_process(&process.path"));
        assert!(watch_source.contains("&mut cache)?"));
        assert!(watch_source.contains("write_guard_event(&event)?"));
        assert!(watch_source
            .contains("write_process_inspection_error(process_id, path, \"hash\", error)?"));
        assert!(inspect_source.contains("Ok(ProcessInspectionOutcome::ErrorReported)"));
        assert!(inspect_source.contains("Ok(ProcessInspectionOutcome::Inspected(ProcessInspection"));
        assert!(!inspect_source.contains("anyhow::Result<Option<ProcessInspection>>"));
        assert!(!inspect_source.contains("return Ok(None);"));
        assert!(!watch_source.contains(&empty_hash_pattern));
        assert!(!watch_source.contains(&native_swallow_pattern));
        assert!(!watch_source.contains(&compat_swallow_pattern));
        assert!(!watch_source.contains("let _ = write_guard_event"));
        assert!(source.contains("process {stage} inspection failed"));
    }

    #[test]
    fn guard_fatal_error_logging_reports_secondary_failures() {
        let main_source = include_str!("main.rs");
        let driver_port_source = include_str!("driver_port.rs");
        let service_start = main_source.find("fn run_windows_service_loop").unwrap();
        let service_end = main_source.find("fn run_console_watch").unwrap();
        let service_source = &main_source[service_start..service_end];
        let old_service_create = ["let _ = fs::create_", "dir_all(event_log_base())"].concat();
        let old_service_write = ["let _ = fs::", "write("].concat();
        let old_service_fatal_direct_write = ["fs::", "write(&path, detail)"].concat();
        let old_driver_create = [
            "let _ = std::fs::create_",
            "dir_all(crate::event_log_base())",
        ]
        .concat();
        let old_driver_write = ["let _ = std::fs::", "write("].concat();
        let old_shutdown_signal = ["let _ = shutdown_", "tx.send(())"].concat();

        assert!(main_source.contains("pub(crate) fn report_guard_fatal_error"));
        assert!(main_source.contains("fn write_guard_fatal_error_log"));
        assert!(main_source.contains("failed to create guard fatal log directory"));
        assert!(main_source.contains("failed to write guard fatal error log"));
        assert!(main_source.contains("temporary guard fatal error log"));
        assert!(main_source.contains("failed to activate guard fatal error log"));
        assert!(main_source.contains("write_guard_fatal_log_file_exclusive"));
        assert!(main_source
            .contains("remove_existing_guard_fatal_log_file(&path, \"guard fatal error log\")"));
        assert!(main_source.contains(
            "cleanup_staged_guard_fatal_log(&temp_path, \"temporary guard fatal error log\")"
        ));
        assert!(!main_source.contains(&old_service_fatal_direct_write));
        assert!(service_source.contains("report_guard_fatal_error("));
        assert!(service_source.contains("\"guard_service_error.log\""));
        assert!(service_source.contains("failed to signal guard service shutdown"));
        assert!(driver_port_source.contains("report_guard_fatal_error(\"driver_port_error.log\""));
        assert!(!service_source.contains(&old_service_create));
        assert!(!service_source.contains(&old_service_write));
        assert!(!service_source.contains(&old_shutdown_signal));
        assert!(!driver_port_source.contains(&old_driver_create));
        assert!(!driver_port_source.contains(&old_driver_write));
        assert!(main_source.contains("event_log_base()?"));
        assert!(main_source.contains("fn absolute_guard_event_env_path"));
        assert!(main_source.contains("guard event log path environment {name} must be absolute"));
        assert!(!main_source.contains("PathBuf::from(\".avorax/events\")"));
        assert!(write_guard_fatal_error_log("../bad.log", "blocked").is_err());
    }

    #[test]
    fn event_log_base_rejects_relative_override_environment() {
        let _lock = env_lock();
        std::env::remove_var("ZENTOR_EVENT_LOG_DIR");
        std::env::set_var("AVORAX_EVENT_LOG_DIR", "relative-events");

        let error = event_log_base().unwrap_err().to_string();

        assert!(error.contains("AVORAX_EVENT_LOG_DIR must be absolute"));
        std::env::remove_var("AVORAX_EVENT_LOG_DIR");
    }

    #[test]
    fn event_log_base_rejects_parent_traversal_override_environment() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_EVENT_LOG_DIR");
        let dir = tempdir().unwrap();
        std::env::remove_var("ZENTOR_EVENT_LOG_DIR");
        std::env::set_var("AVORAX_EVENT_LOG_DIR", dir.path().join(".."));

        let error = event_log_base().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_EVENT_LOG_DIR", value),
            None => std::env::remove_var("AVORAX_EVENT_LOG_DIR"),
        }
        assert!(error.contains("AVORAX_EVENT_LOG_DIR"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[test]
    fn guard_process_stop_failures_are_not_suppressed_or_overclaimed() {
        let source = include_str!("main.rs");
        let handle_start = source.find("fn handle_process_started(").unwrap();
        let watch_start = source.find("fn watch_processes(").unwrap();
        let process_start_source = &source[handle_start..watch_start];
        let stop_start = source.find("fn stop_process(").unwrap();
        let quarantine_start = source.find("fn quarantine_file(").unwrap();
        let stop_source = &source[stop_start..quarantine_start];
        let quarantine_end = source.find("fn regular_guard_file_metadata").unwrap();
        let quarantine_source = &source[quarantine_start..quarantine_end];
        let old_stop_call = ["stop_", "process(pid);"].concat();
        let ignored_command = ["let _ = Command::", "new"].concat();

        assert!(process_start_source.contains("stop_process(pid).with_context"));
        assert!(process_start_source.contains("failed to stop process {pid}"));
        assert!(process_start_source.contains("stopRequestedAndQuarantined"));
        assert!(process_start_source.contains("No process id was supplied"));
        assert!(!process_start_source.contains(&old_stop_call));
        assert!(quarantine_source.contains("file_quarantined_without_process_stop"));
        assert!(quarantine_source.contains("process_stop_requested_and_file_quarantined"));
        assert!(stop_source.contains("fn stop_process(process_id: u32) -> anyhow::Result<()>"));
        assert!(stop_source.contains("windows_system32_tool(\"taskkill.exe\")?"));
        assert!(stop_source.contains("Command::new(&taskkill)"));
        assert!(stop_source.contains("run_guard_process_command("));
        assert!(stop_source.contains("GUARD_PROCESS_COMMAND_TIMEOUT"));
        assert!(stop_source.contains("non_windows_process_kill_tool()?"));
        assert!(stop_source.contains("Command::new(&kill)"));
        assert!(stop_source.contains("PathBuf::from(\"/bin/kill\")"));
        assert!(stop_source.contains("PathBuf::from(\"/usr/bin/kill\")"));
        assert!(stop_source.contains("fs::symlink_metadata(&candidate)"));
        assert!(stop_source.contains("output.status.success()"));
        assert!(stop_source.contains("command_output_excerpt(&output.stderr)"));
        let old_taskkill_launch = ["Command::new(\"", "taskkill\")"].concat();
        let old_kill_launch = ["Command::new(\"", "kill\")"].concat();
        assert!(!stop_source.contains(&old_taskkill_launch));
        assert!(!stop_source.contains(&old_kill_launch));
        assert!(!stop_source.contains(".output()"));
        assert!(!stop_source.contains(&ignored_command));
    }

    #[test]
    fn guard_process_path_accepts_regular_file_and_rejects_directory() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("process.exe");
        fs::write(&file, b"benign process fixture").unwrap();

        assert!(guard_process_path_is_regular_file(&file).unwrap());
        assert!(!guard_process_path_is_regular_file(dir.path()).unwrap());
        assert!(guard_process_directory_is_regular(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn guard_process_path_rejects_symbolic_link() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("process-target");
        let link = dir.path().join("process-link");
        fs::write(&target, b"benign process fixture").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(!guard_process_path_is_regular_file(&link).unwrap());
    }

    #[test]
    fn process_listing_uses_non_following_path_checks() {
        let source = include_str!("main.rs");
        let start = source.find("fn parse_windows_process_json").unwrap();
        let end = source.find("fn stop_process").unwrap();
        let process_source = &source[start..end];

        assert!(process_source.contains("guard_process_path_is_regular_file(&process.path)?"));
        assert!(process_source.contains("guard_process_directory_is_regular(proc)?"));
        assert!(process_source.contains("guard_process_path_is_regular_file(&path)?"));
        assert!(process_source.contains(
            "fn guard_process_path_is_regular_file(path: &Path) -> anyhow::Result<bool>"
        ));
        assert!(process_source.contains(
            "fn guard_process_directory_is_regular(path: &Path) -> anyhow::Result<bool>"
        ));
        assert!(process_source.contains("error.kind() == io::ErrorKind::NotFound"));
        assert!(process_source.contains("unable to inspect guard process path"));
        assert!(process_source.contains("unable to inspect guard process directory"));
        assert!(process_source.contains("fs::symlink_metadata(path)"));
        assert!(process_source.contains("metadata.file_type().is_symlink()"));
        assert!(!process_source.contains("Err(_) => false"));
        assert!(!process_source.contains("process.path.is_file()"));
        assert!(!process_source.contains("proc.is_dir()"));
        assert!(!process_source.contains("path.is_file()"));
    }

    #[test]
    fn process_skip_uses_component_aware_normalized_system_paths() {
        assert!(should_skip_process_path(Path::new(
            r"C:\Windows\System32\.\cmd.exe"
        )));
        assert!(should_skip_process_path(Path::new(
            r"C:\Windows\SysWOW64\rundll32.exe"
        )));
        assert!(should_skip_process_path(Path::new(
            r"C:\Windows\Explorer.exe"
        )));
        assert!(!should_skip_process_path(Path::new(
            r"C:\Windows\System32\..\Temp\payload.exe"
        )));
        assert!(!should_skip_process_path(Path::new(
            r"C:\Users\Brent\Windows\System32\payload.exe"
        )));
        assert!(should_skip_process_path(Path::new("/usr/./bin/true")));
        assert!(!should_skip_process_path(Path::new("/usr/../tmp/payload")));
    }

    #[test]
    fn windows_process_query_output_is_bounded() {
        let source = include_str!("main.rs");
        let start = source.find("fn list_processes_windows").unwrap();
        let end = start
            + source[start..]
                .find("#[derive(Debug, Deserialize)]")
                .unwrap();
        let process_source = &source[start..end];
        let old_stderr = ["String::from_utf8_lossy(&output.stderr", ")"].concat();
        let old_stdout_parse = [
            "parse_windows_process_json(&String::from_utf8_lossy(&output.stdout",
            "))",
        ]
        .concat();

        assert!(source.contains("MAX_WINDOWS_PROCESS_QUERY_BYTES"));
        assert!(process_source.contains("windows_system32_tool(\"powershell.exe\")?"));
        assert!(process_source.contains("powershell_encoded_command(script)"));
        assert!(process_source.contains("Command::new(&powershell)"));
        assert!(process_source.contains("run_guard_process_command("));
        assert!(process_source.contains("MAX_WINDOWS_PROCESS_QUERY_BYTES"));
        assert!(process_source.contains("GUARD_PROCESS_COMMAND_TIMEOUT"));
        assert!(process_source.contains("\"-EncodedCommand\""));
        assert!(process_source.contains("let second = if offset + 1 < bytes.len()"));
        assert!(process_source.contains("let third = if offset + 2 < bytes.len()"));
        assert!(process_source.contains("windows_process_query_text(&output.stdout)?"));
        assert!(process_source.contains("command_output_excerpt(&output.stderr)"));
        assert!(process_source.contains("Windows process query JSON exceeded"));
        let old_powershell_launch = ["Command::new(\"", "powershell\")"].concat();
        let old_command_arg = ["\"-Com", "mand\""].concat();
        let old_base64_padding_default = [".unwrap_or", "(0)"].concat();
        assert!(!process_source.contains(&old_powershell_launch));
        assert!(!process_source.contains(&old_command_arg));
        assert!(!process_source.contains(&old_base64_padding_default));
        assert!(!process_source.contains(&old_stderr));
        assert!(!process_source.contains(&old_stdout_parse));
        assert!(!process_source.contains(".output()"));
    }

    #[test]
    fn guard_process_commands_use_bounded_runner() {
        let source = crate::normalized_test_source(include_str!("main.rs"));
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let runner_start = source.find("fn run_guard_process_command").unwrap();
        let acl_start = source
            .find("#[cfg(windows)]\nstruct BoundedGuardCommandOutput")
            .unwrap();
        let runner_source = &source[runner_start..acl_start];
        let old_output = [".out", "put()"].concat();
        let old_unbounded_read = [".read_to_", "end(&mut bytes)"].concat();

        assert!(production.contains("const GUARD_PROCESS_COMMAND_TIMEOUT: Duration"));
        assert!(runner_source.contains("stdin(Stdio::null())"));
        assert!(runner_source.contains("stdout(Stdio::piped())"));
        assert!(runner_source.contains("stderr(Stdio::piped())"));
        assert!(runner_source.contains("read_bounded_guard_command_output(stdout, stdout_limit)"));
        assert!(runner_source.contains("read_bounded_guard_command_output(stderr, stderr_limit)"));
        assert!(runner_source.contains("wait_for_guard_process_child(&mut child, timeout)"));
        assert!(runner_source.contains("child.try_wait()?"));
        assert!(runner_source.contains("child.kill().err()"));
        assert!(runner_source.contains("child.wait().err()"));
        assert!(runner_source.contains("failed to kill timed-out guard process command"));
        assert!(runner_source.contains("failed to reap timed-out guard process command"));
        assert!(runner_source.contains("join_guard_command_output_reader"));
        assert!(production.contains("failed to read bounded guard command output"));
        assert!(!production.contains(&old_output));
        assert!(!runner_source.contains(&old_unbounded_read));
    }

    #[test]
    fn known_bad_cache_load_errors_are_not_defaulted_empty() {
        let source = include_str!("main.rs");
        let health_start = source.find("\"health\" =>").unwrap();
        let process_start = source.find("\"process_started\" =>").unwrap();
        let trust_source = &source[health_start..process_start];
        let defaulted_cache_pattern = ["load_known_bad_hashes()", ".unwrap_or_default()"].concat();

        assert!(trust_source.contains("known_bad_cache::load_known_bad_hashes()"));
        assert!(trust_source.contains("known-bad cache unavailable"));
        assert!(!trust_source.contains(&defaulted_cache_pattern));
    }

    #[test]
    fn guard_health_post_launch_fallback_is_derived_from_guard_mode() {
        let source = include_str!("main.rs");
        let health_start = source.find("\"health\" =>").unwrap();
        let process_start = source.find("\"process_started\" =>").unwrap();
        let health_source = &source[health_start..process_start];

        assert!(health_source.contains(
            "\"post_launch_fallback\": post_launch_fallback_available(&configured_guard_mode)"
        ));
        assert!(!health_source.contains("\"post_launch_fallback\": true"));
    }

    #[test]
    fn post_launch_fallback_is_unavailable_when_guard_is_disabled() {
        assert!(!post_launch_fallback_available(
            &preexecution_policy::DriverProtectionMode::Disabled
        ));
        assert!(post_launch_fallback_available(
            &preexecution_policy::DriverProtectionMode::ObserveOnly
        ));
        assert!(post_launch_fallback_available(
            &preexecution_policy::DriverProtectionMode::BlockConfirmedThreats
        ));
    }

    #[test]
    fn guard_hash_normalizers_do_not_default_invalid_values() {
        let main_source = include_str!("main.rs");
        let driver_source = include_str!("driver_ipc.rs");
        let self_test_source = include_str!("self_test.rs");
        let main_default = ["normalize_sha256(&value)", ".unwrap_or_default()"].concat();
        let borrowed_default = ["normalize_sha256(value)", ".unwrap_or_default()"].concat();

        assert!(main_source.contains("internal guard test hash must be a valid SHA-256 value"));
        assert!(
            driver_source.contains("internal driver IPC test hash must be a valid SHA-256 value")
        );
        assert!(self_test_source
            .contains("guard self-test generated hash is not a valid SHA-256 value"));
        assert!(!main_source.contains(&main_default));
        assert!(!driver_source.contains(&borrowed_default));
        assert!(!self_test_source.contains(&borrowed_default));
    }

    #[test]
    fn guard_mode_parser_accepts_user_visible_modes() {
        assert_eq!(
            parse_guard_mode("monitorOnly"),
            Some(preexecution_policy::DriverProtectionMode::ObserveOnly)
        );
        assert_eq!(
            parse_guard_mode("Block Confirmed Threats"),
            Some(preexecution_policy::DriverProtectionMode::BlockConfirmedThreats)
        );
        assert_eq!(
            parse_guard_mode("disabled"),
            Some(preexecution_policy::DriverProtectionMode::Disabled)
        );
        assert_eq!(
            parse_guard_mode("lockdown"),
            Some(preexecution_policy::DriverProtectionMode::Lockdown)
        );
    }

    #[test]
    fn configured_guard_mode_uses_avorax_environment() {
        let _lock = env_lock();
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE", "monitorOnly");

        assert_eq!(
            configured_guard_mode().unwrap(),
            preexecution_policy::DriverProtectionMode::ObserveOnly
        );

        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
    }

    #[test]
    fn configured_guard_mode_rejects_malformed_environment_override() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);
        std::env::set_var("AVORAX_GUARD_MODE", "block everything");
        fs::write(&config, r#"{"mode":"disabled"}"#).unwrap();

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("unsupported guard mode in environment AVORAX_GUARD_MODE"));
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn guard_mode_environment_override_errors_are_not_hidden() {
        let source = include_str!("main.rs");
        let configured_start = source.find("fn configured_guard_mode").unwrap();
        let configured_end = source.find("fn read_guard_mode_config").unwrap();
        let configured_slice = &source[configured_start..configured_end];

        assert!(configured_slice.contains("guard_mode_from_env()?"));
        assert!(configured_slice.contains("unsupported guard mode in environment"));
        assert!(!configured_slice.contains(".ok()"));
        assert!(!configured_slice.contains(".and_then(|value| parse_guard_mode(&value))"));
    }

    #[cfg(not(windows))]
    #[test]
    fn procfs_pid_parse_uses_explicit_branch() {
        use std::ffi::OsStr;

        assert_eq!(procfs_pid_from_file_name(OsStr::new("1234")), Some(1234));
        assert_eq!(procfs_pid_from_file_name(OsStr::new("self")), None);

        let source = include_str!("main.rs");
        let procfs_start = source.find("fn list_processes_procfs").unwrap();
        let procfs_end = source
            .find("fn guard_process_path_is_regular_file")
            .unwrap();
        let procfs_source = &source[procfs_start..procfs_end];

        assert!(procfs_source.contains("procfs_pid_from_file_name(&file_name)"));
        assert!(procfs_source.contains("match raw.parse::<u32>()"));
        assert!(!procfs_source.contains(".ok()"));
    }

    #[test]
    fn configured_guard_mode_reads_shared_config_file() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);
        fs::write(&config, r#"{"mode":"disabled"}"#).unwrap();

        assert_eq!(
            configured_guard_mode().unwrap(),
            preexecution_policy::DriverProtectionMode::Disabled
        );

        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn configured_guard_mode_rejects_relative_config_path_environment() {
        let _lock = env_lock();
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE_CONFIG");
        std::env::remove_var("AVORAX_CONFIG_DIR");
        std::env::remove_var("AVORAX_DATA_DIR");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", "relative-guard-mode.json");

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("AVORAX_GUARD_MODE_CONFIG must be absolute"));
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn configured_guard_mode_rejects_relative_config_base_environment() {
        let _lock = env_lock();
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
        std::env::remove_var("ZENTOR_GUARD_MODE_CONFIG");
        std::env::remove_var("AVORAX_DATA_DIR");
        std::env::set_var("AVORAX_CONFIG_DIR", "relative-config");

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("AVORAX_CONFIG_DIR must be absolute"));
        std::env::remove_var("AVORAX_CONFIG_DIR");
    }

    #[test]
    fn configured_guard_mode_rejects_parent_traversal_config_base_environment() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_CONFIG_DIR");
        let dir = tempdir().unwrap();
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
        std::env::remove_var("ZENTOR_GUARD_MODE_CONFIG");
        std::env::remove_var("AVORAX_DATA_DIR");
        std::env::set_var("AVORAX_CONFIG_DIR", dir.path().join(".."));

        let error = configured_guard_mode().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_CONFIG_DIR", value),
            None => std::env::remove_var("AVORAX_CONFIG_DIR"),
        }
        assert!(error.contains("AVORAX_CONFIG_DIR"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[cfg(not(windows))]
    #[test]
    fn guard_config_base_rejects_relative_home_environment() {
        let _lock = env_lock();
        let previous_home = std::env::var_os("HOME");
        std::env::remove_var("AVORAX_CONFIG_DIR");
        std::env::remove_var("AVORAX_DATA_DIR");
        std::env::set_var("HOME", "relative-home");

        let error = guard_config_base().unwrap_err().to_string();

        assert!(error.contains("HOME must be absolute"));
        if let Some(previous_home) = previous_home {
            std::env::set_var("HOME", previous_home);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn corrupt_guard_mode_config_is_not_defaulted() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);
        fs::write(&config, r#"{"mode":"blockEverything"}"#).unwrap();

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("unsupported guard mode in config"));
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn guard_mode_json_config_rejects_unknown_fields() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);
        fs::write(
            &config,
            r#"{"mode":"balanced","updated_at":"2024-01-01T00:00:00Z","source":"fixture","enabled":false}"#,
        )
        .unwrap();

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("unable to parse guard mode config"));
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn guard_mode_json_config_rejects_empty_source() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);
        fs::write(
            &config,
            r#"{"mode":"balanced","updated_at":"2024-01-01T00:00:00Z","source":" "}"#,
        )
        .unwrap();

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("guard mode config source is empty"));
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn guard_mode_json_config_rejects_oversized_mode_field() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);
        let long_mode = "b".repeat(MAX_GUARD_IPC_TEXT_CHARS + 1);
        let raw = serde_json::json!({
            "mode": long_mode,
            "updated_at": "2024-01-01T00:00:00Z",
            "source": "fixture"
        })
        .to_string();
        fs::write(&config, raw).unwrap();

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("guard mode config mode exceeds maximum length"));
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn oversized_guard_mode_config_is_rejected_before_parse() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);
        fs::write(
            &config,
            "x".repeat(MAX_GUARD_MODE_CONFIG_BYTES as usize + 1),
        )
        .unwrap();

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("exceeds maximum size"));
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn guard_text_readers_are_metadata_and_actual_byte_bounded() {
        let source = crate::normalized_test_source(include_str!("main.rs"));
        let config_start = source.find("fn read_bounded_guard_text").unwrap();
        let config_end = source.find("fn guard_config_file_present").unwrap();
        let config_source = &source[config_start..config_end];
        let quarantine_start = source
            .find("fn read_bounded_guard_quarantine_text")
            .unwrap();
        let quarantine_end = source
            .find("fn guard_quarantine_metadata_file_present")
            .unwrap();
        let quarantine_source = &source[quarantine_start..quarantine_end];

        assert!(
            config_source.contains("let metadata = ensure_regular_guard_config_file(path, label)?")
        );
        assert!(quarantine_source.contains(
            "let metadata = ensure_regular_guard_quarantine_metadata_file(path, label)?"
        ));
        assert!(source.contains("fn ensure_regular_guard_config_file(path: &Path, label: &str) -> anyhow::Result<fs::Metadata>"));
        assert!(source.contains(
            ") -> anyhow::Result<fs::Metadata> {\n    let metadata = fs::symlink_metadata(path)"
        ));
        assert!(config_source.contains("metadata.len() > max_bytes"));
        assert!(config_source.contains("let mut total = 0_u64"));
        assert!(config_source.contains("checked_add(read as u64)"));
        assert!(config_source.contains("total > max_bytes"));
        assert!(config_source.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(config_source.contains("String::from_utf8(bytes)"));
        assert!(quarantine_source
            .contains("read_bounded_guard_utf8_file(path, max_bytes, label, &metadata)"));
    }

    #[test]
    fn directory_guard_mode_config_is_rejected_before_read() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let config = dir.path().join("guard_mode.json");
        fs::create_dir(&config).unwrap();
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("not a regular file"));
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_guard_mode_config_is_rejected_before_read() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.json");
        let config = dir.path().join("guard_mode.json");
        fs::write(&target, r#"{"mode":"lockdown"}"#).unwrap();
        symlink(&target, &config).unwrap();
        std::env::remove_var("AVORAX_GUARD_MODE");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE_CONFIG", &config);

        let error = configured_guard_mode().unwrap_err().to_string();

        assert!(error.contains("symbolic link"));
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
    }

    #[test]
    fn guard_mode_config_read_path_safety_markers_stay_in_place() {
        let source = include_str!("main.rs");
        let read_start = source.find("fn read_guard_mode_config").unwrap();
        let path_start = source.find("fn guard_mode_config_path").unwrap();
        let read_source = &source[read_start..path_start];
        let presence_helper_pattern = ["guard_config_file_", "present"].concat();
        let read_guard_pattern = ["ensure_regular_guard_config_", "file(path, label)?"].concat();
        let metadata_helper_pattern = ["ensure_regular_guard_config_", "metadata"].concat();
        let reparse_pattern = ["guard_config_metadata_is_windows_", "reparse_point"].concat();
        let path_exists_pattern = ["path", ".exists()"].concat();

        assert!(read_source.contains(&presence_helper_pattern));
        assert!(source.contains(&read_guard_pattern));
        assert!(source.contains(&metadata_helper_pattern));
        assert!(source.contains(&reparse_pattern));
        assert!(source.contains("fn absolute_guard_env_path"));
        assert!(source.contains("guard config path environment {name} must be absolute"));
        assert!(source.contains("guard_config_base()?.join(\"guard_mode.json\")"));
        assert!(source.contains("no absolute guard config directory is configured"));
        assert!(source.contains("absolute_guard_env_path(\"HOME\")?"));
        assert!(!source.contains("PathBuf::from(\".avorax/config\")"));
        assert!(!read_source.contains(&path_exists_pattern));
    }

    #[test]
    fn guard_mode_json_config_schema_and_values_stay_strict() {
        let source = include_str!("main.rs");
        let struct_start = source.find("struct GuardModeConfigFile").unwrap();
        let read_start = source.find("fn read_guard_mode_config").unwrap();
        let read_end = source.find("fn read_bounded_guard_text").unwrap();
        let read_source = &source[read_start..read_end];

        assert!(source[..struct_start].contains("#[serde(deny_unknown_fields)]"));
        assert!(
            read_source.contains("let config: GuardModeConfigFile = serde_json::from_str(&text)")
        );
        assert!(read_source.contains("guard_mode_from_config_file(config)"));
        assert!(read_source
            .contains("validate_guard_mode_config_text(&mode, \"guard mode config mode\")?"));
        assert!(read_source
            .contains("validate_guard_mode_config_text(source, \"guard mode config source\")?"));
        assert!(read_source.contains("guard mode config source is empty"));
        assert!(read_source.contains("value.contains('\\0')"));
        assert!(!read_source.contains("serde_json::Value"));
        assert!(!read_source.contains(".get(\"mode\")"));
    }

    #[test]
    fn guard_command_serialization_errors_are_not_reported_as_success() {
        let source = include_str!("main.rs");
        let handle_start = source.find("fn handle(").unwrap();
        let sanitize_start = source.find("fn sanitize_external_driver_request").unwrap();
        let handle_source = &source[handle_start..sanitize_start];
        let health_fallback = ["Avorax Guard", " Service ready"].concat();
        let verdict_fallback = ["driver verdict", " created"].concat();
        let self_test_fallback = ["driver self-test", " completed"].concat();

        assert!(handle_source.contains("health serialization failed"));
        assert!(handle_source.contains("driver verdict serialization failed"));
        assert!(handle_source.contains("driver self-test serialization failed"));
        assert!(!handle_source.contains(&health_fallback));
        assert!(!handle_source.contains(&verdict_fallback));
        assert!(!handle_source.contains(&self_test_fallback));
    }

    #[test]
    fn direct_process_start_native_errors_are_not_defaulted_to_no_match() {
        let source = include_str!("main.rs");
        let start = source.find("fn handle_process_started(").unwrap();
        let end = source.find("fn watch_processes(").unwrap();
        let process_start_source = &source[start..end];
        let old_pattern = ["native_threat_match(process_path)", ".unwrap_or(None)"].concat();

        assert!(process_start_source.contains("process native inspection failed"));
        assert!(!process_start_source.contains(&old_pattern));
    }

    #[test]
    fn external_driver_scan_ignores_caller_supplied_trusted_publisher() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let file = dir.path().join("spoofed-signed.exe");
        fs::write(&file, b"unsigned fixture with spoofed publisher").unwrap();
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE", "lockdown");

        let mut request = driver_request_for(&file);
        request.signature_status = Some("valid".to_string());
        request.publisher = Some("Microsoft Corporation".to_string());
        request.signature_verified_by = Some("windows_wintrust".to_string());

        let event = handle(GuardCommand {
            command: "driver_scan_request".to_string(),
            process_id: None,
            process_path: None,
            known_malicious_hashes: None,
            known_good_hashes: None,
            user_approved_hashes: None,
            protection_mode: Some(preexecution_policy::DriverProtectionMode::Disabled),
            poll_interval_ms: None,
            max_iterations: None,
            scan_request: Some(request),
        });
        let verdict = driver_verdict_from_event(&event);

        assert!(event.ok);
        assert_eq!(verdict.action, driver_ipc::DriverVerdictAction::Block);
        assert_eq!(
            verdict.trust_level,
            driver_ipc::ApplicationTrustLevel::Unknown
        );
        assert!(verdict.requires_user_approval);

        std::env::remove_var("AVORAX_GUARD_MODE");
    }

    #[test]
    fn external_driver_scan_ignores_caller_supplied_known_good_hash() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let trusted = dir.path().join("trusted.exe");
        let spoofed = dir.path().join("spoofed.exe");
        fs::write(&trusted, b"trusted fixture").unwrap();
        fs::write(&spoofed, b"different unsigned fixture").unwrap();
        let trusted_hash = sha256_file(&trusted).unwrap();
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE", "lockdown");

        let mut request = driver_request_for(&spoofed);
        request.sha256 = Some(trusted_hash.clone());
        request.sha256_verified_by = Some("avorax_kernel_driver".to_string());

        let event = handle(GuardCommand {
            command: "driver_scan_request".to_string(),
            process_id: None,
            process_path: None,
            known_malicious_hashes: None,
            known_good_hashes: Some(vec![normalize_hash(trusted_hash)]),
            user_approved_hashes: None,
            protection_mode: Some(preexecution_policy::DriverProtectionMode::Disabled),
            poll_interval_ms: None,
            max_iterations: None,
            scan_request: Some(request),
        });
        let verdict = driver_verdict_from_event(&event);

        assert!(event.ok);
        assert_eq!(verdict.action, driver_ipc::DriverVerdictAction::Block);
        assert_eq!(
            verdict.trust_level,
            driver_ipc::ApplicationTrustLevel::Unknown
        );
        assert!(verdict.requires_user_approval);

        std::env::remove_var("AVORAX_GUARD_MODE");
    }

    #[test]
    fn medium_native_script_match_is_review_only_and_not_stopped() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("script.ps1");
        fs::write(&file, "[Convert]::FromBase64String('AAAA')").unwrap();

        let result = handle_process_started(
            Some(4242),
            &file,
            &HashSet::new(),
            preexecution_policy::DriverProtectionMode::BlockConfirmedThreats,
        )
        .unwrap();
        assert_eq!(result.action, "monitored");
        assert!(file.exists());
    }

    #[test]
    fn guard_native_asset_marker_accepts_regular_directory() {
        let dir = tempdir().unwrap();

        assert!(native_asset_marker_dir_is_regular(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn guard_native_asset_marker_rejects_symbolic_link() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("assets-target");
        let link = dir.path().join("zentor_native");
        fs::create_dir_all(&target).unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        assert!(!native_asset_marker_dir_is_regular(&link).unwrap());
    }

    #[test]
    fn guard_native_asset_root_marker_uses_non_following_checks() {
        let source = include_str!("main.rs");
        let start = source.find("fn native_asset_root").unwrap();
        let end = source.find("fn compat_threat_match").unwrap();
        let root_source = &source[start..end];
        let old_current_dir_push = ["roots.push", "(current_dir"].concat();

        assert!(root_source.contains("native_asset_marker_dir_is_regular"));
        assert!(root_source.contains("fn native_asset_root() -> anyhow::Result<PathBuf>"));
        assert!(root_source.contains(
            "fn native_asset_marker_dir_is_regular(path: &Path) -> anyhow::Result<bool>"
        ));
        assert!(root_source.contains("error.kind() == io::ErrorKind::NotFound"));
        assert!(root_source.contains("unable to inspect guard native asset marker"));
        assert!(root_source.contains("guard_asset_root_candidates"));
        assert!(root_source.contains("failed to resolve current executable"));
        assert!(root_source.contains("push_guard_executable_asset_roots"));
        assert!(root_source.contains("#[cfg(debug_assertions)]"));
        assert!(root_source.contains("is_guard_development_root(root)?"));
        assert!(root_source.contains(".join(\"core\")"));
        assert!(root_source.contains(".join(\"zentor_guard_service\")"));
        assert!(root_source.contains("Cargo.toml"));
        assert!(root_source.contains("guard asset root {} must be an absolute local path"));
        assert!(root_source.contains("fs::symlink_metadata(path)"));
        assert!(root_source.contains("metadata.file_type().is_symlink()"));
        assert!(!root_source.contains("Err(_) => false"));
        assert!(!root_source.contains(".exists()"));
        assert!(!root_source.contains("PathBuf::from(\".\")"));
        assert!(!root_source.contains(&old_current_dir_push));
    }

    #[test]
    fn disabled_mode_observes_confirmed_hash_without_quarantine() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"known bad fixture").unwrap();
        let hash = sha256_file(&file).unwrap();

        let result = handle_process_started(
            None,
            &file,
            &HashSet::from([hash]),
            preexecution_policy::DriverProtectionMode::Disabled,
        )
        .unwrap();

        assert_eq!(result.action, "reviewOnly");
        assert!(file.exists());
        assert!(result.quarantine_path.is_none());
    }

    #[test]
    fn guard_sha256_file_streams_full_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("large.bin");
        let bytes = vec![b'G'; 2 * 1024 * 1024 + 31];
        fs::write(&file, &bytes).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let expected = format!("sha256:{:x}", hasher.finalize());

        assert_eq!(sha256_file(&file).unwrap(), expected);
    }

    #[test]
    fn guard_sha256_file_rejects_directory_before_read() {
        let dir = tempdir().unwrap();

        let error = sha256_file(dir.path()).unwrap_err().to_string();

        assert!(error.contains("file to hash"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn guard_sha256_file_rejects_symbolic_link_before_read() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.bin");
        let link = dir.path().join("link.bin");
        fs::write(&target, b"benign hash fixture").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = sha256_file(&link).unwrap_err().to_string();

        assert!(error.contains("refusing to use symbolic link file to hash"));
    }

    #[test]
    fn guard_sha256_file_uses_non_following_regular_file_guard() {
        let source = include_str!("main.rs");
        let start = source.find("fn sha256_file").unwrap();
        let end = source.find("fn normalize_sha256").unwrap();
        let sha_source = &source[start..end];

        assert!(source.contains("const MAX_GUARD_HASH_BYTES"));
        assert!(sha_source
            .contains("let metadata = regular_guard_file_metadata(path, \"file to hash\")?"));
        assert!(sha_source.contains("metadata.len() > MAX_GUARD_HASH_BYTES"));
        assert!(sha_source.contains("fs::File::open(path)?"));
        assert!(sha_source.contains("let mut total = 0_u64"));
        assert!(sha_source.contains("checked_add(read as u64)"));
        assert!(sha_source.contains("total > MAX_GUARD_HASH_BYTES"));
        assert!(sha_source.contains("hasher.update(&buffer[..read])"));
    }

    #[test]
    fn guard_command_rejects_oversized_json_before_parse() {
        let raw = "x".repeat(MAX_GUARD_COMMAND_JSON_BYTES + 1);

        let error = parse_guard_command_line(&raw).unwrap_err().to_string();

        assert!(error.contains("guard command JSON"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn guard_command_reader_rejects_oversized_json_before_line_allocation() {
        let raw = "x".repeat(MAX_GUARD_COMMAND_JSON_BYTES + 1);
        let mut reader = io::Cursor::new(raw.into_bytes());

        let error = read_next_guard_command_line(&mut reader)
            .unwrap_err()
            .to_string();

        assert!(error.contains("guard command JSON"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn guard_command_rejects_unknown_json_fields() {
        let error = parse_guard_command_line(r#"{"command":"health","confirmed":true}"#)
            .unwrap_err()
            .to_string();

        assert!(error.contains("failed to parse guard command JSON"));
    }

    #[test]
    fn guard_command_rejects_unknown_scan_request_fields() {
        let raw = serde_json::json!({
            "command": "driver_scan_request",
            "scan_request": {
                "request_id": "fixture-request",
                "event_type": "image_execute_attempt",
                "file_path": "C:/Temp/fixture.exe",
                "timestamp_utc": "2024-01-01T00:00:00Z",
                "allow_anyway": true
            }
        })
        .to_string();

        let error = parse_guard_command_line(&raw).unwrap_err().to_string();

        assert!(error.contains("failed to parse guard command JSON"));
    }

    #[test]
    fn guard_command_schema_stays_strict() {
        let source = crate::normalized_test_source(include_str!("main.rs"));
        let driver_source = crate::normalized_test_source(include_str!("driver_ipc.rs"));
        let command_start = source.find("struct GuardCommand").unwrap();
        let config_start = source.find("struct GuardModeConfigFile").unwrap();
        let scan_request_start = driver_source.find("pub struct ScanRequest").unwrap();
        let verdict_start = driver_source.find("pub enum DriverVerdictAction").unwrap();
        let parser_start = source.find("fn parse_guard_command_line").unwrap();
        let parser_end = source.find("#[cfg(windows)]\nwindows_service").unwrap();
        let parser_source = &source[parser_start..parser_end];

        assert!(source[..command_start].contains("#[serde(deny_unknown_fields)]"));
        assert!(source[command_start..config_start]
            .contains("scan_request: Option<driver_ipc::ScanRequest>"));
        assert!(driver_source[..scan_request_start].contains("#[serde(deny_unknown_fields)]"));
        assert!(driver_source[scan_request_start..verdict_start]
            .contains("pub signature_verified_by: Option<String>"));
        assert!(parser_source.contains("serde_json::from_str(line)"));
        assert!(parser_source.contains("failed to parse guard command JSON"));
    }

    #[test]
    fn guard_bounded_line_chunk_consumption_is_explicit() {
        let source = include_str!("main.rs");
        let start = source.find("fn read_next_bounded_line").unwrap();
        let end = source.find("fn parse_guard_command_line").unwrap();
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
    fn command_known_bad_hashes_are_normalized_or_rejected() {
        let raw = "A".repeat(64);
        let prefixed = format!("sha256:{}", "b".repeat(64));
        let hashes = normalize_command_hashes(Some(vec![raw, prefixed])).unwrap();

        assert!(hashes.contains(&format!("sha256:{}", "a".repeat(64))));
        assert!(hashes.contains(&format!("sha256:{}", "b".repeat(64))));
        assert!(normalize_command_hashes(Some(vec!["not-a-sha256".to_string()])).is_err());
    }

    #[test]
    fn guard_main_hash_prefix_branch_is_explicit() {
        let source = include_str!("main.rs");
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let native_start = source.find("fn native_threat_match").unwrap();
        let normalize_source = &source[normalize_start..native_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("match trimmed.strip_prefix(\"sha256:\")"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or"));
    }

    #[test]
    fn command_known_bad_hashes_reject_excessive_entries() {
        let values = vec!["a".repeat(64); MAX_GUARD_IPC_HASHES + 1];

        let error = normalize_command_hashes(Some(values))
            .unwrap_err()
            .to_string();

        assert!(error.contains("known malicious SHA-256 list"));
        assert!(error.contains("exceeds maximum"));
    }

    #[test]
    fn process_started_rejects_oversized_ipc_path() {
        let mut command = guard_command("process_started");
        command.process_path = Some("x".repeat(MAX_GUARD_IPC_PATH_CHARS + 1));

        let event = handle(command);

        assert!(!event.ok);
        assert!(event.message.contains("process_path"));
        assert!(event.message.contains("exceeds maximum length"));
    }

    #[test]
    fn process_started_rejects_nul_ipc_path() {
        let mut command = guard_command("process_started");
        command.process_path = Some("C:\\Temp\\bad\0.exe".to_string());

        let event = handle(command);

        assert!(!event.ok);
        assert!(event.message.contains("process_path"));
        assert!(event.message.contains("NUL"));
    }

    #[test]
    fn driver_scan_request_rejects_oversized_file_path() {
        let mut command = guard_command("driver_scan_request");
        let mut request = driver_request_for(Path::new("C:\\Temp\\tool.exe"));
        request.file_path = "x".repeat(MAX_GUARD_IPC_PATH_CHARS + 1);
        command.scan_request = Some(request);

        let event = handle(command);

        assert!(!event.ok);
        assert!(event.message.contains("scan_request.file_path"));
        assert!(event.message.contains("exceeds maximum length"));
    }

    #[test]
    fn external_driver_scan_ignores_caller_supplied_normalized_path() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let clean = dir.path().join("clean.exe");
        let bad = dir.path().join("bad.exe");
        fs::write(&clean, b"ordinary fixture").unwrap();
        fs::write(&bad, b"known bad fixture").unwrap();
        let bad_hash = sha256_file(&bad).unwrap();
        std::env::remove_var("AVORAX_GUARD_MODE_CONFIG");
        std::env::remove_var("AVORAX_PROTECTION_MODE");
        std::env::remove_var("ZENTOR_GUARD_MODE");
        std::env::set_var("AVORAX_GUARD_MODE", "balanced");

        let mut request = driver_request_for(&clean);
        request.normalized_file_path = Some(bad.display().to_string());
        let mut command = guard_command("driver_scan_request");
        command.known_malicious_hashes = Some(vec![bad_hash]);
        command.scan_request = Some(request);

        let event = handle(command);
        let verdict = driver_verdict_from_event(&event);

        assert!(event.ok);
        let clean_path = clean.display().to_string();
        assert_eq!(event.process_path.as_deref(), Some(clean_path.as_str()));
        assert_eq!(
            verdict.action,
            driver_ipc::DriverVerdictAction::AllowAndMonitor
        );

        std::env::remove_var("AVORAX_GUARD_MODE");
    }

    #[cfg(feature = "compat_yara")]
    #[test]
    fn guard_yara_reader_uses_bounded_sample() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("large-script.ps1");
        let mut bytes = vec![b'A'; GUARD_YARA_SAMPLE_LIMIT_BYTES as usize + 1];
        bytes.extend_from_slice(b"ZENTOR-SHOULD-NOT-BE-READ");
        fs::write(&file, bytes).unwrap();

        let sample = read_bounded_sample(&file, GUARD_YARA_SAMPLE_LIMIT_BYTES).unwrap();

        assert_eq!(sample.len(), GUARD_YARA_SAMPLE_LIMIT_BYTES as usize);
        assert!(!String::from_utf8_lossy(&sample).contains("ZENTOR-SHOULD-NOT-BE-READ"));
    }

    #[test]
    fn guard_compat_scan_targets_use_regular_file_metadata() {
        let source = crate::normalized_test_source(include_str!("main.rs"));
        let clamav_start = source.find("fn clamav_signature_match").unwrap();
        let clamav_end = source[clamav_start..]
            .find("#[cfg(any(feature = \"compat_clamav\", test))]")
            .map(|offset| clamav_start + offset)
            .unwrap();
        let clamav_source = &source[clamav_start..clamav_end];
        let yara_start = source.find("fn yara_rule_match").unwrap();
        let sample_end = source
            .find("#[cfg(any(feature = \"compat_yara\", test))]\nfn read_bounded_guard_yara_rules")
            .unwrap();
        let yara_source = &source[yara_start..sample_end];

        assert!(clamav_source
            .contains("regular_guard_file_metadata(path, \"guard ClamAV scan target\")?"));
        assert!(
            yara_source.contains("regular_guard_file_metadata(path, \"guard YARA scan target\")?")
        );
        assert!(yara_source.contains("fn read_bounded_sample(path: &Path, limit: u64)"));
        assert!(!clamav_source.contains("path.is_file()"));
        assert!(!yara_source.contains("path.is_file()"));
    }

    #[test]
    fn guard_yara_best_match_selection_has_explicit_empty_branch() {
        let source = include_str!("main.rs");
        let start = source.find("fn yara_rule_match").unwrap();
        let end = source.find("fn read_bounded_sample").unwrap();
        let yara_source = &source[start..end];
        let old_hidden_default = [".unwrap_or", "(true)"].concat();

        assert!(yara_source.contains("let should_replace_best = match best.as_ref()"));
        assert!(yara_source.contains("Some(existing)"));
        assert!(yara_source.contains("None => true"));
        assert!(!yara_source.contains(&old_hidden_default));
    }

    #[test]
    fn guard_yara_rule_header_names_are_explicit() {
        let source = include_str!("main.rs");
        let start = source.find("fn yara_rule_match").unwrap();
        let end = source.find("fn read_bounded_sample").unwrap();
        let yara_source = &source[start..end];
        let confidence_start = source.find("fn confidence_from_yara").unwrap();
        let confidence_end = source.find("fn confidence_rank").unwrap();
        let confidence_source = &source[confidence_start..confidence_end];
        let old_default_rule = ["zentor", "_yara_rule"].concat();

        assert!(yara_source.contains("let Some(rule_name) = yara_rule_name(trimmed) else"));
        assert!(yara_source.contains("guard YARA rule header is malformed"));
        assert!(
            yara_source.contains("guard YARA rule {current_rule} confidence metadata is malformed")
        );
        assert!(source.contains("guard YARA rule {rule_name} confidence metadata is unsupported"));
        assert!(source.contains("fn confidence_from_yara(rule_name: &str, value: &str) -> anyhow::Result<LocalThreatConfidence>"));
        assert!(
            yara_source.contains("guard YARA rule {current_rule} string declaration is malformed")
        );
        assert!(yara_source.contains("guard YARA rule {current_rule} string pattern is malformed"));
        assert!(yara_source.contains("if current_rule.is_empty()"));
        assert!(yara_source.contains("fn yara_rule_name(line: &str) -> Option<String>"));
        assert!(yara_source.contains("fn is_yara_rule_identifier(value: &str) -> bool"));
        assert!(!yara_source.contains(&old_default_rule));
        assert!(!confidence_source.contains("_ => LocalThreatConfidence::Low"));
        assert!(!yara_source.contains(
            "let Some((_, value)) = trimmed.split_once('=') else {\n                continue;"
        ));
        assert!(!yara_source.contains(
            "let Some(pattern) = quoted_value(value.trim()) else {\n                continue;"
        ));
    }

    #[test]
    fn guard_yara_rule_reader_rejects_oversized_rules_before_parse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("oversized.yar");
        fs::write(
            &path,
            "x".repeat(GUARD_YARA_RULE_TEXT_LIMIT_BYTES as usize + 1),
        )
        .unwrap();

        let error = read_bounded_guard_yara_rules(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("guard YARA rules"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn guard_yara_rule_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("main.rs");
        let start = source.find("fn read_bounded_guard_yara_rules").unwrap();
        let end = source.find("fn guard_yara_rules_file_present").unwrap();
        let reader = &source[start..end];

        assert!(reader.contains("let metadata = ensure_regular_guard_yara_rules(path)?"));
        assert!(reader.contains("metadata.len() > GUARD_YARA_RULE_TEXT_LIMIT_BYTES"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > GUARD_YARA_RULE_TEXT_LIMIT_BYTES"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
        assert!(source.contains(
            "fn ensure_regular_guard_yara_rules(path: &Path) -> anyhow::Result<fs::Metadata>"
        ));
    }

    #[test]
    fn guard_yara_rules_missing_file_is_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.yar");

        assert!(!guard_yara_rules_file_present(&path).unwrap());
    }

    #[test]
    fn guard_yara_rule_reader_rejects_directory_before_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rules.yar");
        fs::create_dir(&path).unwrap();

        let error = read_bounded_guard_yara_rules(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("guard YARA rules"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn guard_yara_rule_reader_rejects_symbolic_link_before_read() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.yar");
        let path = dir.path().join("rules.yar");
        fs::write(&target, "rule Safe { condition: false }").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = read_bounded_guard_yara_rules(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("guard YARA rules"));
        assert!(error.contains("symbolic link"));
        assert!(guard_yara_rules_file_present(&path).unwrap());
    }

    #[test]
    fn guard_yara_default_rules_path_uses_non_following_presence_checks() {
        let source = crate::normalized_test_source(include_str!("main.rs"));
        let start = source.find("fn default_yara_rules_path").unwrap();
        let end = source.find("fn metadata_value").unwrap();
        let default_path_source = &source[start..end];
        let old_optional_current_dir = ["if let Ok", "(current_dir)"].concat();
        let old_current_dir_fallback = ["current_dir", ".join"].concat();

        assert!(default_path_source.contains("guard_yara_rules_file_present(&candidate)?"));
        assert!(default_path_source.contains("Ok(candidate)"));
        assert!(default_path_source.contains("guard_asset_root_candidates"));
        assert!(default_path_source.contains("guard YARA default-rule discovery"));
        assert!(default_path_source.contains("found no controlled roots"));
        assert!(default_path_source.contains(
            "Ok(root\n        .join(\"assets\")\n        .join(\"yara\")\n        .join(\"zentor_core_rules.yar\"))"
        ));
        assert!(!default_path_source.contains("candidate.is_file()"));
        assert!(!default_path_source.contains(&old_optional_current_dir));
        assert!(!default_path_source.contains(&old_current_dir_fallback));
        assert!(!default_path_source.contains("PathBuf::from(\"assets/yara"));
    }

    #[test]
    fn guard_clamscan_path_missing_is_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing-clamscan.exe");

        assert!(!guard_clamscan_path_present(&path).unwrap());
    }

    #[test]
    fn guard_clamscan_path_rejects_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clamscan.exe");
        fs::create_dir(&path).unwrap();

        let error = ensure_regular_guard_clamscan(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("ClamAV scanner"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn guard_clamscan_path_rejects_symbolic_link() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("clamscan-target");
        let path = dir.path().join("clamscan");
        fs::write(&target, b"benign scanner fixture").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = ensure_regular_guard_clamscan(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("ClamAV scanner"));
        assert!(error.contains("symbolic link"));
        assert!(guard_clamscan_path_present(&path).unwrap());
    }

    #[test]
    fn guard_configured_clamscan_path_rejects_parent_traversal_text() {
        let traversal_error =
            validate_guard_configured_clamscan_text("C:\\Avorax\\..\\ClamAV\\clamscan.exe")
                .unwrap_err()
                .to_string();
        let nul_error = validate_guard_configured_clamscan_text("C:\\Avorax\\clam\0scan.exe")
            .unwrap_err()
            .to_string();

        assert!(traversal_error.contains("must not contain parent traversal"));
        assert!(nul_error.contains("contains NUL"));
    }

    #[test]
    fn guard_clamscan_discovery_uses_non_following_path_checks() {
        let source = include_str!("main.rs");
        let start = source.find("fn find_clamscan").unwrap();
        let end = source.find("fn should_skip_process_path").unwrap();
        let clamscan_source = &source[start..end];
        let old_optional_current_dir = ["if let Ok", "(current_dir)"].concat();

        assert!(clamscan_source.contains("ensure_regular_guard_clamscan_executable(&path)?"));
        assert!(clamscan_source.contains("guard_clamscan_executable_present(&candidate)?"));
        assert!(clamscan_source
            .contains("fn ensure_guard_clamscan_location(path: &Path) -> anyhow::Result<()>"));
        assert!(clamscan_source.contains("fn guard_clamscan_path_is_local(path: &Path) -> bool"));
        assert!(clamscan_source
            .contains("failed to read current executable path for guard ClamAV discovery"));
        assert!(clamscan_source.contains("must be an absolute path"));
        assert!(clamscan_source.contains("must be on a local path"));
        assert!(clamscan_source.contains("fs::symlink_metadata(path)"));
        assert!(clamscan_source.contains("metadata.file_type().is_symlink()"));
        assert!(!clamscan_source.contains("path.is_file()"));
        assert!(!clamscan_source.contains("candidate.is_file()"));
        assert!(!clamscan_source.contains("let mut current_dir_error"));
        assert!(!clamscan_source.contains("std::env::current_dir"));
        assert!(!clamscan_source.contains(&old_optional_current_dir));
    }

    #[test]
    fn guard_external_command_outputs_are_bounded() {
        let long = vec![b'a'; MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES + 16];
        let text = read_bounded_guard_clamav_output(long.as_slice(), "test").unwrap();
        assert!(text.ends_with("...[truncated]"));
        assert_eq!(
            text.len(),
            MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES + "...[truncated]".len()
        );

        let source = crate::normalized_test_source(include_str!("main.rs"));
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let clamav_start = source.find("fn clamav_signature_match").unwrap();
        let clamav_end = source[clamav_start..]
            .find("#[cfg(feature = \"compat_yara\")]")
            .map(|offset| clamav_start + offset)
            .unwrap();
        let clamav_source = &source[clamav_start..clamav_end];
        let acl_start = source.find("fn harden_quarantine_base_acl").unwrap();
        let acl_end = source
            .find("#[cfg(windows)]\nfn current_windows_account")
            .unwrap();
        let acl_source = &source[acl_start..acl_end];
        let old_stdout = ["String::from_utf8_lossy(&output.stdout", ")"].concat();
        let old_stderr = ["String::from_utf8_lossy(&output.stderr", ")"].concat();

        assert!(clamav_source.contains("run_guard_clamav_command(&mut process)?"));
        assert!(clamav_source.contains("MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES"));
        assert!(clamav_source.contains("GUARD_CLAMAV_SCAN_TIMEOUT"));
        assert!(clamav_source.contains("failed to reap timed-out guard ClamAV scanner"));
        assert!(acl_source.contains("fn harden_quarantine_base_acl(_path: &Path)"));
        assert!(acl_source.contains("windows_system32_tool(\"icacls.exe\")?"));
        assert!(acl_source.contains("Command::new(&icacls)"));
        assert!(acl_source.contains("let system_root = guard_windows_system_root()?;"));
        assert!(acl_source.contains("fn guard_windows_system_root() -> anyhow::Result<PathBuf>"));
        assert!(acl_source.contains("normalize_guard_windows_system_root_text(&text)"));
        assert!(acl_source.contains("PathBuf::from(normalized_root)"));
        assert!(acl_source.contains("for key in [\"SystemRoot\", \"WINDIR\"]"));
        assert!(acl_source.contains("std::env::var_os(key)"));
        assert!(acl_source.contains("Guard Windows System32 tool root is unavailable"));
        assert!(acl_source.contains("Guard Windows system root must not contain parent traversal"));
        assert!(acl_source
            .contains("fn collapse_guard_windows_system_root_segments(path: &str) -> String"));
        assert!(acl_source.contains("fn split_guard_windows_system_root_prefix(path: &str)"));
        assert!(acl_source.contains("collapse_guard_windows_system_root_segments(&normalized)"));
        assert!(acl_source.contains("match part {\n            \"\" | \".\" => {}"));
        assert!(acl_source.contains("system_root.join(\"System32\").join(name)"));
        assert!(acl_source.contains("fs::symlink_metadata(&candidate)"));
        assert!(acl_source.contains("guard_metadata_is_reparse_point(&metadata)"));
        assert!(acl_source.contains("Prefix::Disk(_) | Prefix::VerbatimDisk(_)"));
        assert!(acl_source.contains("run_guard_acl_command(&mut command)?"));
        assert!(source.contains("fn run_guard_acl_command(command: &mut Command)"));
        assert!(production
            .contains("read_bounded_guard_command_output(stderr, MAX_GUARD_COMMAND_OUTPUT_BYTES)"));
        assert!(production.contains("let retain_limit = max_bytes.saturating_add(1)"));
        assert!(production.contains("let remaining = retain_limit.saturating_sub(bytes.len())"));
        assert!(production.contains("bytes.extend_from_slice(&buffer[..keep])"));
        assert!(!production.contains("reader.take((max_bytes + 1) as u64)"));
        assert!(production.contains(
            "let retain_limit = MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES.saturating_add(1)"
        ));
        assert!(
            !production.contains("reader.take((MAX_GUARD_CLAMAV_COMMAND_OUTPUT_BYTES + 1) as u64)")
        );
        assert!(production.contains("stdin(Stdio::null())"));
        assert!(production.contains("stdout(Stdio::null())"));
        assert!(production.contains("stderr(Stdio::piped())"));
        assert!(acl_source.contains(".arg(_path)"));
        assert!(acl_source.contains("command_output_excerpt(&output.stderr)"));
        let old_windows_root_fallback = ["PathBuf::from(r\"", "C:\\Windows", "\")"].concat();
        let old_env_string_reader = ["std::env::", "var(key)"].concat();
        let old_silent_env_error = [".", "ok()"].concat();
        let old_icacls_launch = ["Command::new(\"", "icacls\")"].concat();
        assert!(!clamav_source.contains(".output()?"));
        assert!(!clamav_source.contains("command_output_excerpt(&output.stdout)"));
        assert!(!clamav_source.contains("command_output_excerpt(&output.stderr)"));
        assert!(!clamav_source.contains(&old_stdout));
        assert!(!clamav_source.contains(&old_stderr));
        assert!(!acl_source.contains(&old_stderr));
        assert!(!acl_source.contains(".output()?"));
        assert!(!acl_source.contains(&old_windows_root_fallback));
        assert!(!acl_source.contains(&old_env_string_reader));
        assert!(!acl_source.contains(&old_silent_env_error));
        assert!(!acl_source.contains(&old_icacls_launch));
        assert!(!acl_source.contains("PathBuf::from(text)"));
        assert!(!acl_source.contains("let _ = path;"));
    }

    #[test]
    fn guard_clamav_scanner_failures_are_not_clean_no_match() {
        let source = include_str!("main.rs");
        let clamav_start = source.find("fn clamav_signature_match").unwrap();
        let clamav_end = source[clamav_start..]
            .find("#[cfg(feature = \"compat_yara\")]")
            .map(|offset| clamav_start + offset)
            .unwrap();
        let clamav_source = &source[clamav_start..clamav_end];
        let old_error_as_no_match = [
            "if status.code() != Some(1) {\n",
            "        return Ok(None);\n",
            "    }",
        ]
        .concat();

        assert!(clamav_source.contains("if status.success()"));
        assert!(clamav_source.contains("return Ok(None);"));
        assert!(clamav_source.contains("if status.code() != Some(1)"));
        assert!(clamav_source.contains("guard ClamAV scanner failed with status"));
        assert!(!clamav_source.contains(&old_error_as_no_match));
    }

    #[test]
    fn guard_clamav_infected_exit_always_returns_detection() {
        let source = include_str!("main.rs");
        let clamav_start = source.find("fn clamav_signature_match").unwrap();
        let clamav_end = source[clamav_start..]
            .find("#[cfg(feature = \"compat_yara\")]")
            .map(|offset| clamav_start + offset)
            .unwrap();
        let clamav_source = &source[clamav_start..clamav_end];
        let old_optional_signature = [
            ".map(|value| value.replace(\"FOUND\", \"\").trim().to_string())\n",
            "        .filter(|value| !value.is_empty()))",
        ]
        .concat();

        assert!(clamav_source.contains("ClamAV compatibility detection"));
        assert!(clamav_source
            .contains("unwrap_or_else(|| \"ClamAV compatibility detection\".to_string())"));
        assert!(clamav_source.contains("Ok(Some(signature))"));
        assert!(!clamav_source.contains(&old_optional_signature));
    }

    #[test]
    fn guard_quarantine_hash_mismatch_cleanup_failures_are_reported() {
        let source = include_str!("main.rs");
        let start = source.find("fn copy_then_remove_verified(").unwrap();
        let end = source
            .find("fn ensure_quarantine_payload_destination_absent")
            .unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("failed to remove invalid guard quarantine destination"));
        assert!(!copy_source.contains("let _ = fs::remove_file(destination);"));
    }

    fn guard_fixture_record(root: &Path, id: &str) -> GuardQuarantineRecord {
        GuardQuarantineRecord {
            quarantine_id: id.to_string(),
            original_path: root.join("bad.exe").display().to_string(),
            quarantine_path: root
                .join("quarantine")
                .join(format!("{id}.avoraxq"))
                .display()
                .to_string(),
            sha256: format!("sha256:{}", "f".repeat(64)),
            file_size: 12,
            detection_name: "Fixture".to_string(),
            engine: "fixture".to_string(),
            action_taken: "process_stop_requested_and_file_quarantined".to_string(),
            quarantined_at: Utc::now(),
            status: QuarantineStatus::Quarantined,
            user_note: None,
            source: "guard_service".to_string(),
            blocked_before_execution: false,
            process_started: true,
            process_id: Some(1234),
        }
    }
}
