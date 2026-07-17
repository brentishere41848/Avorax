use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::fs;
use std::io::{self, BufReader, Read};
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const DRIVER_SERVICE_NAME: &str = "ZentorAvFilter";
const MAX_DRIVER_COMMAND_OUTPUT_BYTES: usize = 4096;
const DRIVER_COMMAND_TIMEOUT_SECONDS: u64 = 30;
#[cfg(not(windows))]
const NON_WINDOWS_DRIVER_HEALTH_UNSUPPORTED: &str =
    "Windows driver health probes are unsupported on this platform";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriverHealth {
    pub installed: bool,
    pub running: bool,
    pub ipc_connected: bool,
    pub test_signed: bool,
    pub secure_boot_enabled: bool,
    pub load_attempted: bool,
    pub load_succeeded: bool,
    pub load_error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probe_errors: Vec<String>,
    pub reboot_required: bool,
    pub status: String,
    pub reason: String,
}

#[derive(Default)]
struct DriverHealthSignals {
    installed: bool,
    running: bool,
    ipc_connected: bool,
    test_signed: bool,
    secure_boot_enabled: bool,
    load_attempted: bool,
    load_succeeded: bool,
    load_error: Option<String>,
    probe_errors: Vec<String>,
}

impl DriverHealth {
    pub fn probe() -> Self {
        let mut probe_errors = Vec::new();
        let installed = match driver_service_installed() {
            Ok(installed) => installed,
            Err(error) => {
                probe_errors.push(format!("driver service probe failed: {error}"));
                false
            }
        };
        let test_signed = match test_signing_enabled() {
            Ok(test_signed) => test_signed,
            Err(error) => {
                probe_errors.push(format!("test-signing probe failed: {error}"));
                false
            }
        };
        let secure_boot_enabled = match secure_boot_enabled() {
            Ok(secure_boot_enabled) => secure_boot_enabled,
            Err(error) => {
                probe_errors.push(format!("secure boot probe failed: {error}"));
                false
            }
        };
        let (mut running, running_probe_failed) = match driver_filter_running() {
            Ok(running) => (running, false),
            Err(error) => {
                probe_errors.push(format!("fltmc filters probe failed: {error}"));
                (false, true)
            }
        };
        let mut load_attempted = false;
        let mut load_succeeded = false;
        let mut load_error = None;

        if installed && !running && test_signed && !running_probe_failed {
            load_attempted = true;
            match try_load_driver_filter() {
                Ok(()) => match driver_filter_running() {
                    Ok(loaded_running) => {
                        running = loaded_running;
                        load_succeeded = running;
                        if !running {
                            load_error = Some(
                                    "fltmc load reported success, but fltmc filters did not list ZentorAvFilter afterward."
                                        .to_string(),
                                );
                        }
                    }
                    Err(error) => {
                        let detail = format!("fltmc filters after load failed: {error}");
                        probe_errors.push(detail.clone());
                        load_error = Some(detail);
                    }
                },
                Err(error) => load_error = Some(error),
            }
        }

        let ipc_connected = if running {
            match driver_ipc_alive() {
                Ok(ipc_connected) => ipc_connected,
                Err(error) => {
                    probe_errors.push(format!("driver IPC probe failed: {error}"));
                    false
                }
            }
        } else {
            false
        };
        classify_driver_health(DriverHealthSignals {
            installed,
            running,
            ipc_connected,
            test_signed,
            secure_boot_enabled,
            load_attempted,
            load_succeeded,
            load_error,
            probe_errors,
        })
    }
}

fn classify_driver_health(signals: DriverHealthSignals) -> DriverHealth {
    let DriverHealthSignals {
        installed,
        running,
        ipc_connected,
        test_signed,
        secure_boot_enabled,
        load_attempted,
        load_succeeded,
        load_error,
        probe_errors,
    } = signals;
    let probe_failed = !probe_errors.is_empty();
    let reboot_required = installed && !running && !test_signed && !probe_failed;
    let status = if installed && running && ipc_connected {
        "communicationOk"
    } else if installed && load_attempted && !load_succeeded {
        "loadFailed"
    } else if probe_failed {
        "probeFailed"
    } else if installed && running {
        "communicationFailed"
    } else if installed && !test_signed && secure_boot_enabled {
        "secureBootBlocksTestSigning"
    } else if installed && !test_signed {
        "testSigningRequired"
    } else if installed {
        "installed"
    } else {
        "notInstalled"
    };
    let mut reason = if installed && running && ipc_connected {
        if load_succeeded {
            "Windows reports the Avorax minifilter is installed/running, Avorax loaded it successfully, and the driver IPC port responded.".to_string()
        } else {
            "Windows reports the Avorax minifilter is installed/running and the driver IPC port responded.".to_string()
        }
    } else if probe_failed && !(installed && load_attempted && !load_succeeded) {
        format!(
            "Avorax could not verify Windows driver health: {}. Post-launch fallback remains available.",
            probe_errors.join("; ")
        )
    } else if installed && running {
        "Windows reports the Avorax minifilter is running, but driver IPC did not respond. Ensure the Guard Service is running the driver port worker and that test_driver_ipc.exe is packaged next to the service under driver-tools."
            .to_string()
    } else if installed && !test_signed && secure_boot_enabled {
        "The custom Avorax minifilter is installed but not loaded. This development build is test-signed, Windows TESTSIGNING is off, and Secure Boot is enabled. Secure Boot blocks bcdedit /set testsigning on, so this test-signed driver cannot load on this boot configuration. To use the development minifilter, disable Secure Boot in UEFI firmware, enable TESTSIGNING from an elevated terminal, reboot, then run the Avorax driver installer/load self-test again. Production builds require a Microsoft-signed driver instead."
            .to_string()
    } else if installed && !test_signed {
        "The custom Avorax minifilter is installed but not loaded. This development build is test-signed and Windows TESTSIGNING is off; run bcdedit /set testsigning on from an elevated terminal and reboot, then run the Avorax driver installer/load self-test again. Production builds require a Microsoft-signed driver instead."
            .to_string()
    } else if installed && load_attempted && !load_succeeded {
        let load_error_detail = load_error
            .as_deref()
            .unwrap_or("missing driver load failure detail");
        format!(
            "Windows TESTSIGNING is enabled and Avorax attempted to load ZentorAvFilter, but the filter is still not running. fltmc load error: {}",
            load_error_detail
        )
    } else if installed {
        "Windows reports the Avorax minifilter service is installed, but the filter is not loaded. Run the Avorax driver installer/load self-test from an elevated terminal."
            .to_string()
    } else {
        "Avorax driver is not installed. Post-launch fallback remains available.".to_string()
    };
    if probe_failed && status != "probeFailed" {
        reason.push_str(" Additional driver-health diagnostics failed: ");
        reason.push_str(&probe_errors.join("; "));
    }
    DriverHealth {
        installed,
        running,
        ipc_connected,
        test_signed,
        secure_boot_enabled,
        load_attempted,
        load_succeeded,
        load_error,
        probe_errors,
        reboot_required,
        status: status.to_string(),
        reason,
    }
}

#[cfg(windows)]
fn driver_service_installed() -> Result<bool, String> {
    let sc = windows_system32_tool("sc.exe")?;
    let label = format!("{} query {DRIVER_SERVICE_NAME}", sc.display());
    let mut command = Command::new(&sc);
    command.args(["query", DRIVER_SERVICE_NAME]);
    let output = run_driver_health_command(&mut command, &label)?;
    if output.status.success() {
        return Ok(true);
    }
    if sc_query_output_reports_service_absent(&output.stdout, &output.stderr) {
        return Ok(false);
    }
    Err(command_failure_detail(&label, &output))
}

#[cfg(not(windows))]
fn driver_service_installed() -> Result<bool, String> {
    Err(NON_WINDOWS_DRIVER_HEALTH_UNSUPPORTED.to_string())
}

#[cfg(windows)]
fn driver_filter_running() -> Result<bool, String> {
    let fltmc = windows_system32_tool("fltmc.exe")?;
    let label = format!("{} filters", fltmc.display());
    let mut command = Command::new(&fltmc);
    command.arg("filters");
    let output = run_driver_health_command(&mut command, &label)?;
    if !output.status.success() {
        return Err(command_failure_detail(&label, &output));
    }
    let stdout = command_output_excerpt(&output.stdout);
    Ok(stdout.to_ascii_lowercase().contains("zentoravfilter"))
}

#[cfg(not(windows))]
fn driver_filter_running() -> Result<bool, String> {
    Err(NON_WINDOWS_DRIVER_HEALTH_UNSUPPORTED.to_string())
}

#[cfg(windows)]
fn try_load_driver_filter() -> Result<(), String> {
    let fltmc = windows_system32_tool("fltmc.exe")?;
    let label = format!("{} load {DRIVER_SERVICE_NAME}", fltmc.display());
    let mut command = Command::new(&fltmc);
    command.args(["load", DRIVER_SERVICE_NAME]);
    let output = run_driver_health_command(&mut command, &label)?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = command_output_excerpt(&output.stderr);
        let stdout = command_output_excerpt(&output.stdout);
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit code {:?}", output.status.code())
        };
        Err(detail)
    }
}

#[cfg(not(windows))]
fn try_load_driver_filter() -> Result<(), String> {
    Err("driver loading is only supported on Windows".to_string())
}

fn run_driver_health_command(command: &mut Command, label: &str) -> Result<Output, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to run {label}: {error}"))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let cleanup_detail = stop_driver_health_child(&mut child, label, "missing stdout pipe");
            return Err(format!(
                "{label} stdout pipe was unavailable{cleanup_detail}"
            ));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let cleanup_detail = stop_driver_health_child(&mut child, label, "missing stderr pipe");
            return Err(format!(
                "{label} stderr pipe was unavailable{cleanup_detail}"
            ));
        }
    };
    let stdout_reader = thread::spawn(move || read_bounded_driver_command_output(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_driver_command_output(stderr));
    let deadline = Instant::now() + Duration::from_secs(DRIVER_COMMAND_TIMEOUT_SECONDS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = join_driver_command_output(stdout_reader, label, "stdout")?;
                let stderr = join_driver_command_output(stderr_reader, label, "stderr")?;
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) if Instant::now() >= deadline => {
                let kill_error = child.kill().err();
                let wait_error = child.wait().err();
                let stdout = join_driver_command_output(stdout_reader, label, "stdout")?;
                let stderr = join_driver_command_output(stderr_reader, label, "stderr")?;
                let mut detail =
                    format!("{label} timed out after {DRIVER_COMMAND_TIMEOUT_SECONDS} seconds");
                if let Some(error) = kill_error {
                    detail.push_str(&format!("; failed to kill timed-out process: {error}"));
                }
                if let Some(error) = wait_error {
                    detail.push_str(&format!("; failed to reap timed-out process: {error}"));
                }
                let stderr_excerpt = command_output_excerpt(&stderr);
                let stdout_excerpt = command_output_excerpt(&stdout);
                if !stderr_excerpt.is_empty() {
                    detail.push_str(&format!("; stderr: {stderr_excerpt}"));
                } else if !stdout_excerpt.is_empty() {
                    detail.push_str(&format!("; stdout: {stdout_excerpt}"));
                }
                return Err(detail);
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(error) => {
                let cleanup_detail =
                    stop_driver_health_child(&mut child, label, "wait poll failure");
                let stdout = join_driver_command_output(stdout_reader, label, "stdout")?;
                let stderr = join_driver_command_output(stderr_reader, label, "stderr")?;
                let stderr_excerpt = command_output_excerpt(&stderr);
                let stdout_excerpt = command_output_excerpt(&stdout);
                let detail = if !stderr_excerpt.is_empty() {
                    format!("; stderr: {stderr_excerpt}")
                } else if !stdout_excerpt.is_empty() {
                    format!("; stdout: {stdout_excerpt}")
                } else {
                    String::new()
                };
                return Err(format!(
                    "failed to wait for {label}: {error}{cleanup_detail}{detail}"
                ));
            }
        }
    }
}

fn stop_driver_health_child(child: &mut std::process::Child, label: &str, reason: &str) -> String {
    let mut detail = String::new();
    match child.try_wait() {
        Ok(Some(_)) => return detail,
        Ok(None) => {
            if let Err(error) = child.kill() {
                detail.push_str(&format!("; failed to kill {label} after {reason}: {error}"));
            }
        }
        Err(error) => {
            detail.push_str(&format!(
                "; failed to poll {label} during cleanup after {reason}: {error}"
            ));
        }
    }
    if let Err(error) = child.wait() {
        detail.push_str(&format!("; failed to reap {label} after {reason}: {error}"));
    }
    detail
}

fn read_bounded_driver_command_output<R: Read>(reader: R) -> io::Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let retain_limit = MAX_DRIVER_COMMAND_OUTPUT_BYTES.saturating_add(1);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if bytes.len() < retain_limit {
            let remaining = retain_limit.saturating_sub(bytes.len());
            let keep = read.min(remaining);
            bytes.extend_from_slice(&buffer[..keep]);
        }
    }
    Ok(bytes)
}

fn join_driver_command_output(
    reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    label: &str,
    stream_name: &str,
) -> Result<Vec<u8>, String> {
    match reader.join() {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(format!("failed to read {stream_name} for {label}: {error}")),
        Err(_) => Err(format!("failed to join {stream_name} reader for {label}")),
    }
}

fn command_output_excerpt(bytes: &[u8]) -> String {
    let limit = bytes.len().min(MAX_DRIVER_COMMAND_OUTPUT_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[..limit]).trim().to_string();
    if bytes.len() > MAX_DRIVER_COMMAND_OUTPUT_BYTES {
        text.push_str("...[truncated]");
    }
    text
}

fn command_failure_detail(command: &str, output: &Output) -> String {
    let stderr = command_output_excerpt(&output.stderr);
    let stdout = command_output_excerpt(&output.stdout);
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit code {:?}", output.status.code())
    };
    format!("{command} failed: {detail}")
}

fn sc_query_output_reports_service_absent(stdout: &[u8], stderr: &[u8]) -> bool {
    let stdout = command_output_excerpt(stdout);
    let stderr = command_output_excerpt(stderr);
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    combined.contains("1060")
        || combined.contains("specified service does not exist")
        || combined.contains("does not exist as an installed service")
}

#[cfg(windows)]
fn driver_ipc_alive() -> Result<bool, String> {
    let exe_path = std::env::current_exe()
        .map_err(|error| format!("failed to locate guard executable: {error}"))?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| "guard executable has no parent directory".to_string())?;
    let candidates = [
        exe_dir
            .join("driver-tools")
            .join("zentor_windows_minifilter")
            .join("usermode_test")
            .join("test_driver_ipc.exe"),
        exe_dir.join("driver-tools").join("test_driver_ipc.exe"),
        exe_dir.join("test_driver_ipc.exe"),
    ];
    let mut errors = Vec::new();
    for candidate in candidates {
        match driver_ipc_helper_is_regular_file(&candidate) {
            Ok(true) => {
                let label = format!("driver IPC helper {} probe", candidate.display());
                let mut command = Command::new(&candidate);
                match run_driver_health_command(&mut command, &label) {
                    Ok(output) if output.status.success() => return Ok(true),
                    Ok(output) => errors.push(command_failure_detail(&label, &output)),
                    Err(error) => errors.push(error),
                }
            }
            Ok(false) => {}
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(false)
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(windows)]
fn driver_ipc_helper_is_regular_file(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "driver IPC helper path is a symbolic link: {}",
                    path.display()
                ));
            }
            if driver_ipc_helper_is_reparse_point(&metadata) {
                return Err(format!(
                    "driver IPC helper path is a Windows reparse point: {}",
                    path.display()
                ));
            }
            if !file_type.is_file() {
                return Err(format!(
                    "driver IPC helper path is not a regular file: {}",
                    path.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "failed to inspect driver IPC helper {}: {error}",
            path.display()
        )),
    }
}

#[cfg(windows)]
fn driver_ipc_helper_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn windows_system32_tool(name: &str) -> Result<PathBuf, String> {
    match name {
        "sc.exe" | "fltmc.exe" | "bcdedit.exe" | "powershell.exe" => {}
        _ => return Err(format!("unsupported Windows driver-health tool: {name}")),
    }
    let root = windows_system_root()?;
    let candidate = if name == "powershell.exe" {
        root.join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join(name)
    } else {
        root.join("System32").join(name)
    };
    if !is_local_windows_drive_path(&candidate) {
        return Err(format!(
            "Windows driver-health tool must be on a local drive: {}",
            candidate.display()
        ));
    }
    match fs::symlink_metadata(&candidate) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "Windows driver-health tool path is a symbolic link: {}",
                    candidate.display()
                ));
            }
            if driver_ipc_helper_is_reparse_point(&metadata) {
                return Err(format!(
                    "Windows driver-health tool path is a reparse point: {}",
                    candidate.display()
                ));
            }
            if !file_type.is_file() {
                return Err(format!(
                    "Windows driver-health tool path is not a regular file: {}",
                    candidate.display()
                ));
            }
            Ok(candidate)
        }
        Err(error) => Err(format!(
            "failed to inspect Windows driver-health tool {}: {error}",
            candidate.display()
        )),
    }
}

#[cfg(windows)]
fn windows_system_root() -> Result<PathBuf, String> {
    let mut diagnostics = Vec::new();
    for variable in ["SystemRoot", "WINDIR"] {
        match std::env::var_os(variable) {
            Some(value) => {
                let text = value.to_string_lossy().trim().to_owned();
                if text.is_empty() {
                    diagnostics.push(format!("{variable} is empty"));
                    continue;
                }
                let normalized_root = match normalize_driver_health_windows_system_root_text(&text)
                {
                    Ok(text) => text,
                    Err(error) => {
                        diagnostics.push(format!("{variable} is unsafe: {error}"));
                        continue;
                    }
                };
                let path = PathBuf::from(normalized_root);
                if !is_local_windows_drive_path(&path) {
                    diagnostics.push(format!(
                        "{variable} must be a local Windows drive path: {}",
                        path.display()
                    ));
                    continue;
                }
                return Ok(path);
            }
            None => diagnostics.push(format!("{variable} is not set")),
        }
    }
    Err(format!(
        "Windows driver-health tool root is unavailable: {}",
        diagnostics.join("; ")
    ))
}

#[cfg(windows)]
fn normalize_driver_health_windows_system_root_text(value: &str) -> Result<String, String> {
    if value.contains('\0') {
        return Err("Windows driver-health system root contains NUL".to_string());
    }
    let normalized = value.trim().replace('/', "\\");
    if normalized.split('\\').any(|part| part == "..") {
        return Err(
            "Windows driver-health system root must not contain parent traversal".to_string(),
        );
    }
    Ok(collapse_driver_health_windows_system_root_segments(
        &normalized,
    ))
}

#[cfg(windows)]
fn collapse_driver_health_windows_system_root_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if trimmed.is_empty() {
        return String::new();
    }
    let (prefix, rest, absolute) = split_driver_health_windows_system_root_prefix(trimmed);
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
fn split_driver_health_windows_system_root_prefix(path: &str) -> (Option<&str>, &str, bool) {
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
    let normalized = path.as_os_str().to_string_lossy().replace('/', "\\");
    let bytes = normalized.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !normalized.starts_with("\\\\")
}

#[cfg(not(windows))]
fn driver_ipc_alive() -> Result<bool, String> {
    Err(NON_WINDOWS_DRIVER_HEALTH_UNSUPPORTED.to_string())
}

#[cfg(windows)]
fn test_signing_enabled() -> Result<bool, String> {
    let bcdedit = windows_system32_tool("bcdedit.exe")?;
    let label = format!("{} /enum", bcdedit.display());
    let mut command = Command::new(&bcdedit);
    command.arg("/enum");
    let output = run_driver_health_command(&mut command, &label)?;
    if !output.status.success() {
        return Err(command_failure_detail(&label, &output));
    }
    let stdout = command_output_excerpt(&output.stdout);
    Ok(stdout.to_ascii_lowercase().contains("testsigning")
        && stdout.to_ascii_lowercase().contains("yes"))
}

#[cfg(not(windows))]
fn test_signing_enabled() -> Result<bool, String> {
    Err(NON_WINDOWS_DRIVER_HEALTH_UNSUPPORTED.to_string())
}

#[cfg(windows)]
fn secure_boot_enabled() -> Result<bool, String> {
    let powershell = windows_system32_tool("powershell.exe")?;
    let script =
        "try { if (Confirm-SecureBootUEFI) { 'true' } else { 'false' } } catch { 'unknown' }";
    let encoded_script = powershell_encoded_command(script);
    let mut command = Command::new(&powershell);
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded_script.as_str(),
    ]);
    let output = run_driver_health_command(&mut command, "PowerShell Confirm-SecureBootUEFI")?;
    if !output.status.success() {
        return Err(command_failure_detail(
            "PowerShell Confirm-SecureBootUEFI",
            &output,
        ));
    }
    let stdout = command_output_excerpt(&output.stdout);
    if stdout.trim().eq_ignore_ascii_case("true") {
        Ok(true)
    } else if stdout.trim().eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        let detail = if stdout.trim().is_empty() {
            "empty output".to_string()
        } else {
            stdout
        };
        Err(format!("Secure Boot probe returned {detail}"))
    }
}

#[cfg(not(windows))]
fn secure_boot_enabled() -> Result<bool, String> {
    Err(NON_WINDOWS_DRIVER_HEALTH_UNSUPPORTED.to_string())
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
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_stopped_testsigning_off_secure_boot_on_reports_firmware_blocker() {
        let health = classify_driver_health(DriverHealthSignals {
            installed: true,
            secure_boot_enabled: true,
            ..DriverHealthSignals::default()
        });

        assert_eq!(health.status, "secureBootBlocksTestSigning");
        assert!(health.reboot_required);
        assert!(!health.load_attempted);
        assert!(health
            .reason
            .contains("Secure Boot blocks bcdedit /set testsigning on"));
        assert!(health
            .reason
            .contains("disable Secure Boot in UEFI firmware"));
    }

    #[test]
    fn installed_stopped_testsigning_off_requires_reboot_policy_step() {
        let health = classify_driver_health(DriverHealthSignals {
            installed: true,
            ..DriverHealthSignals::default()
        });

        assert_eq!(health.status, "testSigningRequired");
        assert!(health.reboot_required);
        assert!(!health.load_attempted);
        assert!(health.reason.contains("bcdedit /set testsigning on"));
        assert!(health.reason.contains("reboot"));
    }

    #[test]
    fn installed_stopped_testsigning_on_reports_load_failure() {
        let health = classify_driver_health(DriverHealthSignals {
            installed: true,
            test_signed: true,
            load_attempted: true,
            load_error: Some("access denied".to_string()),
            ..DriverHealthSignals::default()
        });

        assert_eq!(health.status, "loadFailed");
        assert!(!health.reboot_required);
        assert!(health.load_attempted);
        assert!(health.reason.contains("access denied"));
    }

    #[test]
    fn running_without_ipc_is_not_reported_as_pre_execution_ready() {
        let health = classify_driver_health(DriverHealthSignals {
            installed: true,
            running: true,
            test_signed: true,
            ..DriverHealthSignals::default()
        });

        assert_eq!(health.status, "communicationFailed");
        assert!(health.reason.contains("driver IPC did not respond"));
    }

    #[test]
    fn driver_probe_errors_are_reported_in_health() {
        let health = classify_driver_health(DriverHealthSignals {
            probe_errors: vec!["driver service probe failed: denied".to_string()],
            ..DriverHealthSignals::default()
        });

        assert_eq!(health.status, "probeFailed");
        assert!(!health.reboot_required);
        assert_eq!(
            health.probe_errors,
            vec!["driver service probe failed: denied".to_string()]
        );
        assert!(health
            .reason
            .contains("driver service probe failed: denied"));
        assert!(health
            .reason
            .contains("Post-launch fallback remains available"));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_driver_health_is_unsupported_not_not_installed() {
        let health = DriverHealth::probe();

        assert_eq!(health.status, "probeFailed");
        assert!(!health.installed);
        assert!(!health.probe_errors.is_empty());
        assert!(health
            .probe_errors
            .iter()
            .any(|error| error.contains(NON_WINDOWS_DRIVER_HEALTH_UNSUPPORTED)));
        assert!(health
            .reason
            .contains("could not verify Windows driver health"));
    }

    #[test]
    fn sc_query_absent_service_is_distinct_from_probe_failure() {
        assert!(sc_query_output_reports_service_absent(
            b"",
            b"[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\r\nThe specified service does not exist as an installed service.\r\n",
        ));
        assert!(sc_query_output_reports_service_absent(
            b"[SC] OpenService FAILED 1060:\r\n",
            b"",
        ));
        assert!(!sc_query_output_reports_service_absent(
            b"",
            b"[SC] OpenSCManager FAILED 5:\r\nAccess is denied.\r\n",
        ));
    }

    #[test]
    fn driver_ipc_alive_uses_non_following_helper_path_check() {
        let source = include_str!("driver_health.rs");
        let start = source
            .find("fn driver_ipc_alive() -> Result<bool, String>")
            .unwrap();
        let end = source
            .find("fn driver_ipc_helper_is_reparse_point")
            .unwrap();
        let ipc_source = &source[start..end];

        assert!(ipc_source.contains("driver_ipc_helper_is_regular_file(&candidate)"));
        assert!(ipc_source.contains("fs::symlink_metadata(path)"));
        assert!(ipc_source.contains("file_type.is_symlink()"));
        assert!(ipc_source.contains("driver_ipc_helper_is_reparse_point(&metadata)"));
        assert!(ipc_source.contains("std::io::ErrorKind::NotFound"));
        assert!(!ipc_source.contains("candidate.exists()"));
    }

    #[test]
    fn driver_ipc_helper_nonzero_exit_is_reported() {
        let source = include_str!("driver_health.rs");
        let start = source
            .find("fn driver_ipc_alive() -> Result<bool, String>")
            .unwrap();
        let end = source.find("fn driver_ipc_helper_is_regular_file").unwrap();
        let ipc_source = &source[start..end];
        let old_silent_nonzero = ["Ok(_)", " => {}"].concat();

        assert!(ipc_source.contains("command_failure_detail"));
        assert!(ipc_source.contains("run_driver_health_command(&mut command, &label)"));
        assert!(ipc_source.contains("driver IPC helper"));
        assert!(ipc_source.contains("probe"));
        assert!(!ipc_source.contains(&old_silent_nonzero));
    }

    #[test]
    fn driver_load_command_output_is_bounded() {
        let source = include_str!("driver_health.rs");
        let load_start = source.find("fn try_load_driver_filter").unwrap();
        let ipc_start = source.find("fn driver_ipc_alive").unwrap();
        let load_source = &source[load_start..ipc_start];
        let old_stderr_pattern = [
            "String::from_utf8_lossy(&output.stderr)",
            ".trim().to_string()",
        ]
        .concat();
        let old_stdout_pattern = [
            "String::from_utf8_lossy(&output.stdout)",
            ".trim().to_string()",
        ]
        .concat();
        let long = vec![b'a'; MAX_DRIVER_COMMAND_OUTPUT_BYTES + 16];
        let excerpt = command_output_excerpt(&long);

        assert!(load_source.contains("run_driver_health_command(&mut command, &label)?"));
        assert!(load_source.contains("command_output_excerpt(&output.stderr)"));
        assert!(load_source.contains("command_output_excerpt(&output.stdout)"));
        assert!(!load_source.contains(".output()"));
        assert!(!load_source.contains(&old_stderr_pattern));
        assert!(!load_source.contains(&old_stdout_pattern));
        assert!(excerpt.ends_with("...[truncated]"));
    }

    #[test]
    fn driver_status_probe_outputs_are_bounded() {
        let source = crate::normalized_test_source(include_str!("driver_health.rs"));
        let filter_start = source.find("fn driver_filter_running").unwrap();
        let status_end = source
            .find("#[cfg(not(windows))]\nfn secure_boot_enabled")
            .unwrap();
        let status_source = &source[filter_start..status_end];
        let old_utf8_pattern = ["String::from_utf8(output.stdout)", ".ok()"].concat();

        assert!(status_source.contains("run_driver_health_command(&mut command, &label)?"));
        assert!(status_source.contains("command_output_excerpt(&output.stdout)"));
        assert!(!status_source.contains(".output()"));
        assert!(!status_source.contains(&old_utf8_pattern));
    }

    #[test]
    fn driver_health_external_commands_use_bounded_runner() {
        let source = include_str!("driver_health.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let runner_start = source.find("fn run_driver_health_command").unwrap();
        let excerpt_start = source.find("fn command_output_excerpt").unwrap();
        let runner_source = &source[runner_start..excerpt_start];
        let old_output = [".out", "put()"].concat();
        let old_unbounded_read = [".read_to_", "end(&mut bytes)"].concat();

        assert!(production.contains("const DRIVER_COMMAND_TIMEOUT_SECONDS: u64 = 30"));
        assert!(production.contains("stdin(Stdio::null())"));
        assert!(production.contains("stdout(Stdio::piped())"));
        assert!(production.contains("stderr(Stdio::piped())"));
        assert!(production.contains("run_driver_health_command(&mut command, &label)?"));
        assert!(production.contains(
            "run_driver_health_command(&mut command, \"PowerShell Confirm-SecureBootUEFI\")?"
        ));
        assert!(runner_source.contains("read_bounded_driver_command_output(stdout)"));
        assert!(runner_source.contains("read_bounded_driver_command_output(stderr)"));
        assert!(runner_source.contains("child.try_wait()"));
        assert!(runner_source.contains("child.kill().err()"));
        assert!(runner_source.contains("child.wait().err()"));
        assert!(runner_source.contains("failed to kill timed-out process"));
        assert!(runner_source.contains("failed to reap timed-out process"));
        assert!(runner_source.contains("let mut reader = BufReader::new(reader)"));
        assert!(runner_source
            .contains("let retain_limit = MAX_DRIVER_COMMAND_OUTPUT_BYTES.saturating_add(1)"));
        assert!(runner_source.contains("reader.read(&mut buffer)?"));
        assert!(runner_source.contains("bytes.extend_from_slice(&buffer[..keep])"));
        assert!(!production.contains(&old_output));
        assert!(!runner_source.contains(&old_unbounded_read));
    }

    #[test]
    fn driver_probe_failures_are_not_defaulted_false() {
        let source = crate::normalized_test_source(include_str!("driver_health.rs"));
        let old_bool_default = [".unwrap_or", "(false)"].concat();
        let installed_start = source.find("fn driver_service_installed()").unwrap();
        let installed_end = source
            .find("#[cfg(not(windows))]\nfn driver_service_installed")
            .unwrap();
        let installed_source = &source[installed_start..installed_end];

        assert!(source.contains("pub probe_errors: Vec<String>"));
        assert!(source.contains("driver_service_installed() -> Result<bool, String>"));
        assert!(source.contains("driver_filter_running() -> Result<bool, String>"));
        assert!(source.contains("driver_ipc_alive() -> Result<bool, String>"));
        assert!(source.contains("test_signing_enabled() -> Result<bool, String>"));
        assert!(source.contains("secure_boot_enabled() -> Result<bool, String>"));
        assert!(source.contains("status: status.to_string()"));
        assert!(source.contains("\"probeFailed\""));
        assert!(source.contains("fn sc_query_output_reports_service_absent"));
        assert!(installed_source.contains("sc_query_output_reports_service_absent"));
        assert!(installed_source.contains("command_failure_detail"));
        assert!(!installed_source.contains(".map(|output| output.status.success())"));
        assert!(!source.contains(&old_bool_default));
    }

    #[test]
    fn driver_health_system_commands_use_checked_system32_paths() {
        let source = crate::normalized_test_source(include_str!("driver_health.rs"));
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let old_sc = ["Command::new(\"", "sc.exe\")"].concat();
        let old_fltmc = ["Command::new(\"", "fltmc.exe\")"].concat();
        let old_bcdedit = ["Command::new(\"", "bcdedit.exe\")"].concat();
        let old_powershell = ["Command::new(\"", "powershell.exe\")"].concat();
        let old_windows_root_fallback = ["PathBuf::from(r\"", "C:\\Windows", "\")"].concat();

        assert!(production.contains("windows_system32_tool(\"sc.exe\")?"));
        assert!(production.contains("windows_system32_tool(\"fltmc.exe\")?"));
        assert!(production.contains("windows_system32_tool(\"bcdedit.exe\")?"));
        assert!(production.contains("windows_system32_tool(\"powershell.exe\")?"));
        assert!(production.contains("fn windows_system_root() -> Result<PathBuf, String>"));
        assert!(production.contains("normalize_driver_health_windows_system_root_text(&text)"));
        assert!(production.contains("PathBuf::from(normalized_root)"));
        assert!(production.contains("SystemRoot"));
        assert!(production.contains("WINDIR"));
        assert!(production.contains("Windows driver-health tool root is unavailable"));
        assert!(production.contains("must be a local Windows drive path"));
        assert!(production
            .contains("Windows driver-health system root must not contain parent traversal"));
        assert!(production.contains(
            "fn collapse_driver_health_windows_system_root_segments(path: &str) -> String"
        ));
        assert!(
            production.contains("fn split_driver_health_windows_system_root_prefix(path: &str)")
        );
        assert!(production.contains(
            "collapse_driver_health_windows_system_root_segments(\n        &normalized,"
        ));
        assert!(production.contains("match part {\n            \"\" | \".\" => {}"));
        assert!(!production.contains(&old_windows_root_fallback));
        assert!(production.contains("Windows driver-health tool must be on a local drive"));
        assert!(production.contains("Windows driver-health tool path is a symbolic link"));
        assert!(production.contains("Windows driver-health tool path is a reparse point"));
        assert!(!production.contains("PathBuf::from(text)"));
        assert!(!production.contains(&old_sc));
        assert!(!production.contains(&old_fltmc));
        assert!(!production.contains(&old_bcdedit));
        assert!(!production.contains(&old_powershell));
    }

    #[test]
    fn secure_boot_probe_uses_encoded_powershell_command() {
        let source = crate::normalized_test_source(include_str!("driver_health.rs"));
        let secure_boot_start = source.find("fn secure_boot_enabled()").unwrap();
        let secure_boot_end = source
            .find("#[cfg(not(windows))]\nfn secure_boot_enabled")
            .unwrap();
        let secure_boot_source = &source[secure_boot_start..secure_boot_end];

        assert!(secure_boot_source.contains("powershell_encoded_command(script)"));
        assert!(secure_boot_source.contains("\"-EncodedCommand\""));
        assert!(secure_boot_source.contains("\"-NonInteractive\""));
        assert!(source.contains("fn powershell_encoded_command(script: &str) -> String"));
        assert!(source.contains("fn base64_encode(bytes: &[u8]) -> String"));
        assert!(!secure_boot_source.contains("\"-Command\""));
    }

    #[test]
    fn driver_load_failure_detail_branch_is_explicit() {
        let source = include_str!("driver_health.rs");
        let start = source.find("fn classify_driver_health").unwrap();
        let end = source[start..]
            .find("#[cfg(windows)]")
            .map(|offset| start + offset)
            .unwrap();
        let classify_source = &source[start..end];

        assert!(classify_source.contains(".unwrap_or(\"missing driver load failure detail\")"));
        assert!(!classify_source.contains(".unwrap_or(\"unknown load failure\")"));
    }

    #[test]
    fn auto_loaded_and_ipc_alive_reports_success() {
        let health = classify_driver_health(DriverHealthSignals {
            installed: true,
            running: true,
            ipc_connected: true,
            test_signed: true,
            load_attempted: true,
            load_succeeded: true,
            ..DriverHealthSignals::default()
        });

        assert_eq!(health.status, "communicationOk");
        assert!(health.load_succeeded);
        assert!(health.reason.contains("loaded it successfully"));
    }
}
