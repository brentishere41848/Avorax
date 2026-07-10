use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::io::{BufReader, Read};
#[cfg(windows)]
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::{Duration, Instant};

#[cfg(windows)]
use anyhow::{Context, Result};

const MAX_GUARD_SERVICE_STATUS_OUTPUT_BYTES: usize = 8192;
#[cfg(windows)]
const GUARD_SERVICE_STATUS_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(windows)]
const GUARD_SERVICE_QUERY_NAMES: [&str; 2] = ["avorax_guard_service", "zentor_guard_service"];
#[cfg(not(windows))]
const NON_WINDOWS_GUARD_SERVICE_STATUS_UNSUPPORTED: &str =
    "Guard Service status is only available through Windows service control";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GuardMode {
    Off,
    MonitorOnly,
    BlockConfirmedThreats,
    Aggressive,
}

impl Default for GuardMode {
    fn default() -> Self {
        Self::BlockConfirmedThreats
    }
}

#[derive(Default)]
#[allow(dead_code)]
pub struct GuardService {
    mode: GuardMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardServiceStatusReport {
    pub status: &'static str,
    pub error: Option<String>,
}

impl GuardServiceStatusReport {
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

impl GuardService {
    #[allow(dead_code)]
    pub fn status(&self) -> &'static str {
        match self.mode {
            GuardMode::Off => "off",
            GuardMode::MonitorOnly => "monitorOnly",
            GuardMode::BlockConfirmedThreats => "blockConfirmedThreats",
            GuardMode::Aggressive => "aggressive",
        }
    }

    #[allow(dead_code)]
    pub fn system_status() -> &'static str {
        Self::system_status_report().status
    }

    pub fn system_status_report() -> GuardServiceStatusReport {
        #[cfg(windows)]
        {
            let mut query_errors = Vec::new();
            let sc = match crate::windows_tools::windows_system32_tool("sc.exe") {
                Ok(sc) => sc,
                Err(error) => return GuardServiceStatusReport::unknown(format!("{error:#}")),
            };
            for service_name in GUARD_SERVICE_QUERY_NAMES {
                let mut command = Command::new(&sc);
                command.args(["query", service_name]);
                let label = format!("Guard Service {service_name} sc query");
                let output = match run_guard_service_status_command(&mut command, &label) {
                    Ok(output) => output,
                    Err(error) => {
                        query_errors.push(format!(
                            "failed to query Guard Service {service_name}: {error:#}"
                        ));
                        continue;
                    }
                };
                if !output.status.success() {
                    if guard_service_status_query_reports_absent(&output.stdout, &output.stderr) {
                        continue;
                    }
                    query_errors.push(guard_service_status_query_failure_detail(
                        service_name,
                        output.status.code(),
                        &output.stdout,
                        &output.stderr,
                    ));
                    continue;
                }
                let Some(text) = guard_service_status_output_text(&output.stdout) else {
                    return GuardServiceStatusReport::unknown(format!(
                        "Guard Service {service_name} status output exceeded {} bytes",
                        MAX_GUARD_SERVICE_STATUS_OUTPUT_BYTES
                    ));
                };
                let status = guard_service_status_from_query_text(&text);
                return GuardServiceStatusReport::status(status);
            }
            if !query_errors.is_empty() {
                return GuardServiceStatusReport::unknown(query_errors.join("; "));
            }
            GuardServiceStatusReport::status("off")
        }
        #[cfg(not(windows))]
        {
            GuardServiceStatusReport::unknown(
                NON_WINDOWS_GUARD_SERVICE_STATUS_UNSUPPORTED.to_string(),
            )
        }
    }
}

fn guard_service_status_from_query_text(text: &str) -> &'static str {
    if text.contains("RUNNING") {
        return "running";
    }
    if text.contains("STOPPED") {
        return "stopped";
    }
    "installed"
}

fn guard_service_status_output_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_GUARD_SERVICE_STATUS_OUTPUT_BYTES {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).to_uppercase())
}

#[cfg(windows)]
struct GuardServiceStatusCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(windows)]
fn run_guard_service_status_command(
    command: &mut Command,
    label: &str,
) -> Result<GuardServiceStatusCommandOutput> {
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
    let stdout_reader = thread::spawn(move || read_bounded_guard_service_status_output(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_guard_service_status_output(stderr));
    let status =
        match wait_for_guard_service_status_child(&mut child, GUARD_SERVICE_STATUS_COMMAND_TIMEOUT)
            .with_context(|| format!("failed to wait for {label}"))?
        {
            Some(status) => status,
            None => {
                let kill_error = child.kill().err();
                let wait_error = child.wait().err();
                let stdout = join_guard_service_status_output(stdout_reader, label, "stdout")?;
                let stderr = join_guard_service_status_output(stderr_reader, label, "stderr")?;
                let mut detail = format!(
                    "{label} exceeded {} seconds",
                    GUARD_SERVICE_STATUS_COMMAND_TIMEOUT.as_secs()
                );
                if let Some(error) = kill_error {
                    detail.push_str(&format!(
                        "; failed to kill timed-out Guard Service status command: {error}"
                    ));
                }
                if let Some(error) = wait_error {
                    detail.push_str(&format!(
                        "; failed to reap timed-out Guard Service status command: {error}"
                    ));
                }
                detail.push_str(&format!(
                    "; {}; {}",
                    guard_service_status_output_detail("stdout", &stdout),
                    guard_service_status_output_detail("stderr", &stderr)
                ));
                anyhow::bail!(detail);
            }
        };
    let stdout = join_guard_service_status_output(stdout_reader, label, "stdout")?;
    let stderr = join_guard_service_status_output(stderr_reader, label, "stderr")?;
    Ok(GuardServiceStatusCommandOutput {
        status,
        stdout,
        stderr,
    })
}

#[cfg(windows)]
fn wait_for_guard_service_status_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let started = Instant::now();
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

#[cfg(windows)]
fn read_bounded_guard_service_status_output<R: Read>(reader: R) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let retain_limit = MAX_GUARD_SERVICE_STATUS_OUTPUT_BYTES.saturating_add(1);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("failed to read Guard Service status command output")?;
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

#[cfg(windows)]
fn join_guard_service_status_output(
    reader: thread::JoinHandle<Result<Vec<u8>>>,
    label: &str,
    stream_name: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} {stream_name} reader panicked"))?
}

fn guard_service_status_query_reports_absent(stdout: &[u8], stderr: &[u8]) -> bool {
    let Some(stdout) = guard_service_status_output_text(stdout) else {
        return false;
    };
    let Some(stderr) = guard_service_status_output_text(stderr) else {
        return false;
    };
    let combined = format!("{stdout}\n{stderr}");
    combined.contains("1060")
        || combined.contains("SPECIFIED SERVICE DOES NOT EXIST")
        || combined.contains("DOES NOT EXIST AS AN INSTALLED SERVICE")
}

fn guard_service_status_output_detail(label: &str, bytes: &[u8]) -> String {
    match guard_service_status_output_text(bytes) {
        Some(text) if !text.trim().is_empty() => format!("{label}: {}", text.trim()),
        Some(_) => format!("{label}: <empty>"),
        None => format!("{label}: output exceeded {MAX_GUARD_SERVICE_STATUS_OUTPUT_BYTES} bytes"),
    }
}

#[cfg(windows)]
fn guard_service_status_query_failure_detail(
    service_name: &str,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> String {
    let code = exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "terminated".to_string());
    format!(
        "Guard Service {service_name} query failed with exit {code}; {}; {}",
        guard_service_status_output_detail("stdout", stdout),
        guard_service_status_output_detail("stderr", stderr)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_service_status_output_is_bounded() {
        let oversized = vec![b'a'; MAX_GUARD_SERVICE_STATUS_OUTPUT_BYTES + 1];
        assert!(guard_service_status_output_text(&oversized).is_none());
        assert_eq!(
            guard_service_status_output_text(b"STATE              : 4  RUNNING").as_deref(),
            Some("STATE              : 4  RUNNING")
        );

        let source = include_str!("guard_service.rs");
        let old_direct_output =
            ["String::from_utf8_lossy(&output.stdout)", ".to_uppercase()"].concat();
        assert!(source.contains("MAX_GUARD_SERVICE_STATUS_OUTPUT_BYTES"));
        assert!(source.contains("guard_service_status_output_text(&output.stdout)"));
        assert!(!source.contains(&old_direct_output));
    }

    #[test]
    fn guard_service_status_parses_query_states() {
        assert_eq!(
            guard_service_status_from_query_text("STATE              : 4  RUNNING"),
            "running"
        );
        assert_eq!(
            guard_service_status_from_query_text("STATE              : 1  STOPPED"),
            "stopped"
        );
        assert_eq!(
            guard_service_status_from_query_text("SERVICE_NAME: avorax_guard_service"),
            "installed"
        );
    }

    #[test]
    fn guard_service_status_checks_both_names_and_keeps_launch_errors_unknown() {
        let source = include_str!("guard_service.rs");
        let start = source.find("pub fn system_status").unwrap();
        let end = source
            .find("fn guard_service_status_from_query_text")
            .unwrap();
        let status_source = &source[start..end];

        assert!(status_source.contains("GUARD_SERVICE_QUERY_NAMES"));
        assert!(status_source.contains("windows_tools::windows_system32_tool(\"sc.exe\")"));
        assert!(status_source.contains("Command::new(&sc)"));
        assert!(status_source.contains("run_guard_service_status_command(&mut command, &label)"));
        assert!(status_source.contains("query_errors.push"));
        assert!(status_source.contains("GuardServiceStatusReport::unknown"));
        assert!(status_source.contains("\"off\""));
        assert!(!status_source.contains(".or_else(|_|"));
        assert!(!status_source.contains("let Ok(output) = output else"));
        let old_sc_launch = ["Command::new(\"", "sc.exe\")"].concat();
        assert!(!status_source.contains(&old_sc_launch));
        assert!(!status_source.contains(".output()"));
    }

    #[test]
    fn guard_service_status_query_uses_bounded_runner() {
        let source = include_str!("guard_service.rs");
        let status_start = source.find("pub fn system_status_report").unwrap();
        let status_end = source
            .find("fn guard_service_status_from_query_text")
            .unwrap();
        let status_source = &source[status_start..status_end];
        let runner_start = source.find("fn run_guard_service_status_command").unwrap();
        let runner_end = source
            .find("fn guard_service_status_query_reports_absent")
            .unwrap();
        let runner_source = &source[runner_start..runner_end];

        assert!(source.contains(
            "const GUARD_SERVICE_STATUS_COMMAND_TIMEOUT: Duration = Duration::from_secs(30)"
        ));
        assert!(status_source.contains("run_guard_service_status_command(&mut command, &label)"));
        assert!(runner_source.contains("stdin(Stdio::null())"));
        assert!(runner_source.contains("stdout(Stdio::piped())"));
        assert!(runner_source.contains("stderr(Stdio::piped())"));
        assert!(runner_source.contains("child.try_wait()?"));
        assert!(runner_source.contains("child.kill().err()"));
        assert!(runner_source.contains("child.wait().err()"));
        assert!(runner_source.contains("failed to kill timed-out Guard Service status command"));
        assert!(runner_source.contains("failed to reap timed-out Guard Service status command"));
        assert!(runner_source.contains("read_bounded_guard_service_status_output(stdout)"));
        assert!(runner_source.contains("read_bounded_guard_service_status_output(stderr)"));
        assert!(runner_source.contains("let mut reader = BufReader::new(reader)"));
        assert!(runner_source.contains("MAX_GUARD_SERVICE_STATUS_OUTPUT_BYTES.saturating_add(1)"));
        assert!(runner_source.contains("read(&mut buffer)"));
        assert!(runner_source.contains("bytes.extend_from_slice(&buffer[..keep])"));
        assert!(!status_source.contains(".output()"));
        assert!(!runner_source.contains(".read_to_end(&mut bytes)"));
    }

    #[test]
    fn guard_service_status_query_distinguishes_absent_from_probe_failure() {
        assert!(guard_service_status_query_reports_absent(
            b"",
            b"[SC] OpenService FAILED 1060:\r\nThe specified service does not exist as an installed service.\r\n",
        ));
        assert!(!guard_service_status_query_reports_absent(
            b"",
            b"[SC] OpenSCManager FAILED 5:\r\nAccess is denied.\r\n",
        ));

        let source = include_str!("guard_service.rs");
        let start = source.find("pub fn system_status").unwrap();
        let end = source
            .find("fn guard_service_status_from_query_text")
            .unwrap();
        let status_source = &source[start..end];

        assert!(source.contains("fn guard_service_status_query_reports_absent"));
        assert!(status_source
            .contains("guard_service_status_query_reports_absent(&output.stdout, &output.stderr)"));
        assert!(status_source.contains("query_errors.push"));
        assert!(status_source.contains("GuardServiceStatusReport::unknown"));
        assert!(status_source.contains("\"off\""));
    }

    #[test]
    fn guard_service_status_errors_are_reported_not_silent_unknown() {
        let source = include_str!("guard_service.rs");
        let start = source.find("pub fn system_status_report").unwrap();
        let end = source
            .find("fn guard_service_status_from_query_text")
            .unwrap();
        let status_source = &source[start..end];

        assert!(source.contains("pub struct GuardServiceStatusReport"));
        assert!(source.contains("pub error: Option<String>"));
        assert!(status_source.contains("query_errors.join(\"; \")"));
        assert!(status_source.contains("guard_service_status_query_failure_detail"));
        assert!(status_source.contains("Guard Service {service_name} status output exceeded"));
        assert!(!status_source.contains("Err(_) => return \"unknown\""));
    }

    #[cfg(not(windows))]
    #[test]
    fn guard_service_status_is_unsupported_not_off_off_windows() {
        let report = GuardService::system_status_report();

        assert_eq!(report.status, "unknown");
        assert_eq!(
            report.error.as_deref(),
            Some(NON_WINDOWS_GUARD_SERVICE_STATUS_UNSUPPORTED)
        );
    }
}
