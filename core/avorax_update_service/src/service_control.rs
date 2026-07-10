#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::io::{self, BufReader, Read};
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::{Duration, Instant};

use anyhow::Result;
#[cfg(windows)]
use anyhow::{ensure, Context};

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const MAX_SERVICE_NAME_BYTES: usize = 128;
#[cfg(windows)]
const MAX_SERVICE_CONTROL_COMMAND_OUTPUT_BYTES: usize = 8192;
#[cfg(windows)]
const SERVICE_CONTROL_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub fn stop_service(name: &str) -> Result<()> {
    let service_name = checked_service_name(name)?;
    stop_checked_service(&service_name)
}

pub fn start_service(name: &str) -> Result<()> {
    let service_name = checked_service_name(name)?;
    start_checked_service(&service_name)
}

#[cfg(windows)]
fn stop_checked_service(service_name: &str) -> Result<()> {
    let sc = windows_system32_tool("sc.exe")?;
    let mut command = Command::new(&sc);
    command.args(["stop", service_name]);
    let label = format!("{} stop {service_name}", sc.display());
    let output = run_service_control_command(&mut command, &label)?;
    anyhow::ensure!(
        output.status.success(),
        "{} failed with status {}; {}; {}",
        label,
        output.status,
        service_control_output_detail("stdout", &output.stdout),
        service_control_output_detail("stderr", &output.stderr)
    );
    Ok(())
}

#[cfg(not(windows))]
fn stop_checked_service(service_name: &str) -> Result<()> {
    anyhow::bail!("Windows service stop is unsupported on this platform: {service_name}");
}

#[cfg(windows)]
fn start_checked_service(service_name: &str) -> Result<()> {
    let sc = windows_system32_tool("sc.exe")?;
    let mut command = Command::new(&sc);
    command.args(["start", service_name]);
    let label = format!("{} start {service_name}", sc.display());
    let output = run_service_control_command(&mut command, &label)?;
    anyhow::ensure!(
        output.status.success(),
        "{} failed with status {}; {}; {}",
        label,
        output.status,
        service_control_output_detail("stdout", &output.stdout),
        service_control_output_detail("stderr", &output.stderr)
    );
    Ok(())
}

#[cfg(not(windows))]
fn start_checked_service(service_name: &str) -> Result<()> {
    anyhow::bail!("Windows service start is unsupported on this platform: {service_name}");
}

fn checked_service_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    anyhow::ensure!(!trimmed.is_empty(), "Windows service name is empty");
    anyhow::ensure!(
        trimmed.len() <= MAX_SERVICE_NAME_BYTES,
        "Windows service name is too long"
    );
    anyhow::ensure!(
        trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')),
        "Windows service name contains unsafe characters"
    );
    anyhow::ensure!(
        !trimmed.contains(".."),
        "Windows service name must not contain parent traversal"
    );
    Ok(trimmed.to_string())
}

#[cfg(windows)]
struct ServiceControlCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(windows)]
fn run_service_control_command(
    command: &mut Command,
    label: &str,
) -> Result<ServiceControlCommandOutput> {
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
    let stdout_reader = thread::spawn(move || read_bounded_service_control_command_output(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_service_control_command_output(stderr));
    let status = match wait_for_service_control_child(&mut child, SERVICE_CONTROL_COMMAND_TIMEOUT)
        .with_context(|| format!("failed to wait for {label}"))?
    {
        Some(status) => status,
        None => {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let stdout = join_service_control_command_output(stdout_reader, label, "stdout")?;
            let stderr = join_service_control_command_output(stderr_reader, label, "stderr")?;
            let mut detail = format!(
                "{label} exceeded {} seconds",
                SERVICE_CONTROL_COMMAND_TIMEOUT.as_secs()
            );
            if let Some(error) = kill_error {
                detail.push_str(&format!(
                    "; failed to kill timed-out update service-control command: {error}"
                ));
            }
            if let Some(error) = wait_error {
                detail.push_str(&format!(
                    "; failed to reap timed-out update service-control command: {error}"
                ));
            }
            detail.push_str(&format!(
                "; {}; {}",
                service_control_output_detail("stdout", &stdout),
                service_control_output_detail("stderr", &stderr)
            ));
            anyhow::bail!(detail);
        }
    };
    let stdout = join_service_control_command_output(stdout_reader, label, "stdout")?;
    let stderr = join_service_control_command_output(stderr_reader, label, "stderr")?;
    Ok(ServiceControlCommandOutput {
        status,
        stdout,
        stderr,
    })
}

#[cfg(windows)]
fn wait_for_service_control_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> io::Result<Option<std::process::ExitStatus>> {
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
fn read_bounded_service_control_command_output<R: Read>(reader: R) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let retain_limit = MAX_SERVICE_CONTROL_COMMAND_OUTPUT_BYTES.saturating_add(1);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("failed to read update service-control command output")?;
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
fn join_service_control_command_output(
    reader: thread::JoinHandle<Result<Vec<u8>>>,
    label: &str,
    stream_name: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} {stream_name} reader panicked"))?
}

#[cfg(windows)]
fn service_control_output_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_SERVICE_CONTROL_COMMAND_OUTPUT_BYTES {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).trim().to_string())
}

#[cfg(windows)]
fn service_control_output_detail(label: &str, bytes: &[u8]) -> String {
    match service_control_output_text(bytes) {
        Some(text) if !text.is_empty() => format!("{label}: {text}"),
        Some(_) => format!("{label}: <empty>"),
        None => {
            format!("{label}: output exceeded {MAX_SERVICE_CONTROL_COMMAND_OUTPUT_BYTES} bytes")
        }
    }
}

#[cfg(windows)]
fn windows_system32_tool(name: &str) -> Result<PathBuf> {
    ensure!(name == "sc.exe", "unsupported Windows service-control tool");
    let root = windows_system_root()?;
    let candidate = root.join("System32").join(name);
    ensure!(
        is_local_windows_drive_path(&candidate),
        "Windows service-control tool must be on a local drive: {}",
        candidate.display()
    );
    let metadata = fs::symlink_metadata(&candidate).with_context(|| {
        format!(
            "failed to inspect Windows service-control tool {}",
            candidate.display()
        )
    })?;
    let file_type = metadata.file_type();
    ensure!(
        !file_type.is_symlink(),
        "Windows service-control tool path is a symbolic link: {}",
        candidate.display()
    );
    ensure!(
        !service_control_tool_is_reparse_point(&metadata),
        "Windows service-control tool path is a reparse point: {}",
        candidate.display()
    );
    ensure!(
        file_type.is_file(),
        "Windows service-control tool path is not a regular file: {}",
        candidate.display()
    );
    Ok(candidate)
}

#[cfg(windows)]
fn windows_system_root() -> Result<PathBuf> {
    let mut diagnostics = Vec::new();
    for variable in ["SystemRoot", "WINDIR"] {
        match std::env::var_os(variable) {
            Some(value) => {
                let text = value.to_string_lossy().trim().to_owned();
                if text.is_empty() {
                    diagnostics.push(format!("{variable} is empty"));
                    continue;
                }
                let normalized_root = match normalize_update_windows_system_root_text(&text) {
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
    anyhow::bail!(
        "Windows service-control tool root is unavailable: {}",
        diagnostics.join("; ")
    );
}

#[cfg(windows)]
fn normalize_update_windows_system_root_text(value: &str) -> Result<String> {
    ensure!(
        !value.contains('\0'),
        "Windows service-control system root contains NUL"
    );
    let normalized = value.trim().replace('/', "\\");
    ensure!(
        !normalized.split('\\').any(|part| part == ".."),
        "Windows service-control system root must not contain parent traversal"
    );
    Ok(collapse_update_windows_system_root_segments(&normalized))
}

#[cfg(windows)]
fn collapse_update_windows_system_root_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if trimmed.is_empty() {
        return String::new();
    }
    let (prefix, rest, absolute) = split_update_windows_system_root_prefix(trimmed);
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
fn split_update_windows_system_root_prefix(path: &str) -> (Option<&str>, &str, bool) {
    if path.len() >= 3 && path.as_bytes()[1] == b':' && path.as_bytes()[2] == b'\\' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with('\\') {
        return (None, path.trim_start_matches('\\'), true);
    }
    (None, path, false)
}

#[cfg(windows)]
fn service_control_tool_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
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

#[cfg(test)]
mod tests {
    #[test]
    fn service_control_uses_checked_system32_sc_path_source_marker() {
        let source = include_str!("service_control.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production slice exists");
        let old_windows_root_fallback = ["PathBuf::from(r\"", "C:\\Windows", "\")"].concat();
        assert!(source.contains("windows_system32_tool(\"sc.exe\")?"));
        assert!(source.contains("fn windows_system_root() -> Result<PathBuf>"));
        assert!(source.contains("normalize_update_windows_system_root_text(&text)"));
        assert!(source.contains("PathBuf::from(normalized_root)"));
        assert!(source.contains("SystemRoot"));
        assert!(source.contains("WINDIR"));
        assert!(source.contains("Windows service-control tool root is unavailable"));
        assert!(source
            .contains("Windows service-control system root must not contain parent traversal"));
        assert!(source
            .contains("fn collapse_update_windows_system_root_segments(path: &str) -> String"));
        assert!(source.contains("fn split_update_windows_system_root_prefix(path: &str)"));
        assert!(source.contains("collapse_update_windows_system_root_segments(&normalized)"));
        assert!(source.contains("match part {\n            \"\" | \".\" => {}"));
        assert!(!source.contains(&old_windows_root_fallback));
        assert!(source.contains("fs::symlink_metadata(&candidate)"));
        assert!(source.contains("file_type.is_symlink()"));
        assert!(source.contains("service_control_tool_is_reparse_point(&metadata)"));
        assert!(source.contains("file_type.is_file()"));
        assert!(source.contains("is_local_windows_drive_path(&candidate)"));
        assert!(source.contains("Windows service-control tool must be on a local drive"));
        assert!(source.contains("Windows service-control tool path is a symbolic link"));
        assert!(source.contains("Windows service-control tool path is a reparse point"));
        assert!(source.contains("fn stop_checked_service(service_name: &str) -> Result<()>"));
        assert!(source.contains("fn start_checked_service(service_name: &str) -> Result<()>"));
        assert!(source.contains("unsupported on this platform"));
        assert!(!production.contains("PathBuf::from(text)"));
        assert!(!production.contains("let _ = service_name"));
        let old_launch = ["Command::new(\"", "sc.exe\")"].concat();
        assert!(!source.contains(&old_launch));
        assert!(production.contains("checked_service_name(name)?"));
        assert!(!production.contains(".args([\"stop\", name])"));
        assert!(!production.contains(".args([\"start\", name])"));
        assert!(!production.contains("std::process::Command::new(&sc)"));
        assert!(!production.contains(".status()"));
    }

    #[test]
    fn service_control_commands_use_bounded_runner() {
        let source = include_str!("service_control.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production slice exists");
        let runner_start = production.find("fn run_service_control_command").unwrap();
        let runner_end = production.find("fn windows_system32_tool").unwrap();
        let runner_source = &production[runner_start..runner_end];

        assert!(production
            .contains("const SERVICE_CONTROL_COMMAND_TIMEOUT: Duration = Duration::from_secs(30)"));
        assert!(production.contains("const MAX_SERVICE_CONTROL_COMMAND_OUTPUT_BYTES: usize = 8192"));
        assert!(production.contains("run_service_control_command(&mut command, &label)?"));
        assert!(runner_source.contains("stdin(Stdio::null())"));
        assert!(runner_source.contains("stdout(Stdio::piped())"));
        assert!(runner_source.contains("stderr(Stdio::piped())"));
        assert!(runner_source.contains("child.try_wait()?"));
        assert!(runner_source.contains("child.kill().err()"));
        assert!(runner_source.contains("child.wait().err()"));
        assert!(runner_source.contains("failed to kill timed-out update service-control command"));
        assert!(runner_source.contains("failed to reap timed-out update service-control command"));
        assert!(runner_source.contains("read_bounded_service_control_command_output(stdout)"));
        assert!(runner_source.contains("read_bounded_service_control_command_output(stderr)"));
        assert!(runner_source.contains("let mut reader = BufReader::new(reader)"));
        assert!(
            runner_source.contains("MAX_SERVICE_CONTROL_COMMAND_OUTPUT_BYTES.saturating_add(1)")
        );
        assert!(runner_source.contains("read(&mut buffer)"));
        assert!(runner_source.contains("bytes.extend_from_slice(&buffer[..keep])"));
        assert!(runner_source.contains("failed to read update service-control command output"));
        assert!(!production.contains(".status()"));
        assert!(!runner_source.contains(".read_to_end(&mut bytes)"));
    }

    #[test]
    fn service_control_rejects_unsafe_service_names() {
        assert!(super::checked_service_name("avorax_core_service").is_ok());
        assert!(super::checked_service_name("avorax_guard_service").is_ok());
        assert!(super::checked_service_name("").is_err());
        assert!(super::checked_service_name("avorax/guard").is_err());
        assert!(super::checked_service_name("avorax..guard").is_err());
        assert!(
            super::checked_service_name(&"a".repeat(super::MAX_SERVICE_NAME_BYTES + 1)).is_err()
        );
    }

    #[test]
    fn service_control_service_names_stay_bounded() {
        let source = include_str!("service_control.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production slice exists");

        assert!(production.contains("const MAX_SERVICE_NAME_BYTES: usize = 128"));
        assert!(production.contains("fn checked_service_name(name: &str) -> Result<String>"));
        assert!(production.contains("trimmed.len() <= MAX_SERVICE_NAME_BYTES"));
        assert!(production.contains("Windows service name contains unsafe characters"));
        assert!(production.contains("Windows service name must not contain parent traversal"));
        assert!(production.contains(".args([\"stop\", service_name])"));
        assert!(production.contains(".args([\"start\", service_name])"));
    }

    #[cfg(not(windows))]
    #[test]
    fn service_control_fails_visibly_off_windows() {
        let stop_error = super::stop_service("avorax_core_service")
            .unwrap_err()
            .to_string();
        let start_error = super::start_service("avorax_guard_service")
            .unwrap_err()
            .to_string();

        assert!(stop_error.contains("Windows service stop is unsupported on this platform"));
        assert!(start_error.contains("Windows service start is unsupported on this platform"));
    }
}
