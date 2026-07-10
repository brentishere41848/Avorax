use std::fs;
use std::io::{BufReader, Read};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

const MAX_AUTHENTICODE_JSON_BYTES: usize = 64 * 1024;
const MAX_AUTHENTICODE_SUBJECT_BYTES: usize = 2048;
const MAX_AUTHENTICODE_DIAGNOSTIC_BYTES: usize = 4096;
const AUTHENTICODE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const AUTHENTICODE_TARGET_PATH_ENV: &str = "AVORAX_AUTHENTICODE_TARGET_PATH";

pub fn is_windows_system_path(path: &Path) -> Result<bool> {
    Ok(windows_system_path_roots()?
        .iter()
        .any(|root| path_starts_with_case_insensitive(path, root)))
}

#[cfg(windows)]
fn windows_system_path_roots() -> Result<Vec<PathBuf>> {
    let system_root = native_windows_system_root()?;
    Ok(vec![
        system_root.join("System32"),
        system_root.join("SysWOW64"),
    ])
}

#[cfg(not(windows))]
fn windows_system_path_roots() -> Result<Vec<PathBuf>> {
    Ok(Vec::new())
}

fn path_starts_with_case_insensitive(path: &Path, root: &Path) -> bool {
    let path_text = normalized_path_text(path);
    let root_text = normalized_path_text(root);
    !root_text.is_empty()
        && (path_text == root_text || path_text.starts_with(&format!("{root_text}\\")))
}

fn normalized_path_text(path: &Path) -> String {
    let path_text = path
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    collapse_windows_system_path_segments(&path_text)
}

fn collapse_windows_system_path_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if trimmed.is_empty() {
        return String::new();
    }

    let (prefix, rest, absolute) = split_windows_system_path_prefix(trimmed);
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('\\') {
        match segment {
            "" | "." => {}
            ".." => {
                if let Some(last) = segments.last() {
                    if *last != ".." {
                        segments.pop();
                        continue;
                    }
                }
                if !absolute {
                    segments.push(segment);
                }
            }
            _ => segments.push(segment),
        }
    }

    let body = segments.join("\\");
    match (prefix, absolute, body.is_empty()) {
        (Some(prefix), _, true) => prefix.to_string(),
        (Some(prefix), _, false) => format!("{prefix}\\{body}"),
        (None, true, true) => "\\".to_string(),
        (None, true, false) => format!("\\{body}"),
        (None, false, _) => body,
    }
}

fn split_windows_system_path_prefix(path: &str) -> (Option<&str>, &str, bool) {
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'\\' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with('\\') {
        return (None, path.trim_start_matches('\\'), true);
    }
    (None, path, false)
}

pub fn microsoft_signature_verdict(path: &Path) -> Result<bool> {
    if !cfg!(windows) {
        return Ok(false);
    }
    if !authenticode_candidate_file(path)? {
        return Ok(false);
    }
    let powershell = windows_powershell_tool()?;
    let script = authenticode_probe_script();
    let encoded_script = powershell_encoded_command(&script);
    let mut command = Command::new(&powershell);
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded_script,
        ])
        .env(AUTHENTICODE_TARGET_PATH_ENV, path.as_os_str());
    let label = format!("Authenticode signature inspection for {}", path.display());
    let output = run_authenticode_command(&mut command, &label)?;
    if !output.status.success() {
        let detail = authenticode_command_diagnostic(&output.stderr, &output.stdout);
        anyhow::bail!(
            "Authenticode signature inspection failed for {} with status {}: {}",
            path.display(),
            output.status,
            detail
        );
    }
    let signature = parse_authenticode_json(&output.stdout)?;
    authenticode_json_has_valid_microsoft_signer(&signature)
}

fn authenticode_probe_script() -> String {
    format!(
        "$target = [Environment]::GetEnvironmentVariable('{AUTHENTICODE_TARGET_PATH_ENV}', 'Process'); if ([string]::IsNullOrEmpty($target)) {{ throw 'missing Authenticode target path' }}; Get-AuthenticodeSignature -LiteralPath $target | ConvertTo-Json -Compress"
    )
}

struct AuthenticodeCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_authenticode_command(
    command: &mut Command,
    label: &str,
) -> Result<AuthenticodeCommandOutput> {
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
    let stdout_reader = thread::spawn(move || {
        read_bounded_authenticode_command_output(stdout, MAX_AUTHENTICODE_JSON_BYTES)
    });
    let stderr_reader = thread::spawn(move || {
        read_bounded_authenticode_command_output(stderr, MAX_AUTHENTICODE_DIAGNOSTIC_BYTES)
    });
    let status = match wait_for_authenticode_child(&mut child, AUTHENTICODE_COMMAND_TIMEOUT)
        .with_context(|| format!("failed to wait for {label}"))?
    {
        Some(status) => status,
        None => {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let stdout = join_authenticode_command_output(stdout_reader, label, "stdout")?;
            let stderr = join_authenticode_command_output(stderr_reader, label, "stderr")?;
            let mut detail = format!(
                "{label} exceeded {} seconds",
                AUTHENTICODE_COMMAND_TIMEOUT.as_secs()
            );
            if let Some(error) = kill_error {
                detail.push_str(&format!(
                    "; failed to kill timed-out Authenticode command: {error}"
                ));
            }
            if let Some(error) = wait_error {
                detail.push_str(&format!(
                    "; failed to reap timed-out Authenticode command: {error}"
                ));
            }
            let diagnostic = authenticode_command_diagnostic(&stderr, &stdout);
            if diagnostic != "no diagnostic output" {
                detail.push_str(&format!("; {diagnostic}"));
            }
            anyhow::bail!(detail);
        }
    };
    let stdout = join_authenticode_command_output(stdout_reader, label, "stdout")?;
    let stderr = join_authenticode_command_output(stderr_reader, label, "stderr")?;
    Ok(AuthenticodeCommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_authenticode_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
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

fn read_bounded_authenticode_command_output<R: Read>(
    reader: R,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let retain_limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("failed to read Authenticode command output")?;
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

fn join_authenticode_command_output(
    reader: thread::JoinHandle<Result<Vec<u8>>>,
    label: &str,
    stream_name: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} {stream_name} reader panicked"))?
}

fn authenticode_command_diagnostic(stderr: &[u8], stdout: &[u8]) -> String {
    let stderr = authenticode_output_excerpt(stderr);
    if !stderr.trim().is_empty() {
        return format!("stderr: {}", stderr.trim());
    }
    let stdout = authenticode_output_excerpt(stdout);
    if !stdout.trim().is_empty() {
        return format!("stdout: {}", stdout.trim());
    }
    "no diagnostic output".to_string()
}

fn authenticode_output_excerpt(bytes: &[u8]) -> String {
    let limit = bytes.len().min(MAX_AUTHENTICODE_DIAGNOSTIC_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[..limit]).to_string();
    if bytes.len() > MAX_AUTHENTICODE_DIAGNOSTIC_BYTES {
        text.push_str("...[truncated]");
    }
    text
}

fn powershell_encoded_command(script: &str) -> String {
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.push((unit & 0xff) as u8);
        bytes.push((unit >> 8) as u8);
    }
    base64_encode(&bytes)
}

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

#[cfg(windows)]
fn windows_powershell_tool() -> Result<PathBuf> {
    let system_root = native_windows_system_root()?;
    let candidate = system_root
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let metadata = fs::symlink_metadata(&candidate).with_context(|| {
        format!(
            "unable to inspect WindowsPowerShell executable {}",
            candidate.display()
        )
    })?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to launch symbolic link WindowsPowerShell executable {}",
        candidate.display()
    );
    anyhow::ensure!(
        !is_windows_reparse_point(&metadata),
        "refusing to launch reparse point WindowsPowerShell executable {}",
        candidate.display()
    );
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "WindowsPowerShell executable {} is not a regular file",
        candidate.display()
    );
    Ok(candidate)
}

#[cfg(not(windows))]
fn windows_powershell_tool() -> Result<PathBuf> {
    anyhow::bail!("WindowsPowerShell is unavailable on this platform")
}

#[cfg(windows)]
fn native_windows_system_root() -> Result<PathBuf> {
    let mut diagnostics = Vec::new();
    for key in ["SystemRoot", "WINDIR"] {
        match std::env::var_os(key) {
            Some(value) => {
                let text = value.to_string_lossy().trim().to_string();
                if text.is_empty() {
                    diagnostics.push(format!("{key} is empty"));
                    continue;
                }
                let normalized_root = match normalize_native_windows_system_root_text(&text) {
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
        "Native WindowsPowerShell tool root is unavailable: {}",
        diagnostics.join("; ")
    );
}

#[cfg(windows)]
fn normalize_native_windows_system_root_text(value: &str) -> Result<String> {
    anyhow::ensure!(
        !value.contains('\0'),
        "Native WindowsPowerShell system root contains NUL"
    );
    let normalized = value.trim().replace('/', "\\");
    anyhow::ensure!(
        !normalized.split('\\').any(|part| part == ".."),
        "Native WindowsPowerShell system root must not contain parent traversal"
    );
    Ok(collapse_windows_system_path_segments(&normalized))
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

fn parse_authenticode_json(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_AUTHENTICODE_JSON_BYTES {
        anyhow::bail!("Authenticode JSON output exceeds maximum size");
    }
    let signature =
        serde_json::from_slice::<Value>(bytes).context("failed to parse Authenticode JSON")?;
    signature
        .as_object()
        .context("Authenticode JSON output must be an object")?;
    Ok(signature)
}

fn authenticode_candidate_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()
            && !metadata.file_type().is_symlink()
            && !is_windows_reparse_point(&metadata)),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect Authenticode candidate {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn authenticode_json_has_valid_microsoft_signer(signature: &Value) -> Result<bool> {
    signature
        .as_object()
        .context("Authenticode signature JSON must be an object")?;
    if !authenticode_status_is_valid(signature.get("Status"))? {
        return Ok(false);
    }
    let certificate = signature
        .get("SignerCertificate")
        .context("valid Authenticode signature is missing SignerCertificate")?;
    signer_certificate_is_microsoft(certificate)
}

fn authenticode_status_is_valid(status: Option<&Value>) -> Result<bool> {
    let status = status.context("Authenticode signature JSON is missing Status")?;
    match status {
        Value::Number(number) => number
            .as_i64()
            .map(|value| value == 0)
            .context("Authenticode Status must be an integer"),
        Value::String(text) => Ok(canonical_text(text) == "valid"),
        _ => anyhow::bail!("Authenticode Status must be a string or integer"),
    }
}

fn signer_certificate_is_microsoft(certificate: &Value) -> Result<bool> {
    certificate
        .as_object()
        .context("SignerCertificate must be an object")?;
    let subject = certificate
        .get("Subject")
        .and_then(Value::as_str)
        .context("SignerCertificate is missing string Subject")?;
    anyhow::ensure!(
        subject.len() <= MAX_AUTHENTICODE_SUBJECT_BYTES,
        "SignerCertificate Subject exceeds maximum size"
    );
    distinguished_name_has_microsoft_subject(subject)
}

fn distinguished_name_has_microsoft_subject(subject: &str) -> Result<bool> {
    Ok(distinguished_name_attributes(subject)?
        .iter()
        .any(|(key, value)| {
            let key = canonical_text(key);
            let value = canonical_text(value);
            (key == "o" && value == "microsoft corporation")
                || (key == "cn"
                    && matches!(
                        value.as_str(),
                        "microsoft corporation"
                            | "microsoft windows"
                            | "microsoft windows publisher"
                    ))
        }))
}

fn distinguished_name_attributes(subject: &str) -> Result<Vec<(String, String)>> {
    let mut attributes = Vec::new();
    for (index, part) in subject.split(',').enumerate() {
        let part = part.trim();
        anyhow::ensure!(
            !part.is_empty(),
            "SignerCertificate Subject component {} is empty",
            index
        );
        let Some((key, value)) = part.split_once('=') else {
            anyhow::bail!(
                "SignerCertificate Subject component {} is missing '='",
                index
            );
        };
        let key = key.trim();
        let value = value.trim();
        anyhow::ensure!(
            !key.is_empty() && !value.is_empty(),
            "SignerCertificate Subject component {} has empty key or value",
            index
        );
        attributes.push((key.to_string(), value.to_string()));
    }
    Ok(attributes)
}

fn canonical_text(value: &str) -> String {
    value
        .trim()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    #[test]
    fn authenticode_candidate_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();

        assert!(!authenticode_candidate_file(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn authenticode_candidate_rejects_symbolic_link() {
        use std::os::unix::fs as unix_fs;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let link = dir.path().join("link.exe");
        fs::write(&target, b"benign fixture").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        assert!(!authenticode_candidate_file(&link).unwrap());
    }

    #[test]
    fn microsoft_signature_path_guard_uses_non_following_inspection() {
        let source = include_str!("microsoft_trust.rs");
        let legacy_exists_probe = ["path", ".exists()"].concat();

        assert!(source.contains("authenticode_candidate_file(path)"));
        assert!(source.contains("fs::symlink_metadata(path)"));
        assert!(source.contains("metadata.file_type().is_symlink()"));
        assert!(!source.contains(&legacy_exists_probe));
    }

    #[cfg(windows)]
    #[test]
    fn authenticode_probe_accepts_unsigned_file_without_encoded_command_argument_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("unsigned-fixture.exe");
        fs::write(&file, b"benign unsigned fixture").unwrap();

        let verdict = microsoft_signature_verdict(&file).unwrap();

        assert!(!verdict);
    }

    #[cfg(windows)]
    #[test]
    fn authenticode_probe_accepts_microsoft_signed_windows_powershell_binary() {
        let powershell = windows_powershell_tool().unwrap();

        let verdict = microsoft_signature_verdict(&powershell).unwrap();

        assert!(verdict);
    }

    #[test]
    fn windows_system_path_trust_uses_checked_system_root_not_hardcoded_root() {
        let source = include_str!("microsoft_trust.rs");
        let helper_start = source.find("pub fn is_windows_system_path").unwrap();
        let verdict_start = source.find("pub fn microsoft_signature_verdict").unwrap();
        let helper_source = &source[helper_start..verdict_start];
        let legacy_system32 = ["c:", "\\\\windows\\\\system32"].concat();
        let legacy_syswow64 = ["c:", "\\\\windows\\\\syswow64"].concat();

        assert!(
            helper_source.contains("pub fn is_windows_system_path(path: &Path) -> Result<bool>")
        );
        assert!(helper_source.contains("windows_system_path_roots()?"));
        assert!(helper_source.contains("native_windows_system_root()?"));
        assert!(helper_source.contains("path_starts_with_case_insensitive(path, root)"));
        assert!(helper_source.contains("path_text.starts_with(&format!"));
        assert!(!helper_source
            .to_ascii_lowercase()
            .contains(&legacy_system32));
        assert!(!helper_source
            .to_ascii_lowercase()
            .contains(&legacy_syswow64));
    }

    #[test]
    fn windows_system_path_prefix_requires_component_boundary() {
        assert!(path_starts_with_case_insensitive(
            Path::new(r"C:\Windows\System32\kernel32.dll"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(path_starts_with_case_insensitive(
            Path::new(r"c:/windows/syswow64"),
            Path::new(r"C:\Windows\SysWOW64")
        ));
        assert!(path_starts_with_case_insensitive(
            Path::new(r"C:\Windows\System32\.\kernel32.dll"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(!path_starts_with_case_insensitive(
            Path::new(r"C:\Windows\System32\..\Temp\payload.exe"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(!path_starts_with_case_insensitive(
            Path::new(r"C:\Windows\System32evil\kernel32.dll"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(!path_starts_with_case_insensitive(
            Path::new(r"C:\Windows"),
            Path::new(r"C:\Windows\System32")
        ));
    }

    #[test]
    fn microsoft_signature_output_is_bounded_before_parse() {
        let oversized = vec![b'{'; MAX_AUTHENTICODE_JSON_BYTES + 1];
        let source = include_str!("microsoft_trust.rs");
        let old_parse = ["serde_json::from_slice::<Value>(&output.", "stdout)"].concat();

        assert!(parse_authenticode_json(&oversized).is_err());
        assert!(source.contains("MAX_AUTHENTICODE_JSON_BYTES"));
        assert!(source.contains("parse_authenticode_json(&output.stdout)"));
        assert!(!source.contains(&old_parse));
    }

    #[test]
    fn authenticode_json_parser_rejects_malformed_or_non_object_output() {
        assert!(parse_authenticode_json(b"{not json").is_err());
        assert!(parse_authenticode_json(br#"[{"Status":0}]"#).is_err());
    }

    #[test]
    fn authenticode_json_schema_errors_are_not_false_defaults() {
        let source = include_str!("microsoft_trust.rs");
        let old_silent_parse = ["serde_json::from_slice::<Value>(bytes)", ".ok()"].concat();
        let old_false_default = [".unwrap_or", "(false)"].concat();

        assert!(source.contains("pub fn microsoft_signature_verdict(path: &Path) -> Result<bool>"));
        assert!(source.contains("authenticode_json_has_valid_microsoft_signer(&signature)"));
        assert!(source.contains("valid Authenticode signature is missing SignerCertificate"));
        assert!(source.contains("SignerCertificate is missing string Subject"));
        assert!(!source.contains(&old_silent_parse));
        assert!(!source.contains(&old_false_default));
    }

    #[test]
    fn authenticode_probe_failures_are_reportable_before_bool_compatibility() {
        let source = include_str!("microsoft_trust.rs");
        let verdict_start = source.find("pub fn microsoft_signature_verdict").unwrap();
        let parse_start = source.find("fn parse_authenticode_json").unwrap();
        let verdict_source = &source[verdict_start..parse_start];

        assert!(verdict_source.contains("Authenticode signature inspection for"));
        assert!(verdict_source.contains("failed to launch {label}"));
        assert!(verdict_source.contains("Authenticode signature inspection failed"));
        assert!(verdict_source.contains("parse_authenticode_json(&output.stdout)?"));
        assert!(verdict_source.contains("windows_powershell_tool()?"));
        assert!(verdict_source.contains("authenticode_probe_script()"));
        assert!(verdict_source.contains("powershell_encoded_command(&script)"));
        assert!(verdict_source.contains("Command::new(&powershell)"));
        assert!(verdict_source.contains("run_authenticode_command(&mut command, &label)?"));
        assert!(verdict_source.contains("\"-EncodedCommand\""));
        assert!(verdict_source.contains("AUTHENTICODE_TARGET_PATH_ENV"));
        assert!(verdict_source.contains(".env(AUTHENTICODE_TARGET_PATH_ENV, path.as_os_str())"));
        assert!(verdict_source.contains("fn authenticode_probe_script() -> String"));
        assert!(verdict_source.contains("GetEnvironmentVariable"));
        assert!(verdict_source.contains("Get-AuthenticodeSignature -LiteralPath $target"));
        assert!(verdict_source.contains("let system_root = native_windows_system_root()?;"));
        assert!(verdict_source.contains("fn native_windows_system_root() -> Result<PathBuf>"));
        assert!(verdict_source.contains("normalize_native_windows_system_root_text(&text)"));
        assert!(verdict_source.contains("PathBuf::from(normalized_root)"));
        assert!(verdict_source.contains("for key in [\"SystemRoot\", \"WINDIR\"]"));
        assert!(verdict_source.contains("std::env::var_os(key)"));
        assert!(verdict_source.contains("Native WindowsPowerShell tool root is unavailable"));
        assert!(verdict_source
            .contains("Native WindowsPowerShell system root must not contain parent traversal"));
        assert!(verdict_source.contains("collapse_windows_system_path_segments(&normalized)"));
        assert!(verdict_source.contains("let second = if offset + 1 < bytes.len()"));
        assert!(verdict_source.contains("let third = if offset + 2 < bytes.len()"));
        let old_powershell_launch = ["Command::new(\"", "powershell\")"].concat();
        let old_command_arg = ["\"-Com", "mand\""].concat();
        let old_positional_target_arg = [".arg(path", ".as_os_str())"].concat();
        let old_windows_root_fallback = ["PathBuf::from(r\"", "C:\\Windows", "\")"].concat();
        let old_env_string_reader = ["std::env::", "var(key)"].concat();
        let old_silent_env_error = [".", "ok()"].concat();
        let old_base64_padding_default = [".unwrap_or", "(0)"].concat();
        assert!(!verdict_source.contains(&old_powershell_launch));
        assert!(!verdict_source.contains(&old_command_arg));
        assert!(!verdict_source.contains(&old_positional_target_arg));
        assert!(!verdict_source.contains(&old_windows_root_fallback));
        assert!(!verdict_source.contains(&old_env_string_reader));
        assert!(!verdict_source.contains(&old_silent_env_error));
        assert!(!verdict_source.contains(&old_base64_padding_default));
        assert!(!verdict_source.contains(".output()"));
        assert!(!verdict_source.contains("PathBuf::from(text)"));
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production_source.contains("pub fn has_valid_microsoft_signature"));
    }

    #[test]
    fn authenticode_probe_uses_bounded_command_runner() {
        let source = include_str!("microsoft_trust.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let runner_start = source.find("fn run_authenticode_command").unwrap();
        let powershell_start = source.find("fn powershell_encoded_command").unwrap();
        let runner_source = &source[runner_start..powershell_start];
        let old_output = [".out", "put()"].concat();
        let old_unbounded_read = [".read_to_", "end(&mut bytes)"].concat();

        assert!(production
            .contains("const AUTHENTICODE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30)"));
        assert!(production.contains("const MAX_AUTHENTICODE_DIAGNOSTIC_BYTES: usize = 4096"));
        assert!(runner_source.contains("stdin(Stdio::null())"));
        assert!(runner_source.contains("stdout(Stdio::piped())"));
        assert!(runner_source.contains("stderr(Stdio::piped())"));
        assert!(runner_source.contains(
            "read_bounded_authenticode_command_output(stdout, MAX_AUTHENTICODE_JSON_BYTES)"
        ));
        assert!(runner_source.contains(
            "read_bounded_authenticode_command_output(stderr, MAX_AUTHENTICODE_DIAGNOSTIC_BYTES)"
        ));
        assert!(runner_source
            .contains("wait_for_authenticode_child(&mut child, AUTHENTICODE_COMMAND_TIMEOUT)"));
        assert!(runner_source.contains("child.try_wait()?"));
        assert!(runner_source.contains("child.kill().err()"));
        assert!(runner_source.contains("child.wait().err()"));
        assert!(runner_source.contains("failed to kill timed-out Authenticode command"));
        assert!(runner_source.contains("failed to reap timed-out Authenticode command"));
        assert!(runner_source.contains("let mut reader = BufReader::new(reader)"));
        assert!(runner_source.contains("let retain_limit = max_bytes.saturating_add(1)"));
        assert!(runner_source.contains("bytes.extend_from_slice(&buffer[..keep])"));
        assert!(runner_source.contains("failed to read Authenticode command output"));
        assert!(!production.contains(&old_output));
        assert!(!runner_source.contains(&old_unbounded_read));
    }

    #[test]
    fn authenticode_json_accepts_valid_microsoft_subject() {
        let signature = json!({
            "Status": 0,
            "SignerCertificate": {
                "Subject": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            }
        });

        assert!(authenticode_json_has_valid_microsoft_signer(&signature).unwrap());
    }

    #[test]
    fn authenticode_json_accepts_string_valid_status() {
        let signature = json!({
            "Status": "Valid",
            "SignerCertificate": {
                "Subject": "CN=Microsoft Windows Publisher, O=Microsoft Corporation, C=US"
            }
        });

        assert!(authenticode_json_has_valid_microsoft_signer(&signature).unwrap());
    }

    #[test]
    fn authenticode_json_rejects_status_message_without_valid_status() {
        let signature = json!({
            "StatusMessage": "Status: 0 Microsoft Corporation",
            "SignerCertificate": {
                "Subject": "CN=Microsoft Corporation, O=Microsoft Corporation, C=US"
            }
        });

        assert!(authenticode_json_has_valid_microsoft_signer(&signature).is_err());
    }

    #[test]
    fn authenticode_json_rejects_non_microsoft_subject_with_microsoft_text() {
        let signature = json!({
            "Status": 0,
            "Path": "C:\\Users\\Public\\Microsoft Corporation\\tool.exe",
            "SignerCertificate": {
                "Subject": "CN=Not Microsoft Corporation, O=Contoso Software, C=US"
            }
        });

        assert!(!authenticode_json_has_valid_microsoft_signer(&signature).unwrap());
    }

    #[test]
    fn authenticode_json_rejects_malformed_subject_components() {
        let missing_equals = json!({
            "Status": 0,
            "SignerCertificate": {
                "Subject": "CN=Microsoft Corporation, malformed-component, O=Microsoft Corporation"
            }
        });
        let empty_component = json!({
            "Status": "Valid",
            "SignerCertificate": {
                "Subject": "CN=Microsoft Windows Publisher, , O=Microsoft Corporation"
            }
        });
        let empty_value = json!({
            "Status": 0,
            "SignerCertificate": {
                "Subject": "CN=Microsoft Corporation, O=, C=US"
            }
        });

        assert!(authenticode_json_has_valid_microsoft_signer(&missing_equals).is_err());
        assert!(authenticode_json_has_valid_microsoft_signer(&empty_component).is_err());
        assert!(authenticode_json_has_valid_microsoft_signer(&empty_value).is_err());
    }

    #[test]
    fn authenticode_subject_parser_does_not_silently_drop_components() {
        let source = include_str!("microsoft_trust.rs");
        let start = source.find("fn distinguished_name_attributes").unwrap();
        let end = source.find("fn canonical_text").unwrap();
        let parser_source = &source[start..end];

        assert!(parser_source.contains("SignerCertificate Subject component"));
        assert!(!parser_source.contains(".filter_map("));
    }

    #[test]
    fn authenticode_json_rejects_invalid_status() {
        let signature = json!({
            "Status": 1,
            "SignerCertificate": {
                "Subject": "CN=Microsoft Corporation, O=Microsoft Corporation, C=US"
            }
        });

        assert!(!authenticode_json_has_valid_microsoft_signer(&signature).unwrap());
    }

    #[test]
    fn authenticode_json_reports_missing_signer_schema_for_valid_status() {
        let missing_certificate = json!({
            "Status": 0
        });
        let missing_subject = json!({
            "Status": "Valid",
            "SignerCertificate": {}
        });
        let oversized_subject_text =
            "O=".to_string() + &"A".repeat(MAX_AUTHENTICODE_SUBJECT_BYTES + 1);
        let oversized_subject = json!({
            "Status": 0,
            "SignerCertificate": {
                "Subject": oversized_subject_text
            }
        });

        assert!(authenticode_json_has_valid_microsoft_signer(&missing_certificate).is_err());
        assert!(authenticode_json_has_valid_microsoft_signer(&missing_subject).is_err());
        assert!(authenticode_json_has_valid_microsoft_signer(&oversized_subject).is_err());
    }
}
