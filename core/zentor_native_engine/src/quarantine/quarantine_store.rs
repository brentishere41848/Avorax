use std::fs;
#[cfg(windows)]
use std::io::BufReader;
use std::io::{self, Read, Write};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, ExitStatus, Stdio};
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::quarantine_action::QUARANTINE_EXTENSION;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const MAX_NATIVE_QUARANTINE_COPY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_NATIVE_QUARANTINE_HASH_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_NATIVE_QUARANTINE_METADATA_BYTES: usize = 256 * 1024;
const MAX_NATIVE_QUARANTINE_METADATA_LABEL_CHARS: usize = 256;
const MAX_NATIVE_QUARANTINE_METADATA_STATE_CHARS: usize = 64;
const MAX_NATIVE_QUARANTINE_RECORD_PATH_CHARS: usize = 4096;
const MAX_NATIVE_QUARANTINE_COMMAND_OUTPUT_BYTES: usize = 2048;
#[cfg(windows)]
const NATIVE_QUARANTINE_ACL_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_NATIVE_QUARANTINE_DETECTION_NAME: &str = "Native detection";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    #[serde(default)]
    pub file_size_bytes: u64,
    pub detection_name: String,
    pub engine: String,
    pub quarantined_at: DateTime<Utc>,
    pub blocked_before_execution: bool,
    pub action_taken: String,
}

#[derive(Debug, Clone)]
pub struct QuarantineStore {
    root: PathBuf,
}

impl QuarantineStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn quarantine_file(
        &self,
        path: &Path,
        sha256: &str,
        detection_name: &str,
        blocked_before_execution: bool,
    ) -> Result<QuarantineRecord> {
        let expected_sha256 = normalize_hash(sha256)?;
        let detection_name = native_quarantine_metadata_label(
            "detection name",
            detection_name,
            DEFAULT_NATIVE_QUARANTINE_DETECTION_NAME,
        );
        let original_path = path.display().to_string();
        validate_native_quarantine_record_path_text("original path", &original_path, false)?;
        let id = Uuid::new_v4().to_string();
        let quarantine_path = self.root.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        let quarantine_path_text = quarantine_path.display().to_string();
        validate_native_quarantine_record_path_text("payload path", &quarantine_path_text, true)?;
        let file_size_bytes = ensure_regular_quarantine_source(path)?;
        let source_sha256 = sha256_file(path)?;
        if source_sha256 != expected_sha256 {
            anyhow::bail!("native quarantine source hash changed before move");
        }
        ensure_native_quarantine_root_directory(&self.root)?;
        ensure_quarantine_payload_destination_absent(&quarantine_path)?;
        fs::rename(path, &quarantine_path)
            .or_else(|_| copy_then_remove_verified(path, &quarantine_path, &source_sha256))
            .with_context(|| format!("failed to quarantine {}", path.display()))?;
        let finalize_result = (|| -> Result<QuarantineRecord> {
            ensure_regular_quarantine_payload(&quarantine_path, "quarantine destination")?;
            remove_executable_permissions(&quarantine_path)?;
            let quarantined_sha256 = sha256_file(&quarantine_path)?;
            if quarantined_sha256 != source_sha256 {
                return Err(anyhow!(
                    "quarantine hash verification failed for {}",
                    quarantine_path.display()
                ));
            }
            let record = QuarantineRecord {
                quarantine_id: id.clone(),
                original_path,
                quarantine_path: quarantine_path_text,
                sha256: quarantined_sha256,
                file_size_bytes,
                detection_name,
                engine: "Avorax Native Engine".to_string(),
                quarantined_at: Utc::now(),
                blocked_before_execution,
                action_taken: "quarantined".to_string(),
            };
            validate_native_quarantine_record(&record)?;
            write_record_staged(
                &self.root.join(format!("{id}.json")),
                &serde_json::to_vec_pretty(&record)?,
            )?;
            Ok(record)
        })();
        match finalize_result {
            Ok(record) => Ok(record),
            Err(error) => {
                cleanup_quarantine_partial_file(
                    &quarantine_path,
                    "untracked native quarantine payload",
                )
                .with_context(|| {
                    format!(
                        "failed to clean up untracked native quarantine payload {} after quarantine finalization failure: {error:#}",
                        quarantine_path.display()
                    )
                })?;
                Err(error)
            }
        }
    }
}

fn native_quarantine_metadata_label(label: &str, value: &str, fallback: &str) -> String {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_NATIVE_QUARANTINE_METADATA_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_string();
    if normalized.is_empty()
        || validate_native_quarantine_metadata_text(
            label,
            &normalized,
            MAX_NATIVE_QUARANTINE_METADATA_LABEL_CHARS,
            true,
        )
        .is_err()
    {
        fallback.to_string()
    } else {
        normalized
    }
}

fn validate_native_quarantine_record(record: &QuarantineRecord) -> Result<()> {
    validate_native_quarantine_record_path_text("original path", &record.original_path, false)
        .with_context(|| "invalid native quarantine original path")?;
    validate_native_quarantine_record_path_text("payload path", &record.quarantine_path, true)
        .with_context(|| "invalid native quarantine payload path")?;
    normalize_hash(&record.sha256).with_context(|| "invalid native quarantine metadata sha256")?;
    validate_native_quarantine_metadata_text(
        "detection name",
        &record.detection_name,
        MAX_NATIVE_QUARANTINE_METADATA_LABEL_CHARS,
        true,
    )?;
    validate_native_quarantine_metadata_text(
        "engine",
        &record.engine,
        MAX_NATIVE_QUARANTINE_METADATA_LABEL_CHARS,
        true,
    )?;
    validate_native_quarantine_metadata_text(
        "action taken",
        &record.action_taken,
        MAX_NATIVE_QUARANTINE_METADATA_STATE_CHARS,
        true,
    )?;
    Ok(())
}

fn validate_native_quarantine_record_path_text(
    label: &str,
    text: &str,
    require_payload_extension: bool,
) -> Result<()> {
    if text.trim().is_empty() {
        return Err(anyhow!("native quarantine {label} is empty"));
    }
    if text.contains('\0') {
        return Err(anyhow!("native quarantine {label} contains NUL"));
    }
    if text.chars().count() > MAX_NATIVE_QUARANTINE_RECORD_PATH_CHARS {
        return Err(anyhow!(
            "native quarantine {label} exceeds maximum length of {} characters",
            MAX_NATIVE_QUARANTINE_RECORD_PATH_CHARS
        ));
    }
    if text.chars().any(|ch| ch.is_control()) {
        return Err(anyhow!(
            "native quarantine {label} contains control characters"
        ));
    }
    if native_quarantine_record_path_has_unsafe_segment(text) {
        return Err(anyhow!("unsafe native quarantine {label}"));
    }
    let path = PathBuf::from(text);
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(anyhow!("unsafe native quarantine {label}"));
    }
    if require_payload_extension
        && path.extension().and_then(|value| value.to_str()) != Some(QUARANTINE_EXTENSION)
    {
        return Err(anyhow!("native quarantine {label} has unsafe extension"));
    }
    Ok(())
}

fn native_quarantine_record_path_has_unsafe_segment(text: &str) -> bool {
    text.replace('\\', "/")
        .split('/')
        .any(|part| part == "." || part == "..")
}

fn validate_native_quarantine_metadata_text(
    label: &str,
    value: &str,
    max_chars: usize,
    required: bool,
) -> Result<()> {
    if required && value.trim().is_empty() {
        return Err(anyhow!("native quarantine metadata {label} is required"));
    }
    if required && value.trim() != value {
        return Err(anyhow!(
            "native quarantine metadata {label} contains leading or trailing whitespace"
        ));
    }
    if value.contains('\0') {
        return Err(anyhow!("native quarantine metadata {label} contains NUL"));
    }
    if value.chars().count() > max_chars {
        return Err(anyhow!(
            "native quarantine metadata {label} exceeds maximum length of {max_chars} characters"
        ));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(anyhow!(
            "native quarantine metadata {label} contains control characters"
        ));
    }
    Ok(())
}

fn write_record_staged(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_NATIVE_QUARANTINE_METADATA_BYTES {
        return Err(anyhow!(
            "native quarantine metadata exceeds maximum length of {} bytes",
            MAX_NATIVE_QUARANTINE_METADATA_BYTES
        ));
    }
    ensure_native_quarantine_metadata_parent_directory(path)?;
    let temp_path = path.with_extension(format!("json.tmp-{}", Uuid::new_v4()));
    if let Err(error) =
        write_quarantine_metadata_file_exclusive(&temp_path, bytes, "temporary quarantine metadata")
    {
        return Err(error);
    }
    if let Err(error) =
        ensure_regular_quarantine_metadata_file(&temp_path, "temporary quarantine metadata")
    {
        cleanup_quarantine_metadata_temp_file(&temp_path).with_context(|| {
            format!(
                "failed to clean up temporary quarantine metadata {} after temporary validation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = ensure_native_quarantine_metadata_parent_directory(path) {
        cleanup_quarantine_metadata_temp_file(&temp_path).with_context(|| {
            format!(
                "failed to clean up temporary quarantine metadata {} after activation preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = ensure_quarantine_metadata_destination_absent(path, "quarantine metadata") {
        cleanup_quarantine_metadata_temp_file(&temp_path).with_context(|| {
            format!(
                "failed to clean up temporary quarantine metadata {} after activation preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        cleanup_quarantine_metadata_temp_file(&temp_path).with_context(|| {
            format!(
                "failed to clean up temporary quarantine metadata {} after activation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to activate quarantine metadata {}", path.display()));
    }
    Ok(())
}

fn ensure_native_quarantine_metadata_parent_directory(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow!(
            "native quarantine metadata path has no parent {}",
            path.display()
        )
    })?;
    ensure_existing_native_quarantine_directory(
        parent,
        "native quarantine metadata parent directory",
    )
}

fn cleanup_quarantine_metadata_temp_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove temporary quarantine metadata {}",
                path.display()
            )
        }),
    }
}

fn write_quarantine_metadata_file_exclusive(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create {label} {}", path.display()));
        }
    };
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        cleanup_quarantine_metadata_temp_file(path).with_context(|| {
            format!(
                "failed to clean up {label} {} after write failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error).with_context(|| format!("failed to write {label} {}", path.display()));
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        cleanup_quarantine_metadata_temp_file(path).with_context(|| {
            format!(
                "failed to clean up {label} {} after sync failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error).with_context(|| format!("failed to sync {label} {}", path.display()));
    }
    Ok(())
}

fn ensure_quarantine_metadata_destination_absent(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing to replace symbolic link {label}");
            }
            #[cfg(windows)]
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                anyhow::bail!("refusing to replace reparse point {label}");
            }
            if !metadata.is_file() {
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

fn ensure_regular_quarantine_metadata_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label}");
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!("refusing to use reparse point {label}");
    }
    if !metadata.is_file() {
        anyhow::bail!("refusing to use non-file {label}");
    }
    Ok(())
}

fn ensure_regular_quarantine_source(path: &Path) -> Result<u64> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect quarantine source {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to quarantine symbolic link source {}",
            path.display()
        );
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!(
            "refusing to quarantine reparse point source {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!("quarantine source is not a regular file {}", path.display());
    }
    Ok(metadata.len())
}

fn ensure_regular_quarantine_payload(path: &Path, label: &str) -> Result<u64> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label} {}", path.display());
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!("refusing to use reparse point {label} {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("{label} is not a regular file {}", path.display());
    }
    Ok(metadata.len())
}

fn ensure_native_quarantine_root_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| {
        format!(
            "failed to create native quarantine root directory {}",
            path.display()
        )
    })?;
    ensure_existing_native_quarantine_directory(path, "native quarantine root directory")?;
    harden_native_quarantine_root_acl(path)?;
    Ok(())
}

fn harden_native_quarantine_root_acl(_path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let current_user = current_windows_account()?;
        let current_user_grant = format!("{current_user}:(OI)(CI)F");
        let icacls = native_windows_system32_tool("icacls.exe")?;
        let mut command = Command::new(&icacls);
        command.arg(_path).args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            &current_user_grant,
        ]);
        let output = run_native_quarantine_acl_command(&mut command)?;
        if !output.status.success() {
            return Err(anyhow!(
                "failed to harden native quarantine ACLs: {}",
                command_output_excerpt(&output.stderr)
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
struct BoundedNativeQuarantineCommandOutput {
    status: ExitStatus,
    stderr: Vec<u8>,
}

#[cfg(windows)]
fn run_native_quarantine_acl_command(
    command: &mut Command,
) -> Result<BoundedNativeQuarantineCommandOutput> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("failed to launch native quarantine ACL command")?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture native quarantine ACL command stderr"))?;
    let stderr_reader = thread::spawn(move || {
        read_bounded_native_quarantine_command_output(
            stderr,
            MAX_NATIVE_QUARANTINE_COMMAND_OUTPUT_BYTES,
        )
    });
    let status = match wait_for_native_quarantine_acl_child(&mut child)? {
        Some(status) => status,
        None => {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let stderr = stderr_reader
                .join()
                .map_err(|_| anyhow!("native quarantine ACL stderr reader panicked"))??;
            let mut detail = format!(
                "native quarantine ACL command timed out after {} seconds",
                NATIVE_QUARANTINE_ACL_COMMAND_TIMEOUT.as_secs()
            );
            if let Some(error) = kill_error {
                detail.push_str(&format!(
                    "; failed to kill timed-out native quarantine ACL command: {error}"
                ));
            }
            if let Some(error) = wait_error {
                detail.push_str(&format!(
                    "; failed to reap timed-out native quarantine ACL command: {error}"
                ));
            }
            let stderr_excerpt = command_output_excerpt(&stderr);
            if !stderr_excerpt.is_empty() {
                detail.push_str(&format!("; stderr: {stderr_excerpt}"));
            }
            return Err(anyhow!(detail));
        }
    };
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("native quarantine ACL stderr reader panicked"))??;
    Ok(BoundedNativeQuarantineCommandOutput { status, stderr })
}

#[cfg(windows)]
fn wait_for_native_quarantine_acl_child(
    child: &mut std::process::Child,
) -> Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to poll native quarantine ACL command")?
        {
            return Ok(Some(status));
        }
        if started.elapsed() >= NATIVE_QUARANTINE_ACL_COMMAND_TIMEOUT {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(windows)]
fn read_bounded_native_quarantine_command_output<R: Read>(
    reader: R,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    let retain_limit = max_bytes.saturating_add(1);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("failed to read native quarantine ACL command stderr")?;
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

fn command_output_excerpt(bytes: &[u8]) -> String {
    let limit = bytes.len().min(MAX_NATIVE_QUARANTINE_COMMAND_OUTPUT_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[..limit]).trim().to_string();
    if bytes.len() > MAX_NATIVE_QUARANTINE_COMMAND_OUTPUT_BYTES {
        text.push_str("...[truncated]");
    }
    text
}

#[cfg(windows)]
fn native_windows_system32_tool(name: &str) -> Result<PathBuf> {
    if !name.eq_ignore_ascii_case("icacls.exe") {
        anyhow::bail!("unsupported native Windows System32 tool {name}");
    }
    let system_root = native_windows_system_root()?;
    let is_system32_root = system_root
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("System32"))
        .unwrap_or(false);
    let candidate = if is_system32_root {
        system_root.join(name)
    } else {
        system_root.join("System32").join(name)
    };
    let metadata = fs::symlink_metadata(&candidate).with_context(|| {
        format!(
            "unable to inspect native Windows System32 tool {}",
            candidate.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to launch symbolic link native Windows System32 tool {}",
            candidate.display()
        );
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!(
            "refusing to launch reparse point native Windows System32 tool {}",
            candidate.display()
        );
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "native Windows System32 tool {} is not a regular file",
            candidate.display()
        );
    }
    Ok(candidate)
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
        "Native Windows System32 tool root is unavailable: {}",
        diagnostics.join("; ")
    );
}

#[cfg(windows)]
fn normalize_native_windows_system_root_text(value: &str) -> Result<String> {
    if value.contains('\0') {
        anyhow::bail!("Native Windows system root contains NUL");
    }
    let normalized = value.trim().replace('/', "\\");
    if normalized.split('\\').any(|part| part == "..") {
        anyhow::bail!("Native Windows system root must not contain parent traversal");
    }
    Ok(collapse_native_windows_system_root_segments(&normalized))
}

#[cfg(windows)]
fn collapse_native_windows_system_root_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if trimmed.is_empty() {
        return String::new();
    }
    let (prefix, rest, absolute) = split_native_windows_system_root_prefix(trimmed);
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
fn split_native_windows_system_root_prefix(path: &str) -> (Option<&str>, &str, bool) {
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
fn current_windows_account() -> Result<String> {
    let user = std::env::var("USERNAME").map_err(|_| anyhow!("USERNAME is not set"))?;
    if user.trim().is_empty() {
        return Err(anyhow!("USERNAME is empty"));
    }
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.trim().is_empty() => Ok(format!("{domain}\\{user}")),
        _ => Ok(user),
    }
}

fn ensure_existing_native_quarantine_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        if label == "native quarantine root directory" {
            anyhow::bail!(
                "refusing to use symbolic link native quarantine root directory {}",
                path.display()
            );
        }
        anyhow::bail!("refusing to use symbolic link {label} {}", path.display());
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        if label == "native quarantine root directory" {
            anyhow::bail!(
                "refusing to use reparse point native quarantine root directory {}",
                path.display()
            );
        }
        anyhow::bail!("refusing to use reparse point {label} {}", path.display());
    }
    if !metadata.is_dir() {
        if label == "native quarantine root directory" {
            anyhow::bail!(
                "native quarantine root is not a directory {}",
                path.display()
            );
        }
        anyhow::bail!("{label} is not a directory {}", path.display());
    }
    Ok(())
}

fn ensure_quarantine_payload_destination_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing to use symbolic link quarantine payload destination {}",
                    path.display()
                );
            }
            #[cfg(windows)]
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                anyhow::bail!(
                    "refusing to use reparse point quarantine payload destination {}",
                    path.display()
                );
            }
            anyhow::bail!(
                "quarantine payload destination already exists {}",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect quarantine payload destination {}",
                path.display()
            )
        }),
    }
}

pub(crate) fn copy_then_remove_verified(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<()> {
    let expected_sha256 = normalize_hash(expected_sha256)
        .with_context(|| "invalid native quarantine copy expected sha256")?;
    ensure_regular_quarantine_source(source)?;
    ensure_quarantine_payload_destination_absent(destination)?;
    copy_file_exclusive(source, destination)?;
    let destination_hash = match (|| -> Result<String> {
        ensure_regular_quarantine_payload(destination, "quarantine destination")?;
        sha256_file(destination)
    })() {
        Ok(hash) => hash,
        Err(error) => {
            cleanup_quarantine_partial_file(
                destination,
                "invalid copied native quarantine destination",
            )
            .with_context(|| {
                format!(
                    "failed to clean up invalid copied native quarantine destination {} after verification failure: {error:#}",
                    destination.display()
                )
            })?;
            return Err(error).with_context(|| {
                format!(
                    "failed to verify copied native quarantine destination {}",
                    destination.display()
                )
            });
        }
    };
    if destination_hash != expected_sha256 {
        if let Err(cleanup_error) = fs::remove_file(destination) {
            return Err(anyhow!(
                "hash verification failed before deleting original quarantine source; failed to remove invalid native quarantine destination {}: {cleanup_error}",
                destination.display()
            ));
        }
        return Err(anyhow!(
            "hash verification failed before deleting original quarantine source"
        ));
    }
    if let Err(error) = fs::remove_file(source) {
        cleanup_quarantine_partial_file(destination, "copied native quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up copied native quarantine destination {} after source deletion failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to delete original quarantine source {}",
                source.display()
            )
        });
    }
    Ok(())
}

fn copy_file_exclusive(source: &Path, destination: &Path) -> Result<()> {
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
    if let Err(error) = copy_native_quarantine_payload_limited(
        &mut input,
        &mut output,
        MAX_NATIVE_QUARANTINE_COPY_BYTES,
        source,
    ) {
        drop(output);
        cleanup_quarantine_partial_file(destination, "partial native quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial native quarantine destination {} after copy failure: {error:#}",
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
        cleanup_quarantine_partial_file(destination, "partial native quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial native quarantine destination {} after sync failure: {error:#}",
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

fn cleanup_quarantine_partial_file(path: &Path, label: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {label} {}", path.display()))
        }
    }
}

fn copy_native_quarantine_payload_limited<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    limit: u64,
    source: &Path,
) -> Result<()> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("native quarantine payload copy size overflow"))?;
        if total > limit {
            anyhow::bail!(
                "native quarantine payload {} exceeds the copy size limit",
                source.display()
            );
        }
        output.write_all(&buffer[..read])?;
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let file_size = ensure_regular_quarantine_payload(path, "file to hash")?;
    if file_size > MAX_NATIVE_QUARANTINE_HASH_BYTES {
        anyhow::bail!(
            "file to hash {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_NATIVE_QUARANTINE_HASH_BYTES
        );
    }
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("native quarantine hash size overflow"))?;
        if total > MAX_NATIVE_QUARANTINE_HASH_BYTES {
            anyhow::bail!(
                "file to hash {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_NATIVE_QUARANTINE_HASH_BYTES
            );
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn normalize_hash(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let raw = sha256_body(trimmed);
    if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(raw.to_ascii_lowercase())
    } else {
        anyhow::bail!("invalid quarantine SHA-256 value")
    }
}

fn sha256_body(trimmed: &str) -> &str {
    match trimmed.strip_prefix("sha256:") {
        Some(raw) => raw,
        None => trimmed,
    }
}

#[cfg(unix)]
fn remove_executable_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions =
        ensure_regular_quarantine_payload(path, "quarantine destination")?.permissions();
    permissions.set_mode(permissions.mode() & !0o111);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn remove_executable_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_quarantine_hash_prefix_branch_is_explicit() {
        let source = include_str!("quarantine_store.rs");
        let normalize_start = source.find("fn normalize_hash").unwrap();
        let tests_start = normalize_start + source[normalize_start..].find("#[cfg(test)]").unwrap();
        let normalize_source = &source[normalize_start..tests_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or(trimmed)"));
    }

    #[test]
    fn native_quarantine_normalizes_detection_metadata_before_move() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("native-threat.exe");
        fs::write(&source, b"benign native payload").expect("source");
        let hash = sha256_file(&source).expect("source hash");
        let store = QuarantineStore::new(temp.path().join("quarantine"));

        let record = store
            .quarantine_file(&source, &hash, "\nNative\0Detection\n", false)
            .expect("quarantine");

        assert_eq!(record.detection_name, "Native Detection");
        assert!(!record.detection_name.chars().any(|ch| ch.is_control()));
        assert!(!source.exists());
        let metadata = fs::read_to_string(
            Path::new(&record.quarantine_path)
                .parent()
                .expect("quarantine parent")
                .join(format!("{}.json", record.quarantine_id)),
        )
        .expect("metadata");
        assert!(metadata.contains("Native Detection"));
    }

    #[test]
    fn native_quarantine_record_metadata_validation_rejects_unsafe_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut record = QuarantineRecord {
            quarantine_id: "record".to_string(),
            original_path: temp.path().join("file.exe").display().to_string(),
            quarantine_path: temp
                .path()
                .join(format!("record.{QUARANTINE_EXTENSION}"))
                .display()
                .to_string(),
            sha256: "not-a-sha256".to_string(),
            file_size_bytes: 1,
            detection_name: "Native Detection".to_string(),
            engine: "Avorax Native Engine".to_string(),
            quarantined_at: Utc::now(),
            blocked_before_execution: false,
            action_taken: "quarantined".to_string(),
        };

        let hash_error = validate_native_quarantine_record(&record).unwrap_err();
        assert!(hash_error
            .to_string()
            .contains("invalid native quarantine metadata sha256"));

        record.sha256 = "f".repeat(64);
        record.detection_name = "Native\nDetection".to_string();
        let label_error = validate_native_quarantine_record(&record).unwrap_err();
        assert!(label_error
            .to_string()
            .contains("native quarantine metadata detection name contains control characters"));
    }

    #[test]
    fn native_quarantine_record_path_validation_rejects_unsafe_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut record = QuarantineRecord {
            quarantine_id: "record".to_string(),
            original_path: "relative.exe".to_string(),
            quarantine_path: temp
                .path()
                .join(format!("record.{QUARANTINE_EXTENSION}"))
                .display()
                .to_string(),
            sha256: "f".repeat(64),
            file_size_bytes: 1,
            detection_name: "Native Detection".to_string(),
            engine: "Avorax Native Engine".to_string(),
            quarantined_at: Utc::now(),
            blocked_before_execution: false,
            action_taken: "quarantined".to_string(),
        };

        let original_error = validate_native_quarantine_record(&record).unwrap_err();
        assert!(original_error
            .to_string()
            .contains("invalid native quarantine original path"));

        record.original_path = temp.path().join("restore.exe").display().to_string();
        record.quarantine_path = temp.path().join("record.tmp").display().to_string();
        let payload_error = validate_native_quarantine_record(&record).unwrap_err();
        assert!(payload_error
            .to_string()
            .contains("invalid native quarantine payload path"));
    }

    #[test]
    fn native_quarantine_metadata_writes_are_staged() {
        let source = include_str!("quarantine_store.rs");
        let uuid_pattern = ["Uuid::", "new_v4()"].concat();
        let writer_pattern = ["fn write_quarantine_metadata_file_", "exclusive"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let write_all_pattern = ["write_", "all(bytes)"].concat();
        let sync_pattern = ["file.", "sync_all()"].concat();
        let ensure_temp_pattern =
            ["ensure_regular_quarantine_metadata_", "file(&temp_path"].concat();
        let cleanup_pattern = ["fn cleanup_quarantine_metadata_", "temp_file"].concat();
        let old_temp_write_pattern = ["fs::", "write(&temp_path"].concat();
        let fixed_temp_pattern = ["path.with_", "extension(\"json.tmp\")"].concat();

        assert!(source.contains("fn write_record_staged"));
        assert!(source.contains(&uuid_pattern));
        assert!(source.contains(&writer_pattern));
        assert!(source.contains(&create_new_pattern));
        assert!(source.contains(&write_all_pattern));
        assert!(source.contains(&sync_pattern));
        assert!(source.contains("failed to activate quarantine metadata"));
        assert!(source.contains(&ensure_temp_pattern));
        assert!(source.contains(&cleanup_pattern));
        assert!(!source.contains("fs::write(\n            self.root.join(format!(\"{id}.json\"))"));
        assert!(!source.contains(&old_temp_write_pattern));
        assert!(!source.contains(&fixed_temp_pattern));
    }

    #[test]
    fn native_quarantine_metadata_cleanup_failures_are_reported() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn write_record_staged").unwrap();
        let end = source
            .find("fn write_quarantine_metadata_file_exclusive")
            .unwrap();
        let write_source = &source[start..end];
        let writer_start = source
            .find("fn write_quarantine_metadata_file_exclusive")
            .unwrap();
        let writer_end = source
            .find("fn ensure_quarantine_metadata_destination_absent")
            .unwrap();
        let writer_source = &source[writer_start..writer_end];
        let ignored_cleanup = ["let _ = fs::remove_", "file(&temp_path);"].concat();

        assert!(write_source.contains("fn cleanup_quarantine_metadata_temp_file"));
        assert!(write_source.contains("return Err(error)"));
        assert!(!write_source.contains("after write failure"));
        assert!(writer_source.contains("let mut file = match fs::OpenOptions::new()"));
        assert!(writer_source.contains("Err(error) => {"));
        assert!(writer_source.contains("failed to create {label}"));
        assert!(writer_source.contains("cleanup_quarantine_metadata_temp_file(path)"));
        assert!(writer_source.contains("after write failure"));
        assert!(writer_source.contains("after sync failure"));
        assert!(write_source.contains("after temporary validation failure"));
        assert!(write_source.contains("after activation preflight failure"));
        assert!(write_source.contains("after activation failure"));
        assert!(!write_source.contains(&ignored_cleanup));
    }

    #[test]
    fn native_quarantine_metadata_write_rejects_oversized_bytes_before_temp_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record_path = temp.path().join("record.json");
        let oversized = vec![b'x'; MAX_NATIVE_QUARANTINE_METADATA_BYTES + 1];

        let error = write_record_staged(&record_path, &oversized)
            .expect_err("oversized metadata should be rejected");

        assert!(error
            .to_string()
            .contains("native quarantine metadata exceeds maximum length"));
        assert!(!record_path.exists());
        assert_eq!(fs::read_dir(temp.path()).expect("temp entries").count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn native_quarantine_metadata_write_rejects_linked_parent_before_temp_file() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let external = temp.path().join("external");
        let linked_parent = temp.path().join("linked-parent");
        fs::create_dir(&external).expect("external");
        symlink(&external, &linked_parent).expect("parent symlink");
        let record_path = linked_parent.join("record.json");

        let error = write_record_staged(&record_path, b"{}")
            .expect_err("linked metadata parent should be rejected");

        assert!(error
            .to_string()
            .contains("refusing to use symbolic link native quarantine metadata parent directory"));
        assert_eq!(
            fs::read_dir(&external).expect("external entries").count(),
            0
        );
    }

    #[test]
    fn native_quarantine_metadata_staging_rejects_linked_paths_in_source() {
        let source = include_str!("quarantine_store.rs");
        let ensure_metadata_pattern = ["fn ensure_regular_quarantine_metadata_", "file"].concat();
        let symbolic_use_pattern = ["refusing to use symbolic link ", "{label}"].concat();
        let reparse_use_pattern = ["refusing to use reparse point ", "{label}"].concat();
        let non_file_use_pattern = ["refusing to use non-file ", "{label}"].concat();

        assert!(source.contains("fn ensure_quarantine_metadata_destination_absent"));
        assert!(source.contains("refusing to replace symbolic link {label}"));
        assert!(source.contains("refusing to replace reparse point {label}"));
        assert!(source.contains("refusing to replace non-file {label}"));
        assert!(source.contains("{label} destination already exists"));
        assert!(source.contains(&ensure_metadata_pattern));
        assert!(source.contains(&symbolic_use_pattern));
        assert!(source.contains(&reparse_use_pattern));
        assert!(source.contains(&non_file_use_pattern));
    }

    #[test]
    fn native_quarantine_hash_mismatch_cleanup_failures_are_reported() {
        let source = include_str!("quarantine_store.rs");
        let start = source
            .find("pub(crate) fn copy_then_remove_verified")
            .unwrap();
        let end = source.find("fn copy_file_exclusive").unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("failed to remove invalid native quarantine destination"));
        assert!(!copy_source.contains("let _ = fs::remove_file(destination);"));
    }

    #[cfg(unix)]
    #[test]
    fn native_quarantine_rejects_linked_metadata_final_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let record_path = temp.path().join("record.json");
        let external = temp.path().join("external");
        fs::write(&external, b"do not overwrite").expect("external");
        symlink(&external, &record_path).expect("symlink");

        let error = write_record_staged(&record_path, b"{}")
            .expect_err("linked final metadata path should be rejected");

        assert!(error
            .to_string()
            .contains("refusing to replace symbolic link quarantine metadata"));
        assert_eq!(fs::read(&external).expect("external"), b"do not overwrite");
    }

    #[test]
    fn native_quarantine_metadata_write_rejects_existing_final_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record_path = temp.path().join("record.json");
        fs::write(&record_path, b"existing metadata").expect("existing metadata");

        let error = write_record_staged(&record_path, b"{}")
            .expect_err("existing final metadata path should be rejected");

        assert!(error
            .to_string()
            .contains("quarantine metadata destination already exists"));
        assert_eq!(
            fs::read(&record_path).expect("existing metadata"),
            b"existing metadata"
        );
        assert_eq!(fs::read_dir(temp.path()).expect("temp entries").count(), 1);
    }

    #[test]
    fn native_quarantine_metadata_write_rejects_existing_temp_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let existing_temp_path = temp.path().join("record.json.tmp-fixed");
        fs::write(&existing_temp_path, b"existing").expect("existing temp");

        let error = write_quarantine_metadata_file_exclusive(
            &existing_temp_path,
            b"{}",
            "temporary quarantine metadata",
        )
        .expect_err("exclusive temp metadata creation should reject existing files");

        assert!(error
            .to_string()
            .contains("failed to create temporary quarantine metadata"));
        assert_eq!(fs::read(&existing_temp_path).expect("temp"), b"existing");
    }

    #[test]
    fn native_quarantine_rejects_non_regular_sources_before_metadata_follow() {
        let source = include_str!("quarantine_store.rs");

        assert!(source.contains("fn ensure_regular_quarantine_source"));
        assert!(source.contains("fs::symlink_metadata(path)"));
        assert!(source.contains("refusing to quarantine symbolic link source"));
        assert!(source.contains("refusing to quarantine reparse point source"));
        assert!(source.contains("quarantine source is not a regular file"));
        assert!(!source.contains("fs::metadata(path)\n            .map(|metadata| metadata.len())\n            .unwrap_or(0)"));
    }

    #[test]
    fn native_quarantine_payload_destination_is_exclusive_in_source() {
        let source = include_str!("quarantine_store.rs");
        let copy_start = source.find("fn copy_file_exclusive").unwrap();
        let copy_end = source.find("fn sha256_file").unwrap();
        let copy_source = &source[copy_start..copy_end];
        let destination_absent_pattern =
            ["fn ensure_quarantine_payload_", "destination_absent"].concat();
        let copy_exclusive_pattern = ["fn copy_file_", "exclusive"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let sync_pattern = ["output.", "sync_all()"].concat();
        let regular_payload_pattern = ["fn ensure_regular_quarantine_", "payload"].concat();
        let old_copy_pattern = ["fs::copy(source, ", "destination)"].concat();
        let old_io_copy_pattern = ["io::", "copy(&mut input, &mut output)"].concat();

        assert!(source.contains(&destination_absent_pattern));
        assert!(source.contains(&copy_exclusive_pattern));
        assert!(source.contains(&create_new_pattern));
        assert!(source.contains(&sync_pattern));
        assert!(source.contains(&regular_payload_pattern));
        assert!(copy_source.contains("MAX_NATIVE_QUARANTINE_COPY_BYTES"));
        assert!(copy_source.contains("copy_native_quarantine_payload_limited"));
        assert!(copy_source.contains("let mut buffer = [0_u8; 64 * 1024]"));
        assert!(copy_source.contains("total > limit"));
        assert!(copy_source.contains("output.write_all(&buffer[..read])"));
        assert!(copy_source.contains("cleanup_quarantine_partial_file"));
        assert!(copy_source.contains("after copy failure"));
        assert!(copy_source.contains("after sync failure"));
        assert!(!source.contains(&old_copy_pattern));
        assert!(!copy_source.contains(&old_io_copy_pattern));
    }

    #[test]
    fn native_quarantine_hash_input_is_size_bounded() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn sha256_file").unwrap();
        let end = source.find("fn normalize_hash").unwrap();
        let hash_source = &source[start..end];

        assert!(source.contains("const MAX_NATIVE_QUARANTINE_HASH_BYTES"));
        assert!(hash_source.contains(
            "let file_size = ensure_regular_quarantine_payload(path, \"file to hash\")?"
        ));
        assert!(hash_source.contains("file_size > MAX_NATIVE_QUARANTINE_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("checked_add(read as u64)"));
        assert!(hash_source.contains("total > MAX_NATIVE_QUARANTINE_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
    }

    #[test]
    fn native_quarantine_rejects_directory_source() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = QuarantineStore::new(temp.path().join("quarantine"));
        let hash = "0".repeat(64);

        let error = store
            .quarantine_file(temp.path(), &hash, "directory fixture", false)
            .expect_err("directory quarantine should be rejected");

        assert!(error
            .to_string()
            .contains("quarantine source is not a regular file"));
    }

    #[test]
    fn native_quarantine_rejects_changed_source_hash_before_move() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("changed.exe");
        fs::write(&source, b"original benign native payload").expect("source");
        let stale_hash = sha256_file(&source).expect("stale hash");
        fs::write(&source, b"changed benign native payload").expect("changed source");
        let store = QuarantineStore::new(temp.path().join("quarantine"));

        let error = store
            .quarantine_file(&source, &stale_hash, "changed fixture", false)
            .expect_err("changed source hash should fail before move");

        assert!(error
            .to_string()
            .contains("native quarantine source hash changed before move"));
        assert!(source.exists());
        assert!(!temp.path().join("quarantine").exists());
    }

    #[cfg(unix)]
    #[test]
    fn native_quarantine_removes_executable_permissions_from_payload() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("executable-fixture.exe");
        fs::write(&source, b"benign native executable fixture").expect("source");
        let mut permissions = fs::metadata(&source)
            .expect("source metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&source, permissions).expect("source permissions");
        let hash = sha256_file(&source).expect("source hash");
        let store = QuarantineStore::new(temp.path().join("quarantine"));

        let record = store
            .quarantine_file(&source, &hash, "executable fixture", false)
            .expect("quarantine");

        let payload_permissions = fs::metadata(&record.quarantine_path)
            .expect("payload metadata")
            .permissions();
        assert_eq!(payload_permissions.mode() & 0o111, 0);
    }

    #[cfg(unix)]
    #[test]
    fn native_quarantine_rejects_linked_root_before_payload_move() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let external_root = temp.path().join("external-root");
        let linked_root = temp.path().join("linked-root");
        let source = temp.path().join("source.exe");
        fs::create_dir(&external_root).expect("external root");
        symlink(&external_root, &linked_root).expect("root symlink");
        fs::write(&source, b"benign native payload").expect("source");
        let hash = sha256_file(&source).expect("source hash");
        let store = QuarantineStore::new(linked_root);

        let error = store
            .quarantine_file(&source, &hash, "linked root fixture", false)
            .expect_err("linked native quarantine root should be rejected");

        assert!(error
            .to_string()
            .contains("refusing to use symbolic link native quarantine root directory"));
        assert!(source.exists());
        assert_eq!(
            fs::read_dir(&external_root)
                .expect("external entries")
                .count(),
            0
        );
    }

    #[test]
    fn native_quarantine_root_acl_hardening_uses_checked_system32_tool() {
        let source = include_str!("quarantine_store.rs");
        let root_start = source
            .find("fn ensure_native_quarantine_root_directory")
            .unwrap();
        let root_end = source
            .find("fn ensure_existing_native_quarantine_directory")
            .unwrap();
        let root_source = &source[root_start..root_end];
        let acl_start = source.find("fn harden_native_quarantine_root_acl").unwrap();
        let acl_end = source
            .find("#[cfg(windows)]\nstruct BoundedNativeQuarantineCommandOutput")
            .unwrap();
        let acl_source = &source[acl_start..acl_end];
        let runner_start = source.find("fn run_native_quarantine_acl_command").unwrap();
        let runner_end = source.find("fn command_output_excerpt").unwrap();
        let runner_source = &source[runner_start..runner_end];
        let tool_start = source.find("fn native_windows_system32_tool").unwrap();
        let tool_end = source
            .find("fn ensure_existing_native_quarantine_directory")
            .unwrap();
        let tool_source = &source[tool_start..tool_end];
        let old_icacls_launch = ["Command::new(\"", "icacls\")"].concat();

        assert!(root_source.contains("harden_native_quarantine_root_acl(path)?"));
        assert!(acl_source.contains("current_windows_account()?"));
        assert!(acl_source.contains("native_windows_system32_tool(\"icacls.exe\")?"));
        assert!(acl_source.contains("Command::new(&icacls)"));
        assert!(acl_source.contains("run_native_quarantine_acl_command(&mut command)?"));
        assert!(acl_source.contains("failed to harden native quarantine ACLs"));
        assert!(runner_source.contains("stdin(Stdio::null())"));
        assert!(runner_source.contains("stdout(Stdio::null())"));
        assert!(runner_source.contains("stderr(Stdio::piped())"));
        assert!(runner_source.contains("NATIVE_QUARANTINE_ACL_COMMAND_TIMEOUT"));
        assert!(runner_source.contains("failed to kill timed-out native quarantine ACL command"));
        assert!(runner_source.contains("failed to reap timed-out native quarantine ACL command"));
        assert!(tool_source.contains("Native Windows System32 tool root is unavailable"));
        assert!(
            tool_source.contains("Native Windows system root must not contain parent traversal")
        );
        assert!(tool_source.contains("is_local_windows_drive_path(&path)"));
        assert!(!acl_source.contains(&old_icacls_launch));
    }

    #[test]
    fn native_quarantine_finalization_failures_clean_untracked_payload() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn quarantine_file").unwrap();
        let end = source.find("fn native_quarantine_metadata_label").unwrap();
        let quarantine_source = &source[start..end];

        assert!(quarantine_source.contains("let finalize_result = (|| -> Result<QuarantineRecord>"));
        assert!(quarantine_source.contains("cleanup_quarantine_partial_file("));
        assert!(quarantine_source.contains("\"untracked native quarantine payload\""));
        assert!(quarantine_source.contains("after quarantine finalization failure"));
        assert!(quarantine_source.contains("Err(error)"));
        assert!(
            quarantine_source
                .find("fs::rename(path, &quarantine_path)")
                .unwrap()
                < quarantine_source
                    .find("let finalize_result = (|| -> Result<QuarantineRecord>")
                    .unwrap()
        );
        assert!(
            quarantine_source
                .find("cleanup_quarantine_partial_file(")
                .unwrap()
                < quarantine_source.rfind("Err(error)").unwrap()
        );
    }

    #[test]
    fn native_quarantine_copy_fallback_rejects_invalid_expected_hash_before_copy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("source.exe");
        let destination = temp.path().join("payload.avoraxq");
        fs::write(&source, b"benign native payload").expect("source");

        let error = copy_then_remove_verified(&source, &destination, "not-a-sha256")
            .expect_err("invalid expected hash should be rejected");

        assert!(source.exists());
        assert!(!destination.exists());
        assert!(error
            .to_string()
            .contains("invalid native quarantine copy expected sha256"));
    }

    #[test]
    fn native_quarantine_copy_fallback_accepts_bare_expected_hash() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("source.exe");
        let destination = temp.path().join("payload.avoraxq");
        fs::write(&source, b"benign native payload").expect("source");
        let expected_hash = sha256_body(&sha256_file(&source).expect("source hash")).to_string();

        copy_then_remove_verified(&source, &destination, &expected_hash).expect("copy fallback");

        assert!(!source.exists());
        assert!(destination.exists());
    }

    #[test]
    fn native_quarantine_copy_fallback_source_delete_failure_cleans_destination() {
        let source = include_str!("quarantine_store.rs");
        let start = source
            .find("pub(crate) fn copy_then_remove_verified")
            .unwrap();
        let end = source.find("fn copy_file_exclusive").unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("if let Err(error) = fs::remove_file(source)"));
        assert!(copy_source
            .contains("cleanup_quarantine_partial_file(destination, \"copied native quarantine destination\")"));
        assert!(copy_source.contains("after source deletion failure"));
        assert!(copy_source.contains("failed to delete original quarantine source"));
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
    fn native_quarantine_copy_fallback_verification_failure_cleans_destination() {
        let source = include_str!("quarantine_store.rs");
        let start = source
            .find("pub(crate) fn copy_then_remove_verified")
            .unwrap();
        let end = source.find("fn copy_file_exclusive").unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("let destination_hash = match (|| -> Result<String>"));
        assert!(copy_source.contains("invalid copied native quarantine destination"));
        assert!(copy_source.contains("after verification failure"));
        assert!(copy_source.contains("failed to verify copied native quarantine destination"));
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
    fn native_quarantine_copy_fallback_rejects_existing_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("source.exe");
        let destination = temp.path().join("payload.avoraxq");
        fs::write(&source, b"benign native payload").expect("source");
        fs::write(&destination, b"existing payload").expect("destination");
        let expected_hash = sha256_file(&source).expect("source hash");

        let error = copy_then_remove_verified(&source, &destination, &expected_hash)
            .expect_err("existing destination should be rejected");

        assert!(source.exists());
        assert_eq!(
            fs::read(&destination).expect("destination"),
            b"existing payload"
        );
        assert!(error
            .to_string()
            .contains("quarantine payload destination already exists"));
    }

    #[cfg(unix)]
    #[test]
    fn native_quarantine_copy_fallback_rejects_linked_destination() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("source.exe");
        let destination = temp.path().join("payload.avoraxq");
        let external = temp.path().join("external");
        fs::write(&source, b"benign native payload").expect("source");
        fs::write(&external, b"external payload").expect("external");
        symlink(&external, &destination).expect("symlink");
        let expected_hash = sha256_file(&source).expect("source hash");

        let error = copy_then_remove_verified(&source, &destination, &expected_hash)
            .expect_err("linked destination should be rejected");

        assert!(source.exists());
        assert_eq!(fs::read(&external).expect("external"), b"external payload");
        assert!(error
            .to_string()
            .contains("refusing to use symbolic link quarantine payload destination"));
    }
}
