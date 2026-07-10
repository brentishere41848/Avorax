#![allow(dead_code)]

use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
#[cfg(test)]
use uuid::Uuid;

use super::{ScanResult, ScanStatus, ScannerProvider};

pub struct ClamAvProvider;

#[derive(Clone, Debug)]
struct ClamAvCommand {
    executable: PathBuf,
    engine_name: String,
    database_dir: Option<PathBuf>,
}

#[derive(Debug)]
struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl ClamAvProvider {
    pub fn engine_status(&self) -> &'static str {
        match self.command() {
            Ok(Some(_)) => "available",
            Ok(None) => "unavailable",
            Err(_) => "error",
        }
    }

    fn command(&self) -> Result<Option<ClamAvCommand>> {
        if let Some(command) = configured_clamscan()? {
            return Ok(Some(command));
        }
        if let Some(command) = bundled_clamscan()? {
            return Ok(Some(command));
        }
        Ok(None)
    }
}

impl ScannerProvider for ClamAvProvider {
    fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        let started = Instant::now();
        let sha256 = sha256_file(path)?;
        if local_eicar_signature_match(path)? {
            return Ok(ScanResult {
                status: ScanStatus::Infected,
                scanned_path: path.display().to_string(),
                sha256,
                engine: "zentor-local-signatures".to_string(),
                signature_name: Some("EICAR-Test-Signature".to_string()),
                threat_name: Some("EICAR test signature".to_string()),
                scanned_at: Utc::now(),
                duration_ms: started.elapsed().as_millis(),
                raw_engine_summary: Some(
                    "Matched the standard EICAR antivirus test signature locally.".to_string(),
                ),
            });
        }
        let command = match self.command() {
            Ok(Some(command)) => command,
            Ok(None) => {
                return Ok(ScanResult {
                    status: ScanStatus::EngineUnavailable,
                    scanned_path: path.display().to_string(),
                    sha256,
                    engine: "clamav".to_string(),
                    signature_name: None,
                    threat_name: None,
                    scanned_at: Utc::now(),
                    duration_ms: started.elapsed().as_millis(),
                    raw_engine_summary: Some(
                        "No configured or bundled ClamAV scanner is available.".to_string(),
                    ),
                });
            }
            Err(error) => {
                return Ok(ScanResult {
                    status: ScanStatus::Error,
                    scanned_path: path.display().to_string(),
                    sha256,
                    engine: "clamav".to_string(),
                    signature_name: None,
                    threat_name: None,
                    scanned_at: Utc::now(),
                    duration_ms: started.elapsed().as_millis(),
                    raw_engine_summary: Some(format!("ClamAV scanner discovery failed: {error:#}")),
                });
            }
        };
        let mut process = Command::new(&command.executable);
        process.arg("--no-summary");
        if let Some(database_dir) = &command.database_dir {
            process.arg("--database").arg(database_dir);
        }
        process.arg(path);
        let BoundedCommandOutput {
            status,
            stdout,
            stderr,
        } = run_clamav_command(&mut process)?;
        let combined = format!("{stdout}{stderr}");
        let infected = status.code() == Some(1);
        let clean = status.success();
        let threat = if infected {
            Some(
                combined
                    .split(':')
                    .nth(1)
                    .map(|value| value.replace("FOUND", "").trim().to_string())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "ClamAV compatibility detection".to_string()),
            )
        } else {
            None
        };
        Ok(ScanResult {
            status: if infected {
                ScanStatus::Infected
            } else if clean {
                ScanStatus::Clean
            } else {
                ScanStatus::Error
            },
            scanned_path: path.display().to_string(),
            sha256,
            engine: command.engine_name,
            signature_name: threat.clone(),
            threat_name: threat,
            scanned_at: Utc::now(),
            duration_ms: started.elapsed().as_millis(),
            raw_engine_summary: Some(combined),
        })
    }
}

const EICAR_TEST_SIGNATURE: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const ZENTOR_SAFE_EICAR_SIMULATOR: &str = "ZENTOR-SAFE-EICAR-SIMULATOR-FILE";
const LOCAL_SIGNATURE_SAMPLE_LIMIT_BYTES: u64 = 1_048_576;
const MAX_CLAMAV_HASH_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CLAMAV_COMMAND_OUTPUT_BYTES: usize = 8192;
const CLAMAV_SCAN_TIMEOUT: Duration = Duration::from_secs(120);

fn run_clamav_command(process: &mut Command) -> Result<BoundedCommandOutput> {
    process.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = process.spawn().context("failed to start ClamAV scanner")?;
    let stdout = child.stdout.take().context("missing ClamAV stdout pipe")?;
    let stderr = child.stderr.take().context("missing ClamAV stderr pipe")?;
    let stdout_reader = spawn_bounded_output_reader(stdout, "stdout");
    let stderr_reader = spawn_bounded_output_reader(stderr, "stderr");
    let status = match wait_for_clamav_child(&mut child, CLAMAV_SCAN_TIMEOUT)
        .context("failed to wait for ClamAV scanner")?
    {
        Some(status) => status,
        None => {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let stdout = join_output_reader(stdout_reader, "stdout")?;
            let stderr = join_output_reader(stderr_reader, "stderr")?;
            let detail = format!("{stdout}{stderr}");
            if let Some(error) = &kill_error {
                if let Some(wait_error) = &wait_error {
                    anyhow::bail!(
                        "ClamAV scanner exceeded {} seconds and failed to terminate: {error}; failed to reap timed-out ClamAV scanner: {wait_error}; output: {detail}",
                        CLAMAV_SCAN_TIMEOUT.as_secs()
                    );
                }
                anyhow::bail!(
                    "ClamAV scanner exceeded {} seconds and failed to terminate: {error}; output: {detail}",
                    CLAMAV_SCAN_TIMEOUT.as_secs()
                );
            }
            if let Some(error) = wait_error {
                anyhow::bail!(
                    "ClamAV scanner exceeded {} seconds and failed to reap timed-out ClamAV scanner: {error}; output: {detail}",
                    CLAMAV_SCAN_TIMEOUT.as_secs()
                );
            }
            anyhow::bail!(
                "ClamAV scanner exceeded {} seconds; output: {detail}",
                CLAMAV_SCAN_TIMEOUT.as_secs()
            );
        }
    };
    let stdout = join_output_reader(stdout_reader, "stdout")?;
    let stderr = join_output_reader(stderr_reader, "stderr")?;
    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_clamav_child(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
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

fn spawn_bounded_output_reader<R>(
    reader: R,
    label: &'static str,
) -> thread::JoinHandle<Result<String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || read_bounded_command_output(reader, label))
}

fn join_output_reader(handle: thread::JoinHandle<Result<String>>, label: &str) -> Result<String> {
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("ClamAV {label} reader panicked"))?
}

fn read_bounded_command_output<R: Read>(reader: R, label: &str) -> Result<String> {
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    let retain_limit = MAX_CLAMAV_COMMAND_OUTPUT_BYTES.saturating_add(1);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("failed to read ClamAV {label}"))?;
        if read == 0 {
            break;
        }
        let remaining = retain_limit.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = read.min(remaining);
            bytes.extend_from_slice(&buffer[..keep]);
        }
    }
    let truncated = bytes.len() > MAX_CLAMAV_COMMAND_OUTPUT_BYTES;
    if truncated {
        bytes.truncate(MAX_CLAMAV_COMMAND_OUTPUT_BYTES);
    }
    let mut text = String::from_utf8_lossy(&bytes).to_string();
    if truncated {
        text.push_str("...[truncated]");
    }
    Ok(text)
}

fn local_eicar_signature_match(path: &Path) -> Result<bool> {
    ensure_regular_clamav_file(path, "local signature scan target")?;
    let file = File::open(path).with_context(|| {
        format!(
            "failed to open local signature scan target {}",
            path.display()
        )
    })?;
    local_eicar_signature_match_reader(file, LOCAL_SIGNATURE_SAMPLE_LIMIT_BYTES).with_context(
        || {
            format!(
                "failed to read local signature scan target {}",
                path.display()
            )
        },
    )
}

fn local_eicar_signature_match_reader<R: Read>(mut reader: R, limit: u64) -> io::Result<bool> {
    let max_signature_len = EICAR_TEST_SIGNATURE
        .len()
        .max(ZENTOR_SAFE_EICAR_SIMULATOR.len());
    let overlap_len = max_signature_len.saturating_sub(1);
    let mut overlap = Vec::new();
    let mut buffer = vec![0_u8; 8192];
    let mut remaining = limit;

    while remaining > 0 {
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..read_limit])?;
        if read == 0 {
            return Ok(false);
        }
        remaining -= read as u64;

        let mut sample = Vec::with_capacity(overlap.len() + read);
        sample.extend_from_slice(&overlap);
        sample.extend_from_slice(&buffer[..read]);
        if local_eicar_signature_match_bytes(&sample) {
            return Ok(true);
        }

        let retain = overlap_len.min(sample.len());
        overlap.clear();
        overlap.extend_from_slice(&sample[sample.len() - retain..]);
    }
    Ok(false)
}

fn local_eicar_signature_match_bytes(bytes: &[u8]) -> bool {
    bytes
        .windows(EICAR_TEST_SIGNATURE.len())
        .any(|window| window == EICAR_TEST_SIGNATURE.as_bytes())
        || bytes
            .windows(ZENTOR_SAFE_EICAR_SIMULATOR.len())
            .any(|window| window == ZENTOR_SAFE_EICAR_SIMULATOR.as_bytes())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let metadata = ensure_regular_clamav_file(path, "file to hash")?;
    if metadata.len() > MAX_CLAMAV_HASH_BYTES {
        anyhow::bail!(
            "file to hash {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_CLAMAV_HASH_BYTES
        );
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("ClamAV hash input size overflow"))?;
        if total > MAX_CLAMAV_HASH_BYTES {
            anyhow::bail!(
                "file to hash {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_CLAMAV_HASH_BYTES
            );
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn bundled_clamscan() -> Result<Option<ClamAvCommand>> {
    let executable_name = if cfg!(windows) {
        "clamscan.exe"
    } else {
        "clamscan"
    };

    let mut roots = Vec::new();
    let exe = env::current_exe()
        .context("failed to read current executable path for bundled ClamAV discovery")?;
    let parent = exe
        .parent()
        .context("current executable path has no parent for bundled ClamAV discovery")?;
    roots.push(parent.to_path_buf());

    for root in roots {
        let candidates = [
            root.join("ClamAV").join(executable_name),
            root.join(executable_name),
        ];
        for candidate in candidates {
            if optional_regular_clamav_executable(&candidate, "bundled ClamAV scanner")? {
                return command_from_path(candidate).map(Some);
            }
        }
    }

    Ok(None)
}

fn configured_clamscan() -> Result<Option<ClamAvCommand>> {
    let raw = match env::var("ZENTOR_CLAMAV_CLAMSCAN") {
        Ok(raw) => raw,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(error) => anyhow::bail!("ZENTOR_CLAMAV_CLAMSCAN is not valid Unicode: {error}"),
    };
    if raw.trim().is_empty() {
        anyhow::bail!("configured ClamAV scanner path is empty");
    }
    let executable_text = validate_configured_clamscan_path_text(&raw)?;
    let executable = PathBuf::from(executable_text);
    ensure_regular_clamav_executable(&executable, "configured ClamAV scanner")?;
    command_from_path(executable).map(Some)
}

fn validate_configured_clamscan_path_text(raw: &str) -> Result<&str> {
    let text = raw.trim();
    if text.is_empty() {
        anyhow::bail!("configured ClamAV scanner path is empty");
    }
    if text.contains('\0') {
        anyhow::bail!("configured ClamAV scanner path contains NUL");
    }
    if configured_clamscan_path_has_parent_traversal(text) {
        anyhow::bail!("configured ClamAV scanner path must not contain parent traversal");
    }
    Ok(text)
}

fn configured_clamscan_path_has_parent_traversal(value: &str) -> bool {
    value.replace('\\', "/").split('/').any(|part| part == "..")
}

fn command_from_path(executable: PathBuf) -> Result<ClamAvCommand> {
    let database_dir = if let Some(path) = executable.parent().map(|parent| parent.join("database"))
    {
        if optional_regular_clamav_directory(&path, "ClamAV database directory")? {
            Some(path)
        } else {
            None
        }
    } else {
        None
    };
    Ok(ClamAvCommand {
        engine_name: executable.display().to_string(),
        executable,
        database_dir,
    })
}

fn ensure_regular_clamav_executable(path: &Path, label: &str) -> Result<fs::Metadata> {
    ensure_clamav_executable_location(path, label)?;
    ensure_regular_clamav_file(path, label)
}

fn optional_regular_clamav_executable(path: &Path, label: &str) -> Result<bool> {
    ensure_clamav_executable_location(path, label)?;
    optional_regular_clamav_file(path, label)
}

fn ensure_clamav_executable_location(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("{label} {} must be an absolute path", path.display());
    }
    if !clamav_executable_path_is_local(path) {
        anyhow::bail!("{label} {} must be on a local path", path.display());
    }
    Ok(())
}

fn ensure_regular_clamav_file(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    ensure_clamav_metadata_safe(path, label, &metadata)?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    Ok(metadata)
}

fn ensure_regular_clamav_directory(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    ensure_clamav_metadata_safe(path, label, &metadata)?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("{label} {} is not a directory", path.display());
    }
    Ok(metadata)
}

fn optional_regular_clamav_file(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_clamav_metadata_safe(path, label, &metadata)?;
            if !metadata.file_type().is_file() {
                anyhow::bail!("{label} {} is not a regular file", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect {label} {}", path.display()))
        }
    }
}

fn optional_regular_clamav_directory(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_clamav_metadata_safe(path, label, &metadata)?;
            if !metadata.file_type().is_dir() {
                anyhow::bail!("{label} {} is not a directory", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_clamav_metadata_safe(path: &Path, label: &str, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label} {}", path.display());
    }
    if clamav_metadata_is_windows_reparse_point(metadata) {
        anyhow::bail!("refusing to use reparse point {label} {}", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn clamav_executable_path_is_local(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn clamav_executable_path_is_local(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(windows)]
fn clamav_metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn clamav_metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_clamav_test_path(prefix: &str, extension: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "{prefix}-{}-{}.{extension}",
            std::process::id(),
            Uuid::new_v4()
        ))
    }

    #[test]
    fn local_eicar_signature_bytes_are_detected() {
        assert!(local_eicar_signature_match_bytes(
            EICAR_TEST_SIGNATURE.as_bytes()
        ));
        assert!(local_eicar_signature_match_bytes(
            ZENTOR_SAFE_EICAR_SIMULATOR.as_bytes()
        ));
        assert!(!local_eicar_signature_match_bytes(b"normal installer"));
    }

    #[test]
    fn local_eicar_signature_reader_detects_chunk_boundary_match() {
        let mut bytes = vec![b'A'; 8190];
        bytes.extend_from_slice(EICAR_TEST_SIGNATURE.as_bytes());
        assert!(local_eicar_signature_match_reader(bytes.as_slice(), 16 * 1024).unwrap());
    }

    #[test]
    fn local_eicar_signature_reader_uses_bounded_sample() {
        let mut bytes = vec![b'A'; LOCAL_SIGNATURE_SAMPLE_LIMIT_BYTES as usize + 1];
        bytes.extend_from_slice(EICAR_TEST_SIGNATURE.as_bytes());
        assert!(!local_eicar_signature_match_reader(
            bytes.as_slice(),
            LOCAL_SIGNATURE_SAMPLE_LIMIT_BYTES
        )
        .unwrap());
    }

    #[test]
    fn sha256_file_streams_full_file() {
        let path = unique_clamav_test_path("avorax-clamav-sha256-stream", "bin");
        let bytes = vec![b'Z'; 2 * 1024 * 1024 + 17];
        std::fs::write(&path, &bytes).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let expected = format!("sha256:{:x}", hasher.finalize());
        assert_eq!(sha256_file(&path).unwrap(), expected);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn clamav_hash_input_is_size_bounded() {
        let source = include_str!("clamav_provider.rs");
        let start = source.find("pub fn sha256_file").unwrap();
        let end = source.find("fn bundled_clamscan").unwrap();
        let hash_source = &source[start..end];

        assert!(source.contains("const MAX_CLAMAV_HASH_BYTES"));
        assert!(hash_source.contains("metadata.len() > MAX_CLAMAV_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("checked_add(read as u64)"));
        assert!(hash_source.contains("total > MAX_CLAMAV_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
    }

    #[test]
    fn clamav_command_output_is_bounded() {
        let long = vec![b'a'; MAX_CLAMAV_COMMAND_OUTPUT_BYTES + 16];
        let text = read_bounded_command_output(long.as_slice(), "test").unwrap();
        assert!(text.ends_with("...[truncated]"));
        assert_eq!(
            text.len(),
            MAX_CLAMAV_COMMAND_OUTPUT_BYTES + "...[truncated]".len()
        );

        let source = include_str!("clamav_provider.rs");
        let old_output_call = ["process.arg(path).", "output()?"].concat();
        let old_stdout = ["String::from_utf8_lossy(&output.stdout)", ".to_string()"].concat();
        let old_stderr = ["String::from_utf8_lossy(&output.stderr)", ".to_string()"].concat();
        assert!(source.contains("run_clamav_command(&mut process)?"));
        assert!(source.contains("MAX_CLAMAV_COMMAND_OUTPUT_BYTES"));
        assert!(source.contains("CLAMAV_SCAN_TIMEOUT"));
        assert!(source.contains("failed to reap timed-out ClamAV scanner"));
        assert!(
            source.contains("let retain_limit = MAX_CLAMAV_COMMAND_OUTPUT_BYTES.saturating_add(1)")
        );
        assert!(source.contains("let remaining = retain_limit.saturating_sub(bytes.len())"));
        assert!(source.contains("bytes.extend_from_slice(&buffer[..keep])"));
        let old_wait = ["let _ = child.", "wait();"].concat();
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production_source
            .contains("reader.take((MAX_CLAMAV_COMMAND_OUTPUT_BYTES + 1) as u64)"));
        assert!(!source.contains(&old_output_call));
        assert!(!source.contains(&old_stdout));
        assert!(!source.contains(&old_stderr));
        assert!(!source.contains(&old_wait));
    }

    #[test]
    fn local_signature_scan_errors_are_reported() {
        let source = include_str!("clamav_provider.rs");
        let old_reader_default = [
            "local_eicar_signature_match_reader(file, LOCAL_SIGNATURE_SAMPLE_LIMIT_BYTES)",
            ".unwrap_or(false)",
        ]
        .concat();

        assert!(source.contains("fn local_eicar_signature_match(path: &Path) -> Result<bool>"));
        assert!(source.contains("local_eicar_signature_match(path)?"));
        assert!(source.contains("failed to read local signature scan target"));
        assert!(!source.contains(&old_reader_default));
    }

    #[test]
    fn clamav_infected_exit_always_has_detection_name() {
        let source = include_str!("clamav_provider.rs");
        let scan_start = source.find("fn scan_file(&self").unwrap();
        let scan_end = source.find("const EICAR_TEST_SIGNATURE").unwrap();
        let scan_source = &source[scan_start..scan_end];

        assert!(scan_source.contains("if infected"));
        assert!(scan_source.contains("ClamAV compatibility detection"));
        assert!(scan_source
            .contains("unwrap_or_else(|| \"ClamAV compatibility detection\".to_string())"));
        assert!(scan_source.contains("signature_name: threat.clone()"));
        assert!(scan_source.contains("threat_name: threat"));
        assert!(!scan_source.contains(".filter(|value| !value.is_empty())\n        } else"));
    }

    #[test]
    fn clamav_discovery_avoids_ambient_path_lookup() {
        let source = include_str!("clamav_provider.rs");
        let command_start = source
            .find("fn command(&self) -> Result<Option<ClamAvCommand>>")
            .unwrap();
        let command_end = source
            .find("impl ScannerProvider for ClamAvProvider")
            .unwrap();
        let command_source = &source[command_start..command_end];
        let bundled_start = source.find("fn bundled_clamscan").unwrap();
        let bundled_end = source.find("fn configured_clamscan").unwrap();
        let bundled_source = &source[bundled_start..bundled_end];
        let configured_start = source.find("fn configured_clamscan").unwrap();
        let configured_end = source.find("fn command_from_path").unwrap();
        let configured_source = &source[configured_start..configured_end];
        let old_configured_skip = ["env::var(\"ZENTOR_CLAMAV_CLAMSCAN\").", "ok()?"].concat();
        let old_command_available_fn = ["fn command_", "available"].concat();
        let old_probe_launch = ["Command::", "new(probe)"].concat();
        let old_clamdscan_name = ["PathBuf::from(\"clamd", "scan\")"].concat();
        let old_clamscan_name = ["PathBuf::from(\"clam", "scan\")"].concat();

        assert!(source.contains("fn command(&self) -> Result<Option<ClamAvCommand>>"));
        assert!(source.contains("ClamAV scanner discovery failed: {error:#}"));
        assert!(source.contains("No configured or bundled ClamAV scanner is available."));
        assert!(
            source.contains("failed to read current executable path for bundled ClamAV discovery")
        );
        assert!(source.contains("configured ClamAV scanner path is empty"));
        assert!(source.contains(
            "ensure_regular_clamav_executable(&executable, \"configured ClamAV scanner\")?"
        ));
        assert!(source.contains(
            "optional_regular_clamav_executable(&candidate, \"bundled ClamAV scanner\")?"
        ));
        assert!(source.contains("optional_regular_clamav_directory"));
        assert!(source.contains("must be an absolute path"));
        assert!(source.contains("must be on a local path"));
        assert!(!source.contains(&old_command_available_fn));
        assert!(!source.contains(&old_probe_launch));
        assert!(!source.contains(&old_clamdscan_name));
        assert!(!source.contains(&old_clamscan_name));
        assert!(!command_source.contains("command_available"));
        assert!(!bundled_source.contains("env::current_dir"));
        assert!(!configured_source.contains(&old_configured_skip));
    }

    #[test]
    fn configured_clamscan_path_rejects_parent_traversal_text() {
        let traversal_error =
            validate_configured_clamscan_path_text("C:\\Avorax\\..\\ClamAV\\clamscan.exe")
                .unwrap_err()
                .to_string();
        let nul_error = validate_configured_clamscan_path_text("C:\\Avorax\\clam\0scan.exe")
            .unwrap_err()
            .to_string();

        assert!(traversal_error.contains("must not contain parent traversal"));
        assert!(nul_error.contains("contains NUL"));
    }

    #[cfg(unix)]
    #[test]
    fn clamav_hash_and_local_signature_reject_symbolic_links() {
        let base = unique_clamav_test_path("avorax-clamav-symlink", "dir");
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("target.bin");
        let link = base.join("linked.bin");
        std::fs::write(&target, ZENTOR_SAFE_EICAR_SIMULATOR.as_bytes()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let hash_error = sha256_file(&link).unwrap_err().to_string();

        assert!(hash_error.contains("symbolic link"));
        let local_signature_error = local_eicar_signature_match(&link).unwrap_err().to_string();
        assert!(local_signature_error.contains("symbolic link"));
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_dir(&base);
    }

    #[test]
    fn clamav_provider_uses_non_following_paths() {
        let source = include_str!("clamav_provider.rs");
        let file_helper_pattern = ["fn ensure_regular_clamav_", "file"].concat();
        let dir_helper_pattern = ["fn ensure_regular_clamav_", "directory"].concat();
        let symlink_metadata_pattern = ["fs::", "symlink_metadata(path)"].concat();
        let bundled_candidate_pattern = [
            "optional_regular_clamav_executable(&candidate",
            ", \"bundled ClamAV scanner\")",
        ]
        .concat();
        let configured_pattern = [
            "ensure_regular_clamav_executable(&executable",
            ", \"configured ClamAV scanner\")",
        ]
        .concat();
        let database_pattern = [
            "optional_regular_clamav_directory(&path",
            ", \"ClamAV database directory\")",
        ]
        .concat();
        let symlink_error_pattern = ["refusing to use symbolic link ", "{label}"].concat();
        let reparse_error_pattern = ["refusing to use reparse point ", "{label}"].concat();
        let old_candidate_probe = ["candidate.", "is_file()"].concat();
        let old_executable_probe = ["executable.", "is_file()"].concat();
        let old_database_probe = ["path.", "is_dir()"].concat();
        let old_current_dir_root = ["env::", "current_dir()"].concat();

        assert!(source.contains(&file_helper_pattern));
        assert!(source.contains(&dir_helper_pattern));
        assert!(source.contains(
            "fn ensure_clamav_executable_location(path: &Path, label: &str) -> Result<()>"
        ));
        assert!(source.contains("fn clamav_executable_path_is_local(path: &Path) -> bool"));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&bundled_candidate_pattern));
        assert!(source.contains(&configured_pattern));
        assert!(source.contains(&database_pattern));
        assert!(source.contains(&symlink_error_pattern));
        assert!(source.contains(&reparse_error_pattern));
        assert!(!source.contains(&old_candidate_probe));
        assert!(!source.contains(&old_executable_probe));
        assert!(!source.contains(&old_database_probe));
        assert!(!source.contains(&old_current_dir_root));
    }
}
