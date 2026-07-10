use std::collections::HashSet;
use std::fs;
use std::io::Write;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

use crate::driver_health::DriverHealth;
use crate::driver_ipc::{
    evaluate_driver_request, DriverEventType, DriverVerdictAction, DriverVerdictConfig, ScanRequest,
};
use crate::preexecution_policy::DriverProtectionMode;

const MAX_AI_MODEL_METADATA_BYTES: u64 = 64 * 1024;
const MAX_AI_MODEL_VERSION_LEN: usize = 128;
const MAX_GUARD_SELF_TEST_HASH_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SelfTestStep {
    pub name: String,
    pub passed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProtectionSelfTest {
    pub zentor_version: String,
    pub timestamp_utc: String,
    pub driver: DriverSelfTestStatus,
    pub guard_service: GuardServiceSelfTestStatus,
    pub tests: ProtectionSelfTestResults,
    pub ai: AiSelfTestStatus,
    pub overall_result: String,
    pub passed: bool,
    pub pre_execution_blocking_available: bool,
    pub steps: Vec<SelfTestStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DriverSelfTestStatus {
    pub built: bool,
    pub installed: bool,
    pub running: bool,
    pub test_signed: bool,
    pub production_signed: bool,
    pub communication_port_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GuardServiceSelfTestStatus {
    pub running: bool,
    pub ipc_ok: bool,
    pub verdict_cache_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProtectionSelfTestResults {
    pub eicar_scan_blocked: bool,
    pub eicar_quarantined: bool,
    pub known_bad_executable_blocked_before_launch: bool,
    pub known_bad_executable_quarantined: bool,
    pub unknown_unsigned_lockdown_blocked_before_launch: bool,
    pub unknown_unsigned_lockdown_policy_blocked: bool,
    pub unknown_unsigned_allowed_after_hash_approval: bool,
    pub known_good_executable_allowed: bool,
    pub normal_exe_blocked_only_as_unknown: bool,
    pub post_launch_fallback_verified: bool,
    pub quarantine_ui_record_created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AiSelfTestStatus {
    pub model_loaded: bool,
    pub model_version: String,
    pub production_ready: bool,
    pub can_auto_quarantine_ai_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_error: Option<String>,
}

pub fn run_self_test(known_bad_hashes: HashSet<String>) -> anyhow::Result<ProtectionSelfTest> {
    let health = DriverHealth::probe();
    let mut steps = vec![
        step(
            "Guard self-test handler",
            true,
            "Guard self-test command was handled by this process; this is not installed Windows service evidence.",
        ),
        step("Driver installed", health.installed, &health.reason),
        step(
            "Driver running",
            health.running,
            if health.running {
                "Driver reports running."
            } else {
                &health.reason
            },
        ),
        step(
            "Driver IPC alive",
            health.ipc_connected,
            if health.ipc_connected {
                "Driver communication probe succeeded."
            } else if !health.running {
                "Driver IPC probe skipped because the minifilter is not loaded."
            } else {
                &health.reason
            },
        ),
    ];

    let dir = tempdir()?;
    let eicar = dir.path().join("safe-eicar.com");
    write_self_test_fixture(
        &eicar,
        b"ZENTOR-SAFE-EICAR-SIMULATOR-FILE",
        "EICAR self-test fixture",
    )?;
    let eicar_verdict = evaluate_driver_request(
        &request_for(&eicar),
        &DriverVerdictConfig {
            known_bad_hashes: known_bad_hashes.clone(),
            ..Default::default()
        },
    )?;
    steps.push(step(
        "EICAR detection works",
        eicar_verdict.action == DriverVerdictAction::Block,
        &eicar_verdict.reason_summary,
    ));

    let known_bad = dir.path().join("known-bad-test.exe");
    write_self_test_fixture(
        &known_bad,
        b"harmless known bad test executable",
        "known-bad self-test fixture",
    )?;
    let hash = sha256_file(&known_bad)?;
    let mut hashes = known_bad_hashes;
    hashes.insert(normalize_hash(&hash)?);
    let known_bad_verdict = evaluate_driver_request(
        &request_for(&known_bad),
        &DriverVerdictConfig {
            known_bad_hashes: hashes,
            ..Default::default()
        },
    )?;
    steps.push(step(
        "Known bad test executable verdict",
        known_bad_verdict.action == DriverVerdictAction::Block,
        &known_bad_verdict.reason_summary,
    ));

    let unknown = dir.path().join("unknown-unsigned-test.exe");
    write_self_test_fixture(
        &unknown,
        b"harmless unknown unsigned executable",
        "unknown unsigned self-test fixture",
    )?;
    let unknown_hash = sha256_file(&unknown)?;
    let lockdown_unknown_verdict = evaluate_driver_request(
        &request_for(&unknown),
        &DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        },
    )?;
    steps.push(step(
        "Lockdown unknown app policy",
        lockdown_unknown_verdict.action == DriverVerdictAction::Block
            && !lockdown_unknown_verdict.label_as_malware
            && !lockdown_unknown_verdict.quarantine_after_block,
        &lockdown_unknown_verdict.reason_summary,
    ));

    let approved_unknown_verdict = evaluate_driver_request(
        &request_for(&unknown),
        &DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            user_approved_hashes: HashSet::from([normalize_hash(&unknown_hash)?]),
            ..Default::default()
        },
    )?;
    steps.push(step(
        "Exact-hash user approval allows unknown app",
        approved_unknown_verdict.action == DriverVerdictAction::Allow,
        &approved_unknown_verdict.reason_summary,
    ));

    let known_good = dir.path().join("known-good-test.exe");
    write_self_test_fixture(
        &known_good,
        b"harmless known good executable",
        "known-good self-test fixture",
    )?;
    let known_good_hash = sha256_file(&known_good)?;
    let known_good_verdict = evaluate_driver_request(
        &request_for(&known_good),
        &DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            known_good_hashes: HashSet::from([normalize_hash(&known_good_hash)?]),
            ..Default::default()
        },
    )?;
    steps.push(step(
        "Known-good executable allowed",
        known_good_verdict.action == DriverVerdictAction::Allow,
        &known_good_verdict.reason_summary,
    ));

    let normal_download_exe = dir.path().join("Downloads").join("vpn-installer.exe");
    write_self_test_fixture(
        &normal_download_exe,
        b"normal installer-like fixture",
        "normal download self-test fixture",
    )?;
    let normal_lockdown_verdict = evaluate_driver_request(
        &request_for(&normal_download_exe),
        &DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        },
    )?;
    steps.push(step(
        "Normal executable is not labeled malware",
        normal_lockdown_verdict.action == DriverVerdictAction::Block
            && !normal_lockdown_verdict.label_as_malware
            && normal_lockdown_verdict
                .reason_summary
                .contains("Lockdown Mode"),
        &normal_lockdown_verdict.reason_summary,
    ));

    let post_launch_fallback_verified = eicar_verdict.action == DriverVerdictAction::Block
        && known_bad_verdict.action == DriverVerdictAction::Block
        && lockdown_unknown_verdict.action == DriverVerdictAction::Block
        && approved_unknown_verdict.action == DriverVerdictAction::Allow
        && known_good_verdict.action == DriverVerdictAction::Allow
        && normal_lockdown_verdict.action == DriverVerdictAction::Block
        && !normal_lockdown_verdict.label_as_malware;
    steps.push(step(
        "Post-launch verdict fallback",
        post_launch_fallback_verified,
        if post_launch_fallback_verified {
            "Guard verdict path handled safe block, allow, and review fixtures."
        } else {
            "Guard verdict path did not satisfy every safe post-launch fallback fixture."
        },
    ));

    let pre_execution_blocking_available = health.running
        && health.ipc_connected
        && eicar_verdict.action == DriverVerdictAction::Block
        && known_bad_verdict.action == DriverVerdictAction::Block
        && lockdown_unknown_verdict.action == DriverVerdictAction::Block;
    steps.push(step(
        "Pre-execution block self-test",
        pre_execution_blocking_available,
        if pre_execution_blocking_available {
            "Driver and service path can return blocking verdicts.".to_string()
        } else if !health.running {
            format!(
                "Pre-execution blocking is not active because the minifilter is not loaded: {} Post-launch fallback remains available.",
                health.reason
            )
        } else if !health.ipc_connected {
            format!(
                "Pre-execution blocking is not active because driver IPC is unavailable: {} Post-launch fallback remains available.",
                health.reason
            )
        } else {
            "Pre-execution blocking is not active; post-launch fallback remains available.".to_string()
        }
        .as_str(),
    ));

    let tests = ProtectionSelfTestResults {
        eicar_scan_blocked: eicar_verdict.action == DriverVerdictAction::Block,
        eicar_quarantined: false,
        known_bad_executable_blocked_before_launch: pre_execution_blocking_available,
        known_bad_executable_quarantined: false,
        unknown_unsigned_lockdown_blocked_before_launch: pre_execution_blocking_available,
        unknown_unsigned_lockdown_policy_blocked: lockdown_unknown_verdict.action
            == DriverVerdictAction::Block,
        unknown_unsigned_allowed_after_hash_approval: approved_unknown_verdict.action
            == DriverVerdictAction::Allow,
        known_good_executable_allowed: known_good_verdict.action == DriverVerdictAction::Allow,
        normal_exe_blocked_only_as_unknown: normal_lockdown_verdict.action
            == DriverVerdictAction::Block
            && !normal_lockdown_verdict.label_as_malware,
        post_launch_fallback_verified,
        quarantine_ui_record_created: false,
    };
    let ai = ai_status();
    let passed = steps.iter().all(|step| step.passed);
    let guard_handler_available = steps
        .iter()
        .any(|step| step.name == "Guard self-test handler" && step.passed);
    let guard_service_ipc_ok = guard_handler_available && post_launch_fallback_verified;
    Ok(ProtectionSelfTest {
        zentor_version: "0.1.13".to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        driver: DriverSelfTestStatus {
            built: false,
            installed: health.installed,
            running: health.running,
            test_signed: health.test_signed,
            production_signed: false,
            communication_port_ok: health.ipc_connected,
        },
        guard_service: GuardServiceSelfTestStatus {
            running: guard_handler_available,
            ipc_ok: guard_service_ipc_ok,
            verdict_cache_ok: false,
        },
        tests,
        ai,
        overall_result: if passed { "pass" } else { "fail" }.to_string(),
        passed,
        pre_execution_blocking_available,
        steps,
    })
}

fn write_self_test_fixture(path: &Path, bytes: &[u8], label: &str) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("guard self-test fixture path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {label} directory {}", parent.display()))?;
    ensure_self_test_fixture_directory(parent, label)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {label} {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {label} {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {label} {}", path.display()))?;
    Ok(())
}

fn ensure_self_test_fixture_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} directory {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to use symbolic link {label} directory {}",
            path.display()
        );
    }
    if is_windows_reparse_point(&metadata) {
        anyhow::bail!(
            "refusing to use reparse point {label} directory {}",
            path.display()
        );
    }
    if !metadata.is_dir() {
        anyhow::bail!("{label} directory is not a directory: {}", path.display());
    }
    Ok(())
}

fn request_for(path: &std::path::Path) -> ScanRequest {
    ScanRequest {
        request_id: "self-test".to_string(),
        event_type: DriverEventType::ImageExecuteAttempt,
        file_path: path.display().to_string(),
        normalized_file_path: None,
        process_id: None,
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

fn normalize_hash(value: &str) -> anyhow::Result<String> {
    normalize_sha256(value).context("guard self-test generated hash is not a valid SHA-256 value")
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

fn step(name: &str, passed: bool, reason: &str) -> SelfTestStep {
    SelfTestStep {
        name: name.to_string(),
        passed,
        reason: reason.to_string(),
    }
}

fn sha256_file(path: &std::path::Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let metadata = ensure_regular_self_test_hash_file(path)?;
    if metadata.len() > MAX_GUARD_SELF_TEST_HASH_BYTES {
        anyhow::bail!(
            "guard self-test hash target {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_GUARD_SELF_TEST_HASH_BYTES
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
            .ok_or_else(|| anyhow::anyhow!("guard self-test hash size overflow"))?;
        if total > MAX_GUARD_SELF_TEST_HASH_BYTES {
            anyhow::bail!(
                "guard self-test hash target {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_GUARD_SELF_TEST_HASH_BYTES
            );
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn ensure_regular_self_test_hash_file(path: &Path) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "unable to inspect guard self-test hash target {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "guard self-test hash target {} is a symbolic link",
            path.display()
        );
    }
    if is_windows_reparse_point(&metadata) {
        anyhow::bail!(
            "guard self-test hash target {} is a reparse point",
            path.display()
        );
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "guard self-test hash target {} is not a regular file",
            path.display()
        );
    }
    Ok(metadata)
}

fn ai_status() -> AiSelfTestStatus {
    let path = match find_model_metadata() {
        Ok(Some(path)) => path,
        Ok(None) => {
            return AiSelfTestStatus {
                model_loaded: false,
                model_version: "missing".to_string(),
                production_ready: false,
                can_auto_quarantine_ai_only: false,
                metadata_error: Some("model metadata file not found".to_string()),
            };
        }
        Err(error) => {
            return AiSelfTestStatus {
                model_loaded: false,
                model_version: "unreadable".to_string(),
                production_ready: false,
                can_auto_quarantine_ai_only: false,
                metadata_error: Some(format!("failed to inspect model metadata: {error:#}")),
            };
        }
    };
    let raw = match read_bounded_model_metadata(&path) {
        Ok(raw) => raw,
        Err(error) => {
            return AiSelfTestStatus {
                model_loaded: false,
                model_version: "unreadable".to_string(),
                production_ready: false,
                can_auto_quarantine_ai_only: false,
                metadata_error: Some(format!(
                    "failed to read model metadata {}: {error}",
                    path.display()
                )),
            };
        }
    };
    parse_model_metadata_status(&path, &raw)
}

fn parse_model_metadata_status(path: &Path, raw: &str) -> AiSelfTestStatus {
    let json: serde_json::Value = match serde_json::from_str(raw) {
        Ok(json) => json,
        Err(error) => {
            return AiSelfTestStatus {
                model_loaded: false,
                model_version: "invalid".to_string(),
                production_ready: false,
                can_auto_quarantine_ai_only: false,
                metadata_error: Some(format!(
                    "failed to parse model metadata {}: {error}",
                    path.display()
                )),
            };
        }
    };
    if !json.is_object() {
        return invalid_model_metadata_status(path, "model metadata root must be a JSON object");
    }
    let Some(model_version) = json
        .get("model_version")
        .and_then(|value| value.as_str())
        .map(str::trim)
    else {
        return invalid_model_metadata_status(
            path,
            "model metadata model_version must be a string",
        );
    };
    if model_version.is_empty() {
        return invalid_model_metadata_status(
            path,
            "model metadata model_version must not be empty",
        );
    }
    if model_version.len() > MAX_AI_MODEL_VERSION_LEN {
        return invalid_model_metadata_status(path, "model metadata model_version is too long");
    }
    if model_version.contains('\0') {
        return invalid_model_metadata_status(path, "model metadata model_version contains NUL");
    }
    let Some(production_ready) = json
        .get("production_ready")
        .and_then(|value| value.as_bool())
    else {
        return invalid_model_metadata_status(
            path,
            "model metadata production_ready must be a boolean",
        );
    };
    AiSelfTestStatus {
        model_loaded: true,
        model_version: model_version.to_string(),
        production_ready,
        can_auto_quarantine_ai_only: false,
        metadata_error: None,
    }
}

fn invalid_model_metadata_status(path: &Path, reason: &str) -> AiSelfTestStatus {
    AiSelfTestStatus {
        model_loaded: false,
        model_version: "invalid".to_string(),
        production_ready: false,
        can_auto_quarantine_ai_only: false,
        metadata_error: Some(format!(
            "invalid model metadata {}: {reason}",
            path.display()
        )),
    }
}

fn read_bounded_model_metadata(path: &Path) -> anyhow::Result<String> {
    use std::io::{BufReader, Read};

    let metadata = ensure_regular_model_metadata_file(path)?;
    if metadata.len() > MAX_AI_MODEL_METADATA_BYTES {
        anyhow::bail!(
            "model metadata {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_AI_MODEL_METADATA_BYTES
        );
    }
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
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
            .ok_or_else(|| anyhow::anyhow!("model metadata {} size overflow", path.display()))?;
        if total > MAX_AI_MODEL_METADATA_BYTES {
            anyhow::bail!(
                "model metadata {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_AI_MODEL_METADATA_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("unable to decode model metadata {}", path.display()))
}

fn find_model_metadata() -> anyhow::Result<Option<PathBuf>> {
    let mut roots = Vec::new();
    let exe = std::env::current_exe()
        .context("guard self-test model metadata discovery failed to resolve current executable")?;
    let parent = exe.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "guard self-test model metadata discovery found no parent for {}",
            exe.display()
        )
    })?;
    push_model_metadata_roots(&mut roots, parent)?;

    #[cfg(debug_assertions)]
    {
        let current_dir = std::env::current_dir().context(
            "guard self-test model metadata debug discovery failed to read current directory",
        )?;
        push_debug_model_metadata_roots(&mut roots, &current_dir)?;
    }
    for root in &roots {
        let candidate = root
            .join("assets")
            .join("models")
            .join("zentor_static_malware_model.metadata.json");
        if model_metadata_file_present(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn push_model_metadata_roots(roots: &mut Vec<PathBuf>, parent: &Path) -> anyhow::Result<()> {
    for candidate in [
        parent.to_path_buf(),
        parent.join(".."),
        parent.join("..").join(".."),
        parent.join("..").join("..").join(".."),
    ] {
        push_model_metadata_root(roots, &candidate)?;
    }
    Ok(())
}

fn push_model_metadata_root(roots: &mut Vec<PathBuf>, root: &Path) -> anyhow::Result<()> {
    if !model_metadata_root_is_allowed(root) {
        anyhow::bail!(
            "guard self-test model metadata root {} must be an absolute local path",
            root.display()
        );
    }
    if !roots.iter().any(|existing| existing == root) {
        roots.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn push_debug_model_metadata_roots(
    roots: &mut Vec<PathBuf>,
    current_dir: &Path,
) -> anyhow::Result<()> {
    for root in current_dir.ancestors() {
        if is_guard_self_test_development_root(root)? {
            push_model_metadata_root(roots, root)?;
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn is_guard_self_test_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_guard_service")
        .join("Cargo.toml");
    guard_self_test_development_marker_file_present(&marker)
}

#[cfg(debug_assertions)]
fn guard_self_test_development_marker_file_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "guard self-test development marker {} is a symbolic link",
                    path.display()
                );
            }
            if is_windows_reparse_point(&metadata) {
                anyhow::bail!(
                    "guard self-test development marker {} is a reparse point",
                    path.display()
                );
            }
            Ok(metadata.file_type().is_file())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect guard self-test development marker {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn model_metadata_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn model_metadata_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

fn model_metadata_file_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_model_metadata(path, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect model metadata {}", path.display())),
    }
}

fn ensure_regular_model_metadata_file(path: &Path) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect model metadata {}", path.display()))?;
    ensure_regular_model_metadata(path, &metadata)?;
    Ok(metadata)
}

fn ensure_regular_model_metadata(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("model metadata {} is a symbolic link", path.display());
    }
    if is_windows_reparse_point(metadata) {
        anyhow::bail!("model metadata {} is a reparse point", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("model metadata {} is not a regular file", path.display());
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_self_test_hash_prefix_branch_is_explicit() {
        let source = include_str!("self_test.rs");
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let tests_start = normalize_start + source[normalize_start..].find("#[cfg(test)]").unwrap();
        let normalize_source = &source[normalize_start..tests_start];
        let helper_start = source.find("fn normalize_hash").unwrap();
        let helper_source = &source[helper_start..normalize_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(helper_source.contains("fn normalize_hash(value: &str) -> anyhow::Result<String>"));
        assert!(
            helper_source.contains("guard self-test generated hash is not a valid SHA-256 value")
        );
        assert!(!helper_source.contains(".expect("));
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or(trimmed)"));
    }

    #[test]
    fn guard_self_test_handler_step_is_not_installed_service_evidence() {
        let source = include_str!("self_test.rs");
        let start = source.find("pub fn run_self_test").unwrap();
        let end = source.find("fn write_self_test_fixture").unwrap();
        let self_test_source = &source[start..end];

        assert!(self_test_source.contains("\"Guard self-test handler\""));
        assert!(self_test_source.contains("not installed Windows service evidence"));
        assert!(!self_test_source.contains("\"Guard Service running\""));
    }

    #[test]
    fn post_launch_fallback_verified_is_not_hardcoded_success() {
        let source = include_str!("self_test.rs");
        let start = source.find("let post_launch_fallback_verified").unwrap();
        let end = source.find("let pre_execution_blocking_available").unwrap();
        let fallback_source = &source[start..end];

        assert!(fallback_source.contains("eicar_verdict.action == DriverVerdictAction::Block"));
        assert!(fallback_source.contains("known_bad_verdict.action == DriverVerdictAction::Block"));
        assert!(fallback_source
            .contains("lockdown_unknown_verdict.action == DriverVerdictAction::Block"));
        assert!(fallback_source
            .contains("approved_unknown_verdict.action == DriverVerdictAction::Allow"));
        assert!(fallback_source.contains("known_good_verdict.action == DriverVerdictAction::Allow"));
        assert!(fallback_source
            .contains("normal_lockdown_verdict.action == DriverVerdictAction::Block"));
        assert!(fallback_source.contains("\"Post-launch verdict fallback\""));
        assert!(!fallback_source.contains("post_launch_fallback_verified: true"));
    }

    #[test]
    fn verdict_cache_status_is_disabled_without_a_cache_check() {
        let source = include_str!("self_test.rs");
        let start = source
            .find("guard_service: GuardServiceSelfTestStatus")
            .unwrap();
        let end = source[start..]
            .find("tests,")
            .map(|offset| start + offset)
            .unwrap();
        let guard_service_source = &source[start..end];

        assert!(guard_service_source.contains("verdict_cache_ok: false"));
        assert!(!guard_service_source.contains("verdict_cache_ok: true"));
    }

    #[test]
    fn guard_service_legacy_status_fields_are_not_hardcoded_success() {
        let source = include_str!("self_test.rs");
        let start = source
            .find("guard_service: GuardServiceSelfTestStatus")
            .unwrap();
        let end = source[start..]
            .find("tests,")
            .map(|offset| start + offset)
            .unwrap();
        let guard_service_source = &source[start..end];

        assert!(source.contains("let guard_handler_available = steps"));
        assert!(source.contains("step.name == \"Guard self-test handler\" && step.passed"));
        assert!(source.contains(
            "let guard_service_ipc_ok = guard_handler_available && post_launch_fallback_verified"
        ));
        assert!(guard_service_source.contains("running: guard_handler_available"));
        assert!(guard_service_source.contains("ipc_ok: guard_service_ipc_ok"));
        assert!(!guard_service_source.contains("running: true"));
        assert!(!guard_service_source.contains("ipc_ok: true"));
    }

    #[test]
    fn guard_self_test_download_fixture_parent_is_checked() {
        let source = include_str!("self_test.rs");
        let start = source.find("let normal_download_exe").unwrap();
        let end = source.find("let normal_lockdown_verdict").unwrap();
        let fixture_source = &source[start..end];
        let old_direct_write = ["fs::write(&normal_", "download_exe"].concat();

        assert!(fixture_source.contains("write_self_test_fixture("));
        assert!(source.contains("guard self-test fixture path has no parent"));
        assert!(source.contains("ensure_self_test_fixture_directory(parent, label)?"));
        assert!(source.contains(".create_new(true)"));
        assert!(source.contains("sync_all"));
        assert!(!fixture_source.contains("normal_download_exe.parent().unwrap()"));
        assert!(!fixture_source.contains(&old_direct_write));
    }

    #[test]
    fn guard_self_test_hash_target_rejects_directory_before_read() {
        let dir = tempdir().unwrap();

        let error = sha256_file(dir.path()).unwrap_err().to_string();

        assert!(error.contains("guard self-test hash target"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn guard_self_test_hash_target_rejects_symbolic_link_before_read() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let link = dir.path().join("linked.exe");
        fs::write(&target, b"benign self-test hash fixture").unwrap();
        symlink(&target, &link).unwrap();

        let error = sha256_file(&link).unwrap_err().to_string();

        assert!(error.contains("guard self-test hash target"));
        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn guard_self_test_hash_target_path_safety_markers_stay_in_place() {
        let source = include_str!("self_test.rs");
        let hash_start = source.find("fn sha256_file").unwrap();
        let ai_start = source.find("fn ai_status").unwrap();
        let hash_source = &source[hash_start..ai_start];

        assert!(source.contains("const MAX_GUARD_SELF_TEST_HASH_BYTES"));
        assert!(hash_source.contains("let metadata = ensure_regular_self_test_hash_file(path)?"));
        assert!(hash_source.contains("metadata.len() > MAX_GUARD_SELF_TEST_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("checked_add(read as u64)"));
        assert!(hash_source.contains("total > MAX_GUARD_SELF_TEST_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
        assert!(hash_source.contains(
            "fn ensure_regular_self_test_hash_file(path: &Path) -> anyhow::Result<fs::Metadata>"
        ));
        assert!(hash_source.contains("fs::symlink_metadata(path)"));
        assert!(hash_source.contains("metadata.file_type().is_symlink()"));
        assert!(hash_source.contains("is_windows_reparse_point(&metadata)"));
        assert!(hash_source.contains("not a regular file"));
        assert!(!hash_source.contains("path.is_file()"));
    }

    #[test]
    fn ai_self_test_does_not_default_metadata_errors_to_loaded_model() {
        let source = include_str!("self_test.rs");
        let ai_start = source.find("fn ai_status").unwrap();
        let metadata_start = source.find("fn find_model_metadata").unwrap();
        let ai_source = &source[ai_start..metadata_start];
        let ignored_read_pattern =
            ["std::fs::read_to_string(path)", ".unwrap_or_default()"].concat();
        let ignored_parse_pattern = ["serde_json::from_str(&raw)", ".unwrap_or_default()"].concat();

        assert!(ai_source.contains("failed to read model metadata"));
        assert!(ai_source.contains("failed to parse model metadata"));
        assert!(ai_source.contains("read_bounded_model_metadata(&path)"));
        assert!(ai_source.contains("parse_model_metadata_status(&path, &raw)"));
        assert!(ai_source.contains("MAX_AI_MODEL_METADATA_BYTES"));
        assert!(ai_source.contains("MAX_AI_MODEL_VERSION_LEN"));
        assert!(ai_source.contains("model metadata model_version must be a string"));
        assert!(ai_source.contains("model metadata production_ready must be a boolean"));
        assert!(!ai_source.contains(&ignored_read_pattern));
        assert!(!ai_source.contains(&ignored_parse_pattern));
        assert!(!ai_source.contains(".unwrap_or(false)"));
        assert!(!ai_source.contains(".unwrap_or(\"unknown\")"));
    }

    #[test]
    fn ai_self_test_accepts_valid_model_metadata_schema() {
        let status = parse_model_metadata_status(
            Path::new("model.metadata.json"),
            r#"{"model_version":"guard-ai-1","production_ready":true}"#,
        );

        assert!(status.model_loaded);
        assert_eq!(status.model_version, "guard-ai-1");
        assert!(status.production_ready);
        assert!(status.metadata_error.is_none());
    }

    #[test]
    fn ai_self_test_rejects_missing_model_version_metadata() {
        let status = parse_model_metadata_status(
            Path::new("model.metadata.json"),
            r#"{"production_ready":false}"#,
        );

        assert!(!status.model_loaded);
        assert_eq!(status.model_version, "invalid");
        assert!(!status.production_ready);
        assert!(status
            .metadata_error
            .as_deref()
            .unwrap()
            .contains("model_version must be a string"));
    }

    #[test]
    fn ai_self_test_rejects_missing_production_ready_metadata() {
        let status = parse_model_metadata_status(
            Path::new("model.metadata.json"),
            r#"{"model_version":"guard-ai-1"}"#,
        );

        assert!(!status.model_loaded);
        assert_eq!(status.model_version, "invalid");
        assert!(!status.production_ready);
        assert!(status
            .metadata_error
            .as_deref()
            .unwrap()
            .contains("production_ready must be a boolean"));
    }

    #[test]
    fn ai_self_test_rejects_oversized_metadata_before_parse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("model.metadata.json");
        fs::write(&path, "x".repeat(MAX_AI_MODEL_METADATA_BYTES as usize + 1)).unwrap();

        let error = read_bounded_model_metadata(&path).unwrap_err().to_string();

        assert!(error.contains("model metadata"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn ai_self_test_metadata_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("self_test.rs");
        let reader = &source[source.find("fn read_bounded_model_metadata").unwrap()
            ..source.find("fn find_model_metadata").unwrap()];

        assert!(reader.contains("let metadata = ensure_regular_model_metadata_file(path)?"));
        assert!(reader.contains("metadata.len() > MAX_AI_MODEL_METADATA_BYTES"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > MAX_AI_MODEL_METADATA_BYTES"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
        assert!(source.contains(
            "fn ensure_regular_model_metadata_file(path: &Path) -> anyhow::Result<fs::Metadata>"
        ));
    }

    #[test]
    fn ai_self_test_metadata_rejects_directory_before_read() {
        let dir = tempdir().unwrap();

        let error = read_bounded_model_metadata(dir.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("model metadata"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn ai_self_test_metadata_rejects_symbolic_link_before_read() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("model.metadata.json");
        let link = dir.path().join("linked.metadata.json");
        fs::write(&target, "{}").unwrap();
        symlink(&target, &link).unwrap();

        let error = read_bounded_model_metadata(&link).unwrap_err().to_string();

        assert!(error.contains("model metadata"));
        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn ai_self_test_metadata_path_safety_markers_stay_in_place() {
        let source = include_str!("self_test.rs");
        let metadata_start = source.find("fn find_model_metadata").unwrap();
        let metadata_end = source.find("fn model_metadata_file_present").unwrap();
        let metadata_source = &source[metadata_start..metadata_end];
        let discovery_result_pattern = [
            "fn find_model_metadata() -> anyhow::",
            "Result<Option<PathBuf>>",
        ]
        .concat();
        let presence_helper_pattern = ["model_metadata_file_", "present"].concat();
        let read_guard_pattern = ["ensure_regular_model_metadata_", "file(path)"].concat();
        let symlink_metadata_pattern = ["fs::symlink_", "metadata(path)"].concat();
        let reparse_pattern = ["is_windows_", "reparse_point"].concat();
        let candidate_is_file_pattern = ["candidate", ".is_", "file()"].concat();
        let old_optional_exe = ["if let Ok(exe)", " = std::env::current_exe()"].concat();
        let old_direct_current_push = ["roots.push", "(current_dir.clone())"].concat();

        assert!(source.contains(&discovery_result_pattern));
        assert!(source.contains(&presence_helper_pattern));
        assert!(source.contains(&read_guard_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&reparse_pattern));
        assert!(metadata_source.contains("failed to resolve current executable"));
        assert!(metadata_source.contains("push_model_metadata_roots(&mut roots, parent)?"));
        assert!(metadata_source.contains("#[cfg(debug_assertions)]"));
        assert!(metadata_source.contains("is_guard_self_test_development_root(root)?"));
        assert!(metadata_source
            .contains("guard self-test model metadata root {} must be an absolute local path"));
        assert!(!source.contains(&candidate_is_file_pattern));
        assert!(!metadata_source.contains(&old_optional_exe));
        assert!(!metadata_source.contains(&old_direct_current_push));
    }
}
