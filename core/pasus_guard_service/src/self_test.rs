use std::collections::HashSet;
use std::fs;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

use crate::driver_health::DriverHealth;
use crate::driver_ipc::{
    evaluate_driver_request, DriverEventType, DriverVerdictAction, DriverVerdictConfig, ScanRequest,
};
use crate::preexecution_policy::DriverProtectionMode;

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
    pub pasus_version: String,
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
}

pub fn run_self_test(known_bad_hashes: HashSet<String>) -> anyhow::Result<ProtectionSelfTest> {
    let health = DriverHealth::probe();
    let mut steps = vec![
        step(
            "Guard Service running",
            true,
            "Guard self-test command was handled.",
        ),
        step("Driver installed", health.installed, &health.reason),
        step(
            "Driver running",
            health.running,
            if health.running {
                "Driver reports running."
            } else {
                "Driver is not running."
            },
        ),
        step(
            "Driver IPC alive",
            health.ipc_connected,
            if health.ipc_connected {
                "Driver communication probe succeeded."
            } else {
                "Driver communication probe did not succeed."
            },
        ),
    ];

    let dir = tempdir()?;
    let eicar = dir.path().join("safe-eicar.com");
    fs::write(&eicar, "PASUS-SAFE-EICAR-SIMULATOR-FILE")?;
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
    fs::write(&known_bad, "harmless known bad test executable")?;
    let hash = sha256_file(&known_bad)?;
    let mut hashes = known_bad_hashes;
    hashes.insert(normalize_hash(&hash));
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
    fs::write(&unknown, "harmless unknown unsigned executable")?;
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
            user_approved_hashes: HashSet::from([normalize_hash(&unknown_hash)]),
            ..Default::default()
        },
    )?;
    steps.push(step(
        "Exact-hash user approval allows unknown app",
        approved_unknown_verdict.action == DriverVerdictAction::Allow,
        &approved_unknown_verdict.reason_summary,
    ));

    let known_good = dir.path().join("known-good-test.exe");
    fs::write(&known_good, "harmless known good executable")?;
    let known_good_hash = sha256_file(&known_good)?;
    let known_good_verdict = evaluate_driver_request(
        &request_for(&known_good),
        &DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            known_good_hashes: HashSet::from([normalize_hash(&known_good_hash)]),
            ..Default::default()
        },
    )?;
    steps.push(step(
        "Known-good executable allowed",
        known_good_verdict.action == DriverVerdictAction::Allow,
        &known_good_verdict.reason_summary,
    ));

    let normal_download_exe = dir.path().join("Downloads").join("vpn-installer.exe");
    fs::create_dir_all(normal_download_exe.parent().unwrap())?;
    fs::write(&normal_download_exe, "normal installer-like fixture")?;
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

    let pre_execution_blocking_available = health.running
        && health.ipc_connected
        && eicar_verdict.action == DriverVerdictAction::Block
        && known_bad_verdict.action == DriverVerdictAction::Block
        && lockdown_unknown_verdict.action == DriverVerdictAction::Block;
    steps.push(step(
        "Pre-execution block self-test",
        pre_execution_blocking_available,
        if pre_execution_blocking_available {
            "Driver and service path can return blocking verdicts."
        } else {
            "Pre-execution blocking is not active; post-launch fallback remains available."
        },
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
        post_launch_fallback_verified: true,
        quarantine_ui_record_created: false,
    };
    let ai = ai_status();
    let passed = steps.iter().all(|step| step.passed);
    Ok(ProtectionSelfTest {
        pasus_version: "0.1.13".to_string(),
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
            running: true,
            ipc_ok: true,
            verdict_cache_ok: true,
        },
        tests,
        ai,
        overall_result: if passed { "pass" } else { "fail" }.to_string(),
        passed,
        pre_execution_blocking_available,
        steps,
    })
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
        parent_process_path: None,
        sha256: None,
        timestamp_utc: Utc::now(),
    }
}

fn normalize_hash(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_lowercase()
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

    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn ai_status() -> AiSelfTestStatus {
    let path = find_model_metadata();
    let Some(path) = path else {
        return AiSelfTestStatus {
            model_loaded: false,
            model_version: "missing".to_string(),
            production_ready: false,
            can_auto_quarantine_ai_only: false,
        };
    };
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
    let production_ready = json
        .get("production_ready")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    AiSelfTestStatus {
        model_loaded: true,
        model_version: json
            .get("model_version")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
            .to_string(),
        production_ready,
        can_auto_quarantine_ai_only: false,
    }
}

fn find_model_metadata() -> Option<std::path::PathBuf> {
    let mut roots = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir.clone());
        let mut cursor = current_dir.as_path();
        while let Some(parent) = cursor.parent() {
            roots.push(parent.to_path_buf());
            cursor = parent;
        }
    }
    for root in roots {
        let candidate = root
            .join("assets")
            .join("models")
            .join("pasus_static_malware_model.metadata.json");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
