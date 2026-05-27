use std::collections::HashSet;
use std::fs;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

use crate::driver_health::DriverHealth;
use crate::driver_ipc::{
    evaluate_driver_request, DriverEventType, DriverVerdictAction, DriverVerdictConfig, ScanRequest,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfTestStep {
    pub name: String,
    pub passed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionSelfTest {
    pub passed: bool,
    pub pre_execution_blocking_available: bool,
    pub steps: Vec<SelfTestStep>,
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
    hashes.insert(hash);
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

    let pre_execution_blocking_available = health.running
        && health.ipc_connected
        && eicar_verdict.action == DriverVerdictAction::Block
        && known_bad_verdict.action == DriverVerdictAction::Block;
    steps.push(step(
        "Pre-execution block self-test",
        pre_execution_blocking_available,
        if pre_execution_blocking_available {
            "Driver and service path can return blocking verdicts."
        } else {
            "Pre-execution blocking is not active; post-launch fallback remains available."
        },
    ));

    Ok(ProtectionSelfTest {
        passed: steps.iter().all(|step| step.passed),
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
        sha256: None,
        timestamp_utc: Utc::now(),
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

    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
