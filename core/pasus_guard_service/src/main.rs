use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, Utc};
use pasus_native_engine::{
    EngineConfig, PasusNativeEngine, ScanActionMode as PneScanActionMode, Verdict as PneVerdict,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod driver_health;
mod driver_ipc;
mod known_bad_cache;
mod known_good_cache;
mod preexecution_policy;
mod self_test;

#[derive(Debug, Deserialize)]
struct GuardCommand {
    command: String,
    process_id: Option<u32>,
    process_path: Option<String>,
    known_malicious_hashes: Option<Vec<String>>,
    known_good_hashes: Option<Vec<String>>,
    user_approved_hashes: Option<Vec<String>>,
    protection_mode: Option<preexecution_policy::DriverProtectionMode>,
    poll_interval_ms: Option<u64>,
    max_iterations: Option<u32>,
    scan_request: Option<driver_ipc::ScanRequest>,
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

fn main() -> anyhow::Result<()> {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let command: GuardCommand = serde_json::from_str(&line)?;
        let response = handle(command);
        println!("{}", serde_json::to_string(&response)?);
    }
    Ok(())
}

fn handle(command: GuardCommand) -> GuardEvent {
    match command.command.as_str() {
        "health" => GuardEvent {
            ok: true,
            action: "health".to_string(),
            message: serde_json::to_string(&serde_json::json!({
                "guard": "ready",
                "driver": driver_health::DriverHealth::probe(),
                "policy": preexecution_policy::PreExecutionPolicy::default(),
                "known_bad_hashes": known_bad_cache::load_known_bad_hashes().len(),
                "post_launch_fallback": true,
            }))
            .unwrap_or_else(|_| "Pasus Guard Service ready.".to_string()),
            process_id: None,
            process_path: None,
            quarantine_path: None,
            quarantine_id: None,
            quarantine_record_path: None,
            created_at: Utc::now(),
        },
        "driver_scan_request" => {
            let Some(request) = command.scan_request else {
                return error("scan_request is required");
            };
            let mut hashes = known_bad_cache::load_known_bad_hashes();
            hashes.extend(command.known_malicious_hashes.unwrap_or_default());
            match driver_ipc::evaluate_driver_request(
                &request,
                &driver_ipc::DriverVerdictConfig {
                    known_bad_hashes: hashes,
                    known_good_hashes: command
                        .known_good_hashes
                        .unwrap_or_default()
                        .into_iter()
                        .map(normalize_hash)
                        .collect(),
                    user_approved_hashes: command
                        .user_approved_hashes
                        .unwrap_or_default()
                        .into_iter()
                        .map(normalize_hash)
                        .collect(),
                    mode: command.protection_mode.unwrap_or_default(),
                    ..Default::default()
                },
            ) {
                Ok(verdict) => GuardEvent {
                    ok: true,
                    action: "driverVerdict".to_string(),
                    message: serde_json::to_string(&verdict)
                        .unwrap_or_else(|_| "driver verdict created".to_string()),
                    process_id: request.process_id,
                    process_path: Some(request.file_path),
                    quarantine_id: None,
                    quarantine_path: None,
                    quarantine_record_path: None,
                    created_at: Utc::now(),
                },
                Err(error) => error_event(
                    request.process_id,
                    Some(request.file_path),
                    error.to_string(),
                ),
            }
        }
        "driver_self_test" => {
            let mut hashes = known_bad_cache::load_known_bad_hashes();
            hashes.extend(command.known_malicious_hashes.unwrap_or_default());
            match self_test::run_self_test(hashes) {
                Ok(report) => GuardEvent {
                    ok: report.passed,
                    action: "driverSelfTest".to_string(),
                    message: serde_json::to_string(&report)
                        .unwrap_or_else(|_| "driver self-test completed".to_string()),
                    process_id: None,
                    process_path: None,
                    quarantine_id: None,
                    quarantine_path: None,
                    quarantine_record_path: None,
                    created_at: Utc::now(),
                },
                Err(error) => error_event(None, None, error.to_string()),
            }
        }
        "process_started" => {
            let Some(path) = command.process_path else {
                return error("process_path is required");
            };
            let pid = command.process_id;
            let malicious = command
                .known_malicious_hashes
                .unwrap_or_default()
                .into_iter()
                .collect::<HashSet<_>>();
            match handle_process_started(pid, Path::new(&path), &malicious) {
                Ok(event) => event,
                Err(error) => error_event(pid, Some(path), error.to_string()),
            }
        }
        "watch_processes" => {
            let malicious = command
                .known_malicious_hashes
                .unwrap_or_default()
                .into_iter()
                .collect::<HashSet<_>>();
            match watch_processes(
                &malicious,
                command.poll_interval_ms.unwrap_or(750),
                command.max_iterations,
            ) {
                Ok(event) => event,
                Err(error) => error_event(None, None, error.to_string()),
            }
        }
        _ => error("unknown command"),
    }
}

fn handle_process_started(
    process_id: Option<u32>,
    process_path: &Path,
    known_malicious_hashes: &HashSet<String>,
) -> anyhow::Result<GuardEvent> {
    let hash = sha256_file(process_path)?;
    let native_match = native_threat_match(process_path).unwrap_or(None);
    let local_match = if native_match.is_none() {
        local_signature_match(process_path)?
    } else {
        None
    };
    let yara_match = if local_match.is_none() {
        yara_rule_match(process_path).unwrap_or(None)
    } else {
        None
    };
    let clamav_signature = if local_match.is_none() && yara_match.is_none() {
        clamav_signature_match(process_path).unwrap_or(None)
    } else {
        None
    };
    let confirmed_match = if known_malicious_hashes.contains(&hash) {
        Some(LocalThreatMatch {
            reason: "known malicious hash".to_string(),
            engine: "pasus-known-bad-hash".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        })
    } else if let Some(native_match) = native_match {
        Some(native_match)
    } else if let Some(signature) = local_match {
        Some(signature)
    } else if let Some(yara_match) = yara_match {
        if matches!(
            yara_match.confidence,
            LocalThreatConfidence::Confirmed | LocalThreatConfidence::High
        ) {
            Some(yara_match)
        } else {
            None
        }
    } else {
        clamav_signature.map(|signature| LocalThreatMatch {
            reason: format!("ClamAV signature: {signature}"),
            engine: "clamav".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        })
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

    if let Some(pid) = process_id {
        stop_process(pid);
    }
    let record = quarantine_file(process_path, &hash, process_id, &threat_match)
        .with_context(|| "known malicious process was stopped but quarantine failed")?;
    Ok(GuardEvent {
        ok: true,
        action: "stoppedAndQuarantined".to_string(),
        message: format!(
            "Pasus stopped the process and moved the file to quarantine. Reason: {}.",
            threat_match.reason
        ),
        process_id,
        process_path: Some(process_path.display().to_string()),
        quarantine_id: Some(record.quarantine_id.clone()),
        quarantine_path: Some(record.quarantine_path.clone()),
        quarantine_record_path: Some(
            quarantine_record_path(&record.quarantine_id)
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
) -> anyhow::Result<GuardEvent> {
    let mut seen: HashSet<u32> = list_processes()?
        .into_iter()
        .map(|process| process.process_id)
        .collect();
    let mut cache: HashMap<PathBuf, String> = HashMap::new();
    let mut iterations = 0u32;

    loop {
        iterations = iterations.saturating_add(1);
        for process in list_processes()? {
            if !seen.insert(process.process_id) {
                continue;
            }
            if should_skip_process_path(&process.path) {
                continue;
            }
            let hash = match cache.get(&process.path) {
                Some(hash) => hash.clone(),
                None => {
                    let hash = sha256_file(&process.path).unwrap_or_default();
                    cache.insert(process.path.clone(), hash.clone());
                    hash
                }
            };
            let local_match = local_signature_match(&process.path)
                .ok()
                .flatten()
                .or_else(|| {
                    yara_rule_match(&process.path).ok().flatten().filter(|m| {
                        matches!(
                            m.confidence,
                            LocalThreatConfidence::Confirmed | LocalThreatConfidence::High
                        )
                    })
                })
                .or_else(|| {
                    clamav_signature_match(&process.path)
                        .ok()
                        .flatten()
                        .map(|signature| LocalThreatMatch {
                            reason: format!("ClamAV signature: {signature}"),
                            engine: "clamav".to_string(),
                            confidence: LocalThreatConfidence::Confirmed,
                        })
                });

            if known_malicious_hashes.contains(&hash) || local_match.is_some() {
                return handle_process_started(
                    Some(process.process_id),
                    &process.path,
                    known_malicious_hashes,
                );
            }
        }

        if let Some(max_iterations) = max_iterations {
            if iterations >= max_iterations {
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
        thread::sleep(Duration::from_millis(poll_interval_ms.max(100)));
    }
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
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .context("failed to query Windows processes")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Windows process query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    parse_windows_process_json(&String::from_utf8_lossy(&output.stdout))
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
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: WindowsProcessJson = serde_json::from_str(trimmed)?;
    let rows = match parsed {
        WindowsProcessJson::One(row) => vec![row],
        WindowsProcessJson::Many(rows) => rows,
    };
    Ok(rows
        .into_iter()
        .map(|row| ObservedProcess {
            process_id: row.process_id,
            path: PathBuf::from(row.executable_path),
        })
        .filter(|process| process.path.is_file())
        .collect())
}

#[cfg(not(windows))]
fn list_processes_procfs() -> anyhow::Result<Vec<ObservedProcess>> {
    let mut processes = Vec::new();
    let proc = Path::new("/proc");
    if !proc.is_dir() {
        return Ok(processes);
    }
    for entry in fs::read_dir(proc)? {
        let Ok(entry) = entry else {
            continue;
        };
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let Ok(path) = fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        if path.is_file() {
            processes.push(ObservedProcess {
                process_id: pid,
                path,
            });
        }
    }
    Ok(processes)
}

fn stop_process(process_id: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &process_id.to_string(), "/F"])
            .output();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &process_id.to_string()])
            .output();
    }
}

fn quarantine_file(
    path: &Path,
    sha256: &str,
    process_id: Option<u32>,
    threat_match: &LocalThreatMatch,
) -> anyhow::Result<GuardQuarantineRecord> {
    let base = quarantine_base();
    fs::create_dir_all(&base)?;
    let id = Uuid::new_v4().to_string();
    let destination = base.join(format!("{id}.pasusq"));
    let file_size = fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let mut last_error = None;
    for _ in 0..10 {
        match fs::rename(path, &destination) {
            Ok(()) => {
                remove_executable_permissions(&destination)?;
                let record = GuardQuarantineRecord {
                    quarantine_id: id.clone(),
                    original_path: path.display().to_string(),
                    quarantine_path: destination.display().to_string(),
                    sha256: sha256.to_string(),
                    file_size,
                    detection_name: threat_match.reason.clone(),
                    engine: threat_match.engine.clone(),
                    action_taken: "process_stopped_and_file_quarantined".to_string(),
                    quarantined_at: Utc::now(),
                    status: QuarantineStatus::Quarantined,
                    user_note: None,
                    source: "guard_service".to_string(),
                    blocked_before_execution: false,
                    process_started: process_id.is_some(),
                    process_id,
                };
                write_quarantine_record(&record)?;
                return Ok(record);
            }
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(150));
            }
        }
    }
    return Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("quarantine failed")));
}

fn write_quarantine_record(record: &GuardQuarantineRecord) -> anyhow::Result<()> {
    let path = quarantine_record_path(&record.quarantine_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(record)?)?;
    Ok(())
}

fn quarantine_record_path(id: &str) -> PathBuf {
    quarantine_base().join(format!("{id}.json"))
}

fn remove_executable_permissions(_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(_path)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() & !0o111);
        fs::set_permissions(_path, permissions)?;
    }
    Ok(())
}

fn quarantine_base() -> PathBuf {
    if let Ok(path) = std::env::var("PASUS_GUARD_QUARANTINE_DIR") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("PASUS_QUARANTINE_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        if let Ok(program_data) =
            std::env::var("ProgramData").or_else(|_| std::env::var("PROGRAMDATA"))
        {
            return PathBuf::from(program_data).join("Pasus").join("Quarantine");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Pasus")
                .join("Quarantine");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/pasus/quarantine");
    }
    PathBuf::from(".pasus/quarantine")
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn normalize_hash(value: String) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_lowercase()
}

fn local_signature_match(path: &Path) -> anyhow::Result<Option<LocalThreatMatch>> {
    let bytes = fs::read(path)?;
    Ok(local_signature_match_bytes(&bytes))
}

fn native_threat_match(path: &Path) -> anyhow::Result<Option<LocalThreatMatch>> {
    let mut engine = PasusNativeEngine::initialize(EngineConfig::from_repo_root(native_asset_root()))?;
    let verdict = engine.scan_file(path.to_path_buf(), PneScanActionMode::DetectOnly)?;
    let confidence = match verdict.final_verdict.confidence {
        pasus_native_engine::Confidence::Confirmed => LocalThreatConfidence::Confirmed,
        pasus_native_engine::Confidence::High => LocalThreatConfidence::High,
        pasus_native_engine::Confidence::Medium => LocalThreatConfidence::Medium,
        pasus_native_engine::Confidence::Low => LocalThreatConfidence::Low,
    };
    if matches!(
        verdict.final_verdict.verdict,
        PneVerdict::TestThreat | PneVerdict::ConfirmedMalware | PneVerdict::ProbableMalware
    ) {
        return Ok(Some(LocalThreatMatch {
            reason: verdict.final_verdict.user_visible_explanation,
            engine: "pasus-native-engine".to_string(),
            confidence,
        }));
    }
    Ok(None)
}

fn native_asset_root() -> PathBuf {
    let current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for candidate in current.ancestors() {
        if candidate.join("assets").join("pasus_native").exists() {
            return candidate.to_path_buf();
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            for candidate in [
                parent.to_path_buf(),
                parent.join(".."),
                parent.join("..").join(".."),
                parent.join("..").join("..").join(".."),
            ] {
                if candidate.join("assets").join("pasus_native").exists() {
                    return candidate;
                }
            }
        }
    }
    current
}

fn local_signature_match_bytes(bytes: &[u8]) -> Option<LocalThreatMatch> {
    if bytes
        .windows(EICAR_TEST_SIGNATURE.len())
        .any(|window| window == EICAR_TEST_SIGNATURE.as_bytes())
        || bytes
            .windows(PASUS_SAFE_EICAR_SIMULATOR.len())
            .any(|window| window == PASUS_SAFE_EICAR_SIMULATOR.as_bytes())
    {
        return Some(LocalThreatMatch {
            reason: "EICAR test signature".to_string(),
            engine: "pasus-local-signature".to_string(),
            confidence: LocalThreatConfidence::Confirmed,
        });
    }
    None
}

const EICAR_TEST_SIGNATURE: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const PASUS_SAFE_EICAR_SIMULATOR: &str = "PASUS-SAFE-EICAR-SIMULATOR-FILE";

fn clamav_signature_match(path: &Path) -> anyhow::Result<Option<String>> {
    let Some(clamscan) = find_clamscan() else {
        return Ok(None);
    };
    let output = Command::new(&clamscan)
        .arg("--no-summary")
        .arg(path)
        .output()?;
    if output.status.code() != Some(1) {
        return Ok(None);
    }
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(combined
        .split(':')
        .nth(1)
        .map(|value| value.replace("FOUND", "").trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn yara_rule_match(path: &Path) -> anyhow::Result<Option<LocalThreatMatch>> {
    let rules_path = default_yara_rules_path();
    if !rules_path.is_file() {
        return Ok(None);
    }
    let rules = fs::read_to_string(rules_path)?;
    let body = fs::read(path)?;
    let body_text = String::from_utf8_lossy(&body).to_lowercase();
    let mut best: Option<LocalThreatMatch> = None;
    let mut current_rule = String::new();
    let mut confidence = LocalThreatConfidence::Low;
    let mut description = String::new();

    for line in rules.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            current_rule = trimmed
                .strip_prefix("rule ")
                .and_then(|value| value.split_whitespace().next())
                .unwrap_or("pasus_yara_rule")
                .trim_matches('{')
                .to_string();
            confidence = LocalThreatConfidence::Low;
            description.clear();
        } else if let Some(value) = metadata_value(trimmed, "confidence") {
            confidence = confidence_from_yara(&value);
        } else if let Some(value) = metadata_value(trimmed, "description") {
            description = value;
        } else if trimmed.starts_with('$') {
            let Some((_, value)) = trimmed.split_once('=') else {
                continue;
            };
            let Some(pattern) = quoted_value(value.trim()) else {
                continue;
            };
            if body_text.contains(&pattern.to_lowercase()) {
                let candidate = LocalThreatMatch {
                    reason: if description.is_empty() {
                        format!("YARA rule matched: {current_rule}")
                    } else {
                        description.clone()
                    },
                    engine: format!("pasus-yara/{current_rule}"),
                    confidence: confidence.clone(),
                };
                if best
                    .as_ref()
                    .map(|existing| {
                        confidence_rank(&candidate.confidence)
                            > confidence_rank(&existing.confidence)
                    })
                    .unwrap_or(true)
                {
                    best = Some(candidate);
                }
            }
        }
    }

    Ok(best)
}

fn default_yara_rules_path() -> PathBuf {
    let mut roots = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }
    for root in roots {
        for candidate in [
            root.join("assets")
                .join("yara")
                .join("pasus_core_rules.yar"),
            root.join("..")
                .join("..")
                .join("assets")
                .join("yara")
                .join("pasus_core_rules.yar"),
        ] {
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("assets/yara/pasus_core_rules.yar")
}

fn metadata_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} =");
    line.strip_prefix(&prefix)
        .and_then(|value| quoted_value(value.trim()))
}

fn quoted_value(value: &str) -> Option<String> {
    let start = value.find('"')?;
    let rest = &value[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn confidence_from_yara(value: &str) -> LocalThreatConfidence {
    match value {
        "confirmed" => LocalThreatConfidence::Confirmed,
        "high" => LocalThreatConfidence::High,
        "medium" => LocalThreatConfidence::Medium,
        _ => LocalThreatConfidence::Low,
    }
}

fn confidence_rank(confidence: &LocalThreatConfidence) -> u8 {
    match confidence {
        LocalThreatConfidence::Confirmed => 4,
        LocalThreatConfidence::High => 3,
        LocalThreatConfidence::Medium => 2,
        LocalThreatConfidence::Low => 1,
    }
}

fn find_clamscan() -> Option<PathBuf> {
    if let Ok(configured) = std::env::var("PASUS_CLAMAV_CLAMSCAN") {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return Some(path);
        }
    }
    let executable_name = if cfg!(windows) {
        "clamscan.exe"
    } else {
        "clamscan"
    };
    let mut roots = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }
    for root in roots {
        for candidate in [
            root.join("ClamAV").join(executable_name),
            root.join(executable_name),
        ] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn should_skip_process_path(path: &Path) -> bool {
    let lower = path.display().to_string().to_lowercase();
    lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\syswow64\\")
        || lower == "c:\\windows\\explorer.exe"
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.starts_with("/system/")
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
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn mock_process_start_without_known_hash_is_monitored() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        fs::write(&file, b"developer tool").unwrap();
        let result = handle_process_started(None, &file, &HashSet::new()).unwrap();
        assert_eq!(result.action, "monitored");
        assert!(file.exists());
    }

    #[test]
    fn known_malicious_hash_is_quarantined() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("PASUS_GUARD_QUARANTINE_DIR", dir.path().join("quarantine"));
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"known bad fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let result = handle_process_started(None, &file, &HashSet::from([hash])).unwrap();
        assert_eq!(result.action, "stoppedAndQuarantined");
        assert!(!file.exists());
        assert!(Path::new(result.quarantine_path.as_ref().unwrap()).exists());
        let record_path = result.quarantine_record_path.as_ref().unwrap();
        assert!(Path::new(record_path).exists());
        let record: GuardQuarantineRecord =
            serde_json::from_str(&fs::read_to_string(record_path).unwrap()).unwrap();
        assert_eq!(record.status, QuarantineStatus::Quarantined);
        assert_eq!(record.engine, "pasus-known-bad-hash");
        std::env::remove_var("PASUS_GUARD_QUARANTINE_DIR");
    }

    #[test]
    fn eicar_signature_bytes_are_detected_as_confirmed_test_threat() {
        assert_eq!(
            local_signature_match_bytes(EICAR_TEST_SIGNATURE.as_bytes())
                .map(|matched| matched.reason),
            Some("EICAR test signature".to_string())
        );
        assert_eq!(
            local_signature_match_bytes(PASUS_SAFE_EICAR_SIMULATOR.as_bytes())
                .map(|matched| matched.reason),
            Some("EICAR test signature".to_string())
        );
        assert!(local_signature_match_bytes(b"normal installer").is_none());
    }

    #[test]
    fn watch_processes_completes_without_fake_detection() {
        let result = watch_processes(&HashSet::new(), 100, Some(1)).unwrap();
        assert_eq!(result.action, "watchCompleted");
        assert!(result.ok);
    }

    #[test]
    fn medium_yara_match_is_review_only_and_not_stopped() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("script.ps1");
        fs::write(&file, "[Convert]::FromBase64String('AAAA')").unwrap();

        let yara = yara_rule_match(&file).unwrap().unwrap();
        assert_eq!(yara.confidence, LocalThreatConfidence::Medium);

        let result = handle_process_started(Some(4242), &file, &HashSet::new()).unwrap();
        assert_eq!(result.action, "monitored");
        assert!(file.exists());
    }
}
