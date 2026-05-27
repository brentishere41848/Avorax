use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriverEventType {
    FileOpen,
    FileCreate,
    FileWrite,
    FileRename,
    ImageExecuteAttempt,
    SectionCreateAttempt,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanRequest {
    pub request_id: String,
    pub event_type: DriverEventType,
    pub file_path: String,
    pub normalized_file_path: Option<String>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub user_sid: Option<String>,
    pub desired_access: Option<u32>,
    pub file_size: Option<u64>,
    pub sha256: Option<String>,
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriverVerdictAction {
    Allow,
    Block,
    Quarantine,
    AllowAndMonitor,
    TimeoutAllow,
    TimeoutBlock,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FinalVerdict {
    Clean,
    LikelyClean,
    Unknown,
    Observation,
    Suspicious,
    ProbableMalware,
    ConfirmedMalware,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerdictConfidence {
    Low,
    Medium,
    High,
    Confirmed,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerdictEngine {
    Signature,
    Yara,
    LocalAi,
    Heuristic,
    Behavior,
    KnownBadHash,
    Allowlist,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanVerdict {
    pub request_id: String,
    pub action: DriverVerdictAction,
    pub final_verdict: FinalVerdict,
    pub confidence: VerdictConfidence,
    pub engines_used: Vec<VerdictEngine>,
    pub reason_summary: String,
    pub cache_ttl_ms: u64,
    pub quarantine_after_block: bool,
}

#[derive(Debug, Clone)]
pub struct DriverVerdictConfig {
    pub known_bad_hashes: HashSet<String>,
    pub pre_execution_timeout_ms: u64,
}

impl Default for DriverVerdictConfig {
    fn default() -> Self {
        Self {
            known_bad_hashes: HashSet::new(),
            pre_execution_timeout_ms: 750,
        }
    }
}

pub fn evaluate_driver_request(
    request: &ScanRequest,
    config: &DriverVerdictConfig,
) -> anyhow::Result<ScanVerdict> {
    let path = normalized_path(request);
    if should_fail_open_path(&path) {
        return Ok(allow(
            request,
            FinalVerdict::LikelyClean,
            "Critical system or Pasus-owned path; normal mode fails open.",
            vec![],
        ));
    }

    let hash = request
        .sha256
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| sha256_file(&path).ok());

    if hash
        .as_ref()
        .map(|value| config.known_bad_hashes.contains(value))
        .unwrap_or(false)
    {
        return Ok(block(
            request,
            "Known bad hash matched local cache.",
            vec![VerdictEngine::KnownBadHash],
        ));
    }

    if local_signature_match(&path)? {
        return Ok(block(
            request,
            "EICAR test signature matched local scanner.",
            vec![VerdictEngine::Signature],
        ));
    }

    if let Some(yara) = yara_match(&path)? {
        if yara.confirmed_or_high {
            return Ok(block(request, &yara.reason, vec![VerdictEngine::Yara]));
        }
        return Ok(ScanVerdict {
            request_id: request.request_id.clone(),
            action: DriverVerdictAction::AllowAndMonitor,
            final_verdict: FinalVerdict::Suspicious,
            confidence: VerdictConfidence::Medium,
            engines_used: vec![VerdictEngine::Yara],
            reason_summary: yara.reason,
            cache_ttl_ms: 30_000,
            quarantine_after_block: false,
        });
    }

    Ok(allow(
        request,
        FinalVerdict::Unknown,
        "No confirmed local blocking signal matched.",
        vec![],
    ))
}

fn normalized_path(request: &ScanRequest) -> PathBuf {
    request
        .normalized_file_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&request.file_path)
        .into()
}

fn allow(
    request: &ScanRequest,
    verdict: FinalVerdict,
    reason: &str,
    engines_used: Vec<VerdictEngine>,
) -> ScanVerdict {
    ScanVerdict {
        request_id: request.request_id.clone(),
        action: DriverVerdictAction::Allow,
        final_verdict: verdict,
        confidence: VerdictConfidence::Low,
        engines_used,
        reason_summary: reason.to_string(),
        cache_ttl_ms: 60_000,
        quarantine_after_block: false,
    }
}

fn block(request: &ScanRequest, reason: &str, engines_used: Vec<VerdictEngine>) -> ScanVerdict {
    ScanVerdict {
        request_id: request.request_id.clone(),
        action: DriverVerdictAction::Block,
        final_verdict: FinalVerdict::ConfirmedMalware,
        confidence: VerdictConfidence::Confirmed,
        engines_used,
        reason_summary: reason.to_string(),
        cache_ttl_ms: 300_000,
        quarantine_after_block: true,
    }
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn local_signature_match(path: &Path) -> anyhow::Result<bool> {
    let bytes = fs::read(path)?;
    Ok(bytes
        .windows(EICAR_TEST_SIGNATURE.len())
        .any(|window| window == EICAR_TEST_SIGNATURE.as_bytes())
        || bytes
            .windows(PASUS_SAFE_EICAR_SIMULATOR.len())
            .any(|window| window == PASUS_SAFE_EICAR_SIMULATOR.as_bytes()))
}

struct YaraDecision {
    reason: String,
    confirmed_or_high: bool,
}

fn yara_match(path: &Path) -> anyhow::Result<Option<YaraDecision>> {
    let rules_path = default_yara_rules_path();
    if !rules_path.is_file() {
        return Ok(None);
    }
    let rules = fs::read_to_string(rules_path)?;
    let body = fs::read(path)?;
    let body_text = String::from_utf8_lossy(&body).to_lowercase();
    let mut confidence = "low".to_string();
    let mut description = String::new();

    for line in rules.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            confidence = "low".to_string();
            description.clear();
        } else if let Some(value) = metadata_value(trimmed, "confidence") {
            confidence = value;
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
                return Ok(Some(YaraDecision {
                    reason: if description.is_empty() {
                        "YARA rule matched.".to_string()
                    } else {
                        description.clone()
                    },
                    confirmed_or_high: confidence == "confirmed" || confidence == "high",
                }));
            }
        }
    }
    Ok(None)
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

fn should_fail_open_path(path: &Path) -> bool {
    let lower = path.display().to_string().to_lowercase();
    lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\syswow64\\")
        || lower.contains("\\pasus\\quarantine\\")
        || lower.contains("\\pasus\\guardquarantine\\")
        || lower.ends_with("\\pasus_local_core.exe")
        || lower.ends_with("\\pasus_guard_service.exe")
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.contains("/pasus/quarantine/")
}

const EICAR_TEST_SIGNATURE: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const PASUS_SAFE_EICAR_SIMULATOR: &str = "PASUS-SAFE-EICAR-SIMULATOR-FILE";

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn request_for(path: &Path) -> ScanRequest {
        ScanRequest {
            request_id: "test-request".to_string(),
            event_type: DriverEventType::ImageExecuteAttempt,
            file_path: path.display().to_string(),
            normalized_file_path: None,
            process_id: Some(1234),
            parent_process_id: None,
            user_sid: None,
            desired_access: None,
            file_size: None,
            sha256: None,
            timestamp_utc: Utc::now(),
        }
    }

    #[test]
    fn driver_request_known_clean_allows() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        fs::write(&file, b"normal developer tool").unwrap();
        let verdict = evaluate_driver_request(&request_for(&file), &Default::default()).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
    }

    #[test]
    fn driver_request_known_bad_blocks() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"harmless known bad test fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let config = DriverVerdictConfig {
            known_bad_hashes: HashSet::from([hash]),
            ..Default::default()
        };
        let verdict = evaluate_driver_request(&request_for(&file), &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert!(verdict.quarantine_after_block);
    }

    #[test]
    fn driver_request_safe_eicar_blocks() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("eicar.com");
        fs::write(&file, PASUS_SAFE_EICAR_SIMULATOR).unwrap();
        let verdict = evaluate_driver_request(&request_for(&file), &Default::default()).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.final_verdict, FinalVerdict::ConfirmedMalware);
    }

    #[test]
    fn medium_yara_is_monitor_only() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("script.ps1");
        fs::write(&file, "[Convert]::FromBase64String('AAAA')").unwrap();
        let verdict = evaluate_driver_request(&request_for(&file), &Default::default()).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::AllowAndMonitor);
        assert_eq!(verdict.final_verdict, FinalVerdict::Suspicious);
    }
}
