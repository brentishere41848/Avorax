use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use zentor_native_engine::{
    EngineConfig, ZentorNativeEngine, ScanActionMode as AneScanActionMode, Verdict as AneVerdict,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::preexecution_policy::DriverProtectionMode;

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
    pub file_attributes: Option<u32>,
    pub signature_status: Option<String>,
    pub publisher: Option<String>,
    pub parent_process_path: Option<String>,
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
    KnownGoodHash,
    Allowlist,
    AppControl,
    TrustedPublisher,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationTrustLevel {
    SystemTrusted,
    TrustedPublisher,
    KnownGoodHash,
    UserApproved,
    Allowlisted,
    Unknown,
    Suspicious,
    KnownBad,
    ConfirmedMalware,
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
    pub trust_level: ApplicationTrustLevel,
    pub requires_user_approval: bool,
    pub monitor_process: bool,
    pub label_as_malware: bool,
}

#[derive(Debug, Clone)]
pub struct DriverVerdictConfig {
    pub known_bad_hashes: HashSet<String>,
    pub known_good_hashes: HashSet<String>,
    pub user_approved_hashes: HashSet<String>,
    pub trusted_publishers: HashSet<String>,
    pub mode: DriverProtectionMode,
    pub pre_execution_timeout_ms: u64,
}

impl Default for DriverVerdictConfig {
    fn default() -> Self {
        Self {
            known_bad_hashes: HashSet::new(),
            known_good_hashes: HashSet::new(),
            user_approved_hashes: HashSet::new(),
            trusted_publishers: [
                "microsoft windows".to_string(),
                "microsoft corporation".to_string(),
                "zentor".to_string(),
                "zentor security".to_string(),
            ]
            .into_iter()
            .collect(),
            mode: DriverProtectionMode::Balanced,
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
            "Critical system or Avorax-owned path; normal mode fails open.",
            vec![],
            ApplicationTrustLevel::SystemTrusted,
        ));
    }

    let hash = request
        .sha256
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| sha256_file(&path).ok());

    if hash
        .as_ref()
        .map(|value| config.known_bad_hashes.contains(&normalize_hash(value)))
        .unwrap_or(false)
    {
        return Ok(block(
            request,
            "Known bad hash matched local cache.",
            vec![VerdictEngine::KnownBadHash],
        ));
    }

    if hash
        .as_ref()
        .map(|value| config.known_good_hashes.contains(&normalize_hash(value)))
        .unwrap_or(false)
    {
        return Ok(allow(
            request,
            FinalVerdict::LikelyClean,
            "Known-good exact hash is trusted.",
            vec![VerdictEngine::KnownGoodHash],
            ApplicationTrustLevel::KnownGoodHash,
        ));
    }

    if hash
        .as_ref()
        .map(|value| config.user_approved_hashes.contains(&normalize_hash(value)))
        .unwrap_or(false)
    {
        return Ok(allow(
            request,
            FinalVerdict::LikelyClean,
            "User approved this exact file hash.",
            vec![VerdictEngine::AppControl],
            ApplicationTrustLevel::UserApproved,
        ));
    }

    if trusted_publisher(request, config) {
        return Ok(allow(
            request,
            FinalVerdict::LikelyClean,
            "Valid trusted publisher signature.",
            vec![VerdictEngine::TrustedPublisher],
            ApplicationTrustLevel::TrustedPublisher,
        ));
    }

    if let Some(native) = native_engine_verdict(&path)? {
        if matches!(
            native.final_verdict.verdict,
            AneVerdict::TestThreat | AneVerdict::ConfirmedMalware | AneVerdict::ProbableMalware
        ) {
            return Ok(block(
                request,
                &native.final_verdict.user_visible_explanation,
                native_verdict_engines(&native),
            ));
        }
        if matches!(native.final_verdict.verdict, AneVerdict::Suspicious) {
            return Ok(ScanVerdict {
                request_id: request.request_id.clone(),
                action: DriverVerdictAction::AllowAndMonitor,
                final_verdict: FinalVerdict::Suspicious,
                confidence: VerdictConfidence::Medium,
                engines_used: native_verdict_engines(&native),
                reason_summary: native.final_verdict.user_visible_explanation,
                cache_ttl_ms: 30_000,
                quarantine_after_block: false,
                trust_level: ApplicationTrustLevel::Suspicious,
                requires_user_approval: false,
                monitor_process: true,
                label_as_malware: false,
            });
        }
    }

    #[cfg(feature = "compat_yara")]
    {
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
                trust_level: ApplicationTrustLevel::Suspicious,
                requires_user_approval: false,
                monitor_process: true,
                label_as_malware: false,
            });
        }
    }

    match config.mode {
        DriverProtectionMode::Disabled => Ok(allow(
            request,
            FinalVerdict::Unknown,
            "Driver protection is disabled.",
            vec![],
            ApplicationTrustLevel::Unknown,
        )),
        DriverProtectionMode::ObserveOnly | DriverProtectionMode::DeveloperMode => Ok(monitor(
            request,
            "Unknown app allowed for monitoring in the selected protection profile.",
        )),
        DriverProtectionMode::Balanced
        | DriverProtectionMode::BlockKnownBad
        | DriverProtectionMode::BlockConfirmedThreats
        | DriverProtectionMode::Aggressive => Ok(monitor(
            request,
            "Unknown app is not labeled malware; it is allowed with monitoring.",
        )),
        DriverProtectionMode::Lockdown => Ok(ScanVerdict {
            request_id: request.request_id.clone(),
            action: DriverVerdictAction::Block,
            final_verdict: FinalVerdict::Unknown,
            confidence: VerdictConfidence::Low,
            engines_used: vec![VerdictEngine::AppControl],
            reason_summary: "Lockdown Mode blocks unknown apps until an exact hash is approved."
                .to_string(),
            cache_ttl_ms: 30_000,
            quarantine_after_block: false,
            trust_level: ApplicationTrustLevel::Unknown,
            requires_user_approval: true,
            monitor_process: false,
            label_as_malware: false,
        }),
    }
}

fn normalized_path(request: &ScanRequest) -> PathBuf {
    request
        .normalized_file_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&request.file_path)
        .into()
}

fn native_engine_verdict(
    path: &Path,
) -> anyhow::Result<Option<zentor_native_engine::FileScanVerdict>> {
    if !path.exists() || path.is_dir() {
        return Ok(None);
    }
    let mut engine =
        ZentorNativeEngine::initialize(EngineConfig::from_repo_root(native_asset_root()))?;
    Ok(Some(engine.scan_file(
        path.to_path_buf(),
        AneScanActionMode::DetectOnly,
    )?))
}

fn native_asset_root() -> PathBuf {
    let current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for candidate in current.ancestors() {
        if candidate.join("assets").join("zentor_native").exists() {
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
                if candidate.join("assets").join("zentor_native").exists() {
                    return candidate;
                }
            }
        }
    }
    current
}

fn native_verdict_engines(verdict: &zentor_native_engine::FileScanVerdict) -> Vec<VerdictEngine> {
    let mut engines = verdict
        .final_verdict
        .engines_used
        .iter()
        .map(|engine| match engine {
            zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeSignature => {
                VerdictEngine::Signature
            }
            zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeMl => {
                VerdictEngine::LocalAi
            }
            zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeBehavior => {
                VerdictEngine::Behavior
            }
            _ => VerdictEngine::Heuristic,
        })
        .collect::<Vec<_>>();
    if engines.is_empty() {
        engines.push(VerdictEngine::Heuristic);
    }
    engines.sort_by_key(|engine| format!("{engine:?}"));
    engines.dedup();
    engines
}

fn allow(
    request: &ScanRequest,
    verdict: FinalVerdict,
    reason: &str,
    engines_used: Vec<VerdictEngine>,
    trust_level: ApplicationTrustLevel,
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
        trust_level,
        requires_user_approval: false,
        monitor_process: false,
        label_as_malware: false,
    }
}

fn monitor(request: &ScanRequest, reason: &str) -> ScanVerdict {
    ScanVerdict {
        request_id: request.request_id.clone(),
        action: DriverVerdictAction::AllowAndMonitor,
        final_verdict: FinalVerdict::Unknown,
        confidence: VerdictConfidence::Low,
        engines_used: vec![VerdictEngine::AppControl],
        reason_summary: reason.to_string(),
        cache_ttl_ms: 30_000,
        quarantine_after_block: false,
        trust_level: ApplicationTrustLevel::Unknown,
        requires_user_approval: false,
        monitor_process: true,
        label_as_malware: false,
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
        trust_level: ApplicationTrustLevel::ConfirmedMalware,
        requires_user_approval: false,
        monitor_process: false,
        label_as_malware: true,
    }
}

fn trusted_publisher(request: &ScanRequest, config: &DriverVerdictConfig) -> bool {
    if request.signature_status.as_deref() != Some("valid") {
        return false;
    }
    let Some(publisher) = request.publisher.as_deref() else {
        return false;
    };
    let publisher = publisher.to_lowercase();
    config
        .trusted_publishers
        .iter()
        .any(|trusted| publisher.contains(&trusted.to_lowercase()))
}

fn normalize_hash(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_lowercase()
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(feature = "compat_yara")]
struct YaraDecision {
    reason: String,
    confirmed_or_high: bool,
}

#[cfg(feature = "compat_yara")]
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

#[cfg(feature = "compat_yara")]
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
                .join("zentor_core_rules.yar"),
            root.join("..")
                .join("..")
                .join("assets")
                .join("yara")
                .join("zentor_core_rules.yar"),
        ] {
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("assets/yara/zentor_core_rules.yar")
}

#[cfg(feature = "compat_yara")]
fn metadata_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} =");
    line.strip_prefix(&prefix)
        .and_then(|value| quoted_value(value.trim()))
}

#[cfg(feature = "compat_yara")]
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
        || lower.contains("\\zentor\\quarantine\\")
        || lower.contains("\\zentor\\guardquarantine\\")
        || lower.ends_with("\\zentor_local_core.exe")
        || lower.ends_with("\\zentor_guard_service.exe")
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.contains("/zentor/quarantine/")
}

#[cfg(test)]
const ZENTOR_SAFE_EICAR_SIMULATOR: &str = "ZENTOR-SAFE-EICAR-SIMULATOR-FILE";

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
            file_attributes: None,
            signature_status: None,
            publisher: None,
            parent_process_path: None,
            sha256: None,
            timestamp_utc: Utc::now(),
        }
    }

    #[test]
    fn driver_request_known_clean_allows() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        fs::write(&file, b"normal developer tool").unwrap();
        let hash = sha256_file(&file).unwrap();
        let config = DriverVerdictConfig {
            known_good_hashes: HashSet::from([normalize_hash(&hash)]),
            ..Default::default()
        };
        let verdict = evaluate_driver_request(&request_for(&file), &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
    }

    #[test]
    fn driver_request_unknown_balanced_allows_and_monitors() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("vpn-installer.exe");
        fs::write(&file, b"normal installer").unwrap();
        let verdict = evaluate_driver_request(&request_for(&file), &Default::default()).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::AllowAndMonitor);
        assert_eq!(verdict.final_verdict, FinalVerdict::Unknown);
        assert!(!verdict.label_as_malware);
    }

    #[test]
    fn driver_request_known_bad_blocks() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"harmless known bad test fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let config = DriverVerdictConfig {
            known_bad_hashes: HashSet::from([normalize_hash(&hash)]),
            ..Default::default()
        };
        let verdict = evaluate_driver_request(&request_for(&file), &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert!(verdict.quarantine_after_block);
    }

    #[test]
    fn driver_request_unknown_lockdown_blocks_without_malware_label() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("unknown.exe");
        fs::write(&file, b"unknown but harmless executable").unwrap();
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };
        let verdict = evaluate_driver_request(&request_for(&file), &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.final_verdict, FinalVerdict::Unknown);
        assert!(verdict.requires_user_approval);
        assert!(!verdict.quarantine_after_block);
        assert!(!verdict.label_as_malware);
    }

    #[test]
    fn driver_request_known_good_allows_in_lockdown() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("trusted.exe");
        fs::write(&file, b"trusted fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            known_good_hashes: HashSet::from([normalize_hash(&hash)]),
            ..Default::default()
        };
        let verdict = evaluate_driver_request(&request_for(&file), &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::KnownGoodHash);
    }

    #[test]
    fn driver_request_user_approved_hash_allows_in_lockdown() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("approved.exe");
        fs::write(&file, b"user approved fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            user_approved_hashes: HashSet::from([normalize_hash(&hash)]),
            ..Default::default()
        };
        let verdict = evaluate_driver_request(&request_for(&file), &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::UserApproved);
    }

    #[test]
    fn driver_request_trusted_publisher_allows_in_lockdown() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("signed.exe");
        fs::write(&file, b"signed fixture").unwrap();
        let mut request = request_for(&file);
        request.signature_status = Some("valid".to_string());
        request.publisher = Some("Microsoft Corporation".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };
        let verdict = evaluate_driver_request(&request, &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::TrustedPublisher);
    }

    #[test]
    fn driver_request_safe_eicar_blocks() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("eicar.com");
        fs::write(&file, ZENTOR_SAFE_EICAR_SIMULATOR).unwrap();
        let verdict = evaluate_driver_request(&request_for(&file), &Default::default()).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.final_verdict, FinalVerdict::ConfirmedMalware);
    }

    #[test]
    fn medium_native_rule_is_monitor_only() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("script.ps1");
        fs::write(&file, "[Convert]::FromBase64String('AAAA')").unwrap();
        let verdict = evaluate_driver_request(&request_for(&file), &Default::default()).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::AllowAndMonitor);
        assert_eq!(verdict.final_verdict, FinalVerdict::Suspicious);
    }
}
