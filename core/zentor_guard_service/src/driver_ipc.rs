use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zentor_native_engine::{
    EngineConfig, ScanActionMode as AneScanActionMode, Verdict as AneVerdict, ZentorNativeEngine,
};

use crate::preexecution_policy::DriverProtectionMode;

#[cfg(any(feature = "compat_yara", test))]
const GUARD_YARA_RULE_TEXT_LIMIT_BYTES: u64 = 256 * 1024;
const MAX_DRIVER_HASH_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TRUSTED_PUBLISHER_NAME_LEN: usize = 256;
const MAX_TRUSTED_METADATA_SOURCE_LEN: usize = 64;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

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
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub signature_verified_by: Option<String>,
    pub parent_process_path: Option<String>,
    pub sha256: Option<String>,
    #[serde(default)]
    pub sha256_verified_by: Option<String>,
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
    #[allow(dead_code)]
    pub pre_execution_timeout_ms: u64,
}

enum RequestHashEvidence {
    AbsentOrUntrusted,
    Valid(String),
    MalformedTrustedMetadata,
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
                "avorax".to_string(),
                "avorax security".to_string(),
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

    let mut malformed_trusted_hash = false;
    let mut local_hash_error: Option<String> = None;
    let mut hash_from_trusted_metadata = false;
    let hash = match sha256_file(&path) {
        Ok(hash) => Some(hash),
        Err(error) => {
            local_hash_error = Some(format!("{error:#}"));
            match trusted_request_sha256(request) {
                RequestHashEvidence::Valid(hash) => {
                    hash_from_trusted_metadata = true;
                    Some(hash)
                }
                RequestHashEvidence::MalformedTrustedMetadata => {
                    malformed_trusted_hash = true;
                    None
                }
                RequestHashEvidence::AbsentOrUntrusted => None,
            }
        }
    };

    let known_bad_hash_matched = match hash.as_deref() {
        Some(value) => hash_set_contains(&config.known_bad_hashes, value),
        None => false,
    };

    if known_bad_hash_matched {
        let reason = hash_evidence_reason(
            "Known bad hash matched local cache.",
            local_hash_error.as_deref(),
            hash_from_trusted_metadata,
        );
        return Ok(block(request, &reason, vec![VerdictEngine::KnownBadHash]));
    }

    if malformed_trusted_hash {
        return Ok(malformed_trusted_hash_result(
            request,
            config.mode,
            local_hash_error.as_deref(),
        ));
    }

    let known_good_hash_matched = match hash.as_deref() {
        Some(value) => hash_set_contains(&config.known_good_hashes, value),
        None => false,
    };

    if known_good_hash_matched {
        let reason = hash_evidence_reason(
            "Known-good exact hash is trusted.",
            local_hash_error.as_deref(),
            hash_from_trusted_metadata,
        );
        return Ok(allow(
            request,
            FinalVerdict::LikelyClean,
            &reason,
            vec![VerdictEngine::KnownGoodHash],
            ApplicationTrustLevel::KnownGoodHash,
        ));
    }

    let user_approved_hash_matched = match hash.as_deref() {
        Some(value) => hash_set_contains(&config.user_approved_hashes, value),
        None => false,
    };

    if user_approved_hash_matched {
        let reason = hash_evidence_reason(
            "User approved this exact file hash.",
            local_hash_error.as_deref(),
            hash_from_trusted_metadata,
        );
        return Ok(allow(
            request,
            FinalVerdict::LikelyClean,
            &reason,
            vec![VerdictEngine::AppControl],
            ApplicationTrustLevel::UserApproved,
        ));
    }

    if trusted_publisher(request, config)? {
        let reason = hash_evidence_reason(
            "Valid trusted publisher signature.",
            local_hash_error.as_deref(),
            hash_from_trusted_metadata,
        );
        return Ok(allow(
            request,
            FinalVerdict::LikelyClean,
            &reason,
            vec![VerdictEngine::TrustedPublisher],
            ApplicationTrustLevel::TrustedPublisher,
        ));
    }

    if let Some(native) = cached_native_engine_verdict(&path)? {
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
        DriverProtectionMode::Disabled => {
            let reason = hash_evidence_reason(
                "Driver protection is disabled.",
                local_hash_error.as_deref(),
                hash_from_trusted_metadata,
            );
            Ok(allow(
                request,
                FinalVerdict::Unknown,
                &reason,
                vec![],
                ApplicationTrustLevel::Unknown,
            ))
        }
        DriverProtectionMode::ObserveOnly | DriverProtectionMode::DeveloperMode => {
            let reason = hash_evidence_reason(
                "Unknown app allowed for monitoring in the selected protection profile.",
                local_hash_error.as_deref(),
                hash_from_trusted_metadata,
            );
            Ok(monitor(request, &reason))
        }
        DriverProtectionMode::Balanced
        | DriverProtectionMode::BlockKnownBad
        | DriverProtectionMode::BlockConfirmedThreats
        | DriverProtectionMode::Aggressive => {
            let reason = hash_evidence_reason(
                "Unknown app is not labeled malware; it is allowed with monitoring.",
                local_hash_error.as_deref(),
                hash_from_trusted_metadata,
            );
            Ok(monitor(request, &reason))
        }
        DriverProtectionMode::Lockdown => {
            let reason = hash_evidence_reason(
                "Lockdown Mode blocks unknown apps until an exact hash is approved.",
                local_hash_error.as_deref(),
                hash_from_trusted_metadata,
            );
            Ok(ScanVerdict {
                request_id: request.request_id.clone(),
                action: DriverVerdictAction::Block,
                final_verdict: FinalVerdict::Unknown,
                confidence: VerdictConfidence::Low,
                engines_used: vec![VerdictEngine::AppControl],
                reason_summary: reason,
                cache_ttl_ms: 30_000,
                quarantine_after_block: false,
                trust_level: ApplicationTrustLevel::Unknown,
                requires_user_approval: true,
                monitor_process: false,
                label_as_malware: false,
            })
        }
    }
}

fn normalized_path(request: &ScanRequest) -> PathBuf {
    request_path_text(request).into()
}

fn request_path_text(request: &ScanRequest) -> &str {
    match request.normalized_file_path.as_deref() {
        Some(value) if !value.trim().is_empty() => value,
        Some(_) => &request.file_path,
        None => &request.file_path,
    }
}

struct NativeEngineCache {
    engine: Mutex<ZentorNativeEngine>,
}

static NATIVE_ENGINE_CACHE: OnceLock<Result<NativeEngineCache, String>> = OnceLock::new();

fn cached_native_engine_verdict(
    path: &Path,
) -> anyhow::Result<Option<zentor_native_engine::FileScanVerdict>> {
    if !driver_scan_candidate_is_regular_file(path)? {
        return Ok(None);
    }
    let cache = NATIVE_ENGINE_CACHE
        .get_or_init(|| {
            let asset_root = native_asset_root().map_err(|error| format!("{error:#}"))?;
            EngineConfig::from_repo_root(asset_root)
                .and_then(ZentorNativeEngine::initialize)
                .map(|engine| NativeEngineCache {
                    engine: Mutex::new(engine),
                })
                .map_err(|error| format!("{error:#}"))
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!(error.clone()))?;
    let mut engine = cache
        .engine
        .lock()
        .map_err(|_| anyhow::anyhow!("native engine cache lock poisoned"))?;
    Ok(Some(engine.scan_file(
        path.to_path_buf(),
        AneScanActionMode::DetectOnly,
    )?))
}

fn driver_scan_candidate_is_regular_file(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && !is_guard_driver_reparse_point(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect driver scan candidate {}", path.display())),
    }
}

#[cfg(windows)]
fn is_guard_driver_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_guard_driver_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn native_asset_root() -> anyhow::Result<PathBuf> {
    let roots = guard_asset_root_candidates("driver IPC native asset root discovery")?;
    for candidate in &roots {
        if native_asset_marker_dir_is_regular(&candidate.join("assets").join("zentor_native"))? {
            return Ok(candidate.to_path_buf());
        }
    }
    let root = roots.first().ok_or_else(|| {
        anyhow::anyhow!("driver IPC native asset root discovery found no controlled roots")
    })?;
    Ok(root.to_path_buf())
}

fn native_asset_marker_dir_is_regular(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && !is_guard_native_asset_reparse_point(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect driver IPC native asset marker {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn is_guard_native_asset_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_guard_native_asset_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn guard_asset_root_candidates(context: &str) -> anyhow::Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    let exe = std::env::current_exe()
        .with_context(|| format!("{context} failed to resolve current executable"))?;
    let parent = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{context} found no parent for {}", exe.display()))?;
    push_guard_executable_asset_roots(&mut roots, parent)?;

    #[cfg(debug_assertions)]
    {
        let current_dir = std::env::current_dir()
            .with_context(|| format!("{context} failed to read current directory"))?;
        push_debug_guard_asset_roots(&mut roots, &current_dir)?;
    }

    Ok(roots)
}

fn push_guard_executable_asset_roots(
    roots: &mut Vec<PathBuf>,
    parent: &Path,
) -> anyhow::Result<()> {
    for candidate in [
        parent.to_path_buf(),
        parent.join(".."),
        parent.join("..").join(".."),
        parent.join("..").join("..").join(".."),
    ] {
        push_unique_guard_asset_root(roots, &candidate)?;
    }
    Ok(())
}

fn push_unique_guard_asset_root(roots: &mut Vec<PathBuf>, root: &Path) -> anyhow::Result<()> {
    if !guard_asset_root_is_allowed(root) {
        anyhow::bail!(
            "driver IPC asset root {} must be an absolute local path",
            root.display()
        );
    }
    if !roots.iter().any(|existing| existing == root) {
        roots.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(windows)]
fn guard_asset_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
}

#[cfg(not(windows))]
fn guard_asset_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(debug_assertions)]
fn push_debug_guard_asset_roots(
    roots: &mut Vec<PathBuf>,
    current_dir: &Path,
) -> anyhow::Result<()> {
    for root in current_dir.ancestors() {
        if is_guard_development_root(root)? {
            push_unique_guard_asset_root(roots, root)?;
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn is_guard_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_guard_service")
        .join("Cargo.toml");
    guard_development_marker_file_present(&marker, "driver IPC guard development marker")
}

#[cfg(debug_assertions)]
fn guard_development_marker_file_present(path: &Path, description: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("{description} {} is a symbolic link", path.display());
            }
            if is_guard_native_asset_reparse_point(&metadata) {
                anyhow::bail!("{description} {} is a reparse point", path.display());
            }
            if !metadata.file_type().is_file() {
                anyhow::bail!("{description} {} is not a regular file", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect {description} {}", path.display())),
    }
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

fn hash_evidence_reason(
    base: &str,
    local_hash_error: Option<&str>,
    used_trusted_hash_metadata: bool,
) -> String {
    let Some(local_hash_error) = local_hash_error else {
        return base.to_string();
    };
    let hash_note = if used_trusted_hash_metadata {
        "Local file hash was unavailable; trusted SHA-256 metadata was used instead"
    } else {
        "Local file hash was unavailable; no local hash evidence was used"
    };
    format!("{base} {hash_note}: {local_hash_error}")
}

fn malformed_trusted_hash_result(
    request: &ScanRequest,
    mode: DriverProtectionMode,
    local_hash_error: Option<&str>,
) -> ScanVerdict {
    let reason = hash_evidence_reason(
        "Malformed trusted SHA-256 metadata was supplied by the driver boundary; treating the request as suspicious untrusted metadata.",
        local_hash_error,
        false,
    );
    match mode {
        DriverProtectionMode::Disabled => {
            let disabled_reason = hash_evidence_reason(
                "Driver protection is disabled; malformed trusted SHA-256 metadata was ignored.",
                local_hash_error,
                false,
            );
            allow(
                request,
                FinalVerdict::Unknown,
                &disabled_reason,
                vec![VerdictEngine::AppControl],
                ApplicationTrustLevel::Unknown,
            )
        }
        DriverProtectionMode::Lockdown => ScanVerdict {
            request_id: request.request_id.clone(),
            action: DriverVerdictAction::Block,
            final_verdict: FinalVerdict::Suspicious,
            confidence: VerdictConfidence::Medium,
            engines_used: vec![VerdictEngine::AppControl],
            reason_summary: reason,
            cache_ttl_ms: 30_000,
            quarantine_after_block: false,
            trust_level: ApplicationTrustLevel::Suspicious,
            requires_user_approval: true,
            monitor_process: false,
            label_as_malware: false,
        },
        DriverProtectionMode::ObserveOnly
        | DriverProtectionMode::Balanced
        | DriverProtectionMode::BlockKnownBad
        | DriverProtectionMode::BlockConfirmedThreats
        | DriverProtectionMode::DeveloperMode
        | DriverProtectionMode::Aggressive => ScanVerdict {
            request_id: request.request_id.clone(),
            action: DriverVerdictAction::AllowAndMonitor,
            final_verdict: FinalVerdict::Suspicious,
            confidence: VerdictConfidence::Medium,
            engines_used: vec![VerdictEngine::AppControl],
            reason_summary: reason,
            cache_ttl_ms: 30_000,
            quarantine_after_block: false,
            trust_level: ApplicationTrustLevel::Suspicious,
            requires_user_approval: false,
            monitor_process: true,
            label_as_malware: false,
        },
    }
}

fn trusted_publisher(request: &ScanRequest, config: &DriverVerdictConfig) -> anyhow::Result<bool> {
    if !trusted_metadata_source(request.signature_verified_by.as_deref()) {
        return Ok(false);
    }
    if request.signature_status.as_deref() != Some("valid") {
        return Ok(false);
    }
    let Some(publisher) = request.publisher.as_deref() else {
        return Ok(false);
    };
    let Some(publisher) = normalize_publisher_name(publisher) else {
        return Ok(false);
    };
    Ok(normalized_trusted_publishers(&config.trusted_publishers)?.contains(&publisher))
}

fn normalized_trusted_publishers(values: &HashSet<String>) -> anyhow::Result<HashSet<String>> {
    let mut normalized = HashSet::new();
    for value in values {
        let Some(publisher) = normalize_publisher_name(value) else {
            anyhow::bail!(
                "configured trusted publisher entry is empty, oversized, or contains NUL"
            );
        };
        normalized.insert(publisher);
    }
    Ok(normalized)
}

fn normalize_publisher_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_TRUSTED_PUBLISHER_NAME_LEN
        || trimmed.contains('\0')
    {
        return None;
    }
    let normalized = value
        .trim()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > MAX_TRUSTED_PUBLISHER_NAME_LEN
        || normalized.contains('\0')
    {
        None
    } else {
        Some(normalized)
    }
}

fn trusted_request_sha256(request: &ScanRequest) -> RequestHashEvidence {
    if !trusted_metadata_source(request.sha256_verified_by.as_deref()) {
        return RequestHashEvidence::AbsentOrUntrusted;
    }
    match request.sha256.as_deref() {
        Some(value) => match normalize_sha256(value) {
            Some(hash) => RequestHashEvidence::Valid(format!("sha256:{hash}")),
            None => RequestHashEvidence::MalformedTrustedMetadata,
        },
        None => RequestHashEvidence::AbsentOrUntrusted,
    }
}

fn trusted_metadata_source(source: Option<&str>) -> bool {
    matches!(
        source.and_then(normalize_trusted_metadata_source),
        Some(source)
            if matches!(
                source.as_str(),
                "avorax_kernel_driver"
                    | "avorax_guard_service"
                    | "windows_code_integrity"
                    | "windows_wintrust"
            )
    )
}

fn normalize_trusted_metadata_source(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_TRUSTED_METADATA_SOURCE_LEN
        || trimmed.contains('\0')
    {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

fn hash_set_contains(hashes: &HashSet<String>, value: &str) -> bool {
    let Some(hash) = normalize_sha256(value) else {
        return false;
    };
    hashes.contains(&hash)
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

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    if !driver_scan_candidate_is_regular_file(path)? {
        anyhow::bail!(
            "driver scan candidate {} is not a regular file",
            path.display()
        );
    }
    let mut hasher = Sha256::new();
    let mut reader = BufReader::new(File::open(path)?);
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("driver scan candidate hash size overflow"))?;
        if total > MAX_DRIVER_HASH_BYTES {
            anyhow::bail!(
                "driver scan candidate {} exceeds the hash size limit",
                path.display()
            );
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(feature = "compat_yara")]
struct YaraDecision {
    reason: String,
    confirmed_or_high: bool,
}

#[cfg(feature = "compat_yara")]
fn yara_match(path: &Path) -> anyhow::Result<Option<YaraDecision>> {
    let rules_path = default_yara_rules_path()?;
    if !guard_yara_rules_file_present(&rules_path)? {
        return Ok(None);
    }
    let rules = read_bounded_guard_yara_rules(&rules_path)?;
    let Some(body) = read_bounded_driver_yara_sample(path, 1_048_576)? else {
        return Ok(None);
    };
    let body_text = String::from_utf8_lossy(&body).to_lowercase();
    let mut current_rule = String::new();
    let mut confidence = "low".to_string();
    let mut description = String::new();

    for line in rules.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            let Some(rule_name) = yara_rule_name(trimmed) else {
                anyhow::bail!("driver YARA rule header is malformed");
            };
            current_rule = rule_name;
            confidence = "low".to_string();
            description.clear();
        } else if trimmed.starts_with("confidence") {
            if current_rule.is_empty() {
                continue;
            }
            let Some(value) = metadata_value(trimmed, "confidence") else {
                anyhow::bail!("driver YARA rule {current_rule} confidence metadata is malformed");
            };
            confidence = normalized_yara_confidence(&current_rule, &value)?;
        } else if let Some(value) = metadata_value(trimmed, "description") {
            description = value;
        } else if trimmed.starts_with('$') {
            if current_rule.is_empty() {
                continue;
            }
            let Some((_, value)) = trimmed.split_once('=') else {
                anyhow::bail!("driver YARA rule {current_rule} string declaration is malformed");
            };
            let Some(pattern) = quoted_value(value.trim()) else {
                anyhow::bail!("driver YARA rule {current_rule} string pattern is malformed");
            };
            if body_text.contains(&pattern.to_lowercase()) {
                return Ok(Some(YaraDecision {
                    reason: if description.is_empty() {
                        format!("YARA rule matched: {current_rule}")
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
fn read_bounded_driver_yara_sample(path: &Path, limit: u64) -> anyhow::Result<Option<Vec<u8>>> {
    if !driver_scan_candidate_is_regular_file(path)? {
        return Ok(None);
    }
    let mut reader = BufReader::new(File::open(path)?);
    let mut body = Vec::new();
    let mut remaining = limit;
    let mut buffer = [0_u8; 8192];
    while remaining > 0 {
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
        remaining -= read as u64;
        body.extend_from_slice(&buffer[..read]);
    }
    Ok(Some(body))
}

#[cfg(any(feature = "compat_yara", test))]
fn read_bounded_guard_yara_rules(path: &Path) -> anyhow::Result<String> {
    use std::io::{BufReader, Read};

    let metadata = ensure_regular_guard_yara_rules(path)?;
    if metadata.len() > GUARD_YARA_RULE_TEXT_LIMIT_BYTES {
        anyhow::bail!(
            "driver YARA rules {} exceeds maximum size of {} bytes",
            path.display(),
            GUARD_YARA_RULE_TEXT_LIMIT_BYTES
        );
    }
    let mut reader = BufReader::new(fs::File::open(path)?);
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
            .ok_or_else(|| anyhow::anyhow!("driver YARA rules {} size overflow", path.display()))?;
        if total > GUARD_YARA_RULE_TEXT_LIMIT_BYTES {
            anyhow::bail!(
                "driver YARA rules {} exceeds maximum size of {} bytes",
                path.display(),
                GUARD_YARA_RULE_TEXT_LIMIT_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("unable to decode driver YARA rules {}", path.display()))
}

#[cfg(any(feature = "compat_yara", test))]
fn guard_yara_rules_file_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect driver YARA rules {}", path.display())),
    }
}

#[cfg(any(feature = "compat_yara", test))]
fn ensure_regular_guard_yara_rules(path: &Path) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect driver YARA rules {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("driver YARA rules {} is a symbolic link", path.display());
    }
    if is_guard_yara_reparse_point(&metadata) {
        anyhow::bail!("driver YARA rules {} is a reparse point", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("driver YARA rules {} is not a regular file", path.display());
    }
    Ok(metadata)
}

#[cfg(all(any(feature = "compat_yara", test), windows))]
fn is_guard_yara_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(any(feature = "compat_yara", test), not(windows)))]
fn is_guard_yara_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(feature = "compat_yara")]
fn default_yara_rules_path() -> anyhow::Result<PathBuf> {
    let roots = guard_asset_root_candidates("driver YARA default-rule discovery")?;
    for root in &roots {
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
            if guard_yara_rules_file_present(&candidate)? {
                return Ok(candidate);
            }
        }
    }
    let root = roots.first().ok_or_else(|| {
        anyhow::anyhow!("driver YARA default-rule discovery found no controlled roots")
    })?;
    Ok(root
        .join("assets")
        .join("yara")
        .join("zentor_core_rules.yar"))
}

#[cfg(feature = "compat_yara")]
fn yara_rule_name(line: &str) -> Option<String> {
    let name = line
        .strip_prefix("rule ")
        .and_then(|value| value.split_whitespace().next())?
        .trim_matches('{');
    if is_yara_rule_identifier(name) {
        Some(name.to_string())
    } else {
        None
    }
}

#[cfg(feature = "compat_yara")]
fn is_yara_rule_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
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

#[cfg(feature = "compat_yara")]
fn normalized_yara_confidence(rule_name: &str, value: &str) -> anyhow::Result<String> {
    match value {
        "confirmed" | "high" | "medium" | "low" => Ok(value.to_string()),
        _ => anyhow::bail!("driver YARA rule {rule_name} confidence metadata is unsupported"),
    }
}

fn should_fail_open_path(path: &Path) -> bool {
    let raw = path.display().to_string();
    if runtime_root_candidate_has_parent_traversal(&raw) {
        return false;
    }
    let windows_path = normalize_windows_fail_open_path(&raw);
    let unix_path = normalize_unix_fail_open_path(&raw);
    is_windows_system_runtime_path(&windows_path)
        || is_windows_product_runtime_path(&windows_path)
        || is_unix_system_runtime_path(&unix_path)
        || is_unix_product_runtime_path(&unix_path)
}

fn is_windows_system_runtime_path(path: &str) -> bool {
    windows_directory_candidates().iter().any(|windows| {
        path_is_equal_or_descendant(path, &join_windows_path(windows, "system32"), '\\')
            || path_is_equal_or_descendant(path, &join_windows_path(windows, "syswow64"), '\\')
    })
}

fn is_windows_product_runtime_path(path: &str) -> bool {
    if quarantine_root_candidates()
        .iter()
        .map(|root| normalize_windows_fail_open_path(root))
        .any(|root| path_is_equal_or_descendant(path, &root, '\\'))
    {
        return true;
    }

    if let Ok(exe) = std::env::current_exe() {
        let current_exe = normalize_windows_fail_open_path(&exe.display().to_string());
        if !current_exe.is_empty() && path == current_exe {
            return true;
        }
    }

    let Some(file_name) = path.rsplit('\\').next() else {
        return false;
    };
    if !matches!(
        file_name,
        "avorax_local_core.exe"
            | "avorax_guard_service.exe"
            | "zentor_local_core.exe"
            | "zentor_guard_service.exe"
    ) {
        return false;
    }
    product_install_root_candidates()
        .iter()
        .map(|root| normalize_windows_fail_open_path(root))
        .any(|root| path_is_equal_or_descendant(path, &root, '\\'))
}

fn is_unix_system_runtime_path(path: &str) -> bool {
    ["/usr", "/bin", "/sbin"]
        .iter()
        .any(|root| path_is_equal_or_descendant(path, root, '/'))
}

fn is_unix_product_runtime_path(path: &str) -> bool {
    if quarantine_root_candidates()
        .iter()
        .map(|root| normalize_unix_fail_open_path(root))
        .any(|root| path_is_equal_or_descendant(path, &root, '/'))
    {
        return true;
    }
    if let Ok(exe) = std::env::current_exe() {
        let current_exe = normalize_unix_fail_open_path(&exe.display().to_string());
        if !current_exe.is_empty() && path == current_exe {
            return true;
        }
    }
    false
}

fn windows_directory_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    for key in ["SystemRoot", "WINDIR"] {
        if let Ok(value) = std::env::var(key) {
            if runtime_root_candidate_text_is_safe(&value) {
                push_unique_absolute_runtime_root(
                    &mut candidates,
                    normalize_windows_fail_open_path(&value),
                );
            }
        }
    }
    candidates
}

fn program_data_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    for key in ["ProgramData", "PROGRAMDATA"] {
        if let Ok(value) = std::env::var(key) {
            if runtime_root_candidate_text_is_safe(&value) {
                push_unique_absolute_runtime_root(
                    &mut candidates,
                    normalize_windows_fail_open_path(&value),
                );
            }
        }
    }
    candidates
}

fn product_install_root_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    for key in ["ProgramFiles", "PROGRAMFILES", "ProgramFiles(x86)"] {
        if let Ok(value) = std::env::var(key) {
            if !runtime_root_candidate_text_is_safe(&value) {
                continue;
            }
            let root = normalize_windows_fail_open_path(&value);
            if runtime_root_candidate_is_absolute(&root) {
                for product in ["Avorax", "Zentor"] {
                    push_unique_normalized(&mut candidates, join_windows_path(&root, product));
                }
            }
        }
    }
    candidates
}

fn quarantine_root_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    for key in [
        "AVORAX_GUARD_QUARANTINE_DIR",
        "AVORAX_QUARANTINE_DIR",
        "ZENTOR_GUARD_QUARANTINE_DIR",
        "ZENTOR_QUARANTINE_DIR",
    ] {
        if let Ok(value) = std::env::var(key) {
            if runtime_root_candidate_text_is_safe(&value) {
                push_unique_absolute_runtime_root(&mut candidates, value);
            }
        }
    }
    for program_data in program_data_candidates() {
        for product in ["Avorax", "Zentor"] {
            for child in ["Quarantine", "GuardQuarantine"] {
                push_unique_normalized(
                    &mut candidates,
                    join_windows_path(&join_windows_path(&program_data, product), child),
                );
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if runtime_root_candidate_text_is_safe(&home) && runtime_root_candidate_is_absolute(&home) {
            for product in ["avorax", "zentor"] {
                push_unique_normalized(
                    &mut candidates,
                    format!("{home}/.local/share/{product}/quarantine"),
                );
            }
        }
    }
    candidates
}

fn normalize_windows_fail_open_path(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut previous_separator = false;
    for ch in value.trim().chars() {
        if ch == '\\' || ch == '/' {
            if !previous_separator {
                normalized.push('\\');
            }
            previous_separator = true;
        } else {
            normalized.push(ch);
            previous_separator = false;
        }
    }
    normalized.make_ascii_lowercase();
    collapse_fail_open_path_segments(&normalized, '\\')
}

fn runtime_root_candidate_text_is_safe(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && !trimmed.contains('\0')
        && !runtime_root_candidate_has_parent_traversal(trimmed)
}

fn runtime_root_candidate_has_parent_traversal(value: &str) -> bool {
    value.replace('\\', "/").split('/').any(|part| part == "..")
}

fn normalize_unix_fail_open_path(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut previous_separator = false;
    for ch in value.trim().chars() {
        if ch == '/' {
            if !previous_separator {
                normalized.push('/');
            }
            previous_separator = true;
        } else {
            normalized.push(ch);
            previous_separator = false;
        }
    }
    normalized.make_ascii_lowercase();
    collapse_fail_open_path_segments(&normalized, '/')
}

fn trim_trailing_separator(mut value: String, separator: char) -> String {
    while value.len() > 1
        && value.ends_with(separator)
        && !(separator == '\\' && value.ends_with(":\\"))
    {
        value.pop();
    }
    value
}

fn collapse_fail_open_path_segments(path: &str, separator: char) -> String {
    let trimmed = trim_trailing_separator(path.to_string(), separator);
    if trimmed.is_empty() {
        return String::new();
    }

    let (prefix, rest, absolute) = split_fail_open_path_prefix(&trimmed, separator);
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split(separator) {
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

    let separator = separator.to_string();
    let body = segments.join(&separator);
    match (prefix, absolute, body.is_empty()) {
        (Some(prefix), _, true) => prefix.to_string(),
        (Some(prefix), _, false) => format!("{prefix}{separator}{body}"),
        (None, true, true) => separator,
        (None, true, false) => format!("{separator}{body}"),
        (None, false, _) => body,
    }
}

fn split_fail_open_path_prefix(path: &str, separator: char) -> (Option<&str>, &str, bool) {
    let bytes = path.as_bytes();
    if separator == '\\' && bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'\\' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with(separator) {
        return (None, path.trim_start_matches(separator), true);
    }
    (None, path, false)
}

fn join_windows_path(root: &str, child: &str) -> String {
    let root = trim_trailing_separator(root.to_string(), '\\');
    let child = normalize_windows_fail_open_path(child);
    if root.is_empty() {
        child
    } else if child.is_empty() {
        root
    } else {
        format!("{root}\\{child}")
    }
}

fn path_is_equal_or_descendant(path: &str, root: &str, separator: char) -> bool {
    if root.is_empty() {
        return false;
    }
    if path == root {
        return true;
    }
    let Some(rest) = path.strip_prefix(root) else {
        return false;
    };
    rest.starts_with(separator)
}

fn push_unique_absolute_runtime_root(candidates: &mut Vec<String>, value: String) {
    if runtime_root_candidate_is_absolute(&value) {
        push_unique_normalized(candidates, value);
    }
}

fn runtime_root_candidate_is_absolute(value: &str) -> bool {
    let value = value.trim();
    if value.starts_with('/') {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn push_unique_normalized(candidates: &mut Vec<String>, value: String) {
    if !value.is_empty() && !candidates.iter().any(|candidate| candidate == &value) {
        candidates.push(value);
    }
}

#[cfg(test)]
const ZENTOR_SAFE_EICAR_SIMULATOR: &str = "ZENTOR-SAFE-EICAR-SIMULATOR-FILE";

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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
            signature_verified_by: None,
            parent_process_path: None,
            sha256: None,
            sha256_verified_by: None,
            timestamp_utc: Utc::now(),
        }
    }

    fn evaluate_driver_request_with_env_lock(
        request: &ScanRequest,
        config: &DriverVerdictConfig,
    ) -> anyhow::Result<ScanVerdict> {
        let _lock = env_lock();
        evaluate_driver_request(request, config)
    }

    fn normalize_hash(value: &str) -> String {
        normalize_sha256(value)
            .expect("internal driver IPC test hash must be a valid SHA-256 value")
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
        let verdict = evaluate_driver_request_with_env_lock(&request_for(&file), &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
    }

    #[test]
    fn driver_request_unknown_balanced_allows_and_monitors() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("vpn-installer.exe");
        fs::write(&file, b"normal installer").unwrap();
        let verdict =
            evaluate_driver_request_with_env_lock(&request_for(&file), &Default::default())
                .unwrap();
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
        let verdict = evaluate_driver_request_with_env_lock(&request_for(&file), &config).unwrap();
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
        let verdict = evaluate_driver_request_with_env_lock(&request_for(&file), &config).unwrap();
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
        let verdict = evaluate_driver_request_with_env_lock(&request_for(&file), &config).unwrap();
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
        let verdict = evaluate_driver_request_with_env_lock(&request_for(&file), &config).unwrap();
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
        request.signature_verified_by = Some("windows_wintrust".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };
        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::TrustedPublisher);
    }

    #[test]
    fn trusted_publisher_reports_unreadable_local_hash() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing-signed.exe");
        let mut request = request_for(&missing);
        request.signature_status = Some("valid".to_string());
        request.publisher = Some("Microsoft Corporation".to_string());
        request.signature_verified_by = Some("windows_wintrust".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };

        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();

        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::TrustedPublisher);
        assert!(verdict
            .reason_summary
            .contains("Local file hash was unavailable"));
        assert!(verdict
            .reason_summary
            .contains("no local hash evidence was used"));
    }

    #[test]
    fn driver_request_avorax_publisher_allows_in_lockdown() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("avorax-signed.exe");
        fs::write(&file, b"avorax signed fixture").unwrap();
        let mut request = request_for(&file);
        request.signature_status = Some("valid".to_string());
        request.publisher = Some("Avorax Security".to_string());
        request.signature_verified_by = Some("avorax_guard_service".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };
        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::TrustedPublisher);
    }

    #[test]
    fn trusted_publisher_requires_exact_canonical_name() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("lookalike-signed.exe");
        fs::write(&file, b"signed lookalike fixture").unwrap();
        let mut request = request_for(&file);
        request.signature_status = Some("valid".to_string());
        request.publisher = Some("Not Microsoft Corporation".to_string());
        request.signature_verified_by = Some("windows_wintrust".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };

        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();

        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::Unknown);
        assert!(verdict.requires_user_approval);
    }

    #[test]
    fn trusted_publisher_rejects_oversized_observed_publisher_names() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("oversized-signed.exe");
        fs::write(&file, b"signed oversized publisher fixture").unwrap();
        let oversized = "A".repeat(MAX_TRUSTED_PUBLISHER_NAME_LEN + 1);
        let mut request = request_for(&file);
        request.signature_status = Some("valid".to_string());
        request.publisher = Some(oversized.clone());
        request.signature_verified_by = Some("windows_wintrust".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };

        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();

        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::Unknown);
        assert!(verdict.requires_user_approval);
        assert!(
            normalize_publisher_name(&"A".repeat(MAX_TRUSTED_PUBLISHER_NAME_LEN + 1)).is_none()
        );
    }

    #[test]
    fn trusted_publisher_reports_malformed_configured_names() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("signed.exe");
        fs::write(&file, b"signed fixture").unwrap();
        let mut request = request_for(&file);
        request.signature_status = Some("valid".to_string());
        request.publisher = Some("Microsoft Corporation".to_string());
        request.signature_verified_by = Some("windows_wintrust".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            trusted_publishers: HashSet::from([
                "microsoft corporation".to_string(),
                "bad\0publisher".to_string(),
            ]),
            ..Default::default()
        };

        let error = evaluate_driver_request_with_env_lock(&request, &config)
            .unwrap_err()
            .to_string();

        assert!(error.contains("configured trusted publisher entry"));
    }

    #[test]
    fn trusted_publisher_config_does_not_silently_filter_entries() {
        let source = include_str!("driver_ipc.rs");
        let start = source.find("fn trusted_publisher").unwrap();
        let end = source.find("fn trusted_request_sha256").unwrap();
        let trusted_source = &source[start..end];

        assert!(trusted_source.contains("fn normalized_trusted_publishers"));
        assert!(trusted_source.contains("configured trusted publisher entry"));
        assert!(!trusted_source.contains(".filter_map("));
    }

    #[test]
    fn trusted_metadata_source_rejects_oversized_values() {
        assert!(normalize_trusted_metadata_source("windows_wintrust").is_some());
        assert!(normalize_trusted_metadata_source(
            &"a".repeat(MAX_TRUSTED_METADATA_SOURCE_LEN + 1)
        )
        .is_none());
        assert!(!trusted_metadata_source(Some(
            &"a".repeat(MAX_TRUSTED_METADATA_SOURCE_LEN + 1)
        )));
    }

    #[test]
    fn driver_request_unverified_publisher_metadata_does_not_allow_in_lockdown() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("spoofed-signed.exe");
        fs::write(&file, b"unsigned fixture with caller-supplied publisher").unwrap();
        let mut request = request_for(&file);
        request.signature_status = Some("valid".to_string());
        request.publisher = Some("Microsoft Corporation".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };
        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::Unknown);
        assert!(verdict.requires_user_approval);
        assert!(!verdict.label_as_malware);
    }

    #[test]
    fn driver_request_unverified_hash_metadata_does_not_allow_in_lockdown() {
        let dir = tempdir().unwrap();
        let known_good = dir.path().join("known-good.exe");
        let spoofed = dir.path().join("spoofed.exe");
        fs::write(&known_good, b"trusted fixture").unwrap();
        fs::write(&spoofed, b"different unknown fixture").unwrap();
        let trusted_hash = sha256_file(&known_good).unwrap();
        let mut request = request_for(&spoofed);
        request.sha256 = Some(trusted_hash.clone());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            known_good_hashes: HashSet::from([normalize_hash(&trusted_hash)]),
            ..Default::default()
        };
        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::Unknown);
        assert!(verdict.requires_user_approval);
    }

    #[test]
    fn driver_request_trusted_unreadable_hash_metadata_allows_in_lockdown() {
        let dir = tempdir().unwrap();
        let known_good = dir.path().join("known-good.exe");
        let missing = dir.path().join("missing-at-evaluation.exe");
        fs::write(&known_good, b"trusted fixture").unwrap();
        let trusted_hash = sha256_file(&known_good).unwrap();
        let mut request = request_for(&missing);
        request.sha256 = Some(trusted_hash.clone());
        request.sha256_verified_by = Some("avorax_kernel_driver".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            known_good_hashes: HashSet::from([normalize_hash(&trusted_hash)]),
            ..Default::default()
        };
        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::KnownGoodHash);
        assert!(verdict
            .reason_summary
            .contains("Local file hash was unavailable"));
        assert!(verdict
            .reason_summary
            .contains("trusted SHA-256 metadata was used instead"));
    }

    #[test]
    fn driver_hash_read_errors_are_visible_when_no_trusted_metadata() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing-at-evaluation.exe");

        let verdict =
            evaluate_driver_request_with_env_lock(&request_for(&missing), &Default::default())
                .unwrap();

        assert_eq!(verdict.action, DriverVerdictAction::AllowAndMonitor);
        assert_eq!(verdict.final_verdict, FinalVerdict::Unknown);
        assert!(verdict
            .reason_summary
            .contains("Local file hash was unavailable"));
        assert!(verdict
            .reason_summary
            .contains("no local hash evidence was used"));
        assert!(verdict.reason_summary.contains("driver scan candidate"));
    }

    #[test]
    fn readable_file_hash_overrides_malformed_trusted_hash_metadata() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("known-good.exe");
        fs::write(&file, b"trusted fixture").unwrap();
        let trusted_hash = sha256_file(&file).unwrap();
        let mut request = request_for(&file);
        request.sha256 = Some("sha256:abc123".to_string());
        request.sha256_verified_by = Some("avorax_kernel_driver".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            known_good_hashes: HashSet::from([normalize_hash(&trusted_hash)]),
            ..Default::default()
        };

        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();

        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::KnownGoodHash);
        assert!(!verdict
            .reason_summary
            .contains("Malformed trusted SHA-256 metadata"));
    }

    #[test]
    fn malformed_guard_trusted_hash_metadata_is_reported_as_suspicious() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing-at-evaluation.exe");
        let mut request = request_for(&missing);
        request.sha256 = Some("sha256:abc123".to_string());
        request.sha256_verified_by = Some("avorax_kernel_driver".to_string());

        let verdict = evaluate_driver_request_with_env_lock(&request, &Default::default()).unwrap();

        assert_eq!(verdict.action, DriverVerdictAction::AllowAndMonitor);
        assert_eq!(verdict.final_verdict, FinalVerdict::Suspicious);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(verdict.monitor_process);
        assert!(!verdict.label_as_malware);
        assert!(verdict
            .reason_summary
            .contains("Malformed trusted SHA-256 metadata"));
    }

    #[test]
    fn malformed_guard_hash_trust_entries_fail_closed_in_lockdown() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing-at-evaluation.exe");
        let mut request = request_for(&missing);
        request.sha256 = Some("sha256:abc123".to_string());
        request.sha256_verified_by = Some("avorax_kernel_driver".to_string());
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            known_good_hashes: HashSet::from(["abc123".to_string()]),
            user_approved_hashes: HashSet::from(["abc123".to_string()]),
            ..Default::default()
        };

        let verdict = evaluate_driver_request_with_env_lock(&request, &config).unwrap();

        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.final_verdict, FinalVerdict::Suspicious);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(verdict.requires_user_approval);
        assert!(!verdict.quarantine_after_block);
        assert!(!verdict.label_as_malware);
        assert!(verdict
            .reason_summary
            .contains("Malformed trusted SHA-256 metadata"));
    }

    #[test]
    fn driver_hash_lookup_defaults_are_explicit_branches() {
        let source = include_str!("driver_ipc.rs");
        let evaluate_start = source.find("let mut malformed_trusted_hash").unwrap();
        let publisher_start = source
            .find("if trusted_publisher(request, config)")
            .unwrap();
        let evaluate_source = &source[evaluate_start..publisher_start];
        let native_start = source
            .find("if let Some(native) = cached_native_engine_verdict")
            .unwrap();
        let publisher_source = &source[publisher_start..native_start];
        let helper_start = source.find("fn hash_evidence_reason").unwrap();
        let helper_end = source.find("fn malformed_trusted_hash_result").unwrap();
        let helper_source = &source[helper_start..helper_end];
        let trusted_hash_start = source.find("fn trusted_request_sha256").unwrap();
        let trusted_hash_end = source.find("fn trusted_metadata_source").unwrap();
        let trusted_source = &source[trusted_hash_start..trusted_hash_end];
        let hash_helper_start = source.find("fn hash_set_contains").unwrap();
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let hash_helper_source = &source[hash_helper_start..normalize_start];
        let old_trusted_hash_fallback = ["Err(_) => match ", "trusted_request_sha256"].concat();

        assert!(evaluate_source.contains("let mut local_hash_error"));
        assert!(evaluate_source.contains("let mut hash_from_trusted_metadata"));
        assert!(evaluate_source.contains("Err(error) => {"));
        assert!(evaluate_source.contains("local_hash_error = Some(format!(\"{error:#}\"))"));
        assert!(evaluate_source.contains("hash_from_trusted_metadata = true"));
        assert!(evaluate_source.contains("hash_evidence_reason("));
        assert!(publisher_source.contains("hash_evidence_reason("));
        assert!(publisher_source.contains("\"Valid trusted publisher signature.\""));
        assert!(evaluate_source.contains("let known_bad_hash_matched = match hash.as_deref()"));
        assert!(evaluate_source.contains("let known_good_hash_matched = match hash.as_deref()"));
        assert!(evaluate_source.contains("let user_approved_hash_matched = match hash.as_deref()"));
        assert!(!evaluate_source.contains(&old_trusted_hash_fallback));
        assert!(!evaluate_source.contains(".map(|value| hash_set_contains"));
        assert!(!evaluate_source.contains(".unwrap_or(false)"));
        assert!(helper_source.contains("Local file hash was unavailable"));
        assert!(helper_source.contains("trusted SHA-256 metadata was used instead"));
        assert!(helper_source.contains("no local hash evidence was used"));
        assert!(trusted_source.contains("Some(value) => match normalize_sha256(value)"));
        assert!(trusted_source.contains("None => RequestHashEvidence::MalformedTrustedMetadata"));
        assert!(
            !trusted_source.contains(".unwrap_or(RequestHashEvidence::MalformedTrustedMetadata)")
        );
        assert!(hash_helper_source.contains("let Some(hash) = normalize_sha256(value) else"));
        assert!(hash_helper_source.contains("return false;"));
        assert!(!hash_helper_source.contains(".unwrap_or(false)"));
    }

    #[test]
    fn driver_ipc_hash_prefix_branch_is_explicit() {
        let source = include_str!("driver_ipc.rs");
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let sha_start = source.find("fn sha256_file").unwrap();
        let normalize_source = &source[normalize_start..sha_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("match trimmed.strip_prefix(\"sha256:\")"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or"));
    }

    #[test]
    fn driver_request_path_selection_defaults_are_explicit_branches() {
        let mut request = request_for(Path::new(r"C:\raw\sample.exe"));
        request.normalized_file_path = Some(r"C:\normalized\sample.exe".to_string());
        assert_eq!(
            normalized_path(&request),
            PathBuf::from(r"C:\normalized\sample.exe")
        );

        request.normalized_file_path = Some("   ".to_string());
        assert_eq!(
            normalized_path(&request),
            PathBuf::from(r"C:\raw\sample.exe")
        );

        request.normalized_file_path = None;
        assert_eq!(
            normalized_path(&request),
            PathBuf::from(r"C:\raw\sample.exe")
        );

        let source = include_str!("driver_ipc.rs");
        let start = source.find("fn normalized_path").unwrap();
        let end = source.find("struct NativeEngineCache").unwrap();
        let path_source = &source[start..end];

        assert!(path_source.contains("fn request_path_text(request: &ScanRequest) -> &str"));
        assert!(path_source.contains("Some(value) if !value.trim().is_empty() => value"));
        assert!(path_source.contains("Some(_) => &request.file_path"));
        assert!(path_source.contains("None => &request.file_path"));
        assert!(!path_source.contains(".unwrap_or(&request.file_path)"));
        assert!(!path_source.contains(".filter(|value| !value.trim().is_empty())"));
    }

    #[test]
    fn driver_fails_open_for_avorax_runtime_paths() {
        let _lock = env_lock();
        let previous_program_data = std::env::var_os("ProgramData");
        std::env::set_var("ProgramData", r"C:\ProgramData");
        let request = ScanRequest {
            request_id: "test-request".to_string(),
            event_type: DriverEventType::ImageExecuteAttempt,
            file_path: "C:\\ProgramData\\Avorax\\Quarantine\\item.avoraxq".to_string(),
            normalized_file_path: None,
            process_id: Some(1234),
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
        };
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };
        let verdict = evaluate_driver_request(&request, &config).unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Allow);
        assert_eq!(verdict.trust_level, ApplicationTrustLevel::SystemTrusted);
        assert!(!verdict.label_as_malware);
        if let Some(previous_program_data) = previous_program_data {
            std::env::set_var("ProgramData", previous_program_data);
        } else {
            std::env::remove_var("ProgramData");
        }
    }

    #[test]
    fn fail_open_paths_require_exact_runtime_roots() {
        let _lock = env_lock();
        let previous_program_data = std::env::var_os("ProgramData");
        std::env::set_var("ProgramData", r"C:\ProgramData");
        for windows in windows_directory_candidates() {
            let system_file = format!("{windows}\\System32\\kernel32.dll");
            assert!(should_fail_open_path(Path::new(&system_file)));
        }
        assert!(should_fail_open_path(Path::new(
            r"C:\ProgramData\Avorax\Quarantine\item.avoraxq"
        )));
        assert!(!should_fail_open_path(Path::new(
            r"C:\Users\Public\Windows\System32\lookalike.exe"
        )));
        assert!(!should_fail_open_path(Path::new(
            r"C:\ProgramDataX\Avorax\Quarantine\lookalike.exe"
        )));
        assert!(!should_fail_open_path(Path::new(
            r"C:\Users\Public\avorax_guard_service.exe"
        )));
        if let Some(previous_program_data) = previous_program_data {
            std::env::set_var("ProgramData", previous_program_data);
        } else {
            std::env::remove_var("ProgramData");
        }
    }

    #[test]
    fn fail_open_windows_roots_do_not_use_hardcoded_fallback() {
        let source = include_str!("driver_ipc.rs");
        let start = source.find("fn windows_directory_candidates").unwrap();
        let end = source.find("fn program_data_candidates").unwrap();
        let helper = &source[start..end];

        assert!(helper.contains("[\"SystemRoot\", \"WINDIR\"]"));
        assert!(helper.contains("push_unique_absolute_runtime_root"));
        assert!(!helper.contains("C:\\Windows"));
    }

    #[test]
    fn fail_open_product_and_quarantine_roots_do_not_use_hardcoded_fallbacks() {
        let source = include_str!("driver_ipc.rs");
        let program_data_start = source.find("fn program_data_candidates").unwrap();
        let product_start = source.find("fn product_install_root_candidates").unwrap();
        let quarantine_start = source.find("fn quarantine_root_candidates").unwrap();
        let normalize_start = source.find("fn normalize_windows_fail_open_path").unwrap();
        let program_data_source = &source[program_data_start..product_start];
        let product_source = &source[product_start..quarantine_start];
        let quarantine_source = &source[quarantine_start..normalize_start];
        let hardcoded_program_data = ["C:", "\\ProgramData"].concat();
        let hardcoded_program_files = ["C:", "\\Program Files"].concat();

        assert!(program_data_source.contains("push_unique_absolute_runtime_root"));
        assert!(product_source.contains("runtime_root_candidate_is_absolute"));
        assert!(quarantine_source.contains("program_data_candidates()"));
        assert!(!quarantine_source.contains("std::env::temp_dir()"));
        assert!(!quarantine_source.contains("avorax-native-quarantine"));
        assert!(!quarantine_source.contains("zentor-native-quarantine"));
        assert!(!quarantine_source.contains("avorax-guard-quarantine"));
        assert!(!quarantine_source.contains("zentor-guard-quarantine"));
        assert!(!program_data_source.contains(&hardcoded_program_data));
        assert!(!product_source.contains(&hardcoded_program_files));
    }

    #[test]
    fn fail_open_quarantine_roots_do_not_trust_temp_fallbacks() {
        let _lock = env_lock();
        let env_names = [
            "ProgramData",
            "PROGRAMDATA",
            "AVORAX_GUARD_QUARANTINE_DIR",
            "AVORAX_QUARANTINE_DIR",
            "ZENTOR_GUARD_QUARANTINE_DIR",
            "ZENTOR_QUARANTINE_DIR",
            "HOME",
        ];
        let previous: Vec<_> = env_names
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        for name in env_names {
            std::env::remove_var(name);
        }

        for name in [
            "avorax-native-quarantine",
            "zentor-native-quarantine",
            "avorax-guard-quarantine",
            "zentor-guard-quarantine",
        ] {
            assert!(!quarantine_root_candidates()
                .iter()
                .any(|root| root.contains(name)));
            assert!(!should_fail_open_path(
                &std::env::temp_dir().join(name).join("payload.avoraxq")
            ));
        }

        for (name, value) in previous {
            if let Some(value) = value {
                std::env::set_var(name, value);
            } else {
                std::env::remove_var(name);
            }
        }
    }

    #[test]
    fn fail_open_runtime_roots_ignore_relative_environment_values() {
        let _lock = env_lock();
        let names = [
            "SystemRoot",
            "WINDIR",
            "ProgramData",
            "PROGRAMDATA",
            "ProgramFiles",
            "PROGRAMFILES",
            "ProgramFiles(x86)",
            "AVORAX_GUARD_QUARANTINE_DIR",
            "AVORAX_QUARANTINE_DIR",
            "ZENTOR_GUARD_QUARANTINE_DIR",
            "ZENTOR_QUARANTINE_DIR",
            "HOME",
        ];
        let previous: Vec<_> = names
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        for name in names {
            std::env::set_var(name, "relative-runtime-root");
        }

        assert!(!windows_directory_candidates()
            .iter()
            .any(|root| root.contains("relative-runtime-root")));
        assert!(!product_install_root_candidates()
            .iter()
            .any(|root| root.contains("relative-runtime-root")));
        assert!(!quarantine_root_candidates()
            .iter()
            .any(|root| root.contains("relative-runtime-root")));
        assert!(!should_fail_open_path(Path::new(
            r"relative-runtime-root\System32\kernel32.dll"
        )));
        assert!(!should_fail_open_path(Path::new(
            r"relative-runtime-root\Avorax\Quarantine\payload.avoraxq"
        )));

        for (name, value) in previous {
            if let Some(value) = value {
                std::env::set_var(name, value);
            } else {
                std::env::remove_var(name);
            }
        }
    }

    #[test]
    fn fail_open_runtime_roots_ignore_parent_traversal_environment_values() {
        let _lock = env_lock();
        let names = [
            "SystemRoot",
            "WINDIR",
            "ProgramData",
            "PROGRAMDATA",
            "ProgramFiles",
            "PROGRAMFILES",
            "ProgramFiles(x86)",
            "AVORAX_GUARD_QUARANTINE_DIR",
            "AVORAX_QUARANTINE_DIR",
            "ZENTOR_GUARD_QUARANTINE_DIR",
            "ZENTOR_QUARANTINE_DIR",
            "HOME",
        ];
        let previous: Vec<_> = names
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        std::env::set_var("SystemRoot", r"C:\Windows\..\TempSystem");
        std::env::set_var("WINDIR", r"C:\Windows\..\TempSystem");
        std::env::set_var("ProgramData", r"C:\ProgramData\..\Users");
        std::env::set_var("PROGRAMDATA", r"C:\ProgramData\..\Users");
        std::env::set_var("ProgramFiles", r"C:\Program Files\..\Users");
        std::env::set_var("PROGRAMFILES", r"C:\Program Files\..\Users");
        std::env::set_var("ProgramFiles(x86)", r"C:\Program Files (x86)\..\Users");
        std::env::set_var(
            "AVORAX_GUARD_QUARANTINE_DIR",
            r"C:\ProgramData\Avorax\Quarantine\..\Outside",
        );
        std::env::set_var(
            "AVORAX_QUARANTINE_DIR",
            r"C:\ProgramData\Avorax\Quarantine\..\Outside",
        );
        std::env::set_var(
            "ZENTOR_GUARD_QUARANTINE_DIR",
            r"C:\ProgramData\Zentor\Quarantine\..\Outside",
        );
        std::env::set_var(
            "ZENTOR_QUARANTINE_DIR",
            r"C:\ProgramData\Zentor\Quarantine\..\Outside",
        );
        std::env::set_var("HOME", "/home/avorax/..");
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };

        assert!(!windows_directory_candidates()
            .iter()
            .any(|root| root.contains("tempsystem")));
        assert!(!program_data_candidates()
            .iter()
            .any(|root| root.contains("users")));
        assert!(!product_install_root_candidates()
            .iter()
            .any(|root| root.contains("users")));
        assert!(!quarantine_root_candidates()
            .iter()
            .any(|root| root.contains("outside")));
        let escaped = evaluate_driver_request(
            &request_for(Path::new(r"C:\ProgramData\Avorax\Outside\payload.exe")),
            &config,
        )
        .unwrap();

        for (name, value) in previous {
            if let Some(value) = value {
                std::env::set_var(name, value);
            } else {
                std::env::remove_var(name);
            }
        }

        assert_eq!(escaped.action, DriverVerdictAction::Block);
        assert_eq!(escaped.trust_level, ApplicationTrustLevel::Unknown);
    }

    #[test]
    fn fail_open_path_prefix_checks_do_not_use_false_defaults() {
        let source = include_str!("driver_ipc.rs");
        let helper_start = source.find("fn path_is_equal_or_descendant").unwrap();
        let helper_end = source.find("fn push_unique_normalized").unwrap();
        let helper_source = &source[helper_start..helper_end];

        assert!(helper_source.contains("if path == root"));
        assert!(helper_source.contains("let Some(rest) = path.strip_prefix(root) else"));
        assert!(helper_source.contains("return false;"));
        assert!(!helper_source.contains(".unwrap_or(false)"));
        assert!(!helper_source.contains(".map(|rest| rest.starts_with(separator))"));
    }

    #[test]
    fn lookalike_runtime_paths_do_not_allow_in_lockdown() {
        for path in [
            r"C:\Users\Public\Windows\System32\lookalike.exe",
            r"C:\ProgramDataX\Avorax\Quarantine\lookalike.exe",
            r"C:\Users\Public\avorax_guard_service.exe",
        ] {
            let config = DriverVerdictConfig {
                mode: DriverProtectionMode::Lockdown,
                ..Default::default()
            };
            let verdict =
                evaluate_driver_request_with_env_lock(&request_for(Path::new(path)), &config)
                    .unwrap();
            assert_eq!(verdict.action, DriverVerdictAction::Block);
            assert_eq!(verdict.trust_level, ApplicationTrustLevel::Unknown);
            assert!(verdict.requires_user_approval);
        }
    }

    #[test]
    fn fail_open_rejects_parent_traversal_out_of_runtime_roots() {
        let _lock = env_lock();
        let previous_program_data = std::env::var_os("ProgramData");
        std::env::set_var("ProgramData", r"C:\ProgramData");
        let config = DriverVerdictConfig {
            mode: DriverProtectionMode::Lockdown,
            ..Default::default()
        };

        let escaped = evaluate_driver_request(
            &request_for(Path::new(
                r"C:\ProgramData\Avorax\Quarantine\..\Outside\payload.exe",
            )),
            &config,
        )
        .unwrap();
        let trusted = evaluate_driver_request(
            &request_for(Path::new(
                r"C:\ProgramData\Avorax\Quarantine\.\item.avoraxq",
            )),
            &config,
        )
        .unwrap();

        match previous_program_data {
            Some(value) => std::env::set_var("ProgramData", value),
            None => std::env::remove_var("ProgramData"),
        }

        assert_eq!(escaped.action, DriverVerdictAction::Block);
        assert_eq!(escaped.trust_level, ApplicationTrustLevel::Unknown);
        assert_eq!(trusted.action, DriverVerdictAction::Allow);
        assert_eq!(trusted.trust_level, ApplicationTrustLevel::SystemTrusted);
    }

    #[test]
    fn driver_request_safe_eicar_blocks() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("eicar.com");
        fs::write(&file, ZENTOR_SAFE_EICAR_SIMULATOR).unwrap();
        let verdict =
            evaluate_driver_request_with_env_lock(&request_for(&file), &Default::default())
                .unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::Block);
        assert_eq!(verdict.final_verdict, FinalVerdict::ConfirmedMalware);
    }

    #[test]
    fn medium_native_rule_is_monitor_only() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("script.ps1");
        fs::write(&file, "[Convert]::FromBase64String('AAAA')").unwrap();
        let verdict =
            evaluate_driver_request_with_env_lock(&request_for(&file), &Default::default())
                .unwrap();
        assert_eq!(verdict.action, DriverVerdictAction::AllowAndMonitor);
        assert_eq!(verdict.final_verdict, FinalVerdict::Suspicious);
    }

    #[test]
    fn native_driver_candidate_rejects_directory() {
        let dir = tempdir().unwrap();

        assert!(!driver_scan_candidate_is_regular_file(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn native_driver_candidate_rejects_symbolic_link() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let link = dir.path().join("link.exe");
        fs::write(&target, b"benign driver fixture").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        assert!(!driver_scan_candidate_is_regular_file(&link).unwrap());
    }

    #[test]
    fn native_driver_candidate_uses_non_following_path_guard() {
        let source = crate::normalized_test_source(include_str!("driver_ipc.rs"));
        let start = source.find("fn cached_native_engine_verdict").unwrap();
        let end = source.find("fn native_asset_root").unwrap();
        let native_source = &source[start..end];
        let hash_start = source.find("fn sha256_file").unwrap();
        let hash_end = source
            .find("#[cfg(feature = \"compat_yara\")]\nstruct YaraDecision")
            .unwrap();
        let hash_source = &source[hash_start..hash_end];

        assert!(native_source.contains("driver_scan_candidate_is_regular_file(path)?"));
        assert!(native_source.contains(
            "fn driver_scan_candidate_is_regular_file(path: &Path) -> anyhow::Result<bool>"
        ));
        assert!(native_source.contains("unable to inspect driver scan candidate"));
        assert!(native_source.contains("fs::symlink_metadata(path)"));
        assert!(native_source.contains("metadata.file_type().is_symlink()"));
        assert!(hash_source.contains("driver_scan_candidate_is_regular_file(path)?"));
        assert!(hash_source.contains("driver scan candidate {} is not a regular file"));
        assert!(hash_source.contains("BufReader::new(File::open(path)?)"));
        assert!(hash_source.contains("MAX_DRIVER_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("let mut buffer = [0_u8; 64 * 1024]"));
        assert!(hash_source.contains("total > MAX_DRIVER_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
        let old_hash_copy = ["std::io::", "copy(&mut reader, &mut hasher)?"].concat();
        assert!(!hash_source.contains(&old_hash_copy));
        assert!(!native_source.contains("Err(_) => false"));
        assert!(!native_source.contains("path.exists()"));
        assert!(!native_source.contains("path.is_dir()"));
    }

    #[test]
    fn native_asset_marker_accepts_regular_directory() {
        let dir = tempdir().unwrap();

        assert!(native_asset_marker_dir_is_regular(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn native_asset_marker_rejects_symbolic_link() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("assets-target");
        let link = dir.path().join("zentor_native");
        fs::create_dir_all(&target).unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        assert!(!native_asset_marker_dir_is_regular(&link).unwrap());
    }

    #[test]
    fn native_asset_root_marker_uses_non_following_checks() {
        let source = include_str!("driver_ipc.rs");
        let start = source.find("fn native_asset_root").unwrap();
        let end = source.find("fn native_verdict_engines").unwrap();
        let root_source = &source[start..end];
        let old_current_dir_push = ["roots.push", "(current_dir"].concat();

        assert!(root_source.contains("native_asset_marker_dir_is_regular"));
        assert!(root_source.contains("fn native_asset_root() -> anyhow::Result<PathBuf>"));
        assert!(root_source.contains(
            "fn native_asset_marker_dir_is_regular(path: &Path) -> anyhow::Result<bool>"
        ));
        assert!(root_source.contains("error.kind() == io::ErrorKind::NotFound"));
        assert!(root_source.contains("unable to inspect driver IPC native asset marker"));
        assert!(root_source.contains("guard_asset_root_candidates"));
        assert!(root_source.contains("failed to resolve current executable"));
        assert!(root_source.contains("push_guard_executable_asset_roots"));
        assert!(root_source.contains("#[cfg(debug_assertions)]"));
        assert!(root_source.contains("is_guard_development_root(root)?"));
        assert!(root_source.contains(".join(\"core\")"));
        assert!(root_source.contains(".join(\"zentor_guard_service\")"));
        assert!(root_source.contains("Cargo.toml"));
        assert!(root_source.contains("driver IPC asset root {} must be an absolute local path"));
        assert!(root_source.contains("fs::symlink_metadata(path)"));
        assert!(root_source.contains("metadata.file_type().is_symlink()"));
        assert!(!root_source.contains("Err(_) => false"));
        assert!(!root_source.contains(".exists()"));
        assert!(!root_source.contains("PathBuf::from(\".\")"));
        assert!(!root_source.contains(&old_current_dir_push));
    }

    #[test]
    fn driver_yara_rule_reader_rejects_oversized_rules_before_parse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("oversized.yar");
        fs::write(
            &path,
            "x".repeat(GUARD_YARA_RULE_TEXT_LIMIT_BYTES as usize + 1),
        )
        .unwrap();

        let error = read_bounded_guard_yara_rules(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("driver YARA rules"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn driver_yara_rule_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("driver_ipc.rs");
        let start = source.find("fn read_bounded_guard_yara_rules").unwrap();
        let end = source.find("fn guard_yara_rules_file_present").unwrap();
        let reader = &source[start..end];

        assert!(reader.contains("let metadata = ensure_regular_guard_yara_rules(path)?"));
        assert!(reader.contains("metadata.len() > GUARD_YARA_RULE_TEXT_LIMIT_BYTES"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > GUARD_YARA_RULE_TEXT_LIMIT_BYTES"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
        assert!(source.contains(
            "fn ensure_regular_guard_yara_rules(path: &Path) -> anyhow::Result<fs::Metadata>"
        ));
    }

    #[test]
    fn driver_yara_rules_missing_file_is_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.yar");

        assert!(!guard_yara_rules_file_present(&path).unwrap());
    }

    #[test]
    fn driver_yara_rule_reader_rejects_directory_before_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rules.yar");
        fs::create_dir(&path).unwrap();

        let error = read_bounded_guard_yara_rules(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("driver YARA rules"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn driver_yara_rule_reader_rejects_symbolic_link_before_read() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.yar");
        let path = dir.path().join("rules.yar");
        fs::write(&target, "rule Safe { condition: false }").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = read_bounded_guard_yara_rules(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("driver YARA rules"));
        assert!(error.contains("symbolic link"));
        assert!(guard_yara_rules_file_present(&path).unwrap());
    }

    #[test]
    fn driver_yara_rule_header_names_are_explicit() {
        let source = include_str!("driver_ipc.rs");
        let start = source.find("fn yara_match").unwrap();
        let end = source.find("fn metadata_value").unwrap();
        let yara_source = &source[start..end];

        assert!(yara_source.contains("let Some(rule_name) = yara_rule_name(trimmed) else"));
        assert!(yara_source.contains("driver YARA rule header is malformed"));
        assert!(yara_source
            .contains("driver YARA rule {current_rule} confidence metadata is malformed"));
        assert!(source.contains("driver YARA rule {rule_name} confidence metadata is unsupported"));
        assert!(source.contains(
            "fn normalized_yara_confidence(rule_name: &str, value: &str) -> anyhow::Result<String>"
        ));
        assert!(
            yara_source.contains("driver YARA rule {current_rule} string declaration is malformed")
        );
        assert!(yara_source.contains("driver YARA rule {current_rule} string pattern is malformed"));
        assert!(yara_source.contains("if current_rule.is_empty()"));
        assert!(yara_source.contains("format!(\"YARA rule matched: {current_rule}\")"));
        assert!(yara_source.contains("fn yara_rule_name(line: &str) -> Option<String>"));
        assert!(yara_source.contains("fn is_yara_rule_identifier(value: &str) -> bool"));
        assert!(!yara_source.contains("\"YARA rule matched.\".to_string()"));
        assert!(!yara_source.contains(
            "let Some((_, value)) = trimmed.split_once('=') else {\n                continue;"
        ));
        assert!(!yara_source.contains(
            "let Some(pattern) = quoted_value(value.trim()) else {\n                continue;"
        ));
    }

    #[test]
    fn driver_yara_scan_target_uses_non_following_candidate_check() {
        let source = include_str!("driver_ipc.rs");
        let start = source.find("fn yara_match").unwrap();
        let end = source.find("fn read_bounded_guard_yara_rules").unwrap();
        let yara_source = &source[start..end];

        assert!(yara_source.contains("read_bounded_driver_yara_sample(path, 1_048_576)?"));
        assert!(yara_source.contains("fn read_bounded_driver_yara_sample"));
        assert!(yara_source.contains("driver_scan_candidate_is_regular_file(path)?"));
        assert!(yara_source.contains("return Ok(None);"));
        assert!(!yara_source.contains("BufReader::new(File::open(path)?).take(1_048_576)"));
    }

    #[test]
    fn driver_yara_default_rules_path_uses_non_following_presence_checks() {
        let source = crate::normalized_test_source(include_str!("driver_ipc.rs"));
        let start = source.find("fn default_yara_rules_path").unwrap();
        let end = source.find("fn metadata_value").unwrap();
        let default_path_source = &source[start..end];
        let old_optional_current_dir = ["if let Ok", "(current_dir)"].concat();
        let old_current_dir_fallback = ["current_dir", ".join"].concat();

        assert!(default_path_source.contains("guard_yara_rules_file_present(&candidate)?"));
        assert!(default_path_source.contains("Ok(candidate)"));
        assert!(default_path_source.contains("guard_asset_root_candidates"));
        assert!(default_path_source.contains("driver YARA default-rule discovery"));
        assert!(default_path_source.contains("found no controlled roots"));
        assert!(default_path_source.contains(
            "Ok(root\n        .join(\"assets\")\n        .join(\"yara\")\n        .join(\"zentor_core_rules.yar\"))"
        ));
        assert!(!default_path_source.contains("candidate.is_file()"));
        assert!(!default_path_source.contains(&old_optional_current_dir));
        assert!(!default_path_source.contains(&old_current_dir_fallback));
        assert!(!default_path_source.contains("PathBuf::from(\"assets/yara"));
    }
}
