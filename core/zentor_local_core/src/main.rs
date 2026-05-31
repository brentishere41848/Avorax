use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use zentor_native_engine::{
    Confidence as AneConfidence, EngineConfig, ZentorNativeEngine,
    ScanActionMode as AneScanActionMode, ThreatCategory as AneThreatCategory,
    Verdict as AneVerdict,
};
use serde_json::json;
use sha2::{Digest, Sha256};

mod ai;
mod allowlist;
mod api;
mod app_control;
mod migration;
mod protection;
mod quarantine;
mod scanner;
mod watcher;

use allowlist::{AllowlistEntryType, AllowlistStore};
use api::{CoreCommand, CoreResponse};
use quarantine::QuarantineStore;
use scanner::{
    eligible_for_heuristic_auto_quarantine,
    file_walker::{collect_accessible_files, collect_accessible_files_with_options, WalkOptions},
    ClamAvProvider, DetectionType, HeuristicProvider, RecommendedAction, ReportStatus,
    ReputationProvider, RiskEngine, RiskReason, RiskReasonSource, RiskScore, RiskSeverity,
    RiskVerdict, ScanActionMode, ScanJob, ScanJobStatus, ScanKind, ScanProgress, ScanStatus,
    ScannerProvider, ThreatCategory, ThreatConfidence, ThreatResult, ThreatResultStatus,
    YaraProvider,
};
use uuid::Uuid;
use watcher::WatcherState;

const FULL_SCAN_MAX_SECONDS: u64 = 3 * 60 * 60;
const MAX_SIGNATURE_SCAN_BYTES: u64 = 512 * 1024 * 1024;

fn main() -> Result<()> {
    if let Ok(report) = migration::migrate_from_legacy_brand() {
        let _ = migration::write_migration_event_log(&migration::zentor_data_dir(), &report);
    }
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let command: CoreCommand = serde_json::from_str(&line)?;
        let response = handle(command);
        println!("{}", serde_json::to_string(&response)?);
    }
    Ok(())
}

fn handle(command: CoreCommand) -> serde_json::Value {
    match command.command.as_str() {
        "health" => health_response(),
        "scan_file" => {
            let Some(path) = command.path else {
                return json!({"ok": false, "error": "path is required"});
            };
            let action_mode = parse_action_mode(command.action_mode.as_deref());
            let kind = parse_scan_kind(command.scan_kind.as_deref());
            match scan_paths(vec![PathBuf::from(path)], action_mode, kind, None) {
                Ok(report) => json!(report),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "scan_folder" => {
            let Some(path) = command.path else {
                return json!({"ok": false, "error": "path is required"});
            };
            let action_mode = parse_action_mode(command.action_mode.as_deref());
            let kind = parse_scan_kind(command.scan_kind.as_deref());
            match scan_paths(vec![PathBuf::from(path)], action_mode, kind, None) {
                Ok(report) => json!(report),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "quick_scan_selected_paths" | "full_scan" => {
            let paths = command.paths.unwrap_or_default();
            let action_mode = parse_action_mode(command.action_mode.as_deref());
            let kind = parse_scan_kind(command.scan_kind.as_deref());
            let mut emit = |progress: &ScanProgress| {
                println!(
                    "{}",
                    serde_json::to_string(&json!({"type": "progress", "progress": progress}))
                        .unwrap_or_default()
                );
            };
            match scan_paths(
                paths.into_iter().map(PathBuf::from).collect(),
                action_mode,
                kind,
                Some(&mut emit),
            ) {
                Ok(report) => json!(report),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "list_quarantine" => match QuarantineStore::new().list() {
            Ok(records) => json!({"ok": true, "records": records}),
            Err(error) => json!({"ok": false, "error": error.to_string(), "records": []}),
        },
        "add_allowlist_entry" => {
            let Some(path) = command.path else {
                return json!({"ok": false, "error": "path is required"});
            };
            let mut store = AllowlistStore::new();
            match store.add(
                AllowlistEntryType::File,
                path,
                "Added by local user".to_string(),
            ) {
                Ok(entry) => json!({"ok": true, "entry": entry}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "list_allowlist" => {
            let store = AllowlistStore::new();
            json!({"ok": true, "entries": store.list()})
        }
        "start_watch" => json!({"ok": true, "watcher": WatcherState::stopped()}),
        "stop_watch" => json!({"ok": true, "watcher": WatcherState::stopped()}),
        "quarantine_file" => {
            let Some(path) = command.path else {
                return json!({"ok": false, "error": "path is required"});
            };
            match quarantine_selected_file(
                Path::new(&path),
                command.threat_name.as_deref().unwrap_or("Possible malware"),
                command.engine.as_deref().unwrap_or("zentor-manual-review"),
            ) {
                Ok(record) => json!({"ok": true, "record": record}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "restore_quarantine_item" => {
            let Some(id) = command.quarantine_id else {
                return json!({"ok": false, "error": "quarantine_id is required"});
            };
            match QuarantineStore::new().restore(&id, command.confirmed.unwrap_or(false)) {
                Ok(record) => json!({"ok": true, "record": record}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "delete_quarantine_item" => {
            let Some(id) = command.quarantine_id else {
                return json!({"ok": false, "error": "quarantine_id is required"});
            };
            match QuarantineStore::new().delete(&id, command.confirmed.unwrap_or(false)) {
                Ok(record) => json!({"ok": true, "record": record}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "label_detection" => {
            let Some(path) = command.path else {
                return json!({"ok": false, "error": "path is required"});
            };
            let Some(raw_label) = command.user_label else {
                return json!({"ok": false, "error": "user_label is required"});
            };
            match save_training_label(
                Path::new(&path),
                &raw_label,
                command.user_note,
                command
                    .previous_verdict
                    .unwrap_or_else(|| "unknown".to_string()),
            ) {
                Ok(label_path) => json!({"ok": true, "path": label_path}),
                Err(error) => json!({"ok": false, "error": error.to_string()}),
            }
        }
        "remove_allowlist_entry" => json!({
            "ok": false,
            "error": "command is defined for v1 IPC but not enabled without explicit UI support"
        }),
        _ => json!({"ok": false, "error": "unknown command"}),
    }
}

fn health_response() -> serde_json::Value {
    match native_engine() {
        Ok(mut engine) => {
            let status = engine.status();
            let self_test_ok = engine
                .engine_self_test()
                .map(|report| report.overall_result == "pass")
                .unwrap_or(false);
            json!(CoreResponse {
                ok: true,
                body: json!({
                    "engine_status": if status.native_engine_ready { "available" } else { "error" },
                    "native_engine_status": if status.native_engine_ready { "ready" } else { "error" },
                    "native_signature_count": status.signature_count,
                    "native_rule_count": status.rule_count,
                    "native_ml_status": if status.ml_model_loaded {
                        if status.ml_model_version.as_deref().unwrap_or_default().contains("dev") {
                            "developmentModel"
                        } else {
                            "loaded"
                        }
                    } else {
                        "modelMissing"
                    },
                    "native_ml_model_version": status.ml_model_version,
                    "native_self_test": self_test_ok,
                    "compatibility_engines_enabled": false,
                    "yara_status": "compatDisabled",
                    "yara_rule_count": 0,
                    "ai_status": ai::ModelRunner::default().status(),
                    "ai_model": ai::ModelRunner::default().info(),
                    "ai_self_test": ai::ai_self_test::run_ai_self_test().is_ok(),
                    "guard_status": protection::GuardService::system_status(),
                    "driver_status": "missing",
                    "reputation_status": ReputationProvider.status(),
                    "ipc": "stdio",
                    "network_exposed": false,
                }),
            })
        }
        Err(error) => json!(CoreResponse {
            ok: true,
            body: json!({
                "engine_status": "error",
                "native_engine_status": "error",
                "native_signature_count": 0,
                "native_rule_count": 0,
                "native_ml_status": "modelMissing",
                "native_ml_model_version": null,
                "native_self_test": false,
                "native_error": error.to_string(),
                "compatibility_engines_enabled": false,
                "yara_status": "compatDisabled",
                "yara_rule_count": 0,
                "ai_status": ai::ModelRunner::default().status(),
                "ai_model": ai::ModelRunner::default().info(),
                "ai_self_test": false,
                "guard_status": protection::GuardService::system_status(),
                "driver_status": "missing",
                "reputation_status": ReputationProvider.status(),
                "ipc": "stdio",
                "network_exposed": false,
            }),
        }),
    }
}

fn save_training_label(
    path: &Path,
    raw_label: &str,
    user_note: Option<String>,
    previous_verdict: String,
) -> anyhow::Result<String> {
    use ai::feature_extractor::{extract_static_features, LocationCategory};
    use ai::training_labels::{TrainingLabel, TrainingLabelStore, UserTrainingLabel};

    let user_label = match raw_label {
        "falsePositive" => UserTrainingLabel::FalsePositive,
        "confirmedMalicious" => UserTrainingLabel::ConfirmedMalicious,
        "trustedApp" => UserTrainingLabel::TrustedApp,
        "potentiallyUnwantedButAllowed" => UserTrainingLabel::PotentiallyUnwantedButAllowed,
        _ => UserTrainingLabel::Unsure,
    };
    let features = extract_static_features(path)?;
    let path_category = match &features.location_category {
        LocationCategory::Downloads => "downloads",
        LocationCategory::Temp => "temp",
        LocationCategory::Startup => "startup",
        LocationCategory::System => "system",
        LocationCategory::ProgramFiles => "programFiles",
        LocationCategory::UserProfile => "userProfile",
        LocationCategory::Unknown => "unknown",
    }
    .to_string();
    let label = TrainingLabel {
        label_id: String::new(),
        file_sha256: sha256_for_file(path)?,
        file_name: path
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default(),
        file_path_category: path_category,
        extracted_features: features,
        previous_verdict,
        user_label,
        user_note,
        created_at: Utc::now(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        model_version: ai::ModelRunner::default().status().to_string(),
    };
    let store = TrainingLabelStore::new();
    store.append(label)?;
    Ok(store.path().display().to_string())
}

fn quarantine_selected_file(
    path: &Path,
    threat_name: &str,
    engine: &str,
) -> anyhow::Result<quarantine::QuarantineRecord> {
    let result = scanner::ScanResult {
        status: ScanStatus::Infected,
        scanned_path: path.display().to_string(),
        sha256: sha256_for_file(path)?,
        engine: engine.to_string(),
        signature_name: None,
        threat_name: Some(threat_name.to_string()),
        scanned_at: Utc::now(),
        duration_ms: 0,
        raw_engine_summary: Some("Manual quarantine from Avorax UI".to_string()),
    };
    QuarantineStore::new().quarantine_file(path, &result)
}

fn scan_paths(
    roots: Vec<PathBuf>,
    action_mode: ScanActionMode,
    kind: ScanKind,
    mut emit_progress: Option<&mut dyn FnMut(&ScanProgress)>,
) -> anyhow::Result<scanner::ScanReport> {
    let started = Instant::now();
    let started_at = Utc::now();
    let job = ScanJob::new(kind.clone());
    let mut native_engine = native_engine()?;
    let mut files_scanned: u64 = 0;
    let mut bytes_scanned: u64 = 0;
    let mut skipped_files: u64 = 0;
    let mut permission_denied_count: u64 = 0;
    let mut threats = Vec::new();
    let mut suspicious_found: u64 = 0;
    let mut quarantined_files: u64 = 0;
    let engine_unavailable = false;
    let mut last_path = None;

    let walk = if kind == ScanKind::Quick {
        collect_accessible_files_with_options(&roots, &WalkOptions::quick())
    } else {
        collect_accessible_files(&roots)
    };
    skipped_files += walk.skipped_files;
    permission_denied_count += walk.permission_denied_count;
    let total_files = walk.files.len() as u64;
    let total_bytes = walk.bytes_estimated;
    let mut progress = ScanProgress {
        job_id: job.id.clone(),
        scan_type: kind.clone(),
        status: ScanJobStatus::Running,
        current_path: None,
        files_scanned: 0,
        folders_scanned: walk.folders_scanned,
        bytes_scanned: 0,
        total_files_estimated: Some(total_files),
        total_bytes_estimated: Some(total_bytes),
        threats_found: 0,
        suspicious_found: 0,
        skipped_files,
        permission_denied_count,
        started_at,
        updated_at: Utc::now(),
        elapsed_seconds: 0,
        estimated_remaining_seconds: None,
        progress_percent: None,
    };
    progress.calculate_eta();
    if let Some(emit) = emit_progress.as_deref_mut() {
        emit(&progress);
    }

    for path in walk.files {
        if kind == ScanKind::Full && started.elapsed().as_secs() >= FULL_SCAN_MAX_SECONDS {
            skipped_files = skipped_files.saturating_add(1);
            break;
        }
        let current = path.display().to_string();
        last_path = Some(current.clone());
        files_scanned += 1;
        let file_size = std::fs::metadata(&path)
            .map(|m| m.len())
            .unwrap_or_default();
        bytes_scanned = bytes_scanned.saturating_add(file_size);
        match native_engine.scan_file(path.clone(), AneScanActionMode::DetectOnly) {
            Ok(verdict) => {
                if should_surface_native_verdict(verdict.final_verdict.verdict) {
                    let mut threat = threat_from_native(&path, &verdict);
                    suspicious_found += u64::from(threat.confidence != ThreatConfidence::Confirmed);
                    let allowlisted = AllowlistStore::new().is_allowlisted(&path, &threat.sha256);
                    if allowlisted {
                        threat.status = ThreatResultStatus::Allowlisted;
                        threat.recommended_action = RecommendedAction::Allowlist;
                    } else if native_should_quarantine(action_mode.clone(), &threat) {
                        if let Ok(record) =
                            quarantine_selected_file(&path, &threat.threat_name, &threat.engine)
                        {
                            threat.status = ThreatResultStatus::Quarantined;
                            threat.path = record.original_path;
                            quarantined_files += 1;
                        }
                    }
                    threats.push(threat);
                }
            }
            Err(_) => skipped_files += 1,
        }
        update_progress(
            &mut progress,
            &current,
            files_scanned,
            bytes_scanned,
            threats.len() as u64,
            suspicious_found,
            skipped_files,
            permission_denied_count,
            started,
        );
        if files_scanned == total_files || files_scanned % 25 == 0 {
            if let Some(emit) = emit_progress.as_deref_mut() {
                emit(&progress);
            }
        }
    }

    let status = if !threats.is_empty() {
        ReportStatus::ThreatsFound
    } else if engine_unavailable {
        ReportStatus::EngineUnavailable
    } else if skipped_files > 0 {
        ReportStatus::CompletedWithErrors
    } else {
        ReportStatus::Clean
    };
    progress.status = if status == ReportStatus::Failed {
        ScanJobStatus::Failed
    } else {
        ScanJobStatus::Completed
    };
    progress.updated_at = Utc::now();
    progress.elapsed_seconds = started.elapsed().as_secs();
    progress.files_scanned = files_scanned;
    progress.bytes_scanned = bytes_scanned;
    progress.threats_found = threats.len() as u64;
    progress.suspicious_found = suspicious_found;
    progress.skipped_files = skipped_files;
    progress.permission_denied_count = permission_denied_count;
    progress.progress_percent = Some(100.0);
    progress.estimated_remaining_seconds = Some(0);
    Ok(scanner::ScanReport {
        status,
        kind: kind.clone(),
        action_mode,
        files_scanned,
        folders_scanned: walk.folders_scanned,
        bytes_scanned,
        total_files_estimated: Some(total_files),
        total_bytes_estimated: Some(total_bytes),
        threats_found: threats.len() as u64,
        suspicious_found,
        quarantined_files,
        skipped_files,
        permission_denied_count,
        elapsed_ms: started.elapsed().as_millis(),
        current_path: last_path,
        message: if engine_unavailable {
            Some(
                "Avorax Native Engine is unavailable; files were not reported clean."
                    .to_string(),
            )
        } else if kind == ScanKind::Full {
            Some("Full Scan is optimized to finish within the scan budget by prioritizing risky files and skipping known cache/build folders.".to_string())
        } else if kind == ScanKind::Quick {
            Some(
                "Quick Scan checked high-risk startup, script, installer, archive, and executable locations only. Use Full Scan for exhaustive coverage."
                    .to_string(),
            )
        } else {
            None
        },
        threats,
        progress: Some(progress),
    })
}

fn should_surface_ai_result(result: &ai::model_runner::LocalAiResult) -> bool {
    matches!(
        result.verdict,
        ai::verdict::LocalAiVerdictLabel::Suspicious
            | ai::verdict::LocalAiVerdictLabel::ProbableMalware
            | ai::verdict::LocalAiVerdictLabel::ConfirmedMalware
    )
}

fn should_signature_scan(
    kind: &ScanKind,
    path: &Path,
    file_size: u64,
    last_threat: Option<&ThreatResult>,
) -> bool {
    if file_size > MAX_SIGNATURE_SCAN_BYTES {
        return false;
    }
    if matches!(last_threat, Some(threat) if threat.path == path.display().to_string()) {
        return true;
    }
    if *kind != ScanKind::Full {
        return true;
    }
    let lower_path = path.display().to_string().to_lowercase();
    if lower_path.contains("download")
        || lower_path.contains("desktop")
        || lower_path.contains("temp")
        || lower_path.contains("startup")
        || lower_path.contains("autostart")
    {
        return true;
    }
    let ext = path
        .extension()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "scr"
            | "bat"
            | "cmd"
            | "ps1"
            | "vbs"
            | "js"
            | "jse"
            | "jar"
            | "msi"
            | "com"
            | "pif"
            | "lnk"
            | "zip"
            | "rar"
            | "7z"
            | "iso"
            | "docm"
            | "xlsm"
            | "pptm"
    )
}

#[allow(clippy::too_many_arguments)]
fn update_progress(
    progress: &mut ScanProgress,
    current_path: &str,
    files_scanned: u64,
    bytes_scanned: u64,
    threats_found: u64,
    suspicious_found: u64,
    skipped_files: u64,
    permission_denied_count: u64,
    started: Instant,
) {
    progress.current_path = Some(current_path.to_string());
    progress.files_scanned = files_scanned;
    progress.bytes_scanned = bytes_scanned;
    progress.threats_found = threats_found;
    progress.suspicious_found = suspicious_found;
    progress.skipped_files = skipped_files;
    progress.permission_denied_count = permission_denied_count;
    progress.updated_at = Utc::now();
    progress.elapsed_seconds = started.elapsed().as_secs();
    progress.calculate_eta();
}

fn native_engine() -> anyhow::Result<ZentorNativeEngine> {
    let root = native_asset_root();
    ZentorNativeEngine::initialize(EngineConfig::from_repo_root(root))
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

fn should_surface_native_verdict(verdict: AneVerdict) -> bool {
    !matches!(
        verdict,
        AneVerdict::Clean | AneVerdict::LikelyClean | AneVerdict::Unknown | AneVerdict::Observation
    )
}

fn native_should_quarantine(action_mode: ScanActionMode, threat: &ThreatResult) -> bool {
    match action_mode {
        ScanActionMode::DetectOnly => false,
        ScanActionMode::AutoQuarantineConfirmedOnly => {
            threat.confidence == ThreatConfidence::Confirmed
                && matches!(
                    threat.risk_score.verdict,
                    RiskVerdict::ConfirmedMalware | RiskVerdict::ProbableMalware
                )
        }
        ScanActionMode::AutoQuarantineAllDetections => {
            matches!(
                threat.risk_score.verdict,
                RiskVerdict::ConfirmedMalware | RiskVerdict::ProbableMalware
            ) && matches!(
                threat.confidence,
                ThreatConfidence::Confirmed | ThreatConfidence::High
            )
        }
    }
}

fn threat_from_native(
    path: &Path,
    verdict: &zentor_native_engine::FileScanVerdict,
) -> ThreatResult {
    let metadata = std::fs::metadata(path).ok();
    let confidence = native_confidence(verdict.final_verdict.confidence);
    let risk_verdict = native_risk_verdict(verdict.final_verdict.verdict);
    let engines_used = verdict
        .final_verdict
        .engines_used
        .iter()
        .map(native_engine_source)
        .collect::<Vec<_>>();
    let reasons = verdict
        .final_verdict
        .evidence
        .iter()
        .map(|evidence| RiskReason {
            id: evidence.id.clone(),
            title: evidence.title.clone(),
            detail: evidence.detail.clone(),
            weight: evidence.weight,
            severity: if evidence.weight >= 80 {
                RiskSeverity::Critical
            } else if evidence.weight >= 55 {
                RiskSeverity::High
            } else if evidence.weight >= 25 {
                RiskSeverity::Medium
            } else {
                RiskSeverity::Low
            },
            source: native_reason_source(&evidence.source),
        })
        .collect::<Vec<_>>();
    let detection_type = if engines_used.contains(&RiskEngine::Signature) {
        DetectionType::Signature
    } else if engines_used.contains(&RiskEngine::LocalAi) {
        DetectionType::LocalAi
    } else if engines_used.contains(&RiskEngine::Behavior) {
        DetectionType::Behavior
    } else {
        DetectionType::Heuristic
    };
    ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default(),
        sha256: verdict.sha256.clone(),
        size_bytes: metadata.map(|metadata| metadata.len()).unwrap_or_default(),
        detection_type,
        threat_category: native_category(verdict.final_verdict.category),
        threat_name: native_threat_name(verdict.final_verdict.verdict),
        confidence: confidence.clone(),
        engine: "Avorax Native Engine".to_string(),
        detected_at: verdict.scanned_at,
        recommended_action: if matches!(
            risk_verdict,
            RiskVerdict::ConfirmedMalware | RiskVerdict::ProbableMalware
        ) {
            RecommendedAction::Quarantine
        } else {
            RecommendedAction::Review
        },
        status: ThreatResultStatus::Detected,
        risk_score: RiskScore {
            score: verdict.final_verdict.risk_score,
            verdict: risk_verdict,
            confidence,
            reasons,
            recommended_action: RecommendedAction::Review,
            engines_used,
        },
        reason_summary: verdict.final_verdict.user_visible_explanation.clone(),
    }
}

fn native_confidence(value: AneConfidence) -> ThreatConfidence {
    match value {
        AneConfidence::Confirmed => ThreatConfidence::Confirmed,
        AneConfidence::High => ThreatConfidence::High,
        AneConfidence::Medium => ThreatConfidence::Medium,
        AneConfidence::Low => ThreatConfidence::Low,
    }
}

fn native_risk_verdict(value: AneVerdict) -> RiskVerdict {
    match value {
        AneVerdict::Clean => RiskVerdict::Clean,
        AneVerdict::LikelyClean => RiskVerdict::LikelyClean,
        AneVerdict::Unknown | AneVerdict::Observation => RiskVerdict::Unknown,
        AneVerdict::Suspicious => RiskVerdict::Suspicious,
        AneVerdict::ProbableMalware => RiskVerdict::ProbableMalware,
        AneVerdict::ConfirmedMalware | AneVerdict::TestThreat => RiskVerdict::ConfirmedMalware,
    }
}

fn native_category(value: AneThreatCategory) -> ThreatCategory {
    match value {
        AneThreatCategory::Trojan => ThreatCategory::Trojan,
        AneThreatCategory::Ransomware => ThreatCategory::Ransomware,
        AneThreatCategory::Spyware => ThreatCategory::Spyware,
        AneThreatCategory::Adware => ThreatCategory::Adware,
        AneThreatCategory::Worm => ThreatCategory::Worm,
        AneThreatCategory::Keylogger => ThreatCategory::Keylogger,
        AneThreatCategory::Miner => ThreatCategory::Miner,
        AneThreatCategory::PotentiallyUnwantedApp => ThreatCategory::PotentiallyUnwantedApp,
        _ => ThreatCategory::Unknown,
    }
}

fn native_threat_name(value: AneVerdict) -> String {
    match value {
        AneVerdict::TestThreat => "EICAR safe anti-malware test file".to_string(),
        AneVerdict::ConfirmedMalware => "Confirmed threat".to_string(),
        AneVerdict::ProbableMalware => "Probable malware".to_string(),
        AneVerdict::Suspicious => "Suspicious item".to_string(),
        AneVerdict::Observation => "Low-priority observation".to_string(),
        _ => "Native engine review".to_string(),
    }
}

fn native_engine_source(source: &zentor_native_engine::verdict::risk_fusion::EvidenceSource) -> RiskEngine {
    match source {
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeSignature => {
            RiskEngine::Signature
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeRule
        | zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeHeuristic
        | zentor_native_engine::verdict::risk_fusion::EvidenceSource::ApplicationControl
        | zentor_native_engine::verdict::risk_fusion::EvidenceSource::TrustStore => {
            RiskEngine::Heuristic
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeMl => RiskEngine::LocalAi,
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeBehavior => {
            RiskEngine::Behavior
        }
    }
}

fn native_reason_source(
    source: &zentor_native_engine::verdict::risk_fusion::EvidenceSource,
) -> RiskReasonSource {
    match source {
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeSignature => {
            RiskReasonSource::Signature
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeMl => {
            RiskReasonSource::AiModel
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::NativeBehavior => {
            RiskReasonSource::Behavior
        }
        zentor_native_engine::verdict::risk_fusion::EvidenceSource::TrustStore => {
            RiskReasonSource::UserLabel
        }
        _ => RiskReasonSource::Heuristic,
    }
}

fn threat_from_signature(path: &Path, result: &scanner::ScanResult) -> ThreatResult {
    let metadata = std::fs::metadata(path).ok();
    ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default(),
        sha256: result.sha256.clone(),
        size_bytes: metadata.map(|metadata| metadata.len()).unwrap_or_default(),
        detection_type: DetectionType::Signature,
        threat_category: ThreatCategory::Unknown,
        threat_name: result
            .threat_name
            .clone()
            .unwrap_or_else(|| "Known malware signature".to_string()),
        confidence: ThreatConfidence::Confirmed,
        engine: result.engine.clone(),
        detected_at: result.scanned_at,
        recommended_action: RecommendedAction::Quarantine,
        status: ThreatResultStatus::Detected,
        risk_score: RiskScore {
            score: 100,
            verdict: RiskVerdict::ConfirmedMalware,
            confidence: ThreatConfidence::Confirmed,
            reasons: vec![RiskReason {
                id: "signature_match".to_string(),
                title: "Known malware signature".to_string(),
                detail: "The local signature engine matched this file.".to_string(),
                weight: 100,
                severity: RiskSeverity::Critical,
                source: RiskReasonSource::Signature,
            }],
            recommended_action: RecommendedAction::Quarantine,
            engines_used: vec![RiskEngine::Signature],
        },
        reason_summary: "Known malware signature matched by the local engine.".to_string(),
    }
}

fn threat_from_ai(path: &Path, result: &ai::model_runner::LocalAiResult) -> ThreatResult {
    let metadata = std::fs::metadata(path).ok();
    let confidence = match result.confidence.as_str() {
        "confirmed" => ThreatConfidence::Confirmed,
        "high" => ThreatConfidence::High,
        "medium" => ThreatConfidence::Medium,
        _ => ThreatConfidence::Low,
    };
    let verdict = match result.verdict {
        ai::verdict::LocalAiVerdictLabel::ConfirmedMalware => RiskVerdict::ConfirmedMalware,
        ai::verdict::LocalAiVerdictLabel::ProbableMalware => RiskVerdict::ProbableMalware,
        ai::verdict::LocalAiVerdictLabel::Suspicious => RiskVerdict::Suspicious,
        ai::verdict::LocalAiVerdictLabel::Unknown => RiskVerdict::Unknown,
        ai::verdict::LocalAiVerdictLabel::LikelyClean => RiskVerdict::LikelyClean,
        ai::verdict::LocalAiVerdictLabel::Clean => RiskVerdict::Clean,
    };
    let category = category_from_ai(&result.top_category);
    let threat_name = match verdict {
        RiskVerdict::ProbableMalware => category_label(&category).to_string(),
        RiskVerdict::ConfirmedMalware => "Confirmed threat".to_string(),
        _ => "AI review suggested".to_string(),
    };
    let score = (result.malware_probability * 100.0)
        .round()
        .clamp(0.0, 100.0) as u8;
    let reason_detail = result.explanation_reasons.join(" ");
    ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default(),
        sha256: sha256_for_file(path).unwrap_or_default(),
        size_bytes: metadata.map(|metadata| metadata.len()).unwrap_or_default(),
        detection_type: DetectionType::LocalAi,
        threat_category: category,
        threat_name,
        confidence: confidence.clone(),
        engine: format!("zentor-local-ai/{}", result.model_version),
        detected_at: Utc::now(),
        recommended_action: if result.production_ready
            && matches!(
                verdict,
                RiskVerdict::ProbableMalware | RiskVerdict::ConfirmedMalware
            ) {
            RecommendedAction::Quarantine
        } else {
            RecommendedAction::Review
        },
        status: ThreatResultStatus::Detected,
        risk_score: RiskScore {
            score,
            verdict,
            confidence,
            reasons: vec![RiskReason {
                id: "local_ai_static_model".to_string(),
                title: "Local AI static analysis".to_string(),
                detail: if result.production_ready {
                    reason_detail
                } else {
                    format!("{reason_detail} Development model only; review result manually.")
                },
                weight: score as i32,
                severity: if score >= 90 {
                    RiskSeverity::High
                } else {
                    RiskSeverity::Medium
                },
                source: RiskReasonSource::AiModel,
            }],
            recommended_action: RecommendedAction::Review,
            engines_used: vec![RiskEngine::LocalAi],
        },
        reason_summary: format!(
            "Local AI probability {:.1}%. {}",
            result.malware_probability * 100.0,
            result.explanation_reasons.join(" ")
        ),
    }
}

fn category_from_ai(category: &str) -> ThreatCategory {
    match category {
        "trojan" => ThreatCategory::Trojan,
        "ransomware" => ThreatCategory::Ransomware,
        "spyware" => ThreatCategory::Spyware,
        "adware" => ThreatCategory::Adware,
        "worm" => ThreatCategory::Worm,
        "keylogger" => ThreatCategory::Keylogger,
        "miner" => ThreatCategory::Miner,
        "potentially_unwanted_app" => ThreatCategory::PotentiallyUnwantedApp,
        _ => ThreatCategory::Unknown,
    }
}

fn category_label(category: &ThreatCategory) -> &'static str {
    match category {
        ThreatCategory::Trojan => "Potential Trojan",
        ThreatCategory::Ransomware => "Potential Ransomware",
        ThreatCategory::Spyware => "Potential Spyware",
        ThreatCategory::Adware => "Potential Adware",
        ThreatCategory::Worm => "Potential Worm",
        ThreatCategory::Keylogger => "Potential Keylogger",
        ThreatCategory::Miner => "Potential Miner",
        ThreatCategory::PotentiallyUnwantedApp => "Potentially Unwanted App",
        ThreatCategory::Unknown => "Unknown Suspicious File",
    }
}

fn parse_action_mode(raw: Option<&str>) -> ScanActionMode {
    match raw {
        Some("autoQuarantine") | Some("auto_quarantine") | Some("autoQuarantineConfirmedOnly") => {
            ScanActionMode::AutoQuarantineConfirmedOnly
        }
        Some("autoQuarantineAllDetections") => ScanActionMode::AutoQuarantineAllDetections,
        _ => ScanActionMode::DetectOnly,
    }
}

fn parse_scan_kind(raw: Option<&str>) -> ScanKind {
    match raw {
        Some("quick") => ScanKind::Quick,
        Some("full") => ScanKind::Full,
        _ => ScanKind::Custom,
    }
}

fn sha256_for_file(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use app_control::known_good_store::KnownGoodStore;
    use app_control::publisher_trust::TrustedPublisherPolicy;
    use app_control::trust_store::is_dangerous_allowlist_path;
    use app_control::user_approval::UserApprovalStore;
    use app_control::{
        ApplicationControlDecision, ApplicationControlInput, ApplicationControlPolicy,
        ApplicationTrustLevel, ProtectionMode,
    };
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn detect_only_mode_hides_weak_suspicious_filename_observation() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("invoice.pdf.exe");
        fs::write(&file, b"not malware, just a suspicious filename").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::DetectOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::Clean);
        assert_eq!(report.threats_found, 0);
        assert!(file.exists());
        assert!(report.threats.is_empty());
    }

    #[test]
    fn auto_quarantine_confirmed_only_suppresses_heuristic_only_medium_confidence() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("invoice.pdf.exe");
        fs::write(&file, b"not malware, just a suspicious filename").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.threats_found, 0);
        assert_eq!(report.quarantined_files, 0);
        assert!(file.exists());
        assert!(report.threats.is_empty());
    }

    #[test]
    fn local_ai_unavailable_does_not_mark_file_clean() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        fs::write(&file, b"developer tool").unwrap();
        let runner = ai::ModelRunner::default();

        assert_eq!(runner.status(), "developmentModel");
        let result = runner.classify_file(&file).unwrap().unwrap();
        assert!(!result.production_ready);
        assert_ne!(
            result.verdict,
            ai::verdict::LocalAiVerdictLabel::ConfirmedMalware
        );
    }

    #[test]
    fn full_scan_handles_inaccessible_or_missing_roots_as_skipped() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");

        let report = scan_paths(
            vec![missing],
            ScanActionMode::DetectOnly,
            ScanKind::Full,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::CompletedWithErrors);
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.skipped_files, 1);
    }

    #[test]
    fn safe_eicar_simulator_is_detected_and_auto_quarantined_by_confirmed_mode() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("safe-eicar.com");
        fs::write(&file, "ZENTOR-SAFE-EICAR-SIMULATOR-FILE").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineConfirmedOnly,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::ThreatsFound);
        assert!(report.threats.iter().any(|threat| {
            threat.confidence == ThreatConfidence::Confirmed
                && matches!(
                    threat.status,
                    ThreatResultStatus::Quarantined | ThreatResultStatus::Detected
                )
        }));
        assert!(report.quarantined_files >= 1);
        assert!(!file.exists());
    }

    #[test]
    fn normal_exe_is_not_confirmed_threat() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("vpn-installer.exe");
        fs::write(&file, "normal installer").unwrap();

        let report = scan_paths(
            vec![file.clone()],
            ScanActionMode::AutoQuarantineAllDetections,
            ScanKind::Custom,
            None,
        )
        .unwrap();

        assert!(file.exists());
        assert!(report
            .threats
            .iter()
            .all(|threat| threat.confidence != ThreatConfidence::Confirmed));
        assert_eq!(report.quarantined_files, 0);
    }

    #[test]
    fn balanced_allows_unknown_benign_executable_with_monitoring() {
        let input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\tool.exe");
        let policy = ApplicationControlPolicy::new(ProtectionMode::Balanced);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::AllowAndMonitor);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Unknown);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn lockdown_blocks_unknown_unsigned_executable_without_malware_label() {
        let input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\vpn.exe");
        let policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Unknown);
        assert!(result.requires_user_approval);
        assert!(!result.label_as_malware);
    }

    #[test]
    fn lockdown_allows_known_good_hash() {
        let mut input = ApplicationControlInput::for_path("C:\\Tools\\trusted.exe");
        input.sha256 = Some("sha256:abc123".to_string());
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.known_good = KnownGoodStore::from_hashes(["abc123".to_string()]);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Allow);
        assert_eq!(result.trust_level, ApplicationTrustLevel::KnownGoodHash);
    }

    #[test]
    fn lockdown_allows_trusted_publisher_signature() {
        let mut input = ApplicationControlInput::for_path("C:\\Program Files\\Vendor\\app.exe");
        input.signature_valid = true;
        input.publisher = Some("Contoso Trusted Apps".to_string());
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.trusted_publishers =
            TrustedPublisherPolicy::with_trusted(["contoso trusted apps".to_string()]);

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Allow);
        assert_eq!(result.trust_level, ApplicationTrustLevel::TrustedPublisher);
    }

    #[test]
    fn lockdown_allows_exact_hash_after_user_approval() {
        let mut input = ApplicationControlInput::for_path("C:\\Users\\Brent\\Downloads\\cli.exe");
        input.sha256 = Some("sha256:def456".to_string());
        let mut approvals = UserApprovalStore::default();
        approvals.approve_hash("def456".to_string());
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.user_approvals = approvals;

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Allow);
        assert_eq!(result.trust_level, ApplicationTrustLevel::UserApproved);
    }

    #[test]
    fn dangerous_root_allowlist_paths_are_blocked() {
        assert!(is_dangerous_allowlist_path(Path::new("C:\\")));
        assert!(is_dangerous_allowlist_path(Path::new("C:\\Windows")));
        assert!(is_dangerous_allowlist_path(Path::new("/")));
        assert!(is_dangerous_allowlist_path(Path::new("/usr")));
        assert!(!is_dangerous_allowlist_path(Path::new(
            "C:\\Users\\Brent\\Downloads\\trusted.exe"
        )));
    }
}
