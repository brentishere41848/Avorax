use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::Context;
use chrono::Utc;
use uuid::Uuid;
use zentor_native_engine::trust::zentor_trust;

use super::clamav_provider::sha256_file;
use super::{
    DetectionType, RecommendedAction, RiskEngine, RiskReason, RiskReasonSource, RiskScore,
    RiskSeverity, RiskVerdict, ThreatCategory, ThreatConfidence, ThreatResult, ThreatResultStatus,
};

const HEURISTIC_SCRIPT_SAMPLE_BYTES: u64 = 1_048_576;
const HEURISTIC_ENTROPY_SAMPLE_BYTES: u64 = 1_048_576;
const HEURISTIC_MIN_ENTROPY_BYTES: u64 = 128 * 1024;

pub struct HeuristicProvider;

impl HeuristicProvider {
    pub fn inspect_file(&self, path: &Path) -> anyhow::Result<Option<ThreatResult>> {
        let metadata = inspect_regular_heuristic_target(path)?;
        let risk = self.score_file(path)?;
        if !should_surface_result(&risk) {
            return Ok(None);
        }

        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("heuristic target has no file name"))?
            .to_string_lossy()
            .to_string();
        let category = category_for_risk(&risk);
        let threat_name = match risk.verdict {
            RiskVerdict::ProbableMalware => category.label().to_string(),
            RiskVerdict::Suspicious => "Suspicious file".to_string(),
            _ => "Review suggested".to_string(),
        };
        let reason_summary = summarize_reasons(&risk.reasons);
        Ok(Some(ThreatResult {
            id: Uuid::new_v4().to_string(),
            path: path.display().to_string(),
            file_name,
            sha256: sha256_file(path)?,
            size_bytes: metadata.len(),
            detection_type: DetectionType::Heuristic,
            threat_category: category,
            threat_name,
            confidence: risk.confidence.clone(),
            engine: "zentor-risk-heuristic".to_string(),
            detected_at: Utc::now(),
            recommended_action: risk.recommended_action.clone(),
            status: ThreatResultStatus::Detected,
            quarantine_id: None,
            quarantine_path: None,
            quarantine_action_taken: None,
            risk_score: risk,
            reason_summary,
        }))
    }

    pub fn score_file(&self, path: &Path) -> anyhow::Result<RiskScore> {
        let _metadata = inspect_regular_heuristic_target(path)?;

        let file_name = heuristic_signal_file_name(path);
        let lower = file_name.to_lowercase();
        let path_lower = path.display().to_string().to_lowercase();
        let mut reasons = Vec::new();

        if is_zentor_trusted_artifact(path)? {
            return Ok(RiskScore {
                score: 0,
                verdict: RiskVerdict::LikelyClean,
                confidence: ThreatConfidence::Low,
                reasons: vec![reason(
                    "zentor_trusted_artifact",
                    "Avorax trusted artifact",
                    "Avorax installer, service, driver, quarantine, update, and build artifacts are suppressed unless a confirmed known-bad signature matches.",
                    -90,
                    RiskSeverity::Info,
                    RiskReasonSource::UserLabel,
                )],
                recommended_action: RecommendedAction::Review,
                engines_used: vec![RiskEngine::Heuristic],
            });
        }

        if is_executable_name(&lower) && path_lower.contains("download") {
            reasons.push(reason(
                "exe_downloads",
                "Executable in Downloads",
                "Executable files in Downloads are common for legitimate installers and only add a small informational signal.",
                5,
                RiskSeverity::Info,
                RiskReasonSource::StaticFeature,
            ));
        }

        if is_executable_name(&lower)
            && is_temp_location(&path_lower)
            && !path_lower.contains("download")
        {
            reasons.push(reason(
                "exe_temp",
                "Executable in temporary folder",
                "Executables launched from temporary folders are worth review, but this is not enough by itself.",
                10,
                RiskSeverity::Low,
                RiskReasonSource::StaticFeature,
            ));
        }

        if suspicious_double_extension(&lower) {
            reasons.push(reason(
                "double_extension",
                "Suspicious double extension",
                "The name looks like a document but ends with an executable or script extension.",
                25,
                RiskSeverity::Medium,
                RiskReasonSource::Heuristic,
            ));
        }

        if startup_executable(&lower, &path_lower) {
            reasons.push(reason(
                "startup_executable",
                "Executable in startup location",
                "Software in startup folders can run automatically. This needs context before action.",
                25,
                RiskSeverity::Medium,
                RiskReasonSource::Heuristic,
            ));
        }

        if looks_randomish(&lower)
            && (path_lower.contains("download") || is_temp_location(&path_lower))
        {
            reasons.push(reason(
                "random_name_risky_location",
                "Random-looking executable name",
                "The filename has a random-looking pattern in a risky location.",
                15,
                RiskSeverity::Low,
                RiskReasonSource::Heuristic,
            ));
        }

        if script_has_obfuscated_powershell(path, &lower)? {
            reasons.push(reason(
                "obfuscated_script",
                "Obfuscated script content",
                "The script contains patterns commonly used to hide PowerShell commands.",
                35,
                RiskSeverity::High,
                RiskReasonSource::Heuristic,
            ));
        }

        if likely_packed_or_high_entropy(path, &lower)? {
            reasons.push(reason(
                "high_entropy",
                "Packed or high-entropy content",
                "The file contains high-entropy bytes that can indicate packing. This only matters when combined with other signals.",
                20,
                RiskSeverity::Medium,
                RiskReasonSource::StaticFeature,
            ));
        }

        let engines = if reasons.is_empty() {
            Vec::new()
        } else {
            vec![RiskEngine::Heuristic]
        };
        Ok(score_from_reasons(reasons, engines))
    }
}

impl RiskScore {
    #[allow(dead_code)]
    pub fn clean(reasons: Vec<RiskReason>, engines_used: Vec<RiskEngine>) -> Self {
        Self {
            score: 0,
            verdict: RiskVerdict::Clean,
            confidence: ThreatConfidence::Low,
            reasons,
            recommended_action: RecommendedAction::Review,
            engines_used,
        }
    }
}

pub fn score_from_reasons(reasons: Vec<RiskReason>, engines_used: Vec<RiskEngine>) -> RiskScore {
    let score = reasons
        .iter()
        .map(|reason| reason.weight.max(0) as u16)
        .sum::<u16>()
        .min(100) as u8;
    let high_quality = high_quality_reason_count(&reasons);
    let independent_sources = independent_reason_source_count(&reasons);

    let verdict = if score == 0 {
        RiskVerdict::Clean
    } else if score < 35 {
        RiskVerdict::LikelyClean
    } else if score < 60 {
        RiskVerdict::Unknown
    } else if score < 85 || high_quality < 2 || independent_sources < 2 {
        RiskVerdict::Suspicious
    } else {
        RiskVerdict::ProbableMalware
    };

    let confidence = if score >= 85 && high_quality >= 3 && independent_sources >= 2 {
        ThreatConfidence::High
    } else if score >= 45 {
        ThreatConfidence::Medium
    } else {
        ThreatConfidence::Low
    };

    let recommended_action = match verdict {
        RiskVerdict::ProbableMalware => RecommendedAction::Quarantine,
        RiskVerdict::Suspicious | RiskVerdict::Unknown => RecommendedAction::Review,
        RiskVerdict::Clean | RiskVerdict::LikelyClean => RecommendedAction::Review,
        RiskVerdict::ConfirmedMalware => RecommendedAction::Quarantine,
    };

    RiskScore {
        score,
        verdict,
        confidence,
        reasons,
        recommended_action,
        engines_used,
    }
}

fn high_quality_reason_count(reasons: &[RiskReason]) -> usize {
    reasons
        .iter()
        .filter(|reason| {
            matches!(
                reason.severity,
                RiskSeverity::Medium | RiskSeverity::High | RiskSeverity::Critical
            )
        })
        .count()
}

fn independent_reason_source_count(reasons: &[RiskReason]) -> usize {
    reasons
        .iter()
        .map(|reason| format!("{:?}", reason.source))
        .collect::<HashSet<_>>()
        .len()
}

pub fn eligible_for_heuristic_auto_quarantine(risk: &RiskScore, allowlisted: bool) -> bool {
    if allowlisted || risk.verdict != RiskVerdict::ProbableMalware {
        return false;
    }

    risk.score >= 85
        && risk.confidence == ThreatConfidence::High
        && risk.recommended_action == RecommendedAction::Quarantine
        && risk.engines_used.contains(&RiskEngine::Heuristic)
        && high_quality_reason_count(&risk.reasons) >= 3
        && independent_reason_source_count(&risk.reasons) >= 2
}

fn should_surface_result(risk: &RiskScore) -> bool {
    matches!(
        risk.verdict,
        RiskVerdict::Unknown | RiskVerdict::Suspicious | RiskVerdict::ProbableMalware
    ) && risk.score >= 35
}

fn reason(
    id: &str,
    title: &str,
    detail: &str,
    weight: i32,
    severity: RiskSeverity,
    source: RiskReasonSource,
) -> RiskReason {
    RiskReason {
        id: id.to_string(),
        title: title.to_string(),
        detail: detail.to_string(),
        weight,
        severity,
        source,
    }
}

fn summarize_reasons(reasons: &[RiskReason]) -> String {
    reasons
        .iter()
        .filter(|reason| reason.weight >= 15)
        .map(|reason| reason.title.clone())
        .take(3)
        .collect::<Vec<_>>()
        .join(", ")
}

fn category_for_risk(risk: &RiskScore) -> ThreatCategory {
    if risk
        .reasons
        .iter()
        .any(|reason| reason.id == "obfuscated_script")
    {
        ThreatCategory::Spyware
    } else if risk
        .reasons
        .iter()
        .any(|reason| reason.id == "startup_executable")
    {
        ThreatCategory::PotentiallyUnwantedApp
    } else {
        ThreatCategory::Unknown
    }
}

trait ThreatCategoryLabel {
    fn label(&self) -> &'static str;
}

impl ThreatCategoryLabel for ThreatCategory {
    fn label(&self) -> &'static str {
        match self {
            ThreatCategory::Trojan => "Possible Trojan",
            ThreatCategory::Ransomware => "Possible ransomware",
            ThreatCategory::Spyware => "Possible spyware",
            ThreatCategory::Infostealer => "Potential infostealer",
            ThreatCategory::Adware => "Potential adware",
            ThreatCategory::Worm => "Potential worm",
            ThreatCategory::Keylogger => "Potential keylogger",
            ThreatCategory::Miner => "Potential miner",
            ThreatCategory::RootkitIndicator => "Rootkit indicator",
            ThreatCategory::PotentiallyUnwantedApp => "Potentially unwanted app",
            ThreatCategory::SuspiciousDownloader => "Suspicious downloader",
            ThreatCategory::SuspiciousScript => "Suspicious script",
            ThreatCategory::MaliciousMacro => "Malicious macro indicator",
            ThreatCategory::ExploitDropper => "Exploit dropper indicator",
            ThreatCategory::CredentialTheftIndicator => "Credential theft indicator",
            ThreatCategory::PersistenceIndicator => "Persistence indicator",
            ThreatCategory::SecurityTamperIndicator => "Security tamper indicator",
            ThreatCategory::Unknown => "Possible malware",
        }
    }
}

fn suspicious_double_extension(lower: &str) -> bool {
    let document_exts = [
        ".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".jpg.", ".png.",
    ];
    let executable_exts = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"];
    document_exts.iter().any(|ext| lower.contains(ext))
        && executable_exts.iter().any(|ext| lower.ends_with(ext))
}

fn is_executable_name(lower: &str) -> bool {
    [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".sh",
        ".appimage",
        ".msi",
        ".dll",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}

fn is_temp_location(path_lower: &str) -> bool {
    path_lower.contains("\\temp\\")
        || path_lower.contains("/tmp/")
        || path_lower.ends_with("\\temp")
        || path_lower.ends_with("/tmp")
}

fn startup_executable(lower: &str, path_lower: &str) -> bool {
    is_executable_name(lower)
        && (path_lower.contains("startup") || path_lower.contains("autostart"))
}

fn script_has_obfuscated_powershell(path: &Path, lower: &str) -> anyhow::Result<bool> {
    if !(lower.ends_with(".ps1") || lower.ends_with(".bat") || lower.ends_with(".cmd")) {
        return Ok(false);
    }
    let body = read_bounded_sample(path, HEURISTIC_SCRIPT_SAMPLE_BYTES)
        .with_context(|| format!("unable to read heuristic script sample {}", path.display()))?;
    let lower_body = String::from_utf8_lossy(&body).to_lowercase();
    Ok(lower_body.contains("frombase64string")
        || lower_body.contains("-enc ")
        || lower_body.contains("iex")
        || lower_body.contains("invoke-expression"))
}

fn likely_packed_or_high_entropy(path: &Path, lower: &str) -> anyhow::Result<bool> {
    if !is_executable_name(lower) {
        return Ok(false);
    }
    let metadata = inspect_regular_heuristic_target(path).with_context(|| {
        format!(
            "unable to inspect heuristic entropy target {}",
            path.display()
        )
    })?;
    if metadata.len() < HEURISTIC_MIN_ENTROPY_BYTES {
        return Ok(false);
    }
    let sample = read_bounded_sample(path, HEURISTIC_ENTROPY_SAMPLE_BYTES)
        .with_context(|| format!("unable to read heuristic entropy sample {}", path.display()))?;
    Ok(entropy(&sample) >= 7.6)
}

fn read_bounded_sample(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    inspect_regular_heuristic_target(path)?;
    let mut reader = fs::File::open(path)?;
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
    Ok(body)
}

fn inspect_regular_heuristic_target(path: &Path) -> anyhow::Result<std::fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect heuristic target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to inspect symbolic link heuristic target: {}",
            path.display()
        );
    }
    if heuristic_metadata_is_windows_reparse_point(&metadata) {
        anyhow::bail!(
            "refusing to inspect reparse point heuristic target: {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!(
            "heuristic scan target is not a regular file: {}",
            path.display()
        );
    }
    Ok(metadata)
}

#[cfg(windows)]
fn heuristic_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn heuristic_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn is_zentor_trusted_artifact(path: &Path) -> anyhow::Result<bool> {
    zentor_trust::is_zentor_path(path)
}

fn heuristic_signal_file_name(path: &Path) -> String {
    match heuristic_signal_leaf_name(path) {
        Some(value) => value,
        None => display_path_or_unknown(path),
    }
}

fn heuristic_signal_leaf_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.trim().is_empty())
}

fn display_path_or_unknown(path: &Path) -> String {
    let display = path.display().to_string();
    if display.trim().is_empty() {
        "<unknown-path>".to_string()
    } else {
        display
    }
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_randomish(name: &str) -> bool {
    let stem = first_filename_stem_or_name(name);
    if stem.len() < 8 {
        return false;
    }
    if !stem.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let digits = stem.chars().filter(|c| c.is_ascii_digit()).count();
    let letters = stem.chars().filter(|c| c.is_ascii_alphabetic()).count();
    digits >= 3 && letters >= 3
}

fn first_filename_stem_or_name(name: &str) -> &str {
    match name.split('.').next() {
        Some(stem) => stem,
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn executable_in_downloads_alone_is_not_a_threat() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("expressvpn-windows-x64.exe");
        fs::write(&file, b"normal installer").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).unwrap().is_none());
        let score = HeuristicProvider.score_file(&file).unwrap();
        assert_eq!(score.score, 5);
        assert_eq!(score.verdict, RiskVerdict::LikelyClean);
    }

    #[test]
    fn unsigned_or_unknown_executable_alone_is_not_a_threat() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("sentry-cli.exe");
        fs::write(&file, b"developer tool").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).unwrap().is_none());
    }

    #[test]
    fn heuristic_inspection_reports_non_file_targets_as_errors() {
        let dir = tempdir().unwrap();

        let error = HeuristicProvider
            .inspect_file(dir.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn heuristic_inspection_rejects_symbolic_link_targets() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.ps1");
        let link = dir.path().join("linked.ps1");
        fs::write(&target, b"powershell -enc AAAA").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        let score_error = HeuristicProvider.score_file(&link).unwrap_err().to_string();
        let sample_error = read_bounded_sample(&link, HEURISTIC_SCRIPT_SAMPLE_BYTES)
            .unwrap_err()
            .to_string();

        assert!(score_error.contains("symbolic link"));
        assert!(sample_error.contains("symbolic link"));
    }

    #[test]
    fn heuristic_inspection_uses_non_following_target_metadata() {
        let source = include_str!("heuristic_provider.rs");
        let helper_pattern = ["fn inspect_regular_", "heuristic_target"].concat();
        let helper_call_pattern = ["inspect_regular_", "heuristic_target(path)?"].concat();
        let symlink_metadata_pattern = ["fs::", "symlink_metadata(path)"].concat();
        let symlink_error_pattern =
            ["refusing to inspect symbolic link ", "heuristic target"].concat();
        let reparse_error_pattern =
            ["refusing to inspect reparse point ", "heuristic target"].concat();
        let old_metadata_pattern = ["fs::", "metadata(path)"].concat();

        assert!(source.contains(&helper_pattern));
        assert!(source.contains(&helper_call_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&symlink_error_pattern));
        assert!(source.contains(&reparse_error_pattern));
        assert!(!source.contains(&old_metadata_pattern));
    }

    #[test]
    fn heuristic_sample_errors_are_propagated_not_false_signals() {
        let source = include_str!("heuristic_provider.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;

        assert!(production_source.contains(
            "fn script_has_obfuscated_powershell(path: &Path, lower: &str) -> anyhow::Result<bool>"
        ));
        assert!(production_source.contains(
            "fn likely_packed_or_high_entropy(path: &Path, lower: &str) -> anyhow::Result<bool>"
        ));
        assert!(production_source.contains("unable to read heuristic script sample"));
        assert!(production_source.contains("unable to read heuristic entropy sample"));
        assert!(production_source.contains("unable to inspect heuristic entropy target"));
        assert!(!production_source.contains("let Ok(body) = read_bounded_sample"));
        assert!(!production_source.contains("let Ok(metadata) = inspect_regular_heuristic_target"));
        assert!(!production_source.contains("let Ok(sample) = read_bounded_sample"));
    }

    #[test]
    fn avorax_installer_name_is_not_trusted_by_heuristics() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("Avorax-AntiVirus-0.2.2-x64-setup.exe");
        fs::write(&file, b"avorax installer fixture").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).unwrap().is_none());
        let score = HeuristicProvider.score_file(&file).unwrap();
        assert_eq!(score.verdict, RiskVerdict::LikelyClean);
        assert!(score
            .reasons
            .iter()
            .all(|reason| reason.id != "zentor_trusted_artifact"));
        assert_ne!(score.recommended_action, RecommendedAction::Quarantine);
    }

    #[test]
    fn avorax_msi_name_is_not_trusted_by_heuristics() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("Avorax-AntiVirus-0.2.2-x64.msi");
        fs::write(&file, b"avorax msi fixture").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).unwrap().is_none());
        let score = HeuristicProvider.score_file(&file).unwrap();
        assert_eq!(score.verdict, RiskVerdict::LikelyClean);
        assert!(score
            .reasons
            .iter()
            .all(|reason| reason.id != "zentor_trusted_artifact"));
        assert_ne!(score.recommended_action, RecommendedAction::Quarantine);
    }

    #[test]
    fn setup_exe_in_downloads_is_not_probable_or_confirmed() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("setup.exe");
        fs::write(&file, b"normal setup fixture").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).unwrap().is_none());
        let score = HeuristicProvider.score_file(&file).unwrap();
        assert_eq!(score.verdict, RiskVerdict::LikelyClean);
        assert_ne!(score.recommended_action, RecommendedAction::Quarantine);
    }

    #[test]
    fn repo_lookalike_paths_are_not_trusted_by_heuristics() {
        let dir = tempdir().unwrap();
        let internal = dir
            .path()
            .join("core")
            .join("zentor_native_engine")
            .join("Startup");
        fs::create_dir_all(&internal).unwrap();
        let file = internal.join("invoice.pdf.ps1");
        fs::write(&file, b"powershell -enc AAAA").unwrap();

        let result = HeuristicProvider.inspect_file(&file).unwrap().unwrap();
        assert_eq!(result.risk_score.verdict, RiskVerdict::ProbableMalware);
        assert!(result
            .risk_score
            .reasons
            .iter()
            .all(|reason| reason.id != "zentor_trusted_artifact"));
    }

    #[test]
    fn product_path_trust_errors_are_propagated_by_heuristics() {
        let source = include_str!("heuristic_provider.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;

        assert!(production_source.contains("if is_zentor_trusted_artifact(path)?"));
        assert!(production_source
            .contains("fn is_zentor_trusted_artifact(path: &Path) -> anyhow::Result<bool>"));
        assert!(production_source.contains("zentor_trust::is_zentor_path(path)"));
    }

    #[test]
    fn double_extension_increases_score_without_confirming_malware() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("invoice.pdf.exe");
        fs::write(&file, b"test").unwrap();
        let result = HeuristicProvider.inspect_file(&file).unwrap().unwrap();
        assert!(result.risk_score.score >= 25);
        assert_eq!(result.risk_score.verdict, RiskVerdict::Unknown);
        assert_ne!(result.confidence, ThreatConfidence::Confirmed);
    }

    #[test]
    fn multiple_suspicious_signals_produce_suspicious_verdict() {
        let dir = tempdir().unwrap();
        let startup = dir.path().join("Startup");
        fs::create_dir_all(&startup).unwrap();
        let file = startup.join("invoice.pdf.ps1");
        fs::write(&file, b"powershell -enc AAAA").unwrap();
        let result = HeuristicProvider.inspect_file(&file).unwrap().unwrap();
        assert!(result.risk_score.score >= 85);
        assert_eq!(result.risk_score.verdict, RiskVerdict::ProbableMalware);
    }

    #[test]
    fn heuristic_auto_quarantine_requires_probable_verdict_and_independent_sources() {
        let base_reasons = vec![
            reason(
                "double_extension",
                "Suspicious double extension",
                "fixture",
                30,
                RiskSeverity::Medium,
                RiskReasonSource::Heuristic,
            ),
            reason(
                "obfuscated_script",
                "Obfuscated script content",
                "fixture",
                35,
                RiskSeverity::High,
                RiskReasonSource::Heuristic,
            ),
            reason(
                "high_entropy",
                "Packed or high-entropy content",
                "fixture",
                25,
                RiskSeverity::Medium,
                RiskReasonSource::StaticFeature,
            ),
        ];
        let risk = RiskScore {
            score: 90,
            verdict: RiskVerdict::ProbableMalware,
            confidence: ThreatConfidence::High,
            reasons: base_reasons,
            recommended_action: RecommendedAction::Quarantine,
            engines_used: vec![RiskEngine::Heuristic],
        };

        assert!(eligible_for_heuristic_auto_quarantine(&risk, false));
        assert!(!eligible_for_heuristic_auto_quarantine(&risk, true));

        let mut suspicious = risk.clone();
        suspicious.verdict = RiskVerdict::Suspicious;
        assert!(!eligible_for_heuristic_auto_quarantine(&suspicious, false));

        let mut confirmed = risk.clone();
        confirmed.verdict = RiskVerdict::ConfirmedMalware;
        assert!(!eligible_for_heuristic_auto_quarantine(&confirmed, false));

        let mut review_only = risk.clone();
        review_only.recommended_action = RecommendedAction::Review;
        assert!(!eligible_for_heuristic_auto_quarantine(&review_only, false));

        let mut no_engine_evidence = risk.clone();
        no_engine_evidence.engines_used = Vec::new();
        assert!(!eligible_for_heuristic_auto_quarantine(
            &no_engine_evidence,
            false
        ));

        let mut single_source = risk;
        for reason in &mut single_source.reasons {
            reason.source = RiskReasonSource::Heuristic;
        }
        assert!(!eligible_for_heuristic_auto_quarantine(
            &single_source,
            false
        ));
    }

    #[test]
    fn obfuscated_script_detection_uses_bounded_sample() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("late.ps1");
        let mut body = vec![b'A'; HEURISTIC_SCRIPT_SAMPLE_BYTES as usize + 16];
        body.extend_from_slice(b" FromBase64String ");
        fs::write(&file, body).unwrap();

        let score = HeuristicProvider.score_file(&file).unwrap();

        assert!(!score
            .reasons
            .iter()
            .any(|reason| reason.id == "obfuscated_script"));
    }

    #[test]
    fn entropy_detection_uses_bounded_sample() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("packed.exe");
        let mut body = vec![0_u8; HEURISTIC_ENTROPY_SAMPLE_BYTES as usize];
        body.extend((0..(128 * 1024)).map(|value| (value % 251) as u8));
        fs::write(&file, body).unwrap();

        let score = HeuristicProvider.score_file(&file).unwrap();

        assert!(!score
            .reasons
            .iter()
            .any(|reason| reason.id == "high_entropy"));
    }

    #[test]
    fn heuristic_signal_file_name_uses_leaf_or_path_fallback() {
        assert_eq!(
            heuristic_signal_file_name(Path::new("Invoice.PDF.EXE")),
            "Invoice.PDF.EXE"
        );
        assert_eq!(heuristic_signal_file_name(Path::new("/")), "/");
        assert_eq!(heuristic_signal_file_name(Path::new("")), "<unknown-path>");
    }

    #[test]
    fn heuristic_randomish_stem_default_is_explicit() {
        let source = include_str!("heuristic_provider.rs");
        let randomish_start = source.find("fn looks_randomish").unwrap();
        let tests_start = source.find("#[cfg(test)]").unwrap();
        let randomish_source = &source[randomish_start..tests_start];

        assert_eq!(first_filename_stem_or_name("abc.def"), "abc");
        assert_eq!(first_filename_stem_or_name("abcdef"), "abcdef");
        assert!(randomish_source.contains("let stem = first_filename_stem_or_name(name);"));
        assert!(randomish_source.contains("Some(stem) => stem"));
        assert!(randomish_source.contains("None => name"));
        assert!(!randomish_source.contains("unwrap_or(name)"));
    }

    #[test]
    fn heuristic_filename_signals_do_not_default_to_empty_strings() {
        let source = include_str!("heuristic_provider.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        let old_file_name_default = [
            ".file_name()",
            "\n            .map(|value| value.to_string_lossy().to_string())",
            "\n            .unwrap_or_default()",
        ]
        .concat();

        assert!(production_source.contains("let file_name = heuristic_signal_file_name(path);"));
        assert!(production_source.contains("fn heuristic_signal_file_name(path: &Path) -> String"));
        assert!(production_source
            .contains("fn heuristic_signal_leaf_name(path: &Path) -> Option<String>"));
        assert!(production_source.contains("Some(value) => value"));
        assert!(production_source.contains("None => display_path_or_unknown(path)"));
        assert!(!production_source.contains("unwrap_or_else(|| display_path_or_unknown(path))"));
        assert!(!production_source.contains(&old_file_name_default));
    }
}
