use std::collections::HashSet;
use std::fs;
use std::path::Path;

use chrono::Utc;
use uuid::Uuid;

use super::clamav_provider::sha256_file;
use super::{
    DetectionType, RecommendedAction, RiskEngine, RiskReason, RiskReasonSource, RiskScore,
    RiskSeverity, RiskVerdict, ThreatCategory, ThreatConfidence, ThreatResult, ThreatResultStatus,
};

pub struct HeuristicProvider;

impl HeuristicProvider {
    pub fn inspect_file(&self, path: &Path) -> Option<ThreatResult> {
        let risk = self.score_file(path).ok()?;
        if !should_surface_result(&risk) {
            return None;
        }

        let file_name = path.file_name()?.to_string_lossy().to_string();
        let metadata = fs::metadata(path).ok()?;
        let category = category_for_risk(&risk);
        let threat_name = match risk.verdict {
            RiskVerdict::ProbableMalware => category.label().to_string(),
            RiskVerdict::Suspicious => "Suspicious file".to_string(),
            _ => "Review suggested".to_string(),
        };
        let reason_summary = summarize_reasons(&risk.reasons);
        Some(ThreatResult {
            id: Uuid::new_v4().to_string(),
            path: path.display().to_string(),
            file_name,
            sha256: sha256_file(path).unwrap_or_default(),
            size_bytes: metadata.len(),
            detection_type: DetectionType::Heuristic,
            threat_category: category,
            threat_name,
            confidence: risk.confidence.clone(),
            engine: "zentor-risk-heuristic".to_string(),
            detected_at: Utc::now(),
            recommended_action: risk.recommended_action.clone(),
            status: ThreatResultStatus::Detected,
            risk_score: risk,
            reason_summary,
        })
    }

    pub fn score_file(&self, path: &Path) -> anyhow::Result<RiskScore> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Ok(RiskScore::clean(Vec::new(), Vec::new()));
        }

        let file_name = path
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();
        let lower = file_name.to_lowercase();
        let path_lower = path.display().to_string().to_lowercase();
        let mut reasons = Vec::new();

        if is_zentor_trusted_artifact(&lower, &path_lower) {
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

        if script_has_obfuscated_powershell(path, &lower) {
            reasons.push(reason(
                "obfuscated_script",
                "Obfuscated script content",
                "The script contains patterns commonly used to hide PowerShell commands.",
                35,
                RiskSeverity::High,
                RiskReasonSource::Heuristic,
            ));
        }

        if likely_packed_or_high_entropy(path, &lower) {
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
    let high_quality = reasons
        .iter()
        .filter(|reason| {
            matches!(
                reason.severity,
                RiskSeverity::Medium | RiskSeverity::High | RiskSeverity::Critical
            )
        })
        .count();
    let independent_sources = reasons
        .iter()
        .map(|reason| format!("{:?}", reason.source))
        .collect::<HashSet<_>>()
        .len();

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

pub fn eligible_for_heuristic_auto_quarantine(risk: &RiskScore, allowlisted: bool) -> bool {
    !allowlisted
        && risk.score >= 85
        && risk.confidence == ThreatConfidence::High
        && risk
            .reasons
            .iter()
            .filter(|reason| {
                matches!(
                    reason.severity,
                    RiskSeverity::Medium | RiskSeverity::High | RiskSeverity::Critical
                )
            })
            .count()
            >= 3
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
            ThreatCategory::Adware => "Potential adware",
            ThreatCategory::Worm => "Potential worm",
            ThreatCategory::Keylogger => "Potential keylogger",
            ThreatCategory::Miner => "Potential miner",
            ThreatCategory::PotentiallyUnwantedApp => "Potentially unwanted app",
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

fn script_has_obfuscated_powershell(path: &Path, lower: &str) -> bool {
    if !(lower.ends_with(".ps1") || lower.ends_with(".bat") || lower.ends_with(".cmd")) {
        return false;
    }
    let Ok(body) = fs::read_to_string(path) else {
        return false;
    };
    let lower_body = body.to_lowercase();
    lower_body.contains("frombase64string")
        || lower_body.contains("-enc ")
        || lower_body.contains("iex")
        || lower_body.contains("invoke-expression")
}

fn likely_packed_or_high_entropy(path: &Path, lower: &str) -> bool {
    if !is_executable_name(lower) {
        return false;
    }
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    if bytes.len() < 128 * 1024 {
        return false;
    }
    let sample = if bytes.len() > 1024 * 1024 {
        &bytes[..1024 * 1024]
    } else {
        &bytes
    };
    entropy(sample) >= 7.6
}

fn is_zentor_trusted_artifact(lower_name: &str, path_lower: &str) -> bool {
    (lower_name.starts_with("zentor-antivirus-")
        && (lower_name.ends_with("-setup.exe")
            || lower_name.ends_with("-x64.msi")
            || lower_name.ends_with(".msi")))
        || path_lower.contains("\\program files\\zentor\\")
        || path_lower.contains("\\programdata\\zentor\\")
        || path_lower.contains("\\zentor-quarantine\\")
        || path_lower.contains("\\zentor-native-quarantine\\")
        || path_lower.contains("\\apps\\zentor_client\\")
        || path_lower.contains("\\core\\zentor_")
        || path_lower.contains("\\assets\\zentor_native\\")
        || path_lower.contains("\\installer\\windows\\")
        || path_lower.contains("/apps/zentor_client/")
        || path_lower.contains("/core/zentor_")
        || path_lower.contains("/assets/zentor_native/")
        || path_lower.contains("/installer/windows/")
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
    let stem = name.split('.').next().unwrap_or(name);
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

        assert!(HeuristicProvider.inspect_file(&file).is_none());
        let score = HeuristicProvider.score_file(&file).unwrap();
        assert_eq!(score.score, 5);
        assert_eq!(score.verdict, RiskVerdict::LikelyClean);
    }

    #[test]
    fn unsigned_or_unknown_executable_alone_is_not_a_threat() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("sentry-cli.exe");
        fs::write(&file, b"developer tool").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).is_none());
    }

    #[test]
    fn zentor_installer_exe_is_suppressed() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("Avorax-AntiVirus-0.2.2-x64-setup.exe");
        fs::write(&file, b"zentor installer fixture").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).is_none());
        let score = HeuristicProvider.score_file(&file).unwrap();
        assert_eq!(score.verdict, RiskVerdict::LikelyClean);
        assert_ne!(score.recommended_action, RecommendedAction::Quarantine);
    }

    #[test]
    fn zentor_msi_is_suppressed() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("Avorax-AntiVirus-0.2.2-x64.msi");
        fs::write(&file, b"zentor msi fixture").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).is_none());
        let score = HeuristicProvider.score_file(&file).unwrap();
        assert_eq!(score.verdict, RiskVerdict::LikelyClean);
        assert_ne!(score.recommended_action, RecommendedAction::Quarantine);
    }

    #[test]
    fn setup_exe_in_downloads_is_not_probable_or_confirmed() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("setup.exe");
        fs::write(&file, b"normal setup fixture").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).is_none());
        let score = HeuristicProvider.score_file(&file).unwrap();
        assert_eq!(score.verdict, RiskVerdict::LikelyClean);
        assert_ne!(score.recommended_action, RecommendedAction::Quarantine);
    }

    #[test]
    fn zentor_internal_files_are_never_flagged_by_heuristics() {
        let dir = tempdir().unwrap();
        let internal = dir.path().join("core").join("zentor_native_engine");
        fs::create_dir_all(&internal).unwrap();
        let file = internal.join("zentor_local_core.exe");
        fs::write(&file, b"zentor internal fixture").unwrap();

        assert!(HeuristicProvider.inspect_file(&file).is_none());
        assert_eq!(
            HeuristicProvider.score_file(&file).unwrap().verdict,
            RiskVerdict::LikelyClean
        );
    }

    #[test]
    fn double_extension_increases_score_without_confirming_malware() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("invoice.pdf.exe");
        fs::write(&file, b"test").unwrap();
        let result = HeuristicProvider.inspect_file(&file).unwrap();
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
        let result = HeuristicProvider.inspect_file(&file).unwrap();
        assert!(result.risk_score.score >= 85);
        assert_eq!(result.risk_score.verdict, RiskVerdict::ProbableMalware);
    }
}
