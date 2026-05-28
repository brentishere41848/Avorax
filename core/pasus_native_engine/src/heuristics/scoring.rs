use std::path::Path;

use crate::analyzers::StaticAnalysis;
use crate::verdict::risk_fusion::{Evidence, EvidenceSource};

pub fn score_file(path: &Path, analysis: &StaticAnalysis) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let name_score = super::filename::filename_risk(path);
    if name_score >= 25 {
        evidence.push(Evidence {
            id: "filename_risk".to_string(),
            title: "Suspicious filename pattern".to_string(),
            detail: "The filename uses a deceptive extension or high-risk naming pattern.".to_string(),
            weight: name_score,
            source: EvidenceSource::NativeHeuristic,
        });
    } else if name_score > 0 {
        evidence.push(Evidence {
            id: "filename_observation".to_string(),
            title: "Filename observation".to_string(),
            detail: "The filename has a weak risk indicator; this is not enough to call it malware.".to_string(),
            weight: name_score.min(8),
            source: EvidenceSource::NativeHeuristic,
        });
    }
    let location_score = super::location::location_risk(path);
    if location_score > 0 {
        evidence.push(Evidence {
            id: "location_observation".to_string(),
            title: "Location observation".to_string(),
            detail: "The file is in a location often reviewed by quick scans. This signal is weak by itself.".to_string(),
            weight: location_score,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if analysis.entropy_max > 7.45 {
        evidence.push(Evidence {
            id: "high_entropy".to_string(),
            title: "High entropy content".to_string(),
            detail: "One or more regions look packed or encrypted. Pasus treats this as suspicious only with other signals.".to_string(),
            weight: 18,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if let Some(script) = &analysis.script {
        if script.encoded_command {
            evidence.push(Evidence {
                id: "encoded_script_command".to_string(),
                title: "Encoded script command".to_string(),
                detail: "The script contains encoded command indicators.".to_string(),
                weight: 20,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if script.downloader_patterns > 0 && script.execution_patterns > 0 {
            evidence.push(Evidence {
                id: "download_execute_script".to_string(),
                title: "Downloader plus execution script pattern".to_string(),
                detail: "The script combines download and execution behavior.".to_string(),
                weight: 35,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if script.security_tamper_indicators > 0 {
            evidence.push(Evidence {
                id: "security_tamper_script".to_string(),
                title: "Security tamper indicator".to_string(),
                detail: "The script references backup or security setting tamper commands.".to_string(),
                weight: 35,
                source: EvidenceSource::NativeHeuristic,
            });
        }
    }
    if let Some(pe) = &analysis.pe {
        let import_score = pe.suspicious_imports.process_injection * 12
            + pe.suspicious_imports.credential_access * 14
            + pe.suspicious_imports.persistence * 10
            + pe.suspicious_imports.anti_debugging * 8;
        if import_score > 0 {
            evidence.push(Evidence {
                id: "suspicious_imports".to_string(),
                title: "Suspicious import categories".to_string(),
                detail: "The executable imports APIs associated with injection, credential access, persistence, or anti-debugging.".to_string(),
                weight: import_score.min(45) as i32,
                source: EvidenceSource::NativeHeuristic,
            });
        }
    }
    if let Some(archive) = &analysis.archive {
        if archive.zip_slip_blocked {
            evidence.push(Evidence {
                id: "archive_zip_slip".to_string(),
                title: "Unsafe archive path blocked".to_string(),
                detail: "The archive contains path traversal entries.".to_string(),
                weight: 45,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if archive.contains_executable && archive.suspicious_nested_name_count > 0 {
            evidence.push(Evidence {
                id: "archive_suspicious_executable".to_string(),
                title: "Suspicious executable inside archive".to_string(),
                detail: "The archive contains executable entries with suspicious names.".to_string(),
                weight: 25,
                source: EvidenceSource::NativeHeuristic,
            });
        }
    }
    evidence
}
