use serde::{Deserialize, Serialize};

use super::{Confidence, ThreatCategory, Verdict};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceSource {
    NativeSignature,
    NativeRule,
    NativeHeuristic,
    NativeMl,
    NativeBehavior,
    ApplicationControl,
    TrustStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub weight: i32,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalVerdict {
    pub verdict: Verdict,
    pub category: ThreatCategory,
    pub confidence: Confidence,
    pub risk_score: u8,
    pub evidence: Vec<Evidence>,
    pub engines_used: Vec<EvidenceSource>,
    pub recommended_action: String,
    pub user_visible_explanation: String,
}

pub struct RiskFusion;

impl RiskFusion {
    pub fn fuse(mut evidence: Vec<Evidence>, known_good: bool, allowlisted: bool) -> FinalVerdict {
        let mut engines_used = evidence
            .iter()
            .map(|item| item.source.clone())
            .collect::<Vec<_>>();
        engines_used.sort_by_key(|item| format!("{item:?}"));
        engines_used.dedup();

        if known_good || allowlisted {
            evidence.push(Evidence {
                id: if known_good { "known_good" } else { "allowlisted" }.to_string(),
                title: if known_good { "Known-good trust entry" } else { "User allowlist entry" }.to_string(),
                detail: "Trusted local policy prevents automatic quarantine unless confirmed behavior overrides it.".to_string(),
                weight: -70,
                source: EvidenceSource::TrustStore,
            });
        }

        let has_test = evidence
            .iter()
            .any(|item| item.id == "eicar_test_signature");
        let has_known_bad = evidence.iter().any(|item| item.id == "known_bad_hash");
        let has_confirmed_signature = evidence
            .iter()
            .any(|item| item.source == EvidenceSource::NativeSignature && item.weight >= 90);
        let has_ransomware_behavior = evidence
            .iter()
            .any(|item| item.source == EvidenceSource::NativeBehavior && item.weight >= 85);

        if has_test {
            return final_verdict(
                Verdict::TestThreat,
                ThreatCategory::TestThreat,
                Confidence::Confirmed,
                100,
                evidence,
                engines_used,
                "quarantine",
            );
        }
        if has_known_bad || has_confirmed_signature {
            return final_verdict(
                Verdict::ConfirmedMalware,
                infer_category(&evidence).unwrap_or(ThreatCategory::Unknown),
                Confidence::Confirmed,
                100,
                evidence,
                engines_used,
                "quarantine",
            );
        }
        if has_ransomware_behavior {
            return final_verdict(
                Verdict::ProbableMalware,
                ThreatCategory::Ransomware,
                Confidence::High,
                92,
                evidence,
                engines_used,
                "stop_and_quarantine",
            );
        }

        let score = evidence
            .iter()
            .map(|item| item.weight)
            .sum::<i32>()
            .clamp(0, 100) as u8;
        let strong_positive_count = evidence.iter().filter(|item| item.weight >= 20).count();
        let ml_high = evidence
            .iter()
            .any(|item| item.source == EvidenceSource::NativeMl && item.weight >= 40);
        let verdict = if score >= 85 && strong_positive_count >= 3 {
            Verdict::ProbableMalware
        } else if score >= 60 && (strong_positive_count >= 2 || ml_high) {
            Verdict::ProbableMalware
        } else if score >= 35 {
            Verdict::Suspicious
        } else if score >= 15 {
            Verdict::Observation
        } else if known_good {
            Verdict::LikelyClean
        } else {
            Verdict::Clean
        };
        let confidence = match verdict {
            Verdict::ProbableMalware => Confidence::High,
            Verdict::Suspicious => Confidence::Medium,
            Verdict::Observation => Confidence::Low,
            Verdict::Clean | Verdict::LikelyClean => Confidence::Low,
            Verdict::Unknown => Confidence::Low,
            Verdict::ConfirmedMalware | Verdict::TestThreat => Confidence::Confirmed,
        };
        let action = match verdict {
            Verdict::ProbableMalware => "review_or_quarantine_by_policy",
            Verdict::Suspicious => "review",
            Verdict::Observation => "observe",
            _ => "allow",
        };
        final_verdict(
            verdict,
            infer_category(&evidence).unwrap_or(ThreatCategory::Unknown),
            confidence,
            score,
            evidence,
            engines_used,
            action,
        )
    }
}

fn infer_category(evidence: &[Evidence]) -> Option<ThreatCategory> {
    let text = evidence
        .iter()
        .map(|item| {
            format!(
                "{} {} {}",
                item.id.to_ascii_lowercase(),
                item.title.to_ascii_lowercase(),
                item.detail.to_ascii_lowercase()
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    if text.contains("ransom") || text.contains("shadow") || text.contains("backup delete") {
        Some(ThreatCategory::Ransomware)
    } else if text.contains("infosteal")
        || text.contains("credential")
        || text.contains("browser data")
        || text.contains("wallet")
        || text.contains("token")
    {
        Some(ThreatCategory::Infostealer)
    } else if text.contains("miner") || text.contains("mining") || text.contains("stratum") {
        Some(ThreatCategory::Miner)
    } else if text.contains("adware") || text.contains("pup") || text.contains("unwanted") {
        Some(ThreatCategory::PotentiallyUnwantedApp)
    } else if text.contains("downloader") || text.contains("download") {
        Some(ThreatCategory::SuspiciousDownloader)
    } else if text.contains("script") || text.contains("powershell") {
        Some(ThreatCategory::SuspiciousScript)
    } else if text.contains("persistence") || text.contains("autorun") {
        Some(ThreatCategory::PersistenceIndicator)
    } else if text.contains("tamper") || text.contains("defender") || text.contains("security") {
        Some(ThreatCategory::SecurityTamperIndicator)
    } else if text.contains("trojan") {
        Some(ThreatCategory::Trojan)
    } else {
        None
    }
}

fn final_verdict(
    verdict: Verdict,
    category: ThreatCategory,
    confidence: Confidence,
    risk_score: u8,
    evidence: Vec<Evidence>,
    engines_used: Vec<EvidenceSource>,
    recommended_action: &str,
) -> FinalVerdict {
    let user_visible_explanation = if evidence.is_empty() {
        "Zentor Native Engine did not find suspicious local evidence.".to_string()
    } else {
        evidence
            .iter()
            .map(|item| format!("{}: {}", item.title, item.detail))
            .collect::<Vec<_>>()
            .join(" ")
    };
    FinalVerdict {
        verdict,
        category,
        confidence,
        risk_score,
        evidence,
        engines_used,
        recommended_action: recommended_action.to_string(),
        user_visible_explanation,
    }
}
