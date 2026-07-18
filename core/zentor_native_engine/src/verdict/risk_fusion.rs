use serde::{Deserialize, Serialize};

use super::{Confidence, ThreatCategory, Verdict};

const MAX_REPORTED_EVIDENCE_ITEMS: usize = 32;
const MAX_EXPLANATION_EVIDENCE_ITEMS: usize = 8;
const MAX_EXPLANATION_CHARS: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceSource {
    NativeSignature,
    NativeRule,
    NativeHeuristic,
    NativeMl,
    NativeBehavior,
    CloudReputation,
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
                recommended_action_for_verdict(Verdict::TestThreat),
            );
        }
        if has_known_bad || has_confirmed_signature {
            return final_verdict(
                Verdict::ConfirmedMalware,
                inferred_or_unknown_category(&evidence),
                Confidence::Confirmed,
                100,
                evidence,
                engines_used,
                recommended_action_for_verdict(Verdict::ConfirmedMalware),
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
        let verdict = if (score >= 85 && strong_positive_count >= 3)
            || (score >= 60 && (strong_positive_count >= 2 || ml_high))
        {
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
        let action = recommended_action_for_verdict(verdict);
        final_verdict(
            verdict,
            inferred_or_unknown_category(&evidence),
            confidence,
            score,
            evidence,
            engines_used,
            action,
        )
    }
}

fn recommended_action_for_verdict(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::ConfirmedMalware | Verdict::TestThreat => "quarantine",
        Verdict::ProbableMalware => "review_or_quarantine_by_policy",
        Verdict::Suspicious => "review",
        Verdict::Observation => "observe",
        Verdict::Clean | Verdict::LikelyClean | Verdict::Unknown => "allow",
    }
}

fn inferred_or_unknown_category(evidence: &[Evidence]) -> ThreatCategory {
    match infer_category(evidence) {
        Some(category) => category,
        None => ThreatCategory::Unknown,
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
    } else if text.contains("persistence") || text.contains("autorun") {
        Some(ThreatCategory::PersistenceIndicator)
    } else if text.contains("macro")
        || text.contains("vba")
        || text.contains("autoopen")
        || text.contains("document_open")
        || text.contains("workbook_open")
    {
        Some(ThreatCategory::MaliciousMacro)
    } else if text.contains("downloader") || text.contains("download") {
        Some(ThreatCategory::SuspiciousDownloader)
    } else if text.contains("script") || text.contains("powershell") {
        Some(ThreatCategory::SuspiciousScript)
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
    let omitted_evidence_count = evidence.len().saturating_sub(MAX_REPORTED_EVIDENCE_ITEMS);
    let reported_evidence = evidence
        .into_iter()
        .take(MAX_REPORTED_EVIDENCE_ITEMS)
        .collect::<Vec<_>>();
    let user_visible_explanation = if reported_evidence.is_empty() {
        "Avorax Native Engine did not find suspicious local evidence.".to_string()
    } else {
        let mut explanation = String::new();
        if omitted_evidence_count > 0 {
            explanation.push_str(&format!(
                "{omitted_evidence_count} additional evidence item(s) omitted from this report. "
            ));
        }
        explanation.push_str(
            &reported_evidence
                .iter()
                .take(MAX_EXPLANATION_EVIDENCE_ITEMS)
                .map(|item| format!("{}: {}", item.title, item.detail))
                .collect::<Vec<_>>()
                .join(" "),
        );
        truncate_explanation(explanation)
    };
    FinalVerdict {
        verdict,
        category,
        confidence,
        risk_score,
        evidence: reported_evidence,
        engines_used,
        recommended_action: recommended_action.to_string(),
        user_visible_explanation,
    }
}

fn truncate_explanation(mut explanation: String) -> String {
    if explanation.len() <= MAX_EXPLANATION_CHARS {
        return explanation;
    }
    explanation.truncate(MAX_EXPLANATION_CHARS);
    explanation.push_str("...");
    explanation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weighted_evidence(weights: &[i32]) -> Vec<Evidence> {
        weights
            .iter()
            .enumerate()
            .map(|(index, weight)| Evidence {
                id: format!("weighted-{index}"),
                title: format!("Weighted evidence {index}"),
                detail: "Threshold regression fixture".to_string(),
                weight: *weight,
                source: EvidenceSource::NativeHeuristic,
            })
            .collect()
    }

    #[test]
    fn probable_malware_thresholds_remain_conservative_and_explicit() {
        let two_strong = RiskFusion::fuse(weighted_evidence(&[30, 30]), false, false);
        let three_strong = RiskFusion::fuse(weighted_evidence(&[30, 30, 25]), false, false);
        let one_strong = RiskFusion::fuse(weighted_evidence(&[60]), false, false);

        assert_eq!(two_strong.verdict, Verdict::ProbableMalware);
        assert_eq!(three_strong.verdict, Verdict::ProbableMalware);
        assert_eq!(one_strong.verdict, Verdict::Suspicious);
    }

    #[test]
    fn risk_fusion_bounds_reported_evidence_and_explanation() {
        let evidence = (0..64)
            .map(|index| Evidence {
                id: format!("evidence-{index}"),
                title: format!("Evidence {index}"),
                detail: "x".repeat(512),
                weight: 1,
                source: EvidenceSource::NativeHeuristic,
            })
            .collect::<Vec<_>>();

        let verdict = RiskFusion::fuse(evidence, false, false);

        assert_eq!(verdict.evidence.len(), MAX_REPORTED_EVIDENCE_ITEMS);
        assert!(verdict
            .user_visible_explanation
            .contains("additional evidence item(s) omitted"));
        assert!(verdict.user_visible_explanation.len() <= MAX_EXPLANATION_CHARS + 3);
    }

    #[test]
    fn risk_fusion_recommended_action_mapping_is_exhaustive() {
        assert_eq!(recommended_action_for_verdict(Verdict::Clean), "allow");
        assert_eq!(
            recommended_action_for_verdict(Verdict::LikelyClean),
            "allow"
        );
        assert_eq!(recommended_action_for_verdict(Verdict::Unknown), "allow");
        assert_eq!(
            recommended_action_for_verdict(Verdict::Observation),
            "observe"
        );
        assert_eq!(
            recommended_action_for_verdict(Verdict::Suspicious),
            "review"
        );
        assert_eq!(
            recommended_action_for_verdict(Verdict::ProbableMalware),
            "review_or_quarantine_by_policy"
        );
        assert_eq!(
            recommended_action_for_verdict(Verdict::ConfirmedMalware),
            "quarantine"
        );
        assert_eq!(
            recommended_action_for_verdict(Verdict::TestThreat),
            "quarantine"
        );

        let source = include_str!("risk_fusion.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        let helper_start = production_source
            .find("fn recommended_action_for_verdict")
            .unwrap();
        let helper_end = production_source
            .find("fn inferred_or_unknown_category")
            .unwrap();
        let helper_source = &production_source[helper_start..helper_end];

        assert!(production_source.contains("recommended_action_for_verdict(verdict)"));
        assert!(!helper_source.contains("_ => \"allow\""));
    }

    #[test]
    fn risk_fusion_unknown_category_branch_is_explicit() {
        let evidence = vec![Evidence {
            id: "known_bad_hash".to_string(),
            title: "Known bad hash".to_string(),
            detail: "Exact hash match without category hint".to_string(),
            weight: 100,
            source: EvidenceSource::NativeSignature,
        }];

        let verdict = RiskFusion::fuse(evidence, false, false);

        assert_eq!(verdict.category, ThreatCategory::Unknown);

        let source = include_str!("risk_fusion.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(production_source.contains("fn inferred_or_unknown_category"));
        assert!(production_source.contains("Some(category) => category"));
        assert!(production_source.contains("None => ThreatCategory::Unknown"));
        assert!(!production_source.contains(".unwrap_or(ThreatCategory::Unknown)"));
    }

    #[test]
    fn risk_fusion_macro_category_precedes_downloader_text() {
        let evidence = vec![Evidence {
            id: "office_macro_auto_run_remote_launch".to_string(),
            title: "Macro-enabled Office downloader carrier".to_string(),
            detail: "Macro autoopen downloader evidence.".to_string(),
            weight: 45,
            source: EvidenceSource::NativeHeuristic,
        }];

        let verdict = RiskFusion::fuse(evidence, false, false);

        assert_eq!(verdict.category, ThreatCategory::MaliciousMacro);
        assert_eq!(verdict.verdict, Verdict::Suspicious);
    }
}
