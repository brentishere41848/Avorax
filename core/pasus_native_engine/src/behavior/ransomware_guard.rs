use crate::verdict::risk_fusion::{Evidence, EvidenceSource};

use super::file_activity::FileActivityEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorDecision {
    Allow,
    Monitor,
    Warn,
    StopProcess,
    QuarantineExecutable,
    StartRecovery,
}

pub struct RansomwareGuard;

impl RansomwareGuard {
    pub fn analyze(event: &FileActivityEvent) -> (BehaviorDecision, Option<Evidence>) {
        let mut score = 0;
        if event.files_modified_count >= 25 {
            score += 35;
        }
        if event.files_renamed_count >= 15 {
            score += 25;
        }
        if event.entropy_increase_count >= 10 {
            score += 25;
        }
        if event.ransom_note_created {
            score += 25;
        }
        if event.backup_tamper_attempt {
            score += 35;
        }
        if score >= 85 {
            (
                BehaviorDecision::StopProcess,
                Some(Evidence {
                    id: "ransomware_behavior".to_string(),
                    title: "Ransomware-like behavior".to_string(),
                    detail: "Rapid modifications, renames, entropy changes, ransom-note, or backup tamper signals were observed.".to_string(),
                    weight: score.min(100),
                    source: EvidenceSource::NativeBehavior,
                }),
            )
        } else if score >= 45 {
            (
                BehaviorDecision::Warn,
                Some(Evidence {
                    id: "ransomware_behavior_review".to_string(),
                    title: "Ransomware behavior review".to_string(),
                    detail: "Multiple file activity signals need review.".to_string(),
                    weight: score,
                    source: EvidenceSource::NativeBehavior,
                }),
            )
        } else {
            (BehaviorDecision::Allow, None)
        }
    }
}
