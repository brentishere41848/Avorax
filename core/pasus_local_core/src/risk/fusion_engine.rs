use crate::scanner::{RecommendedAction, RiskScore, RiskVerdict, ThreatConfidence};

use super::false_positive_policy::weak_location_only_signal;

pub fn should_auto_quarantine(risk: &RiskScore, allowlisted: bool, production_ai: bool) -> bool {
    if allowlisted || weak_location_only_signal(&risk.reasons) {
        return false;
    }
    match risk.verdict {
        RiskVerdict::ConfirmedMalware => risk.confidence == ThreatConfidence::Confirmed,
        RiskVerdict::ProbableMalware => {
            production_ai && risk.score >= 90 && risk.confidence == ThreatConfidence::High
        }
        _ => false,
    }
}

pub fn recommended_action_for(risk: &RiskScore) -> RecommendedAction {
    if risk.verdict == RiskVerdict::ConfirmedMalware {
        RecommendedAction::Quarantine
    } else {
        RecommendedAction::Review
    }
}
