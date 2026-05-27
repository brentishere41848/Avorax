use crate::scanner::{RiskScore, RiskVerdict, ThreatConfidence};

pub fn is_confirmed_malware(risk: &RiskScore) -> bool {
    risk.verdict == RiskVerdict::ConfirmedMalware && risk.confidence == ThreatConfidence::Confirmed
}

pub fn is_probable_malware(risk: &RiskScore) -> bool {
    risk.verdict == RiskVerdict::ProbableMalware
        && matches!(risk.confidence, ThreatConfidence::High)
}
