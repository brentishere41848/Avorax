use super::indicator::IndicatorType;
use crate::verdict::Confidence;

pub fn default_confidence(kind: &IndicatorType, trusted_source: bool) -> Confidence {
    match (kind, trusted_source) {
        (IndicatorType::Sha256, true) => Confidence::Confirmed,
        (IndicatorType::Sha1 | IndicatorType::Md5, true) => Confidence::High,
        (IndicatorType::StringPattern | IndicatorType::ScriptPattern, _) => Confidence::Medium,
        (IndicatorType::FilenamePattern | IndicatorType::FilePathPattern, _) => Confidence::Low,
        _ => Confidence::Medium,
    }
}
