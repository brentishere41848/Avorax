use super::indicator::IndicatorType;
use crate::verdict::Confidence;

pub fn default_confidence(kind: &IndicatorType, trusted_source: bool) -> Confidence {
    match (kind, trusted_source) {
        (IndicatorType::Sha256, true) => Confidence::Confirmed,
        (IndicatorType::Sha1 | IndicatorType::Md5, true) => Confidence::High,
        (IndicatorType::StringPattern | IndicatorType::ScriptPattern, _) => Confidence::Medium,
        (IndicatorType::FilenamePattern | IndicatorType::FilePathPattern, _) => Confidence::Low,
        (IndicatorType::Sha256 | IndicatorType::Sha1 | IndicatorType::Md5, false)
        | (IndicatorType::Imphash, _)
        | (IndicatorType::BytePattern, _)
        | (IndicatorType::ImportCombo, _)
        | (IndicatorType::BehaviorPattern, _)
        | (IndicatorType::RegistryPath, _)
        | (IndicatorType::MutexName, _) => Confidence::Medium,
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;

    #[test]
    fn default_confidence_mapping_has_no_medium_wildcard() {
        assert_eq!(
            default_confidence(&IndicatorType::Sha256, true),
            Confidence::Confirmed
        );
        assert_eq!(
            default_confidence(&IndicatorType::Sha256, false),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::Sha1, true),
            Confidence::High
        );
        assert_eq!(
            default_confidence(&IndicatorType::Sha1, false),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::Md5, true),
            Confidence::High
        );
        assert_eq!(
            default_confidence(&IndicatorType::Md5, false),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::Imphash, true),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::FilenamePattern, true),
            Confidence::Low
        );
        assert_eq!(
            default_confidence(&IndicatorType::FilePathPattern, false),
            Confidence::Low
        );
        assert_eq!(
            default_confidence(&IndicatorType::StringPattern, false),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::ScriptPattern, true),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::BytePattern, true),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::ImportCombo, false),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::BehaviorPattern, true),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::RegistryPath, true),
            Confidence::Medium
        );
        assert_eq!(
            default_confidence(&IndicatorType::MutexName, false),
            Confidence::Medium
        );

        let source = include_str!("confidence_mapping.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(!production_source.contains("_ => Confidence::Medium"));
    }
}
