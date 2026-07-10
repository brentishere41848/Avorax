use super::indicator::IndicatorType;

pub fn normalize_indicator_value(kind: &IndicatorType, value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    match kind {
        IndicatorType::Sha256 => {
            let normalized = sha256_body(trimmed).to_ascii_lowercase();
            (normalized.len() == 64 && normalized.chars().all(|c| c.is_ascii_hexdigit()))
                .then_some(normalized)
        }
        IndicatorType::Sha1 => {
            let normalized = trimmed.to_ascii_lowercase();
            (normalized.len() == 40 && normalized.chars().all(|c| c.is_ascii_hexdigit()))
                .then_some(normalized)
        }
        IndicatorType::Md5 => {
            let normalized = trimmed.to_ascii_lowercase();
            (normalized.len() == 32 && normalized.chars().all(|c| c.is_ascii_hexdigit()))
                .then_some(normalized)
        }
        IndicatorType::Imphash
        | IndicatorType::FilenamePattern
        | IndicatorType::StringPattern
        | IndicatorType::BytePattern
        | IndicatorType::ScriptPattern
        | IndicatorType::ImportCombo
        | IndicatorType::BehaviorPattern
        | IndicatorType::RegistryPath
        | IndicatorType::MutexName
        | IndicatorType::FilePathPattern => Some(trimmed.to_string()),
    }
}

fn sha256_body(trimmed: &str) -> &str {
    match trimmed.strip_prefix("sha256:") {
        Some(raw) => raw,
        None => trimmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_intel_indicator_hash_prefix_branch_is_explicit() {
        let source = include_str!("indicator_normalizer.rs");
        let sha256_start = source.find("IndicatorType::Sha256").unwrap();
        let helper_start = source.find("fn sha256_body").unwrap();
        let sha256_source = &source[sha256_start..helper_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(sha256_source.contains("sha256_body(trimmed).to_ascii_lowercase()"));
        assert!(source.contains("Some(raw) => raw"));
        assert!(source.contains("None => trimmed"));
        assert!(!sha256_source.contains("strip_prefix(\"sha256:\").unwrap_or(trimmed)"));
    }

    #[test]
    fn threat_intel_indicator_pass_through_types_are_explicit() {
        let source = include_str!("indicator_normalizer.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert_eq!(
            normalize_indicator_value(&IndicatorType::FilenamePattern, "  invoice*  "),
            Some("invoice*".to_string())
        );
        assert_eq!(
            normalize_indicator_value(&IndicatorType::StringPattern, "  token grab  "),
            Some("token grab".to_string())
        );
        assert_eq!(
            normalize_indicator_value(&IndicatorType::Imphash, "  ABCD  "),
            Some("ABCD".to_string())
        );
        assert_eq!(
            normalize_indicator_value(&IndicatorType::BytePattern, ""),
            None
        );
        assert!(!production_source.contains("_ => Some(trimmed.to_string())"));
    }
}
