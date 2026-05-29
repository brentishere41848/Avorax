use super::indicator::IndicatorType;

pub fn normalize_indicator_value(kind: &IndicatorType, value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    match kind {
        IndicatorType::Sha256 => {
            let normalized = trimmed.strip_prefix("sha256:").unwrap_or(trimmed).to_ascii_lowercase();
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
        _ => Some(trimmed.to_string()),
    }
}
