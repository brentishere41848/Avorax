pub fn normalize_hash(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_ascii_lowercase()
}

pub fn is_sha256(value: &str) -> bool {
    let normalized = normalize_hash(value);
    normalized.len() == 64 && normalized.chars().all(|value| value.is_ascii_hexdigit())
}
