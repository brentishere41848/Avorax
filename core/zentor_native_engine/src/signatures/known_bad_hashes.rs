pub fn normalize_hash(value: &str) -> String {
    let trimmed = value.trim();
    sha256_body(trimmed).to_ascii_lowercase()
}

fn sha256_body(trimmed: &str) -> &str {
    match trimmed.strip_prefix("sha256:") {
        Some(raw) => raw,
        None => trimmed,
    }
}

pub fn is_sha256(value: &str) -> bool {
    let normalized = normalize_hash(value);
    normalized.len() == 64 && normalized.chars().all(|value| value.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_bad_signature_hash_prefix_branch_is_explicit() {
        let source = include_str!("known_bad_hashes.rs");
        let normalize_start = source.find("pub fn normalize_hash").unwrap();
        let is_sha256_start = source.find("pub fn is_sha256").unwrap();
        let normalize_source = &source[normalize_start..is_sha256_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("sha256_body(trimmed).to_ascii_lowercase()"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains(".unwrap_or(value.trim())"));
    }
}
