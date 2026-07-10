#![allow(dead_code)]

use std::collections::HashSet;

#[derive(Default)]
pub struct KnownGoodCache {
    hashes: HashSet<String>,
}

impl KnownGoodCache {
    pub fn contains(&self, hash: &str) -> bool {
        let Some(hash) = normalize_sha256(hash) else {
            return false;
        };
        self.hashes.contains(&hash)
    }

    pub fn insert(&mut self, hash: String) -> anyhow::Result<()> {
        let Some(hash) = normalize_sha256(&hash) else {
            anyhow::bail!("guard known-good cache contains malformed SHA-256 value");
        };
        self.hashes.insert(hash);
        Ok(())
    }
}

fn normalize_sha256(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let raw = sha256_body(trimmed);
    if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(raw.to_lowercase())
    } else {
        None
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

    const VALID_HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    #[test]
    fn known_good_cache_rejects_malformed_hashes() {
        let mut cache = KnownGoodCache::default();
        let error = cache.insert("abc123".to_string()).unwrap_err().to_string();
        cache.insert(format!("sha256:{VALID_HASH}")).unwrap();

        assert!(error.contains("guard known-good cache contains malformed SHA-256 value"));
        assert!(cache.contains(VALID_HASH));
        assert!(!cache.contains("abc123"));
        assert!(!cache.contains(""));
    }

    #[test]
    fn known_good_cache_hash_lookup_uses_explicit_malformed_branch() {
        let source = include_str!("known_good_cache.rs");
        let contains_start = source.find("pub fn contains").unwrap();
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let contains_source = &source[contains_start..normalize_start];

        assert!(contains_source.contains("let Some(hash) = normalize_sha256(hash) else"));
        assert!(contains_source.contains("return false;"));
        assert!(!contains_source.contains(".unwrap_or(false)"));
    }

    #[test]
    fn known_good_cache_hash_prefix_branch_is_explicit() {
        let source = include_str!("known_good_cache.rs");
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let test_start = source.find("#[cfg(test)]").unwrap();
        let normalize_source = &source[normalize_start..test_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("match trimmed.strip_prefix(\"sha256:\")"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or"));
    }
}
