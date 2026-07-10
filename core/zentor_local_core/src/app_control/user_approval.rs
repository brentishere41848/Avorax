use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct UserApprovalStore {
    exact_hashes: HashSet<String>,
}

impl UserApprovalStore {
    pub fn from_hashes(hashes: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut exact_hashes = HashSet::new();
        for hash in hashes {
            let Some(hash) = normalize_sha256(&hash) else {
                anyhow::bail!("user approval store contains malformed SHA-256 value");
            };
            exact_hashes.insert(hash);
        }
        Ok(Self { exact_hashes })
    }

    pub fn approve_hash(&mut self, hash: String) -> anyhow::Result<()> {
        let Some(hash) = normalize_sha256(&hash) else {
            anyhow::bail!("user approval hash is malformed");
        };
        self.exact_hashes.insert(hash);
        Ok(())
    }

    pub fn is_hash_approved(&self, hash: &str) -> bool {
        let Some(hash) = normalize_sha256(hash) else {
            return false;
        };
        self.exact_hashes.contains(&hash)
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

    const VALID_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn user_approval_store_rejects_malformed_hashes() {
        assert!(UserApprovalStore::from_hashes([
            "abc123".to_string(),
            format!("sha256:{VALID_HASH}"),
        ])
        .unwrap_err()
        .to_string()
        .contains("user approval store contains malformed SHA-256 value"));

        let mut store = UserApprovalStore::from_hashes([format!("sha256:{VALID_HASH}")]).unwrap();
        assert!(store
            .approve_hash("not-a-sha256".to_string())
            .unwrap_err()
            .to_string()
            .contains("user approval hash is malformed"));

        assert!(store.is_hash_approved(VALID_HASH));
        assert!(!store.is_hash_approved(""));
        assert!(!store.is_hash_approved("abc123"));
        assert!(!store.is_hash_approved("not-a-sha256"));
    }

    #[test]
    fn user_approval_hash_lookup_uses_explicit_malformed_branch() {
        let source = include_str!("user_approval.rs");
        let contains_start = source.find("pub fn is_hash_approved").unwrap();
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let contains_source = &source[contains_start..normalize_start];

        assert!(contains_source.contains("let Some(hash) = normalize_sha256(hash) else"));
        assert!(contains_source.contains("return false;"));
        assert!(!contains_source.contains(".unwrap_or(false)"));
    }

    #[test]
    fn user_approval_hash_prefix_branch_is_explicit() {
        let source = include_str!("user_approval.rs");
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let tests_start = source.find("#[cfg(test)]").unwrap();
        let normalize_source = &source[normalize_start..tests_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or(trimmed)"));
    }
}
