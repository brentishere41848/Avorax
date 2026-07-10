use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::store_io::MAX_APP_CONTROL_TRUST_STORE_BYTES;
use super::store_io::{default_app_control_asset_path, read_bounded_store_text};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownGoodRecord {
    pub sha256: String,
    pub file_name: String,
    pub publisher: Option<String>,
    pub product_name: Option<String>,
    pub version: Option<String>,
    pub source: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub trust_level: String,
    pub signature_thumbprint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct KnownGoodStore {
    hashes: HashSet<String>,
}

impl KnownGoodStore {
    #[allow(dead_code)]
    pub fn load_default() -> anyhow::Result<Self> {
        Self::from_path(default_known_good_path()?)
    }

    pub fn from_hashes(hashes: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut normalized = HashSet::new();
        for hash in hashes {
            let Some(hash) = normalize_sha256(&hash) else {
                anyhow::bail!("known-good store contains malformed SHA-256 value");
            };
            normalized.insert(hash);
        }
        Ok(Self { hashes: normalized })
    }

    pub fn from_path(path: PathBuf) -> anyhow::Result<Self> {
        let raw = read_bounded_store_text(&path, "known-good store")?;
        let records = serde_json::from_str::<Vec<KnownGoodRecord>>(&raw)
            .with_context(|| format!("unable to parse known-good store {}", path.display()))?;
        let mut hashes = HashSet::new();
        for record in records {
            validate_known_good_record(&record)?;
            let Some(hash) = normalize_sha256(&record.sha256) else {
                anyhow::bail!("known-good store contains malformed SHA-256 value");
            };
            hashes.insert(hash);
        }
        Ok(Self { hashes })
    }

    pub fn contains(&self, hash: &str) -> bool {
        let Some(hash) = normalize_sha256(hash) else {
            return false;
        };
        self.hashes.contains(&hash)
    }
}

fn validate_known_good_record(record: &KnownGoodRecord) -> anyhow::Result<()> {
    if record.trust_level.trim() != "known_good" {
        anyhow::bail!("known-good store contains invalid trust level");
    }
    Ok(())
}

#[allow(dead_code)]
fn default_known_good_path() -> anyhow::Result<PathBuf> {
    default_app_control_asset_path(&["assets", "trust", "zentor_known_good.db"])
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
    use std::fs;

    const VALID_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn known_good_store_rejects_malformed_file_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_good.json");
        fs::write(
            &path,
            format!(
                r#"[{{"sha256":"abc123","file_name":"bad.exe","publisher":null,"product_name":null,"version":null,"source":"fixture","created_at":"now","expires_at":null,"trust_level":"known_good","signature_thumbprint":null}},{{"sha256":"sha256:{VALID_HASH}","file_name":"good.exe","publisher":null,"product_name":null,"version":null,"source":"fixture","created_at":"now","expires_at":null,"trust_level":"known_good","signature_thumbprint":null}}]"#
            ),
        )
        .unwrap();

        let error = KnownGoodStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("known-good store contains malformed SHA-256 value"));
    }

    #[test]
    fn known_good_hash_constructor_rejects_malformed_hashes() {
        let error =
            KnownGoodStore::from_hashes(["abc123".to_string(), format!("sha256:{VALID_HASH}")])
                .unwrap_err()
                .to_string();

        assert!(error.contains("known-good store contains malformed SHA-256 value"));
    }

    #[test]
    fn known_good_store_rejects_records_without_known_good_trust_level() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_good.json");
        fs::write(
            &path,
            format!(
                r#"[{{"sha256":"sha256:{VALID_HASH}","file_name":"tool.exe","publisher":null,"product_name":null,"version":null,"source":"fixture","created_at":"now","expires_at":null,"trust_level":"review","signature_thumbprint":null}}]"#
            ),
        )
        .unwrap();

        let error = KnownGoodStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("known-good store contains invalid trust level"));
    }

    #[test]
    fn known_good_store_rejects_unknown_record_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_good.json");
        fs::write(
            &path,
            format!(
                r#"[{{"sha256":"sha256:{VALID_HASH}","file_name":"tool.exe","publisher":null,"product_name":null,"version":null,"source":"fixture","created_at":"now","expires_at":null,"trust_level":"known_good","signature_thumbprint":null,"allow_all":true}}]"#
            ),
        )
        .unwrap();

        let error = KnownGoodStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("unable to parse known-good store"));
    }

    #[test]
    fn known_good_trust_level_validation_is_not_dead_evidence() {
        let source = include_str!("known_good_store.rs");
        let from_path_start = source.find("pub fn from_path").unwrap();
        let contains_start = source.find("pub fn contains").unwrap();
        let from_path_source = &source[from_path_start..contains_start];

        assert!(source.contains("fn validate_known_good_record"));
        assert!(source.contains("record.trust_level.trim() != \"known_good\""));
        assert!(from_path_source.contains("validate_known_good_record(&record)?"));
    }

    #[test]
    fn known_good_hash_lookup_uses_explicit_malformed_branch() {
        let source = include_str!("known_good_store.rs");
        let contains_start = source.find("pub fn contains").unwrap();
        let normalize_start = source.find("fn default_known_good_path").unwrap();
        let contains_source = &source[contains_start..normalize_start];

        assert!(contains_source.contains("let Some(hash) = normalize_sha256(hash) else"));
        assert!(contains_source.contains("return false;"));
        assert!(!contains_source.contains(".unwrap_or(false)"));
    }

    #[test]
    fn known_good_default_path_uses_checked_asset_resolver() {
        let source = include_str!("known_good_store.rs");
        let start = source.find("pub fn load_default").unwrap();
        let end = source.find("fn normalize_sha256").unwrap();
        let default_source = &source[start..end];

        assert!(default_source.contains("Self::from_path(default_known_good_path()?)"));
        assert!(default_source.contains("fn default_known_good_path() -> anyhow::Result<PathBuf>"));
        assert!(default_source.contains(
            "default_app_control_asset_path(&[\"assets\", \"trust\", \"zentor_known_good.db\"])"
        ));
        assert!(!default_source.contains("PathBuf::from(\"assets/trust/zentor_known_good.db\")"));
    }

    #[test]
    fn known_good_hash_prefix_branch_is_explicit() {
        let source = include_str!("known_good_store.rs");
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let tests_start = normalize_start + source[normalize_start..].find("#[cfg(test)]").unwrap();
        let normalize_source = &source[normalize_start..tests_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or(trimmed)"));
    }

    #[test]
    fn known_good_store_reports_corrupt_store_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_good.json");
        fs::write(&path, "{not-json").unwrap();

        let error = KnownGoodStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("unable to parse known-good store"));
    }

    #[test]
    fn known_good_store_rejects_oversized_file_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_good.json");
        fs::write(
            &path,
            "x".repeat(MAX_APP_CONTROL_TRUST_STORE_BYTES as usize + 1),
        )
        .unwrap();

        let error = KnownGoodStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("known-good store"));
        assert!(error.contains("exceeds maximum size"));
    }
}
