use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;

#[cfg(test)]
use super::store_io::MAX_APP_CONTROL_TRUST_STORE_BYTES;
use super::store_io::{default_app_control_asset_path, read_bounded_store_text};

#[derive(Debug, Clone, Default)]
pub struct KnownBadStore {
    hashes: HashSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownBadFile {
    hashes: Vec<String>,
    description: Option<String>,
}

impl KnownBadStore {
    #[allow(dead_code)]
    pub fn load_default() -> anyhow::Result<Self> {
        Self::from_path(default_known_bad_path()?)
    }

    pub fn from_hashes(hashes: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut normalized = HashSet::new();
        for hash in hashes {
            let Some(hash) = normalize_sha256(&hash) else {
                anyhow::bail!("known-bad store contains malformed SHA-256 value");
            };
            normalized.insert(hash);
        }
        Ok(Self { hashes: normalized })
    }

    pub fn from_path(path: PathBuf) -> anyhow::Result<Self> {
        let raw = read_bounded_store_text(&path, "known-bad store")?;
        let parsed = serde_json::from_str::<KnownBadFile>(&raw)
            .with_context(|| format!("unable to parse known-bad store {}", path.display()))?;
        let KnownBadFile {
            hashes: parsed_hashes,
            description: _description,
        } = parsed;
        let mut hashes = HashSet::new();
        for value in parsed_hashes {
            let Some(hash) = normalize_sha256(&value) else {
                anyhow::bail!("known-bad store contains malformed SHA-256 value");
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

#[allow(dead_code)]
fn default_known_bad_path() -> anyhow::Result<PathBuf> {
    default_app_control_asset_path(&["assets", "threats", "zentor_known_bad_test_hashes.json"])
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

    const VALID_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn known_bad_store_rejects_malformed_file_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(
            &path,
            format!(r#"{{"hashes":["abc123","sha256:{VALID_HASH}"]}}"#),
        )
        .unwrap();

        let error = KnownBadStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("known-bad store contains malformed SHA-256 value"));
    }

    #[test]
    fn known_bad_hash_constructor_rejects_malformed_hashes() {
        let error =
            KnownBadStore::from_hashes(["abc123".to_string(), format!("sha256:{VALID_HASH}")])
                .unwrap_err()
                .to_string();

        assert!(error.contains("known-bad store contains malformed SHA-256 value"));
    }

    #[test]
    fn known_bad_store_accepts_explicit_description_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(&path, r#"{"hashes":[],"description":"safe test fixture"}"#).unwrap();

        let store = KnownBadStore::from_path(path).unwrap();

        assert!(!store.contains(VALID_HASH));
    }

    #[test]
    fn known_bad_store_rejects_unknown_object_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(
            &path,
            r#"{"hashes":[],"description":"safe test fixture","enabled":true}"#,
        )
        .unwrap();

        let error = KnownBadStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("unable to parse known-bad store"));
    }

    #[test]
    fn known_bad_hash_lookup_uses_explicit_malformed_branch() {
        let source = include_str!("known_bad_store.rs");
        let contains_start = source.find("pub fn contains").unwrap();
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let contains_source = &source[contains_start..normalize_start];

        assert!(contains_source.contains("let Some(hash) = normalize_sha256(hash) else"));
        assert!(contains_source.contains("return false;"));
        assert!(!contains_source.contains(".unwrap_or(false)"));
    }

    #[test]
    fn known_bad_default_path_uses_checked_asset_resolver() {
        let source = include_str!("known_bad_store.rs");
        let start = source.find("pub fn load_default").unwrap();
        let end = source.find("fn normalize_sha256").unwrap();
        let default_source = &source[start..end];

        assert!(default_source.contains("Self::from_path(default_known_bad_path()?)"));
        assert!(default_source.contains("fn default_known_bad_path() -> anyhow::Result<PathBuf>"));
        assert!(default_source.contains("default_app_control_asset_path(&["));
        assert!(default_source.contains("\"assets\""));
        assert!(default_source.contains("\"threats\""));
        assert!(default_source.contains("\"zentor_known_bad_test_hashes.json\""));
        assert!(!default_source
            .contains("PathBuf::from(\"assets/threats/zentor_known_bad_test_hashes.json\")"));
    }

    #[test]
    fn known_bad_hash_prefix_branch_is_explicit() {
        let source = include_str!("known_bad_store.rs");
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
    fn known_bad_store_reports_corrupt_store_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(&path, "{not-json").unwrap();

        let error = KnownBadStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("unable to parse known-bad store"));
    }

    #[test]
    fn known_bad_store_rejects_oversized_file_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(
            &path,
            "x".repeat(MAX_APP_CONTROL_TRUST_STORE_BYTES as usize + 1),
        )
        .unwrap();

        let error = KnownBadStore::from_path(path).unwrap_err().to_string();

        assert!(error.contains("known-bad store"));
        assert!(error.contains("exceeds maximum size"));
    }
}
