use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::signatures::known_bad_hashes::{is_sha256, normalize_hash};

#[cfg(test)]
use super::store_io::MAX_NATIVE_TRUST_STORE_BYTES;
use super::store_io::{read_bounded_trust_store_text, trust_store_file_present};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnownGoodStore {
    hashes: BTreeSet<String>,
    #[serde(skip)]
    loaded: bool,
}

impl KnownGoodStore {
    pub fn load(path: &Path) -> Result<Self> {
        if !trust_store_file_present(path, "native known-good store")? {
            return Ok(Self::default());
        }
        let raw_text = read_bounded_trust_store_text(path, "native known-good store")?;
        let raw: TrustHashes = serde_json::from_str(&raw_text).with_context(|| {
            format!("unable to parse native known-good store {}", path.display())
        })?;
        let mut hashes = BTreeSet::new();
        for hash in raw.hashes {
            if !is_sha256(&hash) {
                anyhow::bail!("native known-good store contains malformed SHA-256 value");
            }
            hashes.insert(normalize_hash(&hash));
        }
        Ok(Self {
            hashes,
            loaded: true,
        })
    }

    pub fn contains(&self, sha256: &str) -> bool {
        is_sha256(sha256) && self.hashes.contains(&normalize_hash(sha256))
    }

    pub fn count(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustHashes {
    hashes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const VALID_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn known_good_store_rejects_malformed_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-good.json");
        fs::write(
            &path,
            format!(r#"{{"hashes":["not-a-hash","sha256:{VALID_HASH}"]}}"#),
        )
        .unwrap();

        let error = KnownGoodStore::load(&path).unwrap_err().to_string();

        assert!(error.contains("native known-good store contains malformed SHA-256 value"));
    }

    #[test]
    fn known_good_store_errors_include_path_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-good.json");
        fs::write(&path, "{not-json").unwrap();

        let error = KnownGoodStore::load(&path).unwrap_err().to_string();

        assert!(error.contains("unable to parse native known-good store"));
        assert!(error.contains("known-good.json"));
    }

    #[test]
    fn known_good_store_rejects_unknown_hash_store_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-good.json");
        fs::write(&path, r#"{"hashes":[],"allow_all":true}"#).unwrap();

        let error = KnownGoodStore::load(&path).unwrap_err().to_string();

        assert!(error.contains("unable to parse native known-good store"));
    }

    #[test]
    fn known_good_store_rejects_oversized_store_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-good.json");
        fs::write(&path, "x".repeat(MAX_NATIVE_TRUST_STORE_BYTES as usize + 1)).unwrap();

        let error = KnownGoodStore::load(&path).unwrap_err().to_string();

        assert!(error.contains("native known-good store"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn known_good_store_missing_file_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-known-good.json");

        let store = KnownGoodStore::load(&path).unwrap();

        assert_eq!(store.count(), 0);
        assert!(!store.is_loaded());
    }

    #[test]
    fn known_good_store_loader_uses_non_following_presence_check() {
        let source = include_str!("known_good.rs");
        let load_start = source.find("pub fn load").unwrap();
        let contains_start = source.find("pub fn contains").unwrap();
        let load_source = &source[load_start..contains_start];
        let presence_helper_pattern = ["trust_store_file_", "present"].concat();
        let path_exists_pattern = ["path", ".exists()"].concat();

        assert!(load_source.contains(&presence_helper_pattern));
        assert!(!load_source.contains(&path_exists_pattern));
    }
}
