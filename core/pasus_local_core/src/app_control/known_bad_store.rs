use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Default)]
pub struct KnownBadStore {
    hashes: HashSet<String>,
}

#[derive(Debug, Deserialize)]
struct KnownBadFile {
    hashes: Vec<String>,
}

impl KnownBadStore {
    pub fn load_default() -> Self {
        Self::from_path(PathBuf::from(
            "assets/threats/pasus_known_bad_test_hashes.json",
        ))
    }

    pub fn from_hashes(hashes: impl IntoIterator<Item = String>) -> Self {
        Self {
            hashes: hashes
                .into_iter()
                .map(|hash| normalize_hash(&hash))
                .collect(),
        }
    }

    pub fn from_path(path: PathBuf) -> Self {
        let Ok(raw) = fs::read_to_string(path) else {
            return Self::default();
        };
        let Ok(parsed) = serde_json::from_str::<KnownBadFile>(&raw) else {
            return Self::default();
        };
        Self::from_hashes(parsed.hashes)
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.hashes.contains(&normalize_hash(hash))
    }
}

fn normalize_hash(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_lowercase()
}
