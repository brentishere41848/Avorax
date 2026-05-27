use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn load_default() -> Self {
        Self::from_path(default_known_good_path())
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
        let Ok(records) = serde_json::from_str::<Vec<KnownGoodRecord>>(&raw) else {
            return Self::default();
        };
        Self::from_hashes(records.into_iter().map(|record| record.sha256))
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.hashes.contains(&normalize_hash(hash))
    }
}

fn default_known_good_path() -> PathBuf {
    PathBuf::from("assets/trust/pasus_known_good.db")
}

fn normalize_hash(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_lowercase()
}
