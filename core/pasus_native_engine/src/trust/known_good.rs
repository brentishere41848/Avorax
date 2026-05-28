use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnownGoodStore {
    hashes: BTreeSet<String>,
}

impl KnownGoodStore {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw: TrustHashes = serde_json::from_str(&fs::read_to_string(path)?)?;
        Ok(Self {
            hashes: raw.hashes.into_iter().map(|h| h.to_ascii_lowercase()).collect(),
        })
    }

    pub fn contains(&self, sha256: &str) -> bool {
        self.hashes.contains(&sha256.to_ascii_lowercase())
    }

    pub fn count(&self) -> usize {
        self.hashes.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustHashes {
    hashes: Vec<String>,
}
