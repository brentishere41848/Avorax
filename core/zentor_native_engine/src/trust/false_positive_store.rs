use crate::signatures::known_bad_hashes::{is_sha256, normalize_hash};

#[derive(Debug, Clone, Default)]
pub struct FalsePositiveStore {
    hashes: Vec<String>,
}

impl FalsePositiveStore {
    pub fn from_hashes(hashes: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut normalized = Vec::new();
        for hash in hashes {
            if !is_sha256(&hash) {
                anyhow::bail!("native false-positive store contains malformed SHA-256 value");
            }
            normalized.push(normalize_hash(&hash));
        }
        Ok(Self { hashes: normalized })
    }

    pub fn suppresses(&self, sha256: &str) -> bool {
        if !is_sha256(sha256) {
            return false;
        }
        let sha256 = normalize_hash(sha256);
        self.hashes.iter().any(|hash| hash == &sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn false_positive_store_rejects_malformed_hashes() {
        let error = FalsePositiveStore::from_hashes([
            "not-a-hash".to_string(),
            format!("sha256:{VALID_HASH}"),
        ])
        .unwrap_err()
        .to_string();

        assert!(error.contains("native false-positive store contains malformed SHA-256 value"));
    }

    #[test]
    fn false_positive_store_normalizes_valid_hashes() {
        let store = FalsePositiveStore::from_hashes([format!("sha256:{VALID_HASH}")]).unwrap();

        assert!(store.suppresses(VALID_HASH));
        assert!(!store.suppresses("not-a-hash"));
    }
}
