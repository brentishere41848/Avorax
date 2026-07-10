use crate::signatures::known_bad_hashes::{is_sha256, normalize_hash};

#[derive(Debug, Clone, Default)]
pub struct UserApprovals {
    hashes: Vec<String>,
}

impl UserApprovals {
    pub fn from_hashes(hashes: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut normalized = Vec::new();
        for hash in hashes {
            if !is_sha256(&hash) {
                anyhow::bail!("native user approval store contains malformed SHA-256 value");
            }
            normalized.push(normalize_hash(&hash));
        }
        Ok(Self { hashes: normalized })
    }

    pub fn approves(&self, sha256: &str) -> bool {
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

    const VALID_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn user_approvals_reject_malformed_hashes() {
        let error =
            UserApprovals::from_hashes(["not-a-hash".to_string(), format!("sha256:{VALID_HASH}")])
                .unwrap_err()
                .to_string();

        assert!(error.contains("native user approval store contains malformed SHA-256 value"));
    }

    #[test]
    fn user_approvals_normalize_valid_hashes() {
        let approvals = UserApprovals::from_hashes([format!("sha256:{VALID_HASH}")]).unwrap();

        assert!(approvals.approves(VALID_HASH));
        assert!(!approvals.approves("not-a-hash"));
    }
}
