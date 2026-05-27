use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct UserApprovalStore {
    exact_hashes: HashSet<String>,
}

impl UserApprovalStore {
    pub fn from_hashes(hashes: impl IntoIterator<Item = String>) -> Self {
        Self {
            exact_hashes: hashes
                .into_iter()
                .map(|hash| normalize_hash(&hash))
                .collect(),
        }
    }

    pub fn approve_hash(&mut self, hash: String) {
        self.exact_hashes.insert(normalize_hash(&hash));
    }

    pub fn is_hash_approved(&self, hash: &str) -> bool {
        self.exact_hashes.contains(&normalize_hash(hash))
    }
}

fn normalize_hash(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_lowercase()
}
