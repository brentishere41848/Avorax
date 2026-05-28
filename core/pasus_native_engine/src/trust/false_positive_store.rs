#[derive(Debug, Clone, Default)]
pub struct FalsePositiveStore {
    hashes: Vec<String>,
}

impl FalsePositiveStore {
    pub fn suppresses(&self, sha256: &str) -> bool {
        self.hashes.iter().any(|hash| hash.eq_ignore_ascii_case(sha256))
    }
}
