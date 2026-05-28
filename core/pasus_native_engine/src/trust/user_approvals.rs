#[derive(Debug, Clone, Default)]
pub struct UserApprovals {
    hashes: Vec<String>,
}

impl UserApprovals {
    pub fn approves(&self, sha256: &str) -> bool {
        self.hashes.iter().any(|hash| hash.eq_ignore_ascii_case(sha256))
    }
}
