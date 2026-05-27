use std::collections::HashSet;

#[derive(Default)]
pub struct KnownGoodCache {
    hashes: HashSet<String>,
}

impl KnownGoodCache {
    pub fn contains(&self, hash: &str) -> bool {
        self.hashes.contains(hash)
    }

    pub fn insert(&mut self, hash: String) {
        self.hashes.insert(hash);
    }
}
