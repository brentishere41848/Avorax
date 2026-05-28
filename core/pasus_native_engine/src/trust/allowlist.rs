use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    hashes: Vec<String>,
    paths: Vec<String>,
}

impl Allowlist {
    pub fn contains(&self, path: &Path, sha256: &str) -> bool {
        self.hashes.iter().any(|hash| hash.eq_ignore_ascii_case(sha256))
            || self.paths.iter().any(|entry| path.starts_with(entry))
    }

    pub fn add_hash(&mut self, sha256: String) {
        self.hashes.push(sha256);
    }

    pub fn validate_path(path: &str) -> bool {
        let normalized = path.trim_end_matches(['\\', '/']).to_ascii_lowercase();
        !matches!(
            normalized.as_str(),
            "c:" | "c:\\windows" | "c:\\program files" | "c:\\program files (x86)" | "" | "/" | "/system" | "/usr" | "/bin" | "/sbin" | "/etc"
        )
    }
}
