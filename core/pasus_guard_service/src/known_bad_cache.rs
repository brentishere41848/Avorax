use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct KnownBadFile {
    hashes: Vec<String>,
}

pub fn load_known_bad_hashes() -> HashSet<String> {
    let path = default_known_bad_path();
    load_known_bad_hashes_from_path(&path).unwrap_or_default()
}

pub fn load_known_bad_hashes_from_path(path: &Path) -> anyhow::Result<HashSet<String>> {
    if !path.is_file() {
        return Ok(HashSet::new());
    }
    let raw = fs::read_to_string(path)?;
    if raw.trim_start().starts_with('[') {
        let hashes: Vec<String> = serde_json::from_str(&raw)?;
        return Ok(hashes.into_iter().map(normalize_hash).collect());
    }
    let parsed: KnownBadFile = serde_json::from_str(&raw)?;
    Ok(parsed.hashes.into_iter().map(normalize_hash).collect())
}

fn default_known_bad_path() -> PathBuf {
    let mut roots = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }
    for root in roots {
        for candidate in [
            root.join("assets")
                .join("test")
                .join("known_bad_test_hashes.json"),
            root.join("..")
                .join("..")
                .join("assets")
                .join("test")
                .join("known_bad_test_hashes.json"),
        ] {
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("assets/test/known_bad_test_hashes.json")
}

fn normalize_hash(value: String) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_lowercase()
}
