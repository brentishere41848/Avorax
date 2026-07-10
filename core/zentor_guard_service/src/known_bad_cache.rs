use std::collections::HashSet;
use std::fs;
use std::io::{BufReader, Read};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownBadFile {
    hashes: Vec<String>,
    description: Option<String>,
}

const MAX_KNOWN_BAD_CACHE_BYTES: u64 = 1024 * 1024;

pub fn load_known_bad_hashes() -> anyhow::Result<HashSet<String>> {
    let path = default_known_bad_path()?;
    load_known_bad_hashes_from_path(&path)
}

pub fn load_known_bad_hashes_from_path(path: &Path) -> anyhow::Result<HashSet<String>> {
    let Some(metadata) = ensure_known_bad_cache_file(path)? else {
        return Ok(HashSet::new());
    };
    let raw = read_known_bad_cache_text(path, &metadata)?;
    if raw.trim_start().starts_with('[') {
        let hashes: Vec<String> = serde_json::from_str(&raw)
            .with_context(|| format!("unable to parse guard known-bad cache {}", path.display()))?;
        return normalize_hashes(hashes);
    }
    let parsed: KnownBadFile = serde_json::from_str(&raw)
        .with_context(|| format!("unable to parse guard known-bad cache {}", path.display()))?;
    let KnownBadFile {
        hashes,
        description: _description,
    } = parsed;
    normalize_hashes(hashes)
}

fn ensure_known_bad_cache_file(path: &Path) -> anyhow::Result<Option<fs::Metadata>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("unable to inspect guard known-bad cache {}", path.display())
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "guard known-bad cache {} is a symbolic link",
            path.display()
        ));
    }
    if is_windows_reparse_point(&metadata) {
        return Err(anyhow!(
            "guard known-bad cache {} is a reparse point",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "guard known-bad cache {} is not a regular file",
            path.display()
        ));
    }
    Ok(Some(metadata))
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn read_known_bad_cache_text(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<String> {
    if metadata.len() > MAX_KNOWN_BAD_CACHE_BYTES {
        anyhow::bail!(
            "guard known-bad cache {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_KNOWN_BAD_CACHE_BYTES
        );
    }
    let file = fs::File::open(path)
        .with_context(|| format!("unable to read guard known-bad cache {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("unable to read guard known-bad cache {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("guard known-bad cache {} size overflow", path.display()))?;
        if total > MAX_KNOWN_BAD_CACHE_BYTES {
            anyhow::bail!(
                "guard known-bad cache {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_KNOWN_BAD_CACHE_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("unable to read guard known-bad cache {}", path.display()))
}

fn normalize_hashes(values: Vec<String>) -> anyhow::Result<HashSet<String>> {
    let mut hashes = HashSet::new();
    for value in values {
        let Some(hash) = normalize_sha256(&value) else {
            anyhow::bail!("guard known-bad cache contains malformed SHA-256 value");
        };
        hashes.insert(hash);
    }
    Ok(hashes)
}

fn default_known_bad_path() -> anyhow::Result<PathBuf> {
    let mut roots = Vec::new();
    let current_exe = std::env::current_exe()
        .context("guard known-bad default cache discovery failed to resolve current executable")?;
    let parent = current_exe.parent().ok_or_else(|| {
        anyhow!(
            "guard known-bad default cache discovery found no parent for {}",
            current_exe.display()
        )
    })?;
    push_known_bad_root(&mut roots, parent)?;

    #[cfg(debug_assertions)]
    {
        let current_dir = std::env::current_dir()
            .context("guard known-bad default cache discovery failed to read current directory")?;
        if is_guard_development_root(&current_dir)? {
            push_known_bad_root(&mut roots, &current_dir)?;
        }
    }

    for root in &roots {
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
            if ensure_known_bad_cache_file(&candidate)?.is_some() {
                return Ok(candidate);
            }
        }
    }
    let root = roots.first().ok_or_else(|| {
        anyhow!("guard known-bad default cache discovery found no absolute root candidates")
    })?;
    Ok(root
        .join("assets")
        .join("test")
        .join("known_bad_test_hashes.json"))
}

fn push_known_bad_root(roots: &mut Vec<PathBuf>, root: &Path) -> anyhow::Result<()> {
    if !known_bad_root_is_allowed(root) {
        anyhow::bail!(
            "guard known-bad cache root {} must be an absolute local path",
            root.display()
        );
    }
    if !roots.iter().any(|existing| existing == root) {
        roots.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(windows)]
fn known_bad_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn known_bad_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(debug_assertions)]
fn is_guard_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_guard_service")
        .join("Cargo.toml");
    let metadata = match fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "unable to inspect guard known-bad development marker {}",
                    marker.display()
                )
            });
        }
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "guard known-bad development marker {} is a symbolic link",
            marker.display()
        );
    }
    if is_windows_reparse_point(&metadata) {
        anyhow::bail!(
            "guard known-bad development marker {} is a reparse point",
            marker.display()
        );
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "guard known-bad development marker {} is not a regular file",
            marker.display()
        );
    }
    Ok(true)
}

fn normalize_sha256(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let raw = sha256_body(trimmed);
    if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(raw.to_lowercase())
    } else {
        None
    }
}

fn sha256_body(trimmed: &str) -> &str {
    match trimmed.strip_prefix("sha256:") {
        Some(raw) => raw,
        None => trimmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const VALID_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn known_bad_cache_rejects_malformed_hashes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(
            &path,
            serde_json::json!({
                "hashes": ["", "abc123", format!("sha256:{VALID_HASH}")]
            })
            .to_string(),
        )
        .unwrap();

        let error = load_known_bad_hashes_from_path(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("guard known-bad cache contains malformed SHA-256 value"));
    }

    #[test]
    fn known_bad_cache_reports_corrupt_store_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(&path, "{not-json").unwrap();

        let error = load_known_bad_hashes_from_path(&path).unwrap_err();

        let error = error.to_string();

        assert!(error.contains("unable to parse guard known-bad cache"));
        assert!(error.contains("known_bad.json"));
    }

    #[test]
    fn known_bad_cache_accepts_explicit_description_metadata() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(
            &path,
            serde_json::json!({
                "hashes": [],
                "description": "safe test fixture"
            })
            .to_string(),
        )
        .unwrap();

        let hashes = load_known_bad_hashes_from_path(&path).unwrap();

        assert!(hashes.is_empty());
    }

    #[test]
    fn known_bad_cache_rejects_unknown_object_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(
            &path,
            serde_json::json!({
                "hashes": [],
                "description": "safe test fixture",
                "enabled": true
            })
            .to_string(),
        )
        .unwrap();

        let error = load_known_bad_hashes_from_path(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unable to parse guard known-bad cache"));
    }

    #[test]
    fn known_bad_cache_rejects_oversized_store_before_parse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::write(&path, "x".repeat(MAX_KNOWN_BAD_CACHE_BYTES as usize + 1)).unwrap();

        let error = load_known_bad_hashes_from_path(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("guard known-bad cache"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn known_bad_cache_missing_file_loads_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.json");

        let hashes = load_known_bad_hashes_from_path(&path).unwrap();

        assert!(hashes.is_empty());
    }

    #[test]
    fn known_bad_cache_rejects_directory_before_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_bad.json");
        fs::create_dir(&path).unwrap();

        let error = load_known_bad_hashes_from_path(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("guard known-bad cache"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn known_bad_cache_rejects_symbolic_link_before_read() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.json");
        let path = dir.path().join("known_bad.json");
        fs::write(&target, serde_json::json!({"hashes": []}).to_string()).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = load_known_bad_hashes_from_path(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("guard known-bad cache"));
        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn known_bad_cache_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("known_bad_cache.rs");
        let reader = &source[source.find("fn read_known_bad_cache_text").unwrap()
            ..source.find("fn normalize_hashes").unwrap()];

        assert!(source.contains(
            "fn ensure_known_bad_cache_file(path: &Path) -> anyhow::Result<Option<fs::Metadata>>"
        ));
        assert!(source.contains("let Some(metadata) = ensure_known_bad_cache_file(path)?"));
        assert!(reader.contains("metadata.len() > MAX_KNOWN_BAD_CACHE_BYTES"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > MAX_KNOWN_BAD_CACHE_BYTES"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
    }

    #[test]
    fn default_known_bad_path_uses_non_following_cache_checks() {
        let source = include_str!("known_bad_cache.rs");
        let start = source.find("fn default_known_bad_path").unwrap();
        let end = source.find("fn normalize_sha256").unwrap();
        let default_path_source = &source[start..end];

        assert!(default_path_source.contains("ensure_known_bad_cache_file(&candidate)?.is_some()"));
        assert!(default_path_source.contains("Ok(candidate)"));
        assert!(default_path_source.contains("std::env::current_exe()"));
        assert!(default_path_source.contains("push_known_bad_root(&mut roots"));
        assert!(default_path_source.contains("fn known_bad_root_is_allowed(path: &Path) -> bool"));
        assert!(default_path_source.contains("fn is_guard_development_root(root: &Path)"));
        assert!(!default_path_source.contains("candidate.is_file()"));
        assert!(!default_path_source
            .contains("PathBuf::from(\"assets/test/known_bad_test_hashes.json\")"));
        assert!(!default_path_source.contains("roots.push(current_dir)"));
    }

    #[test]
    fn default_known_bad_path_has_no_relative_fallback() {
        let source = include_str!("known_bad_cache.rs");
        let start = source.find("fn default_known_bad_path").unwrap();
        let end = source.find("fn normalize_sha256").unwrap();
        let default_path_source = &source[start..end];

        assert!(default_path_source.contains(
            "guard known-bad default cache discovery failed to resolve current executable"
        ));
        assert!(default_path_source
            .contains("guard known-bad cache root {} must be an absolute local path"));
        assert!(default_path_source.contains("#[cfg(debug_assertions)]"));
        assert!(default_path_source.contains("is_guard_development_root(&current_dir)?"));
        assert!(!default_path_source.contains("Ok(PathBuf::from("));
        assert!(!default_path_source.contains("if let Ok(current_dir) = std::env::current_dir()"));
    }

    #[test]
    fn known_bad_cache_hash_prefix_branch_is_explicit() {
        let source = include_str!("known_bad_cache.rs");
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let test_start = source.find("#[cfg(test)]").unwrap();
        let normalize_source = &source[normalize_start..test_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("match trimmed.strip_prefix(\"sha256:\")"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or"));
    }
}
