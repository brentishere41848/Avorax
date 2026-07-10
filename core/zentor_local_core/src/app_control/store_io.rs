#![allow(dead_code)]

use std::fs;
use std::io::Read;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};

pub(super) const MAX_APP_CONTROL_TRUST_STORE_BYTES: u64 = 1024 * 1024;

pub(super) fn default_app_control_asset_path(parts: &[&str]) -> anyhow::Result<PathBuf> {
    let mut roots = Vec::new();
    let current_exe = std::env::current_exe().context(
        "local app-control default trust-store discovery failed to resolve current executable",
    )?;
    let parent = current_exe.parent().ok_or_else(|| {
        anyhow!(
            "local app-control default trust-store discovery found no parent for {}",
            current_exe.display()
        )
    })?;
    push_app_control_asset_root(&mut roots, parent)?;

    #[cfg(debug_assertions)]
    {
        let current_dir = std::env::current_dir().context(
            "local app-control default trust-store discovery failed to read current directory",
        )?;
        if is_local_core_development_root(&current_dir)? {
            push_app_control_asset_root(&mut roots, &current_dir)?;
        }
    }

    for root in &roots {
        for candidate in [
            join_asset_parts(root, parts),
            join_asset_parts(&root.join("..").join(".."), parts),
        ] {
            if store_file_present(&candidate, "local app-control default trust store")? {
                return Ok(candidate);
            }
        }
    }
    let root = roots.first().ok_or_else(|| {
        anyhow!("local app-control default trust-store discovery found no absolute root candidates")
    })?;
    Ok(join_asset_parts(root, parts))
}

pub(super) fn read_bounded_store_text(path: &Path, label: &str) -> anyhow::Result<String> {
    let metadata = ensure_regular_store_file(path, label)?;
    if metadata.len() > MAX_APP_CONTROL_TRUST_STORE_BYTES {
        anyhow::bail!(
            "{label} {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_APP_CONTROL_TRUST_STORE_BYTES
        );
    }
    let file = fs::File::open(path)
        .with_context(|| format!("unable to read {label} {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("unable to read {label} {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("{label} {} size overflow", path.display()))?;
        if total > MAX_APP_CONTROL_TRUST_STORE_BYTES {
            anyhow::bail!(
                "{label} {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_APP_CONTROL_TRUST_STORE_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes).with_context(|| format!("unable to read {label} {}", path.display()))
}

fn store_file_present(path: &Path, label: &str) -> anyhow::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("unable to inspect {label} {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("{label} {} is a symbolic link", path.display()));
    }
    if is_windows_reparse_point(&metadata) {
        return Err(anyhow!("{label} {} is a reparse point", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!("{label} {} is not a regular file", path.display()));
    }
    Ok(true)
}

fn ensure_regular_store_file(path: &Path, label: &str) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("{label} {} is a symbolic link", path.display()));
    }
    if is_windows_reparse_point(&metadata) {
        return Err(anyhow!("{label} {} is a reparse point", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!("{label} {} is not a regular file", path.display()));
    }
    Ok(metadata)
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

fn push_app_control_asset_root(roots: &mut Vec<PathBuf>, root: &Path) -> anyhow::Result<()> {
    if !app_control_asset_root_is_allowed(root) {
        anyhow::bail!(
            "local app-control default trust-store root {} must be an absolute local path",
            root.display()
        );
    }
    if !roots.iter().any(|existing| existing == root) {
        roots.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(windows)]
fn app_control_asset_root_is_allowed(path: &Path) -> bool {
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
fn app_control_asset_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(debug_assertions)]
fn is_local_core_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_local_core")
        .join("Cargo.toml");
    store_file_present(&marker, "local app-control development marker")
}

fn join_asset_parts(root: &Path, parts: &[&str]) -> PathBuf {
    let mut path = root.to_path_buf();
    for part in parts {
        path = path.join(part);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_control_store_reader_rejects_directory_before_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-good.json");
        fs::create_dir(&path).unwrap();

        let error = read_bounded_store_text(&path, "known-good store")
            .unwrap_err()
            .to_string();

        assert!(error.contains("known-good store"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn app_control_store_reader_rejects_symbolic_link_before_read() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let path = dir.path().join("known-bad.json");
        fs::write(&target, r#"{"hashes":[]}"#).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = read_bounded_store_text(&path, "known-bad store")
            .unwrap_err()
            .to_string();

        assert!(error.contains("known-bad store"));
        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn app_control_store_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("store_io.rs");
        let reader = &source[source
            .find("pub(super) fn read_bounded_store_text")
            .unwrap()..source.find("fn store_file_present").unwrap()];

        assert!(reader.contains("let metadata = ensure_regular_store_file(path, label)?"));
        assert!(reader.contains("metadata.len() > MAX_APP_CONTROL_TRUST_STORE_BYTES"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > MAX_APP_CONTROL_TRUST_STORE_BYTES"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
        assert!(source.contains(
            "fn ensure_regular_store_file(path: &Path, label: &str) -> anyhow::Result<fs::Metadata>"
        ));
    }

    #[test]
    fn default_app_control_asset_path_has_no_relative_fallbacks() {
        let source = include_str!("store_io.rs");
        let start = source
            .find("pub(super) fn default_app_control_asset_path")
            .unwrap();
        let end = source
            .find("pub(super) fn read_bounded_store_text")
            .unwrap();
        let default_path_source = &source[start..end];

        assert!(default_path_source.contains("std::env::current_exe()"));
        assert!(default_path_source.contains(
            "local app-control default trust-store discovery failed to resolve current executable"
        ));
        assert!(default_path_source.contains("push_app_control_asset_root(&mut roots, parent)?"));
        assert!(default_path_source.contains("#[cfg(debug_assertions)]"));
        assert!(default_path_source.contains("is_local_core_development_root(&current_dir)?"));
        assert!(default_path_source.contains("store_file_present(&candidate"));
        assert!(default_path_source.contains("let root = roots.first().ok_or_else"));
        assert!(!default_path_source.contains("PathBuf::from(\"assets/"));
        assert!(!default_path_source.contains("if let Ok(current_dir) = std::env::current_dir()"));
        assert!(!default_path_source.contains("roots.push(current_dir)"));
    }
}
