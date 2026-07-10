use std::fs;
use std::io::Read;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

pub(super) const MAX_NATIVE_TRUST_STORE_BYTES: u64 = 1024 * 1024;

pub(super) fn read_bounded_trust_store_text(path: &Path, label: &str) -> Result<String> {
    let metadata = ensure_regular_trust_store_file(path, label)?;
    if metadata.len() > MAX_NATIVE_TRUST_STORE_BYTES {
        anyhow::bail!(
            "{label} {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_NATIVE_TRUST_STORE_BYTES
        );
    }
    let mut file = fs::File::open(path)
        .with_context(|| format!("unable to read {label} {}", path.display()))?;
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    let mut bytes = Vec::new();
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("unable to read {label} {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("native trust store read size overflow"))?;
        if total > MAX_NATIVE_TRUST_STORE_BYTES {
            anyhow::bail!(
                "{label} {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_NATIVE_TRUST_STORE_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("{label} {} is not valid UTF-8", path.display()))
}

pub(super) fn trust_store_file_present(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_trust_store_metadata(path, label, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_regular_trust_store_file(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    ensure_regular_trust_store_metadata(path, label, &metadata)?;
    Ok(metadata)
}

fn ensure_regular_trust_store_metadata(
    path: &Path,
    label: &str,
    metadata: &fs::Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("{label} {} is a symbolic link", path.display()));
    }
    if is_windows_reparse_point(&metadata) {
        return Err(anyhow!("{label} {} is a reparse point", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!("{label} {} is not a regular file", path.display()));
    }
    if metadata.len() > MAX_NATIVE_TRUST_STORE_BYTES {
        anyhow::bail!(
            "{label} {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_NATIVE_TRUST_STORE_BYTES
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_trust_store_reader_rejects_directory_before_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-good.json");
        fs::create_dir(&path).unwrap();

        let error = read_bounded_trust_store_text(&path, "native known-good store")
            .unwrap_err()
            .to_string();

        assert!(error.contains("native known-good store"));
        assert!(error.contains("not a regular file"));
    }

    #[test]
    fn native_trust_store_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("store_io.rs");
        let start = source
            .find("pub(super) fn read_bounded_trust_store_text")
            .unwrap();
        let end = source
            .find("pub(super) fn trust_store_file_present")
            .unwrap();
        let read_source = &source[start..end];

        assert!(
            read_source.contains("let metadata = ensure_regular_trust_store_file(path, label)?")
        );
        assert!(read_source.contains("metadata.len() > MAX_NATIVE_TRUST_STORE_BYTES"));
        assert!(read_source.contains("let mut total = 0_u64"));
        assert!(read_source.contains("checked_add(read as u64)"));
        assert!(read_source.contains("total > MAX_NATIVE_TRUST_STORE_BYTES"));
        assert!(read_source.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(read_source.contains("String::from_utf8(bytes)"));
        assert!(source.contains(
            "fn ensure_regular_trust_store_file(path: &Path, label: &str) -> Result<fs::Metadata>"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn native_trust_store_reader_rejects_symbolic_link_before_read() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let path = dir.path().join("known-bad.json");
        fs::write(&target, r#"{"hashes":[]}"#).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = read_bounded_trust_store_text(&path, "native known-bad store")
            .unwrap_err()
            .to_string();

        assert!(error.contains("native known-bad store"));
        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn native_trust_store_missing_path_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");

        assert!(!trust_store_file_present(&path, "native known-good store").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn native_trust_store_presence_rejects_broken_symbolic_link() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("missing-target.json");
        let path = dir.path().join("known-good.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = trust_store_file_present(&path, "native known-good store")
            .unwrap_err()
            .to_string();

        assert!(error.contains("native known-good store"));
        assert!(error.contains("symbolic link"));
    }
}
