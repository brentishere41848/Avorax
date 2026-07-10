use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ScanContent {
    pub sampled_bytes: Vec<u8>,
    pub full_sha256: String,
    pub file_size_bytes: u64,
    pub scanned_bytes: u64,
    pub sample_limited: bool,
}

pub fn read_scan_content(path: &Path) -> Result<ScanContent> {
    let metadata = ensure_regular_scan_content_file(path)?;
    let file_size_bytes = metadata.len();
    let sample_limit = MAX_FILE_BYTES.min(file_size_bytes) as usize;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut sampled_bytes = Vec::with_capacity(sample_limit);
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut bytes_read_total = 0_u64;

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if sampled_bytes.len() < sample_limit {
            let remaining_sample = sample_limit - sampled_bytes.len();
            sampled_bytes.write_all(&buffer[..read.min(remaining_sample)])?;
        }
        bytes_read_total += read as u64;
    }

    Ok(ScanContent {
        sampled_bytes,
        full_sha256: format!("{:x}", hasher.finalize()),
        file_size_bytes,
        scanned_bytes: sample_limit as u64,
        sample_limited: bytes_read_total > MAX_FILE_BYTES,
    })
}

pub fn read_scan_bytes(path: &Path) -> Result<Vec<u8>> {
    Ok(read_scan_content(path)?.sampled_bytes)
}

fn ensure_regular_scan_content_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect scan content {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to read symbolic link scan content {}",
            path.display()
        );
    }
    if scan_content_metadata_is_windows_reparse_point(&metadata) {
        anyhow::bail!(
            "refusing to read reparse point scan content {}",
            path.display()
        );
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("scan content is not a regular file {}", path.display());
    }
    Ok(metadata)
}

#[cfg(windows)]
fn scan_content_metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn scan_content_metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::read_scan_content;
    #[cfg(unix)]
    use std::fs;

    #[cfg(unix)]
    #[test]
    fn native_scan_content_rejects_symbolic_links() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.bin");
        let link = temp.path().join("linked.bin");
        fs::write(&target, b"benign fixture").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let error = read_scan_content(&link).expect_err("linked scan content should fail");

        assert!(error.to_string().contains("symbolic link"));
    }

    #[test]
    fn native_scan_content_uses_non_following_metadata() {
        let source = include_str!("content_reader.rs");
        let helper_pattern = ["fn ensure_regular_scan_", "content_file"].concat();
        let helper_call_pattern = ["ensure_regular_scan_", "content_file(path)?"].concat();
        let symlink_metadata_pattern = ["fs::", "symlink_metadata(path)"].concat();
        let symlink_error_pattern = ["refusing to read symbolic link ", "scan content"].concat();
        let reparse_error_pattern = ["refusing to read reparse point ", "scan content"].concat();
        let old_metadata_pattern = ["fs::", "metadata(path)"].concat();

        assert!(source.contains(&helper_pattern));
        assert!(source.contains(&helper_call_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&symlink_error_pattern));
        assert!(source.contains(&reparse_error_pattern));
        assert!(!source.contains(&old_metadata_pattern));
    }
}
