use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::cancellation::check_scan_cancellation;

pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SCAN_CONTENT_BYTES: u64 = 1024 * 1024 * 1024;
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
    let mut never_cancel = || Ok(false);
    read_scan_content_with_limit_and_cancellation(path, MAX_SCAN_CONTENT_BYTES, &mut never_cancel)
}

pub fn read_scan_content_with_limit(path: &Path, max_total_bytes: u64) -> Result<ScanContent> {
    let mut never_cancel = || Ok(false);
    read_scan_content_with_limit_and_cancellation(path, max_total_bytes, &mut never_cancel)
}

pub(crate) fn read_scan_content_with_cancellation(
    path: &Path,
    should_cancel: &mut dyn FnMut() -> Result<bool>,
) -> Result<ScanContent> {
    read_scan_content_with_limit_and_cancellation(path, MAX_SCAN_CONTENT_BYTES, should_cancel)
}

fn read_scan_content_with_limit_and_cancellation(
    path: &Path,
    max_total_bytes: u64,
    should_cancel: &mut dyn FnMut() -> Result<bool>,
) -> Result<ScanContent> {
    check_scan_cancellation(should_cancel, "content preflight")?;
    let metadata = ensure_regular_scan_content_file(path)?;
    let file_size_bytes = metadata.len();
    ensure_scan_content_size_within_limit(path, file_size_bytes, max_total_bytes)?;
    let sample_limit = MAX_FILE_BYTES.min(file_size_bytes) as usize;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut sampled_bytes = Vec::with_capacity(sample_limit);
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut bytes_read_total = 0_u64;

    loop {
        check_scan_cancellation(should_cancel, "content hashing")?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let next_total = bytes_read_total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("scan content byte count overflow"))?;
        if next_total > max_total_bytes {
            anyhow::bail!(
                "scan content {} grew beyond total read limit of {} bytes",
                path.display(),
                max_total_bytes
            );
        }
        hasher.update(&buffer[..read]);
        if sampled_bytes.len() < sample_limit {
            let remaining_sample = sample_limit - sampled_bytes.len();
            sampled_bytes.write_all(&buffer[..read.min(remaining_sample)])?;
        }
        bytes_read_total = next_total;
    }
    check_scan_cancellation(should_cancel, "content hash completion")?;

    Ok(ScanContent {
        sampled_bytes,
        full_sha256: format!("{:x}", hasher.finalize()),
        file_size_bytes,
        scanned_bytes: sample_limit as u64,
        sample_limited: bytes_read_total > MAX_FILE_BYTES,
    })
}

fn ensure_scan_content_size_within_limit(
    path: &Path,
    file_size_bytes: u64,
    max_total_bytes: u64,
) -> Result<()> {
    if file_size_bytes > max_total_bytes {
        anyhow::bail!(
            "scan content {} exceeds total read limit of {} bytes",
            path.display(),
            max_total_bytes
        );
    }
    Ok(())
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
    use super::{read_scan_content_with_cancellation, HASH_BUFFER_BYTES};
    use std::fs;
    use std::path::Path;

    #[test]
    fn scan_inspection_resource_budget_standard_read_limit_is_one_gib() {
        assert_eq!(super::MAX_SCAN_CONTENT_BYTES, 1024 * 1024 * 1024);
        super::ensure_scan_content_size_within_limit(
            Path::new("exact-limit-benign.bin"),
            super::MAX_SCAN_CONTENT_BYTES,
            super::MAX_SCAN_CONTENT_BYTES,
        )
        .expect("the exact standard scan limit must remain admitted");

        let error = super::ensure_scan_content_size_within_limit(
            Path::new("oversized-benign.bin"),
            super::MAX_SCAN_CONTENT_BYTES + 1,
            super::MAX_SCAN_CONTENT_BYTES,
        )
        .expect_err("one byte over the standard scan limit must fail before file I/O");

        assert!(error.to_string().contains("exceeds total read limit"));
        assert!(error
            .to_string()
            .contains(&super::MAX_SCAN_CONTENT_BYTES.to_string()));
    }

    #[test]
    fn scan_inspection_resource_budget_standard_entrypoints_share_limit() {
        let source = include_str!("content_reader.rs");
        let start = source.find("pub fn read_scan_content(").unwrap();
        let end = source
            .find("fn read_scan_content_with_limit_and_cancellation(")
            .unwrap();
        let entrypoints = &source[start..end];

        assert_eq!(entrypoints.matches("MAX_SCAN_CONTENT_BYTES").count(), 2);
        assert!(!entrypoints.contains("u64::MAX"));
    }

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

    #[test]
    fn native_scan_content_total_read_limit_rejects_oversized_metadata() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("oversized-benign.bin");
        let file = fs::File::create(&target).expect("fixture");
        file.set_len(4097).expect("sparse fixture size");

        let error = super::read_scan_content_with_limit(&target, 4096)
            .expect_err("oversized fixture must fail before content read");

        assert!(error.to_string().contains("exceeds total read limit"));
    }

    #[test]
    fn cooperative_scan_cancellation_interrupts_bounded_hash_reads() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("large-benign-content.bin");
        let file = fs::File::create(&target).expect("fixture");
        file.set_len((HASH_BUFFER_BYTES * 3) as u64)
            .expect("sparse benign fixture size");
        let mut checks = 0_u32;
        let mut should_cancel = || {
            checks += 1;
            Ok(checks >= 3)
        };

        let error = read_scan_content_with_cancellation(&target, &mut should_cancel)
            .expect_err("content read must stop at a cancellation checkpoint");

        assert!(super::super::cancellation::is_cooperative_scan_cancellation(&error));
        assert_eq!(checks, 3);
    }

    #[test]
    fn cooperative_scan_cancellation_surfaces_probe_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("benign-content.bin");
        fs::write(&target, b"benign fixture").expect("fixture");
        let mut should_cancel = || anyhow::bail!("bounded probe failure");

        let error = read_scan_content_with_cancellation(&target, &mut should_cancel)
            .expect_err("probe failure must remain visible");

        assert!(super::super::cancellation::is_scan_cancellation_check_failure(&error));
        assert!(error.to_string().contains("bounded probe failure"));
    }
}
