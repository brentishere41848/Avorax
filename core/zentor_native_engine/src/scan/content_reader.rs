use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::Result;
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
    let metadata = fs::metadata(path)?;
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
