use std::fs;
use std::path::Path;

use anyhow::Result;

pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub fn read_scan_bytes(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_FILE_BYTES {
        let file = fs::File::open(path)?;
        let mut reader = std::io::Read::take(file, MAX_FILE_BYTES);
        let mut bytes = Vec::with_capacity(MAX_FILE_BYTES as usize);
        std::io::Read::read_to_end(&mut reader, &mut bytes)?;
        Ok(bytes)
    } else {
        Ok(fs::read(path)?)
    }
}
