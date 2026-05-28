use anyhow::{bail, Result};

use super::ArchiveAnalysis;

const MAX_ENTRIES: u32 = 256;

pub fn analyze_zip(bytes: &[u8]) -> Result<ArchiveAnalysis> {
    let mut offset = 0usize;
    let mut result = ArchiveAnalysis::default();
    while offset + 30 <= bytes.len() {
        if &bytes[offset..offset + 4] != b"PK\x03\x04" {
            break;
        }
        if result.entry_count >= MAX_ENTRIES {
            result.limit_exceeded = true;
            break;
        }
        let compressed_size = u32::from_le_bytes([
            bytes[offset + 18],
            bytes[offset + 19],
            bytes[offset + 20],
            bytes[offset + 21],
        ]) as usize;
        let name_len = u16::from_le_bytes([bytes[offset + 26], bytes[offset + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;
        let name_start = offset + 30;
        let name_end = name_start.saturating_add(name_len);
        if name_end > bytes.len() {
            bail!("invalid zip entry name length");
        }
        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).to_ascii_lowercase();
        if name.contains("../") || name.contains("..\\") || name.starts_with('/') {
            result.zip_slip_blocked = true;
        }
        if matches!(
            name.rsplit('.').next().unwrap_or_default(),
            "exe" | "dll" | "scr" | "ps1" | "bat" | "cmd" | "vbs" | "js"
        ) {
            result.contains_executable = true;
        }
        if name.contains("invoice") && (name.ends_with(".exe") || name.ends_with(".scr")) {
            result.suspicious_nested_name_count += 1;
        }
        result.entry_count += 1;
        offset = name_end
            .saturating_add(extra_len)
            .saturating_add(compressed_size);
    }
    Ok(result)
}
