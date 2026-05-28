use serde::{Deserialize, Serialize};

use super::imports::ImportCategories;
use crate::analyzers::entropy::entropy;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeAnalysis {
    pub section_count: u16,
    pub high_entropy_section_count: u16,
    pub suspicious_imports: ImportCategories,
    pub has_debug_info: bool,
    pub certificate_table_present: bool,
    pub overlay_size: u64,
}

pub fn parse_pe(bytes: &[u8]) -> PeAnalysis {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return PeAnalysis::default();
    }
    let pe_offset = u32::from_le_bytes([
        bytes.get(0x3c).copied().unwrap_or_default(),
        bytes.get(0x3d).copied().unwrap_or_default(),
        bytes.get(0x3e).copied().unwrap_or_default(),
        bytes.get(0x3f).copied().unwrap_or_default(),
    ]) as usize;
    if pe_offset + 24 >= bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return PeAnalysis::default();
    }
    let section_count = u16::from_le_bytes([
        bytes.get(pe_offset + 6).copied().unwrap_or_default(),
        bytes.get(pe_offset + 7).copied().unwrap_or_default(),
    ]);
    let optional_header_size = u16::from_le_bytes([
        bytes.get(pe_offset + 20).copied().unwrap_or_default(),
        bytes.get(pe_offset + 21).copied().unwrap_or_default(),
    ]) as usize;
    let section_table = pe_offset + 24 + optional_header_size;
    let mut high_entropy_section_count = 0;
    let mut max_section_end = 0usize;
    for index in 0..section_count as usize {
        let offset = section_table + index * 40;
        if offset + 40 > bytes.len() {
            break;
        }
        let raw_size = u32::from_le_bytes([
            bytes[offset + 16],
            bytes[offset + 17],
            bytes[offset + 18],
            bytes[offset + 19],
        ]) as usize;
        let raw_ptr = u32::from_le_bytes([
            bytes[offset + 20],
            bytes[offset + 21],
            bytes[offset + 22],
            bytes[offset + 23],
        ]) as usize;
        let end = raw_ptr.saturating_add(raw_size).min(bytes.len());
        if raw_ptr < end {
            if entropy(&bytes[raw_ptr..end]) > 7.2 {
                high_entropy_section_count += 1;
            }
            max_section_end = max_section_end.max(end);
        }
    }
    let overlay_size = bytes.len().saturating_sub(max_section_end) as u64;
    PeAnalysis {
        section_count,
        high_entropy_section_count,
        suspicious_imports: super::imports::categorize_imports(bytes),
        has_debug_info: bytes.windows(4).any(|w| w.eq_ignore_ascii_case(b".pdb")),
        certificate_table_present: false,
        overlay_size,
    }
}
