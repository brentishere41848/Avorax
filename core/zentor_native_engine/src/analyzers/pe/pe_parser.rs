use serde::{Deserialize, Serialize};

use anyhow::{bail, Result};

use super::imports::ImportCategories;
use super::resources::{PeDataDirectory, PeSectionBounds};
use crate::analyzers::entropy::entropy;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeAnalysis {
    pub section_count: u16,
    pub high_entropy_section_count: u16,
    pub suspicious_imports: ImportCategories,
    pub has_debug_info: bool,
    pub certificate_table_present: bool,
    #[serde(default)]
    pub resource_directory_entry_count: u32,
    pub overlay_size: u64,
}

pub fn parse_pe(bytes: &[u8]) -> Result<PeAnalysis> {
    if !bytes.starts_with(b"MZ") {
        bail!("PE file is missing MZ header");
    }
    if bytes.len() < 0x40 {
        bail!("PE file is too small for DOS header");
    }
    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    if pe_offset
        .checked_add(24)
        .filter(|end| *end <= bytes.len())
        .is_none()
    {
        bail!("PE header is outside the scanned bytes");
    }
    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        bail!("PE file is missing PE signature");
    }
    let section_count = read_u16(bytes, pe_offset + 6)?;
    let optional_header_size = read_u16(bytes, pe_offset + 20)? as usize;
    let optional_header_start = pe_offset
        .checked_add(24)
        .ok_or_else(|| anyhow::anyhow!("PE optional header offset overflow"))?;
    let section_table = optional_header_start
        .checked_add(optional_header_size)
        .ok_or_else(|| anyhow::anyhow!("PE section table offset overflow"))?;
    if section_table > bytes.len() {
        bail!("PE optional header is truncated");
    }
    let certificate_table_present =
        pe_data_directory(bytes, optional_header_start, optional_header_size, 4)?.is_some();
    let resource_directory =
        pe_data_directory(bytes, optional_header_start, optional_header_size, 2)?;
    let mut high_entropy_section_count = 0;
    let mut max_section_end = 0usize;
    let mut sections = Vec::with_capacity(section_count as usize);
    for index in 0..section_count as usize {
        let offset = section_table + index * 40;
        if offset + 40 > bytes.len() {
            bail!("PE section table is truncated");
        }
        let virtual_size = read_u32(bytes, offset + 8)?;
        let virtual_address = read_u32(bytes, offset + 12)?;
        let raw_size = read_u32(bytes, offset + 16)?;
        let raw_ptr = read_u32(bytes, offset + 20)?;
        sections.push(PeSectionBounds {
            virtual_address,
            virtual_size,
            raw_ptr,
            raw_size,
        });
        let raw_size = raw_size as usize;
        let raw_ptr = raw_ptr as usize;
        let end = raw_ptr.saturating_add(raw_size).min(bytes.len());
        if raw_ptr < end {
            if entropy(&bytes[raw_ptr..end]) > 7.2 {
                high_entropy_section_count += 1;
            }
            max_section_end = max_section_end.max(end);
        }
    }
    let overlay_size = bytes.len().saturating_sub(max_section_end) as u64;
    let resource_directory_entry_count =
        super::resources::resource_directory_entry_count(bytes, &sections, resource_directory)?;
    Ok(PeAnalysis {
        section_count,
        high_entropy_section_count,
        suspicious_imports: super::imports::categorize_imports(bytes),
        has_debug_info: bytes.windows(4).any(|w| w.eq_ignore_ascii_case(b".pdb")),
        certificate_table_present,
        resource_directory_entry_count,
        overlay_size,
    })
}

fn pe_data_directory(
    bytes: &[u8],
    optional_header_start: usize,
    optional_header_size: usize,
    index: usize,
) -> Result<Option<PeDataDirectory>> {
    let Some((directory_count_offset, directory_base)) =
        pe_data_directory_layout(bytes, optional_header_start, optional_header_size)?
    else {
        return Ok(None);
    };
    let directory_count = read_u32(bytes, directory_count_offset)? as usize;
    if index >= directory_count {
        return Ok(None);
    }
    let entry_offset = directory_base
        .checked_add(
            index
                .checked_mul(8)
                .ok_or_else(|| anyhow::anyhow!("PE data directory index overflow"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("PE data directory offset overflow"))?;
    let entry_end = entry_offset
        .checked_add(8)
        .ok_or_else(|| anyhow::anyhow!("PE data directory entry overflow"))?;
    let optional_header_end = optional_header_start
        .checked_add(optional_header_size)
        .ok_or_else(|| anyhow::anyhow!("PE optional header offset overflow"))?;
    if entry_end > optional_header_end || entry_end > bytes.len() {
        bail!("PE data directory entry is truncated");
    }
    let virtual_address = read_u32(bytes, entry_offset)?;
    let size = read_u32(bytes, entry_offset + 4)?;
    if virtual_address == 0 || size == 0 {
        return Ok(None);
    }
    Ok(Some(PeDataDirectory {
        virtual_address,
        size,
    }))
}

fn pe_data_directory_layout(
    bytes: &[u8],
    optional_header_start: usize,
    optional_header_size: usize,
) -> Result<Option<(usize, usize)>> {
    const PE32_MAGIC: u16 = 0x10b;
    const PE32_PLUS_MAGIC: u16 = 0x20b;
    const PE32_DIRECTORY_COUNT_OFFSET: usize = 92;
    const PE32_DIRECTORY_BASE: usize = 96;
    const PE32_PLUS_DIRECTORY_COUNT_OFFSET: usize = 108;
    const PE32_PLUS_DIRECTORY_BASE: usize = 112;

    let magic = read_u16(bytes, optional_header_start)?;
    let (count_relative, base_relative) = match magic {
        PE32_MAGIC => (PE32_DIRECTORY_COUNT_OFFSET, PE32_DIRECTORY_BASE),
        PE32_PLUS_MAGIC => (PE32_PLUS_DIRECTORY_COUNT_OFFSET, PE32_PLUS_DIRECTORY_BASE),
        _ => bail!("PE optional header has unsupported magic"),
    };
    let optional_header_end = optional_header_start
        .checked_add(optional_header_size)
        .ok_or_else(|| anyhow::anyhow!("PE optional header offset overflow"))?;
    let count_offset = optional_header_start
        .checked_add(count_relative)
        .ok_or_else(|| anyhow::anyhow!("PE data directory count offset overflow"))?;
    let directory_base = optional_header_start
        .checked_add(base_relative)
        .ok_or_else(|| anyhow::anyhow!("PE data directory base offset overflow"))?;
    let count_end = count_offset
        .checked_add(4)
        .ok_or_else(|| anyhow::anyhow!("PE data directory count overflow"))?;
    if count_end > optional_header_end || directory_base > optional_header_end {
        return Ok(None);
    }
    if count_end > bytes.len() || directory_base > bytes.len() {
        bail!("PE optional header is truncated");
    }
    Ok(Some((count_offset, directory_base)))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("PE offset overflow"))?;
    let Some(slice) = bytes.get(offset..end) else {
        bail!("PE header is truncated");
    };
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow::anyhow!("PE offset overflow"))?;
    let Some(slice) = bytes.get(offset..end) else {
        bail!("PE header is truncated");
    };
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pe_reports_truncated_mz_header() {
        let error = parse_pe(b"MZ").unwrap_err().to_string();

        assert!(error.contains("PE file is too small for DOS header"));
    }

    #[test]
    fn parse_pe_reports_certificate_and_resource_directory_entries() {
        let bytes = pe_with_resource_and_certificate_directories();
        let analysis = parse_pe(&bytes).unwrap();

        assert!(analysis.certificate_table_present);
        assert_eq!(analysis.resource_directory_entry_count, 5);
    }

    #[test]
    fn pe_parser_does_not_default_certificate_or_resources_to_false_zero() {
        let source = include_str!("pe_parser.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let old_certificate_default = ["certificate_table_present:", " false"].concat();
        let old_resource_default = ["resource_directory_entry_count:", " 0"].concat();

        assert!(production
            .contains("pe_data_directory(bytes, optional_header_start, optional_header_size, 4)?"));
        assert!(production
            .contains("resource_directory_entry_count(bytes, &sections, resource_directory)?"));
        assert!(!production.contains(&old_certificate_default));
        assert!(!production.contains(&old_resource_default));
    }

    fn pe_with_resource_and_certificate_directories() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x340];
        bytes[0..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        write_u16(&mut bytes, 0x80 + 6, 1);
        write_u16(&mut bytes, 0x80 + 20, 0xe0);

        let optional = 0x80 + 24;
        write_u16(&mut bytes, optional, 0x10b);
        write_u32(&mut bytes, optional + 92, 16);
        write_u32(&mut bytes, optional + 96 + 2 * 8, 0x1000);
        write_u32(&mut bytes, optional + 96 + 2 * 8 + 4, 0x40);
        write_u32(&mut bytes, optional + 96 + 4 * 8, 0x300);
        write_u32(&mut bytes, optional + 96 + 4 * 8 + 4, 0x20);

        let section = optional + 0xe0;
        write_u32(&mut bytes, section + 8, 0x200);
        write_u32(&mut bytes, section + 12, 0x1000);
        write_u32(&mut bytes, section + 16, 0x100);
        write_u32(&mut bytes, section + 20, 0x200);

        write_u16(&mut bytes, 0x200 + 12, 2);
        write_u16(&mut bytes, 0x200 + 14, 3);
        bytes
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
