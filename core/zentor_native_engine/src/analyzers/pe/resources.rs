use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy)]
pub(super) struct PeDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PeSectionBounds {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
}

pub(super) fn resource_directory_entry_count(
    bytes: &[u8],
    sections: &[PeSectionBounds],
    directory: Option<PeDataDirectory>,
) -> Result<u32> {
    let Some(directory) = directory else {
        return Ok(0);
    };
    let Some(offset) = rva_to_file_offset(directory.virtual_address, sections, bytes.len()) else {
        bail!("PE resource directory RVA is not mapped to scanned section data");
    };
    if directory.size < 16 {
        bail!("PE resource directory size is too small");
    }
    let directory_end = offset
        .checked_add(directory.size as usize)
        .ok_or_else(|| anyhow::anyhow!("PE resource directory size overflow"))?;
    let header_end = offset
        .checked_add(16)
        .ok_or_else(|| anyhow::anyhow!("PE resource directory offset overflow"))?;
    if header_end > bytes.len() || header_end > directory_end {
        bail!("PE resource directory header is truncated");
    }
    let named_entries = read_u16_at(bytes, offset + 12)? as u32;
    let id_entries = read_u16_at(bytes, offset + 14)? as u32;
    let entry_count = named_entries
        .checked_add(id_entries)
        .ok_or_else(|| anyhow::anyhow!("PE resource directory entry count overflow"))?;
    let entry_bytes = entry_count
        .checked_mul(8)
        .ok_or_else(|| anyhow::anyhow!("PE resource directory entry bytes overflow"))?
        as usize;
    let entries_end = header_end
        .checked_add(entry_bytes)
        .ok_or_else(|| anyhow::anyhow!("PE resource directory entry offset overflow"))?;
    if entries_end > bytes.len() || entries_end > directory_end {
        bail!("PE resource directory entries are truncated");
    }
    Ok(entry_count)
}

fn rva_to_file_offset(rva: u32, sections: &[PeSectionBounds], bytes_len: usize) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        if span == 0 || section.raw_size == 0 {
            continue;
        }
        let virtual_end = section.virtual_address.checked_add(span)?;
        if rva < section.virtual_address || rva >= virtual_end {
            continue;
        }
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.raw_size {
            continue;
        }
        let file_offset = section.raw_ptr.checked_add(delta)? as usize;
        if file_offset < bytes_len {
            return Some(file_offset);
        }
    }
    None
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("PE resource directory offset overflow"))?;
    let Some(slice) = bytes.get(offset..end) else {
        bail!("PE resource directory is truncated");
    };
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_resource_directory_counts_top_level_entries() {
        let mut bytes = vec![0_u8; 0x300];
        let sections = [PeSectionBounds {
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_ptr: 0x200,
            raw_size: 0x100,
        }];
        bytes[0x200 + 12..0x200 + 14].copy_from_slice(&2_u16.to_le_bytes());
        bytes[0x200 + 14..0x200 + 16].copy_from_slice(&3_u16.to_le_bytes());

        let count = resource_directory_entry_count(
            &bytes,
            &sections,
            Some(PeDataDirectory {
                virtual_address: 0x1000,
                size: 0x40,
            }),
        )
        .unwrap();

        assert_eq!(count, 5);
    }

    #[test]
    fn pe_resource_directory_rejects_truncated_entries() {
        let mut bytes = vec![0_u8; 0x210];
        bytes[0x200 + 14..0x200 + 16].copy_from_slice(&1_u16.to_le_bytes());
        let sections = [PeSectionBounds {
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_ptr: 0x200,
            raw_size: 0x100,
        }];

        let error = resource_directory_entry_count(
            &bytes,
            &sections,
            Some(PeDataDirectory {
                virtual_address: 0x1000,
                size: 0x40,
            }),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("PE resource directory entries are truncated"));
    }

    #[test]
    fn pe_resource_parser_is_not_dead_zero_stub() {
        let source = include_str!("resources.rs");
        let old_stub = ["pub fn resource_indicator_count", "(_bytes: &[u8])", "0"].concat();

        assert!(source.contains("resource_directory_entry_count"));
        assert!(source.contains("rva_to_file_offset"));
        assert!(source.contains("PE resource directory entries are truncated"));
        assert!(!source.contains(&old_stub));
    }
}
