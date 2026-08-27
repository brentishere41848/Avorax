use anyhow::{bail, Result};

const PE_RESOURCE_SECTION_CANCELLATION_CHUNK_ENTRIES: usize = 4 * 1024;

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

pub(super) fn resource_directory_entry_count_with_cancellation(
    bytes: &[u8],
    sections: &[PeSectionBounds],
    directory: Option<PeDataDirectory>,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    cancellation_checkpoint()?;
    let Some(directory) = directory else {
        return Ok(0);
    };
    let Some(offset) = rva_to_file_offset_with_cancellation(
        directory.virtual_address,
        sections,
        bytes.len(),
        cancellation_checkpoint,
    )?
    else {
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

fn rva_to_file_offset_with_cancellation(
    rva: u32,
    sections: &[PeSectionBounds],
    bytes_len: usize,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<Option<usize>> {
    for (index, section) in sections.iter().enumerate() {
        if index % PE_RESOURCE_SECTION_CANCELLATION_CHUNK_ENTRIES == 0 {
            cancellation_checkpoint()?;
        }
        let span = section.virtual_size.max(section.raw_size);
        if span == 0 || section.raw_size == 0 {
            continue;
        }
        let Some(virtual_end) = section.virtual_address.checked_add(span) else {
            return Ok(None);
        };
        if rva < section.virtual_address || rva >= virtual_end {
            continue;
        }
        let Some(delta) = rva.checked_sub(section.virtual_address) else {
            return Ok(None);
        };
        if delta >= section.raw_size {
            continue;
        }
        let Some(file_offset) = section
            .raw_ptr
            .checked_add(delta)
            .map(|value| value as usize)
        else {
            return Ok(None);
        };
        if file_offset < bytes_len {
            return Ok(Some(file_offset));
        }
    }
    cancellation_checkpoint()?;
    Ok(None)
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

        let mut never_cancel = || Ok(());
        let count = resource_directory_entry_count_with_cancellation(
            &bytes,
            &sections,
            Some(PeDataDirectory {
                virtual_address: 0x1000,
                size: 0x40,
            }),
            &mut never_cancel,
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

        let mut never_cancel = || Ok(());
        let error = resource_directory_entry_count_with_cancellation(
            &bytes,
            &sections,
            Some(PeDataDirectory {
                virtual_address: 0x1000,
                size: 0x40,
            }),
            &mut never_cancel,
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

    #[test]
    fn pe_resource_section_cancellation_interrupts_rva_mapping_chunks() {
        let sections = vec![
            PeSectionBounds {
                virtual_address: 0,
                virtual_size: 0,
                raw_ptr: 0,
                raw_size: 0,
            };
            PE_RESOURCE_SECTION_CANCELLATION_CHUNK_ENTRIES + 1
        ];
        let mut calls = 0usize;
        let mut checkpoint = || {
            calls += 1;
            if calls == 3 {
                anyhow::bail!("benign PE resource section cancellation")
            }
            Ok(())
        };

        let error = resource_directory_entry_count_with_cancellation(
            &[0_u8; 16],
            &sections,
            Some(PeDataDirectory {
                virtual_address: 0x7000_0000,
                size: 16,
            }),
            &mut checkpoint,
        )
        .expect_err("resource section traversal cancellation must abort RVA mapping");

        assert_eq!(calls, 3);
        assert!(error
            .to_string()
            .contains("benign PE resource section cancellation"));
    }

    #[test]
    fn pe_resource_section_cancellation_preserves_resource_count_semantics() {
        let mut bytes = vec![0_u8; 0x300];
        let sections = [PeSectionBounds {
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_ptr: 0x200,
            raw_size: 0x100,
        }];
        bytes[0x200 + 12..0x200 + 14].copy_from_slice(&2_u16.to_le_bytes());
        bytes[0x200 + 14..0x200 + 16].copy_from_slice(&3_u16.to_le_bytes());
        let mut calls = 0usize;
        let mut checkpoint = || {
            calls += 1;
            Ok(())
        };

        let count = resource_directory_entry_count_with_cancellation(
            &bytes,
            &sections,
            Some(PeDataDirectory {
                virtual_address: 0x1000,
                size: 0x40,
            }),
            &mut checkpoint,
        )
        .expect("valid PE resource directory must retain its entry count");

        assert_eq!(count, 5);
        assert_eq!(calls, 2);
    }
}
