use std::io::Read;

use anyhow::{bail, Result};
use flate2::read::DeflateDecoder;

use crate::analyzers::strings;

use super::ArchiveAnalysis;

const MAX_ENTRIES: u32 = 256;
const MAX_STORED_RELATIONSHIP_BYTES: usize = 64 * 1024;
const MAX_DEFLATED_RELATIONSHIP_BYTES: usize = 64 * 1024;
const MAX_INFLATED_RELATIONSHIP_BYTES: usize = 64 * 1024;
const MAX_STORED_AUTORUN_INF_BYTES: usize = 16 * 1024;
const MAX_DEFLATED_AUTORUN_INF_BYTES: usize = 16 * 1024;
const MAX_INFLATED_AUTORUN_INF_BYTES: usize = 16 * 1024;
const MAX_CONTENT_SCAN_ENTRIES: usize = 64;
const MAX_CONTENT_SCAN_ENTRY_BYTES: usize = 1024 * 1024;
const MAX_CONTENT_SCAN_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_CENTRAL_DIRECTORY_BYTES: usize = 256 * 1024;
const MAX_EOCD_SEARCH_BYTES: usize = 22 + u16::MAX as usize;
const ZIP_COMPRESSION_STORED: u16 = 0;
const ZIP_COMPRESSION_DEFLATE: u16 = 8;
const ZIP_GENERAL_PURPOSE_ENCRYPTED: u16 = 0x0001;
const ZIP_GENERAL_PURPOSE_DATA_DESCRIPTOR: u16 = 0x0008;
const ZIP_LOCAL_FILE_HEADER_SIGNATURE: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: &[u8] = b"PK\x01\x02";
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: &[u8] = b"PK\x05\x06";
const ZIP64_U32_SENTINEL: u32 = u32::MAX;

struct CentralDirectoryEntry {
    name: String,
    general_purpose_flags: u16,
    compression_method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedZipEntrySample {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundedZipEntrySamples {
    pub entries: Vec<BoundedZipEntrySample>,
    pub limit_exceeded: bool,
}

pub fn analyze_zip(bytes: &[u8]) -> Result<ArchiveAnalysis> {
    if bytes.starts_with(ZIP_LOCAL_FILE_HEADER_SIGNATURE) && bytes.len() < 30 {
        bail!("truncated zip local file header");
    }
    if bytes.starts_with(ZIP_LOCAL_FILE_HEADER_SIGNATURE) {
        if let Some(analysis) = analyze_central_directory(bytes) {
            return Ok(analysis);
        }
    }
    analyze_local_headers(bytes)
}

pub fn bounded_zip_entry_samples(bytes: &[u8]) -> Result<BoundedZipEntrySamples> {
    if bytes.starts_with(ZIP_LOCAL_FILE_HEADER_SIGNATURE) && bytes.len() < 30 {
        bail!("truncated zip local file header");
    }
    if bytes.starts_with(ZIP_LOCAL_FILE_HEADER_SIGNATURE) {
        if let Some(samples) = bounded_central_directory_entry_samples(bytes) {
            return Ok(samples);
        }
    }
    bounded_local_header_entry_samples(bytes)
}

fn bounded_local_header_entry_samples(bytes: &[u8]) -> Result<BoundedZipEntrySamples> {
    let mut offset = 0usize;
    let mut samples = BoundedZipEntrySamples::default();
    let mut total_sampled_bytes = 0usize;
    while offset + 30 <= bytes.len() {
        if &bytes[offset..offset + 4] != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
            break;
        }
        if samples.entries.len() >= MAX_CONTENT_SCAN_ENTRIES {
            samples.limit_exceeded = true;
            break;
        }
        let general_purpose_flags = u16::from_le_bytes([bytes[offset + 6], bytes[offset + 7]]);
        let compression_method = u16::from_le_bytes([bytes[offset + 8], bytes[offset + 9]]);
        let compressed_size = u32::from_le_bytes([
            bytes[offset + 18],
            bytes[offset + 19],
            bytes[offset + 20],
            bytes[offset + 21],
        ]) as usize;
        let uncompressed_size = u32::from_le_bytes([
            bytes[offset + 22],
            bytes[offset + 23],
            bytes[offset + 24],
            bytes[offset + 25],
        ]) as usize;
        let name_len = u16::from_le_bytes([bytes[offset + 26], bytes[offset + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;
        if name_len == 0 {
            bail!("zip entry name is empty");
        }
        let name_start = offset + 30;
        let name_end = name_start.saturating_add(name_len);
        if name_end > bytes.len() {
            bail!("invalid zip entry name length");
        }
        let extra_end = name_end.saturating_add(extra_len);
        if extra_end > bytes.len() {
            bail!("invalid zip entry extra length");
        }
        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).to_ascii_lowercase();
        let body_start = extra_end;
        collect_bounded_zip_entry_sample(
            &name,
            bytes,
            body_start,
            general_purpose_flags,
            compression_method,
            compressed_size,
            uncompressed_size,
            &mut samples,
            &mut total_sampled_bytes,
        );
        let body_end = body_start.saturating_add(compressed_size);
        if body_end > bytes.len() {
            samples.limit_exceeded = true;
            break;
        }
        offset = body_end;
    }
    Ok(samples)
}

fn bounded_central_directory_entry_samples(bytes: &[u8]) -> Option<BoundedZipEntrySamples> {
    let eocd_offset = find_end_of_central_directory(bytes)?;
    let mut samples = BoundedZipEntrySamples::default();
    let mut total_sampled_bytes = 0usize;
    let total_entries = read_u16_le(bytes, eocd_offset + 10)? as usize;
    let central_directory_size = read_u32_le(bytes, eocd_offset + 12)?;
    let central_directory_offset = read_u32_le(bytes, eocd_offset + 16)?;
    let disk_number = read_u16_le(bytes, eocd_offset + 4)?;
    let central_directory_disk = read_u16_le(bytes, eocd_offset + 6)?;
    let disk_entries = read_u16_le(bytes, eocd_offset + 8)? as usize;
    if disk_number != 0
        || central_directory_disk != 0
        || disk_entries != total_entries
        || central_directory_size == ZIP64_U32_SENTINEL
        || central_directory_offset == ZIP64_U32_SENTINEL
    {
        samples.limit_exceeded = true;
        return Some(samples);
    }
    let central_directory_size = central_directory_size as usize;
    let central_directory_offset = central_directory_offset as usize;
    if central_directory_size > MAX_CENTRAL_DIRECTORY_BYTES {
        samples.limit_exceeded = true;
        return Some(samples);
    }
    let Some(central_directory_end) = central_directory_offset.checked_add(central_directory_size)
    else {
        samples.limit_exceeded = true;
        return Some(samples);
    };
    if central_directory_offset > eocd_offset
        || central_directory_end > eocd_offset
        || central_directory_end > bytes.len()
    {
        samples.limit_exceeded = true;
        return Some(samples);
    }
    let mut offset = central_directory_offset;
    let mut parsed_entries = 0usize;
    while parsed_entries < total_entries {
        if samples.entries.len() >= MAX_CONTENT_SCAN_ENTRIES {
            samples.limit_exceeded = true;
            break;
        }
        let Some((entry, next_offset)) =
            parse_central_directory_entry(bytes, offset, central_directory_end)
        else {
            samples.limit_exceeded = true;
            break;
        };
        if entry.compressed_size == ZIP64_U32_SENTINEL
            || entry.uncompressed_size == ZIP64_U32_SENTINEL
            || entry.local_header_offset == ZIP64_U32_SENTINEL
        {
            samples.limit_exceeded = true;
            offset = next_offset;
            parsed_entries += 1;
            continue;
        }
        let Some(body_start) = central_directory_entry_body_start(bytes, &entry) else {
            samples.limit_exceeded = true;
            offset = next_offset;
            parsed_entries += 1;
            continue;
        };
        collect_bounded_zip_entry_sample(
            &entry.name,
            bytes,
            body_start,
            entry.general_purpose_flags,
            entry.compression_method,
            entry.compressed_size as usize,
            entry.uncompressed_size as usize,
            &mut samples,
            &mut total_sampled_bytes,
        );
        offset = next_offset;
        parsed_entries += 1;
    }
    if parsed_entries < total_entries || offset != central_directory_end {
        samples.limit_exceeded = true;
    }
    Some(samples)
}

fn analyze_local_headers(bytes: &[u8]) -> Result<ArchiveAnalysis> {
    let mut offset = 0usize;
    let mut result = ArchiveAnalysis::default();
    while offset + 30 <= bytes.len() {
        if &bytes[offset..offset + 4] != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
            break;
        }
        if result.entry_count >= MAX_ENTRIES {
            result.limit_exceeded = true;
            break;
        }
        let general_purpose_flags = u16::from_le_bytes([bytes[offset + 6], bytes[offset + 7]]);
        let compression_method = u16::from_le_bytes([bytes[offset + 8], bytes[offset + 9]]);
        let compressed_size = u32::from_le_bytes([
            bytes[offset + 18],
            bytes[offset + 19],
            bytes[offset + 20],
            bytes[offset + 21],
        ]) as usize;
        let uncompressed_size = u32::from_le_bytes([
            bytes[offset + 22],
            bytes[offset + 23],
            bytes[offset + 24],
            bytes[offset + 25],
        ]) as usize;
        let name_len = u16::from_le_bytes([bytes[offset + 26], bytes[offset + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;
        if name_len == 0 {
            bail!("zip entry name is empty");
        }
        let name_start = offset + 30;
        let name_end = name_start.saturating_add(name_len);
        if name_end > bytes.len() {
            bail!("invalid zip entry name length");
        }
        let extra_end = name_end.saturating_add(extra_len);
        if extra_end > bytes.len() {
            bail!("invalid zip entry extra length");
        }
        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).to_ascii_lowercase();
        inspect_zip_entry_name(&name, &mut result);
        let body_start = extra_end;
        let body_end = body_start.saturating_add(compressed_size);
        inspect_ooxml_relationship_entry(
            &name,
            bytes,
            body_start,
            general_purpose_flags,
            compression_method,
            compressed_size,
            uncompressed_size,
            &mut result,
        );
        inspect_archive_autorun_inf_entry(
            &name,
            bytes,
            body_start,
            general_purpose_flags,
            compression_method,
            compressed_size,
            uncompressed_size,
            &mut result,
        );
        result.entry_count += 1;
        if body_end > bytes.len() {
            result.limit_exceeded = true;
            break;
        }
        offset = body_end;
    }
    Ok(result)
}

fn analyze_central_directory(bytes: &[u8]) -> Option<ArchiveAnalysis> {
    let eocd_offset = find_end_of_central_directory(bytes)?;
    let mut result = ArchiveAnalysis::default();
    let total_entries = read_u16_le(bytes, eocd_offset + 10)? as usize;
    let central_directory_size = read_u32_le(bytes, eocd_offset + 12)?;
    let central_directory_offset = read_u32_le(bytes, eocd_offset + 16)?;
    let disk_number = read_u16_le(bytes, eocd_offset + 4)?;
    let central_directory_disk = read_u16_le(bytes, eocd_offset + 6)?;
    let disk_entries = read_u16_le(bytes, eocd_offset + 8)? as usize;
    if disk_number != 0
        || central_directory_disk != 0
        || disk_entries != total_entries
        || central_directory_size == ZIP64_U32_SENTINEL
        || central_directory_offset == ZIP64_U32_SENTINEL
    {
        result.limit_exceeded = true;
        return Some(result);
    }
    let central_directory_size = central_directory_size as usize;
    let central_directory_offset = central_directory_offset as usize;
    if central_directory_size > MAX_CENTRAL_DIRECTORY_BYTES {
        result.limit_exceeded = true;
        return Some(result);
    }
    let Some(central_directory_end) = central_directory_offset.checked_add(central_directory_size)
    else {
        result.limit_exceeded = true;
        return Some(result);
    };
    if central_directory_offset > eocd_offset
        || central_directory_end > eocd_offset
        || central_directory_end > bytes.len()
    {
        result.limit_exceeded = true;
        return Some(result);
    }
    let mut offset = central_directory_offset;
    let mut parsed_entries = 0usize;
    while parsed_entries < total_entries {
        if result.entry_count >= MAX_ENTRIES {
            result.limit_exceeded = true;
            break;
        }
        let Some((entry, next_offset)) =
            parse_central_directory_entry(bytes, offset, central_directory_end)
        else {
            result.limit_exceeded = true;
            break;
        };
        inspect_zip_entry_name(&entry.name, &mut result);
        inspect_central_directory_ooxml_relationship(&entry, bytes, &mut result);
        inspect_central_directory_autorun_inf_entry(&entry, bytes, &mut result);
        result.entry_count += 1;
        offset = next_offset;
        parsed_entries += 1;
    }
    if parsed_entries < total_entries || offset != central_directory_end {
        result.limit_exceeded = true;
    }
    Some(result)
}

fn inspect_central_directory_autorun_inf_entry(
    entry: &CentralDirectoryEntry,
    bytes: &[u8],
    result: &mut ArchiveAnalysis,
) {
    if !archive_autorun_inf_entry(&entry.name) {
        return;
    }
    if entry.compressed_size == ZIP64_U32_SENTINEL
        || entry.uncompressed_size == ZIP64_U32_SENTINEL
        || entry.local_header_offset == ZIP64_U32_SENTINEL
    {
        result.limit_exceeded = true;
        return;
    }
    let Some(body_start) = central_directory_entry_body_start(bytes, entry) else {
        result.limit_exceeded = true;
        return;
    };
    inspect_archive_autorun_inf_entry(
        &entry.name,
        bytes,
        body_start,
        entry.general_purpose_flags,
        entry.compression_method,
        entry.compressed_size as usize,
        entry.uncompressed_size as usize,
        result,
    );
}

fn parse_central_directory_entry(
    bytes: &[u8],
    offset: usize,
    central_directory_end: usize,
) -> Option<(CentralDirectoryEntry, usize)> {
    let fixed_end = offset.checked_add(46)?;
    if fixed_end > central_directory_end
        || fixed_end > bytes.len()
        || bytes.get(offset..offset + 4)? != ZIP_CENTRAL_DIRECTORY_SIGNATURE
    {
        return None;
    }
    let general_purpose_flags = read_u16_le(bytes, offset + 8)?;
    let compression_method = read_u16_le(bytes, offset + 10)?;
    let compressed_size = read_u32_le(bytes, offset + 20)?;
    let uncompressed_size = read_u32_le(bytes, offset + 24)?;
    let name_len = read_u16_le(bytes, offset + 28)? as usize;
    let extra_len = read_u16_le(bytes, offset + 30)? as usize;
    let comment_len = read_u16_le(bytes, offset + 32)? as usize;
    let local_header_offset = read_u32_le(bytes, offset + 42)?;
    let name_start = offset + 46;
    let name_end = name_start.checked_add(name_len)?;
    let extra_end = name_end.checked_add(extra_len)?;
    let comment_end = extra_end.checked_add(comment_len)?;
    if name_len == 0 || comment_end > central_directory_end || comment_end > bytes.len() {
        return None;
    }
    let name = String::from_utf8_lossy(&bytes[name_start..name_end]).to_ascii_lowercase();
    Some((
        CentralDirectoryEntry {
            name,
            general_purpose_flags,
            compression_method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        },
        comment_end,
    ))
}

fn inspect_central_directory_ooxml_relationship(
    entry: &CentralDirectoryEntry,
    bytes: &[u8],
    result: &mut ArchiveAnalysis,
) {
    if !ooxml_relationship_entry(&entry.name) {
        return;
    }
    if entry.compressed_size == ZIP64_U32_SENTINEL
        || entry.uncompressed_size == ZIP64_U32_SENTINEL
        || entry.local_header_offset == ZIP64_U32_SENTINEL
    {
        result.limit_exceeded = true;
        return;
    }
    let Some(body_start) = central_directory_entry_body_start(bytes, entry) else {
        result.limit_exceeded = true;
        return;
    };
    inspect_ooxml_relationship_entry(
        &entry.name,
        bytes,
        body_start,
        entry.general_purpose_flags,
        entry.compression_method,
        entry.compressed_size as usize,
        entry.uncompressed_size as usize,
        result,
    );
}

fn central_directory_entry_body_start(
    bytes: &[u8],
    entry: &CentralDirectoryEntry,
) -> Option<usize> {
    let offset = entry.local_header_offset as usize;
    let fixed_end = offset.checked_add(30)?;
    if fixed_end > bytes.len() || bytes.get(offset..offset + 4)? != ZIP_LOCAL_FILE_HEADER_SIGNATURE
    {
        return None;
    }
    let local_general_purpose_flags = read_u16_le(bytes, offset + 6)?;
    let local_compression_method = read_u16_le(bytes, offset + 8)?;
    let guarded_flags = ZIP_GENERAL_PURPOSE_ENCRYPTED | ZIP_GENERAL_PURPOSE_DATA_DESCRIPTOR;
    if local_compression_method != entry.compression_method
        || (local_general_purpose_flags & guarded_flags)
            != (entry.general_purpose_flags & guarded_flags)
    {
        return None;
    }
    let name_len = read_u16_le(bytes, offset + 26)? as usize;
    let extra_len = read_u16_le(bytes, offset + 28)? as usize;
    let name_start = offset + 30;
    let name_end = name_start.checked_add(name_len)?;
    let extra_end = name_end.checked_add(extra_len)?;
    if name_len == 0 || extra_end > bytes.len() {
        return None;
    }
    let local_name = String::from_utf8_lossy(&bytes[name_start..name_end]).to_ascii_lowercase();
    if local_name != entry.name {
        return None;
    }
    Some(extra_end)
}

fn find_end_of_central_directory(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 22 {
        return None;
    }
    let min_offset = bytes.len().saturating_sub(MAX_EOCD_SEARCH_BYTES);
    let mut offset = bytes.len() - 22;
    loop {
        if bytes.get(offset..offset + 4)? == ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            let comment_len = read_u16_le(bytes, offset + 20)? as usize;
            if offset.checked_add(22)?.checked_add(comment_len)? == bytes.len() {
                return Some(offset);
            }
        }
        if offset == min_offset {
            break;
        }
        offset -= 1;
    }
    None
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let value = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let value = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn inspect_zip_entry_name(name: &str, result: &mut ArchiveAnalysis) {
    if unsafe_archive_path(name) {
        result.zip_slip_blocked = true;
    }
    if let Some(suffix) = zip_entry_extension_suffix(name) {
        if zip_entry_suffix_is_executable_or_script(suffix) {
            result.contains_executable = true;
        }
    }
    if archive_autorun_inf_entry(name) {
        result.autorun_inf_entry_count = result.autorun_inf_entry_count.saturating_add(1);
    } else if archive_shortcut_entry(name) {
        result.shortcut_entry_count = result.shortcut_entry_count.saturating_add(1);
    } else if archive_autorun_companion_name(name) {
        result.autorun_executable_entry_count =
            result.autorun_executable_entry_count.saturating_add(1);
    }
    if suspicious_archive_executable_name(name) {
        result.suspicious_nested_name_count += 1;
    }
    if name.ends_with("vbaproject.bin") {
        result.ooxml_vba_project_count = result.ooxml_vba_project_count.saturating_add(1);
    }
}

fn suspicious_archive_executable_name(name: &str) -> bool {
    let file_name = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim_matches('.');
    let Some(executable_suffix) = zip_entry_extension_suffix(file_name) else {
        return false;
    };
    if !zip_entry_suffix_is_deceptive_review_executable_or_script(executable_suffix) {
        return false;
    }
    let Some((stem, _)) = file_name.rsplit_once('.') else {
        return false;
    };
    let stem = stem.trim_matches('.');
    if stem.is_empty() {
        return false;
    }
    let bait_name = stem
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|part| {
            matches!(
                part,
                "invoice"
                    | "receipt"
                    | "statement"
                    | "payment"
                    | "document"
                    | "scan"
                    | "photo"
                    | "image"
                    | "shipping"
                    | "resume"
            )
        });
    if bait_name {
        return true;
    }
    let Some(decoy_extension) = stem.rsplit('.').next() else {
        return false;
    };
    matches!(
        decoy_extension,
        "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "rtf"
            | "txt"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "html"
            | "htm"
            | "eml"
    )
}

fn archive_autorun_inf_entry(name: &str) -> bool {
    zip_entry_file_name(name) == "autorun.inf"
}

fn archive_shortcut_entry(name: &str) -> bool {
    zip_entry_extension_suffix(zip_entry_file_name(name))
        .is_some_and(|suffix| matches!(suffix, "lnk" | "url" | "scf"))
}

fn archive_autorun_companion_name(name: &str) -> bool {
    zip_entry_extension_suffix(zip_entry_file_name(name))
        .is_some_and(zip_entry_suffix_is_executable_or_script)
}

fn zip_entry_file_name(name: &str) -> &str {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim_matches('.')
}

fn zip_entry_suffix_is_executable_or_script(suffix: &str) -> bool {
    matches!(
        suffix,
        "exe"
            | "dll"
            | "scr"
            | "com"
            | "pif"
            | "cpl"
            | "msi"
            | "ps1"
            | "psm1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "mjs"
            | "cjs"
            | "wsf"
            | "hta"
            | "jar"
    )
}

fn zip_entry_suffix_is_deceptive_review_executable_or_script(suffix: &str) -> bool {
    matches!(
        suffix,
        "exe"
            | "scr"
            | "com"
            | "pif"
            | "cpl"
            | "msi"
            | "ps1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "hta"
            | "jar"
    )
}

fn inspect_ooxml_relationship_entry(
    name: &str,
    bytes: &[u8],
    body_start: usize,
    general_purpose_flags: u16,
    compression_method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
    result: &mut ArchiveAnalysis,
) {
    if !ooxml_relationship_entry(name) {
        return;
    }
    if general_purpose_flags & ZIP_GENERAL_PURPOSE_ENCRYPTED != 0 {
        result.limit_exceeded = true;
        return;
    }
    let Some(body_end) = body_start.checked_add(compressed_size) else {
        result.limit_exceeded = true;
        return;
    };
    if body_end > bytes.len() {
        result.limit_exceeded = true;
        return;
    }
    match bounded_relationship_body(
        &bytes[body_start..body_end],
        compression_method,
        compressed_size,
        uncompressed_size,
    ) {
        Ok(Some(body)) => inspect_ooxml_relationship_body(&body, result),
        Ok(None) => {}
        Err(()) => {
            result.limit_exceeded = true;
        }
    }
}

fn inspect_archive_autorun_inf_entry(
    name: &str,
    bytes: &[u8],
    body_start: usize,
    general_purpose_flags: u16,
    compression_method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
    result: &mut ArchiveAnalysis,
) {
    if !archive_autorun_inf_entry(name) {
        return;
    }
    if general_purpose_flags & ZIP_GENERAL_PURPOSE_ENCRYPTED != 0 {
        result.limit_exceeded = true;
        return;
    }
    let Some(body_end) = body_start.checked_add(compressed_size) else {
        result.limit_exceeded = true;
        return;
    };
    if body_end > bytes.len() {
        result.limit_exceeded = true;
        return;
    }
    match bounded_autorun_inf_body(
        &bytes[body_start..body_end],
        compression_method,
        compressed_size,
        uncompressed_size,
    ) {
        Ok(Some(body)) => {
            let indicators = strings::extract_indicators(&body);
            result.autorun_inf_executable_command_count = result
                .autorun_inf_executable_command_count
                .saturating_add(indicators.autorun_inf_executable_command_count);
        }
        Ok(None) => {}
        Err(()) => {
            result.limit_exceeded = true;
        }
    }
}

fn zip_entry_extension_suffix(name: &str) -> Option<&str> {
    let suffix = name.rsplit('.').next()?;
    if suffix.is_empty() {
        return None;
    }
    Some(suffix)
}

fn unsafe_archive_path(name: &str) -> bool {
    let normalized = name.replace('\\', "/");
    normalized.starts_with('/')
        || normalized.starts_with("//")
        || windows_absolute_path(&normalized)
        || normalized.split('/').any(|segment| segment.trim() == "..")
}

fn windows_absolute_path(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'/' && bytes[0].is_ascii_alphabetic()
}

fn ooxml_relationship_entry(name: &str) -> bool {
    name.ends_with(".rels") && (name == "_rels/.rels" || name.contains("/_rels/"))
}

fn bounded_relationship_body(
    body: &[u8],
    compression_method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
) -> std::result::Result<Option<Vec<u8>>, ()> {
    match compression_method {
        ZIP_COMPRESSION_STORED if compressed_size <= MAX_STORED_RELATIONSHIP_BYTES => {
            Ok(Some(body.to_vec()))
        }
        ZIP_COMPRESSION_STORED => Err(()),
        ZIP_COMPRESSION_DEFLATE
            if compressed_size <= MAX_DEFLATED_RELATIONSHIP_BYTES
                && uncompressed_size <= MAX_INFLATED_RELATIONSHIP_BYTES =>
        {
            inflate_zip_body(body, MAX_INFLATED_RELATIONSHIP_BYTES)
        }
        ZIP_COMPRESSION_DEFLATE => Err(()),
        _ => Err(()),
    }
}

fn bounded_autorun_inf_body(
    body: &[u8],
    compression_method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
) -> std::result::Result<Option<Vec<u8>>, ()> {
    match compression_method {
        ZIP_COMPRESSION_STORED if compressed_size <= MAX_STORED_AUTORUN_INF_BYTES => {
            Ok(Some(body.to_vec()))
        }
        ZIP_COMPRESSION_STORED => Err(()),
        ZIP_COMPRESSION_DEFLATE
            if compressed_size <= MAX_DEFLATED_AUTORUN_INF_BYTES
                && uncompressed_size <= MAX_INFLATED_AUTORUN_INF_BYTES =>
        {
            inflate_zip_body(body, MAX_INFLATED_AUTORUN_INF_BYTES)
        }
        ZIP_COMPRESSION_DEFLATE => Err(()),
        _ => Err(()),
    }
}

fn collect_bounded_zip_entry_sample(
    name: &str,
    bytes: &[u8],
    body_start: usize,
    general_purpose_flags: u16,
    compression_method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
    samples: &mut BoundedZipEntrySamples,
    total_sampled_bytes: &mut usize,
) {
    if name.ends_with('/') {
        return;
    }
    if unsafe_archive_path(name) {
        samples.limit_exceeded = true;
        return;
    }
    if general_purpose_flags & ZIP_GENERAL_PURPOSE_ENCRYPTED != 0 {
        samples.limit_exceeded = true;
        return;
    }
    if general_purpose_flags & ZIP_GENERAL_PURPOSE_DATA_DESCRIPTOR != 0 && compressed_size == 0 {
        samples.limit_exceeded = true;
        return;
    }
    let Some(body_end) = body_start.checked_add(compressed_size) else {
        samples.limit_exceeded = true;
        return;
    };
    if body_end > bytes.len() {
        samples.limit_exceeded = true;
        return;
    }
    let body = match bounded_archive_content_body(
        &bytes[body_start..body_end],
        compression_method,
        compressed_size,
        uncompressed_size,
    ) {
        Ok(Some(body)) => body,
        Ok(None) => return,
        Err(()) => {
            samples.limit_exceeded = true;
            return;
        }
    };
    if body.is_empty() {
        return;
    }
    let Some(next_total) = total_sampled_bytes.checked_add(body.len()) else {
        samples.limit_exceeded = true;
        return;
    };
    if next_total > MAX_CONTENT_SCAN_TOTAL_BYTES {
        samples.limit_exceeded = true;
        return;
    }
    *total_sampled_bytes = next_total;
    samples.entries.push(BoundedZipEntrySample {
        name: name.to_string(),
        bytes: body,
    });
}

fn bounded_archive_content_body(
    body: &[u8],
    compression_method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
) -> std::result::Result<Option<Vec<u8>>, ()> {
    match compression_method {
        ZIP_COMPRESSION_STORED
            if compressed_size <= MAX_CONTENT_SCAN_ENTRY_BYTES
                && uncompressed_size <= MAX_CONTENT_SCAN_ENTRY_BYTES
                && compressed_size == uncompressed_size =>
        {
            Ok(Some(body.to_vec()))
        }
        ZIP_COMPRESSION_STORED => Err(()),
        ZIP_COMPRESSION_DEFLATE
            if compressed_size <= MAX_CONTENT_SCAN_ENTRY_BYTES
                && uncompressed_size <= MAX_CONTENT_SCAN_ENTRY_BYTES =>
        {
            inflate_zip_body(body, MAX_CONTENT_SCAN_ENTRY_BYTES)
        }
        ZIP_COMPRESSION_DEFLATE => Err(()),
        _ => Err(()),
    }
}

fn inflate_zip_body(
    body: &[u8],
    max_inflated_bytes: usize,
) -> std::result::Result<Option<Vec<u8>>, ()> {
    let mut decoder = DeflateDecoder::new(body);
    let mut inflated = Vec::new();
    let mut limited = decoder.by_ref().take((max_inflated_bytes + 1) as u64);
    limited.read_to_end(&mut inflated).map_err(|_| ())?;
    if inflated.len() > max_inflated_bytes {
        return Err(());
    }
    Ok(Some(inflated))
}

fn inspect_ooxml_relationship_body(body: &[u8], result: &mut ArchiveAnalysis) {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    if !text.contains("targetmode") || !text.contains("external") {
        return;
    }
    result.ooxml_external_relationship_count =
        result.ooxml_external_relationship_count.saturating_add(1);
    let indicators = strings::extract_indicators(text.as_bytes());
    if indicators.remote_executable_url_count > 0
        || indicators.remote_network_executable_path_count > 0
    {
        result.ooxml_remote_executable_relationship_count = result
            .ooxml_remote_executable_relationship_count
            .saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zip_with_name(name: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&[0; 22]);
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name);
        bytes
    }

    fn zip_with_stored_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, body) in entries {
            bytes.extend_from_slice(b"PK\x03\x04");
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(body);
        }
        bytes
    }

    fn zip_with_entry_method(
        name: &[u8],
        method: u16,
        body: &[u8],
        declared_uncompressed_size: usize,
    ) -> Vec<u8> {
        zip_with_entry_method_flags(name, method, 0, body, declared_uncompressed_size)
    }

    fn zip_with_entry_method_flags(
        name: &[u8],
        method: u16,
        flags: u16,
        body: &[u8],
        declared_uncompressed_size: usize,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&method.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(declared_uncompressed_size as u32).to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(body);
        bytes
    }

    fn zip_with_data_descriptor_central_directory(
        entries: &[(&[u8], &[u8], u16, &[u8])],
    ) -> Vec<u8> {
        let entries = entries
            .iter()
            .map(|(local_name, central_name, method, body)| {
                (
                    *local_name,
                    *central_name,
                    *method,
                    ZIP_GENERAL_PURPOSE_DATA_DESCRIPTOR,
                    *body,
                )
            })
            .collect::<Vec<_>>();
        zip_with_central_directory_entry_flags(&entries)
    }

    fn zip_with_central_directory_entry_flags(
        entries: &[(&[u8], &[u8], u16, u16, &[u8])],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut central_entries = Vec::new();
        for (local_name, central_name, method, flags, body) in entries {
            let payload = if *method == ZIP_COMPRESSION_DEFLATE {
                deflate_raw(body)
            } else {
                body.to_vec()
            };
            let local_header_offset = bytes.len();
            bytes.extend_from_slice(ZIP_LOCAL_FILE_HEADER_SIGNATURE);
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&flags.to_le_bytes());
            bytes.extend_from_slice(&method.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&((*local_name).len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(local_name);
            bytes.extend_from_slice(&payload);
            bytes.extend_from_slice(b"PK\x07\x08");
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central_entries.push((
                (*central_name).to_vec(),
                *method,
                *flags,
                payload.len(),
                body.len(),
                local_header_offset,
            ));
        }
        let central_directory_offset = bytes.len();
        for (name, method, flags, compressed_size, uncompressed_size, local_header_offset) in
            &central_entries
        {
            bytes.extend_from_slice(ZIP_CENTRAL_DIRECTORY_SIGNATURE);
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&flags.to_le_bytes());
            bytes.extend_from_slice(&method.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(*compressed_size as u32).to_le_bytes());
            bytes.extend_from_slice(&(*uncompressed_size as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(*local_header_offset as u32).to_le_bytes());
            bytes.extend_from_slice(name);
        }
        let central_directory_size = bytes.len() - central_directory_offset;
        bytes.extend_from_slice(ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(central_entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(central_entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(central_directory_size as u32).to_le_bytes());
        bytes.extend_from_slice(&(central_directory_offset as u32).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    }

    fn deflate_raw(body: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn detects_windows_absolute_archive_paths() {
        let analysis = analyze_zip(&zip_with_name(b"C:\\Windows\\Temp\\evil.exe")).unwrap();
        assert!(analysis.zip_slip_blocked);
    }

    #[test]
    fn detects_root_backslash_archive_paths() {
        let analysis = analyze_zip(&zip_with_name(b"\\Windows\\Temp\\evil.exe")).unwrap();
        assert!(analysis.zip_slip_blocked);
    }

    #[test]
    fn detects_unc_archive_paths() {
        let analysis = analyze_zip(&zip_with_name(b"\\\\server\\share\\evil.exe")).unwrap();
        assert!(analysis.zip_slip_blocked);
    }

    #[test]
    fn allows_relative_archive_paths() {
        let analysis = analyze_zip(&zip_with_name(b"folder/tool.exe")).unwrap();
        assert!(!analysis.zip_slip_blocked);
        assert!(analysis.contains_executable);
    }

    #[test]
    fn deceptive_archive_executable_names_are_suspicious() {
        for name in [
            b"invoice.exe".as_slice(),
            b"documents/invoice.pdf.exe".as_slice(),
            b"photos/photo.jpg.scr".as_slice(),
            b"notes/readme.txt.js".as_slice(),
        ] {
            let analysis = analyze_zip(&zip_with_name(name)).unwrap();
            assert!(
                analysis.contains_executable,
                "contains executable: {name:?}"
            );
            assert_eq!(
                analysis.suspicious_nested_name_count, 1,
                "suspicious nested name: {name:?}"
            );
        }
    }

    #[test]
    fn ordinary_archive_executable_names_are_not_suspicious() {
        let analysis = analyze_zip(&zip_with_name(b"tools/setup.exe")).unwrap();
        assert!(analysis.contains_executable);
        assert_eq!(analysis.suspicious_nested_name_count, 0);
        assert_eq!(analysis.autorun_inf_entry_count, 0);
        assert_eq!(analysis.autorun_executable_entry_count, 1);
    }

    #[test]
    fn autorun_inf_and_executable_companion_entries_are_counted() {
        let analysis = analyze_zip(&zip_with_stored_entries(&[
            (b"autorun.inf", b"[autorun]\nopen=setup.exe\n"),
            (b"setup/setup.exe", b"placeholder"),
        ]))
        .unwrap();

        assert_eq!(analysis.autorun_inf_entry_count, 1);
        assert_eq!(analysis.autorun_executable_entry_count, 1);
        assert!(analysis.contains_executable);
    }

    #[test]
    fn autorun_inf_executable_command_body_is_counted() {
        let analysis = analyze_zip(&zip_with_stored_entries(&[
            (b"autorun.inf", b"[autorun]\nopen=setup.exe\n"),
            (b"setup/setup.exe", b"placeholder"),
        ]))
        .unwrap();

        assert_eq!(analysis.autorun_inf_executable_command_count, 1);
        assert!(!analysis.limit_exceeded);
    }

    #[test]
    fn autorun_inf_without_executable_companion_is_not_counted_as_bundle() {
        let analysis = analyze_zip(&zip_with_stored_entries(&[
            (b"autorun.inf", b"[autorun]\nopen=readme.pdf\n"),
            (b"docs/readme.pdf", b"placeholder"),
        ]))
        .unwrap();

        assert_eq!(analysis.autorun_inf_entry_count, 1);
        assert_eq!(analysis.autorun_executable_entry_count, 0);
        assert!(!analysis.contains_executable);
        assert_eq!(analysis.autorun_inf_executable_command_count, 0);
    }

    #[test]
    fn shortcut_and_executable_companion_entries_are_counted() {
        let analysis = analyze_zip(&zip_with_stored_entries(&[
            (b"launch/support.lnk", b"shortcut placeholder"),
            (b"bin/support.exe", b"placeholder"),
        ]))
        .unwrap();

        assert_eq!(analysis.shortcut_entry_count, 1);
        assert!(analysis.contains_executable);
    }

    #[test]
    fn shortcut_without_executable_companion_is_not_executable_bundle() {
        let analysis = analyze_zip(&zip_with_stored_entries(&[
            (
                b"launch/support.url",
                b"[InternetShortcut]\nURL=https://example.invalid/readme\n",
            ),
            (b"docs/readme.pdf", b"placeholder"),
        ]))
        .unwrap();

        assert_eq!(analysis.shortcut_entry_count, 1);
        assert!(!analysis.contains_executable);
    }

    #[test]
    fn bounded_zip_entry_samples_collect_stored_entries() {
        let samples = bounded_zip_entry_samples(&zip_with_stored_entries(&[
            (b"payload/readme.txt", b"hello"),
            (b"payload/tool.exe", b"placeholder"),
        ]))
        .unwrap();

        assert!(!samples.limit_exceeded);
        assert_eq!(samples.entries.len(), 2);
        assert_eq!(samples.entries[0].name, "payload/readme.txt");
        assert_eq!(samples.entries[0].bytes, b"hello");
    }

    #[test]
    fn bounded_zip_entry_samples_inflate_deflated_central_directory_entries() {
        let samples = bounded_zip_entry_samples(&zip_with_central_directory_entry_flags(&[(
            b"payload/readme.txt",
            b"payload/readme.txt",
            ZIP_COMPRESSION_DEFLATE,
            ZIP_GENERAL_PURPOSE_DATA_DESCRIPTOR,
            b"compressed hello",
        )]))
        .unwrap();

        assert!(!samples.limit_exceeded);
        assert_eq!(samples.entries.len(), 1);
        assert_eq!(samples.entries[0].bytes, b"compressed hello");
    }

    #[test]
    fn bounded_zip_entry_samples_do_not_collect_unsafe_paths() {
        let samples = bounded_zip_entry_samples(&zip_with_stored_entries(&[(
            b"../payload/readme.txt",
            b"hello",
        )]))
        .unwrap();

        assert!(samples.limit_exceeded);
        assert!(samples.entries.is_empty());
    }

    #[test]
    fn bounded_zip_entry_samples_mark_oversized_entries_limited() {
        let body = vec![b'a'; MAX_CONTENT_SCAN_ENTRY_BYTES + 1];
        let samples =
            bounded_zip_entry_samples(&zip_with_stored_entries(&[(b"payload/large.txt", &body)]))
                .unwrap();

        assert!(samples.limit_exceeded);
        assert!(samples.entries.is_empty());
    }

    #[test]
    fn encrypted_autorun_inf_body_is_not_inspected() {
        let mut bytes = zip_with_entry_method_flags(
            b"autorun.inf",
            ZIP_COMPRESSION_STORED,
            ZIP_GENERAL_PURPOSE_ENCRYPTED,
            b"[autorun]\nopen=setup.exe\n",
            b"[autorun]\nopen=setup.exe\n".len(),
        );
        bytes.extend_from_slice(&zip_with_name(b"setup/setup.exe"));

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.autorun_inf_entry_count, 1);
        assert_eq!(analysis.autorun_inf_executable_command_count, 0);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn rejects_invalid_extra_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&[0; 22]);
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes.extend_from_slice(&64u16.to_le_bytes());
        bytes.extend_from_slice(b"tool.exe");

        let error = analyze_zip(&bytes).unwrap_err().to_string();
        assert!(error.contains("invalid zip entry extra length"));
    }

    #[test]
    fn rejects_truncated_local_header() {
        let error = analyze_zip(b"PK\x03\x04short").unwrap_err().to_string();

        assert!(error.contains("truncated zip local file header"));
    }

    #[test]
    fn rejects_empty_entry_name() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&[0; 22]);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let error = analyze_zip(&bytes).unwrap_err().to_string();
        assert!(error.contains("zip entry name is empty"));
    }

    #[test]
    fn marks_truncated_entry_body_as_limited() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&[0; 14]);
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(b"tool.exe");

        let analysis = analyze_zip(&bytes).unwrap();
        assert_eq!(analysis.entry_count, 1);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn ooxml_macro_project_and_remote_relationship_are_counted() {
        let analysis = analyze_zip(&zip_with_stored_entries(&[
            (b"word/vbaProject.bin", b"macro project placeholder"),
            (
                b"word/_rels/document.xml.rels",
                br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#,
            ),
        ]))
        .unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 1);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 1);
    }

    #[test]
    fn ooxml_ordinary_external_document_relationship_is_not_remote_executable() {
        let analysis = analyze_zip(&zip_with_stored_entries(&[
            (b"word/vbaProject.bin", b"macro project placeholder"),
            (
                b"word/_rels/document.xml.rels",
                br#"<Relationship TargetMode="External" Target="https://example.invalid/readme.html"/>"#,
            ),
        ]))
        .unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 1);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 0);
    }

    #[test]
    fn ooxml_large_relationship_body_is_not_read_for_remote_targets() {
        let mut large_relationship = vec![b'a'; MAX_STORED_RELATIONSHIP_BYTES + 1];
        large_relationship.extend_from_slice(
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#,
        );
        let analysis = analyze_zip(&zip_with_stored_entries(&[
            (b"word/vbaProject.bin", b"macro project placeholder"),
            (b"word/_rels/document.xml.rels", &large_relationship),
        ]))
        .unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 0);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 0);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn ooxml_deflated_relationship_body_is_bounded_and_counted() {
        let relationship =
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#;
        let deflated_relationship = deflate_raw(relationship);
        let mut bytes = zip_with_stored_entries(&[(b"word/vbaProject.bin", b"macro")]);
        bytes.extend_from_slice(&zip_with_entry_method(
            b"word/_rels/document.xml.rels",
            ZIP_COMPRESSION_DEFLATE,
            &deflated_relationship,
            relationship.len(),
        ));

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 1);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 1);
        assert!(!analysis.limit_exceeded);
    }

    #[test]
    fn ooxml_deflated_relationship_declared_size_limit_is_not_inflated() {
        let relationship =
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#;
        let deflated_relationship = deflate_raw(relationship);
        let mut bytes = zip_with_stored_entries(&[(b"word/vbaProject.bin", b"macro")]);
        bytes.extend_from_slice(&zip_with_entry_method(
            b"word/_rels/document.xml.rels",
            ZIP_COMPRESSION_DEFLATE,
            &deflated_relationship,
            MAX_INFLATED_RELATIONSHIP_BYTES + 1,
        ));

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 0);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 0);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn ooxml_deflated_relationship_decode_error_sets_limit_flag() {
        let mut bytes = zip_with_stored_entries(&[(b"word/vbaProject.bin", b"macro")]);
        bytes.extend_from_slice(&zip_with_entry_method(
            b"word/_rels/document.xml.rels",
            ZIP_COMPRESSION_DEFLATE,
            b"not a raw deflate stream",
            64,
        ));

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 0);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 0);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn ooxml_unsupported_relationship_compression_sets_limit_flag() {
        let relationship =
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#;
        let mut bytes = zip_with_stored_entries(&[(b"word/vbaProject.bin", b"macro")]);
        bytes.extend_from_slice(&zip_with_entry_method(
            b"word/_rels/document.xml.rels",
            99,
            relationship,
            relationship.len(),
        ));

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 0);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 0);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn ooxml_encrypted_relationship_body_is_not_inspected() {
        let relationship =
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#;
        let mut bytes = zip_with_stored_entries(&[(b"word/vbaProject.bin", b"macro")]);
        bytes.extend_from_slice(&zip_with_entry_method_flags(
            b"word/_rels/document.xml.rels",
            ZIP_COMPRESSION_STORED,
            ZIP_GENERAL_PURPOSE_ENCRYPTED,
            relationship,
            relationship.len(),
        ));

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 0);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 0);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn ooxml_data_descriptor_central_directory_relationship_is_counted() {
        let relationship =
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#;
        let bytes = zip_with_data_descriptor_central_directory(&[
            (
                b"word/vbaProject.bin".as_slice(),
                b"word/vbaProject.bin".as_slice(),
                ZIP_COMPRESSION_STORED,
                b"macro".as_slice(),
            ),
            (
                b"word/_rels/document.xml.rels".as_slice(),
                b"word/_rels/document.xml.rels".as_slice(),
                ZIP_COMPRESSION_DEFLATE,
                relationship.as_slice(),
            ),
        ]);

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.entry_count, 2);
        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 1);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 1);
        assert!(!analysis.limit_exceeded);
    }

    #[test]
    fn ooxml_encrypted_central_directory_relationship_body_is_not_inspected() {
        let relationship =
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#;
        let bytes = zip_with_central_directory_entry_flags(&[
            (
                b"word/vbaProject.bin".as_slice(),
                b"word/vbaProject.bin".as_slice(),
                ZIP_COMPRESSION_STORED,
                ZIP_GENERAL_PURPOSE_DATA_DESCRIPTOR,
                b"macro".as_slice(),
            ),
            (
                b"word/_rels/document.xml.rels".as_slice(),
                b"word/_rels/document.xml.rels".as_slice(),
                ZIP_COMPRESSION_STORED,
                ZIP_GENERAL_PURPOSE_DATA_DESCRIPTOR | ZIP_GENERAL_PURPOSE_ENCRYPTED,
                relationship.as_slice(),
            ),
        ]);

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 0);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 0);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn central_directory_relationship_body_requires_matching_local_header_name() {
        let relationship =
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#;
        let bytes = zip_with_data_descriptor_central_directory(&[
            (
                b"word/vbaProject.bin".as_slice(),
                b"word/vbaProject.bin".as_slice(),
                ZIP_COMPRESSION_STORED,
                b"macro".as_slice(),
            ),
            (
                b"word/_rels/benign.xml.rels".as_slice(),
                b"word/_rels/document.xml.rels".as_slice(),
                ZIP_COMPRESSION_DEFLATE,
                relationship.as_slice(),
            ),
        ]);

        let analysis = analyze_zip(&bytes).unwrap();

        assert_eq!(analysis.ooxml_vba_project_count, 1);
        assert_eq!(analysis.ooxml_external_relationship_count, 0);
        assert_eq!(analysis.ooxml_remote_executable_relationship_count, 0);
        assert!(analysis.limit_exceeded);
    }

    #[test]
    fn zip_entry_extension_suffix_uses_explicit_empty_branch() {
        let analysis = analyze_zip(&zip_with_name(b"folder/tool.")).unwrap();
        assert!(!analysis.contains_executable);
        assert_eq!(zip_entry_extension_suffix("tool.exe"), Some("exe"));

        let source = include_str!("zip.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains("fn zip_entry_extension_suffix(name: &str) -> Option<&str>"));
        assert!(production.contains("let suffix = name.rsplit('.').next()?;"));
        assert!(production.contains("return None;"));
        assert!(!production.contains(".unwrap_or_default()"));
    }
}
