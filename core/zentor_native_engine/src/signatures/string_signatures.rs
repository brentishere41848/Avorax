use anyhow::{bail, Result};

pub fn contains_ascii(bytes: &[u8], needle: &str) -> Result<bool> {
    validate_string_pattern(needle)?;
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    Ok(lower.contains(&needle.to_ascii_lowercase()))
}

pub fn contains_utf16(bytes: &[u8], needle: &str) -> Result<bool> {
    validate_string_pattern(needle)?;
    let encoded = needle
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    Ok(bytes.windows(encoded.len()).any(|window| window == encoded))
}

fn validate_string_pattern(needle: &str) -> Result<()> {
    if needle.trim().is_empty() {
        bail!("string signature pattern is empty");
    }
    if needle != needle.trim() {
        bail!("string signature pattern is non-canonical");
    }
    Ok(())
}
