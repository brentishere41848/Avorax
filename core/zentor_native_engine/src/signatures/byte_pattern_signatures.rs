use anyhow::{bail, Context, Result};

use super::search;

pub fn contains_hex_pattern(bytes: &[u8], pattern: &str) -> Result<bool> {
    let mut never_cancel = || Ok(());
    contains_hex_pattern_with_cancellation(bytes, pattern, &mut never_cancel)
}

pub fn contains_hex_pattern_with_cancellation(
    bytes: &[u8],
    pattern: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    let pattern = decode_hex(pattern, "byte pattern")?;
    search::contains_exact_with_cancellation(bytes, &pattern, cancellation_checkpoint)
}

pub fn matches_hex_pattern_at(bytes: &[u8], pattern: &str, offset: usize) -> Result<bool> {
    let pattern = decode_hex(pattern, "byte pattern")?;
    let Some(end) = offset.checked_add(pattern.len()) else {
        return Ok(false);
    };
    let Some(window) = bytes.get(offset..end) else {
        return Ok(false);
    };
    Ok(window == pattern.as_slice())
}

pub fn contains_masked_hex_pattern(bytes: &[u8], pattern: &str, mask: &str) -> Result<bool> {
    let mut never_cancel = || Ok(());
    contains_masked_hex_pattern_with_cancellation(bytes, pattern, mask, &mut never_cancel)
}

pub fn contains_masked_hex_pattern_with_cancellation(
    bytes: &[u8],
    pattern: &str,
    mask: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    let pattern = decode_hex(pattern, "masked byte pattern")?;
    let mask = decode_hex(mask, "masked byte mask")?;
    if pattern.len() != mask.len() {
        bail!("masked byte pattern mask length does not match pattern length");
    }
    search::contains_masked_with_cancellation(bytes, &pattern, &mask, cancellation_checkpoint)
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    let clean = value.replace([' ', '_'], "");
    if clean.is_empty() {
        bail!("{label} hex is empty");
    }
    if !clean.len().is_multiple_of(2) {
        bail!("{label} hex has odd length");
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for index in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[index..index + 2], 16)
            .with_context(|| format!("{label} hex contains invalid byte"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_pattern_offset_no_match_uses_explicit_branch() {
        assert!(!matches_hex_pattern_at(b"MZ", "4d5a", 1).unwrap());
        assert!(!matches_hex_pattern_at(b"MZ", "4d5a", usize::MAX).unwrap());

        let source = include_str!("byte_pattern_signatures.rs");
        let helper_start = source.find("pub fn matches_hex_pattern_at").unwrap();
        let helper_end = source.find("pub fn contains_masked_hex_pattern").unwrap();
        let helper_source = &source[helper_start..helper_end];

        assert!(helper_source.contains("offset.checked_add(pattern.len())"));
        assert!(helper_source.contains("let Some(window) = bytes.get(offset..end) else"));
        assert!(helper_source.contains("return Ok(false);"));
        assert!(!helper_source.contains(".unwrap_or(false)"));
    }

    #[test]
    fn native_provider_cancellation_preserves_byte_pattern_wrappers() {
        let bytes = b"ordinary-safe-prefix-DEADBEEF-suffix";
        let wrapped = contains_hex_pattern(bytes, "4445414442454546").unwrap();
        let masked =
            contains_masked_hex_pattern(bytes, "4040404040404040", "f0f0f0f0f0f0f0f0").unwrap();
        let mut never_cancel = || Ok(());
        let fallible =
            contains_hex_pattern_with_cancellation(bytes, "4445414442454546", &mut never_cancel)
                .unwrap();

        assert!(wrapped);
        assert!(masked);
        assert_eq!(wrapped, fallible);
    }
}
