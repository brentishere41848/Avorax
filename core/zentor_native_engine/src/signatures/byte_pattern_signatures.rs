use anyhow::{bail, Context, Result};

pub fn contains_hex_pattern(bytes: &[u8], pattern: &str) -> Result<bool> {
    let pattern = decode_hex(pattern, "byte pattern")?;
    Ok(bytes.windows(pattern.len()).any(|window| window == pattern))
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
    let pattern = decode_hex(pattern, "masked byte pattern")?;
    let mask = decode_hex(mask, "masked byte mask")?;
    if pattern.len() != mask.len() {
        bail!("masked byte pattern mask length does not match pattern length");
    }
    Ok(bytes.windows(pattern.len()).any(|window| {
        window
            .iter()
            .zip(pattern.iter())
            .zip(mask.iter())
            .all(|((actual, expected), mask)| (*actual & *mask) == (*expected & *mask))
    }))
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
}
