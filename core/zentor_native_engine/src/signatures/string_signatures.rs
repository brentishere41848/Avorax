use anyhow::{bail, Result};

use super::{search, text};

pub fn contains_ascii(bytes: &[u8], needle: &str) -> Result<bool> {
    let mut never_cancel = || Ok(());
    contains_ascii_with_cancellation(bytes, needle, &mut never_cancel)
}

pub fn contains_ascii_with_cancellation(
    bytes: &[u8],
    needle: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    validate_string_pattern(needle)?;
    let lower = text::ascii_lowercase_lossy_with_cancellation(bytes, cancellation_checkpoint)?;
    contains_ascii_in_lower_text_with_cancellation(&lower, needle, cancellation_checkpoint)
}

pub(crate) fn contains_ascii_in_lower_text_with_cancellation(
    lower_text: &str,
    needle: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    validate_string_pattern(needle)?;
    let normalized = needle.to_ascii_lowercase();
    search::contains_exact_with_cancellation(
        lower_text.as_bytes(),
        normalized.as_bytes(),
        cancellation_checkpoint,
    )
}

pub fn contains_utf16(bytes: &[u8], needle: &str) -> Result<bool> {
    let mut never_cancel = || Ok(());
    contains_utf16_with_cancellation(bytes, needle, &mut never_cancel)
}

pub fn contains_utf16_with_cancellation(
    bytes: &[u8],
    needle: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    validate_string_pattern(needle)?;
    let encoded = needle
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    search::contains_exact_with_cancellation(bytes, &encoded, cancellation_checkpoint)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_provider_cancellation_preserves_string_signature_wrappers() {
        let ascii = b"Ordinary BENIGN provider marker";
        let utf16 = "Ordinary benign UTF16"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let mut never_cancel = || Ok(());

        assert_eq!(
            contains_ascii(ascii, "benign provider").unwrap(),
            contains_ascii_with_cancellation(ascii, "benign provider", &mut never_cancel).unwrap()
        );
        assert_eq!(
            contains_utf16(&utf16, "benign UTF16").unwrap(),
            contains_utf16_with_cancellation(&utf16, "benign UTF16", &mut never_cancel).unwrap()
        );
    }

    #[test]
    fn native_provider_normalization_interrupts_ascii_wrapper_between_chunks() {
        let bytes = vec![b'A'; text::TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign ASCII normalization cancellation")
            }
            Ok(())
        };

        let error = contains_ascii_with_cancellation(&bytes, "marker", &mut checkpoint)
            .expect_err("ASCII wrapper must propagate in-normalization cancellation");

        assert!(error
            .to_string()
            .contains("benign ASCII normalization cancellation"));
        assert_eq!(checks, 2);
    }
}
