use anyhow::Result;

pub const TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES: usize = 64 * 1024;

pub fn ascii_lowercase_lossy_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<String> {
    let mut output = String::with_capacity(bytes.len());
    let mut pending = Vec::with_capacity(3);
    let mut buffer = Vec::with_capacity(TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES + 3);

    for chunk in bytes.chunks(TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES) {
        cancellation_checkpoint()?;
        buffer.clear();
        buffer.extend_from_slice(&pending);
        buffer.extend_from_slice(chunk);
        pending.clear();

        if let Some(pending_start) =
            append_ascii_lowercase_lossy_segment(&mut output, &buffer, false)?
        {
            pending.extend_from_slice(&buffer[pending_start..]);
        }
    }

    cancellation_checkpoint()?;
    if !pending.is_empty() {
        append_ascii_lowercase_lossy_segment(&mut output, &pending, true)?;
    }
    Ok(output)
}

fn append_ascii_lowercase_lossy_segment(
    output: &mut String,
    bytes: &[u8],
    final_segment: bool,
) -> Result<Option<usize>> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        match std::str::from_utf8(&bytes[offset..]) {
            Ok(valid) => {
                append_ascii_lowercase(output, valid);
                return Ok(None);
            }
            Err(error) => {
                let valid_end = offset.checked_add(error.valid_up_to()).ok_or_else(|| {
                    anyhow::anyhow!("provider text normalization offset overflow")
                })?;
                let valid = std::str::from_utf8(&bytes[offset..valid_end])?;
                append_ascii_lowercase(output, valid);
                offset = valid_end;

                match error.error_len() {
                    Some(invalid_len) => {
                        output.push('\u{fffd}');
                        offset = offset.checked_add(invalid_len).ok_or_else(|| {
                            anyhow::anyhow!("provider text normalization invalid-span overflow")
                        })?;
                    }
                    None if final_segment => {
                        output.push('\u{fffd}');
                        return Ok(None);
                    }
                    None => return Ok(Some(offset)),
                }
            }
        }
    }
    Ok(None)
}

fn append_ascii_lowercase(output: &mut String, valid: &str) {
    output.extend(valid.chars().map(|value| value.to_ascii_lowercase()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_provider_normalization_preserves_lossy_ascii_lowercase_semantics() {
        let fixtures: Vec<Vec<u8>> = vec![
            b"Ordinary BENIGN ASCII".to_vec(),
            "Straße Δ SAFE".as_bytes().to_vec(),
            vec![b'A', 0xff, b'B'],
            vec![0xf0, 0x9f],
            vec![0xe2, b'X', b'Z'],
            vec![0xf0, 0x9f, b'Q', b'R'],
        ];

        for bytes in fixtures {
            let mut never_cancel = || Ok(());
            let actual = ascii_lowercase_lossy_with_cancellation(&bytes, &mut never_cancel)
                .expect("benign provider normalization must succeed");
            let expected = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn native_provider_normalization_preserves_utf8_across_chunk_boundaries() {
        let mut valid = vec![b'A'; TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES - 1];
        valid.extend_from_slice("€SAFE".as_bytes());
        let mut invalid = vec![b'B'; TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES - 1];
        invalid.extend_from_slice(&[0xe2, b'X', b'Z']);

        for bytes in [valid, invalid] {
            let mut never_cancel = || Ok(());
            let actual = ascii_lowercase_lossy_with_cancellation(&bytes, &mut never_cancel)
                .expect("chunk-boundary normalization must succeed");
            assert_eq!(actual, String::from_utf8_lossy(&bytes).to_ascii_lowercase());
        }
    }

    #[test]
    fn native_provider_normalization_interrupts_between_bounded_chunks() {
        let bytes = vec![b'A'; TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign provider normalization cancellation")
            }
            Ok(())
        };

        let error = ascii_lowercase_lossy_with_cancellation(&bytes, &mut checkpoint)
            .expect_err("the second normalization chunk must propagate cancellation");

        assert!(error
            .to_string()
            .contains("benign provider normalization cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn native_provider_normalization_keeps_arbitrary_callback_errors_visible() {
        let mut checkpoint = || anyhow::bail!("benign normalization callback failure");

        let error = ascii_lowercase_lossy_with_cancellation(
            b"ordinary benign provider bytes",
            &mut checkpoint,
        )
        .expect_err("arbitrary normalization callback errors must propagate");

        assert!(error
            .to_string()
            .contains("benign normalization callback failure"));
    }
}
