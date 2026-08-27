use anyhow::{bail, Result};

pub const SEARCH_CANCELLATION_CHUNK_CANDIDATES: usize = 64 * 1024;

#[cfg(test)]
pub fn contains_exact(bytes: &[u8], needle: &[u8]) -> Result<bool> {
    let mut never_cancel = || Ok(());
    contains_exact_with_cancellation(bytes, needle, &mut never_cancel)
}

pub fn contains_exact_with_cancellation(
    bytes: &[u8],
    needle: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    if needle.is_empty() {
        bail!("signature search needle is empty");
    }
    let Some(last_start) = bytes.len().checked_sub(needle.len()) else {
        cancellation_checkpoint()?;
        return Ok(false);
    };
    let candidate_count = last_start + 1;
    for chunk_start in (0..candidate_count).step_by(SEARCH_CANCELLATION_CHUNK_CANDIDATES) {
        cancellation_checkpoint()?;
        let chunk_end = chunk_start
            .saturating_add(SEARCH_CANCELLATION_CHUNK_CANDIDATES)
            .min(candidate_count);
        let search_end = chunk_end + (needle.len() - 1);
        if bytes[chunk_start..search_end]
            .windows(needle.len())
            .any(|window| window == needle)
        {
            return Ok(true);
        }
    }
    cancellation_checkpoint()?;
    Ok(false)
}

pub(crate) fn find_exact_with_cancellation(
    bytes: &[u8],
    needle: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<Option<usize>> {
    if needle.is_empty() {
        bail!("reference search needle is empty");
    }
    let Some(last_start) = bytes.len().checked_sub(needle.len()) else {
        cancellation_checkpoint()?;
        return Ok(None);
    };
    let candidate_count = last_start + 1;

    for chunk_start in (0..candidate_count).step_by(SEARCH_CANCELLATION_CHUNK_CANDIDATES) {
        cancellation_checkpoint()?;
        let chunk_end = chunk_start
            .saturating_add(SEARCH_CANCELLATION_CHUNK_CANDIDATES)
            .min(candidate_count);
        let search_end = chunk_end + needle.len() - 1;
        if let Some(relative_start) = bytes[chunk_start..search_end]
            .windows(needle.len())
            .position(|window| window == needle)
        {
            return Ok(Some(chunk_start + relative_start));
        }
    }

    cancellation_checkpoint()?;
    Ok(None)
}

pub(crate) fn count_exact_non_overlapping_with_cancellation(
    bytes: &[u8],
    needle: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    if needle.is_empty() {
        bail!("term search needle is empty");
    }
    let Some(last_start) = bytes.len().checked_sub(needle.len()) else {
        cancellation_checkpoint()?;
        return Ok(0);
    };
    let candidate_count = last_start + 1;
    let mut next_start = 0usize;
    let mut total = 0u32;

    while next_start < candidate_count {
        cancellation_checkpoint()?;
        let chunk_end = next_start
            .saturating_add(SEARCH_CANCELLATION_CHUNK_CANDIDATES)
            .min(candidate_count);
        let search_end = chunk_end + needle.len() - 1;

        while next_start < chunk_end {
            let Some(relative_start) = bytes[next_start..search_end]
                .windows(needle.len())
                .position(|window| window == needle)
            else {
                next_start = chunk_end;
                break;
            };
            let match_start = next_start + relative_start;
            total = total.saturating_add(1);
            next_start = match_start + needle.len();
        }
    }

    cancellation_checkpoint()?;
    Ok(total)
}

#[cfg(test)]
pub fn contains_masked(bytes: &[u8], pattern: &[u8], mask: &[u8]) -> Result<bool> {
    let mut never_cancel = || Ok(());
    contains_masked_with_cancellation(bytes, pattern, mask, &mut never_cancel)
}

pub fn contains_masked_with_cancellation(
    bytes: &[u8],
    pattern: &[u8],
    mask: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    if pattern.is_empty() {
        bail!("masked signature search pattern is empty");
    }
    if pattern.len() != mask.len() {
        bail!("masked signature search mask length does not match pattern length");
    }
    let Some(last_start) = bytes.len().checked_sub(pattern.len()) else {
        cancellation_checkpoint()?;
        return Ok(false);
    };
    let candidate_count = last_start + 1;
    for chunk_start in (0..candidate_count).step_by(SEARCH_CANCELLATION_CHUNK_CANDIDATES) {
        cancellation_checkpoint()?;
        let chunk_end = chunk_start
            .saturating_add(SEARCH_CANCELLATION_CHUNK_CANDIDATES)
            .min(candidate_count);
        let search_end = chunk_end + pattern.len() - 1;
        if bytes[chunk_start..search_end]
            .windows(pattern.len())
            .any(|window| {
                window
                    .iter()
                    .zip(pattern.iter())
                    .zip(mask.iter())
                    .all(|((actual, expected), mask)| (*actual & *mask) == (*expected & *mask))
            })
        {
            return Ok(true);
        }
    }
    cancellation_checkpoint()?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_provider_cancellation_interrupts_exact_search_chunks() {
        let bytes = vec![b'a'; SEARCH_CANCELLATION_CHUNK_CANDIDATES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign provider search cancellation")
            }
            Ok(())
        };

        let error = contains_exact_with_cancellation(&bytes, b"zz", &mut checkpoint)
            .expect_err("the second provider-search chunk must propagate cancellation");

        assert!(error
            .to_string()
            .contains("benign provider search cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn native_provider_cancellation_preserves_cross_chunk_and_masked_searches() {
        let boundary = SEARCH_CANCELLATION_CHUNK_CANDIDATES;
        let mut bytes = vec![0_u8; boundary + 8];
        bytes[boundary - 1..boundary + 3].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mut never_cancel = || Ok(());

        assert!(contains_exact(&bytes, &[0xde, 0xad, 0xbe, 0xef]).unwrap());
        assert!(contains_exact_with_cancellation(
            &bytes,
            &[0xde, 0xad, 0xbe, 0xef],
            &mut never_cancel,
        )
        .unwrap());
        assert!(contains_masked(&bytes, &[0xd0, 0xa0, 0xb0, 0xe0], &[0xf0; 4]).unwrap());
    }

    #[test]
    fn native_provider_cancellation_keeps_callback_errors_fail_visible() {
        let mut checkpoint = || anyhow::bail!("benign provider callback failure");

        let error = contains_masked_with_cancellation(
            b"ordinary benign bytes",
            b"safe",
            &[0xff; 4],
            &mut checkpoint,
        )
        .expect_err("arbitrary callback errors must not become no-match");

        assert!(error
            .to_string()
            .contains("benign provider callback failure"));
    }

    #[test]
    fn static_term_search_interrupts_shared_candidate_chunks() {
        let bytes = vec![b'a'; SEARCH_CANCELLATION_CHUNK_CANDIDATES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign static term-search cancellation")
            }
            Ok(())
        };

        let error = count_exact_non_overlapping_with_cancellation(&bytes, b"zz", &mut checkpoint)
            .expect_err("the second term-search chunk must propagate cancellation");

        assert!(error
            .to_string()
            .contains("benign static term-search cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_term_search_preserves_cross_chunk_and_non_overlapping_counts() {
        let boundary = SEARCH_CANCELLATION_CHUNK_CANDIDATES;
        let mut bytes = vec![b'x'; boundary + 16];
        bytes[boundary - 2..boundary + 2].copy_from_slice(b"safe");
        bytes[boundary + 7..boundary + 11].copy_from_slice(b"safe");
        let mut never_cancel = || Ok(());

        assert_eq!(
            count_exact_non_overlapping_with_cancellation(&bytes, b"safe", &mut never_cancel,)
                .unwrap(),
            2
        );
        assert_eq!(
            count_exact_non_overlapping_with_cancellation(b"aaaaa", b"aa", &mut never_cancel,)
                .unwrap(),
            "aaaaa".matches("aa").count() as u32
        );
    }

    #[test]
    fn static_term_search_rejects_empty_needles() {
        let mut never_cancel = || Ok(());
        let error =
            count_exact_non_overlapping_with_cancellation(b"ordinary", b"", &mut never_cancel)
                .expect_err("empty term needles must fail visibly");

        assert!(error.to_string().contains("term search needle is empty"));
    }

    #[test]
    fn static_reference_cancellation_interrupts_shared_find_chunks() {
        let bytes = vec![b'a'; SEARCH_CANCELLATION_CHUNK_CANDIDATES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign static reference-search cancellation")
            }
            Ok(())
        };

        let error = find_exact_with_cancellation(&bytes, b"zz", &mut checkpoint)
            .expect_err("the second reference-search chunk must propagate cancellation");

        assert!(error
            .to_string()
            .contains("benign static reference-search cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_reference_cancellation_preserves_first_cross_chunk_offset() {
        let boundary = SEARCH_CANCELLATION_CHUNK_CANDIDATES;
        let mut bytes = vec![b'x'; boundary + 24];
        bytes[boundary - 2..boundary + 2].copy_from_slice(b"safe");
        bytes[boundary + 10..boundary + 14].copy_from_slice(b"safe");
        let mut never_cancel = || Ok(());

        assert_eq!(
            find_exact_with_cancellation(&bytes, b"safe", &mut never_cancel).unwrap(),
            Some(boundary - 2)
        );
    }

    #[test]
    fn static_reference_cancellation_rejects_empty_find_needles() {
        let mut never_cancel = || Ok(());
        let error = find_exact_with_cancellation(b"ordinary", b"", &mut never_cancel)
            .expect_err("empty reference-search needles must fail visibly");

        assert!(error
            .to_string()
            .contains("reference search needle is empty"));
    }
}
