use anyhow::Result;

use crate::analyzers::archives::zip::{self, BoundedZipEntrySamples};

use super::cancellation::check_scan_cancellation;

pub fn max_archive_depth() -> usize {
    3
}

pub fn collect_bounded_zip_entry_samples(bytes: &[u8]) -> Result<BoundedZipEntrySamples> {
    zip::bounded_zip_entry_samples(bytes)
}

pub fn collect_bounded_zip_entry_samples_with_cancellation(
    bytes: &[u8],
    should_cancel: &mut dyn FnMut() -> Result<bool>,
) -> Result<BoundedZipEntrySamples> {
    check_scan_cancellation(should_cancel, "bounded archive collection preflight")?;
    let samples = collect_bounded_zip_entry_samples(bytes)?;
    check_scan_cancellation(should_cancel, "bounded archive collection completion")?;
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooperative_scan_cancellation_observes_bounded_archive_boundary() {
        let mut checks = 0_u32;
        let mut should_cancel = || {
            checks += 1;
            Ok(checks >= 2)
        };

        let error = collect_bounded_zip_entry_samples_with_cancellation(
            b"ordinary benign fixture",
            &mut should_cancel,
        )
        .expect_err("post-collection cancellation must stop archive analysis");

        assert!(super::super::cancellation::is_cooperative_scan_cancellation(&error));
        assert_eq!(checks, 2);
    }
}
