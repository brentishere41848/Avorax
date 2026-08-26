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
    let samples = {
        let mut cancellation_checkpoint =
            || check_scan_cancellation(should_cancel, "bounded archive collection progress");
        zip::bounded_zip_entry_samples_with_cancellation(bytes, &mut cancellation_checkpoint)?
    };
    check_scan_cancellation(should_cancel, "bounded archive collection completion")?;
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_local_header_entry(name: &[u8], body: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        archive.extend_from_slice(b"PK\x03\x04");
        archive.extend_from_slice(&20_u16.to_le_bytes());
        archive.extend_from_slice(&0_u16.to_le_bytes());
        archive.extend_from_slice(&0_u16.to_le_bytes());
        archive.extend_from_slice(&0_u16.to_le_bytes());
        archive.extend_from_slice(&0_u16.to_le_bytes());
        archive.extend_from_slice(&0_u32.to_le_bytes());
        archive.extend_from_slice(&(body.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(body.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0_u16.to_le_bytes());
        archive.extend_from_slice(name);
        archive.extend_from_slice(body);
        archive
    }

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

    #[test]
    fn cooperative_archive_cancellation_remains_typed_during_collection() {
        let archive = stored_local_header_entry(b"benign/readme.txt", b"ordinary body");
        let mut checks = 0_u32;
        let mut should_cancel = || {
            checks += 1;
            Ok(checks >= 2)
        };

        let error =
            collect_bounded_zip_entry_samples_with_cancellation(&archive, &mut should_cancel)
                .expect_err("intra-collection cancellation must remain typed");

        assert!(super::super::cancellation::is_cooperative_scan_cancellation(&error));
        assert!(error
            .to_string()
            .contains("bounded archive collection progress"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn cooperative_archive_cancellation_probe_failure_remains_fail_visible_during_collection() {
        let archive = stored_local_header_entry(b"benign/readme.txt", b"ordinary body");
        let mut checks = 0_u32;
        let mut should_cancel = || {
            checks += 1;
            if checks >= 2 {
                anyhow::bail!("benign archive token probe failure");
            }
            Ok(false)
        };

        let error =
            collect_bounded_zip_entry_samples_with_cancellation(&archive, &mut should_cancel)
                .expect_err("intra-collection probe failure must remain fail-visible");

        assert!(!super::super::cancellation::is_cooperative_scan_cancellation(&error));
        assert!(super::super::cancellation::is_scan_cancellation_check_failure(&error));
        assert!(error
            .to_string()
            .contains("bounded archive collection progress"));
        assert!(error
            .to_string()
            .contains("benign archive token probe failure"));
        assert_eq!(checks, 2);
    }
}
