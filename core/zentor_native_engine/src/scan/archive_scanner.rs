use anyhow::Result;

use crate::analyzers::archives::zip::{self, BoundedZipEntrySamples};

pub fn max_archive_depth() -> usize {
    3
}

pub fn collect_bounded_zip_entry_samples(bytes: &[u8]) -> Result<BoundedZipEntrySamples> {
    zip::bounded_zip_entry_samples(bytes)
}
