use std::path::Path;

use anyhow::Result;

use super::{microsoft_trust, zentor_trust};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedPublisher {
    Microsoft,
    Avorax,
}

pub fn trusted_publisher_for(path: &Path) -> Result<Option<TrustedPublisher>> {
    if microsoft_trust::microsoft_signature_verdict(path)? {
        return Ok(Some(TrustedPublisher::Microsoft));
    }
    if zentor_trust::is_zentor_path(path)? {
        return Ok(Some(TrustedPublisher::Avorax));
    }
    Ok(None)
}
