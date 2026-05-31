use std::path::Path;

use super::{microsoft_trust, zentor_trust};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedPublisher {
    Microsoft,
    Zentor,
}

pub fn trusted_publisher_for(path: &Path) -> Option<TrustedPublisher> {
    if microsoft_trust::has_valid_microsoft_signature(path) {
        return Some(TrustedPublisher::Microsoft);
    }
    if zentor_trust::is_zentor_path(path) || zentor_trust::has_zentor_artifact_name(path) {
        return Some(TrustedPublisher::Zentor);
    }
    None
}
