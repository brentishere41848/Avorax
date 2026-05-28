use anyhow::{bail, Result};

use super::{NativeSignature, SignatureType};
use crate::verdict::Confidence;

pub fn validate_signatures(signatures: &[NativeSignature]) -> Result<()> {
    for signature in signatures {
        if signature.id.trim().is_empty()
            || signature.name.trim().is_empty()
            || signature.false_positive_notes.trim().is_empty()
        {
            bail!("signature {} is missing required metadata", signature.id);
        }
        if matches!(
            signature.signature_type,
            SignatureType::AsciiString | SignatureType::Utf16String | SignatureType::BytePattern
        ) && signature.pattern.len() < 8
            && signature.confidence != Confidence::Low
        {
            bail!(
                "broad signature {} must be low confidence/review-only",
                signature.id
            );
        }
    }
    Ok(())
}
