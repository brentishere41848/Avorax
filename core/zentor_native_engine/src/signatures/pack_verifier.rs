use anyhow::{bail, Result};

use super::known_bad_hashes::is_sha256;
use super::pack_format::SignaturePack;
use super::{NativeSignature, SignatureType};
use crate::engine::sha256_bytes;

pub const SIGNATURE_PACK_FORMAT: &str = "zentor-signature-pack-v1";
const MAX_SIGNATURES_PER_PACK: usize = 1024;

pub fn verify_pack(pack: &SignaturePack, canonical_bytes: &[u8]) -> Result<()> {
    if pack.format != SIGNATURE_PACK_FORMAT {
        bail!("unsupported signature pack format {}", pack.format);
    }
    if !is_valid_pack_version(&pack.version) {
        bail!("signature pack version must be a dotted numeric version");
    }
    if pack.signatures.len() > MAX_SIGNATURES_PER_PACK {
        bail!("signature pack contains too many signatures");
    }
    match pack.pack_sha256.as_deref() {
        Some(expected) => {
            if !is_sha256(expected) {
                bail!("signature pack hash is not a valid SHA-256 value");
            }
            let actual = sha256_bytes(canonical_bytes);
            if !expected.eq_ignore_ascii_case(&actual) {
                bail!("signature pack hash mismatch");
            }
        }
        None if !pack.signatures.is_empty() => {
            bail!("non-empty signature pack must declare pack_sha256");
        }
        None => {}
    }
    Ok(())
}

fn is_valid_pack_version(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed.split('.').all(|part| {
            !part.is_empty() && part.len() <= 10 && part.chars().all(|ch| ch.is_ascii_digit())
        })
}

pub fn broad_signature_count(signatures: &[NativeSignature]) -> usize {
    signatures
        .iter()
        .filter(|signature| is_broad(signature))
        .count()
}

pub fn is_broad(signature: &NativeSignature) -> bool {
    matches!(
        signature.signature_type,
        SignatureType::AsciiString
            | SignatureType::Utf16String
            | SignatureType::BytePattern
            | SignatureType::MaskedBytePattern
    ) && signature.pattern.replace([' ', '_'], "").len() < 12
}
