use std::path::Path;

use super::{byte_pattern_signatures, eicar_signature, hash_signatures, string_signatures};
use super::{NativeSignature, SignatureMatch, SignatureType};
use crate::analyzers::StaticAnalysis;
use crate::verdict::Confidence;

pub fn matches_signature(
    signature: &NativeSignature,
    _path: &Path,
    sha256: &str,
    bytes: &[u8],
    analysis: &StaticAnalysis,
) -> Option<SignatureMatch> {
    if let Some(min) = signature.min_file_size {
        if bytes.len() as u64 <= min {
            return None;
        }
    }
    if let Some(max) = signature.max_file_size {
        if bytes.len() as u64 >= max {
            return None;
        }
    }
    let matched = match signature.signature_type {
        SignatureType::ExactHash => hash_signatures::matches_exact_hash(sha256, &signature.pattern),
        SignatureType::PartialHash => sha256.starts_with(&signature.pattern.to_ascii_lowercase()),
        SignatureType::BytePattern => byte_pattern_signatures::contains_hex_pattern(bytes, &signature.pattern),
        SignatureType::MaskedBytePattern => byte_pattern_signatures::contains_masked_hex_pattern(
            bytes,
            &signature.pattern,
            signature.mask.as_deref().unwrap_or_default(),
        ),
        SignatureType::AsciiString | SignatureType::ScriptPattern => {
            string_signatures::contains_ascii(bytes, &signature.pattern)
        }
        SignatureType::Utf16String => string_signatures::contains_utf16(bytes, &signature.pattern),
        SignatureType::EicarTestSignature => eicar_signature::contains_eicar(bytes),
        SignatureType::PowershellEncodedCommand => analysis
            .script
            .as_ref()
            .map(|script| script.encoded_command)
            .unwrap_or(false),
        SignatureType::ArchiveNestedExecutable => analysis
            .archive
            .as_ref()
            .map(|archive| archive.contains_executable && archive.suspicious_nested_name_count > 0)
            .unwrap_or(false),
        SignatureType::PeImportCombo => analysis
            .pe
            .as_ref()
            .map(|pe| pe.suspicious_imports.process_injection > 0 && pe.suspicious_imports.network > 0)
            .unwrap_or(false),
        SignatureType::PeSectionEntropy => analysis
            .pe
            .as_ref()
            .map(|pe| pe.high_entropy_section_count > 0)
            .unwrap_or(false),
        SignatureType::PeResourceIndicator => false,
    };
    matched.then(|| SignatureMatch {
        signature_id: signature.id.clone(),
        name: signature.name.clone(),
        category: signature.category,
        confidence: signature.confidence,
        reason: format!("Pasus Native Signature matched: {}", signature.name),
        weight: match signature.confidence {
            Confidence::Confirmed => 100,
            Confidence::High => 45,
            Confidence::Medium => 25,
            Confidence::Low => 10,
        },
    })
}
