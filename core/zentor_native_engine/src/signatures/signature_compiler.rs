use anyhow::{bail, Result};
use chrono::Utc;
use serde_json::Value;
use std::collections::HashSet;

use super::pack_format::{SignaturePack, SignaturePackMetadata};
use super::pack_verifier::{broad_signature_count, is_broad, SIGNATURE_PACK_FORMAT};
use super::{NativeSignature, SignatureType};
use crate::engine::sha256_bytes;
use crate::signatures::hash_signatures::MIN_PARTIAL_HASH_HEX_LEN;
use crate::signatures::known_bad_hashes::{is_sha256, normalize_hash};
use crate::verdict::{Confidence, Verdict};

const MAX_SIGNATURE_NAME_LEN: usize = 160;
const MAX_SIGNATURE_NOTES_LEN: usize = 512;
const MAX_SIGNATURE_PATTERN_LEN: usize = 4096;
const MAX_SIGNATURE_CONTEXT_LEN: usize = 160;

pub fn validate_signatures(signatures: &[NativeSignature]) -> Result<()> {
    let mut seen_ids = HashSet::new();
    for signature in signatures {
        if signature.id.trim().is_empty()
            || signature.name.trim().is_empty()
            || signature.false_positive_notes.trim().is_empty()
        {
            bail!("signature {} is missing required metadata", signature.id);
        }
        validate_signature_identity(signature)?;
        validate_signature_metadata_bounds(signature)?;
        if !seen_ids.insert(signature.id.as_str()) {
            bail!("duplicate signature id {}", signature.id);
        }
        if is_broad(signature) && signature.confidence != Confidence::Low {
            bail!(
                "broad signature {} must be low confidence/review-only",
                signature.id
            );
        }
        if matches!(signature.confidence, Confidence::Confirmed)
            && !matches!(
                signature.signature_type,
                SignatureType::ExactHash | SignatureType::EicarTestSignature
            )
            && signature.action_policy != "quarantine_if_policy_allows"
            && signature.action_policy != "block_or_quarantine_if_policy_allows"
        {
            bail!(
                "confirmed signature {} must use an explicit blocking/quarantine policy",
                signature.id
            );
        }
        if signature.file_types.is_empty() {
            bail!("signature {} must declare file_types", signature.id);
        }
        validate_signature_filters(signature)?;
        if signature.pattern.trim().is_empty() {
            bail!(
                "signature {} must include a non-empty pattern",
                signature.id
            );
        }
        validate_string_signature_pattern(signature)?;
        validate_hash_signature(signature)?;
        validate_byte_pattern_signature(signature)?;
        validate_action_policy(signature)?;
        validate_required_context(signature)?;
    }
    Ok(())
}

fn validate_string_signature_pattern(signature: &NativeSignature) -> Result<()> {
    if matches!(
        signature.signature_type,
        SignatureType::AsciiString | SignatureType::Utf16String | SignatureType::ScriptPattern
    ) && signature.pattern != signature.pattern.trim()
    {
        bail!(
            "signature {} uses non-canonical string pattern",
            signature.id
        );
    }
    Ok(())
}

fn validate_signature_metadata_bounds(signature: &NativeSignature) -> Result<()> {
    if signature.name.trim().len() > MAX_SIGNATURE_NAME_LEN {
        bail!("signature {} name is too long", signature.id);
    }
    if signature.false_positive_notes.trim().len() > MAX_SIGNATURE_NOTES_LEN {
        bail!(
            "signature {} false_positive_notes is too long",
            signature.id
        );
    }
    if signature.pattern.trim().len() > MAX_SIGNATURE_PATTERN_LEN {
        bail!("signature {} pattern is too long", signature.id);
    }
    for context in &signature.required_context {
        if context.trim().len() > MAX_SIGNATURE_CONTEXT_LEN {
            bail!("signature {} required_context is too long", signature.id);
        }
    }
    Ok(())
}

fn validate_signature_filters(signature: &NativeSignature) -> Result<()> {
    if !matches!(
        signature.severity.as_str(),
        "test" | "low" | "medium" | "high" | "critical"
    ) {
        bail!(
            "signature {} uses unsupported severity {}",
            signature.id,
            signature.severity
        );
    }
    for file_type in &signature.file_types {
        let normalized = file_type.trim().to_ascii_lowercase();
        if file_type != &normalized {
            bail!(
                "signature {} uses non-canonical file_type filter {}",
                signature.id,
                file_type
            );
        }
        if !matches!(
            normalized.as_str(),
            "*" | "pe"
                | "elf"
                | "macho"
                | "powershell_script"
                | "javascript"
                | "batch"
                | "vbs"
                | "zip"
                | "text"
                | "document"
                | "unknown"
        ) {
            bail!(
                "signature {} uses unsupported file_type filter {}",
                signature.id,
                file_type
            );
        }
    }
    if let (Some(min), Some(max)) = (signature.min_file_size, signature.max_file_size) {
        if min > max {
            bail!("signature {} has invalid file size bounds", signature.id);
        }
    }
    Ok(())
}

fn validate_signature_identity(signature: &NativeSignature) -> Result<()> {
    if !is_valid_definition_id(&signature.id) {
        bail!("signature {} uses an unsafe id", signature.id);
    }
    if !is_valid_definition_version(&signature.version) {
        bail!(
            "signature {} version must be a dotted numeric version",
            signature.id
        );
    }
    Ok(())
}

fn is_valid_definition_id(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 96
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
}

fn is_valid_definition_version(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed.split('.').all(|part| {
            !part.is_empty() && part.len() <= 10 && part.chars().all(|ch| ch.is_ascii_digit())
        })
}

pub fn recognized_required_context(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "encoded_command"
            | "downloader_and_execution"
            | "archive_nested_executable"
            | "high_entropy_section"
            | "suspicious_import_combo"
            | "credential_access_string"
            | "ransom_note_text"
            | "miner_pool_string"
            | "pup_adware_string"
            | "exact eicar safe test string."
            | "encoded command plus downloader or execution context from native analyzers."
            | "ransom-note-like text; requires behavior or additional context for automatic response."
            | "avorax safe simulator string used only for local validation tests."
    )
}

fn validate_required_context(signature: &NativeSignature) -> Result<()> {
    for context in &signature.required_context {
        if context != context.trim() {
            bail!(
                "signature {} uses non-canonical required_context {}",
                signature.id,
                context
            );
        }
        if !recognized_required_context(context) {
            bail!(
                "signature {} uses unsupported required_context {}",
                signature.id,
                context
            );
        }
    }
    Ok(())
}

fn validate_hash_signature(signature: &NativeSignature) -> Result<()> {
    match signature.signature_type {
        SignatureType::ExactHash => {
            if !is_sha256(&signature.pattern) {
                bail!(
                    "exact hash signature {} must use a valid SHA-256 pattern",
                    signature.id
                );
            }
        }
        SignatureType::PartialHash => {
            let pattern = normalize_hash(&signature.pattern);
            if pattern.len() < MIN_PARTIAL_HASH_HEX_LEN
                || pattern.len() > 64
                || !pattern.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                bail!(
                    "partial hash signature {} must use at least {} hex SHA-256 prefix characters",
                    signature.id,
                    MIN_PARTIAL_HASH_HEX_LEN
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_byte_pattern_signature(signature: &NativeSignature) -> Result<()> {
    match signature.signature_type {
        SignatureType::BytePattern => {
            if !valid_hex_bytes(&signature.pattern) {
                bail!(
                    "byte pattern signature {} must use valid even-length hex bytes",
                    signature.id
                );
            }
        }
        SignatureType::MaskedBytePattern => {
            if !valid_hex_bytes(&signature.pattern) {
                bail!(
                    "masked byte pattern signature {} must use valid even-length hex bytes",
                    signature.id
                );
            }
            let Some(mask) = signature.mask.as_deref() else {
                bail!(
                    "masked byte pattern signature {} must declare mask",
                    signature.id
                );
            };
            if !valid_hex_bytes(mask) {
                bail!(
                    "masked byte pattern signature {} must use a valid even-length hex mask",
                    signature.id
                );
            }
            if compact_hex_len(&signature.pattern) != compact_hex_len(mask) {
                bail!(
                    "masked byte pattern signature {} mask length must match pattern length",
                    signature.id
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_hex_bytes(value: &str) -> bool {
    let compact = value.replace([' ', '_'], "");
    !compact.is_empty()
        && compact.len() % 2 == 0
        && compact.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn compact_hex_len(value: &str) -> usize {
    value.replace([' ', '_'], "").len()
}

fn validate_action_policy(signature: &NativeSignature) -> Result<()> {
    if !matches!(
        signature.action_policy.as_str(),
        "observe"
            | "review_only"
            | "review_or_block_by_policy"
            | "quarantine_if_policy_allows"
            | "block_or_quarantine_if_policy_allows"
    ) {
        bail!(
            "signature {} uses unsupported action_policy {}",
            signature.id,
            signature.action_policy
        );
    }
    Ok(())
}

pub fn compile_pack(
    mut signatures: Vec<NativeSignature>,
    version: String,
) -> Result<(SignaturePack, SignaturePackMetadata)> {
    signatures.sort_by(|left, right| left.id.cmp(&right.id));
    validate_signatures(&signatures)?;
    let created_at = Utc::now();
    let mut pack = SignaturePack {
        format: SIGNATURE_PACK_FORMAT.to_string(),
        version: version.clone(),
        compiler_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        created_at: Some(created_at),
        pack_sha256: None,
        signatures,
    };
    let canonical = canonical_pack_bytes(&pack)?;
    let pack_sha256 = sha256_bytes(&canonical);
    pack.pack_sha256 = Some(pack_sha256.clone());
    let metadata = SignaturePackMetadata {
        format: SIGNATURE_PACK_FORMAT.to_string(),
        version,
        compiler_version: env!("CARGO_PKG_VERSION").to_string(),
        signature_count: pack.signatures.len(),
        pack_sha256,
        created_at,
        broad_signature_count: broad_signature_count(&pack.signatures),
        confirmed_signature_count: pack
            .signatures
            .iter()
            .filter(|signature| signature.confidence == Confidence::Confirmed)
            .count(),
    };
    Ok((pack, metadata))
}

pub fn canonical_pack_bytes(pack: &SignaturePack) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(pack)?;
    if let Value::Object(object) = &mut value {
        object.remove("pack_sha256");
    }
    Ok(serde_json::to_vec(&value)?)
}

#[allow(dead_code)]
pub fn verdict_from_action_policy(action_policy: &str) -> Result<Verdict> {
    let verdict = match action_policy {
        "quarantine_if_policy_allows" | "block_or_quarantine_if_policy_allows" => {
            Verdict::ConfirmedMalware
        }
        "review_or_block_by_policy" => Verdict::Suspicious,
        "observe" | "review_only" => Verdict::Observation,
        _ => bail!("unsupported signature action_policy {action_policy}"),
    };
    Ok(verdict)
}

#[cfg(test)]
mod source_tests {
    use super::*;

    #[test]
    fn action_policy_to_verdict_rejects_unknown_policy() {
        assert_eq!(
            verdict_from_action_policy("quarantine_if_policy_allows").unwrap(),
            Verdict::ConfirmedMalware
        );
        assert_eq!(
            verdict_from_action_policy("block_or_quarantine_if_policy_allows").unwrap(),
            Verdict::ConfirmedMalware
        );
        assert_eq!(
            verdict_from_action_policy("review_or_block_by_policy").unwrap(),
            Verdict::Suspicious
        );
        assert_eq!(
            verdict_from_action_policy("observe").unwrap(),
            Verdict::Observation
        );
        assert_eq!(
            verdict_from_action_policy("review_only").unwrap(),
            Verdict::Observation
        );
        let error = verdict_from_action_policy("delete_immediately")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported signature action_policy"));

        let source = include_str!("signature_compiler.rs");
        let helper_start = source.find("pub fn verdict_from_action_policy").unwrap();
        let test_start = source.find("#[cfg(test)]").unwrap();
        let helper_source = &source[helper_start..test_start];

        assert!(helper_source.contains("Result<Verdict>"));
        assert!(helper_source.contains("unsupported signature action_policy"));
        assert!(!helper_source.contains("_ => Verdict::Observation"));
    }
}
