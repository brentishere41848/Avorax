use std::path::Path;

use super::{byte_pattern_signatures, eicar_signature, hash_signatures, string_signatures};
use super::{NativeSignature, SignatureMatch, SignatureType};
use crate::analyzers::{FileType, StaticAnalysis};
use crate::verdict::Confidence;

pub fn matches_signature(
    signature: &NativeSignature,
    _path: &Path,
    sha256: &str,
    bytes: &[u8],
    analysis: &StaticAnalysis,
) -> Option<SignatureMatch> {
    if let Some(min) = signature.min_file_size {
        if (bytes.len() as u64) < min {
            return None;
        }
    }
    if let Some(max) = signature.max_file_size {
        if (bytes.len() as u64) > max {
            return None;
        }
    }
    if !file_type_allowed(signature, analysis.file_type) {
        return None;
    }
    if !required_context_matches(signature, analysis) {
        return None;
    }
    let matched = match signature.signature_type {
        SignatureType::ExactHash => hash_signatures::matches_exact_hash(sha256, &signature.pattern),
        SignatureType::PartialHash => sha256.starts_with(&signature.pattern.to_ascii_lowercase()),
        SignatureType::BytePattern => match signature.offset {
            Some(offset) => {
                byte_pattern_signatures::matches_hex_pattern_at(bytes, &signature.pattern, offset)
            }
            None => byte_pattern_signatures::contains_hex_pattern(bytes, &signature.pattern),
        },
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
            .map(|pe| {
                pe.suspicious_imports.process_injection > 0 && pe.suspicious_imports.network > 0
            })
            .unwrap_or(false),
        SignatureType::PeSectionEntropy => analysis
            .pe
            .as_ref()
            .map(|pe| pe.high_entropy_section_count > 0)
            .unwrap_or(false),
        SignatureType::PeResourceIndicator => analysis
            .pe
            .as_ref()
            .map(|pe| pe.overlay_size > 512 * 1024 || pe.certificate_table_present)
            .unwrap_or(false),
    };
    matched.then(|| SignatureMatch {
        signature_id: signature.id.clone(),
        name: signature.name.clone(),
        category: signature.category,
        confidence: signature.confidence,
        reason: format!("Avorax Native Signature matched: {}", signature.name),
        weight: match signature.confidence {
            Confidence::Confirmed => 100,
            Confidence::High => 45,
            Confidence::Medium => 25,
            Confidence::Low => 10,
        },
    })
}

fn file_type_allowed(signature: &NativeSignature, actual: FileType) -> bool {
    signature.file_types.iter().any(|file_type| {
        let normalized = file_type.to_ascii_lowercase();
        normalized == "*" || normalized == file_type_name(actual)
    })
}

fn required_context_matches(signature: &NativeSignature, analysis: &StaticAnalysis) -> bool {
    signature.required_context.iter().all(|context| {
        let normalized = context.to_ascii_lowercase();
        match normalized.as_str() {
            "encoded_command" => analysis
                .script
                .as_ref()
                .map(|script| script.encoded_command)
                .unwrap_or(false),
            "downloader_and_execution" => analysis
                .script
                .as_ref()
                .map(|script| script.downloader_patterns > 0 && script.execution_patterns > 0)
                .unwrap_or(false),
            "archive_nested_executable" => analysis
                .archive
                .as_ref()
                .map(|archive| {
                    archive.contains_executable && archive.suspicious_nested_name_count > 0
                })
                .unwrap_or(false),
            "high_entropy_section" => analysis
                .pe
                .as_ref()
                .map(|pe| pe.high_entropy_section_count > 0)
                .unwrap_or(false),
        "suspicious_import_combo" => analysis
                .pe
                .as_ref()
                .map(|pe| {
                    pe.suspicious_imports.process_injection > 0 && pe.suspicious_imports.network > 0
                })
                .unwrap_or(false),
            "credential_access_string" => {
                let text = analysis.string_indicators.suspicious_string_count;
                text > 0
            }
            "ransom_note_text" => true,
            "miner_pool_string" => true,
            "pup_adware_string" => true,
            value => {
                value.starts_with("exact ")
                    || value.starts_with("zentor ")
                    || value.contains("test")
                    || value.contains("safe")
                    || value.contains("review")
                    || value.contains("context")
            }
        }
    })
}

fn file_type_name(value: FileType) -> &'static str {
    match value {
        FileType::Pe => "pe",
        FileType::Elf => "elf",
        FileType::MachO => "macho",
        FileType::PowerShell => "powershell_script",
        FileType::JavaScript => "javascript",
        FileType::Batch => "batch",
        FileType::Vbs => "vbs",
        FileType::Zip => "zip",
        FileType::Text => "text",
        FileType::Document => "document",
        FileType::Unknown => "unknown",
    }
}
