use std::path::Path;

use anyhow::{bail, Result};

use super::{byte_pattern_signatures, eicar_signature, hash_signatures, string_signatures};
use super::{NativeSignature, SignatureMatch, SignatureType};
use crate::analyzers::{archives, pe, scripts, FileType, StaticAnalysis};
use crate::verdict::Confidence;

pub fn matches_signature(
    signature: &NativeSignature,
    _path: &Path,
    sha256: &str,
    bytes: &[u8],
    analysis: &StaticAnalysis,
) -> Result<Option<SignatureMatch>> {
    if let Some(min) = signature.min_file_size {
        if (bytes.len() as u64) < min {
            return Ok(None);
        }
    }
    if let Some(max) = signature.max_file_size {
        if (bytes.len() as u64) > max {
            return Ok(None);
        }
    }
    if !file_type_allowed(signature, analysis.file_type)? {
        return Ok(None);
    }
    if !required_context_matches(signature, bytes, analysis)? {
        return Ok(None);
    }
    let matched = match signature.signature_type {
        SignatureType::ExactHash => {
            hash_signatures::matches_exact_hash(sha256, &signature.pattern)?
        }
        SignatureType::PartialHash => {
            hash_signatures::matches_partial_hash(sha256, &signature.pattern)?
        }
        SignatureType::BytePattern => match signature.offset {
            Some(offset) => {
                byte_pattern_signatures::matches_hex_pattern_at(bytes, &signature.pattern, offset)?
            }
            None => byte_pattern_signatures::contains_hex_pattern(bytes, &signature.pattern)?,
        },
        SignatureType::MaskedBytePattern => {
            let Some(mask) = signature.mask.as_deref() else {
                bail!(
                    "masked byte pattern signature {} is missing mask",
                    signature.id
                );
            };
            byte_pattern_signatures::contains_masked_hex_pattern(bytes, &signature.pattern, mask)?
        }
        SignatureType::AsciiString | SignatureType::ScriptPattern => {
            string_signatures::contains_ascii(bytes, &signature.pattern)?
        }
        SignatureType::Utf16String => string_signatures::contains_utf16(bytes, &signature.pattern)?,
        SignatureType::EicarTestSignature => eicar_signature::contains_eicar(bytes),
        SignatureType::PowershellEncodedCommand => {
            match expected_script_analysis(signature, analysis)? {
                Some(script) => script.encoded_command,
                None => false,
            }
        }
        SignatureType::ArchiveNestedExecutable => {
            match expected_archive_analysis(signature, analysis)? {
                Some(archive) => {
                    archive.contains_executable && archive.suspicious_nested_name_count > 0
                }
                None => false,
            }
        }
        SignatureType::PeImportCombo => match expected_pe_analysis(signature, analysis)? {
            Some(pe) => {
                pe.suspicious_imports.process_injection > 0 && pe.suspicious_imports.network > 0
            }
            None => false,
        },
        SignatureType::PeSectionEntropy => match expected_pe_analysis(signature, analysis)? {
            Some(pe) => pe.high_entropy_section_count > 0,
            None => false,
        },
        SignatureType::PeResourceIndicator => match expected_pe_analysis(signature, analysis)? {
            Some(pe) => {
                pe.overlay_size > 512 * 1024
                    || pe.certificate_table_present
                    || pe.resource_directory_entry_count >= 24
            }
            None => false,
        },
    };
    Ok(matched.then(|| SignatureMatch {
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
    }))
}

fn expected_script_analysis<'a>(
    signature: &NativeSignature,
    analysis: &'a StaticAnalysis,
) -> Result<Option<&'a scripts::ScriptAnalysis>> {
    if let Some(script) = analysis.script.as_ref() {
        return Ok(Some(script));
    }
    if matches!(
        analysis.file_type,
        FileType::PowerShell | FileType::JavaScript | FileType::Batch | FileType::Vbs
    ) {
        bail!(
            "signature {} requires script analysis for {:?}",
            signature.id,
            analysis.file_type
        );
    }
    Ok(None)
}

fn expected_archive_analysis<'a>(
    signature: &NativeSignature,
    analysis: &'a StaticAnalysis,
) -> Result<Option<&'a archives::ArchiveAnalysis>> {
    if let Some(archive) = analysis.archive.as_ref() {
        return Ok(Some(archive));
    }
    if analysis.file_type == FileType::Zip {
        bail!(
            "signature {} requires archive analysis for {:?}",
            signature.id,
            analysis.file_type
        );
    }
    Ok(None)
}

fn expected_pe_analysis<'a>(
    signature: &NativeSignature,
    analysis: &'a StaticAnalysis,
) -> Result<Option<&'a pe::PeAnalysis>> {
    if let Some(pe) = analysis.pe.as_ref() {
        return Ok(Some(pe));
    }
    if analysis.file_type == FileType::Pe {
        bail!(
            "signature {} requires PE analysis for {:?}",
            signature.id,
            analysis.file_type
        );
    }
    Ok(None)
}

fn file_type_allowed(signature: &NativeSignature, actual: FileType) -> Result<bool> {
    if signature.file_types.is_empty() {
        bail!("signature {} must declare file_types", signature.id);
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
        match normalized.as_str() {
            "*" => return Ok(true),
            "pe" | "elf" | "macho" | "powershell_script" | "javascript" | "batch" | "vbs"
            | "zip" | "text" | "document" | "unknown" => {
                if normalized == file_type_name(actual) {
                    return Ok(true);
                }
            }
            _ => bail!(
                "signature {} uses unsupported file_type filter {}",
                signature.id,
                file_type
            ),
        }
    }
    Ok(false)
}

fn required_context_matches(
    signature: &NativeSignature,
    bytes: &[u8],
    analysis: &StaticAnalysis,
) -> Result<bool> {
    let sample_text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for context in &signature.required_context {
        let normalized = context.to_ascii_lowercase();
        let matched = match normalized.as_str() {
            "exact eicar safe test string."
            | "avorax safe simulator string used only for local validation tests." => true,
            "encoded command plus downloader or execution context from native analyzers." => {
                match expected_script_analysis(signature, analysis)? {
                    Some(script) => script.encoded_command,
                    None => false,
                }
            }
            "ransom-note-like text; requires behavior or additional context for automatic response." => {
                true
            }
            "encoded_command" => match expected_script_analysis(signature, analysis)? {
                Some(script) => script.encoded_command,
                None => false,
            },
            "downloader_and_execution" => match expected_script_analysis(signature, analysis)? {
                Some(script) => script.downloader_patterns > 0 && script.execution_patterns > 0,
                None => false,
            },
            "archive_nested_executable" => match expected_archive_analysis(signature, analysis)? {
                Some(archive) => {
                    archive.contains_executable && archive.suspicious_nested_name_count > 0
                }
                None => false,
            },
            "high_entropy_section" => match expected_pe_analysis(signature, analysis)? {
                Some(pe) => pe.high_entropy_section_count > 0,
                None => false,
            },
            "suspicious_import_combo" => match expected_pe_analysis(signature, analysis)? {
                Some(pe) => {
                    pe.suspicious_imports.process_injection > 0 && pe.suspicious_imports.network > 0
                }
                None => false,
            },
            "credential_access_string" => {
                contains_any(
                    &sample_text,
                    &[
                        "login data",
                        "cookies.sqlite",
                        "local state",
                        "wallet.dat",
                        "token grab",
                        "browser credentials",
                    ],
                )
            }
            "ransom_note_text" => contains_any(
                &sample_text,
                &[
                    "your files have been encrypted",
                    "recover your files",
                    "decrypt your files",
                    "ransom note",
                ],
            ),
            "miner_pool_string" => contains_any(
                &sample_text,
                &["stratum+tcp", "xmrpool", "xmrig", "mining pool", "monero"],
            ),
            "pup_adware_string" => contains_any(
                &sample_text,
                &[
                    "silentinstall",
                    "browser extension install",
                    "search hijack",
                    "offer bundle",
                    "unwanted toolbar",
                ],
            ),
            _ => bail!(
                "signature {} uses unsupported required_context {}",
                signature.id,
                context
            ),
        };
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
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
