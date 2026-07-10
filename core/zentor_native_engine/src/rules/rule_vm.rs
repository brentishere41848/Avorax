use std::path::Path;

use anyhow::{bail, Result};

use super::{NativeRule, RuleCondition, RuleMatch};
use crate::analyzers::{archives, pe, scripts, FileType, StaticAnalysis};
use crate::verdict::{Confidence, Verdict};

pub fn evaluate_rule(
    rule: &NativeRule,
    path: &Path,
    bytes: &[u8],
    analysis: &StaticAnalysis,
) -> Result<Option<RuleMatch>> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let path_text = path.display().to_string().to_ascii_lowercase();
    let mut matches = 0;
    for condition in &rule.conditions {
        if condition_matches(rule, condition, &text, &path_text, bytes, analysis)? {
            matches += 1;
        }
    }
    if matches < rule.min_condition_matches {
        return Ok(None);
    }
    Ok(Some(RuleMatch {
        rule_id: rule.id.clone(),
        name: rule.name.clone(),
        category: rule.category,
        confidence: rule.confidence,
        verdict: rule.verdict,
        reason: format!("Avorax Native Rule matched: {}", rule.name),
        weight: rule_match_weight(rule.verdict, rule.confidence),
    }))
}

fn rule_match_weight(verdict: Verdict, confidence: Confidence) -> i32 {
    match (verdict, confidence) {
        (Verdict::ConfirmedMalware | Verdict::TestThreat, Confidence::Confirmed) => 100,
        (Verdict::ProbableMalware, Confidence::High) => 65,
        (Verdict::Suspicious, Confidence::High | Confidence::Medium) => 40,
        (
            Verdict::Clean | Verdict::LikelyClean | Verdict::Unknown | Verdict::Observation,
            Confidence::Low | Confidence::Medium | Confidence::High | Confidence::Confirmed,
        )
        | (Verdict::Suspicious, Confidence::Low | Confidence::Confirmed)
        | (
            Verdict::ProbableMalware,
            Confidence::Low | Confidence::Medium | Confidence::Confirmed,
        )
        | (
            Verdict::ConfirmedMalware | Verdict::TestThreat,
            Confidence::Low | Confidence::Medium | Confidence::High,
        ) => 15,
    }
}

fn condition_matches(
    rule: &NativeRule,
    condition: &RuleCondition,
    text: &str,
    path_text: &str,
    bytes: &[u8],
    analysis: &StaticAnalysis,
) -> Result<bool> {
    Ok(match condition {
        RuleCondition::FileType { equals } => file_type_name(analysis.file_type) == equals,
        RuleCondition::ContainsAscii { value } => {
            let value = validated_string_condition(rule, value)?;
            text.contains(&value.to_ascii_lowercase())
        }
        RuleCondition::ContainsUtf16 { value } => {
            let value = validated_string_condition(rule, value)?;
            let encoded = value
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect::<Vec<_>>();
            !encoded.is_empty() && bytes.windows(encoded.len()).any(|window| window == encoded)
        }
        RuleCondition::EntropyGreaterThan { value } => analysis.entropy_max > *value,
        RuleCondition::SuspiciousImportsAtLeast { value } => {
            match expected_pe_analysis(rule, analysis)? {
                Some(pe) => {
                    pe.suspicious_imports.process_injection
                        + pe.suspicious_imports.credential_access
                        + pe.suspicious_imports.persistence
                        + pe.suspicious_imports.network
                        >= *value
                }
                None => false,
            }
        }
        RuleCondition::EncodedCommand => match expected_script_analysis(rule, analysis)? {
            Some(script) => script.encoded_command,
            None => false,
        },
        RuleCondition::DownloaderAndExecution => match expected_script_analysis(rule, analysis)? {
            Some(script) => script.downloader_patterns > 0 && script.execution_patterns > 0,
            None => false,
        },
        RuleCondition::ArchiveContainsExecutable => {
            match expected_archive_analysis(rule, analysis)? {
                Some(archive) => archive.contains_executable,
                None => false,
            }
        }
        RuleCondition::ArchiveSuspiciousNestedNameAtLeast { value } => {
            match expected_archive_analysis(rule, analysis)? {
                Some(archive) => archive.suspicious_nested_name_count >= *value,
                None => false,
            }
        }
        RuleCondition::PathContains { value } => {
            let value = validated_string_condition(rule, value)?;
            path_text.contains(&value.to_ascii_lowercase())
        }
        RuleCondition::ScriptObfuscationAtLeast { value } => {
            match expected_script_analysis(rule, analysis)? {
                Some(script) => script.obfuscation_score >= *value,
                None => false,
            }
        }
        RuleCondition::ScriptPersistenceAtLeast { value } => {
            match expected_script_analysis(rule, analysis)? {
                Some(script) => script.persistence_patterns >= *value,
                None => false,
            }
        }
        RuleCondition::ScriptSecurityTamperAtLeast { value } => {
            match expected_script_analysis(rule, analysis)? {
                Some(script) => script.security_tamper_indicators >= *value,
                None => false,
            }
        }
        RuleCondition::EmbeddedUrlsAtLeast { value } => {
            analysis.string_indicators.embedded_url_count >= *value
        }
        RuleCondition::SuspiciousStringsAtLeast { value } => {
            analysis.string_indicators.suspicious_string_count >= *value
        }
        RuleCondition::PeImportCategoryAtLeast { category, value } => {
            match expected_pe_analysis(rule, analysis)? {
                Some(pe) => pe_import_category_count(rule, category, pe)? >= *value,
                None => false,
            }
        }
        RuleCondition::RansomNoteText => contains_any(
            text,
            &[
                "your files have been encrypted",
                "recover your files",
                "decrypt your files",
                "ransom note",
            ],
        ),
        RuleCondition::MinerPoolString => contains_any(
            text,
            &["stratum+tcp", "xmrpool", "xmrig", "mining pool", "monero"],
        ),
        RuleCondition::CredentialAccessString => contains_any(
            text,
            &[
                "login data",
                "cookies.sqlite",
                "local state",
                "wallet.dat",
                "token grab",
                "browser credentials",
            ],
        ),
        RuleCondition::AdwarePupString => contains_any(
            text,
            &[
                "silentinstall",
                "browser extension install",
                "search hijack",
                "offer bundle",
                "unwanted toolbar",
            ],
        ),
    })
}

fn expected_script_analysis<'a>(
    rule: &NativeRule,
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
            "rule {} requires script analysis for {:?}",
            rule.id,
            analysis.file_type
        );
    }
    Ok(None)
}

fn expected_archive_analysis<'a>(
    rule: &NativeRule,
    analysis: &'a StaticAnalysis,
) -> Result<Option<&'a archives::ArchiveAnalysis>> {
    if let Some(archive) = analysis.archive.as_ref() {
        return Ok(Some(archive));
    }
    if analysis.file_type == FileType::Zip {
        bail!(
            "rule {} requires archive analysis for {:?}",
            rule.id,
            analysis.file_type
        );
    }
    Ok(None)
}

fn expected_pe_analysis<'a>(
    rule: &NativeRule,
    analysis: &'a StaticAnalysis,
) -> Result<Option<&'a pe::PeAnalysis>> {
    if let Some(pe) = analysis.pe.as_ref() {
        return Ok(Some(pe));
    }
    if analysis.file_type == FileType::Pe {
        bail!(
            "rule {} requires PE analysis for {:?}",
            rule.id,
            analysis.file_type
        );
    }
    Ok(None)
}

fn pe_import_category_count(rule: &NativeRule, category: &str, pe: &pe::PeAnalysis) -> Result<u32> {
    Ok(match category {
        "process_injection" => pe.suspicious_imports.process_injection,
        "credential_access" => pe.suspicious_imports.credential_access,
        "persistence" => pe.suspicious_imports.persistence,
        "network" => pe.suspicious_imports.network,
        "crypto" => pe.suspicious_imports.crypto,
        "process_manipulation" => pe.suspicious_imports.process_manipulation,
        "service_control" => pe.suspicious_imports.service_control,
        "registry_autorun" => pe.suspicious_imports.registry_autorun,
        "anti_debugging" => pe.suspicious_imports.anti_debugging,
        _ => bail!(
            "rule {} uses unsupported PE import category {}",
            rule.id,
            category
        ),
    })
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn validated_string_condition<'a>(rule: &NativeRule, value: &'a str) -> Result<&'a str> {
    if value != value.trim() {
        bail!("rule {} uses non-canonical string condition", rule.id);
    }
    if value.trim().is_empty() {
        bail!("rule {} string condition is empty", rule.id);
    }
    Ok(value)
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

#[cfg(test)]
mod source_tests {
    use super::*;

    #[test]
    fn rule_match_weight_mapping_has_no_wildcard_default() {
        assert_eq!(
            rule_match_weight(Verdict::ConfirmedMalware, Confidence::Confirmed),
            100
        );
        assert_eq!(
            rule_match_weight(Verdict::TestThreat, Confidence::Confirmed),
            100
        );
        assert_eq!(
            rule_match_weight(Verdict::ProbableMalware, Confidence::High),
            65
        );
        assert_eq!(
            rule_match_weight(Verdict::Suspicious, Confidence::Medium),
            40
        );
        assert_eq!(rule_match_weight(Verdict::Suspicious, Confidence::High), 40);
        assert_eq!(rule_match_weight(Verdict::Observation, Confidence::Low), 15);
        assert_eq!(rule_match_weight(Verdict::Clean, Confidence::Low), 15);
        assert_eq!(
            rule_match_weight(Verdict::LikelyClean, Confidence::Medium),
            15
        );
        assert_eq!(
            rule_match_weight(Verdict::Unknown, Confidence::Confirmed),
            15
        );

        let source = include_str!("rule_vm.rs");
        let helper_start = source.find("fn rule_match_weight").unwrap();
        let condition_start = source.find("fn condition_matches").unwrap();
        let helper_source = &source[helper_start..condition_start];

        assert!(source.contains("weight: rule_match_weight(rule.verdict, rule.confidence)"));
        assert!(!helper_source.contains("_ => 15"));
    }
}
