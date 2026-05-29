use std::path::Path;

use super::{NativeRule, RuleCondition, RuleMatch};
use crate::analyzers::{FileType, StaticAnalysis};
use crate::verdict::{Confidence, Verdict};

pub fn evaluate_rule(
    rule: &NativeRule,
    path: &Path,
    bytes: &[u8],
    analysis: &StaticAnalysis,
) -> Option<RuleMatch> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let path_text = path.display().to_string().to_ascii_lowercase();
    let matches = rule
        .conditions
        .iter()
        .filter(|condition| match condition {
            RuleCondition::FileType { equals } => file_type_name(analysis.file_type) == equals,
            RuleCondition::ContainsAscii { value } => text.contains(&value.to_ascii_lowercase()),
            RuleCondition::ContainsUtf16 { value } => {
                let encoded = value
                    .encode_utf16()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>();
                !encoded.is_empty() && bytes.windows(encoded.len()).any(|window| window == encoded)
            }
            RuleCondition::EntropyGreaterThan { value } => analysis.entropy_max > *value,
            RuleCondition::SuspiciousImportsAtLeast { value } => {
                analysis
                    .pe
                    .as_ref()
                    .map(|pe| {
                        pe.suspicious_imports.process_injection
                            + pe.suspicious_imports.credential_access
                            + pe.suspicious_imports.persistence
                            + pe.suspicious_imports.network
                    })
                    .unwrap_or_default()
                    >= *value
            }
            RuleCondition::EncodedCommand => analysis
                .script
                .as_ref()
                .map(|script| script.encoded_command)
                .unwrap_or(false),
            RuleCondition::DownloaderAndExecution => analysis
                .script
                .as_ref()
                .map(|script| script.downloader_patterns > 0 && script.execution_patterns > 0)
                .unwrap_or(false),
            RuleCondition::ArchiveContainsExecutable => analysis
                .archive
                .as_ref()
                .map(|archive| archive.contains_executable)
                .unwrap_or(false),
            RuleCondition::ArchiveSuspiciousNestedNameAtLeast { value } => analysis
                .archive
                .as_ref()
                .map(|archive| archive.suspicious_nested_name_count >= *value)
                .unwrap_or(false),
            RuleCondition::PathContains { value } => {
                path_text.contains(&value.to_ascii_lowercase())
            }
            RuleCondition::ScriptObfuscationAtLeast { value } => analysis
                .script
                .as_ref()
                .map(|script| script.obfuscation_score >= *value)
                .unwrap_or(false),
            RuleCondition::ScriptPersistenceAtLeast { value } => analysis
                .script
                .as_ref()
                .map(|script| script.persistence_patterns >= *value)
                .unwrap_or(false),
            RuleCondition::ScriptSecurityTamperAtLeast { value } => analysis
                .script
                .as_ref()
                .map(|script| script.security_tamper_indicators >= *value)
                .unwrap_or(false),
            RuleCondition::EmbeddedUrlsAtLeast { value } => {
                analysis.string_indicators.embedded_url_count >= *value
            }
            RuleCondition::SuspiciousStringsAtLeast { value } => {
                analysis.string_indicators.suspicious_string_count >= *value
            }
            RuleCondition::PeImportCategoryAtLeast { category, value } => analysis
                .pe
                .as_ref()
                .map(|pe| match category.as_str() {
                    "process_injection" => pe.suspicious_imports.process_injection,
                    "credential_access" => pe.suspicious_imports.credential_access,
                    "persistence" => pe.suspicious_imports.persistence,
                    "network" => pe.suspicious_imports.network,
                    "crypto" => pe.suspicious_imports.crypto,
                    "process_manipulation" => pe.suspicious_imports.process_manipulation,
                    "service_control" => pe.suspicious_imports.service_control,
                    "registry_autorun" => pe.suspicious_imports.registry_autorun,
                    "anti_debugging" => pe.suspicious_imports.anti_debugging,
                    _ => 0,
                } >= *value)
                .unwrap_or(false),
            RuleCondition::RansomNoteText => contains_any(
                &text,
                &[
                    "your files have been encrypted",
                    "recover your files",
                    "decrypt your files",
                    "ransom note",
                ],
            ),
            RuleCondition::MinerPoolString => contains_any(
                &text,
                &["stratum+tcp", "xmrpool", "xmrig", "mining pool", "monero"],
            ),
            RuleCondition::CredentialAccessString => contains_any(
                &text,
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
                &text,
                &[
                    "silentinstall",
                    "browser extension install",
                    "search hijack",
                    "offer bundle",
                    "unwanted toolbar",
                ],
            ),
        })
        .count();
    if matches < rule.min_condition_matches {
        return None;
    }
    Some(RuleMatch {
        rule_id: rule.id.clone(),
        name: rule.name.clone(),
        category: rule.category,
        confidence: rule.confidence,
        verdict: rule.verdict,
        reason: format!("Zentor Native Rule matched: {}", rule.name),
        weight: match (rule.verdict, rule.confidence) {
            (Verdict::ConfirmedMalware | Verdict::TestThreat, Confidence::Confirmed) => 100,
            (Verdict::ProbableMalware, Confidence::High) => 65,
            (Verdict::Suspicious, Confidence::High | Confidence::Medium) => 40,
            _ => 15,
        },
    })
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
