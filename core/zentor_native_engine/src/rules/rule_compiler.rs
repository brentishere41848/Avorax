use anyhow::{bail, Result};

use serde_json::Value;
use std::collections::HashSet;

use super::{NativeRule, RuleCondition, RulePack};
use crate::engine::sha256_bytes;
use crate::signatures::known_bad_hashes::is_sha256;
use crate::verdict::{Confidence, Verdict};

pub const RULE_PACK_FORMAT: &str = "zentor-rule-pack-v1";
const MAX_RULES_PER_PACK: usize = 512;
const MAX_RULE_NAME_LEN: usize = 160;
const MAX_RULE_DESCRIPTION_LEN: usize = 512;
const MAX_RULE_NOTES_LEN: usize = 512;
const MAX_RULE_CONDITIONS: usize = 16;
const MAX_RULE_STRING_CONDITION_LEN: usize = 256;
const MAX_RULE_THRESHOLD: u32 = 64;

pub fn validate_rule_pack(pack: &RulePack) -> Result<()> {
    if pack.format != RULE_PACK_FORMAT {
        bail!("unsupported rule pack format {}", pack.format);
    }
    if !is_valid_pack_version(&pack.version) {
        bail!("rule pack version must be a dotted numeric version");
    }
    if pack.rules.len() > MAX_RULES_PER_PACK {
        bail!("rule pack contains too many rules");
    }
    verify_rule_pack_hash(pack)?;
    validate_rules(&pack.rules)
}

fn is_valid_pack_version(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed.split('.').all(|part| {
            !part.is_empty() && part.len() <= 10 && part.chars().all(|ch| ch.is_ascii_digit())
        })
}

fn verify_rule_pack_hash(pack: &RulePack) -> Result<()> {
    match pack.pack_sha256.as_deref() {
        Some(expected) => {
            if !is_sha256(expected) {
                bail!("rule pack hash is not a valid SHA-256 value");
            }
            let actual = sha256_bytes(&canonical_rule_pack_bytes(pack)?);
            if !expected.eq_ignore_ascii_case(&actual) {
                bail!("rule pack hash mismatch");
            }
        }
        None if !pack.rules.is_empty() => {
            bail!("non-empty rule pack must declare pack_sha256");
        }
        None => {}
    }
    Ok(())
}

pub fn canonical_rule_pack_bytes(pack: &RulePack) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(pack)?;
    if let Value::Object(object) = &mut value {
        object.remove("pack_sha256");
    }
    Ok(serde_json::to_vec(&value)?)
}

pub fn validate_rules(rules: &[NativeRule]) -> Result<()> {
    let mut seen_ids = HashSet::new();
    for rule in rules {
        if rule.id.trim().is_empty()
            || rule.name.trim().is_empty()
            || rule.description.trim().is_empty()
            || rule.false_positive_notes.trim().is_empty()
            || rule.conditions.is_empty()
        {
            bail!("rule {} is missing required metadata", rule.id);
        }
        validate_rule_identity(rule)?;
        validate_rule_metadata_bounds(rule)?;
        if !seen_ids.insert(rule.id.as_str()) {
            bail!("duplicate rule id {}", rule.id);
        }
        if matches!(
            rule.verdict,
            Verdict::ConfirmedMalware | Verdict::TestThreat
        ) && rule.confidence != Confidence::Confirmed
        {
            bail!(
                "rule {} cannot confirm malware without confirmed confidence",
                rule.id
            );
        }
        if rule.conditions.len() < 2 && rule.confidence != Confidence::Low {
            bail!("broad rule {} must be low confidence", rule.id);
        }
        if rule.conditions.len() > MAX_RULE_CONDITIONS {
            bail!("rule {} has too many conditions", rule.id);
        }
        if rule.min_condition_matches == 0 || rule.min_condition_matches > rule.conditions.len() {
            bail!("rule {} has invalid min_condition_matches", rule.id);
        }
        validate_rule_action(rule)?;
        for condition in &rule.conditions {
            validate_condition(rule, condition)?;
        }
    }
    Ok(())
}

fn validate_rule_metadata_bounds(rule: &NativeRule) -> Result<()> {
    if rule.name.trim().len() > MAX_RULE_NAME_LEN {
        bail!("rule {} name is too long", rule.id);
    }
    if rule.description.trim().len() > MAX_RULE_DESCRIPTION_LEN {
        bail!("rule {} description is too long", rule.id);
    }
    if rule.false_positive_notes.trim().len() > MAX_RULE_NOTES_LEN {
        bail!("rule {} false_positive_notes is too long", rule.id);
    }
    Ok(())
}

fn validate_rule_identity(rule: &NativeRule) -> Result<()> {
    if !is_valid_definition_id(&rule.id) {
        bail!("rule {} uses an unsafe id", rule.id);
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

fn validate_rule_action(rule: &NativeRule) -> Result<()> {
    if !matches!(
        rule.action.as_str(),
        "observe" | "review_only" | "review_or_block_by_policy" | "quarantine_if_policy_allows"
    ) {
        bail!("rule {} uses unsupported action {}", rule.id, rule.action);
    }
    Ok(())
}

fn validate_condition(rule: &NativeRule, condition: &RuleCondition) -> Result<()> {
    match condition {
        RuleCondition::FileType { equals } => {
            let value = equals.trim().to_ascii_lowercase();
            if equals != &value {
                bail!("rule {} uses non-canonical file_type condition", rule.id);
            }
            if !matches!(
                value.as_str(),
                "pe" | "elf"
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
                bail!("rule {} uses unsupported file_type condition", rule.id);
            }
        }
        RuleCondition::ContainsAscii { value }
        | RuleCondition::ContainsUtf16 { value }
        | RuleCondition::PathContains { value } => {
            if value != value.trim() {
                bail!("rule {} uses non-canonical string condition", rule.id);
            }
            if value.len() > MAX_RULE_STRING_CONDITION_LEN {
                bail!("rule {} string condition is too long", rule.id);
            }
            if value.trim().is_empty() {
                bail!("rule {} string condition is empty", rule.id);
            }
            if value.trim().len() < 4 && rule.min_condition_matches <= 1 {
                bail!("rule {} uses an unsafe short string condition", rule.id);
            }
        }
        RuleCondition::EntropyGreaterThan { value } => {
            if !value.is_finite() || *value < 0.0 || *value > 8.0 {
                bail!("rule {} uses invalid entropy threshold", rule.id);
            }
        }
        RuleCondition::PeImportCategoryAtLeast { category, value } => {
            validate_threshold(rule, *value, "import")?;
            let canonical_category = category.trim().to_ascii_lowercase();
            if category != &canonical_category {
                bail!("rule {} uses non-canonical PE import category", rule.id);
            }
            if !matches!(
                category.as_str(),
                "process_injection"
                    | "credential_access"
                    | "persistence"
                    | "network"
                    | "crypto"
                    | "process_manipulation"
                    | "service_control"
                    | "registry_autorun"
                    | "anti_debugging"
            ) {
                bail!("rule {} uses unsupported PE import category", rule.id);
            }
        }
        RuleCondition::SuspiciousImportsAtLeast { value }
        | RuleCondition::ArchiveSuspiciousNestedNameAtLeast { value }
        | RuleCondition::ScriptObfuscationAtLeast { value }
        | RuleCondition::ScriptPersistenceAtLeast { value }
        | RuleCondition::ScriptSecurityTamperAtLeast { value }
        | RuleCondition::EmbeddedUrlsAtLeast { value }
        | RuleCondition::SuspiciousStringsAtLeast { value } => {
            validate_threshold(rule, *value, "condition")?;
        }
        RuleCondition::EncodedCommand
        | RuleCondition::DownloaderAndExecution
        | RuleCondition::ArchiveContainsExecutable
        | RuleCondition::RansomNoteText
        | RuleCondition::MinerPoolString
        | RuleCondition::CredentialAccessString
        | RuleCondition::AdwarePupString => {}
    }
    Ok(())
}

fn validate_threshold(rule: &NativeRule, value: u32, label: &str) -> Result<()> {
    if value == 0 {
        bail!("rule {} uses zero {} threshold", rule.id, label);
    }
    if value > MAX_RULE_THRESHOLD {
        bail!("rule {} uses excessive {} threshold", rule.id, label);
    }
    Ok(())
}
