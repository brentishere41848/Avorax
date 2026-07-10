use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::verdict::{Confidence, ThreatCategory, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePack {
    pub format: String,
    pub version: String,
    #[serde(default)]
    pub compiler_version: Option<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub pack_sha256: Option<String>,
    pub rules: Vec<NativeRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ThreatCategory,
    pub confidence: Confidence,
    pub verdict: Verdict,
    pub false_positive_notes: String,
    pub conditions: Vec<RuleCondition>,
    pub min_condition_matches: usize,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleCondition {
    FileType { equals: String },
    ContainsAscii { value: String },
    ContainsUtf16 { value: String },
    EntropyGreaterThan { value: f64 },
    SuspiciousImportsAtLeast { value: u32 },
    EncodedCommand,
    DownloaderAndExecution,
    ArchiveContainsExecutable,
    ArchiveSuspiciousNestedNameAtLeast { value: u32 },
    PathContains { value: String },
    ScriptObfuscationAtLeast { value: u32 },
    ScriptPersistenceAtLeast { value: u32 },
    ScriptSecurityTamperAtLeast { value: u32 },
    EmbeddedUrlsAtLeast { value: u32 },
    SuspiciousStringsAtLeast { value: u32 },
    PeImportCategoryAtLeast { category: String, value: u32 },
    RansomNoteText,
    MinerPoolString,
    CredentialAccessString,
    AdwarePupString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMatch {
    pub rule_id: String,
    pub name: String,
    pub category: ThreatCategory,
    pub confidence: Confidence,
    pub verdict: Verdict,
    pub reason: String,
    pub weight: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_pack_value() -> serde_json::Value {
        serde_json::json!({
            "format": "zentor-rule-pack-v1",
            "version": "test",
            "compiler_version": null,
            "created_at": null,
            "pack_sha256": null,
            "rules": [native_rule_value()],
        })
    }

    fn native_rule_value() -> serde_json::Value {
        serde_json::json!({
            "id": "ZNE-RULE-TEST",
            "name": "Test rule",
            "description": "Benign test rule.",
            "category": "testThreat",
            "confidence": "low",
            "verdict": "suspicious",
            "false_positive_notes": "Test fixture only.",
            "conditions": [
                {
                    "type": "contains_ascii",
                    "value": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
                }
            ],
            "min_condition_matches": 1,
            "action": "review_only",
        })
    }

    #[test]
    fn rule_pack_rejects_unknown_top_level_fields() {
        let mut value = rule_pack_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("enabled".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<RulePack>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn native_rule_rejects_unknown_rule_fields() {
        let mut value = native_rule_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("allow_anyway".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<NativeRule>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn rule_condition_rejects_unknown_fields() {
        let value = serde_json::json!({
            "type": "contains_ascii",
            "value": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            "allow_anyway": true,
        });

        let error = serde_json::from_value::<RuleCondition>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn rule_pack_schema_stays_strict() {
        let source = include_str!("rule.rs");
        let pack_start = source.find("pub struct RulePack").unwrap();
        let pack_prefix = &source[..pack_start];
        let rule_start = source.find("pub struct NativeRule").unwrap();
        let rule_prefix = &source[pack_start..rule_start];
        let condition_start = source.find("pub enum RuleCondition").unwrap();
        let condition_prefix = &source[rule_start..condition_start];
        let match_start = source.find("pub struct RuleMatch").unwrap();
        let match_prefix = &source[condition_start..match_start];

        assert!(pack_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(rule_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(condition_prefix.contains("deny_unknown_fields"));
        assert!(match_prefix.contains("#[serde(deny_unknown_fields)]"));
    }
}
