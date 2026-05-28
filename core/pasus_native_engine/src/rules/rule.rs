use serde::{Deserialize, Serialize};

use crate::verdict::{Confidence, ThreatCategory, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    pub format: String,
    pub version: String,
    pub rules: Vec<NativeRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    FileType { equals: String },
    ContainsAscii { value: String },
    ContainsUtf16 { value: String },
    EntropyGreaterThan { value: f64 },
    SuspiciousImportsAtLeast { value: u32 },
    EncodedCommand,
    DownloaderAndExecution,
    ArchiveContainsExecutable,
    PathContains { value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub name: String,
    pub category: ThreatCategory,
    pub confidence: Confidence,
    pub verdict: Verdict,
    pub reason: String,
    pub weight: i32,
}
