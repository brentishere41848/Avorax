use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::verdict::{Confidence, ThreatCategory};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureType {
    ExactHash,
    PartialHash,
    BytePattern,
    MaskedBytePattern,
    AsciiString,
    Utf16String,
    PeImportCombo,
    PeSectionEntropy,
    PeResourceIndicator,
    ScriptPattern,
    PowershellEncodedCommand,
    ArchiveNestedExecutable,
    EicarTestSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeSignature {
    pub id: String,
    pub name: String,
    pub version: String,
    pub category: ThreatCategory,
    pub confidence: Confidence,
    pub severity: String,
    pub signature_type: SignatureType,
    pub pattern: String,
    #[serde(default)]
    pub mask: Option<String>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub file_types: Vec<String>,
    #[serde(default)]
    pub min_file_size: Option<u64>,
    #[serde(default)]
    pub max_file_size: Option<u64>,
    #[serde(default)]
    pub required_context: Vec<String>,
    pub false_positive_notes: String,
    pub action_policy: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub signature_id: String,
    pub name: String,
    pub category: ThreatCategory,
    pub confidence: Confidence,
    pub reason: String,
    pub weight: i32,
}
