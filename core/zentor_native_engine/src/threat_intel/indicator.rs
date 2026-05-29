use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::verdict::{Confidence, ThreatCategory};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Sha256,
    Sha1,
    Md5,
    Imphash,
    FilenamePattern,
    StringPattern,
    BytePattern,
    ScriptPattern,
    ImportCombo,
    BehaviorPattern,
    RegistryPath,
    MutexName,
    FilePathPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelIndicator {
    pub indicator_id: String,
    pub source_name: String,
    #[serde(default)]
    pub source_url: Option<String>,
    pub source_type: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    #[serde(default)]
    pub malware_family: Option<String>,
    pub threat_category: ThreatCategory,
    pub confidence: Confidence,
    #[serde(default)]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_seen: Option<DateTime<Utc>>,
    pub false_positive_notes: String,
    pub action_policy: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl ThreatIntelIndicator {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.indicator_id.trim().is_empty()
            || self.source_name.trim().is_empty()
            || self.value.trim().is_empty()
            || self.false_positive_notes.trim().is_empty()
        {
            anyhow::bail!("indicator {} is missing required metadata", self.indicator_id);
        }
        Ok(())
    }
}
