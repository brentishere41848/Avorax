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
#[serde(deny_unknown_fields)]
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
            anyhow::bail!(
                "indicator {} is missing required metadata",
                self.indicator_id
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indicator_value() -> serde_json::Value {
        serde_json::json!({
            "indicator_id": "ZTI-TEST-0001",
            "source_name": "safe-fixture-feed",
            "source_url": "https://example.invalid/feed",
            "source_type": "test_fixture",
            "indicator_type": "sha256",
            "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "malware_family": "safe-fixture",
            "threat_category": "testThreat",
            "confidence": "confirmed",
            "first_seen": null,
            "last_seen": null,
            "false_positive_notes": "Benign metadata-only fixture.",
            "action_policy": "review_only",
            "expires_at": null,
        })
    }

    #[test]
    fn threat_intel_indicator_rejects_unknown_fields() {
        let mut value = indicator_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("allow_anyway".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<ThreatIntelIndicator>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn threat_intel_indicator_schema_stays_strict() {
        let source = include_str!("indicator.rs");
        let indicator_start = source.find("pub struct ThreatIntelIndicator").unwrap();
        let indicator_prefix = &source[..indicator_start];

        assert!(indicator_prefix.contains("#[serde(deny_unknown_fields)]"));
    }
}
