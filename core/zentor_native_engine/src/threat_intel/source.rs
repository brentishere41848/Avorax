use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIntelSourceType {
    PublicReport,
    InternalResearch,
    TrustedFeed,
    ManualLab,
    TestFixture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelSource {
    pub source_name: String,
    #[serde(default)]
    pub source_url: Option<String>,
    pub source_type: ThreatIntelSourceType,
}

impl ThreatIntelSource {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.source_name.trim().is_empty() {
            anyhow::bail!("threat intel source_name is required");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_intel_source_rejects_unknown_fields() {
        let value = serde_json::json!({
            "source_name": "safe-fixture-feed",
            "source_url": "https://example.invalid/feed",
            "source_type": "test_fixture",
            "enabled": true,
        });

        let error = serde_json::from_value::<ThreatIntelSource>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn threat_intel_source_schema_stays_strict() {
        let source = include_str!("source.rs");
        let source_start = source.find("pub struct ThreatIntelSource").unwrap();
        let source_prefix = &source[..source_start];

        assert!(source_prefix.contains("#[serde(deny_unknown_fields)]"));
    }
}
