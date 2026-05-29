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
