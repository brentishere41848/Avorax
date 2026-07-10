use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::analyzers::StaticAnalysis;
use crate::verdict::{Evidence, EvidenceSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DetectionProviderStatus {
    Enabled,
    Disabled,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionProviderInfo {
    pub id: String,
    pub display_name: String,
    pub source: EvidenceSource,
    pub status: DetectionProviderStatus,
    pub reason: Option<String>,
}

pub struct ScanContext<'a> {
    pub path: &'a Path,
    pub sha256: &'a str,
    pub bytes: &'a [u8],
    pub analysis: &'a StaticAnalysis,
}

pub trait DetectionProvider: Send + Sync {
    fn id(&self) -> &'static str;

    fn display_name(&self) -> &'static str;

    fn source(&self) -> EvidenceSource;

    fn status(&self) -> DetectionProviderStatus {
        DetectionProviderStatus::Enabled
    }

    fn unavailable_reason(&self) -> Option<String> {
        None
    }

    fn info(&self) -> DetectionProviderInfo {
        DetectionProviderInfo {
            id: self.id().to_string(),
            display_name: self.display_name().to_string(),
            source: self.source(),
            status: self.status(),
            reason: self.unavailable_reason(),
        }
    }

    fn evaluate(&self, context: &ScanContext<'_>) -> Result<Vec<Evidence>>;
}

#[derive(Default)]
pub struct DetectionProviderRegistry {
    providers: Vec<Box<dyn DetectionProvider>>,
}

impl DetectionProviderRegistry {
    pub fn register(&mut self, provider: Box<dyn DetectionProvider>) {
        self.providers.push(provider);
    }

    pub fn providers(&self) -> Vec<DetectionProviderInfo> {
        self.providers
            .iter()
            .map(|provider| provider.info())
            .collect()
    }

    pub fn evaluate(&self, context: &ScanContext<'_>) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();
        for provider in &self.providers {
            if provider.status() != DetectionProviderStatus::Enabled {
                continue;
            }
            evidence.extend(provider.evaluate(context)?);
        }
        Ok(evidence)
    }
}

pub fn builtin_provider_inventory(
    signature_count: usize,
    rule_count: usize,
    ml_loaded: bool,
    ml_production_ready: bool,
    compatibility_enabled: bool,
) -> Vec<DetectionProviderInfo> {
    vec![
        DetectionProviderInfo {
            id: "native.signatures".to_string(),
            display_name: "Avorax native signatures".to_string(),
            source: EvidenceSource::NativeSignature,
            status: if signature_count > 0 {
                DetectionProviderStatus::Enabled
            } else {
                DetectionProviderStatus::Unavailable
            },
            reason: (signature_count == 0)
                .then(|| "signature pack is empty or unavailable".to_string()),
        },
        DetectionProviderInfo {
            id: "native.rules".to_string(),
            display_name: "Avorax native rules".to_string(),
            source: EvidenceSource::NativeRule,
            status: if rule_count > 0 {
                DetectionProviderStatus::Enabled
            } else {
                DetectionProviderStatus::Unavailable
            },
            reason: (rule_count == 0).then(|| "rule pack is empty or unavailable".to_string()),
        },
        DetectionProviderInfo {
            id: "native.heuristics".to_string(),
            display_name: "Avorax native heuristics".to_string(),
            source: EvidenceSource::NativeHeuristic,
            status: DetectionProviderStatus::Enabled,
            reason: None,
        },
        DetectionProviderInfo {
            id: "native.ml".to_string(),
            display_name: "Avorax native ML review".to_string(),
            source: EvidenceSource::NativeMl,
            status: if ml_loaded {
                DetectionProviderStatus::Enabled
            } else {
                DetectionProviderStatus::Unavailable
            },
            reason: if !ml_loaded {
                Some("development ML model is unavailable".to_string())
            } else if !ml_production_ready {
                Some(
                    "development ML model is loaded for review only; not production-ready"
                        .to_string(),
                )
            } else {
                None
            },
        },
        DetectionProviderInfo {
            id: "compatibility.yara".to_string(),
            display_name: "YARA compatibility provider".to_string(),
            source: EvidenceSource::NativeRule,
            status: if compatibility_enabled {
                DetectionProviderStatus::Enabled
            } else {
                DetectionProviderStatus::Disabled
            },
            reason: (!compatibility_enabled)
                .then(|| "compatibility engines are disabled by default".to_string()),
        },
        DetectionProviderInfo {
            id: "cloud.reputation".to_string(),
            display_name: "Cloud reputation provider".to_string(),
            source: EvidenceSource::CloudReputation,
            status: DetectionProviderStatus::Disabled,
            reason: Some("no cloud reputation backend is configured".to_string()),
        },
    ]
}
