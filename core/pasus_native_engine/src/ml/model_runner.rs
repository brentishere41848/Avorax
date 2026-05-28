use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::verdict::{Confidence, ThreatCategory, Verdict};

use super::feature_vector::FeatureVector;
use super::model::NativeModel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMlResult {
    pub malware_probability: f64,
    pub top_category: ThreatCategory,
    pub confidence: Confidence,
    pub verdict: Verdict,
    pub explanation_features: Vec<String>,
    pub model_version: String,
    pub production_ready: bool,
    pub false_positive_rate_from_metadata: f64,
    pub can_contribute_to_auto_quarantine: bool,
}

#[derive(Debug, Clone)]
pub struct NativeModelRunner {
    model: Option<NativeModel>,
}

impl NativeModelRunner {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self { model: None });
        }
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read native model {}", path.display()))?;
        let model: NativeModel = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse native model {}", path.display()))?;
        Ok(Self { model: Some(model) })
    }

    pub fn is_loaded(&self) -> bool {
        self.model.is_some()
    }

    pub fn model_version(&self) -> Option<&str> {
        self.model.as_ref().map(|model| model.model_version.as_str())
    }

    pub fn production_ready(&self) -> bool {
        self.model
            .as_ref()
            .map(|model| model.production_ready)
            .unwrap_or(false)
    }

    pub fn analyze_features(&self, features: &FeatureVector) -> Option<NativeMlResult> {
        let model = self.model.as_ref()?;
        let score = model
            .weights
            .iter()
            .fold(model.bias, |acc, (name, weight)| acc + features.get(name) * weight);
        let probability = 1.0 / (1.0 + (-score).exp());
        let verdict = if probability >= model.thresholds.confirmed_malware && model.production_ready {
            Verdict::ConfirmedMalware
        } else if probability >= model.thresholds.probable_malware {
            Verdict::ProbableMalware
        } else if probability >= model.thresholds.suspicious {
            Verdict::Suspicious
        } else {
            Verdict::LikelyClean
        };
        let confidence = if probability >= model.thresholds.confirmed_malware && model.production_ready {
            Confidence::Confirmed
        } else if probability >= model.thresholds.probable_malware {
            Confidence::High
        } else if probability >= model.thresholds.suspicious {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        let mut contributions = model
            .weights
            .iter()
            .map(|(name, weight)| (name, features.get(name) * weight))
            .collect::<Vec<_>>();
        contributions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let explanation_features = contributions
            .into_iter()
            .take(4)
            .filter(|(_, contribution)| *contribution > 0.01)
            .map(|(name, _)| name.clone())
            .collect();
        Some(NativeMlResult {
            malware_probability: probability,
            top_category: if features.encoded_command_flag > 0.0 {
                ThreatCategory::SuspiciousScript
            } else {
                ThreatCategory::Unknown
            },
            confidence,
            verdict,
            explanation_features,
            model_version: model.model_version.clone(),
            production_ready: model.production_ready,
            false_positive_rate_from_metadata: model.false_positive_rate,
            can_contribute_to_auto_quarantine: model.production_ready
                && model.false_positive_rate <= 0.005
                && probability >= model.thresholds.probable_malware,
        })
    }
}
