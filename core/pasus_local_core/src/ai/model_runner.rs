use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::explanation::explain_static_features;
use super::feature_extractor::{extract_static_features, filename_risk_score, StaticFeatures};
use super::model_metadata::ModelMetadata;
use super::onnx_runtime::run_static_model;
use super::thresholds::FEATURE_COUNT;
use super::verdict::LocalAiVerdictLabel;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AiEngineStatus {
    Active,
    DevelopmentModel,
    ModelMissing,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiModelInfo {
    pub status: AiEngineStatus,
    pub model_version: String,
    pub feature_schema_version: String,
    pub production_ready: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAiResult {
    pub malware_probability: f32,
    pub top_category: String,
    pub category_scores: Vec<(String, f32)>,
    pub confidence: String,
    pub verdict: LocalAiVerdictLabel,
    pub explanation_reasons: Vec<String>,
    pub model_version: String,
    pub feature_schema_version: String,
    pub production_ready: bool,
}

#[derive(Debug, Clone)]
pub struct ModelRunner {
    model_path: Option<PathBuf>,
    metadata_path: Option<PathBuf>,
    metadata: ModelMetadata,
}

impl Default for ModelRunner {
    fn default() -> Self {
        Self::load_default().unwrap_or_else(|_| Self {
            model_path: None,
            metadata_path: None,
            metadata: ModelMetadata::default(),
        })
    }
}

impl ModelRunner {
    pub fn load_default() -> anyhow::Result<Self> {
        let paths = model_paths();
        let metadata = if let Some(metadata_path) = &paths.metadata_path {
            serde_json::from_str::<ModelMetadata>(&fs::read_to_string(metadata_path)?)?
        } else {
            ModelMetadata::default()
        };
        Ok(Self {
            model_path: paths.model_path,
            metadata_path: paths.metadata_path,
            metadata,
        })
    }

    pub fn info(&self) -> AiModelInfo {
        let (status, message) = if self.model_path.is_none() || self.metadata_path.is_none() {
            (
                AiEngineStatus::ModelMissing,
                "Local AI model or metadata is missing.".to_string(),
            )
        } else if !self.metadata.production_ready {
            (
                AiEngineStatus::DevelopmentModel,
                "Development model loaded. AI-only results cannot auto-quarantine.".to_string(),
            )
        } else if self.inference_smoke_test().is_ok() {
            (AiEngineStatus::Active, "Local AI Active.".to_string())
        } else {
            (
                AiEngineStatus::Error,
                "Local AI model exists but inference failed.".to_string(),
            )
        };
        AiModelInfo {
            status,
            model_version: self.metadata.model_version.clone(),
            feature_schema_version: self.metadata.feature_schema_version.clone(),
            production_ready: self.metadata.production_ready,
            message,
        }
    }

    pub fn status(&self) -> &'static str {
        match self.info().status {
            AiEngineStatus::Active => "active",
            AiEngineStatus::DevelopmentModel => "developmentModel",
            AiEngineStatus::ModelMissing => "modelMissing",
            AiEngineStatus::Error => "error",
        }
    }

    pub fn classify_file(&self, path: &Path) -> anyhow::Result<Option<LocalAiResult>> {
        let features = extract_static_features(path)?;
        self.analyze_features(path, &features)
    }

    pub fn analyze_features(
        &self,
        path: &Path,
        features: &StaticFeatures,
    ) -> anyhow::Result<Option<LocalAiResult>> {
        let Some(model_path) = &self.model_path else {
            return Ok(None);
        };
        let vector = features.to_feature_vector(filename_risk_score(path));
        let (probability, category_scores) = run_static_model(model_path, &vector)?;
        let verdict = verdict_for(probability, &self.metadata);
        let confidence = confidence_for(probability, &self.metadata);
        let top_category = top_category(&category_scores);
        let mut explanation_reasons = explain_static_features(features);
        if explanation_reasons.is_empty() {
            explanation_reasons.push(
                "Local AI evaluated static file features without finding a high-risk pattern."
                    .to_string(),
            );
        }
        Ok(Some(LocalAiResult {
            malware_probability: probability,
            top_category,
            category_scores,
            confidence,
            verdict,
            explanation_reasons,
            model_version: self.metadata.model_version.clone(),
            feature_schema_version: self.metadata.feature_schema_version.clone(),
            production_ready: self.metadata.production_ready,
        }))
    }

    pub fn inference_smoke_test(&self) -> anyhow::Result<()> {
        let Some(model_path) = &self.model_path else {
            anyhow::bail!("model missing");
        };
        let vector = [0.0_f32; FEATURE_COUNT];
        let _ = run_static_model(model_path, &vector)?;
        Ok(())
    }
}

fn verdict_for(probability: f32, metadata: &ModelMetadata) -> LocalAiVerdictLabel {
    if probability >= metadata.thresholds.confirmed_malware && metadata.production_ready {
        LocalAiVerdictLabel::ConfirmedMalware
    } else if probability >= metadata.thresholds.probable_malware {
        LocalAiVerdictLabel::ProbableMalware
    } else if probability >= metadata.thresholds.suspicious {
        LocalAiVerdictLabel::Suspicious
    } else if probability < 0.20 {
        LocalAiVerdictLabel::LikelyClean
    } else {
        LocalAiVerdictLabel::Unknown
    }
}

fn confidence_for(probability: f32, metadata: &ModelMetadata) -> String {
    if probability >= metadata.thresholds.confirmed_malware && metadata.production_ready {
        "confirmed".to_string()
    } else if probability >= metadata.thresholds.probable_malware {
        "high".to_string()
    } else if probability >= metadata.thresholds.suspicious {
        "medium".to_string()
    } else {
        "low".to_string()
    }
}

fn top_category(category_scores: &[(String, f32)]) -> String {
    category_scores
        .iter()
        .max_by(|left, right| left.1.total_cmp(&right.1))
        .map(|(category, _)| category.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

struct ModelPaths {
    model_path: Option<PathBuf>,
    metadata_path: Option<PathBuf>,
}

fn model_paths() -> ModelPaths {
    let model_file = "pasus_static_malware_model.onnx";
    let metadata_file = "pasus_static_malware_model.metadata.json";
    if let Ok(model_path) = env::var("PASUS_AI_MODEL") {
        let model = PathBuf::from(model_path);
        let metadata = env::var("PASUS_AI_METADATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| model.with_file_name(metadata_file));
        return ModelPaths {
            model_path: model.is_file().then_some(model),
            metadata_path: metadata.is_file().then_some(metadata),
        };
    }
    let mut roots = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = env::current_dir() {
        roots.push(current_dir.clone());
        roots.push(current_dir.join("apps").join("pasus_client"));
        let mut cursor = current_dir.as_path();
        while let Some(parent) = cursor.parent() {
            roots.push(parent.to_path_buf());
            roots.push(parent.join("apps").join("pasus_client"));
            cursor = parent;
        }
    }
    for root in roots {
        let model = root.join("assets").join("models").join(model_file);
        let metadata = root.join("assets").join("models").join(metadata_file);
        if model.is_file() || metadata.is_file() {
            return ModelPaths {
                model_path: model.is_file().then_some(model),
                metadata_path: metadata.is_file().then_some(metadata),
            };
        }
    }
    ModelPaths {
        model_path: None,
        metadata_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_model_exists_and_metadata_parses() {
        let runner = ModelRunner::load_default().unwrap();
        assert!(runner.model_path.is_some());
        assert!(runner.metadata_path.is_some());
        assert_eq!(runner.metadata.model_name, "pasus_static_malware_model");
    }

    #[test]
    fn model_runner_loads_and_returns_deterministic_output() {
        let runner = ModelRunner::load_default().unwrap();
        let vector = [0.0_f32; FEATURE_COUNT];
        let (left, _) = run_static_model(runner.model_path.as_ref().unwrap(), &vector).unwrap();
        let (right, _) = run_static_model(runner.model_path.as_ref().unwrap(), &vector).unwrap();
        assert!((left - right).abs() < 0.0001);
    }

    #[test]
    fn development_model_cannot_claim_active() {
        let runner = ModelRunner::load_default().unwrap();
        assert_eq!(runner.info().status, AiEngineStatus::DevelopmentModel);
        assert!(!runner.info().production_ready);
    }
}
