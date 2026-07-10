use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const MAX_MODEL_METADATA_TEXT_CHARS: usize = 128;
const MAX_MODEL_METADATA_DATASET_CHARS: usize = 256;
const MAX_MODEL_METADATA_CATEGORY_CHARS: usize = 64;
const MAX_MODEL_METADATA_LIMITATION_CHARS: usize = 512;
const MAX_MODEL_METADATA_LIST_ITEMS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelMetadata {
    pub model_name: String,
    pub model_version: String,
    pub model_type: String,
    pub feature_schema_version: String,
    pub trained_at: DateTime<Utc>,
    pub production_ready: bool,
    pub training_dataset_name: String,
    pub training_sample_count: u64,
    pub validation_sample_count: u64,
    pub false_positive_rate: Option<f32>,
    pub precision: Option<f32>,
    pub recall: Option<f32>,
    pub thresholds: ModelThresholds,
    pub supported_categories: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelThresholds {
    pub suspicious: f32,
    pub probable_malware: f32,
    pub confirmed_malware: f32,
}

impl ModelMetadata {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_required_metadata_text(
            "model_name",
            &self.model_name,
            MAX_MODEL_METADATA_TEXT_CHARS,
        )?;
        validate_required_metadata_text(
            "model_version",
            &self.model_version,
            MAX_MODEL_METADATA_TEXT_CHARS,
        )?;
        validate_required_metadata_text(
            "model_type",
            &self.model_type,
            MAX_MODEL_METADATA_TEXT_CHARS,
        )?;
        validate_required_metadata_text(
            "feature_schema_version",
            &self.feature_schema_version,
            MAX_MODEL_METADATA_TEXT_CHARS,
        )?;
        validate_required_metadata_text(
            "training_dataset_name",
            &self.training_dataset_name,
            MAX_MODEL_METADATA_DATASET_CHARS,
        )?;
        validate_optional_unit_metric("false_positive_rate", self.false_positive_rate)?;
        validate_optional_unit_metric("precision", self.precision)?;
        validate_optional_unit_metric("recall", self.recall)?;
        self.thresholds.validate()?;
        validate_metadata_string_list(
            "supported_categories",
            &self.supported_categories,
            MAX_MODEL_METADATA_LIST_ITEMS,
            MAX_MODEL_METADATA_CATEGORY_CHARS,
        )?;
        validate_metadata_string_list(
            "limitations",
            &self.limitations,
            MAX_MODEL_METADATA_LIST_ITEMS,
            MAX_MODEL_METADATA_LIMITATION_CHARS,
        )?;
        if self.production_ready {
            if self.training_sample_count == 0 {
                anyhow::bail!("production-ready AI metadata requires training samples");
            }
            if self.validation_sample_count == 0 {
                anyhow::bail!("production-ready AI metadata requires validation samples");
            }
            require_unit_metric("false_positive_rate", self.false_positive_rate)?;
            require_unit_metric("precision", self.precision)?;
            require_unit_metric("recall", self.recall)?;
        }
        Ok(())
    }
}

impl ModelThresholds {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_unit_metric("thresholds.suspicious", self.suspicious)?;
        validate_unit_metric("thresholds.probable_malware", self.probable_malware)?;
        validate_unit_metric("thresholds.confirmed_malware", self.confirmed_malware)?;
        if !(self.suspicious < self.probable_malware
            && self.probable_malware < self.confirmed_malware)
        {
            anyhow::bail!(
                "AI metadata thresholds must be ordered suspicious < probable_malware < confirmed_malware"
            );
        }
        Ok(())
    }
}

fn validate_optional_unit_metric(label: &str, value: Option<f32>) -> anyhow::Result<()> {
    if let Some(value) = value {
        validate_unit_metric(label, value)?;
    }
    Ok(())
}

fn require_unit_metric(label: &str, value: Option<f32>) -> anyhow::Result<()> {
    let Some(value) = value else {
        anyhow::bail!("production-ready AI metadata requires {label}");
    };
    validate_unit_metric(label, value)
}

fn validate_unit_metric(label: &str, value: f32) -> anyhow::Result<()> {
    if !value.is_finite() {
        anyhow::bail!("AI metadata {label} must be finite");
    }
    if !(0.0..=1.0).contains(&value) {
        anyhow::bail!("AI metadata {label} must be between 0 and 1");
    }
    Ok(())
}

fn validate_required_metadata_text(
    label: &str,
    value: &str,
    max_chars: usize,
) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("AI metadata {label} is required");
    }
    if value.contains('\0') {
        anyhow::bail!("AI metadata {label} contains NUL");
    }
    if value.chars().count() > max_chars {
        anyhow::bail!("AI metadata {label} exceeds maximum length");
    }
    Ok(())
}

fn validate_metadata_string_list(
    label: &str,
    values: &[String],
    max_items: usize,
    max_chars: usize,
) -> anyhow::Result<()> {
    if values.is_empty() {
        anyhow::bail!("AI metadata {label} must not be empty");
    }
    if values.len() > max_items {
        anyhow::bail!("AI metadata {label} exceeds maximum item count");
    }
    for value in values {
        validate_required_metadata_text(label, value, max_chars)?;
    }
    Ok(())
}

impl Default for ModelMetadata {
    fn default() -> Self {
        Self {
            model_name: "zentor_static_malware_model".to_string(),
            model_version: "unavailable".to_string(),
            model_type: "unavailable".to_string(),
            feature_schema_version: "1.0.0".to_string(),
            trained_at: Utc::now(),
            production_ready: false,
            training_dataset_name: "none".to_string(),
            training_sample_count: 0,
            validation_sample_count: 0,
            false_positive_rate: None,
            precision: None,
            recall: None,
            thresholds: ModelThresholds {
                suspicious: 0.72,
                probable_malware: 0.90,
                confirmed_malware: 0.995,
            },
            supported_categories: vec!["unknown".to_string()],
            limitations: vec!["Model metadata unavailable.".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata_value() -> serde_json::Value {
        serde_json::to_value(ModelMetadata::default()).unwrap()
    }

    #[test]
    fn model_metadata_rejects_unknown_top_level_fields() {
        let mut value = metadata_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("auto_quarantine".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<ModelMetadata>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn model_metadata_rejects_unknown_threshold_fields() {
        let mut value = metadata_value();
        value["thresholds"]
            .as_object_mut()
            .unwrap()
            .insert("force_confirmed".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<ModelMetadata>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn model_metadata_schema_stays_strict() {
        let source = include_str!("model_metadata.rs");
        let metadata_start = source.find("pub struct ModelMetadata").unwrap();
        let metadata_prefix = &source[..metadata_start];
        let thresholds_start = source.find("pub struct ModelThresholds").unwrap();
        let thresholds_prefix = &source[metadata_start..thresholds_start];

        assert!(metadata_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(thresholds_prefix.contains("#[serde(deny_unknown_fields)]"));
    }

    #[test]
    fn model_metadata_validation_rejects_non_finite_thresholds() {
        let mut metadata = ModelMetadata::default();
        metadata.thresholds.suspicious = f32::NAN;

        let error = metadata.validate().unwrap_err().to_string();

        assert!(error.contains("thresholds.suspicious must be finite"));
    }

    #[test]
    fn model_metadata_validation_rejects_unordered_thresholds() {
        let mut metadata = ModelMetadata::default();
        metadata.thresholds.suspicious = 0.9;
        metadata.thresholds.probable_malware = 0.8;

        let error = metadata.validate().unwrap_err().to_string();

        assert!(error.contains("thresholds must be ordered"));
    }

    #[test]
    fn production_model_metadata_requires_metric_evidence() {
        let mut metadata = ModelMetadata::default();
        metadata.production_ready = true;
        metadata.training_sample_count = 1;
        metadata.validation_sample_count = 1;
        metadata.false_positive_rate = Some(0.01);
        metadata.precision = Some(0.99);
        metadata.recall = None;

        let error = metadata.validate().unwrap_err().to_string();

        assert!(error.contains("requires recall"));
    }

    #[test]
    fn model_metadata_validation_source_stays_wired() {
        let source = include_str!("model_metadata.rs");
        let runner_source = include_str!("model_runner.rs");

        assert!(source.contains("pub fn validate(&self) -> anyhow::Result<()>"));
        assert!(source.contains("validate_unit_metric(\"thresholds.suspicious\""));
        assert!(source.contains("production-ready AI metadata requires training samples"));
        assert!(source.contains("validate_metadata_string_list("));
        assert!(runner_source.contains("metadata.validate().with_context"));
    }
}
