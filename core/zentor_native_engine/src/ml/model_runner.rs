use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::verdict::{Confidence, ThreatCategory, Verdict};

use super::feature_vector::FeatureVector;
use super::model::NativeModel;

const MAX_NATIVE_ML_MODEL_BYTES: u64 = 256 * 1024;
const MAX_NATIVE_ML_ID_LEN: usize = 128;
const MAX_NATIVE_ML_WEIGHTS: usize = 128;
const MAX_NATIVE_ML_WEIGHT_ABS: f64 = 100.0;
const MAX_NATIVE_ML_LIMITATIONS: usize = 32;
const MAX_NATIVE_ML_LIMITATION_LEN: usize = 512;
const MAX_NATIVE_ML_FEATURE_ABS: f64 = 1_000_000.0;

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
        if !native_model_path_present(path)? {
            return Ok(Self { model: None });
        }
        let text = read_bounded_native_model(path)
            .with_context(|| format!("failed to read native model {}", path.display()))?;
        let model: NativeModel = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse native model {}", path.display()))?;
        validate_native_model(&model)
            .with_context(|| format!("invalid native model {}", path.display()))?;
        Ok(Self { model: Some(model) })
    }

    pub fn is_loaded(&self) -> bool {
        self.model.is_some()
    }

    pub fn model_version(&self) -> Option<&str> {
        self.model
            .as_ref()
            .map(|model| model.model_version.as_str())
    }

    pub fn production_ready(&self) -> bool {
        let Some(model) = self.model.as_ref() else {
            return false;
        };
        model.production_ready
    }

    pub fn analyze_features(&self, features: &FeatureVector) -> Result<Option<NativeMlResult>> {
        let Some(model) = self.model.as_ref() else {
            return Ok(None);
        };
        validate_feature_vector(features)?;
        let mut score = model.bias;
        for (name, weight) in &model.weights {
            score += features.get(name)? * weight;
        }
        if !score.is_finite() {
            anyhow::bail!("native ML score must be finite");
        }
        let probability = 1.0 / (1.0 + (-score).exp());
        if !probability.is_finite() {
            anyhow::bail!("native ML probability must be finite");
        }
        let verdict = if probability >= model.thresholds.confirmed_malware && model.production_ready
        {
            Verdict::ConfirmedMalware
        } else if probability >= model.thresholds.probable_malware {
            Verdict::ProbableMalware
        } else if probability >= model.thresholds.suspicious {
            Verdict::Suspicious
        } else {
            Verdict::LikelyClean
        };
        let confidence =
            if probability >= model.thresholds.confirmed_malware && model.production_ready {
                Confidence::Confirmed
            } else if probability >= model.thresholds.probable_malware {
                Confidence::High
            } else if probability >= model.thresholds.suspicious {
                Confidence::Medium
            } else {
                Confidence::Low
            };
        let mut contributions = Vec::with_capacity(model.weights.len());
        for (name, weight) in &model.weights {
            contributions.push((name, features.get(name)? * weight));
        }
        contributions.sort_by(|a, b| b.1.total_cmp(&a.1));
        let explanation_features = contributions
            .into_iter()
            .take(4)
            .filter(|(_, contribution)| *contribution > 0.01)
            .map(|(name, _)| name.clone())
            .collect();
        Ok(Some(NativeMlResult {
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
        }))
    }
}

fn read_bounded_native_model(path: &Path) -> Result<String> {
    use std::io::Read;

    let metadata = ensure_regular_native_model_file(path)?;
    if metadata.len() > MAX_NATIVE_ML_MODEL_BYTES {
        anyhow::bail!(
            "native model {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_NATIVE_ML_MODEL_BYTES
        );
    }
    let mut file = fs::File::open(path)?;
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    let mut bytes = Vec::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("native model read size overflow"))?;
        if total > MAX_NATIVE_ML_MODEL_BYTES {
            anyhow::bail!(
                "native model {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_NATIVE_ML_MODEL_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("native model {} is not valid UTF-8", path.display()))
}

fn validate_native_model(model: &NativeModel) -> Result<()> {
    validate_native_model_text("model_name", &model.model_name, MAX_NATIVE_ML_ID_LEN)?;
    validate_native_model_text("model_version", &model.model_version, MAX_NATIVE_ML_ID_LEN)?;
    validate_native_model_text(
        "model_format_version",
        &model.model_format_version,
        MAX_NATIVE_ML_ID_LEN,
    )?;
    validate_native_model_text(
        "feature_schema_version",
        &model.feature_schema_version,
        MAX_NATIVE_ML_ID_LEN,
    )?;
    validate_unit_metric("precision", model.precision)?;
    validate_unit_metric("recall", model.recall)?;
    validate_unit_metric("false_positive_rate", model.false_positive_rate)?;
    if !model.bias.is_finite() {
        anyhow::bail!("native model bias must be finite");
    }
    validate_thresholds(
        model.thresholds.suspicious,
        model.thresholds.probable_malware,
        model.thresholds.confirmed_malware,
    )?;
    if model.weights.is_empty() {
        anyhow::bail!("native model weights must not be empty");
    }
    if model.weights.len() > MAX_NATIVE_ML_WEIGHTS {
        anyhow::bail!(
            "native model weights exceed maximum count of {}",
            MAX_NATIVE_ML_WEIGHTS
        );
    }
    for (feature, weight) in &model.weights {
        validate_native_model_text("weight feature", feature, MAX_NATIVE_ML_ID_LEN)?;
        if !FeatureVector::is_known_feature(feature) {
            anyhow::bail!("native model weight feature {feature} is not in feature schema");
        }
        if !weight.is_finite() {
            anyhow::bail!("native model weight for {feature} must be finite");
        }
        if weight.abs() > MAX_NATIVE_ML_WEIGHT_ABS {
            anyhow::bail!(
                "native model weight for {feature} exceeds maximum absolute value of {}",
                MAX_NATIVE_ML_WEIGHT_ABS
            );
        }
    }
    if model.limitations.len() > MAX_NATIVE_ML_LIMITATIONS {
        anyhow::bail!(
            "native model limitations exceed maximum count of {}",
            MAX_NATIVE_ML_LIMITATIONS
        );
    }
    for limitation in &model.limitations {
        validate_native_model_text("limitation", limitation, MAX_NATIVE_ML_LIMITATION_LEN)?;
    }
    Ok(())
}

fn validate_feature_vector(features: &FeatureVector) -> Result<()> {
    for (name, value) in features.named_values() {
        if !value.is_finite() {
            anyhow::bail!("native ML feature {name} must be finite");
        }
        if value.abs() > MAX_NATIVE_ML_FEATURE_ABS {
            anyhow::bail!(
                "native ML feature {name} exceeds maximum absolute value of {}",
                MAX_NATIVE_ML_FEATURE_ABS
            );
        }
    }
    Ok(())
}

fn validate_native_model_text(field: &str, value: &str, max_len: usize) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("native model {field} must not be empty");
    }
    if trimmed.len() > max_len {
        anyhow::bail!("native model {field} exceeds maximum length of {}", max_len);
    }
    if trimmed.contains('\0') {
        anyhow::bail!("native model {field} contains NUL");
    }
    Ok(())
}

fn validate_unit_metric(field: &str, value: f64) -> Result<()> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        anyhow::bail!("native model {field} must be a finite value between 0 and 1");
    }
    Ok(())
}

fn validate_thresholds(
    suspicious: f64,
    probable_malware: f64,
    confirmed_malware: f64,
) -> Result<()> {
    validate_unit_metric("thresholds.suspicious", suspicious)?;
    validate_unit_metric("thresholds.probable_malware", probable_malware)?;
    validate_unit_metric("thresholds.confirmed_malware", confirmed_malware)?;
    if suspicious > probable_malware || probable_malware > confirmed_malware {
        anyhow::bail!(
            "native model thresholds must be ordered suspicious <= probable_malware <= confirmed_malware"
        );
    }
    Ok(())
}

fn native_model_path_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_native_model(path, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect native model {}", path.display()))
        }
    }
}

fn ensure_regular_native_model_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect native model {}", path.display()))?;
    ensure_regular_native_model(path, &metadata)?;
    Ok(metadata)
}

fn ensure_regular_native_model(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("native model {} is a symbolic link", path.display());
    }
    if is_windows_reparse_point(metadata) {
        anyhow::bail!("native model {} is a reparse point", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("native model {} is not a regular file", path.display());
    }
    if metadata.len() > MAX_NATIVE_ML_MODEL_BYTES {
        anyhow::bail!(
            "native model {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_NATIVE_ML_MODEL_BYTES
        );
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_native_model() -> NativeModel {
        serde_json::from_str(
            r#"{"model_name":"Avorax Native Development Model","model_version":"0.1.0-dev","model_format_version":"zmodel-v1","feature_schema_version":"zne-features-v1","production_ready":false,"precision":0.0,"recall":0.0,"false_positive_rate":1.0,"bias":-3.0,"weights":{"encoded_command_flag":2.5,"suspicious_string_count":1.5,"known_bad_flag":5.0},"thresholds":{"suspicious":0.65,"probable_malware":0.86,"confirmed_malware":0.98},"limitations":["Development fixture model; not production protection."]}"#,
        )
        .unwrap()
    }

    #[test]
    fn native_model_runner_rejects_oversized_model_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.zmodel");
        fs::write(&path, "x".repeat(MAX_NATIVE_ML_MODEL_BYTES as usize + 1)).unwrap();

        let error = read_bounded_native_model(&path).unwrap_err().to_string();

        assert!(error.contains("native model"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn native_model_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("model_runner.rs");
        let start = source.find("fn read_bounded_native_model").unwrap();
        let end = source.find("fn validate_native_model").unwrap();
        let read_source = &source[start..end];

        assert!(read_source.contains("let metadata = ensure_regular_native_model_file(path)?"));
        assert!(read_source.contains("metadata.len() > MAX_NATIVE_ML_MODEL_BYTES"));
        assert!(read_source.contains("let mut total = 0_u64"));
        assert!(read_source.contains("checked_add(read as u64)"));
        assert!(read_source.contains("total > MAX_NATIVE_ML_MODEL_BYTES"));
        assert!(read_source.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(read_source.contains("String::from_utf8(bytes)"));
        assert!(source
            .contains("fn ensure_regular_native_model_file(path: &Path) -> Result<fs::Metadata>"));
    }

    #[test]
    fn native_model_validation_accepts_fixture_shape() {
        let model = valid_native_model();

        validate_native_model(&model).unwrap();
    }

    #[test]
    fn native_model_validation_rejects_empty_identity() {
        let mut model = valid_native_model();
        model.model_version = "   ".to_string();

        let error = validate_native_model(&model).unwrap_err().to_string();

        assert!(error.contains("model_version"));
        assert!(error.contains("must not be empty"));
    }

    #[test]
    fn native_model_validation_rejects_unordered_thresholds() {
        let mut model = valid_native_model();
        model.thresholds.probable_malware = 0.40;

        let error = validate_native_model(&model).unwrap_err().to_string();

        assert!(error.contains("thresholds must be ordered"));
    }

    #[test]
    fn native_model_validation_rejects_nonfinite_weights() {
        let mut model = valid_native_model();
        model
            .weights
            .insert("encoded_command_flag".to_string(), f64::INFINITY);

        let error = validate_native_model(&model).unwrap_err().to_string();

        assert!(error.contains("encoded_command_flag"));
        assert!(error.contains("must be finite"));
    }

    #[test]
    fn native_model_validation_rejects_unknown_feature_weights() {
        let mut model = valid_native_model();
        model.weights.insert("ghost_feature".to_string(), 1.0);

        let error = validate_native_model(&model).unwrap_err().to_string();

        assert!(error.contains("ghost_feature"));
        assert!(error.contains("feature schema"));
    }

    #[test]
    fn native_model_runner_rejects_unknown_feature_at_scoring_time() {
        let mut model = valid_native_model();
        model.weights.insert("ghost_feature".to_string(), 1.0);
        let runner = NativeModelRunner { model: Some(model) };

        let error = runner
            .analyze_features(&FeatureVector::default())
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown native ML feature ghost_feature"));
    }

    #[test]
    fn native_model_runner_rejects_nonfinite_feature_vector() {
        let runner = NativeModelRunner {
            model: Some(valid_native_model()),
        };
        let mut features = FeatureVector::default();
        features.encoded_command_flag = f64::NAN;

        let error = runner.analyze_features(&features).unwrap_err().to_string();

        assert!(error.contains("encoded_command_flag"));
        assert!(error.contains("must be finite"));
    }

    #[test]
    fn native_model_runner_rejects_unbounded_feature_vector() {
        let runner = NativeModelRunner {
            model: Some(valid_native_model()),
        };
        let mut features = FeatureVector::default();
        features.known_bad_flag = MAX_NATIVE_ML_FEATURE_ABS + 1.0;

        let error = runner.analyze_features(&features).unwrap_err().to_string();

        assert!(error.contains("known_bad_flag"));
        assert!(error.contains("exceeds maximum absolute value"));
    }

    #[test]
    fn native_model_runner_load_rejects_invalid_model_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.zmodel");
        fs::write(
            &path,
            r#"{"model_name":"Invalid Native Model","model_version":"","model_format_version":"zmodel-v1","feature_schema_version":"zne-features-v1","production_ready":false,"precision":0.0,"recall":0.0,"false_positive_rate":1.0,"bias":-3.0,"weights":{"known_bad_flag":5.0},"thresholds":{"suspicious":0.65,"probable_malware":0.86,"confirmed_malware":0.98},"limitations":["Invalid fixture."]}"#,
        )
        .unwrap();

        let error = NativeModelRunner::load(&path).unwrap_err();
        let error_chain = format!("{error:#}");

        assert!(error_chain.contains("invalid native model"));
        assert!(error_chain.contains("model_version"));
    }

    #[test]
    fn native_model_runner_missing_model_is_unloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.zmodel");

        let runner = NativeModelRunner::load(&path).unwrap();

        assert!(!runner.is_loaded());
    }

    #[test]
    fn native_model_runner_production_ready_has_explicit_unloaded_branch() {
        let runner = NativeModelRunner { model: None };

        assert!(!runner.production_ready());

        let source = include_str!("model_runner.rs");
        let production_ready_start = source.find("pub fn production_ready").unwrap();
        let analyze_features_start = source.find("pub fn analyze_features").unwrap();
        let production_ready_source = &source[production_ready_start..analyze_features_start];

        assert!(production_ready_source.contains("let Some(model) = self.model.as_ref() else"));
        assert!(production_ready_source.contains("return false;"));
        assert!(!production_ready_source.contains(".unwrap_or(false)"));
    }

    #[test]
    fn native_model_runner_contribution_sort_has_no_nan_equal_fallback() {
        let source = include_str!("model_runner.rs");
        let sort_start = source.find("let mut contributions").unwrap();
        let explanation_start = source.find("let explanation_features").unwrap();
        let sort_source = &source[sort_start..explanation_start];

        assert!(sort_source.contains("contributions.sort_by(|a, b| b.1.total_cmp(&a.1));"));
        assert!(!sort_source.contains("partial_cmp"));
        assert!(!sort_source.contains("unwrap_or(std::cmp::Ordering::Equal)"));
    }

    #[test]
    fn native_model_runner_rejects_directory_before_read() {
        let dir = tempfile::tempdir().unwrap();

        let error = read_bounded_native_model(dir.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("native model"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn native_model_runner_rejects_symbolic_link_before_read() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("model.zmodel");
        let link = dir.path().join("linked.zmodel");
        fs::write(&target, "{}").unwrap();
        symlink(&target, &link).unwrap();

        let error = read_bounded_native_model(&link).unwrap_err().to_string();

        assert!(error.contains("native model"));
        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn native_model_runner_path_safety_markers_stay_in_place() {
        let source = include_str!("model_runner.rs");
        let load_start = source.find("pub fn load").unwrap();
        let loaded_start = source.find("pub fn is_loaded").unwrap();
        let load_source = &source[load_start..loaded_start];
        let presence_helper_pattern = ["native_model_path_", "present(path)?"].concat();
        let read_guard_pattern = ["ensure_regular_native_model_", "file(path)"].concat();
        let symlink_metadata_pattern = ["fs::symlink_", "metadata(path)"].concat();
        let reparse_pattern = ["is_windows_", "reparse_point"].concat();
        let path_exists_pattern = ["path", ".exists()"].concat();

        assert!(load_source.contains(&presence_helper_pattern));
        assert!(source.contains(&read_guard_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&reparse_pattern));
        assert!(!load_source.contains(&path_exists_pattern));
    }
}
