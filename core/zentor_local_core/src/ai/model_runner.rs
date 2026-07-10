use std::env;
use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use super::explanation::explain_static_features;
use super::feature_extractor::{extract_static_features, filename_risk_score, StaticFeatures};
use super::model_metadata::ModelMetadata;
use super::onnx_runtime::run_static_model;
use super::thresholds::FEATURE_COUNT;
use super::verdict::LocalAiVerdictLabel;

const MAX_LOCAL_AI_METADATA_BYTES: u64 = 64 * 1024;

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
    load_error: Option<String>,
}

impl Default for ModelRunner {
    fn default() -> Self {
        match Self::load_default() {
            Ok(runner) => runner,
            Err(error) => Self::unavailable_due_to_load_error(error),
        }
    }
}

impl ModelRunner {
    pub fn load_default() -> anyhow::Result<Self> {
        let paths = model_paths()?;
        let metadata = if let Some(metadata_path) = &paths.metadata_path {
            let raw = read_bounded_model_metadata(metadata_path).with_context(|| {
                format!("failed to read AI metadata {}", metadata_path.display())
            })?;
            let metadata = serde_json::from_str::<ModelMetadata>(&raw).with_context(|| {
                format!("failed to parse AI metadata {}", metadata_path.display())
            })?;
            metadata.validate().with_context(|| {
                format!("failed to validate AI metadata {}", metadata_path.display())
            })?;
            metadata
        } else {
            ModelMetadata::default()
        };
        Ok(Self {
            model_path: paths.model_path,
            metadata_path: paths.metadata_path,
            metadata,
            load_error: None,
        })
    }

    pub fn info(&self) -> AiModelInfo {
        let (status, message) = if let Some(error) = &self.load_error {
            (
                AiEngineStatus::Error,
                format!("Local AI model failed to load: {error}"),
            )
        } else if self.model_path.is_none() || self.metadata_path.is_none() {
            (
                AiEngineStatus::ModelMissing,
                "Local AI model or metadata is missing.".to_string(),
            )
        } else if !self.metadata.production_ready {
            (
                AiEngineStatus::DevelopmentModel,
                "Development model loaded. AI-only results cannot auto-quarantine.".to_string(),
            )
        } else {
            match self.inference_smoke_test() {
                Ok(()) => (AiEngineStatus::Active, "Local AI Active.".to_string()),
                Err(error) => (
                    AiEngineStatus::Error,
                    format!("Local AI model exists but inference failed: {error:#}"),
                ),
            }
        };
        AiModelInfo {
            status,
            model_version: self.metadata.model_version.clone(),
            feature_schema_version: self.metadata.feature_schema_version.clone(),
            production_ready: self.metadata.production_ready,
            message,
        }
    }

    fn unavailable_due_to_load_error(error: anyhow::Error) -> Self {
        Self {
            model_path: None,
            metadata_path: None,
            metadata: ModelMetadata::default(),
            load_error: Some(format!("{error:#}")),
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
        run_static_model(model_path, &vector)?;
        Ok(())
    }
}

fn read_bounded_model_metadata(path: &Path) -> anyhow::Result<String> {
    use std::io::{BufReader, Read};

    let metadata = ensure_regular_ai_asset_path(path, "AI metadata")?;
    if metadata.len() > MAX_LOCAL_AI_METADATA_BYTES {
        anyhow::bail!(
            "AI metadata {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_LOCAL_AI_METADATA_BYTES
        );
    }
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("AI metadata {} size overflow", path.display()))?;
        if total > MAX_LOCAL_AI_METADATA_BYTES {
            anyhow::bail!(
                "AI metadata {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_LOCAL_AI_METADATA_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("unable to decode AI metadata {}", path.display()))
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
    match category_scores
        .iter()
        .max_by(|left, right| left.1.total_cmp(&right.1))
    {
        Some((category, _)) => category.clone(),
        None => unknown_category_label(),
    }
}

fn unknown_category_label() -> String {
    "unknown".to_string()
}

struct ModelPaths {
    model_path: Option<PathBuf>,
    metadata_path: Option<PathBuf>,
}

fn model_paths() -> anyhow::Result<ModelPaths> {
    let model_file = "zentor_static_malware_model.onnx";
    let metadata_file = "zentor_static_malware_model.metadata.json";
    if let Some(model_path) = env::var_os("ZENTOR_AI_MODEL") {
        let model = absolute_ai_env_path("ZENTOR_AI_MODEL", model_path.into())?;
        let metadata = match env::var_os("ZENTOR_AI_METADATA") {
            Some(metadata_path) => {
                absolute_ai_env_path("ZENTOR_AI_METADATA", metadata_path.into())?
            }
            None => model.with_file_name(metadata_file),
        };
        return Ok(ModelPaths {
            model_path: existing_regular_ai_asset_path(&model, "AI model")?,
            metadata_path: existing_regular_ai_asset_path(&metadata, "AI metadata")?,
        });
    }
    let mut roots = Vec::new();
    let exe = env::current_exe()
        .context("local AI model discovery failed to resolve current executable")?;
    let parent = exe.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "local AI model discovery found no parent for {}",
            exe.display()
        )
    })?;
    push_ai_asset_root(&mut roots, parent)?;

    #[cfg(debug_assertions)]
    {
        let current_dir = env::current_dir()
            .context("local AI model discovery failed to read current directory")?;
        push_debug_ai_asset_roots(&mut roots, &current_dir)?;
    }
    for root in &roots {
        let model = root.join("assets").join("models").join(model_file);
        let metadata = root.join("assets").join("models").join(metadata_file);
        let model_path = existing_regular_ai_asset_path(&model, "AI model")?;
        let metadata_path = existing_regular_ai_asset_path(&metadata, "AI metadata")?;
        if model_path.is_some() || metadata_path.is_some() {
            return Ok(ModelPaths {
                model_path,
                metadata_path,
            });
        }
    }
    Ok(ModelPaths {
        model_path: None,
        metadata_path: None,
    })
}

fn existing_regular_ai_asset_path(
    path: &Path,
    description: &str,
) -> anyhow::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_ai_asset_metadata(path, description, &metadata)?;
            Ok(Some(path.to_path_buf()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect {description} {}", path.display())),
    }
}

fn ensure_regular_ai_asset_path(path: &Path, description: &str) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {description} {}", path.display()))?;
    ensure_regular_ai_asset_metadata(path, description, &metadata)?;
    Ok(metadata)
}

fn ensure_regular_ai_asset_metadata(
    path: &Path,
    description: &str,
    metadata: &fs::Metadata,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("{description} {} is a symbolic link", path.display());
    }
    if is_windows_reparse_point(metadata) {
        anyhow::bail!("{description} {} is a reparse point", path.display());
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!("{description} {} is not a regular file", path.display());
    }
    Ok(())
}

fn absolute_ai_env_path(name: &str, path: PathBuf) -> anyhow::Result<PathBuf> {
    let path_text = path.as_os_str().to_string_lossy();
    let trimmed = path_text.trim();
    if trimmed.is_empty() {
        anyhow::bail!("local AI asset environment path {name} is empty");
    }
    if trimmed.contains('\0') {
        anyhow::bail!("local AI asset environment path {name} contains NUL");
    }
    if ai_env_path_has_parent_traversal(trimmed) {
        anyhow::bail!("local AI asset environment path {name} must not contain parent traversal");
    }
    if !ai_asset_root_is_allowed(&path) {
        anyhow::bail!("local AI asset environment path {name} must be an absolute local path");
    }
    Ok(path)
}

fn ai_env_path_has_parent_traversal(value: &str) -> bool {
    value.replace('\\', "/").split('/').any(|part| part == "..")
}

fn push_ai_asset_root(roots: &mut Vec<PathBuf>, root: &Path) -> anyhow::Result<()> {
    if !ai_asset_root_is_allowed(root) {
        anyhow::bail!(
            "local AI asset root {} must be an absolute local path",
            root.display()
        );
    }
    if !roots.iter().any(|existing| existing == root) {
        roots.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn push_debug_ai_asset_roots(roots: &mut Vec<PathBuf>, current_dir: &Path) -> anyhow::Result<()> {
    let mut cursor = Some(current_dir);
    while let Some(root) = cursor {
        if is_local_core_development_root(root)? {
            push_ai_asset_root(roots, root)?;
            push_ai_asset_root(roots, &root.join("apps").join("zentor_client"))?;
        } else if is_zentor_client_development_root(root)? {
            push_ai_asset_root(roots, root)?;
        }
        cursor = root.parent();
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn is_local_core_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_local_core")
        .join("Cargo.toml");
    development_marker_file_present(&marker, "local AI local-core development marker")
}

#[cfg(debug_assertions)]
fn is_zentor_client_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root.join("pubspec.yaml");
    if !development_marker_file_present(&marker, "local AI client development marker")? {
        return Ok(false);
    }
    development_models_dir_present(&root.join("assets").join("models"))
}

#[cfg(debug_assertions)]
fn development_marker_file_present(path: &Path, description: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_ai_asset_metadata(path, description, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect {description} {}", path.display())),
    }
}

#[cfg(debug_assertions)]
fn development_models_dir_present(path: &Path) -> anyhow::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "unable to inspect local AI development models directory {}",
                    path.display()
                )
            });
        }
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "local AI development models directory {} is a symbolic link",
            path.display()
        );
    }
    if is_windows_reparse_point(&metadata) {
        anyhow::bail!(
            "local AI development models directory {} is a reparse point",
            path.display()
        );
    }
    if !metadata.file_type().is_dir() {
        anyhow::bail!(
            "local AI development models directory {} is not a directory",
            path.display()
        );
    }
    Ok(true)
}

#[cfg(windows)]
fn ai_asset_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn ai_asset_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
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

    #[test]
    fn packaged_model_exists_and_metadata_parses() {
        let runner = ModelRunner::load_default().unwrap();
        assert!(runner.model_path.is_some());
        assert!(runner.metadata_path.is_some());
        assert_eq!(runner.metadata.model_name, "zentor_static_malware_model");
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

    #[test]
    fn default_model_runner_preserves_load_error_context() {
        let source = include_str!("model_runner.rs");
        let default_start = source.find("impl Default for ModelRunner").unwrap();
        let impl_start = source.find("impl ModelRunner").unwrap();
        let default_source = &source[default_start..impl_start];
        let helper_start = source
            .find("fn unavailable_due_to_load_error(error: anyhow::Error) -> Self")
            .unwrap();
        let status_start = source.find("pub fn status(&self)").unwrap();
        let helper_source = &source[helper_start..status_start];
        let discarded_error_pattern = ["Self::load_default().unwrap_or_else(|", "_| Self"].concat();

        assert!(default_source.contains("match Self::load_default()"));
        assert!(default_source.contains("Ok(runner) => runner"));
        assert!(default_source.contains("Err(error) => Self::unavailable_due_to_load_error(error)"));
        assert!(helper_source.contains("load_error: Some(format!(\"{error:#}\"))"));
        assert!(!default_source.contains(&discarded_error_pattern));
        assert!(!default_source.contains("Self::load_default().unwrap_or_else"));
        assert!(source.contains("failed to read AI metadata"));
        assert!(source.contains("failed to parse AI metadata"));
        assert!(source.contains("read_bounded_model_metadata(metadata_path)"));
        assert!(source.contains("MAX_LOCAL_AI_METADATA_BYTES"));
    }

    #[test]
    fn model_runner_info_preserves_smoke_test_error_context() {
        let source = include_str!("model_runner.rs");
        let info_start = source.find("pub fn info(&self)").unwrap();
        let status_start = source.find("pub fn status(&self)").unwrap();
        let info_source = &source[info_start..status_start];
        let smoke_start = source.find("pub fn inference_smoke_test(&self)").unwrap();
        let smoke_end = source.find("fn read_bounded_model_metadata").unwrap();
        let smoke_source = &source[smoke_start..smoke_end];
        let old_status_probe = ["self.inference_smoke_", "test().is_ok()"].concat();
        let old_discard = ["let _ = run_static_", "model"].concat();

        assert!(info_source.contains("Local AI model exists but inference failed: {error:#}"));
        assert!(!info_source.contains(&old_status_probe));
        assert!(!smoke_source.contains(&old_discard));
    }

    #[test]
    fn top_category_empty_scores_use_explicit_unknown_branch() {
        assert_eq!(top_category(&[]), "unknown");
        assert_eq!(
            top_category(&[("script".to_string(), 0.25), ("trojan".to_string(), 0.80),]),
            "trojan"
        );

        let source = include_str!("model_runner.rs");
        let start = source.find("fn top_category").unwrap();
        let end = source.find("struct ModelPaths").unwrap();
        let category_source = &source[start..end];

        assert!(category_source.contains("Some((category, _)) => category.clone()"));
        assert!(category_source.contains("None => unknown_category_label()"));
        assert!(category_source.contains("fn unknown_category_label() -> String"));
        assert!(!category_source.contains(".unwrap_or_else(|| \"unknown\".to_string())"));
    }

    #[test]
    fn ai_metadata_env_value_errors_are_not_hidden() {
        let source = include_str!("model_runner.rs");
        let start = source
            .find("if let Some(model_path) = env::var_os(\"ZENTOR_AI_MODEL\")")
            .unwrap();
        let end = source.find("let mut roots = Vec::new()").unwrap();
        let env_source = &source[start..end];

        assert!(env_source.contains("absolute_ai_env_path(\"ZENTOR_AI_MODEL\", model_path.into())"));
        assert!(env_source.contains("match env::var_os(\"ZENTOR_AI_METADATA\")"));
        assert!(env_source
            .contains("absolute_ai_env_path(\"ZENTOR_AI_METADATA\", metadata_path.into())"));
        assert!(env_source.contains("None => model.with_file_name(metadata_file)"));
        assert!(source.contains("fn absolute_ai_env_path(name: &str, path: PathBuf)"));
        assert!(source.contains("local AI asset environment path {name} is empty"));
        assert!(source.contains("local AI asset environment path {name} contains NUL"));
        assert!(source
            .contains("local AI asset environment path {name} must not contain parent traversal"));
        assert!(source
            .contains("local AI asset environment path {name} must be an absolute local path"));
        assert!(env_source.contains("model.with_file_name(metadata_file)"));
        assert!(!env_source.contains("PathBuf::from(model_path)"));
        assert!(!env_source.contains("Ok(metadata_path) => PathBuf::from(metadata_path)"));
        assert!(!env_source.contains(".unwrap_or_else(|_| model.with_file_name(metadata_file))"));
    }

    #[test]
    fn ai_env_paths_reject_nul_and_parent_traversal_text() {
        let dir = tempfile::tempdir().unwrap();
        let traversal = dir.path().join("..").join("model.onnx");
        let traversal_error = absolute_ai_env_path("ZENTOR_AI_MODEL", traversal)
            .unwrap_err()
            .to_string();
        let nul_error = absolute_ai_env_path(
            "ZENTOR_AI_METADATA",
            PathBuf::from("/tmp/model\0metadata.json"),
        )
        .unwrap_err()
        .to_string();

        assert!(traversal_error.contains("must not contain parent traversal"));
        assert!(nul_error.contains("contains NUL"));
    }

    #[test]
    fn default_ai_model_discovery_has_checked_roots() {
        let source = include_str!("model_runner.rs");
        let start = source
            .find("fn model_paths() -> anyhow::Result<ModelPaths>")
            .unwrap();
        let end = source.find("fn existing_regular_ai_asset_path").unwrap();
        let model_paths_source = &source[start..end];

        assert!(model_paths_source.contains("env::current_exe()"));
        assert!(model_paths_source
            .contains("local AI model discovery failed to resolve current executable"));
        assert!(model_paths_source.contains("push_ai_asset_root(&mut roots, parent)?"));
        assert!(model_paths_source.contains("#[cfg(debug_assertions)]"));
        assert!(model_paths_source.contains("push_debug_ai_asset_roots(&mut roots, &current_dir)?"));
        assert!(source.contains("fn ai_asset_root_is_allowed(path: &Path) -> bool"));
        assert!(source.contains("fn is_local_core_development_root(root: &Path)"));
        assert!(source.contains("fn is_zentor_client_development_root(root: &Path)"));
        assert!(source.contains("fn development_models_dir_present(path: &Path)"));
        assert!(!model_paths_source.contains("if let Ok(current_dir) = env::current_dir()"));
        assert!(!model_paths_source.contains("roots.push(current_dir.clone())"));
        assert!(!model_paths_source.contains("roots.push(parent.to_path_buf())"));
    }

    #[test]
    fn model_runner_rejects_oversized_metadata_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.metadata.json");
        fs::write(&path, "x".repeat(MAX_LOCAL_AI_METADATA_BYTES as usize + 1)).unwrap();

        let error = read_bounded_model_metadata(&path).unwrap_err().to_string();

        assert!(error.contains("AI metadata"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn model_runner_metadata_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("model_runner.rs");
        let reader = &source[source.find("fn read_bounded_model_metadata").unwrap()
            ..source.find("fn verdict_for").unwrap()];

        assert!(
            reader.contains("let metadata = ensure_regular_ai_asset_path(path, \"AI metadata\")?")
        );
        assert!(reader.contains("metadata.len() > MAX_LOCAL_AI_METADATA_BYTES"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > MAX_LOCAL_AI_METADATA_BYTES"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
        assert!(source.contains(
            "fn ensure_regular_ai_asset_path(path: &Path, description: &str) -> anyhow::Result<fs::Metadata>"
        ));
    }

    #[test]
    fn model_runner_metadata_rejects_directory_before_read() {
        let dir = tempfile::tempdir().unwrap();

        let error = read_bounded_model_metadata(dir.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("AI metadata"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn model_runner_metadata_rejects_symbolic_link_before_read() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("model.metadata.json");
        let link = dir.path().join("linked.metadata.json");
        fs::write(&target, "{}").unwrap();
        symlink(&target, &link).unwrap();

        let error = read_bounded_model_metadata(&link).unwrap_err().to_string();

        assert!(error.contains("AI metadata"));
        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn model_runner_metadata_path_safety_markers_stay_in_place() {
        let source = include_str!("model_runner.rs");
        let discovery_helper_pattern = ["existing_regular_ai_asset", "_path"].concat();
        let read_guard_pattern =
            ["ensure_regular_ai_asset_path(path, ", "\"AI metadata\")"].concat();
        let symlink_metadata_pattern = ["fs::symlink_", "metadata(path)"].concat();
        let reparse_pattern = ["is_windows_", "reparse_point"].concat();
        let following_then_some_pattern = [".is_", "file().then_", "some"].concat();
        let model_is_file_pattern = ["model", ".is_", "file()"].concat();
        let metadata_is_file_pattern = ["metadata", ".is_", "file()"].concat();

        assert!(source.contains(&discovery_helper_pattern));
        assert!(source.contains(&read_guard_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&reparse_pattern));
        assert!(source.contains("absolute_ai_env_path(\"ZENTOR_AI_MODEL\""));
        assert!(source.contains("absolute_ai_env_path(\"ZENTOR_AI_METADATA\""));
        assert!(source.contains("push_ai_asset_root(&mut roots, parent)?"));
        assert!(!source.contains(&following_then_some_pattern));
        assert!(!source.contains(&model_is_file_pattern));
        assert!(!source.contains(&metadata_is_file_pattern));
    }
}
