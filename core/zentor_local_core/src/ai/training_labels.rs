use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::feature_extractor::StaticFeatures;

const MAX_TRAINING_LABEL_STORE_BYTES: usize = 1024 * 1024;
const MAX_TRAINING_LABEL_LINE_BYTES: usize = 64 * 1024;
const MAX_TRAINING_LABEL_ID_CHARS: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UserTrainingLabel {
    FalsePositive,
    ConfirmedMalicious,
    Unsure,
    TrustedApp,
    PotentiallyUnwantedButAllowed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingLabel {
    pub label_id: String,
    pub file_sha256: String,
    pub file_name: String,
    pub file_path_category: String,
    pub extracted_features: StaticFeatures,
    pub previous_verdict: String,
    pub user_label: UserTrainingLabel,
    pub user_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub app_version: String,
    pub model_version: String,
}

pub struct TrainingLabelStore {
    path: PathBuf,
}

impl TrainingLabelStore {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            path: data_dir()?.join("training_labels.jsonl"),
        })
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn append(&self, mut label: TrainingLabel) -> anyhow::Result<TrainingLabel> {
        if label.label_id.trim().is_empty() {
            label.label_id = Uuid::new_v4().to_string();
        }
        validate_training_label_id(&label.label_id)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            ensure_training_label_directory(parent, "training-label parent directory")?;
        }
        let serialized = serde_json::to_string(&label)?;
        if serialized.len() > MAX_TRAINING_LABEL_LINE_BYTES {
            anyhow::bail!(
                "training label for {} exceeds maximum line size of {} bytes",
                label.file_sha256,
                MAX_TRAINING_LABEL_LINE_BYTES
            );
        }
        let mut contents = read_training_label_store_bytes(&self.path)?;
        if contents.len().saturating_add(serialized.len() + 1) > MAX_TRAINING_LABEL_STORE_BYTES {
            anyhow::bail!(
                "training-label store {} would exceed maximum size of {} bytes",
                self.path.display(),
                MAX_TRAINING_LABEL_STORE_BYTES
            );
        }
        contents.extend_from_slice(serialized.as_bytes());
        contents.push(b'\n');
        write_training_label_store_staged(&self.path, &contents)?;
        Ok(label)
    }

    pub fn suppresses_hash(&self, sha256: &str) -> anyhow::Result<bool> {
        let contents = read_training_label_store_bytes(&self.path)?;
        if contents.is_empty() {
            return Ok(false);
        }
        let mut reader = BufReader::new(contents.as_slice());
        let mut latest: Option<TrainingLabel> = None;
        let mut line = String::new();
        let mut total_bytes = 0usize;
        let mut index = 0usize;
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).with_context(|| {
                format!(
                    "unable to read training-label store {}",
                    self.path.display()
                )
            })?;
            if bytes_read == 0 {
                break;
            }
            index += 1;
            total_bytes = total_bytes.saturating_add(bytes_read);
            if total_bytes > MAX_TRAINING_LABEL_STORE_BYTES {
                anyhow::bail!(
                    "training-label store {} exceeds maximum size of {} bytes",
                    self.path.display(),
                    MAX_TRAINING_LABEL_STORE_BYTES
                );
            }
            if line.len() > MAX_TRAINING_LABEL_LINE_BYTES {
                anyhow::bail!(
                    "training-label store {} line {} exceeds maximum line size of {} bytes",
                    self.path.display(),
                    index,
                    MAX_TRAINING_LABEL_LINE_BYTES
                );
            }
            if line.trim().is_empty() {
                continue;
            }
            let label =
                serde_json::from_str::<TrainingLabel>(line.trim_end()).with_context(|| {
                    format!(
                        "unable to parse training-label store {} at line {}",
                        self.path.display(),
                        index
                    )
                })?;
            validate_training_label_id(&label.label_id).with_context(|| {
                format!(
                    "invalid training-label id in {} at line {}",
                    self.path.display(),
                    index
                )
            })?;
            let should_replace_latest = match latest.as_ref() {
                Some(current) => label.created_at > current.created_at,
                None => true,
            };
            if label.file_sha256 == sha256 && should_replace_latest {
                latest = Some(label);
            }
        }
        Ok(latest.is_some_and(|label| {
            matches!(
                label.user_label,
                UserTrainingLabel::FalsePositive | UserTrainingLabel::TrustedApp
            )
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn validate_training_label_id(id: &str) -> anyhow::Result<()> {
    if id.trim().is_empty() {
        anyhow::bail!("training-label id is required");
    }
    if id.trim() != id {
        anyhow::bail!("training-label id contains leading or trailing whitespace");
    }
    if id.chars().count() > MAX_TRAINING_LABEL_ID_CHARS {
        anyhow::bail!("training-label id exceeds maximum length");
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        anyhow::bail!(
            "invalid training-label id; only ASCII letters, digits, hyphen, and underscore are allowed"
        );
    }
    Ok(())
}

fn read_training_label_store_bytes(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("unable to inspect training-label store {}", path.display())
            })
        }
    };
    ensure_regular_training_label_file(path, "training-label store", &metadata)?;
    if metadata.len() > MAX_TRAINING_LABEL_STORE_BYTES as u64 {
        anyhow::bail!(
            "training-label store {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_TRAINING_LABEL_STORE_BYTES
        );
    }
    let file = fs::File::open(path)
        .with_context(|| format!("unable to read training-label store {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut contents = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0usize;
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("unable to read training-label store {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).ok_or_else(|| {
            anyhow::anyhow!("training-label store {} size overflow", path.display())
        })?;
        if total > MAX_TRAINING_LABEL_STORE_BYTES {
            anyhow::bail!(
                "training-label store {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_TRAINING_LABEL_STORE_BYTES
            );
        }
        contents.extend_from_slice(&buffer[..read]);
    }
    Ok(contents)
}

fn write_training_label_store_staged(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let temp_path = path.with_extension(format!("jsonl.tmp-{}", Uuid::new_v4()));
    if let Err(error) = write_training_label_file_exclusive(&temp_path, bytes) {
        cleanup_training_label_temp_file(&temp_path).with_context(|| {
            format!(
                "unable to clean up temporary training-label store {} after write failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) =
        ensure_training_label_file_at_path(&temp_path, "temporary training-label store")
    {
        cleanup_training_label_temp_file(&temp_path).with_context(|| {
            format!(
                "unable to clean up temporary training-label store {} after temporary validation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = remove_existing_training_label_file(path, "training-label store") {
        cleanup_training_label_temp_file(&temp_path).with_context(|| {
            format!(
                "unable to clean up temporary training-label store {} after activation preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        cleanup_training_label_temp_file(&temp_path).with_context(|| {
            format!(
                "unable to clean up temporary training-label store {} after activation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error).with_context(|| {
            format!("unable to activate training-label store {}", path.display())
        });
    }
    Ok(())
}

fn cleanup_training_label_temp_file(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to remove temporary training-label store {}",
                path.display()
            )
        }),
    }
}

fn write_training_label_file_exclusive(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "unable to create temporary training-label store {}",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("unable to write training-label store {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("unable to sync training-label store {}", path.display()))?;
    Ok(())
}

fn ensure_training_label_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    ensure_training_label_metadata_safe(path, label, &metadata)?;
    if !metadata.is_dir() {
        anyhow::bail!("{label} {} is not a directory", path.display());
    }
    Ok(())
}

fn ensure_training_label_file_at_path(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
    ensure_regular_training_label_file(path, label, &metadata)
}

fn remove_existing_training_label_file(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_training_label_file(path, label, &metadata)?;
            fs::remove_file(path)
                .with_context(|| format!("unable to remove {label} {}", path.display()))?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_regular_training_label_file(
    path: &Path,
    label: &str,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    ensure_training_label_metadata_safe(path, label, metadata)?;
    if !metadata.is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    Ok(())
}

fn ensure_training_label_metadata_safe(
    path: &Path,
    label: &str,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label} {}", path.display());
    }
    if training_label_metadata_is_windows_reparse_point(metadata) {
        anyhow::bail!("refusing to use reparse point {label} {}", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn training_label_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn training_label_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn data_dir() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_training_label_env_path("AVORAX_DATA_DIR")? {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = absolute_training_label_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax").join("data"));
        }
        if let Some(program_data) = absolute_training_label_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax").join("data"));
        }
    }
    if let Some(home) = absolute_training_label_env_path("HOME")? {
        return Ok(home.join(".local/share/avorax/data"));
    }
    anyhow::bail!("training-label data root is unavailable")
}

fn absolute_training_label_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("training-label environment path {name} is empty");
    }
    validate_training_label_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !training_label_root_is_allowed(&path) {
        anyhow::bail!("training-label environment path {name} must be an absolute local path");
    }
    Ok(Some(path))
}

fn validate_training_label_env_root_text(name: &str, text: &str) -> anyhow::Result<()> {
    if text.contains('\0') {
        anyhow::bail!("training-label environment path {name} contains NUL");
    }
    if training_label_env_root_has_parent_traversal(text) {
        anyhow::bail!("training-label environment path {name} must not contain parent traversal");
    }
    Ok(())
}

fn training_label_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn training_label_root_is_allowed(path: &Path) -> bool {
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
fn training_label_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::feature_extractor::{LocationCategory, StaticFeatures};
    use tempfile::tempdir;

    fn training_label_env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    #[test]
    fn false_positive_label_suppresses_same_hash() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        store
            .append(TrainingLabel {
                label_id: String::new(),
                file_sha256: "abc123".to_string(),
                file_name: "tool.exe".to_string(),
                file_path_category: "downloads".to_string(),
                extracted_features: StaticFeatures {
                    file_size: 10,
                    file_extension: "exe".to_string(),
                    location_category: LocationCategory::Downloads,
                    double_extension: false,
                    embedded_urls_count: 0,
                    embedded_ip_addresses_count: 0,
                    suspicious_strings_count: 0,
                    entropy: 1.0,
                    packed_likely: false,
                    macro_or_script: false,
                },
                previous_verdict: "unknown".to_string(),
                user_label: UserTrainingLabel::FalsePositive,
                user_note: None,
                created_at: Utc::now(),
                app_version: "test".to_string(),
                model_version: "unavailable".to_string(),
            })
            .unwrap();
        assert!(store.suppresses_hash("abc123").unwrap());
        assert!(!store.suppresses_hash("other").unwrap());
    }

    #[test]
    fn confirmed_malicious_label_revokes_prior_false_positive_suppression() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        store
            .append(test_label("abc123", UserTrainingLabel::FalsePositive))
            .unwrap();
        store
            .append(test_label("abc123", UserTrainingLabel::ConfirmedMalicious))
            .unwrap();

        assert!(!store.suppresses_hash("abc123").unwrap());
    }

    #[test]
    fn malformed_training_label_store_is_not_treated_as_no_suppression() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        fs::write(store.path(), "{not-json").unwrap();

        let error = store.suppresses_hash("abc123").unwrap_err().to_string();

        assert!(error.contains("unable to parse training-label store"));
    }

    #[test]
    fn missing_training_label_store_does_not_suppress_hash() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("missing.jsonl"));

        assert!(!store.suppresses_hash("abc123").unwrap());
    }

    #[test]
    fn oversized_training_label_line_is_not_treated_as_no_suppression() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        fs::write(store.path(), "x".repeat(MAX_TRAINING_LABEL_LINE_BYTES + 1)).unwrap();

        let error = store.suppresses_hash("abc123").unwrap_err().to_string();

        assert!(error.contains("exceeds maximum line size"));
    }

    #[test]
    fn oversized_training_label_store_is_not_treated_as_no_suppression() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        let chunk = format!("{}\n", " ".repeat(MAX_TRAINING_LABEL_LINE_BYTES / 2));
        let mut body = String::new();
        while body.len() <= MAX_TRAINING_LABEL_STORE_BYTES {
            body.push_str(&chunk);
        }
        fs::write(store.path(), body).unwrap();

        let error = store.suppresses_hash("abc123").unwrap_err().to_string();

        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn append_rejects_oversized_training_label_line() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        let mut label = test_label("abc123", UserTrainingLabel::FalsePositive);
        label.user_note = Some("x".repeat(MAX_TRAINING_LABEL_LINE_BYTES));

        let error = store.append(label).unwrap_err().to_string();

        assert!(error.contains("exceeds maximum line size"));
    }

    #[test]
    fn append_generates_blank_training_label_id_and_rejects_unsafe_ids() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        let mut blank = test_label("abc123", UserTrainingLabel::FalsePositive);
        blank.label_id = " ".to_string();

        let saved = store.append(blank).unwrap();
        assert!(!saved.label_id.trim().is_empty());
        assert!(saved.label_id.contains('-'));

        let mut unsafe_label = test_label("abc123", UserTrainingLabel::FalsePositive);
        unsafe_label.label_id = "bad/id".to_string();
        let error = store.append(unsafe_label).unwrap_err().to_string();
        assert!(error.contains("invalid training-label id"));
    }

    #[test]
    fn persisted_training_label_with_unsafe_id_is_not_treated_as_no_suppression() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        let mut label = test_label("abc123", UserTrainingLabel::FalsePositive);
        label.label_id = "bad/id".to_string();
        fs::write(
            store.path(),
            format!("{}\n", serde_json::to_string(&label).unwrap()),
        )
        .unwrap();

        let error = store.suppresses_hash("abc123").unwrap_err().to_string();

        assert!(error.contains("invalid training-label id"));
    }

    #[test]
    fn persisted_training_label_rejects_unknown_top_level_fields() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        let mut value =
            serde_json::to_value(test_label("abc123", UserTrainingLabel::FalsePositive)).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("allow_all".to_string(), serde_json::json!(true));
        fs::write(store.path(), format!("{value}\n")).unwrap();

        let error = store.suppresses_hash("abc123").unwrap_err().to_string();

        assert!(error.contains("unable to parse training-label store"));
    }

    #[test]
    fn persisted_training_label_rejects_unknown_extracted_feature_fields() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));
        let mut value =
            serde_json::to_value(test_label("abc123", UserTrainingLabel::FalsePositive)).unwrap();
        value["extracted_features"]
            .as_object_mut()
            .unwrap()
            .insert("suppression_override".to_string(), serde_json::json!(true));
        fs::write(store.path(), format!("{value}\n")).unwrap();

        let error = store.suppresses_hash("abc123").unwrap_err().to_string();

        assert!(error.contains("unable to parse training-label store"));
    }

    #[test]
    fn training_label_schema_stays_strict() {
        let source = include_str!("training_labels.rs");
        let feature_source = include_str!("feature_extractor.rs");
        let label_start = source.find("pub struct TrainingLabel").unwrap();
        let label_prefix = &source[..label_start];
        let feature_start = feature_source.find("pub struct StaticFeatures").unwrap();
        let feature_prefix = &feature_source[..feature_start];

        assert!(label_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(feature_prefix.contains("#[serde(deny_unknown_fields)]"));
    }

    #[test]
    fn training_label_id_validation_is_not_dead_suppression_evidence() {
        let source = include_str!("training_labels.rs");
        let append_start = source.find("pub fn append").unwrap();
        let suppress_start = source.find("pub fn suppresses_hash").unwrap();
        let append_source = &source[append_start..suppress_start];
        let suppress_end = source.find("pub fn path(&self)").unwrap();
        let suppress_source = &source[suppress_start..suppress_end];

        assert!(source.contains("const MAX_TRAINING_LABEL_ID_CHARS: usize = 128;"));
        assert!(source.contains("fn validate_training_label_id"));
        assert!(append_source.contains("validate_training_label_id(&label.label_id)?"));
        assert!(suppress_source.contains("validate_training_label_id(&label.label_id)"));
        assert!(source.contains("invalid training-label id in"));
    }

    #[test]
    fn append_uses_staged_write_without_temp_leftover() {
        let dir = tempdir().unwrap();
        let store = TrainingLabelStore::with_path(dir.path().join("labels.jsonl"));

        store
            .append(test_label("abc123", UserTrainingLabel::FalsePositive))
            .unwrap();

        assert!(store.path().exists());
        assert!(fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().contains("jsonl.tmp-")));
    }

    #[cfg(unix)]
    #[test]
    fn training_label_store_rejects_symbolic_link_paths() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("external.jsonl");
        let link = dir.path().join("labels.jsonl");
        fs::write(&target, "{}\n").unwrap();
        unix_fs::symlink(&target, &link).unwrap();
        let store = TrainingLabelStore::with_path(link);

        let read_error = store.suppresses_hash("abc123").unwrap_err().to_string();
        let append_error = store
            .append(test_label("abc123", UserTrainingLabel::FalsePositive))
            .unwrap_err()
            .to_string();

        assert!(read_error.contains("symbolic link"));
        assert!(append_error.contains("symbolic link"));
        assert_eq!(fs::read_to_string(&target).unwrap(), "{}\n");
    }

    #[test]
    fn training_label_store_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("training_labels.rs");
        let start = source.find("fn read_training_label_store_bytes").unwrap();
        let end = source.find("fn write_training_label_store_staged").unwrap();
        let reader = &source[start..end];

        assert!(reader.contains("metadata.len() > MAX_TRAINING_LABEL_STORE_BYTES as u64"));
        assert!(reader.contains("let mut total = 0usize"));
        assert!(reader.contains("checked_add(read)"));
        assert!(reader.contains("total > MAX_TRAINING_LABEL_STORE_BYTES"));
        assert!(reader.contains("contents.extend_from_slice(&buffer[..read])"));
        assert!(!reader.contains(".take(MAX_TRAINING_LABEL_STORE_BYTES"));
        assert!(!reader.contains("read_to_end(&mut contents)"));
    }

    #[test]
    fn training_label_store_uses_non_following_staged_writes() {
        let source = include_str!("training_labels.rs");
        let read_helper_pattern = ["fn read_training_label_store_", "bytes"].concat();
        let staged_helper_pattern = ["fn write_training_label_store_", "staged"].concat();
        let exclusive_helper_pattern = ["fn write_training_label_file_", "exclusive"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let write_all_pattern = ["write_", "all(bytes)"].concat();
        let sync_pattern = ["file.", "sync_all()"].concat();
        let symlink_metadata_pattern = ["fs::", "symlink_metadata(path)"].concat();
        let uuid_pattern = ["Uuid::", "new_v4()"].concat();
        let symlink_error_pattern = ["refusing to use symbolic link ", "{label}"].concat();
        let reparse_error_pattern = ["refusing to use reparse point ", "{label}"].concat();
        let old_metadata_pattern = ["fs::", "metadata(&self.path)"].concat();
        let old_exists_pattern = ["self.path", ".exists()"].concat();
        let old_append_pattern = [".append", "(true)"].concat();

        assert!(source.contains(&read_helper_pattern));
        assert!(source.contains(&staged_helper_pattern));
        assert!(source.contains(&exclusive_helper_pattern));
        assert!(source.contains(&uuid_pattern));
        assert!(source.contains(&create_new_pattern));
        assert!(source.contains(&write_all_pattern));
        assert!(source.contains(&sync_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&symlink_error_pattern));
        assert!(source.contains(&reparse_error_pattern));
        assert!(!source.contains(&old_metadata_pattern));
        assert!(!source.contains(&old_exists_pattern));
        assert!(!source.contains(&old_append_pattern));
    }

    #[test]
    fn training_label_staged_cleanup_failures_are_reported() {
        let source = include_str!("training_labels.rs");
        let start = source.find("fn write_training_label_store_staged").unwrap();
        let end = source
            .find("fn write_training_label_file_exclusive")
            .unwrap();
        let write_source = &source[start..end];
        let ignored_cleanup = ["let _ = fs::remove_", "file(&temp_path);"].concat();

        assert!(write_source.contains("fn cleanup_training_label_temp_file"));
        assert!(write_source.contains("after write failure"));
        assert!(write_source.contains("after temporary validation failure"));
        assert!(write_source.contains("after activation preflight failure"));
        assert!(write_source.contains("after activation failure"));
        assert!(!write_source.contains(&ignored_cleanup));
    }

    #[test]
    fn training_label_data_root_rejects_relative_override() {
        let _lock = training_label_env_lock();
        let previous_avorax = std::env::var_os("AVORAX_DATA_DIR");

        std::env::set_var("AVORAX_DATA_DIR", "relative-training-label-root");
        let result = TrainingLabelStore::new();

        if let Some(previous_avorax) = previous_avorax {
            std::env::set_var("AVORAX_DATA_DIR", previous_avorax);
        } else {
            std::env::remove_var("AVORAX_DATA_DIR");
        }

        let error = match result {
            Ok(_) => panic!("relative training-label root was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("AVORAX_DATA_DIR must be an absolute local path"));
    }

    #[test]
    fn training_label_data_root_rejects_parent_traversal_override() {
        let _lock = training_label_env_lock();
        let previous_avorax = std::env::var_os("AVORAX_DATA_DIR");
        let dir = tempdir().unwrap();

        std::env::set_var("AVORAX_DATA_DIR", dir.path().join(".."));
        let result = TrainingLabelStore::new();

        if let Some(previous_avorax) = previous_avorax {
            std::env::set_var("AVORAX_DATA_DIR", previous_avorax);
        } else {
            std::env::remove_var("AVORAX_DATA_DIR");
        }

        let error = match result {
            Ok(_) => panic!("parent-traversing training-label root was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("AVORAX_DATA_DIR"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[test]
    fn training_label_data_root_has_no_relative_fallback() {
        let _lock = training_label_env_lock();
        let keys = ["AVORAX_DATA_DIR", "ProgramData", "PROGRAMDATA", "HOME"];
        let previous: Vec<_> = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();

        for key in keys {
            std::env::remove_var(key);
        }
        let result = TrainingLabelStore::new();

        for (key, value) in previous {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }

        let source = include_str!("training_labels.rs");
        let start = source.find("impl TrainingLabelStore").unwrap();
        let end = source.find("#[cfg(test)]").unwrap();
        let root_source = &source[start..end];

        let error = match result {
            Ok(_) => panic!("missing training-label root used a relative fallback"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("training-label data root is unavailable"));
        assert!(root_source.contains("pub fn new() -> anyhow::Result<Self>"));
        assert!(root_source.contains("fn data_dir() -> anyhow::Result<PathBuf>"));
        assert!(root_source.contains("fn absolute_training_label_env_path("));
        assert!(root_source.contains("absolute_training_label_env_path(\"AVORAX_DATA_DIR\")?"));
        assert!(root_source.contains("absolute_training_label_env_path(\"HOME\")?"));
        assert!(root_source.contains("training_label_root_is_allowed(&path)"));
        assert!(root_source.contains("training-label data root is unavailable"));
        assert!(!root_source.contains("PathBuf::from(\".avorax/data\")"));
    }

    #[test]
    fn latest_training_label_selection_has_explicit_empty_branch() {
        let source = include_str!("training_labels.rs");
        let start = source.find("pub fn suppresses_hash").unwrap();
        let end = source.find("pub fn path(&self)").unwrap();
        let suppresses_source = &source[start..end];

        assert!(suppresses_source.contains("let should_replace_latest = match latest.as_ref()"));
        assert!(
            suppresses_source.contains("Some(current) => label.created_at > current.created_at")
        );
        assert!(suppresses_source.contains("None => true"));
        assert!(suppresses_source.contains("label.file_sha256 == sha256 && should_replace_latest"));
        assert!(!suppresses_source.contains(".unwrap_or(true)"));
    }

    fn test_label(file_sha256: &str, user_label: UserTrainingLabel) -> TrainingLabel {
        TrainingLabel {
            label_id: String::new(),
            file_sha256: file_sha256.to_string(),
            file_name: "tool.exe".to_string(),
            file_path_category: "downloads".to_string(),
            extracted_features: StaticFeatures {
                file_size: 10,
                file_extension: "exe".to_string(),
                location_category: LocationCategory::Downloads,
                double_extension: false,
                embedded_urls_count: 0,
                embedded_ip_addresses_count: 0,
                suspicious_strings_count: 0,
                entropy: 1.0,
                packed_likely: false,
                macro_or_script: false,
            },
            previous_verdict: "unknown".to_string(),
            user_label,
            user_note: None,
            created_at: Utc::now(),
            app_version: "test".to_string(),
            model_version: "unavailable".to_string(),
        }
    }
}
