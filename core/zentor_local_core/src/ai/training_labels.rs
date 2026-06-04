use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::feature_extractor::StaticFeatures;

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
    pub fn new() -> Self {
        Self {
            path: data_dir().join("training_labels.jsonl"),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn append(&self, mut label: TrainingLabel) -> anyhow::Result<TrainingLabel> {
        if label.label_id.is_empty() {
            label.label_id = Uuid::new_v4().to_string();
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(&label)?)?;
        Ok(label)
    }

    pub fn suppresses_hash(&self, sha256: &str) -> bool {
        let Ok(body) = fs::read_to_string(&self.path) else {
            return false;
        };
        body.lines()
            .filter_map(|line| serde_json::from_str::<TrainingLabel>(line).ok())
            .filter(|label| label.file_sha256 == sha256)
            .max_by_key(|label| label.created_at)
            .is_some_and(|label| {
                matches!(
                    label.user_label,
                    UserTrainingLabel::FalsePositive | UserTrainingLabel::TrustedApp
                )
            })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("AVORAX_DATA_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        if let Ok(program_data) = std::env::var("PROGRAMDATA") {
            return PathBuf::from(program_data).join("Avorax").join("data");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/avorax/data");
    }
    PathBuf::from(".avorax/data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::feature_extractor::{LocationCategory, StaticFeatures};
    use tempfile::tempdir;

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
        assert!(store.suppresses_hash("abc123"));
        assert!(!store.suppresses_hash("other"));
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

        assert!(!store.suppresses_hash("abc123"));
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
