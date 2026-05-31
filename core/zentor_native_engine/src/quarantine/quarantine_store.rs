use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub detection_name: String,
    pub engine: String,
    pub quarantined_at: DateTime<Utc>,
    pub blocked_before_execution: bool,
    pub action_taken: String,
}

#[derive(Debug, Clone)]
pub struct QuarantineStore {
    root: PathBuf,
}

impl QuarantineStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn quarantine_file(
        &self,
        path: &Path,
        sha256: &str,
        detection_name: &str,
        blocked_before_execution: bool,
    ) -> Result<QuarantineRecord> {
        fs::create_dir_all(&self.root)?;
        let id = Uuid::new_v4().to_string();
        let quarantine_path = self.root.join(format!("{id}.zentorq"));
        fs::rename(path, &quarantine_path)
            .or_else(|_| {
                fs::copy(path, &quarantine_path)?;
                fs::remove_file(path)
            })
            .with_context(|| format!("failed to quarantine {}", path.display()))?;
        let record = QuarantineRecord {
            quarantine_id: id.clone(),
            original_path: path.display().to_string(),
            quarantine_path: quarantine_path.display().to_string(),
            sha256: sha256.to_string(),
            detection_name: detection_name.to_string(),
            engine: "Avorax Native Engine".to_string(),
            quarantined_at: Utc::now(),
            blocked_before_execution,
            action_taken: "quarantined".to_string(),
        };
        fs::write(
            self.root.join(format!("{id}.json")),
            serde_json::to_vec_pretty(&record)?,
        )?;
        Ok(record)
    }
}
