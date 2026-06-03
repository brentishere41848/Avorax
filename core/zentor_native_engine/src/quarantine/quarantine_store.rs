use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::quarantine_action::QUARANTINE_EXTENSION;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    #[serde(default)]
    pub file_size_bytes: u64,
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
        let quarantine_path = self.root.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        let file_size_bytes = fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        fs::rename(path, &quarantine_path)
            .or_else(|_| copy_then_remove_verified(path, &quarantine_path, sha256))
            .with_context(|| format!("failed to quarantine {}", path.display()))?;
        if sha256_file(&quarantine_path)? != normalize_hash(sha256) {
            return Err(anyhow!(
                "quarantine hash verification failed for {}",
                quarantine_path.display()
            ));
        }
        let record = QuarantineRecord {
            quarantine_id: id.clone(),
            original_path: path.display().to_string(),
            quarantine_path: quarantine_path.display().to_string(),
            sha256: normalize_hash(sha256),
            file_size_bytes,
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

pub(crate) fn copy_then_remove_verified(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<()> {
    fs::copy(source, destination)?;
    let destination_hash = sha256_file(destination)?;
    if destination_hash != normalize_hash(expected_sha256) {
        let _ = fs::remove_file(destination);
        return Err(anyhow!(
            "hash verification failed before deleting original quarantine source"
        ));
    }
    fs::remove_file(source)?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn normalize_hash(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| value.trim())
        .to_ascii_lowercase()
}
