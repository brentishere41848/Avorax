use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg(test)]
pub(crate) mod quarantine_action;
#[cfg(test)]
pub(crate) mod quarantine_store;

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
