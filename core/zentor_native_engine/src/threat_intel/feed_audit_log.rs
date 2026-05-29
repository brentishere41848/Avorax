use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedAuditEntry {
    pub source_name: String,
    pub indicator_count: usize,
    pub imported_at: DateTime<Utc>,
    pub result: String,
}

pub fn audit_entry(source_name: impl Into<String>, indicator_count: usize) -> FeedAuditEntry {
    FeedAuditEntry {
        source_name: source_name.into(),
        indicator_count,
        imported_at: Utc::now(),
        result: "imported".to_string(),
    }
}
