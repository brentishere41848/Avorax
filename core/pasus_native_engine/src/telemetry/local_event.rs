use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalEvent {
    pub event_type: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
}
