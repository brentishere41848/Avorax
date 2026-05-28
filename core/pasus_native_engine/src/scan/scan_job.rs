use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ScanJobId(pub String);

impl Default for ScanJobId {
    fn default() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanMode {
    Quick,
    Full,
    Custom,
}
