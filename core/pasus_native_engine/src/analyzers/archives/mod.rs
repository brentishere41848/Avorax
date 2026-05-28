pub mod zip;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveAnalysis {
    pub entry_count: u32,
    pub contains_executable: bool,
    pub suspicious_nested_name_count: u32,
    pub zip_slip_blocked: bool,
    pub limit_exceeded: bool,
}
