use serde::{Deserialize, Serialize};

use super::{ScanProgress, ThreatResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ScanActionMode {
    DetectOnly,
    AutoQuarantineConfirmedOnly,
    AutoQuarantineAllDetections,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ScanKind {
    Quick,
    Full,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReportStatus {
    Clean,
    ThreatsFound,
    CompletedWithErrors,
    EngineUnavailable,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub status: ReportStatus,
    pub kind: ScanKind,
    pub action_mode: ScanActionMode,
    pub files_scanned: u64,
    pub folders_scanned: u64,
    pub bytes_scanned: u64,
    pub total_files_estimated: Option<u64>,
    pub total_bytes_estimated: Option<u64>,
    pub threats_found: u64,
    pub suspicious_found: u64,
    pub quarantined_files: u64,
    pub skipped_files: u64,
    pub permission_denied_count: u64,
    pub elapsed_ms: u128,
    pub current_path: Option<String>,
    pub message: Option<String>,
    #[serde(default)]
    pub scan_errors: Vec<String>,
    pub threats: Vec<ThreatResult>,
    pub progress: Option<ScanProgress>,
}
