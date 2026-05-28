use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::quarantine::QuarantineRecord;
use crate::verdict::FinalVerdict;

use super::{ScanJobId, ScanMode, ScanProgress};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanActionMode {
    DetectOnly,
    AutoQuarantineConfirmed,
    AutoQuarantineHighConfidence,
    LockdownReview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileScanVerdict {
    pub path: PathBuf,
    pub sha256: String,
    pub engine: String,
    pub final_verdict: FinalVerdict,
    pub scanned_at: DateTime<Utc>,
    pub quarantine_record: Option<QuarantineRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub job_id: ScanJobId,
    pub scan_mode: ScanMode,
    pub files_scanned: u64,
    pub skipped_files: u64,
    pub threats_found: u64,
    pub quarantined_files: u64,
    pub results: Vec<FileScanVerdict>,
    pub progress: ScanProgress,
}
