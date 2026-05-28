use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{ScanJobId, ScanMode};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub job_id: ScanJobId,
    pub scan_type: ScanMode,
    pub status: String,
    pub current_path: Option<String>,
    pub files_scanned: u64,
    pub folders_scanned: u64,
    pub bytes_scanned: u64,
    pub total_files_estimated: Option<u64>,
    pub total_bytes_estimated: Option<u64>,
    pub threats_found: u64,
    pub skipped_files: u64,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub elapsed_seconds: u64,
    pub estimated_remaining_seconds: Option<u64>,
    pub progress_percent: Option<f64>,
}

impl ScanProgress {
    pub fn new(job_id: ScanJobId, scan_type: ScanMode) -> Self {
        let now = Utc::now();
        Self {
            job_id,
            scan_type,
            status: "running".to_string(),
            current_path: None,
            files_scanned: 0,
            folders_scanned: 0,
            bytes_scanned: 0,
            total_files_estimated: None,
            total_bytes_estimated: None,
            threats_found: 0,
            skipped_files: 0,
            started_at: now,
            updated_at: now,
            elapsed_seconds: 0,
            estimated_remaining_seconds: None,
            progress_percent: None,
        }
    }

    pub fn update_eta(&mut self) {
        if let Some(total) = self.total_files_estimated {
            if total > 0 {
                self.progress_percent =
                    Some((self.files_scanned as f64 / total as f64 * 100.0).clamp(0.0, 99.9));
            }
            if self.files_scanned > 0 && self.elapsed_seconds > 0 && total > self.files_scanned {
                let rate = self.files_scanned as f64 / self.elapsed_seconds as f64;
                if rate > 0.0 {
                    self.estimated_remaining_seconds =
                        Some(((total - self.files_scanned) as f64 / rate).round() as u64);
                }
            }
        }
    }
}
