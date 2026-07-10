use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ScanKind;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ScanJobStatus {
    Queued,
    Running,
    Paused,
    Cancelled,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub job_id: String,
    pub scan_type: ScanKind,
    pub status: ScanJobStatus,
    pub current_path: Option<String>,
    pub files_scanned: u64,
    pub folders_scanned: u64,
    pub bytes_scanned: u64,
    pub total_files_estimated: Option<u64>,
    pub total_bytes_estimated: Option<u64>,
    pub threats_found: u64,
    pub suspicious_found: u64,
    pub skipped_files: u64,
    pub permission_denied_count: u64,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub elapsed_seconds: u64,
    pub estimated_remaining_seconds: Option<u64>,
    pub progress_percent: Option<f64>,
}

impl ScanProgress {
    pub fn calculate_eta(&mut self) {
        let Some(total_bytes) = self.total_bytes_estimated else {
            self.estimated_remaining_seconds = None;
            self.progress_percent = None;
            return;
        };
        if total_bytes == 0 || self.bytes_scanned >= total_bytes {
            self.estimated_remaining_seconds = Some(0);
            self.progress_percent = Some(100.0);
            return;
        }
        self.progress_percent = Some((self.bytes_scanned as f64 / total_bytes as f64) * 100.0);
        if self.elapsed_seconds < 2 || self.bytes_scanned == 0 {
            self.estimated_remaining_seconds = None;
            return;
        }
        let bytes_per_second = self.bytes_scanned as f64 / self.elapsed_seconds as f64;
        if bytes_per_second <= 0.0 {
            self.estimated_remaining_seconds = None;
            return;
        }
        let remaining = total_bytes.saturating_sub(self.bytes_scanned) as f64;
        self.estimated_remaining_seconds = Some((remaining / bytes_per_second).ceil() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eta_is_calculating_without_totals() {
        let mut progress = ScanProgress {
            job_id: "job".to_string(),
            scan_type: ScanKind::Quick,
            status: ScanJobStatus::Running,
            current_path: None,
            files_scanned: 10,
            folders_scanned: 1,
            bytes_scanned: 1000,
            total_files_estimated: None,
            total_bytes_estimated: None,
            threats_found: 0,
            suspicious_found: 0,
            skipped_files: 0,
            permission_denied_count: 0,
            started_at: Utc::now(),
            updated_at: Utc::now(),
            elapsed_seconds: 5,
            estimated_remaining_seconds: None,
            progress_percent: None,
        };
        progress.calculate_eta();
        assert!(progress.estimated_remaining_seconds.is_none());
        assert!(progress.progress_percent.is_none());
    }

    #[test]
    fn eta_updates_when_totals_exist() {
        let mut progress = ScanProgress {
            job_id: "job".to_string(),
            scan_type: ScanKind::Quick,
            status: ScanJobStatus::Running,
            current_path: None,
            files_scanned: 10,
            folders_scanned: 1,
            bytes_scanned: 500,
            total_files_estimated: Some(20),
            total_bytes_estimated: Some(1000),
            threats_found: 0,
            suspicious_found: 0,
            skipped_files: 0,
            permission_denied_count: 0,
            started_at: Utc::now(),
            updated_at: Utc::now(),
            elapsed_seconds: 5,
            estimated_remaining_seconds: None,
            progress_percent: None,
        };
        progress.calculate_eta();
        assert_eq!(progress.progress_percent, Some(50.0));
        assert_eq!(progress.estimated_remaining_seconds, Some(5));
    }
}
