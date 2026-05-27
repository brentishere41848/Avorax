use std::path::Path;

use anyhow::Result;

pub mod clamav_provider;
pub mod file_walker;
pub mod heuristic_provider;
pub mod reputation_provider;
pub mod scan_job;
pub mod scan_progress;
pub mod scan_report;
pub mod scan_result;
pub mod scan_scope;
pub mod threat_result;
pub mod yara_provider;

pub use clamav_provider::ClamAvProvider;
pub use heuristic_provider::eligible_for_heuristic_auto_quarantine;
pub use heuristic_provider::HeuristicProvider;
pub use reputation_provider::ReputationProvider;
pub use scan_job::ScanJob;
pub use scan_progress::{ScanJobStatus, ScanProgress};
pub use scan_report::{ReportStatus, ScanActionMode, ScanKind, ScanReport};
pub use scan_result::{ScanResult, ScanStatus};
pub use threat_result::{
    DetectionType, RecommendedAction, RiskEngine, RiskReason, RiskReasonSource, RiskScore,
    RiskSeverity, RiskVerdict, ThreatCategory, ThreatConfidence, ThreatResult, ThreatResultStatus,
};
pub use yara_provider::YaraProvider;

pub trait ScannerProvider {
    fn scan_file(&self, path: &Path) -> Result<ScanResult>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::NamedTempFile;

    struct FakeProvider(ScanStatus);

    impl ScannerProvider for FakeProvider {
        fn scan_file(&self, path: &Path) -> Result<ScanResult> {
            Ok(ScanResult {
                status: self.0.clone(),
                scanned_path: path.display().to_string(),
                sha256: "sha256:test".to_string(),
                engine: "fake".to_string(),
                signature_name: None,
                threat_name: None,
                scanned_at: Utc::now(),
                duration_ms: 1,
                raw_engine_summary: None,
            })
        }
    }

    #[test]
    fn engine_unavailable_is_not_clean() {
        let file = NamedTempFile::new().unwrap();
        let result = FakeProvider(ScanStatus::EngineUnavailable)
            .scan_file(file.path())
            .unwrap();
        assert_ne!(result.status, ScanStatus::Clean);
    }
}
