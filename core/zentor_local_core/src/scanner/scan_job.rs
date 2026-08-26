use super::{ScanJobStatus, ScanKind};

#[derive(Debug, Clone)]
pub struct ScanJob {
    pub id: String,
    #[allow(dead_code)]
    pub kind: ScanKind,
    pub status: ScanJobStatus,
}

impl ScanJob {
    pub fn with_id(kind: ScanKind, id: String) -> Self {
        Self {
            id,
            kind,
            status: ScanJobStatus::Queued,
        }
    }

    pub fn cancel(&mut self) {
        self.status = ScanJobStatus::Cancelled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_scan_stops_job_safely() {
        let mut job = ScanJob::with_id(
            ScanKind::Full,
            "00000000-0000-0000-0000-000000000001".to_string(),
        );
        job.cancel();
        assert_eq!(job.status, ScanJobStatus::Cancelled);
    }
}
