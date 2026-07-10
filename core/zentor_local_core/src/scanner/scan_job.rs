use uuid::Uuid;

use super::{ScanJobStatus, ScanKind};

#[derive(Debug, Clone)]
pub struct ScanJob {
    pub id: String,
    #[allow(dead_code)]
    pub kind: ScanKind,
    pub status: ScanJobStatus,
}

impl ScanJob {
    pub fn new(kind: ScanKind) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
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
        let mut job = ScanJob::new(ScanKind::Full);
        job.cancel();
        assert_eq!(job.status, ScanJobStatus::Cancelled);
    }
}
