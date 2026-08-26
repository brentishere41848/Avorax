pub mod archive_scanner;
pub mod cancellation;
pub mod content_reader;
pub mod env_roots;
pub mod file_walker;
pub mod full_scan_planner;
pub mod quick_scan_planner;
pub mod scan_job;
pub mod scan_progress;
pub mod scan_result;
pub mod scan_scheduler;
pub mod scan_scope;

pub use cancellation::{is_cooperative_scan_cancellation, is_scan_cancellation_check_failure};
pub use scan_job::{ScanJobId, ScanMode};
pub use scan_progress::ScanProgress;
pub use scan_result::{FileScanVerdict, ScanActionMode, ScanSummary};
