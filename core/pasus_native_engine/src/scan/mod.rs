pub mod archive_scanner;
pub mod content_reader;
pub mod file_walker;
pub mod full_scan_planner;
pub mod quick_scan_planner;
pub mod scan_job;
pub mod scan_progress;
pub mod scan_result;
pub mod scan_scheduler;
pub mod scan_scope;

pub use scan_job::{ScanJobId, ScanMode};
pub use scan_progress::ScanProgress;
pub use scan_result::{FileScanVerdict, ScanActionMode, ScanSummary};
