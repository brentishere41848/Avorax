use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct WatcherState {
    pub active: bool,
    pub watched_paths: Vec<String>,
    pub mode: &'static str,
    pub limitations: Vec<&'static str>,
}

impl WatcherState {
    pub fn stopped() -> Self {
        Self {
            active: false,
            watched_paths: Vec::new(),
            mode: "stopped",
            limitations: Vec::new(),
        }
    }

    pub fn from_requested_paths(paths: Vec<PathBuf>) -> Self {
        let mut watched_paths: Vec<String> = paths
            .into_iter()
            .filter(|path| path.is_dir())
            .map(|path| path.display().to_string())
            .collect();
        watched_paths.sort();
        watched_paths.dedup();

        Self {
            active: !watched_paths.is_empty(),
            watched_paths,
            mode: "userModeBestEffort",
            limitations: vec!["existing-accessible-paths-only"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_at_ms: u64,
    pub observed_at_ms: u64,
}

impl WatchEvent {
    pub fn modified(path: PathBuf, size_bytes: u64, observed_at_ms: u64) -> Self {
        Self {
            path,
            size_bytes,
            modified_at_ms: 0,
            observed_at_ms,
        }
    }

    pub fn modified_with_file_time(
        path: PathBuf,
        size_bytes: u64,
        modified_at_ms: u64,
        observed_at_ms: u64,
    ) -> Self {
        Self {
            path,
            size_bytes,
            modified_at_ms,
            observed_at_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvaluation {
    WaitForDebounce,
    WaitForStableFile,
    AlreadyScannedUnchanged,
    ScanRequired { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MonitorObservation {
    pub path: String,
    pub action: &'static str,
    pub reason: String,
    pub label_as_malware: bool,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
struct FileSnapshot {
    size_bytes: u64,
    modified_at_ms: u64,
    first_seen_ms: u64,
    last_scanned_fingerprint: Option<FileFingerprint>,
    stable_observations: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    size_bytes: u64,
    modified_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct UserModeFileMonitor {
    debounce: Duration,
    required_stable_observations: u8,
    files: HashMap<PathBuf, FileSnapshot>,
}

impl UserModeFileMonitor {
    pub fn new(debounce: Duration, required_stable_observations: u8) -> Self {
        Self {
            debounce,
            required_stable_observations: required_stable_observations.max(1),
            files: HashMap::new(),
        }
    }

    pub fn evaluate_event(&mut self, event: WatchEvent) -> WatchEvaluation {
        let debounce_ms = self.debounce.as_millis() as u64;
        let required_stable_observations = self.required_stable_observations;
        let snapshot = self
            .files
            .entry(event.path.clone())
            .or_insert(FileSnapshot {
                size_bytes: event.size_bytes,
                modified_at_ms: event.modified_at_ms,
                first_seen_ms: event.observed_at_ms,
                last_scanned_fingerprint: None,
                stable_observations: 1,
            });

        if snapshot.size_bytes != event.size_bytes
            || snapshot.modified_at_ms != event.modified_at_ms
        {
            let previous_size_bytes = snapshot.size_bytes;
            let previous_modified_at_ms = snapshot.modified_at_ms;
            let fingerprint = FileFingerprint {
                size_bytes: event.size_bytes,
                modified_at_ms: event.modified_at_ms,
            };
            let same_size_rewrite_after_scan = snapshot.last_scanned_fingerprint.is_some()
                && previous_size_bytes == event.size_bytes
                && previous_modified_at_ms != event.modified_at_ms;

            snapshot.size_bytes = event.size_bytes;
            snapshot.modified_at_ms = event.modified_at_ms;
            snapshot.first_seen_ms = event.observed_at_ms;
            snapshot.stable_observations = 1;

            if same_size_rewrite_after_scan {
                snapshot.last_scanned_fingerprint = Some(fingerprint);
                return WatchEvaluation::ScanRequired {
                    reason: "created-or-modified".to_string(),
                };
            }
            return WatchEvaluation::WaitForStableFile;
        }

        if event.observed_at_ms.saturating_sub(snapshot.first_seen_ms) < debounce_ms {
            return WatchEvaluation::WaitForDebounce;
        }

        if snapshot.stable_observations < required_stable_observations {
            snapshot.stable_observations += 1;
        }

        if snapshot.stable_observations < required_stable_observations {
            return WatchEvaluation::WaitForStableFile;
        }

        let fingerprint = FileFingerprint {
            size_bytes: event.size_bytes,
            modified_at_ms: event.modified_at_ms,
        };
        if snapshot.last_scanned_fingerprint == Some(fingerprint) {
            return WatchEvaluation::AlreadyScannedUnchanged;
        }

        snapshot.last_scanned_fingerprint = Some(fingerprint);
        WatchEvaluation::ScanRequired {
            reason: "created-or-modified".to_string(),
        }
    }

    pub fn observe_review_item(&mut self, path: PathBuf, reason: &str) -> MonitorObservation {
        MonitorObservation {
            path: path.display().to_string(),
            action: "monitorOnly",
            reason: reason.to_string(),
            label_as_malware: false,
            blocked: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn watch_plan_filters_missing_paths_and_marks_best_effort_active() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");
        let state = WatcherState::from_requested_paths(vec![dir.path().to_path_buf(), missing]);

        assert!(state.active);
        assert_eq!(state.watched_paths, vec![dir.path().display().to_string()]);
        assert_eq!(state.mode, "userModeBestEffort");
        assert_eq!(state.limitations, vec!["existing-accessible-paths-only"]);
    }

    #[test]
    fn file_events_wait_for_debounce_and_stable_size_before_scan() {
        let mut monitor = UserModeFileMonitor::new(Duration::from_millis(500), 2);
        let path = PathBuf::from("C:/Users/Brent/Downloads/new.exe");

        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 100, 1_000)),
            WatchEvaluation::WaitForDebounce
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 120, 1_200)),
            WatchEvaluation::WaitForStableFile
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 120, 1_700)),
            WatchEvaluation::ScanRequired {
                reason: "created-or-modified".into()
            }
        );
    }

    #[test]
    fn unchanged_file_cache_suppresses_duplicate_scan_until_file_changes() {
        let mut monitor = UserModeFileMonitor::new(Duration::from_millis(250), 2);
        let path = PathBuf::from("C:/Users/Brent/Downloads/tool.exe");

        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 42, 1_000)),
            WatchEvaluation::WaitForDebounce
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 42, 1_300)),
            WatchEvaluation::ScanRequired {
                reason: "created-or-modified".into()
            }
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 42, 1_700)),
            WatchEvaluation::AlreadyScannedUnchanged
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 99, 2_100)),
            WatchEvaluation::WaitForStableFile
        );
    }

    #[test]
    fn unchanged_file_cache_rescans_same_size_file_when_modified_time_changes() {
        let mut monitor = UserModeFileMonitor::new(Duration::from_millis(250), 2);
        let path = PathBuf::from("C:/Users/Brent/Downloads/tool.exe");

        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified_with_file_time(
                path.clone(),
                42,
                10_000,
                1_000
            )),
            WatchEvaluation::WaitForDebounce
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified_with_file_time(
                path.clone(),
                42,
                10_000,
                1_300
            )),
            WatchEvaluation::ScanRequired {
                reason: "created-or-modified".into()
            }
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified_with_file_time(
                path.clone(),
                42,
                10_000,
                1_700
            )),
            WatchEvaluation::AlreadyScannedUnchanged
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified_with_file_time(
                path.clone(),
                42,
                11_000,
                2_100
            )),
            WatchEvaluation::ScanRequired {
                reason: "created-or-modified".into()
            }
        );
    }

    #[test]
    fn monitor_only_mode_reports_review_without_malware_label_or_block() {
        let mut monitor = UserModeFileMonitor::new(Duration::from_millis(0), 1);
        let path = PathBuf::from("C:/Users/Brent/Downloads/review.ps1");

        let event = monitor.observe_review_item(path, "medium-confidence heuristic");

        assert_eq!(event.action, "monitorOnly");
        assert_eq!(event.reason, "medium-confidence heuristic");
        assert!(!event.label_as_malware);
        assert!(!event.blocked);
    }
}
