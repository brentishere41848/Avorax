use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use walkdir::WalkDir;

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
        let mut requested_any_paths = false;
        let mut rejected_unsafe_paths = false;
        let mut watched_paths: Vec<String> = Vec::new();
        for path in paths {
            requested_any_paths = true;
            match watcher_path_decision(&path) {
                WatchPathDecision::Watch => watched_paths.push(path.display().to_string()),
                WatchPathDecision::Missing => {}
                WatchPathDecision::RejectUnsafe => rejected_unsafe_paths = true,
            }
        }
        watched_paths.sort();
        watched_paths.dedup();
        let mut limitations = vec![
            "existing-accessible-paths-only",
            "one-shot-watch-plan-only",
            "no-persistent-service-monitor",
            "no-kernel-pre-execution-blocking",
        ];
        if rejected_unsafe_paths {
            limitations.push("unsafe-or-uninspectable-paths-ignored");
        }
        if watched_paths.is_empty() {
            limitations.push(if requested_any_paths {
                "no-accessible-watch-paths"
            } else {
                "no-watch-paths-requested"
            });
        }
        let active = !watched_paths.is_empty();

        Self {
            active,
            watched_paths,
            mode: if active {
                "userModeBestEffort"
            } else {
                "stopped"
            },
            limitations,
        }
    }
}

enum WatchPathDecision {
    Watch,
    Missing,
    RejectUnsafe,
}

fn watcher_path_decision(path: &Path) -> WatchPathDecision {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || watcher_metadata_is_windows_reparse_point(&metadata)
            {
                return WatchPathDecision::RejectUnsafe;
            }
            if metadata.file_type().is_dir() {
                WatchPathDecision::Watch
            } else {
                WatchPathDecision::RejectUnsafe
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => WatchPathDecision::Missing,
        Err(_) => WatchPathDecision::RejectUnsafe,
    }
}

#[cfg(windows)]
fn watcher_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn watcher_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_at_ms: Option<u64>,
    pub observed_at_ms: u64,
}

impl WatchEvent {
    pub fn modified(path: PathBuf, size_bytes: u64, observed_at_ms: u64) -> Self {
        Self {
            path,
            size_bytes,
            modified_at_ms: None,
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
            modified_at_ms: Some(modified_at_ms),
            observed_at_ms,
        }
    }

    pub fn modified_with_optional_file_time(
        path: PathBuf,
        size_bytes: u64,
        modified_at_ms: Option<u64>,
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
pub struct WatchCandidate {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchCandidateSnapshot {
    pub candidates: Vec<WatchCandidate>,
    pub scan_errors: Vec<String>,
    pub limit_reached: bool,
}

pub fn collect_watch_candidates(
    roots: &[PathBuf],
    max_files: usize,
    max_depth: usize,
) -> WatchCandidateSnapshot {
    let mut candidates = Vec::new();
    let mut scan_errors = Vec::new();
    let mut limit_reached = false;

    for root in roots {
        for entry in WalkDir::new(root).follow_links(false).max_depth(max_depth) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    push_watch_scan_error(&mut scan_errors, format!("{error}"));
                    continue;
                }
            };
            if entry.file_type().is_dir() {
                continue;
            }
            if entry.file_type().is_symlink() {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path().to_path_buf();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    push_watch_scan_error(
                        &mut scan_errors,
                        format!("{}: metadata failed: {error}", path.display()),
                    );
                    continue;
                }
            };
            if metadata.file_type().is_symlink()
                || watcher_metadata_is_windows_reparse_point(&metadata)
            {
                continue;
            }
            if !metadata.file_type().is_file() {
                continue;
            }
            let modified_at_ms = match metadata_modified_at_ms(&metadata) {
                Ok(value) => Some(value),
                Err(error) => {
                    push_watch_scan_error(
                        &mut scan_errors,
                        format!(
                            "{}: modified timestamp unavailable; file will not be cached as unchanged: {error}",
                            path.display()
                        ),
                    );
                    None
                }
            };
            candidates.push(WatchCandidate {
                path,
                size_bytes: metadata.len(),
                modified_at_ms,
            });
            if candidates.len() >= max_files {
                limit_reached = true;
                break;
            }
        }
        if limit_reached {
            break;
        }
    }

    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    WatchCandidateSnapshot {
        candidates,
        scan_errors,
        limit_reached,
    }
}

fn metadata_modified_at_ms(metadata: &std::fs::Metadata) -> Result<u64, String> {
    let modified = metadata
        .modified()
        .map_err(|error| format!("modified timestamp query failed: {error}"))?;
    system_time_to_unix_ms(modified)
}

fn system_time_to_unix_ms(value: SystemTime) -> Result<u64, String> {
    let duration = value
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("modified timestamp predates Unix epoch: {error}"))?;
    Ok(duration.as_millis().min(u128::from(u64::MAX)) as u64)
}

fn push_watch_scan_error(scan_errors: &mut Vec<String>, detail: String) {
    if scan_errors.len() < 20 {
        scan_errors.push(detail);
    } else if let Some(last) = scan_errors.last_mut() {
        *last = "additional watch-poll scan errors omitted".to_string();
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
    modified_at_ms: Option<u64>,
    first_seen_ms: u64,
    last_scanned_fingerprint: Option<FileFingerprint>,
    stable_observations: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    size_bytes: u64,
    modified_at_ms: Option<u64>,
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
        if event.modified_at_ms.is_none() {
            snapshot.last_scanned_fingerprint = None;
            return WatchEvaluation::ScanRequired {
                reason: "timestamp-unavailable-rescan".to_string(),
            };
        }
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
        assert_eq!(
            state.limitations,
            vec![
                "existing-accessible-paths-only",
                "one-shot-watch-plan-only",
                "no-persistent-service-monitor",
                "no-kernel-pre-execution-blocking",
            ]
        );
    }

    #[test]
    fn watch_plan_reports_stopped_when_no_accessible_paths_remain() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"not a directory").unwrap();

        let state = WatcherState::from_requested_paths(vec![missing, file]);

        assert!(!state.active);
        assert!(state.watched_paths.is_empty());
        assert_eq!(state.mode, "stopped");
        assert_eq!(
            state.limitations,
            vec![
                "existing-accessible-paths-only",
                "one-shot-watch-plan-only",
                "no-persistent-service-monitor",
                "no-kernel-pre-execution-blocking",
                "unsafe-or-uninspectable-paths-ignored",
                "no-accessible-watch-paths",
            ]
        );
    }

    #[test]
    fn watch_plan_reports_stopped_when_no_paths_are_requested() {
        let state = WatcherState::from_requested_paths(Vec::new());

        assert!(!state.active);
        assert!(state.watched_paths.is_empty());
        assert_eq!(state.mode, "stopped");
        assert_eq!(
            state.limitations,
            vec![
                "existing-accessible-paths-only",
                "one-shot-watch-plan-only",
                "no-persistent-service-monitor",
                "no-kernel-pre-execution-blocking",
                "no-watch-paths-requested",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn watch_plan_rejects_linked_directories_without_following() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("linked");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let state = WatcherState::from_requested_paths(vec![target.clone(), link.clone()]);

        assert!(state.active);
        assert_eq!(state.watched_paths, vec![target.display().to_string()]);
        assert!(state
            .limitations
            .contains(&"unsafe-or-uninspectable-paths-ignored"));
    }

    #[test]
    fn watch_plan_uses_non_following_path_checks() {
        let source = include_str!("mod.rs");

        assert!(source.contains("std::fs::symlink_metadata(path)"));
        assert!(source.contains("watcher_metadata_is_windows_reparse_point"));
        assert!(source.contains("unsafe-or-uninspectable-paths-ignored"));
        assert!(source.contains("one-shot-watch-plan-only"));
        assert!(source.contains("no-persistent-service-monitor"));
        assert!(source.contains("no-kernel-pre-execution-blocking"));
        assert!(source.contains("no-accessible-watch-paths"));
        assert!(source.contains("no-watch-paths-requested"));
        let old_following_filter = [".filter(|path| path", ".is_dir())"].concat();
        assert!(!source.contains(&old_following_filter));
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
                reason: "timestamp-unavailable-rescan".into()
            }
        );
    }

    #[test]
    fn unavailable_timestamp_is_never_cached_as_unchanged() {
        let mut monitor = UserModeFileMonitor::new(Duration::from_millis(250), 2);
        let path = PathBuf::from("C:/Users/Brent/Downloads/tool.exe");

        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 42, 1_000)),
            WatchEvaluation::WaitForDebounce
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 42, 1_300)),
            WatchEvaluation::ScanRequired {
                reason: "timestamp-unavailable-rescan".into()
            }
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 42, 1_700)),
            WatchEvaluation::ScanRequired {
                reason: "timestamp-unavailable-rescan".into()
            }
        );
        assert_eq!(
            monitor.evaluate_event(WatchEvent::modified(path.clone(), 99, 2_100)),
            WatchEvaluation::WaitForStableFile
        );
    }

    #[test]
    fn system_time_before_epoch_is_rejected_instead_of_cached_as_zero() {
        let error = system_time_to_unix_ms(UNIX_EPOCH - Duration::from_secs(1)).unwrap_err();

        assert!(error.contains("predates Unix epoch"));
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

    #[test]
    fn watch_candidate_collection_is_bounded_and_non_following() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.bin"), b"a").unwrap();
        std::fs::write(dir.path().join("b.bin"), b"b").unwrap();

        let snapshot = collect_watch_candidates(&[dir.path().to_path_buf()], 1, 4);

        assert_eq!(snapshot.candidates.len(), 1);
        assert!(snapshot.limit_reached);
        assert!(snapshot.scan_errors.is_empty());
        assert_eq!(snapshot.candidates[0].size_bytes, 1);
    }
}
