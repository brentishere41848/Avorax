use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareSignal {
    pub process_id: u32,
    pub process_path: String,
    pub affected_paths: Vec<String>,
    pub files_modified_count: u32,
    pub files_renamed_count: u32,
    pub entropy_change_score: f32,
    pub ransom_note_score: f32,
    pub backup_tamper_score: f32,
    pub time_window_seconds: u32,
    pub severity: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RansomwareGuardConfig {
    pub protected_roots: Vec<PathBuf>,
    pub trusted_process_allowlist: Vec<PathBuf>,
}

pub struct RansomwareGuard;

impl RansomwareGuard {
    pub fn evaluate(
        process_id: u32,
        process_path: impl Into<String>,
        modified_paths: &[PathBuf],
        renamed_count: u32,
        entropy_change_score: f32,
        ransom_note_score: f32,
        backup_tamper_score: f32,
        time_window_seconds: u32,
    ) -> Option<RansomwareSignal> {
        Self::evaluate_with_config(
            process_id,
            process_path,
            modified_paths,
            renamed_count,
            entropy_change_score,
            ransom_note_score,
            backup_tamper_score,
            time_window_seconds,
            &RansomwareGuardConfig::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_with_config(
        process_id: u32,
        process_path: impl Into<String>,
        modified_paths: &[PathBuf],
        renamed_count: u32,
        entropy_change_score: f32,
        ransom_note_score: f32,
        backup_tamper_score: f32,
        time_window_seconds: u32,
        config: &RansomwareGuardConfig,
    ) -> Option<RansomwareSignal> {
        let process_path = process_path.into();
        let protected_paths = protected_modified_paths(modified_paths, &config.protected_roots);
        let modifications = protected_paths.len() as u32;
        let severe_file_activity =
            modifications >= 25 && time_window_seconds <= 120 && entropy_change_score >= 0.55;
        let ransom_note_activity = ransom_note_score >= 0.75 && modifications >= 10;
        let backup_tamper = backup_tamper_score >= 0.75 && modifications >= 1;
        let critical_override = ransom_note_activity || backup_tamper;
        if trusted_process(&process_path, &config.trusted_process_allowlist) && !critical_override {
            return None;
        }
        if !(severe_file_activity || ransom_note_activity || backup_tamper) {
            return None;
        }
        let confidence = if severe_file_activity && (ransom_note_activity || backup_tamper) {
            "high"
        } else {
            "medium"
        };
        Some(RansomwareSignal {
            process_id,
            process_path,
            affected_paths: protected_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            files_modified_count: modifications,
            files_renamed_count: renamed_count,
            entropy_change_score,
            ransom_note_score,
            backup_tamper_score,
            time_window_seconds,
            severity: "critical".to_string(),
            confidence: confidence.to_string(),
        })
    }
}

fn protected_modified_paths(
    modified_paths: &[PathBuf],
    protected_roots: &[PathBuf],
) -> Vec<PathBuf> {
    if protected_roots.is_empty() {
        return modified_paths.to_vec();
    }
    modified_paths
        .iter()
        .filter(|path| {
            protected_roots
                .iter()
                .any(|root| path_is_within(path, root))
        })
        .cloned()
        .collect()
}

fn trusted_process(process_path: &str, trusted_process_allowlist: &[PathBuf]) -> bool {
    trusted_process_allowlist
        .iter()
        .any(|trusted| paths_equal(Path::new(process_path), trusted))
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = normalize_path_text(path);
    let root = normalize_path_text(root);
    if root.is_empty() {
        return false;
    }
    if root == "/" {
        return path.starts_with('/');
    }
    path == root || path.starts_with(&format!("{root}/"))
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    normalize_path_text(left) == normalize_path_text(right)
}

fn normalize_path_text(path: &Path) -> String {
    let path_text = path
        .display()
        .to_string()
        .replace('\\', "/")
        .to_ascii_lowercase();
    collapse_path_segments(&path_text)
}

fn collapse_path_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }

    let (prefix, rest, absolute) = split_path_prefix(trimmed);
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if let Some(last) = segments.last() {
                    if *last != ".." {
                        segments.pop();
                        continue;
                    }
                }
                if !absolute {
                    segments.push(segment);
                }
            }
            _ => segments.push(segment),
        }
    }

    let body = segments.join("/");
    match (prefix, absolute, body.is_empty()) {
        (Some(prefix), _, true) => prefix.to_string(),
        (Some(prefix), _, false) => format!("{prefix}/{body}"),
        (None, true, true) => "/".to_string(),
        (None, true, false) => format!("/{body}"),
        (None, false, _) => body,
    }
}

fn split_path_prefix(path: &str) -> (Option<&str>, &str, bool) {
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'/' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with('/') {
        return (None, path.trim_start_matches('/'), true);
    }
    (None, path, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ransomware_mass_file_modification_triggers_guard() {
        let paths = (0..30)
            .map(|idx| PathBuf::from(format!("C:/Users/Test/Documents/file{idx}.docx")))
            .collect::<Vec<_>>();
        let signal = RansomwareGuard::evaluate(
            42,
            "C:/Users/Test/AppData/Temp/bad.exe",
            &paths,
            30,
            0.8,
            0.0,
            0.0,
            60,
        );
        assert!(signal.is_some());
    }

    #[test]
    fn ransomware_guard_ignores_activity_outside_protected_roots() {
        let protected =
            (0..30).map(|idx| PathBuf::from(format!("C:/Users/Test/Documents/file{idx}.docx")));
        let unprotected =
            (0..30).map(|idx| PathBuf::from(format!("C:/Users/Test/Downloads/file{idx}.tmp")));
        let paths = protected.chain(unprotected).collect::<Vec<_>>();
        let config = RansomwareGuardConfig {
            protected_roots: vec![PathBuf::from("C:/Users/Test/Pictures")],
            trusted_process_allowlist: vec![],
        };
        let signal = RansomwareGuard::evaluate_with_config(
            42,
            "C:/Users/Test/AppData/Temp/tool.exe",
            &paths,
            30,
            0.8,
            0.0,
            0.0,
            60,
            &config,
        );
        assert!(signal.is_none());
    }

    #[test]
    fn ransomware_guard_counts_only_protected_root_activity() {
        let protected =
            (0..25).map(|idx| PathBuf::from(format!("C:/Users/Test/Documents/file{idx}.docx")));
        let unprotected =
            (0..50).map(|idx| PathBuf::from(format!("C:/Users/Test/Downloads/file{idx}.tmp")));
        let paths = protected.chain(unprotected).collect::<Vec<_>>();
        let config = RansomwareGuardConfig {
            protected_roots: vec![PathBuf::from("C:/Users/Test/Documents")],
            trusted_process_allowlist: vec![],
        };
        let signal = RansomwareGuard::evaluate_with_config(
            42,
            "C:/Users/Test/AppData/Temp/tool.exe",
            &paths,
            75,
            0.8,
            0.0,
            0.0,
            60,
            &config,
        )
        .expect("protected document activity should trigger");
        assert_eq!(signal.files_modified_count, 25);
        assert_eq!(signal.affected_paths.len(), 25);
    }

    #[test]
    fn ransomware_guard_does_not_count_traversal_outside_protected_root() {
        let paths = (0..30)
            .map(|idx| {
                PathBuf::from(format!(
                    "C:/Users/Test/Documents/../Downloads/file{idx}.tmp"
                ))
            })
            .collect::<Vec<_>>();
        let config = RansomwareGuardConfig {
            protected_roots: vec![PathBuf::from("C:/Users/Test/Documents")],
            trusted_process_allowlist: vec![],
        };
        let signal = RansomwareGuard::evaluate_with_config(
            42,
            "C:/Users/Test/AppData/Temp/tool.exe",
            &paths,
            30,
            0.8,
            0.0,
            0.0,
            60,
            &config,
        );

        assert!(signal.is_none());
    }

    #[test]
    fn trusted_process_allowlist_uses_collapsed_path_equivalence() {
        let paths = (0..30)
            .map(|idx| PathBuf::from(format!("C:/Users/Test/Documents/file{idx}.docx")))
            .collect::<Vec<_>>();
        let config = RansomwareGuardConfig {
            protected_roots: vec![PathBuf::from("C:/Users/Test/Documents")],
            trusted_process_allowlist: vec![PathBuf::from("C:/Program Files/Backup/backup.exe")],
        };
        let signal = RansomwareGuard::evaluate_with_config(
            42,
            "C:/Program Files/Backup/Tools/../backup.exe",
            &paths,
            30,
            0.8,
            0.0,
            0.0,
            60,
            &config,
        );

        assert!(signal.is_none());
    }

    #[test]
    fn ransomware_guard_suppresses_trusted_process() {
        let paths = (0..30)
            .map(|idx| PathBuf::from(format!("C:/Users/Test/Documents/file{idx}.docx")))
            .collect::<Vec<_>>();
        let config = RansomwareGuardConfig {
            protected_roots: vec![PathBuf::from("C:/Users/Test/Documents")],
            trusted_process_allowlist: vec![PathBuf::from("C:/Program Files/Backup/backup.exe")],
        };
        let signal = RansomwareGuard::evaluate_with_config(
            42,
            "C:/Program Files/Backup/backup.exe",
            &paths,
            30,
            0.8,
            0.0,
            0.0,
            60,
            &config,
        );
        assert!(signal.is_none());
    }

    #[test]
    fn trusted_process_does_not_suppress_ransom_note_or_backup_tamper() {
        let paths = (0..30)
            .map(|idx| PathBuf::from(format!("C:/Users/Test/Documents/file{idx}.docx")))
            .collect::<Vec<_>>();
        let config = RansomwareGuardConfig {
            protected_roots: vec![PathBuf::from("C:/Users/Test/Documents")],
            trusted_process_allowlist: vec![PathBuf::from("C:/Program Files/Backup/backup.exe")],
        };

        let signal = RansomwareGuard::evaluate_with_config(
            42,
            "C:/Program Files/Backup/backup.exe",
            &paths,
            30,
            0.8,
            0.9,
            0.95,
            60,
            &config,
        )
        .expect("critical ransom-note/backup-tamper activity should not be suppressed");

        assert_eq!(signal.confidence, "high");
        assert_eq!(signal.files_modified_count, 30);
    }
}
