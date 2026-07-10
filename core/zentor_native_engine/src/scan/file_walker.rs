use std::path::{Component, Path, PathBuf};

use walkdir::WalkDir;

const MAX_NATIVE_WALK_ERROR_DETAILS: usize = 20;
const MAX_NATIVE_WALK_ERROR_DETAIL_CHARS: usize = 4096;
const NATIVE_WALK_ERROR_TRUNCATION_SUFFIX: &str = "...[truncated]";

#[derive(Debug, Clone, Default)]
pub struct WalkResult {
    pub files: Vec<PathBuf>,
    pub skipped_files: u64,
    pub permission_denied_count: u64,
    pub folders_scanned: u64,
    pub bytes_estimated: u64,
    pub scan_errors: Vec<String>,
}

pub fn collect_files(root: &Path, max_depth: Option<usize>) -> WalkResult {
    let mut result = WalkResult::default();
    let root_metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            result.skipped_files = result.skipped_files.saturating_add(1);
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                result.permission_denied_count = result.permission_denied_count.saturating_add(1);
            }
            push_walk_error(
                &mut result,
                format!("{}: scan root metadata failed: {error}", root.display()),
            );
            return result;
        }
    };
    if let Err(error) = ensure_native_walk_metadata_safe(root, "scan root", &root_metadata) {
        result.skipped_files = result.skipped_files.saturating_add(1);
        push_walk_error(&mut result, error.to_string());
        return result;
    }
    if root_metadata.file_type().is_file() {
        add_native_walk_file(root, &mut result);
        return result;
    }
    if !root_metadata.file_type().is_dir() {
        result.skipped_files = result.skipped_files.saturating_add(1);
        push_walk_error(
            &mut result,
            format!("scan root is not a file or directory: {}", root.display()),
        );
        return result;
    }
    let walker = if let Some(depth) = max_depth {
        WalkDir::new(root).max_depth(depth)
    } else {
        WalkDir::new(root)
    }
    .follow_links(false)
    .into_iter()
    .filter_entry(|entry| !is_excluded_path(entry.path()));

    for entry in walker {
        match entry {
            Ok(entry) if entry.file_type().is_dir() => result.folders_scanned += 1,
            Ok(entry) if entry.file_type().is_file() => {
                add_native_walk_file(entry.path(), &mut result);
            }
            Ok(entry) => {
                result.skipped_files = result.skipped_files.saturating_add(1);
                push_walk_error(
                    &mut result,
                    format!(
                        "skipping non-regular walk entry: {}",
                        entry.path().display()
                    ),
                );
            }
            Err(error) => {
                result.skipped_files = result.skipped_files.saturating_add(1);
                if error
                    .io_error()
                    .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::PermissionDenied)
                {
                    result.permission_denied_count =
                        result.permission_denied_count.saturating_add(1);
                }
                push_walk_error(&mut result, format!("walk error: {error}"));
            }
        }
    }
    result
}

fn add_native_walk_file(path: &Path, result: &mut WalkResult) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if let Err(error) = ensure_native_walk_file_metadata(path, &metadata) {
                result.skipped_files = result.skipped_files.saturating_add(1);
                push_walk_error(result, error.to_string());
                return;
            }
            result.bytes_estimated = result.bytes_estimated.saturating_add(metadata.len());
            result.files.push(path.to_path_buf());
        }
        Err(error) => {
            result.skipped_files = result.skipped_files.saturating_add(1);
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                result.permission_denied_count = result.permission_denied_count.saturating_add(1);
            }
            push_walk_error(
                result,
                format!("{}: metadata failed: {error}", path.display()),
            );
        }
    }
}

fn ensure_native_walk_file_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    ensure_native_walk_metadata_safe(path, "scan file", metadata)?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("scan file is not a regular file: {}", path.display());
    }
    Ok(())
}

fn ensure_native_walk_metadata_safe(
    path: &Path,
    label: &str,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label}: {}", path.display());
    }
    if native_walk_metadata_is_windows_reparse_point(metadata) {
        anyhow::bail!("refusing to use reparse point {label}: {}", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn native_walk_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn native_walk_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn push_walk_error(result: &mut WalkResult, detail: String) {
    if result.scan_errors.len() < MAX_NATIVE_WALK_ERROR_DETAILS {
        result
            .scan_errors
            .push(bounded_native_walk_error_detail(&detail));
    } else if let Some(last) = result.scan_errors.last_mut() {
        let notice = native_walk_error_omission_notice();
        if last != &notice {
            *last = notice;
        }
    }
}

fn native_walk_error_omission_notice() -> String {
    format!(
        "additional native file-walk errors omitted after {MAX_NATIVE_WALK_ERROR_DETAILS} details"
    )
}

fn bounded_native_walk_error_detail(detail: &str) -> String {
    let normalized = detail.replace('\0', "\\0");
    if normalized.chars().count() <= MAX_NATIVE_WALK_ERROR_DETAIL_CHARS {
        return normalized;
    }
    let prefix_len = MAX_NATIVE_WALK_ERROR_DETAIL_CHARS
        .saturating_sub(NATIVE_WALK_ERROR_TRUNCATION_SUFFIX.len());
    let mut bounded: String = normalized.chars().take(prefix_len).collect();
    bounded.push_str(NATIVE_WALK_ERROR_TRUNCATION_SUFFIX);
    bounded
}

fn is_excluded_path(path: &Path) -> bool {
    let components: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    components.iter().any(|component| {
        matches!(
            component.as_str(),
            ".avorax"
                | ".git"
                | "node_modules"
                | "target"
                | "build"
                | ".dart_tool"
                | "quarantine"
                | "avorax-quarantine"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_file_walker_does_not_default_metadata_errors_to_zero_bytes() {
        let source = include_str!("file_walker.rs");
        let ignored_metadata_pattern = [
            "entry.",
            "metadata().map(|m| m.len())",
            ".unwrap_or_default()",
        ]
        .concat();
        assert!(source.contains("metadata failed"));
        assert!(source.contains("walk error:"));
        assert!(!source.contains(&ignored_metadata_pattern));
    }

    #[cfg(unix)]
    #[test]
    fn native_file_walker_rejects_symbolic_link_scan_roots() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.exe");
        let link = temp.path().join("linked.exe");
        std::fs::write(&target, b"benign fixture").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let result = collect_files(&link, None);

        assert!(result.files.is_empty());
        assert_eq!(result.skipped_files, 1);
        assert!(result
            .scan_errors
            .iter()
            .any(|error| error.contains("symbolic link")));
    }

    #[test]
    fn native_file_walker_uses_non_following_metadata() {
        let source = include_str!("file_walker.rs");
        let root_metadata_pattern = ["std::fs::", "symlink_metadata(root)"].concat();
        let file_metadata_pattern = ["std::fs::", "symlink_metadata(path)"].concat();
        let add_file_pattern = ["fn add_native_walk_", "file"].concat();
        let safe_helper_pattern = ["fn ensure_native_walk_metadata_", "safe"].concat();
        let symlink_error_pattern = ["refusing to use symbolic link ", "{label}"].concat();
        let reparse_error_pattern = ["refusing to use reparse point ", "{label}"].concat();
        let old_entry_metadata_pattern = ["entry.", "metadata()"].concat();
        let old_silent_non_regular_branch = ["Ok(_)", " => {}"].concat();

        assert!(source.contains(&root_metadata_pattern));
        assert!(source.contains(&file_metadata_pattern));
        assert!(source.contains(&add_file_pattern));
        assert!(source.contains(&safe_helper_pattern));
        assert!(source.contains(&symlink_error_pattern));
        assert!(source.contains(&reparse_error_pattern));
        assert!(!source.contains(&old_entry_metadata_pattern));
        assert!(source.contains("skipping non-regular walk entry"));
        assert!(!source.contains(&old_silent_non_regular_branch));
    }

    #[cfg(unix)]
    #[test]
    fn native_file_walker_reports_symbolic_links_inside_roots() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.exe");
        let link = temp.path().join("linked.exe");
        std::fs::write(&target, b"benign fixture").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let result = collect_files(temp.path(), None);

        assert!(result.files.iter().any(|path| path == &target));
        assert!(!result.files.iter().any(|path| path == &link));
        assert!(result.skipped_files >= 1);
        assert!(result
            .scan_errors
            .iter()
            .any(|error| error.contains("skipping non-regular walk entry")));
    }

    #[test]
    fn native_file_walker_error_details_are_bounded_and_report_omissions() {
        let mut result = WalkResult::default();
        push_walk_error(
            &mut result,
            format!(
                "{}\0tail",
                "A".repeat(MAX_NATIVE_WALK_ERROR_DETAIL_CHARS + 128)
            ),
        );

        assert_eq!(result.scan_errors.len(), 1);
        assert!(result.scan_errors[0].ends_with(NATIVE_WALK_ERROR_TRUNCATION_SUFFIX));
        assert!(result.scan_errors[0].len() <= MAX_NATIVE_WALK_ERROR_DETAIL_CHARS);
        assert!(!result.scan_errors[0].contains('\0'));

        let mut capped = WalkResult::default();
        for index in 0..(MAX_NATIVE_WALK_ERROR_DETAILS + 2) {
            push_walk_error(&mut capped, format!("native walk error {index}"));
        }
        assert_eq!(capped.scan_errors.len(), MAX_NATIVE_WALK_ERROR_DETAILS);
        assert_eq!(
            capped.scan_errors.last().unwrap(),
            &native_walk_error_omission_notice()
        );
        assert!(!capped
            .scan_errors
            .iter()
            .any(|error| error == "native walk error 21"));
    }
}
