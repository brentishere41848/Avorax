use std::path::{Component, Path, PathBuf};

use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
pub struct WalkResult {
    pub files: Vec<PathBuf>,
    pub skipped_files: u64,
    pub folders_scanned: u64,
    pub bytes_estimated: u64,
}

pub fn collect_files(root: &Path, max_depth: Option<usize>) -> WalkResult {
    let mut result = WalkResult::default();
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
                result.bytes_estimated = result
                    .bytes_estimated
                    .saturating_add(entry.metadata().map(|m| m.len()).unwrap_or_default());
                result.files.push(entry.into_path());
            }
            Ok(_) => {}
            Err(_) => result.skipped_files += 1,
        }
    }
    result
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
