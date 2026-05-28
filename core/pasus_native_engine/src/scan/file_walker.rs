use std::path::{Path, PathBuf};

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
    };
    for entry in walker.into_iter() {
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
