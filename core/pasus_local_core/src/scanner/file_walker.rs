use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct FileWalk {
    pub files: Vec<PathBuf>,
    pub folders_scanned: u64,
    pub bytes_estimated: u64,
    pub skipped_files: u64,
    pub permission_denied_count: u64,
}

#[derive(Debug, Clone)]
pub struct WalkOptions {
    pub max_depth: Option<usize>,
    pub max_files: Option<usize>,
    pub risky_files_only: bool,
}

impl WalkOptions {
    pub fn quick() -> Self {
        Self {
            max_depth: Some(4),
            max_files: Some(5_000),
            risky_files_only: true,
        }
    }

    pub fn full() -> Self {
        Self {
            max_depth: None,
            max_files: None,
            risky_files_only: false,
        }
    }
}

pub fn collect_accessible_files(roots: &[PathBuf]) -> FileWalk {
    collect_accessible_files_with_options(roots, &WalkOptions::full())
}

pub fn collect_accessible_files_with_options(roots: &[PathBuf], options: &WalkOptions) -> FileWalk {
    let mut walk = FileWalk::default();
    for root in roots {
        collect_one(root, &mut walk, options);
        if options
            .max_files
            .is_some_and(|limit| walk.files.len() >= limit)
        {
            break;
        }
    }
    walk.files.sort_by_key(|path| priority(path));
    if let Some(limit) = options.max_files {
        if walk.files.len() > limit {
            let extra = walk.files.len() - limit;
            walk.files.truncate(limit);
            walk.skipped_files = walk.skipped_files.saturating_add(extra as u64);
        }
    }
    walk
}

fn collect_one(root: &Path, walk: &mut FileWalk, options: &WalkOptions) {
    if root.is_file() {
        add_file(root, walk, options);
        return;
    }
    if !root.exists() {
        walk.skipped_files += 1;
        return;
    }
    let mut walker = walkdir::WalkDir::new(root).follow_links(false);
    if let Some(max_depth) = options.max_depth {
        walker = walker.max_depth(max_depth);
    }
    for entry in walker
        .into_iter()
        .filter_entry(|entry| should_descend(entry.path()))
    {
        if options
            .max_files
            .is_some_and(|limit| walk.files.len() >= limit)
        {
            walk.skipped_files = walk.skipped_files.saturating_add(1);
            break;
        }
        match entry {
            Ok(entry) if entry.file_type().is_dir() => walk.folders_scanned += 1,
            Ok(entry) if entry.file_type().is_file() => add_file(entry.path(), walk, options),
            Ok(_) => {}
            Err(error) => {
                walk.skipped_files += 1;
                if error
                    .io_error()
                    .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::PermissionDenied)
                {
                    walk.permission_denied_count += 1;
                }
            }
        }
    }
}

fn should_descend(path: &Path) -> bool {
    let Some(name) = path
        .file_name()
        .map(|value| value.to_string_lossy().to_lowercase())
    else {
        return true;
    };
    !matches!(
        name.as_str(),
        ".git"
            | ".svn"
            | ".hg"
            | "node_modules"
            | "target"
            | "build"
            | ".gradle"
            | ".dart_tool"
            | ".pub-cache"
            | "__pycache__"
            | "windowsapps"
            | "winsxs"
            | "$recycle.bin"
            | "system volume information"
    )
}

fn priority(path: &Path) -> u8 {
    let lower = path.display().to_string().to_lowercase();
    if lower.contains("download")
        || lower.contains("desktop")
        || lower.contains("temp")
        || lower.contains("startup")
        || lower.contains("autostart")
    {
        return 0;
    }
    let ext = path
        .extension()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "scr"
            | "bat"
            | "cmd"
            | "ps1"
            | "vbs"
            | "js"
            | "jar"
            | "msi"
            | "zip"
            | "rar"
            | "7z"
            | "docm"
            | "xlsm"
    ) {
        return 1;
    }
    2
}

fn add_file(path: &Path, walk: &mut FileWalk, options: &WalkOptions) {
    if options.risky_files_only && !is_quick_scan_candidate(path) {
        walk.skipped_files = walk.skipped_files.saturating_add(1);
        return;
    }
    match std::fs::metadata(path) {
        Ok(metadata) => {
            if options.risky_files_only && metadata.len() > 512 * 1024 * 1024 {
                walk.skipped_files = walk.skipped_files.saturating_add(1);
                return;
            }
            walk.bytes_estimated = walk.bytes_estimated.saturating_add(metadata.len());
            walk.files.push(path.to_path_buf());
        }
        Err(error) => {
            walk.skipped_files += 1;
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                walk.permission_denied_count += 1;
            }
        }
    }
}

fn is_quick_scan_candidate(path: &Path) -> bool {
    let lower = path.display().to_string().to_lowercase();
    if lower.contains("startup") || lower.contains("autostart") || lower.contains("launchagents") {
        return true;
    }
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if file_name.contains("eicar") || lower.contains("pasus-safe-eicar") {
        return true;
    }
    let ext = path
        .extension()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "scr"
            | "com"
            | "pif"
            | "msi"
            | "bat"
            | "cmd"
            | "ps1"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "hta"
            | "jar"
            | "lnk"
            | "iso"
            | "img"
            | "zip"
            | "rar"
            | "7z"
            | "docm"
            | "xlsm"
            | "pptm"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn quick_walk_keeps_risky_files_and_skips_plain_documents() {
        let dir = tempdir().unwrap();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        fs::write(downloads.join("installer.exe"), "safe fixture").unwrap();
        fs::write(downloads.join("notes.txt"), "plain text").unwrap();

        let walk =
            collect_accessible_files_with_options(&[downloads.clone()], &WalkOptions::quick());

        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("installer.exe")));
        assert!(!walk.files.iter().any(|path| path.ends_with("notes.txt")));
        assert!(walk.skipped_files >= 1);
    }

    #[test]
    fn quick_walk_respects_max_depth() {
        let dir = tempdir().unwrap();
        let deep = dir.path().join("a").join("b").join("c").join("d").join("e");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("deep.exe"), "safe fixture").unwrap();

        let walk = collect_accessible_files_with_options(
            &[dir.path().to_path_buf()],
            &WalkOptions::quick(),
        );

        assert!(!walk.files.iter().any(|path| path.ends_with("deep.exe")));
    }

    #[test]
    fn full_walk_keeps_plain_documents() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("notes.txt");
        fs::write(&file, "plain text").unwrap();

        let walk = collect_accessible_files(&[dir.path().to_path_buf()]);

        assert!(walk.files.iter().any(|path| path.ends_with("notes.txt")));
    }
}
