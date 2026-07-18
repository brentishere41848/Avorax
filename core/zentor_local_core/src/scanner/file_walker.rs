use std::path::{Path, PathBuf};

const MAX_WALK_ERROR_DETAILS: usize = 20;
const MAX_WALK_ERROR_DETAIL_CHARS: usize = 4096;
const WALK_ERROR_TRUNCATION_SUFFIX: &str = "...[truncated]";

#[derive(Debug, Clone, Default)]
pub struct FileWalk {
    pub files: Vec<PathBuf>,
    pub folders_scanned: u64,
    pub bytes_estimated: u64,
    pub skipped_files: u64,
    pub permission_denied_count: u64,
    pub scan_errors: Vec<String>,
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
    let root_metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            walk.skipped_files += 1;
            push_walk_error(walk, format!("scan root missing: {}", root.display()));
            return;
        }
        Err(error) => {
            walk.skipped_files += 1;
            push_walk_error(
                walk,
                format!("{}: scan root metadata failed: {error}", root.display()),
            );
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                walk.permission_denied_count += 1;
            }
            return;
        }
    };
    if let Err(error) = ensure_walk_metadata_safe(root, "scan root", &root_metadata) {
        walk.skipped_files += 1;
        push_walk_error(walk, error.to_string());
        return;
    }
    if root_metadata.is_file() {
        add_file(root, walk, options);
        return;
    }
    if !root_metadata.is_dir() {
        walk.skipped_files += 1;
        push_walk_error(
            walk,
            format!("scan root is not a file or directory: {}", root.display()),
        );
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
            Ok(entry) => {
                walk.skipped_files = walk.skipped_files.saturating_add(1);
                push_walk_error(
                    walk,
                    format!(
                        "skipping non-regular walk entry: {}",
                        entry.path().display()
                    ),
                );
            }
            Err(error) => {
                walk.skipped_files += 1;
                push_walk_error(walk, format!("walk error: {error}"));
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
    let Some(ext) = lowercase_extension(path) else {
        return 2;
    };
    if matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "bin"
            | "scr"
            | "com"
            | "pif"
            | "cpl"
            | "bat"
            | "cmd"
            | "ps1"
            | "psm1"
            | "psd1"
            | "ps1xml"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "mjs"
            | "cjs"
            | "wsf"
            | "hta"
            | "jar"
            | "apk"
            | "xpi"
            | "vsix"
            | "nupkg"
            | "appx"
            | "msix"
            | "appxbundle"
            | "msixbundle"
            | "msi"
            | "msp"
            | "msu"
            | "inf"
            | "eml"
            | "reg"
            | "application"
            | "appref-ms"
            | "appinstaller"
            | "jnlp"
            | "sct"
            | "wsc"
            | "lnk"
            | "url"
            | "scf"
            | "chm"
            | "rtf"
            | "pdf"
            | "html"
            | "htm"
            | "svg"
            | "iso"
            | "img"
            | "zip"
            | "rar"
            | "7z"
            | "doc"
            | "xls"
            | "ppt"
            | "docm"
            | "xlsm"
            | "pptm"
            | "xlam"
            | "xll"
            | "iqy"
            | "slk"
            | "one"
            | "onepkg"
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
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if let Err(error) = ensure_walk_file_metadata(path, &metadata) {
                walk.skipped_files = walk.skipped_files.saturating_add(1);
                push_walk_error(walk, error.to_string());
                return;
            }
            if options.risky_files_only && metadata.len() > 512 * 1024 * 1024 {
                walk.skipped_files = walk.skipped_files.saturating_add(1);
                return;
            }
            walk.bytes_estimated = walk.bytes_estimated.saturating_add(metadata.len());
            walk.files.push(path.to_path_buf());
        }
        Err(error) => {
            walk.skipped_files += 1;
            push_walk_error(
                walk,
                format!("{}: metadata failed: {error}", path.display()),
            );
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                walk.permission_denied_count += 1;
            }
        }
    }
}

fn ensure_walk_file_metadata(path: &Path, metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    ensure_walk_metadata_safe(path, "scan file", metadata)?;
    if !metadata.is_file() {
        anyhow::bail!("scan file is not a regular file: {}", path.display());
    }
    Ok(())
}

fn ensure_walk_metadata_safe(
    path: &Path,
    label: &str,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symbolic link {label}: {}", path.display());
    }
    if walk_metadata_is_windows_reparse_point(metadata) {
        anyhow::bail!("refusing to use reparse point {label}: {}", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn walk_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn walk_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn push_walk_error(walk: &mut FileWalk, detail: String) {
    if walk.scan_errors.len() < MAX_WALK_ERROR_DETAILS {
        walk.scan_errors.push(bounded_walk_error_detail(&detail));
    } else if let Some(last) = walk.scan_errors.last_mut() {
        let notice = walk_error_omission_notice();
        if last != &notice {
            *last = notice;
        }
    }
}

fn walk_error_omission_notice() -> String {
    format!("additional file-walk errors omitted after {MAX_WALK_ERROR_DETAILS} details")
}

fn bounded_walk_error_detail(detail: &str) -> String {
    let normalized = detail.replace('\0', "\\0");
    if normalized.chars().count() <= MAX_WALK_ERROR_DETAIL_CHARS {
        return normalized;
    }
    let prefix_len = MAX_WALK_ERROR_DETAIL_CHARS.saturating_sub(WALK_ERROR_TRUNCATION_SUFFIX.len());
    let mut bounded: String = normalized.chars().take(prefix_len).collect();
    bounded.push_str(WALK_ERROR_TRUNCATION_SUFFIX);
    bounded
}

fn is_quick_scan_candidate(path: &Path) -> bool {
    let lower = path.display().to_string().to_lowercase();
    if lower.contains("startup") || lower.contains("autostart") || lower.contains("launchagents") {
        return true;
    }
    if lowercase_file_name(path)
        .as_deref()
        .is_some_and(|file_name| file_name.contains("eicar"))
        || lower.contains("zentor-safe-eicar")
    {
        return true;
    }
    let Some(ext) = lowercase_extension(path) else {
        return false;
    };
    matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "bin"
            | "scr"
            | "com"
            | "pif"
            | "cpl"
            | "msi"
            | "msp"
            | "msu"
            | "bat"
            | "cmd"
            | "ps1"
            | "psm1"
            | "psd1"
            | "ps1xml"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "mjs"
            | "cjs"
            | "wsf"
            | "hta"
            | "sct"
            | "wsc"
            | "jar"
            | "apk"
            | "xpi"
            | "vsix"
            | "nupkg"
            | "appx"
            | "msix"
            | "appxbundle"
            | "msixbundle"
            | "lnk"
            | "url"
            | "scf"
            | "inf"
            | "eml"
            | "reg"
            | "application"
            | "appref-ms"
            | "appinstaller"
            | "jnlp"
            | "chm"
            | "rtf"
            | "pdf"
            | "html"
            | "htm"
            | "svg"
            | "iso"
            | "img"
            | "zip"
            | "rar"
            | "7z"
            | "doc"
            | "xls"
            | "ppt"
            | "docm"
            | "xlsm"
            | "pptm"
            | "xlam"
            | "xll"
            | "iqy"
            | "slk"
            | "one"
            | "onepkg"
    )
}

fn lowercase_file_name(path: &Path) -> Option<String> {
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_lowercase())?;
    if file_name.is_empty() {
        return None;
    }
    Some(file_name)
}

fn lowercase_extension(path: &Path) -> Option<String> {
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_lowercase())?;
    if extension.is_empty() {
        return None;
    }
    Some(extension)
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
        fs::write(downloads.join("payload.bin"), "binary payload fixture").unwrap();
        fs::write(
            downloads.join("legacy-tool.com"),
            "legacy executable fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("legacy-link.pif"),
            "program information fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("settings-panel.cpl"),
            "control panel fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("offline-update.msu"),
            "windows update fixture",
        )
        .unwrap();
        fs::write(downloads.join("profile.psm1"), "PowerShell module fixture").unwrap();
        fs::write(
            downloads.join("autorun.reg"),
            "registry persistence fixture",
        )
        .unwrap();
        fs::write(downloads.join("autorun.inf"), "autorun carrier fixture").unwrap();
        fs::write(downloads.join("shortcut.url"), "internet shortcut fixture").unwrap();
        fs::write(downloads.join("support.application"), "clickonce fixture").unwrap();
        fs::write(downloads.join("support.appref-ms"), "clickonce ref fixture").unwrap();
        fs::write(
            downloads.join("support.appinstaller"),
            "windows app installer fixture",
        )
        .unwrap();
        fs::write(downloads.join("support.jnlp"), "java web start fixture").unwrap();
        fs::write(downloads.join("loader.sct"), "windows scriptlet fixture").unwrap();
        fs::write(
            downloads.join("component.wsc"),
            "windows script component fixture",
        )
        .unwrap();
        fs::write(downloads.join("addin.xll"), "office add-in fixture").unwrap();
        fs::write(downloads.join("mobile-app.apk"), "android package fixture").unwrap();
        fs::write(
            downloads.join("browser-extension.xpi"),
            "browser extension package fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("editor-extension.vsix"),
            "editor extension package fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("library-package.nupkg"),
            "nuget package fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("store-package.appx"),
            "windows app package fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("desktop-package.msix"),
            "windows msix package fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("store-package.appxbundle"),
            "windows app bundle fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("desktop-package.msixbundle"),
            "windows msix bundle fixture",
        )
        .unwrap();
        fs::write(
            downloads.join("support-patch.msp"),
            "installer patch fixture",
        )
        .unwrap();
        fs::write(downloads.join("notes.txt"), "plain text").unwrap();

        let walk = collect_accessible_files_with_options(
            std::slice::from_ref(&downloads),
            &WalkOptions::quick(),
        );

        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("installer.exe")));
        assert!(walk.files.iter().any(|path| path.ends_with("payload.bin")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("legacy-tool.com")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("legacy-link.pif")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("settings-panel.cpl")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("offline-update.msu")));
        assert!(walk.files.iter().any(|path| path.ends_with("profile.psm1")));
        assert!(walk.files.iter().any(|path| path.ends_with("autorun.reg")));
        assert!(walk.files.iter().any(|path| path.ends_with("autorun.inf")));
        assert!(walk.files.iter().any(|path| path.ends_with("shortcut.url")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("support.application")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("support.appref-ms")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("support.appinstaller")));
        assert!(walk.files.iter().any(|path| path.ends_with("support.jnlp")));
        assert!(walk.files.iter().any(|path| path.ends_with("loader.sct")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("component.wsc")));
        assert!(walk.files.iter().any(|path| path.ends_with("addin.xll")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("mobile-app.apk")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("browser-extension.xpi")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("editor-extension.vsix")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("library-package.nupkg")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("store-package.appx")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("desktop-package.msix")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("store-package.appxbundle")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("desktop-package.msixbundle")));
        assert!(walk
            .files
            .iter()
            .any(|path| path.ends_with("support-patch.msp")));
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

    #[test]
    fn quick_scan_priority_missing_names_and_extensions_use_explicit_branches() {
        assert_eq!(priority(Path::new("README")), 2);
        assert_eq!(priority(Path::new("driver.sys")), 1);
        assert_eq!(priority(Path::new("payload.bin")), 1);
        assert_eq!(priority(Path::new("support.vbe")), 1);
        assert_eq!(priority(Path::new("support-ticket.wsf")), 1);
        assert_eq!(priority(Path::new("support-ticket.hta")), 1);
        assert_eq!(priority(Path::new("support-link.lnk")), 1);
        assert!(!is_quick_scan_candidate(Path::new("README")));
        assert!(is_quick_scan_candidate(Path::new("EICAR")));
        assert!(!is_quick_scan_candidate(Path::new("/")));

        let source = include_str!("file_walker.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(production_source.contains("fn lowercase_file_name(path: &Path) -> Option<String>"));
        assert!(production_source.contains("fn lowercase_extension(path: &Path) -> Option<String>"));
        assert!(production_source.contains("let Some(ext) = lowercase_extension(path) else"));
        assert!(production_source.contains("return false;"));
        assert!(!production_source.contains(".unwrap_or_default()"));
    }

    #[cfg(unix)]
    #[test]
    fn walk_rejects_symbolic_link_scan_roots() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let link = dir.path().join("linked.exe");
        fs::write(&target, "safe fixture").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        let walk = collect_accessible_files(&[link]);

        assert!(walk.files.is_empty());
        assert_eq!(walk.skipped_files, 1);
        assert!(walk
            .scan_errors
            .iter()
            .any(|error| error.contains("symbolic link")));
    }

    #[cfg(unix)]
    #[test]
    fn walk_reports_symbolic_links_inside_roots_as_skipped() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let link = dir.path().join("linked.exe");
        fs::write(&target, "safe fixture").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        let walk = collect_accessible_files(&[dir.path().to_path_buf()]);

        assert!(walk.files.iter().any(|path| path.ends_with("target.exe")));
        assert!(walk.skipped_files >= 1);
        assert!(walk
            .scan_errors
            .iter()
            .any(|error| error.contains("skipping non-regular walk entry")));
    }

    #[test]
    fn walker_uses_non_following_metadata_probes() {
        let source = include_str!("file_walker.rs");
        let root_file_probe = ["root.", "is_file()"].concat();
        let root_exists_probe = ["root.", "exists()"].concat();
        let old_file_metadata_probe = ["std::fs::", "metadata(path)"].concat();
        let symlink_metadata_root = ["std::fs::", "symlink_metadata(root)"].concat();
        let symlink_metadata_file = ["std::fs::", "symlink_metadata(path)"].concat();
        let root_helper_pattern = ["ensure_walk_metadata_", "safe(root"].concat();
        let file_helper_pattern = ["ensure_walk_file_", "metadata(path"].concat();
        let symlink_error_pattern = ["refusing to use symbolic link ", "{label}"].concat();
        let reparse_error_pattern = ["refusing to use reparse point ", "{label}"].concat();

        assert!(source.contains(&symlink_metadata_root));
        assert!(source.contains(&symlink_metadata_file));
        assert!(source.contains(&root_helper_pattern));
        assert!(source.contains(&file_helper_pattern));
        assert!(source.contains(&symlink_error_pattern));
        assert!(source.contains(&reparse_error_pattern));
        assert!(!source.contains(&root_file_probe));
        assert!(!source.contains(&root_exists_probe));
        assert!(!source.contains(&old_file_metadata_probe));
    }

    #[test]
    fn walker_reports_non_regular_entries_instead_of_silently_ignoring_them() {
        let source = include_str!("file_walker.rs");
        let old_silent_non_regular_branch = ["Ok(_)", " => {}"].concat();
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(production_source.contains("skipping non-regular walk entry"));
        assert!(!production_source.contains(&old_silent_non_regular_branch));
    }

    #[test]
    fn walker_error_details_are_bounded_and_report_omissions() {
        let mut walk = FileWalk::default();
        push_walk_error(
            &mut walk,
            format!("{}\0tail", "A".repeat(MAX_WALK_ERROR_DETAIL_CHARS + 128)),
        );

        assert_eq!(walk.scan_errors.len(), 1);
        assert!(walk.scan_errors[0].ends_with(WALK_ERROR_TRUNCATION_SUFFIX));
        assert!(walk.scan_errors[0].len() <= MAX_WALK_ERROR_DETAIL_CHARS);
        assert!(!walk.scan_errors[0].contains('\0'));

        let mut capped = FileWalk::default();
        for index in 0..(MAX_WALK_ERROR_DETAILS + 2) {
            push_walk_error(&mut capped, format!("walk error {index}"));
        }
        assert_eq!(capped.scan_errors.len(), MAX_WALK_ERROR_DETAILS);
        assert_eq!(
            capped.scan_errors.last().unwrap(),
            &walk_error_omission_notice()
        );
        assert!(!capped
            .scan_errors
            .iter()
            .any(|error| error == "walk error 21"));
    }
}
