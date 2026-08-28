use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_WALK_ERROR_DETAILS: usize = 20;
const MAX_WALK_ERROR_DETAIL_CHARS: usize = 4096;
const WALK_ERROR_TRUNCATION_SUFFIX: &str = "...[truncated]";
const WALK_CANCELLATION_CHUNK_ENTRIES: usize = 128;
const MAX_FULL_SCAN_DISCOVERED_FILES: usize = 250_000;
const MAX_QUICK_SCAN_DISCOVERED_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_FULL_SCAN_DISCOVERED_PATH_BYTES: usize = 128 * 1024 * 1024;
const MAX_QUICK_SCAN_DISCOVERY_WORK_ITEMS: usize = 100_000;
const MAX_FULL_SCAN_DISCOVERY_WORK_ITEMS: usize = 1_000_000;
const MAX_QUICK_SCAN_DISCOVERY_SECONDS: u64 = 10 * 60;
const MAX_FULL_SCAN_DISCOVERY_SECONDS: u64 = 60 * 60;

#[derive(Debug, Clone, Default)]
pub struct FileWalk {
    pub files: Vec<PathBuf>,
    pub folders_scanned: u64,
    pub bytes_estimated: u64,
    pub skipped_files: u64,
    pub permission_denied_count: u64,
    pub scan_errors: Vec<String>,
    pub discovery_cancelled: bool,
    pub file_limit_reached: bool,
    pub path_bytes_collected: usize,
    pub path_byte_limit_reached: bool,
    pub work_items_consumed: usize,
    pub work_item_limit_reached: bool,
    pub time_limit_reached: bool,
}

#[derive(Debug, Clone)]
pub struct WalkOptions {
    pub max_depth: Option<usize>,
    pub max_files: Option<usize>,
    pub max_path_bytes: Option<usize>,
    pub max_work_items: Option<usize>,
    pub max_duration: Option<Duration>,
    pub risky_files_only: bool,
}

impl WalkOptions {
    pub fn quick() -> Self {
        Self {
            max_depth: Some(4),
            max_files: Some(5_000),
            max_path_bytes: Some(MAX_QUICK_SCAN_DISCOVERED_PATH_BYTES),
            max_work_items: Some(MAX_QUICK_SCAN_DISCOVERY_WORK_ITEMS),
            max_duration: Some(Duration::from_secs(MAX_QUICK_SCAN_DISCOVERY_SECONDS)),
            risky_files_only: true,
        }
    }

    pub fn full() -> Self {
        Self {
            max_depth: None,
            max_files: Some(MAX_FULL_SCAN_DISCOVERED_FILES),
            max_path_bytes: Some(MAX_FULL_SCAN_DISCOVERED_PATH_BYTES),
            max_work_items: Some(MAX_FULL_SCAN_DISCOVERY_WORK_ITEMS),
            max_duration: Some(Duration::from_secs(MAX_FULL_SCAN_DISCOVERY_SECONDS)),
            risky_files_only: false,
        }
    }
}

pub fn collect_accessible_files(roots: &[PathBuf]) -> FileWalk {
    collect_accessible_files_with_options(roots, &WalkOptions::full())
}

pub fn collect_accessible_files_with_options(roots: &[PathBuf], options: &WalkOptions) -> FileWalk {
    let mut never_cancel = || Ok(false);
    collect_accessible_files_with_options_and_cancellation(roots, options, &mut never_cancel)
        .expect("the non-cancelling file-discovery callback cannot fail")
}

pub fn collect_accessible_files_with_options_and_cancellation(
    roots: &[PathBuf],
    options: &WalkOptions,
    should_cancel: &mut dyn FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<FileWalk> {
    let mut walk = FileWalk::default();
    let discovery_started = Instant::now();
    for root in roots {
        if apply_discovery_checkpoint(&mut walk, options, discovery_started, should_cancel)? {
            break;
        }
        if let Some(limit) = options.max_files {
            if walk.files.len() >= limit {
                mark_file_limit_reached(&mut walk, limit);
                break;
            }
        }
        if let Some(limit) = options.max_path_bytes {
            if walk.path_bytes_collected >= limit {
                mark_path_byte_limit_reached(&mut walk, limit);
                break;
            }
        }
        if !consume_discovery_work_item(&mut walk, options) {
            break;
        }
        collect_one_with_cancellation(root, &mut walk, options, discovery_started, should_cancel)?;
        if walk.discovery_cancelled
            || walk.file_limit_reached
            || walk.path_byte_limit_reached
            || walk.work_item_limit_reached
            || walk.time_limit_reached
        {
            break;
        }
        if apply_discovery_checkpoint(&mut walk, options, discovery_started, should_cancel)? {
            break;
        }
    }
    if !walk.discovery_cancelled
        && !walk.file_limit_reached
        && !walk.path_byte_limit_reached
        && !walk.work_item_limit_reached
        && !walk.time_limit_reached
        && !apply_discovery_checkpoint(&mut walk, options, discovery_started, should_cancel)?
    {
        let stop_reason = prioritize_files_with_limits(
            &mut walk.files,
            options,
            discovery_started,
            should_cancel,
        )?;
        apply_discovery_stop_reason(&mut walk, options, stop_reason);
    }
    Ok(walk)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryStopReason {
    Continue,
    Cancelled,
    TimeLimitReached,
}

fn discovery_checkpoint(
    options: &WalkOptions,
    discovery_started: Instant,
    should_cancel: &mut dyn FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<DiscoveryStopReason> {
    if should_cancel()? {
        return Ok(DiscoveryStopReason::Cancelled);
    }
    if options
        .max_duration
        .is_some_and(|limit| discovery_started.elapsed() >= limit)
    {
        return Ok(DiscoveryStopReason::TimeLimitReached);
    }
    Ok(DiscoveryStopReason::Continue)
}

fn apply_discovery_checkpoint(
    walk: &mut FileWalk,
    options: &WalkOptions,
    discovery_started: Instant,
    should_cancel: &mut dyn FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let reason = discovery_checkpoint(options, discovery_started, should_cancel)?;
    Ok(apply_discovery_stop_reason(walk, options, reason))
}

fn apply_discovery_stop_reason(
    walk: &mut FileWalk,
    options: &WalkOptions,
    reason: DiscoveryStopReason,
) -> bool {
    match reason {
        DiscoveryStopReason::Continue => false,
        DiscoveryStopReason::Cancelled => {
            walk.discovery_cancelled = true;
            true
        }
        DiscoveryStopReason::TimeLimitReached => {
            mark_time_limit_reached(walk, options.max_duration.unwrap_or(Duration::from_secs(0)));
            true
        }
    }
}

fn consume_discovery_work_item(walk: &mut FileWalk, options: &WalkOptions) -> bool {
    if walk.work_item_limit_reached {
        return false;
    }
    if let Some(limit) = options.max_work_items {
        if walk.work_items_consumed >= limit {
            mark_work_item_limit_reached(walk, limit);
            return false;
        }
    }
    let Some(next) = walk.work_items_consumed.checked_add(1) else {
        mark_work_item_limit_reached(walk, options.max_work_items.unwrap_or(usize::MAX));
        return false;
    };
    walk.work_items_consumed = next;
    true
}

fn collect_one_with_cancellation(
    root: &Path,
    walk: &mut FileWalk,
    options: &WalkOptions,
    discovery_started: Instant,
    should_cancel: &mut dyn FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    if apply_discovery_checkpoint(walk, options, discovery_started, should_cancel)? {
        return Ok(());
    }
    let root_metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            walk.skipped_files += 1;
            push_walk_error(walk, format!("scan root missing: {}", root.display()));
            return Ok(());
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
            return Ok(());
        }
    };
    if let Err(error) = ensure_walk_metadata_safe(root, "scan root", &root_metadata) {
        walk.skipped_files += 1;
        push_walk_error(walk, error.to_string());
        return Ok(());
    }
    if root_metadata.is_file() {
        if let Some(limit) = options.max_files {
            if walk.files.len() >= limit {
                mark_file_limit_reached(walk, limit);
                return Ok(());
            }
        }
        if let Some(limit) = options.max_path_bytes {
            if walk.path_bytes_collected >= limit {
                mark_path_byte_limit_reached(walk, limit);
                return Ok(());
            }
        }
        add_file(root, walk, options);
        if !walk.path_byte_limit_reached {
            apply_discovery_checkpoint(walk, options, discovery_started, should_cancel)?;
        }
        return Ok(());
    }
    if !root_metadata.is_dir() {
        walk.skipped_files += 1;
        push_walk_error(
            walk,
            format!("scan root is not a file or directory: {}", root.display()),
        );
        return Ok(());
    }
    let mut walker = walkdir::WalkDir::new(root).follow_links(false);
    if let Some(max_depth) = options.max_depth {
        walker = walker.max_depth(max_depth);
    }
    let mut entries = walker
        .into_iter()
        .filter_entry(|entry| should_descend(entry.path()));
    let mut entries_since_checkpoint = 0usize;
    loop {
        if entries_since_checkpoint == 0
            && apply_discovery_checkpoint(walk, options, discovery_started, should_cancel)?
        {
            break;
        }
        if !consume_discovery_work_item(walk, options) {
            break;
        }
        let Some(entry) = entries.next() else {
            break;
        };
        if let Some(limit) = options.max_files {
            if walk.files.len() >= limit {
                mark_file_limit_reached(walk, limit);
                break;
            }
        }
        if let Some(limit) = options.max_path_bytes {
            if walk.path_bytes_collected >= limit {
                mark_path_byte_limit_reached(walk, limit);
                break;
            }
        }
        entries_since_checkpoint += 1;
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
        if walk.path_byte_limit_reached || walk.work_item_limit_reached {
            break;
        }
        if entries_since_checkpoint >= WALK_CANCELLATION_CHUNK_ENTRIES {
            entries_since_checkpoint = 0;
        }
    }
    if !walk.discovery_cancelled
        && !walk.file_limit_reached
        && !walk.path_byte_limit_reached
        && !walk.work_item_limit_reached
        && !walk.time_limit_reached
        && apply_discovery_checkpoint(walk, options, discovery_started, should_cancel)?
    {
        return Ok(());
    }
    Ok(())
}

fn mark_file_limit_reached(walk: &mut FileWalk, limit: usize) {
    if walk.file_limit_reached {
        return;
    }
    walk.file_limit_reached = true;
    walk.skipped_files = walk.skipped_files.saturating_add(1);
    push_walk_error(
        walk,
        format!(
            "file discovery limit of {limit} files reached; remaining entries were not enumerated or reported clean"
        ),
    );
}

fn mark_path_byte_limit_reached(walk: &mut FileWalk, limit: usize) {
    if walk.path_byte_limit_reached {
        return;
    }
    walk.path_byte_limit_reached = true;
    walk.skipped_files = walk.skipped_files.saturating_add(1);
    push_walk_error(
        walk,
        format!(
            "file discovery encoded path-byte limit of {limit} bytes reached; remaining entries were not enumerated or reported clean"
        ),
    );
}

fn mark_work_item_limit_reached(walk: &mut FileWalk, limit: usize) {
    if walk.work_item_limit_reached {
        return;
    }
    walk.work_item_limit_reached = true;
    walk.skipped_files = walk.skipped_files.saturating_add(1);
    push_walk_error(
        walk,
        format!(
            "file discovery work-item limit of {limit} root-inspection or directory-iterator attempts reached; remaining entries were not enumerated or reported clean"
        ),
    );
}

fn mark_time_limit_reached(walk: &mut FileWalk, limit: Duration) {
    if walk.time_limit_reached {
        return;
    }
    walk.time_limit_reached = true;
    walk.skipped_files = walk.skipped_files.saturating_add(1);
    push_walk_error(
        walk,
        format!(
            "file discovery monotonic time budget of {} seconds reached; remaining entries were not enumerated or reported clean",
            limit.as_secs()
        ),
    );
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

fn prioritize_files_with_cancellation(
    files: &mut Vec<PathBuf>,
    should_cancel: &mut dyn FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let source = std::mem::take(files);
    let mut remaining = source.into_iter();
    let mut immediate = Vec::new();
    let mut risky = Vec::new();
    let mut ordinary = Vec::new();

    while remaining.len() > 0 {
        if should_cancel()? {
            *files = assemble_priority_buckets(immediate, risky, ordinary, remaining);
            return Ok(true);
        }
        for path in remaining.by_ref().take(WALK_CANCELLATION_CHUNK_ENTRIES) {
            match priority(&path) {
                0 => immediate.push(path),
                1 => risky.push(path),
                _ => ordinary.push(path),
            }
        }
    }

    *files = assemble_priority_buckets(immediate, risky, ordinary, remaining);
    should_cancel()
}

fn prioritize_files_with_limits(
    files: &mut Vec<PathBuf>,
    options: &WalkOptions,
    discovery_started: Instant,
    should_cancel: &mut dyn FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<DiscoveryStopReason> {
    let mut stop_reason = DiscoveryStopReason::Continue;
    let mut should_stop = || {
        let reason = discovery_checkpoint(options, discovery_started, should_cancel)?;
        if reason == DiscoveryStopReason::Continue {
            Ok(false)
        } else {
            stop_reason = reason;
            Ok(true)
        }
    };
    let stopped = prioritize_files_with_cancellation(files, &mut should_stop)?;
    if stopped {
        Ok(stop_reason)
    } else {
        Ok(DiscoveryStopReason::Continue)
    }
}

fn assemble_priority_buckets(
    mut immediate: Vec<PathBuf>,
    mut risky: Vec<PathBuf>,
    mut ordinary: Vec<PathBuf>,
    remaining: std::vec::IntoIter<PathBuf>,
) -> Vec<PathBuf> {
    immediate.reserve(risky.len() + ordinary.len() + remaining.len());
    immediate.append(&mut risky);
    immediate.append(&mut ordinary);
    immediate.extend(remaining);
    immediate
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
            let path_bytes = path.as_os_str().as_encoded_bytes().len();
            let Some(next_path_bytes) = walk.path_bytes_collected.checked_add(path_bytes) else {
                mark_path_byte_limit_reached(walk, options.max_path_bytes.unwrap_or(usize::MAX));
                return;
            };
            if let Some(limit) = options.max_path_bytes {
                if next_path_bytes > limit {
                    mark_path_byte_limit_reached(walk, limit);
                    return;
                }
            }
            walk.path_bytes_collected = next_path_bytes;
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
    fn file_discovery_cancellation_stops_before_next_entry_chunk() {
        let dir = tempdir().unwrap();
        for index in 0..300 {
            fs::write(
                dir.path().join(format!("benign-discovery-{index}.txt")),
                b"ordinary benign discovery fixture",
            )
            .unwrap();
        }
        let mut checkpoints = 0usize;
        let mut should_cancel = || {
            checkpoints += 1;
            Ok(checkpoints >= 4)
        };

        let walk = collect_accessible_files_with_options_and_cancellation(
            &[dir.path().to_path_buf()],
            &WalkOptions::full(),
            &mut should_cancel,
        )
        .unwrap();

        assert!(walk.discovery_cancelled);
        assert!(!walk.file_limit_reached);
        assert!(walk.files.len() < 300);
        assert_eq!(checkpoints, 4);
    }

    #[test]
    fn file_discovery_cancellation_propagates_probe_error() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("benign.txt"), b"benign fixture").unwrap();
        let mut should_cancel = || anyhow::bail!("benign discovery probe failure");

        let error = collect_accessible_files_with_options_and_cancellation(
            &[dir.path().to_path_buf()],
            &WalkOptions::full(),
            &mut should_cancel,
        )
        .expect_err("discovery callback failure must propagate");

        assert!(error.to_string().contains("benign discovery probe failure"));
    }

    #[test]
    fn file_discovery_limit_is_bounded_and_fail_visible() {
        let dir = tempdir().unwrap();
        for index in 0..5 {
            fs::write(
                dir.path().join(format!("benign-limit-{index}.txt")),
                b"ordinary benign discovery fixture",
            )
            .unwrap();
        }
        let options = WalkOptions {
            max_depth: None,
            max_files: Some(3),
            max_path_bytes: Some(MAX_FULL_SCAN_DISCOVERED_PATH_BYTES),
            max_work_items: None,
            max_duration: None,
            risky_files_only: false,
        };
        let mut never_cancel = || Ok(false);

        let walk = collect_accessible_files_with_options_and_cancellation(
            &[dir.path().to_path_buf()],
            &options,
            &mut never_cancel,
        )
        .unwrap();

        assert_eq!(
            WalkOptions::full().max_files,
            Some(MAX_FULL_SCAN_DISCOVERED_FILES)
        );
        assert_eq!(walk.files.len(), 3);
        assert!(walk.file_limit_reached);
        assert!(!walk.discovery_cancelled);
        assert!(walk.skipped_files >= 1);
        assert!(walk.scan_errors.iter().any(|error| {
            error.contains("file discovery limit of 3 files reached")
                && error.contains("not enumerated or reported clean")
        }));
    }

    #[test]
    fn file_discovery_memory_path_byte_limit_is_fail_visible() {
        let dir = tempdir().unwrap();
        let first = dir.path().join("benign-memory-0.txt");
        for index in 0..3 {
            fs::write(
                dir.path().join(format!("benign-memory-{index}.txt")),
                b"ordinary benign path-memory fixture",
            )
            .unwrap();
        }
        let one_path_bytes = first.as_os_str().as_encoded_bytes().len();
        let options = WalkOptions {
            max_depth: None,
            max_files: Some(MAX_FULL_SCAN_DISCOVERED_FILES),
            max_path_bytes: Some(one_path_bytes),
            max_work_items: None,
            max_duration: None,
            risky_files_only: false,
        };
        let mut never_cancel = || Ok(false);

        let walk = collect_accessible_files_with_options_and_cancellation(
            &[dir.path().to_path_buf()],
            &options,
            &mut never_cancel,
        )
        .unwrap();

        assert_eq!(
            WalkOptions::quick().max_path_bytes,
            Some(MAX_QUICK_SCAN_DISCOVERED_PATH_BYTES)
        );
        assert_eq!(
            WalkOptions::full().max_path_bytes,
            Some(MAX_FULL_SCAN_DISCOVERED_PATH_BYTES)
        );
        assert_eq!(walk.files.len(), 1);
        assert_eq!(walk.path_bytes_collected, one_path_bytes);
        assert!(walk.path_byte_limit_reached);
        assert!(!walk.file_limit_reached);
        assert!(!walk.discovery_cancelled);
        assert!(walk.skipped_files >= 1);
        assert!(walk.scan_errors.iter().any(|error| {
            error.contains(&format!(
                "file discovery encoded path-byte limit of {one_path_bytes} bytes reached"
            )) && error.contains("not enumerated or reported clean")
        }));
    }

    #[test]
    fn file_discovery_memory_path_byte_overflow_is_fail_visible() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("benign-overflow.txt");
        fs::write(&file, b"ordinary benign path-overflow fixture").unwrap();
        let options = WalkOptions {
            max_depth: None,
            max_files: None,
            max_path_bytes: None,
            max_work_items: None,
            max_duration: None,
            risky_files_only: false,
        };
        let mut walk = FileWalk {
            path_bytes_collected: usize::MAX,
            ..FileWalk::default()
        };

        add_file(&file, &mut walk, &options);

        assert!(walk.files.is_empty());
        assert_eq!(walk.path_bytes_collected, usize::MAX);
        assert_eq!(walk.bytes_estimated, 0);
        assert!(walk.path_byte_limit_reached);
        assert_eq!(walk.skipped_files, 1);
        assert!(walk.scan_errors.iter().any(|error| {
            error.contains(&format!(
                "file discovery encoded path-byte limit of {} bytes reached",
                usize::MAX
            )) && error.contains("not enumerated or reported clean")
        }));
    }

    #[test]
    fn file_discovery_resource_budget_counts_non_candidate_work_and_fails_visible() {
        let dir = tempdir().unwrap();
        for index in 0..5 {
            fs::write(
                dir.path().join(format!("benign-work-{index}.txt")),
                b"ordinary non-candidate discovery fixture",
            )
            .unwrap();
        }
        let options = WalkOptions {
            max_depth: None,
            max_files: Some(5_000),
            max_path_bytes: Some(MAX_QUICK_SCAN_DISCOVERED_PATH_BYTES),
            max_work_items: Some(3),
            max_duration: None,
            risky_files_only: true,
        };
        let mut never_cancel = || Ok(false);

        let walk = collect_accessible_files_with_options_and_cancellation(
            &[dir.path().to_path_buf()],
            &options,
            &mut never_cancel,
        )
        .unwrap();

        assert_eq!(
            WalkOptions::quick().max_work_items,
            Some(MAX_QUICK_SCAN_DISCOVERY_WORK_ITEMS)
        );
        assert_eq!(
            WalkOptions::full().max_work_items,
            Some(MAX_FULL_SCAN_DISCOVERY_WORK_ITEMS)
        );
        assert_eq!(walk.work_items_consumed, 3);
        assert!(walk.files.is_empty());
        assert!(walk.work_item_limit_reached);
        assert!(!walk.time_limit_reached);
        assert!(!walk.discovery_cancelled);
        assert!(walk.skipped_files >= 1);
        assert!(walk.scan_errors.iter().any(|error| {
            error.contains("file discovery work-item limit of 3")
                && error.contains("root-inspection or directory-iterator attempts")
                && error.contains("not enumerated or reported clean")
        }));
    }

    #[test]
    fn file_discovery_resource_budget_work_counter_overflow_is_fail_visible() {
        let options = WalkOptions {
            max_depth: None,
            max_files: None,
            max_path_bytes: None,
            max_work_items: None,
            max_duration: None,
            risky_files_only: false,
        };
        let mut walk = FileWalk {
            work_items_consumed: usize::MAX,
            ..FileWalk::default()
        };

        assert!(!consume_discovery_work_item(&mut walk, &options));
        assert_eq!(walk.work_items_consumed, usize::MAX);
        assert!(walk.work_item_limit_reached);
        assert_eq!(walk.skipped_files, 1);
        assert!(walk.scan_errors.iter().any(|error| {
            error.contains(&format!("file discovery work-item limit of {}", usize::MAX))
                && error.contains("not enumerated or reported clean")
        }));
    }

    #[test]
    fn file_discovery_resource_budget_zero_deadline_stops_before_root_io() {
        let options = WalkOptions {
            max_depth: None,
            max_files: None,
            max_path_bytes: None,
            max_work_items: None,
            max_duration: Some(Duration::ZERO),
            risky_files_only: false,
        };
        let mut never_cancel = || Ok(false);

        let walk = collect_accessible_files_with_options_and_cancellation(
            &[PathBuf::from("missing-root-must-not-be-inspected")],
            &options,
            &mut never_cancel,
        )
        .unwrap();

        assert_eq!(
            WalkOptions::quick().max_duration,
            Some(Duration::from_secs(MAX_QUICK_SCAN_DISCOVERY_SECONDS))
        );
        assert_eq!(
            WalkOptions::full().max_duration,
            Some(Duration::from_secs(MAX_FULL_SCAN_DISCOVERY_SECONDS))
        );
        assert!(walk.files.is_empty());
        assert_eq!(walk.work_items_consumed, 0);
        assert!(walk.time_limit_reached);
        assert!(!walk.work_item_limit_reached);
        assert!(!walk.discovery_cancelled);
        assert_eq!(walk.skipped_files, 1);
        assert!(walk.scan_errors.iter().any(|error| {
            error.contains("file discovery monotonic time budget of 0 seconds reached")
                && error.contains("not enumerated or reported clean")
        }));
        assert!(!walk
            .scan_errors
            .iter()
            .any(|error| error.contains("scan root missing")));
    }

    #[test]
    fn file_discovery_resource_budget_cancellation_precedes_expired_deadline() {
        let options = WalkOptions {
            max_depth: None,
            max_files: None,
            max_path_bytes: None,
            max_work_items: None,
            max_duration: Some(Duration::ZERO),
            risky_files_only: false,
        };
        let mut should_cancel = || Ok(true);

        let walk = collect_accessible_files_with_options_and_cancellation(
            &[PathBuf::from("missing-root-must-not-be-inspected")],
            &options,
            &mut should_cancel,
        )
        .unwrap();

        assert!(walk.discovery_cancelled);
        assert!(!walk.time_limit_reached);
        assert!(!walk.work_item_limit_reached);
        assert_eq!(walk.work_items_consumed, 0);
        assert!(walk.scan_errors.is_empty());
    }

    #[test]
    fn file_discovery_resource_budget_priority_deadline_retains_all_paths() {
        use std::collections::BTreeSet;

        let mut files = (0..300)
            .map(|index| PathBuf::from(format!("benign-priority-time-{index}.txt")))
            .collect::<Vec<_>>();
        let expected = files.iter().cloned().collect::<BTreeSet<_>>();
        let options = WalkOptions {
            max_depth: None,
            max_files: None,
            max_path_bytes: None,
            max_work_items: None,
            max_duration: Some(Duration::ZERO),
            risky_files_only: false,
        };
        let mut never_cancel = || Ok(false);

        let reason =
            prioritize_files_with_limits(&mut files, &options, Instant::now(), &mut never_cancel)
                .unwrap();

        assert_eq!(reason, DiscoveryStopReason::TimeLimitReached);
        assert_eq!(files.len(), 300);
        assert_eq!(files.into_iter().collect::<BTreeSet<_>>(), expected);
    }

    #[test]
    fn file_discovery_memory_priority_bucketing_is_stable() {
        let mut files = vec![
            PathBuf::from("ordinary-z.txt"),
            PathBuf::from("Downloads/first.txt"),
            PathBuf::from("driver.sys"),
            PathBuf::from("ordinary-a.txt"),
            PathBuf::from("Desktop/later.bin"),
            PathBuf::from("script.ps1"),
        ];
        let mut never_cancel = || Ok(false);

        let cancelled = prioritize_files_with_cancellation(&mut files, &mut never_cancel).unwrap();

        assert!(!cancelled);
        assert_eq!(
            files,
            vec![
                PathBuf::from("Downloads/first.txt"),
                PathBuf::from("Desktop/later.bin"),
                PathBuf::from("driver.sys"),
                PathBuf::from("script.ps1"),
                PathBuf::from("ordinary-z.txt"),
                PathBuf::from("ordinary-a.txt"),
            ]
        );
    }

    #[test]
    fn file_discovery_memory_priority_bucketing_observes_cancellation() {
        use std::collections::BTreeSet;

        let mut files = (0..300)
            .map(|index| PathBuf::from(format!("benign-priority-{index}.txt")))
            .collect::<Vec<_>>();
        let expected = files.iter().cloned().collect::<BTreeSet<_>>();
        let mut checkpoints = 0usize;
        let mut should_cancel = || {
            checkpoints += 1;
            Ok(checkpoints >= 2)
        };

        let cancelled = prioritize_files_with_cancellation(&mut files, &mut should_cancel).unwrap();

        assert!(cancelled);
        assert_eq!(checkpoints, 2);
        assert_eq!(files.len(), 300);
        assert_eq!(files.into_iter().collect::<BTreeSet<_>>(), expected);
    }

    #[test]
    fn file_discovery_memory_priority_bucketing_propagates_probe_errors() {
        let mut files = (0..300)
            .map(|index| PathBuf::from(format!("benign-priority-error-{index}.txt")))
            .collect::<Vec<_>>();
        let mut checkpoints = 0usize;
        let mut should_cancel = || {
            checkpoints += 1;
            if checkpoints >= 2 {
                anyhow::bail!("benign priority cancellation probe failure");
            }
            Ok(false)
        };

        let error = prioritize_files_with_cancellation(&mut files, &mut should_cancel)
            .expect_err("priority cancellation callback failure must propagate");

        assert_eq!(checkpoints, 2);
        assert!(error
            .to_string()
            .contains("benign priority cancellation probe failure"));
    }

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
