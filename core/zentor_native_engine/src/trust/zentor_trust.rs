use std::fs;
use std::io;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub fn is_zentor_path(path: &Path) -> Result<bool> {
    let raw = path.display().to_string();
    let windows_path = normalize_windows_path_text(&raw);
    let unix_path = normalize_unix_path_text(&raw);
    Ok(is_current_executable(&windows_path, &unix_path)?
        || is_installed_product_path(&windows_path, &unix_path)?
        || is_product_quarantine_path(&windows_path, &unix_path)?
        || is_repo_owned_product_path(&windows_path, &unix_path)?)
}

pub fn has_zentor_artifact_name(path: &Path) -> bool {
    let Some(name) = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    (name.starts_with("avorax-antivirus-") || name.starts_with("zentor-antivirus-"))
        && (name.ends_with("-setup.exe") || name.ends_with("-x64.msi") || name.ends_with(".msi"))
}

fn is_current_executable(windows_path: &str, unix_path: &str) -> Result<bool> {
    let exe =
        std::env::current_exe().context("native product path trust failed to read current exe")?;
    let raw = exe.display().to_string();
    Ok(windows_path == normalize_windows_path_text(&raw)
        || unix_path == normalize_unix_path_text(&raw))
}

fn is_installed_product_path(windows_path: &str, unix_path: &str) -> Result<bool> {
    Ok(product_install_root_candidates()?.iter().any(|root| {
        path_is_equal_or_descendant(windows_path, &normalize_windows_path_text(root), '\\')
            || path_is_equal_or_descendant(unix_path, &normalize_unix_path_text(root), '/')
    }))
}

fn is_product_quarantine_path(windows_path: &str, unix_path: &str) -> Result<bool> {
    Ok(quarantine_root_candidates()?.iter().any(|root| {
        path_is_equal_or_descendant(windows_path, &normalize_windows_path_text(root), '\\')
            || path_is_equal_or_descendant(unix_path, &normalize_unix_path_text(root), '/')
    }))
}

fn is_repo_owned_product_path(windows_path: &str, unix_path: &str) -> Result<bool> {
    Ok(repo_root_candidates()?.iter().any(|root| {
        let windows_root = normalize_windows_path_text(root);
        let unix_root = normalize_unix_path_text(root);
        is_repo_owned_product_path_for_root(windows_path, &windows_root, '\\')
            || is_repo_owned_product_path_for_root(unix_path, &unix_root, '/')
    }))
}

fn is_repo_owned_product_path_for_root(path: &str, root: &str, separator: char) -> bool {
    let apps = join_normalized_path(root, "apps/zentor_client", separator);
    let assets = join_normalized_path(root, "assets/zentor_native", separator);
    let installer = join_normalized_path(root, "installer/windows", separator);
    if path_is_equal_or_descendant(path, &apps, separator)
        || path_is_equal_or_descendant(path, &assets, separator)
        || path_is_equal_or_descendant(path, &installer, separator)
    {
        return true;
    }

    let core = join_normalized_path(root, "core", separator);
    let Some(rest) = path.strip_prefix(&format!("{core}{separator}")) else {
        return false;
    };
    rest.starts_with("zentor_")
}

fn product_install_root_candidates() -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    for key in ["ProgramFiles", "PROGRAMFILES", "ProgramFiles(x86)"] {
        if let Some(value) = absolute_native_trust_env_path(key)? {
            for product in ["Avorax", "Zentor"] {
                let value = value.display().to_string();
                push_unique(&mut candidates, join_windows_path(&value, product));
            }
        }
    }
    for root in [
        "/opt/avorax",
        "/opt/zentor",
        "/usr/local/avorax",
        "/usr/local/zentor",
    ] {
        push_unique(&mut candidates, root.to_string());
    }
    Ok(candidates)
}

fn quarantine_root_candidates() -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    for key in [
        "AVORAX_QUARANTINE_DIR",
        "AVORAX_GUARD_QUARANTINE_DIR",
        "ZENTOR_QUARANTINE_DIR",
        "ZENTOR_GUARD_QUARANTINE_DIR",
    ] {
        if let Some(value) = absolute_native_trust_env_path(key)? {
            push_unique(&mut candidates, value.display().to_string());
        }
    }

    for program_data in program_data_candidates()? {
        for product in ["Avorax", "Zentor"] {
            for child in ["Quarantine", "GuardQuarantine"] {
                push_unique(
                    &mut candidates,
                    join_windows_path(&join_windows_path(&program_data, product), child),
                );
            }
        }
    }

    if let Some(home) = absolute_native_trust_env_path("HOME")? {
        for product in ["avorax", "zentor"] {
            push_unique(
                &mut candidates,
                home.join(".local")
                    .join("share")
                    .join(product)
                    .join("quarantine")
                    .display()
                    .to_string(),
            );
        }
    }
    Ok(candidates)
}

fn program_data_candidates() -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    for key in ["ProgramData", "PROGRAMDATA"] {
        if let Some(value) = absolute_native_trust_env_path(key)? {
            push_unique(&mut candidates, value.display().to_string());
        }
    }
    Ok(candidates)
}

fn absolute_native_trust_env_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("native product trust environment path {name} is empty");
    }
    validate_native_product_trust_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !native_product_trust_root_is_allowed(&path) {
        anyhow::bail!(
            "native product trust environment path {name} must be an absolute local path"
        );
    }
    Ok(Some(path))
}

fn validate_native_product_trust_env_root_text(name: &str, text: &str) -> Result<()> {
    if text.contains('\0') {
        anyhow::bail!("native product trust environment path {name} contains NUL");
    }
    if native_product_trust_env_root_has_parent_traversal(text) {
        anyhow::bail!(
            "native product trust environment path {name} must not contain parent traversal"
        );
    }
    Ok(())
}

fn native_product_trust_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn native_product_trust_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn native_product_trust_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

fn repo_root_candidates() -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    let exe =
        std::env::current_exe().context("native product path trust failed to read current exe")?;
    let parent = exe.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "native product path trust found no parent for current exe {}",
            exe.display()
        )
    })?;
    collect_repo_roots_from(parent, &mut candidates)?;

    #[cfg(debug_assertions)]
    {
        let current = std::env::current_dir()
            .context("native product path trust debug discovery failed to read current dir")?;
        collect_repo_roots_from(&current, &mut candidates)?;
    }
    Ok(candidates)
}

fn collect_repo_roots_from(start: &Path, candidates: &mut Vec<String>) -> Result<()> {
    for ancestor in start.ancestors() {
        let assets_marker = ancestor.join("assets").join("zentor_native");
        let engine_marker = ancestor.join("core").join("zentor_native_engine");
        if repo_marker_dir_is_regular(&assets_marker)?
            && repo_marker_dir_is_regular(&engine_marker)?
        {
            if !native_product_trust_root_is_allowed(ancestor) {
                anyhow::bail!(
                    "native product repository root {} must be an absolute local path",
                    ancestor.display()
                );
            }
            push_unique(candidates, ancestor.display().to_string());
        }
    }
    Ok(())
}

fn repo_marker_dir_is_regular(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && !is_windows_reparse_point(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect native product repository marker {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn normalize_windows_path_text(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut previous_separator = false;
    for ch in value.trim().chars() {
        if ch == '\\' || ch == '/' {
            if !previous_separator {
                normalized.push('\\');
            }
            previous_separator = true;
        } else {
            normalized.push(ch);
            previous_separator = false;
        }
    }
    normalized.make_ascii_lowercase();
    collapse_product_trust_path_segments(&normalized, '\\')
}

fn normalize_unix_path_text(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut previous_separator = false;
    for ch in value.trim().chars() {
        if ch == '/' {
            if !previous_separator {
                normalized.push('/');
            }
            previous_separator = true;
        } else {
            normalized.push(ch);
            previous_separator = false;
        }
    }
    normalized.make_ascii_lowercase();
    collapse_product_trust_path_segments(&normalized, '/')
}

fn trim_trailing_separator(mut value: String, separator: char) -> String {
    while value.len() > 1
        && value.ends_with(separator)
        && !(separator == '\\' && value.ends_with(":\\"))
    {
        value.pop();
    }
    value
}

fn collapse_product_trust_path_segments(path: &str, separator: char) -> String {
    let trimmed = trim_trailing_separator(path.to_string(), separator);
    if trimmed.is_empty() {
        return String::new();
    }

    let (prefix, rest, absolute) = split_product_trust_path_prefix(&trimmed, separator);
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split(separator) {
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

    let separator = separator.to_string();
    let body = segments.join(&separator);
    match (prefix, absolute, body.is_empty()) {
        (Some(prefix), _, true) => prefix.to_string(),
        (Some(prefix), _, false) => format!("{prefix}{separator}{body}"),
        (None, true, true) => separator,
        (None, true, false) => format!("{separator}{body}"),
        (None, false, _) => body,
    }
}

fn split_product_trust_path_prefix(path: &str, separator: char) -> (Option<&str>, &str, bool) {
    let bytes = path.as_bytes();
    if separator == '\\' && bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'\\' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with(separator) {
        return (None, path.trim_start_matches(separator), true);
    }
    (None, path, false)
}

fn join_windows_path(root: &str, child: &str) -> String {
    let root = trim_trailing_separator(normalize_windows_path_text(root), '\\');
    let child = normalize_windows_path_text(child);
    if root.is_empty() {
        child
    } else if child.is_empty() {
        root
    } else {
        format!("{root}\\{child}")
    }
}

fn join_normalized_path(root: &str, child: &str, separator: char) -> String {
    let root = trim_trailing_separator(root.to_string(), separator);
    let child = if separator == '\\' {
        normalize_windows_path_text(child)
    } else {
        normalize_unix_path_text(child)
    };
    if root.is_empty() {
        child
    } else if child.is_empty() {
        root
    } else {
        format!("{root}{separator}{child}")
    }
}

fn path_is_equal_or_descendant(path: &str, root: &str, separator: char) -> bool {
    if root.is_empty() {
        return false;
    }
    if path == root {
        return true;
    }
    let Some(rest) = path.strip_prefix(root) else {
        return false;
    };
    rest.starts_with(separator)
}

fn push_unique(candidates: &mut Vec<String>, value: String) {
    if !value.trim().is_empty() && !candidates.iter().any(|candidate| candidate == &value) {
        candidates.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn trust_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn product_path_trust_requires_exact_roots() {
        let _lock = trust_env_lock();
        let previous_program_data = std::env::var_os("ProgramData");
        let previous_program_files = std::env::var_os("ProgramFiles");
        std::env::set_var("ProgramData", r"C:\ProgramData");
        std::env::set_var("ProgramFiles", r"C:\Program Files");

        let trusted_quarantine =
            is_zentor_path(Path::new(r"C:\ProgramData\Avorax\Quarantine\item.avoraxq")).unwrap();
        let trusted_quarantine_current_dir = is_zentor_path(Path::new(
            r"C:\ProgramData\Avorax\Quarantine\.\item.avoraxq",
        ))
        .unwrap();
        let escaped_quarantine = is_zentor_path(Path::new(
            r"C:\ProgramData\Avorax\Quarantine\..\Outside\payload.exe",
        ))
        .unwrap();
        let trusted_install = is_zentor_path(Path::new(
            r"C:\Program Files\Avorax\avorax_guard_service.exe",
        ))
        .unwrap();
        let lookalike_program_files = is_zentor_path(Path::new(
            r"C:\Users\Public\Program Files\Avorax\lookalike.exe",
        ))
        .unwrap();
        let lookalike_program_data = is_zentor_path(Path::new(
            r"C:\ProgramDataX\Avorax\Quarantine\lookalike.exe",
        ))
        .unwrap();

        match previous_program_data {
            Some(value) => std::env::set_var("ProgramData", value),
            None => std::env::remove_var("ProgramData"),
        }
        match previous_program_files {
            Some(value) => std::env::set_var("ProgramFiles", value),
            None => std::env::remove_var("ProgramFiles"),
        }

        assert!(trusted_quarantine);
        assert!(trusted_quarantine_current_dir);
        assert!(!escaped_quarantine);
        assert!(trusted_install);
        assert!(!lookalike_program_files);
        assert!(!lookalike_program_data);
    }

    #[test]
    fn repo_lookalike_path_outside_repo_is_not_trusted() {
        let dir = tempdir().unwrap();
        let path = dir
            .path()
            .join("core")
            .join("zentor_native_engine")
            .join("zentor_local_core.exe");

        assert!(!is_zentor_path(&path).unwrap());
    }

    #[test]
    fn repo_marker_dirs_accept_regular_directories() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("assets").join("zentor_native")).unwrap();
        fs::create_dir_all(dir.path().join("core").join("zentor_native_engine")).unwrap();
        let mut candidates = Vec::new();

        collect_repo_roots_from(
            &dir.path().join("assets").join("zentor_native"),
            &mut candidates,
        )
        .unwrap();

        assert!(candidates
            .iter()
            .any(|candidate| candidate == &dir.path().display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn repo_marker_dirs_reject_symbolic_links() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let redirected_assets = dir.path().join("redirected-assets");
        fs::create_dir_all(&redirected_assets).unwrap();
        fs::create_dir_all(dir.path().join("assets")).unwrap();
        fs::create_dir_all(dir.path().join("core").join("zentor_native_engine")).unwrap();
        unix_fs::symlink(
            &redirected_assets,
            dir.path().join("assets").join("zentor_native"),
        )
        .unwrap();
        let mut candidates = Vec::new();

        collect_repo_roots_from(
            &dir.path().join("core").join("zentor_native_engine"),
            &mut candidates,
        )
        .unwrap();

        assert!(!candidates
            .iter()
            .any(|candidate| candidate == &dir.path().display().to_string()));
    }

    #[test]
    fn repo_marker_detection_uses_non_following_directory_checks() {
        let source = include_str!("zentor_trust.rs");
        let legacy_assets_probe = [
            "ancestor.join(\"assets\").join(\"zentor_native\")",
            ".is_dir()",
        ]
        .concat();
        let legacy_engine_probe = [
            "ancestor.join(\"core\").join(\"zentor_native_engine\")",
            ".is_dir()",
        ]
        .concat();

        assert!(source.contains("repo_marker_dir_is_regular(&assets_marker)"));
        assert!(source.contains("fs::symlink_metadata(path)"));
        assert!(source.contains("metadata.file_type().is_symlink()"));
        assert!(!source.contains(&legacy_assets_probe));
        assert!(!source.contains(&legacy_engine_probe));
    }

    #[test]
    fn repo_root_candidates_use_controlled_roots() {
        let source = include_str!("zentor_trust.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        let start = production_source.find("fn repo_root_candidates").unwrap();
        let end = production_source
            .find("fn repo_marker_dir_is_regular")
            .unwrap();
        let repo_source = &production_source[start..end];
        let old_current_dir_error =
            ["native product path trust failed", " to read current dir"].concat();
        let old_optional_exe_parent = ["if let Some(parent)", " = exe.parent()"].concat();

        assert!(repo_source.contains("std::env::current_exe()"));
        assert!(repo_source.contains("found no parent for current exe"));
        assert!(repo_source.contains("collect_repo_roots_from(parent, &mut candidates)?"));
        assert!(repo_source.contains("#[cfg(debug_assertions)]"));
        assert!(repo_source
            .contains("native product path trust debug discovery failed to read current dir"));
        assert!(repo_source.contains("native_product_trust_root_is_allowed(ancestor)"));
        assert!(repo_source.contains("must be an absolute local path"));
        assert!(!repo_source.contains(&old_current_dir_error));
        assert!(!repo_source.contains(&old_optional_exe_parent));
    }

    #[test]
    fn installer_name_alone_is_not_product_path_trust() {
        let path = Path::new(r"C:\Users\Public\Downloads\Avorax-AntiVirus-0.2.2-x64-setup.exe");

        assert!(has_zentor_artifact_name(path));
        assert!(!is_zentor_path(path).unwrap());
    }

    #[test]
    fn product_path_prefix_checks_do_not_use_false_defaults() {
        let source = include_str!("zentor_trust.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        let old_prefix_default = [
            ".map(|rest| rest.starts_with(separator))",
            "\n            .unwrap_or(false)",
        ]
        .concat();
        let old_core_default = [
            ".map(|rest| rest.starts_with(\"zentor_\"))",
            "\n        .unwrap_or(false)",
        ]
        .concat();

        assert!(production_source.contains("let Some(rest) = path.strip_prefix(root) else"));
        assert!(production_source
            .contains("let Some(rest) = path.strip_prefix(&format!(\"{core}{separator}\")) else"));
        assert!(!production_source.contains(&old_prefix_default));
        assert!(!production_source.contains(&old_core_default));
    }

    #[test]
    fn repo_marker_inspection_errors_are_not_false_defaults() {
        let source = include_str!("zentor_trust.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;

        assert!(production_source
            .contains("fn repo_marker_dir_is_regular(path: &Path) -> Result<bool>"));
        assert!(production_source.contains("error.kind() == io::ErrorKind::NotFound"));
        assert!(production_source.contains("unable to inspect native product repository marker"));
        assert!(!production_source.contains("Err(_) => false"));
        assert!(production_source.contains("fn is_zentor_path(path: &Path) -> Result<bool>"));
    }

    #[test]
    fn quarantine_trust_roots_reject_relative_overrides() {
        let _lock = trust_env_lock();
        let previous = std::env::var_os("AVORAX_QUARANTINE_DIR");

        std::env::set_var("AVORAX_QUARANTINE_DIR", "relative-quarantine");
        let result = is_zentor_path(Path::new(r"C:\Users\Public\Downloads\tool.exe"));

        match previous {
            Some(value) => std::env::set_var("AVORAX_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_QUARANTINE_DIR"),
        }

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_QUARANTINE_DIR must be an absolute local path"));
    }

    #[test]
    fn quarantine_trust_roots_reject_parent_traversal_overrides() {
        let _lock = trust_env_lock();
        let previous = std::env::var_os("AVORAX_QUARANTINE_DIR");
        let dir = tempdir().unwrap();

        std::env::set_var("AVORAX_QUARANTINE_DIR", dir.path().join(".."));
        let result = is_zentor_path(Path::new(r"C:\Users\Public\Downloads\tool.exe"));

        match previous {
            Some(value) => std::env::set_var("AVORAX_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_QUARANTINE_DIR"),
        }

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_QUARANTINE_DIR"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[test]
    fn quarantine_trust_roots_do_not_use_temp_or_hardcoded_program_data() {
        let source = include_str!("zentor_trust.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        let start = production_source
            .find("fn quarantine_root_candidates")
            .unwrap();
        let end = production_source.find("fn repo_root_candidates").unwrap();
        let quarantine_source = &production_source[start..end];

        assert!(production_source.contains(
            "fn is_product_quarantine_path(windows_path: &str, unix_path: &str) -> Result<bool>"
        ));
        assert!(
            quarantine_source.contains("fn quarantine_root_candidates() -> Result<Vec<String>>")
        );
        assert!(production_source.contains(
            "fn is_installed_product_path(windows_path: &str, unix_path: &str) -> Result<bool>"
        ));
        assert!(production_source
            .contains("fn product_install_root_candidates() -> Result<Vec<String>>"));
        assert!(quarantine_source.contains("fn program_data_candidates() -> Result<Vec<String>>"));
        assert!(production_source.contains("fn absolute_native_trust_env_path("));
        assert!(quarantine_source.contains("\"AVORAX_QUARANTINE_DIR\""));
        assert!(quarantine_source.contains("absolute_native_trust_env_path(\"HOME\")?"));
        assert!(production_source.contains("native_product_trust_root_is_allowed(&path)"));
        assert!(!quarantine_source.contains("std::env::temp_dir()"));
        assert!(!quarantine_source.contains("r\"C:\\ProgramData\".to_string()"));
        assert!(!production_source.contains("r\"C:\\Program Files\\Avorax\""));
    }
}
