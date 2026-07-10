use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn is_dangerous_allowlist_path(path: &Path) -> bool {
    let raw = path.display().to_string();
    let windows_path = normalize_windows_path_text(&raw);
    let unix_path = normalize_unix_path_text(&raw);
    is_blocked_windows_allowlist_root(&windows_path) || is_blocked_unix_allowlist_root(&unix_path)
}

fn is_blocked_windows_allowlist_root(path: &str) -> bool {
    if is_windows_drive_root(path) {
        return true;
    }
    let Some(rest) = windows_drive_absolute_rest(path) else {
        return false;
    };
    matches!(
        rest,
        "windows" | "program files" | "program files (x86)" | "programdata" | "users"
    )
}

fn is_windows_drive_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() == 2 || (bytes.len() == 3 && bytes[2] == b'\\'))
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
}

fn windows_drive_absolute_rest(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        Some(&path[3..])
    } else {
        None
    }
}

fn is_blocked_unix_allowlist_root(path: &str) -> bool {
    matches!(path, "/" | "/system" | "/usr" | "/bin" | "/sbin" | "/etc")
}

pub fn is_passthrough_system_or_zentor_path(path: &Path) -> Result<bool> {
    let raw = path.display().to_string();
    let windows_path = normalize_windows_path_text(&raw);
    let unix_path = normalize_unix_path_text(&raw);
    Ok(is_windows_system_passthrough_path(&windows_path)?
        || is_windows_product_passthrough_path(&windows_path)?
        || is_unix_system_passthrough_path(&unix_path)
        || is_unix_product_passthrough_path(&unix_path)?)
}

fn is_windows_system_passthrough_path(path: &str) -> Result<bool> {
    Ok(windows_directory_candidates()?.iter().any(|windows| {
        path_is_equal_or_descendant(path, &join_windows_path(windows, "system32"), '\\')
            || path_is_equal_or_descendant(path, &join_windows_path(windows, "syswow64"), '\\')
    }))
}

fn is_windows_product_passthrough_path(path: &str) -> Result<bool> {
    if quarantine_root_candidates()?
        .iter()
        .map(|root| normalize_windows_path_text(root))
        .any(|root| path_is_equal_or_descendant(path, &root, '\\'))
    {
        return Ok(true);
    }
    if let Ok(exe) = std::env::current_exe() {
        let current_exe = normalize_windows_path_text(&exe.display().to_string());
        if !current_exe.is_empty() && path == current_exe {
            return Ok(true);
        }
    }
    let Some(file_name) = path.rsplit('\\').next() else {
        return Ok(false);
    };
    if !matches!(
        file_name,
        "avorax_local_core.exe"
            | "avorax_guard_service.exe"
            | "zentor_local_core.exe"
            | "zentor_guard_service.exe"
    ) {
        return Ok(false);
    }
    Ok(product_install_root_candidates()?
        .iter()
        .map(|root| normalize_windows_path_text(root))
        .any(|root| path_is_equal_or_descendant(path, &root, '\\')))
}

fn is_unix_system_passthrough_path(path: &str) -> bool {
    ["/usr", "/bin", "/sbin"]
        .iter()
        .any(|root| path_is_equal_or_descendant(path, root, '/'))
}

fn is_unix_product_passthrough_path(path: &str) -> Result<bool> {
    if quarantine_root_candidates()?
        .iter()
        .map(|root| normalize_unix_path_text(root))
        .any(|root| path_is_equal_or_descendant(path, &root, '/'))
    {
        return Ok(true);
    }
    if let Ok(exe) = std::env::current_exe() {
        let current_exe = normalize_unix_path_text(&exe.display().to_string());
        if !current_exe.is_empty() && path == current_exe {
            return Ok(true);
        }
    }
    Ok(false)
}

fn windows_directory_candidates() -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    for key in ["SystemRoot", "WINDIR"] {
        if let Some(value) = absolute_passthrough_env_path(key)? {
            push_unique(
                &mut candidates,
                normalize_windows_path_text(&value.display().to_string()),
            );
        }
    }
    Ok(candidates)
}

fn program_data_candidates() -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    for key in ["ProgramData", "PROGRAMDATA"] {
        if let Some(value) = absolute_passthrough_env_path(key)? {
            push_unique(
                &mut candidates,
                normalize_windows_path_text(&value.display().to_string()),
            );
        }
    }
    Ok(candidates)
}

fn product_install_root_candidates() -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    for key in ["ProgramFiles", "PROGRAMFILES", "ProgramFiles(x86)"] {
        if let Some(value) = absolute_passthrough_env_path(key)? {
            let value = normalize_windows_path_text(&value.display().to_string());
            for product in ["Avorax", "Zentor"] {
                push_unique(&mut candidates, join_windows_path(&value, product));
            }
        }
    }
    Ok(candidates)
}

fn quarantine_root_candidates() -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    for key in [
        "AVORAX_QUARANTINE_DIR",
        "ZENTOR_QUARANTINE_DIR",
        "AVORAX_GUARD_QUARANTINE_DIR",
        "ZENTOR_GUARD_QUARANTINE_DIR",
    ] {
        if let Some(value) = absolute_passthrough_env_path(key)? {
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
    if let Some(home) = absolute_passthrough_env_path("HOME")? {
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

fn absolute_passthrough_env_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("local passthrough environment path {name} is empty");
    }
    validate_passthrough_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !passthrough_root_is_allowed(&path) {
        anyhow::bail!("local passthrough environment path {name} must be an absolute local path");
    }
    Ok(Some(path))
}

fn validate_passthrough_env_root_text(name: &str, text: &str) -> Result<()> {
    if text.contains('\0') {
        anyhow::bail!("local passthrough environment path {name} contains NUL");
    }
    if passthrough_env_root_has_parent_traversal(text) {
        anyhow::bail!(
            "local passthrough environment path {name} must not contain parent traversal"
        );
    }
    Ok(())
}

fn passthrough_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn passthrough_root_is_allowed(path: &Path) -> bool {
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
fn passthrough_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
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
    collapse_passthrough_path_segments(&normalized, '\\')
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
    collapse_passthrough_path_segments(&normalized, '/')
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

fn collapse_passthrough_path_segments(path: &str, separator: char) -> String {
    let trimmed = trim_trailing_separator(path.to_string(), separator);
    if trimmed.is_empty() {
        return String::new();
    }

    let (prefix, rest, absolute) = split_passthrough_path_prefix(&trimmed, separator);
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

fn split_passthrough_path_prefix(path: &str, separator: char) -> (Option<&str>, &str, bool) {
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
    let root = trim_trailing_separator(root.to_string(), '\\');
    let child = normalize_windows_path_text(child);
    if root.is_empty() {
        child
    } else if child.is_empty() {
        root
    } else {
        format!("{root}\\{child}")
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
    if !value.is_empty() && !candidates.iter().any(|candidate| candidate == &value) {
        candidates.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn passthrough_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn passthrough_allows_exact_system_and_quarantine_roots() {
        let _lock = passthrough_env_lock();
        let previous_program_data = std::env::var_os("ProgramData");
        std::env::set_var("ProgramData", r"C:\ProgramData");

        for windows in windows_directory_candidates().unwrap() {
            let system_file = format!("{windows}\\System32\\kernel32.dll");
            assert!(is_passthrough_system_or_zentor_path(Path::new(&system_file)).unwrap());
        }
        let trusted_quarantine = is_passthrough_system_or_zentor_path(Path::new(
            r"C:\ProgramData\Avorax\Quarantine\item.avoraxq",
        ))
        .unwrap();

        match previous_program_data {
            Some(value) => std::env::set_var("ProgramData", value),
            None => std::env::remove_var("ProgramData"),
        }

        assert!(trusted_quarantine);
    }

    #[test]
    fn passthrough_windows_roots_do_not_use_hardcoded_fallback() {
        let source = include_str!("trust_store.rs");
        let start = source.find("fn windows_directory_candidates").unwrap();
        let end = source.find("fn program_data_candidates").unwrap();
        let helper = &source[start..end];

        assert!(helper.contains("[\"SystemRoot\", \"WINDIR\"]"));
        assert!(!helper.contains("C:\\Windows"));
    }

    #[test]
    fn passthrough_rejects_lookalike_system_and_quarantine_paths() {
        assert!(!is_passthrough_system_or_zentor_path(Path::new(
            r"C:\Users\Public\Windows\System32\lookalike.exe"
        ))
        .unwrap());
        assert!(!is_passthrough_system_or_zentor_path(Path::new(
            r"C:\ProgramDataX\Avorax\Quarantine\lookalike.exe"
        ))
        .unwrap());
    }

    #[test]
    fn passthrough_rejects_parent_traversal_out_of_trusted_roots() {
        let _lock = passthrough_env_lock();
        let previous_program_data = std::env::var_os("ProgramData");
        std::env::set_var("ProgramData", r"C:\ProgramData");

        let escaped_quarantine = is_passthrough_system_or_zentor_path(Path::new(
            r"C:\ProgramData\Avorax\Quarantine\..\Outside\payload.exe",
        ))
        .unwrap();
        let trusted_quarantine = is_passthrough_system_or_zentor_path(Path::new(
            r"C:\ProgramData\Avorax\Quarantine\.\item.avoraxq",
        ))
        .unwrap();

        match previous_program_data {
            Some(value) => std::env::set_var("ProgramData", value),
            None => std::env::remove_var("ProgramData"),
        }

        assert!(!escaped_quarantine);
        assert!(trusted_quarantine);
    }

    #[test]
    fn passthrough_rejects_service_name_outside_product_roots() {
        let _lock = passthrough_env_lock();
        let previous_program_files = std::env::var_os("ProgramFiles");
        std::env::set_var("ProgramFiles", r"C:\Program Files");

        assert!(!is_passthrough_system_or_zentor_path(Path::new(
            r"C:\Users\Public\zentor_local_core.exe"
        ))
        .unwrap());
        let trusted_service = is_passthrough_system_or_zentor_path(Path::new(
            r"C:\Program Files\Avorax\zentor_local_core.exe",
        ))
        .unwrap();

        match previous_program_files {
            Some(value) => std::env::set_var("ProgramFiles", value),
            None => std::env::remove_var("ProgramFiles"),
        }

        assert!(trusted_service);
    }

    #[test]
    fn passthrough_path_prefix_checks_do_not_use_false_defaults() {
        let source = include_str!("trust_store.rs");
        let helper_start = source.find("fn path_is_equal_or_descendant").unwrap();
        let helper_end = source.find("fn push_unique").unwrap();
        let helper_source = &source[helper_start..helper_end];

        assert!(helper_source.contains("if path == root"));
        assert!(helper_source.contains("let Some(rest) = path.strip_prefix(root) else"));
        assert!(helper_source.contains("return false;"));
        assert!(!helper_source.contains(".unwrap_or(false)"));
        assert!(!helper_source.contains(".map(|rest| rest.starts_with(separator))"));
    }

    #[test]
    fn passthrough_roots_reject_relative_overrides() {
        let _lock = passthrough_env_lock();
        let previous = std::env::var_os("AVORAX_QUARANTINE_DIR");

        std::env::set_var("AVORAX_QUARANTINE_DIR", "relative-quarantine");
        let result =
            is_passthrough_system_or_zentor_path(Path::new(r"C:\Users\Public\Downloads\tool.exe"));

        match previous {
            Some(value) => std::env::set_var("AVORAX_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_QUARANTINE_DIR"),
        }

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_QUARANTINE_DIR must be an absolute local path"));
    }

    #[test]
    fn passthrough_roots_reject_parent_traversal_overrides() {
        let _lock = passthrough_env_lock();
        let previous = std::env::var_os("AVORAX_QUARANTINE_DIR");
        let dir = tempfile::tempdir().unwrap();

        std::env::set_var("AVORAX_QUARANTINE_DIR", dir.path().join(".."));
        let result =
            is_passthrough_system_or_zentor_path(Path::new(r"C:\Users\Public\Downloads\tool.exe"));

        match previous {
            Some(value) => std::env::set_var("AVORAX_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_QUARANTINE_DIR"),
        }

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_QUARANTINE_DIR"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[test]
    fn passthrough_product_roots_do_not_use_hardcoded_fallbacks() {
        let source = include_str!("trust_store.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        let start = production_source
            .find("fn windows_directory_candidates")
            .unwrap();
        let end = production_source
            .find("fn normalize_windows_path_text")
            .unwrap();
        let root_source = &production_source[start..end];

        assert!(production_source
            .contains("pub fn is_passthrough_system_or_zentor_path(path: &Path) -> Result<bool>"));
        assert!(root_source.contains("fn program_data_candidates() -> Result<Vec<String>>"));
        assert!(root_source.contains("fn product_install_root_candidates() -> Result<Vec<String>>"));
        assert!(root_source.contains("fn quarantine_root_candidates() -> Result<Vec<String>>"));
        assert!(root_source.contains("fn absolute_passthrough_env_path("));
        assert!(root_source.contains("absolute_passthrough_env_path(\"HOME\")?"));
        assert!(root_source.contains("passthrough_root_is_allowed(&path)"));
        assert!(!root_source.contains("normalize_windows_path_text(r\"C:\\ProgramData\")"));
        assert!(!root_source.contains("r\"C:\\Program Files\\Avorax\""));
    }

    #[test]
    fn dangerous_allowlist_paths_block_broad_windows_roots() {
        assert!(is_dangerous_allowlist_path(Path::new(r"C:\")));
        assert!(is_dangerous_allowlist_path(Path::new(r"D:\")));
        assert!(is_dangerous_allowlist_path(Path::new(r"C:\ProgramData")));
        assert!(is_dangerous_allowlist_path(Path::new(r"D:\Program Files")));
        assert!(is_dangerous_allowlist_path(Path::new(r"C:\Users")));
        assert!(is_dangerous_allowlist_path(Path::new(
            r"C:\Users\Brent\..\..\Windows"
        )));
        assert!(is_dangerous_allowlist_path(Path::new(
            "/home/brent/../../usr"
        )));
        assert!(!is_dangerous_allowlist_path(Path::new(
            r"C:\Users\Brent\Downloads\trusted.exe"
        )));
    }
}
