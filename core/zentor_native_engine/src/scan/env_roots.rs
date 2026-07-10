use std::path::{Path, PathBuf};

pub fn absolute_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    validate_env_path(name, PathBuf::from(text)).map(Some)
}

pub fn validate_env_path(name: &str, path: PathBuf) -> anyhow::Result<PathBuf> {
    let text = path.as_os_str().to_string_lossy();
    if text.trim().is_empty() {
        anyhow::bail!("native scan root environment path {name} is empty");
    }
    if native_scan_env_root_has_parent_traversal(&text) {
        anyhow::bail!("native scan root environment path {name} must not contain parent traversal");
    }
    if !scan_root_is_allowed(&path) {
        anyhow::bail!("native scan root environment path {name} must be an absolute local path");
    }
    Ok(path)
}

fn native_scan_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn scan_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
}

#[cfg(not(windows))]
fn scan_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_scan_env_roots_reject_relative_values() {
        let error = validate_env_path("USERPROFILE", PathBuf::from("relative-user"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("USERPROFILE"));
        assert!(error.contains("absolute local path"));
    }

    #[test]
    fn native_scan_env_roots_reject_empty_values() {
        let error = validate_env_path("TEMP", PathBuf::from("   "))
            .unwrap_err()
            .to_string();

        assert!(error.contains("TEMP"));
        assert!(error.contains("empty"));
    }

    #[test]
    fn native_scan_env_roots_reject_parent_traversal_values() {
        let error = validate_env_path("USERPROFILE", PathBuf::from("/tmp/.."))
            .unwrap_err()
            .to_string();

        assert!(error.contains("USERPROFILE"));
        assert!(error.contains("must not contain parent traversal"));
    }
}
