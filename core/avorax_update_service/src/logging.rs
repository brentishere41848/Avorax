use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::path_safety::{create_dir_all_checked, write_bytes_staged};

pub fn program_data_dir() -> Result<PathBuf> {
    if let Some(path) = absolute_update_env_path("AVORAX_DATA_DIR")? {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = absolute_update_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax"));
        }
        if let Some(program_data) = absolute_update_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax"));
        }
    }
    if let Some(home) = absolute_update_env_path("HOME")? {
        return Ok(home.join(".local/share/avorax"));
    }
    anyhow::bail!("update-service ProgramData root is unavailable")
}

pub fn update_logs_dir() -> Result<PathBuf> {
    Ok(program_data_dir()?.join("updates").join("logs"))
}

pub fn write_update_log(name: &str, message: &str) -> Result<PathBuf> {
    let dir = update_logs_dir()?;
    create_dir_all_checked(&dir, "update log directory")?;
    let path = dir.join(safe_log_name(name)?);
    write_bytes_staged(&path, &dir, "update log file", message.as_bytes())?;
    Ok(path)
}

fn absolute_update_env_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("update-service environment path {name} is empty");
    }
    validate_update_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !update_root_is_allowed(&path) {
        anyhow::bail!("update-service environment path {name} must be an absolute local path");
    }
    Ok(Some(path))
}

fn validate_update_env_root_text(name: &str, text: &str) -> Result<()> {
    if text.contains('\0') {
        anyhow::bail!("update-service environment path {name} contains NUL");
    }
    if update_env_root_has_parent_traversal(text) {
        anyhow::bail!("update-service environment path {name} must not contain parent traversal");
    }
    Ok(())
}

fn update_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn update_root_is_allowed(path: &Path) -> bool {
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
fn update_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

fn safe_log_name(name: &str) -> Result<&str> {
    let trimmed = name.trim();
    anyhow::ensure!(!trimmed.is_empty(), "update log name is empty");
    anyhow::ensure!(
        trimmed != ".",
        "update log name must not be current directory"
    );
    anyhow::ensure!(
        trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')),
        "update log name contains unsafe characters"
    );
    anyhow::ensure!(
        !trimmed.contains(".."),
        "update log name must not contain parent traversal"
    );
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn update_log_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn update_log_name_rejects_traversal() {
        assert!(safe_log_name("update_report.json").is_ok());
        assert!(safe_log_name(".").is_err());
        assert!(safe_log_name("../update_report.json").is_err());
        assert!(safe_log_name("nested/update_report.json").is_err());
        assert!(safe_log_name("update..report.json").is_err());
    }

    #[test]
    fn update_program_data_root_rejects_relative_override() {
        let _lock = update_log_env_lock();
        let previous_avorax = std::env::var_os("AVORAX_DATA_DIR");

        std::env::set_var("AVORAX_DATA_DIR", "relative-update-root");
        let result = program_data_dir();

        if let Some(previous_avorax) = previous_avorax {
            std::env::set_var("AVORAX_DATA_DIR", previous_avorax);
        } else {
            std::env::remove_var("AVORAX_DATA_DIR");
        }

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_DATA_DIR must be an absolute local path"));
    }

    #[test]
    fn update_program_data_root_rejects_parent_traversal_override() {
        let _lock = update_log_env_lock();
        let previous_avorax = std::env::var_os("AVORAX_DATA_DIR");
        let dir = tempfile::tempdir().unwrap();

        std::env::set_var("AVORAX_DATA_DIR", dir.path().join(".."));
        let result = program_data_dir();

        if let Some(previous_avorax) = previous_avorax {
            std::env::set_var("AVORAX_DATA_DIR", previous_avorax);
        } else {
            std::env::remove_var("AVORAX_DATA_DIR");
        }

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_DATA_DIR"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[test]
    fn update_program_data_root_has_no_temp_fallback() {
        let _lock = update_log_env_lock();
        let keys = ["AVORAX_DATA_DIR", "ProgramData", "PROGRAMDATA", "HOME"];
        let previous: Vec<_> = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();

        for key in keys {
            std::env::remove_var(key);
        }
        let result = program_data_dir();

        for (key, value) in previous {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }

        let source = include_str!("logging.rs");
        let start = source.find("pub fn program_data_dir").unwrap();
        let end = source.find("#[cfg(test)]").unwrap();
        let root_source = &source[start..end];

        let error = result.unwrap_err().to_string();
        assert!(error.contains("update-service ProgramData root is unavailable"));
        assert!(root_source.contains("pub fn program_data_dir() -> Result<PathBuf>"));
        assert!(root_source.contains("pub fn update_logs_dir() -> Result<PathBuf>"));
        assert!(root_source.contains("fn absolute_update_env_path("));
        assert!(root_source.contains("absolute_update_env_path(\"AVORAX_DATA_DIR\")?"));
        assert!(root_source.contains("absolute_update_env_path(\"HOME\")?"));
        assert!(root_source.contains("update_root_is_allowed(&path)"));
        assert!(root_source.contains("update-service ProgramData root is unavailable"));
        assert!(root_source.contains("update log name must not be current directory"));
        assert!(!root_source.contains("std::env::temp_dir().join(\"Avorax\")"));
    }
}
