use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AllowlistEntryType {
    File,
    Folder,
    App,
    Executable,
    Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub id: String,
    pub entry_type: AllowlistEntryType,
    pub path: String,
    pub sha256: Option<String>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub active: bool,
}

pub struct AllowlistStore {
    entries: Vec<AllowlistEntry>,
    path: Option<PathBuf>,
}

impl AllowlistStore {
    pub fn new() -> Self {
        let path = std::env::var("ZENTOR_ALLOWLIST_FILE")
            .ok()
            .map(PathBuf::from);
        let entries = path
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        Self { entries, path }
    }

    pub fn in_memory(entries: Vec<AllowlistEntry>) -> Self {
        Self {
            entries,
            path: None,
        }
    }

    pub fn add(
        &mut self,
        entry_type: AllowlistEntryType,
        path: String,
        reason: String,
    ) -> Result<AllowlistEntry> {
        validate_path(&path)?;
        let entry = AllowlistEntry {
            id: Uuid::new_v4().to_string(),
            entry_type,
            path,
            sha256: None,
            reason,
            created_at: Utc::now(),
            created_by: "local_user".to_string(),
            active: true,
        };
        self.entries.push(entry.clone());
        self.save()?;
        Ok(entry)
    }

    pub fn list(&self) -> &[AllowlistEntry] {
        &self.entries
    }

    pub fn is_allowlisted(&self, path: &Path, sha256: &str) -> bool {
        let normalized = path.display().to_string().replace('\\', "/");
        self.entries.iter().any(|entry| {
            if !entry.active {
                return false;
            }
            if let Some(entry_hash) = &entry.sha256 {
                if entry_hash == sha256 {
                    return true;
                }
            }
            let entry_path = entry.path.replace('\\', "/");
            normalized == entry_path || normalized.starts_with(&format!("{entry_path}/"))
        })
    }

    fn save(&self) -> Result<()> {
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, serde_json::to_string_pretty(&self.entries)?)?;
        }
        Ok(())
    }
}

pub fn validate_path(path: &str) -> Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("allowlist path is empty"));
    }
    let normalized = trimmed.replace('\\', "/").trim_end_matches('/').to_string();
    let blocked = [
        "C:",
        "C:/Windows",
        "/System",
        "/usr",
        "/",
        "/bin",
        "/sbin",
        "/etc",
    ];
    if blocked
        .iter()
        .any(|blocked| normalized.eq_ignore_ascii_case(blocked))
    {
        return Err(anyhow!("unsafe root folders cannot be allowlisted"));
    }
    let path = Path::new(trimmed);
    if path
        .components()
        .all(|component| matches!(component, Component::RootDir))
    {
        return Err(anyhow!("unsafe root folders cannot be allowlisted"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_unsafe_root_paths() {
        assert!(validate_path("/").is_err());
        assert!(validate_path("/usr").is_err());
        assert!(validate_path("C:\\").is_err());
        assert!(validate_path("C:\\Windows").is_err());
    }

    #[test]
    fn allows_normal_file_or_folder_path() {
        assert!(validate_path("/home/user/Tools/example.exe").is_ok());
        assert!(validate_path("C:\\Users\\Example\\Tools\\example.exe").is_ok());
    }
}
