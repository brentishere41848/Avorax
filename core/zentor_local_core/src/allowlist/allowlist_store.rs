use std::fs;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
        let sha256 = hash_required_for_entry(&entry_type, Path::new(&path))?;
        let entry = AllowlistEntry {
            id: Uuid::new_v4().to_string(),
            entry_type,
            path,
            sha256,
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
        let normalized_path = normalize_path_text(path);
        let normalized_hash = normalize_hash_text(sha256);
        self.entries.iter().any(|entry| {
            if !entry.active {
                return false;
            }

            match entry.entry_type {
                AllowlistEntryType::Hash => entry
                    .sha256
                    .as_deref()
                    .map(normalize_hash_text)
                    .or_else(|| Some(normalize_hash_text(&entry.path)))
                    .is_some_and(|entry_hash| {
                        !entry_hash.is_empty() && entry_hash == normalized_hash
                    }),
                AllowlistEntryType::Folder => {
                    let entry_path = normalize_entry_path(&entry.path);
                    path_matches_folder(&normalized_path, &entry_path)
                }
                AllowlistEntryType::File
                | AllowlistEntryType::App
                | AllowlistEntryType::Executable => {
                    let entry_path = normalize_entry_path(&entry.path);
                    if normalized_path != entry_path {
                        return false;
                    }
                    match entry.sha256.as_deref() {
                        Some(entry_hash) => normalize_hash_text(entry_hash) == normalized_hash,
                        None => false,
                    }
                }
            }
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

fn hash_required_for_entry(entry_type: &AllowlistEntryType, path: &Path) -> Result<Option<String>> {
    match entry_type {
        AllowlistEntryType::File | AllowlistEntryType::App | AllowlistEntryType::Executable => {
            Ok(Some(sha256_file(path).with_context(|| {
                format!(
                    "file/app/executable allowlist entries must be hashed before allowlisting: {}",
                    path.display()
                )
            })?))
        }
        AllowlistEntryType::Folder | AllowlistEntryType::Hash => Ok(None),
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn normalize_entry_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn normalize_path_text(path: &Path) -> String {
    normalize_entry_path(&path.display().to_string())
}

fn normalize_hash_text(hash: &str) -> String {
    hash.trim().to_ascii_lowercase()
}

fn path_matches_folder(path: &str, folder: &str) -> bool {
    !folder.is_empty() && (path == folder || path.starts_with(&format!("{folder}/")))
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

    fn entry(entry_type: AllowlistEntryType, path: &str, sha256: Option<&str>) -> AllowlistEntry {
        AllowlistEntry {
            id: "test-entry".to_string(),
            entry_type,
            path: path.to_string(),
            sha256: sha256.map(str::to_string),
            reason: "test".to_string(),
            created_at: Utc::now(),
            created_by: "test".to_string(),
            active: true,
        }
    }

    #[test]
    fn file_allowlist_entry_requires_matching_hash_when_hash_is_recorded() {
        let store = AllowlistStore::in_memory(vec![entry(
            AllowlistEntryType::File,
            "C:/Users/Example/Downloads/trusted.exe",
            Some("sha256:trusted"),
        )]);

        assert!(store.is_allowlisted(
            Path::new("C:/Users/Example/Downloads/trusted.exe"),
            "sha256:trusted"
        ));
        assert!(!store.is_allowlisted(
            Path::new("C:/Users/Example/Downloads/trusted.exe"),
            "sha256:changed"
        ));
    }

    #[test]
    fn file_allowlist_hash_does_not_allow_other_paths() {
        let store = AllowlistStore::in_memory(vec![entry(
            AllowlistEntryType::File,
            "C:/Users/Example/Downloads/trusted.exe",
            Some("sha256:trusted"),
        )]);

        assert!(!store.is_allowlisted(
            Path::new("C:/Users/Example/AppData/Temp/payload.exe"),
            "sha256:trusted"
        ));
    }

    #[test]
    fn legacy_path_only_file_allowlist_entry_fails_closed() {
        let store = AllowlistStore::in_memory(vec![entry(
            AllowlistEntryType::File,
            "C:/Users/Example/Downloads/trusted.exe",
            None,
        )]);

        assert!(!store.is_allowlisted(
            Path::new("C:/Users/Example/Downloads/trusted.exe"),
            "sha256:any-payload"
        ));
    }

    #[test]
    fn explicit_hash_allowlist_entry_allows_same_hash_anywhere() {
        let store = AllowlistStore::in_memory(vec![entry(
            AllowlistEntryType::Hash,
            "sha256:trusted",
            Some("sha256:trusted"),
        )]);

        assert!(store.is_allowlisted(
            Path::new("C:/Users/Example/AppData/Temp/renamed.exe"),
            "sha256:trusted"
        ));
        assert!(!store.is_allowlisted(
            Path::new("C:/Users/Example/AppData/Temp/renamed.exe"),
            "sha256:changed"
        ));
    }

    #[test]
    fn add_file_entry_records_current_file_hash() {
        let dir = tempfile::tempdir().unwrap();
        let trusted = dir.path().join("trusted.exe");
        fs::write(&trusted, b"trusted-v1").unwrap();
        let mut store = AllowlistStore::in_memory(vec![]);

        let entry = store
            .add(
                AllowlistEntryType::File,
                trusted.display().to_string(),
                "test".to_string(),
            )
            .unwrap();

        assert_eq!(
            entry.sha256.as_deref(),
            Some("sha256:8665eae168c977de7d2a9ccc35bca880b62d3dd69d67ec29bb27d3ca789b5938")
        );
        assert!(store.is_allowlisted(&trusted, entry.sha256.as_deref().unwrap()));
    }

    #[test]
    fn add_file_entry_fails_closed_when_file_cannot_be_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.exe");
        let mut store = AllowlistStore::in_memory(vec![]);

        let err = store
            .add(
                AllowlistEntryType::Executable,
                missing.display().to_string(),
                "test".to_string(),
            )
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("must be hashed before allowlisting"));
        assert!(store.list().is_empty());
    }
}
