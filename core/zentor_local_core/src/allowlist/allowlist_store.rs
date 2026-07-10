use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read, Write};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
#[serde(deny_unknown_fields)]
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

#[derive(Debug)]
pub struct AllowlistStore {
    entries: Vec<AllowlistEntry>,
    path: Option<PathBuf>,
}

const MAX_ALLOWLIST_STORE_BYTES: u64 = 1024 * 1024;
const MAX_ALLOWLIST_HASH_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ALLOWLIST_ID_CHARS: usize = 128;

impl AllowlistStore {
    pub fn new() -> Result<Self> {
        let path = allowlist_file_from_env()?;
        let entries = match path.as_ref() {
            Some(path) => {
                let raw = read_bounded_allowlist_file(path)?;
                let entries: Vec<AllowlistEntry> =
                    serde_json::from_str(&raw).with_context(|| {
                        format!("unable to parse allowlist file {}", path.display())
                    })?;
                validate_loaded_entries(&entries)
                    .with_context(|| format!("invalid allowlist file {}", path.display()))?;
                entries
            }
            None => Vec::new(),
        };
        Ok(Self { entries, path })
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

    pub fn deactivate(&mut self, id: &str) -> Result<AllowlistEntry> {
        validate_allowlist_id(id)?;
        let Some(entry) = self.entries.iter_mut().find(|entry| entry.id == id) else {
            return Err(anyhow!("allowlist entry not found"));
        };
        entry.active = false;
        let entry = entry.clone();
        self.save()?;
        Ok(entry)
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
                fs::create_dir_all(parent).with_context(|| {
                    format!("unable to create allowlist directory {}", parent.display())
                })?;
                ensure_allowlist_directory(parent)?;
            }
            let data = serde_json::to_vec_pretty(&self.entries)?;
            write_allowlist_store_staged(path, &data)?;
        }
        Ok(())
    }
}

fn allowlist_file_from_env() -> Result<Option<PathBuf>> {
    match std::env::var("ZENTOR_ALLOWLIST_FILE") {
        Ok(path) => Ok(Some(validate_allowlist_file_env_path(
            "ZENTOR_ALLOWLIST_FILE",
            &path,
        )?)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(anyhow!(
            "invalid ZENTOR_ALLOWLIST_FILE environment value: {error}"
        )),
    }
}

fn validate_allowlist_file_env_path(name: &str, raw: &str) -> Result<PathBuf> {
    let text = raw.trim();
    if text.is_empty() {
        return Err(anyhow!("{name} environment path must not be empty"));
    }
    if text.contains('\0') {
        return Err(anyhow!("{name} environment path must not contain NUL"));
    }
    if allowlist_env_path_has_parent_traversal(text) {
        return Err(anyhow!(
            "{name} environment path must not contain parent traversal"
        ));
    }
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        return Err(anyhow!("{name} environment path must be absolute"));
    }
    if !allowlist_env_path_is_local(&path) {
        return Err(anyhow!("{name} environment path must be local"));
    }
    Ok(path)
}

fn allowlist_env_path_has_parent_traversal(value: &str) -> bool {
    value.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn allowlist_env_path_is_local(path: &Path) -> bool {
    use std::path::Prefix;

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn allowlist_env_path_is_local(path: &Path) -> bool {
    path.is_absolute()
}

fn write_allowlist_store_staged(path: &Path, data: &[u8]) -> Result<()> {
    ensure_replaceable_allowlist_file(path)?;
    let temp_path = allocate_allowlist_temp_path(path)?;
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .with_context(|| {
                format!(
                    "unable to create temporary allowlist file {}",
                    temp_path.display()
                )
            })?;
        file.write_all(data).with_context(|| {
            format!(
                "unable to write temporary allowlist file {}",
                temp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "unable to flush temporary allowlist file {}",
                temp_path.display()
            )
        })?;
        Ok(())
    })();
    if let Err(error) = write_result {
        cleanup_allowlist_temp_file(&temp_path).with_context(|| {
            format!(
                "unable to clean up temporary allowlist file {} after write failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }

    if let Err(error) = remove_existing_allowlist_file(path) {
        cleanup_allowlist_temp_file(&temp_path).with_context(|| {
            format!(
                "unable to clean up temporary allowlist file {} after activation preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        cleanup_allowlist_temp_file(&temp_path).with_context(|| {
            format!(
                "unable to clean up temporary allowlist file {} after activation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error).with_context(|| {
            format!(
                "unable to activate allowlist file {} from {}",
                path.display(),
                temp_path.display()
            )
        });
    }
    Ok(())
}

fn cleanup_allowlist_temp_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to remove temporary allowlist file {}",
                path.display()
            )
        }),
    }
}

fn allocate_allowlist_temp_path(path: &Path) -> Result<PathBuf> {
    let parent = allowlist_temp_parent(path);
    let file_name = allowlist_temp_file_name(path)?;
    let nonce = allowlist_temp_nonce()?;
    for attempt in 0..32_u8 {
        let candidate = parent.join(format!(
            "{file_name}.{}.{}.{}.tmp",
            std::process::id(),
            nonce,
            attempt
        ));
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                reject_link_or_reparse_metadata(&candidate, &metadata, "temporary allowlist file")?;
                if metadata.file_type().is_file() {
                    continue;
                }
                return Err(anyhow!(
                    "temporary allowlist path {} is not a regular file",
                    candidate.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "unable to inspect temporary allowlist file {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    Err(anyhow!(
        "unable to allocate temporary allowlist file for {}",
        path.display()
    ))
}

fn allowlist_temp_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) => parent,
        None => Path::new("."),
    }
}

fn allowlist_temp_file_name(path: &Path) -> Result<&str> {
    let Some(file_name) = path.file_name() else {
        return Err(anyhow!(
            "allowlist file {} has no file name for temporary staging",
            path.display()
        ));
    };
    let Some(file_name) = file_name.to_str() else {
        return Err(anyhow!(
            "allowlist file {} has a non-Unicode file name for temporary staging",
            path.display()
        ));
    };
    if file_name.is_empty() {
        return Err(anyhow!(
            "allowlist file {} has an empty file name for temporary staging",
            path.display()
        ));
    }
    Ok(file_name)
}

fn allowlist_temp_nonce() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context(
            "system time is before UNIX_EPOCH; cannot allocate allowlist temporary file nonce",
        )?
        .as_nanos())
}

fn ensure_allowlist_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect allowlist directory {}", path.display()))?;
    reject_link_or_reparse_metadata(path, &metadata, "allowlist directory")?;
    if !metadata.file_type().is_dir() {
        return Err(anyhow!(
            "allowlist directory {} is not a directory",
            path.display()
        ));
    }
    Ok(())
}

fn ensure_replaceable_allowlist_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_link_or_reparse_metadata(path, &metadata, "allowlist file")?;
            if !metadata.file_type().is_file() {
                return Err(anyhow!(
                    "allowlist file {} is not a regular file",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect allowlist file {}", path.display())),
    }
}

fn remove_existing_allowlist_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_link_or_reparse_metadata(path, &metadata, "allowlist file")?;
            if !metadata.file_type().is_file() {
                return Err(anyhow!(
                    "allowlist file {} is not a regular file",
                    path.display()
                ));
            }
            fs::remove_file(path)
                .with_context(|| format!("unable to replace allowlist file {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect allowlist file {}", path.display())),
    }
}

fn reject_link_or_reparse_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("{label} {} is a symbolic link", path.display()));
    }
    if is_windows_reparse_point(metadata) {
        return Err(anyhow!("{label} {} is a reparse point", path.display()));
    }
    Ok(())
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

fn read_bounded_allowlist_file(path: &Path) -> Result<String> {
    let metadata = ensure_readable_allowlist_file(path)?;
    if metadata.len() > MAX_ALLOWLIST_STORE_BYTES {
        return Err(anyhow!(
            "allowlist file {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_ALLOWLIST_STORE_BYTES
        ));
    }
    let file = fs::File::open(path)
        .with_context(|| format!("unable to read allowlist file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("unable to read allowlist file {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("allowlist file {} size overflow", path.display()))?;
        if total > MAX_ALLOWLIST_STORE_BYTES {
            return Err(anyhow!(
                "allowlist file {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_ALLOWLIST_STORE_BYTES
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("unable to read allowlist file {}", path.display()))
}

fn ensure_readable_allowlist_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect allowlist file {}", path.display()))?;
    reject_link_or_reparse_metadata(path, &metadata, "allowlist file")?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "allowlist file {} is not a regular file",
            path.display()
        ));
    }
    Ok(metadata)
}

fn hash_required_for_entry(entry_type: &AllowlistEntryType, path: &Path) -> Result<Option<String>> {
    match entry_type {
        AllowlistEntryType::File | AllowlistEntryType::App | AllowlistEntryType::Executable => {
            ensure_hashable_allowlist_entry_file(path).with_context(|| {
                format!(
                    "file/app/executable allowlist entries must be hashed before allowlisting: {}",
                    path.display()
                )
            })?;
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

fn ensure_hashable_allowlist_entry_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect allowlist entry file {}", path.display()))?;
    reject_link_or_reparse_metadata(path, &metadata, "allowlist entry file")?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "allowlist entry file {} is not a regular file",
            path.display()
        ));
    }
    Ok(metadata)
}

fn sha256_file(path: &Path) -> Result<String> {
    let metadata = ensure_hashable_allowlist_entry_file(path)?;
    if metadata.len() > MAX_ALLOWLIST_HASH_BYTES {
        return Err(anyhow!(
            "allowlist entry file {} exceeds maximum hash size of {} bytes",
            path.display(),
            MAX_ALLOWLIST_HASH_BYTES
        ));
    }
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("allowlist entry hash size overflow"))?;
        if total > MAX_ALLOWLIST_HASH_BYTES {
            return Err(anyhow!(
                "allowlist entry file {} exceeds maximum hash size of {} bytes",
                path.display(),
                MAX_ALLOWLIST_HASH_BYTES
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn normalize_entry_path(path: &str) -> String {
    let path_text = path.replace('\\', "/").to_ascii_lowercase();
    collapse_allowlist_path_segments(&path_text)
}

fn normalize_path_text(path: &Path) -> String {
    normalize_entry_path(&path.display().to_string())
}

fn normalize_hash_text(hash: &str) -> String {
    let normalized = hash.trim().to_ascii_lowercase();
    normalized_sha256_body(&normalized).to_string()
}

fn is_valid_sha256(hash: &str) -> bool {
    let normalized = normalize_hash_text(hash);
    let raw = normalized_sha256_body(&normalized);
    raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn normalized_sha256_body(normalized: &str) -> &str {
    match normalized.strip_prefix("sha256:") {
        Some(raw) => raw,
        None => normalized,
    }
}

fn validate_loaded_entries(entries: &[AllowlistEntry]) -> Result<()> {
    for entry in entries {
        validate_allowlist_id(&entry.id)?;
        match entry.entry_type {
            AllowlistEntryType::Hash => {
                let candidate = hash_allowlist_entry_sha256_candidate(entry);
                if !is_valid_sha256(candidate) {
                    return Err(anyhow!("hash allowlist entry has malformed SHA-256"));
                }
            }
            AllowlistEntryType::Folder => {
                validate_path(&entry.path)?;
            }
            AllowlistEntryType::File | AllowlistEntryType::App | AllowlistEntryType::Executable => {
                validate_path(&entry.path)?;
                let Some(hash) = entry.sha256.as_deref() else {
                    return Err(anyhow!("file allowlist entry is missing SHA-256"));
                };
                if !is_valid_sha256(hash) {
                    return Err(anyhow!("file allowlist entry has malformed SHA-256"));
                }
            }
        }
    }
    Ok(())
}

fn validate_allowlist_id(id: &str) -> Result<()> {
    if id.trim().is_empty() {
        return Err(anyhow!("allowlist id is required"));
    }
    if id.trim() != id {
        return Err(anyhow!(
            "allowlist id contains leading or trailing whitespace"
        ));
    }
    if id.chars().count() > MAX_ALLOWLIST_ID_CHARS {
        return Err(anyhow!("allowlist id exceeds maximum length"));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(anyhow!(
            "invalid allowlist id; only ASCII letters, digits, hyphen, and underscore are allowed"
        ));
    }
    Ok(())
}

fn hash_allowlist_entry_sha256_candidate(entry: &AllowlistEntry) -> &str {
    match entry.sha256.as_deref() {
        Some(hash) => hash,
        None => &entry.path,
    }
}

fn path_matches_folder(path: &str, folder: &str) -> bool {
    !folder.is_empty() && (path == folder || path.starts_with(&format!("{folder}/")))
}

pub fn validate_path(path: &str) -> Result<()> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("allowlist path is empty"));
    }
    let normalized = normalize_allowlist_root_text(trimmed);
    if is_blocked_allowlist_root(&normalized) {
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

fn normalize_allowlist_root_text(path: &str) -> String {
    normalize_entry_path(path.trim())
}

fn collapse_allowlist_path_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }

    let (prefix, rest, absolute) = split_allowlist_path_prefix(trimmed);
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('/') {
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

    let body = segments.join("/");
    match (prefix, absolute, body.is_empty()) {
        (Some(prefix), _, true) => prefix.to_string(),
        (Some(prefix), _, false) => format!("{prefix}/{body}"),
        (None, true, true) => "/".to_string(),
        (None, true, false) => format!("/{body}"),
        (None, false, _) => body,
    }
}

fn split_allowlist_path_prefix(path: &str) -> (Option<&str>, &str, bool) {
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'/' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with('/') {
        return (None, path.trim_start_matches('/'), true);
    }
    (None, path, false)
}

fn is_blocked_allowlist_root(normalized: &str) -> bool {
    if is_windows_drive_root(normalized) {
        return true;
    }
    if let Some(rest) = windows_drive_absolute_rest(normalized) {
        return matches!(
            rest,
            "windows" | "program files" | "program files (x86)" | "programdata" | "users"
        );
    }
    matches!(
        normalized,
        "/system" | "/usr" | "/" | "/bin" | "/sbin" | "/etc"
    )
}

fn is_windows_drive_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() == 2 || (bytes.len() == 3 && bytes[2] == b'/'))
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
}

fn windows_drive_absolute_rest(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        Some(&path[3..])
    } else {
        None
    }
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
        assert!(validate_path("C:\\Program Files").is_err());
        assert!(validate_path("C:\\Program Files (x86)").is_err());
        assert!(validate_path("C:\\ProgramData").is_err());
        assert!(validate_path("C:\\Users").is_err());
        assert!(validate_path("C:\\\\Windows").is_err());
        assert!(validate_path("D://ProgramData").is_err());
        assert!(validate_path("D:\\").is_err());
        assert!(validate_path("D:\\Windows").is_err());
        assert!(validate_path("D:\\Program Files").is_err());
        assert!(validate_path("/usr//").is_err());
        assert!(validate_path("C:\\Users\\Example\\..\\..\\Windows").is_err());
        assert!(validate_path("/home/example/../../usr").is_err());
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
    fn folder_allowlist_does_not_match_traversal_outside_folder() {
        let store = AllowlistStore::in_memory(vec![entry(
            AllowlistEntryType::Folder,
            "C:/Users/Example/Trusted",
            None,
        )]);

        assert!(!store.is_allowlisted(
            Path::new("C:/Users/Example/Trusted/../Temp/payload.exe"),
            "sha256:any-payload"
        ));
        assert!(store.is_allowlisted(
            Path::new("C:/Users/Example/Trusted/./Tools/../tool.exe"),
            "sha256:any-payload"
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

        let error_chain = format!("{err:#}");
        assert!(error_chain.contains("must be hashed before allowlisting"));
        assert!(store.list().is_empty());
    }

    #[test]
    fn add_file_entry_rejects_directory_before_hashing() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("selected.exe");
        fs::create_dir(&selected).unwrap();
        let mut store = AllowlistStore::in_memory(vec![]);

        let error = store
            .add(
                AllowlistEntryType::File,
                selected.display().to_string(),
                "test".to_string(),
            )
            .unwrap_err();
        let error_chain = format!("{error:#}");

        assert!(error_chain.contains("allowlist entry file"));
        assert!(error_chain.contains("not a regular file"));
        assert!(store.list().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn add_file_entry_rejects_symbolic_link_before_hashing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let selected = dir.path().join("selected.exe");
        fs::write(&target, b"trusted-v1").unwrap();
        std::os::unix::fs::symlink(&target, &selected).unwrap();
        let mut store = AllowlistStore::in_memory(vec![]);

        let error = store
            .add(
                AllowlistEntryType::Executable,
                selected.display().to_string(),
                "test".to_string(),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("allowlist entry file"));
        assert!(error.contains("symbolic link"));
        assert_eq!(fs::read(&target).unwrap(), b"trusted-v1");
        assert!(store.list().is_empty());
    }

    #[test]
    fn deactivate_marks_entry_inactive_without_deleting_history() {
        let mut store = AllowlistStore::in_memory(vec![entry(
            AllowlistEntryType::Hash,
            "sha256:trusted",
            Some("sha256:trusted"),
        )]);

        let deactivated = store.deactivate("test-entry").unwrap();

        assert!(!deactivated.active);
        assert_eq!(store.list().len(), 1);
        assert!(!store.is_allowlisted(Path::new("C:/Users/Example/tool.exe"), "sha256:trusted"));
    }

    #[test]
    fn deactivate_rejects_unsafe_allowlist_ids_before_lookup() {
        let mut store = AllowlistStore::in_memory(vec![entry(
            AllowlistEntryType::Hash,
            "sha256:trusted",
            Some("sha256:trusted"),
        )]);

        let blank = store.deactivate("").unwrap_err();
        assert!(blank.to_string().contains("allowlist id is required"));

        let spaced = store.deactivate(" test-entry").unwrap_err();
        assert!(spaced
            .to_string()
            .contains("leading or trailing whitespace"));

        for unsafe_id in ["../entry", r"..\entry", "bad/id", "bad.id"] {
            let error = store.deactivate(unsafe_id).unwrap_err();
            assert!(error.to_string().contains("invalid allowlist id"));
        }
    }

    #[test]
    fn loaded_allowlist_entries_reject_unsafe_ids() {
        let mut bad = entry(
            AllowlistEntryType::Hash,
            "sha256:trusted",
            Some("sha256:trusted"),
        );
        bad.id = "bad/id".to_string();

        let error = validate_loaded_entries(&[bad]).unwrap_err();

        assert!(error.to_string().contains("invalid allowlist id"));
    }

    #[test]
    fn allowlist_id_validation_is_not_a_dead_action_control() {
        let source = include_str!("allowlist_store.rs");
        let deactivate_start = source.find("pub fn deactivate").unwrap();
        let is_allowlisted_start = source.find("pub fn is_allowlisted").unwrap();
        let deactivate_source = &source[deactivate_start..is_allowlisted_start];

        assert!(source.contains("fn validate_allowlist_id"));
        assert!(source.contains("const MAX_ALLOWLIST_ID_CHARS: usize = 128;"));
        assert!(deactivate_source.contains("validate_allowlist_id(id)?"));
        assert!(source.contains("validate_allowlist_id(&entry.id)?"));
    }

    #[test]
    fn save_uses_staged_write_without_temp_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("allowlist.json");
        fs::write(&store_path, "[]").unwrap();
        let trusted = dir.path().join("trusted.exe");
        fs::write(&trusted, b"trusted-v1").unwrap();
        let mut store = AllowlistStore {
            entries: Vec::new(),
            path: Some(store_path.clone()),
        };

        store
            .add(
                AllowlistEntryType::File,
                trusted.display().to_string(),
                "test".to_string(),
            )
            .unwrap();

        assert!(store_path.exists());
        let leftovers: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .filter(|name| name.starts_with("allowlist.json.") && name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
        let raw = fs::read_to_string(store_path).unwrap();
        assert!(raw.contains("trusted.exe"));
    }

    #[test]
    fn allowlist_env_path_errors_are_not_hidden() {
        let source = include_str!("allowlist_store.rs");
        let new_start = source.find("pub fn new() -> Result<Self>").unwrap();
        let new_end = source.find("pub fn in_memory").unwrap();
        let new_source = &source[new_start..new_end];

        assert!(new_source.contains("let path = allowlist_file_from_env()?;"));
        assert!(source.contains("fn allowlist_file_from_env() -> Result<Option<PathBuf>>"));
        assert!(source.contains("invalid ZENTOR_ALLOWLIST_FILE environment value"));
        assert!(!new_source.contains(".ok()"));
    }

    #[test]
    fn allowlist_env_path_rejects_unsafe_text_before_path_use() {
        let dir = tempfile::tempdir().unwrap();
        let traversal = dir.path().join("..").join("allowlist.json");
        let traversal_error = validate_allowlist_file_env_path(
            "ZENTOR_ALLOWLIST_FILE",
            &traversal.display().to_string(),
        )
        .unwrap_err()
        .to_string();
        let nul_error =
            validate_allowlist_file_env_path("ZENTOR_ALLOWLIST_FILE", "/tmp/allow\0list.json")
                .unwrap_err()
                .to_string();
        let relative_error =
            validate_allowlist_file_env_path("ZENTOR_ALLOWLIST_FILE", "relative/allowlist.json")
                .unwrap_err()
                .to_string();

        assert!(traversal_error.contains("must not contain parent traversal"));
        assert!(nul_error.contains("must not contain NUL"));
        assert!(relative_error.contains("must be absolute"));
    }

    #[test]
    fn allowlist_staged_cleanup_failures_are_reported() {
        let source = include_str!("allowlist_store.rs");
        let start = source.find("fn write_allowlist_store_staged").unwrap();
        let end = source.find("fn allocate_allowlist_temp_path").unwrap();
        let write_source = &source[start..end];
        let ignored_cleanup = ["let _ = fs::remove_", "file(&temp_path);"].concat();

        assert!(write_source.contains("fn cleanup_allowlist_temp_file"));
        assert!(write_source.contains("after write failure"));
        assert!(write_source.contains("after activation preflight failure"));
        assert!(write_source.contains("after activation failure"));
        assert!(!write_source.contains(&ignored_cleanup));
    }

    #[test]
    fn allowlist_file_hashing_is_size_bounded() {
        let source = include_str!("allowlist_store.rs");
        let start = source.find("fn sha256_file").unwrap();
        let end = source.find("fn normalize_entry_path").unwrap();
        let hash_source = &source[start..end];

        assert!(source.contains("const MAX_ALLOWLIST_HASH_BYTES"));
        assert!(hash_source.contains("ensure_hashable_allowlist_entry_file(path)?"));
        assert!(hash_source.contains("metadata.len() > MAX_ALLOWLIST_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("checked_add(read as u64)"));
        assert!(hash_source.contains("total > MAX_ALLOWLIST_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
    }

    #[test]
    fn allowlist_temp_path_defaults_are_explicit_branches() {
        let source = include_str!("allowlist_store.rs");
        let start = source.find("fn allocate_allowlist_temp_path").unwrap();
        let end = source.find("fn ensure_allowlist_directory").unwrap();
        let allocation_source = &source[start..end];

        assert!(allocation_source.contains("let parent = allowlist_temp_parent(path);"));
        assert!(allocation_source.contains("let file_name = allowlist_temp_file_name(path)?;"));
        assert!(allocation_source.contains("let nonce = allowlist_temp_nonce()?;"));
        assert!(allocation_source.contains("Some(parent) => parent"));
        assert!(allocation_source.contains("None => Path::new(\".\")"));
        assert!(allocation_source.contains("has no file name for temporary staging"));
        assert!(allocation_source.contains("non-Unicode file name"));
        assert!(allocation_source.contains("system time is before UNIX_EPOCH"));
        assert!(!allocation_source.contains(".unwrap_or_else(|| Path::new(\".\"))"));
        assert!(!allocation_source.contains(".unwrap_or(\"allowlist\")"));
        assert!(!allocation_source.contains(".unwrap_or(0)"));
    }

    #[test]
    fn allowlist_temp_path_rejects_missing_file_name() {
        let error = allowlist_temp_file_name(Path::new("/"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("has no file name for temporary staging"));
    }

    #[test]
    fn save_rejects_directory_target() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("allowlist.json");
        fs::create_dir(&store_path).unwrap();
        let store = AllowlistStore {
            entries: Vec::new(),
            path: Some(store_path),
        };

        let error = store.save().unwrap_err().to_string();

        assert!(error.contains("allowlist file"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn save_rejects_symbolic_link_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let store_path = dir.path().join("allowlist.json");
        fs::write(&target, "sentinel").unwrap();
        std::os::unix::fs::symlink(&target, &store_path).unwrap();
        let store = AllowlistStore {
            entries: vec![entry(
                AllowlistEntryType::Hash,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            )],
            path: Some(store_path),
        };

        let error = store.save().unwrap_err().to_string();

        assert!(error.contains("symbolic link"));
        assert_eq!(fs::read_to_string(target).unwrap(), "sentinel");
    }

    #[test]
    fn loading_allowlist_rejects_malformed_persisted_hash_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("allowlist.json");
        fs::write(
            &store_path,
            r#"[{"id":"bad-hash","entry_type":"hash","path":"not-a-sha256","sha256":null,"reason":"test","created_at":"2024-01-01T00:00:00Z","created_by":"test","active":true}]"#,
        )
        .unwrap();
        std::env::set_var("ZENTOR_ALLOWLIST_FILE", &store_path);

        let error = AllowlistStore::new().unwrap_err();
        let error_chain = format!("{error:#}");

        std::env::remove_var("ZENTOR_ALLOWLIST_FILE");
        assert!(error_chain.contains("invalid allowlist file"));
        assert!(error_chain.contains("hash allowlist entry has malformed SHA-256"));
    }

    #[test]
    fn loading_allowlist_rejects_unknown_entry_fields() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("allowlist.json");
        fs::write(
            &store_path,
            r#"[{"id":"unknown-field","entry_type":"hash","path":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256":null,"reason":"test","created_at":"2024-01-01T00:00:00Z","created_by":"test","active":true,"allow_all":true}]"#,
        )
        .unwrap();
        std::env::set_var("ZENTOR_ALLOWLIST_FILE", &store_path);

        let error = AllowlistStore::new().unwrap_err().to_string();

        std::env::remove_var("ZENTOR_ALLOWLIST_FILE");
        assert!(error.contains("unable to parse allowlist file"));
    }

    #[test]
    fn allowlist_entry_schema_stays_strict() {
        let source = include_str!("allowlist_store.rs");
        let entry_start = source.find("pub struct AllowlistEntry").unwrap();
        let store_start = source.find("pub struct AllowlistStore").unwrap();
        let load_start = source.find("pub fn new() -> Result<Self>").unwrap();
        let in_memory_start = source.find("pub fn in_memory").unwrap();
        let load_source = &source[load_start..in_memory_start];

        assert!(source[..entry_start].contains("#[serde(deny_unknown_fields)]"));
        assert!(source[entry_start..store_start].contains("pub active: bool"));
        assert!(load_source.contains("serde_json::from_str(&raw)"));
        assert!(load_source.contains("unable to parse allowlist file"));
    }

    #[test]
    fn hash_allowlist_entry_sha256_candidate_defaults_are_explicit() {
        let raw = "a".repeat(64);
        let prefixed = format!("sha256:{}", "b".repeat(64));
        let legacy = entry(AllowlistEntryType::Hash, &raw, None);
        let explicit = entry(AllowlistEntryType::Hash, "legacy-path", Some(&prefixed));
        let blank_explicit = entry(AllowlistEntryType::Hash, &raw, Some(" "));
        let source = include_str!("allowlist_store.rs");
        let start = source.find("fn is_valid_sha256").unwrap();
        let end = source.find("fn path_matches_folder").unwrap();
        let validation_source = &source[start..end];

        assert!(is_valid_sha256(&raw));
        assert!(is_valid_sha256(&prefixed));
        assert_eq!(
            hash_allowlist_entry_sha256_candidate(&legacy),
            legacy.path.as_str()
        );
        assert_eq!(
            hash_allowlist_entry_sha256_candidate(&explicit),
            prefixed.as_str()
        );
        assert!(validate_loaded_entries(&[legacy, explicit]).is_ok());
        assert!(validate_loaded_entries(&[blank_explicit]).is_err());
        assert!(validation_source.contains("match normalized.strip_prefix(\"sha256:\")"));
        assert!(validation_source.contains("Some(raw) => raw"));
        assert!(validation_source.contains("None => normalized"));
        assert!(validation_source.contains("match entry.sha256.as_deref()"));
        assert!(validation_source.contains("Some(hash) => hash"));
        assert!(validation_source.contains("None => &entry.path"));
        assert!(!validation_source.contains(".strip_prefix(\"sha256:\").unwrap_or"));
        assert!(!validation_source.contains(".sha256.as_deref().unwrap_or(&entry.path)"));
    }

    #[test]
    fn loading_allowlist_rejects_path_entries_without_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("allowlist.json");
        fs::write(
            &store_path,
            r#"[{"id":"missing-hash","entry_type":"file","path":"C:/Users/Example/Downloads/tool.exe","sha256":null,"reason":"test","created_at":"2024-01-01T00:00:00Z","created_by":"test","active":true}]"#,
        )
        .unwrap();
        std::env::set_var("ZENTOR_ALLOWLIST_FILE", &store_path);

        let error = AllowlistStore::new().unwrap_err();
        let error_chain = format!("{error:#}");

        std::env::remove_var("ZENTOR_ALLOWLIST_FILE");
        assert!(error_chain.contains("invalid allowlist file"));
        assert!(error_chain.contains("file allowlist entry is missing SHA-256"));
    }

    #[test]
    fn loading_allowlist_rejects_oversized_file_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("allowlist.json");
        fs::write(
            &store_path,
            "x".repeat(MAX_ALLOWLIST_STORE_BYTES as usize + 1),
        )
        .unwrap();

        let error = read_bounded_allowlist_file(&store_path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("allowlist file"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn loading_allowlist_rejects_directory_before_read() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("allowlist.json");
        fs::create_dir(&store_path).unwrap();

        let error = read_bounded_allowlist_file(&store_path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("allowlist file"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn loading_allowlist_rejects_symbolic_link_before_read() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let store_path = dir.path().join("allowlist.json");
        fs::write(&target, "[]").unwrap();
        std::os::unix::fs::symlink(&target, &store_path).unwrap();

        let error = read_bounded_allowlist_file(&store_path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn allowlist_store_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("allowlist_store.rs");
        let reader = &source[source.find("fn read_bounded_allowlist_file").unwrap()
            ..source.find("fn hash_required_for_entry").unwrap()];

        assert!(reader.contains("let metadata = ensure_readable_allowlist_file(path)?"));
        assert!(reader.contains("metadata.len() > MAX_ALLOWLIST_STORE_BYTES"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > MAX_ALLOWLIST_STORE_BYTES"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
        assert!(source
            .contains("fn ensure_readable_allowlist_file(path: &Path) -> Result<fs::Metadata>"));
    }
}
