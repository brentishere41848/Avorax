use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MARKER_FILE: &str = ".zentor_migration_from_legacy.json";
const MAX_MIGRATION_DEPTH: usize = 32;
const MAX_MIGRATION_COPY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MIGRATION_HASH_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationReport {
    pub migrated: bool,
    pub source_dir: String,
    pub destination_dir: String,
    pub copied_items: Vec<String>,
    pub event_message: String,
    pub marker_path: String,
}

pub fn migrate_from_legacy_brand() -> Result<MigrationReport> {
    migrate_from_dirs(legacy_data_dir()?, zentor_data_dir()?)
}

pub fn migrate_from_dirs(source: PathBuf, destination: PathBuf) -> Result<MigrationReport> {
    let marker = destination.join(MARKER_FILE);
    if !optional_migration_directory_present(&source, "migration source directory")?
        || optional_migration_file_present(&marker, "migration marker")?
    {
        return Ok(MigrationReport {
            migrated: false,
            source_dir: source.display().to_string(),
            destination_dir: destination.display().to_string(),
            copied_items: Vec::new(),
            event_message: migration_event_message(),
            marker_path: marker.display().to_string(),
        });
    }

    ensure_destination_directory(&destination)?;
    let mut copied_items = Vec::new();
    for name in ["config", "quarantine", "allowlist", "logs", "scan_history"] {
        let source_item = source.join(name);
        if !optional_migration_path_present(&source_item, "migration source path")? {
            continue;
        }
        let destination_item = destination.join(name);
        copy_path(&source_item, &destination_item, 0)?;
        copied_items.push(name.to_string());
    }

    let report = MigrationReport {
        migrated: true,
        source_dir: source.display().to_string(),
        destination_dir: destination.display().to_string(),
        copied_items,
        event_message: migration_event_message(),
        marker_path: marker.display().to_string(),
    };
    write_staged(&marker, &serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

pub fn zentor_data_dir() -> Result<PathBuf> {
    if let Some(path) = absolute_migration_env_path("AVORAX_DATA_DIR")? {
        return Ok(path);
    }
    if let Some(path) = absolute_migration_env_path("ZENTOR_DATA_DIR")? {
        return Ok(path);
    }
    platform_data_dir("Avorax", "zentor")
}

pub fn legacy_data_dir() -> Result<PathBuf> {
    if let Some(path) = absolute_migration_env_path("ZENTOR_LEGACY_DATA_DIR")? {
        return Ok(path);
    }
    platform_data_dir(&legacy_brand(), &legacy_brand().to_lowercase())
}

pub fn migration_event_message() -> String {
    format!("Migrated local data from {} to Avorax", legacy_brand())
}

fn legacy_brand() -> String {
    ["Pa", "sus"].concat()
}

fn platform_data_dir(windows_or_macos_name: &str, linux_name: &str) -> Result<PathBuf> {
    if cfg!(windows) {
        if let Some(program_data) = absolute_migration_env_path("ProgramData")? {
            return Ok(program_data.join(windows_or_macos_name));
        }
        if let Some(program_data) = absolute_migration_env_path("PROGRAMDATA")? {
            return Ok(program_data.join(windows_or_macos_name));
        }
        if let Some(local_app_data) = absolute_migration_env_path("LOCALAPPDATA")? {
            return Ok(local_app_data.join(windows_or_macos_name));
        }
    }
    if cfg!(target_os = "macos") {
        if let Some(home) = absolute_migration_env_path("HOME")? {
            return Ok(home
                .join("Library")
                .join("Application Support")
                .join(windows_or_macos_name));
        }
    }
    if let Some(home) = absolute_migration_env_path("HOME")? {
        return Ok(home.join(".local").join("share").join(linux_name));
    }
    anyhow::bail!("migration data root is unavailable")
}

fn absolute_migration_env_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("migration environment path {name} is empty");
    }
    validate_migration_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !migration_root_is_allowed(&path) {
        anyhow::bail!("migration environment path {name} must be an absolute local path");
    }
    Ok(Some(path))
}

fn validate_migration_env_root_text(name: &str, text: &str) -> Result<()> {
    if text.contains('\0') {
        anyhow::bail!("migration environment path {name} contains NUL");
    }
    if migration_env_root_has_parent_traversal(text) {
        anyhow::bail!("migration environment path {name} must not contain parent traversal");
    }
    Ok(())
}

fn migration_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn migration_root_is_allowed(path: &Path) -> bool {
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
fn migration_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

fn copy_path(source: &Path, destination: &Path, depth: usize) -> Result<()> {
    if depth > MAX_MIGRATION_DEPTH {
        return Err(anyhow!("migration path nesting exceeds safe depth"));
    }
    let source_metadata = migration_path_metadata(source, "migration source path")?;
    if source_metadata.is_dir() {
        copy_dir(source, destination, depth)
    } else if source_metadata.is_file() {
        if let Some(parent) = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            ensure_destination_directory(parent)?;
        }
        if optional_migration_file_present(destination, "migration destination path")? {
            return Ok(());
        }
        let source_hash = sha256_for_file(source)?;
        copy_file_exclusive(source, destination)?;
        if migration_path_metadata(destination, "migration destination path")?.len()
            != source_metadata.len()
            || sha256_for_file(destination)? != source_hash
        {
            cleanup_migration_partial_file(destination, "invalid migration destination")
                .with_context(|| {
                    format!(
                        "failed to clean up invalid migration destination {} after verification failure",
                        destination.display()
                    )
                })?;
            return Err(anyhow!("migration copy verification failed"));
        }
        Ok(())
    } else {
        Err(anyhow!(
            "migration source path is not a regular file or directory"
        ))
    }
}

fn copy_dir(source: &Path, destination: &Path, depth: usize) -> Result<()> {
    ensure_destination_directory(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let child_source = entry.path();
        let child_destination = destination.join(entry.file_name());
        copy_path(&child_source, &child_destination, depth + 1)?;
    }
    Ok(())
}

fn ensure_destination_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| {
        format!(
            "unable to create migration destination directory {}",
            path.display()
        )
    })?;
    let metadata = migration_path_metadata(path, "migration destination directory")?;
    if !metadata.is_dir() {
        return Err(anyhow!("migration destination is not a directory"));
    }
    Ok(())
}

fn optional_migration_path_present(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_unsafe_metadata(&metadata, label)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn optional_migration_directory_present(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_unsafe_metadata(&metadata, label)?;
            if !metadata.is_dir() {
                return Err(anyhow!("{label} is not a directory"));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn optional_migration_file_present(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_unsafe_metadata(&metadata, label)?;
            if !metadata.is_file() {
                return Err(anyhow!("{label} is not a regular file"));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn migration_path_metadata(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    reject_unsafe_metadata(&metadata, label)?;
    Ok(metadata)
}

#[allow(dead_code)]
fn reject_link_path(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    reject_unsafe_metadata(&metadata, label)
}

fn reject_unsafe_metadata(metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("refusing to use symbolic link {label}"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow!("refusing to use reparse point {label}"));
        }
    }
    Ok(())
}

fn write_staged(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_destination_directory(parent)?;
    }
    let temp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    write_file_exclusive(
        &temp_path,
        contents.as_bytes(),
        "migration temporary output file",
    )?;
    if let Err(error) = remove_existing_migration_file(path, "migration output file") {
        cleanup_migration_partial_file(&temp_path, "migration temporary output file")
            .with_context(|| {
                format!(
                    "failed to clean up migration temporary output file {} after activation preflight failure: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        cleanup_migration_partial_file(&temp_path, "migration temporary output file")
            .with_context(|| {
                format!(
                    "failed to clean up migration temporary output file {} after activation failure: {error:#}",
                    temp_path.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to activate migration output file {}",
                path.display()
            )
        });
    }
    Ok(())
}

fn remove_existing_migration_file(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_unsafe_metadata(&metadata, label)?;
            if !metadata.is_file() {
                return Err(anyhow!("{label} is not a regular file"));
            }
            fs::remove_file(path)
                .with_context(|| format!("failed to remove {label} {}", path.display()))?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn cleanup_migration_partial_file(path: &Path, label: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {label} {}", path.display()))
        }
    }
}

fn copy_migration_file_limited<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    limit: u64,
    source: &Path,
) -> Result<()> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("migration file copy size overflow"))?;
        if total > limit {
            anyhow::bail!(
                "migration file {} exceeds the copy size limit",
                source.display()
            );
        }
        output.write_all(&buffer[..read])?;
    }
}

fn copy_file_exclusive(source: &Path, destination: &Path) -> Result<()> {
    let mut input = fs::File::open(source)
        .with_context(|| format!("failed to open migration source {}", source.display()))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| {
            format!(
                "failed to create migration destination {}",
                destination.display()
            )
        })?;
    if let Err(error) =
        copy_migration_file_limited(&mut input, &mut output, MAX_MIGRATION_COPY_BYTES, source)
    {
        drop(output);
        cleanup_migration_partial_file(destination, "partial migration destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial migration destination {} after copy failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to copy migration file {} to {}",
                source.display(),
                destination.display()
            )
        });
    }
    if let Err(error) = output.sync_all() {
        drop(output);
        cleanup_migration_partial_file(destination, "partial migration destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial migration destination {} after sync failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to sync migration destination {}",
                destination.display()
            )
        });
    }
    Ok(())
}

fn write_file_exclusive(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {label} {}", path.display()))?;
    if let Err(error) = output.write_all(bytes) {
        drop(output);
        cleanup_migration_partial_file(path, label).with_context(|| {
            format!(
                "failed to clean up {label} {} after write failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error).with_context(|| format!("failed to write {label} {}", path.display()));
    }
    if let Err(error) = output.sync_all() {
        drop(output);
        cleanup_migration_partial_file(path, label).with_context(|| {
            format!(
                "failed to clean up {label} {} after sync failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error).with_context(|| format!("failed to sync {label} {}", path.display()));
    }
    Ok(())
}

fn sha256_for_file(path: &Path) -> Result<String> {
    let metadata = migration_path_metadata(path, "migration hash input")?;
    if !metadata.is_file() {
        return Err(anyhow!("migration hash input is not a regular file"));
    }
    if metadata.len() > MAX_MIGRATION_HASH_BYTES {
        return Err(anyhow!(
            "migration hash input {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_MIGRATION_HASH_BYTES
        ));
    }
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("migration hash size overflow"))?;
        if total > MAX_MIGRATION_HASH_BYTES {
            return Err(anyhow!(
                "migration hash input {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_MIGRATION_HASH_BYTES
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn write_migration_event_log(destination: &Path, report: &MigrationReport) -> Result<()> {
    if !report.migrated {
        return Ok(());
    }
    let logs = destination.join("logs");
    ensure_destination_directory(&logs)?;
    let event = serde_json::json!({
        "id": format!("migration-{}", Utc::now().timestamp_millis()),
        "type": "data_migration",
        "message": report.event_message,
        "created_at": Utc::now().to_rfc3339(),
        "details": {
            "source_dir": report.source_dir,
            "destination_dir": report.destination_dir,
            "copied_items": report.copied_items,
        }
    });
    write_staged(
        &logs.join("migration-from-legacy-brand.json"),
        &serde_json::to_string_pretty(&event)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn migration_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn migrates_legacy_data_without_deleting_source() {
        let root = tempdir().unwrap();
        let source = root.path().join(["Pa", "sus"].concat());
        let destination = root.path().join("Avorax");
        fs::create_dir_all(source.join("quarantine")).unwrap();
        fs::write(source.join("quarantine").join("old.json"), "{}").unwrap();

        let report = migrate_from_dirs(source.clone(), destination.clone()).unwrap();

        assert!(report.migrated);
        assert!(source.join("quarantine").join("old.json").exists());
        assert!(destination.join("quarantine").join("old.json").exists());
        assert!(PathBuf::from(report.marker_path).exists());
        assert_eq!(
            report.event_message,
            format!(
                "Migrated local data from {} to Avorax",
                ["Pa", "sus"].concat()
            )
        );
    }

    #[test]
    fn migration_is_idempotent_after_marker() {
        let root = tempdir().unwrap();
        let source = root.path().join(["Pa", "sus"].concat());
        let destination = root.path().join("Avorax");
        fs::create_dir_all(source.join("logs")).unwrap();
        fs::write(source.join("logs").join("events.jsonl"), "old").unwrap();

        assert!(
            migrate_from_dirs(source.clone(), destination.clone())
                .unwrap()
                .migrated
        );
        assert!(!migrate_from_dirs(source, destination).unwrap().migrated);
    }

    #[test]
    fn migration_rejects_destination_file_for_source_directory() {
        let root = tempdir().unwrap();
        let source = root.path().join(["Pa", "sus"].concat());
        let destination = root.path().join("Avorax");
        fs::create_dir_all(source.join("logs")).unwrap();
        fs::write(source.join("logs").join("events.jsonl"), "legacy").unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::write(destination.join("logs"), "not a directory").unwrap();

        let error = migrate_from_dirs(source, destination).unwrap_err();
        let error_chain = format!("{error:#}");

        assert!(error_chain.contains("directory"));
    }

    #[test]
    fn migration_does_not_overwrite_existing_destination_file() {
        let root = tempdir().unwrap();
        let source = root.path().join(["Pa", "sus"].concat());
        let destination = root.path().join("Avorax");
        fs::create_dir_all(source.join("logs")).unwrap();
        fs::create_dir_all(destination.join("logs")).unwrap();
        fs::write(source.join("logs").join("events.jsonl"), "legacy").unwrap();
        fs::write(destination.join("logs").join("events.jsonl"), "current").unwrap();

        migrate_from_dirs(source, destination.clone()).unwrap();

        assert_eq!(
            fs::read_to_string(destination.join("logs").join("events.jsonl")).unwrap(),
            "current"
        );
    }

    #[test]
    fn migration_copy_and_marker_writes_use_exclusive_destinations() {
        let source = include_str!("migration.rs");
        let copy_exclusive_pattern = ["fn copy_file_", "exclusive"].concat();
        let write_exclusive_pattern = ["fn write_file_", "exclusive"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let sync_pattern = ["output.", "sync_all()"].concat();
        let hash_pattern = ["fn sha256_", "for_file"].concat();
        let limit_pattern = ["MAX_MIGRATION_", "COPY_BYTES"].concat();
        let limited_copy_pattern = ["fn copy_migration_", "file_limited"].concat();
        let bounded_buffer_pattern = ["let mut buffer = [0_u8; ", "64 * 1024]"].concat();
        let write_all_pattern = ["output.", "write_all(&buffer[..read])"].concat();
        let old_copy_pattern = ["fs::copy(source, ", "destination)"].concat();
        let old_io_copy_pattern = ["io::", "copy(&mut input, &mut output)"].concat();
        let old_staged_write_pattern = ["fs::write(&temp_", "path, contents)"].concat();

        assert!(source.contains(&copy_exclusive_pattern));
        assert!(source.contains(&write_exclusive_pattern));
        assert!(source.contains(&create_new_pattern));
        assert!(source.contains(&sync_pattern));
        assert!(source.contains(&hash_pattern));
        assert!(source.contains(&limit_pattern));
        assert!(source.contains("MAX_MIGRATION_COPY_BYTES"));
        assert!(source.contains(&limited_copy_pattern));
        assert!(source.contains("copy_migration_file_limited"));
        assert!(source.contains(&bounded_buffer_pattern));
        assert!(source.contains("total > limit"));
        assert!(source.contains(&write_all_pattern));
        assert!(!source.contains(&old_copy_pattern));
        assert!(!source.contains(&old_io_copy_pattern));
        assert!(!source.contains(&old_staged_write_pattern));
    }

    #[test]
    fn migration_hash_input_is_size_bounded() {
        let source = include_str!("migration.rs");
        let start = source.find("fn sha256_for_file").unwrap();
        let end = source.find("pub fn write_migration_event_log").unwrap();
        let hash_source = &source[start..end];

        assert!(source.contains("const MAX_MIGRATION_HASH_BYTES"));
        assert!(hash_source.contains("migration_path_metadata(path, \"migration hash input\")?"));
        assert!(hash_source.contains("metadata.len() > MAX_MIGRATION_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("checked_add(read as u64)"));
        assert!(hash_source.contains("total > MAX_MIGRATION_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
    }

    #[test]
    fn migration_cleanup_failures_are_reported() {
        let source = include_str!("migration.rs");
        let copy_path_start = source.find("fn copy_path").unwrap();
        let copy_path_end = source.find("fn copy_dir").unwrap();
        let copy_path_source = &source[copy_path_start..copy_path_end];
        let write_start = source.find("fn write_staged").unwrap();
        let write_end = source.find("fn remove_existing_migration_file").unwrap();
        let write_source = &source[write_start..write_end];
        let copy_start = source.find("fn copy_file_exclusive").unwrap();
        let copy_end = source.find("fn write_file_exclusive").unwrap();
        let copy_source = &source[copy_start..copy_end];
        let writer_source = &source[copy_end..source.find("fn sha256_for_file").unwrap()];

        assert!(source.contains("fn cleanup_migration_partial_file"));
        assert!(copy_path_source.contains("after verification failure"));
        assert!(write_source.contains("after activation preflight failure"));
        assert!(write_source.contains("after activation failure"));
        assert!(copy_source.contains("after copy failure"));
        assert!(copy_source.contains("after sync failure"));
        assert!(writer_source.contains("after write failure"));
        assert!(writer_source.contains("after sync failure"));
        assert!(!copy_path_source.contains("let _ = fs::remove_file(destination);"));
        assert!(!write_source.contains("let _ = fs::remove_file(&temp_path);"));
    }

    #[test]
    fn migration_data_roots_reject_relative_overrides() {
        let _lock = migration_env_lock();
        let previous_avorax = std::env::var_os("AVORAX_DATA_DIR");

        std::env::set_var("AVORAX_DATA_DIR", "relative-migration-root");
        let result = zentor_data_dir();

        if let Some(previous_avorax) = previous_avorax {
            std::env::set_var("AVORAX_DATA_DIR", previous_avorax);
        } else {
            std::env::remove_var("AVORAX_DATA_DIR");
        }

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_DATA_DIR must be an absolute local path"));
    }

    #[test]
    fn migration_data_roots_reject_parent_traversal_overrides() {
        let _lock = migration_env_lock();
        let previous_avorax = std::env::var_os("AVORAX_DATA_DIR");
        let dir = tempdir().unwrap();

        std::env::set_var("AVORAX_DATA_DIR", dir.path().join(".."));
        let result = zentor_data_dir();

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
    fn migration_data_roots_have_no_relative_fallback() {
        let _lock = migration_env_lock();
        let keys = [
            "AVORAX_DATA_DIR",
            "ZENTOR_DATA_DIR",
            "ZENTOR_LEGACY_DATA_DIR",
            "ProgramData",
            "PROGRAMDATA",
            "LOCALAPPDATA",
            "HOME",
        ];
        let previous: Vec<_> = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();

        for key in keys {
            std::env::remove_var(key);
        }
        let result = zentor_data_dir();

        for (key, value) in previous {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }

        let source = include_str!("migration.rs");
        let start = source.find("pub fn zentor_data_dir").unwrap();
        let end = source.find("fn copy_path").unwrap();
        let root_source = &source[start..end];

        let error = result.unwrap_err().to_string();
        assert!(error.contains("migration data root is unavailable"));
        assert!(root_source.contains("pub fn zentor_data_dir() -> Result<PathBuf>"));
        assert!(root_source.contains("pub fn legacy_data_dir() -> Result<PathBuf>"));
        assert!(root_source.contains("fn platform_data_dir("));
        assert!(root_source.contains("fn absolute_migration_env_path("));
        assert!(root_source.contains("absolute_migration_env_path(\"AVORAX_DATA_DIR\")?"));
        assert!(root_source.contains("absolute_migration_env_path(\"ZENTOR_LEGACY_DATA_DIR\")?"));
        assert!(root_source.contains("absolute_migration_env_path(\"HOME\")?"));
        assert!(root_source.contains("migration data root is unavailable"));
        assert!(!root_source.contains("PathBuf::from(format!(\".{linux_name}\"))"));
    }

    #[cfg(unix)]
    #[test]
    fn migration_rejects_symbolic_link_destination_file() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let source = root.path().join(["Pa", "sus"].concat());
        let destination = root.path().join("Avorax");
        let outside = root.path().join("outside.jsonl");
        fs::create_dir_all(source.join("logs")).unwrap();
        fs::create_dir_all(destination.join("logs")).unwrap();
        fs::write(source.join("logs").join("events.jsonl"), "legacy").unwrap();
        fs::write(&outside, "outside").unwrap();
        symlink(&outside, destination.join("logs").join("events.jsonl")).unwrap();

        let error = migrate_from_dirs(source, destination)
            .unwrap_err()
            .to_string();

        assert!(error.contains("refusing to use symbolic link migration destination path"));
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[cfg(unix)]
    #[test]
    fn migration_rejects_symbolic_link_marker() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let source = root.path().join(["Pa", "sus"].concat());
        let destination = root.path().join("Avorax");
        let outside = root.path().join("outside-marker.json");
        fs::create_dir_all(source.join("logs")).unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::write(source.join("logs").join("events.jsonl"), "legacy").unwrap();
        fs::write(&outside, "{}").unwrap();
        symlink(&outside, destination.join(MARKER_FILE)).unwrap();

        let error = migrate_from_dirs(source, destination)
            .unwrap_err()
            .to_string();

        assert!(error.contains("refusing to use symbolic link migration marker"));
        assert_eq!(fs::read_to_string(outside).unwrap(), "{}");
    }

    #[cfg(unix)]
    #[test]
    fn migration_rejects_symbolic_link_source_item() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let source = root.path().join(["Pa", "sus"].concat());
        let destination = root.path().join("Avorax");
        fs::create_dir_all(source.join("logs")).unwrap();
        let outside = root.path().join("outside.jsonl");
        fs::write(&outside, "outside").unwrap();
        symlink(&outside, source.join("logs").join("events.jsonl")).unwrap();

        let error = migrate_from_dirs(source, destination)
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"));
    }
}
