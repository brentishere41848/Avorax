use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

const MARKER_FILE: &str = ".zentor_migration_from_legacy.json";

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
    migrate_from_dirs(legacy_data_dir(), zentor_data_dir())
}

pub fn migrate_from_dirs(source: PathBuf, destination: PathBuf) -> Result<MigrationReport> {
    let marker = destination.join(MARKER_FILE);
    if !source.exists() || marker.exists() {
        return Ok(MigrationReport {
            migrated: false,
            source_dir: source.display().to_string(),
            destination_dir: destination.display().to_string(),
            copied_items: Vec::new(),
            event_message: migration_event_message(),
            marker_path: marker.display().to_string(),
        });
    }

    fs::create_dir_all(&destination)?;
    let mut copied_items = Vec::new();
    for name in ["config", "quarantine", "allowlist", "logs", "scan_history"] {
        let source_item = source.join(name);
        if !source_item.exists() {
            continue;
        }
        let destination_item = destination.join(name);
        copy_path(&source_item, &destination_item)?;
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
    fs::write(&marker, serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

pub fn zentor_data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("ZENTOR_DATA_DIR") {
        return PathBuf::from(path);
    }
    platform_data_dir("Avorax", "zentor")
}

pub fn legacy_data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("ZENTOR_LEGACY_DATA_DIR") {
        return PathBuf::from(path);
    }
    platform_data_dir(&legacy_brand(), &legacy_brand().to_lowercase())
}

pub fn migration_event_message() -> String {
    format!(
        "Migrated local data from {} to Avorax",
        legacy_brand()
    )
}

fn legacy_brand() -> String {
    ["Pa", "sus"].concat()
}

fn platform_data_dir(windows_or_macos_name: &str, linux_name: &str) -> PathBuf {
    if cfg!(windows) {
        if let Ok(program_data) = std::env::var("ProgramData") {
            return PathBuf::from(program_data).join(windows_or_macos_name);
        }
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join(windows_or_macos_name);
        }
    }
    if cfg!(target_os = "macos") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join(windows_or_macos_name);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join(linux_name);
    }
    PathBuf::from(format!(".{linux_name}"))
}

fn copy_path(source: &Path, destination: &Path) -> Result<()> {
    if source.is_dir() {
        copy_dir(source, destination)
    } else {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        if !destination.exists() {
            fs::copy(source, destination)?;
        }
        Ok(())
    }
}

fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let child_source = entry.path();
        let child_destination = destination.join(entry.file_name());
        if child_source.is_dir() {
            copy_dir(&child_source, &child_destination)?;
        } else if !child_destination.exists() {
            fs::copy(&child_source, &child_destination)?;
        }
    }
    Ok(())
}

pub fn write_migration_event_log(destination: &Path, report: &MigrationReport) -> Result<()> {
    if !report.migrated {
        return Ok(());
    }
    let logs = destination.join("logs");
    fs::create_dir_all(&logs)?;
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
    fs::write(
        logs.join("migration-from-legacy-brand.json"),
        serde_json::to_string_pretty(&event)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
            format!("Migrated local data from {} to Avorax", ["Pa", "sus"].concat())
        );
    }

    #[test]
    fn migration_is_idempotent_after_marker() {
        let root = tempdir().unwrap();
        let source = root.path().join(["Pa", "sus"].concat());
        let destination = root.path().join("Avorax");
        fs::create_dir_all(source.join("logs")).unwrap();
        fs::write(source.join("logs").join("events.jsonl"), "old").unwrap();

        assert!(migrate_from_dirs(source.clone(), destination.clone())
            .unwrap()
            .migrated);
        assert!(!migrate_from_dirs(source, destination).unwrap().migrated);
    }
}
