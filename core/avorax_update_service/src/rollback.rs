use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::logging::program_data_dir;

pub fn rollback_root() -> PathBuf {
    program_data_dir().join("updates").join("rollback")
}

pub fn create_snapshot(install_dir: &Path, version: &str) -> Result<PathBuf> {
    let snapshot = rollback_root().join(version);
    if snapshot.exists() {
        std::fs::remove_dir_all(&snapshot)?;
    }
    std::fs::create_dir_all(&snapshot)?;
    for item in [
        "Avorax.exe",
        "avorax_core_service.exe",
        "avorax_guard_service.exe",
        "engine",
    ] {
        let source = install_dir.join(item);
        if source.is_file() {
            std::fs::copy(&source, snapshot.join(item))?;
        } else if source.is_dir() {
            copy_dir(&source, &snapshot.join(item))?;
        }
    }
    Ok(snapshot)
}

pub fn restore_latest_snapshot(install_dir: &Path) -> Result<PathBuf> {
    let root = rollback_root();
    let mut snapshots = Vec::new();
    if root.exists() {
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                snapshots.push((metadata.modified()?, entry.path()));
            }
        }
    }
    snapshots.sort_by(|left, right| right.0.cmp(&left.0));
    let snapshot = snapshots
        .into_iter()
        .map(|(_, path)| path)
        .next()
        .context("No Avorax rollback snapshot is available.")?;
    for item in [
        "Avorax.exe",
        "avorax_core_service.exe",
        "avorax_guard_service.exe",
        "engine",
    ] {
        let source = snapshot.join(item);
        let target = install_dir.join(item);
        if source.is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&source, &target)?;
        } else if source.is_dir() {
            if target.exists() {
                std::fs::remove_dir_all(&target)?;
            }
            copy_dir(&source, &target)?;
        }
    }
    Ok(snapshot)
}

fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
