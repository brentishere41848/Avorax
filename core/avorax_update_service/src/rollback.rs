use anyhow::Result;
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
    for item in ["Avorax.exe", "avorax_core_service.exe", "avorax_guard_service.exe", "engine"] {
        let source = install_dir.join(item);
        if source.is_file() {
            std::fs::copy(&source, snapshot.join(item))?;
        } else if source.is_dir() {
            copy_dir(&source, &snapshot.join(item))?;
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
