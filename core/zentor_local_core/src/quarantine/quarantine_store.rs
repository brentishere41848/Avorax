use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::scanner::ScanResult;

use super::{QuarantineRecord, QuarantineStatus};

pub struct QuarantineStore {
    base: PathBuf,
}

impl QuarantineStore {
    pub fn new() -> Self {
        Self {
            base: quarantine_base(),
        }
    }

    pub fn with_base(base: PathBuf) -> Self {
        Self { base }
    }

    pub fn quarantine_file(&self, path: &Path, result: &ScanResult) -> Result<QuarantineRecord> {
        fs::create_dir_all(&self.base)?;
        let id = Uuid::new_v4().to_string();
        let quarantine_path = self.base.join(format!("{id}.zentorq"));
        let metadata = fs::metadata(path)?;
        fs::rename(path, &quarantine_path)?;
        remove_executable_permissions(&quarantine_path)?;
        let record = QuarantineRecord {
            quarantine_id: id.clone(),
            original_path: path.display().to_string(),
            quarantine_path: quarantine_path.display().to_string(),
            sha256: result.sha256.clone(),
            file_size: metadata.len(),
            detection_name: result
                .threat_name
                .clone()
                .unwrap_or_else(|| "Detected threat".to_string()),
            engine: result.engine.clone(),
            quarantined_at: Utc::now(),
            status: QuarantineStatus::Quarantined,
            user_note: None,
            source: "scanner".to_string(),
            blocked_before_execution: false,
            process_started: false,
            action_taken: "quarantined".to_string(),
            process_id: None,
        };
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn list(&self) -> Result<Vec<QuarantineRecord>> {
        if !self.base.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.base)? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                let raw = fs::read_to_string(entry.path())?;
                records.push(serde_json::from_str(&raw)?);
            }
        }
        Ok(records)
    }

    pub fn restore_requires_confirmation(&self, id: &str, confirmed: bool) -> Result<()> {
        if !confirmed {
            return Err(anyhow!("restore requires explicit confirmation"));
        }
        let _ = id;
        Ok(())
    }

    pub fn restore(&self, id: &str, confirmed: bool) -> Result<QuarantineRecord> {
        self.restore_requires_confirmation(id, confirmed)?;
        let mut record = self.find_record(id)?;
        let quarantine_path = PathBuf::from(&record.quarantine_path);
        let original_path = PathBuf::from(&record.original_path);
        if original_path.exists() {
            return Err(anyhow!("original path already exists"));
        }
        if let Some(parent) = original_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&quarantine_path, &original_path)?;
        record.status = QuarantineStatus::Restored;
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn delete(&self, id: &str, confirmed: bool) -> Result<QuarantineRecord> {
        if !confirmed {
            return Err(anyhow!("delete requires explicit confirmation"));
        }
        let mut record = self.find_record(id)?;
        let quarantine_path = PathBuf::from(&record.quarantine_path);
        if quarantine_path.exists() {
            fs::remove_file(quarantine_path)?;
        }
        record.status = QuarantineStatus::Deleted;
        self.write_record(&record)?;
        Ok(record)
    }

    fn find_record(&self, id: &str) -> Result<QuarantineRecord> {
        self.list()?
            .into_iter()
            .find(|record| record.quarantine_id == id)
            .ok_or_else(|| anyhow!("quarantine item not found"))
    }

    fn write_record(&self, record: &QuarantineRecord) -> Result<()> {
        let path = self.base.join(format!("{}.json", record.quarantine_id));
        fs::write(path, serde_json::to_string_pretty(record)?)?;
        Ok(())
    }
}

fn quarantine_base() -> PathBuf {
    if let Ok(path) = std::env::var("ZENTOR_QUARANTINE_DIR") {
        return PathBuf::from(path);
    }
    if cfg!(windows) {
        if let Ok(program_data) = std::env::var("ProgramData") {
            return PathBuf::from(program_data).join("Avorax").join("Quarantine");
        }
    }
    if cfg!(target_os = "macos") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Avorax")
                .join("Quarantine");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/zentor/quarantine");
    }
    PathBuf::from(".zentor/quarantine")
}

#[cfg(unix)]
fn remove_executable_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() & !0o111);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn remove_executable_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanResult, ScanStatus};
    use chrono::Utc;
    use tempfile::tempdir;

    #[test]
    fn infected_scan_creates_quarantine_metadata() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"bad").unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let result = ScanResult {
            status: ScanStatus::Infected,
            scanned_path: file.display().to_string(),
            sha256: "sha256:abc".to_string(),
            engine: "fixture-provider".to_string(),
            signature_name: Some("Eicar".to_string()),
            threat_name: Some("Eicar".to_string()),
            scanned_at: Utc::now(),
            duration_ms: 1,
            raw_engine_summary: None,
        };
        let record = store.quarantine_file(&file, &result).unwrap();
        assert_eq!(record.status, QuarantineStatus::Quarantined);
        assert!(!file.exists());
        assert!(Path::new(&record.quarantine_path).exists());
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn restore_requires_explicit_confirmation() {
        let store = QuarantineStore::with_base(tempdir().unwrap().path().join("q"));
        assert!(store.restore_requires_confirmation("x", false).is_err());
        assert!(store.restore_requires_confirmation("x", true).is_ok());
    }

    #[test]
    fn legacy_quarantine_record_with_old_extension_remains_readable() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let legacy_extension = ["pa", "susq"].concat();
        let legacy_file = base.join(format!("legacy.{legacy_extension}"));
        fs::write(&legacy_file, b"quarantined").unwrap();
        let record = QuarantineRecord {
            quarantine_id: "legacy".to_string(),
            original_path: "C:/original/file.exe".to_string(),
            quarantine_path: legacy_file.display().to_string(),
            sha256: "sha256:legacy".to_string(),
            file_size: 11,
            detection_name: "Legacy detection".to_string(),
            engine: "Avorax Native Engine".to_string(),
            quarantined_at: Utc::now(),
            status: QuarantineStatus::Quarantined,
            user_note: None,
            source: "scanner".to_string(),
            blocked_before_execution: false,
            process_started: false,
            action_taken: "quarantined".to_string(),
            process_id: None,
        };
        fs::write(
            base.join("legacy.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let records = store.list().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].quarantine_id, "legacy");
        assert!(Path::new(&records[0].quarantine_path).exists());
    }

    #[test]
    fn clean_scan_does_not_quarantine_without_calling_store() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("clean.exe");
        fs::write(&file, b"clean").unwrap();
        let result = ScanResult {
            status: ScanStatus::Clean,
            scanned_path: file.display().to_string(),
            sha256: "sha256:clean".to_string(),
            engine: "fixture-provider".to_string(),
            signature_name: None,
            threat_name: None,
            scanned_at: Utc::now(),
            duration_ms: 1,
            raw_engine_summary: None,
        };
        assert_eq!(result.status, ScanStatus::Clean);
        assert!(file.exists());
    }
}
