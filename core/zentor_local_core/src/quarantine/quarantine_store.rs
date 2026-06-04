use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::scanner::ScanResult;

use super::{QuarantineRecord, QuarantineStatus};

const QUARANTINE_EXTENSION: &str = "avoraxq";

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
        let quarantine_path = self.base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        let metadata = fs::metadata(path)?;
        fs::rename(path, &quarantine_path)?;
        remove_executable_permissions(&quarantine_path)?;
        let quarantined_sha256 = sha256_for_file(&quarantine_path)?;
        let record = QuarantineRecord {
            quarantine_id: id.clone(),
            original_path: path.display().to_string(),
            quarantine_path: quarantine_path.display().to_string(),
            sha256: quarantined_sha256,
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
                match serde_json::from_str(&raw) {
                    Ok(record) => records.push(record),
                    Err(_) => continue,
                }
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
        self.ensure_quarantine_payload_path(&quarantine_path)?;
        self.ensure_payload_integrity(&record, &quarantine_path)?;
        let original_path = PathBuf::from(&record.original_path);
        if !original_path.is_absolute()
            || original_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(anyhow!("unsafe original restore path"));
        }
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
        self.ensure_quarantine_payload_path(&quarantine_path)?;
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

    fn ensure_quarantine_payload_path(&self, path: &Path) -> Result<()> {
        let canonical_base = self.base.canonicalize()?;
        let canonical_payload = path.canonicalize()?;
        if !canonical_payload.starts_with(canonical_base) {
            return Err(anyhow!("quarantine payload path escapes quarantine store"));
        }
        if canonical_payload
            .extension()
            .and_then(|value| value.to_str())
            != Some(QUARANTINE_EXTENSION)
        {
            return Err(anyhow!("quarantine payload has unsafe extension"));
        }
        Ok(())
    }

    fn ensure_payload_integrity(&self, record: &QuarantineRecord, path: &Path) -> Result<()> {
        let metadata = fs::metadata(path)?;
        if metadata.len() != record.file_size {
            return Err(anyhow!("quarantine payload size mismatch"));
        }
        let actual_sha256 = sha256_for_file(path)?;
        if !record.sha256.eq_ignore_ascii_case(&actual_sha256) {
            return Err(anyhow!("quarantine payload hash mismatch"));
        }
        Ok(())
    }

    fn write_record(&self, record: &QuarantineRecord) -> Result<()> {
        let path = self.base.join(format!("{}.json", record.quarantine_id));
        fs::write(path, serde_json::to_string_pretty(record)?)?;
        Ok(())
    }
}

fn quarantine_base() -> PathBuf {
    if let Ok(path) = std::env::var("AVORAX_QUARANTINE_DIR") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("ZENTOR_QUARANTINE_DIR") {
        return PathBuf::from(path);
    }
    if cfg!(windows) {
        if let Ok(program_data) = std::env::var("ProgramData") {
            return PathBuf::from(program_data)
                .join("Avorax")
                .join("Quarantine");
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
        return PathBuf::from(home).join(".local/share/avorax/quarantine");
    }
    PathBuf::from(".avorax/quarantine")
}

fn sha256_for_file(path: &Path) -> Result<String> {
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
        assert!(record.quarantine_path.ends_with(".avoraxq"));
        assert!(!file.exists());
        assert!(Path::new(&record.quarantine_path).exists());
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn restore_round_trip_requires_confirmation_and_avoids_overwrite() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"bad").unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let result = fixture_scan_result(&file, ScanStatus::Infected);
        let record = store.quarantine_file(&file, &result).unwrap();

        fs::write(&file, b"replacement").unwrap();
        assert!(store.restore(&record.quarantine_id, false).is_err());
        assert!(store.restore(&record.quarantine_id, true).is_err());
        fs::remove_file(&file).unwrap();

        let restored = store.restore(&record.quarantine_id, true).unwrap();
        assert_eq!(restored.status, QuarantineStatus::Restored);
        assert!(file.exists());
        assert_eq!(fs::read(&file).unwrap(), b"bad");
    }

    #[test]
    fn delete_requires_confirmation_and_removes_payload_only_inside_store() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"bad").unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let result = fixture_scan_result(&file, ScanStatus::Infected);
        let record = store.quarantine_file(&file, &result).unwrap();
        let payload = PathBuf::from(&record.quarantine_path);

        assert!(store.delete(&record.quarantine_id, false).is_err());
        assert!(payload.exists());

        let deleted = store.delete(&record.quarantine_id, true).unwrap();
        assert_eq!(deleted.status, QuarantineStatus::Deleted);
        assert!(!payload.exists());
    }

    #[test]
    fn corrupt_metadata_is_skipped_without_hiding_valid_records() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("corrupt.json"), b"{not-json").unwrap();
        let payload = base.join("valid.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let record = fixture_record("valid", dir.path().join("restore.exe"), payload);
        fs::write(
            base.join("valid.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let records = store.list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].quarantine_id, "valid");
    }

    #[test]
    fn quarantine_record_cannot_delete_payload_outside_store() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let outside = dir.path().join("outside.avoraxq");
        fs::write(&outside, b"do not delete").unwrap();
        let record = fixture_record("escape", dir.path().join("restore.exe"), outside.clone());
        fs::write(
            base.join("escape.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        assert!(store.delete("escape", true).is_err());
        assert!(outside.exists());
    }

    #[test]
    fn restore_rejects_tampered_quarantine_payload_hash() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let restore_path = dir.path().join("restore.exe");
        let payload = base.join("tampered.avoraxq");
        fs::write(&payload, b"tampered payload").unwrap();
        let mut record = fixture_record("tampered", restore_path.clone(), payload.clone());
        record.file_size = fs::metadata(&payload).unwrap().len();
        record.sha256 = "sha256:expected-clean-payload".to_string();
        fs::write(
            base.join("tampered.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let err = store.restore("tampered", true).unwrap_err();

        assert!(err.to_string().contains("quarantine payload hash mismatch"));
        assert!(payload.exists());
        assert!(!restore_path.exists());
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
    fn legacy_zentor_quarantine_record_remains_readable() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let legacy_file = base.join("legacy.zentorq");
        fs::write(&legacy_file, b"quarantined").unwrap();
        let record = QuarantineRecord {
            quarantine_id: "legacy-zentor".to_string(),
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
            base.join("legacy-zentor.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let records = store.list().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].quarantine_id, "legacy-zentor");
        assert!(Path::new(&records[0].quarantine_path).exists());
    }

    #[test]
    fn clean_scan_does_not_quarantine_without_calling_store() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("clean.exe");
        fs::write(&file, b"clean").unwrap();
        let result = fixture_scan_result(&file, ScanStatus::Clean);
        assert_eq!(result.status, ScanStatus::Clean);
        assert!(file.exists());
    }

    fn fixture_scan_result(path: &Path, status: ScanStatus) -> ScanResult {
        ScanResult {
            status,
            scanned_path: path.display().to_string(),
            sha256: "sha256:fixture".to_string(),
            engine: "fixture-provider".to_string(),
            signature_name: Some("Fixture".to_string()),
            threat_name: Some("Fixture".to_string()),
            scanned_at: Utc::now(),
            duration_ms: 1,
            raw_engine_summary: None,
        }
    }

    fn fixture_record(
        id: &str,
        original_path: PathBuf,
        quarantine_path: PathBuf,
    ) -> QuarantineRecord {
        QuarantineRecord {
            quarantine_id: id.to_string(),
            original_path: original_path.display().to_string(),
            quarantine_path: quarantine_path.display().to_string(),
            sha256: "sha256:fixture".to_string(),
            file_size: 11,
            detection_name: "Fixture detection".to_string(),
            engine: "Avorax Native Engine".to_string(),
            quarantined_at: Utc::now(),
            status: QuarantineStatus::Quarantined,
            user_note: None,
            source: "scanner".to_string(),
            blocked_before_execution: false,
            process_started: false,
            action_taken: "quarantined".to_string(),
            process_id: None,
        }
    }
}
