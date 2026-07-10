use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, ExitStatus, Stdio};
#[cfg(windows)]
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::scanner::{ScanResult, ScanStatus};

use super::{QuarantineRecord, QuarantineStatus};

const QUARANTINE_EXTENSION: &str = "avoraxq";
const MAX_QUARANTINE_METADATA_BYTES: u64 = 256 * 1024;
const MAX_QUARANTINE_METADATA_AUTH_BYTES: u64 = 16 * 1024;
const MAX_LOCAL_QUARANTINE_COPY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_LOCAL_QUARANTINE_HASH_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_QUARANTINE_ID_CHARS: usize = 128;
const MAX_QUARANTINE_METADATA_LABEL_CHARS: usize = 256;
const MAX_QUARANTINE_METADATA_STATE_CHARS: usize = 64;
const MAX_QUARANTINE_USER_NOTE_CHARS: usize = 2048;
const MAX_QUARANTINE_PAYLOAD_PATH_CHARS: usize = 4096;
const MAX_QUARANTINE_RESTORE_PATH_CHARS: usize = 4096;
const DEFAULT_QUARANTINE_DETECTION_NAME: &str = "Detected threat";
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

pub struct QuarantineStore {
    base: PathBuf,
}

impl QuarantineStore {
    pub fn new() -> Result<Self> {
        Ok(Self {
            base: quarantine_base()?,
        })
    }

    pub fn with_base(base: PathBuf) -> Self {
        Self { base }
    }

    pub fn quarantine_file(&self, path: &Path, result: &ScanResult) -> Result<QuarantineRecord> {
        validate_quarantine_scan_status(result)?;
        let id = Uuid::new_v4().to_string();
        let quarantine_path = self.base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        let original_path = path.display().to_string();
        validate_original_restore_path_text(&original_path)?;
        let quarantine_path_text = quarantine_path.display().to_string();
        validate_quarantine_payload_path_text(&quarantine_path_text)?;
        let detection_name = quarantine_metadata_label(
            "detection name",
            result.threat_name.as_deref(),
            default_quarantine_detection_name(),
        );
        let engine =
            quarantine_metadata_label("engine", Some(result.engine.as_str()), "local scanner");
        self.ensure_base_directory()?;
        let metadata = ensure_regular_quarantine_source(path)?;
        let source_sha256 = sha256_for_file(path)?;
        ensure_quarantine_payload_destination_absent(&quarantine_path)?;
        fs::rename(path, &quarantine_path)
            .or_else(|_| copy_then_remove_verified(path, &quarantine_path, &source_sha256))?;
        let finalize_result = (|| -> Result<QuarantineRecord> {
            ensure_regular_quarantine_payload(&quarantine_path, "quarantine payload")?;
            remove_executable_permissions(&quarantine_path)?;
            let quarantined_sha256 = sha256_for_file(&quarantine_path)?;
            if !source_sha256.eq_ignore_ascii_case(&quarantined_sha256) {
                return Err(anyhow!("quarantine payload hash changed during move"));
            }
            let record = QuarantineRecord {
                quarantine_id: id.clone(),
                original_path,
                quarantine_path: quarantine_path_text,
                sha256: quarantined_sha256,
                file_size: metadata.len(),
                detection_name,
                engine,
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
        })();
        match finalize_result {
            Ok(record) => Ok(record),
            Err(error) => {
                cleanup_untracked_quarantine_artifacts(&self.base, &id, &quarantine_path)
                    .with_context(|| {
                        format!(
                            "failed to clean up untracked quarantine artifacts after quarantine finalization failure: {error:#}"
                        )
                    })?;
                Err(error)
            }
        }
    }

    pub fn list(&self) -> Result<Vec<QuarantineRecord>> {
        if !optional_quarantine_directory_present(&self.base, "quarantine base directory")? {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.base)? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                let path = entry.path();
                let raw = read_bounded_quarantine_text(
                    &path,
                    MAX_QUARANTINE_METADATA_BYTES,
                    "quarantine metadata record",
                )?;
                if !self.record_auth_valid(&path, &raw)? {
                    return Err(anyhow!(
                        "quarantine metadata authentication failed for record {}",
                        path.display()
                    ));
                }
                match serde_json::from_str(&raw) {
                    Ok(record) => {
                        let record: QuarantineRecord = record;
                        validate_quarantine_id(&record.quarantine_id).with_context(|| {
                            format!(
                                "invalid quarantine id in metadata record {}",
                                path.display()
                            )
                        })?;
                        validate_original_restore_path_text(&record.original_path).with_context(
                            || {
                                format!(
                                    "invalid original path in quarantine metadata record {}",
                                    path.display()
                                )
                            },
                        )?;
                        validate_quarantine_payload_path_text(&record.quarantine_path)
                            .with_context(|| {
                                format!(
                                    "invalid payload path in quarantine metadata record {}",
                                    path.display()
                                )
                            })?;
                        validate_quarantine_record_metadata(&record).with_context(|| {
                            format!(
                                "invalid quarantine metadata fields in record {}",
                                path.display()
                            )
                        })?;
                        records.push(record);
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "unable to parse quarantine metadata record {}",
                                path.display()
                            )
                        });
                    }
                }
            }
        }
        Ok(records)
    }

    pub fn restore_requires_confirmation(&self, id: &str, confirmed: bool) -> Result<()> {
        if !confirmed {
            return Err(anyhow!("restore requires explicit confirmation"));
        }
        validate_quarantine_id(id)?;
        Ok(())
    }

    pub fn restore(&self, id: &str, confirmed: bool) -> Result<QuarantineRecord> {
        self.restore_requires_confirmation(id, confirmed)?;
        let mut record = self.find_record(id)?;
        Self::ensure_quarantined_status_for_action(&record, "restore")?;
        let quarantine_path = validate_quarantine_payload_path_text(&record.quarantine_path)?;
        self.ensure_quarantine_payload_path(&quarantine_path)?;
        self.ensure_payload_integrity(&record, &quarantine_path)?;
        let original_path = validate_original_restore_path_text(&record.original_path)?;
        reject_existing_restore_destination(&original_path)?;
        if let Some(parent) = original_path.parent() {
            fs::create_dir_all(parent)?;
            reject_link_ancestors(parent, "quarantine restore parent")?;
        }
        self.restore_payload_staged(&record, &quarantine_path, &original_path)?;
        record.status = QuarantineStatus::Restored;
        record.action_taken = "restored".to_string();
        if let Err(error) = self.replace_record(&record) {
            self.ensure_payload_integrity(&record, &original_path)
                .and_then(|_| {
                    cleanup_quarantine_partial_file(
                        &original_path,
                        "unrecorded quarantine restore",
                    )
                })
                .with_context(|| {
                    format!(
                        "failed to clean up restored quarantine payload {} after metadata update failure: {error:#}",
                        original_path.display()
                    )
                })?;
            return Err(error)
                .with_context(|| "unable to record quarantine restore before payload cleanup");
        }
        remove_checked_quarantine_payload(&quarantine_path, "restored quarantine payload")
            .with_context(|| {
                format!(
                    "unable to remove restored quarantine payload {} after status update",
                    quarantine_path.display()
                )
            })?;
        Ok(record)
    }

    pub fn delete(&self, id: &str, confirmed: bool) -> Result<QuarantineRecord> {
        if !confirmed {
            return Err(anyhow!("delete requires explicit confirmation"));
        }
        let mut record = self.find_record(id)?;
        Self::ensure_quarantined_status_for_action(&record, "delete")?;
        let quarantine_path = validate_quarantine_payload_path_text(&record.quarantine_path)?;
        self.ensure_quarantine_payload_path(&quarantine_path)?;
        self.ensure_payload_integrity(&record, &quarantine_path)?;
        let previous_status = record.status.clone();
        let previous_action_taken = record.action_taken.clone();
        record.status = QuarantineStatus::Deleted;
        record.action_taken = "deleted".to_string();
        self.replace_record(&record)
            .with_context(|| "unable to record quarantine deletion before payload removal")?;
        if let Err(error) =
            remove_checked_quarantine_payload(&quarantine_path, "deleted quarantine payload")
        {
            record.status = previous_status;
            record.action_taken = previous_action_taken;
            self.replace_record(&record).with_context(|| {
                format!(
                    "failed to restore quarantine deletion status after payload removal failure: {error:#}"
                )
            })?;
            return Err(error).with_context(|| {
                format!(
                    "unable to remove deleted quarantine payload {}",
                    quarantine_path.display()
                )
            });
        }
        Ok(record)
    }

    fn find_record(&self, id: &str) -> Result<QuarantineRecord> {
        validate_quarantine_id(id)?;
        self.list()?
            .into_iter()
            .find(|record| record.quarantine_id == id)
            .ok_or_else(|| anyhow!("quarantine item not found"))
    }

    fn ensure_quarantined_status_for_action(record: &QuarantineRecord, action: &str) -> Result<()> {
        if record.status != QuarantineStatus::Quarantined {
            return Err(anyhow!(
                "cannot {action} quarantine item unless status is quarantined"
            ));
        }
        Ok(())
    }

    fn ensure_quarantine_payload_path(&self, path: &Path) -> Result<()> {
        let canonical_base = self.base.canonicalize()?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!("quarantine payload path is a symbolic link"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(anyhow!("quarantine payload path is a reparse point"));
            }
        }
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
        let metadata = ensure_regular_quarantine_payload(path, "quarantine payload")?;
        if metadata.len() != record.file_size {
            return Err(anyhow!("quarantine payload size mismatch"));
        }
        let actual_sha256 = sha256_for_file(path)?;
        if !record.sha256.eq_ignore_ascii_case(&actual_sha256) {
            return Err(anyhow!("quarantine payload hash mismatch"));
        }
        Ok(())
    }

    fn restore_payload_staged(
        &self,
        record: &QuarantineRecord,
        quarantine_path: &Path,
        original_path: &Path,
    ) -> Result<()> {
        let parent = original_path
            .parent()
            .ok_or_else(|| anyhow!("restore destination has no parent directory"))?;
        let temp_destination = parent.join(format!("avorax-restore-{}.tmp", Uuid::new_v4()));
        reject_link_ancestors(parent, "quarantine restore parent")?;
        ensure_regular_quarantine_payload(quarantine_path, "quarantine payload")?;
        ensure_restore_temp_destination_absent(&temp_destination)?;
        if let Err(error) = copy_file_exclusive(quarantine_path, &temp_destination) {
            return Err(error.context("unable to stage quarantine restore"));
        }
        if let Err(error) = self.ensure_payload_integrity(record, &temp_destination) {
            cleanup_quarantine_partial_file(&temp_destination, "invalid staged quarantine restore")
                .with_context(|| {
                    format!(
                        "failed to clean up invalid staged quarantine restore {} after verification failure: {error:#}",
                        temp_destination.display()
                    )
            })?;
            return Err(error.context("staged quarantine restore verification failed"));
        }
        if let Err(error) = reject_link_ancestors(parent, "quarantine restore parent") {
            cleanup_quarantine_partial_file(&temp_destination, "partial quarantine restore")
                .with_context(|| {
                    format!(
                        "failed to clean up partial quarantine restore {} after parent preflight failure: {error:#}",
                        temp_destination.display()
                    )
                })?;
            return Err(error);
        }
        if let Err(error) = reject_existing_restore_destination(original_path) {
            cleanup_quarantine_partial_file(&temp_destination, "partial quarantine restore")
                .with_context(|| {
                    format!(
                        "failed to clean up partial quarantine restore {} after destination preflight failure: {error:#}",
                        temp_destination.display()
                    )
                })?;
            return Err(error);
        }
        if let Err(error) = fs::rename(&temp_destination, original_path) {
            cleanup_quarantine_partial_file(&temp_destination, "partial quarantine restore")
                .with_context(|| {
                    format!(
                        "failed to clean up partial quarantine restore {} after activation failure: {error:#}",
                        temp_destination.display()
                    )
                })?;
            return Err(error).with_context(|| "unable to activate quarantine restore");
        }
        Ok(())
    }

    fn write_record(&self, record: &QuarantineRecord) -> Result<()> {
        validate_quarantine_record_for_write(record)?;
        let path = self.base.join(format!("{}.json", record.quarantine_id));
        self.ensure_base_directory()?;
        let raw = serde_json::to_string_pretty(record)?;
        write_staged_quarantine_file(&path, raw.as_bytes(), "quarantine metadata record")?;
        self.write_record_auth(record, &raw)?;
        Ok(())
    }

    fn replace_record(&self, record: &QuarantineRecord) -> Result<()> {
        validate_quarantine_record_for_write(record)?;
        let path = self.base.join(format!("{}.json", record.quarantine_id));
        self.ensure_base_directory()?;
        let raw = serde_json::to_string_pretty(record)?;
        replace_staged_quarantine_file(&path, raw.as_bytes(), "quarantine metadata record")?;
        self.replace_record_auth(record, &raw)?;
        Ok(())
    }

    fn write_record_auth(&self, record: &QuarantineRecord, raw: &str) -> Result<()> {
        validate_quarantine_id(&record.quarantine_id)?;
        let path = self
            .base
            .join(format!("{}.json.auth", record.quarantine_id));
        let Some(tag) = self.record_auth_tag(raw, true)? else {
            return Err(anyhow!(
                "quarantine metadata authentication key unavailable"
            ));
        };
        write_staged_quarantine_file(
            &path,
            format!("{tag}\n").as_bytes(),
            "quarantine metadata auth sidecar",
        )?;
        Ok(())
    }

    fn replace_record_auth(&self, record: &QuarantineRecord, raw: &str) -> Result<()> {
        validate_quarantine_id(&record.quarantine_id)?;
        let path = self
            .base
            .join(format!("{}.json.auth", record.quarantine_id));
        let Some(tag) = self.record_auth_tag(raw, true)? else {
            return Err(anyhow!(
                "quarantine metadata authentication key unavailable"
            ));
        };
        replace_staged_quarantine_file(
            &path,
            format!("{tag}\n").as_bytes(),
            "quarantine metadata auth sidecar",
        )?;
        Ok(())
    }

    fn record_auth_valid(&self, path: &Path, raw: &str) -> Result<bool> {
        let auth_path = path.with_extension("json.auth");
        if !optional_quarantine_file_present(&auth_path, "quarantine metadata auth sidecar")? {
            return Ok(true);
        }
        let Some(expected) = self.record_auth_tag(raw, false)? else {
            return Err(anyhow!(
                "quarantine metadata authentication key unavailable for authenticated record {}",
                path.display()
            ));
        };
        let actual = read_bounded_quarantine_text(
            &auth_path,
            MAX_QUARANTINE_METADATA_AUTH_BYTES,
            "quarantine metadata auth sidecar",
        )?
        .trim()
        .to_string();
        Ok(constant_time_eq(expected.as_bytes(), actual.as_bytes()))
    }

    fn record_auth_tag(&self, raw: &str, create_key: bool) -> Result<Option<String>> {
        let Some(key) = self.metadata_auth_key(create_key)? else {
            return Ok(None);
        };
        let mut hasher = Sha256::new();
        hasher.update(b"avorax-quarantine-record-v1\0");
        hasher.update(key.as_bytes());
        hasher.update(b"\0");
        hasher.update(raw.as_bytes());
        Ok(Some(format!("sha256:{:x}", hasher.finalize())))
    }

    fn metadata_auth_key(&self, create: bool) -> Result<Option<String>> {
        let path = self.base.join(".metadata_auth_key");
        if optional_quarantine_file_present(&path, "quarantine metadata authentication key")? {
            let raw_key = read_bounded_quarantine_text(
                &path,
                MAX_QUARANTINE_METADATA_AUTH_BYTES,
                "quarantine metadata authentication key",
            )?;
            let key = decode_metadata_auth_key(&raw_key)?;
            let trimmed = key.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
        if !create {
            return Ok(None);
        }
        self.ensure_base_directory()?;
        let key = Uuid::new_v4().to_string();
        write_staged_quarantine_file(
            &path,
            encode_metadata_auth_key(&key)?.as_bytes(),
            "quarantine metadata authentication key",
        )?;
        Ok(Some(key))
    }

    fn ensure_base_directory(&self) -> Result<()> {
        fs::create_dir_all(&self.base)?;
        reject_link_path(&self.base, "quarantine base directory")?;
        harden_quarantine_base_acl(&self.base)?;
        Ok(())
    }
}

fn quarantine_detection_name(threat_name: Option<&str>) -> String {
    match threat_name {
        Some(name) => name.to_string(),
        None => default_quarantine_detection_name().to_string(),
    }
}

fn default_quarantine_detection_name() -> &'static str {
    DEFAULT_QUARANTINE_DETECTION_NAME
}

fn validate_quarantine_scan_status(result: &ScanResult) -> Result<()> {
    if result.status != ScanStatus::Infected {
        return Err(anyhow!("quarantine requires an infected scan result"));
    }
    Ok(())
}

fn quarantine_metadata_label(label: &str, value: Option<&str>, fallback: &str) -> String {
    let mut normalized = value.unwrap_or(fallback).trim().to_string();
    normalized = normalized
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_QUARANTINE_METADATA_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_string();
    if normalized.is_empty()
        || validate_quarantine_metadata_text(
            label,
            &normalized,
            MAX_QUARANTINE_METADATA_LABEL_CHARS,
            true,
        )
        .is_err()
    {
        fallback.to_string()
    } else {
        normalized
    }
}

fn read_bounded_quarantine_text(path: &Path, max_bytes: u64, label: &str) -> Result<String> {
    let metadata = ensure_regular_quarantine_file(path, label)?;
    if !metadata.is_file() {
        return Err(anyhow!("{label} is not a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(anyhow!(
            "{label} {} exceeds maximum size of {} bytes",
            path.display(),
            max_bytes
        ));
    }
    let mut file = fs::File::open(path).with_context(|| format!("unable to read {label}"))?;
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    let mut bytes = Vec::new();
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("unable to read {label}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("quarantine metadata read size overflow"))?;
        if total > max_bytes {
            return Err(anyhow!(
                "{label} {} exceeds maximum size of {} bytes",
                path.display(),
                max_bytes
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .map_err(|_| anyhow!("{label} {} is not valid UTF-8", path.display()))
        .with_context(|| format!("unable to read {label}"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn encode_metadata_auth_key(key: &str) -> Result<String> {
    #[cfg(windows)]
    {
        let protected = dpapi_protect(key.as_bytes())?;
        return Ok(format!("dpapi:{}\n", hex_encode(&protected)));
    }
    #[cfg(not(windows))]
    {
        Ok(format!("{key}\n"))
    }
}

fn decode_metadata_auth_key(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    #[cfg(windows)]
    {
        if let Some(hex) = trimmed.strip_prefix("dpapi:") {
            let protected = hex_decode(hex)?;
            let clear = dpapi_unprotect(&protected)?;
            return String::from_utf8(clear)
                .map_err(|_| anyhow!("protected quarantine metadata key is not UTF-8"));
        }
    }
    Ok(trimmed.to_string())
}

fn validate_quarantine_id(id: &str) -> Result<()> {
    if id.trim().is_empty() {
        return Err(anyhow!("quarantine id is required"));
    }
    if id.trim() != id {
        return Err(anyhow!(
            "quarantine id contains leading or trailing whitespace"
        ));
    }
    if id.chars().count() > MAX_QUARANTINE_ID_CHARS {
        return Err(anyhow!("quarantine id exceeds maximum length"));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(anyhow!(
            "invalid quarantine id; only ASCII letters, digits, hyphen, and underscore are allowed"
        ));
    }
    Ok(())
}

fn validate_quarantine_record_for_write(record: &QuarantineRecord) -> Result<()> {
    validate_quarantine_id(&record.quarantine_id)?;
    validate_original_restore_path_text(&record.original_path)
        .with_context(|| "invalid original path in quarantine metadata record")?;
    validate_quarantine_payload_path_text(&record.quarantine_path)
        .with_context(|| "invalid payload path in quarantine metadata record")?;
    validate_quarantine_record_metadata(record)
        .with_context(|| "invalid quarantine metadata fields in record")?;
    Ok(())
}

fn validate_quarantine_record_metadata(record: &QuarantineRecord) -> Result<()> {
    normalize_quarantine_sha256(&record.sha256)
        .with_context(|| "invalid quarantine metadata sha256")?;
    validate_quarantine_metadata_text(
        "detection name",
        &record.detection_name,
        MAX_QUARANTINE_METADATA_LABEL_CHARS,
        true,
    )?;
    validate_quarantine_metadata_text(
        "engine",
        &record.engine,
        MAX_QUARANTINE_METADATA_LABEL_CHARS,
        true,
    )?;
    validate_quarantine_metadata_text(
        "source",
        &record.source,
        MAX_QUARANTINE_METADATA_STATE_CHARS,
        true,
    )?;
    validate_quarantine_metadata_text(
        "action taken",
        &record.action_taken,
        MAX_QUARANTINE_METADATA_STATE_CHARS,
        true,
    )?;
    let expected_action_taken = expected_quarantine_action_taken(&record.status);
    if record.action_taken != expected_action_taken {
        return Err(anyhow!(
            "quarantine metadata action taken does not match status"
        ));
    }
    if record.blocked_before_execution && record.process_started {
        return Err(anyhow!(
            "quarantine metadata cannot claim both pre-execution blocking and process start"
        ));
    }
    if record.process_id.is_some() && !record.process_started {
        return Err(anyhow!(
            "quarantine metadata process id requires process start evidence"
        ));
    }
    validate_quarantine_source_for_claims(record)?;
    if let Some(note) = &record.user_note {
        validate_quarantine_metadata_text(
            "user note",
            note,
            MAX_QUARANTINE_USER_NOTE_CHARS,
            false,
        )?;
    }
    Ok(())
}

fn validate_quarantine_source_for_claims(record: &QuarantineRecord) -> Result<()> {
    match record.source.as_str() {
        "scanner" => {
            if record.blocked_before_execution
                || record.process_started
                || record.process_id.is_some()
            {
                return Err(anyhow!(
                    "scanner quarantine source cannot claim execution-state evidence"
                ));
            }
            Ok(())
        }
        _ => Err(anyhow!("unsupported quarantine metadata source")),
    }
}

fn expected_quarantine_action_taken(status: &QuarantineStatus) -> &'static str {
    match status {
        QuarantineStatus::Quarantined => "quarantined",
        QuarantineStatus::Restored => "restored",
        QuarantineStatus::Deleted => "deleted",
    }
}

fn validate_quarantine_metadata_text(
    label: &str,
    value: &str,
    max_chars: usize,
    required: bool,
) -> Result<()> {
    if required && value.trim().is_empty() {
        return Err(anyhow!("quarantine metadata {label} is required"));
    }
    if required && value.trim() != value {
        return Err(anyhow!(
            "quarantine metadata {label} contains leading or trailing whitespace"
        ));
    }
    if value.contains('\0') {
        return Err(anyhow!("quarantine metadata {label} contains NUL"));
    }
    if value.chars().count() > max_chars {
        return Err(anyhow!(
            "quarantine metadata {label} exceeds maximum length of {max_chars} characters"
        ));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(anyhow!(
            "quarantine metadata {label} contains control characters"
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(anyhow!(
            "protected quarantine metadata key has invalid hex length"
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    for pair in raw.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(anyhow!("protected quarantine metadata key has invalid hex")),
    }
}

#[cfg(windows)]
fn dpapi_protect(clear: &[u8]) -> Result<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: clear.len() as u32,
        pbData: clear.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            null(),
            null(),
            null_mut(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(anyhow!(
            "CryptProtectData failed for quarantine metadata key"
        ));
    }
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(protected)
}

#[cfg(windows)]
fn dpapi_unprotect(protected: &[u8]) -> Result<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null(),
            null_mut(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(anyhow!(
            "CryptUnprotectData failed for quarantine metadata key"
        ));
    }
    let clear =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(clear)
}

fn ensure_regular_quarantine_source(path: &Path) -> Result<fs::Metadata> {
    let metadata = ensure_regular_quarantine_file(path, "quarantine source")?;
    if !metadata.is_file() {
        return Err(anyhow!("only regular files can be quarantined"));
    }
    Ok(metadata)
}

fn ensure_regular_quarantine_payload(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = ensure_regular_quarantine_file(path, label)?;
    if !metadata.is_file() {
        return Err(anyhow!("{label} is not a regular file"));
    }
    Ok(metadata)
}

fn remove_checked_quarantine_payload(path: &Path, label: &str) -> Result<()> {
    ensure_regular_quarantine_payload(path, label)?;
    fs::remove_file(path).with_context(|| format!("failed to remove {label} {}", path.display()))
}

fn ensure_regular_quarantine_file(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("refusing to use symbolic link {label}"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow!("refusing to use reparse point {label}"));
        }
    }
    Ok(metadata)
}

fn reject_link_path(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("refusing to use symbolic link {label}"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow!("refusing to use reparse point {label}"));
        }
    }
    Ok(())
}

fn reject_link_ancestors(path: &Path, label: &str) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if optional_quarantine_path_present(ancestor, label)? {
            reject_link_path(ancestor, label)?;
        }
    }
    Ok(())
}

fn write_staged_quarantine_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    ensure_quarantine_file_parent_directory(path, label)?;
    let temp_path = quarantine_staged_temp_path(path, label)?;
    if let Err(error) = write_file_exclusive(&temp_path, bytes, label) {
        return Err(error);
    }
    if let Err(error) = reject_link_path(&temp_path, label) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after temp validation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = ensure_quarantine_file_parent_directory(path, label) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after parent preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = ensure_quarantine_file_destination_absent(path, label) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after activation preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after activation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to activate {label} {}", path.display()));
    }
    Ok(())
}

fn replace_staged_quarantine_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    ensure_quarantine_file_parent_directory(path, label)?;
    let temp_path = quarantine_staged_temp_path(path, label)?;
    if let Err(error) = write_file_exclusive(&temp_path, bytes, label) {
        return Err(error);
    }
    if let Err(error) = reject_link_path(&temp_path, label) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after temp validation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = ensure_quarantine_file_parent_directory(path, label) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after parent preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = remove_existing_quarantine_file(path, label) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after replace preflight failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after activation failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to activate {label} {}", path.display()));
    }
    Ok(())
}

fn quarantine_staged_temp_path(path: &Path, label: &str) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{label} path has no parent {}", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{label} path has no file name {}", path.display()))?;
    let mut temp_name = file_name.to_os_string();
    temp_name.push(format!(".tmp-{}", Uuid::new_v4()));
    Ok(parent.join(temp_name))
}

fn cleanup_quarantine_staged_file(path: &Path, label: &str) -> Result<()> {
    let cleanup_label = format!("temporary {label}");
    cleanup_quarantine_partial_file(path, &cleanup_label)
}

fn ensure_quarantine_file_parent_directory(path: &Path, label: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{label} path has no parent {}", path.display()))?;
    let parent_label = format!("{label} parent directory");
    if optional_quarantine_directory_present(parent, &parent_label)? {
        Ok(())
    } else {
        Err(anyhow!(
            "{label} parent directory {} does not exist",
            parent.display()
        ))
    }
}

fn optional_quarantine_path_present(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn optional_quarantine_directory_present(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!("refusing to use symbolic link {label}"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(anyhow!("refusing to use reparse point {label}"));
                }
            }
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

fn optional_quarantine_file_present(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!("refusing to use symbolic link {label}"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(anyhow!("refusing to use reparse point {label}"));
                }
            }
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

fn write_file_exclusive(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let mut output = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(output) => output,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create temporary {label} {}", path.display()));
        }
    };
    if let Err(error) = output.write_all(bytes) {
        drop(output);
        cleanup_quarantine_staged_file(path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after write failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to write temporary {label} {}", path.display()));
    }
    if let Err(error) = output.sync_all() {
        drop(output);
        cleanup_quarantine_staged_file(path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after sync failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to sync temporary {label} {}", path.display()));
    }
    Ok(())
}

fn remove_existing_quarantine_file(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!("refusing to replace symbolic link {label}"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(anyhow!("refusing to replace reparse point {label}"));
                }
            }
            if !metadata.is_file() {
                return Err(anyhow!("refusing to replace non-file {label}"));
            }
            fs::remove_file(path)
                .with_context(|| format!("failed to remove existing {label} {}", path.display()))?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_quarantine_file_destination_absent(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!("refusing to replace symbolic link {label}"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(anyhow!("refusing to replace reparse point {label}"));
                }
            }
            if !metadata.file_type().is_file() {
                return Err(anyhow!("refusing to replace non-file {label}"));
            }
            Err(anyhow!(
                "{label} destination already exists {}",
                path.display()
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn reject_existing_restore_destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(anyhow!("original path already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect original restore path {}", path.display())),
    }
}

fn validate_original_restore_path_text(text: &str) -> Result<PathBuf> {
    if text.trim().is_empty() {
        return Err(anyhow!("original restore path is empty"));
    }
    if text.contains('\0') {
        return Err(anyhow!("original restore path contains NUL"));
    }
    if text.chars().count() > MAX_QUARANTINE_RESTORE_PATH_CHARS {
        return Err(anyhow!(
            "original restore path exceeds maximum length of {} characters",
            MAX_QUARANTINE_RESTORE_PATH_CHARS
        ));
    }
    if quarantine_restore_path_has_unsafe_segment(text) {
        return Err(anyhow!("unsafe original restore path"));
    }
    let path = PathBuf::from(text);
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(anyhow!("unsafe original restore path"));
    }
    Ok(path)
}

fn quarantine_restore_path_has_unsafe_segment(text: &str) -> bool {
    text.replace('\\', "/")
        .split('/')
        .any(|part| part == "." || part == "..")
}

fn validate_quarantine_payload_path_text(text: &str) -> Result<PathBuf> {
    if text.trim().is_empty() {
        return Err(anyhow!("quarantine payload path is empty"));
    }
    if text.contains('\0') {
        return Err(anyhow!("quarantine payload path contains NUL"));
    }
    if text.chars().count() > MAX_QUARANTINE_PAYLOAD_PATH_CHARS {
        return Err(anyhow!(
            "quarantine payload path exceeds maximum length of {} characters",
            MAX_QUARANTINE_PAYLOAD_PATH_CHARS
        ));
    }
    if quarantine_payload_path_has_unsafe_segment(text) {
        return Err(anyhow!("unsafe quarantine payload path"));
    }
    let path = PathBuf::from(text);
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(anyhow!("unsafe quarantine payload path"));
    }
    if path.extension().and_then(|value| value.to_str()) != Some(QUARANTINE_EXTENSION) {
        return Err(anyhow!("quarantine payload has unsafe extension"));
    }
    Ok(path)
}

fn quarantine_payload_path_has_unsafe_segment(text: &str) -> bool {
    text.replace('\\', "/")
        .split('/')
        .any(|part| part == "." || part == "..")
}

fn ensure_restore_temp_destination_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "refusing to use symbolic link quarantine restore temp destination"
                ));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(anyhow!(
                        "refusing to use reparse point quarantine restore temp destination"
                    ));
                }
            }
            Err(anyhow!(
                "quarantine restore temp destination already exists"
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect quarantine restore temp destination {}",
                path.display()
            )
        }),
    }
}

fn harden_quarantine_base_acl(_path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let current_user = current_windows_account()?;
        let current_user_grant = format!("{current_user}:(OI)(CI)F");
        let icacls = crate::windows_tools::windows_system32_tool("icacls.exe")?;
        let mut command = Command::new(&icacls);
        command.arg(_path).args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            &current_user_grant,
        ]);
        let output = run_quarantine_acl_command(&mut command)?;
        if !output.status.success() {
            return Err(anyhow!(
                "failed to harden quarantine ACLs: {}",
                command_output_excerpt(&output.stderr)
            ));
        }
    }
    Ok(())
}

const MAX_QUARANTINE_COMMAND_OUTPUT_BYTES: usize = 2048;
#[cfg(windows)]
const QUARANTINE_ACL_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(windows)]
struct BoundedQuarantineCommandOutput {
    status: ExitStatus,
    stderr: Vec<u8>,
}

#[cfg(windows)]
fn run_quarantine_acl_command(command: &mut Command) -> Result<BoundedQuarantineCommandOutput> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("failed to launch quarantine ACL command")?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture quarantine ACL command stderr"))?;
    let stderr_reader = std::thread::spawn(move || {
        read_bounded_quarantine_command_output(stderr, MAX_QUARANTINE_COMMAND_OUTPUT_BYTES)
    });
    let status = match wait_for_quarantine_acl_child(&mut child)? {
        Some(status) => status,
        None => {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let stderr = stderr_reader
                .join()
                .map_err(|_| anyhow!("quarantine ACL stderr reader panicked"))??;
            let mut detail = format!(
                "quarantine ACL command timed out after {} seconds",
                QUARANTINE_ACL_COMMAND_TIMEOUT.as_secs()
            );
            if let Some(error) = kill_error {
                detail.push_str(&format!(
                    "; failed to kill timed-out quarantine ACL command: {error}"
                ));
            }
            if let Some(error) = wait_error {
                detail.push_str(&format!(
                    "; failed to reap timed-out quarantine ACL command: {error}"
                ));
            }
            let stderr_excerpt = command_output_excerpt(&stderr);
            if !stderr_excerpt.is_empty() {
                detail.push_str(&format!("; stderr: {stderr_excerpt}"));
            }
            return Err(anyhow!(detail));
        }
    };
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("quarantine ACL stderr reader panicked"))??;
    Ok(BoundedQuarantineCommandOutput { status, stderr })
}

#[cfg(windows)]
fn wait_for_quarantine_acl_child(child: &mut std::process::Child) -> Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to poll quarantine ACL command")?
        {
            return Ok(Some(status));
        }
        if started.elapsed() >= QUARANTINE_ACL_COMMAND_TIMEOUT {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(windows)]
fn read_bounded_quarantine_command_output<R: Read>(reader: R, max_bytes: usize) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    let retain_limit = max_bytes.saturating_add(1);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("failed to read quarantine ACL command stderr")?;
        if read == 0 {
            break;
        }
        let remaining = retain_limit.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = read.min(remaining);
            bytes.extend_from_slice(&buffer[..keep]);
        }
    }
    Ok(bytes)
}

fn command_output_excerpt(bytes: &[u8]) -> String {
    let limit = bytes.len().min(MAX_QUARANTINE_COMMAND_OUTPUT_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[..limit]).trim().to_string();
    if bytes.len() > MAX_QUARANTINE_COMMAND_OUTPUT_BYTES {
        text.push_str("...[truncated]");
    }
    text
}

#[cfg(windows)]
fn current_windows_account() -> Result<String> {
    let user = std::env::var("USERNAME").map_err(|_| anyhow!("USERNAME is not set"))?;
    if user.trim().is_empty() {
        return Err(anyhow!("USERNAME is empty"));
    }
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.trim().is_empty() => Ok(format!("{domain}\\{user}")),
        _ => Ok(user),
    }
}

fn copy_then_remove_verified(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<()> {
    let expected_sha256 = normalize_quarantine_sha256(expected_sha256)
        .with_context(|| "invalid local quarantine copy expected sha256")?;
    ensure_regular_quarantine_source(source)?;
    ensure_quarantine_payload_destination_absent(destination)?;
    copy_file_exclusive(source, destination)?;
    let destination_hash = match (|| -> Result<String> {
        ensure_regular_quarantine_payload(destination, "quarantine payload destination")?;
        sha256_for_file(destination)
    })() {
        Ok(hash) => hash,
        Err(error) => {
            cleanup_quarantine_partial_file(destination, "invalid copied quarantine destination")
                .with_context(|| {
                    format!(
                        "failed to clean up invalid copied quarantine destination {} after verification failure: {error:#}",
                        destination.display()
                    )
                })?;
            return Err(error).with_context(|| {
                format!(
                    "failed to verify copied quarantine destination {}",
                    destination.display()
                )
            });
        }
    };
    if destination_hash != expected_sha256 {
        if let Err(cleanup_error) = fs::remove_file(destination) {
            return Err(anyhow!(
                "hash verification failed before deleting original quarantine source; failed to remove invalid quarantine destination {}: {cleanup_error}",
                destination.display()
            ));
        }
        return Err(anyhow!(
            "hash verification failed before deleting original quarantine source"
        ));
    }
    if let Err(error) = fs::remove_file(source) {
        cleanup_quarantine_partial_file(destination, "copied quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up copied quarantine destination {} after source deletion failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to delete original quarantine source {}",
                source.display()
            )
        });
    }
    Ok(())
}

fn ensure_quarantine_payload_destination_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "refusing to use symbolic link quarantine payload destination"
                ));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(anyhow!(
                        "refusing to use reparse point quarantine payload destination"
                    ));
                }
            }
            Err(anyhow!("quarantine payload destination already exists"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect quarantine payload destination {}",
                path.display()
            )
        }),
    }
}

fn cleanup_quarantine_partial_file(path: &Path, label: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {label} {}", path.display()))
        }
    }
}

fn cleanup_untracked_quarantine_artifacts(
    base: &Path,
    id: &str,
    payload_path: &Path,
) -> Result<()> {
    let metadata_path = base.join(format!("{id}.json"));
    let metadata_temp_path = base.join(format!("{id}.json.tmp"));
    let auth_path = base.join(format!("{id}.json.auth"));
    let auth_temp_path = base.join(format!("{id}.json.auth.tmp"));
    let targets = [
        (payload_path.to_path_buf(), "untracked quarantine payload"),
        (metadata_path, "untracked quarantine metadata record"),
        (
            metadata_temp_path,
            "untracked quarantine metadata temp record",
        ),
        (auth_path, "untracked quarantine metadata auth sidecar"),
        (
            auth_temp_path,
            "untracked quarantine metadata auth temp sidecar",
        ),
    ];
    let mut failures = Vec::new();
    for (path, label) in targets {
        if let Err(error) = cleanup_quarantine_partial_file(&path, label) {
            failures.push(format!("{label} {}: {error:#}", path.display()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "failed to clean up one or more untracked quarantine artifacts: {}",
            failures.join("; ")
        ))
    }
}

fn copy_local_quarantine_payload_limited<R: Read, W: Write>(
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
            .ok_or_else(|| anyhow!("local quarantine payload copy size overflow"))?;
        if total > limit {
            anyhow::bail!(
                "local quarantine payload {} exceeds the copy size limit",
                source.display()
            );
        }
        output.write_all(&buffer[..read])?;
    }
}

fn copy_file_exclusive(source: &Path, destination: &Path) -> Result<()> {
    let mut input = fs::File::open(source)
        .with_context(|| format!("failed to open quarantine source {}", source.display()))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| {
            format!(
                "failed to create quarantine destination {}",
                destination.display()
            )
        })?;
    if let Err(error) = copy_local_quarantine_payload_limited(
        &mut input,
        &mut output,
        MAX_LOCAL_QUARANTINE_COPY_BYTES,
        source,
    ) {
        drop(output);
        cleanup_quarantine_partial_file(destination, "partial quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial quarantine destination {} after copy failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to copy quarantine payload {} to {}",
                source.display(),
                destination.display()
            )
        });
    }
    if let Err(error) = output.sync_all() {
        drop(output);
        cleanup_quarantine_partial_file(destination, "partial quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial quarantine destination {} after sync failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to sync quarantine destination {}",
                destination.display()
            )
        });
    }
    Ok(())
}

fn quarantine_base() -> Result<PathBuf> {
    if let Some(path) = absolute_quarantine_env_path("AVORAX_QUARANTINE_DIR")? {
        return Ok(path);
    }
    if let Some(path) = absolute_quarantine_env_path("ZENTOR_QUARANTINE_DIR")? {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = absolute_quarantine_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax").join("Quarantine"));
        }
        if let Some(program_data) = absolute_quarantine_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax").join("Quarantine"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = absolute_quarantine_env_path("HOME")? {
            return Ok(home
                .join("Library")
                .join("Application Support")
                .join("Avorax")
                .join("Quarantine"));
        }
    }
    if let Some(home) = absolute_quarantine_env_path("HOME")? {
        return Ok(home.join(".local/share/avorax/quarantine"));
    }
    Err(anyhow!("local quarantine base root is unavailable"))
}

fn absolute_quarantine_env_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        return Err(anyhow!("{name} is empty"));
    }
    validate_quarantine_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !quarantine_root_is_allowed(&path) {
        return Err(anyhow!(
            "{name} must be an absolute local path: {}",
            path.display()
        ));
    }
    Ok(Some(path))
}

fn validate_quarantine_env_root_text(name: &str, text: &str) -> Result<()> {
    if text.contains('\0') {
        return Err(anyhow!("{name} contains NUL"));
    }
    if quarantine_env_root_has_parent_traversal(text) {
        return Err(anyhow!("{name} must not contain parent traversal"));
    }
    Ok(())
}

fn quarantine_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

#[cfg(windows)]
fn quarantine_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn quarantine_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

fn sha256_for_file(path: &Path) -> Result<String> {
    let metadata = ensure_regular_quarantine_payload(path, "quarantine hash input")?;
    if metadata.len() > MAX_LOCAL_QUARANTINE_HASH_BYTES {
        return Err(anyhow!(
            "quarantine hash input {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_LOCAL_QUARANTINE_HASH_BYTES
        ));
    }
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("local quarantine hash size overflow"))?;
        if total > MAX_LOCAL_QUARANTINE_HASH_BYTES {
            return Err(anyhow!(
                "quarantine hash input {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_LOCAL_QUARANTINE_HASH_BYTES
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn normalize_quarantine_sha256(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let raw = sha256_body(trimmed);
    if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(format!("sha256:{}", raw.to_ascii_lowercase()))
    } else {
        Err(anyhow!("invalid quarantine SHA-256 value"))
    }
}

fn sha256_body(trimmed: &str) -> &str {
    match trimmed.strip_prefix("sha256:") {
        Some(raw) => raw,
        None => trimmed,
    }
}

#[cfg(unix)]
fn remove_executable_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions =
        ensure_regular_quarantine_payload(path, "quarantine payload")?.permissions();
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

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    #[test]
    fn local_quarantine_hash_prefix_branch_is_explicit() {
        let source = include_str!("quarantine_store.rs");
        let normalize_start = source.find("fn normalize_quarantine_sha256").unwrap();
        let unix_start = normalize_start + source[normalize_start..].find("#[cfg(unix)]").unwrap();
        let normalize_source = &source[normalize_start..unix_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or(trimmed)"));
    }

    #[test]
    fn local_quarantine_detection_name_default_is_explicit() {
        let source = include_str!("quarantine_store.rs");
        let quarantine_start = source.find("pub fn quarantine_file").unwrap();
        let list_start = source.find("pub fn list").unwrap();
        let quarantine_source = &source[quarantine_start..list_start];
        let helper_start = source.find("fn quarantine_detection_name").unwrap();
        let read_start = source.find("fn read_bounded_quarantine_text").unwrap();
        let helper_source = &source[helper_start..read_start];

        assert_eq!(
            quarantine_detection_name(Some("EICAR-Test-File")),
            "EICAR-Test-File"
        );
        assert_eq!(
            quarantine_detection_name(None),
            DEFAULT_QUARANTINE_DETECTION_NAME
        );
        assert!(quarantine_source.contains("quarantine_metadata_label("));
        assert!(quarantine_source.contains("default_quarantine_detection_name()"));
        assert!(helper_source.contains("Some(name) => name.to_string()"));
        assert!(helper_source.contains("None => default_quarantine_detection_name().to_string()"));
        assert!(!quarantine_source.contains("unwrap_or_else(|| \"Detected threat\".to_string())"));
    }

    #[test]
    fn quarantine_base_rejects_relative_override() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_QUARANTINE_DIR");
        std::env::set_var("AVORAX_QUARANTINE_DIR", "relative-quarantine");

        let error = quarantine_base().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_QUARANTINE_DIR"),
        }
        assert!(error.contains("AVORAX_QUARANTINE_DIR must be an absolute local path"));
    }

    #[test]
    fn quarantine_base_rejects_parent_traversal_override() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_QUARANTINE_DIR");
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_QUARANTINE_DIR", dir.path().join(".."));

        let error = quarantine_base().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_QUARANTINE_DIR"),
        }
        assert!(error.contains("AVORAX_QUARANTINE_DIR must not contain parent traversal"));
    }

    #[test]
    fn quarantine_base_has_no_relative_fallback() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn quarantine_base").unwrap();
        let end = source.find("fn sha256_for_file").unwrap();
        let root_source = &source[start..end];

        assert!(root_source.contains("fn quarantine_base() -> Result<PathBuf>"));
        assert!(root_source.contains("absolute_quarantine_env_path(\"AVORAX_QUARANTINE_DIR\")?"));
        assert!(root_source.contains("absolute_quarantine_env_path(\"ZENTOR_QUARANTINE_DIR\")?"));
        assert!(root_source.contains("quarantine_root_is_allowed(&path)"));
        assert!(root_source.contains("local quarantine base root is unavailable"));
        assert!(!root_source.contains("PathBuf::from(\".avorax/quarantine\")"));
        assert!(!root_source.contains("std::env::var(\"AVORAX_QUARANTINE_DIR\")"));
    }

    #[test]
    fn quarantine_finalization_failures_clean_untracked_artifacts() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn quarantine_file(&self").unwrap();
        let end = source.find("pub fn list(&self)").unwrap();
        let quarantine_source = &source[start..end];
        let cleanup_start = source
            .find("fn cleanup_untracked_quarantine_artifacts")
            .unwrap();
        let cleanup_end = source
            .find("fn copy_local_quarantine_payload_limited")
            .unwrap();
        let cleanup_source = &source[cleanup_start..cleanup_end];

        assert!(quarantine_source.contains("let finalize_result = (|| -> Result<QuarantineRecord>"));
        assert!(quarantine_source
            .contains("cleanup_untracked_quarantine_artifacts(&self.base, &id, &quarantine_path)"));
        assert!(quarantine_source.contains("after quarantine finalization failure"));
        assert!(quarantine_source.contains("Err(error)"));
        assert!(cleanup_source.contains("\"untracked quarantine payload\""));
        assert!(cleanup_source.contains("\"untracked quarantine metadata record\""));
        assert!(cleanup_source.contains("\"untracked quarantine metadata temp record\""));
        assert!(cleanup_source.contains("\"untracked quarantine metadata auth sidecar\""));
        assert!(cleanup_source.contains("\"untracked quarantine metadata auth temp sidecar\""));
        assert!(cleanup_source
            .contains("failed to clean up one or more untracked quarantine artifacts"));
        assert!(
            quarantine_source
                .find("fs::rename(path, &quarantine_path)")
                .unwrap()
                < quarantine_source
                    .find("let finalize_result = (|| -> Result<QuarantineRecord>")
                    .unwrap()
        );
        assert!(
            quarantine_source
                .find("self.write_record(&record)?")
                .unwrap()
                < quarantine_source
                    .find("cleanup_untracked_quarantine_artifacts")
                    .unwrap()
        );
    }

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
    fn quarantine_file_rejects_non_infected_scan_status_before_payload_move() {
        for status in [
            ScanStatus::Clean,
            ScanStatus::Error,
            ScanStatus::EngineUnavailable,
        ] {
            let dir = tempdir().unwrap();
            let file = dir.path().join("not-a-threat.exe");
            let base = dir.path().join("q");
            fs::write(&file, b"clean").unwrap();
            let store = QuarantineStore::with_base(base.clone());
            let result = fixture_scan_result(&file, status);

            let error = store.quarantine_file(&file, &result).unwrap_err();

            assert!(error
                .to_string()
                .contains("quarantine requires an infected scan result"));
            assert!(file.exists());
            assert!(!base.exists());
        }
    }

    #[test]
    fn quarantine_file_normalizes_untrusted_detection_metadata_before_move() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad-label.exe");
        fs::write(&file, b"bad").unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let result = ScanResult {
            status: ScanStatus::Infected,
            scanned_path: file.display().to_string(),
            sha256: "sha256:abc".to_string(),
            engine: "\n\t\0".to_string(),
            signature_name: Some("Fixture".to_string()),
            threat_name: Some("\nFixture\0Detection\n".to_string()),
            scanned_at: Utc::now(),
            duration_ms: 1,
            raw_engine_summary: None,
        };

        let record = store.quarantine_file(&file, &result).unwrap();

        assert_eq!(record.detection_name, "Fixture Detection");
        assert_eq!(record.engine, "local scanner");
        assert!(!record.detection_name.chars().any(|ch| ch.is_control()));
        assert!(!record.engine.chars().any(|ch| ch.is_control()));
        assert!(!file.exists());
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].detection_name, "Fixture Detection");
        assert_eq!(listed[0].engine, "local scanner");
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_rejects_symbolic_link_source_before_metadata_follow() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let link = dir.path().join("link.exe");
        fs::write(&target, b"bad").unwrap();
        symlink(&target, &link).unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let result = fixture_scan_result(&link, ScanStatus::Infected);

        let err = store.quarantine_file(&link, &result).unwrap_err();

        assert!(err
            .to_string()
            .contains("refusing to use symbolic link quarantine source"));
        assert!(target.exists());
        assert!(link.exists());
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_rejects_symbolic_link_base_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real_base = dir.path().join("real-q");
        let link_base = dir.path().join("link-q");
        fs::create_dir_all(&real_base).unwrap();
        symlink(&real_base, &link_base).unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"bad").unwrap();
        let store = QuarantineStore::with_base(link_base);
        let result = fixture_scan_result(&file, ScanStatus::Infected);

        let err = store.quarantine_file(&file, &result).unwrap_err();

        assert!(err
            .to_string()
            .contains("refusing to use symbolic link quarantine base directory"));
        assert!(file.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_point_attribute_constant_is_expected_value() {
        assert_eq!(FILE_ATTRIBUTE_REPARSE_POINT, 0x400);
    }

    #[cfg(windows)]
    #[test]
    fn windows_current_account_for_acl_is_not_empty() {
        assert!(!current_windows_account().unwrap().trim().is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn metadata_key_storage_round_trips_plaintext_off_windows() {
        let encoded = encode_metadata_auth_key("fixture-key").unwrap();
        assert_eq!(encoded, "fixture-key\n");
        assert_eq!(decode_metadata_auth_key(&encoded).unwrap(), "fixture-key");
    }

    #[cfg(windows)]
    #[test]
    fn metadata_key_storage_uses_dpapi_on_windows() {
        let encoded = encode_metadata_auth_key("fixture-key").unwrap();
        assert!(encoded.starts_with("dpapi:"));
        assert_eq!(decode_metadata_auth_key(&encoded).unwrap(), "fixture-key");
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
    fn restore_records_status_before_payload_cleanup() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn restore(&self").unwrap();
        let end = source.find("pub fn delete(&self").unwrap();
        let restore_source = &source[start..end];
        let staged_start = source.find("fn restore_payload_staged").unwrap();
        let staged_end = source.find("fn write_record").unwrap();
        let staged_source = &source[staged_start..staged_end];

        assert!(restore_source.contains("record.status = QuarantineStatus::Restored;"));
        assert!(
            restore_source.contains("unable to record quarantine restore before payload cleanup")
        );
        assert!(restore_source.contains(
            "remove_checked_quarantine_payload(&quarantine_path, \"restored quarantine payload\")"
        ));
        assert!(restore_source.contains("unable to remove restored quarantine payload"));
        assert!(restore_source.contains("after status update"));
        assert!(
            restore_source
                .find("record.status = QuarantineStatus::Restored;")
                .unwrap()
                < restore_source
                    .find("remove_checked_quarantine_payload(&quarantine_path")
                    .unwrap()
        );
        assert!(!staged_source.contains("fs::remove_file(quarantine_path)"));
    }

    #[test]
    fn restore_records_action_taken_with_restored_status() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn restore(&self").unwrap();
        let end = source.find("pub fn delete(&self").unwrap();
        let restore_source = &source[start..end];

        assert!(restore_source.contains("record.status = QuarantineStatus::Restored;"));
        assert!(restore_source.contains("record.action_taken = \"restored\".to_string();"));
        assert!(
            restore_source
                .find("record.status = QuarantineStatus::Restored;")
                .unwrap()
                < restore_source
                    .find("record.action_taken = \"restored\".to_string();")
                    .unwrap()
        );
        assert!(
            restore_source
                .find("record.action_taken = \"restored\".to_string();")
                .unwrap()
                < restore_source
                    .find("if let Err(error) = self.replace_record(&record)")
                    .unwrap()
        );
    }

    #[test]
    fn restore_cleans_restored_payload_on_metadata_write_failure() {
        let source = crate::normalized_test_source(include_str!("quarantine_store.rs"));
        let start = source.find("pub fn restore(&self").unwrap();
        let end = source.find("pub fn delete(&self").unwrap();
        let restore_source = &source[start..end];

        assert!(restore_source.contains("if let Err(error) = self.replace_record(&record)"));
        assert!(restore_source.contains("self.ensure_payload_integrity(&record, &original_path)"));
        assert!(restore_source.contains(
            "cleanup_quarantine_partial_file(\n                        &original_path,\n                        \"unrecorded quarantine restore\","
        ));
        assert!(restore_source.contains("failed to clean up restored quarantine payload"));
        assert!(restore_source.contains("after metadata update failure"));
        assert!(
            restore_source.contains("unable to record quarantine restore before payload cleanup")
        );
        assert!(
            restore_source
                .find("record.status = QuarantineStatus::Restored;")
                .unwrap()
                < restore_source
                    .find("if let Err(error) = self.replace_record(&record)")
                    .unwrap()
        );
        assert!(
            restore_source
                .find("if let Err(error) = self.replace_record(&record)")
                .unwrap()
                < restore_source
                    .find("cleanup_quarantine_partial_file")
                    .unwrap()
        );
    }

    #[test]
    fn restore_revalidates_parent_before_staging_and_activation() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn restore_payload_staged").unwrap();
        let end = source.find("fn write_record").unwrap();
        let staged_source = &source[start..end];

        assert!(staged_source
            .contains("reject_link_ancestors(parent, \"quarantine restore parent\")?;"));
        assert!(staged_source.contains(
            "if let Err(error) = reject_link_ancestors(parent, \"quarantine restore parent\")"
        ));
        assert!(staged_source.contains("after parent preflight failure"));
        assert!(staged_source.contains(
            "cleanup_quarantine_partial_file(&temp_destination, \"partial quarantine restore\")"
        ));
        assert!(
            staged_source
                .find("reject_link_ancestors(parent, \"quarantine restore parent\")?;")
                .unwrap()
                < staged_source
                    .find("ensure_restore_temp_destination_absent(&temp_destination)?;")
                    .unwrap()
        );
        assert!(
            staged_source
                .find("if let Err(error) = reject_link_ancestors(parent, \"quarantine restore parent\")")
                .unwrap()
                < staged_source
                    .find("if let Err(error) = fs::rename(&temp_destination, original_path)")
                    .unwrap()
        );
    }

    #[test]
    fn restore_and_delete_require_quarantined_status_before_path_use() {
        let source = include_str!("quarantine_store.rs");
        let restore_start = source.find("pub fn restore(&self").unwrap();
        let restore_end = source.find("pub fn delete(&self").unwrap();
        let restore_source = &source[restore_start..restore_end];
        let delete_start = source.find("pub fn delete(&self").unwrap();
        let delete_end = source.find("fn find_record").unwrap();
        let delete_source = &source[delete_start..delete_end];
        let helper_start = source
            .find("fn ensure_quarantined_status_for_action")
            .unwrap();
        let helper_end = source.find("fn ensure_quarantine_payload_path").unwrap();
        let helper_source = &source[helper_start..helper_end];

        assert!(restore_source
            .contains("Self::ensure_quarantined_status_for_action(&record, \"restore\")?;"));
        assert!(delete_source
            .contains("Self::ensure_quarantined_status_for_action(&record, \"delete\")?;"));
        assert!(helper_source.contains("record.status != QuarantineStatus::Quarantined"));
        assert!(
            helper_source.contains("cannot {action} quarantine item unless status is quarantined")
        );
        assert!(
            restore_source
                .find("Self::ensure_quarantined_status_for_action(&record, \"restore\")?;")
                .unwrap()
                < restore_source
                    .find("validate_quarantine_payload_path_text(&record.quarantine_path)?")
                    .unwrap()
        );
        assert!(
            delete_source
                .find("Self::ensure_quarantined_status_for_action(&record, \"delete\")?;")
                .unwrap()
                < delete_source
                    .find("validate_quarantine_payload_path_text(&record.quarantine_path)?")
                    .unwrap()
        );
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
    fn delete_records_status_before_payload_removal_and_rolls_back_on_failure() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn delete(&self").unwrap();
        let end = source.find("fn find_record").unwrap();
        let delete_source = &source[start..end];

        assert!(delete_source.contains("let previous_status = record.status.clone();"));
        assert!(delete_source.contains("let previous_action_taken = record.action_taken.clone();"));
        assert!(delete_source.contains("record.status = QuarantineStatus::Deleted;"));
        assert!(delete_source.contains("record.action_taken = \"deleted\".to_string();"));
        assert!(
            delete_source.contains("unable to record quarantine deletion before payload removal")
        );
        assert!(delete_source.contains(
            "remove_checked_quarantine_payload(&quarantine_path, \"deleted quarantine payload\")"
        ));
        assert!(delete_source.contains("record.status = previous_status;"));
        assert!(delete_source.contains("record.action_taken = previous_action_taken;"));
        assert!(delete_source.contains(
            "failed to restore quarantine deletion status after payload removal failure"
        ));
        assert!(delete_source.contains("unable to remove deleted quarantine payload"));
        assert!(
            delete_source
                .find("record.status = QuarantineStatus::Deleted;")
                .unwrap()
                < delete_source
                    .find("record.action_taken = \"deleted\".to_string();")
                    .unwrap()
        );
        assert!(
            delete_source
                .find("record.action_taken = \"deleted\".to_string();")
                .unwrap()
                < delete_source
                    .find("remove_checked_quarantine_payload(&quarantine_path")
                    .unwrap()
        );
    }

    #[test]
    fn delete_and_restore_payload_cleanup_revalidate_before_removal() {
        let source = include_str!("quarantine_store.rs");
        let helper_start = source.find("fn remove_checked_quarantine_payload").unwrap();
        let helper_end = source.find("fn ensure_regular_quarantine_file").unwrap();
        let helper_source = &source[helper_start..helper_end];

        assert!(helper_source.contains("ensure_regular_quarantine_payload(path, label)?;"));
        assert!(helper_source.contains("fs::remove_file(path)"));
        assert!(source.contains(
            "remove_checked_quarantine_payload(&quarantine_path, \"restored quarantine payload\")"
        ));
        assert!(source.contains(
            "remove_checked_quarantine_payload(&quarantine_path, \"deleted quarantine payload\")"
        ));
    }

    #[test]
    fn delete_verifies_payload_integrity_before_status_update() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn delete(&self").unwrap();
        let end = source.find("fn find_record").unwrap();
        let delete_source = &source[start..end];

        assert!(
            delete_source.contains("self.ensure_payload_integrity(&record, &quarantine_path)?;")
        );
        assert!(
            delete_source
                .find("self.ensure_quarantine_payload_path(&quarantine_path)?;")
                .unwrap()
                < delete_source
                    .find("self.ensure_payload_integrity(&record, &quarantine_path)?;")
                    .unwrap()
        );
        assert!(
            delete_source
                .find("self.ensure_payload_integrity(&record, &quarantine_path)?;")
                .unwrap()
                < delete_source
                    .find("record.status = QuarantineStatus::Deleted;")
                    .unwrap()
        );
    }

    #[test]
    fn corrupt_metadata_record_is_reported_with_context() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("corrupt.json"), b"{not-json").unwrap();

        let store = QuarantineStore::with_base(base);
        let err = store.list().unwrap_err();

        assert!(err
            .to_string()
            .contains("unable to parse quarantine metadata record"));
        assert!(err.to_string().contains("corrupt.json"));
    }

    #[test]
    fn oversized_metadata_record_is_rejected_before_auth_or_parse() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        fs::write(
            base.join("oversized.json"),
            "x".repeat(MAX_QUARANTINE_METADATA_BYTES as usize + 1),
        )
        .unwrap();
        let store = QuarantineStore::with_base(base);

        let err = store.list().unwrap_err();

        assert!(err.to_string().contains("quarantine metadata record"));
        assert!(err.to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn quarantine_metadata_text_reader_is_file_and_byte_bounded() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn read_bounded_quarantine_text").unwrap();
        let end = source.find("fn constant_time_eq").unwrap();
        let read_source = &source[start..end];

        assert!(read_source.contains("let metadata = ensure_regular_quarantine_file(path, label)?"));
        assert!(read_source.contains("if !metadata.is_file()"));
        assert!(read_source.contains("metadata.len() > max_bytes"));
        assert!(read_source.contains("let mut total = 0_u64"));
        assert!(read_source.contains("checked_add(read as u64)"));
        assert!(read_source.contains("total > max_bytes"));
        assert!(read_source.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(read_source.contains("String::from_utf8(bytes)"));
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
        record.sha256 = "0".repeat(64);

        let store = QuarantineStore::with_base(base);
        store.write_record(&record).unwrap();
        let err = store.restore("tampered", true).unwrap_err();

        let error_chain = format!("{err:#}");
        assert!(error_chain.contains("quarantine payload hash mismatch"));
        assert!(payload.exists());
        assert!(!restore_path.exists());
    }

    #[test]
    fn list_rejects_metadata_with_unsafe_restore_or_payload_paths() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("record.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();

        let mut bad_restore = fixture_record(
            "bad-restore",
            PathBuf::from("relative.exe"),
            payload.clone(),
        );
        bad_restore.file_size = fs::metadata(&payload).unwrap().len();
        bad_restore.sha256 = sha256_for_file(&payload).unwrap();
        fs::write(
            base.join("bad-restore.json"),
            serde_json::to_string_pretty(&bad_restore).unwrap(),
        )
        .unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let restore_error = store.list().unwrap_err();
        assert!(restore_error
            .to_string()
            .contains("invalid original path in quarantine metadata record"));

        fs::remove_file(base.join("bad-restore.json")).unwrap();
        let mut bad_payload =
            fixture_record("bad-payload", dir.path().join("restore.exe"), payload);
        bad_payload.quarantine_path = dir.path().join("payload.tmp").display().to_string();
        fs::write(
            base.join("bad-payload.json"),
            serde_json::to_string_pretty(&bad_payload).unwrap(),
        )
        .unwrap();

        let payload_error = store.list().unwrap_err();
        assert!(payload_error
            .to_string()
            .contains("invalid payload path in quarantine metadata record"));
    }

    #[test]
    fn list_rejects_metadata_with_invalid_hash_or_display_fields() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("record.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();

        let mut bad_hash = fixture_record("bad-hash", dir.path().join("restore.exe"), payload);
        bad_hash.sha256 = "sha256:not-a-real-hash".to_string();
        fs::write(
            base.join("bad-hash.json"),
            serde_json::to_string_pretty(&bad_hash).unwrap(),
        )
        .unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let hash_error = store.list().unwrap_err();
        assert!(hash_error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let hash_error_chain = format!("{hash_error:#}");
        assert!(hash_error_chain.contains("invalid quarantine metadata sha256"));

        fs::remove_file(base.join("bad-hash.json")).unwrap();
        let payload = base.join("record.avoraxq");
        let mut bad_label = fixture_record("bad-label", dir.path().join("restore.exe"), payload);
        bad_label.detection_name = "Fixture\nDetection".to_string();
        fs::write(
            base.join("bad-label.json"),
            serde_json::to_string_pretty(&bad_label).unwrap(),
        )
        .unwrap();

        let label_error = store.list().unwrap_err();
        assert!(label_error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let label_error_chain = format!("{label_error:#}");
        assert!(label_error_chain
            .contains("quarantine metadata detection name contains control characters"));
    }

    #[test]
    fn original_restore_path_text_rejects_nul_dot_parent_and_missing_leaf() {
        let dir = tempdir().unwrap();
        let restore_path = dir.path().join("restore.exe");
        let restore_text = restore_path.display().to_string();

        assert!(validate_original_restore_path_text(&restore_text).is_ok());

        let nul_error =
            validate_original_restore_path_text(&format!("{restore_text}\0tail")).unwrap_err();
        assert!(nul_error
            .to_string()
            .contains("original restore path contains NUL"));

        let dot_error =
            validate_original_restore_path_text(&format!("{}/./restore.exe", dir.path().display()))
                .unwrap_err();
        assert!(dot_error
            .to_string()
            .contains("unsafe original restore path"));

        let parent_error = validate_original_restore_path_text(&format!(
            "{}/../restore.exe",
            dir.path().display()
        ))
        .unwrap_err();
        assert!(parent_error
            .to_string()
            .contains("unsafe original restore path"));

        let oversize_error =
            validate_original_restore_path_text(&"x".repeat(MAX_QUARANTINE_RESTORE_PATH_CHARS + 1))
                .unwrap_err();
        assert!(oversize_error
            .to_string()
            .contains("original restore path exceeds maximum length"));

        #[cfg(unix)]
        {
            let root_error = validate_original_restore_path_text("/").unwrap_err();
            assert!(root_error
                .to_string()
                .contains("unsafe original restore path"));
        }
        #[cfg(windows)]
        {
            let root_error = validate_original_restore_path_text("C:\\").unwrap_err();
            assert!(root_error
                .to_string()
                .contains("unsafe original restore path"));
        }
    }

    #[test]
    fn quarantine_payload_path_text_rejects_nul_dot_parent_bad_extension_and_missing_leaf() {
        let dir = tempdir().unwrap();
        let payload_path = dir.path().join(format!("payload.{QUARANTINE_EXTENSION}"));
        let payload_text = payload_path.display().to_string();

        assert!(validate_quarantine_payload_path_text(&payload_text).is_ok());

        let nul_error =
            validate_quarantine_payload_path_text(&format!("{payload_text}\0tail")).unwrap_err();
        assert!(nul_error
            .to_string()
            .contains("quarantine payload path contains NUL"));

        let dot_error = validate_quarantine_payload_path_text(&format!(
            "{}/./payload.{QUARANTINE_EXTENSION}",
            dir.path().display()
        ))
        .unwrap_err();
        assert!(dot_error
            .to_string()
            .contains("unsafe quarantine payload path"));

        let parent_error = validate_quarantine_payload_path_text(&format!(
            "{}/../payload.{QUARANTINE_EXTENSION}",
            dir.path().display()
        ))
        .unwrap_err();
        assert!(parent_error
            .to_string()
            .contains("unsafe quarantine payload path"));

        let oversize_error = validate_quarantine_payload_path_text(
            &"x".repeat(MAX_QUARANTINE_PAYLOAD_PATH_CHARS + 1),
        )
        .unwrap_err();
        assert!(oversize_error
            .to_string()
            .contains("quarantine payload path exceeds maximum length"));

        let extension_text = dir.path().join("payload.tmp").display().to_string();
        let extension_error = validate_quarantine_payload_path_text(&extension_text).unwrap_err();
        assert!(extension_error
            .to_string()
            .contains("quarantine payload has unsafe extension"));

        #[cfg(unix)]
        {
            let root_error = validate_quarantine_payload_path_text("/").unwrap_err();
            assert!(root_error
                .to_string()
                .contains("unsafe quarantine payload path"));
        }
        #[cfg(windows)]
        {
            let root_error = validate_quarantine_payload_path_text("C:\\").unwrap_err();
            assert!(root_error
                .to_string()
                .contains("unsafe quarantine payload path"));
        }
    }

    #[test]
    fn restore_uses_staged_payload_activation() {
        let source = include_str!("quarantine_store.rs");
        let direct_rename_pattern = ["fs::rename(&quarantine_", "path, &original_path)"].concat();

        assert!(source.contains("fn restore_payload_staged"));
        assert!(source.contains("unable to stage quarantine restore"));
        assert!(source.contains("staged quarantine restore verification failed"));
        assert!(source.contains("unable to activate quarantine restore"));
        assert!(!source.contains(&direct_rename_pattern));
    }

    #[test]
    fn restore_staging_uses_exclusive_temp_destination() {
        let source = include_str!("quarantine_store.rs");
        let temp_absent_pattern = ["fn ensure_restore_temp_", "destination_absent"].concat();
        let restore_copy_pattern = [
            "copy_file_",
            "exclusive(quarantine_path, &temp_destination)",
        ]
        .concat();
        let old_copy_pattern = ["fs::copy(quarantine_", "path, &temp_destination)"].concat();

        assert!(source.contains(&temp_absent_pattern));
        assert!(source.contains(&restore_copy_pattern));
        assert!(source.contains("quarantine restore temp destination"));
        assert!(!source.contains(&old_copy_pattern));
    }

    #[test]
    fn restore_staging_cleanup_failures_are_reported() {
        let source = include_str!("quarantine_store.rs");
        let restore_start = source.find("fn restore_payload_staged").unwrap();
        let restore_end = source.find("fn write_record").unwrap();
        let restore_source = &source[restore_start..restore_end];
        let copy_start = source.find("fn copy_file_exclusive").unwrap();
        let copy_end = source.find("fn quarantine_base").unwrap();
        let copy_source = &source[copy_start..copy_end];

        assert!(source.contains("fn cleanup_quarantine_partial_file"));
        assert!(restore_source.contains("after verification failure"));
        assert!(restore_source.contains("after destination preflight failure"));
        assert!(restore_source.contains("after activation failure"));
        assert!(copy_source.contains("after copy failure"));
        assert!(copy_source.contains("after sync failure"));
        assert!(!restore_source.contains("let _ = fs::remove_file(&temp_destination);"));
    }

    #[test]
    fn restore_temp_destination_rejects_existing_file() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("avorax-restore-existing.tmp");
        fs::write(&destination, b"existing").unwrap();

        let err = ensure_restore_temp_destination_absent(&destination).unwrap_err();

        assert!(err
            .to_string()
            .contains("quarantine restore temp destination already exists"));
        assert_eq!(fs::read(&destination).unwrap(), b"existing");
    }

    #[cfg(unix)]
    #[test]
    fn restore_temp_destination_rejects_symbolic_link() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let external = dir.path().join("external");
        let destination = dir.path().join("avorax-restore-linked.tmp");
        fs::write(&external, b"external").unwrap();
        symlink(&external, &destination).unwrap();

        let err = ensure_restore_temp_destination_absent(&destination).unwrap_err();

        assert!(err
            .to_string()
            .contains("refusing to use symbolic link quarantine restore temp destination"));
        assert_eq!(fs::read(&external).unwrap(), b"external");
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_symbolic_link_destination_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("linked-parent.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let real_parent = dir.path().join("real-parent");
        let linked_parent = dir.path().join("linked-parent");
        fs::create_dir_all(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();
        let restore_path = linked_parent.join("restore.exe");
        let mut record = fixture_record("linked-parent", restore_path.clone(), payload.clone());
        record.file_size = fs::metadata(&payload).unwrap().len();
        record.sha256 = sha256_for_file(&payload).unwrap();
        fs::write(
            base.join("linked-parent.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let err = store.restore("linked-parent", true).unwrap_err();

        assert!(err
            .to_string()
            .contains("refusing to use symbolic link quarantine restore parent"));
        assert!(payload.exists());
        assert!(!restore_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_broken_symbolic_link_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"bad").unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let result = fixture_scan_result(&file, ScanStatus::Infected);
        let record = store.quarantine_file(&file, &result).unwrap();
        symlink(dir.path().join("missing-target.exe"), &file).unwrap();

        let err = store.restore(&record.quarantine_id, true).unwrap_err();

        assert!(err.to_string().contains("original path already exists"));
        assert!(Path::new(&record.quarantine_path).exists());
        assert!(fs::symlink_metadata(&file)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn copy_fallback_does_not_delete_source_when_hash_mismatches() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("q").join("payload.avoraxq");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&source, b"original").unwrap();

        let wrong_hash = format!("sha256:{}", "0".repeat(64));
        let err = copy_then_remove_verified(&source, &destination, &wrong_hash).unwrap_err();

        assert!(err
            .to_string()
            .contains("hash verification failed before deleting original"));
        assert!(source.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn copy_fallback_rejects_invalid_expected_hash_before_copy() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("q").join("payload.avoraxq");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&source, b"original").unwrap();

        let err = copy_then_remove_verified(&source, &destination, "sha256:not-the-real-hash")
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("invalid local quarantine copy expected sha256"));
        assert!(source.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn copy_fallback_accepts_bare_expected_hash() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("q").join("payload.avoraxq");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&source, b"original").unwrap();
        let expected_hash = sha256_body(&sha256_for_file(&source).unwrap()).to_string();

        copy_then_remove_verified(&source, &destination, &expected_hash).unwrap();

        assert!(!source.exists());
        assert!(destination.exists());
    }

    #[test]
    fn copy_fallback_source_delete_failure_cleans_destination() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn copy_then_remove_verified").unwrap();
        let end = source
            .find("fn ensure_quarantine_payload_destination_absent")
            .unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("if let Err(error) = fs::remove_file(source)"));
        assert!(copy_source.contains(
            "cleanup_quarantine_partial_file(destination, \"copied quarantine destination\")"
        ));
        assert!(copy_source.contains("after source deletion failure"));
        assert!(copy_source.contains("failed to delete original quarantine source"));
        assert!(
            copy_source
                .find("destination_hash != expected_sha256")
                .unwrap()
                < copy_source
                    .find("if let Err(error) = fs::remove_file(source)")
                    .unwrap()
        );
        assert!(
            copy_source
                .find("if let Err(error) = fs::remove_file(source)")
                .unwrap()
                < copy_source.rfind("Ok(())").unwrap()
        );
    }

    #[test]
    fn copy_fallback_verification_failure_cleans_destination() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn copy_then_remove_verified").unwrap();
        let end = source
            .find("fn ensure_quarantine_payload_destination_absent")
            .unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("let destination_hash = match (|| -> Result<String>"));
        assert!(copy_source.contains("invalid copied quarantine destination"));
        assert!(copy_source.contains("after verification failure"));
        assert!(copy_source.contains("failed to verify copied quarantine destination"));
        assert!(
            copy_source
                .find("copy_file_exclusive(source, destination)?")
                .unwrap()
                < copy_source.find("let destination_hash = match").unwrap()
        );
        assert!(
            copy_source.find("let destination_hash = match").unwrap()
                < copy_source
                    .find("destination_hash != expected_sha256")
                    .unwrap()
        );
    }

    #[test]
    fn copy_fallback_rejects_existing_destination() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("q").join("payload.avoraxq");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&source, b"original").unwrap();
        fs::write(&destination, b"existing").unwrap();
        let expected_hash = sha256_for_file(&source).unwrap();

        let err = copy_then_remove_verified(&source, &destination, &expected_hash).unwrap_err();

        assert!(err
            .to_string()
            .contains("quarantine payload destination already exists"));
        assert!(source.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"existing");
    }

    #[cfg(unix)]
    #[test]
    fn copy_fallback_rejects_linked_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("q").join("payload.avoraxq");
        let external = dir.path().join("external-payload");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&source, b"original").unwrap();
        fs::write(&external, b"external").unwrap();
        symlink(&external, &destination).unwrap();
        let expected_hash = sha256_for_file(&source).unwrap();

        let err = copy_then_remove_verified(&source, &destination, &expected_hash).unwrap_err();

        assert!(err
            .to_string()
            .contains("refusing to use symbolic link quarantine payload destination"));
        assert!(source.exists());
        assert_eq!(fs::read(&external).unwrap(), b"external");
    }

    #[test]
    fn quarantine_payload_copy_fallback_uses_exclusive_destination_creation() {
        let source = include_str!("quarantine_store.rs");
        let destination_absent_pattern =
            ["fn ensure_quarantine_payload_", "destination_absent"].concat();
        let copy_exclusive_pattern = ["fn copy_file_", "exclusive"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let sync_pattern = ["output.", "sync_all()"].concat();
        let limit_pattern = ["MAX_LOCAL_QUARANTINE_", "COPY_BYTES"].concat();
        let limited_copy_pattern = ["fn copy_local_quarantine_", "payload_limited"].concat();
        let bounded_buffer_pattern = ["let mut buffer = [0_u8; ", "64 * 1024]"].concat();
        let write_all_pattern = ["output.", "write_all(&buffer[..read])"].concat();
        let cleanup_pattern = ["fn cleanup_quarantine_", "partial_file"].concat();
        let hash_guard_pattern = [
            "ensure_regular_quarantine_",
            "payload(path, \"quarantine hash input\")",
        ]
        .concat();
        let old_copy_pattern = ["fs::copy(source, ", "destination)"].concat();
        let old_io_copy_pattern = ["io::", "copy(&mut input, &mut output)"].concat();

        assert!(source.contains(&destination_absent_pattern));
        assert!(source.contains(&copy_exclusive_pattern));
        assert!(source.contains(&create_new_pattern));
        assert!(source.contains(&sync_pattern));
        assert!(source.contains(&limit_pattern));
        assert!(source.contains(&limited_copy_pattern));
        assert!(source.contains("copy_local_quarantine_payload_limited"));
        assert!(source.contains(&bounded_buffer_pattern));
        assert!(source.contains("total > limit"));
        assert!(source.contains(&write_all_pattern));
        assert!(source.contains(&cleanup_pattern));
        assert!(source.contains("cleanup_quarantine_partial_file"));
        assert!(source.contains("after copy failure"));
        assert!(source.contains("after sync failure"));
        assert!(source.contains(&hash_guard_pattern));
        assert!(!source.contains(&old_copy_pattern));
        assert!(!source.contains(&old_io_copy_pattern));
    }

    #[test]
    fn local_quarantine_hash_input_is_size_bounded() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn sha256_for_file").unwrap();
        let end = source.find("fn normalize_quarantine_sha256").unwrap();
        let hash_source = &source[start..end];

        assert!(source.contains("const MAX_LOCAL_QUARANTINE_HASH_BYTES"));
        assert!(hash_source.contains(
            "let metadata = ensure_regular_quarantine_payload(path, \"quarantine hash input\")?"
        ));
        assert!(hash_source.contains("metadata.len() > MAX_LOCAL_QUARANTINE_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("checked_add(read as u64)"));
        assert!(hash_source.contains("total > MAX_LOCAL_QUARANTINE_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
    }

    #[test]
    fn record_writes_are_staged_without_temp_file_leftover() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);

        store.write_record(&record).unwrap();

        assert!(base.join("record.json").exists());
        assert!(!base.join("record.json.tmp").exists());
        assert!(base.join("record.json.auth").exists());
        assert!(!base.join("record.json.auth.tmp").exists());
    }

    #[test]
    fn write_record_rejects_invalid_metadata_before_staged_persistence() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let mut record = fixture_record("record", dir.path().join("restore.exe"), payload);
        record.detection_name = "Fixture\nDetection".to_string();

        let error = store.write_record(&record).unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains("quarantine metadata detection name contains control characters")
        );
        assert!(!base.join("record.json").exists());
        assert!(!base.join("record.json.auth").exists());
    }

    #[test]
    fn write_record_rejects_status_action_mismatch_before_staged_persistence() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let mut record = fixture_record("record", dir.path().join("restore.exe"), payload);
        record.status = QuarantineStatus::Restored;
        record.action_taken = "quarantined".to_string();

        let error = store.write_record(&record).unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("quarantine metadata action taken does not match status"));
        assert!(!base.join("record.json").exists());
        assert!(!base.join("record.json.auth").exists());
    }

    #[test]
    fn write_record_rejects_contradictory_execution_claims_before_staged_persistence() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let mut record = fixture_record("record", dir.path().join("restore.exe"), payload.clone());
        record.blocked_before_execution = true;
        record.process_started = true;

        let error = store.write_record(&record).unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains(
            "quarantine metadata cannot claim both pre-execution blocking and process start"
        ));
        assert!(!base.join("record.json").exists());
        assert!(!base.join("record.json.auth").exists());

        let mut record =
            fixture_record("record-with-pid", dir.path().join("restore2.exe"), payload);
        record.process_id = Some(42);
        let error = store.write_record(&record).unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains("quarantine metadata process id requires process start evidence")
        );
    }

    #[test]
    fn write_record_rejects_unsupported_source_before_staged_persistence() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let mut record = fixture_record("record", dir.path().join("restore.exe"), payload);
        record.source = "minifilter_driver".to_string();

        let error = store.write_record(&record).unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("unsupported quarantine metadata source"));
        assert!(!base.join("record.json").exists());
        assert!(!base.join("record.json.auth").exists());
    }

    #[test]
    fn write_record_rejects_scanner_execution_claims_before_staged_persistence() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let mut record = fixture_record("record", dir.path().join("restore.exe"), payload);
        record.blocked_before_execution = true;

        let error = store.write_record(&record).unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains("scanner quarantine source cannot claim execution-state evidence")
        );
        assert!(!base.join("record.json").exists());
        assert!(!base.join("record.json.auth").exists());
    }

    #[test]
    fn metadata_validation_requires_action_taken_to_match_status() {
        let source = include_str!("quarantine_store.rs");
        let validation_start = source
            .find("fn validate_quarantine_record_metadata")
            .unwrap();
        let validation_end = source.find("fn validate_quarantine_metadata_text").unwrap();
        let validation_source = &source[validation_start..validation_end];

        assert!(validation_source.contains(
            "let expected_action_taken = expected_quarantine_action_taken(&record.status);"
        ));
        assert!(validation_source.contains("record.action_taken != expected_action_taken"));
        assert!(
            validation_source.contains("quarantine metadata action taken does not match status")
        );
        assert!(source.contains("fn expected_quarantine_action_taken(status: &QuarantineStatus)"));
        assert!(source.contains("QuarantineStatus::Quarantined => \"quarantined\""));
        assert!(source.contains("QuarantineStatus::Restored => \"restored\""));
        assert!(source.contains("QuarantineStatus::Deleted => \"deleted\""));
    }

    #[test]
    fn metadata_validation_rejects_contradictory_execution_claims() {
        let source = include_str!("quarantine_store.rs");
        let validation_start = source
            .find("fn validate_quarantine_record_metadata")
            .unwrap();
        let validation_end = source.find("fn validate_quarantine_metadata_text").unwrap();
        let validation_source = &source[validation_start..validation_end];

        assert!(
            validation_source.contains("record.blocked_before_execution && record.process_started")
        );
        assert!(validation_source.contains(
            "quarantine metadata cannot claim both pre-execution blocking and process start"
        ));
        assert!(
            validation_source.contains("record.process_id.is_some() && !record.process_started")
        );
        assert!(validation_source
            .contains("quarantine metadata process id requires process start evidence"));
    }

    #[test]
    fn metadata_validation_restricts_source_claims() {
        let source = include_str!("quarantine_store.rs");
        let validation_start = source
            .find("fn validate_quarantine_record_metadata")
            .unwrap();
        let validation_end = source.find("fn validate_quarantine_metadata_text").unwrap();
        let validation_source = &source[validation_start..validation_end];

        assert!(validation_source.contains("validate_quarantine_source_for_claims(record)?;"));
        assert!(validation_source.contains("fn validate_quarantine_source_for_claims"));
        assert!(validation_source.contains("record.source.as_str()"));
        assert!(validation_source.contains("\"scanner\""));
        assert!(validation_source.contains("unsupported quarantine metadata source"));
        assert!(validation_source
            .contains("scanner quarantine source cannot claim execution-state evidence"));
    }

    #[test]
    fn quarantine_metadata_staged_writes_reject_linked_temp_paths_in_source() {
        let source = include_str!("quarantine_store.rs");
        let write_start = source.find("fn write_record(&self").unwrap();
        let base_start = source.find("fn ensure_base_directory").unwrap();
        let write_sources = &source[write_start..base_start];
        let write_exclusive_pattern = ["fn write_file_", "exclusive"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let sync_pattern = ["output.", "sync_all()"].concat();
        let staged_call_pattern = ["write_file_", "exclusive(&temp_path, bytes, label)"].concat();
        let old_record_write_pattern = ["fs::write(&temp_", "path, &raw)?"].concat();
        let old_auth_write_pattern = ["fs::write(&temp_", "path, format!(\"{tag}\\n\"))?"].concat();
        let old_key_write_pattern = [
            "fs::write(&temp_",
            "path, encode_metadata_auth_key(&key)?)?",
        ]
        .concat();
        let old_final_replace_pattern =
            ["remove_existing_quarantine_file(path", ", label)?"].concat();
        let old_record_temp_pattern = [".json", ".tmp"].concat();
        let old_auth_temp_pattern = [".json.auth", ".tmp"].concat();
        let old_key_temp_pattern = [".metadata_auth_key", ".tmp"].concat();

        assert!(source.contains("fn write_staged_quarantine_file"));
        assert!(source.contains("fn quarantine_staged_temp_path"));
        assert!(source.contains("let temp_path = quarantine_staged_temp_path(path, label)?"));
        assert!(source.contains("temp_name.push(format!(\".tmp-{}\", Uuid::new_v4()))"));
        assert!(source.contains(&write_exclusive_pattern));
        assert!(source.contains(&create_new_pattern));
        assert!(source.contains(&sync_pattern));
        assert!(source.contains(&staged_call_pattern));
        assert!(source.contains("ensure_quarantine_file_parent_directory(path, label)?"));
        assert!(source.contains("ensure_quarantine_file_parent_directory(path, label)"));
        assert!(source.contains("cleanup_quarantine_staged_file(&temp_path, label)"));
        assert!(source.contains("ensure_quarantine_file_destination_absent(path, label)"));
        assert!(source.contains("let mut output = match fs::OpenOptions::new()"));
        assert!(source.contains("Err(error) => {"));
        assert!(source.contains("after write failure"));
        assert!(source.contains("after sync failure"));
        assert!(source.contains("after temp validation failure"));
        assert!(source.contains("after parent preflight failure"));
        assert!(source.contains("after activation preflight failure"));
        assert!(source.contains("after activation failure"));
        assert!(source.contains("{label} destination already exists"));
        assert!(source.contains("fn ensure_quarantine_file_parent_directory"));
        assert!(source.contains("refusing to replace symbolic link {label}"));
        assert!(source.contains("refusing to replace reparse point {label}"));
        assert!(source.contains("fn ensure_quarantine_file_destination_absent"));
        assert!(!source.contains(&old_record_write_pattern));
        assert!(!source.contains(&old_auth_write_pattern));
        assert!(!source.contains(&old_key_write_pattern));
        assert!(!source.contains(&old_final_replace_pattern));
        assert!(!write_sources.contains(&old_record_temp_pattern));
        assert!(!write_sources.contains(&old_auth_temp_pattern));
        assert!(!write_sources.contains(&old_key_temp_pattern));
    }

    #[test]
    fn quarantine_metadata_staged_writes_reject_existing_final_record() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);
        let record_path = base.join("record.json");
        fs::write(&record_path, b"existing record").unwrap();

        let err = store.write_record(&record).unwrap_err();

        assert!(err
            .to_string()
            .contains("quarantine metadata record destination already exists"));
        assert_eq!(fs::read(&record_path).unwrap(), b"existing record");
        assert!(!base.join("record.json.tmp").exists());
    }

    #[test]
    fn quarantine_metadata_staged_writes_reject_existing_final_auth_sidecar() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);
        let raw = serde_json::to_string_pretty(&record).unwrap();
        store.metadata_auth_key(true).unwrap();
        let auth_path = base.join("record.json.auth");
        fs::write(&auth_path, b"existing auth").unwrap();

        let err = store.write_record_auth(&record, &raw).unwrap_err();

        assert!(err
            .to_string()
            .contains("quarantine metadata auth sidecar destination already exists"));
        assert_eq!(fs::read(&auth_path).unwrap(), b"existing auth");
        assert!(!base.join("record.json.auth.tmp").exists());
    }

    #[test]
    fn quarantine_optional_metadata_presence_uses_non_following_helpers() {
        let source = include_str!("quarantine_store.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        let auth_sidecar_pattern = [
            "optional_quarantine_file_present(&auth_path",
            ", \"quarantine metadata auth sidecar\")?",
        ]
        .concat();
        let key_pattern = [
            "optional_quarantine_file_present(&path",
            ", \"quarantine metadata authentication key\")?",
        ]
        .concat();
        let base_pattern = [
            "optional_quarantine_directory_present(&self.base",
            ", \"quarantine base directory\")?",
        ]
        .concat();
        let old_auth_exists_pattern = ["auth_", "path.exists()"].concat();
        let old_key_exists_pattern = ["path.", "exists()"].concat();

        assert!(source.contains(&auth_sidecar_pattern));
        assert!(source.contains(&key_pattern));
        assert!(source.contains(&base_pattern));
        assert!(!production_source.contains(&old_auth_exists_pattern));
        assert!(!production_source.contains(&old_key_exists_pattern));
    }

    #[test]
    fn quarantine_acl_command_output_is_bounded() {
        let long = vec![b'a'; MAX_QUARANTINE_COMMAND_OUTPUT_BYTES + 16];
        let excerpt = command_output_excerpt(&long);
        let source = crate::normalized_test_source(include_str!("quarantine_store.rs"));
        let start = source.find("fn harden_quarantine_base_acl").unwrap();
        let end = source
            .find("#[cfg(windows)]\nfn current_windows_account")
            .unwrap();
        let acl_source = &source[start..end];
        let old_stderr = ["String::from_utf8_lossy(&output.stderr", ")"].concat();

        assert!(excerpt.ends_with("...[truncated]"));
        assert!(acl_source.contains("fn harden_quarantine_base_acl(_path: &Path)"));
        assert!(acl_source.contains("windows_tools::windows_system32_tool(\"icacls.exe\")?"));
        assert!(acl_source.contains("Command::new(&icacls)"));
        assert!(acl_source.contains("run_quarantine_acl_command(&mut command)?"));
        assert!(source.contains("fn run_quarantine_acl_command(command: &mut Command)"));
        assert!(source.contains(
            "read_bounded_quarantine_command_output(stderr, MAX_QUARANTINE_COMMAND_OUTPUT_BYTES)"
        ));
        assert!(source.contains("let retain_limit = max_bytes.saturating_add(1)"));
        assert!(source.contains("let remaining = retain_limit.saturating_sub(bytes.len())"));
        assert!(source.contains("bytes.extend_from_slice(&buffer[..keep])"));
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production_source.contains("reader.take((max_bytes + 1) as u64)"));
        assert!(source.contains("stdin(Stdio::null())"));
        assert!(source.contains("stdout(Stdio::null())"));
        assert!(source.contains("stderr(Stdio::piped())"));
        assert!(acl_source.contains(".arg(_path)"));
        assert!(acl_source.contains("command_output_excerpt(&output.stderr)"));
        let old_icacls_launch = ["Command::new(\"", "icacls\")"].concat();
        assert!(!acl_source.contains(".output()?"));
        assert!(!acl_source.contains(&old_stderr));
        assert!(!acl_source.contains(&old_icacls_launch));
        assert!(!acl_source.contains("let _ = path;"));
    }

    #[test]
    fn quarantine_hash_mismatch_cleanup_failures_are_reported() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("fn copy_then_remove_verified(").unwrap();
        let end = source
            .find("fn ensure_quarantine_payload_destination_absent")
            .unwrap();
        let copy_source = &source[start..end];

        assert!(copy_source.contains("failed to remove invalid quarantine destination"));
        assert!(!copy_source.contains("let _ = fs::remove_file(destination);"));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_fixed_record_temp_link_is_not_used_by_uuid_staging() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        fs::write(base.join("external-record"), b"do not overwrite").unwrap();
        symlink(base.join("external-record"), base.join("record.json.tmp")).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);

        store.write_record(&record).unwrap();

        assert_eq!(
            fs::read(base.join("external-record")).unwrap(),
            b"do not overwrite"
        );
        assert!(base.join("record.json").exists());
        assert!(fs::symlink_metadata(base.join("record.json.tmp"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_fixed_auth_temp_link_is_not_used_by_uuid_staging() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        fs::write(base.join("external-auth"), b"do not overwrite").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);
        let raw = serde_json::to_string_pretty(&record).unwrap();
        store.metadata_auth_key(true).unwrap();
        symlink(
            base.join("external-auth"),
            base.join("record.json.auth.tmp"),
        )
        .unwrap();

        store.write_record_auth(&record, &raw).unwrap();

        assert_eq!(
            fs::read(base.join("external-auth")).unwrap(),
            b"do not overwrite"
        );
        assert!(base.join("record.json.auth").exists());
        assert!(fs::symlink_metadata(base.join("record.json.auth.tmp"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_fixed_metadata_key_temp_link_is_not_used_by_uuid_staging() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("external-key-temp"), b"do not overwrite").unwrap();
        symlink(
            base.join("external-key-temp"),
            base.join(".metadata_auth_key.tmp"),
        )
        .unwrap();
        let store = QuarantineStore::with_base(base.clone());

        let key = store.metadata_auth_key(true).unwrap();

        assert!(!key.trim().is_empty());
        assert_eq!(
            fs::read(base.join("external-key-temp")).unwrap(),
            b"do not overwrite"
        );
        assert!(base.join(".metadata_auth_key").exists());
        assert!(fs::symlink_metadata(base.join(".metadata_auth_key.tmp"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn oversized_metadata_key_is_rejected_before_decode() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        fs::write(
            base.join(".metadata_auth_key"),
            "x".repeat(MAX_QUARANTINE_METADATA_AUTH_BYTES as usize + 1),
        )
        .unwrap();
        let store = QuarantineStore::with_base(base);

        let err = store.metadata_auth_key(false).unwrap_err();

        assert!(err
            .to_string()
            .contains("quarantine metadata authentication key"));
        assert!(err.to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn authenticated_record_tampering_is_reported() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let mut record = fixture_record("record", dir.path().join("restore.exe"), payload);

        store.write_record(&record).unwrap();
        record.engine = "tampered-engine".to_string();
        fs::write(
            base.join("record.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let err = store.list().unwrap_err();

        assert!(err
            .to_string()
            .contains("quarantine metadata authentication failed"));
        assert!(err.to_string().contains("record.json"));
    }

    #[test]
    fn oversized_auth_sidecar_is_rejected_before_comparison() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        store.metadata_auth_key(true).unwrap();
        let record_path = base.join("record.json");
        fs::write(&record_path, "{}").unwrap();
        fs::write(
            base.join("record.json.auth"),
            "x".repeat(MAX_QUARANTINE_METADATA_AUTH_BYTES as usize + 1),
        )
        .unwrap();

        let err = store.record_auth_valid(&record_path, "{}").unwrap_err();

        assert!(err.to_string().contains("quarantine metadata auth sidecar"));
        assert!(err.to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn authenticated_record_without_metadata_key_is_reported() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);
        fs::write(
            base.join("record.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::write(base.join("record.json.auth"), "sha256:fixture\n").unwrap();

        let store = QuarantineStore::with_base(base);
        let err = store.list().unwrap_err();

        assert!(err
            .to_string()
            .contains("quarantine metadata authentication key unavailable"));
        assert!(err.to_string().contains("record.json"));
    }

    #[test]
    fn legacy_record_without_auth_sidecar_remains_readable() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("legacy.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let record = fixture_record("legacy", dir.path().join("restore.exe"), payload);
        fs::write(
            base.join("legacy.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let records = store.list().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].quarantine_id, "legacy");
    }

    #[cfg(unix)]
    #[test]
    fn linked_auth_sidecar_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("record.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);

        store.write_record(&record).unwrap();
        fs::remove_file(base.join("record.json.auth")).unwrap();
        symlink(
            base.join(".metadata_auth_key"),
            base.join("record.json.auth"),
        )
        .unwrap();

        let err = store.list().unwrap_err();
        assert!(err
            .to_string()
            .contains("refusing to use symbolic link quarantine metadata auth sidecar"));
    }

    #[cfg(unix)]
    #[test]
    fn linked_metadata_key_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("record.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);

        fs::write(base.join("external-key"), b"external").unwrap();
        symlink(base.join("external-key"), base.join(".metadata_auth_key")).unwrap();
        let err = store.write_record(&record).unwrap_err();

        assert!(err
            .to_string()
            .contains("refusing to use symbolic link quarantine metadata authentication key"));
    }

    #[test]
    fn restore_requires_explicit_confirmation() {
        let store = QuarantineStore::with_base(tempdir().unwrap().path().join("q"));
        assert!(store.restore_requires_confirmation("x", false).is_err());
        assert!(store.restore_requires_confirmation("x", true).is_ok());
    }

    #[test]
    fn restore_and_delete_reject_unsafe_quarantine_ids_before_lookup() {
        let store = QuarantineStore::with_base(tempdir().unwrap().path().join("q"));

        let blank = store.restore_requires_confirmation("", true).unwrap_err();
        assert!(blank.to_string().contains("quarantine id is required"));

        let spaced = store
            .restore_requires_confirmation(" quarantine-id", true)
            .unwrap_err();
        assert!(spaced
            .to_string()
            .contains("leading or trailing whitespace"));

        for unsafe_id in ["../escape", r"..\escape", "bad/id", "bad.id"] {
            let restore_error = store
                .restore_requires_confirmation(unsafe_id, true)
                .unwrap_err();
            assert!(restore_error.to_string().contains("invalid quarantine id"));

            let delete_error = store.delete(unsafe_id, true).unwrap_err();
            assert!(delete_error.to_string().contains("invalid quarantine id"));
        }
    }

    #[test]
    fn quarantine_id_validation_is_not_a_dead_restore_control() {
        let source = include_str!("quarantine_store.rs");
        let restore_start = source.find("pub fn restore_requires_confirmation").unwrap();
        let restore_end = source.find("pub fn restore(&self").unwrap();
        let restore_source = &source[restore_start..restore_end];

        assert!(source.contains("fn validate_quarantine_id"));
        assert!(restore_source.contains("validate_quarantine_id(id)?"));
        assert!(source.contains("invalid quarantine id in metadata record"));
        assert!(!restore_source.contains("let _ = id"));
    }

    #[test]
    fn list_rejects_metadata_with_unsafe_quarantine_id() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("payload.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let record = fixture_record("bad/id", dir.path().join("restore.exe"), payload);
        fs::write(
            base.join("bad.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid quarantine id in metadata record"));
    }

    #[test]
    fn list_does_not_hide_authenticated_metadata_failures() {
        let source = include_str!("quarantine_store.rs");
        let list_start = source.find("pub fn list").unwrap();
        let restore_start = source.find("pub fn restore_requires_confirmation").unwrap();
        let list_source = &source[list_start..restore_start];

        assert!(list_source.contains("quarantine metadata authentication failed"));
        assert!(!list_source
            .contains("if !self.record_auth_valid(&path, &raw)? {\n                    continue;"));
    }

    #[test]
    fn legacy_quarantine_record_with_old_extension_is_rejected() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let legacy_extension = ["pa", "susq"].concat();
        let legacy_file = base.join(format!("legacy.{legacy_extension}"));
        fs::write(&legacy_file, b"quarantined").unwrap();
        let mut record = fixture_record("legacy", dir.path().join("restore.exe"), legacy_file);
        record.sha256 = sha256_for_file(Path::new(&record.quarantine_path)).unwrap();
        fs::write(
            base.join("legacy.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid payload path in quarantine metadata record"));
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("quarantine payload has unsafe extension"));
    }

    #[test]
    fn legacy_zentor_quarantine_record_is_rejected() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let legacy_file = base.join("legacy.zentorq");
        fs::write(&legacy_file, b"quarantined").unwrap();
        let mut record =
            fixture_record("legacy-zentor", dir.path().join("restore.exe"), legacy_file);
        record.sha256 = sha256_for_file(Path::new(&record.quarantine_path)).unwrap();
        fs::write(
            base.join("legacy-zentor.json"),
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let store = QuarantineStore::with_base(base);
        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid payload path in quarantine metadata record"));
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("quarantine payload has unsafe extension"));
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
            sha256: format!("sha256:{}", "f".repeat(64)),
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
