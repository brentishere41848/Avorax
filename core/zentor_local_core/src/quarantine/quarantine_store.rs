use std::fs;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
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
const QUARANTINE_AUTH_HMAC_PREFIX: &str = "hmac-sha256:";
const QUARANTINE_AUTH_HMAC_DOMAIN: &[u8] = b"avorax-quarantine-record-v2\0";
const QUARANTINE_FINALIZATION_JOURNAL_FORMAT: &str = "avorax-quarantine-finalization-journal-v1";
const QUARANTINE_FINALIZATION_JOURNAL_AUTH_DOMAIN: &[u8] =
    b"avorax-quarantine-finalization-journal-v1\0";
const QUARANTINE_METADATA_UPDATE_JOURNAL_FORMAT: &str =
    "avorax-quarantine-metadata-update-journal-v1";
const QUARANTINE_METADATA_UPDATE_JOURNAL_AUTH_DOMAIN: &[u8] =
    b"avorax-quarantine-metadata-update-journal-v1\0";
const MAX_QUARANTINE_METADATA_UPDATE_JOURNAL_BYTES: u64 = 1024 * 1024;
const QUARANTINE_ACTION_JOURNAL_FORMAT: &str = "avorax-quarantine-action-journal-v1";
const QUARANTINE_ACTION_JOURNAL_AUTH_DOMAIN: &[u8] = b"avorax-quarantine-action-journal-v1\0";
const MAX_QUARANTINE_ACTION_JOURNAL_BYTES: u64 = 1024 * 1024;
const MAX_QUARANTINE_RECOVERY_ENTRIES: usize = 65_536;
const QUARANTINE_AUTH_LEGACY_DOMAIN: &[u8] = b"avorax-quarantine-record-v1\0";
const QUARANTINE_AUTH_GUARD_LEGACY_DOMAIN: &[u8] = b"avorax-guard-quarantine-record-v1\0";
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuarantineMetadataAuthScheme {
    HmacSha256V2,
    LegacyPrefixSha256V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExclusiveCopySecurity {
    Quarantine,
    Restore,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuarantineFinalizationJournal {
    format: String,
    record: QuarantineRecord,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuarantineMetadataUpdateJournal {
    body: QuarantineMetadataUpdateJournalBody,
    authentication: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuarantineMetadataUpdateJournalBody {
    format: String,
    quarantine_id: String,
    previous_record_raw: String,
    previous_record_auth: String,
    next_record_raw: String,
    next_record_auth: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum QuarantineLifecycleAction {
    Restore,
    Delete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum QuarantineActionPhase {
    Prepared,
    RestoreReserved,
    RestoreStaged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedFileIdentity {
    platform: String,
    scope: u64,
    file: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuarantineActionJournal {
    body: QuarantineActionJournalBody,
    authentication: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuarantineActionJournalBody {
    format: String,
    quarantine_id: String,
    action: QuarantineLifecycleAction,
    phase: QuarantineActionPhase,
    previous_record_raw: String,
    previous_record_auth: String,
    next_record_raw: String,
    next_record_auth: String,
    restore_staging_path: Option<String>,
    restore_identity: Option<PersistedFileIdentity>,
}

pub struct QuarantineStore {
    base: PathBuf,
}

impl QuarantineStore {
    pub fn new() -> Result<Self> {
        Ok(Self {
            base: quarantine_base()?,
        })
    }

    #[cfg(test)]
    fn with_base(base: PathBuf) -> Self {
        Self { base }
    }

    pub fn quarantine_file(&self, path: &Path, result: &ScanResult) -> Result<QuarantineRecord> {
        validate_quarantine_scan_status(result)?;
        let expected_sha256 = normalize_quarantine_sha256(&result.sha256)
            .with_context(|| "infected scan result has an invalid SHA-256")?;
        let id = Uuid::new_v4().to_string();
        let quarantine_path = self.base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        let original_path = path.display().to_string();
        if result.scanned_path != original_path {
            return Err(anyhow!(
                "quarantine scan-result path does not match the selected source; rescan required"
            ));
        }
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
        ensure_regular_quarantine_source(path)?;
        let source_link_guard = open_single_link_quarantine_file(path, "quarantine source")?;
        let metadata = source_link_guard.metadata().with_context(|| {
            format!(
                "failed to inspect opened quarantine source {}",
                path.display()
            )
        })?;
        let source_sha256 = sha256_for_open_file(&source_link_guard, path)?;
        if source_sha256 != expected_sha256 {
            return Err(anyhow!(
                "quarantine source changed after its scan verdict; rescan required before quarantine"
            ));
        }
        self.ensure_base_directory()?;
        let record = QuarantineRecord {
            quarantine_id: id.clone(),
            original_path,
            quarantine_path: quarantine_path_text,
            sha256: source_sha256.clone(),
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
        ensure_quarantine_payload_destination_absent(&quarantine_path)?;
        let _finalization_journal_lock = self.write_finalization_journal(&record)?;
        let move_result = avorax_platform_security::ensure_open_file_has_single_link(
            &source_link_guard,
            path,
            "quarantine source immediately before move",
        )
        .and_then(|_| {
            ensure_regular_quarantine_source(path)?;
            avorax_platform_security::ensure_path_matches_open_file(
                &source_link_guard,
                path,
                "quarantine source immediately before move",
            )
            .context("quarantine source identity changed after scan; rescan required")
        })
        .and_then(|_| move_quarantine_payload_no_replace(path, &quarantine_path, &source_sha256));
        if let Err(error) = move_result {
            match optional_quarantine_path_present(
                &quarantine_path,
                "quarantine destination after source move failure",
            ) {
                Ok(true) => {
                    return Err(error).with_context(|| {
                        format!(
                            "quarantine source move failed and left a destination artifact; authenticated recovery journal was retained at {}",
                            quarantine_path.display()
                        )
                    });
                }
                Err(inspection_error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "quarantine source move failed and destination absence could not be established; authenticated recovery journal was retained at {}: {inspection_error:#}",
                            quarantine_path.display()
                        )
                    });
                }
                Ok(false) => {}
            }
            self.cleanup_finalization_journal(&id).with_context(|| {
                format!(
                    "failed to clean up unused quarantine finalization journal after source move failure: {error:#}"
                )
            })?;
            return Err(error);
        }
        let finalize_result = (|| -> Result<QuarantineRecord> {
            ensure_regular_quarantine_payload(&quarantine_path, "quarantine payload")?;
            harden_quarantine_payload_permissions(&quarantine_path)?;
            let quarantined_sha256 = sha256_for_file(&quarantine_path)?;
            if !source_sha256.eq_ignore_ascii_case(&quarantined_sha256) {
                return Err(anyhow!("quarantine payload hash changed during move"));
            }
            self.write_record(&record)?;
            Ok(record)
        })();
        match finalize_result {
            Ok(record) => {
                self.cleanup_finalization_journal(&id).with_context(|| {
                    format!(
                        "quarantine record was finalized but its recovery journal could not be removed for {}",
                        quarantine_path.display()
                    )
                })?;
                Ok(record)
            }
            Err(error) => {
                cleanup_untracked_quarantine_metadata_artifacts(&self.base, &id)
                    .with_context(|| {
                        format!(
                            "failed to clean up incomplete quarantine metadata after finalization failure; payload and authenticated recovery journal were retained at {}: {error:#}",
                            quarantine_path.display()
                        )
                    })?;
                Err(error).with_context(|| {
                    format!(
                        "quarantine finalization failed; payload and authenticated recovery journal were retained for bounded retry at {}",
                        quarantine_path.display()
                    )
                })
            }
        }
    }

    fn write_finalization_journal(&self, record: &QuarantineRecord) -> Result<fs::File> {
        validate_quarantine_record_for_write(record)?;
        if record.status != QuarantineStatus::Quarantined {
            return Err(anyhow!(
                "quarantine finalization journal requires quarantined status"
            ));
        }
        self.ensure_base_directory()?;
        self.ensure_action_journal_absent(&record.quarantine_id, "finalize")?;
        let path = self.finalization_journal_path(&record.quarantine_id)?;
        let auth_path = self.finalization_journal_auth_path(&record.quarantine_id)?;
        let journal = QuarantineFinalizationJournal {
            format: QUARANTINE_FINALIZATION_JOURNAL_FORMAT.to_string(),
            record: record.clone(),
        };
        let raw = serde_json::to_string_pretty(&journal)?;
        let Some(key) = self.metadata_auth_key(true)? else {
            return Err(anyhow!(
                "quarantine finalization journal authentication key unavailable"
            ));
        };
        let tag = hmac_finalization_journal_auth_tag(&key, &raw)?;
        write_staged_quarantine_file(
            &auth_path,
            format!("{tag}\n").as_bytes(),
            "quarantine finalization journal auth sidecar",
        )?;
        if let Err(error) =
            write_staged_quarantine_file(&path, raw.as_bytes(), "quarantine finalization journal")
        {
            cleanup_quarantine_partial_file(
                &auth_path,
                "unused quarantine finalization journal auth sidecar",
            )
            .with_context(|| {
                format!(
                    "failed to clean up journal auth sidecar after journal write failure: {error:#}"
                )
            })?;
            return Err(error);
        }
        let (journal_lock, persisted) =
            read_locked_bounded_quarantine_text(
                &path,
                MAX_QUARANTINE_METADATA_BYTES,
                "quarantine finalization journal",
            )
            .with_context(|| {
                format!(
                    "unable to lock persisted quarantine finalization journal {}; source was not moved and recovery evidence was retained",
                    path.display()
                )
            })?;
        if persisted != raw {
            self.cleanup_finalization_journal(&record.quarantine_id)?;
            return Err(anyhow!(
                "quarantine finalization journal changed after write"
            ));
        }
        if let Err(error) = self.ensure_finalization_journal_auth_valid(&path, &persisted) {
            self.cleanup_finalization_journal(&record.quarantine_id)
                .with_context(|| {
                    format!("failed to clean up invalid quarantine finalization journal: {error:#}")
                })?;
            return Err(error);
        }
        self.ensure_action_journal_absent(&record.quarantine_id, "finalize")?;
        Ok(journal_lock)
    }

    fn recover_pending_finalizations(&self) -> Result<()> {
        let mut actions = Vec::new();
        let mut metadata_updates = Vec::new();
        let mut journals = Vec::new();
        let mut journal_auth = Vec::new();
        let mut count = 0_usize;
        for entry in fs::read_dir(&self.base)
            .context("unable to enumerate quarantine finalization journals")?
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| anyhow!("quarantine recovery entry count overflow"))?;
            if count > MAX_QUARANTINE_RECOVERY_ENTRIES {
                return Err(anyhow!(
                    "quarantine recovery exceeds the entry limit of {MAX_QUARANTINE_RECOVERY_ENTRIES}"
                ));
            }
            let entry = entry.context("unable to read quarantine recovery directory entry")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("quarantine recovery entry name is not Unicode"))?;
            if let Some(id) = name.strip_suffix(".action.pending") {
                validate_quarantine_id(id)?;
                actions.push((id.to_string(), entry.path()));
            } else if let Some(id) = name.strip_suffix(".update.pending") {
                validate_quarantine_id(id)?;
                metadata_updates.push((id.to_string(), entry.path()));
            } else if let Some(id) = name.strip_suffix(".pending.auth") {
                validate_quarantine_id(id)?;
                journal_auth.push((id.to_string(), entry.path()));
            } else if let Some(id) = name.strip_suffix(".pending") {
                validate_quarantine_id(id)?;
                journals.push((id.to_string(), entry.path()));
            }
        }
        actions.sort_by(|left, right| left.0.cmp(&right.0));
        metadata_updates.sort_by(|left, right| left.0.cmp(&right.0));
        journals.sort_by(|left, right| left.0.cmp(&right.0));
        journal_auth.sort_by(|left, right| left.0.cmp(&right.0));

        for (id, path) in &metadata_updates {
            if journals.iter().any(|(journal_id, _)| journal_id == id)
                || journal_auth.iter().any(|(journal_id, _)| journal_id == id)
                || actions.iter().any(|(action_id, _)| action_id == id)
            {
                return Err(anyhow!(
                    "quarantine item {id} has conflicting metadata-update, action, or finalization recovery journals"
                ));
            }
            self.recover_metadata_update_journal(id, path)?;
        }

        for (id, path) in &actions {
            if journals.iter().any(|(journal_id, _)| journal_id == id)
                || journal_auth.iter().any(|(journal_id, _)| journal_id == id)
            {
                return Err(anyhow!(
                    "quarantine item {id} has conflicting action and finalization recovery journals"
                ));
            }
            self.recover_action_journal(id, path)?;
        }

        for (id, auth_path) in journal_auth {
            let journal_path = self.finalization_journal_path(&id)?;
            if optional_quarantine_file_present(&journal_path, "quarantine finalization journal")? {
                continue;
            }
            self.recover_orphan_finalization_journal_auth(&id, &auth_path)?;
        }

        for (id, path) in journals {
            self.recover_finalization_journal(&id, &path)?;
        }
        Ok(())
    }

    fn recover_metadata_update_journal(&self, id: &str, path: &Path) -> Result<()> {
        let expected_path = self.metadata_update_journal_path(id)?;
        if path != expected_path {
            return Err(anyhow!(
                "quarantine metadata-update journal path does not match id {id}"
            ));
        }
        let (journal_lock, raw) = read_locked_bounded_quarantine_text(
            path,
            MAX_QUARANTINE_METADATA_UPDATE_JOURNAL_BYTES,
            "quarantine metadata-update journal",
        )
        .with_context(|| {
            format!(
                "quarantine metadata-update journal {} is active or unavailable; recovery evidence was preserved",
                path.display()
            )
        })?;
        let body = self.validated_metadata_update_journal(path, &raw)?;
        let metadata_path = self.base.join(format!("{id}.json"));
        let metadata_auth_path = self.base.join(format!("{id}.json.auth"));
        if !optional_quarantine_file_present(
            &metadata_path,
            "quarantine metadata record during update recovery",
        )? || !optional_quarantine_file_present(
            &metadata_auth_path,
            "quarantine metadata auth sidecar during update recovery",
        )? {
            return Err(anyhow!(
                "quarantine metadata-update recovery requires both record and authentication sidecar for {id}; recovery evidence was preserved"
            ));
        }

        let current_record_raw = read_bounded_quarantine_text(
            &metadata_path,
            MAX_QUARANTINE_METADATA_BYTES,
            "quarantine metadata record during update recovery",
        )?;
        let current_record_auth = read_bounded_quarantine_text(
            &metadata_auth_path,
            MAX_QUARANTINE_METADATA_AUTH_BYTES,
            "quarantine metadata auth sidecar during update recovery",
        )?;
        let record_is_previous = current_record_raw == body.previous_record_raw;
        let record_is_next = current_record_raw == body.next_record_raw;
        let auth_is_previous = constant_time_eq(
            current_record_auth.as_bytes(),
            body.previous_record_auth.as_bytes(),
        );
        let auth_is_next = constant_time_eq(
            current_record_auth.as_bytes(),
            body.next_record_auth.as_bytes(),
        );
        if !record_is_previous && !record_is_next {
            return Err(anyhow!(
                "quarantine metadata-update recovery found record bytes that match neither authenticated journal version for {id}; recovery evidence was preserved"
            ));
        }
        if !auth_is_previous && !auth_is_next {
            return Err(anyhow!(
                "quarantine metadata-update recovery found authentication bytes that match neither authenticated journal version for {id}; recovery evidence was preserved"
            ));
        }

        if !record_is_previous {
            replace_staged_quarantine_file(
                &metadata_path,
                body.previous_record_raw.as_bytes(),
                "quarantine metadata record during update rollback",
            )?;
        }
        if !auth_is_previous {
            replace_staged_quarantine_file(
                &metadata_auth_path,
                body.previous_record_auth.as_bytes(),
                "quarantine metadata auth sidecar during update rollback",
            )?;
        }
        let previous_record: QuarantineRecord = serde_json::from_str(&body.previous_record_raw)
            .with_context(|| {
                "unable to parse authenticated previous quarantine metadata during update recovery"
            })?;
        self.ensure_metadata_pair_exact(
            &previous_record,
            &body.previous_record_raw,
            &body.previous_record_auth,
            "rolled-back quarantine metadata pair",
        )?;
        self.cleanup_metadata_update_journal(id)
            .with_context(|| {
                format!(
                    "rolled back quarantine metadata update for {id}, but could not remove its authenticated recovery journal"
                )
            })?;
        drop(journal_lock);
        Ok(())
    }

    fn recover_action_journal(&self, id: &str, path: &Path) -> Result<()> {
        let expected_path = self.action_journal_path(id)?;
        if path != expected_path {
            return Err(anyhow!(
                "quarantine action journal path does not match id {id}"
            ));
        }
        self.ensure_action_journal_conflicts_absent(id)?;
        let (journal_lock, raw) = read_locked_bounded_quarantine_text(
            path,
            MAX_QUARANTINE_ACTION_JOURNAL_BYTES,
            "quarantine action journal",
        )
        .with_context(|| {
            format!(
                "quarantine action journal {} is active or unavailable; recovery evidence was preserved",
                path.display()
            )
        })?;
        let body = self.validated_action_journal(path, &raw)?;
        let previous_record: QuarantineRecord = serde_json::from_str(&body.previous_record_raw)
            .context("unable to parse previous quarantine action record")?;
        let next_record: QuarantineRecord = serde_json::from_str(&body.next_record_raw)
            .context("unable to parse next quarantine action record")?;
        let payload_path = validate_quarantine_payload_path_text(&previous_record.quarantine_path)?;
        self.ensure_quarantine_payload_path_for_id(id, &payload_path)?;

        match body.action {
            QuarantineLifecycleAction::Delete => {
                self.ensure_action_metadata_pair_known(&body)?;
                let payload_present = optional_quarantine_file_present(
                    &payload_path,
                    "quarantine payload during delete recovery",
                )?;
                if payload_present {
                    self.ensure_quarantine_payload_path(&payload_path)?;
                    harden_quarantine_payload_permissions(&payload_path)?;
                    self.ensure_payload_integrity(&previous_record, &payload_path)?;
                }
                self.drive_action_metadata_pair_to_next(&body, &next_record)?;
                if payload_present {
                    remove_checked_quarantine_payload(
                        &payload_path,
                        "deleted quarantine payload during action recovery",
                    )?;
                }
                if optional_quarantine_path_present(
                    &payload_path,
                    "deleted quarantine payload after action recovery",
                )? {
                    return Err(anyhow!(
                        "delete action recovery did not remove quarantine payload for {id}; recovery evidence was preserved"
                    ));
                }
            }
            QuarantineLifecycleAction::Restore => match body.phase {
                QuarantineActionPhase::Prepared => {
                    self.ensure_metadata_pair_exact(
                        &previous_record,
                        &body.previous_record_raw,
                        &body.previous_record_auth,
                        "prepared restore metadata pair",
                    )?;
                    if !optional_quarantine_file_present(
                        &payload_path,
                        "quarantine payload during prepared restore recovery",
                    )? {
                        return Err(anyhow!(
                            "prepared restore recovery requires its quarantine payload for {id}; recovery evidence was preserved"
                        ));
                    }
                    self.ensure_quarantine_payload_path(&payload_path)?;
                    harden_quarantine_payload_permissions(&payload_path)?;
                    self.ensure_payload_integrity(&previous_record, &payload_path)?;
                    let staging_path = action_restore_staging_path(&body)?;
                    let destination =
                        validate_original_restore_path_text(&previous_record.original_path)?;
                    let staging_present = optional_quarantine_path_present(
                        &staging_path,
                        "prepared quarantine restore staging path",
                    )?;
                    let destination_present = optional_quarantine_path_present(
                        &destination,
                        "prepared quarantine restore destination",
                    )?;
                    if destination_present {
                        return Err(anyhow!(
                            "prepared restore recovery found an unexpected destination for {id}; recovery evidence was preserved for manual review"
                        ));
                    }
                    if staging_present {
                        cleanup_unbound_empty_restore_staging(&staging_path).with_context(|| {
                            format!(
                                "prepared restore recovery found a non-empty, linked, or unavailable unbound staging file for {id}; recovery evidence was preserved for manual review"
                            )
                        })?;
                    }
                }
                QuarantineActionPhase::RestoreReserved => {
                    self.ensure_metadata_pair_exact(
                        &previous_record,
                        &body.previous_record_raw,
                        &body.previous_record_auth,
                        "restore-reserved metadata pair",
                    )?;
                    if !optional_quarantine_file_present(
                        &payload_path,
                        "quarantine payload during restore-reserved recovery",
                    )? {
                        return Err(anyhow!(
                            "restore-reserved recovery requires its quarantine payload for {id}; recovery evidence was preserved"
                        ));
                    }
                    self.ensure_quarantine_payload_path(&payload_path)?;
                    harden_quarantine_payload_permissions(&payload_path)?;
                    self.ensure_payload_integrity(&previous_record, &payload_path)?;
                    let staging_path = action_restore_staging_path(&body)?;
                    let destination =
                        validate_original_restore_path_text(&previous_record.original_path)?;
                    let identity = body.restore_identity.as_ref().ok_or_else(|| {
                        anyhow!("restore-reserved action journal has no persistent file identity")
                    })?;
                    let staging_present = optional_quarantine_path_present(
                        &staging_path,
                        "reserved quarantine restore during recovery",
                    )?;
                    if optional_quarantine_path_present(
                        &destination,
                        "quarantine restore destination during reserved recovery",
                    )? {
                        return Err(anyhow!(
                            "restore-reserved recovery found a destination before staged activation for {id}; recovery evidence was preserved"
                        ));
                    }
                    if staging_present {
                        if self.action_restore_file_matches_record(
                            &previous_record,
                            &staging_path,
                            identity,
                            "reserved quarantine restore staging file",
                        )? {
                            let mut staged_body = body.clone();
                            staged_body.phase = QuarantineActionPhase::RestoreStaged;
                            drop(journal_lock);
                            let (staged_lock, _staged_raw) = self.replace_action_journal(
                                &raw,
                                QuarantineActionPhase::RestoreReserved,
                                staged_body,
                            )?;
                            drop(staged_lock);
                            return self.recover_action_journal(id, path);
                        }
                        self.remove_action_restore_file_identity(
                            &staging_path,
                            identity,
                            "incomplete reserved quarantine restore staging file",
                        )?;
                    }
                }
                QuarantineActionPhase::RestoreStaged => {
                    self.ensure_action_metadata_pair_known(&body)?;
                    let staging_path = action_restore_staging_path(&body)?;
                    let destination =
                        validate_original_restore_path_text(&previous_record.original_path)?;
                    let identity = body.restore_identity.as_ref().ok_or_else(|| {
                        anyhow!("restore-staged action journal has no persistent file identity")
                    })?;
                    let staging_present = optional_quarantine_path_present(
                        &staging_path,
                        "staged quarantine restore during recovery",
                    )?;
                    let destination_present = optional_quarantine_path_present(
                        &destination,
                        "quarantine restore destination during recovery",
                    )?;
                    if staging_present == destination_present {
                        return Err(anyhow!(
                            "restore-staged recovery requires exactly one identity-bound staging file or destination for {id}; recovery evidence was preserved"
                        ));
                    }
                    if staging_present {
                        if !optional_quarantine_file_present(
                            &payload_path,
                            "quarantine payload before staged restore activation",
                        )? {
                            return Err(anyhow!(
                                "restore-staged recovery cannot activate staging without the intact quarantine payload for {id}; recovery evidence was preserved"
                            ));
                        }
                        self.ensure_quarantine_payload_path(&payload_path)?;
                        harden_quarantine_payload_permissions(&payload_path)?;
                        self.ensure_payload_integrity(&previous_record, &payload_path)?;
                        self.ensure_action_restore_file_identity(
                            &previous_record,
                            &staging_path,
                            identity,
                            "staged quarantine restore",
                        )?;
                        let parent = destination.parent().ok_or_else(|| {
                            anyhow!("restore destination has no parent directory")
                        })?;
                        reject_link_ancestors(parent, "quarantine restore parent")?;
                        reject_existing_restore_destination(&destination)?;
                        activate_quarantine_restore_no_replace(&staging_path, &destination)
                            .context("unable to resume quarantine restore activation")?;
                    }
                    self.ensure_action_restore_file_identity(
                        &previous_record,
                        &destination,
                        identity,
                        "restored quarantine destination",
                    )?;
                    self.drive_action_metadata_pair_to_next(&body, &next_record)?;
                    if optional_quarantine_file_present(
                        &payload_path,
                        "quarantine payload during restore cleanup",
                    )? {
                        self.ensure_quarantine_payload_path(&payload_path)?;
                        harden_quarantine_payload_permissions(&payload_path)?;
                        self.ensure_payload_integrity(&previous_record, &payload_path)?;
                        remove_checked_quarantine_payload(
                            &payload_path,
                            "restored quarantine payload during action recovery",
                        )?;
                    }
                    self.ensure_action_restore_file_identity(
                        &previous_record,
                        &destination,
                        identity,
                        "restored quarantine destination after cleanup",
                    )?;
                    if optional_quarantine_path_present(
                        &payload_path,
                        "restored quarantine payload after action recovery",
                    )? {
                        return Err(anyhow!(
                            "restore action recovery did not remove quarantine payload for {id}; recovery evidence was preserved"
                        ));
                    }
                }
            },
        }

        self.cleanup_action_journal(id).with_context(|| {
            format!(
                "quarantine action for {id} reached its verified final state, but journal cleanup failed"
            )
        })?;
        drop(journal_lock);
        Ok(())
    }

    fn validated_action_journal(
        &self,
        path: &Path,
        raw: &str,
    ) -> Result<QuarantineActionJournalBody> {
        let journal: QuarantineActionJournal =
            serde_json::from_str(raw).context("unable to parse quarantine action journal")?;
        if journal.body.format != QUARANTINE_ACTION_JOURNAL_FORMAT {
            return Err(anyhow!("unsupported quarantine action journal format"));
        }
        validate_quarantine_id(&journal.body.quarantine_id)?;
        if self.action_journal_path(&journal.body.quarantine_id)? != path {
            return Err(anyhow!(
                "quarantine action journal id does not match its filename"
            ));
        }
        let Some(key) = self.metadata_auth_key(false)? else {
            return Err(anyhow!(
                "quarantine action journal authentication key unavailable"
            ));
        };
        let expected_auth = hmac_action_journal_auth_tag(&key, &journal.body)?;
        if !constant_time_eq(expected_auth.as_bytes(), journal.authentication.as_bytes()) {
            return Err(anyhow!(
                "quarantine action journal authentication failed for {}",
                path.display()
            ));
        }
        let previous_record = self.validate_metadata_update_record_version(
            &journal.body.quarantine_id,
            &journal.body.previous_record_raw,
            &journal.body.previous_record_auth,
            &key,
            "previous action",
        )?;
        let next_record = self.validate_metadata_update_record_version(
            &journal.body.quarantine_id,
            &journal.body.next_record_raw,
            &journal.body.next_record_auth,
            &key,
            "next action",
        )?;
        validate_quarantine_action_transition(&previous_record, &next_record, journal.body.action)?;
        if journal.body.previous_record_raw == journal.body.next_record_raw
            || constant_time_eq(
                journal.body.previous_record_auth.as_bytes(),
                journal.body.next_record_auth.as_bytes(),
            )
        {
            return Err(anyhow!(
                "quarantine action journal does not describe a changed authenticated record"
            ));
        }

        match journal.body.action {
            QuarantineLifecycleAction::Restore => {
                let staging_path = action_restore_staging_path(&journal.body)?;
                validate_restore_staging_path(&previous_record, &staging_path)?;
                match journal.body.phase {
                    QuarantineActionPhase::Prepared => {
                        if journal.body.restore_identity.is_some() {
                            return Err(anyhow!(
                                "prepared restore action journal must not contain a file identity"
                            ));
                        }
                    }
                    QuarantineActionPhase::RestoreReserved
                    | QuarantineActionPhase::RestoreStaged => {
                        let identity = journal.body.restore_identity.as_ref().ok_or_else(|| {
                            anyhow!(
                                "restore-reserved or restore-staged action journal requires a file identity"
                            )
                        })?;
                        validate_persisted_file_identity(identity)?;
                    }
                }
            }
            QuarantineLifecycleAction::Delete => {
                if journal.body.phase != QuarantineActionPhase::Prepared
                    || journal.body.restore_staging_path.is_some()
                    || journal.body.restore_identity.is_some()
                {
                    return Err(anyhow!("delete action journal contains restore-only state"));
                }
            }
        }
        Ok(journal.body)
    }

    fn ensure_action_metadata_pair_known(
        &self,
        body: &QuarantineActionJournalBody,
    ) -> Result<(bool, bool)> {
        let id = &body.quarantine_id;
        let record_path = self.base.join(format!("{id}.json"));
        let auth_path = self.base.join(format!("{id}.json.auth"));
        if !optional_quarantine_file_present(
            &record_path,
            "quarantine metadata record during action recovery",
        )? || !optional_quarantine_file_present(
            &auth_path,
            "quarantine metadata auth sidecar during action recovery",
        )? {
            return Err(anyhow!(
                "quarantine action recovery requires both record and authentication sidecar for {id}; recovery evidence was preserved"
            ));
        }
        let current_record = read_bounded_quarantine_text(
            &record_path,
            MAX_QUARANTINE_METADATA_BYTES,
            "quarantine metadata record during action recovery",
        )?;
        let current_auth = read_bounded_quarantine_text(
            &auth_path,
            MAX_QUARANTINE_METADATA_AUTH_BYTES,
            "quarantine metadata auth sidecar during action recovery",
        )?;
        let record_is_previous = current_record == body.previous_record_raw;
        let record_is_next = current_record == body.next_record_raw;
        let auth_is_previous = constant_time_eq(
            current_auth.as_bytes(),
            body.previous_record_auth.as_bytes(),
        );
        let auth_is_next =
            constant_time_eq(current_auth.as_bytes(), body.next_record_auth.as_bytes());
        if !record_is_previous && !record_is_next {
            return Err(anyhow!(
                "quarantine action recovery found record bytes that match neither authenticated journal version for {id}; recovery evidence was preserved"
            ));
        }
        if !auth_is_previous && !auth_is_next {
            return Err(anyhow!(
                "quarantine action recovery found authentication bytes that match neither authenticated journal version for {id}; recovery evidence was preserved"
            ));
        }
        Ok((record_is_previous, auth_is_previous))
    }

    fn drive_action_metadata_pair_to_next(
        &self,
        body: &QuarantineActionJournalBody,
        next_record: &QuarantineRecord,
    ) -> Result<()> {
        let (record_is_previous, auth_is_previous) =
            self.ensure_action_metadata_pair_known(body)?;
        let record_path = self.base.join(format!("{}.json", body.quarantine_id));
        let auth_path = self.base.join(format!("{}.json.auth", body.quarantine_id));
        if record_is_previous {
            replace_staged_quarantine_file(
                &record_path,
                body.next_record_raw.as_bytes(),
                "quarantine action metadata record",
            )?;
        }
        let record_after_replace = read_bounded_quarantine_text(
            &record_path,
            MAX_QUARANTINE_METADATA_BYTES,
            "quarantine action metadata record before auth replacement",
        )?;
        let auth_before_replace = read_bounded_quarantine_text(
            &auth_path,
            MAX_QUARANTINE_METADATA_AUTH_BYTES,
            "quarantine action metadata auth before replacement",
        )?;
        if record_after_replace != body.next_record_raw
            || (!constant_time_eq(
                auth_before_replace.as_bytes(),
                body.previous_record_auth.as_bytes(),
            ) && !constant_time_eq(
                auth_before_replace.as_bytes(),
                body.next_record_auth.as_bytes(),
            ))
        {
            return Err(anyhow!(
                "quarantine metadata pair changed unexpectedly during action recovery; journal was preserved"
            ));
        }
        if auth_is_previous {
            replace_staged_quarantine_file(
                &auth_path,
                body.next_record_auth.as_bytes(),
                "quarantine action metadata auth sidecar",
            )?;
        }
        self.ensure_metadata_pair_exact(
            next_record,
            &body.next_record_raw,
            &body.next_record_auth,
            "completed quarantine action metadata pair",
        )
    }

    fn ensure_action_restore_file_identity(
        &self,
        record: &QuarantineRecord,
        path: &Path,
        expected: &PersistedFileIdentity,
        label: &str,
    ) -> Result<()> {
        let file = self.open_action_restore_file_identity(path, expected, label)?;
        let metadata = file
            .metadata()
            .with_context(|| format!("failed to inspect opened {label} {}", path.display()))?;
        if metadata.len() != record.file_size {
            return Err(anyhow!("{label} size does not match quarantine record"));
        }
        let actual_sha256 = sha256_for_open_file(&file, path)?;
        if !record.sha256.eq_ignore_ascii_case(&actual_sha256) {
            return Err(anyhow!("{label} hash does not match quarantine record"));
        }
        avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
        avorax_platform_security::ensure_path_matches_file_identity(
            avorax_platform_security::StableFileIdentity {
                scope: expected.scope,
                file: expected.file,
            },
            path,
            label,
        )
    }

    fn open_action_restore_file_identity(
        &self,
        path: &Path,
        expected: &PersistedFileIdentity,
        label: &str,
    ) -> Result<fs::File> {
        validate_persisted_file_identity(expected)?;
        let file = open_single_link_quarantine_file(path, label)?;
        let actual = persisted_file_identity(avorax_platform_security::capture_open_file_identity(
            &file, path, label,
        )?);
        if &actual != expected {
            return Err(anyhow!(
                "{label} {} does not match the authenticated persistent file identity; recovery evidence was preserved",
                path.display()
            ));
        }
        avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
        avorax_platform_security::ensure_path_matches_file_identity(
            avorax_platform_security::StableFileIdentity {
                scope: expected.scope,
                file: expected.file,
            },
            path,
            label,
        )?;
        Ok(file)
    }

    fn action_restore_file_matches_record(
        &self,
        record: &QuarantineRecord,
        path: &Path,
        expected: &PersistedFileIdentity,
        label: &str,
    ) -> Result<bool> {
        let file = self.open_action_restore_file_identity(path, expected, label)?;
        let metadata = file
            .metadata()
            .with_context(|| format!("failed to inspect opened {label} {}", path.display()))?;
        let matches = if metadata.len() == record.file_size {
            record
                .sha256
                .eq_ignore_ascii_case(&sha256_for_open_file(&file, path)?)
        } else {
            false
        };
        avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
        Ok(matches)
    }

    fn remove_action_restore_file_identity(
        &self,
        path: &Path,
        expected: &PersistedFileIdentity,
        label: &str,
    ) -> Result<()> {
        let file = self.open_action_restore_file_identity(path, expected, label)?;
        avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
        avorax_platform_security::ensure_open_file_has_single_link(&file, path, label)?;
        fs::remove_file(path)
            .with_context(|| format!("failed to remove {label} {}", path.display()))?;
        drop(file);
        if optional_quarantine_path_present(path, label)? {
            return Err(anyhow!("{label} remained after checked cleanup"));
        }
        Ok(())
    }

    fn ensure_quarantine_payload_path_for_id(&self, id: &str, path: &Path) -> Result<()> {
        let expected = self.base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        if path != expected {
            return Err(anyhow!(
                "quarantine action payload path does not match journal id {id}"
            ));
        }
        Ok(())
    }

    fn validated_metadata_update_journal(
        &self,
        path: &Path,
        raw: &str,
    ) -> Result<QuarantineMetadataUpdateJournalBody> {
        let journal: QuarantineMetadataUpdateJournal = serde_json::from_str(raw)
            .context("unable to parse quarantine metadata-update journal")?;
        if journal.body.format != QUARANTINE_METADATA_UPDATE_JOURNAL_FORMAT {
            return Err(anyhow!(
                "unsupported quarantine metadata-update journal format"
            ));
        }
        validate_quarantine_id(&journal.body.quarantine_id)?;
        if self.metadata_update_journal_path(&journal.body.quarantine_id)? != path {
            return Err(anyhow!(
                "quarantine metadata-update journal id does not match its filename"
            ));
        }
        let Some(key) = self.metadata_auth_key(false)? else {
            return Err(anyhow!(
                "quarantine metadata-update journal authentication key unavailable"
            ));
        };
        let expected_journal_auth = hmac_metadata_update_journal_auth_tag(&key, &journal.body)?;
        if !constant_time_eq(
            expected_journal_auth.as_bytes(),
            journal.authentication.as_bytes(),
        ) {
            return Err(anyhow!(
                "quarantine metadata-update journal authentication failed for {}",
                path.display()
            ));
        }

        let previous_record = self.validate_metadata_update_record_version(
            &journal.body.quarantine_id,
            &journal.body.previous_record_raw,
            &journal.body.previous_record_auth,
            &key,
            "previous",
        )?;
        let next_record = self.validate_metadata_update_record_version(
            &journal.body.quarantine_id,
            &journal.body.next_record_raw,
            &journal.body.next_record_auth,
            &key,
            "next",
        )?;
        validate_metadata_update_transition(&previous_record, &next_record)?;
        if previous_record == next_record
            || journal.body.previous_record_raw == journal.body.next_record_raw
            || constant_time_eq(
                journal.body.previous_record_auth.as_bytes(),
                journal.body.next_record_auth.as_bytes(),
            )
        {
            return Err(anyhow!(
                "quarantine metadata-update journal does not describe a changed authenticated record"
            ));
        }
        Ok(journal.body)
    }

    fn validate_metadata_update_record_version(
        &self,
        id: &str,
        raw: &str,
        auth: &str,
        key: &str,
        version: &str,
    ) -> Result<QuarantineRecord> {
        if raw.len() as u64 > MAX_QUARANTINE_METADATA_BYTES {
            return Err(anyhow!(
                "{version} quarantine metadata-update record exceeds maximum size"
            ));
        }
        if auth.len() as u64 > MAX_QUARANTINE_METADATA_AUTH_BYTES {
            return Err(anyhow!(
                "{version} quarantine metadata-update authentication exceeds maximum size"
            ));
        }
        let record: QuarantineRecord = serde_json::from_str(raw).with_context(|| {
            format!("unable to parse {version} quarantine metadata-update record")
        })?;
        validate_quarantine_record_for_write(&record)?;
        if record.quarantine_id != id {
            return Err(anyhow!(
                "{version} quarantine metadata-update record id does not match journal id"
            ));
        }
        self.ensure_record_path_matches_id(&self.base.join(format!("{id}.json")), id)?;
        let expected_payload = self.base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        if validate_quarantine_payload_path_text(&record.quarantine_path)? != expected_payload {
            return Err(anyhow!(
                "{version} quarantine metadata-update payload path does not match journal id"
            ));
        }
        let expected_auth = format!("{}\n", hmac_record_auth_tag(key, raw)?);
        if !constant_time_eq(expected_auth.as_bytes(), auth.as_bytes()) {
            return Err(anyhow!(
                "{version} quarantine metadata-update authentication does not match its record"
            ));
        }
        Ok(record)
    }

    fn recover_orphan_finalization_journal_auth(&self, id: &str, auth_path: &Path) -> Result<()> {
        let expected_auth_path = self.finalization_journal_auth_path(id)?;
        if auth_path != expected_auth_path {
            return Err(anyhow!(
                "orphan quarantine finalization journal auth path does not match id {id}"
            ));
        }
        if !optional_quarantine_file_present(
            auth_path,
            "orphan quarantine finalization journal auth sidecar",
        )? {
            return Ok(());
        }
        let payload_path = self.base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        let metadata_path = self.base.join(format!("{id}.json"));
        let metadata_auth_path = self.base.join(format!("{id}.json.auth"));
        let payload_present = optional_quarantine_file_present(
            &payload_path,
            "quarantine payload related to orphan finalization journal auth",
        )?;
        let metadata_present = optional_quarantine_file_present(
            &metadata_path,
            "quarantine metadata related to orphan finalization journal auth",
        )?;
        let metadata_auth_present = optional_quarantine_file_present(
            &metadata_auth_path,
            "quarantine metadata auth related to orphan finalization journal auth",
        )?;

        if !payload_present && !metadata_present && !metadata_auth_present {
            return cleanup_quarantine_partial_file(
                auth_path,
                "orphan quarantine finalization journal auth sidecar",
            );
        }
        if !metadata_present || !metadata_auth_present {
            return Err(anyhow!(
                "orphan quarantine finalization journal auth sidecar has incomplete related state for {id}; refusing automatic cleanup"
            ));
        }

        let raw = read_bounded_quarantine_text(
            &metadata_path,
            MAX_QUARANTINE_METADATA_BYTES,
            "finalized quarantine metadata related to orphan finalization journal auth",
        )?;
        if self.verified_record_auth_scheme(&metadata_path, &raw)?
            != QuarantineMetadataAuthScheme::HmacSha256V2
        {
            return Err(anyhow!(
                "orphan quarantine finalization journal auth sidecar requires a current authenticated final record for {id}"
            ));
        }
        let record: QuarantineRecord = serde_json::from_str(&raw).context(
            "unable to parse finalized quarantine metadata related to orphan finalization journal auth",
        )?;
        validate_quarantine_record_for_write(&record)?;
        self.ensure_record_path_matches_id(&metadata_path, id)?;
        if record.quarantine_id != id {
            return Err(anyhow!(
                "finalized quarantine record id does not match orphan journal auth for {id}"
            ));
        }
        let recorded_payload = validate_quarantine_payload_path_text(&record.quarantine_path)?;
        if recorded_payload != payload_path {
            return Err(anyhow!(
                "finalized quarantine payload path does not match orphan journal auth for {id}"
            ));
        }
        match record.status {
            QuarantineStatus::Quarantined => {
                if !payload_present {
                    return Err(anyhow!(
                        "authenticated quarantined record related to orphan journal auth has no payload for {id}"
                    ));
                }
                harden_quarantine_payload_permissions(&payload_path)?;
                self.ensure_payload_integrity(&record, &payload_path)?;
            }
            QuarantineStatus::Restored | QuarantineStatus::Deleted => {
                if payload_present {
                    return Err(anyhow!(
                        "authenticated non-quarantined record related to orphan journal auth still has a payload for {id}"
                    ));
                }
            }
        }
        cleanup_quarantine_partial_file(
            auth_path,
            "verified orphan quarantine finalization journal auth sidecar",
        )
    }

    fn recover_finalization_journal(&self, id: &str, path: &Path) -> Result<()> {
        let expected_path = self.finalization_journal_path(id)?;
        if path != expected_path {
            return Err(anyhow!(
                "quarantine finalization journal path does not match id {id}"
            ));
        }
        let (_journal_lock, raw) = read_locked_bounded_quarantine_text(
            path,
            MAX_QUARANTINE_METADATA_BYTES,
            "quarantine finalization journal",
        )
        .with_context(|| {
            format!(
                "quarantine finalization journal {} is active or unavailable; recovery evidence was preserved",
                path.display()
            )
        })?;
        self.ensure_finalization_journal_auth_valid(path, &raw)?;
        let journal: QuarantineFinalizationJournal = serde_json::from_str(&raw)
            .context("unable to parse authenticated quarantine finalization journal")?;
        if journal.format != QUARANTINE_FINALIZATION_JOURNAL_FORMAT {
            return Err(anyhow!(
                "unsupported quarantine finalization journal format"
            ));
        }
        if journal.record.quarantine_id != id {
            return Err(anyhow!(
                "quarantine finalization journal id does not match its filename"
            ));
        }
        validate_quarantine_record_for_write(&journal.record)?;
        if journal.record.status != QuarantineStatus::Quarantined {
            return Err(anyhow!(
                "quarantine finalization journal record is not quarantined"
            ));
        }
        let expected_payload = self.base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        let recorded_payload =
            validate_quarantine_payload_path_text(&journal.record.quarantine_path)?;
        if recorded_payload != expected_payload {
            return Err(anyhow!(
                "quarantine finalization journal payload path does not match id {id}"
            ));
        }
        let metadata_path = self.base.join(format!("{id}.json"));
        let metadata_auth_path = self.base.join(format!("{id}.json.auth"));
        let metadata_present = optional_quarantine_file_present(
            &metadata_path,
            "quarantine metadata record during finalization recovery",
        )?;
        let metadata_auth_present = optional_quarantine_file_present(
            &metadata_auth_path,
            "quarantine metadata auth sidecar during finalization recovery",
        )?;
        let payload_present = optional_quarantine_file_present(
            &expected_payload,
            "quarantine payload during finalization recovery",
        )?;

        if metadata_present && metadata_auth_present {
            let final_raw = read_bounded_quarantine_text(
                &metadata_path,
                MAX_QUARANTINE_METADATA_BYTES,
                "quarantine metadata record during finalization recovery",
            )?;
            self.verified_record_auth_scheme(&metadata_path, &final_raw)?;
            let final_record: QuarantineRecord = serde_json::from_str(&final_raw)
                .context("unable to parse finalized quarantine metadata during recovery")?;
            validate_quarantine_record_for_write(&final_record)?;
            if final_record != journal.record {
                return Err(anyhow!(
                    "finalized quarantine record conflicts with authenticated recovery journal for {id}"
                ));
            }
            if !payload_present {
                return Err(anyhow!(
                    "finalized quarantine record and recovery journal exist without payload for {id}"
                ));
            }
            harden_quarantine_payload_permissions(&expected_payload)?;
            self.ensure_payload_integrity(&journal.record, &expected_payload)?;
            self.cleanup_finalization_journal(id)?;
            return Ok(());
        }

        if !payload_present {
            if metadata_present || metadata_auth_present {
                return Err(anyhow!(
                    "incomplete quarantine metadata and recovery journal exist without payload for {id}"
                ));
            }
            self.ensure_abandoned_journal_source_intact(&journal.record)?;
            self.cleanup_finalization_journal(id)?;
            return Ok(());
        }

        let original_path = validate_original_restore_path_text(&journal.record.original_path)?;
        if optional_quarantine_path_present(
            &original_path,
            "original source during quarantine finalization recovery",
        )? {
            return Err(anyhow!(
                "quarantine finalization recovery found both isolated payload and original source for {id}; refusing to claim completed quarantine"
            ));
        }
        harden_quarantine_payload_permissions(&expected_payload)?;
        self.ensure_payload_integrity(&journal.record, &expected_payload)?;
        cleanup_untracked_quarantine_metadata_artifacts(&self.base, id)?;
        self.write_record(&journal.record)?;
        let final_raw = read_bounded_quarantine_text(
            &metadata_path,
            MAX_QUARANTINE_METADATA_BYTES,
            "recovered quarantine metadata record",
        )?;
        if self.verified_record_auth_scheme(&metadata_path, &final_raw)?
            != QuarantineMetadataAuthScheme::HmacSha256V2
            || serde_json::from_str::<QuarantineRecord>(&final_raw)? != journal.record
        {
            return Err(anyhow!(
                "recovered quarantine metadata verification failed for {id}"
            ));
        }
        self.cleanup_finalization_journal(id)?;
        Ok(())
    }

    fn ensure_abandoned_journal_source_intact(&self, record: &QuarantineRecord) -> Result<()> {
        let source = validate_original_restore_path_text(&record.original_path)?;
        let metadata = ensure_regular_quarantine_source(&source).with_context(|| {
            "pending quarantine journal has neither payload nor intact original source"
        })?;
        if metadata.len() != record.file_size {
            return Err(anyhow!(
                "pending quarantine journal original source size changed"
            ));
        }
        let opened = open_single_link_quarantine_file(
            &source,
            "pending quarantine journal original source",
        )?;
        let actual = sha256_for_file(&source)?;
        if !record.sha256.eq_ignore_ascii_case(&actual) {
            return Err(anyhow!(
                "pending quarantine journal original source hash changed"
            ));
        }
        avorax_platform_security::ensure_open_file_has_single_link(
            &opened,
            &source,
            "pending quarantine journal original source after hash",
        )?;
        Ok(())
    }

    fn ensure_finalization_journal_auth_valid(&self, path: &Path, raw: &str) -> Result<()> {
        let auth_path = path.with_extension("pending.auth");
        if !optional_quarantine_file_present(
            &auth_path,
            "quarantine finalization journal auth sidecar",
        )? {
            return Err(anyhow!(
                "quarantine finalization journal auth sidecar is required for {}",
                path.display()
            ));
        }
        let Some(key) = self.metadata_auth_key(false)? else {
            return Err(anyhow!(
                "quarantine finalization journal authentication key unavailable"
            ));
        };
        let actual = read_bounded_quarantine_text(
            &auth_path,
            MAX_QUARANTINE_METADATA_AUTH_BYTES,
            "quarantine finalization journal auth sidecar",
        )?
        .trim()
        .to_string();
        let expected = hmac_finalization_journal_auth_tag(&key, raw)?;
        if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
            return Err(anyhow!(
                "quarantine finalization journal authentication failed for {}",
                path.display()
            ));
        }
        Ok(())
    }

    fn cleanup_finalization_journal(&self, id: &str) -> Result<()> {
        validate_quarantine_id(id)?;
        let path = self.finalization_journal_path(id)?;
        let auth_path = self.finalization_journal_auth_path(id)?;
        cleanup_quarantine_partial_file(&path, "quarantine finalization journal")?;
        cleanup_quarantine_partial_file(&auth_path, "quarantine finalization journal auth sidecar")
    }

    fn finalization_journal_path(&self, id: &str) -> Result<PathBuf> {
        validate_quarantine_id(id)?;
        Ok(self.base.join(format!("{id}.pending")))
    }

    fn finalization_journal_auth_path(&self, id: &str) -> Result<PathBuf> {
        validate_quarantine_id(id)?;
        Ok(self.base.join(format!("{id}.pending.auth")))
    }

    fn metadata_update_journal_path(&self, id: &str) -> Result<PathBuf> {
        validate_quarantine_id(id)?;
        Ok(self.base.join(format!("{id}.update.pending")))
    }

    fn action_journal_path(&self, id: &str) -> Result<PathBuf> {
        validate_quarantine_id(id)?;
        Ok(self.base.join(format!("{id}.action.pending")))
    }

    fn cleanup_metadata_update_journal(&self, id: &str) -> Result<()> {
        let path = self.metadata_update_journal_path(id)?;
        cleanup_quarantine_partial_file(&path, "quarantine metadata-update journal")
    }

    fn cleanup_action_journal(&self, id: &str) -> Result<()> {
        let path = self.action_journal_path(id)?;
        cleanup_quarantine_partial_file(&path, "quarantine action journal")
    }

    pub fn list(&self) -> Result<Vec<QuarantineRecord>> {
        if !optional_quarantine_directory_present(&self.base, "quarantine base directory")? {
            return Ok(Vec::new());
        }
        reject_link_ancestors(&self.base, "quarantine base directory")?;
        avorax_platform_security::validate_quarantine_directory_contents(&self.base)
            .context("refusing to change permissions on an unrecognized quarantine directory")?;
        harden_quarantine_base_permissions(&self.base)?;
        self.recover_pending_finalizations()?;
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
                let auth_scheme = self.verified_record_auth_scheme(&path, &raw)?;
                match serde_json::from_str(&raw) {
                    Ok(record) => {
                        let record: QuarantineRecord = record;
                        validate_quarantine_id(&record.quarantine_id).with_context(|| {
                            format!(
                                "invalid quarantine id in metadata record {}",
                                path.display()
                            )
                        })?;
                        self.ensure_record_path_matches_id(&path, &record.quarantine_id)
                            .with_context(|| {
                                format!(
                                    "quarantine metadata filename does not match record id in {}",
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
                        self.harden_record_payload_if_present(&record)?;
                        if auth_scheme == QuarantineMetadataAuthScheme::LegacyPrefixSha256V1 {
                            self.migrate_legacy_record_auth(&path, &record, &raw)?;
                        }
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
        let record = self.find_record(id)?;
        Self::ensure_quarantined_status_for_action(&record, "restore")?;
        let quarantine_path = validate_quarantine_payload_path_text(&record.quarantine_path)?;
        self.ensure_quarantine_payload_path(&quarantine_path)?;
        harden_quarantine_payload_permissions(&quarantine_path)?;
        self.ensure_payload_integrity(&record, &quarantine_path)?;
        let original_path = validate_original_restore_path_text(&record.original_path)?;
        reject_existing_restore_destination(&original_path)?;
        let parent = original_path
            .parent()
            .ok_or_else(|| anyhow!("restore destination has no parent directory"))?;
        fs::create_dir_all(parent)?;
        reject_link_ancestors(parent, "quarantine restore parent")?;
        let staging_path = new_restore_staging_path(&original_path)?;
        let mut restored = record.clone();
        restored.status = QuarantineStatus::Restored;
        restored.action_taken = "restored".to_string();
        let mut action_body = self.prepare_action_journal_body(
            &record,
            &restored,
            QuarantineLifecycleAction::Restore,
            Some(staging_path.display().to_string()),
        )?;
        let (prepared_lock, prepared_raw) = self.write_action_journal(action_body.clone())?;
        let (mut staging_file, identity) = self.reserve_restore_staging_file(&staging_path)?;
        action_body.phase = QuarantineActionPhase::RestoreReserved;
        action_body.restore_identity = Some(identity.clone());
        drop(prepared_lock);
        let (reserved_lock, reserved_raw) = self.replace_action_journal(
            &prepared_raw,
            QuarantineActionPhase::Prepared,
            action_body.clone(),
        )?;
        self.copy_payload_to_reserved_restore(
            &record,
            &quarantine_path,
            &staging_path,
            &mut staging_file,
            &identity,
        )?;
        action_body.phase = QuarantineActionPhase::RestoreStaged;
        drop(reserved_lock);
        let (action_lock, _staged_raw) = self.replace_action_journal(
            &reserved_raw,
            QuarantineActionPhase::RestoreReserved,
            action_body.clone(),
        )?;
        drop(staging_file);
        self.ensure_action_restore_file_identity(
            &record,
            &staging_path,
            &identity,
            "staged quarantine restore before activation",
        )?;
        reject_link_ancestors(parent, "quarantine restore parent")?;
        reject_existing_restore_destination(&original_path)?;
        activate_quarantine_restore_no_replace(&staging_path, &original_path)
            .context("unable to activate quarantine restore")?;
        self.ensure_action_restore_file_identity(
            &record,
            &original_path,
            &identity,
            "restored quarantine destination",
        )?;
        self.drive_action_metadata_pair_to_next(&action_body, &restored)?;
        remove_checked_quarantine_payload(&quarantine_path, "restored quarantine payload")
            .with_context(|| {
                format!(
                    "unable to remove restored quarantine payload {} after status update",
                    quarantine_path.display()
                )
            })?;
        self.ensure_action_restore_file_identity(
            &record,
            &original_path,
            &identity,
            "restored quarantine destination after payload cleanup",
        )?;
        if optional_quarantine_path_present(
            &quarantine_path,
            "restored quarantine payload after cleanup",
        )? {
            return Err(anyhow!(
                "quarantine restore payload remained after cleanup; action journal was preserved"
            ));
        }
        self.cleanup_action_journal(id)
            .context("restore completed, but action journal cleanup failed")?;
        drop(action_lock);
        Ok(restored)
    }

    pub fn delete(&self, id: &str, confirmed: bool) -> Result<QuarantineRecord> {
        if !confirmed {
            return Err(anyhow!("delete requires explicit confirmation"));
        }
        let record = self.find_record(id)?;
        Self::ensure_quarantined_status_for_action(&record, "delete")?;
        let quarantine_path = validate_quarantine_payload_path_text(&record.quarantine_path)?;
        self.ensure_quarantine_payload_path(&quarantine_path)?;
        harden_quarantine_payload_permissions(&quarantine_path)?;
        self.ensure_payload_integrity(&record, &quarantine_path)?;
        let mut deleted = record.clone();
        deleted.status = QuarantineStatus::Deleted;
        deleted.action_taken = "deleted".to_string();
        let action_body = self.prepare_action_journal_body(
            &record,
            &deleted,
            QuarantineLifecycleAction::Delete,
            None,
        )?;
        let (action_lock, _raw) = self.write_action_journal(action_body.clone())?;
        self.drive_action_metadata_pair_to_next(&action_body, &deleted)
            .with_context(|| "unable to record quarantine deletion before payload removal")?;
        remove_checked_quarantine_payload(&quarantine_path, "deleted quarantine payload")
            .with_context(|| {
                format!(
                    "unable to remove deleted quarantine payload {}; action journal was preserved for recovery",
                    quarantine_path.display()
                )
            })?;
        if optional_quarantine_path_present(
            &quarantine_path,
            "deleted quarantine payload after cleanup",
        )? {
            return Err(anyhow!(
                "quarantine delete payload remained after cleanup; action journal was preserved"
            ));
        }
        self.cleanup_action_journal(id)
            .context("delete completed, but action journal cleanup failed")?;
        drop(action_lock);
        Ok(deleted)
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

    fn harden_record_payload_if_present(&self, record: &QuarantineRecord) -> Result<()> {
        let path = validate_quarantine_payload_path_text(&record.quarantine_path)?;
        if !optional_quarantine_file_present(&path, "quarantine payload")? {
            return Ok(());
        }
        self.ensure_quarantine_payload_path(&path)?;
        harden_quarantine_payload_permissions(&path).with_context(|| {
            format!(
                "failed to harden existing quarantine payload {}",
                path.display()
            )
        })
    }

    fn reserve_restore_staging_file(
        &self,
        temp_destination: &Path,
    ) -> Result<(fs::File, PersistedFileIdentity)> {
        let parent = temp_destination
            .parent()
            .ok_or_else(|| anyhow!("restore staging path has no parent directory"))?;
        reject_link_ancestors(parent, "quarantine restore staging parent")?;
        ensure_restore_temp_destination_absent(temp_destination)?;
        let staged = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(temp_destination)
            .with_context(|| {
                format!(
                    "failed to reserve quarantine restore staging file {}",
                    temp_destination.display()
                )
            })?;
        let reservation = (|| -> Result<PersistedFileIdentity> {
            harden_open_quarantine_file_permissions(
                &staged,
                temp_destination,
                "reserved quarantine restore staging file",
                ExclusiveCopySecurity::Restore,
            )?;
            let metadata = staged.metadata().with_context(|| {
                format!(
                    "failed to inspect reserved quarantine restore staging file {}",
                    temp_destination.display()
                )
            })?;
            if !metadata.is_file() || metadata.len() != 0 {
                return Err(anyhow!(
                    "reserved quarantine restore staging file is not an empty regular file"
                ));
            }
            let identity =
                persisted_file_identity(avorax_platform_security::capture_open_file_identity(
                    &staged,
                    temp_destination,
                    "reserved quarantine restore staging file",
                )?);
            avorax_platform_security::ensure_path_matches_open_file(
                &staged,
                temp_destination,
                "reserved quarantine restore staging file",
            )?;
            staged.sync_all().with_context(|| {
                format!(
                    "failed to synchronize reserved quarantine restore staging file {}",
                    temp_destination.display()
                )
            })?;
            Ok(identity)
        })();
        match reservation {
            Ok(identity) => Ok((staged, identity)),
            Err(error) => {
                drop(staged);
                cleanup_quarantine_partial_file(
                    temp_destination,
                    "unbound quarantine restore staging reservation",
                )
                .with_context(|| {
                    format!(
                        "failed to clean up quarantine restore staging reservation {} after reservation failure: {error:#}",
                        temp_destination.display()
                    )
                })?;
                Err(error.context("unable to reserve quarantine restore staging file"))
            }
        }
    }

    fn copy_payload_to_reserved_restore(
        &self,
        record: &QuarantineRecord,
        quarantine_path: &Path,
        temp_destination: &Path,
        staged: &mut fs::File,
        expected: &PersistedFileIdentity,
    ) -> Result<()> {
        validate_persisted_file_identity(expected)?;
        avorax_platform_security::ensure_open_file_has_single_link(
            staged,
            temp_destination,
            "reserved quarantine restore staging file",
        )?;
        let actual = persisted_file_identity(avorax_platform_security::capture_open_file_identity(
            staged,
            temp_destination,
            "reserved quarantine restore staging file",
        )?);
        if &actual != expected {
            return Err(anyhow!(
                "reserved quarantine restore staging file identity changed before copy; recovery evidence was preserved"
            ));
        }
        avorax_platform_security::ensure_path_matches_open_file(
            staged,
            temp_destination,
            "reserved quarantine restore staging file",
        )?;
        let metadata = staged.metadata().with_context(|| {
            format!(
                "failed to inspect reserved quarantine restore staging file {}",
                temp_destination.display()
            )
        })?;
        if metadata.len() != 0 {
            return Err(anyhow!(
                "reserved quarantine restore staging file was not empty before copy; recovery evidence was preserved"
            ));
        }

        let mut input = open_single_link_quarantine_file(
            quarantine_path,
            "quarantine payload for reserved restore",
        )?;
        avorax_platform_security::ensure_path_matches_open_file(
            &input,
            quarantine_path,
            "quarantine payload for reserved restore",
        )?;
        copy_local_quarantine_payload_limited(
            &mut input,
            staged,
            MAX_LOCAL_QUARANTINE_COPY_BYTES,
            quarantine_path,
        )
        .context(
            "unable to copy quarantine payload into identity-bound restore staging; recovery evidence was preserved",
        )?;
        staged.sync_all().with_context(|| {
            format!(
                "failed to synchronize identity-bound restore staging {}; recovery evidence was preserved",
                temp_destination.display()
            )
        })?;
        avorax_platform_security::ensure_path_matches_open_file(
            &input,
            quarantine_path,
            "quarantine payload after reserved restore copy",
        )?;
        avorax_platform_security::ensure_path_matches_open_file(
            staged,
            temp_destination,
            "identity-bound quarantine restore staging file",
        )?;
        staged.seek(SeekFrom::Start(0)).with_context(|| {
            format!(
                "failed to rewind identity-bound restore staging {}",
                temp_destination.display()
            )
        })?;
        let staged_metadata = staged.metadata().with_context(|| {
            format!(
                "failed to inspect identity-bound restore staging {}",
                temp_destination.display()
            )
        })?;
        if staged_metadata.len() != record.file_size {
            return Err(anyhow!(
                "identity-bound restore staging size does not match quarantine record; recovery evidence was preserved"
            ));
        }
        let staged_sha256 = sha256_for_open_file(staged, temp_destination)?;
        if !record.sha256.eq_ignore_ascii_case(&staged_sha256) {
            return Err(anyhow!(
                "identity-bound restore staging hash does not match quarantine record; recovery evidence was preserved"
            ));
        }
        avorax_platform_security::ensure_path_matches_open_file(
            staged,
            temp_destination,
            "identity-bound quarantine restore staging file after copy",
        )?;
        let final_identity =
            persisted_file_identity(avorax_platform_security::capture_open_file_identity(
                staged,
                temp_destination,
                "identity-bound quarantine restore staging file after copy",
            )?);
        if &final_identity != expected {
            return Err(anyhow!(
                "identity-bound restore staging file identity changed during copy; recovery evidence was preserved"
            ));
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
        if self.verified_record_auth_scheme(&path, &raw)?
            != QuarantineMetadataAuthScheme::HmacSha256V2
        {
            return Err(anyhow!(
                "quarantine metadata authentication verification failed after write"
            ));
        }
        Ok(())
    }

    fn replace_record(&self, record: &QuarantineRecord) -> Result<()> {
        validate_quarantine_record_for_write(record)?;
        let path = self.base.join(format!("{}.json", record.quarantine_id));
        let auth_path = self
            .base
            .join(format!("{}.json.auth", record.quarantine_id));
        self.ensure_base_directory()?;
        let (previous_record, previous_raw, previous_auth) =
            self.read_current_metadata_pair(&record.quarantine_id)?;
        validate_metadata_update_transition(&previous_record, record)?;
        let next_raw = serde_json::to_string_pretty(record)?;
        if next_raw == previous_raw {
            return Err(anyhow!(
                "quarantine metadata update does not change the authenticated record"
            ));
        }
        let Some(key) = self.metadata_auth_key(false)? else {
            return Err(anyhow!(
                "quarantine metadata authentication key unavailable"
            ));
        };
        let next_auth = format!("{}\n", hmac_record_auth_tag(&key, &next_raw)?);
        let body = QuarantineMetadataUpdateJournalBody {
            format: QUARANTINE_METADATA_UPDATE_JOURNAL_FORMAT.to_string(),
            quarantine_id: record.quarantine_id.clone(),
            previous_record_raw: previous_raw.clone(),
            previous_record_auth: previous_auth.clone(),
            next_record_raw: next_raw.clone(),
            next_record_auth: next_auth.clone(),
        };
        let journal_path = self.metadata_update_journal_path(&record.quarantine_id)?;
        let journal_lock = self.write_metadata_update_journal(body)?;
        let activation_result = (|| -> Result<()> {
            self.ensure_metadata_pair_exact(
                &previous_record,
                &previous_raw,
                &previous_auth,
                "quarantine metadata pair immediately before update",
            )?;
            replace_staged_quarantine_file(
                &path,
                next_raw.as_bytes(),
                "quarantine metadata record",
            )?;
            let record_after_replace = read_bounded_quarantine_text(
                &path,
                MAX_QUARANTINE_METADATA_BYTES,
                "quarantine metadata record before auth replacement",
            )?;
            let auth_before_replace = read_bounded_quarantine_text(
                &auth_path,
                MAX_QUARANTINE_METADATA_AUTH_BYTES,
                "quarantine metadata auth sidecar before replacement",
            )?;
            if record_after_replace != next_raw
                || !constant_time_eq(auth_before_replace.as_bytes(), previous_auth.as_bytes())
            {
                return Err(anyhow!(
                    "quarantine metadata pair changed unexpectedly between record and auth replacement"
                ));
            }
            replace_staged_quarantine_file(
                &auth_path,
                next_auth.as_bytes(),
                "quarantine metadata auth sidecar",
            )?;
            self.ensure_metadata_pair_exact(
                record,
                &next_raw,
                &next_auth,
                "proposed quarantine metadata pair after update",
            )
        })();
        if let Err(update_error) = activation_result {
            drop(journal_lock);
            return match self.recover_metadata_update_journal(
                &record.quarantine_id,
                &journal_path,
            ) {
                Ok(()) => Err(update_error)
                    .context("quarantine metadata update failed; previous authenticated pair was restored"),
                Err(rollback_error) => Err(rollback_error).with_context(|| {
                    format!(
                        "quarantine metadata update failed and authenticated rollback also failed; journal was preserved: {update_error:#}"
                    )
                }),
            };
        }

        if let Err(cleanup_error) = self.cleanup_metadata_update_journal(&record.quarantine_id) {
            drop(journal_lock);
            return match self.recover_metadata_update_journal(
                &record.quarantine_id,
                &journal_path,
            ) {
                Ok(()) => Err(cleanup_error).context(
                    "quarantine metadata update journal cleanup failed; previous authenticated pair was restored",
                ),
                Err(rollback_error) => Err(rollback_error).with_context(|| {
                    format!(
                        "quarantine metadata update journal cleanup failed and authenticated rollback also failed; journal was preserved: {cleanup_error:#}"
                    )
                }),
            };
        }
        drop(journal_lock);
        Ok(())
    }

    fn read_current_metadata_pair(&self, id: &str) -> Result<(QuarantineRecord, String, String)> {
        validate_quarantine_id(id)?;
        let path = self.base.join(format!("{id}.json"));
        let auth_path = self.base.join(format!("{id}.json.auth"));
        let raw = read_bounded_quarantine_text(
            &path,
            MAX_QUARANTINE_METADATA_BYTES,
            "current quarantine metadata record",
        )?;
        let auth = read_bounded_quarantine_text(
            &auth_path,
            MAX_QUARANTINE_METADATA_AUTH_BYTES,
            "current quarantine metadata auth sidecar",
        )?;
        let Some(key) = self.metadata_auth_key(false)? else {
            return Err(anyhow!(
                "quarantine metadata authentication key unavailable"
            ));
        };
        let record =
            self.validate_metadata_update_record_version(id, &raw, &auth, &key, "current")?;
        Ok((record, raw, auth))
    }

    fn prepare_action_journal_body(
        &self,
        previous: &QuarantineRecord,
        next: &QuarantineRecord,
        action: QuarantineLifecycleAction,
        restore_staging_path: Option<String>,
    ) -> Result<QuarantineActionJournalBody> {
        validate_quarantine_action_transition(previous, next, action)?;
        let (current, previous_record_raw, previous_record_auth) =
            self.read_current_metadata_pair(&previous.quarantine_id)?;
        if current != *previous {
            return Err(anyhow!(
                "quarantine metadata changed before lifecycle action journal creation"
            ));
        }
        self.ensure_metadata_pair_exact(
            previous,
            &previous_record_raw,
            &previous_record_auth,
            "quarantine metadata pair before lifecycle action",
        )?;
        let next_record_raw = serde_json::to_string_pretty(next)?;
        let Some(key) = self.metadata_auth_key(false)? else {
            return Err(anyhow!(
                "quarantine action journal authentication key unavailable"
            ));
        };
        let next_record_auth = format!("{}\n", hmac_record_auth_tag(&key, &next_record_raw)?);
        Ok(QuarantineActionJournalBody {
            format: QUARANTINE_ACTION_JOURNAL_FORMAT.to_string(),
            quarantine_id: previous.quarantine_id.clone(),
            action,
            phase: QuarantineActionPhase::Prepared,
            previous_record_raw,
            previous_record_auth,
            next_record_raw,
            next_record_auth,
            restore_staging_path,
            restore_identity: None,
        })
    }

    fn write_action_journal(
        &self,
        body: QuarantineActionJournalBody,
    ) -> Result<(fs::File, String)> {
        self.ensure_base_directory()?;
        self.ensure_action_journal_conflicts_absent(&body.quarantine_id)?;
        let path = self.action_journal_path(&body.quarantine_id)?;
        let raw = self.serialized_action_journal(&body)?;
        write_staged_quarantine_file(&path, raw.as_bytes(), "quarantine action journal")?;
        let (journal_lock, persisted) = read_locked_bounded_quarantine_text(
            &path,
            MAX_QUARANTINE_ACTION_JOURNAL_BYTES,
            "quarantine action journal",
        )?;
        if persisted != raw {
            return Err(anyhow!(
                "quarantine action journal changed after write; recovery evidence was preserved"
            ));
        }
        self.validated_action_journal(&path, &persisted).context(
            "quarantine action journal failed post-write validation; recovery evidence was preserved",
        )?;
        self.ensure_action_journal_conflicts_absent(&body.quarantine_id)?;
        Ok((journal_lock, raw))
    }

    fn replace_action_journal(
        &self,
        expected_raw: &str,
        expected_phase: QuarantineActionPhase,
        body: QuarantineActionJournalBody,
    ) -> Result<(fs::File, String)> {
        let path = self.action_journal_path(&body.quarantine_id)?;
        let (current_lock, current_raw) = read_locked_bounded_quarantine_text(
            &path,
            MAX_QUARANTINE_ACTION_JOURNAL_BYTES,
            "current quarantine action journal",
        )?;
        if current_raw != expected_raw {
            return Err(anyhow!(
                "quarantine action journal changed before adjacent phase activation; recovery evidence was preserved"
            ));
        }
        let current_body = self.validated_action_journal(&path, &current_raw)?;
        let valid_phase_transition = current_body.action == QuarantineLifecycleAction::Restore
            && body.action == QuarantineLifecycleAction::Restore
            && match (
                expected_phase,
                current_body.restore_identity.as_ref(),
                body.phase,
                body.restore_identity.as_ref(),
            ) {
                (
                    QuarantineActionPhase::Prepared,
                    None,
                    QuarantineActionPhase::RestoreReserved,
                    Some(_),
                ) => true,
                (
                    QuarantineActionPhase::RestoreReserved,
                    Some(current),
                    QuarantineActionPhase::RestoreStaged,
                    Some(next),
                ) => current == next,
                _ => false,
            };
        if current_body.action != body.action
            || current_body.phase != expected_phase
            || current_body.quarantine_id != body.quarantine_id
            || current_body.previous_record_raw != body.previous_record_raw
            || !constant_time_eq(
                current_body.previous_record_auth.as_bytes(),
                body.previous_record_auth.as_bytes(),
            )
            || current_body.next_record_raw != body.next_record_raw
            || !constant_time_eq(
                current_body.next_record_auth.as_bytes(),
                body.next_record_auth.as_bytes(),
            )
            || current_body.restore_staging_path != body.restore_staging_path
            || !valid_phase_transition
        {
            return Err(anyhow!(
                "quarantine action journal phase replacement was not an exact adjacent transition"
            ));
        }
        self.ensure_action_journal_conflicts_absent(&body.quarantine_id)?;
        let next_raw = self.serialized_action_journal(&body)?;
        drop(current_lock);
        replace_staged_quarantine_file(
            &path,
            next_raw.as_bytes(),
            "quarantine action journal phase",
        )?;
        let (next_lock, persisted) = read_locked_bounded_quarantine_text(
            &path,
            MAX_QUARANTINE_ACTION_JOURNAL_BYTES,
            "advanced quarantine action journal",
        )?;
        if persisted != next_raw {
            return Err(anyhow!(
                "advanced quarantine action journal changed after phase activation; recovery evidence was preserved"
            ));
        }
        self.validated_action_journal(&path, &persisted).context(
            "advanced quarantine action journal failed post-write validation; recovery evidence was preserved",
        )?;
        self.ensure_action_journal_conflicts_absent(&body.quarantine_id)?;
        Ok((next_lock, next_raw))
    }

    fn serialized_action_journal(&self, body: &QuarantineActionJournalBody) -> Result<String> {
        let Some(key) = self.metadata_auth_key(false)? else {
            return Err(anyhow!(
                "quarantine action journal authentication key unavailable"
            ));
        };
        let journal = QuarantineActionJournal {
            body: body.clone(),
            authentication: hmac_action_journal_auth_tag(&key, body)?,
        };
        let raw = serde_json::to_string_pretty(&journal)?;
        if raw.len() as u64 > MAX_QUARANTINE_ACTION_JOURNAL_BYTES {
            return Err(anyhow!("quarantine action journal exceeds maximum size"));
        }
        Ok(raw)
    }

    fn ensure_action_journal_conflicts_absent(&self, id: &str) -> Result<()> {
        let update_path = self.metadata_update_journal_path(id)?;
        let finalization_path = self.finalization_journal_path(id)?;
        let finalization_auth_path = self.finalization_journal_auth_path(id)?;
        if optional_quarantine_file_present(
            &update_path,
            "metadata-update journal conflicting with quarantine action",
        )? || optional_quarantine_file_present(
            &finalization_path,
            "finalization journal conflicting with quarantine action",
        )? || optional_quarantine_file_present(
            &finalization_auth_path,
            "finalization auth sidecar conflicting with quarantine action",
        )? {
            return Err(anyhow!(
                "quarantine item {id} has a conflicting recovery journal; evidence was preserved"
            ));
        }
        Ok(())
    }

    fn ensure_action_journal_absent(&self, id: &str, operation: &str) -> Result<()> {
        let path = self.action_journal_path(id)?;
        if optional_quarantine_file_present(&path, "quarantine action journal")? {
            return Err(anyhow!(
                "cannot {operation} quarantine item {id} while an action journal is active"
            ));
        }
        Ok(())
    }

    fn write_metadata_update_journal(
        &self,
        body: QuarantineMetadataUpdateJournalBody,
    ) -> Result<fs::File> {
        let quarantine_id = body.quarantine_id.clone();
        self.ensure_action_journal_absent(&quarantine_id, "update metadata for")?;
        let path = self.metadata_update_journal_path(&quarantine_id)?;
        let Some(key) = self.metadata_auth_key(false)? else {
            return Err(anyhow!(
                "quarantine metadata-update journal authentication key unavailable"
            ));
        };
        let journal = QuarantineMetadataUpdateJournal {
            authentication: hmac_metadata_update_journal_auth_tag(&key, &body)?,
            body,
        };
        let raw = serde_json::to_string_pretty(&journal)?;
        if raw.len() as u64 > MAX_QUARANTINE_METADATA_UPDATE_JOURNAL_BYTES {
            return Err(anyhow!(
                "quarantine metadata-update journal exceeds maximum size"
            ));
        }
        write_staged_quarantine_file(&path, raw.as_bytes(), "quarantine metadata-update journal")?;
        let (journal_lock, persisted) = read_locked_bounded_quarantine_text(
            &path,
            MAX_QUARANTINE_METADATA_UPDATE_JOURNAL_BYTES,
            "quarantine metadata-update journal",
        )?;
        if persisted != raw {
            drop(journal_lock);
            return Err(anyhow!(
                "quarantine metadata-update journal changed after write; recovery evidence was preserved"
            ));
        }
        if let Err(error) = self.validated_metadata_update_journal(&path, &persisted) {
            drop(journal_lock);
            return Err(error).context(
                "quarantine metadata-update journal failed post-write validation; recovery evidence was preserved",
            );
        }
        self.ensure_action_journal_absent(&quarantine_id, "update metadata for")?;
        Ok(journal_lock)
    }

    fn ensure_metadata_pair_exact(
        &self,
        expected_record: &QuarantineRecord,
        expected_raw: &str,
        expected_auth: &str,
        label: &str,
    ) -> Result<()> {
        let path = self
            .base
            .join(format!("{}.json", expected_record.quarantine_id));
        let auth_path = self
            .base
            .join(format!("{}.json.auth", expected_record.quarantine_id));
        let raw = read_bounded_quarantine_text(&path, MAX_QUARANTINE_METADATA_BYTES, label)?;
        let auth =
            read_bounded_quarantine_text(&auth_path, MAX_QUARANTINE_METADATA_AUTH_BYTES, label)?;
        if raw != expected_raw || !constant_time_eq(auth.as_bytes(), expected_auth.as_bytes()) {
            return Err(anyhow!("{label} does not match its expected bytes"));
        }
        if self.verified_record_auth_scheme(&path, &raw)?
            != QuarantineMetadataAuthScheme::HmacSha256V2
        {
            return Err(anyhow!("{label} is not authenticated with current HMAC"));
        }
        let reparsed: QuarantineRecord =
            serde_json::from_str(&raw).with_context(|| format!("unable to parse {label}"))?;
        if reparsed != *expected_record {
            return Err(anyhow!("{label} record does not match expected metadata"));
        }
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

    fn verified_record_auth_scheme(
        &self,
        path: &Path,
        raw: &str,
    ) -> Result<QuarantineMetadataAuthScheme> {
        let auth_path = path.with_extension("json.auth");
        if !optional_quarantine_file_present(&auth_path, "quarantine metadata auth sidecar")? {
            return Err(anyhow!(
                "quarantine metadata authentication sidecar is required for record {}; unsigned legacy metadata is disabled",
                path.display()
            ));
        }
        let Some(key) = self.metadata_auth_key(false)? else {
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
        let expected = hmac_record_auth_tag(&key, raw)?;
        if constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
            return Ok(QuarantineMetadataAuthScheme::HmacSha256V2);
        }
        let local_legacy_expected = legacy_record_auth_tag(&key, raw);
        let guard_legacy_expected = guard_legacy_record_auth_tag(&key, raw);
        if constant_time_eq(local_legacy_expected.as_bytes(), actual.as_bytes())
            || constant_time_eq(guard_legacy_expected.as_bytes(), actual.as_bytes())
        {
            return Ok(QuarantineMetadataAuthScheme::LegacyPrefixSha256V1);
        }
        Err(anyhow!(
            "quarantine metadata authentication failed for record {}",
            path.display()
        ))
    }

    fn record_auth_tag(&self, raw: &str, create_key: bool) -> Result<Option<String>> {
        let Some(key) = self.metadata_auth_key(create_key)? else {
            return Ok(None);
        };
        Ok(Some(hmac_record_auth_tag(&key, raw)?))
    }

    fn migrate_legacy_record_auth(
        &self,
        path: &Path,
        record: &QuarantineRecord,
        raw: &str,
    ) -> Result<()> {
        let current_raw = read_bounded_quarantine_text(
            path,
            MAX_QUARANTINE_METADATA_BYTES,
            "quarantine metadata record during authentication migration",
        )?;
        if current_raw != raw {
            return Err(anyhow!(
                "quarantine metadata changed before authentication migration for record {}",
                path.display()
            ));
        }
        self.replace_record_auth(record, raw)
            .with_context(|| "unable to migrate legacy quarantine metadata authentication")?;
        let verified_raw = read_bounded_quarantine_text(
            path,
            MAX_QUARANTINE_METADATA_BYTES,
            "quarantine metadata record after authentication migration",
        )?;
        if verified_raw != raw
            || self.verified_record_auth_scheme(path, &verified_raw)?
                != QuarantineMetadataAuthScheme::HmacSha256V2
        {
            return Err(anyhow!(
                "quarantine metadata authentication migration verification failed for record {}",
                path.display()
            ));
        }
        Ok(())
    }

    fn ensure_record_path_matches_id(&self, path: &Path, id: &str) -> Result<()> {
        let expected = self.base.join(format!("{id}.json"));
        if path != expected {
            return Err(anyhow!(
                "quarantine metadata path {} does not match record id {id}",
                path.display()
            ));
        }
        Ok(())
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
        let key = generate_metadata_auth_key()?;
        write_staged_quarantine_file(
            &path,
            encode_metadata_auth_key(&key)?.as_bytes(),
            "quarantine metadata authentication key",
        )?;
        Ok(Some(key))
    }

    fn ensure_base_directory(&self) -> Result<()> {
        reject_link_ancestors(&self.base, "quarantine base directory")?;
        fs::create_dir_all(&self.base)?;
        reject_link_ancestors(&self.base, "quarantine base directory")?;
        avorax_platform_security::validate_quarantine_directory_contents(&self.base)
            .context("refusing to change permissions on an unrecognized quarantine directory")?;
        harden_quarantine_base_permissions(&self.base)?;
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
    let expected = ensure_regular_quarantine_file(path, label)?;
    if !expected.is_file() {
        return Err(anyhow!("{label} is not a regular file"));
    }
    let mut file = fs::File::open(path).with_context(|| format!("unable to read {label}"))?;
    harden_open_quarantine_file_permissions(&file, path, label, ExclusiveCopySecurity::Quarantine)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("unable to inspect opened {label}"))?;
    if !metadata.is_file() {
        return Err(anyhow!("opened {label} is not a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(anyhow!(
            "{label} {} exceeds maximum size of {} bytes",
            path.display(),
            max_bytes
        ));
    }
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

fn read_locked_bounded_quarantine_text(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<(fs::File, String)> {
    let expected = ensure_regular_quarantine_file(path, label)?;
    if !expected.is_file() {
        return Err(anyhow!("{label} is not a regular file"));
    }
    let file = fs::File::open(path).with_context(|| format!("unable to lock {label}"))?;
    file.try_lock()
        .map_err(io::Error::from)
        .with_context(|| format!("unable to acquire exclusive lock for {label}"))?;
    harden_open_quarantine_file_permissions(&file, path, label, ExclusiveCopySecurity::Quarantine)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("unable to inspect locked {label}"))?;
    if !metadata.is_file() {
        return Err(anyhow!("locked {label} is not a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(anyhow!(
            "{label} {} exceeds maximum size of {} bytes",
            path.display(),
            max_bytes
        ));
    }
    let mut reader = file
        .try_clone()
        .with_context(|| format!("unable to clone locked {label} handle"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::take(&mut reader, max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("unable to read locked {label}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(anyhow!(
            "{label} {} exceeds maximum size of {} bytes",
            path.display(),
            max_bytes
        ));
    }
    let raw = String::from_utf8(bytes)
        .map_err(|_| anyhow!("{label} {} is not valid UTF-8", path.display()))
        .with_context(|| format!("unable to read locked {label}"))?;
    Ok((file, raw))
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

fn validate_metadata_update_transition(
    previous: &QuarantineRecord,
    next: &QuarantineRecord,
) -> Result<()> {
    if previous.quarantine_id != next.quarantine_id
        || previous.original_path != next.original_path
        || previous.quarantine_path != next.quarantine_path
        || previous.sha256 != next.sha256
        || previous.file_size != next.file_size
        || previous.detection_name != next.detection_name
        || previous.engine != next.engine
        || previous.quarantined_at != next.quarantined_at
        || previous.source != next.source
        || previous.blocked_before_execution != next.blocked_before_execution
        || previous.process_started != next.process_started
        || previous.process_id != next.process_id
    {
        return Err(anyhow!(
            "quarantine metadata update attempted to change immutable threat evidence"
        ));
    }
    Ok(())
}

fn validate_quarantine_action_transition(
    previous: &QuarantineRecord,
    next: &QuarantineRecord,
    action: QuarantineLifecycleAction,
) -> Result<()> {
    validate_metadata_update_transition(previous, next)?;
    if previous.status != QuarantineStatus::Quarantined {
        return Err(anyhow!(
            "quarantine lifecycle action requires an authenticated quarantined record"
        ));
    }
    let mut expected = previous.clone();
    match action {
        QuarantineLifecycleAction::Restore => {
            expected.status = QuarantineStatus::Restored;
            expected.action_taken = "restored".to_string();
        }
        QuarantineLifecycleAction::Delete => {
            expected.status = QuarantineStatus::Deleted;
            expected.action_taken = "deleted".to_string();
        }
    }
    if next != &expected {
        return Err(anyhow!(
            "quarantine lifecycle action journal contains an invalid status transition"
        ));
    }
    Ok(())
}

fn new_restore_staging_path(destination: &Path) -> Result<PathBuf> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("restore destination has no parent directory"))?;
    let path = parent.join(format!("avorax-restore-{}.tmp", Uuid::new_v4()));
    let staging_text = path.display().to_string();
    validate_original_restore_path_text(&staging_text)?;
    Ok(path)
}

fn action_restore_staging_path(body: &QuarantineActionJournalBody) -> Result<PathBuf> {
    let raw = body
        .restore_staging_path
        .as_deref()
        .ok_or_else(|| anyhow!("restore action journal does not contain a staging path"))?;
    validate_original_restore_path_text(raw)
        .context("restore action journal contains an invalid staging path")
}

fn validate_restore_staging_path(record: &QuarantineRecord, staging: &Path) -> Result<()> {
    let destination = validate_original_restore_path_text(&record.original_path)?;
    if staging == destination || staging.parent() != destination.parent() {
        return Err(anyhow!(
            "restore action staging path must be adjacent to and distinct from its destination"
        ));
    }
    let name = staging
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("restore action staging filename is not Unicode"))?;
    let token = name
        .strip_prefix("avorax-restore-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .ok_or_else(|| anyhow!("restore action staging filename is not controlled"))?;
    let uuid = Uuid::parse_str(token)
        .map_err(|_| anyhow!("restore action staging filename has an invalid identifier"))?;
    if uuid.hyphenated().to_string() != token {
        return Err(anyhow!(
            "restore action staging filename identifier is not canonical"
        ));
    }
    Ok(())
}

fn persisted_file_identity(
    identity: avorax_platform_security::StableFileIdentity,
) -> PersistedFileIdentity {
    PersistedFileIdentity {
        platform: current_file_identity_platform().to_string(),
        scope: identity.scope,
        file: identity.file,
    }
}

fn validate_persisted_file_identity(identity: &PersistedFileIdentity) -> Result<()> {
    if identity.platform != current_file_identity_platform() {
        return Err(anyhow!(
            "quarantine action file identity platform does not match this runtime"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn current_file_identity_platform() -> &'static str {
    "windows-volume-file-id-v1"
}

#[cfg(unix)]
fn current_file_identity_platform() -> &'static str {
    "unix-device-inode-v1"
}

#[cfg(not(any(unix, windows)))]
fn current_file_identity_platform() -> &'static str {
    "unsupported-file-identity-v1"
}

fn hmac_record_auth_tag(key: &str, raw: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow!("invalid quarantine metadata authentication key"))?;
    mac.update(QUARANTINE_AUTH_HMAC_DOMAIN);
    mac.update(raw.as_bytes());
    let tag = mac.finalize().into_bytes();
    Ok(format!("{QUARANTINE_AUTH_HMAC_PREFIX}{}", hex_encode(&tag)))
}

fn hmac_finalization_journal_auth_tag(key: &str, raw: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow!("invalid quarantine finalization journal authentication key"))?;
    mac.update(QUARANTINE_FINALIZATION_JOURNAL_AUTH_DOMAIN);
    mac.update(raw.as_bytes());
    let tag = mac.finalize().into_bytes();
    Ok(format!("{QUARANTINE_AUTH_HMAC_PREFIX}{}", hex_encode(&tag)))
}

fn hmac_metadata_update_journal_auth_tag(
    key: &str,
    body: &QuarantineMetadataUpdateJournalBody,
) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow!("invalid quarantine metadata-update journal authentication key"))?;
    mac.update(QUARANTINE_METADATA_UPDATE_JOURNAL_AUTH_DOMAIN);
    mac.update(&serde_json::to_vec(body)?);
    let tag = mac.finalize().into_bytes();
    Ok(format!("{QUARANTINE_AUTH_HMAC_PREFIX}{}", hex_encode(&tag)))
}

fn hmac_action_journal_auth_tag(key: &str, body: &QuarantineActionJournalBody) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow!("invalid quarantine action journal authentication key"))?;
    mac.update(QUARANTINE_ACTION_JOURNAL_AUTH_DOMAIN);
    mac.update(&serde_json::to_vec(body)?);
    let tag = mac.finalize().into_bytes();
    Ok(format!("{QUARANTINE_AUTH_HMAC_PREFIX}{}", hex_encode(&tag)))
}

fn generate_metadata_auth_key() -> Result<String> {
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|error| {
        anyhow!("unable to generate quarantine metadata authentication key: {error}")
    })?;
    Ok(hex_encode(&key))
}

fn legacy_record_auth_tag(key: &str, raw: &str) -> String {
    legacy_record_auth_tag_for_domain(QUARANTINE_AUTH_LEGACY_DOMAIN, key, raw)
}

fn guard_legacy_record_auth_tag(key: &str, raw: &str) -> String {
    legacy_record_auth_tag_for_domain(QUARANTINE_AUTH_GUARD_LEGACY_DOMAIN, key, raw)
}

fn legacy_record_auth_tag_for_domain(domain: &[u8], key: &str, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(key.as_bytes());
    hasher.update(b"\0");
    hasher.update(raw.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn encode_metadata_auth_key(key: &str) -> Result<String> {
    #[cfg(windows)]
    {
        let protected = dpapi_protect(key.as_bytes())?;
        Ok(format!("dpapi:{}\n", hex_encode(&protected)))
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
        Err(anyhow!(
            "plaintext quarantine metadata authentication keys are not accepted on Windows"
        ))
    }
    #[cfg(not(windows))]
    {
        Ok(trimmed.to_string())
    }
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
    let expected_action_taken = expected_quarantine_action_taken(record)?;
    if record.action_taken != expected_action_taken {
        return Err(anyhow!(
            "quarantine metadata action taken does not match status"
        ));
    }
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
        "guard_service" => {
            if record.blocked_before_execution {
                return Err(anyhow!(
                    "guard service quarantine source cannot claim pre-execution blocking"
                ));
            }
            if record.process_started && record.process_id.is_none() {
                return Err(anyhow!(
                    "guard service process-start evidence requires a process id"
                ));
            }
            Ok(())
        }
        _ => Err(anyhow!("unsupported quarantine metadata source")),
    }
}

fn expected_quarantine_action_taken(record: &QuarantineRecord) -> Result<&'static str> {
    match (record.source.as_str(), &record.status) {
        ("scanner", QuarantineStatus::Quarantined) => Ok("quarantined"),
        ("guard_service", QuarantineStatus::Quarantined) if record.process_started => {
            Ok("process_stop_requested_and_file_quarantined")
        }
        ("guard_service", QuarantineStatus::Quarantined) => {
            Ok("file_quarantined_without_process_stop")
        }
        ("scanner" | "guard_service", QuarantineStatus::Restored) => Ok("restored"),
        ("scanner" | "guard_service", QuarantineStatus::Deleted) => Ok("deleted"),
        _ => Err(anyhow!("unsupported quarantine metadata source")),
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
    if !value.len().is_multiple_of(2) {
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

    let input = CRYPT_INTEGER_BLOB {
        cbData: clear.len() as u32,
        pbData: clear.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
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

    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
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

fn open_single_link_quarantine_file(path: &Path, label: &str) -> Result<fs::File> {
    let metadata = ensure_regular_quarantine_file(path, label)?;
    if !metadata.is_file() {
        return Err(anyhow!("{label} is not a regular file"));
    }
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    avorax_platform_security::ensure_open_file_has_single_link(&file, path, label)?;
    Ok(file)
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
    write_file_exclusive(&temp_path, bytes, label)?;
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
    if let Err(error) = activate_quarantine_metadata_no_replace(&temp_path, path, label) {
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
    write_file_exclusive(&temp_path, bytes, label)?;
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
    if let Err(error) = activate_quarantine_metadata_replace_existing(&temp_path, path, label) {
        cleanup_quarantine_staged_file(&temp_path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after atomic replacement failure: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error).with_context(|| {
            format!(
                "failed to atomically replace existing {label} {}",
                path.display()
            )
        });
    }
    Ok(())
}

fn activate_quarantine_metadata_replace_existing(
    staged: &Path,
    destination: &Path,
    label: &str,
) -> Result<()> {
    avorax_platform_security::replace_existing_file_atomically(staged, destination, label)
}

fn activate_quarantine_metadata_no_replace(
    staged: &Path,
    destination: &Path,
    label: &str,
) -> Result<()> {
    avorax_platform_security::rename_file_no_replace(staged, destination, label)
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

fn activate_quarantine_restore_no_replace(staged: &Path, destination: &Path) -> Result<()> {
    avorax_platform_security::rename_file_no_replace(staged, destination, "quarantine restore")
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
    if let Err(error) = harden_open_quarantine_file_permissions(
        &output,
        path,
        label,
        ExclusiveCopySecurity::Quarantine,
    ) {
        drop(output);
        cleanup_quarantine_staged_file(path, label).with_context(|| {
            format!(
                "failed to clean up temporary {label} {} after permission hardening failure: {error:#}",
                path.display()
            )
        })?;
        return Err(error)
            .with_context(|| format!("failed to harden temporary {label} {}", path.display()));
    }
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

fn harden_quarantine_base_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    avorax_platform_security::harden_unix_private_directory(path)
        .context("failed to enforce owner-only quarantine directory permissions")?;
    #[cfg(windows)]
    avorax_platform_security::harden_windows_private_directory(path)
        .context("failed to enforce exact quarantine directory DACL")?;
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

fn move_quarantine_payload_no_replace(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<()> {
    match avorax_platform_security::rename_file_no_replace(
        source,
        destination,
        "local quarantine payload",
    ) {
        Ok(()) => Ok(()),
        Err(rename_error) => copy_then_remove_verified(source, destination, expected_sha256)
            .with_context(|| {
                format!(
                    "atomic no-replace quarantine rename failed: {rename_error}; exclusive verified copy fallback also failed"
                )
            }),
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
    let source_file = copy_file_exclusive(source, destination, ExclusiveCopySecurity::Quarantine)?;
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
    if let Err(error) = avorax_platform_security::ensure_open_file_has_single_link(
        &source_file,
        source,
        "quarantine copy source before removal",
    ) {
        cleanup_quarantine_partial_file(destination, "copied quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up copied quarantine destination {} after hard-link pre-removal failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).context(
            "quarantine copy source link count changed before removal; original was preserved",
        );
    }
    if let Err(error) = (|| -> Result<()> {
        ensure_regular_quarantine_source(source)?;
        avorax_platform_security::ensure_path_matches_open_file(
            &source_file,
            source,
            "quarantine copy source before removal",
        )
    })() {
        cleanup_quarantine_partial_file(destination, "copied quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up copied quarantine destination {} after source identity failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).context(
            "quarantine copy source path changed before removal; current path was preserved and rescan is required",
        );
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

fn cleanup_unbound_empty_restore_staging(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("unbound restore staging path has no parent directory"))?;
    reject_link_ancestors(parent, "unbound quarantine restore staging parent")?;
    let file = open_single_link_quarantine_file(path, "unbound quarantine restore staging file")?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect unbound quarantine restore staging file {}",
            path.display()
        )
    })?;
    if metadata.len() != 0 {
        return Err(anyhow!(
            "unbound quarantine restore staging file is not empty"
        ));
    }
    avorax_platform_security::ensure_path_matches_open_file(
        &file,
        path,
        "unbound quarantine restore staging file",
    )?;
    avorax_platform_security::ensure_open_file_has_single_link(
        &file,
        path,
        "unbound quarantine restore staging file",
    )?;
    let final_metadata = file.metadata().with_context(|| {
        format!(
            "failed to re-inspect unbound quarantine restore staging file {}",
            path.display()
        )
    })?;
    if final_metadata.len() != 0 {
        return Err(anyhow!(
            "unbound quarantine restore staging file changed before checked cleanup"
        ));
    }
    fs::remove_file(path).with_context(|| {
        format!(
            "failed to remove unbound quarantine restore staging file {}",
            path.display()
        )
    })?;
    drop(file);
    if optional_quarantine_path_present(path, "unbound quarantine restore staging file")? {
        return Err(anyhow!(
            "unbound quarantine restore staging file remained after checked cleanup"
        ));
    }
    Ok(())
}

fn cleanup_untracked_quarantine_metadata_artifacts(base: &Path, id: &str) -> Result<()> {
    let metadata_path = base.join(format!("{id}.json"));
    let metadata_temp_path = base.join(format!("{id}.json.tmp"));
    let auth_path = base.join(format!("{id}.json.auth"));
    let auth_temp_path = base.join(format!("{id}.json.auth.tmp"));
    let targets = [
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
            "failed to clean up one or more untracked quarantine metadata artifacts: {}",
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

fn copy_file_exclusive(
    source: &Path,
    destination: &Path,
    security: ExclusiveCopySecurity,
) -> Result<fs::File> {
    let mut input = fs::File::open(source)
        .with_context(|| format!("failed to open quarantine source {}", source.display()))?;
    avorax_platform_security::ensure_open_file_has_single_link(
        &input,
        source,
        "quarantine copy source",
    )?;
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
    if let Err(error) = harden_open_quarantine_file_permissions(
        &output,
        destination,
        "quarantine copy destination",
        security,
    ) {
        drop(output);
        cleanup_quarantine_partial_file(destination, "unhardened quarantine destination")
            .with_context(|| {
                format!(
                    "failed to clean up quarantine destination {} after permission hardening failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "failed to harden quarantine destination {}",
                destination.display()
            )
        });
    }
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
    Ok(input)
}

#[cfg(not(test))]
fn quarantine_base() -> Result<PathBuf> {
    quarantine_base_from_environment()
}

#[cfg(test)]
fn quarantine_base() -> Result<PathBuf> {
    test_quarantine_base()
}

fn quarantine_base_from_environment() -> Result<PathBuf> {
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

#[cfg(test)]
thread_local! {
    static TEST_QUARANTINE_TEMP_DIR: tempfile::TempDir = tempfile::tempdir()
        .expect("create isolated local-core quarantine test directory");
    static TEST_QUARANTINE_BASE_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct TestQuarantineBaseOverride {
    previous: Option<PathBuf>,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl Drop for TestQuarantineBaseOverride {
    fn drop(&mut self) {
        TEST_QUARANTINE_BASE_OVERRIDE.with(|value| {
            value.replace(self.previous.take());
        });
    }
}

#[cfg(test)]
pub(crate) fn override_test_quarantine_base(base: PathBuf) -> TestQuarantineBaseOverride {
    let previous = TEST_QUARANTINE_BASE_OVERRIDE.with(|value| value.replace(Some(base)));
    TestQuarantineBaseOverride {
        previous,
        _not_send: std::marker::PhantomData,
    }
}

#[cfg(test)]
fn test_quarantine_base() -> Result<PathBuf> {
    if let Some(base) = TEST_QUARANTINE_BASE_OVERRIDE.with(|value| value.borrow().clone()) {
        return Ok(base);
    }
    TEST_QUARANTINE_TEMP_DIR.with(|directory| Ok(directory.path().join("Quarantine")))
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
    if matches!(name, "AVORAX_QUARANTINE_DIR" | "ZENTOR_QUARANTINE_DIR") {
        validate_quarantine_override_leaf(name, &path)?;
    }
    Ok(Some(path))
}

fn validate_quarantine_override_leaf(name: &str, path: &Path) -> Result<()> {
    let leaf = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("{name} must end in a dedicated Quarantine directory"))?;
    if !leaf.eq_ignore_ascii_case("quarantine") {
        return Err(anyhow!(
            "{name} must end in a dedicated Quarantine directory"
        ));
    }
    Ok(())
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
    ensure_regular_quarantine_payload(path, "quarantine hash input")?;
    let file = fs::File::open(path)?;
    sha256_for_open_file(&file, path)
}

fn sha256_for_open_file(file: &fs::File, path: &Path) -> Result<String> {
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect opened quarantine hash input {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "opened quarantine hash input {} is not a regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_LOCAL_QUARANTINE_HASH_BYTES {
        return Err(anyhow!(
            "quarantine hash input {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_LOCAL_QUARANTINE_HASH_BYTES
        ));
    }
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

fn harden_quarantine_payload_permissions(path: &Path) -> Result<()> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open quarantine payload {}", path.display()))?;
    harden_open_quarantine_file_permissions(
        &file,
        path,
        "quarantine payload",
        ExclusiveCopySecurity::Quarantine,
    )?;
    Ok(())
}

fn harden_open_quarantine_file_permissions(
    file: &fs::File,
    path: &Path,
    label: &str,
    security: ExclusiveCopySecurity,
) -> Result<()> {
    avorax_platform_security::ensure_open_file_has_single_link(file, path, label)
        .with_context(|| format!("failed to enforce single-link policy for {label}"))?;
    #[cfg(unix)]
    {
        let _ = security;
        avorax_platform_security::harden_unix_private_file(file, path)
            .with_context(|| format!("failed to enforce owner-only permissions for {label}"))?;
    }
    #[cfg(windows)]
    {
        let _ = file;
        if security == ExclusiveCopySecurity::Quarantine {
            avorax_platform_security::harden_windows_quarantine_file(file, path)
                .with_context(|| format!("failed to enforce exact DACL for {label}"))?;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, path, label, security);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanResult, ScanStatus};
    use chrono::Utc;
    use tempfile::{tempdir, tempdir_in};

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

        let error = quarantine_base_from_environment().unwrap_err().to_string();

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

        let error = quarantine_base_from_environment().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_QUARANTINE_DIR"),
        }
        assert!(error.contains("AVORAX_QUARANTINE_DIR must not contain parent traversal"));
    }

    #[test]
    fn quarantine_base_override_requires_dedicated_leaf() {
        let _lock = env_lock();
        let previous = std::env::var_os("AVORAX_QUARANTINE_DIR");
        let dir = tempdir().unwrap();
        std::env::set_var("AVORAX_QUARANTINE_DIR", dir.path().join("not-a-vault"));

        let error = quarantine_base_from_environment().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("AVORAX_QUARANTINE_DIR", value),
            None => std::env::remove_var("AVORAX_QUARANTINE_DIR"),
        }
        assert!(error.contains("must end in a dedicated Quarantine directory"));
    }

    #[test]
    fn quarantine_base_uses_an_isolated_test_directory() {
        let base = quarantine_base().unwrap();

        assert!(base.ends_with("Quarantine"));
        assert!(base.starts_with(std::env::temp_dir()));
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
    fn quarantine_finalization_failures_preserve_payload_and_authenticated_journal() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn quarantine_file(&self").unwrap();
        let end = source.find("pub fn list(&self)").unwrap();
        let quarantine_source = &source[start..end];
        let cleanup_start = source
            .find("fn cleanup_untracked_quarantine_metadata_artifacts")
            .unwrap();
        let cleanup_end = source
            .find("fn copy_local_quarantine_payload_limited")
            .unwrap();
        let cleanup_source = &source[cleanup_start..cleanup_end];

        assert!(quarantine_source.contains("let finalize_result = (|| -> Result<QuarantineRecord>"));
        assert!(quarantine_source.contains("self.write_finalization_journal(&record)?"));
        assert!(quarantine_source.contains("let _finalization_journal_lock"));
        assert!(quarantine_source
            .contains("cleanup_untracked_quarantine_metadata_artifacts(&self.base, &id)"));
        assert!(quarantine_source.contains(
            "payload and authenticated recovery journal were retained for bounded retry"
        ));
        assert!(quarantine_source.contains("let move_result ="));
        assert!(quarantine_source.contains("optional_quarantine_path_present("));
        assert!(quarantine_source.contains(
            "destination absence could not be established; authenticated recovery journal was retained"
        ));
        assert!(quarantine_source.contains("self.cleanup_finalization_journal(&id)"));
        assert!(quarantine_source.contains("Err(error)"));
        assert!(!cleanup_source.contains("\"untracked quarantine payload\""));
        assert!(cleanup_source.contains("\"untracked quarantine metadata record\""));
        assert!(cleanup_source.contains("\"untracked quarantine metadata temp record\""));
        assert!(cleanup_source.contains("\"untracked quarantine metadata auth sidecar\""));
        assert!(cleanup_source.contains("\"untracked quarantine metadata auth temp sidecar\""));
        assert!(cleanup_source
            .contains("failed to clean up one or more untracked quarantine metadata artifacts"));
        assert!(
            quarantine_source
                .find("self.write_finalization_journal(&record)?")
                .unwrap()
                < quarantine_source
                    .find("move_quarantine_payload_no_replace(")
                    .unwrap()
        );
        assert!(
            quarantine_source
                .find("move_quarantine_payload_no_replace(")
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
                    .find("cleanup_untracked_quarantine_metadata_artifacts")
                    .unwrap()
        );
    }

    #[test]
    fn quarantine_finalization_metadata_cleanup_never_deletes_payload() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir(&base).unwrap();
        let id = "cleanup-fixture";
        let payload = base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        let metadata = base.join(format!("{id}.json"));
        let metadata_temp = base.join(format!("{id}.json.tmp"));
        let auth = base.join(format!("{id}.json.auth"));
        let auth_temp = base.join(format!("{id}.json.auth.tmp"));
        fs::write(&payload, b"preserve").unwrap();
        for path in [&metadata, &metadata_temp, &auth, &auth_temp] {
            fs::write(path, b"partial").unwrap();
        }

        cleanup_untracked_quarantine_metadata_artifacts(&base, id).unwrap();

        assert_eq!(fs::read(&payload).unwrap(), b"preserve");
        for path in [metadata, metadata_temp, auth, auth_temp] {
            assert!(!path.exists());
        }
    }

    #[test]
    fn pending_finalization_recovers_isolated_payload_to_authenticated_record() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) =
            recovery_fixture_record(&store, dir.path(), "recover-record", b"benign recovery");
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();

        let records = store.list().unwrap();

        assert_eq!(records, vec![record.clone()]);
        assert!(!original.exists());
        assert_eq!(fs::read(&payload).unwrap(), b"benign recovery");
        assert!(!store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(!store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap()
            .exists());
        let metadata = store.base.join(format!("{}.json", record.quarantine_id));
        let raw = fs::read_to_string(&metadata).unwrap();
        assert_eq!(
            store.verified_record_auth_scheme(&metadata, &raw).unwrap(),
            QuarantineMetadataAuthScheme::HmacSha256V2
        );
    }

    #[test]
    fn pending_finalization_tampering_fails_closed_and_preserves_payload() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) =
            recovery_fixture_record(&store, dir.path(), "tampered-journal", b"benign tamper");
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        let journal_path = store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap();
        let tampered = fs::read_to_string(&journal_path)
            .unwrap()
            .replace("Fixture detection", "Tampered detection");
        fs::write(&journal_path, tampered).unwrap();

        let error = store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("finalization journal authentication failed"));
        assert_eq!(fs::read(&payload).unwrap(), b"benign tamper");
        assert!(journal_path.exists());
        assert!(store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(!store
            .base
            .join(format!("{}.json", record.quarantine_id))
            .exists());
    }

    #[test]
    fn authenticated_pending_finalization_rejects_unknown_fields() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) = recovery_fixture_record(
            &store,
            dir.path(),
            "unknown-journal-field",
            b"benign unknown field",
        );
        store.write_finalization_journal(&record).unwrap();
        let journal_path = store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        write_authenticated_finalization_journal_raw(
            &store,
            &record.quarantine_id,
            &serde_json::to_string_pretty(&value).unwrap(),
        );
        fs::rename(&original, &payload).unwrap();

        let error = store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("unable to parse authenticated quarantine finalization journal"));
        assert!(detail.contains("unknown field"));
        assert_eq!(fs::read(&payload).unwrap(), b"benign unknown field");
        assert!(journal_path.exists());
    }

    #[test]
    fn authenticated_pending_finalization_rejects_filename_id_mismatch() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) = recovery_fixture_record(
            &store,
            dir.path(),
            "journal-record-id",
            b"benign id mismatch",
        );
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        let original_journal = store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap();
        let original_auth = store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap();
        let renamed_journal = store
            .finalization_journal_path("different-journal-id")
            .unwrap();
        let renamed_auth = store
            .finalization_journal_auth_path("different-journal-id")
            .unwrap();
        fs::rename(original_journal, &renamed_journal).unwrap();
        fs::rename(original_auth, &renamed_auth).unwrap();

        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("journal id does not match its filename"));
        assert_eq!(fs::read(&payload).unwrap(), b"benign id mismatch");
        assert!(renamed_journal.exists());
        assert!(renamed_auth.exists());
    }

    #[test]
    fn pending_finalization_rejects_changed_payload_and_preserves_evidence() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) =
            recovery_fixture_record(&store, dir.path(), "changed-payload", b"fixture-one");
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        fs::write(&payload, b"fixture-two").unwrap();

        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("quarantine payload hash mismatch"));
        assert_eq!(fs::read(&payload).unwrap(), b"fixture-two");
        assert!(store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap()
            .exists());
    }

    #[test]
    fn pending_finalization_rejects_conflicting_authenticated_final_record() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) =
            recovery_fixture_record(&store, dir.path(), "conflicting-final", b"benign conflict");
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        let mut conflicting = record.clone();
        conflicting.engine = "Conflicting engine".to_string();
        store.write_record(&conflicting).unwrap();

        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("finalized quarantine record conflicts with authenticated recovery journal"));
        assert_eq!(fs::read(&payload).unwrap(), b"benign conflict");
        assert!(store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(store
            .base
            .join(format!("{}.json", record.quarantine_id))
            .exists());
    }

    #[test]
    fn pending_finalization_without_auth_fails_closed_and_preserves_payload() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) = recovery_fixture_record(
            &store,
            dir.path(),
            "missing-journal-auth",
            b"benign missing auth",
        );
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        let auth_path = store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap();
        fs::remove_file(&auth_path).unwrap();

        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("finalization journal auth sidecar is required"));
        assert_eq!(fs::read(&payload).unwrap(), b"benign missing auth");
        assert!(store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(!auth_path.exists());
    }

    #[test]
    fn abandoned_pending_finalization_cleans_journal_only_when_source_is_intact() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) =
            recovery_fixture_record(&store, dir.path(), "abandoned-journal", b"benign abandoned");
        store.write_finalization_journal(&record).unwrap();

        assert!(store.list().unwrap().is_empty());
        assert_eq!(fs::read(&original).unwrap(), b"benign abandoned");
        assert!(!payload.exists());
        assert!(!store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(!store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap()
            .exists());
    }

    #[test]
    fn active_pending_finalization_lock_blocks_concurrent_recovery() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) = recovery_fixture_record(
            &store,
            dir.path(),
            "active-journal",
            b"benign active journal",
        );
        let journal_lock = store.write_finalization_journal(&record).unwrap();

        let error = store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("active or unavailable"));
        assert!(detail.contains("exclusive lock"));
        assert_eq!(fs::read(&original).unwrap(), b"benign active journal");
        assert!(!payload.exists());
        assert!(store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap()
            .exists());

        drop(journal_lock);
        assert!(store.list().unwrap().is_empty());
        assert_eq!(fs::read(&original).unwrap(), b"benign active journal");
        assert!(!store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(!store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap()
            .exists());
    }

    #[test]
    fn pending_finalization_with_source_and_payload_refuses_ambiguous_recovery() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) =
            recovery_fixture_record(&store, dir.path(), "duplicate-state", b"benign duplicate");
        store.write_finalization_journal(&record).unwrap();
        fs::copy(&original, &payload).unwrap();

        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("both isolated payload and original source"));
        assert_eq!(fs::read(&original).unwrap(), b"benign duplicate");
        assert_eq!(fs::read(&payload).unwrap(), b"benign duplicate");
        assert!(store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap()
            .exists());
    }

    #[test]
    fn pending_finalization_replaces_partial_metadata_after_payload_move() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) =
            recovery_fixture_record(&store, dir.path(), "partial-metadata", b"benign partial");
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        let metadata = store.base.join(format!("{}.json", record.quarantine_id));
        fs::write(&metadata, b"partial").unwrap();

        let records = store.list().unwrap();

        assert_eq!(records, vec![record.clone()]);
        let raw = fs::read_to_string(&metadata).unwrap();
        assert_eq!(
            serde_json::from_str::<QuarantineRecord>(&raw).unwrap(),
            record
        );
        assert!(metadata.with_extension("json.auth").exists());
        assert!(!store
            .finalization_journal_path("partial-metadata")
            .unwrap()
            .exists());
    }

    #[test]
    fn completed_finalization_cleans_stale_authenticated_journal() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) = recovery_fixture_record(
            &store,
            dir.path(),
            "completed-finalization",
            b"benign completed",
        );
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        store.write_record(&record).unwrap();

        assert_eq!(store.list().unwrap(), vec![record.clone()]);
        assert!(!store
            .finalization_journal_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert!(!store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap()
            .exists());
        assert_eq!(fs::read(&payload).unwrap(), b"benign completed");
    }

    #[test]
    fn completed_finalization_cleans_orphan_journal_auth_after_verification() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) = recovery_fixture_record(
            &store,
            dir.path(),
            "orphan-auth-completed",
            b"benign orphan auth",
        );
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        store.write_record(&record).unwrap();
        fs::remove_file(
            store
                .finalization_journal_path(&record.quarantine_id)
                .unwrap(),
        )
        .unwrap();
        let orphan_auth = store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap();

        assert_eq!(store.list().unwrap(), vec![record]);
        assert!(!orphan_auth.exists());
        assert_eq!(fs::read(&payload).unwrap(), b"benign orphan auth");
    }

    #[test]
    fn orphan_journal_auth_with_payload_but_no_final_record_fails_closed() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));
        let (record, original, payload) = recovery_fixture_record(
            &store,
            dir.path(),
            "orphan-auth-incomplete",
            b"benign incomplete auth",
        );
        store.write_finalization_journal(&record).unwrap();
        fs::rename(&original, &payload).unwrap();
        fs::remove_file(
            store
                .finalization_journal_path(&record.quarantine_id)
                .unwrap(),
        )
        .unwrap();
        let orphan_auth = store
            .finalization_journal_auth_path(&record.quarantine_id)
            .unwrap();

        let error = store.list().unwrap_err();

        assert!(error.to_string().contains(
            "orphan quarantine finalization journal auth sidecar has incomplete related state"
        ));
        assert!(orphan_auth.exists());
        assert_eq!(fs::read(&payload).unwrap(), b"benign incomplete auth");
    }

    #[test]
    fn orphan_journal_auth_without_related_state_is_cleaned() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let orphan_auth = base.join("unused-journal.pending.auth");
        fs::write(&orphan_auth, b"uncommitted auth fixture").unwrap();
        let store = QuarantineStore::with_base(base);

        assert!(store.list().unwrap().is_empty());
        assert!(!orphan_auth.exists());
    }

    #[test]
    fn existing_quarantine_base_rejects_unknown_content_before_permission_changes() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("quarantine");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("unrelated.txt"), b"preserve").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
        }
        let store = QuarantineStore::with_base(base.clone());

        let error = store.list().unwrap_err();

        assert!(format!("{error:#}").contains("unrecognized entry unrelated.txt"));
        assert_eq!(fs::read(base.join("unrelated.txt")).unwrap(), b"preserve");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(base).unwrap().permissions().mode() & 0o7777,
                0o777
            );
        }
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
            sha256: sha256_for_file(&file).unwrap(),
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
    fn scan_quarantine_binding_rejects_changed_payload_without_vault_mutation() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("candidate.bin");
        let base = dir.path().join("q");
        fs::write(&file, b"harmless scanned bytes").unwrap();
        let result = fixture_scan_result(&file, ScanStatus::Infected);
        fs::write(&file, b"harmless replacement bytes").unwrap();
        let store = QuarantineStore::with_base(base.clone());

        let error = store.quarantine_file(&file, &result).unwrap_err();

        assert!(format!("{error:#}").contains("changed after its scan verdict"));
        assert!(format!("{error:#}").contains("rescan required"));
        assert_eq!(fs::read(&file).unwrap(), b"harmless replacement bytes");
        assert!(!base.exists());
    }

    #[test]
    fn scan_quarantine_binding_rejects_invalid_verdict_hash_without_vault_mutation() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("candidate.bin");
        let base = dir.path().join("q");
        fs::write(&file, b"harmless fixture").unwrap();
        let mut result = fixture_scan_result(&file, ScanStatus::Infected);
        result.sha256 = "sha256:not-a-valid-verdict-hash".to_string();
        let store = QuarantineStore::with_base(base.clone());

        let error = store.quarantine_file(&file, &result).unwrap_err();

        assert!(format!("{error:#}").contains("infected scan result has an invalid SHA-256"));
        assert_eq!(fs::read(&file).unwrap(), b"harmless fixture");
        assert!(!base.exists());
    }

    #[test]
    fn scan_quarantine_binding_rejects_mismatched_verdict_path_without_vault_mutation() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("candidate.bin");
        let base = dir.path().join("q");
        fs::write(&file, b"harmless fixture").unwrap();
        let mut result = fixture_scan_result(&file, ScanStatus::Infected);
        result.scanned_path = dir.path().join("different.bin").display().to_string();
        let store = QuarantineStore::with_base(base.clone());

        let error = store.quarantine_file(&file, &result).unwrap_err();

        assert!(format!("{error:#}").contains("scan-result path does not match"));
        assert_eq!(fs::read(&file).unwrap(), b"harmless fixture");
        assert!(!base.exists());
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_artifacts_are_owner_only_and_non_executable_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        let base = dir.path().join("q");
        fs::write(&file, b"bad").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o777)).unwrap();
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let result = fixture_scan_result(&file, ScanStatus::Infected);

        let record = store.quarantine_file(&file, &result).unwrap();

        assert_eq!(
            fs::metadata(&base).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        for path in [
            PathBuf::from(&record.quarantine_path),
            base.join(format!("{}.json", record.quarantine_id)),
            base.join(format!("{}.json.auth", record.quarantine_id)),
            base.join(".metadata_auth_key"),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn list_repairs_existing_quarantine_artifact_modes_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        let base = dir.path().join("q");
        fs::write(&file, b"bad").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let result = fixture_scan_result(&file, ScanStatus::Infected);
        let record = store.quarantine_file(&file, &result).unwrap();
        let artifacts = [
            PathBuf::from(&record.quarantine_path),
            base.join(format!("{}.json", record.quarantine_id)),
            base.join(format!("{}.json.auth", record.quarantine_id)),
            base.join(".metadata_auth_key"),
        ];
        fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
        for path in &artifacts {
            fs::set_permissions(path, fs::Permissions::from_mode(0o777)).unwrap();
        }

        assert_eq!(store.list().unwrap().len(), 1);

        assert_eq!(
            fs::metadata(&base).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        for path in artifacts {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
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
            sha256: sha256_for_file(&file).unwrap(),
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

    #[cfg(any(unix, windows))]
    #[test]
    fn quarantine_rejects_hard_linked_source_before_move() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        let alternate = dir.path().join("alternate.exe");
        let base = dir.path().join("q");
        fs::write(&file, b"benign known-bad fixture").unwrap();
        fs::hard_link(&file, &alternate).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let result = fixture_scan_result(&file, ScanStatus::Infected);

        let error = store.quarantine_file(&file, &result).unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("hard-link count is 2"), "{detail}");
        assert!(file.exists());
        assert!(alternate.exists());
        assert!(!base.exists());
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

    #[cfg(unix)]
    #[test]
    fn quarantine_rejects_symbolic_link_base_ancestor_before_creation() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real_parent = dir.path().join("real-parent");
        let linked_parent = dir.path().join("linked-parent");
        fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"bad").unwrap();
        let store = QuarantineStore::with_base(linked_parent.join("q"));
        let result = fixture_scan_result(&file, ScanStatus::Infected);

        let error = store.quarantine_file(&file, &result).unwrap_err();

        assert!(error
            .to_string()
            .contains("refusing to use symbolic link quarantine base directory"));
        assert!(file.exists());
        assert!(!real_parent.join("q").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_point_attribute_constant_is_expected_value() {
        assert_eq!(FILE_ATTRIBUTE_REPARSE_POINT, 0x400);
    }

    #[cfg(windows)]
    #[test]
    fn windows_process_sid_for_quarantine_acl_is_not_empty() {
        let sid = avorax_platform_security::current_windows_process_sid().unwrap();
        assert!(sid.starts_with("S-1-"));
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
        assert!(!encoded.contains("fixture-key"));
        assert_eq!(decode_metadata_auth_key(&encoded).unwrap(), "fixture-key");
    }

    #[cfg(windows)]
    #[test]
    fn metadata_key_storage_rejects_plaintext_on_windows() {
        let error = decode_metadata_auth_key("fixture-key\n").unwrap_err();

        assert!(error
            .to_string()
            .contains("plaintext quarantine metadata authentication keys are not accepted"));
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

    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        all(unix, target_vendor = "apple")
    ))]
    #[test]
    fn quarantine_restore_no_replace_activation_preserves_competing_file() {
        let dir = tempdir().unwrap();
        let staged = dir.path().join("avorax-restore-fixture.tmp");
        let destination = dir.path().join("original.bin");
        fs::write(&staged, b"harmless quarantined bytes").unwrap();
        fs::write(&destination, b"harmless competing bytes").unwrap();

        let error = activate_quarantine_restore_no_replace(&staged, &destination).unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("without replacing"), "{detail}");
        assert_eq!(fs::read(&staged).unwrap(), b"harmless quarantined bytes");
        assert_eq!(fs::read(&destination).unwrap(), b"harmless competing bytes");
    }

    #[test]
    fn restore_journals_intent_before_activation_and_payload_cleanup() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn restore(&self").unwrap();
        let end = source.find("pub fn delete(&self").unwrap();
        let restore_source = &source[start..end];
        let staged_start = source.find("fn reserve_restore_staging_file").unwrap();
        let staged_end = source.find("fn write_record").unwrap();
        let staged_source = &source[staged_start..staged_end];

        assert!(restore_source.contains("restored.status = QuarantineStatus::Restored;"));
        assert!(restore_source.contains("self.write_action_journal(action_body.clone())?"));
        assert!(restore_source.contains("self.replace_action_journal("));
        assert!(restore_source.contains("QuarantineActionPhase::RestoreReserved"));
        assert!(restore_source.contains("self.drive_action_metadata_pair_to_next"));
        assert!(restore_source.contains(
            "remove_checked_quarantine_payload(&quarantine_path, \"restored quarantine payload\")"
        ));
        assert!(restore_source.contains("unable to remove restored quarantine payload"));
        assert!(restore_source.contains("after status update"));
        assert!(
            restore_source
                .find("self.write_action_journal(action_body.clone())?")
                .unwrap()
                < restore_source
                    .find("activate_quarantine_restore_no_replace")
                    .unwrap()
        );
        assert!(
            restore_source
                .find("self.drive_action_metadata_pair_to_next")
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

        assert!(restore_source.contains("restored.status = QuarantineStatus::Restored;"));
        assert!(restore_source.contains("restored.action_taken = \"restored\".to_string();"));
        assert!(
            restore_source
                .find("restored.status = QuarantineStatus::Restored;")
                .unwrap()
                < restore_source
                    .find("restored.action_taken = \"restored\".to_string();")
                    .unwrap()
        );
        assert!(
            restore_source
                .find("restored.action_taken = \"restored\".to_string();")
                .unwrap()
                < restore_source
                    .find("self.write_action_journal(action_body.clone())?")
                    .unwrap()
        );
    }

    #[test]
    fn restore_preserves_authenticated_recovery_until_verified_completion() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn restore(&self").unwrap();
        let end = source.find("pub fn delete(&self").unwrap();
        let restore_source = &source[start..end];

        assert!(restore_source.contains("self.write_action_journal(action_body.clone())?"));
        assert!(restore_source.contains("self.replace_action_journal("));
        assert!(restore_source.contains("self.reserve_restore_staging_file"));
        assert!(restore_source.contains("self.copy_payload_to_reserved_restore"));
        assert!(restore_source.contains("self.ensure_action_restore_file_identity"));
        assert!(restore_source.contains("self.cleanup_action_journal(id)"));
        assert!(!restore_source.contains("unrecorded quarantine restore"));
        assert!(
            restore_source
                .find("self.write_action_journal(action_body.clone())?")
                .unwrap()
                < restore_source
                    .find("self.reserve_restore_staging_file")
                    .unwrap()
        );
        assert!(
            restore_source
                .find("remove_checked_quarantine_payload(&quarantine_path")
                .unwrap()
                < restore_source
                    .find("self.cleanup_action_journal(id)")
                    .unwrap()
        );
    }

    #[test]
    fn restore_revalidates_parent_before_staging_and_activation() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn restore(&self").unwrap();
        let end = source.find("pub fn delete(&self").unwrap();
        let restore_source = &source[start..end];
        let staged_start = source.find("fn reserve_restore_staging_file").unwrap();
        let staged_end = source.find("fn write_record").unwrap();
        let staged_source = &source[staged_start..staged_end];

        assert!(staged_source
            .contains("reject_link_ancestors(parent, \"quarantine restore staging parent\")?;"));
        assert!(restore_source
            .contains("reject_link_ancestors(parent, \"quarantine restore parent\")?;"));
        assert!(
            restore_source
                .find("reject_link_ancestors(parent, \"quarantine restore parent\")?;")
                .unwrap()
                < restore_source
                    .find("self.write_action_journal(action_body.clone())?")
                    .unwrap()
        );
        assert!(
            restore_source
                .rfind("reject_link_ancestors(parent, \"quarantine restore parent\")?;")
                .unwrap()
                < restore_source
                    .find("activate_quarantine_restore_no_replace(")
                    .unwrap()
        );
        assert!(!restore_source.contains("fs::rename(&staging_path, &original_path)"));
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
        let helper_end = helper_start
            + source[helper_start..]
                .find("fn ensure_quarantine_payload_path")
                .unwrap();
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
    fn delete_journals_status_transition_before_payload_removal() {
        let source = include_str!("quarantine_store.rs");
        let start = source.find("pub fn delete(&self").unwrap();
        let end = source.find("fn find_record").unwrap();
        let delete_source = &source[start..end];

        assert!(delete_source.contains("deleted.status = QuarantineStatus::Deleted;"));
        assert!(delete_source.contains("deleted.action_taken = \"deleted\".to_string();"));
        assert!(delete_source.contains("self.write_action_journal(action_body.clone())?"));
        assert!(
            delete_source.contains("unable to record quarantine deletion before payload removal")
        );
        assert!(delete_source.contains(
            "remove_checked_quarantine_payload(&quarantine_path, \"deleted quarantine payload\")"
        ));
        assert!(delete_source.contains("action journal was preserved for recovery"));
        assert!(!delete_source.contains("previous_status"));
        assert!(!delete_source.contains("previous_action_taken"));
        assert!(delete_source.contains("unable to remove deleted quarantine payload"));
        assert!(
            delete_source
                .find("deleted.status = QuarantineStatus::Deleted;")
                .unwrap()
                < delete_source
                    .find("deleted.action_taken = \"deleted\".to_string();")
                    .unwrap()
        );
        assert!(
            delete_source
                .find("self.write_action_journal(action_body.clone())?")
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
                    .find("deleted.status = QuarantineStatus::Deleted;")
                    .unwrap()
        );
    }

    #[test]
    fn corrupt_metadata_record_is_reported_with_context() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        write_authenticated_raw(&store, &base.join("corrupt.json"), "{not-json");
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

        assert!(read_source.contains("let expected = ensure_regular_quarantine_file(path, label)?"));
        assert!(read_source.contains("harden_open_quarantine_file_permissions("));
        assert!(
            read_source
                .find("harden_open_quarantine_file_permissions(")
                .unwrap()
                < read_source.find("let mut total = 0_u64").unwrap()
        );
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
        let store = QuarantineStore::with_base(base.clone());
        write_authenticated_fixture(&store, &base.join("escape.json"), &record);
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
        let store = QuarantineStore::with_base(base.clone());
        write_authenticated_fixture(&store, &base.join("bad-restore.json"), &bad_restore);
        let restore_error = store.list().unwrap_err();
        assert!(restore_error
            .to_string()
            .contains("invalid original path in quarantine metadata record"));

        fs::remove_file(base.join("bad-restore.json")).unwrap();
        fs::remove_file(base.join("bad-restore.json.auth")).unwrap();
        let mut bad_payload =
            fixture_record("bad-payload", dir.path().join("restore.exe"), payload);
        bad_payload.quarantine_path = dir.path().join("payload.tmp").display().to_string();
        write_authenticated_fixture(&store, &base.join("bad-payload.json"), &bad_payload);

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
        let store = QuarantineStore::with_base(base.clone());
        write_authenticated_fixture(&store, &base.join("bad-hash.json"), &bad_hash);
        let hash_error = store.list().unwrap_err();
        assert!(hash_error
            .to_string()
            .contains("invalid quarantine metadata fields in record"));
        let hash_error_chain = format!("{hash_error:#}");
        assert!(hash_error_chain.contains("invalid quarantine metadata sha256"));

        fs::remove_file(base.join("bad-hash.json")).unwrap();
        fs::remove_file(base.join("bad-hash.json.auth")).unwrap();
        let payload = base.join("record.avoraxq");
        let mut bad_label = fixture_record("bad-label", dir.path().join("restore.exe"), payload);
        bad_label.detection_name = "Fixture\nDetection".to_string();
        write_authenticated_fixture(&store, &base.join("bad-label.json"), &bad_label);

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

        assert!(source.contains("fn reserve_restore_staging_file"));
        assert!(source.contains("fn copy_payload_to_reserved_restore"));
        assert!(source.contains("unable to reserve quarantine restore staging file"));
        assert!(source.contains("identity-bound restore staging hash does not match"));
        assert!(source.contains("unable to activate quarantine restore"));
        assert!(!source.contains(&direct_rename_pattern));
    }

    #[test]
    fn restore_staging_uses_exclusive_temp_destination() {
        let source = include_str!("quarantine_store.rs");
        let restore_start = source.find("fn reserve_restore_staging_file").unwrap();
        let restore_end = source.find("fn write_record").unwrap();
        let restore_source = &source[restore_start..restore_end];
        let temp_absent_pattern = ["fn ensure_restore_temp_", "destination_absent"].concat();
        let old_copy_pattern = ["fs::copy(quarantine_", "path, &temp_destination)"].concat();

        assert!(source.contains(&temp_absent_pattern));
        assert!(restore_source.contains("copy_local_quarantine_payload_limited("));
        assert!(restore_source.contains(".create_new(true)"));
        assert!(restore_source.contains("ExclusiveCopySecurity::Restore"));
        assert!(source.contains("quarantine restore temp destination"));
        assert!(!source.contains(&old_copy_pattern));
    }

    #[test]
    fn restore_staging_verification_and_copy_cleanup_failures_are_reported() {
        let source = include_str!("quarantine_store.rs");
        let restore_start = source.find("fn reserve_restore_staging_file").unwrap();
        let restore_end = source.find("fn write_record").unwrap();
        let restore_source = &source[restore_start..restore_end];
        let copy_start = source.find("fn copy_file_exclusive").unwrap();
        let copy_end = source.find("fn quarantine_base").unwrap();
        let copy_source = &source[copy_start..copy_end];

        assert!(source.contains("fn cleanup_quarantine_partial_file"));
        assert!(restore_source.contains("after reservation failure"));
        assert!(restore_source.contains("unbound quarantine restore staging reservation"));
        assert!(restore_source.contains("recovery evidence was preserved"));
        assert!(restore_source.contains("identity-bound quarantine restore staging file"));
        assert!(copy_source.contains("after copy failure"));
        assert!(copy_source.contains("after sync failure"));
        assert!(!restore_source.contains("let _ = fs::remove_file(temp_destination);"));
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
        let store = QuarantineStore::with_base(base.clone());
        write_authenticated_fixture(&store, &base.join("linked-parent.json"), &record);
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

    #[cfg(any(unix, windows))]
    #[test]
    fn copy_fallback_rejects_hard_linked_source_before_destination_creation() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let alternate = dir.path().join("alternate.exe");
        let destination = dir.path().join("q").join("payload.avoraxq");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&source, b"benign fixture").unwrap();
        fs::hard_link(&source, &alternate).unwrap();
        let expected_hash = sha256_for_file(&source).unwrap();

        let error = copy_then_remove_verified(&source, &destination, &expected_hash).unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("hard-link count is 2"), "{detail}");
        assert!(source.exists());
        assert!(alternate.exists());
        assert!(!destination.exists());
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
                .find(
                    "copy_file_exclusive(source, destination, ExclusiveCopySecurity::Quarantine)?",
                )
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

    #[test]
    fn quarantine_ingest_no_replace_preserves_competing_destination() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("q").join("payload.avoraxq");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&source, b"benign quarantine source").unwrap();
        fs::write(&destination, b"benign competing destination").unwrap();
        let expected_hash = sha256_for_file(&source).unwrap();

        let error = move_quarantine_payload_no_replace(&source, &destination, &expected_hash)
            .expect_err("a competing quarantine destination must not be replaced");
        let detail = format!("{error:#}");

        assert!(detail.contains("atomic no-replace quarantine rename failed"));
        assert!(detail.contains("exclusive verified copy fallback also failed"));
        assert_eq!(fs::read(&source).unwrap(), b"benign quarantine source");
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"benign competing destination"
        );
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
        assert!(hash_source
            .contains("ensure_regular_quarantine_payload(path, \"quarantine hash input\")?"));
        assert!(hash_source.contains("sha256_for_open_file(&file, path)"));
        assert!(hash_source.contains("fn sha256_for_open_file("));
        assert!(hash_source.contains("let metadata = file.metadata()"));
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
    fn guard_service_record_is_listed_and_restored_through_local_core() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("guard-record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let restore_path = dir.path().join("restore.exe");
        let store = QuarantineStore::with_base(base);
        let mut record = fixture_record("guard-record", restore_path.clone(), payload.clone());
        record.file_size = fs::metadata(&payload).unwrap().len();
        record.sha256 = sha256_for_file(&payload).unwrap();
        record.source = "guard_service".to_string();
        record.action_taken = "process_stop_requested_and_file_quarantined".to_string();
        record.process_started = true;
        record.process_id = Some(4242);

        store.write_record(&record).unwrap();
        let listed = store.list().unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].source, "guard_service");
        assert_eq!(
            listed[0].action_taken,
            "process_stop_requested_and_file_quarantined"
        );
        assert!(listed[0].process_started);
        assert_eq!(listed[0].process_id, Some(4242));

        let restored = store.restore("guard-record", true).unwrap();

        assert_eq!(restored.status, QuarantineStatus::Restored);
        assert_eq!(restored.action_taken, "restored");
        assert_eq!(restored.source, "guard_service");
        assert_eq!(fs::read(&restore_path).unwrap(), b"quarantined");
        assert!(!payload.exists());
    }

    #[test]
    fn guard_service_record_rejects_inconsistent_execution_evidence() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        let payload = base.join("guard-record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let mut record = fixture_record("guard-record", dir.path().join("restore.exe"), payload);
        record.source = "guard_service".to_string();
        record.action_taken = "process_stop_requested_and_file_quarantined".to_string();
        record.process_started = true;

        let missing_pid = store.write_record(&record).unwrap_err();
        assert!(format!("{missing_pid:#}")
            .contains("guard service process-start evidence requires a process id"));

        record.process_started = false;
        record.blocked_before_execution = true;
        record.action_taken = "file_quarantined_without_process_stop".to_string();
        let preexecution = store.write_record(&record).unwrap_err();
        assert!(format!("{preexecution:#}")
            .contains("guard service quarantine source cannot claim pre-execution blocking"));
        assert!(!base.join("guard-record.json").exists());
        assert!(!base.join("guard-record.json.auth").exists());
    }

    #[test]
    fn metadata_validation_requires_action_taken_to_match_status() {
        let source = include_str!("quarantine_store.rs");
        let validation_start = source
            .find("fn validate_quarantine_record_metadata")
            .unwrap();
        let validation_end = source.find("fn validate_quarantine_metadata_text").unwrap();
        let validation_source = &source[validation_start..validation_end];

        assert!(validation_source
            .contains("let expected_action_taken = expected_quarantine_action_taken(record)?;"));
        assert!(validation_source.contains("record.action_taken != expected_action_taken"));
        assert!(
            validation_source.contains("quarantine metadata action taken does not match status")
        );
        assert!(source.contains("fn expected_quarantine_action_taken(record: &QuarantineRecord)"));
        assert!(source.contains("(\"scanner\", QuarantineStatus::Quarantined)"));
        assert!(source.contains("process_stop_requested_and_file_quarantined"));
        assert!(source.contains("file_quarantined_without_process_stop"));
        assert!(source.contains("QuarantineStatus::Restored"));
        assert!(source.contains("QuarantineStatus::Deleted"));
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
        assert!(validation_source.contains("\"guard_service\""));
        assert!(validation_source.contains("unsupported quarantine metadata source"));
        assert!(validation_source
            .contains("scanner quarantine source cannot claim execution-state evidence"));
        assert!(validation_source
            .contains("guard service quarantine source cannot claim pre-execution blocking"));
        assert!(validation_source
            .contains("guard service process-start evidence requires a process id"));
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
        let atomic_replace_pattern = [
            "avorax_platform_security::replace_existing_file_atomically(staged, destination, label)",
        ]
        .concat();
        let old_remove_helper_pattern = ["fn remove_existing_", "quarantine_file("].concat();
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
        assert!(source.contains("after atomic replacement failure"));
        assert!(source.contains("{label} destination already exists"));
        assert!(source.contains("fn ensure_quarantine_file_parent_directory"));
        assert!(source.contains("refusing to replace symbolic link {label}"));
        assert!(source.contains("refusing to replace reparse point {label}"));
        assert!(source.contains("fn ensure_quarantine_file_destination_absent"));
        assert!(!source.contains(&old_record_write_pattern));
        assert!(!source.contains(&old_auth_write_pattern));
        assert!(!source.contains(&old_key_write_pattern));
        assert!(source.contains(&atomic_replace_pattern));
        assert!(!source.contains(&old_remove_helper_pattern));
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
    fn quarantine_metadata_no_replace_activation_preserves_competing_file() {
        let dir = tempdir().unwrap();
        let staged = dir.path().join("record.json.tmp-benign");
        let destination = dir.path().join("record.json");
        fs::write(&staged, b"benign staged quarantine metadata").unwrap();
        fs::write(&destination, b"benign competing quarantine metadata").unwrap();

        let error = activate_quarantine_metadata_no_replace(
            &staged,
            &destination,
            "quarantine metadata fixture",
        )
        .expect_err("a competing quarantine metadata file must not be replaced");
        let detail = format!("{error:#}");

        assert!(detail.contains("without replacing"), "{detail}");
        assert_eq!(
            fs::read(&staged).unwrap(),
            b"benign staged quarantine metadata"
        );
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"benign competing quarantine metadata"
        );
    }

    #[test]
    fn quarantine_metadata_atomic_replace_replaces_existing_regular_file() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("record.json");
        fs::write(&destination, b"benign old quarantine metadata").unwrap();

        replace_staged_quarantine_file(
            &destination,
            b"benign new quarantine metadata",
            "quarantine metadata fixture",
        )
        .unwrap();

        assert_eq!(
            fs::read(&destination).unwrap(),
            b"benign new quarantine metadata"
        );
        let residue = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-") || name.contains(".avorax-replace-backup"))
            .collect::<Vec<_>>();
        assert!(residue.is_empty(), "replacement residue: {residue:?}");
    }

    #[test]
    fn quarantine_metadata_atomic_replace_rejects_missing_existing_file() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("missing-record.json");

        let error = replace_staged_quarantine_file(
            &destination,
            b"benign staged quarantine metadata",
            "quarantine metadata fixture",
        )
        .expect_err("replacement must require an existing destination");
        let detail = format!("{error:#}");

        assert!(
            detail.contains("failed to atomically replace existing quarantine metadata fixture"),
            "{detail}"
        );
        assert!(!destination.exists());
        let residue = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-") || name.contains(".avorax-replace-backup"))
            .collect::<Vec<_>>();
        assert!(residue.is_empty(), "replacement residue: {residue:?}");
    }

    #[test]
    fn quarantine_metadata_atomic_replace_updates_authenticated_record_pair() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"benign quarantined payload fixture").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let mut record = fixture_record("record", dir.path().join("restore.exe"), payload);
        store.write_record(&record).unwrap();
        let record_path = base.join("record.json");
        let auth_path = base.join("record.json.auth");
        let old_raw = fs::read_to_string(&record_path).unwrap();
        let old_auth = fs::read_to_string(&auth_path).unwrap();

        record.user_note = Some("benign atomic replacement fixture".to_string());
        store.replace_record(&record).unwrap();

        let new_raw = fs::read_to_string(&record_path).unwrap();
        let new_auth = fs::read_to_string(&auth_path).unwrap();
        let reparsed: QuarantineRecord = serde_json::from_str(&new_raw).unwrap();
        assert_ne!(new_raw, old_raw);
        assert_ne!(new_auth, old_auth);
        assert_eq!(reparsed.user_note, record.user_note);
        assert_eq!(
            store
                .verified_record_auth_scheme(&record_path, &new_raw)
                .unwrap(),
            QuarantineMetadataAuthScheme::HmacSha256V2
        );
        let residue = fs::read_dir(&base)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-") || name.contains(".avorax-replace-backup"))
            .collect::<Vec<_>>();
        assert!(residue.is_empty(), "replacement residue: {residue:?}");
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_delete_drives_all_known_pair_states_forward() {
        for state in [
            "previous-previous",
            "next-previous",
            "previous-next",
            "next-next",
        ] {
            let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let base = dir.path().join("q");
            let fixture = stage_action_fixture(
                &base,
                dir.path(),
                "delete-record",
                QuarantineLifecycleAction::Delete,
                QuarantineActionPhase::Prepared,
            );
            if state == "next-previous" || state == "next-next" {
                fs::write(&fixture.record_path, &fixture.body.next_record_raw).unwrap();
            }
            if state == "previous-next" || state == "next-next" {
                fs::write(&fixture.auth_path, &fixture.body.next_record_auth).unwrap();
            }

            let records = fixture.store.list().unwrap();

            assert_eq!(records, vec![fixture.next_record.clone()], "{state}");
            assert!(!fixture.payload_path.exists(), "{state}");
            assert!(!fixture.journal_path.exists(), "{state}");
        }
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_delete_accepts_already_absent_payload() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "delete-absent",
            QuarantineLifecycleAction::Delete,
            QuarantineActionPhase::Prepared,
        );
        fs::remove_file(&fixture.payload_path).unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.next_record]);
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_prepared_restore_cleans_only_intent() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-prepared",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.previous_record]);
        assert!(fixture.payload_path.exists());
        assert!(!fixture.destination_path.exists());
        assert!(!fixture.staging_path.unwrap().exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_prepared_restore_preserves_unbound_stage() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-unbound",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );
        let staging = fixture.staging_path.as_ref().unwrap();
        fs::write(staging, ACTION_FIXTURE_BYTES).unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("unbound staging file"), "{detail}");
        assert!(staging.exists());
        assert!(fixture.payload_path.exists());
        assert!(fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_prepared_restore_cleans_empty_unbound_reservation() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-empty-unbound",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );
        let staging = fixture.staging_path.clone().unwrap();
        fs::File::create(&staging).unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.previous_record]);
        assert!(fixture.payload_path.exists());
        assert!(!fixture.destination_path.exists());
        assert!(!staging.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_reserved_cleans_empty_stage() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-reserved-empty",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreReserved,
        );
        let staging = fixture.staging_path.clone().unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.previous_record]);
        assert!(fixture.payload_path.exists());
        assert!(!fixture.destination_path.exists());
        assert!(!staging.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_reserved_cleans_partial_stage() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-reserved-partial",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreReserved,
        );
        let staging = fixture.staging_path.clone().unwrap();
        fs::write(&staging, b"benign partial restore stage").unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.previous_record]);
        assert!(fixture.payload_path.exists());
        assert!(!fixture.destination_path.exists());
        assert!(!staging.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_reserved_cleans_same_size_tampered_stage() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-reserved-tampered",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreReserved,
        );
        let staging = fixture.staging_path.clone().unwrap();
        fs::write(&staging, vec![b'x'; ACTION_FIXTURE_BYTES.len()]).unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.previous_record]);
        assert!(fixture.payload_path.exists());
        assert!(!fixture.destination_path.exists());
        assert!(!staging.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_prepared_restore_rejects_hard_linked_empty_stage() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-unbound-hard-link",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );
        let external = dir.path().join("benign-empty-external-stage.bin");
        fs::File::create(&external).unwrap();
        let staging = fixture.staging_path.as_ref().unwrap();
        fs::hard_link(&external, staging).unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("hard-link count"), "{detail}");
        assert!(external.exists());
        assert!(staging.exists());
        assert!(fixture.payload_path.exists());
        assert!(fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_reserved_resumes_completed_copy() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-reserved-complete",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreReserved,
        );
        let staging = fixture.staging_path.clone().unwrap();
        fs::write(&staging, ACTION_FIXTURE_BYTES).unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.next_record]);
        assert_eq!(
            fs::read(&fixture.destination_path).unwrap(),
            ACTION_FIXTURE_BYTES
        );
        assert!(!fixture.payload_path.exists());
        assert!(!staging.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_reserved_rejects_identity_mismatch() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-reserved-identity",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreReserved,
        );
        let staging = fixture.staging_path.as_ref().unwrap();
        fs::rename(staging, dir.path().join("preserved-reserved-stage.bin")).unwrap();
        fs::File::create(staging).unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("persistent file identity"), "{detail}");
        assert!(staging.exists());
        assert!(fixture.payload_path.exists());
        assert!(fixture.journal_path.exists());
        assert!(!fixture.destination_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_reserved_rejects_early_destination() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-reserved-destination",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreReserved,
        );
        fs::write(&fixture.destination_path, b"benign competing destination").unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("destination before staged activation"),
            "{detail}"
        );
        assert!(fixture.staging_path.unwrap().exists());
        assert!(fixture.payload_path.exists());
        assert!(fixture.journal_path.exists());
        assert!(fixture.destination_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_non_adjacent_phase_transition() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-phase-skip",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );
        let staging = fixture.staging_path.as_ref().unwrap();
        let (staged_file, identity) = fixture.store.reserve_restore_staging_file(staging).unwrap();
        let mut skipped = fixture.body.clone();
        skipped.phase = QuarantineActionPhase::RestoreStaged;
        skipped.restore_identity = Some(identity);
        let prepared_raw = fs::read_to_string(&fixture.journal_path).unwrap();
        drop(staged_file);

        let error = fixture
            .store
            .replace_action_journal(&prepared_raw, QuarantineActionPhase::Prepared, skipped)
            .unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("not an exact adjacent transition"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert!(fixture.payload_path.exists());
        assert!(staging.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_delete_phase_transition() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "delete-phase-transition",
            QuarantineLifecycleAction::Delete,
            QuarantineActionPhase::Prepared,
        );
        let prepared_raw = fs::read_to_string(&fixture.journal_path).unwrap();
        let mut invalid = fixture.body.clone();
        invalid.phase = QuarantineActionPhase::RestoreReserved;
        invalid.restore_identity = Some(PersistedFileIdentity {
            platform: current_file_identity_platform().to_string(),
            scope: 1,
            file: 1,
        });

        let error = fixture
            .store
            .replace_action_journal(&prepared_raw, QuarantineActionPhase::Prepared, invalid)
            .unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("not an exact adjacent transition"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert!(fixture.payload_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_staged_resumes_from_staging() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-stage",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreStaged,
        );
        let staging = fixture.staging_path.clone().unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.next_record]);
        assert_eq!(
            fs::read(&fixture.destination_path).unwrap(),
            ACTION_FIXTURE_BYTES
        );
        assert!(!staging.exists());
        assert!(!fixture.payload_path.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_staged_resumes_from_destination() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-destination",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreStaged,
        );
        let staging = fixture.staging_path.clone().unwrap();
        activate_quarantine_restore_no_replace(&staging, &fixture.destination_path).unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.next_record]);
        assert_eq!(
            fs::read(&fixture.destination_path).unwrap(),
            ACTION_FIXTURE_BYTES
        );
        assert!(!fixture.payload_path.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_restore_staged_cleans_committed_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-committed",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreStaged,
        );
        activate_quarantine_restore_no_replace(
            fixture.staging_path.as_ref().unwrap(),
            &fixture.destination_path,
        )
        .unwrap();
        fs::write(&fixture.record_path, &fixture.body.next_record_raw).unwrap();
        fs::write(&fixture.auth_path, &fixture.body.next_record_auth).unwrap();
        fs::remove_file(&fixture.payload_path).unwrap();

        let records = fixture.store.list().unwrap();

        assert_eq!(records, vec![fixture.next_record]);
        assert!(fixture.destination_path.exists());
        assert!(!fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_restore_identity_mismatch() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-identity",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreStaged,
        );
        let staging = fixture.staging_path.as_ref().unwrap();
        fs::rename(staging, dir.path().join("preserved-identity-fixture.bin")).unwrap();
        fs::write(staging, ACTION_FIXTURE_BYTES).unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("persistent file identity"), "{detail}");
        assert!(fixture.journal_path.exists());
        assert!(fixture.payload_path.exists());
        assert!(!fixture.destination_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_tampered_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "action-tamper",
            QuarantineLifecycleAction::Delete,
            QuarantineActionPhase::Prepared,
        );
        let raw = fs::read_to_string(&fixture.journal_path).unwrap();
        let mut journal: QuarantineActionJournal = serde_json::from_str(&raw).unwrap();
        journal.authentication = format!("{QUARANTINE_AUTH_HMAC_PREFIX}{}", "0".repeat(64));
        fs::write(
            &fixture.journal_path,
            serde_json::to_string_pretty(&journal).unwrap(),
        )
        .unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("action journal authentication failed"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert!(fixture.payload_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_unknown_metadata_bytes() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "action-unknown",
            QuarantineLifecycleAction::Delete,
            QuarantineActionPhase::Prepared,
        );
        fs::write(&fixture.record_path, b"{\"benign\":\"unknown\"}").unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("match neither authenticated journal version"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert!(fixture.payload_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_active_lock_blocks_concurrent_list() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let locked = stage_action_fixture_with_lock(
            &base,
            dir.path(),
            "action-locked",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );

        let error = locked.fixture.store.list().unwrap_err();
        assert!(format!("{error:#}").contains("active or unavailable"));
        assert!(locked.fixture.journal_path.exists());
        drop(locked.journal_lock);
        assert_eq!(locked.fixture.store.list().unwrap().len(), 1);
        assert!(!locked.fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_conflicting_update_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "action-conflict",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );
        let update_path = base.join("action-conflict.update.pending");
        fs::write(&update_path, b"benign conflicting recovery fixture").unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("conflicting metadata-update"), "{detail}");
        assert!(fixture.journal_path.exists());
        assert!(update_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_existing_journal_blocks_second_action() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let locked = stage_action_fixture_with_lock(
            &base,
            dir.path(),
            "action-existing",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );

        let error = locked
            .fixture
            .store
            .write_action_journal(locked.fixture.body.clone())
            .unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("action journal"), "{detail}");
        assert!(detail.contains("destination already exists"), "{detail}");
        assert!(locked.fixture.journal_path.exists());
        drop(locked.journal_lock);
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_oversized_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "action-oversized",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );
        fs::write(
            &fixture.journal_path,
            vec![b'x'; MAX_QUARANTINE_ACTION_JOURNAL_BYTES as usize + 1],
        )
        .unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("action journal"), "{detail}");
        assert!(detail.contains("exceeds maximum size"), "{detail}");
        assert!(fixture.journal_path.exists());
        assert!(fixture.payload_path.exists());
    }

    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_both_restore_artifacts() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "restore-duplicate",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::RestoreStaged,
        );
        fs::copy(
            fixture.staging_path.as_ref().unwrap(),
            &fixture.destination_path,
        )
        .unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("exactly one identity-bound"), "{detail}");
        assert!(fixture.journal_path.exists());
        assert!(fixture.payload_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_lifecycle_action_recovery_rejects_linked_journal() {
        use std::os::unix::fs::symlink;

        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_action_fixture(
            &base,
            dir.path(),
            "action-linked",
            QuarantineLifecycleAction::Restore,
            QuarantineActionPhase::Prepared,
        );
        let external = dir.path().join("external-benign-action-journal.json");
        fs::write(&external, b"benign external action journal").unwrap();
        fs::remove_file(&fixture.journal_path).unwrap();
        symlink(&external, &fixture.journal_path).unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("not a non-link regular file"), "{detail}");
        assert_eq!(
            fs::read(&external).unwrap(),
            b"benign external action journal"
        );
        assert!(fixture.payload_path.exists());
    }

    #[test]
    fn quarantine_metadata_update_recovery_rolls_back_all_known_pair_states() {
        for state in [
            "previous-previous",
            "next-previous",
            "previous-next",
            "next-next",
        ] {
            let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let base = dir.path().join("q");
            let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
            if state == "next-previous" || state == "next-next" {
                fs::write(&fixture.record_path, &fixture.next_raw).unwrap();
            }
            if state == "previous-next" || state == "next-next" {
                fs::write(&fixture.auth_path, &fixture.next_auth).unwrap();
            }

            let records = fixture.store.list().unwrap();

            assert_eq!(records, vec![fixture.previous_record.clone()], "{state}");
            assert_eq!(
                fs::read_to_string(&fixture.record_path).unwrap(),
                fixture.previous_raw,
                "{state}"
            );
            assert_eq!(
                fs::read_to_string(&fixture.auth_path).unwrap(),
                fixture.previous_auth,
                "{state}"
            );
            assert!(!fixture.journal_path.exists(), "{state}");
        }
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_tampered_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        let raw = fs::read_to_string(&fixture.journal_path).unwrap();
        let mut journal: QuarantineMetadataUpdateJournal = serde_json::from_str(&raw).unwrap();
        journal.authentication = format!("{QUARANTINE_AUTH_HMAC_PREFIX}{}", "0".repeat(64));
        fs::write(
            &fixture.journal_path,
            serde_json::to_string_pretty(&journal).unwrap(),
        )
        .unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("metadata-update journal authentication failed"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert_eq!(
            fs::read_to_string(&fixture.auth_path).unwrap(),
            fixture.previous_auth
        );
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_malformed_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        fs::write(&fixture.journal_path, b"{not-valid-json").unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("unable to parse quarantine metadata-update journal"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert_eq!(
            fs::read_to_string(&fixture.auth_path).unwrap(),
            fixture.previous_auth
        );
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_semantically_unchanged_record() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        let raw = fs::read_to_string(&fixture.journal_path).unwrap();
        let mut journal: QuarantineMetadataUpdateJournal = serde_json::from_str(&raw).unwrap();
        let key = fixture.store.metadata_auth_key(false).unwrap().unwrap();
        journal.body.next_record_raw = serde_json::to_string(&fixture.previous_record).unwrap();
        journal.body.next_record_auth = format!(
            "{}\n",
            hmac_record_auth_tag(&key, &journal.body.next_record_raw).unwrap()
        );
        journal.authentication =
            hmac_metadata_update_journal_auth_tag(&key, &journal.body).unwrap();
        fs::write(
            &fixture.journal_path,
            serde_json::to_string_pretty(&journal).unwrap(),
        )
        .unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("does not describe a changed authenticated record"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert_eq!(
            fs::read_to_string(&fixture.auth_path).unwrap(),
            fixture.previous_auth
        );
    }

    #[test]
    fn quarantine_metadata_update_recovery_writer_preserves_invalid_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("record.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);
        store.write_record(&record).unwrap();
        let previous_raw = fs::read_to_string(base.join("record.json")).unwrap();
        let previous_auth = fs::read_to_string(base.join("record.json.auth")).unwrap();
        let next_raw = serde_json::to_string(&record).unwrap();
        let key = store.metadata_auth_key(false).unwrap().unwrap();
        let next_auth = format!("{}\n", hmac_record_auth_tag(&key, &next_raw).unwrap());

        let error = store
            .write_metadata_update_journal(QuarantineMetadataUpdateJournalBody {
                format: QUARANTINE_METADATA_UPDATE_JOURNAL_FORMAT.to_string(),
                quarantine_id: record.quarantine_id.clone(),
                previous_record_raw: previous_raw,
                previous_record_auth: previous_auth,
                next_record_raw: next_raw,
                next_record_auth: next_auth,
            })
            .unwrap_err();
        let detail = format!("{error:#}");
        let journal_path = base.join("record.update.pending");

        assert!(
            detail.contains("does not describe a changed authenticated record"),
            "{detail}"
        );
        assert!(
            detail.contains("recovery evidence was preserved"),
            "{detail}"
        );
        assert!(journal_path.exists());

        let recovery_error = store.list().unwrap_err();
        assert!(format!("{recovery_error:#}")
            .contains("does not describe a changed authenticated record"));
        assert!(journal_path.exists());
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_conflicting_finalization_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        let finalization_lock = fixture
            .store
            .write_finalization_journal(&fixture.previous_record)
            .unwrap();
        drop(finalization_lock);

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail
                .contains("conflicting metadata-update, action, or finalization recovery journals"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert!(base.join("record.pending").exists());
        assert!(base.join("record.pending.auth").exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert_eq!(
            fs::read_to_string(&fixture.auth_path).unwrap(),
            fixture.previous_auth
        );
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_unknown_record_bytes() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        fs::write(&fixture.record_path, b"{\"benign\":\"unknown-record\"}").unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("match neither authenticated journal version"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            "{\"benign\":\"unknown-record\"}"
        );
        assert_eq!(
            fs::read_to_string(&fixture.auth_path).unwrap(),
            fixture.previous_auth
        );
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_unknown_auth_bytes() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        fs::write(
            &fixture.auth_path,
            format!("{QUARANTINE_AUTH_HMAC_PREFIX}{}\n", "1".repeat(64)),
        )
        .unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("match neither authenticated journal version"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert!(fs::read_to_string(&fixture.auth_path)
            .unwrap()
            .contains(&"1".repeat(64)));
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_missing_pair_member() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        fs::remove_file(&fixture.auth_path).unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("requires both record and authentication sidecar"),
            "{detail}"
        );
        assert!(fixture.journal_path.exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert!(!fixture.auth_path.exists());
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_oversized_journal() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        fs::write(
            &fixture.journal_path,
            vec![b'x'; MAX_QUARANTINE_METADATA_UPDATE_JOURNAL_BYTES as usize + 1],
        )
        .unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("metadata-update journal"), "{detail}");
        assert!(detail.contains("exceeds maximum size"), "{detail}");
        assert!(fixture.journal_path.exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert_eq!(
            fs::read_to_string(&fixture.auth_path).unwrap(),
            fixture.previous_auth
        );
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_metadata_update_recovery_rejects_linked_journal() {
        use std::os::unix::fs::symlink;

        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        let external = dir.path().join("external-benign-journal.json");
        fs::write(&external, b"benign external journal fixture").unwrap();
        fs::remove_file(&fixture.journal_path).unwrap();
        symlink(&external, &fixture.journal_path).unwrap();

        let error = fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("not a non-link regular file"), "{detail}");
        assert_eq!(
            fs::read(&external).unwrap(),
            b"benign external journal fixture"
        );
        assert!(fs::symlink_metadata(&fixture.journal_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert_eq!(
            fs::read_to_string(&fixture.auth_path).unwrap(),
            fixture.previous_auth
        );
    }

    #[test]
    fn quarantine_metadata_update_recovery_active_lock_blocks_concurrent_list() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture_with_lock(&base, dir.path(), "record");

        let error = fixture.fixture.store.list().unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("active or unavailable"), "{detail}");
        assert!(fixture.fixture.journal_path.exists());
        drop(fixture.journal_lock);
        assert_eq!(fixture.fixture.store.list().unwrap().len(), 1);
        assert!(!fixture.fixture.journal_path.exists());
    }

    #[test]
    fn quarantine_metadata_update_recovery_existing_journal_blocks_second_update() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let fixture = stage_metadata_update_fixture(&base, dir.path(), "record");
        let mut competing = fixture.previous_record.clone();
        competing.user_note = Some("benign competing update fixture".to_string());

        let error = fixture.store.replace_record(&competing).unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("metadata-update journal"), "{detail}");
        assert!(detail.contains("destination already exists"), "{detail}");
        assert!(fixture.journal_path.exists());
        assert_eq!(
            fs::read_to_string(&fixture.record_path).unwrap(),
            fixture.previous_raw
        );
        assert_eq!(
            fs::read_to_string(&fixture.auth_path).unwrap(),
            fixture.previous_auth
        );
    }

    #[test]
    fn quarantine_metadata_update_recovery_rejects_immutable_evidence_change() {
        let dir = tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = dir.path().join("q");
        let payload = base.join("record.avoraxq");
        fs::create_dir_all(&base).unwrap();
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);
        store.write_record(&record).unwrap();
        let previous_raw = fs::read_to_string(base.join("record.json")).unwrap();
        let previous_auth = fs::read_to_string(base.join("record.json.auth")).unwrap();
        let mut changed = record;
        changed.engine = "benign but changed evidence".to_string();

        let error = store.replace_record(&changed).unwrap_err();

        assert!(error
            .to_string()
            .contains("attempted to change immutable threat evidence"));
        assert_eq!(
            fs::read_to_string(base.join("record.json")).unwrap(),
            previous_raw
        );
        assert_eq!(
            fs::read_to_string(base.join("record.json.auth")).unwrap(),
            previous_auth
        );
        assert!(!base.join("record.update.pending").exists());
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
    fn quarantine_permissions_use_shared_verified_platform_controls() {
        let source = crate::normalized_test_source(include_str!("quarantine_store.rs"));
        let base_start = source
            .find("fn harden_quarantine_base_permissions")
            .unwrap();
        let base_end = source.find("fn copy_then_remove_verified").unwrap();
        let base_source = &source[base_start..base_end];
        let payload_start = source
            .find("fn harden_quarantine_payload_permissions")
            .unwrap();
        let tests_start = source.find("#[cfg(test)]\nmod tests").unwrap();
        let payload_source = &source[payload_start..tests_start];

        assert!(base_source.contains("harden_unix_private_directory(path)"));
        assert!(base_source.contains("harden_windows_private_directory(path)"));
        assert!(payload_source.contains("harden_unix_private_file(file, path)"));
        assert!(payload_source.contains("harden_windows_quarantine_file(file, path)"));
        assert!(payload_source.contains("security == ExclusiveCopySecurity::Quarantine"));
        let production_source = &source[..tests_start];
        assert!(production_source.contains("ExclusiveCopySecurity::Restore"));
        assert!(production_source.contains("ExclusiveCopySecurity::Quarantine"));
        assert!(!production_source.contains("current_windows_account"));
        assert!(!production_source.contains("std::env::var(\"USERNAME\")"));
        assert!(!production_source.contains("icacls.exe"));
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

        let key = store
            .metadata_auth_key(true)
            .unwrap()
            .expect("metadata authentication key should be created");

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
        let auth = fs::read_to_string(base.join("record.json.auth")).unwrap();
        let auth = auth.trim();
        assert!(auth.starts_with(QUARANTINE_AUTH_HMAC_PREFIX));
        assert_eq!(auth.len(), QUARANTINE_AUTH_HMAC_PREFIX.len() + 64);
        assert!(!auth.starts_with("sha256:"));
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

        let err = store
            .verified_record_auth_scheme(&record_path, "{}")
            .unwrap_err();

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
    fn unsigned_legacy_record_without_auth_sidecar_is_rejected() {
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
        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("quarantine metadata authentication sidecar is required"));
        assert!(error
            .to_string()
            .contains("unsigned legacy metadata is disabled"));
    }

    #[test]
    fn legacy_authenticated_record_migrates_to_hmac_after_validation() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("legacy.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let record = fixture_record("legacy", dir.path().join("restore.exe"), payload);
        let raw = serde_json::to_string_pretty(&record).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let key = store.metadata_auth_key(true).unwrap().unwrap();
        let legacy_tag = legacy_record_auth_tag(&key, &raw);
        fs::write(base.join("legacy.json"), &raw).unwrap();
        fs::write(base.join("legacy.json.auth"), format!("{legacy_tag}\n")).unwrap();

        let records = store.list().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].quarantine_id, "legacy");
        let migrated = fs::read_to_string(base.join("legacy.json.auth")).unwrap();
        assert!(migrated.trim().starts_with(QUARANTINE_AUTH_HMAC_PREFIX));
        assert!(!migrated.trim().starts_with("sha256:"));
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn legacy_guard_authenticated_record_migrates_to_shared_hmac() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("guard-record.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let mut record = fixture_record("guard-record", dir.path().join("restore.exe"), payload);
        record.source = "guard_service".to_string();
        record.action_taken = "process_stop_requested_and_file_quarantined".to_string();
        record.process_started = true;
        record.process_id = Some(4242);
        let raw = serde_json::to_string_pretty(&record).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let key = store.metadata_auth_key(true).unwrap().unwrap();
        let legacy_tag = guard_legacy_record_auth_tag(&key, &raw);
        fs::write(base.join("guard-record.json"), &raw).unwrap();
        fs::write(
            base.join("guard-record.json.auth"),
            format!("{legacy_tag}\n"),
        )
        .unwrap();

        let records = store.list().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source, "guard_service");
        assert_eq!(records[0].process_id, Some(4242));
        let migrated = fs::read_to_string(base.join("guard-record.json.auth")).unwrap();
        assert!(migrated.trim().starts_with(QUARANTINE_AUTH_HMAC_PREFIX));
        assert!(!migrated.trim().starts_with("sha256:"));
    }

    #[test]
    fn legacy_authenticated_record_with_unknown_field_is_not_migrated() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("legacy.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let record = fixture_record("legacy", dir.path().join("restore.exe"), payload);
        let mut value = serde_json::to_value(&record).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        let raw = serde_json::to_string_pretty(&value).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        let key = store.metadata_auth_key(true).unwrap().unwrap();
        let legacy_tag = legacy_record_auth_tag(&key, &raw);
        fs::write(base.join("legacy.json"), &raw).unwrap();
        fs::write(base.join("legacy.json.auth"), format!("{legacy_tag}\n")).unwrap();

        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("unable to parse quarantine metadata record"));
        assert!(format!("{error:#}").contains("unknown field"));
        assert_eq!(
            fs::read_to_string(base.join("legacy.json.auth"))
                .unwrap()
                .trim(),
            legacy_tag
        );
    }

    #[test]
    fn hmac_authenticated_record_with_unknown_field_is_rejected() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("record.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);
        let mut value = serde_json::to_value(&record).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        let raw = serde_json::to_string_pretty(&value).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        write_authenticated_raw(&store, &base.join("record.json"), &raw);

        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("unable to parse quarantine metadata record"));
        assert!(format!("{error:#}").contains("unknown field"));
        assert!(fs::read_to_string(base.join("record.json.auth"))
            .unwrap()
            .trim()
            .starts_with(QUARANTINE_AUTH_HMAC_PREFIX));
    }

    #[test]
    fn authenticated_record_filename_must_match_quarantine_id() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let payload = base.join("record.avoraxq");
        fs::write(&payload, b"quarantined").unwrap();
        let record = fixture_record("record", dir.path().join("restore.exe"), payload);
        let raw = serde_json::to_string_pretty(&record).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        write_authenticated_raw(&store, &base.join("other.json"), &raw);

        let error = store.list().unwrap_err();

        assert!(error
            .to_string()
            .contains("quarantine metadata filename does not match record id"));
        assert!(format!("{error:#}").contains("does not match record id record"));
    }

    #[test]
    fn generated_metadata_auth_key_is_32_random_bytes_encoded_as_hex() {
        let dir = tempdir().unwrap();
        let store = QuarantineStore::with_base(dir.path().join("q"));

        let key = store.metadata_auth_key(true).unwrap().unwrap();

        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(key, key.to_ascii_lowercase());
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
        let store = QuarantineStore::with_base(base.clone());
        write_authenticated_fixture(&store, &base.join("bad.json"), &record);
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

        assert!(list_source.contains("self.verified_record_auth_scheme(&path, &raw)?"));
        assert!(!list_source
            .contains("if !self.record_auth_valid(&path, &raw)? {\n                    continue;"));
    }

    #[test]
    fn legacy_quarantine_record_with_old_extension_is_rejected() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        store.metadata_auth_key(true).unwrap();
        let legacy_extension = ["pa", "susq"].concat();
        let legacy_file = base.join(format!("legacy.{legacy_extension}"));
        fs::write(&legacy_file, b"quarantined").unwrap();
        let mut record = fixture_record("legacy", dir.path().join("restore.exe"), legacy_file);
        record.sha256 = sha256_for_file(Path::new(&record.quarantine_path)).unwrap();
        write_authenticated_fixture(&store, &base.join("legacy.json"), &record);
        let error = store.list().unwrap_err();

        let error_chain = format!("{error:#}");
        assert!(error_chain
            .contains("refusing to change permissions on an unrecognized quarantine directory"));
        assert!(error_chain.contains(&format!("unrecognized entry legacy.{legacy_extension}")));
    }

    #[test]
    fn legacy_zentor_quarantine_record_is_rejected() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("q");
        fs::create_dir_all(&base).unwrap();
        let store = QuarantineStore::with_base(base.clone());
        store.metadata_auth_key(true).unwrap();
        let legacy_file = base.join("legacy.zentorq");
        fs::write(&legacy_file, b"quarantined").unwrap();
        let mut record =
            fixture_record("legacy-zentor", dir.path().join("restore.exe"), legacy_file);
        record.sha256 = sha256_for_file(Path::new(&record.quarantine_path)).unwrap();
        write_authenticated_fixture(&store, &base.join("legacy-zentor.json"), &record);
        let error = store.list().unwrap_err();

        let error_chain = format!("{error:#}");
        assert!(error_chain
            .contains("refusing to change permissions on an unrecognized quarantine directory"));
        assert!(error_chain.contains("unrecognized entry legacy.zentorq"));
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

    fn write_authenticated_raw(store: &QuarantineStore, path: &Path, raw: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, raw).unwrap();
        let tag = store.record_auth_tag(raw, true).unwrap().unwrap();
        fs::write(path.with_extension("json.auth"), format!("{tag}\n")).unwrap();
    }

    fn write_authenticated_fixture(
        store: &QuarantineStore,
        path: &Path,
        record: &QuarantineRecord,
    ) {
        let raw = serde_json::to_string_pretty(record).unwrap();
        write_authenticated_raw(store, path, &raw);
    }

    fn write_authenticated_finalization_journal_raw(store: &QuarantineStore, id: &str, raw: &str) {
        let key = store.metadata_auth_key(false).unwrap().unwrap();
        let tag = hmac_finalization_journal_auth_tag(&key, raw).unwrap();
        fs::write(store.finalization_journal_path(id).unwrap(), raw).unwrap();
        fs::write(
            store.finalization_journal_auth_path(id).unwrap(),
            format!("{tag}\n"),
        )
        .unwrap();
    }

    struct MetadataUpdateFixture {
        store: QuarantineStore,
        previous_record: QuarantineRecord,
        previous_raw: String,
        previous_auth: String,
        next_raw: String,
        next_auth: String,
        record_path: PathBuf,
        auth_path: PathBuf,
        journal_path: PathBuf,
    }

    struct LockedMetadataUpdateFixture {
        fixture: MetadataUpdateFixture,
        journal_lock: fs::File,
    }

    fn stage_metadata_update_fixture(base: &Path, root: &Path, id: &str) -> MetadataUpdateFixture {
        let LockedMetadataUpdateFixture {
            fixture,
            journal_lock,
        } = stage_metadata_update_fixture_with_lock(base, root, id);
        drop(journal_lock);
        fixture
    }

    fn stage_metadata_update_fixture_with_lock(
        base: &Path,
        root: &Path,
        id: &str,
    ) -> LockedMetadataUpdateFixture {
        fs::create_dir_all(base).unwrap();
        let payload = base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        fs::write(&payload, b"quarantined").unwrap();
        let store = QuarantineStore::with_base(base.to_path_buf());
        let previous_record = fixture_record(id, root.join("restore.exe"), payload);
        store.write_record(&previous_record).unwrap();
        let record_path = base.join(format!("{id}.json"));
        let auth_path = base.join(format!("{id}.json.auth"));
        let journal_path = base.join(format!("{id}.update.pending"));
        let previous_raw = fs::read_to_string(&record_path).unwrap();
        let previous_auth = fs::read_to_string(&auth_path).unwrap();
        let mut next_record = previous_record.clone();
        next_record.user_note = Some("benign metadata update recovery fixture".to_string());
        let next_raw = serde_json::to_string_pretty(&next_record).unwrap();
        let key = store.metadata_auth_key(false).unwrap().unwrap();
        let next_auth = format!("{}\n", hmac_record_auth_tag(&key, &next_raw).unwrap());
        let journal_lock = store
            .write_metadata_update_journal(QuarantineMetadataUpdateJournalBody {
                format: QUARANTINE_METADATA_UPDATE_JOURNAL_FORMAT.to_string(),
                quarantine_id: id.to_string(),
                previous_record_raw: previous_raw.clone(),
                previous_record_auth: previous_auth.clone(),
                next_record_raw: next_raw.clone(),
                next_record_auth: next_auth.clone(),
            })
            .unwrap();
        LockedMetadataUpdateFixture {
            fixture: MetadataUpdateFixture {
                store,
                previous_record,
                previous_raw,
                previous_auth,
                next_raw,
                next_auth,
                record_path,
                auth_path,
                journal_path,
            },
            journal_lock,
        }
    }

    const ACTION_FIXTURE_BYTES: &[u8] = b"benign quarantine action recovery fixture";

    struct ActionFixture {
        store: QuarantineStore,
        previous_record: QuarantineRecord,
        next_record: QuarantineRecord,
        body: QuarantineActionJournalBody,
        record_path: PathBuf,
        auth_path: PathBuf,
        journal_path: PathBuf,
        payload_path: PathBuf,
        staging_path: Option<PathBuf>,
        destination_path: PathBuf,
    }

    struct LockedActionFixture {
        fixture: ActionFixture,
        journal_lock: fs::File,
    }

    fn stage_action_fixture(
        base: &Path,
        root: &Path,
        id: &str,
        action: QuarantineLifecycleAction,
        phase: QuarantineActionPhase,
    ) -> ActionFixture {
        let LockedActionFixture {
            fixture,
            journal_lock,
        } = stage_action_fixture_with_lock(base, root, id, action, phase);
        drop(journal_lock);
        fixture
    }

    fn stage_action_fixture_with_lock(
        base: &Path,
        root: &Path,
        id: &str,
        action: QuarantineLifecycleAction,
        phase: QuarantineActionPhase,
    ) -> LockedActionFixture {
        fs::create_dir_all(base).unwrap();
        let payload_path = base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        fs::write(&payload_path, ACTION_FIXTURE_BYTES).unwrap();
        let destination_path = root.join(format!("{id}-restored.exe"));
        let store = QuarantineStore::with_base(base.to_path_buf());
        let mut previous_record =
            fixture_record(id, destination_path.clone(), payload_path.clone());
        previous_record.file_size = ACTION_FIXTURE_BYTES.len() as u64;
        previous_record.sha256 = sha256_for_file(&payload_path).unwrap();
        store.write_record(&previous_record).unwrap();
        let mut next_record = previous_record.clone();
        match action {
            QuarantineLifecycleAction::Restore => {
                next_record.status = QuarantineStatus::Restored;
                next_record.action_taken = "restored".to_string();
            }
            QuarantineLifecycleAction::Delete => {
                next_record.status = QuarantineStatus::Deleted;
                next_record.action_taken = "deleted".to_string();
            }
        }
        let staging_path = match action {
            QuarantineLifecycleAction::Restore => {
                Some(new_restore_staging_path(&destination_path).unwrap())
            }
            QuarantineLifecycleAction::Delete => None,
        };
        let mut body = store
            .prepare_action_journal_body(
                &previous_record,
                &next_record,
                action,
                staging_path.as_ref().map(|path| path.display().to_string()),
            )
            .unwrap();
        let (prepared_lock, prepared_raw) = store.write_action_journal(body.clone()).unwrap();
        let journal_lock = match phase {
            QuarantineActionPhase::Prepared => prepared_lock,
            QuarantineActionPhase::RestoreReserved | QuarantineActionPhase::RestoreStaged => {
                assert_eq!(action, QuarantineLifecycleAction::Restore);
                let staging = staging_path.as_ref().unwrap();
                let (mut staged_file, identity) =
                    store.reserve_restore_staging_file(staging).unwrap();
                body.phase = QuarantineActionPhase::RestoreReserved;
                body.restore_identity = Some(identity);
                drop(prepared_lock);
                let (reserved_lock, reserved_raw) = store
                    .replace_action_journal(
                        &prepared_raw,
                        QuarantineActionPhase::Prepared,
                        body.clone(),
                    )
                    .unwrap();
                if phase == QuarantineActionPhase::RestoreReserved {
                    drop(staged_file);
                    reserved_lock
                } else {
                    store
                        .copy_payload_to_reserved_restore(
                            &previous_record,
                            &payload_path,
                            staging,
                            &mut staged_file,
                            body.restore_identity.as_ref().unwrap(),
                        )
                        .unwrap();
                    body.phase = QuarantineActionPhase::RestoreStaged;
                    drop(reserved_lock);
                    let staged_lock = store
                        .replace_action_journal(
                            &reserved_raw,
                            QuarantineActionPhase::RestoreReserved,
                            body.clone(),
                        )
                        .unwrap()
                        .0;
                    drop(staged_file);
                    staged_lock
                }
            }
        };
        LockedActionFixture {
            fixture: ActionFixture {
                store,
                previous_record,
                next_record,
                body,
                record_path: base.join(format!("{id}.json")),
                auth_path: base.join(format!("{id}.json.auth")),
                journal_path: base.join(format!("{id}.action.pending")),
                payload_path,
                staging_path,
                destination_path,
            },
            journal_lock,
        }
    }

    fn fixture_scan_result(path: &Path, status: ScanStatus) -> ScanResult {
        ScanResult {
            status,
            scanned_path: path.display().to_string(),
            sha256: sha256_for_file(path).unwrap_or_else(|_| format!("sha256:{}", "f".repeat(64))),
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

    fn recovery_fixture_record(
        store: &QuarantineStore,
        root: &Path,
        id: &str,
        bytes: &[u8],
    ) -> (QuarantineRecord, PathBuf, PathBuf) {
        let original = root.join(format!("{id}-original.exe"));
        let payload = store.base.join(format!("{id}.{QUARANTINE_EXTENSION}"));
        fs::write(&original, bytes).unwrap();
        let mut record = fixture_record(id, original.clone(), payload.clone());
        record.file_size = bytes.len() as u64;
        record.sha256 = sha256_for_file(&original).unwrap();
        (record, original, payload)
    }
}
