use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

use crate::path_safety::{
    create_dir_all_checked, ensure_existing_path_chain_not_link, ensure_not_link_or_reparse,
    remove_dir_all_checked,
};

const RECOVERY_DIRECTORY_NAME: &str = ".avorax-update-recovery";
const RECOVERY_LOCK_NAME: &str = ".activation.lock";
const RECOVERY_KEY_NAME: &str = ".activation_auth_key";
const RECOVERY_SCHEMA_VERSION: u32 = 1;
const RECOVERY_OPERATION_ID_BYTES: usize = 16;
const RECOVERY_OPERATION_ID_HEX_LEN: usize = RECOVERY_OPERATION_ID_BYTES * 2;
const RECOVERY_KEY_BYTES: usize = 32;
const MAX_RECOVERY_FILE_BYTES: u64 = 16 * 1024;
const MAX_RECOVERY_KEY_FILE_BYTES: u64 = 16 * 1024;
const MAX_RECOVERY_DIRECTORY_ENTRIES: usize = 128;
const MAX_RECOVERY_PARENT_ENTRIES: usize = 512;
const MAX_RECOVERY_REPORT_ERROR_CHARS: usize = 4096;
const RECOVERY_HMAC_DOMAIN: &[u8] = b"avorax-update-directory-activation-recovery-v1\0";
const BOUNDARY_HASH_DOMAIN: &[u8] = b"avorax-update-directory-activation-boundary-v1\0";
const ALLOWED_DESTINATIONS: &[&str] = &[
    "engine",
    "engine/signatures",
    "engine/rules",
    "engine/ml",
    "engine/trust",
];

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ActivationRecoverySummary {
    pub recovered_backups: usize,
    pub completed_activations: usize,
    pub aborted_pre_activation: usize,
    pub removed_journals: usize,
}

impl ActivationRecoverySummary {
    fn add_assign(&mut self, other: &Self) {
        self.recovered_backups += other.recovered_backups;
        self.completed_activations += other.completed_activations;
        self.aborted_pre_activation += other.aborted_pre_activation;
        self.removed_journals += other.removed_journals;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRecoveryRecord {
    schema_version: u32,
    operation_id: String,
    boundary_sha256: String,
    destination_relative: String,
    had_destination: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedActivationRecoveryJournal {
    record: ActivationRecoveryRecord,
    auth_hmac_sha256: String,
}

#[derive(Debug)]
struct DerivedActivationPaths {
    destination: PathBuf,
    staging: PathBuf,
    backup: PathBuf,
}

struct ActivationRecoveryLock {
    _file: File,
}

pub struct DirectoryActivationTransaction {
    boundary: PathBuf,
    recovery_root: PathBuf,
    journal_path: PathBuf,
    record: ActivationRecoveryRecord,
    paths: DerivedActivationPaths,
    _lock: ActivationRecoveryLock,
}

impl DirectoryActivationTransaction {
    pub fn staging_path(&self) -> &Path {
        &self.paths.staging
    }

    #[cfg(test)]
    pub(crate) fn destination_path(&self) -> &Path {
        &self.paths.destination
    }

    #[cfg(test)]
    pub(crate) fn backup_path(&self) -> &Path {
        &self.paths.backup
    }

    pub fn commit(self) -> Result<()> {
        self.commit_with_hooks(|| Ok(()), || Ok(()))
    }

    pub(crate) fn commit_with_hooks<BeforeBackupMove, BeforeActivation>(
        mut self,
        before_backup_move: BeforeBackupMove,
        before_activation: BeforeActivation,
    ) -> Result<()>
    where
        BeforeBackupMove: FnOnce() -> Result<()>,
        BeforeActivation: FnOnce() -> Result<()>,
    {
        ensure_directory_state(&self.paths.staging, "update activation staging")?;
        ensure_path_chain(
            &self.paths.destination,
            &self.boundary,
            "update activation destination",
        )?;
        ensure_path_chain(
            &self.paths.backup,
            &self.boundary,
            "update activation backup",
        )?;
        let had_destination =
            path_is_directory_or_absent(&self.paths.destination, "update activation destination")?;
        ensure_path_absent(&self.paths.backup, "update activation backup")?;
        self.record.had_destination = had_destination;
        write_authenticated_journal(&self.recovery_root, &self.journal_path, &self.record)?;

        let activation_result = (|| -> Result<()> {
            ensure_expected_pre_activation_state(&self.paths, had_destination)?;
            if had_destination {
                before_backup_move()?;
                avorax_platform_security::rename_directory_no_replace(
                    &self.paths.destination,
                    &self.paths.backup,
                    "update activation destination backup move",
                )
                .with_context(|| {
                    format!(
                        "failed to move update activation destination {} to backup {}",
                        self.paths.destination.display(),
                        self.paths.backup.display()
                    )
                })?;
            }

            before_activation()?;
            avorax_platform_security::rename_directory_no_replace(
                &self.paths.staging,
                &self.paths.destination,
                "update activation staged directory move",
            )
            .with_context(|| {
                format!(
                    "failed to activate staged update directory {} as {}",
                    self.paths.staging.display(),
                    self.paths.destination.display()
                )
            })
        })();

        let reconciliation = reconcile_record_locked(
            &self.boundary,
            &self.recovery_root,
            &self.journal_path,
            &self.record,
        );
        match (activation_result, reconciliation) {
            (Ok(()), Ok(_)) => Ok(()),
            (Ok(()), Err(recovery_error)) => Err(recovery_error)
                .context("update activation completed but recovery evidence cleanup failed"),
            (Err(error), Ok(_)) => Err(error).context(
                "update activation failed; authenticated recovery reconciled the non-ambiguous state",
            ),
            (Err(error), Err(recovery_error)) => Err(error).context(format!(
                "update activation failed and authenticated recovery preserved ambiguous evidence: {recovery_error:#}"
            )),
        }
    }
}

pub fn begin_directory_activation(
    boundary: &Path,
    destination: &Path,
) -> Result<DirectoryActivationTransaction> {
    let relative = allowed_destination_relative(boundary, destination)?;
    let boundary = canonical_recovery_boundary(boundary)?;
    let recovery_root = ensure_recovery_root(&boundary)?;
    let recovery_lock = acquire_recovery_lock(&boundary, &recovery_root)?;
    recover_pending_locked(&boundary, &recovery_root)?;

    for _ in 0..16 {
        let operation_id = generate_operation_id()?;
        let record = ActivationRecoveryRecord {
            schema_version: RECOVERY_SCHEMA_VERSION,
            operation_id: operation_id.clone(),
            boundary_sha256: boundary_sha256(&boundary),
            destination_relative: relative.clone(),
            had_destination: false,
        };
        let paths = derive_activation_paths(&boundary, &record)?;
        let journal_path = recovery_root.join(format!("{operation_id}.json"));
        if path_is_absent(&journal_path)?
            && path_is_absent(&paths.staging)?
            && path_is_absent(&paths.backup)?
        {
            return Ok(DirectoryActivationTransaction {
                boundary,
                recovery_root,
                journal_path,
                record,
                paths,
                _lock: recovery_lock,
            });
        }
    }
    anyhow::bail!(
        "could not allocate an authenticated update activation recovery operation for {}",
        destination.display()
    )
}

pub fn recover_pending_directory_activations(boundary: &Path) -> Result<ActivationRecoverySummary> {
    let boundary = canonical_recovery_boundary(boundary)?;
    let recovery_root = ensure_recovery_root(&boundary)?;
    let _lock = acquire_recovery_lock(&boundary, &recovery_root)?;
    recover_pending_locked(&boundary, &recovery_root)
}

pub fn recover_pending_directory_activations_with_report(
    boundary: &Path,
    trigger: &str,
) -> Result<ActivationRecoverySummary> {
    anyhow::ensure!(
        matches!(
            trigger,
            "apply-preflight" | "rollback-preflight" | "service-start" | "manual-cli"
        ),
        "unsupported update activation recovery trigger"
    );
    let boundary = canonical_recovery_boundary(boundary)?;
    let recovery = recover_pending_directory_activations(&boundary);
    let error = recovery
        .as_ref()
        .err()
        .map(|value| bounded_error_text(&format!("{value:#}")));
    let report = serde_json::json!({
        "schema_version": 1,
        "ok": recovery.is_ok(),
        "trigger": trigger,
        "install_dir": boundary,
        "summary": recovery.as_ref().ok(),
        "error": error,
        "timestamp_utc": time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?,
    });
    let report_result = crate::logging::write_update_log(
        "activation_recovery_report.json",
        &serde_json::to_string_pretty(&report)?,
    );
    match (recovery, report_result) {
        (Ok(summary), Ok(_)) => Ok(summary),
        (Ok(_), Err(report_error)) => Err(report_error)
            .context("update activation recovery completed but its report could not be written"),
        (Err(recovery_error), Ok(_)) => Err(recovery_error),
        (Err(recovery_error), Err(report_error)) => Err(recovery_error).context(format!(
            "update activation recovery failed and its report could not be written: {report_error:#}"
        )),
    }
}

fn bounded_error_text(value: &str) -> String {
    if value.chars().count() <= MAX_RECOVERY_REPORT_ERROR_CHARS {
        return value.to_string();
    }
    value
        .chars()
        .take(MAX_RECOVERY_REPORT_ERROR_CHARS)
        .collect()
}

fn recover_pending_locked(
    boundary: &Path,
    recovery_root: &Path,
) -> Result<ActivationRecoverySummary> {
    let journal_paths = enumerate_recovery_journals(recovery_root)?;
    let mut summary = ActivationRecoverySummary::default();
    for journal_path in journal_paths {
        let record = read_authenticated_journal(recovery_root, &journal_path)?;
        let item = reconcile_record_locked(boundary, recovery_root, &journal_path, &record)?;
        summary.add_assign(&item);
    }
    ensure_no_orphan_activation_siblings(boundary)?;
    Ok(summary)
}

fn reconcile_record_locked(
    boundary: &Path,
    recovery_root: &Path,
    journal_path: &Path,
    record: &ActivationRecoveryRecord,
) -> Result<ActivationRecoverySummary> {
    validate_record(boundary, recovery_root, journal_path, record)?;
    let authenticated = read_authenticated_journal(recovery_root, journal_path)?;
    anyhow::ensure!(
        authenticated == *record,
        "update activation recovery journal changed after authentication"
    );
    let paths = derive_activation_paths(boundary, record)?;
    let destination_exists =
        path_is_directory_or_absent(&paths.destination, "recovery destination")?;
    let staging_exists = path_is_directory_or_absent(&paths.staging, "recovery staging")?;
    let backup_exists = path_is_directory_or_absent(&paths.backup, "recovery backup")?;
    let mut summary = ActivationRecoverySummary::default();

    match (
        record.had_destination,
        destination_exists,
        staging_exists,
        backup_exists,
    ) {
        (true, true, true, false) => {
            cleanup_recovery_directory(&paths.staging, "aborted update activation staging")?;
            summary.aborted_pre_activation = 1;
        }
        (true, false, true, true) => {
            avorax_platform_security::rename_directory_no_replace(
                &paths.backup,
                &paths.destination,
                "authenticated update activation backup recovery",
            )
            .with_context(|| {
                format!(
                    "failed to restore authenticated update activation backup {} as {}",
                    paths.backup.display(),
                    paths.destination.display()
                )
            })?;
            cleanup_recovery_directory(&paths.staging, "recovered update activation staging")?;
            summary.recovered_backups = 1;
        }
        (true, true, false, true) => {
            cleanup_recovery_directory(&paths.backup, "completed update activation backup")?;
            summary.completed_activations = 1;
        }
        (true, true, false, false) => {
            summary.completed_activations = 1;
        }
        (false, false, true, false) => {
            cleanup_recovery_directory(&paths.staging, "aborted new update activation staging")?;
            summary.aborted_pre_activation = 1;
        }
        (false, true, false, false) => {
            summary.completed_activations = 1;
        }
        state => {
            anyhow::bail!(
                "ambiguous authenticated update activation recovery state for {}: had_destination={}, destination={}, staging={}, backup={}; preserving all evidence",
                record.destination_relative,
                state.0,
                state.1,
                state.2,
                state.3
            );
        }
    }

    ensure_reconciled_final_state(&paths, record.had_destination)?;
    remove_private_regular_file(journal_path, "update activation recovery journal")?;
    summary.removed_journals = 1;
    Ok(summary)
}

fn ensure_expected_pre_activation_state(
    paths: &DerivedActivationPaths,
    had_destination: bool,
) -> Result<()> {
    let destination_exists =
        path_is_directory_or_absent(&paths.destination, "update activation destination")?;
    anyhow::ensure!(
        destination_exists == had_destination,
        "update activation destination state changed after authenticated journal creation"
    );
    ensure_directory_state(&paths.staging, "update activation staging")?;
    ensure_path_absent(&paths.backup, "update activation backup")
}

fn ensure_reconciled_final_state(
    paths: &DerivedActivationPaths,
    had_destination: bool,
) -> Result<()> {
    let destination_exists =
        path_is_directory_or_absent(&paths.destination, "reconciled update destination")?;
    let staging_exists = path_is_directory_or_absent(&paths.staging, "reconciled update staging")?;
    let backup_exists = path_is_directory_or_absent(&paths.backup, "reconciled update backup")?;
    anyhow::ensure!(
        destination_exists || !had_destination,
        "authenticated update activation recovery did not restore the required destination"
    );
    anyhow::ensure!(
        !staging_exists && !backup_exists,
        "authenticated update activation recovery left staging or backup residue"
    );
    Ok(())
}

fn validate_record(
    boundary: &Path,
    recovery_root: &Path,
    journal_path: &Path,
    record: &ActivationRecoveryRecord,
) -> Result<()> {
    anyhow::ensure!(
        record.schema_version == RECOVERY_SCHEMA_VERSION,
        "unsupported update activation recovery schema {}",
        record.schema_version
    );
    validate_operation_id(&record.operation_id)?;
    anyhow::ensure!(
        record.boundary_sha256 == boundary_sha256(boundary),
        "update activation recovery boundary fingerprint mismatch"
    );
    validate_allowed_relative_text(&record.destination_relative)?;
    let expected_journal = recovery_root.join(format!("{}.json", record.operation_id));
    anyhow::ensure!(
        journal_path == expected_journal,
        "update activation recovery journal filename does not match its authenticated operation id"
    );
    Ok(())
}

fn write_authenticated_journal(
    recovery_root: &Path,
    journal_path: &Path,
    record: &ActivationRecoveryRecord,
) -> Result<()> {
    validate_record(
        &canonical_recovery_boundary(
            recovery_root
                .parent()
                .context("update activation recovery root has no boundary")?,
        )?,
        recovery_root,
        journal_path,
        record,
    )?;
    let key = recovery_auth_key(recovery_root, true)?
        .context("update activation recovery authentication key was not created")?;
    let record_bytes = serde_json::to_vec(record)?;
    let auth_hmac_sha256 = recovery_hmac(&key, &record_bytes)?;
    let journal = AuthenticatedActivationRecoveryJournal {
        record: record.clone(),
        auth_hmac_sha256,
    };
    let bytes = serde_json::to_vec_pretty(&journal)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_RECOVERY_FILE_BYTES,
        "update activation recovery journal exceeds its size limit"
    );
    write_new_private_file(journal_path, &bytes, "update activation recovery journal")?;
    let persisted = read_authenticated_journal(recovery_root, journal_path)?;
    anyhow::ensure!(
        persisted == *record,
        "update activation recovery journal verification failed after write"
    );
    Ok(())
}

fn read_authenticated_journal(
    recovery_root: &Path,
    journal_path: &Path,
) -> Result<ActivationRecoveryRecord> {
    let raw = read_bounded_private_file(
        journal_path,
        MAX_RECOVERY_FILE_BYTES,
        "update activation recovery journal",
    )?;
    let journal: AuthenticatedActivationRecoveryJournal = serde_json::from_slice(&raw)
        .context("failed to parse authenticated update activation recovery journal")?;
    let key = recovery_auth_key(recovery_root, false)?
        .context("update activation recovery authentication key is unavailable")?;
    let record_bytes = serde_json::to_vec(&journal.record)?;
    verify_recovery_hmac(&key, &record_bytes, &journal.auth_hmac_sha256)?;
    Ok(journal.record)
}

fn recovery_hmac(key: &[u8], record_bytes: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid update activation recovery authentication key"))?;
    mac.update(RECOVERY_HMAC_DOMAIN);
    mac.update(record_bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_recovery_hmac(key: &[u8], record_bytes: &[u8], actual: &str) -> Result<()> {
    anyhow::ensure!(
        actual.len() == 64
            && actual
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "update activation recovery journal authentication tag is malformed"
    );
    let actual = hex::decode(actual)
        .context("update activation recovery journal authentication tag is invalid hex")?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid update activation recovery authentication key"))?;
    mac.update(RECOVERY_HMAC_DOMAIN);
    mac.update(record_bytes);
    mac.verify_slice(&actual)
        .map_err(|_| anyhow::anyhow!("update activation recovery journal authentication failed"))
}

fn recovery_auth_key(recovery_root: &Path, create: bool) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let path = recovery_root.join(RECOVERY_KEY_NAME);
    if !path_is_absent(&path)? {
        let raw = read_bounded_private_file(
            &path,
            MAX_RECOVERY_KEY_FILE_BYTES,
            "update activation recovery authentication key",
        )?;
        return decode_recovery_auth_key(&raw).map(Some);
    }
    if !create {
        return Ok(None);
    }
    let mut key = Zeroizing::new(vec![0_u8; RECOVERY_KEY_BYTES]);
    getrandom::getrandom(&mut key).map_err(|error| {
        anyhow::anyhow!("failed to generate update activation recovery authentication key: {error}")
    })?;
    let encoded = encode_recovery_auth_key(&key)?;
    write_new_private_file(
        &path,
        encoded.as_bytes(),
        "update activation recovery authentication key",
    )?;
    let persisted = read_bounded_private_file(
        &path,
        MAX_RECOVERY_KEY_FILE_BYTES,
        "update activation recovery authentication key",
    )?;
    let decoded = decode_recovery_auth_key(&persisted)?;
    anyhow::ensure!(
        decoded.as_slice() == key.as_slice(),
        "update activation recovery authentication key verification failed after write"
    );
    Ok(Some(key))
}

fn encode_recovery_auth_key(key: &[u8]) -> Result<String> {
    anyhow::ensure!(
        key.len() == RECOVERY_KEY_BYTES,
        "update activation recovery authentication key has an invalid length"
    );
    #[cfg(windows)]
    {
        let protected = avorax_platform_security::protect_windows_machine_secret(key)?;
        Ok(format!("dpapi-machine:{}\n", hex::encode(protected)))
    }
    #[cfg(unix)]
    {
        Ok(format!("unix-private:{}\n", hex::encode(key)))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = key;
        anyhow::bail!("secure update activation recovery keys are unsupported on this platform")
    }
}

fn decode_recovery_auth_key(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(raw)
        .context("update activation recovery authentication key is not UTF-8")?
        .trim();
    #[cfg(windows)]
    let key = {
        let protected = text.strip_prefix("dpapi-machine:").context(
            "plaintext update activation recovery authentication keys are not accepted on Windows",
        )?;
        let protected = hex::decode(protected)
            .context("protected update activation recovery authentication key is invalid hex")?;
        Zeroizing::new(avorax_platform_security::unprotect_windows_machine_secret(
            &protected,
        )?)
    };
    #[cfg(unix)]
    let key = {
        let encoded = text
            .strip_prefix("unix-private:")
            .context("update activation recovery authentication key has an invalid format")?;
        Zeroizing::new(
            hex::decode(encoded)
                .context("update activation recovery authentication key is invalid hex")?,
        )
    };
    #[cfg(not(any(unix, windows)))]
    let key: Zeroizing<Vec<u8>> = {
        let _ = text;
        anyhow::bail!("secure update activation recovery keys are unsupported on this platform")
    };
    anyhow::ensure!(
        key.len() == RECOVERY_KEY_BYTES,
        "update activation recovery authentication key has an invalid length"
    );
    Ok(key)
}

fn ensure_recovery_root(boundary: &Path) -> Result<PathBuf> {
    let root = boundary.join(RECOVERY_DIRECTORY_NAME);
    ensure_path_chain(&root, boundary, "update activation recovery directory")?;
    create_dir_all_checked(&root, "update activation recovery directory")?;
    ensure_private_directory(&root)?;
    ensure_path_chain(&root, boundary, "update activation recovery directory")?;
    Ok(root)
}

fn acquire_recovery_lock(boundary: &Path, recovery_root: &Path) -> Result<ActivationRecoveryLock> {
    let path = recovery_root.join(RECOVERY_LOCK_NAME);
    ensure_path_chain(&path, boundary, "update activation recovery lock")?;
    ensure_not_link_or_reparse(&path, "update activation recovery lock")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| {
            format!(
                "failed to open update activation recovery lock {}",
                path.display()
            )
        })?;
    ensure_not_link_or_reparse(&path, "update activation recovery lock")?;
    avorax_platform_security::ensure_path_matches_open_file(
        &file,
        &path,
        "update activation recovery lock",
    )?;
    ensure_private_file(&file, &path)?;
    ensure_not_link_or_reparse(&path, "update activation recovery lock")?;
    avorax_platform_security::ensure_path_matches_open_file(
        &file,
        &path,
        "update activation recovery lock",
    )?;
    file.try_lock()
        .map_err(std::io::Error::from)
        .context("another update activation or recovery operation is active")?;
    Ok(ActivationRecoveryLock { _file: file })
}

fn write_new_private_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} has no parent: {}", path.display()))?;
    ensure_existing_path_chain_not_link(path, parent, label)?;
    ensure_not_link_or_reparse(path, label)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {label} {}", path.display()))?;
    avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
    ensure_private_file(&file, path)?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {label} {}", path.display()))?;
    file.flush()
        .and_then(|_| file.sync_all())
        .with_context(|| format!("failed to synchronize {label} {}", path.display()))?;
    avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
    Ok(())
}

fn read_bounded_private_file(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    ensure_not_link_or_reparse(path, label)?;
    let mut file =
        File::open(path).with_context(|| format!("failed to open {label} {}", path.display()))?;
    avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
    ensure_private_file(&file, path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened {label} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{label} is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= limit,
        "{label} exceeds its size limit: {}",
        path.display()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= limit,
        "{label} grew beyond its size limit while reading: {}",
        path.display()
    );
    avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
    Ok(bytes)
}

fn remove_private_regular_file(path: &Path, label: &str) -> Result<()> {
    ensure_not_link_or_reparse(path, label)?;
    let file = File::open(path)
        .with_context(|| format!("failed to open {label} before removal {}", path.display()))?;
    avorax_platform_security::ensure_path_matches_open_file(&file, path, label)?;
    ensure_private_file(&file, path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "{label} is not a regular file: {}",
        path.display()
    );
    drop(file);
    ensure_not_link_or_reparse(path, label)?;
    std::fs::remove_file(path)
        .with_context(|| format!("failed to remove {label} {}", path.display()))
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    avorax_platform_security::harden_unix_private_directory(path)
        .context("failed to enforce owner-only update recovery directory permissions")?;
    #[cfg(windows)]
    avorax_platform_security::harden_windows_private_directory(path)
        .context("failed to enforce exact update recovery directory DACL")?;
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("secure update activation recovery directories are unsupported on this platform");
    Ok(())
}

fn ensure_private_file(file: &File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    avorax_platform_security::harden_unix_private_file(file, path)
        .context("failed to enforce owner-only update recovery file permissions")?;
    #[cfg(windows)]
    avorax_platform_security::harden_windows_private_file(file, path)
        .context("failed to enforce exact update recovery file DACL")?;
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("secure update activation recovery files are unsupported on this platform");
    Ok(())
}

fn enumerate_recovery_journals(recovery_root: &Path) -> Result<Vec<PathBuf>> {
    let mut journals = Vec::new();
    let mut entries = 0_usize;
    for entry in std::fs::read_dir(recovery_root)
        .context("failed to enumerate update activation recovery directory")?
    {
        entries = entries
            .checked_add(1)
            .context("update activation recovery entry count overflow")?;
        anyhow::ensure!(
            entries <= MAX_RECOVERY_DIRECTORY_ENTRIES,
            "update activation recovery directory exceeds its entry limit"
        );
        let entry = entry?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("update activation recovery entry name is not Unicode"))?;
        if name == RECOVERY_LOCK_NAME || name == RECOVERY_KEY_NAME {
            ensure_private_recovery_entry_kind(&path, &name)?;
            continue;
        }
        let Some(operation_id) = name.strip_suffix(".json") else {
            anyhow::bail!("unrecognized update activation recovery entry: {name}");
        };
        validate_operation_id(operation_id)?;
        ensure_private_recovery_entry_kind(&path, &name)?;
        journals.push(path);
    }
    journals.sort();
    Ok(journals)
}

fn ensure_private_recovery_entry_kind(path: &Path, name: &str) -> Result<()> {
    ensure_not_link_or_reparse(path, "update activation recovery entry")?;
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_file(),
        "update activation recovery entry is not a regular file: {name}"
    );
    Ok(())
}

fn ensure_no_orphan_activation_siblings(boundary: &Path) -> Result<()> {
    inspect_recovery_parent_for_orphans(boundary)?;
    let engine = boundary.join("engine");
    match std::fs::symlink_metadata(&engine) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(&engine, "update engine directory during recovery audit")?;
            anyhow::ensure!(
                metadata.is_dir(),
                "update engine path is not a directory during recovery audit"
            );
            inspect_recovery_parent_for_orphans(&engine)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect update engine recovery parent"),
    }
    Ok(())
}

fn inspect_recovery_parent_for_orphans(parent: &Path) -> Result<()> {
    let mut entries = 0_usize;
    for entry in std::fs::read_dir(parent).with_context(|| {
        format!(
            "failed to enumerate update recovery parent {}",
            parent.display()
        )
    })? {
        entries = entries
            .checked_add(1)
            .context("update recovery parent entry count overflow")?;
        anyhow::ensure!(
            entries <= MAX_RECOVERY_PARENT_ENTRIES,
            "update recovery parent exceeds its bounded entry limit: {}",
            parent.display()
        );
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') && name.ends_with(".avorax-dir") {
            anyhow::bail!(
                "orphan update activation staging or backup sibling requires manual review: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn canonical_recovery_boundary(boundary: &Path) -> Result<PathBuf> {
    ensure_not_link_or_reparse(boundary, "update activation recovery boundary")?;
    let canonical = boundary.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize update recovery boundary {}",
            boundary.display()
        )
    })?;
    ensure_not_link_or_reparse(&canonical, "canonical update activation recovery boundary")?;
    let metadata = std::fs::symlink_metadata(&canonical)?;
    anyhow::ensure!(
        metadata.is_dir(),
        "update activation recovery boundary is not a directory: {}",
        canonical.display()
    );
    Ok(canonical)
}

fn allowed_destination_relative(boundary: &Path, destination: &Path) -> Result<String> {
    ensure_path_chain(destination, boundary, "update activation destination")?;
    let relative = destination.strip_prefix(boundary).with_context(|| {
        format!(
            "update activation destination escaped recovery boundary: {}",
            destination.display()
        )
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(
                value
                    .to_str()
                    .context("update activation destination contains a non-Unicode component")?,
            ),
            _ => anyhow::bail!("update activation destination contains an unsafe component"),
        }
    }
    let text = parts.join("/");
    validate_allowed_relative_text(&text)?;
    Ok(text)
}

fn validate_allowed_relative_text(relative: &str) -> Result<()> {
    anyhow::ensure!(
        ALLOWED_DESTINATIONS.contains(&relative),
        "update activation recovery destination is not allowlisted: {relative}"
    );
    Ok(())
}

fn derive_activation_paths(
    boundary: &Path,
    record: &ActivationRecoveryRecord,
) -> Result<DerivedActivationPaths> {
    validate_operation_id(&record.operation_id)?;
    validate_allowed_relative_text(&record.destination_relative)?;
    let mut destination = boundary.to_path_buf();
    for part in record.destination_relative.split('/') {
        destination.push(part);
    }
    let parent = destination
        .parent()
        .context("allowlisted update activation destination has no parent")?;
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .context("allowlisted update activation destination has no Unicode name")?;
    let staging = parent.join(format!(
        ".{name}.{}.staging.avorax-dir",
        record.operation_id
    ));
    let backup = parent.join(format!(".{name}.{}.backup.avorax-dir", record.operation_id));
    for path in [&destination, &staging, &backup] {
        ensure_path_chain(path, boundary, "derived update activation recovery path")?;
    }
    Ok(DerivedActivationPaths {
        destination,
        staging,
        backup,
    })
}

fn ensure_path_chain(path: &Path, boundary: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(
        path.starts_with(boundary),
        "{label} escaped boundary: {}",
        path.display()
    );
    ensure_existing_path_chain_not_link(path, boundary, label)
}

fn generate_operation_id() -> Result<String> {
    let mut bytes = [0_u8; RECOVERY_OPERATION_ID_BYTES];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        anyhow::anyhow!("failed to generate update recovery operation id: {error}")
    })?;
    Ok(hex::encode(bytes))
}

fn validate_operation_id(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == RECOVERY_OPERATION_ID_HEX_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "update activation recovery operation id is invalid"
    );
    Ok(())
}

fn boundary_sha256(boundary: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(BOUNDARY_HASH_DOMAIN);
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for unit in boundary.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(boundary.as_os_str().as_bytes());
    }
    #[cfg(not(any(unix, windows)))]
    hasher.update(boundary.to_string_lossy().as_bytes());
    hex::encode(hasher.finalize())
}

fn path_is_absent(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect path {}", path.display()))
        }
    }
}

fn ensure_path_absent(path: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(
        path_is_absent(path)?,
        "{label} already exists: {}",
        path.display()
    );
    Ok(())
}

fn path_is_directory_or_absent(path: &Path, label: &str) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(path, label)?;
            anyhow::ensure!(
                metadata.is_dir(),
                "{label} is not a directory: {}",
                path.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_directory_state(path: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(
        path_is_directory_or_absent(path, label)?,
        "{label} is missing: {}",
        path.display()
    );
    Ok(())
}

fn cleanup_recovery_directory(path: &Path, label: &str) -> Result<()> {
    ensure_directory_state(path, label)?;
    remove_dir_all_checked(path, label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn assert_unix_mode(path: &Path, expected: u32) {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o7777, expected);
    }

    fn setup_transaction() -> (tempfile::TempDir, PathBuf, DirectoryActivationTransaction) {
        let root = tempdir().unwrap();
        let install = root.path().join("install");
        let destination = install.join("engine/signatures");
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(destination.join("current.asig"), b"benign current fixture").unwrap();
        let transaction = begin_directory_activation(&install, &destination).unwrap();
        std::fs::create_dir_all(transaction.staging_path()).unwrap();
        std::fs::write(
            transaction.staging_path().join("next.asig"),
            b"benign staged fixture",
        )
        .unwrap();
        (root, install, transaction)
    }

    fn assert_journal_preserved(transaction: &DirectoryActivationTransaction) {
        assert!(transaction.journal_path.exists());
        assert!(transaction.paths.destination.exists());
        assert!(transaction.paths.staging.exists());
        assert!(transaction.paths.backup.exists());
    }

    #[test]
    fn activation_recovery_restores_backup_move_gap() {
        let (_root, install, transaction) = setup_transaction();
        let journal_path = transaction.journal_path.clone();
        let staging = transaction.paths.staging.clone();
        let backup = transaction.paths.backup.clone();
        let destination = transaction.paths.destination.clone();
        transaction
            .commit_with_hooks(
                || Ok(()),
                || anyhow::bail!("benign simulated interruption before activation"),
            )
            .unwrap_err();

        assert_eq!(
            std::fs::read(destination.join("current.asig")).unwrap(),
            b"benign current fixture"
        );
        assert!(!staging.exists());
        assert!(!backup.exists());
        assert!(!journal_path.exists());
        assert_eq!(
            recover_pending_directory_activations(&install).unwrap(),
            ActivationRecoverySummary::default()
        );
    }

    #[test]
    fn activation_recovery_finishes_completed_activation_cleanup() {
        let (_root, install, transaction) = setup_transaction();
        let journal_path = transaction.journal_path.clone();
        let backup = transaction.paths.backup.clone();
        let destination = transaction.paths.destination.clone();

        transaction.commit().unwrap();

        assert_eq!(
            std::fs::read(destination.join("next.asig")).unwrap(),
            b"benign staged fixture"
        );
        assert!(!backup.exists());
        assert!(!journal_path.exists());
        assert_eq!(
            recover_pending_directory_activations(&install).unwrap(),
            ActivationRecoverySummary::default()
        );
    }

    #[test]
    fn activation_recovery_fresh_call_restores_backup_move_gap() {
        let (_root, install, mut transaction) = setup_transaction();
        transaction.record.had_destination = true;
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();
        avorax_platform_security::rename_directory_no_replace(
            &transaction.paths.destination,
            &transaction.paths.backup,
            "benign interrupted activation backup move",
        )
        .unwrap();
        let destination = transaction.paths.destination.clone();
        let staging = transaction.paths.staging.clone();
        let backup = transaction.paths.backup.clone();
        let journal = transaction.journal_path.clone();
        drop(transaction);

        let summary = recover_pending_directory_activations(&install).unwrap();

        assert_eq!(summary.recovered_backups, 1);
        assert_eq!(summary.removed_journals, 1);
        assert_eq!(
            std::fs::read(destination.join("current.asig")).unwrap(),
            b"benign current fixture"
        );
        assert!(!staging.exists());
        assert!(!backup.exists());
        assert!(!journal.exists());
    }

    #[test]
    fn activation_recovery_fresh_call_finishes_completed_cleanup() {
        let (_root, install, mut transaction) = setup_transaction();
        transaction.record.had_destination = true;
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();
        avorax_platform_security::rename_directory_no_replace(
            &transaction.paths.destination,
            &transaction.paths.backup,
            "benign completed activation backup move",
        )
        .unwrap();
        avorax_platform_security::rename_directory_no_replace(
            &transaction.paths.staging,
            &transaction.paths.destination,
            "benign completed staged activation",
        )
        .unwrap();
        let destination = transaction.paths.destination.clone();
        let backup = transaction.paths.backup.clone();
        let journal = transaction.journal_path.clone();
        drop(transaction);

        let summary = recover_pending_directory_activations(&install).unwrap();

        assert_eq!(summary.completed_activations, 1);
        assert_eq!(summary.removed_journals, 1);
        assert_eq!(
            std::fs::read(destination.join("next.asig")).unwrap(),
            b"benign staged fixture"
        );
        assert!(!backup.exists());
        assert!(!journal.exists());
    }

    #[test]
    fn activation_recovery_handles_new_destination_states() {
        let root = tempdir().unwrap();
        let install = root.path().join("install");
        std::fs::create_dir_all(install.join("engine")).unwrap();
        let destination = install.join("engine/rules");
        let transaction = begin_directory_activation(&install, &destination).unwrap();
        std::fs::create_dir_all(transaction.staging_path()).unwrap();
        std::fs::write(
            transaction.staging_path().join("next.zrule"),
            b"benign new rule fixture",
        )
        .unwrap();
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();
        let staging = transaction.paths.staging.clone();
        drop(transaction);

        let aborted = recover_pending_directory_activations(&install).unwrap();
        assert_eq!(aborted.aborted_pre_activation, 1);
        assert!(!destination.exists());
        assert!(!staging.exists());

        let transaction = begin_directory_activation(&install, &destination).unwrap();
        std::fs::create_dir_all(transaction.staging_path()).unwrap();
        std::fs::write(
            transaction.staging_path().join("next.zrule"),
            b"benign activated rule fixture",
        )
        .unwrap();
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();
        avorax_platform_security::rename_directory_no_replace(
            &transaction.paths.staging,
            &transaction.paths.destination,
            "benign new destination activation",
        )
        .unwrap();
        drop(transaction);

        let completed = recover_pending_directory_activations(&install).unwrap();
        assert_eq!(completed.completed_activations, 1);
        assert_eq!(
            std::fs::read(destination.join("next.zrule")).unwrap(),
            b"benign activated rule fixture"
        );
    }

    #[test]
    fn activation_recovery_tampering_fails_closed_and_preserves_state() {
        let (_root, _install, mut transaction) = setup_transaction();
        transaction.record.had_destination = true;
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();
        let raw = std::fs::read_to_string(&transaction.journal_path).unwrap();
        std::fs::write(
            &transaction.journal_path,
            raw.replace("engine/signatures", "engine/rules"),
        )
        .unwrap();

        let error = reconcile_record_locked(
            &transaction.boundary,
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("authentication failed"));
        assert!(transaction.journal_path.exists());
        assert!(transaction.paths.destination.exists());
        assert!(transaction.paths.staging.exists());
        assert!(!transaction.paths.backup.exists());
    }

    #[test]
    fn activation_recovery_ambiguous_state_fixture_preserves_every_directory() {
        let (_root, _install, mut transaction) = setup_transaction();
        transaction.record.had_destination = true;
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();
        avorax_platform_security::rename_directory_no_replace(
            &transaction.paths.destination,
            &transaction.paths.backup,
            "benign recovery test backup move",
        )
        .unwrap();
        std::fs::create_dir_all(&transaction.paths.destination).unwrap();
        std::fs::write(
            transaction.paths.destination.join("competing.asig"),
            b"benign competing fixture",
        )
        .unwrap();

        let error = reconcile_record_locked(
            &transaction.boundary,
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("ambiguous authenticated"));
        assert_journal_preserved(&transaction);
    }

    #[test]
    fn activation_recovery_rejects_orphan_sibling_without_journal() {
        let root = tempdir().unwrap();
        let install = root.path().join("install");
        let engine = install.join("engine");
        std::fs::create_dir_all(&engine).unwrap();
        let orphan = install.join(".engine.0123456789abcdef0123456789abcdef.backup.avorax-dir");
        std::fs::create_dir_all(&orphan).unwrap();

        let error = recover_pending_directory_activations(&install).unwrap_err();

        assert!(format!("{error:#}").contains("orphan update activation"));
        assert!(orphan.exists());
    }

    #[test]
    fn activation_recovery_rejects_unrecognized_recovery_entry() {
        let root = tempdir().unwrap();
        let install = root.path().join("install");
        std::fs::create_dir_all(&install).unwrap();
        recover_pending_directory_activations(&install).unwrap();
        let unexpected = install.join(RECOVERY_DIRECTORY_NAME).join("unexpected.tmp");
        write_new_private_file(&unexpected, b"benign unexpected fixture", "test fixture").unwrap();

        let error = recover_pending_directory_activations(&install).unwrap_err();

        assert!(format!("{error:#}").contains("unrecognized update activation recovery entry"));
        assert!(unexpected.exists());
    }

    #[test]
    fn activation_recovery_rejects_oversized_journal_and_preserves_it() {
        let (_root, install, mut transaction) = setup_transaction();
        transaction.record.had_destination = true;
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();
        let journal = transaction.journal_path.clone();
        OpenOptions::new()
            .write(true)
            .open(&journal)
            .unwrap()
            .set_len(MAX_RECOVERY_FILE_BYTES + 1)
            .unwrap();
        drop(transaction);

        let error = recover_pending_directory_activations(&install).unwrap_err();

        assert!(format!("{error:#}").contains("exceeds its size limit"));
        assert!(journal.exists());
    }

    #[test]
    fn activation_recovery_lock_rejects_concurrent_operation() {
        let (_root, install, transaction) = setup_transaction();

        let error = recover_pending_directory_activations(&install).unwrap_err();

        assert!(format!("{error:#}").contains("another update activation or recovery operation"));
        assert!(transaction.staging_path().exists());
    }

    #[test]
    fn activation_recovery_journal_rejects_unknown_fields() {
        let (_root, _install, mut transaction) = setup_transaction();
        transaction.record.had_destination = true;
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&transaction.journal_path).unwrap()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        std::fs::write(
            &transaction.journal_path,
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();

        let error =
            read_authenticated_journal(&transaction.recovery_root, &transaction.journal_path)
                .unwrap_err();

        assert!(format!("{error:#}").contains("unknown field"));
        assert!(transaction.journal_path.exists());
    }

    #[test]
    fn activation_recovery_destination_is_exactly_allowlisted() {
        let root = tempdir().unwrap();
        let install = root.path().join("install");
        std::fs::create_dir_all(&install).unwrap();

        let error = begin_directory_activation(&install, &install.join("docs"))
            .err()
            .unwrap();

        assert!(format!("{error:#}").contains("not allowlisted"));
    }

    #[test]
    fn activation_recovery_operation_ids_are_strict_lower_hex() {
        assert!(validate_operation_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_operation_id("0123456789ABCDEF0123456789ABCDEF").is_err());
        assert!(validate_operation_id("../0123456789abcdef0123456789ab").is_err());
    }

    #[test]
    fn activation_recovery_authentication_tags_are_strict_lower_hex() {
        let key = [7_u8; RECOVERY_KEY_BYTES];
        let tag = recovery_hmac(&key, b"benign record fixture").unwrap();

        assert!(verify_recovery_hmac(&key, b"benign record fixture", &tag).is_ok());
        let error =
            verify_recovery_hmac(&key, b"benign record fixture", &"A".repeat(64)).unwrap_err();
        assert!(error
            .to_string()
            .contains("authentication tag is malformed"));
    }

    #[test]
    fn activation_recovery_report_error_text_is_bounded() {
        let long = "x".repeat(MAX_RECOVERY_REPORT_ERROR_CHARS + 100);
        assert_eq!(
            bounded_error_text(&long).chars().count(),
            MAX_RECOVERY_REPORT_ERROR_CHARS
        );
        assert_eq!(bounded_error_text("short"), "short");
    }

    #[cfg(unix)]
    #[test]
    fn activation_recovery_unix_artifacts_are_owner_only_and_non_executable() {
        let (_root, _install, mut transaction) = setup_transaction();
        transaction.record.had_destination = true;
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();

        let key_path = transaction.recovery_root.join(RECOVERY_KEY_NAME);
        let lock_path = transaction.recovery_root.join(RECOVERY_LOCK_NAME);
        assert_unix_mode(&transaction.recovery_root, 0o700);
        assert_unix_mode(&key_path, 0o600);
        assert_unix_mode(&lock_path, 0o600);
        assert_unix_mode(&transaction.journal_path, 0o600);
        assert!(std::fs::read_to_string(key_path)
            .unwrap()
            .starts_with("unix-private:"));
    }

    #[cfg(unix)]
    #[test]
    fn activation_recovery_unix_repairs_private_modes_before_use() {
        use std::os::unix::fs::PermissionsExt;

        let (_root, install, mut transaction) = setup_transaction();
        transaction.record.had_destination = true;
        write_authenticated_journal(
            &transaction.recovery_root,
            &transaction.journal_path,
            &transaction.record,
        )
        .unwrap();

        let recovery_root = transaction.recovery_root.clone();
        let key_path = recovery_root.join(RECOVERY_KEY_NAME);
        let lock_path = recovery_root.join(RECOVERY_LOCK_NAME);
        let journal_path = transaction.journal_path.clone();
        std::fs::set_permissions(&recovery_root, std::fs::Permissions::from_mode(0o777)).unwrap();
        for path in [&key_path, &lock_path, &journal_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        drop(transaction);

        let summary = recover_pending_directory_activations(&install).unwrap();

        assert_eq!(summary.aborted_pre_activation, 1);
        assert_eq!(summary.removed_journals, 1);
        assert_unix_mode(&recovery_root, 0o700);
        assert_unix_mode(&key_path, 0o600);
        assert_unix_mode(&lock_path, 0o600);
        assert!(!journal_path.exists());
    }

    #[test]
    fn activation_recovery_unix_runtime_contract_is_wired() {
        let source = include_str!("activation_recovery.rs");
        let workflow = include_str!("../../../.github/workflows/ci.yml");

        for marker in [
            "activation_recovery_unix_artifacts_are_owner_only_and_non_executable",
            "activation_recovery_unix_repairs_private_modes_before_use",
            "assert_unix_mode(&transaction.recovery_root, 0o700)",
            "assert_unix_mode(&key_path, 0o600)",
            "assert_unix_mode(&lock_path, 0o600)",
            "assert_unix_mode(&transaction.journal_path, 0o600)",
        ] {
            assert!(
                source.contains(marker),
                "missing Unix recovery marker: {marker}"
            );
        }
        for marker in [
            "name: Test update recovery Unix runtime",
            "--manifest-path core/avorax_update_service/Cargo.toml",
            "activation_recovery_unix_",
            "-- --test-threads=1",
        ] {
            assert!(
                workflow.contains(marker),
                "missing Unix CI marker: {marker}"
            );
        }
    }

    #[test]
    fn activation_recovery_macos_runtime_contract_is_wired() {
        let workflow = include_str!("../../../.github/workflows/ci.yml");
        let job_start = workflow
            .find("  update-recovery-macos:\n")
            .expect("missing dedicated macOS update recovery job");
        let job_end = workflow[job_start..]
            .find("\n  flutter:\n")
            .map(|offset| job_start + offset)
            .expect("missing macOS update recovery job boundary");
        let job = &workflow[job_start..job_end];

        for marker in [
            "name: macOS update recovery permission runtime",
            "runs-on: macos-15",
            "timeout-minutes: 30",
            "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
            "dtolnay/rust-toolchain@fa04a1451ff1842e2626ccb99004d0195b455a88",
            "toolchain: 1.96.1",
            "name: Test update recovery macOS runtime",
            "cargo test --locked",
            "--manifest-path core/avorax_update_service/Cargo.toml",
            "activation_recovery_unix_",
            "-- --test-threads=1",
        ] {
            assert!(job.contains(marker), "missing macOS CI marker: {marker}");
        }
    }
}
