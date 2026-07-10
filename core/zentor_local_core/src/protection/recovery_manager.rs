use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_RECOVERY_COPY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RECOVERY_HASH_BYTES: u64 = 1024 * 1024 * 1024;

pub struct RecoveryManager {
    vault: PathBuf,
}

impl RecoveryManager {
    pub fn new(vault: PathBuf) -> Self {
        Self { vault }
    }

    pub fn backup_before_change(&self, original: &Path) -> anyhow::Result<PathBuf> {
        self.ensure_vault_directory()?;
        let metadata = ensure_regular_recovery_file(original, "recovery source")?;
        let source_hash = sha256_for_file(original)?;
        let backup = self.vault.join(format!("{}.avoraxrv", Uuid::new_v4()));
        ensure_recovery_destination_absent(&backup, "recovery vault copy destination")?;
        copy_file_exclusive(original, &backup)
            .with_context(|| "unable to create recovery vault copy")?;
        if ensure_regular_recovery_file(&backup, "recovery vault copy")?.len() != metadata.len()
            || sha256_for_file(&backup)? != source_hash
        {
            if let Err(cleanup_error) =
                cleanup_recovery_partial_file(&backup, "invalid recovery vault copy")
            {
                return Err(anyhow!(
                    "recovery vault copy verification failed; failed to remove invalid recovery vault copy {}: {cleanup_error:#}",
                    backup.display()
                ));
            }
            return Err(anyhow!("recovery vault copy verification failed"));
        }
        Ok(backup)
    }

    pub fn restore_from_vault(&self, backup: &Path, destination: &Path) -> anyhow::Result<()> {
        self.ensure_vault_directory()?;
        self.ensure_backup_path(backup)?;
        if destination
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(anyhow!("unsafe recovery restore destination"));
        }
        ensure_existing_recovery_restore_destination_replaceable(destination)?;
        if let Some(parent) = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
            reject_link_path(parent, "recovery restore parent")?;
        }
        let expected_len = ensure_regular_recovery_file(backup, "recovery vault copy")?.len();
        let expected_hash = sha256_for_file(backup)?;
        let temp_destination =
            destination.with_extension(format!("avorax-restore-{}.tmp", Uuid::new_v4()));
        ensure_recovery_destination_absent(&temp_destination, "recovery restore temp destination")?;
        if let Err(error) = copy_file_exclusive(backup, &temp_destination) {
            if let Err(cleanup_error) =
                cleanup_recovery_partial_file(&temp_destination, "partial recovery restore")
            {
                return Err(anyhow!(
                    "unable to stage recovery restore: {error:#}; failed to remove partial recovery restore {}: {cleanup_error:#}",
                    temp_destination.display()
                ));
            }
            return Err(error.context("unable to stage recovery restore"));
        }
        if ensure_regular_recovery_file(&temp_destination, "recovery restore temp file")?.len()
            != expected_len
            || sha256_for_file(&temp_destination)? != expected_hash
        {
            if let Err(cleanup_error) =
                cleanup_recovery_partial_file(&temp_destination, "invalid recovery restore")
            {
                return Err(anyhow!(
                    "staged recovery restore verification failed; failed to remove invalid recovery restore {}: {cleanup_error:#}",
                    temp_destination.display()
                ));
            }
            return Err(anyhow!("staged recovery restore verification failed"));
        }
        if let Err(error) = remove_existing_recovery_restore_destination(destination) {
            if let Err(cleanup_error) =
                cleanup_recovery_partial_file(&temp_destination, "partial recovery restore")
            {
                return Err(anyhow!(
                    "{error:#}; failed to remove partial recovery restore {}: {cleanup_error:#}",
                    temp_destination.display()
                ));
            }
            return Err(error);
        }
        fs::rename(&temp_destination, destination)
            .with_context(|| "unable to activate recovery restore")?;
        Ok(())
    }

    fn ensure_vault_directory(&self) -> anyhow::Result<()> {
        fs::create_dir_all(&self.vault)?;
        reject_link_path(&self.vault, "recovery vault directory")?;
        Ok(())
    }

    fn ensure_backup_path(&self, backup: &Path) -> anyhow::Result<()> {
        reject_link_path(backup, "recovery vault copy")?;
        let canonical_vault = self.vault.canonicalize()?;
        let canonical_backup = backup.canonicalize()?;
        if !canonical_backup.starts_with(canonical_vault) {
            return Err(anyhow!("recovery vault copy escapes vault directory"));
        }
        if canonical_backup
            .extension()
            .and_then(|value| value.to_str())
            != Some("avoraxrv")
        {
            return Err(anyhow!("recovery vault copy has unsafe extension"));
        }
        ensure_regular_recovery_file(&canonical_backup, "recovery vault copy")?;
        Ok(())
    }
}

fn cleanup_recovery_partial_file(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to remove {label} partial file {}", path.display())),
    }
}

fn copy_recovery_file_limited<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    limit: u64,
    source: &Path,
) -> anyhow::Result<()> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("recovery file copy size overflow"))?;
        if total > limit {
            anyhow::bail!(
                "recovery file {} exceeds the copy size limit",
                source.display()
            );
        }
        output.write_all(&buffer[..read])?;
    }
}

fn sha256_for_file(path: &Path) -> anyhow::Result<String> {
    let metadata = ensure_regular_recovery_file(path, "recovery hash input")?;
    if metadata.len() > MAX_RECOVERY_HASH_BYTES {
        return Err(anyhow!(
            "recovery hash input {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_RECOVERY_HASH_BYTES
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
            .ok_or_else(|| anyhow!("recovery hash size overflow"))?;
        if total > MAX_RECOVERY_HASH_BYTES {
            return Err(anyhow!(
                "recovery hash input {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_RECOVERY_HASH_BYTES
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn ensure_regular_recovery_file(path: &Path, label: &str) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} {}", path.display()))?;
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
    if !metadata.is_file() {
        return Err(anyhow!("{label} is not a regular file"));
    }
    Ok(metadata)
}

fn ensure_recovery_destination_absent(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
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
            Err(anyhow!("{label} already exists"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_existing_recovery_restore_destination_replaceable(
    destination: &Path,
) -> anyhow::Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "refusing to use symbolic link recovery restore destination"
                ));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(anyhow!(
                        "refusing to use reparse point recovery restore destination"
                    ));
                }
            }
            if !metadata.is_file() {
                return Err(anyhow!(
                    "recovery restore destination is not a regular file"
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect recovery restore destination {}",
                destination.display()
            )
        }),
    }
}

fn remove_existing_recovery_restore_destination(destination: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "refusing to replace symbolic link recovery restore destination"
                ));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(anyhow!(
                        "refusing to replace reparse point recovery restore destination"
                    ));
                }
            }
            if !metadata.is_file() {
                return Err(anyhow!(
                    "recovery restore destination is not a regular file"
                ));
            }
            fs::remove_file(destination)
                .with_context(|| "unable to replace existing recovery destination")?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect recovery restore destination {}",
                destination.display()
            )
        }),
    }
}

fn copy_file_exclusive(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let mut input = fs::File::open(source)
        .with_context(|| format!("unable to open recovery source {}", source.display()))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| {
            format!(
                "unable to create recovery destination {}",
                destination.display()
            )
        })?;
    if let Err(error) =
        copy_recovery_file_limited(&mut input, &mut output, MAX_RECOVERY_COPY_BYTES, source)
    {
        drop(output);
        cleanup_recovery_partial_file(destination, "partial recovery destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial recovery destination {} after copy failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "unable to copy recovery file {} to {}",
                source.display(),
                destination.display()
            )
        });
    }
    if let Err(error) = output.sync_all() {
        drop(output);
        cleanup_recovery_partial_file(destination, "partial recovery destination")
            .with_context(|| {
                format!(
                    "failed to clean up partial recovery destination {} after sync failure: {error:#}",
                    destination.display()
                )
            })?;
        return Err(error).with_context(|| {
            format!(
                "unable to sync recovery destination {}",
                destination.display()
            )
        });
    }
    Ok(())
}

fn reject_link_path(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn recovery_manager_restores_from_test_recovery_vault() {
        let dir = tempdir().unwrap();
        let original = dir.path().join("report.docx");
        fs::write(&original, b"original").unwrap();
        let manager = RecoveryManager::new(dir.path().join("vault"));
        let backup = manager.backup_before_change(&original).unwrap();
        fs::write(&original, b"encrypted").unwrap();
        manager.restore_from_vault(&backup, &original).unwrap();
        assert_eq!(fs::read(&original).unwrap(), b"original");
    }

    #[test]
    fn recovery_backup_uses_opaque_vault_extension() {
        let dir = tempdir().unwrap();
        let original = dir.path().join("report.docx");
        fs::write(&original, b"original").unwrap();
        let manager = RecoveryManager::new(dir.path().join("vault"));

        let backup = manager.backup_before_change(&original).unwrap();

        assert_eq!(
            backup.extension().and_then(|value| value.to_str()),
            Some("avoraxrv")
        );
        assert!(!backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("report.docx"));
    }

    #[test]
    fn recovery_copy_paths_use_exclusive_destinations() {
        let source = include_str!("recovery_manager.rs");
        let exclusive_copy_pattern = ["fn copy_file_", "exclusive"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let sync_pattern = ["output.", "sync_all()"].concat();
        let limit_pattern = ["MAX_RECOVERY_", "COPY_BYTES"].concat();
        let limited_copy_pattern = ["fn copy_recovery_", "file_limited"].concat();
        let bounded_buffer_pattern = ["let mut buffer = [0_u8; ", "64 * 1024]"].concat();
        let write_all_pattern = ["output.", "write_all(&buffer[..read])"].concat();
        let backup_absent_pattern = [
            "ensure_recovery_destination_absent(&backup",
            ", \"recovery vault copy destination\")",
        ]
        .concat();
        let restore_absent_pattern = [
            "ensure_recovery_destination_absent(&temp_destination",
            ", \"recovery restore temp destination\")",
        ]
        .concat();
        let old_backup_copy_pattern = ["fs::copy(original, ", "&backup)"].concat();
        let old_restore_copy_pattern = ["fs::copy(backup, ", "&temp_destination)"].concat();
        let old_io_copy_pattern = ["io::", "copy(&mut input, &mut output)"].concat();

        assert!(source.contains(&exclusive_copy_pattern));
        assert!(source.contains(&create_new_pattern));
        assert!(source.contains(&sync_pattern));
        assert!(source.contains(&limit_pattern));
        assert!(source.contains("MAX_RECOVERY_COPY_BYTES"));
        assert!(source.contains(&limited_copy_pattern));
        assert!(source.contains("copy_recovery_file_limited"));
        assert!(source.contains(&bounded_buffer_pattern));
        assert!(source.contains("total > limit"));
        assert!(source.contains(&write_all_pattern));
        assert!(source.contains(&backup_absent_pattern));
        assert!(source.contains(&restore_absent_pattern));
        assert!(source.contains("after copy failure"));
        assert!(source.contains("after sync failure"));
        assert!(!source.contains(&old_backup_copy_pattern));
        assert!(!source.contains(&old_restore_copy_pattern));
        assert!(!source.contains(&old_io_copy_pattern));
    }

    #[test]
    fn recovery_hash_input_is_size_bounded() {
        let source = include_str!("recovery_manager.rs");
        let start = source.find("fn sha256_for_file").unwrap();
        let end = source.find("fn ensure_regular_recovery_file").unwrap();
        let hash_source = &source[start..end];

        assert!(source.contains("const MAX_RECOVERY_HASH_BYTES"));
        assert!(hash_source.contains(
            "let metadata = ensure_regular_recovery_file(path, \"recovery hash input\")?"
        ));
        assert!(hash_source.contains("metadata.len() > MAX_RECOVERY_HASH_BYTES"));
        assert!(hash_source.contains("let mut total = 0_u64"));
        assert!(hash_source.contains("checked_add(read as u64)"));
        assert!(hash_source.contains("total > MAX_RECOVERY_HASH_BYTES"));
        assert!(hash_source.contains("hasher.update(&buffer[..read])"));
    }

    #[test]
    fn recovery_partial_cleanup_failures_are_reported() {
        let source = include_str!("recovery_manager.rs");
        let manager_start = source.find("impl RecoveryManager").unwrap();
        let helper_start = source.find("fn cleanup_recovery_partial_file").unwrap();
        let manager_source = &source[manager_start..helper_start];
        let old_backup_cleanup = ["let _ = fs::remove_", "file(&backup);"].concat();
        let old_restore_cleanup = ["let _ = fs::remove_", "file(&temp_destination);"].concat();

        assert!(source.contains("fn cleanup_recovery_partial_file"));
        assert!(manager_source.contains("failed to remove invalid recovery vault copy"));
        assert!(manager_source.contains("failed to remove partial recovery restore"));
        assert!(manager_source.contains("failed to remove invalid recovery restore"));
        assert!(!manager_source.contains(&old_backup_cleanup));
        assert!(!manager_source.contains(&old_restore_cleanup));
    }

    #[test]
    fn recovery_destination_absent_rejects_existing_file() {
        let dir = tempdir().unwrap();
        let destination = dir.path().join("existing.avoraxrv");
        fs::write(&destination, b"existing").unwrap();

        let error =
            ensure_recovery_destination_absent(&destination, "recovery vault copy destination")
                .unwrap_err();

        assert!(error
            .to_string()
            .contains("recovery vault copy destination already exists"));
        assert_eq!(fs::read(&destination).unwrap(), b"existing");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_destination_absent_rejects_symbolic_link() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let external = dir.path().join("external");
        let destination = dir.path().join("linked.avoraxrv");
        fs::write(&external, b"external").unwrap();
        symlink(&external, &destination).unwrap();

        let error =
            ensure_recovery_destination_absent(&destination, "recovery vault copy destination")
                .unwrap_err();

        assert!(error
            .to_string()
            .contains("refusing to use symbolic link recovery vault copy destination"));
        assert_eq!(fs::read(&external).unwrap(), b"external");
    }

    #[test]
    fn recovery_restore_rejects_backup_outside_vault() {
        let dir = tempdir().unwrap();
        let outside = dir.path().join("outside.avoraxrv");
        fs::write(&outside, b"outside").unwrap();
        let manager = RecoveryManager::new(dir.path().join("vault"));

        let error = manager
            .restore_from_vault(&outside, &dir.path().join("restored.txt"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("escapes vault"));
    }

    #[test]
    fn recovery_restore_rejects_parent_dir_destination() {
        let dir = tempdir().unwrap();
        let original = dir.path().join("report.docx");
        fs::write(&original, b"original").unwrap();
        let manager = RecoveryManager::new(dir.path().join("vault"));
        let backup = manager.backup_before_change(&original).unwrap();

        let error = manager
            .restore_from_vault(&backup, Path::new("..").join("escaped.txt").as_path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsafe recovery restore destination"));
    }

    #[cfg(unix)]
    #[test]
    fn recovery_restore_rejects_symbolic_link_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let original = dir.path().join("report.docx");
        let linked_destination = dir.path().join("linked-report.docx");
        let external = dir.path().join("external.docx");
        fs::write(&original, b"original").unwrap();
        fs::write(&external, b"external").unwrap();
        symlink(&external, &linked_destination).unwrap();
        let manager = RecoveryManager::new(dir.path().join("vault"));
        let backup = manager.backup_before_change(&original).unwrap();

        let error = manager
            .restore_from_vault(&backup, &linked_destination)
            .unwrap_err()
            .to_string();

        assert!(error.contains("refusing to use symbolic link recovery restore destination"));
        assert_eq!(fs::read(&external).unwrap(), b"external");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_restore_rejects_symbolic_link_backup() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        fs::create_dir_all(&vault).unwrap();
        let target = dir.path().join("outside.avoraxrv");
        fs::write(&target, b"outside").unwrap();
        let linked = vault.join("linked.avoraxrv");
        symlink(&target, &linked).unwrap();
        let manager = RecoveryManager::new(vault);

        let error = manager
            .restore_from_vault(&linked, &dir.path().join("restored.txt"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"));
    }
}
