use anyhow::{Context, Result};
use std::cmp::Reverse;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::logging::program_data_dir;
use crate::path_safety::{
    copy_file_staged, create_dir_all_checked, ensure_existing_path_chain_not_link,
    ensure_not_link_or_reparse, remove_dir_all_checked,
};

pub fn rollback_root() -> Result<PathBuf> {
    Ok(program_data_dir()?.join("updates").join("rollback"))
}

#[derive(Clone, Copy)]
enum RollbackItemKind {
    File,
    Directory,
}

struct RollbackItem {
    name: &'static str,
    kind: RollbackItemKind,
}

const ROLLBACK_ITEMS: &[RollbackItem] = &[
    RollbackItem {
        name: "Avorax.exe",
        kind: RollbackItemKind::File,
    },
    RollbackItem {
        name: "avorax_core_service.exe",
        kind: RollbackItemKind::File,
    },
    RollbackItem {
        name: "avorax_guard_service.exe",
        kind: RollbackItemKind::File,
    },
    RollbackItem {
        name: "engine",
        kind: RollbackItemKind::Directory,
    },
];

pub fn create_snapshot(install_dir: &Path, version: &str) -> Result<PathBuf> {
    let install_dir = canonical_install_dir(install_dir)?;
    let snapshot = rollback_root()?.join(safe_snapshot_name(version)?);
    remove_existing_rollback_dir(&snapshot, "rollback snapshot")?;
    create_dir_all_checked(&snapshot, "rollback snapshot")?;
    if let Err(error) = copy_snapshot_items(&install_dir, &snapshot) {
        remove_existing_rollback_dir(&snapshot, "rollback snapshot").with_context(|| {
            format!(
                "failed to clean rollback snapshot {} after create failure: {error:#}",
                snapshot.display()
            )
        })?;
        return Err(error);
    }
    Ok(snapshot)
}

fn copy_snapshot_items(install_dir: &Path, snapshot: &Path) -> Result<()> {
    for item in ROLLBACK_ITEMS {
        let source = install_dir.join(item.name);
        ensure_required_item(&source, item, "rollback source")?;
        match item.kind {
            RollbackItemKind::File => copy_file_staged(
                &source,
                &snapshot.join(item.name),
                snapshot,
                "rollback snapshot",
            )?,
            RollbackItemKind::Directory => copy_dir(&source, &snapshot.join(item.name))?,
        }
    }
    Ok(())
}

pub fn restore_latest_snapshot(install_dir: &Path) -> Result<PathBuf> {
    let root = rollback_root()?;
    let mut snapshots = Vec::new();
    if let Some(root) = rollback_root_for_enumeration(&root)? {
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            let path = entry.path();
            ensure_not_link_or_reparse(&path, "rollback snapshot")?;
            let metadata = path.symlink_metadata()?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                if safe_snapshot_name(name).is_ok() {
                    snapshots.push((metadata.modified()?, path));
                }
            }
        }
    }
    snapshots.sort_by_key(|entry| Reverse(entry.0));
    let snapshot = snapshots
        .into_iter()
        .map(|(_, path)| path)
        .next()
        .context("No Avorax rollback snapshot is available.")?;
    restore_snapshot(&snapshot, install_dir)?;
    Ok(snapshot)
}

pub fn restore_snapshot(snapshot: &Path, install_dir: &Path) -> Result<()> {
    let snapshot = canonical_snapshot_dir(snapshot)?;
    let install_dir = canonical_install_dir(install_dir)?;
    ensure_existing_install_directory(&install_dir, "rollback install directory before restore")?;
    preflight_restore_snapshot(&snapshot, &install_dir)?;
    for item in ROLLBACK_ITEMS {
        let source = snapshot.join(item.name);
        ensure_required_item(&source, item, "rollback snapshot")?;
        let target = install_dir.join(item.name);
        match item.kind {
            RollbackItemKind::File => {
                ensure_restore_file_target_ready(&target, &install_dir)?;
                create_restore_target_parent(&target)?;
                ensure_existing_path_chain_not_link(&target, &install_dir, "rollback destination")?;
                copy_file_staged(&source, &target, &install_dir, "rollback destination")?;
            }
            RollbackItemKind::Directory => {
                ensure_restore_directory_target_ready(&target, &install_dir)?;
                replace_dir_from_snapshot(&source, &target, &install_dir)?;
            }
        }
    }
    Ok(())
}

fn preflight_restore_snapshot(snapshot: &Path, install_dir: &Path) -> Result<()> {
    for item in ROLLBACK_ITEMS {
        ensure_required_item(&snapshot.join(item.name), item, "rollback snapshot")?;
        let target = install_dir.join(item.name);
        ensure_restore_target_within_install(&target, install_dir)?;
        match item.kind {
            RollbackItemKind::File => {
                ensure_restore_file_target_ready(&target, install_dir)?;
            }
            RollbackItemKind::Directory => {
                ensure_restore_directory_target_ready(&target, install_dir)?;
            }
        }
    }
    Ok(())
}

fn ensure_restore_target_within_install(target: &Path, install_dir: &Path) -> Result<()> {
    anyhow::ensure!(
        target.starts_with(install_dir),
        "rollback target escaped install directory"
    );
    Ok(())
}

fn ensure_restore_target_parent(target: &Path, install_dir: &Path) -> Result<()> {
    ensure_restore_target_within_install(target, install_dir)?;
    if let Some(parent) = target.parent() {
        ensure_existing_path_chain_not_link(parent, install_dir, "rollback destination")?;
    }
    Ok(())
}

fn create_restore_target_parent(target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        create_dir_all_checked(parent, "rollback destination")?;
    }
    Ok(())
}

fn ensure_restore_file_target_ready(target: &Path, install_dir: &Path) -> Result<()> {
    ensure_restore_target_parent(target, install_dir)?;
    ensure_existing_path_chain_not_link(target, install_dir, "rollback destination")?;
    match std::fs::symlink_metadata(target) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(target, "rollback destination")?;
            anyhow::ensure!(
                metadata.is_file(),
                "rollback destination target is not a regular file: {}",
                target.display()
            );
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect rollback destination target {}",
                    target.display()
                )
            });
        }
    }
    Ok(())
}

fn ensure_restore_directory_target_ready(target: &Path, install_dir: &Path) -> Result<()> {
    ensure_restore_target_within_install(target, install_dir)?;
    ensure_existing_path_chain_not_link(target, install_dir, "rollback destination")?;
    match std::fs::symlink_metadata(target) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(target, "rollback destination")?;
            anyhow::ensure!(
                metadata.is_dir(),
                "rollback destination target is not a directory: {}",
                target.display()
            );
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect rollback destination target {}",
                    target.display()
                )
            });
        }
    }
    Ok(())
}

fn replace_dir_from_snapshot(source: &Path, destination: &Path, install_dir: &Path) -> Result<()> {
    ensure_restore_directory_target_ready(destination, install_dir)?;
    let staging = allocate_restore_sibling_dir_path(destination, install_dir, "staged")?;
    let backup = allocate_restore_sibling_dir_path(destination, install_dir, "backup")?;

    if let Err(error) = copy_dir(source, &staging) {
        cleanup_restore_directory(&staging, "rollback destination staging directory").with_context(
            || {
                format!(
                    "failed to clean rollback destination staging directory {} after copy failure: {error:#}",
                    staging.display()
                )
            },
        )?;
        return Err(error);
    }

    if let Err(error) = activate_staged_restore_dir(&staging, destination, &backup, install_dir) {
        cleanup_restore_directory(&staging, "rollback destination staging directory").with_context(
            || {
                format!(
                    "failed to clean rollback destination staging directory {} after activation failure: {error:#}",
                    staging.display()
                )
            },
        )?;
        return Err(error);
    }

    Ok(())
}

fn activate_staged_restore_dir(
    staging: &Path,
    destination: &Path,
    backup: &Path,
    install_dir: &Path,
) -> Result<()> {
    ensure_existing_path_chain_not_link(
        staging,
        install_dir,
        "rollback destination staging directory",
    )?;
    ensure_existing_rollback_directory(staging, "rollback destination staging directory")?;
    ensure_restore_directory_target_ready(destination, install_dir)?;
    ensure_existing_path_chain_not_link(backup, install_dir, "rollback destination backup")?;
    ensure_restore_sibling_absent(backup, "rollback destination backup")?;

    let destination_exists = match std::fs::symlink_metadata(destination) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(destination, "rollback destination")?;
            anyhow::ensure!(
                metadata.is_dir(),
                "rollback destination target is not a directory: {}",
                destination.display()
            );
            true
        }
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect rollback destination target {}",
                    destination.display()
                )
            });
        }
    };

    if destination_exists {
        std::fs::rename(destination, backup).with_context(|| {
            format!(
                "failed to move rollback destination {} to backup {}",
                destination.display(),
                backup.display()
            )
        })?;
    }

    if let Err(error) = std::fs::rename(staging, destination).with_context(|| {
        format!(
            "failed to activate staged rollback destination {} as {}",
            staging.display(),
            destination.display()
        )
    }) {
        let activation_error = format!("{error:#}");
        if destination_exists {
            if let Err(restore_error) = std::fs::rename(backup, destination) {
                return Err(error).context(format!(
                    "failed to restore rollback destination backup {} after activation failure: {restore_error}",
                    backup.display()
                ));
            }
        }
        return Err(error).context(format!(
            "rollback destination activation failed before backup cleanup: {activation_error}"
        ));
    }

    if destination_exists {
        cleanup_restore_directory(backup, "rollback destination backup").with_context(|| {
            format!(
                "failed to clean rollback destination backup {} after activation",
                backup.display()
            )
        })?;
    }
    Ok(())
}

fn cleanup_restore_directory(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            ensure_not_link_or_reparse(path, label)?;
            remove_dir_all_checked(path, label)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_restore_sibling_absent(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => anyhow::bail!("{label} already exists: {}", path.display()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn allocate_restore_sibling_dir_path(
    target: &Path,
    install_dir: &Path,
    role: &str,
) -> Result<PathBuf> {
    let parent = target.parent().ok_or_else(|| {
        anyhow::anyhow!("rollback destination missing parent: {}", target.display())
    })?;
    let name = target
        .file_name()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "rollback destination missing filename: {}",
                target.display()
            )
        })?
        .to_string_lossy();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .context("failed to read system time for rollback destination staging directory")?;
    for attempt in 0..16 {
        let candidate = parent.join(format!(
            ".{name}.{}.{}.{}.{}.avorax-dir",
            std::process::id(),
            unique,
            attempt,
            role
        ));
        ensure_restore_target_within_install(&candidate, install_dir)?;
        ensure_existing_path_chain_not_link(
            &candidate,
            install_dir,
            "rollback destination sibling directory",
        )?;
        ensure_not_link_or_reparse(&candidate, "rollback destination sibling directory")?;
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(candidate),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect rollback destination sibling directory {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    anyhow::bail!(
        "could not allocate rollback destination {role} directory for {}",
        target.display()
    )
}

fn ensure_required_item(source: &Path, item: &RollbackItem, label: &str) -> Result<()> {
    ensure_not_link_or_reparse(source, label)?;
    let metadata = match std::fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let kind = match item.kind {
                RollbackItemKind::File => "file",
                RollbackItemKind::Directory => "directory",
            };
            anyhow::bail!(
                "{label} missing required {kind} {} at {}",
                item.name,
                source.display()
            );
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {label} {}", source.display()));
        }
    };
    match item.kind {
        RollbackItemKind::File => anyhow::ensure!(
            metadata.is_file(),
            "{label} missing required file {} at {}",
            item.name,
            source.display()
        ),
        RollbackItemKind::Directory => anyhow::ensure!(
            metadata.is_dir(),
            "{label} missing required directory {} at {}",
            item.name,
            source.display()
        ),
    }
    Ok(())
}

fn remove_existing_rollback_dir(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            ensure_not_link_or_reparse(path, label)?;
            remove_dir_all_checked(path, label)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn rollback_root_for_enumeration(root: &Path) -> Result<Option<PathBuf>> {
    match std::fs::symlink_metadata(root) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(root, "rollback root")?;
            anyhow::ensure!(
                metadata.is_dir(),
                "rollback root is not a directory: {}",
                root.display()
            );
            let canonical = root
                .canonicalize()
                .context("failed to canonicalize rollback root")?;
            ensure_existing_rollback_directory(&canonical, "canonical rollback root")?;
            Ok(Some(canonical))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect rollback root {}", root.display())),
    }
}

fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
    ensure_not_link_or_reparse(source, "rollback snapshot")?;
    let source = source
        .canonicalize()
        .with_context(|| format!("failed to canonicalize source {}", source.display()))?;
    ensure_existing_rollback_directory(&source, "canonical rollback snapshot")?;
    ensure_not_link_or_reparse(destination, "rollback destination")?;
    create_dir_all_checked(destination, "rollback destination")?;
    let destination = destination.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize destination {}",
            destination.display()
        )
    })?;
    ensure_existing_rollback_directory(&destination, "canonical rollback destination")?;
    for entry in walkdir::WalkDir::new(&source) {
        let entry = entry?;
        ensure_not_link_or_reparse(entry.path(), "rollback snapshot")?;
        anyhow::ensure!(
            !entry.file_type().is_symlink(),
            "refusing to copy symbolic link from rollback snapshot: {}",
            entry.path().display()
        );
        let relative = entry.path().strip_prefix(&source)?;
        let target = destination.join(relative);
        anyhow::ensure!(
            target.starts_with(&destination),
            "rollback copy target escaped destination"
        );
        ensure_existing_path_chain_not_link(&target, &destination, "rollback destination")?;
        if entry.file_type().is_dir() {
            create_dir_all_checked(&target, "rollback destination")?;
        } else {
            if let Some(parent) = target.parent() {
                ensure_existing_path_chain_not_link(parent, &destination, "rollback destination")?;
                create_dir_all_checked(parent, "rollback destination")?;
            }
            copy_file_staged(entry.path(), &target, &destination, "rollback destination")?;
        }
    }
    Ok(())
}

fn ensure_existing_rollback_directory(path: &Path, label: &str) -> Result<()> {
    ensure_not_link_or_reparse(path, label)?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "{label} is not a directory: {}",
        path.display()
    );
    ensure_not_link_or_reparse(path, label)?;
    Ok(())
}

fn canonical_install_dir(install_dir: &Path) -> Result<PathBuf> {
    validate_install_dir_path_text(install_dir)?;
    create_dir_all_checked(install_dir, "install directory")?;
    let canonical = install_dir.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize install dir {}",
            install_dir.display()
        )
    })?;
    ensure_existing_install_directory(&canonical, "canonical rollback install directory")?;
    anyhow::ensure!(
        canonical.parent().is_some(),
        "refusing to restore rollback to filesystem root"
    );
    Ok(canonical)
}

fn ensure_existing_install_directory(path: &Path, label: &str) -> Result<()> {
    ensure_not_link_or_reparse(path, label)?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "{label} is not a directory: {}",
        path.display()
    );
    ensure_not_link_or_reparse(path, label)?;
    Ok(())
}

fn validate_install_dir_path_text(path: &Path) -> Result<()> {
    let text = path.as_os_str().to_string_lossy();
    anyhow::ensure!(
        !text.contains('\0'),
        "install directory contains NUL: {}",
        path.display()
    );
    anyhow::ensure!(
        !install_dir_path_has_parent_traversal(path),
        "install directory must not contain parent traversal: {}",
        path.display()
    );
    Ok(())
}

fn install_dir_path_has_parent_traversal(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn canonical_snapshot_dir(snapshot: &Path) -> Result<PathBuf> {
    let root = rollback_root()?;
    create_dir_all_checked(&root, "rollback root")?;
    let root = root
        .canonicalize()
        .context("failed to canonicalize rollback root")?;
    ensure_existing_rollback_directory(&root, "canonical rollback root")?;
    let snapshot = snapshot
        .canonicalize()
        .with_context(|| format!("failed to canonicalize snapshot {}", snapshot.display()))?;
    anyhow::ensure!(
        snapshot.starts_with(&root),
        "rollback snapshot is outside the Avorax rollback root"
    );
    ensure_existing_rollback_directory(&snapshot, "canonical rollback snapshot")?;
    Ok(snapshot)
}

fn safe_snapshot_name(value: &str) -> Result<String> {
    let trimmed = value.trim();
    anyhow::ensure!(!trimmed.is_empty(), "rollback snapshot version is empty");
    anyhow::ensure!(
        trimmed != ".",
        "rollback snapshot version must not be current directory"
    );
    anyhow::ensure!(
        trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')),
        "rollback snapshot version contains unsafe characters"
    );
    anyhow::ensure!(
        !trimmed.contains(".."),
        "rollback snapshot version must not contain parent traversal"
    );
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    #[test]
    fn snapshot_version_rejects_traversal() {
        assert!(safe_snapshot_name("0.2.16").is_ok());
        assert!(safe_snapshot_name(".").is_err());
        assert!(safe_snapshot_name("../escape").is_err());
        assert!(safe_snapshot_name("0.2/escape").is_err());
    }

    #[test]
    fn rollback_install_dir_rejects_unsafe_text_before_creation() {
        let nul_error = canonical_install_dir(Path::new("install\0dir"))
            .unwrap_err()
            .to_string();
        assert!(nul_error.contains("install directory contains NUL"));

        let dir = tempdir().unwrap();
        let traversal_dir = dir.path().join("install").join("..").join("other");
        let traversal_error = canonical_install_dir(&traversal_dir)
            .unwrap_err()
            .to_string();
        assert!(traversal_error.contains("install directory must not contain parent traversal"));
    }

    #[test]
    fn missing_rollback_dir_cleanup_is_noop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing-rollback-dir");

        remove_existing_rollback_dir(&path, "rollback snapshot").unwrap();
    }

    #[test]
    fn rollback_dir_cleanup_rejects_non_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback-file");
        std::fs::write(&path, b"not a directory").unwrap();

        let error = remove_existing_rollback_dir(&path, "rollback snapshot")
            .unwrap_err()
            .to_string();

        assert!(error.contains("not a directory"));
    }

    #[test]
    fn rollback_root_enumeration_accepts_absence_and_canonical_directory() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("rollback-root");

        assert!(rollback_root_for_enumeration(&root).unwrap().is_none());
        std::fs::create_dir_all(&root).unwrap();
        let canonical = rollback_root_for_enumeration(&root).unwrap().unwrap();
        assert_eq!(canonical, root.canonicalize().unwrap());
    }

    #[test]
    fn rollback_root_enumeration_rejects_non_directory() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("rollback-root");
        std::fs::write(&root, b"not a directory").unwrap();

        let error = rollback_root_for_enumeration(&root)
            .unwrap_err()
            .to_string();

        assert!(error.contains("rollback root is not a directory"));
    }

    #[test]
    fn required_item_rejects_wrong_kind_with_metadata_check() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("Avorax.exe");
        std::fs::create_dir_all(&source).unwrap();
        let item = RollbackItem {
            name: "Avorax.exe",
            kind: RollbackItemKind::File,
        };

        let error = ensure_required_item(&source, &item, "rollback source")
            .unwrap_err()
            .to_string();

        assert!(error.contains("rollback source missing required file Avorax.exe"));
    }

    #[cfg(unix)]
    #[test]
    fn rollback_dir_cleanup_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real = dir.path().join("real-rollback-dir");
        let linked = dir.path().join("linked-rollback-dir");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&real, &linked).unwrap();

        let error = remove_existing_rollback_dir(&linked, "rollback snapshot")
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"));
    }

    #[cfg(unix)]
    #[test]
    fn rollback_root_presence_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real = dir.path().join("real-rollback-root");
        let linked = dir.path().join("rollback-root");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&real, &linked).unwrap();

        let error = rollback_root_for_enumeration(&linked)
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn rollback_uses_non_following_presence_checks() {
        let source = include_str!("rollback.rs");
        let old_snapshot_probe = ["snapshot", ".exists()"].join("");
        let old_root_probe = ["root", ".exists()"].join("");
        let old_target_probe = ["target", ".exists()"].join("");
        let old_file_probe = ["source", ".is_file()"].join("");
        let old_dir_probe = ["source", ".is_dir()"].join("");

        assert!(source.contains("fn remove_existing_rollback_dir"));
        assert!(source.contains("fn rollback_root_for_enumeration"));
        assert!(source.contains("std::fs::symlink_metadata(path)"));
        assert!(source.contains("std::fs::symlink_metadata(root)"));
        assert!(source.contains("std::fs::symlink_metadata(source)"));
        assert!(!source.contains(&old_snapshot_probe));
        assert!(!source.contains(&old_root_probe));
        assert!(!source.contains(&old_target_probe));
        assert!(!source.contains(&old_file_probe));
        assert!(!source.contains(&old_dir_probe));
    }

    #[test]
    fn restore_latest_revalidates_canonical_root_before_enumeration() {
        let source = include_str!("rollback.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let latest_source = &production[production.find("pub fn restore_latest_snapshot").unwrap()
            ..production.find("pub fn restore_snapshot").unwrap()];
        let helper_source = &production[production.find("fn rollback_root_for_enumeration").unwrap()
            ..production.find("fn copy_dir").unwrap()];

        assert!(latest_source.contains("if let Some(root) = rollback_root_for_enumeration(&root)?"));
        assert!(
            latest_source
                .find("rollback_root_for_enumeration(&root)?")
                .unwrap()
                < latest_source.find("std::fs::read_dir(&root)").unwrap()
        );
        assert!(helper_source.contains(".canonicalize()"));
        assert!(helper_source.contains(
            "ensure_existing_rollback_directory(&canonical, \"canonical rollback root\")?"
        ));
        assert!(helper_source.contains("Ok(Some(canonical))"));
        assert!(helper_source.contains("ErrorKind::NotFound => Ok(None)"));
    }

    #[test]
    fn restore_revalidates_install_root_before_copying_items() {
        let source = include_str!("rollback.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let restore_source = &production[production.find("pub fn restore_snapshot").unwrap()
            ..production.find("fn ensure_required_item").unwrap()];
        let install_source = &production[production.find("fn canonical_install_dir").unwrap()
            ..production
                .find("fn validate_install_dir_path_text")
                .unwrap()];
        let helper_source = &production[production
            .find("fn ensure_existing_install_directory")
            .unwrap()
            ..production
                .find("fn validate_install_dir_path_text")
                .unwrap()];

        assert!(restore_source
            .contains("ensure_existing_install_directory(&install_dir, \"rollback install directory before restore\")?"));
        assert!(
            restore_source
                .find("ensure_existing_install_directory(&install_dir, \"rollback install directory before restore\")?")
                .unwrap()
                < restore_source.find("for item in ROLLBACK_ITEMS").unwrap()
        );
        assert!(install_source.contains(
            "ensure_existing_install_directory(&canonical, \"canonical rollback install directory\")?"
        ));
        assert!(helper_source.contains("std::fs::symlink_metadata(path)"));
        assert!(helper_source.contains("metadata.is_dir()"));
        assert!(
            helper_source
                .matches("ensure_not_link_or_reparse(path, label)?")
                .count()
                >= 2
        );
    }

    #[test]
    fn canonical_snapshot_revalidates_root_and_snapshot_after_canonicalize() {
        let source = include_str!("rollback.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let snapshot_source = &production[production.find("fn canonical_snapshot_dir").unwrap()
            ..production.find("fn safe_snapshot_name").unwrap()];

        assert!(snapshot_source
            .contains("ensure_existing_rollback_directory(&root, \"canonical rollback root\")?"));
        assert!(snapshot_source.contains(
            "ensure_existing_rollback_directory(&snapshot, \"canonical rollback snapshot\")?"
        ));
        assert!(
            snapshot_source
                .find("ensure_existing_rollback_directory(&root, \"canonical rollback root\")?")
                .unwrap()
                > snapshot_source
                    .find("failed to canonicalize rollback root")
                    .unwrap()
        );
        assert!(
            snapshot_source
                .find("snapshot.starts_with(&root)")
                .unwrap()
                < snapshot_source
                    .find("ensure_existing_rollback_directory(&snapshot, \"canonical rollback snapshot\")?")
                    .unwrap()
        );
    }

    #[test]
    fn restore_rejects_snapshot_outside_rollback_root() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let install = dir.path().join("install");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let error = restore_snapshot(&outside, &install).unwrap_err();
        assert!(error
            .to_string()
            .contains("rollback snapshot is outside the Avorax rollback root"));
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }

    #[test]
    fn restore_latest_ignores_unsafe_snapshot_names() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let install = dir.path().join("install");
        let unsafe_snapshot = rollback_root().unwrap().join("bad name");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&unsafe_snapshot).unwrap();

        let error = restore_latest_snapshot(&install).unwrap_err().to_string();
        assert!(error.contains("No Avorax rollback snapshot is available"));
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_latest_rejects_linked_snapshot_entries() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let root = rollback_root().unwrap();
        let install = dir.path().join("install");
        let real_snapshot = dir.path().join("real-snapshot");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&real_snapshot).unwrap();
        symlink(&real_snapshot, root.join("0.2.16")).unwrap();

        let error = restore_latest_snapshot(&install).unwrap_err().to_string();
        assert!(error.contains("rollback snapshot must not be a symbolic link"));
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }

    #[cfg(unix)]
    #[test]
    fn copy_dir_rejects_linked_snapshot_entries() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let source = dir.path().join("snapshot");
        let destination = dir.path().join("restore");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, source.join("linked-engine")).unwrap();

        let error = copy_dir(&source, &destination).unwrap_err().to_string();
        assert!(error.contains("rollback snapshot must not be a symbolic link"));
    }

    #[test]
    fn copy_dir_revalidates_canonicalized_roots() {
        let source = include_str!("rollback.rs");
        let start = source.find("fn copy_dir").unwrap();
        let end = source
            .find("fn ensure_existing_rollback_directory")
            .unwrap();
        let copy_source = &source[start..end];
        let helper_source = &source[end..source.find("fn canonical_install_dir").unwrap()];

        assert!(
            copy_source.find(".canonicalize()").unwrap()
                < copy_source
                    .find("ensure_existing_rollback_directory(&source, \"canonical rollback snapshot\")?")
                    .unwrap()
        );
        assert!(
            copy_source
                .find("ensure_existing_rollback_directory(&destination, \"canonical rollback destination\")?")
                .unwrap()
                > copy_source.rfind(".canonicalize()").unwrap()
        );
        assert!(helper_source.contains("std::fs::symlink_metadata(path)"));
        assert!(helper_source.contains("metadata.is_dir()"));
        assert!(
            helper_source
                .matches("ensure_not_link_or_reparse(path, label)?")
                .count()
                >= 2
        );
    }

    #[test]
    fn create_snapshot_rejects_missing_required_component() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let install = dir.path().join("install");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::write(install.join("Avorax.exe"), b"safe rollback fixture").unwrap();
        std::fs::write(
            install.join("avorax_core_service.exe"),
            b"safe rollback fixture",
        )
        .unwrap();
        std::fs::write(
            install.join("avorax_guard_service.exe"),
            b"safe rollback fixture",
        )
        .unwrap();

        let error = create_snapshot(&install, "0.2.16").unwrap_err().to_string();
        assert!(error.contains("rollback source missing required directory engine"));
        assert_eq!(
            std::fs::symlink_metadata(rollback_root().unwrap().join("0.2.16"))
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }

    #[test]
    fn restore_rejects_partial_snapshot() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let install = dir.path().join("install");
        let snapshot = rollback_root().unwrap().join("0.2.16");
        std::fs::create_dir_all(install.join("engine")).unwrap();
        std::fs::create_dir_all(snapshot.join("engine")).unwrap();
        std::fs::write(snapshot.join("Avorax.exe"), b"safe rollback fixture").unwrap();
        std::fs::write(snapshot.join("engine/defs.zsig"), b"safe rollback fixture").unwrap();
        std::fs::write(install.join("Avorax.exe"), b"current app fixture").unwrap();
        std::fs::write(
            install.join("avorax_core_service.exe"),
            b"current core fixture",
        )
        .unwrap();
        std::fs::write(
            install.join("avorax_guard_service.exe"),
            b"current guard fixture",
        )
        .unwrap();
        std::fs::write(
            install.join("engine/current.asig"),
            b"current engine fixture",
        )
        .unwrap();

        let error = restore_snapshot(&snapshot, &install)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rollback snapshot missing required file avorax_core_service.exe"));
        assert_eq!(
            std::fs::read(install.join("Avorax.exe")).unwrap(),
            b"current app fixture"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_core_service.exe")).unwrap(),
            b"current core fixture"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_guard_service.exe")).unwrap(),
            b"current guard fixture"
        );
        assert_eq!(
            std::fs::read(install.join("engine/current.asig")).unwrap(),
            b"current engine fixture"
        );
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }

    #[test]
    fn restore_rejects_wrong_kind_service_destination_before_copying_files() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let install = dir.path().join("install");
        let snapshot = rollback_root().unwrap().join("0.2.16");
        std::fs::create_dir_all(snapshot.join("engine")).unwrap();
        std::fs::write(snapshot.join("Avorax.exe"), b"rollback app fixture").unwrap();
        std::fs::write(
            snapshot.join("avorax_core_service.exe"),
            b"rollback core fixture",
        )
        .unwrap();
        std::fs::write(
            snapshot.join("avorax_guard_service.exe"),
            b"rollback guard fixture",
        )
        .unwrap();
        std::fs::write(snapshot.join("engine/rollback.asig"), b"rollback engine").unwrap();

        std::fs::create_dir_all(install.join("engine")).unwrap();
        std::fs::create_dir_all(install.join("avorax_core_service.exe")).unwrap();
        std::fs::write(install.join("Avorax.exe"), b"current app fixture").unwrap();
        std::fs::write(
            install.join("avorax_guard_service.exe"),
            b"current guard fixture",
        )
        .unwrap();
        std::fs::write(
            install.join("engine/current.asig"),
            b"current engine fixture",
        )
        .unwrap();

        let error = restore_snapshot(&snapshot, &install)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rollback destination target is not a regular file"));
        assert_eq!(
            std::fs::read(install.join("Avorax.exe")).unwrap(),
            b"current app fixture"
        );
        assert!(install.join("avorax_core_service.exe").is_dir());
        assert_eq!(
            std::fs::read(install.join("avorax_guard_service.exe")).unwrap(),
            b"current guard fixture"
        );
        assert_eq!(
            std::fs::read(install.join("engine/current.asig")).unwrap(),
            b"current engine fixture"
        );
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }

    #[test]
    fn restore_rejects_wrong_kind_engine_destination_before_copying_files() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let install = dir.path().join("install");
        let snapshot = rollback_root().unwrap().join("0.2.16");
        std::fs::create_dir_all(snapshot.join("engine")).unwrap();
        std::fs::create_dir_all(&install).unwrap();
        std::fs::write(snapshot.join("Avorax.exe"), b"rollback app fixture").unwrap();
        std::fs::write(
            snapshot.join("avorax_core_service.exe"),
            b"rollback core fixture",
        )
        .unwrap();
        std::fs::write(
            snapshot.join("avorax_guard_service.exe"),
            b"rollback guard fixture",
        )
        .unwrap();
        std::fs::write(snapshot.join("engine/rollback.asig"), b"rollback engine").unwrap();

        std::fs::write(install.join("Avorax.exe"), b"current app fixture").unwrap();
        std::fs::write(
            install.join("avorax_core_service.exe"),
            b"current core fixture",
        )
        .unwrap();
        std::fs::write(
            install.join("avorax_guard_service.exe"),
            b"current guard fixture",
        )
        .unwrap();
        std::fs::write(install.join("engine"), b"current engine file fixture").unwrap();

        let error = restore_snapshot(&snapshot, &install)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rollback destination target is not a directory"));
        assert_eq!(
            std::fs::read(install.join("Avorax.exe")).unwrap(),
            b"current app fixture"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_core_service.exe")).unwrap(),
            b"current core fixture"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_guard_service.exe")).unwrap(),
            b"current guard fixture"
        );
        assert_eq!(
            std::fs::read(install.join("engine")).unwrap(),
            b"current engine file fixture"
        );
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }

    #[test]
    fn restore_replaces_engine_via_staging_and_cleans_backup() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let install = dir.path().join("install");
        let snapshot = rollback_root().unwrap().join("0.2.16");
        std::fs::create_dir_all(snapshot.join("engine/signatures")).unwrap();
        std::fs::create_dir_all(install.join("engine/signatures")).unwrap();
        std::fs::create_dir_all(install.join("engine/obsolete")).unwrap();

        std::fs::write(snapshot.join("Avorax.exe"), b"rollback app fixture").unwrap();
        std::fs::write(
            snapshot.join("avorax_core_service.exe"),
            b"rollback core fixture",
        )
        .unwrap();
        std::fs::write(
            snapshot.join("avorax_guard_service.exe"),
            b"rollback guard fixture",
        )
        .unwrap();
        std::fs::write(
            snapshot.join("engine/signatures/rollback.asig"),
            b"rollback engine fixture",
        )
        .unwrap();

        std::fs::write(install.join("Avorax.exe"), b"current app fixture").unwrap();
        std::fs::write(
            install.join("avorax_core_service.exe"),
            b"current core fixture",
        )
        .unwrap();
        std::fs::write(
            install.join("avorax_guard_service.exe"),
            b"current guard fixture",
        )
        .unwrap();
        std::fs::write(
            install.join("engine/signatures/current.asig"),
            b"current engine fixture",
        )
        .unwrap();
        std::fs::write(
            install.join("engine/obsolete/old.model"),
            b"obsolete engine fixture",
        )
        .unwrap();

        restore_snapshot(&snapshot, &install).unwrap();

        assert_eq!(
            std::fs::read(install.join("engine/signatures/rollback.asig")).unwrap(),
            b"rollback engine fixture"
        );
        assert_eq!(
            std::fs::symlink_metadata(install.join("engine/signatures/current.asig"))
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            std::fs::symlink_metadata(install.join("engine/obsolete/old.model"))
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
        let leftover_siblings: Vec<_> = std::fs::read_dir(&install)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with(".engine.") && name.ends_with(".avorax-dir"))
            .collect();
        assert!(leftover_siblings.is_empty(), "{leftover_siblings:?}");
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }

    #[test]
    fn staged_directory_activation_rejects_existing_backup_path() {
        let dir = tempdir().unwrap();
        let install = dir.path().join("install");
        let destination = install.join("engine");
        let staging = install.join(".engine.test.staged.avorax-dir");
        let backup = install.join(".engine.test.backup.avorax-dir");
        std::fs::create_dir_all(destination.join("signatures")).unwrap();
        std::fs::create_dir_all(staging.join("signatures")).unwrap();
        std::fs::write(destination.join("signatures/current.asig"), b"current").unwrap();
        std::fs::write(staging.join("signatures/rollback.asig"), b"rollback").unwrap();
        std::fs::write(&backup, b"preexisting backup collision").unwrap();

        let error = activate_staged_restore_dir(&staging, &destination, &backup, &install)
            .unwrap_err()
            .to_string();

        assert!(error.contains("rollback destination backup already exists"));
        assert_eq!(
            std::fs::read(destination.join("signatures/current.asig")).unwrap(),
            b"current"
        );
        assert_eq!(
            std::fs::read(staging.join("signatures/rollback.asig")).unwrap(),
            b"rollback"
        );
    }

    #[test]
    fn restore_uses_staged_directory_activation_for_engine() {
        let source = include_str!("rollback.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let restore_source = &production[production.find("pub fn restore_snapshot").unwrap()
            ..production.find("fn preflight_restore_snapshot").unwrap()];
        let staged_helper_source =
            &production[production.find("fn replace_dir_from_snapshot").unwrap()
                ..production.find("fn ensure_required_item").unwrap()];
        let old_direct_restore = [
            "remove_existing_rollback_dir(&target, \"rollback destination\")?;",
            "copy_dir(&source, &target)?;",
        ]
        .join("\n");

        assert!(
            restore_source.contains("replace_dir_from_snapshot(&source, &target, &install_dir)?;")
        );
        assert!(!restore_source.contains(&old_direct_restore));
        assert!(staged_helper_source.contains("fn activate_staged_restore_dir"));
        assert!(staged_helper_source.contains("fn cleanup_restore_directory"));
        assert!(staged_helper_source.contains("fn ensure_restore_sibling_absent"));
        assert!(staged_helper_source.contains("fn allocate_restore_sibling_dir_path"));
        assert!(staged_helper_source.contains("std::fs::rename(destination, backup)"));
        assert!(staged_helper_source.contains("std::fs::rename(staging, destination)"));
        assert!(staged_helper_source
            .contains("ensure_restore_sibling_absent(backup, \"rollback destination backup\")?"));
        assert!(staged_helper_source
            .contains("ensure_restore_target_within_install(&candidate, install_dir)?"));
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_symbolic_link_destination_parent() {
        use std::os::unix::fs::symlink;

        let _lock = env_lock();
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("AVORAX_DATA_DIR", dir.path().join("data"));
        }
        let install = dir.path().join("install");
        let outside = dir.path().join("outside");
        let snapshot = rollback_root().unwrap().join("0.2.16");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(snapshot.join("engine")).unwrap();
        std::fs::write(snapshot.join("engine/defs.zsig"), b"safe rollback fixture").unwrap();
        symlink(&outside, install.join("engine")).unwrap();

        let error = restore_snapshot(&snapshot, &install)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not be a symbolic link"));
        unsafe {
            std::env::remove_var("AVORAX_DATA_DIR");
        }
    }
}
