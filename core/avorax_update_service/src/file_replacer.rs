use anyhow::{Context, Result};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::path_safety::{
    copy_file_staged, create_dir_all_checked, ensure_existing_path_chain_not_link,
    ensure_not_link_or_reparse,
};

pub fn copy_tree_overwrite(source: &Path, destination: &Path) -> Result<()> {
    ensure_not_link_or_reparse(source, "update source")?;
    let source = source
        .canonicalize()
        .with_context(|| format!("failed to canonicalize source {}", source.display()))?;
    ensure_existing_update_directory(&source, "canonical update source")?;
    ensure_not_link_or_reparse(destination, "update destination")?;
    create_dir_all_checked(destination, "update destination")?;
    let destination = destination.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize destination {}",
            destination.display()
        )
    })?;
    ensure_existing_update_directory(&destination, "canonical update destination")?;
    for entry in walkdir::WalkDir::new(&source) {
        let entry = entry?;
        ensure_not_link_or_reparse(entry.path(), "update source")?;
        anyhow::ensure!(
            !entry.file_type().is_symlink(),
            "refusing to copy symbolic link from update payload: {}",
            entry.path().display()
        );
        let relative = entry.path().strip_prefix(&source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let target = destination.join(relative);
        anyhow::ensure!(
            target.starts_with(&destination),
            "update copy target escaped destination"
        );
        ensure_existing_path_chain_not_link(&target, &destination, "update destination")?;
        if entry.file_type().is_dir() {
            create_dir_all_checked(&target, "update destination")?;
        } else {
            if let Some(parent) = target.parent() {
                ensure_existing_path_chain_not_link(parent, &destination, "update destination")?;
                create_dir_all_checked(parent, "update destination")?;
            }
            copy_file_staged(entry.path(), &target, &destination, "update destination")?;
        }
    }
    Ok(())
}

pub fn replace_tree_atomically(source: &Path, destination: &Path, boundary: &Path) -> Result<()> {
    ensure_not_link_or_reparse(boundary, "atomic tree replacement boundary")?;
    ensure_existing_update_directory(boundary, "atomic tree replacement boundary")?;
    ensure_existing_path_chain_not_link(
        destination,
        boundary,
        "atomic tree replacement destination",
    )?;
    let parent = destination.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "atomic tree replacement destination has no parent: {}",
            destination.display()
        )
    })?;
    ensure_existing_path_chain_not_link(parent, boundary, "atomic tree replacement parent")?;
    create_dir_all_checked(parent, "atomic tree replacement parent")?;

    let staging = allocate_tree_sibling(destination, boundary, "staging")?;
    let backup = allocate_tree_sibling(destination, boundary, "backup")?;
    if let Err(error) = copy_tree_overwrite(source, &staging) {
        cleanup_tree_sibling(&staging, "atomic tree replacement staging").with_context(|| {
            format!(
                "failed to clean atomic tree replacement staging {} after copy failure: {error:#}",
                staging.display()
            )
        })?;
        return Err(error);
    }

    if let Err(error) = activate_replacement_tree(&staging, destination, &backup, boundary) {
        cleanup_tree_sibling(&staging, "atomic tree replacement staging").with_context(|| {
            format!(
                "failed to clean atomic tree replacement staging {} after activation failure: {error:#}",
                staging.display()
            )
        })?;
        return Err(error);
    }
    Ok(())
}

fn activate_replacement_tree(
    staging: &Path,
    destination: &Path,
    backup: &Path,
    boundary: &Path,
) -> Result<()> {
    ensure_existing_path_chain_not_link(staging, boundary, "atomic tree staging")?;
    ensure_existing_update_directory(staging, "atomic tree staging")?;
    ensure_existing_path_chain_not_link(destination, boundary, "atomic tree destination")?;
    ensure_existing_path_chain_not_link(backup, boundary, "atomic tree backup")?;
    ensure_tree_sibling_absent(backup, "atomic tree backup")?;

    let destination_exists = match std::fs::symlink_metadata(destination) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(destination, "atomic tree destination")?;
            anyhow::ensure!(
                metadata.is_dir(),
                "atomic tree destination is not a directory: {}",
                destination.display()
            );
            true
        }
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect atomic tree destination {}",
                    destination.display()
                )
            });
        }
    };

    if destination_exists {
        std::fs::rename(destination, backup).with_context(|| {
            format!(
                "failed to move atomic tree destination {} to backup {}",
                destination.display(),
                backup.display()
            )
        })?;
    }

    if let Err(error) = std::fs::rename(staging, destination).with_context(|| {
        format!(
            "failed to activate atomic tree staging {} as {}",
            staging.display(),
            destination.display()
        )
    }) {
        if destination_exists {
            if let Err(restore_error) = std::fs::rename(backup, destination) {
                return Err(error).context(format!(
                    "failed to restore atomic tree backup {} after activation failure: {restore_error}",
                    backup.display()
                ));
            }
        }
        return Err(error);
    }

    if destination_exists {
        cleanup_tree_sibling(backup, "atomic tree backup")?;
    }
    Ok(())
}

fn allocate_tree_sibling(destination: &Path, boundary: &Path, role: &str) -> Result<PathBuf> {
    let parent = destination.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "atomic tree replacement destination has no parent: {}",
            destination.display()
        )
    })?;
    let name = destination
        .file_name()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "atomic tree replacement destination has no name: {}",
                destination.display()
            )
        })?
        .to_string_lossy();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .context("failed to read time for atomic tree replacement")?;
    for attempt in 0..16 {
        let candidate = parent.join(format!(
            ".{name}.{}.{}.{}.{}.avorax-dir",
            std::process::id(),
            unique,
            attempt,
            role
        ));
        anyhow::ensure!(
            candidate.starts_with(boundary),
            "atomic tree replacement sibling escaped boundary: {}",
            candidate.display()
        );
        ensure_existing_path_chain_not_link(&candidate, boundary, "atomic tree sibling")?;
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(candidate),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect atomic tree sibling {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    anyhow::bail!(
        "could not allocate atomic tree replacement {role} path for {}",
        destination.display()
    )
}

fn cleanup_tree_sibling(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(path, label)?;
            anyhow::ensure!(
                metadata.is_dir(),
                "{label} is not a directory: {}",
                path.display()
            );
            crate::path_safety::remove_dir_all_checked(path, label)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_tree_sibling_absent(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => anyhow::bail!("{label} already exists: {}", path.display()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn ensure_existing_update_directory(path: &Path, label: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn copy_tree_rejects_symbolic_link_destination_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let real_destination = dir.path().join("real-destination");
        let linked_destination = dir.path().join("linked-destination");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("Avorax.exe"), b"safe update fixture").unwrap();
        std::fs::create_dir_all(&real_destination).unwrap();
        symlink(&real_destination, &linked_destination).unwrap();

        let error = copy_tree_overwrite(&source, &linked_destination)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not be a symbolic link"));
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_rejects_symbolic_link_destination_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(source.join("engine")).unwrap();
        std::fs::write(source.join("engine/defs.zsig"), b"safe update fixture").unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, destination.join("engine")).unwrap();

        let error = copy_tree_overwrite(&source, &destination)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not be a symbolic link"));
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_rejects_symbolic_link_source_entry() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, source.join("linked-payload")).unwrap();

        let error = copy_tree_overwrite(&source, &destination)
            .unwrap_err()
            .to_string();
        assert!(error.contains("update source must not be a symbolic link"));
    }

    #[test]
    fn copy_tree_revalidates_canonicalized_roots() {
        let source = include_str!("file_replacer.rs");
        let start = source.find("pub fn copy_tree_overwrite").unwrap();
        let end = source.find("fn ensure_existing_update_directory").unwrap();
        let copy_source = &source[start..end];
        let helper_source = &source[end..source.find("#[cfg(test)]").unwrap()];

        assert!(
            copy_source.find(".canonicalize()").unwrap()
                < copy_source
                    .find("ensure_existing_update_directory(&source, \"canonical update source\")?")
                    .unwrap()
        );
        assert!(
            copy_source
                .find("ensure_existing_update_directory(&destination, \"canonical update destination\")?")
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
    fn copy_tree_uses_staged_file_activation() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(source.join("Avorax.exe"), b"new safe update fixture").unwrap();
        std::fs::write(destination.join("Avorax.exe"), b"old fixture").unwrap();

        copy_tree_overwrite(&source, &destination).unwrap();

        assert_eq!(
            std::fs::read(destination.join("Avorax.exe")).unwrap(),
            b"new safe update fixture"
        );
        assert_no_staged_update_files(&destination);
    }

    #[test]
    fn copy_tree_ignores_stale_staged_file_collision() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(source.join("Avorax.exe"), b"new safe update fixture").unwrap();
        std::fs::write(
            destination.join(".Avorax.exe.stale.0.0.avorax-part"),
            b"stale",
        )
        .unwrap();

        copy_tree_overwrite(&source, &destination).unwrap();

        assert_eq!(
            std::fs::read(destination.join("Avorax.exe")).unwrap(),
            b"new safe update fixture"
        );
        assert_eq!(
            std::fs::read(destination.join(".Avorax.exe.stale.0.0.avorax-part")).unwrap(),
            b"stale"
        );
    }

    #[test]
    fn copy_tree_cleans_staged_file_when_activation_fails() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(destination.join("Avorax.exe")).unwrap();
        std::fs::write(source.join("Avorax.exe"), b"new safe update fixture").unwrap();

        let error = copy_tree_overwrite(&source, &destination)
            .unwrap_err()
            .to_string();

        assert!(error.contains("target is not a regular file"));
        assert_no_staged_update_files(&destination);
    }

    #[test]
    fn atomic_tree_replacement_removes_files_missing_from_new_component() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let install = dir.path().join("install");
        let destination = install.join("engine/signatures");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(source.join("new.zsig"), b"new safe signature").unwrap();
        std::fs::write(destination.join("revoked.zsig"), b"revoked fixture").unwrap();

        replace_tree_atomically(&source, &destination, &install).unwrap();

        assert_eq!(
            std::fs::read(destination.join("new.zsig")).unwrap(),
            b"new safe signature"
        );
        assert!(!destination.join("revoked.zsig").exists());
        assert_no_tree_replacement_siblings(destination.parent().unwrap());
    }

    #[test]
    fn atomic_tree_replacement_rejects_non_directory_destination() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let install = dir.path().join("install");
        let destination = install.join("engine/signatures");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(source.join("new.zsig"), b"new safe signature").unwrap();
        std::fs::write(&destination, b"wrong destination kind").unwrap();

        let error = replace_tree_atomically(&source, &destination, &install)
            .unwrap_err()
            .to_string();

        assert!(error.contains("atomic tree destination is not a directory"));
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"wrong destination kind"
        );
        assert_no_tree_replacement_siblings(destination.parent().unwrap());
    }

    fn assert_no_tree_replacement_siblings(parent: &Path) {
        for entry in std::fs::read_dir(parent).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_string();
            assert!(
                !name.ends_with(".avorax-dir"),
                "atomic tree replacement left a sibling behind: {name}"
            );
        }
    }

    fn assert_no_staged_update_files(destination: &Path) {
        for entry in std::fs::read_dir(destination).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy();
            assert!(
                !name.ends_with(".avorax-part"),
                "staged update file was left behind: {}",
                path.display()
            );
        }
    }
}
