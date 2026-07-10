use anyhow::{Context, Result};
use std::path::Path;

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
