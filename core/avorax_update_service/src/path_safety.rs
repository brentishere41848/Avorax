use anyhow::{Context, Result};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_STAGED_FILE_COPY_BYTES: u64 = 1024 * 1024 * 1024;

pub fn create_dir_all_checked(path: &Path, label: &str) -> Result<()> {
    ensure_existing_ancestors_not_link(path, label)?;
    std::fs::create_dir_all(path)?;
    ensure_existing_ancestors_not_link(path, label)?;
    ensure_not_link_or_reparse(path, label)?;
    Ok(())
}

pub fn copy_file_staged(source: &Path, target: &Path, boundary: &Path, label: &str) -> Result<()> {
    let before_open = checked_staged_source_metadata(source, label)?;
    if let Some(parent) = target.parent() {
        ensure_existing_path_chain_not_link(parent, boundary, label)?;
        create_dir_all_checked(parent, label)?;
    }
    ensure_existing_path_chain_not_link(target, boundary, label)?;
    let temp_target = allocate_staged_temp_path(target, label)?;
    let mut input = File::open(source)
        .with_context(|| format!("failed to open {label} source {}", source.display()))?;
    let opened = input.metadata().with_context(|| {
        format!(
            "failed to inspect opened {label} source {}",
            source.display()
        )
    })?;
    let after_open = checked_staged_source_metadata(source, label)?;
    ensure_opened_staged_source_matches_checked_path(&before_open, &opened, &after_open, label)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_target)?;
    if let Err(error) = copy_staged_file_payload_limited(
        &mut input,
        &mut output,
        MAX_STAGED_FILE_COPY_BYTES,
        source,
    ) {
        drop(output);
        cleanup_staged_temp_file(&temp_target, label).with_context(|| {
            format!(
                "failed to clean up {label} staged temporary file {} after copy failure: {error}",
                temp_target.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = output.flush().and_then(|_| output.sync_all()) {
        drop(output);
        cleanup_staged_temp_file(&temp_target, label).with_context(|| {
            format!(
                "failed to clean up {label} staged temporary file {} after sync failure: {error}",
                temp_target.display()
            )
        })?;
        return Err(error.into());
    }
    drop(output);
    if let Err(error) = activate_staged_file(&temp_target, target, boundary, label) {
        cleanup_staged_temp_file(&temp_target, label).with_context(|| {
            format!(
                "failed to clean up {label} staged temporary file {} after activation failure: {error:#}",
                temp_target.display()
            )
        })?;
        return Err(error);
    }
    Ok(())
}

fn checked_staged_source_metadata(source: &Path, label: &str) -> Result<Metadata> {
    ensure_not_link_or_reparse(source, label)?;
    let metadata = std::fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect {label} source {}", source.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{label} source is not a regular file: {}",
        source.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_STAGED_FILE_COPY_BYTES,
        "{label} source exceeds the staged copy size limit: {}",
        source.display()
    );
    Ok(metadata)
}

#[cfg(unix)]
fn ensure_opened_staged_source_matches_checked_path(
    before_open: &Metadata,
    opened: &Metadata,
    after_open: &Metadata,
    label: &str,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    anyhow::ensure!(
        opened.is_file(),
        "opened {label} source is not a regular file"
    );
    anyhow::ensure!(
        before_open.dev() == opened.dev()
            && before_open.ino() == opened.ino()
            && after_open.dev() == opened.dev()
            && after_open.ino() == opened.ino(),
        "{label} source changed while opening"
    );
    Ok(())
}

#[cfg(windows)]
fn ensure_opened_staged_source_matches_checked_path(
    before_open: &Metadata,
    opened: &Metadata,
    after_open: &Metadata,
    label: &str,
) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    anyhow::ensure!(
        opened.is_file(),
        "opened {label} source is not a regular file"
    );
    anyhow::ensure!(
        before_open.file_size() == opened.file_size()
            && after_open.file_size() == opened.file_size()
            && before_open.last_write_time() == opened.last_write_time()
            && after_open.last_write_time() == opened.last_write_time()
            && before_open.creation_time() == opened.creation_time()
            && after_open.creation_time() == opened.creation_time()
            && before_open.file_attributes() == opened.file_attributes()
            && after_open.file_attributes() == opened.file_attributes(),
        "{label} source changed while opening"
    );
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_opened_staged_source_matches_checked_path(
    before_open: &Metadata,
    opened: &Metadata,
    after_open: &Metadata,
    label: &str,
) -> Result<()> {
    anyhow::ensure!(
        opened.is_file(),
        "opened {label} source is not a regular file"
    );
    anyhow::ensure!(
        before_open.len() == opened.len() && after_open.len() == opened.len(),
        "{label} source changed while opening"
    );
    Ok(())
}

pub fn write_bytes_staged(target: &Path, boundary: &Path, label: &str, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        ensure_existing_path_chain_not_link(parent, boundary, label)?;
        create_dir_all_checked(parent, label)?;
    }
    ensure_existing_path_chain_not_link(target, boundary, label)?;
    let temp_target = allocate_staged_temp_path(target, label)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_target)?;
    if let Err(error) = output.write_all(bytes) {
        drop(output);
        cleanup_staged_temp_file(&temp_target, label).with_context(|| {
            format!(
                "failed to clean up {label} staged temporary file {} after write failure: {error}",
                temp_target.display()
            )
        })?;
        return Err(error.into());
    }
    if let Err(error) = output.flush().and_then(|_| output.sync_all()) {
        drop(output);
        cleanup_staged_temp_file(&temp_target, label).with_context(|| {
            format!(
                "failed to clean up {label} staged temporary file {} after sync failure: {error}",
                temp_target.display()
            )
        })?;
        return Err(error.into());
    }
    drop(output);
    if let Err(error) = activate_staged_file(&temp_target, target, boundary, label) {
        cleanup_staged_temp_file(&temp_target, label).with_context(|| {
            format!(
                "failed to clean up {label} staged temporary file {} after activation failure: {error:#}",
                temp_target.display()
            )
        })?;
        return Err(error);
    }
    Ok(())
}

fn copy_staged_file_payload_limited<R: Read, W: Write>(
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
            .ok_or_else(|| anyhow::anyhow!("staged file copy size overflow"))?;
        if total > limit {
            anyhow::bail!(
                "staged file copy {} exceeds the copy size limit",
                source.display()
            );
        }
        output.write_all(&buffer[..read])?;
    }
}

fn cleanup_staged_temp_file(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_not_link_or_reparse(path, label)?;
            anyhow::ensure!(
                metadata.is_file(),
                "{label} staged temporary cleanup target is not a regular file: {}",
                path.display()
            );
            std::fs::remove_file(path).with_context(|| {
                format!(
                    "failed to remove {label} staged temporary file {}",
                    path.display()
                )
            })
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect {label} staged temporary file {} before cleanup",
                path.display()
            )
        }),
    }
}

pub fn remove_dir_all_checked(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_dir(),
        "{label} is not a directory: {}",
        path.display()
    );
    ensure_not_link_or_reparse(path, label)?;
    std::fs::remove_dir_all(path)?;
    Ok(())
}

// Source-contract tests intentionally precede the lower-level path-chain helpers.
#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn staged_temp_cleanup_failures_are_reported() {
        let source = include_str!("path_safety.rs");
        let copy_start = source.find("pub fn copy_file_staged").unwrap();
        let copy_end = source.find("pub fn write_bytes_staged").unwrap();
        let copy_source = &source[copy_start..copy_end];
        let write_start = copy_end;
        let write_end = source.find("pub fn remove_dir_all_checked").unwrap();
        let write_source = &source[write_start..write_end];
        let helper_start = source.find("fn copy_staged_file_payload_limited").unwrap();
        let helper_end = source.find("fn cleanup_staged_temp_file").unwrap();
        let helper_source = &source[helper_start..helper_end];
        let ignored_cleanup = ["let _ = std::fs::remove_", "file(&temp_target);"].concat();
        let old_copy_pattern = ["std::io::", "copy(&mut input, &mut output)"].concat();

        assert!(source.contains("fn cleanup_staged_temp_file"));
        assert!(source.contains("const MAX_STAGED_FILE_COPY_BYTES"));
        assert!(copy_source.contains("copy_staged_file_payload_limited"));
        assert!(copy_source.contains("MAX_STAGED_FILE_COPY_BYTES"));
        assert!(helper_source.contains("let mut buffer = [0_u8; 64 * 1024]"));
        assert!(helper_source.contains("total > limit"));
        assert!(helper_source.contains("output.write_all(&buffer[..read])"));
        assert!(copy_source.contains("after copy failure"));
        assert!(copy_source.contains("after sync failure"));
        assert!(copy_source.contains("after activation failure"));
        assert!(write_source.contains("after write failure"));
        assert!(write_source.contains("after sync failure"));
        assert!(write_source.contains("after activation failure"));
        assert!(!copy_source.contains(&ignored_cleanup));
        assert!(!copy_source.contains(&old_copy_pattern));
        assert!(!write_source.contains(&ignored_cleanup));
    }

    #[test]
    fn staged_temp_cleanup_rejects_non_regular_targets() {
        let dir = tempdir().unwrap();
        let temp_target = dir.path().join(".Avorax.exe.cleanup.avorax-part");
        std::fs::create_dir_all(&temp_target).unwrap();

        let error = cleanup_staged_temp_file(&temp_target, "test target")
            .unwrap_err()
            .to_string();

        assert!(error.contains("staged temporary cleanup target is not a regular file"));
    }

    #[test]
    fn staged_copy_rechecks_source_metadata_after_open_before_copy() {
        let source = include_str!("path_safety.rs");
        let copy_start = source.find("pub fn copy_file_staged").unwrap();
        let copy_end = source.find("pub fn write_bytes_staged").unwrap();
        let copy_source = &source[copy_start..copy_end];

        assert!(source.contains("fn checked_staged_source_metadata"));
        assert!(source.contains("fn ensure_opened_staged_source_matches_checked_path"));
        assert!(source.contains("source is not a regular file"));
        assert!(source.contains("source exceeds the staged copy size limit"));
        assert!(source.contains("source changed while opening"));
        assert!(copy_source
            .contains("let before_open = checked_staged_source_metadata(source, label)?"));
        assert!(copy_source.contains("let opened = input.metadata()"));
        assert!(
            copy_source.contains("let after_open = checked_staged_source_metadata(source, label)?")
        );
        assert!(copy_source.contains(
            "ensure_opened_staged_source_matches_checked_path(&before_open, &opened, &after_open, label)?"
        ));
        assert!(
            copy_source
                .find("ensure_opened_staged_source_matches_checked_path")
                .unwrap()
                < copy_source
                    .find("copy_staged_file_payload_limited(")
                    .unwrap()
        );
    }

    #[test]
    fn staged_temp_timestamp_errors_are_reported() {
        let source = include_str!("path_safety.rs");
        let start = source.rfind("fn staged_temp_path").unwrap();
        let end = source[start..]
            .find("fn activate_staged_file")
            .map(|offset| start + offset)
            .unwrap();
        let temp_source = &source[start..end];

        assert!(temp_source.contains("failed to read system time for staged temporary file"));
        assert!(!temp_source.contains(".unwrap_or_default()"));
    }

    #[test]
    fn staged_activation_replaces_existing_regular_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("Avorax.exe");
        let temp_target = dir.path().join(".Avorax.exe.test.0.avorax-part");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&temp_target, b"new").unwrap();

        activate_staged_file(&temp_target, &target, dir.path(), "test target").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!temp_target.exists());
    }

    #[test]
    fn staged_activation_rejects_directory_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("Avorax.exe");
        let temp_target = dir.path().join(".Avorax.exe.test.0.avorax-part");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(&temp_target, b"new").unwrap();

        let error = activate_staged_file(&temp_target, &target, dir.path(), "test target")
            .unwrap_err()
            .to_string();

        assert!(error.contains("target is not a regular file"));
    }

    #[test]
    fn staged_activation_rejects_non_regular_temp_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("Avorax.exe");
        let temp_target = dir.path().join(".Avorax.exe.test.0.avorax-part");
        std::fs::create_dir_all(&temp_target).unwrap();

        let error = activate_staged_file(&temp_target, &target, dir.path(), "test target")
            .unwrap_err()
            .to_string();

        assert!(error.contains("staged temporary file is not a regular file"));
    }

    #[test]
    fn staged_activation_uses_non_following_target_probe() {
        let source = include_str!("path_safety.rs");
        let start = source.rfind("fn activate_staged_file").unwrap();
        let end = source[start..]
            .find("pub fn ensure_not_link_or_reparse")
            .map(|offset| start + offset)
            .unwrap();
        let activation_source = &source[start..end];
        let old_probe = ["target", ".exists()"].join("");

        assert!(source.contains("fn staged_target_file_present"));
        assert!(source.contains("fn ensure_staged_temp_file_ready"));
        assert!(activation_source.contains("ensure_staged_temp_file_ready(temp_target, label)?"));
        assert!(activation_source.contains("staged_target_file_present(target, label)?"));
        assert!(activation_source.contains("target still exists after removal"));
        assert!(source.contains("std::fs::symlink_metadata(target)"));
        assert!(!activation_source.contains(&old_probe));
    }

    #[test]
    fn staged_activation_rechecks_parent_chain_after_target_removal_before_rename() {
        let source = include_str!("path_safety.rs");
        let start = source.rfind("fn activate_staged_file").unwrap();
        let end = source[start..]
            .find("fn ensure_staged_temp_file_ready")
            .map(|offset| start + offset)
            .unwrap();
        let activation_source = &source[start..end];

        assert!(activation_source.contains("if let Some(parent) = target.parent()"));
        assert!(activation_source
            .contains("ensure_existing_path_chain_not_link(parent, boundary, label)?"));
        assert!(
            activation_source
                .find("target still exists after removal")
                .unwrap()
                < activation_source
                    .find("ensure_existing_path_chain_not_link(parent, boundary, label)?")
                    .unwrap()
        );
        assert!(
            activation_source
                .find("ensure_existing_path_chain_not_link(parent, boundary, label)?")
                .unwrap()
                < activation_source
                    .find("std::fs::rename(temp_target, target)?")
                    .unwrap()
        );
    }

    #[test]
    fn missing_link_or_reparse_check_target_is_absent() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");

        ensure_not_link_or_reparse(&missing, "test path").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn link_or_reparse_check_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::write(&target, b"safe fixture").unwrap();
        symlink(&target, &link).unwrap();

        let error = ensure_not_link_or_reparse(&link, "test path")
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn link_or_reparse_checks_do_not_treat_inspection_errors_as_absent() {
        let source = include_str!("path_safety.rs");
        let start = source.rfind("pub fn ensure_not_link_or_reparse").unwrap();
        let end = source[start..]
            .find("pub fn ensure_existing_path_chain_not_link")
            .map(|offset| start + offset)
            .unwrap();
        let helper_source = &source[start..end];
        let old_probe = [
            "let Ok(metadata) = std::fs::symlink_",
            "metadata(path) else",
        ]
        .concat();
        let old_ancestor_probe = ["std::fs::symlink_metadata(&current)", ".is_ok()"].concat();

        assert!(helper_source.contains("ErrorKind::NotFound => return Ok(())"));
        assert!(helper_source.contains("failed to inspect {label}"));
        assert!(!helper_source.contains(&old_probe));
        assert!(!source.contains(&old_ancestor_probe));
    }
}

pub fn ensure_existing_ancestors_not_link(path: &Path, label: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(_) => ensure_not_link_or_reparse(&current, label)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect existing {label} ancestor {}",
                        current.display()
                    )
                });
            }
        }
    }
    Ok(())
}

fn allocate_staged_temp_path(target: &Path, label: &str) -> Result<PathBuf> {
    for attempt in 0..16 {
        let candidate = staged_temp_path(target, attempt)?;
        ensure_not_link_or_reparse(&candidate, label)?;
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(candidate),
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow::anyhow!(
        "{label} could not allocate a staged temporary file for {}",
        target.display()
    ))
}

fn staged_temp_path(target: &Path, attempt: u32) -> Result<PathBuf> {
    let file_name = target
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("staged copy target missing filename"))?
        .to_string_lossy();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .context("failed to read system time for staged temporary file")?;
    Ok(target.with_file_name(format!(
        ".{file_name}.{}.{}.{}.avorax-part",
        std::process::id(),
        unique,
        attempt
    )))
}

fn activate_staged_file(
    temp_target: &Path,
    target: &Path,
    boundary: &Path,
    label: &str,
) -> Result<()> {
    ensure_staged_temp_file_ready(temp_target, label)?;
    ensure_existing_path_chain_not_link(target, boundary, label)?;
    ensure_not_link_or_reparse(target, label)?;
    if staged_target_file_present(target, label)? {
        std::fs::remove_file(target)?;
    }
    anyhow::ensure!(
        !staged_target_file_present(target, label)?,
        "{label} target still exists after removal: {}",
        target.display()
    );
    if let Some(parent) = target.parent() {
        ensure_existing_path_chain_not_link(parent, boundary, label)?;
    }
    std::fs::rename(temp_target, target)?;
    Ok(())
}

fn ensure_staged_temp_file_ready(temp_target: &Path, label: &str) -> Result<()> {
    ensure_not_link_or_reparse(temp_target, label)?;
    let metadata = std::fs::symlink_metadata(temp_target).with_context(|| {
        format!(
            "failed to inspect {label} staged temporary file {}",
            temp_target.display()
        )
    })?;
    anyhow::ensure!(
        metadata.is_file(),
        "{label} staged temporary file is not a regular file: {}",
        temp_target.display()
    );
    Ok(())
}

fn staged_target_file_present(target: &Path, label: &str) -> Result<bool> {
    match std::fs::symlink_metadata(target) {
        Ok(metadata) => {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "{label} must not be a symbolic link: {}",
                target.display()
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                anyhow::ensure!(
                    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                    "{label} must not be a reparse point: {}",
                    target.display()
                );
            }
            anyhow::ensure!(
                metadata.is_file(),
                "{label} target is not a regular file: {}",
                target.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect {label} target {}", target.display())),
    }
}

pub fn ensure_not_link_or_reparse(path: &Path, label: &str) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {label} {}", path.display()));
        }
    };
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "{label} must not be a symbolic link: {}",
        path.display()
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        anyhow::ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "{label} must not be a reparse point: {}",
            path.display()
        );
    }
    Ok(())
}

pub fn ensure_existing_path_chain_not_link(
    path: &Path,
    boundary: &Path,
    label: &str,
) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !current.starts_with(boundary) {
            continue;
        }
        ensure_not_link_or_reparse(&current, label)?;
    }
    Ok(())
}
