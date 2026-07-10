use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata, OpenOptions};
use std::io::ErrorKind;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zip::ZipArchive;

use crate::path_safety::{
    create_dir_all_checked, ensure_existing_path_chain_not_link, ensure_not_link_or_reparse,
};
use crate::update_manifest::{is_sha256, UpdateManifest};

const MAX_PAYLOAD_FILES: usize = 20_000;
const MAX_PAYLOAD_UNCOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PAYLOAD_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PAYLOAD_HASH_PATH_BYTES: usize = 4096;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_SIGNATURE_BYTES: u64 = 16 * 1024;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAX_UPDATE_PACKAGE_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const MAX_UPDATE_ARCHIVE_ENTRIES: usize = 25_000;
const MAX_UPDATE_ARCHIVE_ENTRY_NAME_BYTES: usize = 4096 + "payload/".len();

pub struct UpdatePackage {
    pub path: PathBuf,
}

impl UpdatePackage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[allow(dead_code)]
    pub fn read_manifest(&self) -> Result<UpdateManifest> {
        let file = self.open_checked_package_file()?;
        let mut archive = ZipArchive::new(file).context("failed to open .aup archive")?;
        validate_archive_entry_count(&archive)?;
        validate_archive_entry_names(&mut archive)?;
        let mut manifest = archive
            .by_name("manifest.json")
            .context("update package is missing manifest.json")?;
        let text =
            read_zip_entry_to_string_limited(&mut manifest, MAX_MANIFEST_BYTES, "update manifest")?;
        serde_json::from_str(&text).context("failed to parse update manifest")
    }

    pub fn read_manifest_bytes_and_signature(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let file = self.open_checked_package_file()?;
        let mut archive = ZipArchive::new(file)?;
        validate_archive_entry_count(&archive)?;
        validate_archive_entry_names(&mut archive)?;
        let mut manifest = archive.by_name("manifest.json")?;
        let manifest_bytes =
            read_zip_entry_to_end_limited(&mut manifest, MAX_MANIFEST_BYTES, "update manifest")?;
        drop(manifest);
        let mut sig = archive.by_name("manifest.sig")?;
        let signature_text = read_zip_entry_to_string_limited(
            &mut sig,
            MAX_MANIFEST_SIGNATURE_BYTES,
            "manifest signature",
        )?;
        let signature = hex::decode(signature_text.trim()).context("manifest.sig is not hex")?;
        anyhow::ensure!(
            signature.len() == ED25519_SIGNATURE_BYTES,
            "manifest.sig is not a 64-byte Ed25519 signature"
        );
        Ok((manifest_bytes, signature))
    }

    pub fn package_sha256(&self) -> Result<String> {
        let mut file = self.open_checked_package_file()?;
        sha256_reader(&mut file)
    }

    pub fn verify_payload_hashes(&self, expected_hashes: &BTreeMap<String, String>) -> Result<()> {
        validate_payload_hash_manifest_shape(expected_hashes)?;

        let file = self.open_checked_package_file()?;
        let mut archive = ZipArchive::new(file)?;
        validate_archive_entry_count(&archive)?;
        validate_payload_limits(&mut archive)?;
        for (relative, expected_hash) in expected_hashes {
            let relative_path = safe_relative_path(&relative.replace('\\', "/"))?;
            ensure_no_restricted_payload_path(&relative_path)?;
            let archive_name = format!(
                "payload/{}",
                relative_path.to_string_lossy().replace('\\', "/")
            );
            let actual_hash = hash_archive_entry_by_normalized_name(&mut archive, &archive_name)
                .with_context(|| format!("payload file missing from package: {archive_name}"))?;
            anyhow::ensure!(
                actual_hash.eq_ignore_ascii_case(expected_hash),
                "payload hash mismatch for {archive_name}"
            );
        }

        for index in 0..archive.len() {
            let entry = archive.by_index(index)?;
            let name = entry.name().replace('\\', "/");
            if !name.starts_with("payload/") || name.ends_with('/') {
                continue;
            }
            let relative = safe_relative_path(name.trim_start_matches("payload/"))?;
            ensure_no_restricted_payload_path(&relative)?;
            let key = relative.to_string_lossy().replace('\\', "/");
            anyhow::ensure!(
                expected_hashes.contains_key(&key),
                "payload file is not listed in signed manifest: {key}"
            );
        }

        Ok(())
    }

    pub fn verify_payload_matches_manifest(&self, manifest: &UpdateManifest) -> Result<()> {
        self.verify_payload_hashes(&manifest.payload_hashes)?;
        for relative in manifest.payload_hashes.keys() {
            let relative_path = safe_relative_path(&relative.replace('\\', "/"))?;
            ensure_payload_root_matches_manifest(&relative_path, manifest)?;
        }
        ensure_manifest_components_have_payload_hashes(manifest)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn extract_payload_to(&self, destination: &Path) -> Result<()> {
        let file = self.open_checked_package_file()?;
        self.extract_payload_from_file(destination, file)
    }

    pub fn extract_payload_to_verified_hash(
        &self,
        destination: &Path,
        expected_package_sha256: &str,
    ) -> Result<()> {
        anyhow::ensure!(
            is_sha256(expected_package_sha256),
            "expected update package SHA-256 is not valid"
        );
        let mut file = self.open_checked_package_file()?;
        let actual_package_sha256 = sha256_reader(&mut file)
            .context("failed to hash update package before payload extraction")?;
        anyhow::ensure!(
            actual_package_sha256.eq_ignore_ascii_case(expected_package_sha256),
            "update package changed after verification"
        );
        file.seek(SeekFrom::Start(0))
            .context("failed to rewind update package before payload extraction")?;
        self.extract_payload_from_file(destination, file)
    }

    fn extract_payload_from_file(&self, destination: &Path, file: File) -> Result<()> {
        ensure_not_link_or_reparse(destination, "payload extraction destination")?;
        create_dir_all_checked(destination, "payload extraction destination")?;
        let destination = destination
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", destination.display()))?;
        Self::ensure_existing_payload_extraction_directory(
            &destination,
            "canonical payload extraction destination",
        )?;
        let mut archive = ZipArchive::new(file)?;
        validate_archive_entry_count(&archive)?;
        validate_payload_limits(&mut archive)?;
        let mut extracted_uncompressed = 0u64;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let name = entry.name().replace('\\', "/");
            if !name.starts_with("payload/") || name.ends_with('/') {
                continue;
            }
            let relative = safe_relative_path(name.trim_start_matches("payload/"))?;
            ensure_no_restricted_payload_path(&relative)?;
            let target = destination.join(relative);
            anyhow::ensure!(
                target.starts_with(&destination),
                "payload extraction target escaped destination"
            );
            if let Some(parent) = target.parent() {
                ensure_existing_path_chain_not_link(
                    parent,
                    &destination,
                    "payload extraction destination",
                )?;
                create_dir_all_checked(parent, "payload extraction destination")?;
            }
            ensure_existing_path_chain_not_link(
                &target,
                &destination,
                "payload extraction destination",
            )?;
            ensure_payload_extraction_target_absent(&target)?;
            let temp_target = allocate_extraction_temp_path(&target)?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_target)
                .with_context(|| {
                    format!(
                        "failed to create temporary payload extraction file {}",
                        temp_target.display()
                    )
                })?;
            let copied = match copy_reader_limited(
                &mut entry,
                &mut output,
                MAX_PAYLOAD_ENTRY_BYTES,
                "payload extraction entry",
            ) {
                Ok(copied) => copied,
                Err(error) => {
                    drop(output);
                    Self::cleanup_extraction_temp_file(&temp_target).with_context(|| {
                        format!(
                            "failed to clean up temporary payload extraction file {} after copy failure: {error}",
                            temp_target.display()
                        )
                    })?;
                    return Err(error).with_context(|| {
                        format!(
                            "failed to write temporary payload extraction file {}",
                            temp_target.display()
                        )
                    });
                }
            };
            let next_extracted = match extracted_uncompressed.checked_add(copied) {
                Some(value) if value <= MAX_PAYLOAD_UNCOMPRESSED_BYTES => value,
                Some(_) => {
                    drop(output);
                    Self::cleanup_extraction_temp_file(&temp_target).with_context(|| {
                        format!(
                            "failed to clean up temporary payload extraction file {} after aggregate size failure",
                            temp_target.display()
                        )
                    })?;
                    anyhow::bail!(
                        "update package payload exceeds maximum uncompressed size during extraction"
                    );
                }
                None => {
                    drop(output);
                    Self::cleanup_extraction_temp_file(&temp_target).with_context(|| {
                        format!(
                            "failed to clean up temporary payload extraction file {} after aggregate size overflow",
                            temp_target.display()
                        )
                    })?;
                    anyhow::bail!("payload extraction size overflow");
                }
            };
            extracted_uncompressed = next_extracted;
            if let Err(error) = output.sync_all() {
                drop(output);
                Self::cleanup_extraction_temp_file(&temp_target).with_context(|| {
                    format!(
                        "failed to clean up temporary payload extraction file {} after sync failure: {error}",
                        temp_target.display()
                    )
                })?;
                return Err(error).with_context(|| {
                    format!(
                        "failed to sync temporary payload extraction file {}",
                        temp_target.display()
                    )
                });
            }
            drop(output);
            if let Err(error) =
                Self::activate_extracted_payload_file(&temp_target, &target, &destination)
            {
                Self::cleanup_extraction_temp_file(&temp_target).with_context(|| {
                    format!(
                        "failed to clean up temporary payload extraction file {} after activation failure: {error:#}",
                        temp_target.display()
                    )
                })?;
                return Err(error);
            }
        }
        Ok(())
    }

    fn activate_extracted_payload_file(
        temp_target: &Path,
        target: &Path,
        destination: &Path,
    ) -> Result<()> {
        Self::ensure_extraction_temp_file_ready(temp_target)?;
        if let Some(parent) = target.parent() {
            ensure_existing_path_chain_not_link(
                parent,
                destination,
                "payload extraction destination",
            )?;
        }
        ensure_payload_extraction_target_absent(target)?;
        if let Some(parent) = target.parent() {
            ensure_existing_path_chain_not_link(
                parent,
                destination,
                "payload extraction destination",
            )?;
        }
        std::fs::rename(temp_target, target).with_context(|| {
            format!(
                "failed to activate extracted payload file {}",
                target.display()
            )
        })?;
        Ok(())
    }

    fn ensure_extraction_temp_file_ready(path: &Path) -> Result<()> {
        ensure_not_link_or_reparse(path, "payload extraction temporary file")?;
        let metadata = std::fs::symlink_metadata(path).with_context(|| {
            format!(
                "failed to inspect payload extraction temporary file {}",
                path.display()
            )
        })?;
        anyhow::ensure!(
            metadata.is_file(),
            "payload extraction temporary file is not a regular file: {}",
            path.display()
        );
        Ok(())
    }

    fn cleanup_extraction_temp_file(path: &Path) -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                ensure_not_link_or_reparse(path, "payload extraction temporary file")?;
                anyhow::ensure!(
                    metadata.is_file(),
                    "temporary payload extraction cleanup target is not a regular file: {}",
                    path.display()
                );
                std::fs::remove_file(path).with_context(|| {
                    format!(
                        "failed to remove temporary payload extraction file {}",
                        path.display()
                    )
                })
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to inspect temporary payload extraction file {} before cleanup",
                    path.display()
                )
            }),
        }
    }

    fn ensure_existing_payload_extraction_directory(path: &Path, label: &str) -> Result<()> {
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

    fn ensure_package_path_safe(&self) -> Result<Metadata> {
        self.checked_package_metadata()
    }

    fn checked_package_metadata(&self) -> Result<Metadata> {
        validate_package_path_text(&self.path)?;
        ensure_not_link_or_reparse(&self.path, "update package")?;
        let metadata = std::fs::symlink_metadata(&self.path)
            .with_context(|| format!("failed to inspect update package {}", self.path.display()))?;
        anyhow::ensure!(
            metadata.is_file(),
            "update package is not a regular file: {}",
            self.path.display()
        );
        anyhow::ensure!(
            metadata.len() > 0,
            "update package is empty: {}",
            self.path.display()
        );
        anyhow::ensure!(
            metadata.len() <= MAX_UPDATE_PACKAGE_BYTES,
            "update package exceeds maximum size: {}",
            self.path.display()
        );
        anyhow::ensure!(
            self.path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("aup")),
            "update package must use the .aup extension: {}",
            self.path.display()
        );
        Ok(metadata)
    }

    fn open_checked_package_file(&self) -> Result<File> {
        let before_open = self.ensure_package_path_safe()?;
        let file = File::open(&self.path)
            .with_context(|| format!("failed to open update package {}", self.path.display()))?;
        let opened = file.metadata().with_context(|| {
            format!(
                "failed to inspect opened update package {}",
                self.path.display()
            )
        })?;
        let after_open = self.ensure_package_path_safe()?;
        ensure_opened_package_matches_checked_path(&before_open, &opened, &after_open)?;
        Ok(file)
    }
}

#[cfg(unix)]
fn ensure_opened_package_matches_checked_path(
    before_open: &Metadata,
    opened: &Metadata,
    after_open: &Metadata,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    anyhow::ensure!(
        opened.is_file(),
        "opened update package is not a regular file"
    );
    anyhow::ensure!(
        before_open.dev() == opened.dev()
            && before_open.ino() == opened.ino()
            && after_open.dev() == opened.dev()
            && after_open.ino() == opened.ino(),
        "update package changed while opening"
    );
    Ok(())
}

#[cfg(windows)]
fn ensure_opened_package_matches_checked_path(
    before_open: &Metadata,
    opened: &Metadata,
    after_open: &Metadata,
) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    anyhow::ensure!(
        opened.is_file(),
        "opened update package is not a regular file"
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
        "update package changed while opening"
    );
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_opened_package_matches_checked_path(
    before_open: &Metadata,
    opened: &Metadata,
    after_open: &Metadata,
) -> Result<()> {
    anyhow::ensure!(
        opened.is_file(),
        "opened update package is not a regular file"
    );
    anyhow::ensure!(
        before_open.len() == opened.len() && after_open.len() == opened.len(),
        "update package changed while opening"
    );
    Ok(())
}

fn validate_package_path_text(path: &Path) -> Result<()> {
    let text = path.as_os_str().to_string_lossy();
    anyhow::ensure!(
        !text.contains('\0'),
        "update package path contains NUL: {}",
        path.display()
    );
    anyhow::ensure!(
        !update_package_path_has_parent_traversal(path),
        "update package path must not contain parent traversal: {}",
        path.display()
    );
    Ok(())
}

fn update_package_path_has_parent_traversal(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn validate_payload_hash_manifest_shape(expected_hashes: &BTreeMap<String, String>) -> Result<()> {
    let mut normalized_payload_hash_paths = BTreeSet::new();
    anyhow::ensure!(
        !expected_hashes.is_empty(),
        "update package manifest does not list payload hashes"
    );
    anyhow::ensure!(
        expected_hashes.len() <= MAX_PAYLOAD_FILES,
        "update package manifest lists too many payload hashes"
    );
    for (relative, expected_hash) in expected_hashes {
        validate_payload_hash_path_text(relative)?;
        let normalized_path = safe_relative_path(&relative.replace('\\', "/"))?
            .to_string_lossy()
            .replace('\\', "/");
        anyhow::ensure!(
            normalized_payload_hash_paths.insert(normalized_path.clone()),
            "payload hash path normalizes to duplicate entry: {normalized_path}"
        );
        validate_payload_hash_value(relative, expected_hash)?;
    }
    Ok(())
}

fn validate_payload_hash_path_text(relative: &str) -> Result<()> {
    anyhow::ensure!(!relative.contains('\0'), "payload hash path contains NUL");
    anyhow::ensure!(
        !relative.chars().any(|ch| ch.is_control()),
        "payload hash path must not contain control characters"
    );
    let trimmed = relative.trim();
    anyhow::ensure!(!trimmed.is_empty(), "payload hash path is empty");
    anyhow::ensure!(
        relative == trimmed,
        "payload hash path must not contain surrounding whitespace"
    );
    anyhow::ensure!(
        relative.len() <= MAX_PAYLOAD_HASH_PATH_BYTES,
        "payload hash path exceeds maximum length"
    );
    Ok(())
}

fn validate_payload_hash_value(relative: &str, expected_hash: &str) -> Result<()> {
    anyhow::ensure!(
        !expected_hash.chars().any(|ch| ch.is_control()),
        "payload hash for {relative} must not contain control characters"
    );
    let trimmed = expected_hash.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "payload hash for {relative} is not a valid SHA-256 value"
    );
    anyhow::ensure!(
        expected_hash == trimmed,
        "payload hash for {relative} must not contain surrounding whitespace"
    );
    anyhow::ensure!(
        is_sha256(trimmed),
        "payload hash for {relative} is not a valid SHA-256 value"
    );
    Ok(())
}

fn ensure_payload_extraction_target_absent(target: &Path) -> Result<()> {
    match std::fs::symlink_metadata(target) {
        Ok(metadata) => {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "payload extraction target must not be a symbolic link: {}",
                target.display()
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                anyhow::ensure!(
                    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                    "payload extraction target must not be a reparse point: {}",
                    target.display()
                );
            }
            anyhow::bail!(
                "payload extraction target already exists: {}",
                target.display()
            );
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect payload extraction target {}",
                target.display()
            )
        }),
    }
}

fn allocate_extraction_temp_path(target: &Path) -> Result<PathBuf> {
    for attempt in 0..16 {
        let candidate = extraction_temp_path(target, attempt)?;
        ensure_not_link_or_reparse(&candidate, "payload extraction temporary file")?;
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(candidate),
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow::anyhow!(
        "could not allocate temporary payload extraction file for {}",
        target.display()
    ))
}

fn extraction_temp_path(target: &Path, attempt: u32) -> Result<PathBuf> {
    let file_name = target
        .file_name()
        .context("payload extraction target missing filename")?
        .to_string_lossy();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .context("failed to read system time for payload extraction temporary file")?;
    Ok(target.with_file_name(format!(
        ".{file_name}.{}.{}.{}.avorax-part",
        std::process::id(),
        unique,
        attempt
    )))
}

fn validate_payload_limits(archive: &mut ZipArchive<File>) -> Result<()> {
    validate_archive_entry_count(archive)?;
    validate_archive_entry_names(archive)?;
    let mut payload_files = 0usize;
    let mut total_uncompressed = 0u64;
    let mut payload_names = BTreeSet::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name().replace('\\', "/");
        if !name.starts_with("payload/") || name.ends_with('/') {
            continue;
        }
        let relative = safe_relative_path(name.trim_start_matches("payload/"))?;
        ensure_no_restricted_payload_path(&relative)?;
        let normalized = relative.to_string_lossy().replace('\\', "/");
        anyhow::ensure!(!normalized.is_empty(), "empty payload path");
        anyhow::ensure!(
            payload_names.insert(normalized.clone()),
            "duplicate payload file in update package: {normalized}"
        );
        let size = entry.size();
        anyhow::ensure!(
            size <= MAX_PAYLOAD_ENTRY_BYTES,
            "payload entry exceeds maximum size: {normalized}"
        );
        payload_files = payload_files.saturating_add(1);
        anyhow::ensure!(
            payload_files <= MAX_PAYLOAD_FILES,
            "update package contains too many payload files"
        );
        total_uncompressed = total_uncompressed
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("payload size overflow"))?;
        anyhow::ensure!(
            total_uncompressed <= MAX_PAYLOAD_UNCOMPRESSED_BYTES,
            "update package payload exceeds maximum uncompressed size"
        );
    }
    anyhow::ensure!(
        payload_files > 0,
        "update package contains no payload files"
    );
    Ok(())
}

fn validate_archive_entry_count(archive: &ZipArchive<File>) -> Result<()> {
    anyhow::ensure!(
        archive.len() <= MAX_UPDATE_ARCHIVE_ENTRIES,
        "update package contains too many archive entries"
    );
    Ok(())
}

fn validate_archive_entry_names(archive: &mut ZipArchive<File>) -> Result<()> {
    let mut manifest_seen = false;
    let mut signature_seen = false;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name().replace('\\', "/");
        validate_archive_entry_name(&name)?;
        match name.as_str() {
            "manifest.json" => {
                anyhow::ensure!(
                    !manifest_seen,
                    "duplicate manifest.json entry in update package"
                );
                manifest_seen = true;
            }
            "manifest.sig" => {
                anyhow::ensure!(
                    !signature_seen,
                    "duplicate manifest.sig entry in update package"
                );
                signature_seen = true;
            }
            _ => {}
        }
    }
    anyhow::ensure!(manifest_seen, "update package is missing manifest.json");
    anyhow::ensure!(signature_seen, "update package is missing manifest.sig");
    Ok(())
}

fn validate_archive_entry_name(name: &str) -> Result<()> {
    validate_archive_entry_name_text(name)?;
    if name == "manifest.json" || name == "manifest.sig" {
        return Ok(());
    }
    if let Some(relative) = name.strip_prefix("payload/") {
        let relative = relative.trim_end_matches('/');
        anyhow::ensure!(
            !relative.is_empty(),
            "update package payload archive entry path is empty"
        );
        let relative_path = safe_relative_path(relative).with_context(|| {
            format!("update package contains unsafe payload archive entry: {name}")
        })?;
        ensure_no_restricted_payload_path(&relative_path)?;
        return Ok(());
    }
    anyhow::bail!("update package contains unexpected archive entry: {name}");
}

fn validate_archive_entry_name_text(name: &str) -> Result<()> {
    anyhow::ensure!(
        !name.contains('\0'),
        "update package archive entry name contains NUL"
    );
    anyhow::ensure!(
        !name.chars().any(|ch| ch.is_control()),
        "update package archive entry name must not contain control characters"
    );
    anyhow::ensure!(
        name.len() <= MAX_UPDATE_ARCHIVE_ENTRY_NAME_BYTES,
        "update package archive entry name exceeds maximum length"
    );
    Ok(())
}

fn read_zip_entry_to_string_limited(
    reader: &mut impl Read,
    limit: u64,
    label: &str,
) -> Result<String> {
    let bytes = read_zip_entry_to_end_limited(reader, limit, label)?;
    String::from_utf8(bytes).with_context(|| format!("{label} is not valid UTF-8"))
}

fn read_zip_entry_to_end_limited(
    reader: &mut impl Read,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("failed to read {label}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("{label} size overflow"))?;
        anyhow::ensure!(total <= limit, "{label} exceeds maximum size");
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
}

pub fn sha256_reader(reader: &mut impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_reader_limited(reader: &mut impl Read, limit: u64, label: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("{label} size overflow"))?;
        anyhow::ensure!(total <= limit, "{label} exceeds maximum size");
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn copy_reader_limited(
    reader: &mut impl Read,
    writer: &mut impl Write,
    limit: u64,
    label: &str,
) -> Result<u64> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("{label} size overflow"))?;
        anyhow::ensure!(total <= limit, "{label} exceeds maximum size");
        writer.write_all(&buffer[..read])?;
    }
    Ok(total)
}

fn hash_archive_entry_by_normalized_name(
    archive: &mut ZipArchive<File>,
    expected_name: &str,
) -> Result<String> {
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.name().replace('\\', "/") == expected_name {
            return sha256_reader_limited(
                &mut entry,
                MAX_PAYLOAD_ENTRY_BYTES,
                "payload hash entry",
            );
        }
    }
    anyhow::bail!("specified file not found in archive")
}

pub fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    anyhow::ensure!(!path.is_absolute(), "absolute payload path is not allowed");
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => anyhow::bail!("unsafe payload path: {value}"),
        }
    }
    anyhow::ensure!(!out.as_os_str().is_empty(), "empty payload path");
    Ok(out)
}

fn ensure_no_restricted_payload_path(relative: &Path) -> Result<()> {
    let first = payload_root(relative)?;
    anyhow::ensure!(
        first != "driver" && first != "driver-tools",
        "driver payload paths require a separate explicit driver workflow: {}",
        relative.display()
    );
    anyhow::ensure!(
        first != "tools",
        "tools payload paths require a separate explicit tooling workflow: {}",
        relative.display()
    );
    anyhow::ensure!(
        first != "migrations",
        "migration payload paths require a separate explicit migration workflow: {}",
        relative.display()
    );
    Ok(())
}

fn ensure_payload_root_matches_manifest(relative: &Path, manifest: &UpdateManifest) -> Result<()> {
    let root = payload_root(relative)?;
    let allowed = match root.as_str() {
        "app" => app_payload_allowed(relative, manifest)?,
        "services" => {
            service_payload_allowed(relative, manifest)?;
            true
        }
        "engine" => engine_payload_allowed(relative, manifest)?,
        "docs" => docs_payload_allowed(relative, manifest)?,
        _ => false,
    };
    anyhow::ensure!(
        allowed,
        "payload root {root} is not declared by update manifest components"
    );
    Ok(())
}

fn ensure_manifest_components_have_payload_hashes(manifest: &UpdateManifest) -> Result<()> {
    let payloads = normalized_manifest_payload_paths(manifest)?;

    ensure_declared_component_has_payload(
        manifest.components.app,
        payloads.iter().any(|path| payload_has_root(path, "app")),
        "app",
        "app payload",
    )?;
    ensure_declared_component_has_payload(
        manifest.components.core_service,
        payloads
            .iter()
            .any(|path| payload_is_direct_service_file(path, "avorax_core_service.exe")),
        "core_service",
        "services/avorax_core_service.exe",
    )?;
    ensure_declared_component_has_payload(
        manifest.components.guard_service,
        payloads
            .iter()
            .any(|path| payload_is_direct_service_file(path, "avorax_guard_service.exe")),
        "guard_service",
        "services/avorax_guard_service.exe",
    )?;
    ensure_declared_component_has_payload(
        manifest.components.native_engine_assets,
        payloads.iter().any(|path| payload_has_root(path, "engine")),
        "native_engine_assets",
        "engine payload",
    )?;
    ensure_engine_subcomponent_declared_with_payload(
        &payloads,
        manifest.components.native_engine_assets,
        manifest.components.signatures,
        "signatures",
    )?;
    ensure_engine_subcomponent_declared_with_payload(
        &payloads,
        manifest.components.native_engine_assets,
        manifest.components.rules,
        "rules",
    )?;
    ensure_engine_subcomponent_declared_with_payload(
        &payloads,
        manifest.components.native_engine_assets,
        manifest.components.ml_model,
        "ml",
    )?;
    ensure_engine_subcomponent_declared_with_payload(
        &payloads,
        manifest.components.native_engine_assets,
        manifest.components.trust_packs,
        "trust",
    )?;
    ensure_declared_component_has_payload(
        manifest.components.docs,
        payloads.iter().any(|path| payload_has_root(path, "docs")),
        "docs",
        "docs payload",
    )?;

    Ok(())
}

fn normalized_manifest_payload_paths(manifest: &UpdateManifest) -> Result<Vec<PathBuf>> {
    manifest
        .payload_hashes
        .keys()
        .map(|relative| safe_relative_path(&relative.replace('\\', "/")))
        .collect()
}

fn ensure_declared_component_has_payload(
    declared: bool,
    present: bool,
    component: &str,
    payload_description: &str,
) -> Result<()> {
    if declared {
        anyhow::ensure!(
            present,
            "manifest component {component} is declared but no {payload_description} hash is listed"
        );
    }
    Ok(())
}

fn ensure_engine_subcomponent_declared_with_payload(
    payloads: &[PathBuf],
    native_engine_assets_declared: bool,
    declared: bool,
    subcomponent: &str,
) -> Result<()> {
    if !declared {
        return Ok(());
    }
    anyhow::ensure!(
        native_engine_assets_declared,
        "manifest component {subcomponent} is declared without native_engine_assets"
    );
    ensure_declared_component_has_payload(
        true,
        payloads
            .iter()
            .any(|path| payload_is_engine_subcomponent(path, subcomponent)),
        subcomponent,
        &format!("engine/{subcomponent} payload"),
    )
}

fn payload_has_root(relative: &Path, expected_root: &str) -> bool {
    payload_root(relative).is_ok_and(|root| root == expected_root)
}

fn payload_is_direct_service_file(relative: &Path, expected_file: &str) -> bool {
    payload_has_root(relative, "services")
        && direct_service_payload_file_name(relative)
            .is_ok_and(|file_name| file_name == expected_file)
}

fn payload_is_engine_subcomponent(relative: &Path, expected_subcomponent: &str) -> bool {
    payload_has_root(relative, "engine")
        && engine_payload_subcomponent(relative)
            .is_ok_and(|subcomponent| subcomponent == expected_subcomponent)
}

fn app_payload_allowed(relative: &Path, manifest: &UpdateManifest) -> Result<bool> {
    let install_child = payload_second_component(relative, "app payload")?.ok_or_else(|| {
        anyhow::anyhow!(
            "app payload must contain a file below app: {}",
            relative.display()
        )
    })?;
    match install_child.as_str() {
        "engine" | "docs" | "tools" | "driver" | "driver-tools" | "migrations" => {
            anyhow::bail!(
                "app payload must not target restricted install path {install_child}: {}",
                relative.display()
            )
        }
        "avorax_update_service.exe" | "avorax_core_service.exe" | "avorax_guard_service.exe" => {
            anyhow::bail!(
                "app payload must not include managed service or updater executable {install_child}: {}",
                relative.display()
            )
        }
        _ => Ok(manifest.components.app),
    }
}

fn service_payload_allowed(relative: &Path, manifest: &UpdateManifest) -> Result<()> {
    let file_name = direct_service_payload_file_name(relative)?;
    let allowed = match file_name.as_str() {
        "avorax_core_service.exe" => manifest.components.core_service,
        "avorax_guard_service.exe" => manifest.components.guard_service,
        _ => anyhow::bail!(
            "service payload {} is not supported by normal updates",
            relative.display()
        ),
    };
    anyhow::ensure!(
        allowed,
        "service payload {} is not declared by update manifest components",
        relative.display()
    );
    Ok(())
}

fn direct_service_payload_file_name(relative: &Path) -> Result<String> {
    let mut components = relative.components();
    let _root = components.next();
    let Some(component) = components.next() else {
        anyhow::bail!(
            "service payload path is missing a UTF-8 filename: {}",
            relative.display()
        );
    };
    let Component::Normal(file_name) = component else {
        anyhow::bail!(
            "service payload path contains an unsafe component: {}",
            relative.display()
        );
    };
    anyhow::ensure!(
        components.next().is_none(),
        "service payload must be directly under services: {}",
        relative.display()
    );
    file_name
        .to_str()
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "service payload path is missing a UTF-8 filename: {}",
                relative.display()
            )
        })
}

fn engine_payload_allowed(relative: &Path, manifest: &UpdateManifest) -> Result<bool> {
    let subdir = engine_payload_subcomponent(relative)?;
    let subcomponent_allowed = match subdir.as_str() {
        "signatures" => manifest.components.signatures,
        "rules" => manifest.components.rules,
        "ml" => manifest.components.ml_model,
        "trust" => manifest.components.trust_packs,
        other => {
            anyhow::bail!(
                "engine payload subcomponent {other} is not supported by normal updates: {}",
                relative.display()
            )
        }
    };
    Ok(manifest.components.native_engine_assets && subcomponent_allowed)
}

fn docs_payload_allowed(relative: &Path, manifest: &UpdateManifest) -> Result<bool> {
    let file_name = payload_file_name(relative, "docs payload")?;
    anyhow::ensure!(
        relative.components().count() >= 2,
        "docs payload must be a Markdown file under docs: {}",
        relative.display()
    );
    anyhow::ensure!(
        file_name != ".md" && file_name.ends_with(".md"),
        "docs payload file must be Markdown-only for normal updates: {}",
        relative.display()
    );
    Ok(manifest.components.docs)
}

fn engine_payload_subcomponent(relative: &Path) -> Result<String> {
    let subdir = payload_second_component(relative, "engine payload")?.ok_or_else(|| {
        anyhow::anyhow!(
            "engine payload must be under an explicit runtime subdirectory: {}",
            relative.display()
        )
    })?;
    anyhow::ensure!(
        relative.components().count() >= 3,
        "engine payload must be a file under an explicit runtime subdirectory: {}",
        relative.display()
    );
    Ok(subdir)
}

fn payload_root(relative: &Path) -> Result<String> {
    relative
        .components()
        .next()
        .and_then(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "payload path is missing a root component: {}",
                relative.display()
            )
        })
}

fn payload_file_name(relative: &Path, label: &str) -> Result<String> {
    relative
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{label} path is missing a UTF-8 filename: {}",
                relative.display()
            )
        })
}

fn payload_second_component(relative: &Path, label: &str) -> Result<Option<String>> {
    let mut components = relative.components();
    let _root = components.next();
    let Some(component) = components.next() else {
        return Ok(None);
    };
    let Component::Normal(value) = component else {
        anyhow::bail!(
            "{label} path contains an unsafe component: {}",
            relative.display()
        );
    };
    let Some(value) = value.to_str() else {
        anyhow::bail!(
            "{label} path contains a non-UTF-8 component: {}",
            relative.display()
        );
    };
    anyhow::ensure!(
        !value.is_empty(),
        "{label} path contains an empty component: {}",
        relative.display()
    );
    Ok(Some(value.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_manifest::{
        UpdateChannel, UpdateComponentSet, PACKAGE_FORMAT_VERSION, PRODUCT_NAME,
    };
    use std::io::Write;
    use tempfile::tempdir;

    fn manifest_with_hashes(payload_hashes: BTreeMap<String, String>) -> UpdateManifest {
        UpdateManifest {
            product: PRODUCT_NAME.to_string(),
            package_format_version: PACKAGE_FORMAT_VERSION,
            version: "0.2.99".to_string(),
            previous_min_version: "0.2.98".to_string(),
            channel: UpdateChannel::Dev,
            release_date: "2026-06-23T00:00:00Z".to_string(),
            package_id: "test-package".to_string(),
            components: UpdateComponentSet {
                app: false,
                core_service: false,
                guard_service: false,
                update_service: false,
                native_engine_assets: false,
                signatures: false,
                rules: false,
                ml_model: false,
                trust_packs: false,
                docs: false,
                driver_tools: false,
            },
            requires_restart: true,
            requires_reboot: false,
            requires_admin: true,
            driver_update_included: false,
            migration_steps: vec![],
            rollback_supported: true,
            payload_hashes,
            package_sha256: String::new(),
            signature_algorithm: "ed25519".to_string(),
            public_key_id: "avorax-dev-ed25519".to_string(),
            release_notes_url: None,
        }
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        sha256_reader(&mut std::io::Cursor::new(bytes)).unwrap()
    }

    fn write_minimal_manifest_signature_entries(archive: &mut zip::ZipWriter<File>) {
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(b"{}").unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive.write_all(b"00").unwrap();
    }

    fn write_payload_package_entries(package_path: &Path, payloads: &[(&str, &[u8])]) {
        let file = File::create(package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        for (payload_path, payload) in payloads {
            archive.start_file(*payload_path, options).unwrap();
            archive.write_all(payload).unwrap();
        }
        archive.finish().unwrap();
    }

    fn write_payload_package(package_path: &Path, payload_path: &str, payload: &[u8]) {
        write_payload_package_entries(package_path, &[(payload_path, payload)]);
    }

    #[test]
    fn package_file_reads_recheck_path_after_open() {
        let source = include_str!("update_package.rs");
        let test_start = source.find("#[cfg(test)]").unwrap();
        let production = &source[..test_start];
        let metadata_source = &production[production
            .find("fn checked_package_metadata")
            .expect("metadata helper must exist")
            ..production
                .find("fn open_checked_package_file")
                .expect("open helper must exist")];
        let helper_source = &production[production
            .find("fn open_checked_package_file")
            .expect("open helper must exist")..];

        assert!(metadata_source.contains("fn checked_package_metadata(&self) -> Result<Metadata>"));
        assert!(metadata_source.contains("validate_package_path_text(&self.path)?"));
        assert!(metadata_source.contains("std::fs::symlink_metadata(&self.path)"));
        assert!(production.contains("fn ensure_package_path_safe(&self) -> Result<Metadata>"));
        assert!(helper_source.contains("let before_open = self.ensure_package_path_safe()?"));
        assert!(helper_source.contains("File::open(&self.path)"));
        assert!(helper_source.contains("let opened = file.metadata()"));
        assert!(helper_source.contains("let after_open = self.ensure_package_path_safe()?"));
        assert!(helper_source.contains(
            "ensure_opened_package_matches_checked_path(&before_open, &opened, &after_open)?"
        ));
        assert!(production.contains("fn ensure_opened_package_matches_checked_path"));
        assert!(production.contains("update package changed while opening"));
        assert!(production.contains("opened update package is not a regular file"));
        assert!(production.contains("let file = self.open_checked_package_file()?"));
        assert_eq!(production.matches("File::open(&self.path)").count(), 1);
        assert!(!production.contains("sha256_file(&self.path)"));
        assert!(!production.contains("pub fn sha256_file"));
    }

    #[test]
    fn package_metadata_enforces_size_bounds_before_open() {
        let source = include_str!("update_package.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let metadata_source = &production[production
            .find("fn checked_package_metadata")
            .expect("metadata helper must exist")
            ..production
                .find("fn open_checked_package_file")
                .expect("open helper must exist")];

        assert!(production.contains("const MAX_UPDATE_PACKAGE_BYTES: u64"));
        assert!(metadata_source.contains("metadata.len() > 0"));
        assert!(metadata_source.contains("metadata.len() <= MAX_UPDATE_PACKAGE_BYTES"));
        assert!(
            metadata_source.find("metadata.len() > 0").unwrap()
                < metadata_source
                    .find("self.path\n                .extension()")
                    .unwrap()
        );
    }

    #[test]
    fn package_archive_entry_count_is_bounded_before_archive_reads() {
        let source = include_str!("update_package.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let read_manifest_source = &production[production
            .find("pub fn read_manifest")
            .expect("manifest reader must exist")
            ..production
                .find("pub fn read_manifest_bytes_and_signature")
                .expect("signature reader must exist")];
        let signature_source = &production[production
            .find("pub fn read_manifest_bytes_and_signature")
            .expect("signature reader must exist")
            ..production
                .find("pub fn package_sha256")
                .expect("package hash must exist")];
        let limits_source = &production[production
            .find("fn validate_payload_limits")
            .expect("payload limits helper must exist")
            ..production
                .find("fn read_zip_entry_to_string_limited")
                .expect("zip read helper must exist")];

        assert!(production.contains("const MAX_UPDATE_ARCHIVE_ENTRIES: usize"));
        assert!(production.contains("fn validate_archive_entry_count"));
        assert!(production.contains("archive.len() <= MAX_UPDATE_ARCHIVE_ENTRIES"));
        assert!(
            read_manifest_source
                .find("validate_archive_entry_count(&archive)?")
                .unwrap()
                < read_manifest_source
                    .find(".by_name(\"manifest.json\")")
                    .unwrap()
        );
        assert!(
            signature_source
                .find("validate_archive_entry_count(&archive)?")
                .unwrap()
                < signature_source
                    .find("archive.by_name(\"manifest.json\")")
                    .unwrap()
        );
        assert!(
            production
                .matches("validate_archive_entry_count(&archive)?")
                .count()
                >= 4
        );
        assert!(limits_source.contains("validate_archive_entry_count(archive)?"));
    }

    #[test]
    fn package_archive_entries_are_allowlisted_before_archive_reads() {
        let source = include_str!("update_package.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let read_manifest_source = &production[production
            .find("pub fn read_manifest")
            .expect("manifest reader must exist")
            ..production
                .find("pub fn read_manifest_bytes_and_signature")
                .expect("signature reader must exist")];
        let signature_source = &production[production
            .find("pub fn read_manifest_bytes_and_signature")
            .expect("signature reader must exist")
            ..production
                .find("pub fn package_sha256")
                .expect("package hash must exist")];
        let limits_source = &production[production
            .find("fn validate_payload_limits")
            .expect("payload limits helper must exist")
            ..production
                .find("fn read_zip_entry_to_string_limited")
                .expect("zip read helper must exist")];

        assert!(production.contains("fn validate_archive_entry_names"));
        assert!(production.contains("fn validate_archive_entry_name"));
        assert!(production.contains("const MAX_UPDATE_ARCHIVE_ENTRY_NAME_BYTES"));
        assert!(production.contains("fn validate_archive_entry_name_text"));
        assert!(production.contains("validate_archive_entry_name_text(name)?"));
        assert!(production.contains("archive entry name contains NUL"));
        assert!(production.contains("archive entry name must not contain control characters"));
        assert!(production.contains("archive entry name exceeds maximum length"));
        assert!(production.contains("let mut manifest_seen = false"));
        assert!(production.contains("let mut signature_seen = false"));
        assert!(production.contains("duplicate manifest.json entry in update package"));
        assert!(production.contains("duplicate manifest.sig entry in update package"));
        assert!(production.contains("update package is missing manifest.json"));
        assert!(production.contains("update package is missing manifest.sig"));
        assert!(production.contains("name == \"manifest.json\" || name == \"manifest.sig\""));
        assert!(production.contains("name.strip_prefix(\"payload/\")"));
        assert!(production.contains("safe_relative_path(relative)"));
        assert!(production.contains("update package contains unexpected archive entry"));
        assert!(
            read_manifest_source
                .find("validate_archive_entry_names(&mut archive)?")
                .unwrap()
                < read_manifest_source
                    .find(".by_name(\"manifest.json\")")
                    .unwrap()
        );
        assert!(
            signature_source
                .find("validate_archive_entry_names(&mut archive)?")
                .unwrap()
                < signature_source
                    .find("archive.by_name(\"manifest.json\")")
                    .unwrap()
        );
        assert!(
            limits_source
                .find("validate_archive_entry_names(archive)?")
                .unwrap()
                < limits_source.find("for index in 0..archive.len()").unwrap()
        );
    }

    #[test]
    fn read_manifest_rejects_unexpected_archive_entry() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(b"{}").unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive.write_all(b"00").unwrap();
        archive.start_file("install.ps1", options).unwrap();
        archive.write_all(b"benign test fixture").unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest()
            .unwrap_err()
            .to_string();

        assert!(error.contains("unexpected archive entry"));
    }

    #[test]
    fn read_manifest_rejects_restricted_payload_directory_entry() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive.add_directory("payload/tools/", options).unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest()
            .unwrap_err()
            .to_string();

        assert!(error.contains("tools payload paths require a separate explicit tooling workflow"));
    }

    #[test]
    fn read_manifest_rejects_control_character_archive_entry_name() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/app/bad\nname.txt", options)
            .unwrap();
        archive.write_all(b"safe payload fixture").unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest()
            .unwrap_err()
            .to_string();

        assert!(error.contains("archive entry name must not contain control characters"));
    }

    #[test]
    fn read_manifest_rejects_duplicate_manifest_entry() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(b"{}").unwrap();
        if let Err(error) = archive.start_file("manifest.json", options) {
            assert!(error.to_string().contains("Duplicate filename"));
            return;
        }
        archive.write_all(b"{}").unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive.write_all(b"00").unwrap();
        if let Err(error) = archive.finish() {
            assert!(error.to_string().contains("Duplicate filename"));
            return;
        }

        let error = UpdatePackage::new(&package_path)
            .read_manifest()
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicate manifest.json entry"));
    }

    #[test]
    fn read_manifest_rejects_missing_manifest_entry() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.sig", options).unwrap();
        archive.write_all(b"00").unwrap();
        archive
            .start_file("payload/app/Avorax.exe", options)
            .unwrap();
        archive.write_all(b"safe payload fixture").unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest()
            .unwrap_err()
            .to_string();

        assert!(error.contains("update package is missing manifest.json"));
    }

    #[test]
    fn read_manifest_signature_rejects_duplicate_signature_entry() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(b"{}").unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive.write_all(b"00").unwrap();
        if let Err(error) = archive.start_file("manifest.sig", options) {
            assert!(error.to_string().contains("Duplicate filename"));
            return;
        }
        archive.write_all(b"00").unwrap();
        if let Err(error) = archive.finish() {
            assert!(error.to_string().contains("Duplicate filename"));
            return;
        }

        let error = UpdatePackage::new(&package_path)
            .read_manifest_bytes_and_signature()
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicate manifest.sig entry"));
    }

    #[test]
    fn read_manifest_signature_rejects_missing_signature_entry() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(b"{}").unwrap();
        archive
            .start_file("payload/app/Avorax.exe", options)
            .unwrap();
        archive.write_all(b"safe payload fixture").unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest_bytes_and_signature()
            .unwrap_err()
            .to_string();

        assert!(error.contains("update package is missing manifest.sig"));
    }

    #[test]
    fn read_manifest_rejects_oversized_manifest_entry() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive
            .write_all(&vec![b'{'; (MAX_MANIFEST_BYTES + 1) as usize])
            .unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive.write_all(b"00").unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest()
            .unwrap_err()
            .to_string();

        assert!(error.contains("update manifest exceeds maximum size"));
    }

    #[test]
    fn manifest_zip_entry_reads_enforce_actual_byte_limits() {
        let source = include_str!("update_package.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let helper_source = &production[production
            .find("fn read_zip_entry_to_end_limited")
            .expect("zip read helper must exist")
            ..production
                .find("pub fn sha256_reader")
                .expect("package hash helper must exist")];

        assert!(helper_source.contains("let mut total = 0_u64"));
        assert!(helper_source.contains("checked_add(read as u64)"));
        assert!(helper_source.contains("total <= limit"));
        assert!(helper_source.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(!helper_source.contains("reader.take(limit + 1)"));
        assert!(!helper_source.contains("read_to_end(&mut bytes)"));
    }

    #[test]
    fn read_manifest_signature_rejects_oversized_signature_entry() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(br#"{"product":"Avorax"}"#).unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive
            .write_all(&vec![b'a'; (MAX_MANIFEST_SIGNATURE_BYTES + 1) as usize])
            .unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest_bytes_and_signature()
            .unwrap_err()
            .to_string();

        assert!(error.contains("manifest signature exceeds maximum size"));
    }

    #[test]
    fn read_manifest_signature_rejects_wrong_signature_length() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(br#"{"product":"Avorax"}"#).unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive.write_all(b"00").unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest_bytes_and_signature()
            .unwrap_err()
            .to_string();

        assert!(error.contains("manifest.sig is not a 64-byte Ed25519 signature"));
    }

    #[test]
    fn payload_hashes_reject_driver_payload_path() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/driver/AvoraxDrv.sys", options)
            .unwrap();
        archive.write_all(b"safe non-driver test fixture").unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("driver/AvoraxDrv.sys".to_string(), "00".repeat(32));
        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("driver payload paths require a separate explicit driver workflow"));
    }

    #[test]
    fn payload_hashes_reject_tools_payload_path() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/tools/helper.ps1", options)
            .unwrap();
        archive.write_all(b"safe tooling fixture").unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("tools/helper.ps1".to_string(), "00".repeat(32));
        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("tools payload paths require a separate explicit tooling workflow"));
    }

    #[test]
    fn payload_hashes_reject_migrations_payload_path() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/migrations/step.ps1", options)
            .unwrap();
        archive.write_all(b"safe migration fixture").unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("migrations/step.ps1".to_string(), "00".repeat(32));
        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error
            .contains("migration payload paths require a separate explicit migration workflow"));
    }

    #[test]
    fn payload_hashes_reject_excessive_manifest_entries() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        File::create(&package_path).unwrap();

        let mut hashes = BTreeMap::new();
        for index in 0..=MAX_PAYLOAD_FILES {
            hashes.insert(format!("app/file-{index}.txt"), "00".repeat(32));
        }

        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("too many payload hashes"));
    }

    #[test]
    fn payload_hashes_reject_oversized_manifest_paths() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        File::create(&package_path).unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            format!("app/{}", "a".repeat(MAX_PAYLOAD_HASH_PATH_BYTES + 1)),
            "00".repeat(32),
        );

        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload hash path exceeds maximum length"));
    }

    #[test]
    fn payload_hashes_reject_nul_manifest_paths() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        File::create(&package_path).unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("app/bad\0name.txt".to_string(), "00".repeat(32));

        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload hash path contains NUL"));
    }

    #[test]
    fn payload_hashes_reject_whitespace_wrapped_manifest_paths_before_archive_open() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("not-a-zip.aup");
        File::create(&package_path).unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(" app/Avorax.exe ".to_string(), "00".repeat(32));

        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload hash path must not contain surrounding whitespace"));
        assert!(!error.contains("invalid Zip archive"));
    }

    #[test]
    fn payload_hashes_reject_control_character_manifest_paths_before_archive_open() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("not-a-zip.aup");
        File::create(&package_path).unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("app/\nAvorax.exe".to_string(), "00".repeat(32));

        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload hash path must not contain control characters"));
        assert!(!error.contains("invalid Zip archive"));
    }

    #[test]
    fn payload_hashes_reject_whitespace_wrapped_hash_before_archive_open() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("not-a-zip.aup");
        File::create(&package_path).unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "app/Avorax.exe".to_string(),
            format!(" {} ", "00".repeat(32)),
        );

        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error
            .contains("payload hash for app/Avorax.exe must not contain surrounding whitespace"));
        assert!(!error.contains("invalid Zip archive"));
    }

    #[test]
    fn payload_hashes_reject_control_character_hash_before_archive_open() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("not-a-zip.aup");
        File::create(&package_path).unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "app/Avorax.exe".to_string(),
            format!("{}\n", "00".repeat(32)),
        );

        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("payload hash for app/Avorax.exe must not contain control characters")
        );
        assert!(!error.contains("invalid Zip archive"));
    }

    #[test]
    fn payload_hashes_reject_duplicate_normalized_manifest_paths_before_archive_open() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("not-a-zip.aup");
        File::create(&package_path).unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("app/Avorax.exe".to_string(), "00".repeat(32));
        hashes.insert("app/./Avorax.exe".to_string(), "00".repeat(32));

        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload hash path normalizes to duplicate entry"));
        assert!(!error.contains("invalid Zip archive"));
    }

    #[test]
    fn payload_limits_reject_duplicate_normalized_entries() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/app/Avorax.exe", options)
            .unwrap();
        archive.write_all(b"safe payload fixture").unwrap();
        archive
            .start_file("payload/app/./Avorax.exe", options)
            .unwrap();
        archive.write_all(b"duplicate payload fixture").unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "app/Avorax.exe".to_string(),
            sha256_bytes(b"safe payload fixture"),
        );
        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicate payload file in update package"));
    }

    #[test]
    fn payload_limits_reject_empty_payload_archives() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        write_minimal_manifest_signature_entries(&mut archive);
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .extract_payload_to(&dir.path().join("staging"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("update package contains no payload files"));
    }

    #[test]
    fn payload_extraction_verified_hash_rejects_changed_package_before_extracting() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        write_payload_package(
            &package_path,
            "payload/app/Avorax.exe",
            b"safe original payload",
        );
        let verified_package_hash = UpdatePackage::new(&package_path).package_sha256().unwrap();
        write_payload_package(
            &package_path,
            "payload/app/Avorax.exe",
            b"safe replacement payload",
        );
        let destination = dir.path().join("staging");

        let error = UpdatePackage::new(&package_path)
            .extract_payload_to_verified_hash(&destination, &verified_package_hash)
            .unwrap_err()
            .to_string();

        assert!(error.contains("update package changed after verification"));
        assert!(!destination.exists());
    }

    #[test]
    fn payload_hash_manifest_shape_is_checked_before_archive_open() {
        let source = include_str!("update_package.rs");
        let verify_start = source.find("pub fn verify_payload_hashes").unwrap();
        let verify_end = source
            .find("pub fn verify_payload_matches_manifest")
            .unwrap();
        let verify_source = &source[verify_start..verify_end];

        assert!(source.contains("const MAX_PAYLOAD_HASH_PATH_BYTES"));
        assert!(source.contains("fn validate_payload_hash_manifest_shape"));
        assert!(verify_source.contains("validate_payload_hash_manifest_shape(expected_hashes)?"));
        assert!(
            verify_source.find("validate_payload_hash_manifest_shape(expected_hashes)?")
                < verify_source.find("open_checked_package_file()?")
        );
        assert!(source.contains("payload_hashes_reject_excessive_manifest_entries"));
        assert!(source.contains("payload_hashes_reject_oversized_manifest_paths"));
        assert!(source.contains("payload_hashes_reject_nul_manifest_paths"));
    }

    #[test]
    fn payload_extraction_rejects_driver_tools_payload_path() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/driver-tools/readme.txt", options)
            .unwrap();
        archive.write_all(b"safe driver-tool test fixture").unwrap();
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .extract_payload_to(&dir.path().join("staging"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("driver payload paths require a separate explicit driver workflow"));
    }

    #[test]
    fn payload_extraction_cleanup_failures_are_reported() {
        let source = include_str!("update_package.rs");
        let start = source.find("pub fn extract_payload_to").unwrap();
        let end = source.find("fn ensure_package_path_safe").unwrap();
        let extraction_source = &source[start..end];
        let ignored_cleanup = ["let _ = std::fs::remove_", "file(&temp_target);"].concat();

        assert!(extraction_source.contains("fn cleanup_extraction_temp_file"));
        assert!(extraction_source.contains("after copy failure"));
        assert!(extraction_source.contains("after sync failure"));
        assert!(extraction_source.contains("after activation failure"));
        assert!(!extraction_source.contains(&ignored_cleanup));
    }

    #[test]
    fn payload_extraction_cleanup_rejects_non_regular_targets() {
        let dir = tempdir().unwrap();
        let temp_target = dir.path().join(".Avorax.exe.cleanup.avorax-part");
        std::fs::create_dir_all(&temp_target).unwrap();

        let error = UpdatePackage::cleanup_extraction_temp_file(&temp_target)
            .unwrap_err()
            .to_string();

        assert!(error.contains("temporary payload extraction cleanup target is not a regular file"));
    }

    #[test]
    fn payload_extraction_rejects_existing_target_file() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let destination = dir.path().join("staging");
        write_payload_package(
            &package_path,
            "payload/app/Avorax.exe",
            b"safe payload fixture",
        );
        std::fs::create_dir_all(destination.join("app")).unwrap();
        std::fs::write(destination.join("app/Avorax.exe"), b"existing").unwrap();

        let error = UpdatePackage::new(&package_path)
            .extract_payload_to(&destination)
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload extraction target already exists"));
    }

    #[cfg(unix)]
    #[test]
    fn payload_extraction_rejects_broken_symbolic_link_target() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let destination = dir.path().join("staging");
        write_payload_package(
            &package_path,
            "payload/app/Avorax.exe",
            b"safe payload fixture",
        );
        std::fs::create_dir_all(destination.join("app")).unwrap();
        symlink("missing-target", destination.join("app/Avorax.exe")).unwrap();

        let error = UpdatePackage::new(&package_path)
            .extract_payload_to(&destination)
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn payload_extraction_target_presence_uses_non_following_metadata() {
        let source = include_str!("update_package.rs");
        let start = source.find("pub fn extract_payload_to").unwrap();
        let end = source
            .find("fn ensure_payload_extraction_target_absent")
            .unwrap();
        let extraction_source = &source[start..end];
        let old_probe = ["target", ".exists()"].join("");

        assert!(source.contains("fn ensure_payload_extraction_target_absent"));
        assert!(extraction_source.contains("ensure_payload_extraction_target_absent(&target)?"));
        assert!(source.contains("std::fs::symlink_metadata(target)"));
        assert!(source.contains("failed to inspect payload extraction target"));
        assert!(!extraction_source.contains(&old_probe));
    }

    #[test]
    fn payload_extraction_revalidates_canonical_destination() {
        let source = include_str!("update_package.rs");
        let start = source.find("pub fn extract_payload_to").unwrap();
        let end = source
            .find("fn ensure_existing_payload_extraction_directory")
            .unwrap();
        let extraction_source = &source[start..end];
        let helper_source = &source[end..source.find("fn ensure_package_path_safe").unwrap()];

        assert!(
            extraction_source.find(".canonicalize()").unwrap()
                < extraction_source
                    .find("ensure_existing_payload_extraction_directory")
                    .unwrap()
        );
        assert!(extraction_source.contains(
            "ensure_existing_payload_extraction_directory(\n            &destination,\n            \"canonical payload extraction destination\",\n        )?"
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
    fn payload_hash_and_extraction_enforce_actual_byte_limits() {
        let source = include_str!("update_package.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let extraction_source = &production[production
            .find("pub fn extract_payload_to")
            .expect("extract helper must exist")
            ..production
                .find("fn activate_extracted_payload_file")
                .expect("activation helper must exist")];
        let hash_source = &production[production
            .find("fn hash_archive_entry_by_normalized_name")
            .expect("hash helper must exist")
            ..production
                .find("pub fn safe_relative_path")
                .expect("safe path helper must exist")];

        assert!(production.contains("fn sha256_reader_limited"));
        assert!(production.contains("fn copy_reader_limited"));
        assert!(production.contains("total <= limit"));
        assert!(hash_source.contains("sha256_reader_limited("));
        assert!(hash_source.contains("MAX_PAYLOAD_ENTRY_BYTES"));
        assert!(extraction_source.contains("let mut extracted_uncompressed = 0u64"));
        assert!(extraction_source.contains("copy_reader_limited("));
        assert!(extraction_source.contains("MAX_PAYLOAD_ENTRY_BYTES"));
        assert!(extraction_source.contains("MAX_PAYLOAD_UNCOMPRESSED_BYTES"));
        assert!(extraction_source.contains("after aggregate size failure"));
        assert!(!extraction_source.contains("std::io::copy(&mut entry"));
    }

    #[test]
    fn payload_activation_rechecks_target_before_rename() {
        let dir = tempdir().unwrap();
        let temp_target = dir.path().join(".Avorax.exe.test.avorax-part");
        let target = dir.path().join("Avorax.exe");
        std::fs::write(&temp_target, b"new payload").unwrap();
        std::fs::write(&target, b"existing payload").unwrap();

        let error =
            UpdatePackage::activate_extracted_payload_file(&temp_target, &target, dir.path())
                .unwrap_err()
                .to_string();

        assert!(error.contains("payload extraction target already exists"));
        assert!(temp_target.exists());
        assert_eq!(std::fs::read(&target).unwrap(), b"existing payload");
    }

    #[test]
    fn payload_activation_rechecks_parent_chain_before_rename() {
        let source = include_str!("update_package.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let activation_source = &production[production
            .find("fn activate_extracted_payload_file")
            .expect("activation helper must exist")
            ..production
                .find("fn ensure_extraction_temp_file_ready")
                .expect("temp file helper must exist")];

        assert!(activation_source.contains("destination: &Path"));
        assert!(activation_source.contains("ensure_existing_path_chain_not_link("));
        assert!(activation_source.contains("\"payload extraction destination\""));
        assert_eq!(
            activation_source
                .matches("ensure_existing_path_chain_not_link(")
                .count(),
            2
        );
        assert!(
            activation_source
                .find("ensure_existing_path_chain_not_link(")
                .unwrap()
                < activation_source
                    .find("ensure_payload_extraction_target_absent(target)?")
                    .unwrap()
        );
        assert!(
            activation_source
                .rfind("ensure_existing_path_chain_not_link(")
                .unwrap()
                > activation_source
                    .find("ensure_payload_extraction_target_absent(target)?")
                    .unwrap()
        );
        assert!(
            activation_source
                .rfind("ensure_existing_path_chain_not_link(")
                .unwrap()
                < activation_source
                    .find("std::fs::rename(temp_target, target)")
                    .unwrap()
        );
    }

    #[test]
    fn payload_activation_rechecks_temp_file_type_before_rename() {
        let dir = tempdir().unwrap();
        let temp_target = dir.path().join(".Avorax.exe.test.avorax-part");
        let target = dir.path().join("Avorax.exe");
        std::fs::create_dir_all(&temp_target).unwrap();

        let error =
            UpdatePackage::activate_extracted_payload_file(&temp_target, &target, dir.path())
                .unwrap_err()
                .to_string();

        assert!(error.contains("payload extraction temporary file is not a regular file"));
    }

    #[test]
    fn extraction_temp_timestamp_errors_are_reported() {
        let source = include_str!("update_package.rs");
        let start = source.find("fn extraction_temp_path").unwrap();
        let end = source.find("fn validate_payload_limits").unwrap();
        let temp_source = &source[start..end];

        assert!(temp_source
            .contains("failed to read system time for payload extraction temporary file"));
        assert!(!temp_source.contains(".unwrap_or_default()"));
    }

    #[test]
    fn payload_component_defaults_are_not_silent() {
        let source = include_str!("update_package.rs");
        let start = source.find("fn ensure_no_restricted_payload_path").unwrap();
        let end = source.find("#[cfg(test)]").unwrap();
        let component_source = &source[start..end];

        assert!(component_source.contains("let first = payload_root(relative)?"));
        assert!(component_source.contains("first != \"tools\""));
        assert!(component_source.contains("first != \"migrations\""));
        assert!(!component_source.contains("\"tools\" => true"));
        assert!(!component_source.contains("\"migrations\" => true"));
        assert!(component_source.contains("direct_service_payload_file_name(relative)?"));
        assert!(component_source.contains("service payload must be directly under services"));
        assert!(component_source.contains("is not supported by normal updates"));
        assert!(component_source.contains("engine_payload_subcomponent(relative)?"));
        assert!(
            component_source.contains("payload_second_component(relative, \"engine payload\")?")
        );
        assert!(component_source
            .contains("engine payload subcomponent {other} is not supported by normal updates"));
        assert!(component_source
            .contains("manifest.components.native_engine_assets && subcomponent_allowed"));
        assert!(!component_source.contains("_ => manifest.components.native_engine_assets"));
        assert!(component_source.contains("path is missing a UTF-8 filename"));
        assert!(component_source.contains("path contains a non-UTF-8 component"));
        assert!(!component_source.contains(".unwrap_or_default()"));
    }

    #[test]
    fn manifest_payload_verification_rejects_undeclared_service_root() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe service fixture";
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/services/avorax_core_service.exe", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "services/avorax_core_service.exe".to_string(),
            sha256_bytes(payload),
        );
        let manifest = manifest_with_hashes(hashes);
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("service payload"));
        assert!(error.contains("avorax_core_service.exe"));
        assert!(error.contains("is not declared"));
    }

    #[test]
    fn manifest_payload_verification_rejects_unknown_payload_root() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe unknown-root fixture";
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/unknown/file.txt", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("unknown/file.txt".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        manifest.components.core_service = true;
        manifest.components.guard_service = true;
        manifest.components.native_engine_assets = true;
        manifest.components.docs = true;
        manifest.migration_steps.push("safe-test-step".to_string());
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload root unknown is not declared"));
    }

    #[test]
    fn manifest_payload_verification_rejects_tools_payload_even_with_migration_steps() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe tooling fixture";
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/tools/helper.ps1", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("tools/helper.ps1".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        manifest.components.core_service = true;
        manifest.components.guard_service = true;
        manifest.components.native_engine_assets = true;
        manifest.components.signatures = true;
        manifest.components.rules = true;
        manifest.components.ml_model = true;
        manifest.components.trust_packs = true;
        manifest.components.docs = true;
        manifest.migration_steps.push("safe-test-step".to_string());
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("tools payload paths require a separate explicit tooling workflow"));
    }

    #[test]
    fn manifest_payload_verification_rejects_migration_payload_even_with_migration_steps() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe migration fixture";
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/migrations/step.ps1", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert("migrations/step.ps1".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.migration_steps.push("safe-test-step".to_string());
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error
            .contains("migration payload paths require a separate explicit migration workflow"));
    }

    #[test]
    fn manifest_payload_verification_rejects_app_nested_restricted_payload() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe nested engine fixture";
        write_payload_package(
            &package_path,
            "payload/app/engine/signatures/pack.avsig",
            payload,
        );

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "app/engine/signatures/pack.avsig".to_string(),
            sha256_bytes(payload),
        );
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("app payload must not target restricted install path engine"));
    }

    #[test]
    fn manifest_payload_verification_rejects_app_managed_updater_executable() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe updater-name fixture";
        write_payload_package(
            &package_path,
            "payload/app/avorax_update_service.exe",
            payload,
        );

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "app/avorax_update_service.exe".to_string(),
            sha256_bytes(payload),
        );
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("app payload must not include managed service or updater executable")
        );
    }

    #[test]
    fn manifest_payload_verification_rejects_declared_app_without_payload() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe markdown docs fixture";
        write_payload_package(&package_path, "payload/docs/release.md", payload);

        let mut hashes = BTreeMap::new();
        hashes.insert("docs/release.md".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        manifest.components.docs = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("manifest component app is declared"));
        assert!(error.contains("no app payload hash is listed"));
    }

    #[test]
    fn manifest_payload_verification_rejects_declared_core_service_without_payload() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe app fixture";
        write_payload_package(&package_path, "payload/app/Avorax.exe", payload);

        let mut hashes = BTreeMap::new();
        hashes.insert("app/Avorax.exe".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        manifest.components.core_service = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("manifest component core_service is declared"));
        assert!(error.contains("no services/avorax_core_service.exe hash is listed"));
    }

    #[test]
    fn manifest_payload_verification_rejects_undeclared_guard_service_file() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe guard service fixture";
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/services/avorax_guard_service.exe", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "services/avorax_guard_service.exe".to_string(),
            sha256_bytes(payload),
        );
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.core_service = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("service payload"));
        assert!(error.contains("avorax_guard_service.exe"));
        assert!(error.contains("is not declared"));
    }

    #[test]
    fn manifest_payload_verification_rejects_unknown_service_file() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe unknown service fixture";
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/services/extra_service.exe", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "services/extra_service.exe".to_string(),
            sha256_bytes(payload),
        );
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.core_service = true;
        manifest.components.guard_service = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("service payload"));
        assert!(error.contains("extra_service.exe"));
        assert!(error.contains("is not supported by normal updates"));
    }

    #[test]
    fn manifest_payload_verification_rejects_nested_service_file() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe nested service fixture";
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/services/nested/avorax_core_service.exe", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "services/nested/avorax_core_service.exe".to_string(),
            sha256_bytes(payload),
        );
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.core_service = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("service payload must be directly under services"));
    }

    #[test]
    fn manifest_payload_verification_rejects_undeclared_engine_subcomponent() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe signature fixture";
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive
            .start_file("payload/engine/signatures/defs.zsig", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "engine/signatures/defs.zsig".to_string(),
            sha256_bytes(payload),
        );
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.native_engine_assets = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload root engine is not declared"));
    }

    #[test]
    fn manifest_payload_verification_rejects_unknown_engine_subcomponent() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe test-corpus fixture";
        write_payload_package(
            &package_path,
            "payload/engine/test_corpus/README.md",
            payload,
        );

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "engine/test_corpus/README.md".to_string(),
            sha256_bytes(payload),
        );
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.native_engine_assets = true;
        manifest.components.signatures = true;
        manifest.components.rules = true;
        manifest.components.ml_model = true;
        manifest.components.trust_packs = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains(
            "engine payload subcomponent test_corpus is not supported by normal updates"
        ));
    }

    #[test]
    fn manifest_payload_verification_rejects_engine_subcomponent_file() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe engine component file fixture";
        write_payload_package(&package_path, "payload/engine/signatures", payload);

        let mut hashes = BTreeMap::new();
        hashes.insert("engine/signatures".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.native_engine_assets = true;
        manifest.components.signatures = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("engine payload must be a file under an explicit runtime subdirectory")
        );
    }

    #[test]
    fn manifest_payload_verification_rejects_declared_engine_without_payload() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe app fixture";
        write_payload_package(&package_path, "payload/app/Avorax.exe", payload);

        let mut hashes = BTreeMap::new();
        hashes.insert("app/Avorax.exe".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        manifest.components.native_engine_assets = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("manifest component native_engine_assets is declared"));
        assert!(error.contains("no engine payload hash is listed"));
    }

    #[test]
    fn manifest_payload_verification_rejects_declared_engine_subcomponent_without_payload() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let app_payload = b"safe app fixture";
        let rules_payload = b"safe rule fixture";
        write_payload_package_entries(
            &package_path,
            &[
                ("payload/app/Avorax.exe", app_payload.as_slice()),
                ("payload/engine/rules/rule.avrule", rules_payload.as_slice()),
            ],
        );

        let mut hashes = BTreeMap::new();
        hashes.insert("app/Avorax.exe".to_string(), sha256_bytes(app_payload));
        hashes.insert(
            "engine/rules/rule.avrule".to_string(),
            sha256_bytes(rules_payload),
        );
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        manifest.components.native_engine_assets = true;
        manifest.components.rules = true;
        manifest.components.signatures = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("manifest component signatures is declared"));
        assert!(error.contains("no engine/signatures payload hash is listed"));
    }

    #[test]
    fn manifest_payload_verification_rejects_non_markdown_docs_payload() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe docs script fixture";
        write_payload_package(&package_path, "payload/docs/helper.ps1", payload);

        let mut hashes = BTreeMap::new();
        hashes.insert("docs/helper.ps1".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.docs = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("docs payload file must be Markdown-only for normal updates"));
    }

    #[test]
    fn manifest_payload_verification_rejects_declared_docs_without_payload() {
        let dir = tempdir().unwrap();
        let package_path = dir.path().join("update.aup");
        let payload = b"safe app fixture";
        write_payload_package(&package_path, "payload/app/Avorax.exe", payload);

        let mut hashes = BTreeMap::new();
        hashes.insert("app/Avorax.exe".to_string(), sha256_bytes(payload));
        let mut manifest = manifest_with_hashes(hashes);
        manifest.components.app = true;
        manifest.components.docs = true;
        let error = UpdatePackage::new(&package_path)
            .verify_payload_matches_manifest(&manifest)
            .unwrap_err()
            .to_string();

        assert!(error.contains("manifest component docs is declared"));
        assert!(error.contains("no docs payload hash is listed"));
    }
}
