use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use zip::ZipArchive;

use crate::update_manifest::UpdateManifest;

pub struct UpdatePackage {
    pub path: PathBuf,
}

impl UpdatePackage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn read_manifest(&self) -> Result<UpdateManifest> {
        let file = File::open(&self.path)
            .with_context(|| format!("failed to open update package {}", self.path.display()))?;
        let mut archive = ZipArchive::new(file).context("failed to open .aup archive")?;
        let mut manifest = archive
            .by_name("manifest.json")
            .context("update package is missing manifest.json")?;
        let mut text = String::new();
        manifest
            .read_to_string(&mut text)
            .context("failed to read update manifest")?;
        serde_json::from_str(&text).context("failed to parse update manifest")
    }

    pub fn read_manifest_bytes_and_signature(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let file = File::open(&self.path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut manifest = archive.by_name("manifest.json")?;
        let mut manifest_bytes = Vec::new();
        manifest.read_to_end(&mut manifest_bytes)?;
        drop(manifest);
        let mut sig = archive.by_name("manifest.sig")?;
        let mut signature_text = String::new();
        sig.read_to_string(&mut signature_text)?;
        let signature = hex::decode(signature_text.trim()).context("manifest.sig is not hex")?;
        Ok((manifest_bytes, signature))
    }

    pub fn package_sha256(&self) -> Result<String> {
        sha256_file(&self.path)
    }

    pub fn verify_payload_hashes(&self, expected_hashes: &BTreeMap<String, String>) -> Result<()> {
        anyhow::ensure!(
            !expected_hashes.is_empty(),
            "update package manifest does not list payload hashes"
        );

        let file = File::open(&self.path)?;
        let mut archive = ZipArchive::new(file)?;
        for (relative, expected_hash) in expected_hashes {
            let relative_path = safe_relative_path(&relative.replace('\\', "/"))?;
            let archive_name = format!(
                "payload/{}",
                relative_path.to_string_lossy().replace('\\', "/")
            );
            let mut entry = archive
                .by_name(&archive_name)
                .with_context(|| format!("payload file missing from package: {archive_name}"))?;
            let actual_hash = sha256_reader(&mut entry)?;
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
            let key = relative.to_string_lossy().replace('\\', "/");
            anyhow::ensure!(
                expected_hashes.contains_key(&key),
                "payload file is not listed in signed manifest: {key}"
            );
        }

        Ok(())
    }

    pub fn extract_payload_to(&self, destination: &Path) -> Result<()> {
        std::fs::create_dir_all(destination)?;
        let file = File::open(&self.path)?;
        let mut archive = ZipArchive::new(file)?;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let name = entry.name().replace('\\', "/");
            if !name.starts_with("payload/") || name.ends_with('/') {
                continue;
            }
            let relative = safe_relative_path(name.trim_start_matches("payload/"))?;
            let target = destination.join(relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut output = File::create(&target)?;
            std::io::copy(&mut entry, &mut output)?;
        }
        Ok(())
    }
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    sha256_reader(&mut file)
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
