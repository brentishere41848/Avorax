use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let manifest_path = PathBuf::from(args.next().context("manifest path is required")?);
    let sig_path = PathBuf::from(args.next().context("signature output path is required")?);
    anyhow::ensure!(args.next().is_none(), "unexpected extra signer arguments");
    let private_key_hex = std::env::var("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
        .context("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX is required")?;
    let key_bytes = hex::decode(private_key_hex.trim()).context("invalid private key hex")?;
    anyhow::ensure!(
        key_bytes.len() == 32 || key_bytes.len() == 64,
        "Ed25519 private key must be a 32-byte seed or 64-byte expanded key"
    );
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&key_bytes[..32]);
    let signing_key = SigningKey::from_bytes(&seed);
    let manifest = read_manifest_bounded(&manifest_path)?;
    ensure_new_signature_output(&sig_path)?;
    let signature = signing_key.sign(&manifest);
    write_new_signature(
        &sig_path,
        format!("{}\n", hex::encode(signature.to_bytes())).as_bytes(),
    )?;
    Ok(())
}

fn read_manifest_bounded(path: &Path) -> Result<Vec<u8>> {
    ensure_absolute_local_path(path, "manifest path")?;
    ensure_existing_ancestors_not_link(path, "manifest path")?;
    ensure_not_link_or_reparse(path, "manifest path")?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect manifest path {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "manifest path is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_MANIFEST_BYTES,
        "manifest path exceeds maximum size: {}",
        path.display()
    );
    read_file_bounded(path, MAX_MANIFEST_BYTES, "manifest path")
}

fn read_file_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut input = std::fs::File::open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .with_context(|| format!("failed to read {label} {}", path.display()))?;
        if read == 0 {
            return Ok(bytes);
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("{label} read size overflow"))?;
        anyhow::ensure!(
            total <= limit,
            "{label} exceeds maximum size: {}",
            path.display()
        );
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn ensure_new_signature_output(path: &Path) -> Result<()> {
    ensure_absolute_local_path(path, "signature output path")?;
    let parent = path
        .parent()
        .context("signature output path is missing a parent directory")?;
    ensure_existing_ancestors_not_link(parent, "signature output directory")?;
    ensure_not_link_or_reparse(parent, "signature output directory")?;
    let parent_metadata = std::fs::symlink_metadata(parent).with_context(|| {
        format!(
            "failed to inspect signature output directory {}",
            parent.display()
        )
    })?;
    anyhow::ensure!(
        parent_metadata.is_dir(),
        "signature output directory is not a directory: {}",
        parent.display()
    );
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            ensure_not_link_or_reparse(path, "signature output path")?;
            anyhow::bail!("signature output path already exists: {}", path.display());
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect signature output path {}", path.display())),
    }
}

fn write_new_signature(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    output
        .flush()
        .and_then(|_| output.sync_all())
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

fn ensure_absolute_local_path(path: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(
        path.is_absolute(),
        "{label} must be an absolute path: {}",
        path.display()
    );
    #[cfg(windows)]
    {
        anyhow::ensure!(
            has_windows_drive_prefix(path),
            "{label} must be on a local Windows drive: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn has_windows_drive_prefix(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
}

fn ensure_existing_ancestors_not_link(path: &Path, label: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(_) => ensure_not_link_or_reparse(&current, label)?,
            Err(error) if error.kind() == ErrorKind::NotFound => break,
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

fn ensure_not_link_or_reparse(path: &Path, label: &str) -> Result<()> {
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
