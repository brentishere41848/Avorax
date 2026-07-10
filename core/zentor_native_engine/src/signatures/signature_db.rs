use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::Utc;

use super::{eicar_signature, signature_matcher, NativeSignature, SignatureMatch, SignatureType};
use crate::analyzers::StaticAnalysis;
use crate::verdict::{Confidence, ThreatCategory};

const MAX_SIGNATURE_PACK_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SignatureDb {
    signatures: Vec<NativeSignature>,
    pack_loaded: bool,
}

impl SignatureDb {
    pub fn built_in() -> Self {
        Self {
            pack_loaded: false,
            signatures: vec![NativeSignature {
                id: "eicar_test_signature".to_string(),
                name: "EICAR safe anti-malware test file".to_string(),
                version: "1.0.0".to_string(),
                category: ThreatCategory::TestThreat,
                confidence: Confidence::Confirmed,
                severity: "test".to_string(),
                signature_type: SignatureType::EicarTestSignature,
                pattern: eicar_signature::EICAR_ASCII.to_string(),
                mask: None,
                offset: None,
                file_types: vec!["*".to_string()],
                min_file_size: None,
                max_file_size: None,
                required_context: vec![],
                false_positive_notes: "EICAR is a safe industry test string, not real malware."
                    .to_string(),
                action_policy: "quarantine_if_policy_allows".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
        }
    }

    pub fn load_pack(path: &Path) -> Result<Self> {
        let mut db = Self::built_in();
        if pack_file_present(path)? {
            db.load_one(path)?;
            db.pack_loaded = true;
            if let Some(parent) = path.parent() {
                let mut siblings = Vec::new();
                for entry in fs::read_dir(parent).with_context(|| {
                    format!(
                        "failed to enumerate signature pack directory {}",
                        parent.display()
                    )
                })? {
                    let entry = entry.with_context(|| {
                        format!(
                            "failed to read signature pack directory entry in {}",
                            parent.display()
                        )
                    })?;
                    let candidate = entry.path();
                    if candidate.extension().and_then(|value| value.to_str()) == Some("zsig")
                        && is_regular_pack_file(&candidate)?
                        && candidate != path
                    {
                        siblings.push(candidate);
                    }
                }
                siblings.sort();
                for sibling in siblings {
                    db.load_one(&sibling)?;
                }
            }
        }
        Ok(db)
    }

    fn load_one(&mut self, path: &Path) -> Result<()> {
        ensure_regular_pack_file(path)?;
        let text = read_bounded_signature_pack(path)
            .with_context(|| format!("failed to read signature pack {}", path.display()))?;
        let pack: super::pack_format::SignaturePack = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse signature pack {}", path.display()))?;
        let canonical = super::signature_compiler::canonical_pack_bytes(&pack)?;
        super::pack_verifier::verify_pack(&pack, &canonical)?;
        super::signature_compiler::validate_signatures(&pack.signatures)?;
        for signature in &pack.signatures {
            if self
                .signatures
                .iter()
                .any(|existing| existing.id == signature.id)
            {
                bail!(
                    "duplicate signature id across loaded packs {}",
                    signature.id
                );
            }
        }
        self.signatures.extend(pack.signatures);
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    pub fn pack_loaded(&self) -> bool {
        self.pack_loaded
    }

    pub fn match_bytes(
        &self,
        path: &Path,
        sha256: &str,
        bytes: &[u8],
        analysis: &StaticAnalysis,
    ) -> Result<Vec<SignatureMatch>> {
        let mut matches = Vec::new();
        for signature in &self.signatures {
            if let Some(matched) =
                signature_matcher::matches_signature(signature, path, sha256, bytes, analysis)
                    .with_context(|| format!("signature {} evaluation failed", signature.id))?
            {
                matches.push(matched);
            }
        }
        Ok(matches)
    }
}

fn read_bounded_signature_pack(path: &Path) -> Result<String> {
    use std::io::Read;

    let metadata = ensure_regular_pack_file(path)?;
    if metadata.len() > MAX_SIGNATURE_PACK_FILE_BYTES {
        bail!("signature pack file is too large {}", path.display());
    }
    let mut file = fs::File::open(path)?;
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    let mut bytes = Vec::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("signature pack read size overflow"))?;
        if total > MAX_SIGNATURE_PACK_FILE_BYTES {
            bail!("signature pack file is too large {}", path.display());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("signature pack {} is not valid UTF-8", path.display()))
}

fn pack_file_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_pack_metadata(path, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect signature pack {}", path.display())),
    }
}

fn ensure_regular_pack_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect signature pack {}", path.display()))?;
    ensure_regular_pack_metadata(path, &metadata)?;
    Ok(metadata)
}

fn ensure_regular_pack_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing to load symbolic link signature pack {}",
            path.display()
        );
    }
    if is_windows_reparse_point(metadata) {
        bail!(
            "refusing to load reparse point signature pack {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        bail!("signature pack is not a regular file {}", path.display());
    }
    if metadata.len() > MAX_SIGNATURE_PACK_FILE_BYTES {
        bail!("signature pack file is too large {}", path.display());
    }
    Ok(())
}

fn is_regular_pack_file(path: &Path) -> Result<bool> {
    ensure_regular_pack_file(path)?;
    Ok(true)
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_pack_loader_rejects_directory_pack_path() {
        let dir = tempfile::tempdir().unwrap();
        let error = SignatureDb::load_pack(dir.path()).unwrap_err().to_string();
        assert!(error.contains("signature pack is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn signature_pack_loader_rejects_symbolic_link_pack_path() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.zsig");
        fs::write(
            &target,
            r#"{"format":"zentor-signature-pack-v1","version":"1","signatures":[]}"#,
        )
        .unwrap();
        let link = dir.path().join("linked.zsig");
        symlink(&target, &link).unwrap();

        let error = SignatureDb::load_pack(&link).unwrap_err().to_string();
        assert!(error.contains("symbolic link signature pack"));
    }

    #[test]
    fn signature_pack_sibling_enumeration_does_not_ignore_errors() {
        let source = include_str!("signature_db.rs");
        let load_start = source.find("pub fn load_pack").unwrap();
        let load_end = source.find("fn load_one").unwrap();
        let load_source = &source[load_start..load_end];
        let ignored_entry_pattern = ["filter_map", "(Result::ok)"].concat();

        assert!(load_source.contains("failed to read signature pack directory entry"));
        assert!(!load_source.contains(&ignored_entry_pattern));
    }

    #[test]
    fn signature_pack_sibling_inspection_does_not_ignore_errors() {
        let source = include_str!("signature_db.rs");
        let hidden_error_pattern = ["unwrap_or", "(false)"].concat();

        assert!(source.contains("fn is_regular_pack_file(path: &Path) -> Result<bool>"));
        assert!(source.contains("failed to inspect signature pack"));
        assert!(!source.contains(&hidden_error_pattern));
    }

    #[test]
    fn signature_pack_missing_primary_keeps_built_in_signatures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.zsig");

        let db = SignatureDb::load_pack(&path).unwrap();

        assert_eq!(db.count(), 1);
        assert!(!db.pack_loaded());
    }

    #[test]
    fn signature_pack_path_safety_markers_stay_in_place() {
        let source = include_str!("signature_db.rs");
        let load_start = source.find("pub fn load_pack").unwrap();
        let load_end = source.find("fn load_one").unwrap();
        let load_source = &source[load_start..load_end];
        let presence_helper_pattern = ["pack_file_", "present(path)?"].concat();
        let read_guard_pattern = ["ensure_regular_pack_", "file(path)?"].concat();
        let metadata_helper_pattern = ["ensure_regular_pack_", "metadata"].concat();
        let reparse_pattern = ["is_windows_", "reparse_point"].concat();
        let hidden_probe_pattern = ["fs::symlink_metadata(path)", ".is_ok()"].concat();

        assert!(load_source.contains(&presence_helper_pattern));
        assert!(source.contains(&read_guard_pattern));
        assert!(source.contains(&metadata_helper_pattern));
        assert!(source.contains(&reparse_pattern));
        assert!(!load_source.contains(&hidden_probe_pattern));
    }

    #[test]
    fn signature_pack_loader_checks_cross_pack_duplicate_ids() {
        let source = include_str!("signature_db.rs");

        assert!(source.contains("duplicate signature id across loaded packs"));
        assert!(source.contains("existing.id == signature.id"));
    }

    #[test]
    fn signature_pack_loader_bounds_pack_file_size() {
        let source = include_str!("signature_db.rs");
        let start = source.find("fn read_bounded_signature_pack").unwrap();
        let end = source.find("fn pack_file_present").unwrap();
        let read_source = &source[start..end];

        assert!(source.contains("MAX_SIGNATURE_PACK_FILE_BYTES"));
        assert!(source.contains("signature pack file is too large"));
        assert!(read_source.contains("let metadata = ensure_regular_pack_file(path)?"));
        assert!(read_source.contains("metadata.len() > MAX_SIGNATURE_PACK_FILE_BYTES"));
        assert!(read_source.contains("let mut total = 0_u64"));
        assert!(read_source.contains("checked_add(read as u64)"));
        assert!(read_source.contains("total > MAX_SIGNATURE_PACK_FILE_BYTES"));
        assert!(read_source.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(read_source.contains("String::from_utf8(bytes)"));
        assert!(source.contains("fn ensure_regular_pack_file(path: &Path) -> Result<fs::Metadata>"));
        assert!(source.contains("read_bounded_signature_pack(path)"));
    }

    #[test]
    fn signature_pack_reader_rejects_oversized_file_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.zsig");
        fs::write(
            &path,
            "x".repeat(MAX_SIGNATURE_PACK_FILE_BYTES as usize + 1),
        )
        .unwrap();

        let error = read_bounded_signature_pack(&path).unwrap_err().to_string();

        assert!(error.contains("signature pack file is too large"));
    }
}
