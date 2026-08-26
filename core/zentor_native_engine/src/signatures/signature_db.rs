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
const MAX_SIGNATURE_PACK_FILES: usize = 32;
const MAX_SIGNATURE_PACK_DIRECTORY_ENTRIES: usize = 256;
const MAX_SIGNATURE_PACK_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOADED_SIGNATURES: usize = 4096;

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
                pattern: eicar_signature::eicar_test_string(),
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
            let primary_metadata = ensure_regular_pack_file(path)?;
            let mut pack_file_count = 1usize;
            let mut inspected_directory_entries = 0usize;
            let mut total_pack_bytes = primary_metadata.len();
            let mut siblings = Vec::new();
            if let Some(parent) = path.parent() {
                for entry in fs::read_dir(parent).with_context(|| {
                    format!(
                        "failed to enumerate signature pack directory {}",
                        parent.display()
                    )
                })? {
                    inspected_directory_entries =
                        inspected_directory_entries.checked_add(1).ok_or_else(|| {
                            anyhow::anyhow!("signature pack directory entry count overflow")
                        })?;
                    if inspected_directory_entries > MAX_SIGNATURE_PACK_DIRECTORY_ENTRIES {
                        bail!(
                            "signature pack directory exceeds maximum inspected entry count of {}",
                            MAX_SIGNATURE_PACK_DIRECTORY_ENTRIES
                        );
                    }
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
                        pack_file_count = pack_file_count
                            .checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("signature pack file count overflow"))?;
                        if pack_file_count > MAX_SIGNATURE_PACK_FILES {
                            bail!(
                                "signature pack set exceeds maximum file count of {}",
                                MAX_SIGNATURE_PACK_FILES
                            );
                        }
                        let candidate_bytes = ensure_regular_pack_file(&candidate)?.len();
                        total_pack_bytes = total_pack_bytes
                            .checked_add(candidate_bytes)
                            .ok_or_else(|| anyhow::anyhow!("signature pack total size overflow"))?;
                        if total_pack_bytes > MAX_SIGNATURE_PACK_TOTAL_BYTES {
                            bail!(
                                "signature pack set exceeds maximum total bytes of {}",
                                MAX_SIGNATURE_PACK_TOTAL_BYTES
                            );
                        }
                        siblings.push(candidate);
                    }
                }
            }
            siblings.sort();
            let mut loaded_pack_bytes = db.load_one(path, MAX_SIGNATURE_PACK_TOTAL_BYTES)?;
            db.pack_loaded = true;
            for sibling in siblings {
                let remaining_pack_bytes = MAX_SIGNATURE_PACK_TOTAL_BYTES
                    .checked_sub(loaded_pack_bytes)
                    .ok_or_else(|| anyhow::anyhow!("signature pack loaded size overflow"))?;
                let sibling_bytes = db.load_one(&sibling, remaining_pack_bytes)?;
                loaded_pack_bytes = loaded_pack_bytes
                    .checked_add(sibling_bytes)
                    .ok_or_else(|| anyhow::anyhow!("signature pack loaded size overflow"))?;
            }
        }
        Ok(db)
    }

    fn load_one(&mut self, path: &Path, remaining_pack_bytes: u64) -> Result<u64> {
        ensure_regular_pack_file(path)?;
        let text = read_bounded_signature_pack_with_limit(path, remaining_pack_bytes)
            .with_context(|| format!("failed to read signature pack {}", path.display()))?;
        let loaded_bytes = u64::try_from(text.len())
            .map_err(|_| anyhow::anyhow!("signature pack loaded size overflow"))?;
        let pack: super::pack_format::SignaturePack = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse signature pack {}", path.display()))?;
        let canonical = super::signature_compiler::canonical_pack_bytes(&pack)?;
        super::pack_verifier::verify_pack(&pack, &canonical)?;
        super::signature_compiler::validate_signatures(&pack.signatures)?;
        self.ensure_signature_capacity(pack.signatures.len())?;
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
        Ok(loaded_bytes)
    }

    fn ensure_signature_capacity(&self, additional: usize) -> Result<()> {
        let next = self
            .signatures
            .len()
            .checked_add(additional)
            .ok_or_else(|| anyhow::anyhow!("loaded signature count overflow"))?;
        if next > MAX_LOADED_SIGNATURES {
            bail!(
                "loaded signature count exceeds maximum of {}",
                MAX_LOADED_SIGNATURES
            );
        }
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
        let mut never_cancel = || Ok(());
        self.match_bytes_with_cancellation(path, sha256, bytes, analysis, &mut never_cancel)
    }

    pub fn match_bytes_with_cancellation(
        &self,
        path: &Path,
        sha256: &str,
        bytes: &[u8],
        analysis: &StaticAnalysis,
        cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<SignatureMatch>> {
        let lower_text =
            super::text::ascii_lowercase_lossy_with_cancellation(bytes, cancellation_checkpoint)?;
        let mut matches = Vec::new();
        for signature in &self.signatures {
            cancellation_checkpoint()?;
            if let Some(matched) =
                signature_matcher::matches_signature_with_prepared_text_and_cancellation(
                    signature,
                    path,
                    sha256,
                    bytes,
                    analysis,
                    &lower_text,
                    cancellation_checkpoint,
                )
                .with_context(|| format!("signature {} evaluation failed", signature.id))?
            {
                matches.push(matched);
            }
        }
        cancellation_checkpoint()?;
        Ok(matches)
    }
}

#[cfg(test)]
fn read_bounded_signature_pack(path: &Path) -> Result<String> {
    read_bounded_signature_pack_with_limit(path, MAX_SIGNATURE_PACK_FILE_BYTES)
}

fn read_bounded_signature_pack_with_limit(
    path: &Path,
    remaining_pack_bytes: u64,
) -> Result<String> {
    use std::io::Read;

    let metadata = ensure_regular_pack_file(path)?;
    if metadata.len() > MAX_SIGNATURE_PACK_FILE_BYTES {
        bail!("signature pack file is too large {}", path.display());
    }
    if metadata.len() > remaining_pack_bytes {
        bail!(
            "signature pack set exceeds maximum total bytes of {}",
            MAX_SIGNATURE_PACK_TOTAL_BYTES
        );
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
        if total > remaining_pack_bytes {
            bail!(
                "signature pack set exceeds maximum total bytes of {}",
                MAX_SIGNATURE_PACK_TOTAL_BYTES
            );
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

    #[test]
    fn native_provider_pack_limits_reject_excess_signature_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.zsig");
        let empty_pack = r#"{"format":"zentor-signature-pack-v1","version":"1","signatures":[]}"#;
        fs::write(&primary, empty_pack).unwrap();
        for index in 0..MAX_SIGNATURE_PACK_FILES {
            fs::write(
                dir.path().join(format!("sibling-{index:02}.zsig")),
                empty_pack,
            )
            .unwrap();
        }

        let error = SignatureDb::load_pack(&primary).unwrap_err().to_string();

        assert!(error.contains("signature pack set exceeds maximum file count"));
    }

    #[test]
    fn native_provider_pack_limits_reject_signature_directory_entry_flood() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.zsig");
        let empty_pack = r#"{"format":"zentor-signature-pack-v1","version":"1","signatures":[]}"#;
        fs::write(&primary, empty_pack).unwrap();
        for index in 0..MAX_SIGNATURE_PACK_DIRECTORY_ENTRIES {
            fs::write(
                dir.path().join(format!("unrelated-{index:03}.txt")),
                "benign",
            )
            .unwrap();
        }

        let error = SignatureDb::load_pack(&primary).unwrap_err().to_string();

        assert!(error.contains("signature pack directory exceeds maximum inspected entry count"));
    }

    #[test]
    fn native_provider_pack_limits_reject_aggregate_signature_pack_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.zsig");
        let empty_pack = r#"{"format":"zentor-signature-pack-v1","version":"1","signatures":[]}"#;
        fs::write(&primary, empty_pack).unwrap();
        for index in 0..8 {
            fs::File::create(dir.path().join(format!("sibling-{index:02}.zsig")))
                .unwrap()
                .set_len(MAX_SIGNATURE_PACK_FILE_BYTES)
                .unwrap();
        }

        let error = SignatureDb::load_pack(&primary).unwrap_err().to_string();

        assert!(error.contains("signature pack set exceeds maximum total bytes"));
    }

    #[test]
    fn native_provider_pack_limits_recheck_signature_bytes_during_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bounded.zsig");
        fs::write(&path, "ordinary benign pack bytes").unwrap();

        let error = read_bounded_signature_pack_with_limit(&path, 8)
            .unwrap_err()
            .to_string();

        assert!(error.contains("signature pack set exceeds maximum total bytes"));

        let source = include_str!("signature_db.rs");
        let start = source
            .find("fn read_bounded_signature_pack_with_limit")
            .unwrap();
        let end = source.find("fn pack_file_present").unwrap();
        let read_source = &source[start..end];
        assert!(read_source.contains("metadata.len() > remaining_pack_bytes"));
        assert!(read_source.contains("total > remaining_pack_bytes"));
    }

    #[test]
    fn native_provider_pack_limits_reject_aggregate_signature_count() {
        let mut db = SignatureDb::built_in();
        let template = db.signatures[0].clone();
        db.signatures.resize(MAX_LOADED_SIGNATURES, template);

        let error = db.ensure_signature_capacity(1).unwrap_err().to_string();

        assert!(error.contains("loaded signature count exceeds maximum"));
    }

    #[test]
    fn native_provider_cancellation_preserves_signature_db_wrapper_and_errors() {
        let db = SignatureDb::built_in();
        let bytes = eicar_signature::eicar_test_bytes();
        let analysis = crate::analyzers::analyze_path(Path::new("eicar.com.txt"), bytes).unwrap();
        let sha256 = crate::engine::sha256_bytes(bytes);
        let wrapped = db
            .match_bytes(Path::new("eicar.com.txt"), &sha256, bytes, &analysis)
            .unwrap();
        let mut never_cancel = || Ok(());
        let fallible = db
            .match_bytes_with_cancellation(
                Path::new("eicar.com.txt"),
                &sha256,
                bytes,
                &analysis,
                &mut never_cancel,
            )
            .unwrap();
        let mut failure = || anyhow::bail!("benign signature provider callback failure");
        let error = db
            .match_bytes_with_cancellation(
                Path::new("eicar.com.txt"),
                &sha256,
                bytes,
                &analysis,
                &mut failure,
            )
            .expect_err("signature callback failure must abort evaluation");

        assert_eq!(wrapped.len(), fallible.len());
        assert_eq!(wrapped[0].signature_id, fallible[0].signature_id);
        assert!(error
            .to_string()
            .contains("benign signature provider callback failure"));
    }

    #[test]
    fn native_provider_normalization_cancels_signature_db_before_evidence() {
        let db = SignatureDb::built_in();
        let bytes =
            vec![b'A'; crate::signatures::text::TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES * 3];
        let path = Path::new("ordinary-benign-normalization.txt");
        let analysis = crate::analyzers::analyze_path(path, &bytes).unwrap();
        let sha256 = crate::engine::sha256_bytes(&bytes);
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign signature DB normalization cancellation")
            }
            Ok(())
        };

        let error = db
            .match_bytes_with_cancellation(path, &sha256, &bytes, &analysis, &mut checkpoint)
            .expect_err("signature DB must not publish evidence after normalization cancellation");

        assert!(error
            .to_string()
            .contains("benign signature DB normalization cancellation"));
        assert_eq!(checks, 2);
    }
}
