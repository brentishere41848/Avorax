use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::{rule_compiler, rule_vm, NativeRule, RuleMatch, RulePack};
use crate::analyzers::StaticAnalysis;

const MAX_RULE_PACK_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct RuleDb {
    rules: Vec<NativeRule>,
    pack_loaded: bool,
}

impl RuleDb {
    pub fn load_pack(path: &Path) -> Result<Self> {
        let mut db = Self::default();
        if pack_file_present(path)? {
            db.load_one(path)?;
            db.pack_loaded = true;
            if let Some(parent) = path.parent() {
                let mut siblings = Vec::new();
                for entry in fs::read_dir(parent).with_context(|| {
                    format!(
                        "failed to enumerate rule pack directory {}",
                        parent.display()
                    )
                })? {
                    let entry = entry.with_context(|| {
                        format!(
                            "failed to read rule pack directory entry in {}",
                            parent.display()
                        )
                    })?;
                    let candidate = entry.path();
                    if candidate.extension().and_then(|value| value.to_str()) == Some("zrule")
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
        let text = read_bounded_rule_pack(path)
            .with_context(|| format!("failed to read rule pack {}", path.display()))?;
        let pack: RulePack = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse rule pack {}", path.display()))?;
        rule_compiler::validate_rule_pack(&pack)?;
        for rule in &pack.rules {
            if self.rules.iter().any(|existing| existing.id == rule.id) {
                bail!("duplicate rule id across loaded packs {}", rule.id);
            }
        }
        self.rules.extend(pack.rules);
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.rules.len()
    }

    pub fn pack_loaded(&self) -> bool {
        self.pack_loaded
    }

    pub fn evaluate(
        &self,
        path: &Path,
        bytes: &[u8],
        analysis: &StaticAnalysis,
    ) -> Result<Vec<RuleMatch>> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if let Some(matched) = rule_vm::evaluate_rule(rule, path, bytes, analysis)
                .with_context(|| format!("rule {} evaluation failed", rule.id))?
            {
                matches.push(matched);
            }
        }
        Ok(matches)
    }
}

fn read_bounded_rule_pack(path: &Path) -> Result<String> {
    use std::io::Read;

    let metadata = ensure_regular_pack_file(path)?;
    if metadata.len() > MAX_RULE_PACK_FILE_BYTES {
        bail!("rule pack file is too large {}", path.display());
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
            .ok_or_else(|| anyhow::anyhow!("rule pack read size overflow"))?;
        if total > MAX_RULE_PACK_FILE_BYTES {
            bail!("rule pack file is too large {}", path.display());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("rule pack {} is not valid UTF-8", path.display()))
}

fn pack_file_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_regular_pack_metadata(path, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect rule pack {}", path.display()))
        }
    }
}

fn ensure_regular_pack_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect rule pack {}", path.display()))?;
    ensure_regular_pack_metadata(path, &metadata)?;
    Ok(metadata)
}

fn ensure_regular_pack_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing to load symbolic link rule pack {}",
            path.display()
        );
    }
    if is_windows_reparse_point(metadata) {
        bail!(
            "refusing to load reparse point rule pack {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        bail!("rule pack is not a regular file {}", path.display());
    }
    if metadata.len() > MAX_RULE_PACK_FILE_BYTES {
        bail!("rule pack file is too large {}", path.display());
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
    fn rule_pack_loader_rejects_directory_pack_path() {
        let dir = tempfile::tempdir().unwrap();
        let error = RuleDb::load_pack(dir.path()).unwrap_err().to_string();
        assert!(error.contains("rule pack is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn rule_pack_loader_rejects_symbolic_link_pack_path() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.zrule");
        fs::write(
            &target,
            r#"{"format":"zentor-rule-pack-v1","version":"1","rules":[]}"#,
        )
        .unwrap();
        let link = dir.path().join("linked.zrule");
        symlink(&target, &link).unwrap();

        let error = RuleDb::load_pack(&link).unwrap_err().to_string();
        assert!(error.contains("symbolic link rule pack"));
    }

    #[test]
    fn rule_pack_sibling_enumeration_does_not_ignore_errors() {
        let source = include_str!("rule_parser.rs");
        let load_start = source.find("pub fn load_pack").unwrap();
        let load_end = source.find("fn load_one").unwrap();
        let load_source = &source[load_start..load_end];
        let ignored_entry_pattern = ["filter_map", "(Result::ok)"].concat();

        assert!(load_source.contains("failed to read rule pack directory entry"));
        assert!(!load_source.contains(&ignored_entry_pattern));
    }

    #[test]
    fn rule_pack_sibling_inspection_does_not_ignore_errors() {
        let source = include_str!("rule_parser.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(source.contains("fn is_regular_pack_file(path: &Path) -> Result<bool>"));
        assert!(source.contains("failed to inspect rule pack"));
        assert!(!production_source.contains("unwrap_or(false)"));
    }

    #[test]
    fn rule_pack_missing_primary_keeps_empty_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.zrule");

        let db = RuleDb::load_pack(&path).unwrap();

        assert_eq!(db.count(), 0);
        assert!(!db.pack_loaded());
    }

    #[test]
    fn rule_pack_path_safety_markers_stay_in_place() {
        let source = include_str!("rule_parser.rs");
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
    fn rule_pack_loader_checks_cross_pack_duplicate_ids() {
        let source = include_str!("rule_parser.rs");

        assert!(source.contains("duplicate rule id across loaded packs"));
        assert!(source.contains("existing.id == rule.id"));
    }

    #[test]
    fn rule_pack_loader_bounds_pack_file_size() {
        let source = include_str!("rule_parser.rs");
        let start = source.find("fn read_bounded_rule_pack").unwrap();
        let end = source.find("fn pack_file_present").unwrap();
        let read_source = &source[start..end];

        assert!(source.contains("MAX_RULE_PACK_FILE_BYTES"));
        assert!(source.contains("rule pack file is too large"));
        assert!(read_source.contains("let metadata = ensure_regular_pack_file(path)?"));
        assert!(read_source.contains("metadata.len() > MAX_RULE_PACK_FILE_BYTES"));
        assert!(read_source.contains("let mut total = 0_u64"));
        assert!(read_source.contains("checked_add(read as u64)"));
        assert!(read_source.contains("total > MAX_RULE_PACK_FILE_BYTES"));
        assert!(read_source.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(read_source.contains("String::from_utf8(bytes)"));
        assert!(source.contains("fn ensure_regular_pack_file(path: &Path) -> Result<fs::Metadata>"));
        assert!(source.contains("read_bounded_rule_pack(path)"));
    }

    #[test]
    fn rule_pack_reader_rejects_oversized_file_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.zrule");
        fs::write(&path, "x".repeat(MAX_RULE_PACK_FILE_BYTES as usize + 1)).unwrap();

        let error = read_bounded_rule_pack(&path).unwrap_err().to_string();

        assert!(error.contains("rule pack file is too large"));
    }
}
