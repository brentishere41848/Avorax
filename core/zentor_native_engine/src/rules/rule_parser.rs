use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::{rule_compiler, rule_vm, NativeRule, RuleMatch, RulePack};
use crate::analyzers::StaticAnalysis;

const MAX_RULE_PACK_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RULE_PACK_FILES: usize = 32;
const MAX_RULE_PACK_DIRECTORY_ENTRIES: usize = 256;
const MAX_RULE_PACK_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOADED_RULES: usize = 4096;

#[derive(Debug, Clone, Default)]
pub struct RuleDb {
    rules: Vec<NativeRule>,
    pack_loaded: bool,
}

impl RuleDb {
    pub fn load_pack(path: &Path) -> Result<Self> {
        let mut db = Self::default();
        if pack_file_present(path)? {
            let primary_metadata = ensure_regular_pack_file(path)?;
            let mut pack_file_count = 1usize;
            let mut inspected_directory_entries = 0usize;
            let mut total_pack_bytes = primary_metadata.len();
            let mut siblings = Vec::new();
            if let Some(parent) = path.parent() {
                for entry in fs::read_dir(parent).with_context(|| {
                    format!(
                        "failed to enumerate rule pack directory {}",
                        parent.display()
                    )
                })? {
                    inspected_directory_entries =
                        inspected_directory_entries.checked_add(1).ok_or_else(|| {
                            anyhow::anyhow!("rule pack directory entry count overflow")
                        })?;
                    if inspected_directory_entries > MAX_RULE_PACK_DIRECTORY_ENTRIES {
                        bail!(
                            "rule pack directory exceeds maximum inspected entry count of {}",
                            MAX_RULE_PACK_DIRECTORY_ENTRIES
                        );
                    }
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
                        pack_file_count = pack_file_count
                            .checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("rule pack file count overflow"))?;
                        if pack_file_count > MAX_RULE_PACK_FILES {
                            bail!(
                                "rule pack set exceeds maximum file count of {}",
                                MAX_RULE_PACK_FILES
                            );
                        }
                        let candidate_bytes = ensure_regular_pack_file(&candidate)?.len();
                        total_pack_bytes = total_pack_bytes
                            .checked_add(candidate_bytes)
                            .ok_or_else(|| anyhow::anyhow!("rule pack total size overflow"))?;
                        if total_pack_bytes > MAX_RULE_PACK_TOTAL_BYTES {
                            bail!(
                                "rule pack set exceeds maximum total bytes of {}",
                                MAX_RULE_PACK_TOTAL_BYTES
                            );
                        }
                        siblings.push(candidate);
                    }
                }
            }
            siblings.sort();
            let mut loaded_pack_bytes = db.load_one(path, MAX_RULE_PACK_TOTAL_BYTES)?;
            db.pack_loaded = true;
            for sibling in siblings {
                let remaining_pack_bytes = MAX_RULE_PACK_TOTAL_BYTES
                    .checked_sub(loaded_pack_bytes)
                    .ok_or_else(|| anyhow::anyhow!("rule pack loaded size overflow"))?;
                let sibling_bytes = db.load_one(&sibling, remaining_pack_bytes)?;
                loaded_pack_bytes = loaded_pack_bytes
                    .checked_add(sibling_bytes)
                    .ok_or_else(|| anyhow::anyhow!("rule pack loaded size overflow"))?;
            }
        }
        Ok(db)
    }

    fn load_one(&mut self, path: &Path, remaining_pack_bytes: u64) -> Result<u64> {
        ensure_regular_pack_file(path)?;
        let text = read_bounded_rule_pack_with_limit(path, remaining_pack_bytes)
            .with_context(|| format!("failed to read rule pack {}", path.display()))?;
        let loaded_bytes = u64::try_from(text.len())
            .map_err(|_| anyhow::anyhow!("rule pack loaded size overflow"))?;
        let pack: RulePack = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse rule pack {}", path.display()))?;
        rule_compiler::validate_rule_pack(&pack)?;
        self.ensure_rule_capacity(pack.rules.len())?;
        for rule in &pack.rules {
            if self.rules.iter().any(|existing| existing.id == rule.id) {
                bail!("duplicate rule id across loaded packs {}", rule.id);
            }
        }
        self.rules.extend(pack.rules);
        Ok(loaded_bytes)
    }

    fn ensure_rule_capacity(&self, additional: usize) -> Result<()> {
        let next = self
            .rules
            .len()
            .checked_add(additional)
            .ok_or_else(|| anyhow::anyhow!("loaded rule count overflow"))?;
        if next > MAX_LOADED_RULES {
            bail!("loaded rule count exceeds maximum of {}", MAX_LOADED_RULES);
        }
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
        let mut never_cancel = || Ok(());
        self.evaluate_with_cancellation(path, bytes, analysis, &mut never_cancel)
    }

    pub fn evaluate_with_cancellation(
        &self,
        path: &Path,
        bytes: &[u8],
        analysis: &StaticAnalysis,
        cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<RuleMatch>> {
        cancellation_checkpoint()?;
        if self.rules.is_empty() {
            cancellation_checkpoint()?;
            return Ok(Vec::new());
        }
        let lower_text = crate::signatures::text::ascii_lowercase_lossy_with_cancellation(
            bytes,
            cancellation_checkpoint,
        )?;
        let path_display = path.display().to_string();
        let lower_path_text = crate::signatures::text::ascii_lowercase_lossy_with_cancellation(
            path_display.as_bytes(),
            cancellation_checkpoint,
        )?;
        let mut matches = Vec::new();
        for rule in &self.rules {
            cancellation_checkpoint()?;
            if let Some(matched) = rule_vm::evaluate_rule_with_prepared_text_and_cancellation(
                rule,
                bytes,
                analysis,
                &lower_text,
                &lower_path_text,
                cancellation_checkpoint,
            )
            .with_context(|| format!("rule {} evaluation failed", rule.id))?
            {
                matches.push(matched);
            }
        }
        cancellation_checkpoint()?;
        Ok(matches)
    }
}

#[cfg(test)]
fn read_bounded_rule_pack(path: &Path) -> Result<String> {
    read_bounded_rule_pack_with_limit(path, MAX_RULE_PACK_FILE_BYTES)
}

fn read_bounded_rule_pack_with_limit(path: &Path, remaining_pack_bytes: u64) -> Result<String> {
    use std::io::Read;

    let metadata = ensure_regular_pack_file(path)?;
    if metadata.len() > MAX_RULE_PACK_FILE_BYTES {
        bail!("rule pack file is too large {}", path.display());
    }
    if metadata.len() > remaining_pack_bytes {
        bail!(
            "rule pack set exceeds maximum total bytes of {}",
            MAX_RULE_PACK_TOTAL_BYTES
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
            .ok_or_else(|| anyhow::anyhow!("rule pack read size overflow"))?;
        if total > MAX_RULE_PACK_FILE_BYTES {
            bail!("rule pack file is too large {}", path.display());
        }
        if total > remaining_pack_bytes {
            bail!(
                "rule pack set exceeds maximum total bytes of {}",
                MAX_RULE_PACK_TOTAL_BYTES
            );
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

    #[test]
    fn native_provider_pack_limits_reject_excess_rule_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.zrule");
        let empty_pack = r#"{"format":"zentor-rule-pack-v1","version":"1","rules":[]}"#;
        fs::write(&primary, empty_pack).unwrap();
        for index in 0..MAX_RULE_PACK_FILES {
            fs::write(
                dir.path().join(format!("sibling-{index:02}.zrule")),
                empty_pack,
            )
            .unwrap();
        }

        let error = RuleDb::load_pack(&primary).unwrap_err().to_string();

        assert!(error.contains("rule pack set exceeds maximum file count"));
    }

    #[test]
    fn native_provider_pack_limits_reject_rule_directory_entry_flood() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.zrule");
        let empty_pack = r#"{"format":"zentor-rule-pack-v1","version":"1","rules":[]}"#;
        fs::write(&primary, empty_pack).unwrap();
        for index in 0..MAX_RULE_PACK_DIRECTORY_ENTRIES {
            fs::write(
                dir.path().join(format!("unrelated-{index:03}.txt")),
                "benign",
            )
            .unwrap();
        }

        let error = RuleDb::load_pack(&primary).unwrap_err().to_string();

        assert!(error.contains("rule pack directory exceeds maximum inspected entry count"));
    }

    #[test]
    fn native_provider_pack_limits_reject_aggregate_rule_pack_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.zrule");
        let empty_pack = r#"{"format":"zentor-rule-pack-v1","version":"1","rules":[]}"#;
        fs::write(&primary, empty_pack).unwrap();
        for index in 0..8 {
            fs::File::create(dir.path().join(format!("sibling-{index:02}.zrule")))
                .unwrap()
                .set_len(MAX_RULE_PACK_FILE_BYTES)
                .unwrap();
        }

        let error = RuleDb::load_pack(&primary).unwrap_err().to_string();

        assert!(error.contains("rule pack set exceeds maximum total bytes"));
    }

    #[test]
    fn native_provider_pack_limits_recheck_rule_bytes_during_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bounded.zrule");
        fs::write(&path, "ordinary benign pack bytes").unwrap();

        let error = read_bounded_rule_pack_with_limit(&path, 8)
            .unwrap_err()
            .to_string();

        assert!(error.contains("rule pack set exceeds maximum total bytes"));

        let source = include_str!("rule_parser.rs");
        let start = source.find("fn read_bounded_rule_pack_with_limit").unwrap();
        let end = source.find("fn pack_file_present").unwrap();
        let read_source = &source[start..end];
        assert!(read_source.contains("metadata.len() > remaining_pack_bytes"));
        assert!(read_source.contains("total > remaining_pack_bytes"));
    }

    #[test]
    fn native_provider_pack_limits_reject_aggregate_rule_count() {
        let template = NativeRule {
            id: "ZNE-RULE-BENIGN-CAPACITY".to_string(),
            name: "Benign capacity rule".to_string(),
            description: "Capacity fixture only.".to_string(),
            category: crate::verdict::ThreatCategory::TestThreat,
            confidence: crate::verdict::Confidence::Low,
            verdict: crate::verdict::Verdict::Observation,
            false_positive_notes: "Benign fixture only.".to_string(),
            conditions: vec![crate::rules::RuleCondition::FileType {
                equals: "text".to_string(),
            }],
            min_condition_matches: 1,
            action: "review_only".to_string(),
        };
        let mut db = RuleDb::default();
        db.rules.resize(MAX_LOADED_RULES, template);

        let error = db.ensure_rule_capacity(1).unwrap_err().to_string();

        assert!(error.contains("loaded rule count exceeds maximum"));
    }

    #[test]
    fn native_provider_cancellation_preserves_rule_db_wrapper_and_errors() {
        let rule = NativeRule {
            id: "ZNE-RULE-BENIGN-PROVIDER".to_string(),
            name: "Benign provider rule".to_string(),
            description: "Cancellation fixture only.".to_string(),
            category: crate::verdict::ThreatCategory::TestThreat,
            confidence: crate::verdict::Confidence::Low,
            verdict: crate::verdict::Verdict::Observation,
            false_positive_notes: "Benign fixture only.".to_string(),
            conditions: vec![crate::rules::RuleCondition::ContainsAscii {
                value: "ordinary provider marker".to_string(),
            }],
            min_condition_matches: 1,
            action: "review_only".to_string(),
        };
        let db = RuleDb {
            rules: vec![rule],
            pack_loaded: true,
        };
        let bytes = b"ordinary provider marker";
        let path = Path::new("benign.txt");
        let analysis = crate::analyzers::analyze_path(path, bytes).unwrap();
        let wrapped = db.evaluate(path, bytes, &analysis).unwrap();
        let mut never_cancel = || Ok(());
        let fallible = db
            .evaluate_with_cancellation(path, bytes, &analysis, &mut never_cancel)
            .unwrap();
        let mut failure = || anyhow::bail!("benign rule provider callback failure");
        let error = db
            .evaluate_with_cancellation(path, bytes, &analysis, &mut failure)
            .expect_err("rule callback failure must abort evaluation");

        assert_eq!(wrapped.len(), fallible.len());
        assert_eq!(wrapped[0].rule_id, fallible[0].rule_id);
        assert!(error
            .to_string()
            .contains("benign rule provider callback failure"));
    }

    #[test]
    fn native_provider_normalization_cancels_rule_db_before_evidence() {
        let rule = NativeRule {
            id: "ZNE-RULE-BENIGN-NORMALIZATION".to_string(),
            name: "Benign normalization rule".to_string(),
            description: "Normalization cancellation fixture only.".to_string(),
            category: crate::verdict::ThreatCategory::TestThreat,
            confidence: crate::verdict::Confidence::Low,
            verdict: crate::verdict::Verdict::Observation,
            false_positive_notes: "Benign fixture only.".to_string(),
            conditions: vec![crate::rules::RuleCondition::ContainsAscii {
                value: "marker absent from fixture".to_string(),
            }],
            min_condition_matches: 1,
            action: "review_only".to_string(),
        };
        let db = RuleDb {
            rules: vec![rule],
            pack_loaded: true,
        };
        let bytes =
            vec![b'A'; crate::signatures::text::TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES * 3];
        let path = Path::new("ordinary-benign-normalization.txt");
        let analysis = crate::analyzers::analyze_path(path, &bytes).unwrap();
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 3 {
                anyhow::bail!("benign rule DB normalization cancellation")
            }
            Ok(())
        };

        let error = db
            .evaluate_with_cancellation(path, &bytes, &analysis, &mut checkpoint)
            .expect_err("rule DB must not publish evidence after normalization cancellation");

        assert!(error
            .to_string()
            .contains("benign rule DB normalization cancellation"));
        assert_eq!(checks, 3);
    }
}
