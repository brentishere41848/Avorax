#![allow(dead_code)]

use std::fs;
use std::io::{BufReader, Read};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::clamav_provider::sha256_file;
use super::{
    DetectionType, RecommendedAction, RiskEngine, RiskReason, RiskReasonSource, RiskScore,
    RiskSeverity, RiskVerdict, ThreatCategory, ThreatConfidence, ThreatResult, ThreatResultStatus,
};

const YARA_SAMPLE_LIMIT_BYTES: u64 = 1_048_576;
const YARA_RULE_TEXT_LIMIT_BYTES: u64 = 256 * 1024;
const MAX_YARA_RULE_NAME_CHARS: usize = 128;
const MAX_YARA_PATTERN_CHARS: usize = 512;
const MAX_YARA_METADATA_CHARS: usize = 1024;
const EMBEDDED_DEFAULT_RULES: &str =
    include_str!("../../../../apps/zentor_client/assets/yara/zentor_core_rules.yar");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct YaraMatch {
    pub rule_name: String,
    pub category: ThreatCategory,
    pub confidence: ThreatConfidence,
    pub description: String,
    pub false_positive_notes: String,
    pub matched_pattern: String,
}

#[derive(Debug, Clone)]
struct YaraRule {
    name: String,
    category: ThreatCategory,
    confidence: ThreatConfidence,
    description: String,
    false_positive_notes: String,
    patterns: Vec<String>,
}

#[derive(Debug)]
pub struct YaraProvider {
    rules: Vec<YaraRule>,
}

impl YaraProvider {
    pub fn from_default_rules() -> Result<Self> {
        let path = default_rules_path()?;
        if !runtime_rule_file_present(&path)? {
            return Self::from_embedded_default_rules();
        }
        let raw = read_bounded_rule_text(&path)
            .with_context(|| format!("failed to read YARA rules {}", path.display()))?;
        Self::from_rule_text(&raw)
            .with_context(|| format!("failed to parse YARA rules {}", path.display()))
    }

    pub fn from_embedded_default_rules() -> Result<Self> {
        Self::from_rule_text(EMBEDDED_DEFAULT_RULES)
            .context("failed to parse embedded Avorax YARA rules")
    }

    pub fn from_rule_text(raw: &str) -> Result<Self> {
        let mut rules = Vec::new();
        let mut current_name: Option<String> = None;
        let mut category: Option<ThreatCategory> = None;
        let mut confidence: Option<ThreatConfidence> = None;
        let mut description: Option<String> = None;
        let mut false_positive_notes: Option<String> = None;
        let mut patterns = Vec::new();

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("rule ") {
                if let Some(name) = current_name.take() {
                    let rule = build_yara_rule(
                        name,
                        category.take(),
                        confidence.take(),
                        description.take(),
                        false_positive_notes.take(),
                        std::mem::take(&mut patterns),
                    )?;
                    push_yara_rule(&mut rules, rule)?;
                }
                let name = trimmed
                    .strip_prefix("rule ")
                    .and_then(|value| value.split_whitespace().next())
                    .map(|value| value.trim_matches('{').to_string())
                    .ok_or_else(|| anyhow!("YARA rule declaration is missing a name"))?;
                validate_yara_rule_name(&name)?;
                current_name = Some(name);
            } else if metadata_key_present(trimmed, "category") {
                let rule_name = current_yara_rule_name(current_name.as_deref(), "category")?;
                let value = metadata_value(rule_name, trimmed, "category")?;
                category = Some(category_from_yara(rule_name, &value)?);
            } else if metadata_key_present(trimmed, "confidence") {
                let rule_name = current_yara_rule_name(current_name.as_deref(), "confidence")?;
                let value = metadata_value(rule_name, trimmed, "confidence")?;
                confidence = Some(confidence_from_yara(rule_name, &value)?);
            } else if metadata_key_present(trimmed, "description") {
                let rule_name = current_yara_rule_name(current_name.as_deref(), "description")?;
                let value = metadata_value(rule_name, trimmed, "description")?;
                validate_yara_metadata_text(rule_name, "description", &value)?;
                description = Some(value);
            } else if metadata_key_present(trimmed, "false_positive_notes") {
                let rule_name =
                    current_yara_rule_name(current_name.as_deref(), "false_positive_notes")?;
                let value = metadata_value(rule_name, trimmed, "false_positive_notes")?;
                validate_yara_metadata_text(rule_name, "false_positive_notes", &value)?;
                false_positive_notes = Some(value);
            } else if trimmed.starts_with('$') {
                let Some(rule_name) = current_name.as_deref() else {
                    anyhow::bail!("YARA string pattern appears before rule declaration");
                };
                let Some((_, value)) = trimmed.split_once('=') else {
                    anyhow::bail!("YARA rule {rule_name} has malformed string pattern");
                };
                let value = value.trim();
                let Some(pattern) = quoted_value(value) else {
                    anyhow::bail!("YARA rule {rule_name} has malformed string pattern");
                };
                validate_yara_pattern(rule_name, &pattern)?;
                patterns.push(pattern);
            }
        }

        if let Some(name) = current_name.take() {
            let rule = build_yara_rule(
                name,
                category.take(),
                confidence.take(),
                description.take(),
                false_positive_notes.take(),
                patterns,
            )?;
            push_yara_rule(&mut rules, rule)?;
        }

        Ok(Self { rules })
    }

    pub fn status(&self) -> &'static str {
        if self.rules.is_empty() {
            "rulesUnavailable"
        } else {
            "ready"
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn inspect_file(&self, path: &Path) -> Result<Option<ThreatResult>> {
        let body = read_bounded_sample(path)?;
        let body_text = String::from_utf8_lossy(&body).to_lowercase();
        let matched = self
            .rules
            .iter()
            .filter_map(|rule| {
                rule.patterns.iter().find_map(|pattern| {
                    if body_text.contains(&pattern.to_lowercase()) {
                        Some(YaraMatch {
                            rule_name: rule.name.clone(),
                            category: rule.category.clone(),
                            confidence: rule.confidence.clone(),
                            description: rule.description.clone(),
                            false_positive_notes: rule.false_positive_notes.clone(),
                            matched_pattern: pattern.clone(),
                        })
                    } else {
                        None
                    }
                })
            })
            .max_by_key(|m| confidence_rank(&m.confidence));

        let Some(matched) = matched else {
            return Ok(None);
        };
        Ok(Some(threat_from_yara(path, matched)?))
    }
}

fn build_yara_rule(
    name: String,
    category: Option<ThreatCategory>,
    confidence: Option<ThreatConfidence>,
    description: Option<String>,
    false_positive_notes: Option<String>,
    patterns: Vec<String>,
) -> Result<YaraRule> {
    let category =
        category.ok_or_else(|| anyhow!("YARA rule {name} is missing category metadata"))?;
    let confidence =
        confidence.ok_or_else(|| anyhow!("YARA rule {name} is missing confidence metadata"))?;
    let description =
        description.ok_or_else(|| anyhow!("YARA rule {name} is missing description metadata"))?;
    let false_positive_notes = false_positive_notes
        .ok_or_else(|| anyhow!("YARA rule {name} is missing false_positive_notes metadata"))?;
    validate_yara_metadata_text(&name, "description", &description)?;
    validate_yara_metadata_text(&name, "false_positive_notes", &false_positive_notes)?;
    Ok(YaraRule {
        name,
        category,
        confidence,
        description,
        false_positive_notes,
        patterns,
    })
}

fn push_yara_rule(rules: &mut Vec<YaraRule>, rule: YaraRule) -> Result<()> {
    validate_yara_rule(&rule)?;
    rules.push(rule);
    Ok(())
}

fn validate_yara_rule(rule: &YaraRule) -> Result<()> {
    validate_yara_rule_name(&rule.name)?;
    if rule.patterns.is_empty() {
        anyhow::bail!("YARA rule {} has no string patterns", rule.name);
    }
    for pattern in &rule.patterns {
        validate_yara_pattern(&rule.name, pattern)?;
    }
    Ok(())
}

fn validate_yara_rule_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("YARA rule declaration is missing a name");
    }
    if name.trim() != name {
        anyhow::bail!("YARA rule name contains leading or trailing whitespace");
    }
    if name.chars().count() > MAX_YARA_RULE_NAME_CHARS {
        anyhow::bail!("YARA rule name exceeds maximum length");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        anyhow::bail!(
            "YARA rule name contains unsupported characters; use ASCII letters, digits, underscore, or hyphen"
        );
    }
    Ok(())
}

fn validate_yara_pattern(rule_name: &str, pattern: &str) -> Result<()> {
    if pattern.trim().is_empty() {
        anyhow::bail!("YARA rule {rule_name} has an empty string pattern");
    }
    if pattern.chars().count() > MAX_YARA_PATTERN_CHARS {
        anyhow::bail!("YARA rule {rule_name} string pattern exceeds maximum length");
    }
    Ok(())
}

fn read_bounded_sample(path: &Path) -> Result<Vec<u8>> {
    ensure_regular_yara_scan_file(path)?;
    let mut reader = fs::File::open(path)?;
    let mut body = Vec::new();
    let mut remaining = YARA_SAMPLE_LIMIT_BYTES;
    let mut buffer = [0_u8; 8192];
    while remaining > 0 {
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
        remaining -= read as u64;
        body.extend_from_slice(&buffer[..read]);
    }
    Ok(body)
}

fn read_bounded_rule_text(path: &Path) -> Result<String> {
    let metadata = ensure_regular_yara_rule_file(path)?;
    if metadata.len() > YARA_RULE_TEXT_LIMIT_BYTES {
        anyhow::bail!(
            "YARA rules {} exceeds maximum size of {} bytes",
            path.display(),
            YARA_RULE_TEXT_LIMIT_BYTES
        );
    }
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("YARA rules {} size overflow", path.display()))?;
        if total > YARA_RULE_TEXT_LIMIT_BYTES {
            anyhow::bail!(
                "YARA rules {} exceeds maximum size of {} bytes",
                path.display(),
                YARA_RULE_TEXT_LIMIT_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("unable to decode YARA rules {}", path.display()))
}

fn runtime_rule_file_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("unable to inspect YARA rules {}", path.display()))
        }
    }
}

fn ensure_regular_yara_rule_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect YARA rules {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("YARA rules {} is a symbolic link", path.display()));
    }
    if is_windows_reparse_point(&metadata) {
        return Err(anyhow!("YARA rules {} is a reparse point", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "YARA rules {} is not a regular file",
            path.display()
        ));
    }
    Ok(metadata)
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

fn yara_display_file_name(path: &Path) -> String {
    match yara_leaf_file_name(path) {
        Some(name) => name,
        None => yara_display_path_fallback(path),
    }
}

fn yara_leaf_file_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.trim().is_empty())
}

fn yara_display_path_fallback(path: &Path) -> String {
    path.display().to_string()
}

fn threat_from_yara(path: &Path, matched: YaraMatch) -> Result<ThreatResult> {
    let metadata = ensure_regular_yara_scan_file(path)?;
    let confirmed = matched.confidence == ThreatConfidence::Confirmed;
    let high = matched.confidence == ThreatConfidence::High;
    let score = match matched.confidence {
        ThreatConfidence::Confirmed => 100,
        ThreatConfidence::High => 85,
        ThreatConfidence::Medium => 55,
        ThreatConfidence::Low => 25,
    };
    let verdict = if confirmed {
        RiskVerdict::ConfirmedMalware
    } else if high {
        RiskVerdict::ProbableMalware
    } else if score >= 45 {
        RiskVerdict::Suspicious
    } else {
        RiskVerdict::Unknown
    };
    Ok(ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: yara_display_file_name(path),
        sha256: sha256_file(path)?,
        size_bytes: metadata.len(),
        detection_type: DetectionType::Yara,
        threat_category: matched.category,
        threat_name: if confirmed {
            "Known malware rule match".to_string()
        } else {
            "YARA review suggested".to_string()
        },
        confidence: matched.confidence.clone(),
        engine: format!("zentor-yara/{}", matched.rule_name),
        detected_at: Utc::now(),
        recommended_action: if confirmed || high {
            RecommendedAction::Quarantine
        } else {
            RecommendedAction::Review
        },
        status: ThreatResultStatus::Detected,
        risk_score: RiskScore {
            score,
            verdict,
            confidence: matched.confidence,
            reasons: vec![RiskReason {
                id: "yara_rule_match".to_string(),
                title: "YARA rule matched".to_string(),
                detail: format!(
                    "{} Matched pattern: {}. False-positive notes: {}",
                    matched.description, matched.matched_pattern, matched.false_positive_notes
                ),
                weight: score as i32,
                severity: if confirmed {
                    RiskSeverity::Critical
                } else if high {
                    RiskSeverity::High
                } else {
                    RiskSeverity::Medium
                },
                source: RiskReasonSource::Yara,
            }],
            recommended_action: if confirmed || high {
                RecommendedAction::Quarantine
            } else {
                RecommendedAction::Review
            },
            engines_used: vec![RiskEngine::Yara],
        },
        reason_summary: matched.description,
        quarantine_id: None,
        quarantine_path: None,
        quarantine_action_taken: None,
    })
}

fn default_rules_path() -> Result<PathBuf> {
    let mut roots = Vec::new();
    let current_exe = std::env::current_exe()
        .context("local YARA default rule discovery failed to resolve current executable")?;
    let parent = current_exe.parent().ok_or_else(|| {
        anyhow!(
            "local YARA default rule discovery found no parent for {}",
            current_exe.display()
        )
    })?;
    push_yara_asset_root(&mut roots, parent)?;

    #[cfg(debug_assertions)]
    {
        let current_dir = std::env::current_dir()
            .context("local YARA default rule discovery failed to read current directory")?;
        if is_local_core_development_root(&current_dir)? {
            push_yara_asset_root(&mut roots, &current_dir)?;
        }
    }

    for root in &roots {
        for candidate in [
            root.join("assets")
                .join("yara")
                .join("zentor_core_rules.yar"),
            root.join("..")
                .join("..")
                .join("assets")
                .join("yara")
                .join("zentor_core_rules.yar"),
        ] {
            if runtime_rule_file_present(&candidate)? {
                return Ok(candidate);
            }
        }
    }
    let root = roots.first().ok_or_else(|| {
        anyhow!("local YARA default rule discovery found no absolute root candidates")
    })?;
    Ok(root
        .join("assets")
        .join("yara")
        .join("zentor_core_rules.yar"))
}

fn push_yara_asset_root(roots: &mut Vec<PathBuf>, root: &Path) -> Result<()> {
    if !yara_asset_root_is_allowed(root) {
        anyhow::bail!(
            "local YARA default rule root {} must be an absolute local path",
            root.display()
        );
    }
    if !roots.iter().any(|existing| existing == root) {
        roots.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(windows)]
fn yara_asset_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn yara_asset_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(debug_assertions)]
fn is_local_core_development_root(root: &Path) -> Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_local_core")
        .join("Cargo.toml");
    let metadata = match fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "unable to inspect local YARA development marker {}",
                    marker.display()
                )
            });
        }
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "local YARA development marker {} is a symbolic link",
            marker.display()
        );
    }
    if is_windows_reparse_point(&metadata) {
        anyhow::bail!(
            "local YARA development marker {} is a reparse point",
            marker.display()
        );
    }
    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "local YARA development marker {} is not a regular file",
            marker.display()
        );
    }
    Ok(true)
}

fn ensure_regular_yara_scan_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect YARA scan target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "YARA scan target {} is a symbolic link",
            path.display()
        ));
    }
    if is_windows_reparse_point(&metadata) {
        return Err(anyhow!(
            "YARA scan target {} is a reparse point",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "YARA scan target {} is not a regular file",
            path.display()
        ));
    }
    Ok(metadata)
}

fn validate_yara_metadata_text(rule_name: &str, field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("YARA rule {rule_name} has empty {field} metadata");
    }
    if value.contains('\0') {
        anyhow::bail!("YARA rule {rule_name} has NUL in {field} metadata");
    }
    if value.chars().count() > MAX_YARA_METADATA_CHARS {
        anyhow::bail!("YARA rule {rule_name} {field} metadata exceeds maximum length");
    }
    Ok(())
}

fn current_yara_rule_name<'a>(rule_name: Option<&'a str>, field: &str) -> Result<&'a str> {
    rule_name.ok_or_else(|| anyhow!("YARA {field} metadata appears before rule declaration"))
}

fn metadata_key_present(line: &str, key: &str) -> bool {
    let prefix = format!("{key} =");
    line.strip_prefix(&prefix).is_some()
}

fn metadata_value(rule_name: &str, line: &str, key: &str) -> Result<String> {
    let prefix = format!("{key} =");
    let Some(value) = line.strip_prefix(&prefix) else {
        anyhow::bail!("YARA rule {rule_name} is missing {key} metadata");
    };
    quoted_value(value.trim())
        .ok_or_else(|| anyhow!("YARA rule {rule_name} has malformed {key} metadata"))
}

fn quoted_value(value: &str) -> Option<String> {
    let start = value.find('"')?;
    let rest = &value[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn category_from_yara(rule_name: &str, value: &str) -> Result<ThreatCategory> {
    match value {
        "unknown" => Ok(ThreatCategory::Unknown),
        "trojan" => Ok(ThreatCategory::Trojan),
        "ransomware" => Ok(ThreatCategory::Ransomware),
        "spyware" => Ok(ThreatCategory::Spyware),
        "infostealer" => Ok(ThreatCategory::Infostealer),
        "adware" => Ok(ThreatCategory::Adware),
        "worm" => Ok(ThreatCategory::Worm),
        "keylogger" => Ok(ThreatCategory::Keylogger),
        "miner" => Ok(ThreatCategory::Miner),
        "rootkit_indicator" => Ok(ThreatCategory::RootkitIndicator),
        "potentially_unwanted_app" => Ok(ThreatCategory::PotentiallyUnwantedApp),
        "suspicious_downloader" => Ok(ThreatCategory::SuspiciousDownloader),
        "suspicious_script" => Ok(ThreatCategory::SuspiciousScript),
        "malicious_macro" => Ok(ThreatCategory::MaliciousMacro),
        "exploit_dropper" => Ok(ThreatCategory::ExploitDropper),
        "credential_theft_indicator" => Ok(ThreatCategory::CredentialTheftIndicator),
        "persistence_indicator" => Ok(ThreatCategory::PersistenceIndicator),
        "security_tamper_indicator" => Ok(ThreatCategory::SecurityTamperIndicator),
        _ => anyhow::bail!("YARA rule {rule_name} has unsupported category metadata: {value}"),
    }
}

fn confidence_from_yara(rule_name: &str, value: &str) -> Result<ThreatConfidence> {
    match value {
        "confirmed" => Ok(ThreatConfidence::Confirmed),
        "high" => Ok(ThreatConfidence::High),
        "medium" => Ok(ThreatConfidence::Medium),
        "low" => Ok(ThreatConfidence::Low),
        _ => anyhow::bail!("YARA rule {rule_name} has unsupported confidence metadata: {value}"),
    }
}

fn confidence_rank(confidence: &ThreatConfidence) -> u8 {
    match confidence {
        ThreatConfidence::Confirmed => 4,
        ThreatConfidence::High => 3,
        ThreatConfidence::Medium => 2,
        ThreatConfidence::Low => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    impl Default for YaraProvider {
        fn default() -> Self {
            Self::from_embedded_default_rules().expect("embedded Avorax YARA rules must parse")
        }
    }

    #[test]
    fn confirmed_yara_rule_is_confirmed() {
        let rules = r#"
rule Zentor_Safe_EICAR_Simulator
{
  meta:
    category = "unknown"
    confidence = "confirmed"
    description = "Safe EICAR simulator signature."
    false_positive_notes = "Only matches the Avorax safe test fixture."
  strings:
    $eicar = "ZENTOR-SAFE-EICAR-SIMULATOR-FILE"
  condition:
    any of them
}
"#;
        let provider = YaraProvider::from_rule_text(rules).unwrap();
        let dir = tempdir().unwrap();
        let file = dir.path().join("safe-eicar.com");
        fs::write(&file, "ZENTOR-SAFE-EICAR-SIMULATOR-FILE").unwrap();
        let threat = provider.inspect_file(&file).unwrap().unwrap();
        assert_eq!(threat.detection_type, DetectionType::Yara);
        assert_eq!(threat.confidence, ThreatConfidence::Confirmed);
        assert_eq!(threat.risk_score.verdict, RiskVerdict::ConfirmedMalware);
    }

    #[test]
    fn normal_exe_text_does_not_match_yara() {
        let provider = YaraProvider::from_rule_text(
            r#"
rule Review_Only
{
  meta:
    category = "spyware"
    confidence = "medium"
    description = "Review rule."
    false_positive_notes = "Review only."
  strings:
    $s1 = "FromBase64String"
  condition:
    any of them
}
"#,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        fs::write(&file, "normal developer tool").unwrap();
        assert!(provider.inspect_file(&file).unwrap().is_none());
    }

    #[test]
    fn yara_display_file_name_uses_leaf_or_path_fallback() {
        assert_eq!(
            yara_display_file_name(Path::new("C:/Temp/tool.exe")),
            "tool.exe"
        );
        assert_eq!(
            yara_display_file_name(Path::new("/")),
            Path::new("/").display().to_string()
        );
    }

    #[test]
    fn yara_threat_file_names_do_not_default_to_empty_strings() {
        let source = include_str!("yara_provider.rs");
        let production_source = source
            .split_once("#[cfg(test)]")
            .map(|(production, _)| production)
            .expect("test module marker");
        let old_fallback = [
            ".file_name()\n            .map(|name| name.to_string_lossy().to_string())\n            .unwrap_or_default()",
        ]
        .concat();

        assert_eq!(
            production_source
                .matches("file_name: yara_display_file_name(path)")
                .count(),
            1
        );
        assert!(production_source.contains("fn yara_leaf_file_name(path: &Path) -> Option<String>"));
        assert!(production_source.contains("Some(name) => name"));
        assert!(production_source.contains("None => yara_display_path_fallback(path)"));
        assert!(!production_source.contains("unwrap_or_else(|| path.display().to_string())"));
        assert!(!production_source.contains(&old_fallback));
    }

    #[test]
    fn yara_inspection_reports_unreadable_targets_as_errors() {
        let provider = YaraProvider::from_rule_text("").unwrap();
        let dir = tempdir().unwrap();

        assert!(provider.inspect_file(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn yara_inspection_rejects_symbolic_link_targets() {
        let provider = YaraProvider::from_rule_text("").unwrap();
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.ps1");
        let link = dir.path().join("linked.ps1");
        fs::write(&target, "[Convert]::FromBase64String('AAAA')").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let inspect_error = provider.inspect_file(&link).unwrap_err().to_string();
        let sample_error = read_bounded_sample(&link).unwrap_err().to_string();

        assert!(inspect_error.contains("symbolic link"));
        assert!(sample_error.contains("symbolic link"));
    }

    #[test]
    fn yara_provider_uses_non_following_scan_and_rule_paths() {
        let source = include_str!("yara_provider.rs");
        let scan_helper_pattern = ["fn ensure_regular_yara_", "scan_file"].concat();
        let scan_helper_call_pattern = ["ensure_regular_yara_", "scan_file(path)?"].concat();
        let rule_helper_candidate_pattern = "runtime_rule_file_present(&candidate)?";
        let symlink_metadata_pattern = ["fs::", "symlink_metadata(path)"].concat();
        let scan_target_pattern = ["YARA scan ", "target"].concat();
        let scan_symlink_pattern = ["YARA scan target {} is a ", "symbolic link"].concat();
        let scan_reparse_pattern = ["YARA scan target {} is a ", "reparse point"].concat();
        let old_scan_metadata = ["fs::", "metadata(path)"].concat();
        let old_candidate_probe = ["candidate.", "is_file()"].concat();

        assert!(source.contains(&scan_helper_pattern));
        assert!(source.contains(&scan_helper_call_pattern));
        assert!(source.contains(rule_helper_candidate_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&scan_target_pattern));
        assert!(source.contains(&scan_symlink_pattern));
        assert!(source.contains(&scan_reparse_pattern));
        assert!(!source.contains(&old_scan_metadata));
        assert!(!source.contains(&old_candidate_probe));
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production_source.contains("ensure_regular_yara_rule_file(&candidate).is_ok()"));
    }

    #[test]
    fn review_yara_rule_is_not_confirmed() {
        let provider = YaraProvider::from_rule_text(
            r#"
rule Review_Only
{
  meta:
    category = "spyware"
    confidence = "medium"
    description = "Review rule."
    false_positive_notes = "Review only."
  strings:
    $s1 = "FromBase64String"
  condition:
    any of them
}
"#,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        let file = dir.path().join("script.ps1");
        fs::write(&file, "[Convert]::FromBase64String('AAAA')").unwrap();
        let threat = provider.inspect_file(&file).unwrap().unwrap();
        assert_eq!(threat.confidence, ThreatConfidence::Medium);
        assert_eq!(threat.recommended_action, RecommendedAction::Review);
        assert_ne!(threat.risk_score.verdict, RiskVerdict::ConfirmedMalware);
    }

    #[test]
    fn yara_provider_reads_only_bounded_sample() {
        let provider = YaraProvider::from_rule_text(
            r#"
rule Beyond_Sample_Limit
{
  meta:
    category = "unknown"
    confidence = "confirmed"
    description = "Marker beyond sample limit should not match."
    false_positive_notes = "Boundary fixture only."
  strings:
    $late = "BOUNDARY-MARKER"
  condition:
    any of them
}
"#,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        let file = dir.path().join("large.bin");
        let mut body = vec![b'A'; YARA_SAMPLE_LIMIT_BYTES as usize + 16];
        body.extend_from_slice(b"BOUNDARY-MARKER");
        fs::write(&file, body).unwrap();

        assert!(provider.inspect_file(&file).unwrap().is_none());
    }

    #[test]
    fn default_yara_provider_does_not_silently_drop_rules_on_load_error() {
        let source = include_str!("yara_provider.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        let default_start = source.find("impl Default for YaraProvider").unwrap();
        let default_source = &source[default_start..];
        let silent_empty_pattern = ["unwrap_or_else(|_| Self { rules: Vec::new()", ")"].concat();

        assert!(production_source.contains("pub fn from_default_rules() -> Result<Self>"));
        assert!(!production_source.contains("impl Default for YaraProvider"));
        assert!(!production_source.contains("embedded Avorax YARA rules must parse"));
        assert!(default_source.contains("from_embedded_default_rules"));
        assert!(!default_source.contains(&silent_empty_pattern));
        assert!(source.contains("read_bounded_rule_text(&path)"));
        assert!(source.contains("YARA_RULE_TEXT_LIMIT_BYTES"));
        assert!(YaraProvider::default().rule_count() > 0);
    }

    #[test]
    fn default_yara_rules_path_has_no_relative_fallback() {
        let source = include_str!("yara_provider.rs");
        let start = source.find("fn default_rules_path").unwrap();
        let end = source.find("fn ensure_regular_yara_scan_file").unwrap();
        let default_source = &source[start..end];

        assert!(source.contains("let path = default_rules_path()?"));
        assert!(default_source.contains("fn default_rules_path() -> Result<PathBuf>"));
        assert!(default_source.contains("std::env::current_exe()"));
        assert!(default_source
            .contains("local YARA default rule discovery failed to resolve current executable"));
        assert!(default_source.contains("push_yara_asset_root(&mut roots, parent)?"));
        assert!(default_source.contains("#[cfg(debug_assertions)]"));
        assert!(default_source.contains("is_local_core_development_root(&current_dir)?"));
        assert!(default_source.contains("runtime_rule_file_present(&candidate)?"));
        assert!(default_source.contains("let root = roots.first().ok_or_else"));
        assert!(!default_source.contains("if let Ok(current_dir) = std::env::current_dir()"));
        assert!(!default_source.contains("PathBuf::from(\"assets/yara/zentor_core_rules.yar\")"));
        assert!(!default_source.contains("ensure_regular_yara_rule_file(&candidate).is_ok()"));
    }

    #[test]
    fn yara_rule_parser_requires_explicit_metadata() {
        let source = include_str!("yara_provider.rs");
        let parser_start = source.find("pub fn from_rule_text").unwrap();
        let status_start = source.find("pub fn status").unwrap();
        let parser_source = &source[parser_start..status_start];
        let missing_category = r#"
rule Missing_Category
{
  meta:
    confidence = "medium"
    description = "Missing category."
    false_positive_notes = "Fixture."
  strings:
    $s1 = "marker"
  condition:
    any of them
}
"#;
        let unsupported_category = r#"
rule Bad_Category
{
  meta:
    category = "policy_override"
    confidence = "medium"
    description = "Bad category."
    false_positive_notes = "Fixture."
  strings:
    $s1 = "marker"
  condition:
    any of them
}
"#;
        let unsupported_confidence = r#"
rule Bad_Confidence
{
  meta:
    category = "unknown"
    confidence = "certain"
    description = "Bad confidence."
    false_positive_notes = "Fixture."
  strings:
    $s1 = "marker"
  condition:
    any of them
}
"#;
        let empty_description = r#"
rule Empty_Description
{
  meta:
    category = "unknown"
    confidence = "low"
    description = "   "
    false_positive_notes = "Fixture."
  strings:
    $s1 = "marker"
  condition:
    any of them
}
"#;

        assert!(YaraProvider::from_rule_text(missing_category)
            .unwrap_err()
            .to_string()
            .contains("YARA rule Missing_Category is missing category metadata"));
        assert!(YaraProvider::from_rule_text(unsupported_category)
            .unwrap_err()
            .to_string()
            .contains("YARA rule Bad_Category has unsupported category metadata"));
        assert!(YaraProvider::from_rule_text(unsupported_confidence)
            .unwrap_err()
            .to_string()
            .contains("YARA rule Bad_Confidence has unsupported confidence metadata"));
        assert!(YaraProvider::from_rule_text(empty_description)
            .unwrap_err()
            .to_string()
            .contains("YARA rule Empty_Description has empty description metadata"));
        assert!(source.contains("fn build_yara_rule("));
        assert!(source.contains("const MAX_YARA_METADATA_CHARS: usize = 1024;"));
        assert!(source.contains("fn validate_yara_metadata_text"));
        assert!(!parser_source.contains("let mut category = ThreatCategory::Unknown"));
        assert!(!parser_source.contains("let mut confidence = ThreatConfidence::Low"));
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production_source.contains("_ => ThreatCategory::Unknown"));
        assert!(!production_source.contains("_ => ThreatConfidence::Low"));
    }

    #[test]
    fn yara_provider_rejects_rules_without_string_patterns() {
        let rules = r#"
rule Empty_Rule
{
  meta:
    category = "unknown"
    confidence = "low"
    description = "No strings fixture."
    false_positive_notes = "Fixture."
  condition:
    true
}
"#;

        let error = YaraProvider::from_rule_text(rules).unwrap_err().to_string();

        assert!(error.contains("YARA rule Empty_Rule has no string patterns"));
    }

    #[test]
    fn yara_provider_rejects_malformed_string_patterns() {
        let rules = r#"
rule Bad_String
{
  meta:
    category = "unknown"
    confidence = "low"
    description = "Bad string fixture."
    false_positive_notes = "Fixture."
  strings:
    $bad = not_quoted
  condition:
    any of them
}
"#;

        let error = YaraProvider::from_rule_text(rules).unwrap_err().to_string();

        assert!(error.contains("YARA rule Bad_String has malformed string pattern"));
    }

    #[test]
    fn yara_provider_rejects_string_patterns_before_rule_declaration() {
        let error = YaraProvider::from_rule_text("$bad = \"orphan\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("YARA string pattern appears before rule declaration"));
    }

    #[test]
    fn yara_rule_parser_does_not_silently_drop_malformed_patterns() {
        let source = include_str!("yara_provider.rs");
        let parser_start = source.find("pub fn from_rule_text").unwrap();
        let status_start = source.find("pub fn status").unwrap();
        let parser_source = &source[parser_start..status_start];

        assert!(source.contains("fn push_yara_rule"));
        assert!(source.contains("fn validate_yara_rule"));
        assert!(source.contains("fn validate_yara_pattern"));
        assert!(parser_source.contains("YARA rule {rule_name} has malformed string pattern"));
        assert!(parser_source.contains("YARA string pattern appears before rule declaration"));
        assert!(!parser_source.contains("if let Some(pattern) = quoted_value(value)"));
    }

    #[test]
    fn yara_provider_rejects_oversized_runtime_rules_before_parse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("oversized.yar");
        fs::write(&path, "x".repeat(YARA_RULE_TEXT_LIMIT_BYTES as usize + 1)).unwrap();

        let error = read_bounded_rule_text(&path).unwrap_err().to_string();

        assert!(error.contains("YARA rules"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn yara_rule_reader_is_metadata_and_actual_byte_bounded() {
        let source = include_str!("yara_provider.rs");
        let start = source.find("fn read_bounded_rule_text").unwrap();
        let end = source.find("fn runtime_rule_file_present").unwrap();
        let reader = &source[start..end];

        assert!(reader.contains("let metadata = ensure_regular_yara_rule_file(path)?"));
        assert!(reader.contains("metadata.len() > YARA_RULE_TEXT_LIMIT_BYTES"));
        assert!(reader.contains("let mut total = 0_u64"));
        assert!(reader.contains("checked_add(read as u64)"));
        assert!(reader.contains("total > YARA_RULE_TEXT_LIMIT_BYTES"));
        assert!(reader.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(reader.contains("String::from_utf8(bytes)"));
        assert!(source
            .contains("fn ensure_regular_yara_rule_file(path: &Path) -> Result<fs::Metadata>"));
    }

    #[test]
    fn missing_runtime_yara_rules_use_embedded_fallback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.yar");

        assert!(!runtime_rule_file_present(&path).unwrap());
        assert!(
            YaraProvider::from_embedded_default_rules()
                .unwrap()
                .rule_count()
                > 0
        );
    }

    #[test]
    fn runtime_yara_rules_reject_directory_before_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rules.yar");
        fs::create_dir(&path).unwrap();

        let error = read_bounded_rule_text(&path).unwrap_err().to_string();

        assert!(error.contains("YARA rules"));
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_yara_rules_reject_symbolic_link_before_read() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.yar");
        let path = dir.path().join("rules.yar");
        fs::write(&target, "rule Safe { condition: false }").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = read_bounded_rule_text(&path).unwrap_err().to_string();

        assert!(error.contains("YARA rules"));
        assert!(error.contains("symbolic link"));
        assert!(runtime_rule_file_present(&path).unwrap());
    }
}
