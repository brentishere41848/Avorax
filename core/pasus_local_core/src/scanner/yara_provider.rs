use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::clamav_provider::sha256_file;
use super::{
    DetectionType, RecommendedAction, RiskEngine, RiskReason, RiskReasonSource, RiskScore,
    RiskSeverity, RiskVerdict, ThreatCategory, ThreatConfidence, ThreatResult, ThreatResultStatus,
};

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

pub struct YaraProvider {
    rules: Vec<YaraRule>,
}

impl Default for YaraProvider {
    fn default() -> Self {
        Self::from_default_rules().unwrap_or_else(|_| Self { rules: Vec::new() })
    }
}

impl YaraProvider {
    pub fn from_default_rules() -> Result<Self> {
        let path = default_rules_path();
        let raw = fs::read_to_string(path)?;
        Self::from_rule_text(&raw)
    }

    pub fn from_rule_text(raw: &str) -> Result<Self> {
        let mut rules = Vec::new();
        let mut current_name: Option<String> = None;
        let mut category = ThreatCategory::Unknown;
        let mut confidence = ThreatConfidence::Low;
        let mut description = String::new();
        let mut false_positive_notes = String::new();
        let mut patterns = Vec::new();

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("rule ") {
                if let Some(name) = current_name.take() {
                    rules.push(YaraRule {
                        name,
                        category: category.clone(),
                        confidence: confidence.clone(),
                        description: description.clone(),
                        false_positive_notes: false_positive_notes.clone(),
                        patterns: patterns.clone(),
                    });
                    category = ThreatCategory::Unknown;
                    confidence = ThreatConfidence::Low;
                    description.clear();
                    false_positive_notes.clear();
                    patterns.clear();
                }
                current_name = trimmed
                    .strip_prefix("rule ")
                    .and_then(|value| value.split_whitespace().next())
                    .map(|value| value.trim_matches('{').to_string());
            } else if let Some(value) = metadata_value(trimmed, "category") {
                category = category_from_yara(&value);
            } else if let Some(value) = metadata_value(trimmed, "confidence") {
                confidence = confidence_from_yara(&value);
            } else if let Some(value) = metadata_value(trimmed, "description") {
                description = value;
            } else if let Some(value) = metadata_value(trimmed, "false_positive_notes") {
                false_positive_notes = value;
            } else if trimmed.starts_with('$') {
                if let Some((_, value)) = trimmed.split_once('=') {
                    let value = value.trim();
                    if let Some(pattern) = quoted_value(value) {
                        patterns.push(pattern);
                    }
                }
            }
        }

        if let Some(name) = current_name.take() {
            rules.push(YaraRule {
                name,
                category,
                confidence,
                description,
                false_positive_notes,
                patterns,
            });
        }

        Ok(Self { rules })
    }

    pub fn status(&self) -> &'static str {
        if self.rules.is_empty() {
            "rulesUnavailable"
        } else {
            "available"
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn inspect_file(&self, path: &Path) -> Option<ThreatResult> {
        let body = fs::read(path).ok()?;
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
            .max_by_key(|m| confidence_rank(&m.confidence))?;

        Some(threat_from_yara(path, matched))
    }
}

fn threat_from_yara(path: &Path, matched: YaraMatch) -> ThreatResult {
    let metadata = fs::metadata(path).ok();
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
    ThreatResult {
        id: Uuid::new_v4().to_string(),
        path: path.display().to_string(),
        file_name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default(),
        sha256: sha256_file(path).unwrap_or_default(),
        size_bytes: metadata.map(|metadata| metadata.len()).unwrap_or_default(),
        detection_type: DetectionType::Yara,
        threat_category: matched.category,
        threat_name: if confirmed {
            "Known malware rule match".to_string()
        } else {
            "YARA review suggested".to_string()
        },
        confidence: matched.confidence.clone(),
        engine: format!("pasus-yara/{}", matched.rule_name),
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
    }
}

fn default_rules_path() -> PathBuf {
    let mut roots = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }
    for root in roots {
        for candidate in [
            root.join("assets")
                .join("yara")
                .join("pasus_core_rules.yar"),
            root.join("..")
                .join("..")
                .join("assets")
                .join("yara")
                .join("pasus_core_rules.yar"),
        ] {
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("assets/yara/pasus_core_rules.yar")
}

fn metadata_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} =");
    line.strip_prefix(&prefix)
        .and_then(|value| quoted_value(value.trim()))
}

fn quoted_value(value: &str) -> Option<String> {
    let start = value.find('"')?;
    let rest = &value[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn category_from_yara(value: &str) -> ThreatCategory {
    match value {
        "trojan" => ThreatCategory::Trojan,
        "ransomware" => ThreatCategory::Ransomware,
        "spyware" => ThreatCategory::Spyware,
        "adware" => ThreatCategory::Adware,
        "worm" => ThreatCategory::Worm,
        "keylogger" => ThreatCategory::Keylogger,
        "miner" => ThreatCategory::Miner,
        "potentially_unwanted_app" => ThreatCategory::PotentiallyUnwantedApp,
        _ => ThreatCategory::Unknown,
    }
}

fn confidence_from_yara(value: &str) -> ThreatConfidence {
    match value {
        "confirmed" => ThreatConfidence::Confirmed,
        "high" => ThreatConfidence::High,
        "medium" => ThreatConfidence::Medium,
        _ => ThreatConfidence::Low,
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

    #[test]
    fn confirmed_yara_rule_is_confirmed() {
        let rules = r#"
rule Pasus_Safe_EICAR_Simulator
{
  meta:
    category = "unknown"
    confidence = "confirmed"
    description = "Safe EICAR simulator signature."
    false_positive_notes = "Only matches the Pasus safe test fixture."
  strings:
    $eicar = "PASUS-SAFE-EICAR-SIMULATOR-FILE"
  condition:
    any of them
}
"#;
        let provider = YaraProvider::from_rule_text(rules).unwrap();
        let dir = tempdir().unwrap();
        let file = dir.path().join("safe-eicar.com");
        fs::write(&file, "PASUS-SAFE-EICAR-SIMULATOR-FILE").unwrap();
        let threat = provider.inspect_file(&file).unwrap();
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
        assert!(provider.inspect_file(&file).is_none());
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
        let threat = provider.inspect_file(&file).unwrap();
        assert_eq!(threat.confidence, ThreatConfidence::Medium);
        assert_eq!(threat.recommended_action, RecommendedAction::Review);
        assert_ne!(threat.risk_score.verdict, RiskVerdict::ConfirmedMalware);
    }
}
