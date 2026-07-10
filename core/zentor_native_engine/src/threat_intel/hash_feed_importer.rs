use crate::verdict::{Confidence, ThreatCategory};

use super::indicator::{IndicatorType, ThreatIntelIndicator};
use super::indicator_normalizer::normalize_indicator_value;
use super::source::ThreatIntelSource;

pub fn import_hash_lines(
    source: &ThreatIntelSource,
    lines: impl IntoIterator<Item = String>,
    category: ThreatCategory,
) -> anyhow::Result<Vec<ThreatIntelIndicator>> {
    source.validate()?;
    let mut indicators = Vec::new();
    for (index, raw) in lines.into_iter().enumerate() {
        let Some(value) = first_hash_field(&raw) else {
            continue;
        };
        let Some(normalized) = normalize_indicator_value(&IndicatorType::Sha256, value) else {
            anyhow::bail!("invalid SHA-256 indicator on line {}", index + 1);
        };
        indicators.push(ThreatIntelIndicator {
            indicator_id: format!(
                "ZTI-{}-{:04}",
                source.source_name.replace(' ', "-"),
                index + 1
            ),
            source_name: source.source_name.clone(),
            source_url: source.source_url.clone(),
            source_type: format!("{:?}", source.source_type).to_ascii_lowercase(),
            indicator_type: IndicatorType::Sha256,
            value: normalized,
            malware_family: None,
            threat_category: category,
            confidence: Confidence::Confirmed,
            first_seen: None,
            last_seen: None,
            false_positive_notes: "Exact SHA-256 indicator from supplied threat-intel source."
                .to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            expires_at: None,
        });
    }
    Ok(indicators)
}

fn first_hash_field(raw: &str) -> Option<&str> {
    let value = raw.split(',').next()?.trim();
    if value.is_empty() || value.starts_with('#') {
        return None;
    }
    Some(value)
}
