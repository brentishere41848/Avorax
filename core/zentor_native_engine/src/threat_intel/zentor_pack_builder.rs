use chrono::Utc;

use crate::signatures::signature_compiler;
use crate::signatures::{NativeSignature, SignatureType};

use super::indicator::{IndicatorType, ThreatIntelIndicator};

const DEFAULT_INDICATOR_FAMILY: &str = "Known bad";

pub fn indicators_to_signature_pack_json(
    indicators: &[ThreatIntelIndicator],
    version: &str,
) -> anyhow::Result<String> {
    let signatures = indicators
        .iter()
        .map(indicator_to_signature)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let (pack, _) = signature_compiler::compile_pack(signatures, version.to_string())?;
    Ok(serde_json::to_string_pretty(&pack)?)
}

fn indicator_to_signature(indicator: &ThreatIntelIndicator) -> anyhow::Result<NativeSignature> {
    indicator.validate()?;
    let signature_type = match indicator.indicator_type {
        IndicatorType::Sha256 => SignatureType::ExactHash,
        IndicatorType::StringPattern => SignatureType::AsciiString,
        IndicatorType::ScriptPattern => SignatureType::ScriptPattern,
        IndicatorType::BytePattern => SignatureType::BytePattern,
        IndicatorType::ImportCombo => SignatureType::PeImportCombo,
        _ => anyhow::bail!("indicator type cannot be compiled to zsig yet"),
    };
    Ok(NativeSignature {
        id: indicator.indicator_id.clone(),
        name: format!(
            "{} indicator from {}",
            indicator_family_or_default(indicator.malware_family.as_deref()),
            indicator.source_name
        ),
        version: "1".to_string(),
        category: indicator.threat_category,
        confidence: indicator.confidence,
        severity: match indicator.confidence {
            crate::verdict::Confidence::Confirmed => "critical",
            crate::verdict::Confidence::High => "high",
            crate::verdict::Confidence::Medium => "medium",
            crate::verdict::Confidence::Low => "low",
        }
        .to_string(),
        signature_type,
        pattern: indicator.value.clone(),
        mask: None,
        offset: None,
        file_types: vec!["*".to_string()],
        min_file_size: None,
        max_file_size: None,
        required_context: vec![],
        false_positive_notes: indicator.false_positive_notes.clone(),
        action_policy: indicator.action_policy.clone(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

fn indicator_family_or_default(malware_family: Option<&str>) -> &str {
    match malware_family {
        Some(family) => family,
        None => default_indicator_family(),
    }
}

fn default_indicator_family() -> &'static str {
    DEFAULT_INDICATOR_FAMILY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_intel_indicator_family_default_is_explicit() {
        let source = include_str!("zentor_pack_builder.rs");
        let builder_start = source.find("fn indicator_to_signature").unwrap();
        let helper_start = source.find("fn indicator_family_or_default").unwrap();
        let builder_source = &source[builder_start..helper_start];
        let helper_source = &source[helper_start..];

        assert_eq!(
            indicator_family_or_default(Some("Trojan.Fixture")),
            "Trojan.Fixture"
        );
        assert_eq!(indicator_family_or_default(None), DEFAULT_INDICATOR_FAMILY);
        assert!(builder_source
            .contains("indicator_family_or_default(indicator.malware_family.as_deref())"));
        assert!(helper_source.contains("Some(family) => family"));
        assert!(helper_source.contains("None => default_indicator_family()"));
        assert!(!builder_source.contains(".unwrap_or_else(|| \"Known bad\".to_string())"));
    }
}
