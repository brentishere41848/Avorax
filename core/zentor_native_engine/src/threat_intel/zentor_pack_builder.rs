use chrono::Utc;

use crate::signatures::{NativeSignature, SignatureType};
use crate::signatures::signature_compiler;

use super::indicator::{IndicatorType, ThreatIntelIndicator};

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
            indicator
                .malware_family
                .clone()
                .unwrap_or_else(|| "Known bad".to_string()),
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
        required_context: vec!["Threat-intel indicator; metadata-only import.".to_string()],
        false_positive_notes: indicator.false_positive_notes.clone(),
        action_policy: indicator.action_policy.clone(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}
