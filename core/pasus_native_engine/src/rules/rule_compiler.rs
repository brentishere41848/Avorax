use anyhow::{bail, Result};

use super::NativeRule;
use crate::verdict::{Confidence, Verdict};

pub fn validate_rules(rules: &[NativeRule]) -> Result<()> {
    for rule in rules {
        if rule.id.trim().is_empty()
            || rule.name.trim().is_empty()
            || rule.description.trim().is_empty()
            || rule.false_positive_notes.trim().is_empty()
            || rule.conditions.is_empty()
        {
            bail!("rule {} is missing required metadata", rule.id);
        }
        if matches!(rule.verdict, Verdict::ConfirmedMalware | Verdict::TestThreat)
            && rule.confidence != Confidence::Confirmed
        {
            bail!("rule {} cannot confirm malware without confirmed confidence", rule.id);
        }
        if rule.conditions.len() < 2 && rule.confidence != Confidence::Low {
            bail!("broad rule {} must be low confidence", rule.id);
        }
    }
    Ok(())
}
