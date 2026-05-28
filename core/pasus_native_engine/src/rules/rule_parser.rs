use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::{rule_compiler, rule_vm, NativeRule, RuleMatch, RulePack};
use crate::analyzers::StaticAnalysis;

#[derive(Debug, Clone, Default)]
pub struct RuleDb {
    rules: Vec<NativeRule>,
}

impl RuleDb {
    pub fn load_pack(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read rule pack {}", path.display()))?;
        let pack: RulePack = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse rule pack {}", path.display()))?;
        rule_compiler::validate_rules(&pack.rules)?;
        Ok(Self { rules: pack.rules })
    }

    pub fn count(&self) -> usize {
        self.rules.len()
    }

    pub fn evaluate(&self, path: &Path, bytes: &[u8], analysis: &StaticAnalysis) -> Vec<RuleMatch> {
        self.rules
            .iter()
            .filter_map(|rule| rule_vm::evaluate_rule(rule, path, bytes, analysis))
            .collect()
    }
}
