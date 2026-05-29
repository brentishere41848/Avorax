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
        let mut db = Self::default();
        if path.exists() {
            db.load_one(path)?;
            if let Some(parent) = path.parent() {
                let mut siblings = fs::read_dir(parent)?
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|candidate| {
                        candidate.extension().and_then(|value| value.to_str()) == Some("zrule")
                            && candidate != path
                    })
                    .collect::<Vec<_>>();
                siblings.sort();
                for sibling in siblings {
                    db.load_one(&sibling)?;
                }
            }
        }
        Ok(db)
    }

    fn load_one(&mut self, path: &Path) -> Result<()> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read rule pack {}", path.display()))?;
        let pack: RulePack = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse rule pack {}", path.display()))?;
        rule_compiler::validate_rules(&pack.rules)?;
        self.rules.extend(pack.rules);
        Ok(())
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
