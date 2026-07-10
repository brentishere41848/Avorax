pub mod batch;
pub mod javascript;
pub mod powershell;
pub mod vbs;

use serde::{Deserialize, Serialize};

use super::FileType;
use anyhow::{bail, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptAnalysis {
    pub encoded_command: bool,
    pub obfuscation_score: u32,
    pub downloader_patterns: u32,
    pub execution_patterns: u32,
    pub persistence_patterns: u32,
    pub security_tamper_indicators: u32,
}

pub fn analyze_script(file_type: FileType, bytes: &[u8]) -> Result<ScriptAnalysis> {
    Ok(match file_type {
        FileType::PowerShell => powershell::analyze(bytes),
        FileType::JavaScript => javascript::analyze(bytes),
        FileType::Batch => batch::analyze(bytes),
        FileType::Vbs => vbs::analyze(bytes),
        _ => bail!("unsupported script analysis file type: {:?}", file_type),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_analysis_rejects_unsupported_file_types() {
        let error = analyze_script(FileType::Text, b"plain text")
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported script analysis file type"));
    }

    #[test]
    fn script_analysis_default_branch_is_not_silent() {
        let source = include_str!("mod.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains("pub fn analyze_script"));
        assert!(production.contains("-> Result<ScriptAnalysis>"));
        assert!(production.contains("unsupported script analysis file type"));
        let old_default = ["_ => ScriptAnalysis::", "default()"].concat();
        assert!(!production.contains(&old_default));
    }
}
