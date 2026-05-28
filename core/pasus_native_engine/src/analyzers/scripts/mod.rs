pub mod batch;
pub mod javascript;
pub mod powershell;
pub mod vbs;

use serde::{Deserialize, Serialize};

use super::FileType;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptAnalysis {
    pub encoded_command: bool,
    pub obfuscation_score: u32,
    pub downloader_patterns: u32,
    pub execution_patterns: u32,
    pub persistence_patterns: u32,
    pub security_tamper_indicators: u32,
}

pub fn analyze_script(file_type: FileType, bytes: &[u8]) -> ScriptAnalysis {
    match file_type {
        FileType::PowerShell => powershell::analyze(bytes),
        FileType::JavaScript => javascript::analyze(bytes),
        FileType::Batch => batch::analyze(bytes),
        FileType::Vbs => vbs::analyze(bytes),
        _ => ScriptAnalysis::default(),
    }
}
