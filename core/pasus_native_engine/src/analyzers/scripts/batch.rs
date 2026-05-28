use super::ScriptAnalysis;

pub fn analyze(bytes: &[u8]) -> ScriptAnalysis {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    ScriptAnalysis {
        encoded_command: false,
        obfuscation_score: text.matches('^').count() as u32,
        downloader_patterns: text.matches("bitsadmin").count() as u32 + text.matches("curl ").count() as u32,
        execution_patterns: text.matches("start ").count() as u32 + text.matches("powershell").count() as u32,
        persistence_patterns: text.matches("schtasks").count() as u32 + text.matches("reg add").count() as u32,
        security_tamper_indicators: text.matches("vssadmin delete").count() as u32,
    }
}
