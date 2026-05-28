use super::ScriptAnalysis;

pub fn analyze(bytes: &[u8]) -> ScriptAnalysis {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let encoded_command = ["-enc", "-encodedcommand", "frombase64string"]
        .iter()
        .any(|term| text.contains(term));
    let downloader_patterns = ["downloadstring", "invoke-webrequest", "webclient", "curl "]
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum();
    let execution_patterns = ["invoke-expression", "iex ", "start-process", "powershell -"]
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum();
    let persistence_patterns = ["schtasks", "new-service", "currentversion\\run"]
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum();
    let security_tamper_indicators = ["set-mppreference", "disableantispyware", "vssadmin delete"]
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum();
    let obfuscation_score = u32::from(encoded_command)
        + text.matches('`').count() as u32
        + text.matches("$(").count() as u32
        + text.matches("^^").count() as u32;
    ScriptAnalysis {
        encoded_command,
        obfuscation_score,
        downloader_patterns,
        execution_patterns,
        persistence_patterns,
        security_tamper_indicators,
    }
}
