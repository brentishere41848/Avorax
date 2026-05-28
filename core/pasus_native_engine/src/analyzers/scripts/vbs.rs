use super::ScriptAnalysis;

pub fn analyze(bytes: &[u8]) -> ScriptAnalysis {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    ScriptAnalysis {
        encoded_command: text.contains("base64"),
        obfuscation_score: text.matches("chr(").count() as u32,
        downloader_patterns: text.matches("msxml2.xmlhttp").count() as u32,
        execution_patterns: text.matches("wscript.shell").count() as u32,
        persistence_patterns: text.matches("runonce").count() as u32,
        security_tamper_indicators: 0,
    }
}
