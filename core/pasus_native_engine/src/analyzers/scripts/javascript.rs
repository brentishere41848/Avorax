use super::ScriptAnalysis;

pub fn analyze(bytes: &[u8]) -> ScriptAnalysis {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    ScriptAnalysis {
        encoded_command: text.contains("atob(") || text.contains("fromcharcode"),
        obfuscation_score: text.matches("eval(").count() as u32 + text.matches("fromcharcode").count() as u32,
        downloader_patterns: text.matches("xmlhttprequest").count() as u32 + text.matches("fetch(").count() as u32,
        execution_patterns: text.matches("wscript.shell").count() as u32 + text.matches("child_process").count() as u32,
        persistence_patterns: text.matches("runonce").count() as u32,
        security_tamper_indicators: 0,
    }
}
