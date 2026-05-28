pub fn script_execution_indicator(command_line: &str) -> bool {
    let lower = command_line.to_ascii_lowercase();
    lower.contains("powershell") || lower.contains("wscript") || lower.contains("cscript")
}
