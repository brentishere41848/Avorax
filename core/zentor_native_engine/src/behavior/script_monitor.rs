pub fn script_execution_indicator(executable_name: &str) -> bool {
    [
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    ]
    .iter()
    .any(|expected| executable_name.eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_behavior_script_host_requires_an_exact_executable_name() {
        assert!(super::script_execution_indicator("PowerShell.exe"));
        assert!(super::script_execution_indicator("mshta.exe"));
        assert!(!super::script_execution_indicator("notpowershell.exe"));
        assert!(!super::script_execution_indicator(
            "benign.exe --note powershell.exe"
        ));
    }
}
