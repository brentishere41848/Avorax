pub fn suspicious_script_child_process(parent: &str, child: &str) -> bool {
    ["wscript.exe", "cscript.exe", "mshta.exe", "winword.exe"]
        .iter()
        .any(|expected| parent.eq_ignore_ascii_case(expected))
        && ["powershell.exe", "cmd.exe", "rundll32.exe"]
            .iter()
            .any(|expected| child.eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_behavior_disabled_child_classifier_is_exact_and_allocation_free() {
        assert!(super::suspicious_script_child_process(
            "WINWORD.EXE",
            "PowerShell.exe"
        ));
        assert!(!super::suspicious_script_child_process(
            "not-winword.exe",
            "powershell.exe"
        ));
    }
}
