pub fn suspicious_script_child_process(parent: &str, child: &str) -> bool {
    let parent = parent.to_ascii_lowercase();
    let child = child.to_ascii_lowercase();
    matches!(
        parent.as_str(),
        "wscript.exe" | "cscript.exe" | "mshta.exe" | "winword.exe"
    ) && matches!(
        child.as_str(),
        "powershell.exe" | "cmd.exe" | "rundll32.exe"
    )
}
