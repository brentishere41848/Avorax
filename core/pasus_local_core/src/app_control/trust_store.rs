use std::path::Path;

pub fn is_dangerous_allowlist_path(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('/', "\\").to_lowercase();
    matches!(
        normalized.trim_end_matches('\\'),
        "c:" | "c:\\windows" | "c:\\program files" | "c:\\program files (x86)"
    ) || matches!(
        path.display().to_string().as_str(),
        "/" | "/System" | "/usr" | "/bin" | "/sbin" | "/etc"
    )
}

pub fn is_passthrough_system_or_pasus_path(path: &Path) -> bool {
    let lower = path.display().to_string().to_lowercase();
    lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\syswow64\\")
        || lower.ends_with("\\pasus_local_core.exe")
        || lower.ends_with("\\pasus_guard_service.exe")
        || lower.contains("\\pasus\\quarantine\\")
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.contains("/pasus/quarantine/")
}
