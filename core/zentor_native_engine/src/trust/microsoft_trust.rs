use std::path::Path;
use std::process::Command;

pub fn is_windows_system_path(path: &Path) -> bool {
    let value = path.display().to_string().to_ascii_lowercase();
    value.starts_with("c:\\windows\\system32\\") || value.starts_with("c:\\windows\\syswow64\\")
}

pub fn has_valid_microsoft_signature(path: &Path) -> bool {
    if !cfg!(windows) || !path.exists() {
        return false;
    }

    let Ok(output) = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-AuthenticodeSignature -LiteralPath $args[0] | ConvertTo-Json -Compress)",
            &path.display().to_string(),
        ])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    text.contains("\"status\":0")
        && text.contains("microsoft")
        && (text.contains("corporation") || text.contains("windows"))
}
