use std::path::Path;

pub fn location_risk(path: &Path) -> i32 {
    let lower = path.display().to_string().to_ascii_lowercase();
    if lower.contains("\\temp\\") || lower.contains("/tmp/") {
        8
    } else if lower.contains("\\downloads\\") || lower.contains("/downloads/") {
        5
    } else if lower.contains("startup") || lower.contains("autostart") {
        18
    } else {
        0
    }
}
