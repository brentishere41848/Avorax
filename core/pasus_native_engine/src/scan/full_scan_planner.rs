use std::path::PathBuf;

pub fn full_scan_roots() -> Vec<PathBuf> {
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        vec![PathBuf::from(profile)]
    } else {
        vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))]
    }
}
