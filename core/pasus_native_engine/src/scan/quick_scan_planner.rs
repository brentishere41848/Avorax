use std::path::PathBuf;

pub fn quick_scan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let profile = PathBuf::from(profile);
        roots.push(profile.join("Downloads"));
        roots.push(profile.join("Desktop"));
        roots.push(profile.join("AppData").join("Roaming").join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup"));
    }
    if let Some(temp) = std::env::var_os("TEMP") {
        roots.push(PathBuf::from(temp));
    }
    roots.into_iter().filter(|path| path.exists()).collect()
}
