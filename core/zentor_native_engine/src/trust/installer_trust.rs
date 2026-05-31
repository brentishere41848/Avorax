use std::path::Path;

pub fn is_installer_artifact(path: &Path) -> bool {
    let Some(name) = path.file_name().map(|name| name.to_string_lossy().to_ascii_lowercase()) else {
        return false;
    };
    name.ends_with(".msi")
        || name.ends_with("setup.exe")
        || name.contains("installer")
        || name.contains("install")
}
