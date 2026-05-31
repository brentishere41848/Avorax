use std::path::Path;

pub fn is_zentor_path(path: &Path) -> bool {
    let value = path.display().to_string().replace('/', "\\").to_ascii_lowercase();
    value.contains("\\program files\\zentor\\")
        || value.contains("\\programdata\\zentor\\")
        || value.contains("\\zentor-quarantine\\")
        || value.contains("\\zentor-native-quarantine\\")
        || value.contains("\\apps\\zentor_client\\")
        || value.contains("\\core\\zentor_")
        || value.contains("\\assets\\zentor_native\\")
        || value.contains("\\installer\\windows\\")
}

pub fn has_zentor_artifact_name(path: &Path) -> bool {
    let Some(name) = path.file_name().map(|name| name.to_string_lossy().to_ascii_lowercase()) else {
        return false;
    };
    name.starts_with("zentor-antivirus-")
        && (name.ends_with("-setup.exe") || name.ends_with("-x64.msi") || name.ends_with(".msi"))
}
