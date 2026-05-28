use std::path::Path;

pub fn filename_risk(path: &Path) -> i32 {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let double_extensions = [
        ".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".png.exe", ".txt.exe", ".pdf.scr",
    ];
    if double_extensions.iter().any(|ext| name.ends_with(ext)) {
        return 25;
    }
    if name.ends_with(".exe") {
        return 3;
    }
    0
}
