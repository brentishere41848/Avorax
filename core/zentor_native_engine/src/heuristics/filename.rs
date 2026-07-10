use std::path::Path;

pub fn filename_risk(path: &Path) -> i32 {
    let name = filename_signal_name(path);
    let double_extensions = [
        ".pdf.exe",
        ".doc.exe",
        ".docx.exe",
        ".jpg.exe",
        ".png.exe",
        ".txt.exe",
        ".pdf.scr",
    ];
    if double_extensions.iter().any(|ext| name.ends_with(ext)) {
        return 25;
    }
    if name.ends_with(".exe") {
        return 3;
    }
    0
}

fn filename_signal_name(path: &Path) -> String {
    let signal = match filename_leaf_signal_name(path) {
        Some(value) => value,
        None => display_path_signal_name(path),
    };
    signal.to_ascii_lowercase()
}

fn filename_leaf_signal_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.trim().is_empty())
}

fn display_path_signal_name(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_signal_name_uses_leaf_or_path_fallback() {
        assert_eq!(
            filename_signal_name(Path::new("C:/Temp/invoice.pdf.exe")),
            "invoice.pdf.exe"
        );
        assert_eq!(
            filename_signal_name(Path::new("/")),
            Path::new("/").display().to_string()
        );
    }

    #[test]
    fn filename_risk_does_not_default_missing_name_to_empty_signal() {
        let source = include_str!("filename.rs");
        let production_source = source
            .split_once("#[cfg(test)]")
            .map(|(production, _)| production)
            .expect("test module marker");

        assert!(production_source.contains("let name = filename_signal_name(path);"));
        assert!(production_source
            .contains("fn filename_leaf_signal_name(path: &Path) -> Option<String>"));
        assert!(production_source.contains("Some(value) => value"));
        assert!(production_source.contains("None => display_path_signal_name(path)"));
        assert!(!production_source.contains(".unwrap_or_default()"));
        assert!(!production_source
            .contains("unwrap_or_else(|| path.display().to_string().to_ascii_lowercase())"));
    }
}
