use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileType {
    Pe,
    Elf,
    MachO,
    PowerShell,
    JavaScript,
    Batch,
    Vbs,
    Zip,
    Text,
    Document,
    Unknown,
}

pub fn detect_file_type(path: &Path, bytes: &[u8]) -> FileType {
    if bytes.starts_with(b"MZ") {
        return FileType::Pe;
    }
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return FileType::Elf;
    }
    if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        || bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        || bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
    {
        return FileType::MachO;
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return FileType::Zip;
    }
    let Some(ext) = normalized_extension(path) else {
        return FileType::Unknown;
    };
    match ext.as_str() {
        "ps1" | "psm1" | "psd1" | "ps1xml" => FileType::PowerShell,
        "js" | "jse" | "mjs" | "cjs" => FileType::JavaScript,
        "bat" | "cmd" => FileType::Batch,
        "vbs" | "vbe" | "wsf" | "hta" | "sct" | "wsc" => FileType::Vbs,
        "txt" | "log" | "md" | "inf" | "eml" | "application" | "appref-ms" | "jnlp"
        | "appinstaller" => FileType::Text,
        "doc" | "docx" | "docm" | "xls" | "xlsx" | "xlsm" | "ppt" | "pptx" | "pptm" | "rtf"
        | "pdf" | "html" | "htm" | "svg" => FileType::Document,
        _ => FileType::Unknown,
    }
}

fn normalized_extension(path: &Path) -> Option<String> {
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())?;
    if extension.is_empty() {
        return None;
    }
    Some(extension)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_missing_extension_uses_explicit_unknown_branch() {
        assert_eq!(
            detect_file_type(Path::new("README"), b"plain"),
            FileType::Unknown
        );

        let source = include_str!("file_type.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains("let Some(ext) = normalized_extension(path) else"));
        assert!(production.contains("return FileType::Unknown;"));
        assert!(!production.contains(".unwrap_or_default()"));
    }

    #[test]
    fn high_risk_script_extensions_get_script_file_types() {
        assert_eq!(
            detect_file_type(Path::new("module.psm1"), b"new-service x"),
            FileType::PowerShell
        );
        assert_eq!(
            detect_file_type(Path::new("types.ps1xml"), b"frombase64string"),
            FileType::PowerShell
        );
        assert_eq!(
            detect_file_type(Path::new("worker.mjs"), b"fetch('https://example.invalid')"),
            FileType::JavaScript
        );
        assert_eq!(
            detect_file_type(Path::new("launcher.hta"), b"msxml2.xmlhttp"),
            FileType::Vbs
        );
        assert_eq!(
            detect_file_type(Path::new("launcher.wsf"), b"wscript.shell"),
            FileType::Vbs
        );
        assert_eq!(
            detect_file_type(Path::new("loader.sct"), b"<scriptlet></scriptlet>"),
            FileType::Vbs
        );
        assert_eq!(
            detect_file_type(Path::new("component.wsc"), b"<component></component>"),
            FileType::Vbs
        );
    }

    #[test]
    fn clickonce_carriers_get_text_file_type() {
        assert_eq!(
            detect_file_type(Path::new("support.application"), b"<deploymentProvider />"),
            FileType::Text
        );
        assert_eq!(
            detect_file_type(
                Path::new("support.appref-ms"),
                b"https://example.invalid/Support.application"
            ),
            FileType::Text
        );
    }

    #[test]
    fn java_web_start_carriers_get_text_file_type() {
        assert_eq!(
            detect_file_type(Path::new("support.jnlp"), b"<jnlp><resources /></jnlp>"),
            FileType::Text
        );
    }

    #[test]
    fn windows_appinstaller_carriers_get_text_file_type() {
        assert_eq!(
            detect_file_type(
                Path::new("support.appinstaller"),
                b"<AppInstaller><MainPackage /></AppInstaller>"
            ),
            FileType::Text
        );
    }
}
