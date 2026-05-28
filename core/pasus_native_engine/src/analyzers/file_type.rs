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
    let ext = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "ps1" | "psm1" | "psd1" => FileType::PowerShell,
        "js" | "jse" | "mjs" | "cjs" => FileType::JavaScript,
        "bat" | "cmd" => FileType::Batch,
        "vbs" | "vbe" => FileType::Vbs,
        "txt" | "log" | "md" => FileType::Text,
        "doc" | "docx" | "docm" | "xls" | "xlsx" | "xlsm" | "ppt" | "pptx" | "pptm" => {
            FileType::Document
        }
        _ => FileType::Unknown,
    }
}
