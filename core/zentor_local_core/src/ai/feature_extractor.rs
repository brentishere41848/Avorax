use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use super::thresholds::FEATURE_COUNT;

const STATIC_FEATURE_SAMPLE_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticFeatures {
    pub file_size: u64,
    pub file_extension: String,
    pub location_category: LocationCategory,
    pub double_extension: bool,
    pub embedded_urls_count: usize,
    pub embedded_ip_addresses_count: usize,
    pub suspicious_strings_count: usize,
    pub entropy: f64,
    pub packed_likely: bool,
    pub macro_or_script: bool,
}

impl StaticFeatures {
    pub fn to_feature_vector(&self, filename_risk_score: f32) -> [f32; FEATURE_COUNT] {
        let ext = self.file_extension.as_str();
        [
            ((self.file_size as f32 + 1.0).ln() / 20.0).clamp(0.0, 1.0),
            bool_feature(matches!(ext, "exe" | "dll" | "msi" | "scr" | "appimage")),
            bool_feature(matches!(ext, "ps1" | "bat" | "cmd" | "vbs" | "js" | "sh")),
            bool_feature(matches!(ext, "zip" | "rar" | "7z" | "iso")),
            bool_feature(matches!(
                self.location_category,
                LocationCategory::Downloads
            )),
            bool_feature(matches!(self.location_category, LocationCategory::Temp)),
            bool_feature(matches!(self.location_category, LocationCategory::Startup)),
            bool_feature(matches!(
                self.location_category,
                LocationCategory::ProgramFiles
            )),
            bool_feature(matches!(self.location_category, LocationCategory::System)),
            bool_feature(self.double_extension),
            (self.entropy as f32 / 8.0).clamp(0.0, 1.0),
            (self.embedded_urls_count as f32 / 10.0).clamp(0.0, 1.0),
            (self.embedded_ip_addresses_count as f32 / 10.0).clamp(0.0, 1.0),
            (self.suspicious_strings_count as f32 / 6.0).clamp(0.0, 1.0),
            bool_feature(self.packed_likely),
            bool_feature(self.macro_or_script),
            filename_risk_score.clamp(0.0, 1.0),
            0.0,
        ]
    }
}

fn bool_feature(value: bool) -> f32 {
    if value {
        1.0
    } else {
        0.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocationCategory {
    Downloads,
    Temp,
    Startup,
    System,
    ProgramFiles,
    UserProfile,
    Unknown,
}

pub fn extract_static_features(path: &Path) -> anyhow::Result<StaticFeatures> {
    let metadata = inspect_regular_static_feature_target(path)?;
    let path_lower = path.display().to_string().to_lowercase();
    let file_name = static_feature_file_name(path);
    let extension = static_feature_extension(path);
    let sample = read_static_feature_sample(path)?;
    let text = String::from_utf8_lossy(&sample).to_lowercase();
    let entropy = entropy(&sample);
    Ok(StaticFeatures {
        file_size: metadata.len(),
        file_extension: extension.clone(),
        location_category: location_category(&path_lower),
        double_extension: suspicious_double_extension(&file_name),
        embedded_urls_count: text.matches("http://").count() + text.matches("https://").count(),
        embedded_ip_addresses_count: count_ipv4_like(&text),
        suspicious_strings_count: count_suspicious_strings(&text),
        entropy,
        packed_likely: entropy >= 7.6,
        macro_or_script: matches!(
            extension.as_str(),
            "ps1" | "bat" | "cmd" | "vbs" | "js" | "docm" | "xlsm"
        ),
    })
}

fn read_static_feature_sample(path: &Path) -> anyhow::Result<Vec<u8>> {
    inspect_regular_static_feature_target(path)?;
    let mut reader = fs::File::open(path)
        .with_context(|| format!("unable to read file content for {}", path.display()))?;
    let mut sample = Vec::new();
    let mut remaining = STATIC_FEATURE_SAMPLE_BYTES;
    let mut buffer = [0_u8; 8192];
    while remaining > 0 {
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let read = reader
            .read(&mut buffer[..read_limit])
            .with_context(|| format!("unable to read file content for {}", path.display()))?;
        if read == 0 {
            break;
        }
        remaining -= read as u64;
        sample.extend_from_slice(&buffer[..read]);
    }
    Ok(sample)
}

fn inspect_regular_static_feature_target(path: &Path) -> anyhow::Result<std::fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to read metadata for {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to inspect symbolic link static feature target: {}",
            path.display()
        );
    }
    if static_feature_metadata_is_windows_reparse_point(&metadata) {
        anyhow::bail!(
            "refusing to inspect reparse point static feature target: {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!(
            "static feature extraction requires a regular file: {}",
            path.display()
        );
    }
    Ok(metadata)
}

#[cfg(windows)]
fn static_feature_metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn static_feature_metadata_is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub fn filename_risk_score(path: &Path) -> f32 {
    let file_name = static_feature_file_name(path);
    let mut score: f32 = 0.0;
    if suspicious_double_extension(&file_name) {
        score += 0.45;
    }
    if looks_randomish(&file_name) {
        score += 0.20;
    }
    if file_name.contains("crack") || file_name.contains("keygen") || file_name.contains("patcher")
    {
        score += 0.25;
    }
    score.clamp(0.0, 1.0)
}

fn static_feature_file_name(path: &Path) -> String {
    static_feature_file_name_text(path).to_lowercase()
}

fn static_feature_file_name_text(path: &Path) -> String {
    match static_feature_leaf_name(path) {
        Some(name) => name,
        None => display_path_or_unknown(path),
    }
}

fn static_feature_leaf_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.trim().is_empty())
}

fn static_feature_extension(path: &Path) -> String {
    match static_feature_extension_text(path) {
        Some(extension) => extension.to_lowercase(),
        None => default_static_feature_extension().to_string(),
    }
}

fn static_feature_extension_text(path: &Path) -> Option<String> {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_string())
        .filter(|ext| !ext.trim().is_empty())
}

fn default_static_feature_extension() -> &'static str {
    ""
}

fn display_path_or_unknown(path: &Path) -> String {
    let display = path.display().to_string();
    if display.trim().is_empty() {
        "<unknown-path>".to_string()
    } else {
        display
    }
}

fn location_category(path_lower: &str) -> LocationCategory {
    if path_lower.contains("download") {
        LocationCategory::Downloads
    } else if path_lower.contains("\\temp\\") || path_lower.contains("/tmp/") {
        LocationCategory::Temp
    } else if path_lower.contains("startup") || path_lower.contains("autostart") {
        LocationCategory::Startup
    } else if path_lower.contains("\\windows\\") || path_lower.starts_with("/system") {
        LocationCategory::System
    } else if path_lower.contains("program files") || path_lower.starts_with("/usr") {
        LocationCategory::ProgramFiles
    } else if path_lower.contains("users") || path_lower.contains("/home/") {
        LocationCategory::UserProfile
    } else {
        LocationCategory::Unknown
    }
}

fn suspicious_double_extension(lower: &str) -> bool {
    [
        ".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".jpg.", ".png.",
    ]
    .iter()
    .any(|ext| lower.contains(ext))
        && [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"]
            .iter()
            .any(|ext| lower.ends_with(ext))
}

fn count_suspicious_strings(text: &str) -> usize {
    [
        "frombase64string",
        "invoke-expression",
        "powershell -enc",
        "vssadmin delete shadows",
        "bcdedit /set",
        "disableantispyware",
    ]
    .iter()
    .filter(|needle| text.contains(**needle))
    .count()
}

fn count_ipv4_like(text: &str) -> usize {
    text.split_whitespace()
        .filter(|part| {
            let octets = part.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            let values = octets.split('.').collect::<Vec<_>>();
            values.len() == 4 && values.iter().all(|value| value.parse::<u8>().is_ok())
        })
        .count()
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_randomish(name: &str) -> bool {
    let stem = first_filename_stem_or_name(name);
    if stem.len() < 8 || !stem.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let digits = stem.chars().filter(|c| c.is_ascii_digit()).count();
    let letters = stem.chars().filter(|c| c.is_ascii_alphabetic()).count();
    digits >= 3 && letters >= 3
}

fn first_filename_stem_or_name(name: &str) -> &str {
    match name.split('.').next() {
        Some(stem) => stem,
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn static_feature_extraction_rejects_directories() {
        let dir = tempdir().unwrap();

        let error = extract_static_features(dir.path()).unwrap_err().to_string();

        assert!(error.contains("requires a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn static_feature_extraction_rejects_symbolic_links() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let link = dir.path().join("linked.exe");
        fs::write(&target, b"benign fixture").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        let feature_error = extract_static_features(&link).unwrap_err().to_string();
        let sample_error = read_static_feature_sample(&link).unwrap_err().to_string();

        assert!(feature_error.contains("symbolic link"));
        assert!(sample_error.contains("symbolic link"));
    }

    #[test]
    fn static_feature_extraction_uses_non_following_target_metadata() {
        let source = include_str!("feature_extractor.rs");
        let helper_pattern = ["fn inspect_regular_static_", "feature_target"].concat();
        let helper_call_pattern = ["inspect_regular_static_", "feature_target(path)?"].concat();
        let symlink_metadata_pattern = ["fs::", "symlink_metadata(path)"].concat();
        let symlink_error_pattern = [
            "refusing to inspect symbolic link ",
            "static feature target",
        ]
        .concat();
        let reparse_error_pattern = [
            "refusing to inspect reparse point ",
            "static feature target",
        ]
        .concat();
        let old_metadata_pattern = ["fs::", "metadata(path)"].concat();

        assert!(source.contains(&helper_pattern));
        assert!(source.contains(&helper_call_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains(&symlink_error_pattern));
        assert!(source.contains(&reparse_error_pattern));
        assert!(!source.contains(&old_metadata_pattern));
    }

    #[test]
    fn static_feature_extraction_uses_bounded_sample() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let mut bytes = vec![b'A'; STATIC_FEATURE_SAMPLE_BYTES as usize];
        bytes.extend_from_slice(b"http://outside-sample.example");
        fs::write(&path, bytes).unwrap();

        let features = extract_static_features(&path).unwrap();

        assert!(features.file_size > STATIC_FEATURE_SAMPLE_BYTES);
        assert_eq!(features.embedded_urls_count, 0);
    }

    #[test]
    fn static_feature_file_name_uses_leaf_or_path_fallback() {
        assert_eq!(
            static_feature_file_name(Path::new("Invoice.PDF.EXE")),
            "invoice.pdf.exe"
        );
        assert_eq!(static_feature_file_name(Path::new("/")), "/");
        assert_eq!(static_feature_file_name(Path::new("")), "<unknown-path>");
    }

    #[test]
    fn static_feature_extension_default_is_explicit() {
        let source = include_str!("feature_extractor.rs");
        let extension_start = source.find("fn static_feature_extension").unwrap();
        let display_start = source.find("fn display_path_or_unknown").unwrap();
        let extension_source = &source[extension_start..display_start];

        assert_eq!(static_feature_extension(Path::new("Tool.PS1")), "ps1");
        assert_eq!(static_feature_extension(Path::new("README")), "");
        assert!(extension_source.contains("Some(extension) => extension.to_lowercase()"));
        assert!(extension_source.contains("None => default_static_feature_extension().to_string()"));
        assert!(extension_source.contains("fn default_static_feature_extension() -> &'static str"));
        assert!(!extension_source.contains("unwrap_or_else(String::new)"));
    }

    #[test]
    fn static_feature_randomish_stem_default_is_explicit() {
        let source = include_str!("feature_extractor.rs");
        let randomish_start = source.find("fn looks_randomish").unwrap();
        let tests_start = source.find("#[cfg(test)]").unwrap();
        let randomish_source = &source[randomish_start..tests_start];

        assert_eq!(first_filename_stem_or_name("abc.def"), "abc");
        assert_eq!(first_filename_stem_or_name("abcdef"), "abcdef");
        assert!(randomish_source.contains("let stem = first_filename_stem_or_name(name);"));
        assert!(randomish_source.contains("Some(stem) => stem"));
        assert!(randomish_source.contains("None => name"));
        assert!(!randomish_source.contains("unwrap_or(name)"));
    }

    #[test]
    fn static_feature_filename_signals_do_not_default_to_empty_strings() {
        let source = include_str!("feature_extractor.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        let old_file_name_default = [
            ".file_name()",
            "\n        .map(|name| name.to_string_lossy().to_lowercase())",
            "\n        .unwrap_or_default()",
        ]
        .concat();

        assert!(production_source.contains("let file_name = static_feature_file_name(path);"));
        assert!(production_source.contains("fn static_feature_file_name(path: &Path) -> String"));
        assert!(
            production_source.contains("fn static_feature_file_name_text(path: &Path) -> String")
        );
        assert!(production_source.contains("Some(name) => name"));
        assert!(production_source.contains("None => display_path_or_unknown(path)"));
        assert!(!production_source.contains("unwrap_or_else(|| display_path_or_unknown(path))"));
        assert!(!production_source.contains(&old_file_name_default));
    }
}
