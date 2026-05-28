use std::path::Path;

use crate::analyzers::{FileType, StaticAnalysis};
use crate::heuristics::{filename, location};

use super::feature_vector::FeatureVector;

pub fn extract_features(
    path: &Path,
    analysis: &StaticAnalysis,
    known_good: bool,
    known_bad: bool,
) -> FeatureVector {
    let ext = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let executable_ext = matches!(
        ext.as_str(),
        "exe" | "dll" | "sys" | "scr" | "com" | "ps1" | "bat" | "cmd" | "vbs" | "js"
    );
    let pe = analysis.pe.as_ref();
    let script = analysis.script.as_ref();
    FeatureVector {
        file_size: (analysis.file_size as f64).log10().max(0.0),
        extension_executable: f64::from(executable_ext),
        file_type_executable: f64::from(matches!(analysis.file_type, FileType::Pe | FileType::Elf | FileType::MachO)),
        location_risk: location::location_risk(path) as f64 / 20.0,
        filename_risk: filename::filename_risk(path) as f64 / 25.0,
        double_extension: f64::from(filename::filename_risk(path) >= 25),
        entropy_mean: analysis.entropy_mean / 8.0,
        entropy_max: analysis.entropy_max / 8.0,
        section_count: pe.map(|pe| pe.section_count as f64 / 10.0).unwrap_or(0.0),
        high_entropy_section_count: pe
            .map(|pe| pe.high_entropy_section_count as f64 / 5.0)
            .unwrap_or(0.0),
        suspicious_import_count: pe
            .map(|pe| {
                (pe.suspicious_imports.process_injection
                    + pe.suspicious_imports.credential_access
                    + pe.suspicious_imports.persistence
                    + pe.suspicious_imports.anti_debugging) as f64
                    / 8.0
            })
            .unwrap_or(0.0),
        network_import_count: pe
            .map(|pe| pe.suspicious_imports.network as f64 / 5.0)
            .unwrap_or(0.0),
        injection_import_count: pe
            .map(|pe| pe.suspicious_imports.process_injection as f64 / 3.0)
            .unwrap_or(0.0),
        persistence_import_count: pe
            .map(|pe| pe.suspicious_imports.persistence as f64 / 3.0)
            .unwrap_or(0.0),
        crypto_import_count: pe
            .map(|pe| pe.suspicious_imports.crypto as f64 / 5.0)
            .unwrap_or(0.0),
        embedded_url_count: analysis.string_indicators.embedded_url_count as f64 / 5.0,
        embedded_ip_count: analysis.string_indicators.embedded_ip_count as f64 / 5.0,
        suspicious_string_count: analysis.string_indicators.suspicious_string_count as f64 / 10.0,
        script_obfuscation_score: script
            .map(|script| script.obfuscation_score as f64 / 10.0)
            .unwrap_or(0.0),
        encoded_command_flag: script
            .map(|script| f64::from(script.encoded_command))
            .unwrap_or(0.0),
        archive_contains_executable: analysis
            .archive
            .as_ref()
            .map(|archive| f64::from(archive.contains_executable))
            .unwrap_or(0.0),
        startup_location_flag: f64::from(location::location_risk(path) >= 18),
        known_good_flag: f64::from(known_good),
        known_bad_flag: f64::from(known_bad),
    }
}
