use std::path::Path;

use crate::analyzers::{
    archives::ArchiveAnalysis, pe::PeAnalysis, scripts::ScriptAnalysis, FileType, StaticAnalysis,
};
use crate::heuristics::{filename, location};

use super::feature_vector::FeatureVector;

pub fn extract_features(
    path: &Path,
    analysis: &StaticAnalysis,
    known_good: bool,
    known_bad: bool,
) -> FeatureVector {
    let executable_ext = extension_is_executable(path);
    let pe = analysis.pe.as_ref();
    let script = analysis.script.as_ref();
    let archive = analysis.archive.as_ref();
    FeatureVector {
        file_size: (analysis.file_size as f64).log10().max(0.0),
        extension_executable: f64::from(executable_ext),
        file_type_executable: f64::from(matches!(
            analysis.file_type,
            FileType::Pe | FileType::Elf | FileType::MachO
        )),
        location_risk: location::location_risk(path) as f64 / 20.0,
        filename_risk: filename::filename_risk(path) as f64 / 25.0,
        double_extension: f64::from(filename::filename_risk(path) >= 25),
        entropy_mean: analysis.entropy_mean / 8.0,
        entropy_max: analysis.entropy_max / 8.0,
        section_count: pe_feature(pe, |pe| pe.section_count as f64 / 10.0),
        high_entropy_section_count: pe_feature(pe, |pe| pe.high_entropy_section_count as f64 / 5.0),
        suspicious_import_count: pe_feature(pe, |pe| {
            (pe.suspicious_imports.process_injection
                + pe.suspicious_imports.credential_access
                + pe.suspicious_imports.persistence
                + pe.suspicious_imports.anti_debugging) as f64
                / 8.0
        }),
        network_import_count: pe_feature(pe, |pe| pe.suspicious_imports.network as f64 / 5.0),
        injection_import_count: pe_feature(pe, |pe| {
            pe.suspicious_imports.process_injection as f64 / 3.0
        }),
        persistence_import_count: pe_feature(pe, |pe| {
            pe.suspicious_imports.persistence as f64 / 3.0
        }),
        crypto_import_count: pe_feature(pe, |pe| pe.suspicious_imports.crypto as f64 / 5.0),
        embedded_url_count: analysis.string_indicators.embedded_url_count as f64 / 5.0,
        embedded_ip_count: analysis.string_indicators.embedded_ip_count as f64 / 5.0,
        suspicious_string_count: analysis.string_indicators.suspicious_string_count as f64 / 10.0,
        script_obfuscation_score: script_feature(script, |script| {
            script.obfuscation_score as f64 / 10.0
        }),
        encoded_command_flag: script_feature(script, |script| f64::from(script.encoded_command)),
        archive_contains_executable: archive_feature(archive, |archive| {
            f64::from(archive.contains_executable)
        }),
        startup_location_flag: f64::from(location::location_risk(path) >= 18),
        known_good_flag: f64::from(known_good),
        known_bad_flag: f64::from(known_bad),
    }
}

fn pe_feature(pe: Option<&PeAnalysis>, value: impl FnOnce(&PeAnalysis) -> f64) -> f64 {
    match pe {
        Some(pe) => value(pe),
        None => absent_subanalysis_feature(),
    }
}

fn script_feature(
    script: Option<&ScriptAnalysis>,
    value: impl FnOnce(&ScriptAnalysis) -> f64,
) -> f64 {
    match script {
        Some(script) => value(script),
        None => absent_subanalysis_feature(),
    }
}

fn archive_feature(
    archive: Option<&ArchiveAnalysis>,
    value: impl FnOnce(&ArchiveAnalysis) -> f64,
) -> f64 {
    match archive {
        Some(archive) => value(archive),
        None => absent_subanalysis_feature(),
    }
}

fn absent_subanalysis_feature() -> f64 {
    0.0
}

fn extension_is_executable(path: &Path) -> bool {
    let Some(ext) = normalized_extension(path) else {
        return false;
    };
    matches!(
        ext.as_str(),
        "exe" | "dll" | "sys" | "scr" | "com" | "ps1" | "bat" | "cmd" | "vbs" | "js"
    )
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
    use crate::analyzers::StringIndicators;

    #[test]
    fn feature_extractor_missing_extension_uses_explicit_non_executable_branch() {
        let analysis = StaticAnalysis {
            file_type: FileType::Unknown,
            file_size: 1,
            entropy_mean: 0.0,
            entropy_max: 0.0,
            string_indicators: StringIndicators::default(),
            pe: None,
            script: None,
            archive: None,
        };

        assert!(!extension_is_executable(Path::new("README")));
        assert!(extension_is_executable(Path::new("sample.EXE")));
        assert_eq!(
            extract_features(Path::new("README"), &analysis, false, false).extension_executable,
            0.0
        );

        let source = include_str!("feature_extractor.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains("let Some(ext) = normalized_extension(path) else"));
        assert!(production.contains("return false;"));
        assert!(!production.contains(".unwrap_or_default()"));
    }

    #[test]
    fn feature_extractor_absent_subanalysis_defaults_are_explicit() {
        let analysis = StaticAnalysis {
            file_type: FileType::Unknown,
            file_size: 1,
            entropy_mean: 0.0,
            entropy_max: 0.0,
            string_indicators: StringIndicators::default(),
            pe: None,
            script: None,
            archive: None,
        };

        let features = extract_features(Path::new("README"), &analysis, false, false);

        assert_eq!(features.section_count, 0.0);
        assert_eq!(features.suspicious_import_count, 0.0);
        assert_eq!(features.script_obfuscation_score, 0.0);
        assert_eq!(features.archive_contains_executable, 0.0);

        let source = include_str!("feature_extractor.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains("fn pe_feature("));
        assert!(production.contains("fn script_feature("));
        assert!(production.contains("fn archive_feature("));
        assert!(production.contains("fn absent_subanalysis_feature() -> f64"));
        assert!(production.contains("None => absent_subanalysis_feature()"));
        assert!(!production.contains(".unwrap_or(0.0)"));
    }
}
