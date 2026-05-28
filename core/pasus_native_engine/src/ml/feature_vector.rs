use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureVector {
    pub file_size: f64,
    pub extension_executable: f64,
    pub file_type_executable: f64,
    pub location_risk: f64,
    pub filename_risk: f64,
    pub double_extension: f64,
    pub entropy_mean: f64,
    pub entropy_max: f64,
    pub section_count: f64,
    pub high_entropy_section_count: f64,
    pub suspicious_import_count: f64,
    pub network_import_count: f64,
    pub injection_import_count: f64,
    pub persistence_import_count: f64,
    pub crypto_import_count: f64,
    pub embedded_url_count: f64,
    pub embedded_ip_count: f64,
    pub suspicious_string_count: f64,
    pub script_obfuscation_score: f64,
    pub encoded_command_flag: f64,
    pub archive_contains_executable: f64,
    pub startup_location_flag: f64,
    pub known_good_flag: f64,
    pub known_bad_flag: f64,
}

impl FeatureVector {
    pub fn get(&self, name: &str) -> f64 {
        match name {
            "file_size" => self.file_size,
            "extension_executable" => self.extension_executable,
            "file_type_executable" => self.file_type_executable,
            "location_risk" => self.location_risk,
            "filename_risk" => self.filename_risk,
            "double_extension" => self.double_extension,
            "entropy_mean" => self.entropy_mean,
            "entropy_max" => self.entropy_max,
            "section_count" => self.section_count,
            "high_entropy_section_count" => self.high_entropy_section_count,
            "suspicious_import_count" => self.suspicious_import_count,
            "network_import_count" => self.network_import_count,
            "injection_import_count" => self.injection_import_count,
            "persistence_import_count" => self.persistence_import_count,
            "crypto_import_count" => self.crypto_import_count,
            "embedded_url_count" => self.embedded_url_count,
            "embedded_ip_count" => self.embedded_ip_count,
            "suspicious_string_count" => self.suspicious_string_count,
            "script_obfuscation_score" => self.script_obfuscation_score,
            "encoded_command_flag" => self.encoded_command_flag,
            "archive_contains_executable" => self.archive_contains_executable,
            "startup_location_flag" => self.startup_location_flag,
            "known_good_flag" => self.known_good_flag,
            "known_bad_flag" => self.known_bad_flag,
            _ => 0.0,
        }
    }
}
