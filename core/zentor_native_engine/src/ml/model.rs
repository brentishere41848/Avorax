use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeModel {
    pub model_name: String,
    pub model_version: String,
    pub model_format_version: String,
    pub feature_schema_version: String,
    pub production_ready: bool,
    pub precision: f64,
    pub recall: f64,
    pub false_positive_rate: f64,
    pub bias: f64,
    pub weights: BTreeMap<String, f64>,
    pub thresholds: Thresholds,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub suspicious: f64,
    pub probable_malware: f64,
    pub confirmed_malware: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_native_model_value() -> serde_json::Value {
        serde_json::json!({
            "model_name": "Avorax Native Development Model",
            "model_version": "0.1.0-dev",
            "model_format_version": "zmodel-v1",
            "feature_schema_version": "zne-features-v1",
            "production_ready": false,
            "precision": 0.0,
            "recall": 0.0,
            "false_positive_rate": 1.0,
            "bias": -3.0,
            "weights": {
                "known_bad_flag": 5.0,
                "encoded_command_flag": 2.5
            },
            "thresholds": {
                "suspicious": 0.65,
                "probable_malware": 0.86,
                "confirmed_malware": 0.98
            },
            "limitations": [
                "Development fixture model; not production protection."
            ]
        })
    }

    #[test]
    fn native_model_rejects_unknown_top_level_fields() {
        let mut value = valid_native_model_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("auto_quarantine".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<NativeModel>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("auto_quarantine"));
    }

    #[test]
    fn native_model_thresholds_reject_unknown_fields() {
        let mut value = valid_native_model_value();
        value
            .get_mut("thresholds")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("force_confirmed".to_string(), serde_json::json!(0.01));

        let error = serde_json::from_value::<NativeModel>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("force_confirmed"));
    }

    #[test]
    fn native_model_schema_stays_strict() {
        let source = include_str!("model.rs");
        let model_start = source.find("pub struct NativeModel").unwrap();
        let thresholds_start = source.find("pub struct Thresholds").unwrap();
        let model_source = &source[..thresholds_start];
        let thresholds_source = &source[thresholds_start..];

        assert!(source[..model_start].contains("#[serde(deny_unknown_fields)]"));
        assert!(model_source.contains("pub thresholds: Thresholds"));
        assert!(thresholds_source.contains("#[serde(deny_unknown_fields)]"));
        assert!(source.contains("native_model_rejects_unknown_top_level_fields"));
        assert!(source.contains("native_model_thresholds_reject_unknown_fields"));
    }
}
