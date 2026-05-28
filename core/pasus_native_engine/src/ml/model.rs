use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct Thresholds {
    pub suspicious: f64,
    pub probable_malware: f64,
    pub confirmed_malware: f64,
}
