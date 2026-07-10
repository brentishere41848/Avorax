use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::NativeSignature;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignaturePack {
    pub format: String,
    pub version: String,
    #[serde(default)]
    pub compiler_version: Option<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub pack_sha256: Option<String>,
    pub signatures: Vec<NativeSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignaturePackMetadata {
    pub format: String,
    pub version: String,
    pub compiler_version: String,
    pub signature_count: usize,
    pub pack_sha256: String,
    pub created_at: DateTime<Utc>,
    pub broad_signature_count: usize,
    pub confirmed_signature_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature_pack_value() -> serde_json::Value {
        serde_json::json!({
            "format": "zentor-signature-pack-v1",
            "version": "test",
            "compiler_version": null,
            "created_at": null,
            "pack_sha256": null,
            "signatures": [native_signature_value()],
        })
    }

    fn native_signature_value() -> serde_json::Value {
        serde_json::json!({
            "id": "ZNE-SIG-TEST",
            "name": "Test signature",
            "version": "1",
            "category": "testThreat",
            "confidence": "confirmed",
            "severity": "test",
            "signature_type": "ascii_string",
            "pattern": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            "mask": null,
            "offset": null,
            "file_types": ["text"],
            "min_file_size": null,
            "max_file_size": null,
            "required_context": [],
            "false_positive_notes": "Benign test fixture.",
            "action_policy": "review_only",
            "created_at": "2026-05-28T00:00:00Z",
            "updated_at": "2026-05-28T00:00:00Z",
        })
    }

    #[test]
    fn signature_pack_rejects_unknown_top_level_fields() {
        let mut value = signature_pack_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("enabled".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<SignaturePack>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn native_signature_rejects_unknown_fields() {
        let mut value = native_signature_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("allow_anyway".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<NativeSignature>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn signature_pack_metadata_rejects_unknown_fields() {
        let value = serde_json::json!({
            "format": "zentor-signature-pack-metadata-v1",
            "version": "test",
            "compiler_version": "test",
            "signature_count": 1,
            "pack_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "created_at": "2026-05-28T00:00:00Z",
            "broad_signature_count": 0,
            "confirmed_signature_count": 1,
            "allow_anyway": true,
        });

        let error = serde_json::from_value::<SignaturePackMetadata>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn signature_pack_schema_stays_strict() {
        let pack_source = include_str!("pack_format.rs");
        let signature_source = include_str!("signature.rs");
        let pack_start = pack_source.find("pub struct SignaturePack").unwrap();
        let pack_prefix = &pack_source[..pack_start];
        let metadata_start = pack_source
            .find("pub struct SignaturePackMetadata")
            .unwrap();
        let metadata_prefix = &pack_source[pack_start..metadata_start];
        let signature_start = signature_source.find("pub struct NativeSignature").unwrap();
        let signature_prefix = &signature_source[..signature_start];
        let match_start = signature_source.find("pub struct SignatureMatch").unwrap();
        let match_prefix = &signature_source[signature_start..match_start];

        assert!(pack_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(metadata_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(signature_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(match_prefix.contains("#[serde(deny_unknown_fields)]"));
    }
}
