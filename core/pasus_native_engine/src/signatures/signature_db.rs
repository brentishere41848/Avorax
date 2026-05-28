use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;

use super::{eicar_signature, signature_matcher, NativeSignature, SignatureMatch, SignatureType};
use crate::analyzers::StaticAnalysis;
use crate::verdict::{Confidence, ThreatCategory};

#[derive(Debug, Clone)]
pub struct SignatureDb {
    signatures: Vec<NativeSignature>,
}

impl SignatureDb {
    pub fn built_in() -> Self {
        Self {
            signatures: vec![NativeSignature {
                id: "eicar_test_signature".to_string(),
                name: "EICAR safe anti-malware test file".to_string(),
                version: "1.0.0".to_string(),
                category: ThreatCategory::TestThreat,
                confidence: Confidence::Confirmed,
                severity: "test".to_string(),
                signature_type: SignatureType::EicarTestSignature,
                pattern: eicar_signature::EICAR_ASCII.to_string(),
                mask: None,
                offset: None,
                file_types: vec!["*".to_string()],
                min_file_size: None,
                max_file_size: None,
                required_context: vec![],
                false_positive_notes: "EICAR is a safe industry test string, not real malware.".to_string(),
                action_policy: "quarantine_if_policy_allows".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
        }
    }

    pub fn load_pack(path: &Path) -> Result<Self> {
        let mut db = Self::built_in();
        if path.exists() {
            let text = fs::read_to_string(path)
                .with_context(|| format!("failed to read signature pack {}", path.display()))?;
            let pack: super::pack_format::SignaturePack = serde_json::from_str(&text)
                .with_context(|| format!("failed to parse signature pack {}", path.display()))?;
            super::signature_compiler::validate_signatures(&pack.signatures)?;
            db.signatures.extend(pack.signatures);
        }
        Ok(db)
    }

    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    pub fn match_bytes(
        &self,
        path: &Path,
        sha256: &str,
        bytes: &[u8],
        analysis: &StaticAnalysis,
    ) -> Vec<SignatureMatch> {
        self.signatures
            .iter()
            .filter_map(|signature| {
                signature_matcher::matches_signature(signature, path, sha256, bytes, analysis)
            })
            .collect()
    }
}
