use serde::{Deserialize, Serialize};

use super::NativeSignature;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePack {
    pub format: String,
    pub version: String,
    pub signatures: Vec<NativeSignature>,
}
