use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PRODUCT_NAME: &str = "Avorax Anti-Virus";
pub const PACKAGE_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UpdateChannel {
    Stable,
    Beta,
    Dev,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateComponentSet {
    pub app: bool,
    pub core_service: bool,
    pub guard_service: bool,
    pub update_service: bool,
    pub native_engine_assets: bool,
    pub signatures: bool,
    pub rules: bool,
    pub ml_model: bool,
    pub trust_packs: bool,
    pub docs: bool,
    pub driver_tools: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateManifest {
    pub product: String,
    pub package_format_version: u32,
    pub version: String,
    pub previous_min_version: String,
    pub channel: UpdateChannel,
    pub release_date: String,
    pub package_id: String,
    pub components: UpdateComponentSet,
    pub requires_restart: bool,
    pub requires_reboot: bool,
    pub requires_admin: bool,
    pub driver_update_included: bool,
    pub migration_steps: Vec<String>,
    pub rollback_supported: bool,
    pub payload_hashes: BTreeMap<String, String>,
    pub package_sha256: String,
    pub signature_algorithm: String,
    pub public_key_id: String,
    pub release_notes_url: Option<String>,
}

impl UpdateManifest {
    pub fn validate_static_fields(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.product == PRODUCT_NAME,
            "wrong product: {}",
            self.product
        );
        anyhow::ensure!(
            self.package_format_version == PACKAGE_FORMAT_VERSION,
            "unsupported update package format: {}",
            self.package_format_version
        );
        anyhow::ensure!(
            self.signature_algorithm == "ed25519",
            "unsupported signature algorithm: {}",
            self.signature_algorithm
        );
        anyhow::ensure!(
            !self.driver_update_included,
            "driver updates require a separate explicit driver workflow"
        );
        if self.rollback_supported {
            anyhow::ensure!(
                !self.previous_min_version.trim().is_empty(),
                "rollback-capable packages must declare previous_min_version"
            );
        }
        Ok(())
    }
}
