use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::update_manifest::{UpdateChannel, UpdateManifest};
use crate::update_package::UpdatePackage;

pub const DEV_PUBLIC_KEY_ID: &str = "avorax-dev-ed25519";
pub const DEFAULT_DEV_PUBLIC_KEY_HEX: &str =
    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    pub current_version: String,
    pub channel: UpdateChannel,
    pub allow_dev_key: bool,
    pub public_keys: BTreeMap<String, String>,
}

impl VerificationPolicy {
    pub fn production(current_version: impl Into<String>) -> Self {
        Self {
            current_version: current_version.into(),
            channel: UpdateChannel::Stable,
            allow_dev_key: false,
            public_keys: configured_public_keys(),
        }
    }

    pub fn development(current_version: impl Into<String>) -> Self {
        let public_keys = configured_public_keys();
        Self {
            current_version: current_version.into(),
            channel: UpdateChannel::Dev,
            allow_dev_key: true,
            public_keys,
        }
    }

    pub fn for_cli(current_version: impl Into<String>, allow_development_updates: bool) -> Self {
        if allow_development_updates || development_updates_enabled_by_environment() {
            Self::development(current_version)
        } else {
            Self::production(current_version)
        }
    }
}

fn development_updates_enabled_by_environment() -> bool {
    std::env::var("AVORAX_ALLOW_DEVELOPMENT_UPDATES")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn configured_public_keys() -> BTreeMap<String, String> {
    let mut public_keys = BTreeMap::new();
    let key_id = std::env::var("AVORAX_UPDATE_PUBLIC_KEY_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEV_PUBLIC_KEY_ID.to_string());
    let public_key_hex = std::env::var("AVORAX_UPDATE_PUBLIC_KEY_HEX")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            option_env!("AVORAX_UPDATE_PUBLIC_KEY_HEX")
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| DEFAULT_DEV_PUBLIC_KEY_HEX.to_string());
    public_keys.insert(key_id, public_key_hex);
    public_keys
}

#[derive(Debug, Clone)]
pub struct VerifiedUpdate {
    pub manifest: UpdateManifest,
    pub package_sha256: String,
}

pub struct UpdateVerifier {
    policy: VerificationPolicy,
}

impl UpdateVerifier {
    pub fn new(policy: VerificationPolicy) -> Self {
        Self { policy }
    }

    pub fn verify_package(&self, package: &UpdatePackage) -> Result<VerifiedUpdate> {
        let manifest = package.read_manifest()?;
        manifest.validate_static_fields()?;
        anyhow::ensure!(
            manifest.channel == self.policy.channel,
            "update channel mismatch"
        );
        anyhow::ensure!(
            compare_versions(&manifest.version, &self.policy.current_version) > 0,
            "update package is not newer than installed version"
        );
        if manifest.public_key_id == DEV_PUBLIC_KEY_ID {
            anyhow::ensure!(
                self.policy.allow_dev_key,
                "dev-signed update packages are rejected by this build"
            );
        }
        let package_hash = package.package_sha256()?;
        if !manifest.package_sha256.trim().is_empty() {
            anyhow::ensure!(
                package_hash.eq_ignore_ascii_case(&manifest.package_sha256),
                "update package SHA-256 mismatch"
            );
        }
        self.verify_manifest_signature(package)?;
        package.verify_payload_hashes(&manifest.payload_hashes)?;
        Ok(VerifiedUpdate {
            manifest,
            package_sha256: package_hash,
        })
    }

    fn verify_manifest_signature(&self, package: &UpdatePackage) -> Result<()> {
        let manifest = package.read_manifest()?;
        let public_key_hex = self
            .policy
            .public_keys
            .get(&manifest.public_key_id)
            .with_context(|| format!("unknown update signing key: {}", manifest.public_key_id))?;
        let key_bytes = hex::decode(public_key_hex).context("invalid public key hex")?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&key_array)?;
        let (manifest_bytes, signature_bytes) = package.read_manifest_bytes_and_signature()?;
        let signature = Signature::from_slice(&signature_bytes)?;
        verifying_key
            .verify(&manifest_bytes, &signature)
            .context("manifest signature verification failed")
    }
}

pub fn compare_versions(left: &str, right: &str) -> i32 {
    let a = version_parts(left);
    let b = version_parts(right);
    let max = a.len().max(b.len());
    for i in 0..max {
        let left = *a.get(i).unwrap_or(&0);
        let right = *b.get(i).unwrap_or(&0);
        if left != right {
            return match left.cmp(&right) {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            };
        }
    }
    0
}

fn version_parts(value: &str) -> Vec<u64> {
    value
        .trim()
        .trim_start_matches(['v', 'V'])
        .split(['.', '-', '+'])
        .filter_map(|part| part.parse::<u64>().ok())
        .collect()
}
