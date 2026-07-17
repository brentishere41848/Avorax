use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::update_manifest::{validate_version, UpdateChannel, UpdateManifest};
use crate::update_package::UpdatePackage;

pub const DEV_PUBLIC_KEY_ID: &str = "avorax-dev-ed25519";
pub const DEFAULT_DEV_PUBLIC_KEY_HEX: &str =
    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
const DEVELOPMENT_UPDATES_ENV: &str = "AVORAX_ALLOW_DEVELOPMENT_UPDATES";
const UPDATE_PUBLIC_KEY_HEX_ENV: &str = "AVORAX_UPDATE_PUBLIC_KEY_HEX";
const UPDATE_PUBLIC_KEY_ID_ENV: &str = "AVORAX_UPDATE_PUBLIC_KEY_ID";
const DEFAULT_PRODUCTION_PUBLIC_KEY_ID: &str = "avorax-production-ed25519";
const MAX_UPDATE_PUBLIC_KEY_ID_LEN: usize = 128;
const ED25519_PUBLIC_KEY_HEX_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    pub current_version: String,
    pub channel: UpdateChannel,
    pub allow_dev_key: bool,
    pub public_keys: BTreeMap<String, String>,
}

impl VerificationPolicy {
    pub fn production(current_version: impl Into<String>) -> Result<Self> {
        Ok(Self {
            current_version: current_version.into(),
            channel: UpdateChannel::Stable,
            allow_dev_key: false,
            public_keys: configured_public_keys(false)?,
        })
    }

    pub fn development(current_version: impl Into<String>) -> Result<Self> {
        let public_keys = configured_public_keys(true)?;
        Ok(Self {
            current_version: current_version.into(),
            channel: UpdateChannel::Dev,
            allow_dev_key: true,
            public_keys,
        })
    }

    pub fn for_cli(
        current_version: impl Into<String>,
        allow_development_updates: bool,
    ) -> Result<Self> {
        if allow_development_updates || development_updates_enabled_by_environment()? {
            Self::development(current_version)
        } else {
            Self::production(current_version)
        }
    }
}

fn development_updates_enabled_by_environment() -> Result<bool> {
    match std::env::var(DEVELOPMENT_UPDATES_ENV) {
        Ok(value) => parse_development_update_flag(&value, DEVELOPMENT_UPDATES_ENV),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{DEVELOPMENT_UPDATES_ENV} must be valid Unicode")
        }
    }
}

fn parse_development_update_flag(value: &str, label: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!(
            "{label} must be explicitly true or false; use one of 1/true/yes/on or 0/false/no/off"
        ),
    }
}

fn configured_public_keys(include_development_key: bool) -> Result<BTreeMap<String, String>> {
    let mut public_keys = BTreeMap::new();
    if let Some(valid_public_key_hex) = configured_update_public_key_hex()? {
        let valid_key_id = configured_update_public_key_id_or_default()?;
        public_keys.insert(valid_key_id, valid_public_key_hex);
    }
    if include_development_key {
        public_keys.insert(
            DEV_PUBLIC_KEY_ID.to_string(),
            DEFAULT_DEV_PUBLIC_KEY_HEX.to_string(),
        );
    }
    Ok(public_keys)
}

fn configured_update_public_key_id_or_default() -> Result<String> {
    match configured_update_public_key_id()? {
        Some(valid_key_id) => Ok(valid_key_id),
        None => Ok(DEFAULT_PRODUCTION_PUBLIC_KEY_ID.to_string()),
    }
}

fn configured_update_public_key_hex() -> Result<Option<String>> {
    configured_optional_text(
        UPDATE_PUBLIC_KEY_HEX_ENV,
        option_env!("AVORAX_UPDATE_PUBLIC_KEY_HEX"),
    )?
    .map(|value| validate_update_public_key_hex(&value))
    .transpose()
}

fn configured_update_public_key_id() -> Result<Option<String>> {
    configured_optional_text(
        UPDATE_PUBLIC_KEY_ID_ENV,
        option_env!("AVORAX_UPDATE_PUBLIC_KEY_ID"),
    )?
    .map(|value| validate_update_public_key_id(&value))
    .transpose()
}

fn configured_optional_text(
    name: &str,
    compile_time_value: Option<&'static str>,
) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => return Ok(Some(normalize_config_text(&value, name)?)),
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid Unicode"),
    }
    compile_time_value
        .map(|value| normalize_config_text(value, name))
        .transpose()
}

fn normalize_config_text(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "{label} must not be empty when configured"
    );
    anyhow::ensure!(
        !trimmed.contains('\0'),
        "{label} must not contain NUL bytes"
    );
    Ok(trimmed.to_string())
}

fn validate_update_public_key_id(value: &str) -> Result<String> {
    let trimmed = value.trim();
    anyhow::ensure!(!trimmed.is_empty(), "update public key ID is empty");
    anyhow::ensure!(
        trimmed.len() <= MAX_UPDATE_PUBLIC_KEY_ID_LEN,
        "update public key ID is too long"
    );
    anyhow::ensure!(
        trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')),
        "update public key ID contains unsafe characters"
    );
    anyhow::ensure!(
        !trimmed.contains(".."),
        "update public key ID must not contain parent traversal"
    );
    Ok(trimmed.to_string())
}

fn validate_update_public_key_hex(value: &str) -> Result<String> {
    let trimmed = value.trim();
    anyhow::ensure!(
        trimmed.len() == ED25519_PUBLIC_KEY_HEX_LEN,
        "update public key hex must be a 32-byte Ed25519 public key"
    );
    anyhow::ensure!(
        trimmed.chars().all(|ch| ch.is_ascii_hexdigit()),
        "update public key hex must contain only hexadecimal characters"
    );
    let key_bytes = hex::decode(trimmed).context("invalid update public key hex")?;
    anyhow::ensure!(
        key_bytes.len() == 32,
        "update public key hex must decode to 32 bytes"
    );
    Ok(trimmed.to_ascii_lowercase())
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
        let (manifest_bytes, signature_bytes) = package.read_manifest_bytes_and_signature()?;
        let manifest: UpdateManifest =
            serde_json::from_slice(&manifest_bytes).context("failed to parse update manifest")?;
        manifest.validate_static_fields()?;
        anyhow::ensure!(
            !self.policy.public_keys.is_empty(),
            "no trusted production update signing key is configured"
        );
        anyhow::ensure!(
            manifest.channel == self.policy.channel,
            "update channel mismatch"
        );
        validate_version(
            &self.policy.current_version,
            "installed update policy version",
        )?;
        anyhow::ensure!(
            compare_versions(&manifest.version, &self.policy.current_version)
                .context("failed to compare update versions")?
                > 0,
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
        self.verify_manifest_signature(&manifest.public_key_id, &manifest_bytes, &signature_bytes)?;
        package.verify_payload_matches_manifest(&manifest)?;
        Ok(VerifiedUpdate {
            manifest,
            package_sha256: package_hash,
        })
    }

    fn verify_manifest_signature(
        &self,
        public_key_id: &str,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<()> {
        let public_key_hex = self
            .policy
            .public_keys
            .get(public_key_id)
            .with_context(|| format!("unknown update signing key: {public_key_id}"))?;
        let key_bytes = hex::decode(public_key_hex).context("invalid public key hex")?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&key_array)?;
        let signature = Signature::from_slice(signature_bytes)?;
        verifying_key
            .verify(manifest_bytes, &signature)
            .context("manifest signature verification failed")
    }
}

pub fn compare_versions(left: &str, right: &str) -> Result<i32> {
    let a = version_parts(left, "left update version")?;
    let b = version_parts(right, "right update version")?;
    let max = a.len().max(b.len());
    for i in 0..max {
        let left = version_part_or_zero(&a, i);
        let right = version_part_or_zero(&b, i);
        if left != right {
            return Ok(match left.cmp(&right) {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            });
        }
    }
    Ok(0)
}

fn version_part_or_zero(parts: &[u64], index: usize) -> u64 {
    match parts.get(index) {
        Some(value) => *value,
        None => 0,
    }
}

fn version_parts(value: &str, label: &str) -> Result<Vec<u64>> {
    validate_version(value, label)?;
    value
        .trim()
        .split('.')
        .map(|part| {
            part.parse::<u64>()
                .with_context(|| format!("{label} contains an invalid numeric component"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_manifest::{UpdateComponentSet, PACKAGE_FORMAT_VERSION, PRODUCT_NAME};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    const TEST_UPDATE_KEY_ID: &str = "avorax-test-production-ed25519";

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn test_public_key_hex(signing_key: &SigningKey) -> String {
        hex::encode(signing_key.verifying_key().to_bytes())
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn signed_manifest_for_payload(payload: &[u8]) -> UpdateManifest {
        let mut payload_hashes = BTreeMap::new();
        payload_hashes.insert("app/Avorax.exe".to_string(), sha256_bytes(payload));
        UpdateManifest {
            product: PRODUCT_NAME.to_string(),
            package_format_version: PACKAGE_FORMAT_VERSION,
            version: "0.2.12".to_string(),
            previous_min_version: "0.2.10".to_string(),
            channel: UpdateChannel::Stable,
            release_date: "2026-05-31T00:00:00Z".to_string(),
            package_id: "stable-package".to_string(),
            components: UpdateComponentSet {
                app: true,
                core_service: false,
                guard_service: false,
                update_service: false,
                native_engine_assets: false,
                signatures: false,
                rules: false,
                ml_model: false,
                trust_packs: false,
                docs: false,
                driver_tools: false,
            },
            requires_restart: true,
            requires_reboot: false,
            requires_admin: true,
            driver_update_included: false,
            migration_steps: vec![],
            rollback_supported: true,
            payload_hashes,
            package_sha256: String::new(),
            signature_algorithm: "ed25519".to_string(),
            public_key_id: TEST_UPDATE_KEY_ID.to_string(),
            release_notes_url: None,
        }
    }

    fn write_signed_test_package(
        path: &Path,
        manifest: &UpdateManifest,
        payload: &[u8],
        signing_key: &SigningKey,
    ) {
        let manifest_bytes = serde_json::to_vec(manifest).unwrap();
        let signature = signing_key.sign(&manifest_bytes);
        let file = File::create(path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(&manifest_bytes).unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive
            .write_all(hex::encode(signature.to_bytes()).as_bytes())
            .unwrap();
        archive
            .start_file("payload/app/Avorax.exe", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();
    }

    fn verifier_for_key(signing_key: &SigningKey, current_version: &str) -> UpdateVerifier {
        let mut public_keys = BTreeMap::new();
        public_keys.insert(
            TEST_UPDATE_KEY_ID.to_string(),
            test_public_key_hex(signing_key),
        );
        UpdateVerifier::new(VerificationPolicy {
            current_version: current_version.to_string(),
            channel: UpdateChannel::Stable,
            allow_dev_key: false,
            public_keys,
        })
    }

    #[test]
    fn version_compare_rejects_malformed_versions() {
        let source = include_str!("update_verifier.rs");
        let old_silent_parse = [".filter_map(|part| part.parse::<u64>()", ".ok())"].concat();

        assert!(compare_versions("0.2.12", "0.2.11").unwrap() > 0);
        assert!(compare_versions("0.2.beta", "0.2.11").is_err());
        assert!(compare_versions("v0.2.12", "0.2.11").is_err());
        assert!(source.contains("validate_version(value, label)?"));
        assert!(!source.contains(&old_silent_parse));
    }

    #[test]
    fn version_compare_missing_parts_are_explicit_zeroes() {
        let source = include_str!("update_verifier.rs");
        let old_missing_part_default = [".unwrap_or", "(&0)"].concat();

        assert_eq!(compare_versions("1", "1.0").unwrap(), 0);
        assert!(compare_versions("1.0.1", "1").unwrap() > 0);
        assert!(compare_versions("1", "1.0.1").unwrap() < 0);
        assert!(source.contains("fn version_part_or_zero(parts: &[u64], index: usize) -> u64"));
        assert!(source.contains("None => 0"));
        assert!(!source.contains(&old_missing_part_default));
    }

    #[test]
    fn development_update_env_flag_accepts_only_explicit_boolean_values() {
        assert!(parse_development_update_flag("1", "TEST_FLAG").unwrap());
        assert!(parse_development_update_flag(" true ", "TEST_FLAG").unwrap());
        assert!(parse_development_update_flag("YES", "TEST_FLAG").unwrap());
        assert!(parse_development_update_flag("on", "TEST_FLAG").unwrap());
        assert!(!parse_development_update_flag("0", "TEST_FLAG").unwrap());
        assert!(!parse_development_update_flag(" false ", "TEST_FLAG").unwrap());
        assert!(!parse_development_update_flag("NO", "TEST_FLAG").unwrap());
        assert!(!parse_development_update_flag("off", "TEST_FLAG").unwrap());
        assert!(parse_development_update_flag("", "TEST_FLAG").is_err());
        assert!(parse_development_update_flag("maybe", "TEST_FLAG").is_err());
    }

    #[test]
    fn cli_development_update_env_flag_is_fallible_not_false_default() {
        let source = include_str!("update_verifier.rs");
        let old_false_default = [".unwrap_or", "(false)"].concat();

        assert!(source.contains("pub fn for_cli("));
        assert!(source.contains(") -> Result<Self>"));
        assert!(source.contains("development_updates_enabled_by_environment()?"));
        assert!(source.contains(
            "fn parse_development_update_flag(value: &str, label: &str) -> Result<bool>"
        ));
        assert!(source.contains("must be explicitly true or false"));
        assert!(!source.contains(&old_false_default));
    }

    #[test]
    fn configured_update_public_key_id_uses_safe_token_shape() {
        assert_eq!(
            validate_update_public_key_id(" avorax-production-ed25519 ").unwrap(),
            "avorax-production-ed25519"
        );
        assert!(validate_update_public_key_id("").is_err());
        assert!(validate_update_public_key_id("../avorax").is_err());
        assert!(validate_update_public_key_id("avorax/prod").is_err());
        assert!(
            validate_update_public_key_id(&"a".repeat(MAX_UPDATE_PUBLIC_KEY_ID_LEN + 1)).is_err()
        );
    }

    #[test]
    fn configured_update_public_key_hex_requires_ed25519_key_shape() {
        let uppercase = DEFAULT_DEV_PUBLIC_KEY_HEX.to_ascii_uppercase();

        assert_eq!(
            validate_update_public_key_hex(&uppercase).unwrap(),
            DEFAULT_DEV_PUBLIC_KEY_HEX
        );
        assert!(validate_update_public_key_hex("").is_err());
        assert!(validate_update_public_key_hex("a").is_err());
        assert!(validate_update_public_key_hex(&"g".repeat(ED25519_PUBLIC_KEY_HEX_LEN)).is_err());
        assert!(
            validate_update_public_key_hex(&"a".repeat(ED25519_PUBLIC_KEY_HEX_LEN + 2)).is_err()
        );
    }

    #[test]
    fn configured_update_public_keys_are_validated_before_policy_state() {
        let source = include_str!("update_verifier.rs");
        let old_hex_env_parse = [
            "std::env::var(\"AVORAX_UPDATE_PUBLIC_KEY_HEX\")",
            "\n        .ok()",
        ]
        .concat();
        let old_raw_insert = ["public_keys.insert(key_id", ", public_key_hex);"].concat();

        assert!(source
            .contains("pub fn production(current_version: impl Into<String>) -> Result<Self>"));
        assert!(source
            .contains("pub fn development(current_version: impl Into<String>) -> Result<Self>"));
        assert!(source.contains(
            "fn configured_public_keys(include_development_key: bool) -> Result<BTreeMap<String, String>>"
        ));
        assert!(source.contains("configured_update_public_key_hex()?"));
        assert!(source.contains("configured_update_public_key_id()?"));
        assert!(source.contains("validate_update_public_key_hex"));
        assert!(source.contains("validate_update_public_key_id"));
        assert!(!source.contains(&old_hex_env_parse));
        assert!(!source.contains(&old_raw_insert));
    }

    #[test]
    fn configured_update_public_key_id_default_is_explicit() {
        let source = include_str!("update_verifier.rs");
        let old_hidden_default = [
            ".unwrap_or_else(|| ",
            "DEFAULT_PRODUCTION_PUBLIC_KEY_ID.to_string())",
        ]
        .concat();

        assert!(
            source.contains("fn configured_update_public_key_id_or_default() -> Result<String>")
        );
        assert!(source.contains("Some(valid_key_id) => Ok(valid_key_id)"));
        assert!(source.contains("None => Ok(DEFAULT_PRODUCTION_PUBLIC_KEY_ID.to_string())"));
        assert!(!source.contains(&old_hidden_default));
    }

    #[test]
    fn verifier_parses_the_signed_manifest_bytes() {
        let source = include_str!("update_verifier.rs");
        let start = source.find("pub fn verify_package").unwrap();
        let end = source.find("fn verify_manifest_signature").unwrap();
        let verify_package_source = &source[start..end];

        assert!(verify_package_source.contains("package.read_manifest_bytes_and_signature()?"));
        assert!(verify_package_source.contains("serde_json::from_slice(&manifest_bytes)"));
        assert!(verify_package_source.contains(
            "self.verify_manifest_signature(&manifest.public_key_id, &manifest_bytes, &signature_bytes)?"
        ));
        assert!(!verify_package_source.contains("package.read_manifest()?"));
    }

    #[test]
    fn signed_update_package_verifies_manifest_signature_and_payload_hashes() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("signed.aup");
        let signing_key = test_signing_key();
        let payload = b"benign signed update payload";
        let manifest = signed_manifest_for_payload(payload);

        write_signed_test_package(&package_path, &manifest, payload, &signing_key);

        let verified = verifier_for_key(&signing_key, "0.2.11")
            .verify_package(&UpdatePackage::new(&package_path))
            .unwrap();

        assert_eq!(verified.manifest.version, "0.2.12");
        assert_eq!(verified.manifest.public_key_id, TEST_UPDATE_KEY_ID);
        assert_eq!(verified.package_sha256.len(), 64);
    }

    #[test]
    fn signed_update_package_rejects_tampered_manifest_signature() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("tampered-manifest.aup");
        let signing_key = test_signing_key();
        let payload = b"benign signed update payload";
        let signed_manifest = signed_manifest_for_payload(payload);
        let mut tampered_manifest = signed_manifest.clone();
        tampered_manifest.version = "0.2.13".to_string();
        let signed_manifest_bytes = serde_json::to_vec(&signed_manifest).unwrap();
        let signature = signing_key.sign(&signed_manifest_bytes);
        let tampered_manifest_bytes = serde_json::to_vec(&tampered_manifest).unwrap();
        let file = File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(&tampered_manifest_bytes).unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive
            .write_all(hex::encode(signature.to_bytes()).as_bytes())
            .unwrap();
        archive
            .start_file("payload/app/Avorax.exe", options)
            .unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let error = verifier_for_key(&signing_key, "0.2.11")
            .verify_package(&UpdatePackage::new(&package_path))
            .unwrap_err()
            .to_string();

        assert!(error.contains("manifest signature verification failed"));
    }

    #[test]
    fn signed_update_package_rejects_tampered_payload_hash() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("tampered-payload.aup");
        let signing_key = test_signing_key();
        let payload = b"benign signed update payload";
        let tampered_payload = b"changed benign update payload";
        let manifest = signed_manifest_for_payload(payload);

        write_signed_test_package(&package_path, &manifest, tampered_payload, &signing_key);

        let error = verifier_for_key(&signing_key, "0.2.11")
            .verify_package(&UpdatePackage::new(&package_path))
            .unwrap_err()
            .to_string();

        assert!(error.contains("payload hash mismatch"));
    }
}
