use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PRODUCT_NAME: &str = "Avorax Anti-Virus";
pub const PACKAGE_FORMAT_VERSION: u32 = 1;
const MAX_VERSION_LEN: usize = 64;
const MAX_ID_LEN: usize = 128;
const MAX_RELEASE_DATE_LEN: usize = 64;
const MAX_RELEASE_NOTES_URL_LEN: usize = 2048;
const MAX_MIGRATION_STEPS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UpdateChannel {
    Stable,
    Beta,
    Dev,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
        validate_version(&self.version, "manifest version")?;
        validate_version(&self.previous_min_version, "manifest previous_min_version")?;
        validate_safe_token(&self.package_id, MAX_ID_LEN, "manifest package_id")?;
        validate_safe_token(&self.public_key_id, MAX_ID_LEN, "manifest public_key_id")?;
        validate_release_date(&self.release_date)?;
        validate_release_notes_url(self.release_notes_url.as_deref())?;
        validate_migration_steps(&self.migration_steps)?;
        anyhow::ensure!(
            self.migration_steps.is_empty(),
            "normal update packages must not declare migration steps"
        );
        anyhow::ensure!(
            self.signature_algorithm == "ed25519",
            "unsupported signature algorithm: {}",
            self.signature_algorithm
        );
        validate_optional_sha256(&self.package_sha256, "manifest package_sha256")?;
        anyhow::ensure!(
            !self.driver_update_included,
            "driver updates require a separate explicit driver workflow"
        );
        anyhow::ensure!(
            !self.components.update_service,
            "Update Service self-updates require a separate helper workflow"
        );
        anyhow::ensure!(
            !self.components.driver_tools,
            "driver tools require a separate explicit driver workflow"
        );
        anyhow::ensure!(
            self.requires_admin,
            "normal update packages must declare requires_admin"
        );
        anyhow::ensure!(
            self.requires_restart,
            "normal update packages must declare requires_restart"
        );
        anyhow::ensure!(
            !self.requires_reboot,
            "reboot-required updates require a separate explicit workflow"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest_value() -> serde_json::Value {
        serde_json::json!({
            "product": PRODUCT_NAME,
            "package_format_version": PACKAGE_FORMAT_VERSION,
            "version": "1.2.3",
            "previous_min_version": "1.2.0",
            "channel": "dev",
            "release_date": "2026-06-25T00:00:00Z",
            "package_id": "avorax-1.2.3-dev",
            "components": {
                "app": true,
                "core_service": true,
                "guard_service": true,
                "update_service": false,
                "native_engine_assets": true,
                "signatures": true,
                "rules": true,
                "ml_model": true,
                "trust_packs": true,
                "docs": true,
                "driver_tools": false
            },
            "requires_restart": true,
            "requires_reboot": false,
            "requires_admin": true,
            "driver_update_included": false,
            "migration_steps": [],
            "rollback_supported": true,
            "payload_hashes": {
                "app/Avorax.exe": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "package_sha256": "",
            "signature_algorithm": "ed25519",
            "public_key_id": "avorax-dev-ed25519",
            "release_notes_url": null
        })
    }

    #[test]
    fn update_manifest_rejects_unknown_top_level_fields() {
        let mut value = valid_manifest_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("install_script".to_string(), serde_json::json!("run.ps1"));

        let error = serde_json::from_value::<UpdateManifest>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("install_script"));
    }

    #[test]
    fn update_manifest_rejects_unknown_component_fields() {
        let mut value = valid_manifest_value();
        value
            .get_mut("components")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("kernel_driver".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<UpdateManifest>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("kernel_driver"));
    }

    #[test]
    fn update_manifest_schema_stays_strict() {
        let source = include_str!("update_manifest.rs");
        let component_start = source.find("pub struct UpdateComponentSet").unwrap();
        let manifest_start = source.find("pub struct UpdateManifest").unwrap();
        let component_prefix = &source[..component_start];
        let manifest_prefix = &source[component_start..manifest_start];

        assert!(component_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(manifest_prefix.contains("#[serde(deny_unknown_fields)]"));
        assert!(source.contains("serde_json::from_value::<UpdateManifest>"));
        assert!(source.contains("update_manifest_rejects_unknown_top_level_fields"));
        assert!(source.contains("update_manifest_rejects_unknown_component_fields"));
    }

    #[test]
    fn manifest_scalar_fields_reject_surrounding_whitespace() {
        let mut value = valid_manifest_value();
        value["package_id"] = serde_json::json!(" avorax-1.2.3-dev");
        let manifest = serde_json::from_value::<UpdateManifest>(value).unwrap();
        let error = manifest.validate_static_fields().unwrap_err().to_string();

        assert!(error.contains("manifest package_id must not contain surrounding whitespace"));
    }

    #[test]
    fn manifest_scalar_fields_reject_raw_control_characters_before_trim() {
        let mut value = valid_manifest_value();
        value["release_notes_url"] = serde_json::json!("\nhttps://updates.example.test/release");
        let manifest = serde_json::from_value::<UpdateManifest>(value).unwrap();
        let error = manifest.validate_static_fields().unwrap_err().to_string();

        assert!(error.contains("manifest release_notes_url must not contain control characters"));
    }

    #[test]
    fn manifest_package_sha256_rejects_whitespace_wrapped_hash() {
        let mut value = valid_manifest_value();
        value["package_sha256"] = serde_json::json!(format!(" {} ", "0".repeat(64)));
        let manifest = serde_json::from_value::<UpdateManifest>(value).unwrap();
        let error = manifest.validate_static_fields().unwrap_err().to_string();

        assert!(error.contains("manifest package_sha256 must not contain surrounding whitespace"));
    }

    #[test]
    fn manifest_safe_tokens_reject_current_directory_alias() {
        let mut value = valid_manifest_value();
        value["package_id"] = serde_json::json!(".");
        let manifest = serde_json::from_value::<UpdateManifest>(value).unwrap();
        let error = manifest.validate_static_fields().unwrap_err().to_string();

        assert!(error.contains("manifest package_id must not be current directory"));
    }

    #[test]
    fn update_manifest_scalar_validation_checks_raw_text_before_trim() {
        let source = include_str!("update_manifest.rs");
        let production_helpers = &source[source
            .rfind("fn validate_manifest_scalar_text")
            .expect("scalar helper must exist")..];
        let helper_source = &production_helpers[production_helpers
            .find("fn validate_manifest_scalar_text")
            .unwrap()
            ..production_helpers.find("pub fn is_sha256").unwrap()];
        let safe_token_source =
            &production_helpers[production_helpers.find("fn validate_safe_token").unwrap()
                ..production_helpers
                    .find("pub(crate) fn validate_version")
                    .unwrap()];
        let version_source = &production_helpers[production_helpers
            .find("pub(crate) fn validate_version")
            .unwrap()
            ..production_helpers.find("fn validate_release_date").unwrap()];
        let release_date_source =
            &production_helpers[production_helpers.find("fn validate_release_date").unwrap()
                ..production_helpers
                    .find("fn validate_release_notes_url")
                    .unwrap()];
        let release_notes_source = &production_helpers[production_helpers
            .find("fn validate_release_notes_url")
            .unwrap()
            ..production_helpers
                .find("fn validate_optional_sha256")
                .unwrap()];

        assert!(helper_source.contains("value.chars().any(|ch| ch.is_control())"));
        assert!(helper_source.contains("let trimmed = value.trim()"));
        assert!(helper_source.contains("value == trimmed"));
        assert!(safe_token_source.contains("validate_manifest_scalar_text(value, label)?"));
        assert!(safe_token_source.contains("trimmed != \".\""));
        assert!(version_source.contains("validate_manifest_scalar_text(value, label)?"));
        assert!(release_date_source
            .contains("validate_manifest_scalar_text(value, \"manifest release_date\")?"));
        assert!(release_notes_source
            .contains("validate_manifest_scalar_text(value, \"manifest release_notes_url\")?"));
    }
}

fn validate_manifest_scalar_text<'a>(value: &'a str, label: &str) -> anyhow::Result<&'a str> {
    anyhow::ensure!(
        !value.chars().any(|ch| ch.is_control()),
        "{label} must not contain control characters"
    );
    let trimmed = value.trim();
    anyhow::ensure!(!trimmed.is_empty(), "{label} is empty");
    anyhow::ensure!(
        value == trimmed,
        "{label} must not contain surrounding whitespace"
    );
    Ok(trimmed)
}

pub fn is_sha256(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() == 64 && trimmed.chars().all(|value| value.is_ascii_hexdigit())
}

fn validate_safe_token(value: &str, max_len: usize, label: &str) -> anyhow::Result<()> {
    let trimmed = validate_manifest_scalar_text(value, label)?;
    anyhow::ensure!(trimmed.len() <= max_len, "{label} is too long");
    anyhow::ensure!(trimmed != ".", "{label} must not be current directory");
    anyhow::ensure!(
        trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')),
        "{label} contains unsafe characters"
    );
    anyhow::ensure!(
        !trimmed.contains(".."),
        "{label} must not contain parent traversal"
    );
    Ok(())
}

pub(crate) fn validate_version(value: &str, label: &str) -> anyhow::Result<()> {
    let trimmed = validate_manifest_scalar_text(value, label)?;
    anyhow::ensure!(trimmed.len() <= MAX_VERSION_LEN, "{label} is too long");
    anyhow::ensure!(
        trimmed.split('.').all(|part| {
            !part.is_empty() && part.len() <= 10 && part.chars().all(|ch| ch.is_ascii_digit())
        }),
        "{label} must be a dotted numeric version"
    );
    Ok(())
}

fn validate_release_date(value: &str) -> anyhow::Result<()> {
    let trimmed = validate_manifest_scalar_text(value, "manifest release_date")?;
    anyhow::ensure!(
        trimmed.len() <= MAX_RELEASE_DATE_LEN,
        "manifest release_date is too long"
    );
    anyhow::ensure!(
        trimmed
            .chars()
            .all(|ch| { ch.is_ascii_digit() || matches!(ch, 'T' | 'Z' | ':' | '.' | '-' | '+') }),
        "manifest release_date contains unsafe characters"
    );
    Ok(())
}

fn validate_release_notes_url(value: Option<&str>) -> anyhow::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let trimmed = validate_manifest_scalar_text(value, "manifest release_notes_url")?;
    anyhow::ensure!(
        trimmed.len() <= MAX_RELEASE_NOTES_URL_LEN,
        "manifest release_notes_url is too long"
    );
    anyhow::ensure!(
        trimmed.starts_with("https://"),
        "manifest release_notes_url must use HTTPS"
    );
    Ok(())
}

fn validate_optional_sha256(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    let trimmed = validate_manifest_scalar_text(value, label)?;
    anyhow::ensure!(is_sha256(trimmed), "{label} is not a valid SHA-256 value");
    Ok(())
}

fn validate_migration_steps(values: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        values.len() <= MAX_MIGRATION_STEPS,
        "manifest declares too many migration steps"
    );
    for value in values {
        validate_safe_token(value, MAX_ID_LEN, "manifest migration step")?;
    }
    Ok(())
}
