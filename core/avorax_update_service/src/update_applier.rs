use anyhow::{Context, Result};
use serde_json::json;
use std::path::{Path, PathBuf};

use crate::file_replacer::copy_tree_overwrite;
use crate::logging::{program_data_dir, write_update_log};
use crate::rollback::{create_snapshot, restore_snapshot};
use crate::service_control::{start_service, stop_service};
use crate::update_package::UpdatePackage;
use crate::update_verifier::{UpdateVerifier, VerificationPolicy};

pub fn staging_root() -> PathBuf {
    program_data_dir().join("updates").join("staging")
}

pub fn apply_package(
    package_path: &Path,
    install_dir: &Path,
    current_version: &str,
    policy: VerificationPolicy,
) -> Result<()> {
    let package = UpdatePackage::new(package_path);
    let verifier = UpdateVerifier::new(policy);
    let verified = verifier.verify_package(&package)?;
    let staging = staging_root().join(&verified.manifest.package_id);
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    package.extract_payload_to(&staging)?;
    let rollback = create_snapshot(install_dir, current_version)
        .context("failed to create update rollback snapshot")?;

    stop_services()?;
    if let Err(error) = apply_payload_sections(&staging, install_dir) {
        let rollback_result = restore_snapshot(&rollback, install_dir);
        let _ = start_services();
        let rollback_error = rollback_result.as_ref().err().map(|err| format!("{err:#}"));
        let report = json!({
            "ok": false,
            "version": verified.manifest.version,
            "package_id": verified.manifest.package_id,
            "package_sha256": verified.package_sha256,
            "rollback": rollback,
            "install_dir": install_dir,
            "apply_error": format!("{error:#}"),
            "rollback_ok": rollback_result.is_ok(),
            "rollback_error": rollback_error,
        });
        let _ = write_update_log(
            "update_report.json",
            &serde_json::to_string_pretty(&report)?,
        );
        rollback_result
            .context("failed to restore rollback snapshot after update apply failure")?;
        return Err(error).context("update apply failed; rollback snapshot was restored");
    }
    start_services()?;

    let report = json!({
        "ok": true,
        "version": verified.manifest.version,
        "package_id": verified.manifest.package_id,
        "package_sha256": verified.package_sha256,
        "rollback": rollback,
        "install_dir": install_dir,
    });
    write_update_log(
        "update_report.json",
        &serde_json::to_string_pretty(&report)?,
    )?;
    Ok(())
}

fn apply_payload_sections(staging: &Path, install_dir: &Path) -> Result<()> {
    copy_payload_section(&staging.join("app"), install_dir)?;
    copy_payload_section(&staging.join("services"), install_dir)?;
    copy_payload_section(&staging.join("engine"), &install_dir.join("engine"))?;
    copy_payload_section(&staging.join("docs"), &install_dir.join("docs"))?;
    copy_payload_section(&staging.join("tools"), &install_dir.join("tools"))?;
    copy_payload_section(&staging.join("migrations"), &install_dir.join("migrations"))?;
    Ok(())
}

fn copy_payload_section(source: &Path, destination: &Path) -> Result<()> {
    if source.exists() {
        copy_tree_overwrite(source, destination)?;
    }
    Ok(())
}

fn stop_services() -> Result<()> {
    stop_service("avorax_guard_service")?;
    stop_service("avorax_core_service")?;
    Ok(())
}

fn start_services() -> Result<()> {
    start_service("avorax_core_service")?;
    start_service("avorax_guard_service")?;
    Ok(())
}
