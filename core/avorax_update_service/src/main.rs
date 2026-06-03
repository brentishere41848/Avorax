use anyhow::{Context, Result};
use serde_json::json;
use std::path::PathBuf;

mod file_replacer;
mod ipc;
mod logging;
mod rollback;
mod service;
mod service_control;
mod update_applier;
mod update_downloader;
mod update_manifest;
mod update_package;
mod update_verifier;

use update_applier::apply_package;
use update_package::UpdatePackage;
use update_verifier::{UpdateVerifier, VerificationPolicy};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().cloned().unwrap_or_else(|| "help".to_string());
    let result = run_cli(args);
    match result {
        Ok(()) => {
            let _ = write_cli_status(&command, true, None);
            std::process::exit(0);
        }
        Err(error) => {
            let message = format!("{error:#}");
            eprintln!("{message}");
            let _ = write_cli_status(&command, false, Some(&message));
            std::process::exit(1);
        }
    }
}

fn run_cli(args: Vec<String>) -> Result<()> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some("--service") => service::run_service(),
        Some("--verify") => {
            let package = args.next().context("--verify requires a .aup path")?;
            let current = args.next().unwrap_or_else(|| "0.0.0".to_string());
            let verifier = UpdateVerifier::new(VerificationPolicy::development(current));
            let verified = verifier.verify_package(&UpdatePackage::new(package))?;
            println!("{}", serde_json::to_string(&verified.manifest)?);
            Ok(())
        }
        Some("--apply") => {
            let package = PathBuf::from(args.next().context("--apply requires a .aup path")?);
            let install_dir = PathBuf::from(args.next().unwrap_or_else(default_install_dir));
            let current = args.next().unwrap_or_else(|| "0.0.0".to_string());
            apply_package(&package, &install_dir, &current)
        }
        Some("--rollback") => {
            let install_dir = PathBuf::from(args.next().unwrap_or_else(default_install_dir));
            rollback::restore_latest_snapshot(&install_dir).map(|_| ())
        }
        _ => {
            eprintln!(
                "avorax_update_service --service | --verify <package.aup> [current] | --apply <package.aup> [install_dir] [current] | --rollback [install_dir]"
            );
            Ok(())
        }
    }
}

fn write_cli_status(command: &str, ok: bool, error: Option<&str>) -> Result<()> {
    let report = json!({
        "ok": ok,
        "command": command,
        "error": error,
        "timestamp_utc": time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,
    });
    logging::write_update_log(
        "update_cli_status.json",
        &serde_json::to_string_pretty(&report)?,
    )?;
    Ok(())
}

fn default_install_dir() -> String {
    #[cfg(windows)]
    {
        r"C:\Program Files\Avorax".to_string()
    }
    #[cfg(not(windows))]
    {
        ".".to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::update_manifest::{
        UpdateChannel, UpdateComponentSet, UpdateManifest, PACKAGE_FORMAT_VERSION, PRODUCT_NAME,
    };
    use crate::update_package::safe_relative_path;
    use crate::update_package::UpdatePackage;
    use crate::update_verifier::compare_versions;
    use std::collections::BTreeMap;
    use std::io::Write;

    fn manifest(product: &str) -> UpdateManifest {
        UpdateManifest {
            product: product.to_string(),
            package_format_version: PACKAGE_FORMAT_VERSION,
            version: "0.2.12".to_string(),
            previous_min_version: "0.2.10".to_string(),
            channel: UpdateChannel::Dev,
            release_date: "2026-05-31T00:00:00Z".to_string(),
            package_id: "dev-package".to_string(),
            components: UpdateComponentSet {
                app: true,
                core_service: true,
                guard_service: true,
                update_service: false,
                native_engine_assets: true,
                signatures: true,
                rules: true,
                ml_model: true,
                trust_packs: true,
                docs: true,
                driver_tools: false,
            },
            requires_restart: true,
            requires_reboot: false,
            requires_admin: true,
            driver_update_included: false,
            migration_steps: vec![],
            rollback_supported: true,
            payload_hashes: BTreeMap::new(),
            package_sha256: String::new(),
            signature_algorithm: "ed25519".to_string(),
            public_key_id: "avorax-dev-ed25519".to_string(),
            release_notes_url: None,
        }
    }

    #[test]
    fn manifest_rejects_wrong_product() {
        assert!(manifest("Wrong").validate_static_fields().is_err());
        assert!(manifest(PRODUCT_NAME).validate_static_fields().is_ok());
    }

    #[test]
    fn manifest_rejects_driver_update() {
        let mut value = manifest(PRODUCT_NAME);
        value.driver_update_included = true;
        assert!(value.validate_static_fields().is_err());
    }

    #[test]
    fn rejects_payload_path_traversal() {
        assert!(safe_relative_path("../Avorax.exe").is_err());
        assert!(safe_relative_path("app/Avorax.exe").is_ok());
    }

    #[test]
    fn version_compare_requires_newer() {
        assert!(compare_versions("0.2.12", "0.2.11") > 0);
        assert_eq!(compare_versions("0.2.11", "0.2.11"), 0);
        assert!(compare_versions("0.2.10", "0.2.11") < 0);
    }

    #[test]
    fn package_payload_hashes_are_enforced() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("update.aup");
        let file = std::fs::File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive
            .start_file("payload/app/Avorax.exe", options)
            .unwrap();
        archive.write_all(b"safe payload").unwrap();
        archive.finish().unwrap();

        let mut hashes = BTreeMap::new();
        hashes.insert(
            "app/Avorax.exe".to_string(),
            "3537b758adaaf3d10abb5297b0c1cfb5186357feb0146363d06cd36ea3de76c2".to_string(),
        );
        assert!(UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .is_ok());

        hashes.insert("app/extra.exe".to_string(), "00".repeat(32));
        assert!(UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .is_err());
    }
}
