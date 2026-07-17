use anyhow::{Context, Result};
use serde_json::json;
use std::path::{Path, PathBuf};

mod file_replacer;
mod logging;
mod path_safety;
mod rollback;
mod service;
mod service_control;
mod update_applier;
mod update_manifest;
mod update_package;
mod update_verifier;

use update_applier::apply_package;
use update_package::UpdatePackage;
use update_verifier::{UpdateVerifier, VerificationPolicy};

const MAX_CLI_STATUS_COMMAND_CHARS: usize = 64;
const MAX_CLI_STATUS_ERROR_CHARS: usize = 4096;
const CLI_STATUS_TRUNCATED_SUFFIX: &str = "...[truncated]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = cli_status_command_label(&args);
    let result = run_cli(args);
    match result {
        Ok(()) => match write_cli_status(&command, true, None) {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                let bounded_error =
                    bounded_cli_status_text(&format!("{error:#}"), MAX_CLI_STATUS_ERROR_CHARS);
                eprintln!("failed to write update CLI status: {bounded_error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            let message = format!("{error:#}");
            let bounded_message = bounded_cli_status_text(&message, MAX_CLI_STATUS_ERROR_CHARS);
            eprintln!("{bounded_message}");
            if let Err(status_error) = write_cli_status(&command, false, Some(&message)) {
                let bounded_status_error = bounded_cli_status_text(
                    &format!("{status_error:#}"),
                    MAX_CLI_STATUS_ERROR_CHARS,
                );
                eprintln!("failed to write update CLI status: {bounded_status_error}");
            }
            std::process::exit(1);
        }
    }
}

fn run_cli(args: Vec<String>) -> Result<()> {
    let mut args = args.into_iter().peekable();
    match args.next() {
        Some(command) if command == "--service" => service::run_service(),
        Some(command) if command == "--verify" => {
            let package = args.next().context("--verify requires a .aup path")?;
            let current = cli_current_version_or_default(cli_next_optional_positional(
                &mut args,
                "update current version",
            )?)?;
            let allow_development_updates = cli_allow_development_updates_or_reject(args)?;
            let verifier = UpdateVerifier::new(VerificationPolicy::for_cli(
                current,
                allow_development_updates,
            )?);
            let verified = verifier.verify_package(&UpdatePackage::new(package))?;
            println!("{}", serde_json::to_string(&verified.manifest)?);
            Ok(())
        }
        Some(command) if command == "--apply" => {
            let package = PathBuf::from(args.next().context("--apply requires a .aup path")?);
            let install_dir = cli_install_dir_or_default(cli_next_optional_positional(
                &mut args,
                "update install directory",
            )?)?;
            let current = cli_current_version_or_default(cli_next_optional_positional(
                &mut args,
                "update current version",
            )?)?;
            let allow_development_updates = cli_allow_development_updates_or_reject(args)?;
            let policy = VerificationPolicy::for_cli(current.as_str(), allow_development_updates)?;
            apply_package(&package, &install_dir, &current, policy)
        }
        Some(command) if command == "--rollback" => {
            let install_dir = cli_install_dir_or_default(cli_next_optional_positional(
                &mut args,
                "update install directory",
            )?)?;
            cli_reject_unexpected_args(args, "--rollback")?;
            rollback::restore_latest_snapshot(&install_dir).map(|_| ())
        }
        Some(command) if command == "--help" || command == "-h" => {
            print_cli_usage();
            Ok(())
        }
        Some(command) => anyhow::bail!(
            "unsupported update CLI command: {}",
            bounded_cli_status_text(&command, MAX_CLI_STATUS_COMMAND_CHARS)
        ),
        None => {
            print_cli_usage();
            Ok(())
        }
    }
}

fn print_cli_usage() {
    eprintln!(
        "avorax_update_service --service | --verify <package.aup> [current] [--allow-development-key] | --apply <package.aup> [install_dir] [current] [--allow-development-key] | --rollback [install_dir]"
    );
}

fn cli_status_command_label(args: &[String]) -> String {
    match args.first() {
        Some(command) => bounded_cli_status_text(command, MAX_CLI_STATUS_COMMAND_CHARS),
        None => "help".to_string(),
    }
}

fn cli_current_version_or_default(value: Option<String>) -> Result<String> {
    match value {
        Some(current_version) => {
            cli_positional_value_or_reject(current_version, "update current version")
        }
        None => Ok(default_cli_current_version()),
    }
}

fn default_cli_current_version() -> String {
    "0.0.0".to_string()
}

fn cli_next_optional_positional(
    args: &mut std::iter::Peekable<std::vec::IntoIter<String>>,
    label: &str,
) -> Result<Option<String>> {
    let Some(next) = args.peek() else {
        return Ok(None);
    };
    if next.trim().starts_with('-') {
        return Ok(None);
    }
    let value = args
        .next()
        .context("peeked optional CLI positional value disappeared")?;
    cli_positional_value_or_reject(value, label).map(Some)
}

fn cli_allow_development_updates_or_reject(args: impl IntoIterator<Item = String>) -> Result<bool> {
    let mut allow_development_updates = false;
    for arg in args {
        match arg.as_str() {
            "--allow-development-key" => allow_development_updates = true,
            _ => {
                anyhow::bail!(
                    "unsupported update CLI argument: {}",
                    bounded_cli_status_text(&arg, MAX_CLI_STATUS_COMMAND_CHARS)
                );
            }
        }
    }
    Ok(allow_development_updates)
}

fn cli_reject_unexpected_args(args: impl IntoIterator<Item = String>, command: &str) -> Result<()> {
    if let Some(arg) = args.into_iter().next() {
        anyhow::bail!(
            "unsupported {command} argument: {}",
            bounded_cli_status_text(&arg, MAX_CLI_STATUS_COMMAND_CHARS)
        );
    }
    Ok(())
}

fn cli_install_dir_or_default(value: Option<String>) -> Result<PathBuf> {
    match value {
        Some(install_dir) => checked_cli_install_dir_from_text(cli_positional_value_or_reject(
            install_dir,
            "update install directory",
        )?),
        None => default_install_dir(),
    }
}

fn checked_cli_install_dir_from_text(install_dir: String) -> Result<PathBuf> {
    validate_cli_install_dir_text(&install_dir)?;
    checked_cli_install_dir(PathBuf::from(install_dir))
}

fn validate_cli_install_dir_text(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.contains('\0'),
        "update install directory contains NUL"
    );
    anyhow::ensure!(
        !cli_install_dir_has_parent_traversal(value),
        "update install directory must not contain parent traversal"
    );
    Ok(())
}

fn cli_install_dir_has_parent_traversal(value: &str) -> bool {
    value.replace('\\', "/").split('/').any(|part| part == "..")
}

fn cli_positional_value_or_reject(value: String, label: &str) -> Result<String> {
    let trimmed = value.trim();
    anyhow::ensure!(!trimmed.is_empty(), "{label} is empty");
    anyhow::ensure!(
        !trimmed.starts_with('-'),
        "{label} must be a value, not an option: {}",
        bounded_cli_status_text(trimmed, MAX_CLI_STATUS_COMMAND_CHARS)
    );
    Ok(trimmed.to_string())
}

fn write_cli_status(command: &str, ok: bool, error: Option<&str>) -> Result<()> {
    let bounded_command = bounded_cli_status_text(command, MAX_CLI_STATUS_COMMAND_CHARS);
    let bounded_error = bounded_cli_status_error(error);
    let report = json!({
        "ok": ok,
        "command": bounded_command,
        "error": bounded_error,
        "timestamp_utc": time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,
    });
    logging::write_update_log(
        "update_cli_status.json",
        &serde_json::to_string_pretty(&report)?,
    )?;
    Ok(())
}

fn bounded_cli_status_error(error: Option<&str>) -> Option<String> {
    error.map(|value| bounded_cli_status_text(value, MAX_CLI_STATUS_ERROR_CHARS))
}

fn bounded_cli_status_text(value: &str, max_chars: usize) -> String {
    let normalized = value
        .chars()
        .map(|ch| {
            if ch == '\0' || ch.is_control() {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>();
    let trimmed = normalized.trim();
    let text = if trimmed.is_empty() {
        "unknown"
    } else {
        trimmed
    };
    truncate_with_marker(text, max_chars)
}

fn truncate_with_marker(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let marker_len = CLI_STATUS_TRUNCATED_SUFFIX.chars().count();
    if max_chars <= marker_len {
        return value.chars().take(max_chars).collect();
    }
    let mut bounded: String = value.chars().take(max_chars - marker_len).collect();
    bounded.push_str(CLI_STATUS_TRUNCATED_SUFFIX);
    bounded
}

fn checked_cli_install_dir(install_dir: PathBuf) -> Result<PathBuf> {
    ensure_absolute_local_path(&install_dir, "update install directory")?;
    Ok(install_dir)
}

fn default_install_dir() -> Result<PathBuf> {
    let current_exe =
        std::env::current_exe().context("failed to resolve update service executable path")?;
    let parent = current_exe
        .parent()
        .context("update service executable has no parent install directory")?;
    ensure_absolute_local_path(parent, "update install directory")?;
    Ok(parent.to_path_buf())
}

fn ensure_absolute_local_path(path: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(
        path.is_absolute(),
        "{label} must be an absolute local path: {}",
        path.display()
    );
    #[cfg(windows)]
    {
        let normalized = path.as_os_str().to_string_lossy().replace('/', "\\");
        anyhow::ensure!(
            !normalized.starts_with(r"\\"),
            "{label} must be a local Windows drive path: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    // Environment variables are process-wide, so every test module shares one lock.
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap()
}

#[cfg(test)]
fn normalized_test_source(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use crate::update_manifest::{
        UpdateChannel, UpdateComponentSet, UpdateManifest, PACKAGE_FORMAT_VERSION, PRODUCT_NAME,
    };
    use crate::update_package::safe_relative_path;
    use crate::update_package::UpdatePackage;
    use crate::update_verifier::{compare_versions, VerificationPolicy, DEV_PUBLIC_KEY_ID};
    use std::collections::BTreeMap;
    use std::fs::File;
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

    fn write_minimal_manifest_signature_entries(archive: &mut zip::ZipWriter<File>) {
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(b"{}").unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive.write_all("00".repeat(64).as_bytes()).unwrap();
    }

    fn write_payload_package(package_path: &std::path::Path, payload_path: &str, payload: &[u8]) {
        let file = std::fs::File::create(package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        write_minimal_manifest_signature_entries(&mut archive);
        archive.start_file(payload_path, options).unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();
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
    fn manifest_rejects_unsupported_update_workflows() {
        let mut value = manifest(PRODUCT_NAME);
        value.components.update_service = true;
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.components.driver_tools = true;
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.requires_reboot = true;
        assert!(value.validate_static_fields().is_err());
    }

    #[test]
    fn manifest_requires_admin_and_restart_flags() {
        let mut value = manifest(PRODUCT_NAME);
        value.requires_admin = false;
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.requires_restart = false;
        assert!(value.validate_static_fields().is_err());
    }

    #[test]
    fn manifest_rejects_malformed_package_hash() {
        let mut value = manifest(PRODUCT_NAME);
        value.package_sha256 = "not-a-sha256".to_string();
        assert!(value.validate_static_fields().is_err());

        value.package_sha256 = "a".repeat(64);
        assert!(value.validate_static_fields().is_ok());
    }

    #[test]
    fn manifest_rejects_unsafe_string_fields() {
        let mut value = manifest(PRODUCT_NAME);
        value.package_id = "../escape".to_string();
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.public_key_id = "bad/key".to_string();
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.version = "".to_string();
        assert!(value.validate_static_fields().is_err());
    }

    #[test]
    fn manifest_rejects_malformed_versions() {
        let mut value = manifest(PRODUCT_NAME);
        value.version = "v0.2.12".to_string();
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.version = "0.2.beta".to_string();
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.previous_min_version = "0..2".to_string();
        assert!(value.validate_static_fields().is_err());
    }

    #[test]
    fn installed_policy_version_rejects_malformed_versions() {
        assert!(crate::update_manifest::validate_version(
            "0.2.31",
            "installed update policy version"
        )
        .is_ok());
        assert!(crate::update_manifest::validate_version(
            "current",
            "installed update policy version"
        )
        .is_err());
        assert!(crate::update_manifest::validate_version(
            "0.2+dev",
            "installed update policy version"
        )
        .is_err());
    }

    #[test]
    fn manifest_rejects_unsafe_release_notes_and_migrations() {
        let mut value = manifest(PRODUCT_NAME);
        value.release_notes_url = Some("file:///tmp/release-notes.txt".to_string());
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.release_notes_url = Some("http://example.invalid/release-notes".to_string());
        assert!(value.validate_static_fields().is_err());

        let mut value = manifest(PRODUCT_NAME);
        value.release_notes_url = Some("https://example.invalid/release-notes".to_string());
        assert!(value.validate_static_fields().is_ok());

        let mut value = manifest(PRODUCT_NAME);
        value.migration_steps.push("../escape".to_string());
        assert!(value.validate_static_fields().is_err());
    }

    #[test]
    fn manifest_rejects_normal_update_migration_steps() {
        let mut value = manifest(PRODUCT_NAME);
        value.migration_steps.push("safe-step".to_string());
        let error = value.validate_static_fields().unwrap_err().to_string();

        assert!(error.contains("normal update packages must not declare migration steps"));
    }

    #[test]
    fn rejects_payload_path_traversal() {
        assert!(safe_relative_path("../Avorax.exe").is_err());
        assert!(safe_relative_path("app/Avorax.exe").is_ok());
    }

    #[test]
    fn version_compare_requires_newer() {
        assert!(compare_versions("0.2.12", "0.2.11").unwrap() > 0);
        assert_eq!(compare_versions("0.2.11", "0.2.11").unwrap(), 0);
        assert!(compare_versions("0.2.10", "0.2.11").unwrap() < 0);
    }

    #[test]
    fn production_policy_rejects_development_update_keys_by_default() {
        let policy = VerificationPolicy::production("0.2.31").unwrap();
        assert_eq!(policy.channel, UpdateChannel::Stable);
        assert!(!policy.allow_dev_key);
        assert!(!policy.public_keys.contains_key(DEV_PUBLIC_KEY_ID));
    }

    #[test]
    fn cli_policy_allows_development_updates_only_when_explicit() {
        let default_policy = VerificationPolicy::production("0.2.31").unwrap();
        assert_eq!(default_policy.channel, UpdateChannel::Stable);
        assert!(!default_policy.allow_dev_key);

        let development_policy = VerificationPolicy::for_cli("0.2.31", true).unwrap();
        assert_eq!(development_policy.channel, UpdateChannel::Dev);
        assert!(development_policy.allow_dev_key);
        assert!(development_policy
            .public_keys
            .contains_key(DEV_PUBLIC_KEY_ID));
    }

    #[test]
    fn update_cli_positional_defaults_are_explicit_branches() {
        let empty_args: Vec<String> = Vec::new();
        let source = include_str!("main.rs");
        let test_start = source
            .find("#[cfg(test)]")
            .expect("test module marker must exist");
        let production = &source[..test_start];
        let old_command_clone = ["Some(command) => command", ".clone()"].concat();

        assert_eq!(crate::cli_status_command_label(&empty_args), "help");
        assert_eq!(
            crate::cli_current_version_or_default(None).unwrap(),
            "0.0.0"
        );
        let default_install_dir = crate::cli_install_dir_or_default(None).unwrap();
        assert!(default_install_dir.is_absolute());
        assert!(production.contains("fn cli_status_command_label(args: &[String]) -> String"));
        assert!(
            production.contains("bounded_cli_status_text(command, MAX_CLI_STATUS_COMMAND_CHARS)")
        );
        assert!(production.contains(
            "fn cli_current_version_or_default(value: Option<String>) -> Result<String>"
        ));
        assert!(production
            .contains("fn cli_install_dir_or_default(value: Option<String>) -> Result<PathBuf>"));
        assert!(production.contains("None => \"help\".to_string()"));
        assert!(production.contains("None => Ok(default_cli_current_version())"));
        assert!(production.contains("None => default_install_dir()"));
        assert!(!production.contains("args.first().cloned().unwrap_or_else"));
        assert!(!production.contains(&old_command_clone));
        assert!(!production.contains("unwrap_or_else(|| \"0.0.0\".to_string())"));
        assert!(!production.contains("unwrap_or_else(default_install_dir)"));
        assert!(!production.contains(r#"r"C:\Program Files\Avorax""#));
        assert!(!production.contains("\".\".to_string()"));
        assert!(production.contains("std::env::current_exe()"));
        assert!(production.contains("ensure_absolute_local_path(parent"));
    }

    #[test]
    fn update_cli_install_dir_rejects_relative_paths() {
        let error = crate::cli_install_dir_or_default(Some("relative-install".to_string()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("update install directory must be an absolute local path"));
    }

    #[test]
    fn update_cli_install_dir_rejects_unsafe_text_before_path_use() {
        let nul_error = crate::cli_install_dir_or_default(Some("C:\\Avorax\0x".to_string()))
            .unwrap_err()
            .to_string();
        assert!(nul_error.contains("update install directory contains NUL"));

        let traversal_error = crate::cli_install_dir_or_default(Some(
            "C:\\Program Files\\Avorax\\..\\Other".to_string(),
        ))
        .unwrap_err()
        .to_string();
        assert!(
            traversal_error.contains("update install directory must not contain parent traversal")
        );
    }

    #[test]
    fn update_cli_install_dir_text_validation_stays_before_pathbuf() {
        let source = include_str!("main.rs");
        let test_start = source
            .find("#[cfg(test)]")
            .expect("test module marker must exist");
        let production = &source[..test_start];
        let install_dir_source = &production[production
            .find("fn cli_install_dir_or_default")
            .expect("install-dir helper must exist")
            ..production
                .find("fn cli_positional_value_or_reject")
                .expect("positional helper must exist")];

        assert!(install_dir_source.contains("checked_cli_install_dir_from_text("));
        assert!(install_dir_source
            .contains("fn validate_cli_install_dir_text(value: &str) -> Result<()>"));
        assert!(install_dir_source.contains("!value.contains('\\0')"));
        assert!(install_dir_source.contains("cli_install_dir_has_parent_traversal(value)"));
        assert!(install_dir_source
            .contains("value.replace('\\\\', \"/\").split('/').any(|part| part == \"..\")"));
        assert!(install_dir_source.contains("PathBuf::from(install_dir)"));
    }

    #[test]
    fn update_cli_preserves_options_for_trailing_parser() {
        let mut args = vec!["--allow-development-key".to_string()]
            .into_iter()
            .peekable();

        let current =
            crate::cli_next_optional_positional(&mut args, "update current version").unwrap();

        assert!(current.is_none());
        assert!(crate::cli_allow_development_updates_or_reject(args).unwrap());
    }

    #[test]
    fn update_cli_required_positional_validator_rejects_options() {
        let current_error = crate::cli_positional_value_or_reject(
            "--allow-development-key".to_string(),
            "update current version",
        )
        .unwrap_err()
        .to_string();
        assert!(current_error.contains("update current version must be a value"));

        let install_error = crate::cli_positional_value_or_reject(
            "--allow-development-key".to_string(),
            "update install directory",
        )
        .unwrap_err()
        .to_string();
        assert!(install_error.contains("update install directory must be a value"));
    }

    #[test]
    fn rollback_cli_rejects_extra_arguments() {
        let error = crate::cli_reject_unexpected_args(
            vec!["--allow-development-key".to_string()],
            "--rollback",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unsupported --rollback argument"));
        assert!(error.contains("--allow-development-key"));
    }

    #[test]
    fn update_cli_optional_positionals_stay_flag_guarded() {
        let source = include_str!("main.rs");
        let test_start = source
            .find("#[cfg(test)]")
            .expect("test module marker must exist");
        let production = &source[..test_start];

        assert!(production.contains("fn cli_next_optional_positional("));
        assert!(production.contains("fn cli_positional_value_or_reject("));
        assert!(production.contains("must be a value, not an option"));
        assert!(production.contains("cli_next_optional_positional("));
        assert!(production.contains("if next.trim().starts_with('-')"));
        assert!(production.contains("cli_reject_unexpected_args(args, \"--rollback\")?"));
    }

    #[test]
    fn update_cli_rejects_unknown_commands() {
        let error = crate::run_cli(vec!["--install-script".to_string()])
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported update CLI command"));
        assert!(error.contains("--install-script"));
        assert!(crate::run_cli(vec!["--help".to_string()]).is_ok());
        assert!(crate::run_cli(Vec::new()).is_ok());
    }

    #[test]
    fn update_cli_unknown_command_stays_fail_visible() {
        let source = include_str!("main.rs");
        let test_start = source
            .find("#[cfg(test)]")
            .expect("test module marker must exist");
        let production = &source[..test_start];
        let old_help_fallback = ["_ => {", "\n            eprintln!("].concat();

        assert!(production.contains("Some(command) => anyhow::bail!"));
        assert!(production.contains("unsupported update CLI command"));
        assert!(production.contains("print_cli_usage()"));
        assert!(!production.contains(&old_help_fallback));
    }

    #[test]
    fn update_cli_rejects_unknown_extra_arguments() {
        assert!(crate::cli_allow_development_updates_or_reject(vec![
            "--allow-development-key".to_string()
        ])
        .unwrap());

        let error = crate::cli_allow_development_updates_or_reject(vec![
            "--allow-development-key".to_string(),
            "--install-script".to_string(),
        ])
        .unwrap_err()
        .to_string();

        assert!(error.contains("unsupported update CLI argument"));
        assert!(error.contains("--install-script"));
    }

    #[test]
    fn update_cli_trailing_arguments_stay_strict() {
        let source = include_str!("main.rs");
        let test_start = source
            .find("#[cfg(test)]")
            .expect("test module marker must exist");
        let production = &source[..test_start];
        let old_silent_arg_scan =
            ["args.any(|arg| arg == ", "\"--allow-development-key\")"].concat();

        assert!(production.contains("fn cli_allow_development_updates_or_reject("));
        assert!(production.contains("unsupported update CLI argument"));
        assert!(
            production
                .matches("cli_allow_development_updates_or_reject(args)?")
                .count()
                >= 2
        );
        assert!(!production.contains(&old_silent_arg_scan));
    }

    #[test]
    fn package_payload_hashes_are_enforced() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("update.aup");
        write_payload_package(&package_path, "payload/app/Avorax.exe", b"safe payload");

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

    #[test]
    fn package_payload_hashes_reject_malformed_sha256() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("update.aup");
        write_payload_package(&package_path, "payload/app/Avorax.exe", b"safe payload");

        let mut hashes = BTreeMap::new();
        hashes.insert("app/Avorax.exe".to_string(), "not-a-sha256".to_string());
        let error = UpdatePackage::new(&package_path)
            .verify_payload_hashes(&hashes)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a valid SHA-256"));
    }

    #[test]
    fn update_package_path_requires_aup_extension() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("update.zip");
        let file = std::fs::File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        write_minimal_manifest_signature_entries(&mut archive);
        archive.finish().unwrap();

        let error = UpdatePackage::new(&package_path)
            .read_manifest()
            .unwrap_err()
            .to_string();

        assert!(error.contains("must use the .aup extension"));
    }

    #[test]
    fn update_package_path_rejects_unsafe_text_before_filesystem_probe() {
        let nul_error = UpdatePackage::new("update\0.aup")
            .read_manifest()
            .unwrap_err()
            .to_string();
        assert!(nul_error.contains("update package path contains NUL"));

        let temp = tempfile::tempdir().unwrap();
        let traversal_path = temp.path().join("packages").join("..").join("update.aup");
        let traversal_error = UpdatePackage::new(&traversal_path)
            .read_manifest()
            .unwrap_err()
            .to_string();
        assert!(traversal_error.contains("update package path must not contain parent traversal"));
    }

    #[cfg(unix)]
    #[test]
    fn update_package_path_rejects_symbolic_link() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("update.aup");
        let linked_package = temp.path().join("linked.aup");
        let file = std::fs::File::create(&package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        write_minimal_manifest_signature_entries(&mut archive);
        archive.finish().unwrap();
        symlink(&package_path, &linked_package).unwrap();

        let error = UpdatePackage::new(&linked_package)
            .read_manifest()
            .unwrap_err()
            .to_string();

        assert!(error.contains("must not be a symbolic link"));
    }

    #[test]
    fn package_extraction_rejects_existing_payload_target() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("update.aup");
        write_payload_package(&package_path, "payload/app/Avorax.exe", b"safe payload");

        let destination = temp.path().join("staging");
        std::fs::create_dir_all(destination.join("app")).unwrap();
        std::fs::write(destination.join("app/Avorax.exe"), b"stale payload").unwrap();

        let error = UpdatePackage::new(&package_path)
            .extract_payload_to(&destination)
            .unwrap_err()
            .to_string();
        assert!(error.contains("payload extraction target already exists"));
    }

    #[test]
    fn package_extraction_ignores_stale_temp_collision() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("update.aup");
        write_payload_package(&package_path, "payload/app/Avorax.exe", b"safe payload");

        let destination = temp.path().join("staging");
        std::fs::create_dir_all(destination.join("app")).unwrap();
        let stale_temp = destination.join("app/.Avorax.exe.stale.0.0.avorax-part");
        std::fs::write(&stale_temp, b"stale temp").unwrap();

        UpdatePackage::new(&package_path)
            .extract_payload_to(&destination)
            .unwrap();

        assert_eq!(
            std::fs::read(destination.join("app/Avorax.exe")).unwrap(),
            b"safe payload"
        );
        assert_eq!(std::fs::read(stale_temp).unwrap(), b"stale temp");
    }

    #[cfg(unix)]
    #[test]
    fn package_extraction_rejects_linked_payload_parent() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("update.aup");
        write_payload_package(&package_path, "payload/app/Avorax.exe", b"safe payload");

        let destination = temp.path().join("staging");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, destination.join("app")).unwrap();

        let error = UpdatePackage::new(&package_path)
            .extract_payload_to(&destination)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not be a symbolic link"));
    }

    #[cfg(unix)]
    #[test]
    fn checked_recursive_remove_rejects_symbolic_link() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        std::fs::create_dir_all(&target).unwrap();
        symlink(&target, &link).unwrap();

        let error = crate::path_safety::remove_dir_all_checked(&link, "test cleanup")
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not be a symbolic link"));
        assert!(target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn checked_create_dir_rejects_symbolic_link_ancestor() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        let linked_parent = temp.path().join("linked-parent");
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, &linked_parent).unwrap();

        let target = linked_parent.join("nested");
        let error = crate::path_safety::create_dir_all_checked(&target, "test create")
            .unwrap_err()
            .to_string();

        assert!(error.contains("must not be a symbolic link"));
        assert!(!outside.join("nested").exists());
    }

    #[test]
    fn cli_status_write_failures_are_not_ignored() {
        let source = include_str!("main.rs");
        let start = source.find("fn main()").unwrap();
        let end = source.find("fn run_cli").unwrap();
        let main_source = &source[start..end];

        assert!(main_source.contains("failed to write update CLI status"));
        assert!(main_source.contains("if let Err(status_error)"));
        assert!(!main_source.contains("let _ = write_cli_status"));
    }

    #[test]
    fn update_cli_console_diagnostics_are_bounded() {
        let source = include_str!("main.rs");
        let start = source.find("fn main()").unwrap();
        let end = source.find("fn run_cli").unwrap();
        let main_source = &source[start..end];

        assert!(main_source.contains("let bounded_error ="));
        assert!(main_source.contains("let bounded_message = bounded_cli_status_text"));
        assert!(main_source.contains("let bounded_status_error = bounded_cli_status_text"));
        assert!(main_source.contains("eprintln!(\"{bounded_message}\")"));
        assert!(main_source.contains("{bounded_error}"));
        assert!(main_source.contains("{bounded_status_error}"));
        assert!(!main_source.contains("eprintln!(\"{message}\")"));
        assert!(!main_source.contains("failed to write update CLI status: {error:#}"));
        assert!(!main_source.contains("failed to write update CLI status: {status_error:#}"));
    }

    #[test]
    fn update_cli_status_fields_are_bounded() {
        let long_command = "a".repeat(crate::MAX_CLI_STATUS_COMMAND_CHARS + 32);
        let bounded_command = crate::cli_status_command_label(&[long_command]);
        assert!(bounded_command.chars().count() <= crate::MAX_CLI_STATUS_COMMAND_CHARS);
        assert!(bounded_command.ends_with(crate::CLI_STATUS_TRUNCATED_SUFFIX));

        let control_command = crate::cli_status_command_label(&["\0--apply\n".to_string()]);
        assert!(!control_command.contains('\0'));
        assert!(!control_command.contains('\n'));
        assert_eq!(
            crate::cli_status_command_label(&["\r\n\t".to_string()]),
            "unknown"
        );

        let long_error = "e".repeat(crate::MAX_CLI_STATUS_ERROR_CHARS + 32);
        let bounded_error = crate::bounded_cli_status_error(Some(&long_error)).unwrap();
        assert!(bounded_error.chars().count() <= crate::MAX_CLI_STATUS_ERROR_CHARS);
        assert!(bounded_error.ends_with(crate::CLI_STATUS_TRUNCATED_SUFFIX));
    }

    #[test]
    fn update_cli_status_report_uses_bounded_fields() {
        let source = include_str!("main.rs");
        let start = source.find("fn write_cli_status").unwrap();
        let end = source[start..]
            .find("fn checked_cli_install_dir")
            .map(|offset| start + offset)
            .unwrap_or_else(|| source.find("#[cfg(test)]").unwrap());
        let status_source = &source[start..end];

        assert!(source.contains("const MAX_CLI_STATUS_COMMAND_CHARS: usize = 64"));
        assert!(source.contains("const MAX_CLI_STATUS_ERROR_CHARS: usize = 4096"));
        assert!(status_source.contains("let bounded_command = bounded_cli_status_text"));
        assert!(status_source.contains("let bounded_error = bounded_cli_status_error(error)"));
        assert!(status_source.contains("\"command\": bounded_command"));
        assert!(status_source.contains("\"error\": bounded_error"));
        assert!(!status_source.contains("\"command\": command"));
        assert!(!status_source.contains("\"error\": error"));
    }
}
