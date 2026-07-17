use anyhow::{Context, Result};
use serde_json::json;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use crate::file_replacer::{copy_tree_overwrite, replace_tree_atomically};
use crate::logging::{program_data_dir, write_update_log};
use crate::path_safety::{
    copy_file_staged, create_dir_all_checked, ensure_not_link_or_reparse, remove_dir_all_checked,
};
use crate::rollback::{create_snapshot, restore_snapshot};
use crate::service_control::{start_service, stop_service};
use crate::update_package::UpdatePackage;
use crate::update_verifier::{UpdateVerifier, VerificationPolicy};

const MAX_UPDATE_STAGING_ID_BYTES: usize = 128;
const NORMAL_SERVICE_PAYLOAD_FILES: &[&str] =
    &["avorax_core_service.exe", "avorax_guard_service.exe"];
const NORMAL_ENGINE_PAYLOAD_COMPONENTS: &[&str] = &["signatures", "rules", "ml", "trust"];

#[derive(Debug)]
struct ServicePayloadFile {
    source: PathBuf,
    name: &'static str,
}

#[derive(Debug)]
struct EnginePayloadComponent {
    source: PathBuf,
    name: &'static str,
}

#[derive(Debug)]
struct DocsPayloadFile {
    source: PathBuf,
    relative: PathBuf,
}

pub fn staging_root() -> Result<PathBuf> {
    Ok(program_data_dir()?.join("updates").join("staging"))
}

pub fn apply_package(
    package_path: &Path,
    install_dir: &Path,
    current_version: &str,
    policy: VerificationPolicy,
) -> Result<()> {
    let mut service_control = WindowsUpdateServiceControl;
    apply_package_with_service_control(
        package_path,
        install_dir,
        current_version,
        policy,
        &mut service_control,
    )
}

fn apply_package_with_service_control(
    package_path: &Path,
    install_dir: &Path,
    current_version: &str,
    policy: VerificationPolicy,
    service_control: &mut impl UpdateServiceControl,
) -> Result<()> {
    let install_dir = canonical_install_dir(install_dir)?;
    let package = UpdatePackage::new(package_path);
    let verifier = UpdateVerifier::new(policy);
    let verified = verifier.verify_package(&package)?;
    let staging = staging_root()?.join(safe_update_id(&verified.manifest.package_id)?);
    if let Err(error) = remove_existing_staging_dir(&staging) {
        let staging_cleanup_error = Some(format!("{error:#}"));
        return report_pre_activation_failure(
            error,
            "staging_prepare_error",
            "update apply aborted before activation because staging cleanup failed",
            &verified.manifest.version,
            &verified.manifest.package_id,
            &verified.package_sha256,
            &install_dir,
            false,
            staging_cleanup_error,
        );
    }
    if let Err(error) = package.extract_payload_to_verified_hash(&staging, &verified.package_sha256)
    {
        let staging_cleanup_result = remove_existing_staging_dir(&staging);
        let staging_cleanup_error = staging_cleanup_result
            .as_ref()
            .err()
            .map(|err| format!("{err:#}"));
        return report_pre_activation_failure(
            error,
            "extract_error",
            "update apply aborted before activation because payload extraction failed",
            &verified.manifest.version,
            &verified.manifest.package_id,
            &verified.package_sha256,
            &install_dir,
            staging_cleanup_result.is_ok(),
            staging_cleanup_error,
        );
    }
    let rollback = match create_snapshot(&install_dir, current_version)
        .context("failed to create update rollback snapshot")
    {
        Ok(rollback) => rollback,
        Err(error) => {
            let staging_cleanup_result = remove_existing_staging_dir(&staging);
            let staging_cleanup_error = staging_cleanup_result
                .as_ref()
                .err()
                .map(|err| format!("{err:#}"));
            return report_pre_activation_failure(
                error,
                "snapshot_error",
                "update apply aborted before activation because rollback snapshot creation failed",
                &verified.manifest.version,
                &verified.manifest.package_id,
                &verified.package_sha256,
                &install_dir,
                staging_cleanup_result.is_ok(),
                staging_cleanup_error,
            );
        }
    };

    if let Err(error) = service_control.stop_services() {
        let restart_after_stop_failure_result = service_control.start_services();
        let restart_after_stop_failure_error = restart_after_stop_failure_result
            .as_ref()
            .err()
            .map(|err| format!("{err:#}"));
        let staging_cleanup_result = remove_existing_staging_dir(&staging);
        let staging_cleanup_error = staging_cleanup_result
            .as_ref()
            .err()
            .map(|err| format!("{err:#}"));
        let mut context = "update apply aborted because services did not stop".to_string();
        if let Some(restart_error) = restart_after_stop_failure_error.as_deref() {
            context.push_str("; additionally failed to restart services after stop failure: ");
            context.push_str(restart_error);
        }
        let report = json!({
            "ok": false,
            "applied": false,
            "version": verified.manifest.version,
            "package_id": verified.manifest.package_id,
            "package_sha256": verified.package_sha256,
            "rollback": rollback,
            "install_dir": install_dir,
            "stop_error": format!("{error:#}"),
            "restart_after_stop_failure_ok": restart_after_stop_failure_result.is_ok(),
            "restart_after_stop_failure_error": restart_after_stop_failure_error,
            "staging_cleanup_ok": staging_cleanup_result.is_ok(),
            "staging_cleanup_error": staging_cleanup_error.clone(),
        });
        let report_error = write_update_report(&report)
            .err()
            .map(|error| format!("{error:#}"));
        return Err(error).context(context_with_report_and_cleanup_error(
            &context,
            report_error.as_deref(),
            staging_cleanup_error.as_deref(),
        ));
    }
    if let Err(error) = apply_payload_sections(&staging, &install_dir) {
        let rollback_result = restore_snapshot(&rollback, &install_dir);
        let rollback_restart_result = service_control.start_services();
        let rollback_error = rollback_result.as_ref().err().map(|err| format!("{err:#}"));
        let rollback_restart_error = rollback_restart_result
            .as_ref()
            .err()
            .map(|err| format!("{err:#}"));
        let staging_cleanup_result = remove_existing_staging_dir(&staging);
        let staging_cleanup_error = staging_cleanup_result
            .as_ref()
            .err()
            .map(|err| format!("{err:#}"));
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
            "rollback_restart_ok": rollback_restart_result.is_ok(),
            "rollback_restart_error": rollback_restart_error,
            "staging_cleanup_ok": staging_cleanup_result.is_ok(),
            "staging_cleanup_error": staging_cleanup_error.clone(),
        });
        let report_error = write_update_report(&report)
            .err()
            .map(|error| format!("{error:#}"));
        if let Err(rollback_error) = rollback_result {
            return Err(rollback_error).context(context_with_report_and_cleanup_error(
                "failed to restore rollback snapshot after update apply failure",
                report_error.as_deref(),
                staging_cleanup_error.as_deref(),
            ));
        }
        if let Err(rollback_restart_error) = rollback_restart_result {
            return Err(rollback_restart_error).context(context_with_report_and_cleanup_error(
                "failed to restart services after rollback restore",
                report_error.as_deref(),
                staging_cleanup_error.as_deref(),
            ));
        }
        return Err(error).context(context_with_report_and_cleanup_error(
            "update apply failed; rollback snapshot was restored",
            report_error.as_deref(),
            staging_cleanup_error.as_deref(),
        ));
    }
    if let Err(error) = service_control.start_services() {
        let rollback_result = restore_snapshot(&rollback, &install_dir);
        let rollback_restart_result = service_control.start_services();
        let rollback_error = rollback_result.as_ref().err().map(|err| format!("{err:#}"));
        let rollback_restart_error = rollback_restart_result
            .as_ref()
            .err()
            .map(|err| format!("{err:#}"));
        let staging_cleanup_result = remove_existing_staging_dir(&staging);
        let staging_cleanup_error = staging_cleanup_result
            .as_ref()
            .err()
            .map(|err| format!("{err:#}"));
        let report = json!({
            "ok": false,
            "version": verified.manifest.version,
            "package_id": verified.manifest.package_id,
            "package_sha256": verified.package_sha256,
            "rollback": rollback,
            "install_dir": install_dir,
            "apply_error": null,
            "restart_error": format!("{error:#}"),
            "rollback_ok": rollback_result.is_ok(),
            "rollback_error": rollback_error,
            "rollback_restart_ok": rollback_restart_result.is_ok(),
            "rollback_restart_error": rollback_restart_error,
            "staging_cleanup_ok": staging_cleanup_result.is_ok(),
            "staging_cleanup_error": staging_cleanup_error.clone(),
        });
        let report_error = write_update_report(&report)
            .err()
            .map(|error| format!("{error:#}"));
        if let Err(rollback_error) = rollback_result {
            return Err(rollback_error).context(context_with_report_and_cleanup_error(
                "failed to restore rollback snapshot after service restart failure",
                report_error.as_deref(),
                staging_cleanup_error.as_deref(),
            ));
        }
        if let Err(rollback_restart_error) = rollback_restart_result {
            return Err(rollback_restart_error).context(context_with_report_and_cleanup_error(
                "failed to restart services after rollback restore",
                report_error.as_deref(),
                staging_cleanup_error.as_deref(),
            ));
        }
        return Err(error).context(context_with_report_and_cleanup_error(
            "update apply failed because services did not restart; rollback snapshot was restored",
            report_error.as_deref(),
            staging_cleanup_error.as_deref(),
        ));
    }

    let staging_cleanup_result = remove_existing_staging_dir(&staging);
    let staging_cleanup_error = staging_cleanup_result
        .as_ref()
        .err()
        .map(|err| format!("{err:#}"));
    let report = json!({
        "ok": staging_cleanup_result.is_ok(),
        "applied": true,
        "version": verified.manifest.version,
        "package_id": verified.manifest.package_id,
        "package_sha256": verified.package_sha256,
        "rollback": rollback,
        "install_dir": install_dir,
        "staging_cleanup_ok": staging_cleanup_result.is_ok(),
        "staging_cleanup_error": staging_cleanup_error,
    });
    write_update_report(&report)?;
    if let Err(error) = staging_cleanup_result {
        return Err(error).context("update apply completed but failed to clean staging directory");
    }
    Ok(())
}

trait UpdateServiceControl {
    fn stop_services(&mut self) -> Result<()>;
    fn start_services(&mut self) -> Result<()>;
}

struct WindowsUpdateServiceControl;

impl UpdateServiceControl for WindowsUpdateServiceControl {
    fn stop_services(&mut self) -> Result<()> {
        stop_services()
    }

    fn start_services(&mut self) -> Result<()> {
        start_services()
    }
}

fn write_update_report(report: &serde_json::Value) -> Result<()> {
    write_update_log("update_report.json", &serde_json::to_string_pretty(report)?)?;
    Ok(())
}

fn context_with_report_error(message: &str, report_error: Option<&str>) -> String {
    match report_error {
        Some(error) => format!("{message}; failed to write failed update report: {error}"),
        None => message.to_string(),
    }
}

fn context_with_report_and_cleanup_error(
    message: &str,
    report_error: Option<&str>,
    staging_cleanup_error: Option<&str>,
) -> String {
    let mut context = context_with_report_error(message, report_error);
    if let Some(error) = staging_cleanup_error {
        context.push_str("; failed to clean update staging directory: ");
        context.push_str(error);
    }
    context
}

fn report_pre_activation_failure(
    error: anyhow::Error,
    error_field: &str,
    context: &str,
    version: &str,
    package_id: &str,
    package_sha256: &str,
    install_dir: &Path,
    staging_cleanup_ok: bool,
    staging_cleanup_error: Option<String>,
) -> Result<()> {
    let error_text = format!("{error:#}");
    let mut report = json!({
        "ok": false,
        "applied": false,
        "version": version,
        "package_id": package_id,
        "package_sha256": package_sha256,
        "rollback": null,
        "install_dir": install_dir,
        "staging_cleanup_ok": staging_cleanup_ok,
        "staging_cleanup_error": staging_cleanup_error.clone(),
    });
    if let Some(object) = report.as_object_mut() {
        object.insert(error_field.to_string(), json!(error_text));
    }
    let report_error = write_update_report(&report)
        .err()
        .map(|error| format!("{error:#}"));
    Err(error).context(context_with_report_and_cleanup_error(
        context,
        report_error.as_deref(),
        staging_cleanup_error.as_deref(),
    ))
}

fn apply_payload_sections(staging: &Path, install_dir: &Path) -> Result<()> {
    ensure_existing_install_directory(
        install_dir,
        "update install directory before payload apply",
    )?;
    copy_app_payload_section(&staging.join("app"), install_dir)?;
    copy_service_payload_section(&staging.join("services"), install_dir)?;
    copy_engine_payload_section(&staging.join("engine"), &install_dir.join("engine"))?;
    copy_docs_payload_section(&staging.join("docs"), &install_dir.join("docs"))?;
    Ok(())
}

fn copy_app_payload_section(source: &Path, destination: &Path) -> Result<()> {
    if payload_section_dir_present(source)? {
        let regular_files = validate_app_payload_section(source)?;
        anyhow::ensure!(
            regular_files > 0,
            "app update payload contains no regular files: {}",
            source.display()
        );
        copy_payload_section(source, destination)?;
    }
    Ok(())
}

fn validate_app_payload_section(source: &Path) -> Result<usize> {
    ensure_payload_section_dir_ready(source)?;
    let mut regular_files = 0;
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry.with_context(|| {
            format!(
                "failed to enumerate app update payload {}",
                source.display()
            )
        })?;
        let path = entry.path();
        ensure_not_link_or_reparse(path, "app update payload entry")?;
        let relative = path.strip_prefix(source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        ensure_app_payload_relative_allowed(relative, path)?;
        anyhow::ensure!(
            entry.file_type().is_dir() || entry.file_type().is_file(),
            "app update payload entry must be a regular file or directory: {}",
            path.display()
        );
        if entry.file_type().is_file() {
            regular_files += 1;
        }
    }
    Ok(regular_files)
}

fn ensure_app_payload_relative_allowed(relative: &Path, path: &Path) -> Result<()> {
    let install_child = app_payload_first_component(relative, path)?;
    match install_child.as_str() {
        "engine" | "docs" | "tools" | "driver" | "driver-tools" | "migrations" => {
            anyhow::bail!(
                "app update payload must not target restricted install path {install_child}: {}",
                path.display()
            )
        }
        "avorax_update_service.exe" | "avorax_core_service.exe" | "avorax_guard_service.exe" => {
            anyhow::bail!(
                "app update payload must not include managed service or updater executable {install_child}: {}",
                path.display()
            )
        }
        _ => Ok(()),
    }
}

fn app_payload_first_component(relative: &Path, path: &Path) -> Result<String> {
    let Some(component) = relative.components().next() else {
        anyhow::bail!(
            "app update payload entry is missing a relative path: {}",
            path.display()
        );
    };
    let Component::Normal(value) = component else {
        anyhow::bail!(
            "app update payload entry contains an unsafe path component: {}",
            path.display()
        );
    };
    value
        .to_str()
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "app update payload entry has a non-UTF-8 path component: {}",
                path.display()
            )
        })
}

fn copy_payload_section(source: &Path, destination: &Path) -> Result<()> {
    if payload_section_dir_present(source)? {
        copy_tree_overwrite(source, destination)?;
    }
    Ok(())
}

fn copy_service_payload_section(source: &Path, install_dir: &Path) -> Result<()> {
    if !payload_section_dir_present(source)? {
        return Ok(());
    }
    let files = service_payload_files(source)?;
    anyhow::ensure!(
        !files.is_empty(),
        "service update payload contains no supported service files: {}",
        source.display()
    );
    ensure_not_link_or_reparse(install_dir, "service update destination")?;
    create_dir_all_checked(install_dir, "service update destination")?;
    for file in files {
        copy_file_staged(
            &file.source,
            &install_dir.join(file.name),
            install_dir,
            "service update destination",
        )?;
    }
    Ok(())
}

fn service_payload_files(source: &Path) -> Result<Vec<ServicePayloadFile>> {
    ensure_payload_section_dir_ready(source)?;
    let mut files = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(source).with_context(|| {
        format!(
            "failed to enumerate service update payload {}",
            source.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "failed to read service update payload entry {}",
                source.display()
            )
        })?;
        let path = entry.path();
        ensure_not_link_or_reparse(&path, "service update payload entry")?;
        let metadata = std::fs::symlink_metadata(&path).with_context(|| {
            format!(
                "failed to inspect service update payload entry {}",
                path.display()
            )
        })?;
        anyhow::ensure!(
            metadata.is_file(),
            "service update payload entry must be a regular file: {}",
            path.display()
        );
        let raw_name = entry.file_name();
        let Some(raw_name) = raw_name.to_str() else {
            anyhow::bail!(
                "service update payload entry has a non-UTF-8 name: {}",
                path.display()
            );
        };
        let normalized = raw_name.to_ascii_lowercase();
        let Some(canonical) = canonical_service_payload_file(&normalized) else {
            anyhow::bail!(
                "service update payload file {raw_name} is not supported by normal updates"
            );
        };
        anyhow::ensure!(
            seen.insert(canonical),
            "duplicate service update payload file: {canonical}"
        );
        files.push(ServicePayloadFile {
            source: path,
            name: canonical,
        });
    }
    Ok(files)
}

fn canonical_service_payload_file(value: &str) -> Option<&'static str> {
    NORMAL_SERVICE_PAYLOAD_FILES
        .iter()
        .copied()
        .find(|file| *file == value)
}

fn copy_engine_payload_section(source: &Path, destination: &Path) -> Result<()> {
    if !payload_section_dir_present(source)? {
        return Ok(());
    }
    let components = engine_payload_components(source)?;
    anyhow::ensure!(
        !components.is_empty(),
        "engine update payload contains no supported runtime subdirectories: {}",
        source.display()
    );
    for component in components {
        replace_tree_atomically(
            &component.source,
            &destination.join(component.name),
            destination.parent().ok_or_else(|| {
                anyhow::anyhow!("engine update destination has no install parent")
            })?,
        )?;
    }
    Ok(())
}

fn engine_payload_components(source: &Path) -> Result<Vec<EnginePayloadComponent>> {
    ensure_payload_section_dir_ready(source)?;
    let mut components = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(source).with_context(|| {
        format!(
            "failed to enumerate engine update payload {}",
            source.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "failed to read engine update payload entry {}",
                source.display()
            )
        })?;
        let path = entry.path();
        ensure_not_link_or_reparse(&path, "engine update payload subcomponent")?;
        let metadata = std::fs::symlink_metadata(&path).with_context(|| {
            format!(
                "failed to inspect engine update payload subcomponent {}",
                path.display()
            )
        })?;
        anyhow::ensure!(
            metadata.is_dir(),
            "engine update payload subcomponent must be a directory: {}",
            path.display()
        );
        let raw_name = entry.file_name();
        let Some(raw_name) = raw_name.to_str() else {
            anyhow::bail!(
                "engine update payload subcomponent has a non-UTF-8 name: {}",
                path.display()
            );
        };
        let normalized = raw_name.to_ascii_lowercase();
        let Some(canonical) = canonical_engine_payload_component(&normalized) else {
            anyhow::bail!(
                "engine update payload subcomponent {raw_name} is not supported by normal updates"
            );
        };
        anyhow::ensure!(
            seen.insert(canonical),
            "duplicate engine update payload subcomponent: {canonical}"
        );
        components.push(EnginePayloadComponent {
            source: path,
            name: canonical,
        });
    }
    Ok(components)
}

fn canonical_engine_payload_component(value: &str) -> Option<&'static str> {
    NORMAL_ENGINE_PAYLOAD_COMPONENTS
        .iter()
        .copied()
        .find(|component| *component == value)
}

fn copy_docs_payload_section(source: &Path, destination: &Path) -> Result<()> {
    if !payload_section_dir_present(source)? {
        return Ok(());
    }
    let files = docs_payload_files(source)?;
    anyhow::ensure!(
        !files.is_empty(),
        "docs update payload contains no Markdown files: {}",
        source.display()
    );
    ensure_not_link_or_reparse(destination, "docs update destination")?;
    create_dir_all_checked(destination, "docs update destination")?;
    for file in files {
        copy_file_staged(
            &file.source,
            &destination.join(&file.relative),
            destination,
            "docs update destination",
        )?;
    }
    Ok(())
}

fn docs_payload_files(source: &Path) -> Result<Vec<DocsPayloadFile>> {
    ensure_payload_section_dir_ready(source)?;
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry.with_context(|| {
            format!(
                "failed to enumerate docs update payload {}",
                source.display()
            )
        })?;
        let path = entry.path();
        ensure_not_link_or_reparse(path, "docs update payload entry")?;
        let relative = path.strip_prefix(source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_dir() {
            continue;
        }
        anyhow::ensure!(
            entry.file_type().is_file(),
            "docs update payload entry must be a regular file: {}",
            path.display()
        );
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "docs update payload entry has a non-UTF-8 filename: {}",
                    path.display()
                )
            })?;
        anyhow::ensure!(
            file_name != ".md" && file_name.ends_with(".md"),
            "docs update payload file must be Markdown-only for normal updates: {}",
            path.display()
        );
        files.push(DocsPayloadFile {
            source: path.to_path_buf(),
            relative: relative.to_path_buf(),
        });
    }
    Ok(files)
}

fn remove_existing_staging_dir(staging: &Path) -> Result<()> {
    match std::fs::symlink_metadata(staging) {
        Ok(_) => {
            ensure_not_link_or_reparse(staging, "update staging directory")?;
            remove_dir_all_checked(staging, "update staging directory")
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect update staging directory {}",
                staging.display()
            )
        }),
    }
}

fn payload_section_dir_present(source: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(source) {
        Ok(metadata) => {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "update payload section must not be a symbolic link: {}",
                source.display()
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                anyhow::ensure!(
                    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                    "update payload section must not be a reparse point: {}",
                    source.display()
                );
            }
            anyhow::ensure!(
                metadata.is_dir(),
                "update payload section is not a directory: {}",
                source.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect update payload section {}",
                source.display()
            )
        }),
    }
}

fn ensure_payload_section_dir_ready(source: &Path) -> Result<()> {
    match std::fs::symlink_metadata(source) {
        Ok(metadata) => {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "update payload section must not be a symbolic link: {}",
                source.display()
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                anyhow::ensure!(
                    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                    "update payload section must not be a reparse point: {}",
                    source.display()
                );
            }
            anyhow::ensure!(
                metadata.is_dir(),
                "update payload section is not a directory: {}",
                source.display()
            );
            Ok(())
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to revalidate update payload section {} before enumeration",
                source.display()
            )
        }),
    }
}

fn canonical_install_dir(install_dir: &Path) -> Result<PathBuf> {
    validate_install_dir_path_text(install_dir)?;
    create_dir_all_checked(install_dir, "install directory")?;
    let canonical = install_dir.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize install dir {}",
            install_dir.display()
        )
    })?;
    ensure_existing_install_directory(&canonical, "canonical install directory")?;
    anyhow::ensure!(
        canonical.parent().is_some(),
        "refusing to apply update to filesystem root"
    );
    Ok(canonical)
}

fn ensure_existing_install_directory(path: &Path, label: &str) -> Result<()> {
    ensure_not_link_or_reparse(path, label)?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "{label} is not a directory: {}",
        path.display()
    );
    ensure_not_link_or_reparse(path, label)?;
    Ok(())
}

fn validate_install_dir_path_text(path: &Path) -> Result<()> {
    let text = path.as_os_str().to_string_lossy();
    anyhow::ensure!(
        !text.contains('\0'),
        "install directory contains NUL: {}",
        path.display()
    );
    anyhow::ensure!(
        !install_dir_path_has_parent_traversal(path),
        "install directory must not contain parent traversal: {}",
        path.display()
    );
    Ok(())
}

fn install_dir_path_has_parent_traversal(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn safe_update_id(value: &str) -> Result<String> {
    let trimmed = value.trim();
    anyhow::ensure!(!trimmed.is_empty(), "update package id is empty");
    anyhow::ensure!(
        trimmed != ".",
        "update package id must not be current directory"
    );
    anyhow::ensure!(
        trimmed.len() <= MAX_UPDATE_STAGING_ID_BYTES,
        "update package id is too long"
    );
    anyhow::ensure!(
        trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')),
        "update package id contains unsafe characters"
    );
    anyhow::ensure!(
        !trimmed.contains(".."),
        "update package id must not contain parent traversal"
    );
    Ok(trimmed.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollback::rollback_root;
    use crate::update_manifest::{
        UpdateChannel, UpdateComponentSet, UpdateManifest, PACKAGE_FORMAT_VERSION, PRODUCT_NAME,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    const TEST_UPDATE_KEY_ID: &str = "avorax-test-apply-ed25519";

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    struct EnvVarGuard {
        name: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set_path(name: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(name);
            unsafe {
                std::env::set_var(name, value);
            }
            Self { name, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.name, value),
                    None => std::env::remove_var(self.name),
                }
            }
        }
    }

    #[derive(Default)]
    struct FakeUpdateServiceControl {
        calls: Vec<&'static str>,
        stop_errors: VecDeque<&'static str>,
        start_errors: VecDeque<&'static str>,
    }

    impl UpdateServiceControl for FakeUpdateServiceControl {
        fn stop_services(&mut self) -> Result<()> {
            self.calls.push("stop");
            if let Some(error) = self.stop_errors.pop_front() {
                anyhow::bail!("{error}");
            }
            Ok(())
        }

        fn start_services(&mut self) -> Result<()> {
            self.calls.push("start");
            if let Some(error) = self.start_errors.pop_front() {
                anyhow::bail!("{error}");
            }
            Ok(())
        }
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9_u8; 32])
    }

    fn test_policy(signing_key: &SigningKey, current_version: &str) -> VerificationPolicy {
        let mut public_keys = BTreeMap::new();
        public_keys.insert(
            TEST_UPDATE_KEY_ID.to_string(),
            hex::encode(signing_key.verifying_key().to_bytes()),
        );
        VerificationPolicy {
            current_version: current_version.to_string(),
            channel: UpdateChannel::Stable,
            allow_dev_key: false,
            public_keys,
        }
    }

    fn setup_apply_install_tree(install: &Path) {
        std::fs::create_dir_all(install.join("engine/signatures")).unwrap();
        std::fs::write(install.join("Avorax.exe"), b"old app binary").unwrap();
        std::fs::write(install.join("avorax_core_service.exe"), b"old core service").unwrap();
        std::fs::write(
            install.join("avorax_guard_service.exe"),
            b"old guard service",
        )
        .unwrap();
        std::fs::write(install.join("engine/signatures/old.asig"), b"old signature").unwrap();
    }

    fn signed_apply_manifest(
        package_id: &str,
        version: &str,
        payload_hashes: BTreeMap<String, String>,
    ) -> UpdateManifest {
        UpdateManifest {
            product: PRODUCT_NAME.to_string(),
            package_format_version: PACKAGE_FORMAT_VERSION,
            version: version.to_string(),
            previous_min_version: "0.5.0".to_string(),
            channel: UpdateChannel::Stable,
            release_date: "2026-07-06T00:00:00Z".to_string(),
            package_id: package_id.to_string(),
            components: UpdateComponentSet {
                app: true,
                core_service: true,
                guard_service: true,
                update_service: false,
                native_engine_assets: true,
                signatures: true,
                rules: false,
                ml_model: false,
                trust_packs: false,
                docs: true,
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

    fn write_signed_apply_package(
        package_path: &Path,
        manifest: &UpdateManifest,
        payloads: &[(&str, &[u8])],
        signing_key: &SigningKey,
    ) {
        let manifest_bytes = serde_json::to_vec(manifest).unwrap();
        let signature = signing_key.sign(&manifest_bytes);
        let file = File::create(package_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("manifest.json", options).unwrap();
        archive.write_all(&manifest_bytes).unwrap();
        archive.start_file("manifest.sig", options).unwrap();
        archive
            .write_all(hex::encode(signature.to_bytes()).as_bytes())
            .unwrap();
        for (relative, bytes) in payloads {
            archive
                .start_file(format!("payload/{relative}"), options)
                .unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap();
    }

    fn payload_hashes(payloads: &[(&str, &[u8])]) -> BTreeMap<String, String> {
        payloads
            .iter()
            .map(|(relative, bytes)| ((*relative).to_string(), sha256_bytes(bytes)))
            .collect()
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn read_json_file(path: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn update_package_id_rejects_traversal() {
        assert!(safe_update_id("avorax-0.2.16").is_ok());
        assert!(safe_update_id(".").is_err());
        assert!(safe_update_id("../escape").is_err());
        assert!(safe_update_id("avorax/escape").is_err());
        assert!(safe_update_id("avorax..escape").is_err());
        assert!(safe_update_id(&"a".repeat(MAX_UPDATE_STAGING_ID_BYTES + 1)).is_err());
    }

    #[test]
    fn update_package_id_path_shape_stays_bounded() {
        let source = include_str!("update_applier.rs");
        let start = source.find("fn safe_update_id").unwrap();
        let end = start + source[start..].find("fn stop_services").unwrap();
        let safe_id_source = &source[start..end];

        assert!(source.contains("const MAX_UPDATE_STAGING_ID_BYTES: usize = 128"));
        assert!(safe_id_source.contains("trimmed != \".\""));
        assert!(safe_id_source.contains("update package id must not be current directory"));
        assert!(safe_id_source.contains("trimmed.len() <= MAX_UPDATE_STAGING_ID_BYTES"));
        assert!(safe_id_source.contains("update package id is too long"));
        assert!(safe_id_source.contains("update package id contains unsafe characters"));
        assert!(safe_id_source.contains("update package id must not contain parent traversal"));
    }

    #[test]
    fn update_apply_install_dir_rejects_unsafe_text_before_creation() {
        let nul_error = canonical_install_dir(Path::new("install\0dir"))
            .unwrap_err()
            .to_string();
        assert!(nul_error.contains("install directory contains NUL"));

        let dir = tempdir().unwrap();
        let traversal_dir = dir.path().join("install").join("..").join("other");
        let traversal_error = canonical_install_dir(&traversal_dir)
            .unwrap_err()
            .to_string();
        assert!(traversal_error.contains("install directory must not contain parent traversal"));
    }

    #[test]
    fn failed_update_report_write_failures_are_not_ignored() {
        let source = include_str!("update_applier.rs");
        let start = source.find("pub fn apply_package").unwrap();
        let end = source.find("fn apply_payload_sections").unwrap();
        let apply_source = &source[start..end];

        assert!(apply_source.contains("write_update_report(&report)"));
        assert!(apply_source.contains("context_with_report_error"));
        assert!(apply_source.contains("failed to write failed update report"));
        assert!(!apply_source.contains("let _ = write_update_log"));
    }

    #[test]
    fn successful_update_cleans_staging_before_success() {
        let source = include_str!("update_applier.rs");
        let start = source.find("\"applied\": true").unwrap();
        let end = start + source[start..].find("Ok(())").unwrap();
        let success_source = &source[start..end];

        assert!(success_source.contains("staging_cleanup_ok"));
        assert!(success_source.contains("staging_cleanup_error"));
        assert!(success_source.contains("write_update_report(&report)?"));
        assert!(
            success_source.contains("update apply completed but failed to clean staging directory")
        );
    }

    #[test]
    fn failed_update_reports_staging_cleanup_evidence() {
        let source = include_str!("update_applier.rs");
        let start = source
            .find("if let Err(error) = apply_payload_sections")
            .unwrap();
        let end = start + source[start..].find("\"applied\": true").unwrap();
        let failure_source = &source[start..end];

        assert!(
            failure_source
                .matches("remove_existing_staging_dir(&staging)")
                .count()
                >= 2
        );
        assert!(failure_source.matches("\"staging_cleanup_ok\"").count() >= 2);
        assert!(failure_source.matches("\"staging_cleanup_error\"").count() >= 2);
        assert!(
            failure_source
                .matches("context_with_report_and_cleanup_error")
                .count()
                >= 6
        );
        assert!(
            failure_source
                .matches("staging_cleanup_error.as_deref()")
                .count()
                >= 6
        );
        assert!(source.contains("failed to clean update staging directory"));
    }

    #[test]
    fn stop_service_failure_reports_and_cleans_staging() {
        let source = include_str!("update_applier.rs");
        let start = source
            .find("if let Err(error) = service_control.stop_services()")
            .unwrap();
        let end = source
            .find("if let Err(error) = apply_payload_sections")
            .unwrap();
        let stop_failure_source = &source[start..end];

        assert!(stop_failure_source.contains("\"applied\": false"));
        assert!(stop_failure_source.contains("\"stop_error\""));
        assert!(stop_failure_source.contains("restart_after_stop_failure_ok"));
        assert!(stop_failure_source.contains("remove_existing_staging_dir(&staging)"));
        assert!(stop_failure_source.contains("write_update_report(&report)"));
        assert!(stop_failure_source.contains("context_with_report_and_cleanup_error"));
        assert!(stop_failure_source.contains("staging_cleanup_error.as_deref()"));
        assert!(stop_failure_source.contains("update apply aborted because services did not stop"));
    }

    #[test]
    fn apply_package_extracts_only_verified_package_hash() {
        let source = include_str!("update_applier.rs");
        let start = source
            .find("fn apply_package_with_service_control")
            .unwrap();
        let end = source.find("fn apply_payload_sections").unwrap();
        let apply_source = &source[start..end];

        assert!(apply_source.contains("let verified = verifier.verify_package(&package)?"));
        assert!(apply_source.contains(
            "package.extract_payload_to_verified_hash(&staging, &verified.package_sha256)"
        ));
        assert!(!apply_source.contains("package.extract_payload_to(&staging)?"));
        assert!(!apply_source.contains("create_dir_all_checked(&staging"));
        assert!(apply_source.contains("report_pre_activation_failure("));
        assert!(apply_source.contains("\"extract_error\""));
        assert!(apply_source.contains("\"staging_prepare_error\""));
        assert!(
            apply_source
                .find("let verified = verifier.verify_package(&package)?")
                .unwrap()
                < apply_source
                    .find("package.extract_payload_to_verified_hash")
                    .unwrap()
        );
    }

    #[test]
    fn apply_package_reports_pre_activation_staging_prepare_failure_without_stopping_services() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        let _data_guard = EnvVarGuard::set_path("AVORAX_DATA_DIR", &data);
        let install = dir.path().join("install");
        let package_path = dir.path().join("staging-prepare-failure.aup");
        setup_apply_install_tree(&install);
        let signing_key = test_signing_key();
        let package_id = "avorax-test-preactivation-staging-failure";
        let payloads: Vec<(&str, &[u8])> = vec![
            ("app/Avorax.exe", b"new app binary"),
            ("services/avorax_core_service.exe", b"new core service"),
            ("services/avorax_guard_service.exe", b"new guard service"),
            ("engine/signatures/new.asig", b"new signature"),
            ("docs/release.md", b"new release docs"),
        ];
        let manifest = signed_apply_manifest(package_id, "0.6.0", payload_hashes(&payloads));
        write_signed_apply_package(&package_path, &manifest, &payloads, &signing_key);
        let stale_staging_path = data.join("updates/staging").join(package_id);
        std::fs::create_dir_all(stale_staging_path.parent().unwrap()).unwrap();
        std::fs::write(&stale_staging_path, b"stale non-directory staging path").unwrap();
        let mut service_control = FakeUpdateServiceControl::default();

        let error = format!(
            "{:#}",
            apply_package_with_service_control(
                &package_path,
                &install,
                "0.5.0",
                test_policy(&signing_key, "0.5.0"),
                &mut service_control,
            )
            .unwrap_err()
        );

        assert!(
            error.contains("update apply aborted before activation because staging cleanup failed")
        );
        assert!(error.contains("failed to clean update staging directory"));
        assert!(service_control.calls.is_empty());
        assert_eq!(
            std::fs::read(install.join("Avorax.exe")).unwrap(),
            b"old app binary"
        );
        assert!(std::fs::symlink_metadata(&stale_staging_path)
            .unwrap()
            .is_file());
        let report = read_json_file(&data.join("updates/logs/update_report.json"));
        assert_eq!(report["ok"], false);
        assert_eq!(report["applied"], false);
        assert_eq!(report["rollback"], serde_json::Value::Null);
        assert_eq!(report["package_id"], package_id);
        assert_eq!(report["staging_cleanup_ok"], false);
        assert!(report["staging_prepare_error"]
            .as_str()
            .unwrap()
            .contains("update staging directory"));
        assert!(report["staging_cleanup_error"]
            .as_str()
            .unwrap()
            .contains("update staging directory"));
    }

    #[test]
    fn apply_package_reports_pre_activation_snapshot_failure_and_cleans_staging() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        let _data_guard = EnvVarGuard::set_path("AVORAX_DATA_DIR", &data);
        let install = dir.path().join("install");
        let package_path = dir.path().join("snapshot-failure.aup");
        setup_apply_install_tree(&install);
        std::fs::remove_dir_all(install.join("engine")).unwrap();
        let signing_key = test_signing_key();
        let package_id = "avorax-test-preactivation-snapshot-failure";
        let payloads: Vec<(&str, &[u8])> = vec![
            ("app/Avorax.exe", b"new app binary"),
            ("services/avorax_core_service.exe", b"new core service"),
            ("services/avorax_guard_service.exe", b"new guard service"),
            ("engine/signatures/new.asig", b"new signature"),
            ("docs/release.md", b"new release docs"),
        ];
        let manifest = signed_apply_manifest(package_id, "0.6.0", payload_hashes(&payloads));
        write_signed_apply_package(&package_path, &manifest, &payloads, &signing_key);
        let mut service_control = FakeUpdateServiceControl::default();

        let error = format!(
            "{:#}",
            apply_package_with_service_control(
                &package_path,
                &install,
                "0.5.0",
                test_policy(&signing_key, "0.5.0"),
                &mut service_control,
            )
            .unwrap_err()
        );

        assert!(error.contains(
            "update apply aborted before activation because rollback snapshot creation failed"
        ));
        assert!(error.contains("rollback source missing required directory engine"));
        assert!(service_control.calls.is_empty());
        assert_eq!(
            std::fs::read(install.join("Avorax.exe")).unwrap(),
            b"old app binary"
        );
        assert_missing_path(&install.join("engine/signatures/new.asig"));
        assert_missing_path(&staging_root().unwrap().join(package_id));
        assert_missing_path(&rollback_root().unwrap().join("0.5.0"));
        let report = read_json_file(&data.join("updates/logs/update_report.json"));
        assert_eq!(report["ok"], false);
        assert_eq!(report["applied"], false);
        assert_eq!(report["rollback"], serde_json::Value::Null);
        assert_eq!(report["package_id"], package_id);
        assert_eq!(report["staging_cleanup_ok"], true);
        assert!(report["snapshot_error"]
            .as_str()
            .unwrap()
            .contains("failed to create update rollback snapshot"));
        assert!(report["snapshot_error"]
            .as_str()
            .unwrap()
            .contains("rollback source missing required directory engine"));
    }

    #[test]
    fn apply_package_with_service_control_applies_signed_payload_and_reports_success() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        let _data_guard = EnvVarGuard::set_path("AVORAX_DATA_DIR", &data);
        let install = dir.path().join("install");
        let package_path = dir.path().join("apply-success.aup");
        setup_apply_install_tree(&install);
        let signing_key = test_signing_key();
        let payloads: Vec<(&str, &[u8])> = vec![
            ("app/Avorax.exe", b"new app binary"),
            ("services/avorax_core_service.exe", b"new core service"),
            ("services/avorax_guard_service.exe", b"new guard service"),
            ("engine/signatures/new.asig", b"new signature"),
            ("docs/release.md", b"new release docs"),
        ];
        let manifest = signed_apply_manifest(
            "avorax-test-apply-success",
            "0.6.0",
            payload_hashes(&payloads),
        );
        write_signed_apply_package(&package_path, &manifest, &payloads, &signing_key);
        let mut service_control = FakeUpdateServiceControl::default();

        apply_package_with_service_control(
            &package_path,
            &install,
            "0.5.0",
            test_policy(&signing_key, "0.5.0"),
            &mut service_control,
        )
        .unwrap();

        assert_eq!(service_control.calls, vec!["stop", "start"]);
        assert_eq!(
            std::fs::read(install.join("Avorax.exe")).unwrap(),
            b"new app binary"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_core_service.exe")).unwrap(),
            b"new core service"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_guard_service.exe")).unwrap(),
            b"new guard service"
        );
        assert_eq!(
            std::fs::read(install.join("engine/signatures/new.asig")).unwrap(),
            b"new signature"
        );
        assert_eq!(
            std::fs::read(install.join("docs/release.md")).unwrap(),
            b"new release docs"
        );
        assert_missing_path(&staging_root().unwrap().join("avorax-test-apply-success"));
        let report = read_json_file(&data.join("updates/logs/update_report.json"));
        assert_eq!(report["ok"], true);
        assert_eq!(report["applied"], true);
        assert_eq!(report["package_id"], "avorax-test-apply-success");
        assert_eq!(report["staging_cleanup_ok"], true);
        let rollback = PathBuf::from(report["rollback"].as_str().unwrap());
        assert_eq!(
            std::fs::read(rollback.join("Avorax.exe")).unwrap(),
            b"old app binary"
        );
        assert_eq!(
            std::fs::read(rollback.join("engine/signatures/old.asig")).unwrap(),
            b"old signature"
        );
    }

    #[test]
    fn apply_package_with_service_control_rolls_back_after_restart_failure() {
        let _lock = env_lock();
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        let _data_guard = EnvVarGuard::set_path("AVORAX_DATA_DIR", &data);
        let install = dir.path().join("install");
        let package_path = dir.path().join("restart-failure.aup");
        setup_apply_install_tree(&install);
        let signing_key = test_signing_key();
        let payloads: Vec<(&str, &[u8])> = vec![
            ("app/Avorax.exe", b"new app binary"),
            ("services/avorax_core_service.exe", b"new core service"),
            ("services/avorax_guard_service.exe", b"new guard service"),
            ("engine/signatures/new.asig", b"new signature"),
            ("docs/release.md", b"new release docs"),
        ];
        let manifest = signed_apply_manifest(
            "avorax-test-apply-restart-failure",
            "0.6.0",
            payload_hashes(&payloads),
        );
        write_signed_apply_package(&package_path, &manifest, &payloads, &signing_key);
        let mut service_control = FakeUpdateServiceControl::default();
        service_control
            .start_errors
            .push_back("synthetic restart failure");

        let error = format!(
            "{:#}",
            apply_package_with_service_control(
                &package_path,
                &install,
                "0.5.0",
                test_policy(&signing_key, "0.5.0"),
                &mut service_control,
            )
            .unwrap_err()
        );

        assert!(error.contains(
            "update apply failed because services did not restart; rollback snapshot was restored"
        ));
        assert!(error.contains("synthetic restart failure"));
        assert_eq!(service_control.calls, vec!["stop", "start", "start"]);
        assert_eq!(
            std::fs::read(install.join("Avorax.exe")).unwrap(),
            b"old app binary"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_core_service.exe")).unwrap(),
            b"old core service"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_guard_service.exe")).unwrap(),
            b"old guard service"
        );
        assert_eq!(
            std::fs::read(install.join("engine/signatures/old.asig")).unwrap(),
            b"old signature"
        );
        assert_missing_path(&install.join("engine/signatures/new.asig"));
        assert_missing_path(
            &staging_root()
                .unwrap()
                .join("avorax-test-apply-restart-failure"),
        );
        let report = read_json_file(&data.join("updates/logs/update_report.json"));
        assert_eq!(report["ok"], false);
        assert_eq!(report["package_id"], "avorax-test-apply-restart-failure");
        assert_eq!(report["apply_error"], serde_json::Value::Null);
        assert!(report["restart_error"]
            .as_str()
            .unwrap()
            .contains("synthetic restart failure"));
        assert_eq!(report["rollback_ok"], true);
        assert_eq!(report["rollback_restart_ok"], true);
        assert_eq!(report["staging_cleanup_ok"], true);
    }

    #[test]
    fn missing_staging_dir_cleanup_is_noop() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("missing-staging");

        remove_existing_staging_dir(&staging).unwrap();
    }

    #[test]
    fn staging_cleanup_rejects_non_directory() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging-file");
        std::fs::write(&staging, b"not a directory").unwrap();

        let error = remove_existing_staging_dir(&staging)
            .unwrap_err()
            .to_string();

        assert!(error.contains("not a directory"));
    }

    #[test]
    fn payload_section_presence_accepts_directories_and_absence() {
        let dir = tempdir().unwrap();
        let section = dir.path().join("engine");
        std::fs::create_dir_all(&section).unwrap();

        assert!(payload_section_dir_present(&section).unwrap());
        assert!(!payload_section_dir_present(&dir.path().join("missing")).unwrap());
    }

    #[test]
    fn payload_section_presence_rejects_files() {
        let dir = tempdir().unwrap();
        let section = dir.path().join("engine");
        std::fs::write(&section, b"not a directory").unwrap();

        let error = payload_section_dir_present(&section)
            .unwrap_err()
            .to_string();

        assert!(error.contains("not a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn payload_section_presence_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real_section = dir.path().join("real-engine");
        let linked_section = dir.path().join("engine");
        std::fs::create_dir_all(&real_section).unwrap();
        symlink(&real_section, &linked_section).unwrap();

        let error = payload_section_dir_present(&linked_section)
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn normal_update_apply_does_not_activate_tools_or_migration_payloads() {
        let source = include_str!("update_applier.rs");
        let start = source.find("fn apply_payload_sections").unwrap();
        let end = source.find("fn copy_payload_section").unwrap();
        let apply_sections = &source[start..end];

        assert!(!apply_sections.contains("staging.join(\"tools\")"));
        assert!(!apply_sections.contains("install_dir.join(\"tools\")"));
        assert!(!apply_sections.contains("staging.join(\"migrations\")"));
        assert!(!apply_sections.contains("install_dir.join(\"migrations\")"));
        assert!(apply_sections.contains("ensure_existing_install_directory("));
        assert!(apply_sections.contains("update install directory before payload apply"));
        assert!(
            apply_sections
                .find("ensure_existing_install_directory")
                .unwrap()
                < apply_sections
                    .find("copy_app_payload_section(&staging.join(\"app\")")
                    .unwrap()
        );
        assert!(apply_sections.contains("copy_app_payload_section(&staging.join(\"app\")"));
        assert!(!apply_sections.contains("copy_payload_section(&staging.join(\"app\")"));
        assert!(apply_sections.contains("copy_service_payload_section(&staging.join(\"services\")"));
        assert!(!apply_sections.contains("copy_payload_section(&staging.join(\"services\")"));
        assert!(apply_sections.contains("copy_engine_payload_section(&staging.join(\"engine\")"));
        assert!(!apply_sections.contains("copy_payload_section(&staging.join(\"engine\")"));
        assert!(apply_sections.contains("copy_docs_payload_section(&staging.join(\"docs\")"));
        assert!(!apply_sections.contains("copy_payload_section(&staging.join(\"docs\")"));
    }

    #[test]
    fn apply_payload_sections_copies_allowlisted_payloads_to_install_subtrees() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging");
        let install = dir.path().join("install");
        std::fs::create_dir_all(staging.join("app/bin")).unwrap();
        std::fs::create_dir_all(staging.join("services")).unwrap();
        std::fs::create_dir_all(staging.join("engine/signatures")).unwrap();
        std::fs::create_dir_all(staging.join("engine/rules")).unwrap();
        std::fs::create_dir_all(staging.join("engine/ml")).unwrap();
        std::fs::create_dir_all(staging.join("engine/trust")).unwrap();
        std::fs::create_dir_all(staging.join("docs/audit")).unwrap();
        std::fs::create_dir_all(staging.join("tools")).unwrap();
        std::fs::create_dir_all(staging.join("migrations")).unwrap();
        std::fs::create_dir_all(install.join("engine/signatures")).unwrap();
        std::fs::write(
            install.join("engine/signatures/revoked.asig"),
            b"revoked old signature",
        )
        .unwrap();

        std::fs::write(staging.join("app/bin/AvoraxApp.txt"), b"new app").unwrap();
        std::fs::write(
            staging.join("services/avorax_core_service.exe"),
            b"new core service",
        )
        .unwrap();
        std::fs::write(
            staging.join("services/avorax_guard_service.exe"),
            b"new guard service",
        )
        .unwrap();
        std::fs::write(staging.join("engine/signatures/new.asig"), b"new signature").unwrap();
        std::fs::write(staging.join("engine/rules/new.zrule"), b"new rule").unwrap();
        std::fs::write(staging.join("engine/ml/model.zmodel"), b"new model").unwrap();
        std::fs::write(staging.join("engine/trust/trust.json"), b"new trust").unwrap();
        std::fs::write(staging.join("docs/audit/release.md"), b"new docs").unwrap();
        std::fs::write(staging.join("tools/not-activated.txt"), b"tool fixture").unwrap();
        std::fs::write(
            staging.join("migrations/not-activated.txt"),
            b"migration fixture",
        )
        .unwrap();

        apply_payload_sections(&staging, &install).unwrap();

        assert_eq!(
            std::fs::read(install.join("bin/AvoraxApp.txt")).unwrap(),
            b"new app"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_core_service.exe")).unwrap(),
            b"new core service"
        );
        assert_eq!(
            std::fs::read(install.join("avorax_guard_service.exe")).unwrap(),
            b"new guard service"
        );
        assert_eq!(
            std::fs::read(install.join("engine/signatures/new.asig")).unwrap(),
            b"new signature"
        );
        assert_missing_path(&install.join("engine/signatures/revoked.asig"));
        assert_eq!(
            std::fs::read(install.join("engine/rules/new.zrule")).unwrap(),
            b"new rule"
        );
        assert_eq!(
            std::fs::read(install.join("engine/ml/model.zmodel")).unwrap(),
            b"new model"
        );
        assert_eq!(
            std::fs::read(install.join("engine/trust/trust.json")).unwrap(),
            b"new trust"
        );
        assert_eq!(
            std::fs::read(install.join("docs/audit/release.md")).unwrap(),
            b"new docs"
        );
        assert_missing_path(&install.join("tools/not-activated.txt"));
        assert_missing_path(&install.join("migrations/not-activated.txt"));
    }

    #[test]
    fn apply_payload_sections_revalidates_install_root_before_activation() {
        let source = include_str!("update_applier.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let apply_source = &production[production.find("fn apply_payload_sections").unwrap()
            ..production.find("fn copy_app_payload_section").unwrap()];
        let install_source = &production[production.find("fn canonical_install_dir").unwrap()
            ..production
                .find("fn validate_install_dir_path_text")
                .unwrap()];
        let helper_source = &production[production
            .find("fn ensure_existing_install_directory")
            .unwrap()
            ..production
                .find("fn validate_install_dir_path_text")
                .unwrap()];

        assert!(apply_source.contains("ensure_existing_install_directory("));
        assert!(apply_source.contains("update install directory before payload apply"));
        assert!(
            apply_source
                .find("ensure_existing_install_directory")
                .unwrap()
                < apply_source
                    .find("copy_app_payload_section(&staging.join(\"app\"), install_dir)?")
                    .unwrap()
        );
        assert!(install_source.contains(
            "ensure_existing_install_directory(&canonical, \"canonical install directory\")?"
        ));
        assert!(helper_source.contains("std::fs::symlink_metadata(path)"));
        assert!(helper_source.contains("metadata.is_dir()"));
        assert!(
            helper_source
                .matches("ensure_not_link_or_reparse(path, label)?")
                .count()
                >= 2
        );
    }

    #[test]
    fn normal_update_apply_app_payload_rejects_restricted_install_surfaces() {
        let source = include_str!("update_applier.rs");
        let start = source.find("fn copy_app_payload_section").unwrap();
        let end = source.find("fn copy_payload_section").unwrap();
        let app_source = &source[start..end];

        assert!(app_source.contains("validate_app_payload_section(source)?"));
        assert!(app_source.contains("app update payload contains no regular files"));
        assert!(app_source.contains("copy_payload_section(source, destination)?"));
        assert!(app_source.contains("app update payload must not target restricted install path"));
        assert!(app_source
            .contains("app update payload must not include managed service or updater executable"));
        assert!(app_source.contains("\"engine\" | \"docs\" | \"tools\""));
        assert!(app_source.contains("\"avorax_update_service.exe\""));
    }

    #[test]
    fn app_payload_section_rejects_restricted_install_directory() {
        let dir = tempdir().unwrap();
        let app = dir.path().join("app");
        std::fs::create_dir_all(app.join("engine").join("signatures")).unwrap();

        let error = validate_app_payload_section(&app).unwrap_err().to_string();

        assert!(error.contains("app update payload must not target restricted install path engine"));
    }

    #[test]
    fn app_payload_section_rejects_managed_updater_executable() {
        let dir = tempdir().unwrap();
        let app = dir.path().join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("avorax_update_service.exe"),
            b"safe updater-name fixture",
        )
        .unwrap();

        let error = validate_app_payload_section(&app).unwrap_err().to_string();

        assert!(error
            .contains("app update payload must not include managed service or updater executable"));
    }

    #[test]
    fn copy_app_payload_section_rejects_empty_app_directory() {
        let dir = tempdir().unwrap();
        let app = dir.path().join("app");
        let install = dir.path().join("install");
        std::fs::create_dir_all(app.join("bin")).unwrap();

        let error = copy_app_payload_section(&app, &install)
            .unwrap_err()
            .to_string();

        assert!(error.contains("app update payload contains no regular files"));
        assert!(!install.exists());
    }

    #[test]
    fn normal_update_apply_service_payload_is_file_allowlisted() {
        let source = crate::normalized_test_source(include_str!("update_applier.rs"));
        let start = source.find("fn copy_service_payload_section").unwrap();
        let end = source.find("fn copy_engine_payload_section").unwrap();
        let service_source = &source[start..end];

        assert!(source.contains(
            "const NORMAL_SERVICE_PAYLOAD_FILES: &[&str] =\n    &[\"avorax_core_service.exe\", \"avorax_guard_service.exe\"]"
        ));
        assert!(service_source.contains("service_payload_files(source)?"));
        assert!(service_source.contains("copy_file_staged("));
        assert!(service_source.contains("canonical_service_payload_file"));
        assert!(service_source
            .contains("service update payload file {raw_name} is not supported by normal updates"));
        assert!(service_source.contains("service update payload entry must be a regular file"));
        assert!(service_source.contains("duplicate service update payload file"));
        assert!(!service_source.contains("copy_tree_overwrite(source, destination)?"));
    }

    #[test]
    fn service_payload_files_rejects_unknown_service_file() {
        let dir = tempdir().unwrap();
        let services = dir.path().join("services");
        std::fs::create_dir_all(&services).unwrap();
        std::fs::write(services.join("extra_service.exe"), b"safe service fixture").unwrap();

        let error = service_payload_files(&services).unwrap_err().to_string();

        assert!(error.contains("service update payload file extra_service.exe is not supported"));
    }

    #[test]
    fn service_payload_files_rejects_nested_service_directory() {
        let dir = tempdir().unwrap();
        let services = dir.path().join("services");
        std::fs::create_dir_all(services.join("nested")).unwrap();

        let error = service_payload_files(&services).unwrap_err().to_string();

        assert!(error.contains("service update payload entry must be a regular file"));
    }

    #[test]
    fn copy_service_payload_section_rejects_empty_services_directory() {
        let dir = tempdir().unwrap();
        let services = dir.path().join("services");
        let install = dir.path().join("install");
        std::fs::create_dir_all(&services).unwrap();

        let error = copy_service_payload_section(&services, &install)
            .unwrap_err()
            .to_string();

        assert!(error.contains("service update payload contains no supported service files"));
        assert!(!install.exists());
    }

    #[test]
    fn normal_update_apply_engine_payload_is_component_allowlisted() {
        let source = include_str!("update_applier.rs");
        let start = source.find("fn copy_engine_payload_section").unwrap();
        let end = source.find("fn remove_existing_staging_dir").unwrap();
        let engine_source = &source[start..end];

        assert!(source.contains(
            "const NORMAL_ENGINE_PAYLOAD_COMPONENTS: &[&str] = &[\"signatures\", \"rules\", \"ml\", \"trust\"]"
        ));
        assert!(engine_source.contains("engine_payload_components(source)?"));
        assert!(engine_source.contains("replace_tree_atomically("));
        assert!(engine_source.contains("canonical_engine_payload_component"));
        assert!(engine_source.contains("is not supported by normal updates"));
        assert!(engine_source.contains("engine update payload subcomponent must be a directory"));
        assert!(engine_source.contains("duplicate engine update payload subcomponent"));
        assert!(!engine_source.contains("copy_tree_overwrite(source, destination)?"));
    }

    #[test]
    fn engine_payload_components_rejects_unknown_subcomponent() {
        let dir = tempdir().unwrap();
        let engine = dir.path().join("engine");
        std::fs::create_dir_all(engine.join("config")).unwrap();

        let error = engine_payload_components(&engine).unwrap_err().to_string();

        assert!(error.contains("engine update payload subcomponent config is not supported"));
    }

    #[test]
    fn engine_payload_components_rejects_subcomponent_files() {
        let dir = tempdir().unwrap();
        let engine = dir.path().join("engine");
        std::fs::create_dir_all(&engine).unwrap();
        std::fs::write(engine.join("signatures"), b"safe direct file fixture").unwrap();

        let error = engine_payload_components(&engine).unwrap_err().to_string();

        assert!(error.contains("engine update payload subcomponent must be a directory"));
    }

    #[test]
    fn copy_engine_payload_section_rejects_empty_engine_directory() {
        let dir = tempdir().unwrap();
        let engine = dir.path().join("engine");
        let install_engine = dir.path().join("install").join("engine");
        std::fs::create_dir_all(&engine).unwrap();

        let error = copy_engine_payload_section(&engine, &install_engine)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("engine update payload contains no supported runtime subdirectories")
        );
        assert!(!install_engine.exists());
    }

    #[test]
    fn normal_update_apply_docs_payload_is_markdown_allowlisted() {
        let source = include_str!("update_applier.rs");
        let start = source.find("fn copy_docs_payload_section").unwrap();
        let end = source.find("fn remove_existing_staging_dir").unwrap();
        let docs_source = &source[start..end];

        assert!(docs_source.contains("docs_payload_files(source)?"));
        assert!(docs_source.contains("copy_file_staged("));
        assert!(docs_source.contains("file_name != \".md\" && file_name.ends_with(\".md\")"));
        assert!(docs_source.contains("docs update payload file must be Markdown-only"));
        assert!(docs_source.contains("docs update payload entry must be a regular file"));
        assert!(!docs_source.contains("copy_tree_overwrite(source, destination)?"));
    }

    #[test]
    fn docs_payload_files_rejects_non_markdown_file() {
        let dir = tempdir().unwrap();
        let docs = dir.path().join("docs");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("helper.ps1"), b"safe script-name fixture").unwrap();

        let error = docs_payload_files(&docs).unwrap_err().to_string();

        assert!(error.contains("docs update payload file must be Markdown-only"));
    }

    #[test]
    fn copy_docs_payload_section_rejects_empty_docs_directory() {
        let dir = tempdir().unwrap();
        let docs = dir.path().join("docs");
        let install = dir.path().join("install");
        std::fs::create_dir_all(&docs).unwrap();

        let error = copy_docs_payload_section(&docs, &install)
            .unwrap_err()
            .to_string();

        assert!(error.contains("docs update payload contains no Markdown files"));
        assert!(!install.exists());
    }

    #[test]
    fn docs_payload_files_accepts_nested_markdown_file() {
        let dir = tempdir().unwrap();
        let docs = dir.path().join("docs");
        std::fs::create_dir_all(docs.join("audit")).unwrap();
        std::fs::write(docs.join("audit").join("note.md"), b"safe markdown fixture").unwrap();

        let files = docs_payload_files(&docs).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].relative, PathBuf::from("audit").join("note.md"));
    }

    #[test]
    fn payload_section_enumerators_revalidate_section_root_before_enumeration() {
        let source = include_str!("update_applier.rs");
        let app_source = &source[source.find("fn validate_app_payload_section").unwrap()
            ..source
                .find("fn ensure_app_payload_relative_allowed")
                .unwrap()];
        let service_source = &source[source.find("fn service_payload_files").unwrap()
            ..source.find("fn canonical_service_payload_file").unwrap()];
        let engine_source = &source[source.find("fn engine_payload_components").unwrap()
            ..source
                .find("fn canonical_engine_payload_component")
                .unwrap()];
        let docs_source = &source[source.find("fn docs_payload_files").unwrap()
            ..source.find("fn remove_existing_staging_dir").unwrap()];

        assert!(source.contains("fn ensure_payload_section_dir_ready(source: &Path) -> Result<()>"));
        assert!(source.contains("failed to revalidate update payload section"));
        assert!(
            app_source
                .find("ensure_payload_section_dir_ready(source)?")
                .unwrap()
                < app_source.find("WalkDir::new(source)").unwrap()
        );
        assert!(
            service_source
                .find("ensure_payload_section_dir_ready(source)?")
                .unwrap()
                < service_source.find("std::fs::read_dir(source)").unwrap()
        );
        assert!(
            engine_source
                .find("ensure_payload_section_dir_ready(source)?")
                .unwrap()
                < engine_source.find("std::fs::read_dir(source)").unwrap()
        );
        assert!(
            docs_source
                .find("ensure_payload_section_dir_ready(source)?")
                .unwrap()
                < docs_source.find("WalkDir::new(source)").unwrap()
        );
    }

    #[test]
    fn update_applier_uses_non_following_presence_checks() {
        let source = include_str!("update_applier.rs");
        let old_staging_probe = ["staging", ".exists()"].join("");
        let old_section_probe = ["source", ".exists()"].join("");

        assert!(source.contains("fn remove_existing_staging_dir"));
        assert!(source.contains("fn payload_section_dir_present"));
        assert!(source.contains("std::fs::symlink_metadata(staging)"));
        assert!(source.contains("std::fs::symlink_metadata(source)"));
        assert!(!source.contains(&old_staging_probe));
        assert!(!source.contains(&old_section_probe));
    }

    fn assert_missing_path(path: &Path) {
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }
}
