use std::fs;
use std::path::PathBuf;

#[cfg(windows)]
const WINDOWS_ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsServiceStatus {
    Missing,
    Running,
    Stopped,
    Installed,
}

#[cfg(windows)]
pub fn query_windows_service_status(name: &str) -> anyhow::Result<WindowsServiceStatus> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    anyhow::ensure!(
        matches!(
            name,
            "avorax_core_service" | "avorax_guard_service" | "zentor_guard_service"
        ),
        "unsupported Windows service status query {name}"
    );
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to connect to Windows Service Control Manager: {}",
                windows_service_error_detail(&error)
            )
        })?;
    let service = match manager.open_service(name, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(error)
            if windows_service_error_code(&error) == Some(WINDOWS_ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            return Ok(WindowsServiceStatus::Missing);
        }
        Err(error) => {
            anyhow::bail!(
                "failed to open Windows service {name} for status query: {}",
                windows_service_error_detail(&error)
            );
        }
    };
    let status = match service.query_status() {
        Ok(status) => status,
        Err(error)
            if windows_service_error_code(&error) == Some(WINDOWS_ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            return Ok(WindowsServiceStatus::Missing);
        }
        Err(error) => {
            anyhow::bail!(
                "failed to query Windows service {name} status: {}",
                windows_service_error_detail(&error)
            );
        }
    };
    Ok(classify_windows_service_state(status.current_state))
}

#[cfg(windows)]
fn classify_windows_service_state(
    state: windows_service::service::ServiceState,
) -> WindowsServiceStatus {
    use windows_service::service::ServiceState;

    match state {
        ServiceState::Running => WindowsServiceStatus::Running,
        ServiceState::Stopped => WindowsServiceStatus::Stopped,
        ServiceState::StartPending
        | ServiceState::StopPending
        | ServiceState::ContinuePending
        | ServiceState::PausePending
        | ServiceState::Paused => WindowsServiceStatus::Installed,
    }
}

#[cfg(windows)]
fn windows_service_error_code(error: &windows_service::Error) -> Option<i32> {
    match error {
        windows_service::Error::Winapi(error) => error.raw_os_error(),
        _ => None,
    }
}

#[cfg(windows)]
fn windows_service_error_detail(error: &windows_service::Error) -> String {
    match error {
        windows_service::Error::Winapi(source) => match source.raw_os_error() {
            Some(code) => format!("{error}: {source} (Windows error {code})"),
            None => format!("{error}: {source}"),
        },
        _ => error.to_string(),
    }
}

#[cfg(windows)]
pub fn windows_system32_tool(name: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        matches!(name, "sc.exe" | "icacls.exe"),
        "unsupported Windows System32 tool {name}"
    );
    let system_root = windows_system_root()?;
    let candidate = system_root.join("System32").join(name);
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|error| anyhow::anyhow!("unable to inspect {}: {error}", candidate.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to launch symbolic link {}",
        candidate.display()
    );
    anyhow::ensure!(
        !windows_metadata_is_reparse_point(&metadata),
        "refusing to launch reparse point {}",
        candidate.display()
    );
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "Windows System32 tool {} is not a regular file",
        candidate.display()
    );
    Ok(candidate)
}

#[cfg(not(windows))]
pub fn windows_system32_tool(name: &str) -> anyhow::Result<PathBuf> {
    anyhow::bail!("Windows System32 tool {name} is unavailable on this platform")
}

#[cfg(windows)]
fn windows_system_root() -> anyhow::Result<PathBuf> {
    let mut diagnostics = Vec::new();
    for key in ["SystemRoot", "WINDIR"] {
        match std::env::var_os(key) {
            Some(value) => {
                let text = value.to_string_lossy().trim().to_string();
                if text.is_empty() {
                    diagnostics.push(format!("{key} is empty"));
                    continue;
                }
                let normalized_root = match normalize_windows_system_root_text(&text) {
                    Ok(text) => text,
                    Err(error) => {
                        diagnostics.push(format!("{key} is unsafe: {error}"));
                        continue;
                    }
                };
                let path = PathBuf::from(normalized_root);
                if !is_local_windows_drive_path(&path) {
                    diagnostics.push(format!(
                        "{key} must be a local Windows drive path: {}",
                        path.display()
                    ));
                    continue;
                }
                return Ok(path);
            }
            None => diagnostics.push(format!("{key} is not set")),
        }
    }
    anyhow::bail!(
        "Windows System32 tool root is unavailable: {}",
        diagnostics.join("; ")
    );
}

#[cfg(windows)]
fn normalize_windows_system_root_text(value: &str) -> anyhow::Result<String> {
    anyhow::ensure!(!value.contains('\0'), "Windows system root contains NUL");
    let normalized = value.trim().replace('/', "\\");
    anyhow::ensure!(
        !normalized.split('\\').any(|part| part == ".."),
        "Windows system root must not contain parent traversal"
    );
    Ok(collapse_windows_system_root_segments(&normalized))
}

#[cfg(windows)]
fn collapse_windows_system_root_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if trimmed.is_empty() {
        return String::new();
    }
    let (prefix, rest, absolute) = split_windows_system_root_prefix(trimmed);
    let mut parts = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            _ => parts.push(part),
        }
    }
    let joined = parts.join("\\");
    match (prefix, absolute, joined.is_empty()) {
        (Some(prefix), true, true) => format!("{prefix}\\"),
        (Some(prefix), true, false) => format!("{prefix}\\{joined}"),
        (None, true, true) => "\\".to_string(),
        (None, true, false) => format!("\\{joined}"),
        (Some(prefix), false, true) => prefix.to_string(),
        (Some(prefix), false, false) => format!("{prefix}{joined}"),
        (None, false, _) => joined,
    }
}

#[cfg(windows)]
fn split_windows_system_root_prefix(path: &str) -> (Option<&str>, &str, bool) {
    if path.len() >= 3 && path.as_bytes()[1] == b':' && path.as_bytes()[2] == b'\\' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with('\\') {
        return (None, path.trim_start_matches('\\'), true);
    }
    (None, path, false)
}

#[cfg(windows)]
fn is_local_windows_drive_path(path: &std::path::Path) -> bool {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(windows)]
fn windows_metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::*;

    #[test]
    fn windows_system32_tool_uses_checked_system32_paths_source_marker() {
        let source = include_str!("windows_tools.rs");
        let old_windows_root_fallback = ["PathBuf::from(r\"", "C:\\Windows", "\")"].concat();
        let old_env_string_reader = ["std::env::", "var(key)"].concat();
        let old_silent_env_error = [".", "ok()"].concat();
        assert!(source.contains("matches!(name, \"sc.exe\" | \"icacls.exe\")"));
        assert!(source.contains("fn windows_system_root() -> anyhow::Result<PathBuf>"));
        assert!(source.contains("normalize_windows_system_root_text(&text)"));
        assert!(source.contains("for key in [\"SystemRoot\", \"WINDIR\"]"));
        assert!(source.contains("Windows System32 tool root is unavailable"));
        assert!(!source.contains(&old_windows_root_fallback));
        assert!(!source.contains(&old_env_string_reader));
        assert!(!source.contains(&old_silent_env_error));
        assert!(source.contains("system_root.join(\"System32\").join(name)"));
        assert!(source.contains("fs::symlink_metadata(&candidate)"));
        assert!(source.contains("metadata.file_type().is_symlink()"));
        assert!(source.contains("windows_metadata_is_reparse_point(&metadata)"));
        assert!(source.contains("metadata.file_type().is_file()"));
        assert!(source.contains("Prefix::Disk(_) | Prefix::VerbatimDisk(_)"));
    }

    #[test]
    fn windows_system32_tool_rejects_parent_traversal_source_marker() {
        let source = crate::normalized_test_source(include_str!("windows_tools.rs"));
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(source.contains(
            "fn normalize_windows_system_root_text(value: &str) -> anyhow::Result<String>"
        ));
        assert!(source.contains("fn collapse_windows_system_root_segments(path: &str) -> String"));
        assert!(source.contains("fn split_windows_system_root_prefix(path: &str)"));
        assert!(source.contains("Windows system root must not contain parent traversal"));
        assert!(source.contains("collapse_windows_system_root_segments(&normalized)"));
        assert!(source.contains("match part {\n            \"\" | \".\" => {}"));
        assert!(!production_source.contains("let path = PathBuf::from(text);"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_error_classification_uses_numeric_code_only() {
        let missing = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(
            WINDOWS_ERROR_SERVICE_DOES_NOT_EXIST,
        ));
        let denied = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5));

        assert_eq!(
            windows_service_error_code(&missing),
            Some(WINDOWS_ERROR_SERVICE_DOES_NOT_EXIST)
        );
        assert_eq!(windows_service_error_code(&denied), Some(5));
        assert!(windows_service_error_detail(&missing).contains("Windows error 1060"));
        assert!(windows_service_error_detail(&denied).contains("Windows error 5"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_states_are_mapped_without_localized_text() {
        use windows_service::service::ServiceState;

        assert_eq!(
            classify_windows_service_state(ServiceState::Running),
            WindowsServiceStatus::Running
        );
        assert_eq!(
            classify_windows_service_state(ServiceState::Stopped),
            WindowsServiceStatus::Stopped
        );
        for state in [
            ServiceState::StartPending,
            ServiceState::StopPending,
            ServiceState::ContinuePending,
            ServiceState::PausePending,
            ServiceState::Paused,
        ] {
            assert_eq!(
                classify_windows_service_state(state),
                WindowsServiceStatus::Installed
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_status_queries_are_read_only_and_name_bounded() {
        for name in [
            "avorax_core_service",
            "avorax_guard_service",
            "zentor_guard_service",
        ] {
            let status = query_windows_service_status(name).unwrap_or_else(|error| {
                panic!("read-only status query failed for {name}: {error:#}")
            });
            assert!(matches!(
                status,
                WindowsServiceStatus::Missing
                    | WindowsServiceStatus::Running
                    | WindowsServiceStatus::Stopped
                    | WindowsServiceStatus::Installed
            ));
        }

        let error = query_windows_service_status("unapproved_service_name")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported Windows service status query"));
    }
}
