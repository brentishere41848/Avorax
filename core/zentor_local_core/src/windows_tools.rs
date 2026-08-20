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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsServiceRuntimeStatus {
    pub status: WindowsServiceStatus,
    pub process_id: Option<u32>,
}

#[cfg(windows)]
pub fn query_windows_service_runtime_status(
    name: &str,
) -> anyhow::Result<WindowsServiceRuntimeStatus> {
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
            return Ok(WindowsServiceRuntimeStatus {
                status: WindowsServiceStatus::Missing,
                process_id: None,
            });
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
            return Ok(WindowsServiceRuntimeStatus {
                status: WindowsServiceStatus::Missing,
                process_id: None,
            });
        }
        Err(error) => {
            anyhow::bail!(
                "failed to query Windows service {name} status: {}",
                windows_service_error_detail(&error)
            );
        }
    };
    Ok(WindowsServiceRuntimeStatus {
        status: classify_windows_service_state(status.current_state),
        process_id: status.process_id.filter(|process_id| *process_id != 0),
    })
}

#[cfg(windows)]
pub fn query_windows_service_status(name: &str) -> anyhow::Result<WindowsServiceStatus> {
    Ok(query_windows_service_runtime_status(name)?.status)
}

#[cfg(windows)]
pub fn query_running_windows_service_process_id(name: &str) -> anyhow::Result<u32> {
    let runtime = query_windows_service_runtime_status(name)?;
    running_windows_service_process_id(name, runtime)
}

#[cfg(windows)]
fn running_windows_service_process_id(
    name: &str,
    runtime: WindowsServiceRuntimeStatus,
) -> anyhow::Result<u32> {
    anyhow::ensure!(
        runtime.status == WindowsServiceStatus::Running,
        "Windows service {name} is not running (status: {:?})",
        runtime.status
    );
    runtime.process_id.ok_or_else(|| {
        anyhow::anyhow!("running Windows service {name} did not report a process ID")
    })
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

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::*;

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

        assert_eq!(
            running_windows_service_process_id(
                "avorax_core_service",
                WindowsServiceRuntimeStatus {
                    status: WindowsServiceStatus::Running,
                    process_id: Some(4242),
                },
            )
            .unwrap(),
            4242
        );
        for runtime in [
            WindowsServiceRuntimeStatus {
                status: WindowsServiceStatus::Running,
                process_id: None,
            },
            WindowsServiceRuntimeStatus {
                status: WindowsServiceStatus::Stopped,
                process_id: None,
            },
        ] {
            assert!(running_windows_service_process_id("avorax_core_service", runtime).is_err());
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

            let runtime = query_windows_service_runtime_status(name).unwrap_or_else(|error| {
                panic!("read-only runtime status query failed for {name}: {error:#}")
            });
            assert_eq!(runtime.status, status);
            if runtime.status == WindowsServiceStatus::Running {
                assert!(runtime.process_id.is_some());
            }
        }

        let error = query_windows_service_status("unapproved_service_name")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported Windows service status query"));
    }
}
