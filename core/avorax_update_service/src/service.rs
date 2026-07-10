#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;
use serde_json::json;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::time::Duration;

const SERVICE_NAME: &str = "avorax_update_service";
const MAX_SERVICE_ERROR_CHARS: usize = 4096;
const SERVICE_ERROR_TRUNCATED_SUFFIX: &str = "...[truncated]";

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, windows_service_main);

pub fn run_service() -> Result<()> {
    run_platform_service()
}

#[cfg(windows)]
fn run_platform_service() -> Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
fn run_platform_service() -> Result<()> {
    anyhow::bail!("Update Service Windows service mode is unsupported on this platform")
}

#[cfg(windows)]
fn windows_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_windows_service_loop() {
        report_service_error(&format!("update service loop failed: {error:#}"));
    }
}

#[cfg(windows)]
fn run_windows_service_loop() -> Result<()> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let status_handle =
        service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Err(error) = shutdown_tx.send(()) {
                        report_service_error(&format!(
                            "failed to signal update service shutdown: {error:#}"
                        ));
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;
    shutdown_rx
        .recv()
        .context("update service shutdown channel closed before stop signal")?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;
    Ok(())
}

#[cfg(windows)]
fn report_service_error(message: &str) {
    match service_error_report(message) {
        Ok(report) => {
            if let Err(error) =
                crate::logging::write_update_log("update_service_error.json", &report)
            {
                let bounded_error = bounded_service_error_message(&format!("{error:#}"));
                let bounded_message = bounded_service_error_message(message);
                eprintln!(
                    "failed to write update service error report: {bounded_error}; {bounded_message}"
                );
            }
        }
        Err(error) => {
            let bounded_error = bounded_service_error_message(&format!("{error:#}"));
            let bounded_message = bounded_service_error_message(message);
            eprintln!(
                "failed to build update service error report: {bounded_error}; {bounded_message}"
            );
        }
    }
}

fn service_error_report(message: &str) -> Result<String> {
    let report = json!({
        "ok": false,
        "error": bounded_service_error_message(message),
        "timestamp_utc": time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,
    });
    Ok(serde_json::to_string_pretty(&report)?)
}

fn bounded_service_error_message(value: &str) -> String {
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
    truncate_service_error(text)
}

fn truncate_service_error(value: &str) -> String {
    if value.chars().count() <= MAX_SERVICE_ERROR_CHARS {
        return value.to_string();
    }
    let marker_len = SERVICE_ERROR_TRUNCATED_SUFFIX.chars().count();
    let mut bounded: String = value
        .chars()
        .take(MAX_SERVICE_ERROR_CHARS - marker_len)
        .collect();
    bounded.push_str(SERVICE_ERROR_TRUNCATED_SUFFIX);
    bounded
}

#[cfg(test)]
mod error_report_tests {
    #[test]
    fn update_service_error_report_is_bounded_json() {
        let long_message = "e".repeat(super::MAX_SERVICE_ERROR_CHARS + 32);
        let report = super::service_error_report(&long_message).unwrap();
        let value: serde_json::Value = serde_json::from_str(&report).unwrap();
        let error = value["error"].as_str().unwrap();

        assert_eq!(value["ok"].as_bool(), Some(false));
        assert!(value["timestamp_utc"].as_str().is_some());
        assert!(error.chars().count() <= super::MAX_SERVICE_ERROR_CHARS);
        assert!(error.ends_with(super::SERVICE_ERROR_TRUNCATED_SUFFIX));
    }

    #[test]
    fn update_service_error_report_normalizes_controls() {
        let report = super::service_error_report("\0failed\nhard").unwrap();
        let value: serde_json::Value = serde_json::from_str(&report).unwrap();
        let error = value["error"].as_str().unwrap();

        assert!(!error.contains('\0'));
        assert!(!error.contains('\n'));
    }

    #[test]
    fn update_service_error_report_source_contract() {
        let source = include_str!("service.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production slice exists");

        assert!(source.contains("fn service_error_report(message: &str) -> Result<String>"));
        assert!(source.contains("fn bounded_service_error_message(value: &str) -> String"));
        assert!(source.contains("const MAX_SERVICE_ERROR_CHARS: usize = 4096"));
        assert!(source.contains("\"error\": bounded_service_error_message(message)"));
        assert!(production.contains("service_error_report(message)"));
        assert!(!production.contains("write_update_log(\"update_service_error.json\", message)"));
        assert!(!production.contains("; {message}"));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn update_service_shutdown_errors_are_not_ignored() {
        let source = include_str!("service.rs");

        assert!(source.contains("failed to signal update service shutdown"));
        assert!(source.contains("update service shutdown channel closed before stop signal"));
        assert!(source.contains("update service loop failed"));
        assert!(source.contains("fn run_platform_service() -> Result<()>"));
        assert!(
            source.contains("Update Service Windows service mode is unsupported on this platform")
        );
        assert!(source.contains("report_service_error"));
        let old_send = ["let _ = shutdown_", "tx.send(())"].concat();
        let old_recv = ["let _ = shutdown_", "rx.recv()"].concat();
        let old_loop = ["let _ = run_windows_", "service_loop()"].concat();
        let old_sleep_loop = ["std::thread::sleep", "(Duration::from_secs(60))"].concat();

        assert!(!source.contains(&old_send));
        assert!(!source.contains(&old_recv));
        assert!(!source.contains(&old_loop));
        assert!(!source.contains(&old_sleep_loop));
    }

    #[cfg(not(windows))]
    #[test]
    fn update_service_mode_fails_visibly_off_windows() {
        let error = super::run_service().unwrap_err().to_string();

        assert!(
            error.contains("Update Service Windows service mode is unsupported on this platform")
        );
    }
}
