use anyhow::Result;
use std::ffi::OsString;
use std::time::Duration;

const SERVICE_NAME: &str = "avorax_update_service";

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, windows_service_main);

pub fn run_service() -> Result<()> {
    #[cfg(windows)]
    {
        windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        return Ok(());
    }
    #[cfg(not(windows))]
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(windows)]
fn windows_service_main(_arguments: Vec<OsString>) {
    let _ = run_windows_service_loop();
}

#[cfg(windows)]
fn run_windows_service_loop() -> Result<()> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;
    let _ = shutdown_rx.recv();
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
