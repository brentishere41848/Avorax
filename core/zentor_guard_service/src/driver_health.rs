use serde::{Deserialize, Serialize};
use std::process::Command;

const DRIVER_SERVICE_NAME: &str = "ZentorAvFilter";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriverHealth {
    pub installed: bool,
    pub running: bool,
    pub ipc_connected: bool,
    pub test_signed: bool,
    pub status: String,
    pub reason: String,
}

impl DriverHealth {
    pub fn probe() -> Self {
        let installed = driver_service_installed();
        let running = driver_filter_running();
        let ipc_connected = driver_ipc_alive();
        let test_signed = test_signing_enabled();
        let status = if installed && running && ipc_connected {
            "communicationOk"
        } else if installed && running {
            "communicationFailed"
        } else if installed && !test_signed {
            "testSigningRequired"
        } else if installed {
            "installed"
        } else {
            "notInstalled"
        };
        let reason = if installed && running && ipc_connected {
            "Windows reports the Avorax minifilter is installed/running and the driver IPC port responded."
        } else if installed && running {
            "Windows reports the Avorax minifilter is running, but driver IPC did not respond."
        } else if installed && !test_signed {
            "The custom Avorax minifilter is installed but not loaded. This development build is test-signed and Windows TESTSIGNING is off; run bcdedit /set testsigning on from an elevated terminal and reboot, or install a Microsoft-signed production driver."
        } else if installed {
            "Windows reports the Avorax minifilter service is installed, but the filter is not loaded."
        } else {
            "Avorax driver is not installed. Post-launch fallback remains available."
        };
        Self {
            installed,
            running,
            ipc_connected,
            test_signed,
            status: status.to_string(),
            reason: reason.to_string(),
        }
    }
}

#[cfg(windows)]
fn driver_service_installed() -> bool {
    Command::new("sc.exe")
        .args(["query", DRIVER_SERVICE_NAME])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn driver_service_installed() -> bool {
    false
}

#[cfg(windows)]
fn driver_filter_running() -> bool {
    let output = Command::new("fltmc.exe").arg("filters").output();
    output
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.to_ascii_lowercase().contains("zentoravfilter"))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn driver_filter_running() -> bool {
    false
}

#[cfg(windows)]
fn driver_ipc_alive() -> bool {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()));
    let candidates = exe_dir
        .into_iter()
        .flat_map(|dir| {
            [
                dir.join("driver-tools")
                    .join("zentor_windows_minifilter")
                    .join("usermode_test")
                    .join("test_driver_ipc.exe"),
                dir.join("test_driver_ipc.exe"),
            ]
        })
        .collect::<Vec<_>>();
    candidates.iter().any(|candidate| {
        candidate.exists()
            && Command::new(candidate)
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
    })
}

#[cfg(not(windows))]
fn driver_ipc_alive() -> bool {
    false
}

#[cfg(windows)]
fn test_signing_enabled() -> bool {
    let output = Command::new("bcdedit.exe").arg("/enum").output();
    output
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| {
            stdout.to_ascii_lowercase().contains("testsigning")
                && stdout.to_ascii_lowercase().contains("yes")
        })
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn test_signing_enabled() -> bool {
    false
}
