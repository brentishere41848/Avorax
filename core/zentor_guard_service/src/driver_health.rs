use serde::{Deserialize, Serialize};

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
        let installed = std::env::var("ZENTOR_DRIVER_INSTALLED").ok().as_deref() == Some("1");
        let running = std::env::var("ZENTOR_DRIVER_RUNNING").ok().as_deref() == Some("1");
        let ipc_connected =
            std::env::var("ZENTOR_DRIVER_IPC_CONNECTED").ok().as_deref() == Some("1");
        let test_signed = std::env::var("ZENTOR_DRIVER_TEST_SIGNED").ok().as_deref() == Some("1");
        let status = if installed && running && ipc_connected {
            "communicationOk"
        } else if installed && running {
            "communicationFailed"
        } else if installed {
            "installed"
        } else {
            "notInstalled"
        };
        Self {
            installed,
            running,
            ipc_connected,
            test_signed,
            status: status.to_string(),
            reason: if installed {
                "Driver status is supplied by the Windows service/installer health probe."
                    .to_string()
            } else {
                "Avorax driver is not installed. Post-launch fallback remains available.".to_string()
            },
        }
    }
}
