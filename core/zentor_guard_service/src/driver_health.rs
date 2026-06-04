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
    pub secure_boot_enabled: bool,
    pub load_attempted: bool,
    pub load_succeeded: bool,
    pub load_error: Option<String>,
    pub reboot_required: bool,
    pub status: String,
    pub reason: String,
}

impl DriverHealth {
    pub fn probe() -> Self {
        let installed = driver_service_installed();
        let test_signed = test_signing_enabled();
        let secure_boot_enabled = secure_boot_enabled();
        let mut running = driver_filter_running();
        let mut load_attempted = false;
        let mut load_succeeded = false;
        let mut load_error = None;

        if installed && !running && test_signed {
            load_attempted = true;
            match try_load_driver_filter() {
                Ok(()) => {
                    running = driver_filter_running();
                    load_succeeded = running;
                    if !running {
                        load_error = Some(
                            "fltmc load reported success, but fltmc filters did not list ZentorAvFilter afterward."
                                .to_string(),
                        );
                    }
                }
                Err(error) => load_error = Some(error),
            }
        }

        let ipc_connected = if running { driver_ipc_alive() } else { false };
        classify_driver_health(
            installed,
            running,
            ipc_connected,
            test_signed,
            secure_boot_enabled,
            load_attempted,
            load_succeeded,
            load_error,
        )
    }
}

fn classify_driver_health(
    installed: bool,
    running: bool,
    ipc_connected: bool,
    test_signed: bool,
    secure_boot_enabled: bool,
    load_attempted: bool,
    load_succeeded: bool,
    load_error: Option<String>,
) -> DriverHealth {
    let reboot_required = installed && !running && !test_signed;
    let status = if installed && running && ipc_connected {
        "communicationOk"
    } else if installed && running {
        "communicationFailed"
    } else if installed && !test_signed && secure_boot_enabled {
        "secureBootBlocksTestSigning"
    } else if installed && !test_signed {
        "testSigningRequired"
    } else if installed && load_attempted && !load_succeeded {
        "loadFailed"
    } else if installed {
        "installed"
    } else {
        "notInstalled"
    };
    let reason = if installed && running && ipc_connected {
        if load_succeeded {
            "Windows reports the Avorax minifilter is installed/running, Avorax loaded it successfully, and the driver IPC port responded.".to_string()
        } else {
            "Windows reports the Avorax minifilter is installed/running and the driver IPC port responded.".to_string()
        }
    } else if installed && running {
        "Windows reports the Avorax minifilter is running, but driver IPC did not respond. Ensure the Guard Service is running the driver port worker and that test_driver_ipc.exe is packaged next to the service under driver-tools."
            .to_string()
    } else if installed && !test_signed && secure_boot_enabled {
        "The custom Avorax minifilter is installed but not loaded. This development build is test-signed, Windows TESTSIGNING is off, and Secure Boot is enabled. Secure Boot blocks bcdedit /set testsigning on, so this test-signed driver cannot load on this boot configuration. To use the development minifilter, disable Secure Boot in UEFI firmware, enable TESTSIGNING from an elevated terminal, reboot, then run the Avorax driver installer/load self-test again. Production builds require a Microsoft-signed driver instead."
            .to_string()
    } else if installed && !test_signed {
        "The custom Avorax minifilter is installed but not loaded. This development build is test-signed and Windows TESTSIGNING is off; run bcdedit /set testsigning on from an elevated terminal and reboot, then run the Avorax driver installer/load self-test again. Production builds require a Microsoft-signed driver instead."
            .to_string()
    } else if installed && load_attempted && !load_succeeded {
        format!(
            "Windows TESTSIGNING is enabled and Avorax attempted to load ZentorAvFilter, but the filter is still not running. fltmc load error: {}",
            load_error
                .as_deref()
                .unwrap_or("unknown load failure")
        )
    } else if installed {
        "Windows reports the Avorax minifilter service is installed, but the filter is not loaded. Run the Avorax driver installer/load self-test from an elevated terminal."
            .to_string()
    } else {
        "Avorax driver is not installed. Post-launch fallback remains available.".to_string()
    };
    DriverHealth {
        installed,
        running,
        ipc_connected,
        test_signed,
        secure_boot_enabled,
        load_attempted,
        load_succeeded,
        load_error,
        reboot_required,
        status: status.to_string(),
        reason,
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
fn try_load_driver_filter() -> Result<(), String> {
    let output = Command::new("fltmc.exe")
        .args(["load", DRIVER_SERVICE_NAME])
        .output()
        .map_err(|error| format!("failed to run fltmc.exe: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit code {:?}", output.status.code())
        };
        Err(detail)
    }
}

#[cfg(not(windows))]
fn try_load_driver_filter() -> Result<(), String> {
    Err("driver loading is only supported on Windows".to_string())
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
                dir.join("driver-tools").join("test_driver_ipc.exe"),
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

#[cfg(windows)]
fn secure_boot_enabled() -> bool {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "try { if (Confirm-SecureBootUEFI) { 'true' } else { 'false' } } catch { 'unknown' }",
        ])
        .output();
    output
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn secure_boot_enabled() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_stopped_testsigning_off_secure_boot_on_reports_firmware_blocker() {
        let health = classify_driver_health(true, false, false, false, true, false, false, None);

        assert_eq!(health.status, "secureBootBlocksTestSigning");
        assert!(health.reboot_required);
        assert!(!health.load_attempted);
        assert!(health.reason.contains("Secure Boot blocks bcdedit /set testsigning on"));
        assert!(health.reason.contains("disable Secure Boot in UEFI firmware"));
    }

    #[test]
    fn installed_stopped_testsigning_off_requires_reboot_policy_step() {
        let health = classify_driver_health(true, false, false, false, false, false, false, None);

        assert_eq!(health.status, "testSigningRequired");
        assert!(health.reboot_required);
        assert!(!health.load_attempted);
        assert!(health.reason.contains("bcdedit /set testsigning on"));
        assert!(health.reason.contains("reboot"));
    }

    #[test]
    fn installed_stopped_testsigning_on_reports_load_failure() {
        let health = classify_driver_health(
            true,
            false,
            false,
            true,
            false,
            true,
            false,
            Some("access denied".to_string()),
        );

        assert_eq!(health.status, "loadFailed");
        assert!(!health.reboot_required);
        assert!(health.load_attempted);
        assert!(health.reason.contains("access denied"));
    }

    #[test]
    fn running_without_ipc_is_not_reported_as_pre_execution_ready() {
        let health = classify_driver_health(true, true, false, true, false, false, false, None);

        assert_eq!(health.status, "communicationFailed");
        assert!(health.reason.contains("driver IPC did not respond"));
    }

    #[test]
    fn auto_loaded_and_ipc_alive_reports_success() {
        let health = classify_driver_health(true, true, true, true, false, true, true, None);

        assert_eq!(health.status, "communicationOk");
        assert!(health.load_succeeded);
        assert!(health.reason.contains("loaded it successfully"));
    }
}
