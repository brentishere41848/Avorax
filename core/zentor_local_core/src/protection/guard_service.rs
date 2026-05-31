use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GuardMode {
    Off,
    MonitorOnly,
    BlockConfirmedThreats,
    Aggressive,
}

impl Default for GuardMode {
    fn default() -> Self {
        Self::BlockConfirmedThreats
    }
}

#[derive(Default)]
pub struct GuardService {
    mode: GuardMode,
}

impl GuardService {
    pub fn status(&self) -> &'static str {
        match self.mode {
            GuardMode::Off => "off",
            GuardMode::MonitorOnly => "monitorOnly",
            GuardMode::BlockConfirmedThreats => "blockConfirmedThreats",
            GuardMode::Aggressive => "aggressive",
        }
    }

    pub fn system_status() -> &'static str {
        #[cfg(windows)]
        {
            let output = Command::new("sc.exe")
                .args(["query", "avorax_guard_service"])
                .output()
                .or_else(|_| {
                    Command::new("sc.exe")
                        .args(["query", "zentor_guard_service"])
                        .output()
                });
            let Ok(output) = output else {
                return "off";
            };
            if !output.status.success() {
                return "off";
            }
            let text = String::from_utf8_lossy(&output.stdout).to_uppercase();
            if text.contains("RUNNING") {
                return "running";
            }
            if text.contains("STOPPED") {
                return "stopped";
            }
            return "installed";
        }
        #[cfg(not(windows))]
        {
            "off"
        }
    }
}
