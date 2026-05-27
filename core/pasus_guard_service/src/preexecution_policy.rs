use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DriverProtectionMode {
    Disabled,
    ObserveOnly,
    Balanced,
    BlockKnownBad,
    BlockConfirmedThreats,
    Lockdown,
    DeveloperMode,
    Aggressive,
}

impl Default for DriverProtectionMode {
    fn default() -> Self {
        Self::BlockConfirmedThreats
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PreExecutionPolicy {
    pub mode: DriverProtectionMode,
    pub default_pre_execution_timeout_ms: u64,
    pub default_file_open_timeout_ms: u64,
    pub critical_system_path_policy: String,
    pub high_risk_user_path_policy: String,
}

impl Default for PreExecutionPolicy {
    fn default() -> Self {
        Self {
            mode: DriverProtectionMode::Balanced,
            default_pre_execution_timeout_ms: 750,
            default_file_open_timeout_ms: 500,
            critical_system_path_policy: "fail_open".to_string(),
            high_risk_user_path_policy: "block_known_bad_only".to_string(),
        }
    }
}
