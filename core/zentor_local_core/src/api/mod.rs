use serde::{Deserialize, Serialize};

use crate::protection::process_monitor::{ProcessMonitorPolicy, ProcessObservation};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RansomwareActivityRequest {
    pub process_id: u32,
    pub process_path: String,
    pub modified_paths: Vec<String>,
    pub files_renamed_count: u32,
    pub entropy_change_score: f32,
    pub ransom_note_score: f32,
    pub backup_tamper_score: f32,
    pub time_window_seconds: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreCommand {
    pub command: String,
    pub path: Option<String>,
    pub paths: Option<Vec<String>>,
    pub action_mode: Option<String>,
    pub scan_kind: Option<String>,
    pub threat_name: Option<String>,
    pub engine: Option<String>,
    pub quarantine_id: Option<String>,
    pub allowlist_id: Option<String>,
    pub confirmed: Option<bool>,
    #[allow(dead_code)]
    pub sha256: Option<String>,
    pub user_label: Option<String>,
    pub user_note: Option<String>,
    pub previous_verdict: Option<String>,
    pub protection_mode: Option<String>,
    pub protected_roots: Option<Vec<String>>,
    pub trusted_process_allowlist: Option<Vec<String>>,
    pub ransomware_activity: Option<RansomwareActivityRequest>,
    pub process_observations: Option<Vec<ProcessObservation>>,
    pub process_monitor_policy: Option<ProcessMonitorPolicy>,
    pub duration_ms: Option<u64>,
    pub poll_interval_ms: Option<u64>,
    pub max_events: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CoreResponse<T: Serialize> {
    pub ok: bool,
    #[serde(flatten)]
    pub body: T,
}
