use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CoreCommand {
    pub command: String,
    pub path: Option<String>,
    pub paths: Option<Vec<String>>,
    pub action_mode: Option<String>,
    pub scan_kind: Option<String>,
    pub threat_name: Option<String>,
    pub engine: Option<String>,
    pub quarantine_id: Option<String>,
    pub confirmed: Option<bool>,
    pub sha256: Option<String>,
    pub user_label: Option<String>,
    pub user_note: Option<String>,
    pub previous_verdict: Option<String>,
    pub protection_mode: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CoreResponse<T: Serialize> {
    pub ok: bool,
    #[serde(flatten)]
    pub body: T,
}
