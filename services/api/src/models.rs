use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProjectResponse {
    pub project_id: Uuid,
    pub name: String,
    pub slug: String,
    pub public_client_key: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub project_id: Uuid,
    pub external_device_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub device_id: Uuid,
    pub project_id: Uuid,
    pub external_device_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub project_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub platform: String,
    pub client_version: Option<String>,
    pub file_hash: Option<String>,
    pub device_fingerprint_hash: Option<String>,
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub session_id: Option<Uuid>,
    pub monotonic_time: i64,
    pub client_timestamp: DateTime<Utc>,
    pub signed_payload: String,
    pub environment: Value,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum SecurityEventRequest {
    FileScanEvent { payload: Value },
    ProtectionDecisionEvent { payload: Value },
    QuarantineEvent { payload: Value },
    AllowlistEvent { payload: Value },
    ServiceHealthEvent { payload: Value },
}

#[derive(Debug, Deserialize)]
pub struct DetectionReportRequest {
    pub project_id: Option<Uuid>,
    pub scanned_path_hash: String,
    pub engine: String,
    pub threat_name: Option<String>,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct QuarantineMetadataRequest {
    pub project_id: Option<Uuid>,
    pub quarantine_id: String,
    pub sha256: String,
    pub detection_name: String,
    pub engine: String,
    pub quarantined_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateBanRequest {
    pub device_id: Uuid,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct RiskResponse {
    pub device_id: Uuid,
    pub score: i32,
    pub severity: String,
    pub reasons: Vec<String>,
}
