use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DetectionType {
    Signature,
    Yara,
    Heuristic,
    LocalAi,
    Behavior,
    RansomwareGuard,
    SuspiciousBehavior,
    Reputation,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RiskVerdict {
    Clean,
    LikelyClean,
    Unknown,
    Suspicious,
    ProbableMalware,
    ConfirmedMalware,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RiskSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RiskReasonSource {
    StaticFeature,
    Signature,
    Yara,
    Heuristic,
    AiModel,
    Behavior,
    UserLabel,
    Allowlist,
    CloudOptional,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RiskEngine {
    Signature,
    Yara,
    Heuristic,
    LocalAi,
    Behavior,
    RansomwareGuard,
    ReputationOptional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReason {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub weight: i32,
    pub severity: RiskSeverity,
    pub source: RiskReasonSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u8,
    pub verdict: RiskVerdict,
    pub confidence: ThreatConfidence,
    pub reasons: Vec<RiskReason>,
    pub recommended_action: RecommendedAction,
    pub engines_used: Vec<RiskEngine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ThreatCategory {
    Trojan,
    Ransomware,
    Spyware,
    Adware,
    Worm,
    Keylogger,
    Miner,
    PotentiallyUnwantedApp,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ThreatConfidence {
    Low,
    Medium,
    High,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RecommendedAction {
    Quarantine,
    Review,
    Allowlist,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ThreatResultStatus {
    Detected,
    Quarantined,
    Ignored,
    Restored,
    Deleted,
    Allowlisted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResult {
    pub id: String,
    pub path: String,
    pub file_name: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub detection_type: DetectionType,
    pub threat_category: ThreatCategory,
    pub threat_name: String,
    pub confidence: ThreatConfidence,
    pub engine: String,
    pub detected_at: DateTime<Utc>,
    pub recommended_action: RecommendedAction,
    pub status: ThreatResultStatus,
    pub risk_score: RiskScore,
    pub reason_summary: String,
}
