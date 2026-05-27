use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationControlDecision {
    Allow,
    Block,
    Quarantine,
    AllowAndMonitor,
    AskUser,
    TimeoutAllow,
    TimeoutBlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationTrustLevel {
    SystemTrusted,
    TrustedPublisher,
    KnownGoodHash,
    UserApproved,
    Allowlisted,
    Unknown,
    Suspicious,
    KnownBad,
    ConfirmedMalware,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationControlResult {
    pub decision: ApplicationControlDecision,
    pub trust_level: ApplicationTrustLevel,
    pub reason: String,
    pub label_as_malware: bool,
    pub requires_user_approval: bool,
    pub monitor_process: bool,
    pub cache_ttl_ms: u64,
}
