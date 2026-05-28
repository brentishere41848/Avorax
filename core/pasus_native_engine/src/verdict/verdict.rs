use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    Clean,
    LikelyClean,
    Unknown,
    Observation,
    Suspicious,
    ProbableMalware,
    ConfirmedMalware,
    TestThreat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ThreatCategory {
    Trojan,
    Ransomware,
    Spyware,
    Adware,
    Worm,
    Keylogger,
    Miner,
    RootkitIndicator,
    PotentiallyUnwantedApp,
    SuspiciousScript,
    MaliciousMacro,
    ExploitDropper,
    CredentialTheftIndicator,
    TestThreat,
    Unknown,
}
