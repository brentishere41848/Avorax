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
    Infostealer,
    Adware,
    Worm,
    Keylogger,
    Miner,
    RootkitIndicator,
    PotentiallyUnwantedApp,
    SuspiciousDownloader,
    SuspiciousScript,
    MaliciousMacro,
    ExploitDropper,
    CredentialTheftIndicator,
    PersistenceIndicator,
    SecurityTamperIndicator,
    TestThreat,
    Unknown,
}
