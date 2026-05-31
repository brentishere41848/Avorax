use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::decision::{
    ApplicationControlDecision, ApplicationControlResult, ApplicationTrustLevel,
};
use super::known_bad_store::KnownBadStore;
use super::known_good_store::KnownGoodStore;
use super::publisher_trust::{PublisherStatus, TrustedPublisherPolicy};
use super::script_policy::ScriptPolicy;
use super::trust_store::is_passthrough_system_or_zentor_path;
use super::user_approval::UserApprovalStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtectionMode {
    Off,
    MonitorOnly,
    Balanced,
    BlockConfirmedThreats,
    Lockdown,
    DeveloperMode,
}

impl Default for ProtectionMode {
    fn default() -> Self {
        Self::Balanced
    }
}

impl ProtectionMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::MonitorOnly => "Monitor Only",
            Self::Balanced => "Balanced Protection",
            Self::BlockConfirmedThreats => "Block Confirmed Threats",
            Self::Lockdown => "Lockdown Protection",
            Self::DeveloperMode => "Developer Mode",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApplicationControlInput {
    pub path: PathBuf,
    pub sha256: Option<String>,
    pub publisher: Option<String>,
    pub signature_valid: bool,
    pub parent_process_path: Option<PathBuf>,
    pub is_script: bool,
    pub downloaded_from_internet: bool,
    pub strong_risk_signal: bool,
    pub confirmed_malware: bool,
    pub probable_malware: bool,
}

impl ApplicationControlInput {
    pub fn for_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            sha256: None,
            publisher: None,
            signature_valid: false,
            parent_process_path: None,
            is_script: false,
            downloaded_from_internet: false,
            strong_risk_signal: false,
            confirmed_malware: false,
            probable_malware: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApplicationControlPolicy {
    pub mode: ProtectionMode,
    pub known_good: KnownGoodStore,
    pub known_bad: KnownBadStore,
    pub user_approvals: UserApprovalStore,
    pub trusted_publishers: TrustedPublisherPolicy,
    pub script_policy: ScriptPolicy,
}

impl ApplicationControlPolicy {
    pub fn new(mode: ProtectionMode) -> Self {
        Self {
            mode,
            known_good: KnownGoodStore::default(),
            known_bad: KnownBadStore::default(),
            user_approvals: UserApprovalStore::default(),
            trusted_publishers: TrustedPublisherPolicy::default(),
            script_policy: ScriptPolicy::default(),
        }
    }

    pub fn evaluate(&self, input: &ApplicationControlInput) -> ApplicationControlResult {
        if self.mode == ProtectionMode::Off {
            return result(
                ApplicationControlDecision::Allow,
                ApplicationTrustLevel::Unknown,
                "Application control is off.",
                false,
                false,
                false,
                10_000,
            );
        }

        if is_passthrough_system_or_zentor_path(&input.path) {
            return result(
                ApplicationControlDecision::Allow,
                ApplicationTrustLevel::SystemTrusted,
                "Critical system or Avorax-owned path is allowed by fail-open policy.",
                false,
                false,
                false,
                300_000,
            );
        }

        if input
            .sha256
            .as_ref()
            .map(|hash| self.known_bad.contains(hash))
            .unwrap_or(false)
            || input.confirmed_malware
        {
            return result(
                ApplicationControlDecision::Quarantine,
                ApplicationTrustLevel::ConfirmedMalware,
                "Confirmed local threat signal matched.",
                true,
                false,
                false,
                300_000,
            );
        }

        if input
            .sha256
            .as_ref()
            .map(|hash| self.known_good.contains(hash))
            .unwrap_or(false)
        {
            return result(
                ApplicationControlDecision::Allow,
                ApplicationTrustLevel::KnownGoodHash,
                "Known-good exact hash is trusted.",
                false,
                false,
                false,
                300_000,
            );
        }

        if input
            .sha256
            .as_ref()
            .map(|hash| self.user_approvals.is_hash_approved(hash))
            .unwrap_or(false)
        {
            return result(
                ApplicationControlDecision::Allow,
                ApplicationTrustLevel::UserApproved,
                "User approved this exact file hash.",
                false,
                false,
                false,
                300_000,
            );
        }

        if input.signature_valid {
            match self.trusted_publishers.evaluate(input.publisher.as_deref()) {
                PublisherStatus::Trusted => {
                    return result(
                        ApplicationControlDecision::Allow,
                        ApplicationTrustLevel::TrustedPublisher,
                        "Valid trusted publisher signature.",
                        false,
                        false,
                        false,
                        300_000,
                    );
                }
                PublisherStatus::Suspicious => {
                    if self.mode == ProtectionMode::Lockdown {
                        return result(
                            ApplicationControlDecision::AskUser,
                            ApplicationTrustLevel::Suspicious,
                            "Publisher is signed but not trusted for Lockdown Mode.",
                            false,
                            true,
                            true,
                            30_000,
                        );
                    }
                }
                PublisherStatus::Unknown => {}
            }
        }

        if input.is_script {
            let script_decision = self.script_policy.evaluate(input);
            if script_decision.decision != ApplicationControlDecision::AllowAndMonitor {
                return script_decision;
            }
        }

        if input.probable_malware && input.strong_risk_signal {
            return result(
                ApplicationControlDecision::Quarantine,
                ApplicationTrustLevel::KnownBad,
                "High-confidence probable malware with independent risk signal.",
                true,
                false,
                false,
                300_000,
            );
        }

        match self.mode {
            ProtectionMode::MonitorOnly | ProtectionMode::DeveloperMode => result(
                ApplicationControlDecision::AllowAndMonitor,
                ApplicationTrustLevel::Unknown,
                "Unknown app allowed for monitoring in the selected protection profile.",
                false,
                false,
                true,
                30_000,
            ),
            ProtectionMode::Balanced | ProtectionMode::BlockConfirmedThreats => result(
                ApplicationControlDecision::AllowAndMonitor,
                ApplicationTrustLevel::Unknown,
                "Unknown app is not labeled malware; it is allowed with monitoring.",
                false,
                false,
                true,
                30_000,
            ),
            ProtectionMode::Lockdown => result(
                ApplicationControlDecision::Block,
                ApplicationTrustLevel::Unknown,
                "Lockdown Mode blocks unknown apps until an exact hash is approved.",
                false,
                true,
                false,
                30_000,
            ),
            ProtectionMode::Off => unreachable!(),
        }
    }
}

pub fn location_category(path: &Path) -> &'static str {
    let lower = path.display().to_string().to_lowercase();
    if lower.contains("\\downloads\\") || lower.contains("/downloads/") {
        "downloads"
    } else if lower.contains("\\temp\\") || lower.contains("/tmp/") {
        "temp"
    } else if lower.contains("\\program files\\") {
        "program_files"
    } else if lower.contains("\\windows\\") || lower.starts_with("/system/") {
        "system"
    } else {
        "unknown"
    }
}

fn result(
    decision: ApplicationControlDecision,
    trust_level: ApplicationTrustLevel,
    reason: &str,
    label_as_malware: bool,
    requires_user_approval: bool,
    monitor_process: bool,
    cache_ttl_ms: u64,
) -> ApplicationControlResult {
    ApplicationControlResult {
        decision,
        trust_level,
        reason: reason.to_string(),
        label_as_malware,
        requires_user_approval,
        monitor_process,
        cache_ttl_ms,
    }
}
