use super::decision::{
    ApplicationControlDecision, ApplicationControlResult, ApplicationTrustLevel,
};
use super::policy::{ApplicationControlInput, ProtectionMode};

#[derive(Debug, Clone)]
pub struct ScriptPolicy {
    pub mode: ProtectionMode,
}

impl Default for ScriptPolicy {
    fn default() -> Self {
        Self {
            mode: ProtectionMode::Balanced,
        }
    }
}

impl ScriptPolicy {
    pub fn evaluate(&self, input: &ApplicationControlInput) -> ApplicationControlResult {
        if !input.is_script {
            return monitor("Not a script.");
        }
        if input.strong_risk_signal || input.downloaded_from_internet {
            return ApplicationControlResult {
                decision: if self.mode == ProtectionMode::Lockdown {
                    ApplicationControlDecision::Block
                } else {
                    ApplicationControlDecision::AskUser
                },
                trust_level: ApplicationTrustLevel::Suspicious,
                reason: "Script has unknown or high-risk origin and requires review.".to_string(),
                label_as_malware: false,
                requires_user_approval: true,
                monitor_process: true,
                cache_ttl_ms: 30_000,
            };
        }
        monitor("Script is unknown and remains monitored.")
    }
}

fn monitor(reason: &str) -> ApplicationControlResult {
    ApplicationControlResult {
        decision: ApplicationControlDecision::AllowAndMonitor,
        trust_level: ApplicationTrustLevel::Unknown,
        reason: reason.to_string(),
        label_as_malware: false,
        requires_user_approval: false,
        monitor_process: true,
        cache_ttl_ms: 30_000,
    }
}
