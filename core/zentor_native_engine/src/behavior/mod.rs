pub mod behavior_score;
pub mod browser_data_access;
pub mod credential_access_behavior;
pub mod file_activity;
pub mod file_activity_window;
pub mod infostealer_behavior;
pub mod persistence_behavior;
pub mod persistence_monitor;
pub mod process_behavior;
pub mod process_event;
pub mod ransomware_guard;
pub mod script_monitor;
pub mod security_tamper;
pub mod suspicious_child_processes;

pub use file_activity::FileActivityEvent;
pub use file_activity_window::RansomwareActivityWindow;
pub use process_event::ProcessStartEvent;
pub use ransomware_guard::{BehaviorDecision, RansomwareGuard};

use crate::detection_provider::{DetectionProviderInfo, DetectionProviderStatus};
use crate::verdict::risk_fusion::EvidenceSource;

pub fn builtin_behavior_provider_inventory() -> Vec<DetectionProviderInfo> {
    vec![
        behavior_provider(
            "native.behavior.ransomware_window",
            "Bounded ransomware file-activity window",
            DetectionProviderStatus::Enabled,
            Some("available through the explicit file-activity API; user-mode telemetry is post-write"),
        ),
        behavior_provider(
            "native.behavior.process_script_host",
            "Process script-host observation",
            DetectionProviderStatus::Enabled,
            Some("connected to bounded app-lifetime process snapshots through the explicit process-start API; host identity alone has zero risk weight"),
        ),
        behavior_provider(
            "native.behavior.process_security_tamper",
            "Bounded process security-tamper review",
            DetectionProviderStatus::Enabled,
            Some("connected to bounded app-lifetime process snapshots through the explicit post-start API; emits review evidence and does not stop a process"),
        ),
        behavior_provider(
            "native.behavior.browser_data_access",
            "Browser-data path access correlation",
            DetectionProviderStatus::Disabled,
            Some("disabled: no trusted per-process browser-data path access telemetry is connected"),
        ),
        behavior_provider(
            "native.behavior.infostealer_correlation",
            "Credential access, staging, and network correlation",
            DetectionProviderStatus::Disabled,
            Some("disabled: no trusted per-process credential-read, archive, and outbound-network correlation feed is connected"),
        ),
        behavior_provider(
            "native.behavior.persistence_correlation",
            "Autorun persistence write correlation",
            DetectionProviderStatus::Disabled,
            Some("disabled: no trusted registry/file autorun write and parent-signature telemetry is connected"),
        ),
        behavior_provider(
            "native.behavior.suspicious_child_lineage",
            "Suspicious parent-child image lineage",
            DetectionProviderStatus::Disabled,
            Some("disabled: ProcessStartEvent carries only a parent PID, not a verified parent image identity"),
        ),
    ]
}

fn behavior_provider(
    id: &str,
    display_name: &str,
    status: DetectionProviderStatus,
    reason: Option<&str>,
) -> DetectionProviderInfo {
    DetectionProviderInfo {
        id: id.to_string(),
        display_name: display_name.to_string(),
        source: EvidenceSource::NativeBehavior,
        status,
        reason: reason.map(str::to_string),
    }
}

#[cfg(test)]
mod inventory_tests {
    use std::collections::BTreeSet;

    use crate::detection_provider::DetectionProviderStatus;

    #[test]
    fn process_behavior_inventory_accounts_for_active_and_disabled_engines() {
        let inventory = super::builtin_behavior_provider_inventory();
        let ids = inventory
            .iter()
            .map(|provider| provider.id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(inventory.len(), 7);
        assert_eq!(ids.len(), inventory.len());
        assert!(inventory.iter().any(|provider| {
            provider.id == "native.behavior.process_security_tamper"
                && provider.status == DetectionProviderStatus::Enabled
        }));
        assert!(inventory.iter().any(|provider| {
            provider.id == "native.behavior.suspicious_child_lineage"
                && provider.status == DetectionProviderStatus::Disabled
                && provider
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("parent image"))
        }));
        assert!(inventory
            .iter()
            .filter(|provider| { provider.status == DetectionProviderStatus::Disabled })
            .all(|provider| provider
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("disabled:"))));
    }
}
