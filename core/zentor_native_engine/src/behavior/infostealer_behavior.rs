use crate::verdict::risk_fusion::{Evidence, EvidenceSource};

use super::credential_access_behavior::credential_access_score;

#[derive(Debug, Clone, Default)]
pub struct InfostealerBehaviorEvent {
    pub process_id: u32,
    pub browser_store_reads: u32,
    pub wallet_file_reads: u32,
    pub archive_created: bool,
    pub outbound_network_after_access: bool,
}

pub fn analyze(event: &InfostealerBehaviorEvent) -> Option<Evidence> {
    let mut score =
        credential_access_score(event.browser_store_reads, event.wallet_file_reads).min(60);
    if event.archive_created {
        score = score.saturating_add(20);
    }
    if event.outbound_network_after_access {
        score = score.saturating_add(25);
    }
    (score >= 60).then(|| Evidence {
        id: "infostealer_behavior".to_string(),
        title: "Potential infostealer behavior".to_string(),
        detail: "Multiple local indicators suggest credential-store access followed by staging or network activity.".to_string(),
        weight: i32::try_from(score.min(95)).unwrap_or(95),
        source: EvidenceSource::NativeBehavior,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_behavior_disabled_infostealer_correlation_is_overflow_safe() {
        let evidence = super::analyze(&super::InfostealerBehaviorEvent {
            process_id: 7,
            browser_store_reads: u32::MAX,
            wallet_file_reads: u32::MAX,
            archive_created: true,
            outbound_network_after_access: true,
        })
        .unwrap();
        assert_eq!(evidence.weight, 95);
    }
}
