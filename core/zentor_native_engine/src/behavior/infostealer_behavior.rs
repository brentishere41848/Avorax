use crate::verdict::risk_fusion::{Evidence, EvidenceSource};

#[derive(Debug, Clone, Default)]
pub struct InfostealerBehaviorEvent {
    pub process_id: u32,
    pub browser_store_reads: u32,
    pub wallet_file_reads: u32,
    pub archive_created: bool,
    pub outbound_network_after_access: bool,
}

pub fn analyze(event: &InfostealerBehaviorEvent) -> Option<Evidence> {
    let mut score = 0;
    if event.browser_store_reads >= 2 {
        score += 35;
    }
    if event.wallet_file_reads > 0 {
        score += 25;
    }
    if event.archive_created {
        score += 20;
    }
    if event.outbound_network_after_access {
        score += 25;
    }
    (score >= 60).then(|| Evidence {
        id: "infostealer_behavior".to_string(),
        title: "Potential infostealer behavior".to_string(),
        detail: "Multiple local indicators suggest credential-store access followed by staging or network activity.".to_string(),
        weight: score.min(95),
        source: EvidenceSource::NativeBehavior,
    })
}
