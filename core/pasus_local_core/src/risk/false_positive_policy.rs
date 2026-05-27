use crate::scanner::{RiskReason, RiskReasonSource};

pub fn weak_location_only_signal(reasons: &[RiskReason]) -> bool {
    !reasons.is_empty()
        && reasons.iter().all(|reason| {
            reason.source == RiskReasonSource::StaticFeature
                && matches!(
                    reason.id.as_str(),
                    "exe_downloads" | "exe_temp" | "random_name_risky_location"
                )
        })
}
