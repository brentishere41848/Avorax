use super::{Confidence, Verdict};
use crate::scan::ScanActionMode;

pub fn should_auto_quarantine(mode: ScanActionMode, verdict: Verdict, confidence: Confidence) -> bool {
    match mode {
        ScanActionMode::DetectOnly | ScanActionMode::LockdownReview => false,
        ScanActionMode::AutoQuarantineConfirmed => {
            matches!(verdict, Verdict::ConfirmedMalware | Verdict::TestThreat)
                && confidence == Confidence::Confirmed
        }
        ScanActionMode::AutoQuarantineHighConfidence => matches!(
            (verdict, confidence),
            (Verdict::ConfirmedMalware | Verdict::TestThreat, Confidence::Confirmed)
                | (Verdict::ProbableMalware, Confidence::High)
        ),
    }
}
