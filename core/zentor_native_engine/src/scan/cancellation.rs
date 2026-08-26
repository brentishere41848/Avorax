use std::error::Error;
use std::fmt::{Display, Formatter};

use anyhow::Result;

#[derive(Debug)]
struct CooperativeScanCancelled {
    stage: &'static str,
}

impl Display for CooperativeScanCancelled {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native scan cancelled cooperatively during {}",
            self.stage
        )
    }
}

impl Error for CooperativeScanCancelled {}

#[derive(Debug)]
struct ScanCancellationCheckFailed {
    stage: &'static str,
    detail: String,
}

impl Display for ScanCancellationCheckFailed {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native scan cancellation check failed during {}: {}",
            self.stage, self.detail
        )
    }
}

impl Error for ScanCancellationCheckFailed {}

pub(crate) fn check_scan_cancellation(
    should_cancel: &mut dyn FnMut() -> Result<bool>,
    stage: &'static str,
) -> Result<()> {
    let cancelled = should_cancel().map_err(|error| ScanCancellationCheckFailed {
        stage,
        detail: format!("{error:#}"),
    })?;
    if cancelled {
        return Err(CooperativeScanCancelled { stage }.into());
    }
    Ok(())
}

pub fn is_cooperative_scan_cancellation(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CooperativeScanCancelled>().is_some()
}

pub fn is_scan_cancellation_check_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ScanCancellationCheckFailed>()
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooperative_scan_cancellation_errors_are_distinct_and_fail_visible() {
        let mut cancelled = || Ok(true);
        let cancel_error = check_scan_cancellation(&mut cancelled, "benign fixture").unwrap_err();
        assert!(is_cooperative_scan_cancellation(&cancel_error));
        assert!(!is_scan_cancellation_check_failure(&cancel_error));
        assert!(cancel_error
            .to_string()
            .contains("cancelled cooperatively during benign fixture"));

        let mut failed = || anyhow::bail!("bounded token diagnostic");
        let check_error = check_scan_cancellation(&mut failed, "benign fixture").unwrap_err();
        assert!(!is_cooperative_scan_cancellation(&check_error));
        assert!(is_scan_cancellation_check_failure(&check_error));
        assert!(check_error
            .to_string()
            .contains("cancellation check failed"));
        assert!(check_error.to_string().contains("bounded token diagnostic"));
    }
}
