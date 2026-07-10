use std::path::Path;

use super::ThreatResult;

const REPUTATION_PROVIDER_STATUS: &str = "unavailable";
const REPUTATION_PROVIDER_REASON: &str = "no local or cloud reputation backend is configured";

pub struct ReputationProvider;

impl ReputationProvider {
    pub fn inspect_file(&self, _path: &Path) -> Option<ThreatResult> {
        None
    }

    pub fn status(&self) -> &'static str {
        REPUTATION_PROVIDER_STATUS
    }

    pub fn status_reason(&self) -> &'static str {
        REPUTATION_PROVIDER_REASON
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reputation_provider_is_explicitly_disabled_noop() {
        let provider = ReputationProvider;

        assert!(provider.inspect_file(Path::new("fixture.exe")).is_none());
        assert_eq!(provider.status(), "unavailable");
        assert_eq!(
            provider.status_reason(),
            "no local or cloud reputation backend is configured"
        );
    }
}
