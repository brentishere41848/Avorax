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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtectionMode {
    Off,
    MonitorOnly,
    #[default]
    Balanced,
    BlockConfirmedThreats,
    Lockdown,
    DeveloperMode,
}

impl ProtectionMode {
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
            script_policy: ScriptPolicy::new(mode),
        }
    }

    pub fn evaluate(&self, input: &ApplicationControlInput) -> ApplicationControlResult {
        if self.mode == ProtectionMode::Off {
            return application_control_off_result();
        }

        match is_passthrough_system_or_zentor_path(&input.path) {
            Ok(true) => {
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
            Ok(false) => {}
            Err(error) => {
                return result(
                    ApplicationControlDecision::AllowAndMonitor,
                    ApplicationTrustLevel::Unknown,
                    &format!("Application-control passthrough root validation failed: {error:#}"),
                    false,
                    true,
                    false,
                    60_000,
                );
            }
        }

        let normalized_sha256 = input.sha256.as_deref().and_then(normalize_sha256);
        let malformed_sha256 = input.sha256.is_some() && normalized_sha256.is_none();
        let known_bad_hash_matched = match normalized_sha256.as_deref() {
            Some(hash) => self.known_bad.contains(hash),
            None => false,
        };

        if known_bad_hash_matched || input.confirmed_malware {
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

        if input.probable_malware && input.strong_risk_signal {
            return probable_malware_result(self.mode);
        }

        if malformed_sha256 {
            return malformed_hash_result(self.mode);
        }

        let known_good_hash_matched = match normalized_sha256.as_deref() {
            Some(hash) => self.known_good.contains(hash),
            None => false,
        };

        if known_good_hash_matched {
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

        let user_approved_hash_matched = match normalized_sha256.as_deref() {
            Some(hash) => self.user_approvals.is_hash_approved(hash),
            None => false,
        };

        if user_approved_hash_matched {
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
            ProtectionMode::Off => application_control_off_result(),
        }
    }
}

fn normalize_sha256(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let raw = sha256_body(trimmed);
    if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(raw.to_lowercase())
    } else {
        None
    }
}

fn sha256_body(trimmed: &str) -> &str {
    match trimmed.strip_prefix("sha256:") {
        Some(raw) => raw,
        None => trimmed,
    }
}

fn malformed_hash_result(mode: ProtectionMode) -> ApplicationControlResult {
    let reason = "Malformed SHA-256 evidence was supplied; treating the app as untrusted metadata.";
    match mode {
        ProtectionMode::Lockdown => result(
            ApplicationControlDecision::Block,
            ApplicationTrustLevel::Suspicious,
            reason,
            false,
            true,
            false,
            30_000,
        ),
        ProtectionMode::MonitorOnly | ProtectionMode::DeveloperMode => result(
            ApplicationControlDecision::AllowAndMonitor,
            ApplicationTrustLevel::Suspicious,
            reason,
            false,
            false,
            true,
            30_000,
        ),
        ProtectionMode::Balanced | ProtectionMode::BlockConfirmedThreats => result(
            ApplicationControlDecision::AllowAndMonitor,
            ApplicationTrustLevel::Suspicious,
            reason,
            false,
            false,
            true,
            30_000,
        ),
        ProtectionMode::Off => application_control_off_result(),
    }
}

fn probable_malware_result(mode: ProtectionMode) -> ApplicationControlResult {
    match mode {
        ProtectionMode::Lockdown => result(
            ApplicationControlDecision::Block,
            ApplicationTrustLevel::Suspicious,
            "Strong probable-malware evidence overrides stale trust records in Lockdown Mode; user review is required before allowing execution.",
            false,
            true,
            false,
            30_000,
        ),
        ProtectionMode::MonitorOnly
        | ProtectionMode::DeveloperMode
        | ProtectionMode::Balanced
        | ProtectionMode::BlockConfirmedThreats => result(
            ApplicationControlDecision::AllowAndMonitor,
            ApplicationTrustLevel::Suspicious,
            "Strong probable-malware evidence overrides stale trust records and requires review; automatic quarantine is limited to confirmed threats.",
            false,
            false,
            true,
            30_000,
        ),
        ProtectionMode::Off => application_control_off_result(),
    }
}

fn application_control_off_result() -> ApplicationControlResult {
    result(
        ApplicationControlDecision::Allow,
        ApplicationTrustLevel::Unknown,
        "Application control is off.",
        false,
        false,
        false,
        10_000,
    )
}

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn policy_hash_lookup_defaults_are_explicit_branches() {
        let source = include_str!("policy.rs");
        let evaluate_start = source.find("pub fn evaluate").unwrap();
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let evaluate_source = &source[evaluate_start..normalize_start];

        assert!(evaluate_source
            .contains("let known_bad_hash_matched = match normalized_sha256.as_deref()"));
        assert!(evaluate_source
            .contains("let known_good_hash_matched = match normalized_sha256.as_deref()"));
        assert!(evaluate_source
            .contains("let user_approved_hash_matched = match normalized_sha256.as_deref()"));
        assert!(!evaluate_source.contains(".map(|hash| self.known_bad.contains(hash))"));
        assert!(!evaluate_source.contains(".map(|hash| self.known_good.contains(hash))"));
        assert!(
            !evaluate_source.contains(".map(|hash| self.user_approvals.is_hash_approved(hash))")
        );
        assert!(!evaluate_source.contains(".unwrap_or(false)"));
    }

    #[test]
    fn malformed_hash_uses_visible_policy_route_before_allow_hashes() {
        let mut policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        policy.known_good = KnownGoodStore::from_hashes([format!("sha256:{VALID_HASH}")]).unwrap();
        let mut input = ApplicationControlInput::for_path(r"C:\Users\Brent\Downloads\tool.exe");
        input.sha256 = Some("not-a-sha256".to_string());

        let result = policy.evaluate(&input);

        assert_eq!(result.decision, ApplicationControlDecision::Block);
        assert_eq!(result.trust_level, ApplicationTrustLevel::Suspicious);
        assert!(result.reason.contains("Malformed SHA-256 evidence"));
    }

    #[test]
    fn policy_hash_prefix_branch_is_explicit() {
        let source = include_str!("policy.rs");
        let normalize_start = source.find("fn normalize_sha256").unwrap();
        let malformed_start = source.find("fn malformed_hash_result").unwrap();
        let normalize_source = &source[normalize_start..malformed_start];

        assert_eq!(sha256_body("sha256:abc"), "abc");
        assert_eq!(sha256_body("abc"), "abc");
        assert!(normalize_source.contains("let raw = sha256_body(trimmed)"));
        assert!(normalize_source.contains("Some(raw) => raw"));
        assert!(normalize_source.contains("None => trimmed"));
        assert!(!normalize_source.contains("strip_prefix(\"sha256:\").unwrap_or(trimmed)"));
    }

    #[test]
    fn off_mode_policy_routes_do_not_panic() {
        let policy = ApplicationControlPolicy::new(ProtectionMode::Off);
        let mut input = ApplicationControlInput::for_path(r"C:\Users\Brent\Downloads\tool.exe");
        input.probable_malware = true;
        input.strong_risk_signal = true;

        let policy_result = policy.evaluate(&input);
        let malformed_hash = malformed_hash_result(ProtectionMode::Off);
        let probable_malware = probable_malware_result(ProtectionMode::Off);

        for result in [policy_result, malformed_hash, probable_malware] {
            assert_eq!(&result.decision, &ApplicationControlDecision::Allow);
            assert_eq!(&result.trust_level, &ApplicationTrustLevel::Unknown);
            assert_eq!(result.reason.as_str(), "Application control is off.");
            assert!(!result.label_as_malware);
            assert!(!result.requires_user_approval);
            assert!(!result.monitor_process);
        }
    }

    #[test]
    fn off_mode_policy_routes_are_explicit_not_unreachable() {
        let source = include_str!("policy.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;

        assert!(production_source.contains("fn application_control_off_result()"));
        assert!(
            production_source.contains("ProtectionMode::Off => application_control_off_result()")
        );
        assert!(!production_source.contains("ProtectionMode::Off => unreachable!()"));
        assert!(!production_source.contains("unreachable!()"));
    }

    #[test]
    fn constructor_propagates_mode_to_script_policy() {
        let policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);
        assert_eq!(policy.script_policy.mode, ProtectionMode::Lockdown);

        let source = include_str!("policy.rs");
        let constructor_start = source.find("pub fn new(mode: ProtectionMode)").unwrap();
        let evaluate_start = source.find("pub fn evaluate").unwrap();
        let constructor_source = &source[constructor_start..evaluate_start];

        assert!(constructor_source.contains("script_policy: ScriptPolicy::new(mode)"));
        assert!(!constructor_source.contains("script_policy: ScriptPolicy::default()"));
    }

    #[test]
    fn lockdown_blocks_high_risk_script_from_constructor() {
        let mut input = ApplicationControlInput::for_path(r"C:\Users\Brent\Downloads\run.ps1");
        input.is_script = true;
        input.downloaded_from_internet = true;
        let policy = ApplicationControlPolicy::new(ProtectionMode::Lockdown);

        let result = policy.evaluate(&input);

        assert_eq!(&result.decision, &ApplicationControlDecision::Block);
        assert_eq!(&result.trust_level, &ApplicationTrustLevel::Suspicious);
        assert!(result.requires_user_approval);
    }
}
