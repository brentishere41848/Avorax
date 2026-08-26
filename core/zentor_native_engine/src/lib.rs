pub mod analyzers;
pub mod behavior;
pub mod config;
pub mod detection_provider;
pub mod engine;
pub mod heuristics;
pub mod ml;
pub mod quarantine;
pub mod rules;
pub mod scan;
pub mod signatures;
pub mod telemetry;
pub mod threat_intel;
pub mod trust;
pub mod verdict;

#[cfg(windows)]
mod windows_authenticode;

#[cfg(windows)]
mod windows_system;

#[cfg(windows)]
#[doc(hidden)]
pub fn run_authenticode_helper_stdio() -> anyhow::Result<()> {
    windows_authenticode::run_authenticode_helper_stdio()
}

#[cfg(windows)]
#[doc(hidden)]
pub fn run_authenticode_client_self_test_stdio() -> anyhow::Result<()> {
    windows_authenticode::run_authenticode_client_self_test_stdio()
}

pub use config::EngineConfig;
pub use detection_provider::{DetectionProviderInfo, DetectionProviderStatus};
pub use engine::{EngineStatus, SelfTestReport, ZentorNativeEngine};
pub use scan::{
    is_cooperative_scan_cancellation, is_scan_cancellation_check_failure, FileScanVerdict,
    ScanActionMode, ScanJobId, ScanMode, ScanProgress, ScanSummary,
};
pub use verdict::{Confidence, ThreatCategory, Verdict};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod integration_tests;

#[cfg(test)]
pub(crate) mod test_support {
    use std::process::Command;

    const ISOLATED_ENV_CASE: &str = "AVORAX_NATIVE_ENGINE_ISOLATED_ENV_CASE";

    pub(crate) fn is_isolated_environment_case(case: &str) -> bool {
        std::env::var(ISOLATED_ENV_CASE).as_deref() == Ok(case)
    }

    pub(crate) fn run_isolated_environment_case(
        test_name: &str,
        case: &str,
        configure: impl FnOnce(&mut Command),
    ) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .arg("--test-threads=1");
        configure(&mut command);
        command.env(ISOLATED_ENV_CASE, case);

        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "isolated environment test {test_name} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
