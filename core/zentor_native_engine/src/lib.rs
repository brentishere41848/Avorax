pub mod analyzers;
pub mod behavior;
pub mod config;
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
pub mod updates;
pub mod verdict;

#[cfg(test)]
mod tests;

pub use config::EngineConfig;
pub use engine::{EngineStatus, ZentorNativeEngine, SelfTestReport};
pub use scan::{FileScanVerdict, ScanActionMode, ScanJobId, ScanMode, ScanProgress, ScanSummary};
pub use verdict::{Confidence, ThreatCategory, Verdict};
