use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use zentor_native_engine::behavior::{
    process_behavior::process_start_requires_native_review, ProcessStartEvent,
};
use zentor_native_engine::engine::ExecutionDecision;
use zentor_native_engine::verdict::{risk_fusion::EvidenceSource, Verdict as AneVerdict};

pub struct ProcessMonitor;

const PROCESS_MONITOR_STATUS: &str = "notActive";
const PROCESS_MONITOR_STATUS_REASON: &str =
    "local process monitor capability is snapshot-only; no local-core polling loop is active";
const MAX_PROCESS_SNAPSHOT_ITEMS: usize = 256;
const MAX_PROCESS_TEXT_CHARS: usize = 4096;
const MAX_PROCESS_FINDINGS: usize = 64;
const MAX_NATIVE_PROCESS_REVIEWS: usize = 16;
const MAX_PROCESS_DIAGNOSTICS: usize = 16;
const PROCESS_TEXT_TRUNCATION_MARKER: &str = " ...[truncated-middle]... ";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    pub pid: u32,
    #[serde(default)]
    pub parent_pid: Option<u32>,
    pub image_path: String,
    #[serde(default)]
    pub command_line: Option<String>,
    #[serde(default)]
    pub command_line_truncated: bool,
    #[serde(default)]
    pub signer_trusted: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMonitorPolicy {
    #[serde(default = "default_process_monitor_threshold")]
    pub suspicious_threshold: u32,
    #[serde(default)]
    pub allowed_image_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshotReport {
    pub ok: bool,
    pub status: &'static str,
    pub capability: &'static str,
    pub status_reason: &'static str,
    pub observed_processes: usize,
    pub skipped_processes: usize,
    pub native_behavior_attempted: usize,
    pub native_behavior_completed: usize,
    pub native_behavior_failed: usize,
    pub native_behavior_limited: usize,
    pub findings: Vec<ProcessFinding>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProcessFinding {
    pub pid: u32,
    pub image_path: String,
    pub score: u32,
    pub verdict: &'static str,
    pub reasons: Vec<String>,
}

impl Default for ProcessMonitorPolicy {
    fn default() -> Self {
        Self {
            suspicious_threshold: default_process_monitor_threshold(),
            allowed_image_paths: Vec::new(),
        }
    }
}

impl ProcessMonitor {
    pub fn capability() -> &'static str {
        if cfg!(windows) {
            "userModeSnapshot"
        } else if cfg!(target_os = "macos") {
            "endpointSecuritySnapshotWhenEntitled"
        } else if cfg!(target_os = "linux") {
            "procfsSnapshotWhenAvailable"
        } else {
            "unavailable"
        }
    }

    pub fn status() -> &'static str {
        PROCESS_MONITOR_STATUS
    }

    pub fn status_reason() -> &'static str {
        PROCESS_MONITOR_STATUS_REASON
    }

    pub fn evaluate_snapshot(
        observations: &[ProcessObservation],
        policy: &ProcessMonitorPolicy,
    ) -> ProcessSnapshotReport {
        let allowlist = normalized_allowlist(&policy.allowed_image_paths);
        let mut findings = Vec::new();
        let mut skipped_processes = observations
            .len()
            .saturating_sub(MAX_PROCESS_SNAPSHOT_ITEMS);

        for observation in observations.iter().take(MAX_PROCESS_SNAPSHOT_ITEMS) {
            if observation.pid == 0 {
                skipped_processes = skipped_processes.saturating_add(1);
                continue;
            }
            let Some(image_path) = normalize_process_path_text(&observation.image_path) else {
                skipped_processes = skipped_processes.saturating_add(1);
                continue;
            };
            if allowlist.contains(&image_path.to_ascii_lowercase()) {
                continue;
            }

            let command_line = match observation.command_line.as_deref() {
                Some(value) => {
                    let Some(normalized) =
                        normalize_process_command_text(value, observation.command_line_truncated)
                    else {
                        skipped_processes += 1;
                        continue;
                    };
                    Some(normalized)
                }
                None if observation.command_line_truncated => {
                    skipped_processes += 1;
                    continue;
                }
                None => None,
            };
            let mut score = 0;
            let mut reasons = Vec::new();

            let image_leaf = process_image_leaf(&image_path);
            let command_lower = command_line
                .as_ref()
                .map(|value| value.text.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let image_lower = image_path.to_ascii_lowercase();

            if is_script_host(image_leaf) && has_encoded_or_hidden_script_flags(&command_lower) {
                score += 45;
                reasons.push(
                    "script host launched with encoded or hidden execution flags".to_string(),
                );
            }
            if is_network_capable_lolbin(image_leaf) && has_remote_transfer_flags(&command_lower) {
                score += 35;
                reasons.push(
                    "network-capable Windows tool shows remote transfer arguments".to_string(),
                );
            }
            if is_user_writable_execution_path(&image_lower)
                && observation.signer_trusted == Some(false)
            {
                score += 30;
                reasons.push(
                    "unsigned process image is running from a user-writable location".to_string(),
                );
            }
            if command_line.as_ref().is_some_and(|value| value.truncated) {
                score += 10;
                reasons
                    .push("process command line reached the bounded inspection limit".to_string());
                if is_script_host(image_leaf) || is_network_capable_lolbin(image_leaf) {
                    score += 30;
                    reasons.push(
                        "security-sensitive process command line was truncated; omitted arguments require review"
                            .to_string(),
                    );
                }
            }

            if score >= policy.suspicious_threshold && findings.len() < MAX_PROCESS_FINDINGS {
                findings.push(ProcessFinding {
                    pid: observation.pid,
                    image_path,
                    score,
                    verdict: "suspiciousProcess",
                    reasons,
                });
            }
        }

        ProcessSnapshotReport {
            ok: true,
            status: Self::status(),
            capability: Self::capability(),
            status_reason: Self::status_reason(),
            observed_processes: observations.len(),
            skipped_processes,
            native_behavior_attempted: 0,
            native_behavior_completed: 0,
            native_behavior_failed: 0,
            native_behavior_limited: 0,
            findings,
            diagnostics: Vec::new(),
        }
    }

    pub fn evaluate_snapshot_with_native(
        observations: &[ProcessObservation],
        policy: &ProcessMonitorPolicy,
        analyzer: &mut dyn FnMut(ProcessStartEvent) -> anyhow::Result<ExecutionDecision>,
    ) -> ProcessSnapshotReport {
        let mut report = Self::evaluate_snapshot(observations, policy);
        let allowlist = normalized_allowlist(&policy.allowed_image_paths);

        for observation in observations.iter().take(MAX_PROCESS_SNAPSHOT_ITEMS) {
            if observation.pid == 0 {
                continue;
            }
            let Some(image_path) = normalize_process_path_text(&observation.image_path) else {
                continue;
            };
            if allowlist.contains(&image_path.to_ascii_lowercase()) {
                continue;
            }
            let command_line = match observation.command_line.as_deref() {
                Some(value) => {
                    let Some(normalized) =
                        normalize_process_command_text(value, observation.command_line_truncated)
                    else {
                        continue;
                    };
                    Some(normalized)
                }
                None if observation.command_line_truncated => continue,
                None => None,
            };
            let event = ProcessStartEvent {
                process_id: observation.pid,
                parent_process_id: observation.parent_pid,
                executable_path: PathBuf::from(&image_path),
                command_line: command_line.as_ref().map(|value| value.text.clone()),
                command_line_truncated: command_line.as_ref().is_some_and(|value| value.truncated),
            };
            let requires_review = match process_start_requires_native_review(&event) {
                Ok(value) => value,
                Err(error) => {
                    report.native_behavior_failed = report.native_behavior_failed.saturating_add(1);
                    push_process_diagnostic(
                        &mut report.diagnostics,
                        format!(
                            "Native process behavior preflight failed for PID {}: {error:#}",
                            observation.pid
                        ),
                    );
                    continue;
                }
            };
            if !requires_review {
                continue;
            }
            if report.native_behavior_attempted >= MAX_NATIVE_PROCESS_REVIEWS {
                report.native_behavior_limited = report.native_behavior_limited.saturating_add(1);
                continue;
            }

            report.native_behavior_attempted = report.native_behavior_attempted.saturating_add(1);
            match analyzer(event) {
                Ok(decision) => {
                    report.native_behavior_completed =
                        report.native_behavior_completed.saturating_add(1);
                    merge_native_process_decision(
                        &mut report.findings,
                        observation.pid,
                        &image_path,
                        decision,
                    );
                }
                Err(error) => {
                    report.native_behavior_failed = report.native_behavior_failed.saturating_add(1);
                    push_process_diagnostic(
                        &mut report.diagnostics,
                        format!(
                            "Native process behavior review failed for PID {}: {error:#}",
                            observation.pid
                        ),
                    );
                }
            }
        }

        if report.native_behavior_limited > 0 {
            push_process_diagnostic(
                &mut report.diagnostics,
                format!(
                    "Native process behavior review limit reached; {} eligible observation(s) were not reviewed",
                    report.native_behavior_limited
                ),
            );
        }
        report
    }
}

fn merge_native_process_decision(
    findings: &mut Vec<ProcessFinding>,
    pid: u32,
    image_path: &str,
    decision: ExecutionDecision,
) {
    let behavior_review_score = decision
        .verdict
        .evidence
        .iter()
        .filter(|evidence| evidence.source == EvidenceSource::NativeBehavior)
        .fold(0_u32, |score, evidence| {
            score.saturating_add(evidence.weight.max(0) as u32)
        })
        .min(100);
    let mut reasons = decision
        .verdict
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.source == EvidenceSource::NativeBehavior
                && (evidence.weight > 0 || evidence.id == "process_command_line_inspection_limited")
        })
        .map(|evidence| format!("{}: {}", evidence.title, evidence.detail))
        .collect::<Vec<_>>();
    let file_verdict_requires_review = matches!(
        decision.verdict.verdict,
        AneVerdict::Suspicious
            | AneVerdict::ProbableMalware
            | AneVerdict::ConfirmedMalware
            | AneVerdict::TestThreat
    );
    if reasons.is_empty() && !file_verdict_requires_review {
        return;
    }
    if file_verdict_requires_review {
        reasons.push(format!(
            "Native post-start file-plus-behavior verdict: {} No process action was taken.",
            decision.verdict.user_visible_explanation
        ));
    }
    reasons.truncate(16);
    let verdict = match decision.verdict.verdict {
        AneVerdict::ConfirmedMalware | AneVerdict::TestThreat => "confirmedProcessThreat",
        AneVerdict::ProbableMalware => "probableProcessThreat",
        _ => "suspiciousProcess",
    };
    let score = u32::from(decision.verdict.risk_score).max(behavior_review_score);

    if let Some(existing) = findings
        .iter_mut()
        .find(|finding| finding.pid == pid && finding.image_path == image_path)
    {
        existing.score = existing.score.max(score);
        if process_verdict_rank(verdict) > process_verdict_rank(existing.verdict) {
            existing.verdict = verdict;
        }
        for reason in reasons {
            if existing.reasons.len() >= 16 {
                break;
            }
            if !existing.reasons.contains(&reason) {
                existing.reasons.push(reason);
            }
        }
    } else if findings.len() < MAX_PROCESS_FINDINGS {
        findings.push(ProcessFinding {
            pid,
            image_path: image_path.to_string(),
            score,
            verdict,
            reasons,
        });
    }
}

fn process_verdict_rank(verdict: &str) -> u8 {
    match verdict {
        "confirmedProcessThreat" => 3,
        "probableProcessThreat" => 2,
        "suspiciousProcess" => 1,
        _ => 0,
    }
}

fn push_process_diagnostic(diagnostics: &mut Vec<String>, diagnostic: String) {
    if diagnostics.len() < MAX_PROCESS_DIAGNOSTICS {
        let sanitized = diagnostic
            .chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .take(MAX_PROCESS_TEXT_CHARS)
            .collect::<String>();
        diagnostics.push(sanitized);
    }
}

fn default_process_monitor_threshold() -> u32 {
    40
}

fn normalized_allowlist(paths: &[String]) -> HashSet<String> {
    paths
        .iter()
        .filter_map(|path| normalize_process_path_text(path))
        .map(|path| path.to_ascii_lowercase())
        .collect()
}

fn normalize_process_path_text(raw: &str) -> Option<String> {
    if raw.contains('\0') || raw.chars().count() > MAX_PROCESS_TEXT_CHARS {
        return None;
    }
    let text = sanitize_process_text(raw)?;
    let path = PathBuf::from(&text);
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => return None,
            other => normalized.push(other.as_os_str()),
        }
    }
    if normalized.as_os_str().is_empty() {
        None
    } else {
        Some(normalized.display().to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedProcessCommand {
    text: String,
    truncated: bool,
}

fn normalize_process_command_text(
    raw: &str,
    source_reported_truncated: bool,
) -> Option<NormalizedProcessCommand> {
    if raw.contains('\0') {
        return None;
    }
    let (sample, locally_truncated) = bounded_process_text(raw);
    let text = sanitize_process_text(&sample)?;
    Some(NormalizedProcessCommand {
        text,
        truncated: source_reported_truncated || locally_truncated,
    })
}

fn bounded_process_text(raw: &str) -> (String, bool) {
    let char_count = raw.chars().count();
    if char_count <= MAX_PROCESS_TEXT_CHARS {
        return (raw.to_string(), false);
    }

    let marker_chars = PROCESS_TEXT_TRUNCATION_MARKER.chars().count();
    let retained_chars = MAX_PROCESS_TEXT_CHARS.saturating_sub(marker_chars);
    let head_chars = retained_chars / 2;
    let tail_chars = retained_chars.saturating_sub(head_chars);
    let mut sample = String::new();
    sample.extend(raw.chars().take(head_chars));
    sample.push_str(PROCESS_TEXT_TRUNCATION_MARKER);
    let reversed_tail: String = raw.chars().rev().take(tail_chars).collect();
    sample.extend(reversed_tail.chars().rev());
    (sample, true)
}

fn sanitize_process_text(raw: &str) -> Option<String> {
    let value: String = raw
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let value = value.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn process_image_leaf(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .trim_matches('"')
}

fn is_script_host(image_leaf: &str) -> bool {
    matches!(
        image_leaf.to_ascii_lowercase().as_str(),
        "powershell.exe" | "pwsh.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
    )
}

fn has_encoded_or_hidden_script_flags(command_line: &str) -> bool {
    command_line.contains("-encodedcommand")
        || command_line.contains("-enc ")
        || command_line.contains("/e:")
        || command_line.contains(" -w hidden")
        || command_line.contains("-windowstyle hidden")
}

fn is_network_capable_lolbin(image_leaf: &str) -> bool {
    matches!(
        image_leaf.to_ascii_lowercase().as_str(),
        "bitsadmin.exe"
            | "certutil.exe"
            | "curl.exe"
            | "msiexec.exe"
            | "powershell.exe"
            | "pwsh.exe"
    )
}

fn has_remote_transfer_flags(command_line: &str) -> bool {
    command_line.contains("http://")
        || command_line.contains("https://")
        || command_line.contains("ftp://")
        || command_line.contains("downloadfile")
        || command_line.contains("invoke-webrequest")
        || command_line.contains("start-bitstransfer")
        || command_line.contains("urlcache")
}

fn is_user_writable_execution_path(image_path_lower: &str) -> bool {
    image_path_lower.contains("\\users\\")
        || image_path_lower.contains("/users/")
        || image_path_lower.contains("\\appdata\\")
        || image_path_lower.contains("/appdata/")
        || image_path_lower.contains("\\temp\\")
        || image_path_lower.contains("/tmp/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentor_native_engine::verdict::risk_fusion::{Evidence, RiskFusion};

    #[test]
    fn process_monitor_status_is_snapshot_only_without_polling_loop() {
        assert_eq!(ProcessMonitor::status(), "notActive");
        assert_eq!(
            ProcessMonitor::status_reason(),
            "local process monitor capability is snapshot-only; no local-core polling loop is active"
        );
        assert!(!ProcessMonitor::capability().trim().is_empty());
    }

    #[test]
    fn snapshot_reports_encoded_script_host_as_suspicious_without_blocking_claim() {
        let report = ProcessMonitor::evaluate_snapshot(
            &[ProcessObservation {
                pid: 42,
                parent_pid: Some(1),
                image_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    .to_string(),
                command_line: Some(
                    "powershell.exe -WindowStyle Hidden -EncodedCommand benignfixture".to_string(),
                ),
                command_line_truncated: false,
                signer_trusted: Some(true),
            }],
            &ProcessMonitorPolicy::default(),
        );

        assert_eq!(report.status, "notActive");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].verdict, "suspiciousProcess");
        assert!(report.findings[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("encoded or hidden")));
    }

    #[test]
    fn snapshot_honors_exact_normalized_allowlist() {
        let allowed = r"C:\Users\Brent\AppData\Local\Temp\known-tool.exe".to_string();
        let report = ProcessMonitor::evaluate_snapshot(
            &[ProcessObservation {
                pid: 7,
                parent_pid: None,
                image_path: allowed.clone(),
                command_line: Some("known-tool.exe --fixture".to_string()),
                command_line_truncated: false,
                signer_trusted: Some(false),
            }],
            &ProcessMonitorPolicy {
                allowed_image_paths: vec![allowed],
                ..ProcessMonitorPolicy::default()
            },
        );

        assert!(report.findings.is_empty());
        assert_eq!(report.skipped_processes, 0);
    }

    #[test]
    fn snapshot_rejects_parent_traversal_and_bounds_inventory() {
        let mut observations = Vec::new();
        observations.push(ProcessObservation {
            pid: 1,
            parent_pid: None,
            image_path: r"C:\Users\Brent\..\Temp\bad.exe".to_string(),
            command_line: None,
            command_line_truncated: false,
            signer_trusted: Some(false),
        });
        for pid in 2..270 {
            observations.push(ProcessObservation {
                pid,
                parent_pid: None,
                image_path: format!(r"C:\Windows\System32\benign-{pid}.exe"),
                command_line: None,
                command_line_truncated: false,
                signer_trusted: Some(true),
            });
        }

        let report =
            ProcessMonitor::evaluate_snapshot(&observations, &ProcessMonitorPolicy::default());

        assert_eq!(report.observed_processes, 269);
        assert_eq!(
            report.skipped_processes,
            1 + observations
                .len()
                .saturating_sub(MAX_PROCESS_SNAPSHOT_ITEMS)
        );
        assert!(report.findings.is_empty());
    }

    #[test]
    fn snapshot_detects_unsigned_user_writable_remote_transfer() {
        let report = ProcessMonitor::evaluate_snapshot(
            &[ProcessObservation {
                pid: 77,
                parent_pid: Some(1),
                image_path: r"C:\Users\Brent\AppData\Local\Temp\curl.exe".to_string(),
                command_line: Some("curl.exe https://example.invalid/benign-fixture".to_string()),
                command_line_truncated: false,
                signer_trusted: Some(false),
            }],
            &ProcessMonitorPolicy::default(),
        );

        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].score >= 40);
        assert!(report.findings[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("remote transfer")));
        assert!(report.findings[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("user-writable")));
    }

    #[test]
    fn snapshot_inspects_bounded_command_tail_for_suspicious_flags() {
        let command_line = format!(
            "powershell.exe {} -EncodedCommand benignfixture",
            "a".repeat(MAX_PROCESS_TEXT_CHARS + 256)
        );
        let report = ProcessMonitor::evaluate_snapshot(
            &[ProcessObservation {
                pid: 78,
                parent_pid: Some(1),
                image_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    .to_string(),
                command_line: Some(command_line),
                command_line_truncated: false,
                signer_trusted: Some(true),
            }],
            &ProcessMonitorPolicy::default(),
        );

        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("encoded or hidden")));
        assert!(report.findings[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("truncated")));
    }

    #[test]
    fn snapshot_reviews_pretruncated_security_sensitive_command() {
        let report = ProcessMonitor::evaluate_snapshot(
            &[ProcessObservation {
                pid: 79,
                parent_pid: Some(1),
                image_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    .to_string(),
                command_line: Some("powershell.exe benign head and tail sample".to_string()),
                command_line_truncated: true,
                signer_trusted: Some(true),
            }],
            &ProcessMonitorPolicy::default(),
        );

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].score, 40);
        assert!(report.findings[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("omitted arguments require review")));
    }

    #[test]
    fn exact_limit_benign_command_is_not_marked_truncated() {
        let command_line = "a".repeat(MAX_PROCESS_TEXT_CHARS);
        let report = ProcessMonitor::evaluate_snapshot(
            &[ProcessObservation {
                pid: 80,
                parent_pid: Some(1),
                image_path: r"C:\Windows\System32\notepad.exe".to_string(),
                command_line: Some(command_line),
                command_line_truncated: false,
                signer_trusted: Some(true),
            }],
            &ProcessMonitorPolicy::default(),
        );

        assert!(report.findings.is_empty());
    }

    #[test]
    fn snapshot_rejects_truncation_flag_without_command_evidence() {
        let report = ProcessMonitor::evaluate_snapshot(
            &[ProcessObservation {
                pid: 81,
                parent_pid: Some(1),
                image_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    .to_string(),
                command_line: None,
                command_line_truncated: true,
                signer_trusted: Some(true),
            }],
            &ProcessMonitorPolicy::default(),
        );

        assert_eq!(report.skipped_processes, 1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn snapshot_rejects_nul_command_evidence() {
        let report = ProcessMonitor::evaluate_snapshot(
            &[ProcessObservation {
                pid: 82,
                parent_pid: Some(1),
                image_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    .to_string(),
                command_line: Some("powershell.exe\0-EncodedCommand fixture".to_string()),
                command_line_truncated: false,
                signer_trusted: Some(true),
            }],
            &ProcessMonitorPolicy::default(),
        );

        assert_eq!(report.skipped_processes, 1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn native_process_review_is_bounded_and_preserves_source_truncation() {
        let observations = (1..=18)
            .map(|pid| ProcessObservation {
                pid,
                parent_pid: Some(1),
                image_path: format!(r"C:\Windows\System32\cmd-{pid}\cmd.exe"),
                command_line: Some(format!(
                    "cmd.exe /c benign fixture {pid} vssadmin.exe delete shadows"
                )),
                command_line_truncated: pid == 1,
                signer_trusted: Some(true),
            })
            .collect::<Vec<_>>();
        let mut saw_source_truncation = false;
        let mut analyzer = |event: ProcessStartEvent| {
            if event.process_id == 1 {
                saw_source_truncation = event.command_line_truncated;
            }
            Ok(ExecutionDecision {
                action: "allow_and_monitor".to_string(),
                verdict: RiskFusion::fuse(
                    vec![Evidence {
                        id: "security_tamper_command_review".to_string(),
                        title: "Security-tamper command review".to_string(),
                        detail: "One bounded post-start indicator requires review; no process was stopped."
                            .to_string(),
                        weight: 25,
                        source: EvidenceSource::NativeBehavior,
                    }],
                    true,
                    false,
                ),
            })
        };

        let report = ProcessMonitor::evaluate_snapshot_with_native(
            &observations,
            &ProcessMonitorPolicy::default(),
            &mut analyzer,
        );

        assert!(saw_source_truncation);
        assert_eq!(report.native_behavior_attempted, MAX_NATIVE_PROCESS_REVIEWS);
        assert_eq!(report.native_behavior_completed, MAX_NATIVE_PROCESS_REVIEWS);
        assert_eq!(report.native_behavior_failed, 0);
        assert_eq!(report.native_behavior_limited, 2);
        assert_eq!(report.findings.len(), MAX_NATIVE_PROCESS_REVIEWS);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0].contains("review limit reached"));
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.verdict == "suspiciousProcess"));
        assert!(report.findings.iter().all(|finding| finding.score == 25));
        assert!(report
            .findings
            .iter()
            .flat_map(|finding| finding.reasons.iter())
            .all(|reason| !reason.contains("vssadmin.exe")));
    }

    #[test]
    fn native_process_review_failures_are_visible_and_allowlist_is_not_read() {
        let allowed = r"C:\Windows\System32\cmd.exe".to_string();
        let observations = vec![
            ProcessObservation {
                pid: 42,
                parent_pid: Some(1),
                image_path: allowed.clone(),
                command_line: Some("cmd.exe /c benign allowlisted fixture".to_string()),
                command_line_truncated: false,
                signer_trusted: Some(true),
            },
            ProcessObservation {
                pid: 43,
                parent_pid: Some(1),
                image_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    .to_string(),
                command_line: Some("powershell.exe benign failing fixture".to_string()),
                command_line_truncated: false,
                signer_trusted: Some(true),
            },
        ];
        let mut analyzed_pids = Vec::new();
        let mut analyzer = |event: ProcessStartEvent| {
            analyzed_pids.push(event.process_id);
            anyhow::bail!("bounded benign analyzer failure")
        };

        let report = ProcessMonitor::evaluate_snapshot_with_native(
            &observations,
            &ProcessMonitorPolicy {
                allowed_image_paths: vec![allowed],
                ..ProcessMonitorPolicy::default()
            },
            &mut analyzer,
        );

        assert_eq!(analyzed_pids, vec![43]);
        assert_eq!(report.native_behavior_attempted, 1);
        assert_eq!(report.native_behavior_completed, 0);
        assert_eq!(report.native_behavior_failed, 1);
        assert!(report.findings.is_empty());
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0].contains("PID 43"));
        assert!(report.diagnostics[0].contains("bounded benign analyzer failure"));
    }

    #[test]
    fn native_process_review_rejects_zero_pid_before_file_io() {
        let mut called = false;
        let mut analyzer = |_event: ProcessStartEvent| {
            called = true;
            anyhow::bail!("must not be called")
        };
        let report = ProcessMonitor::evaluate_snapshot_with_native(
            &[ProcessObservation {
                pid: 0,
                parent_pid: None,
                image_path: r"C:\Windows\System32\cmd.exe".to_string(),
                command_line: Some("cmd.exe /c benign fixture".to_string()),
                command_line_truncated: false,
                signer_trusted: Some(true),
            }],
            &ProcessMonitorPolicy::default(),
            &mut analyzer,
        );

        assert!(!called);
        assert_eq!(report.skipped_processes, 1);
        assert_eq!(report.native_behavior_attempted, 0);
    }
}
