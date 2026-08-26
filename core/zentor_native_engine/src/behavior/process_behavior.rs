use anyhow::{bail, Result};

use crate::verdict::risk_fusion::{Evidence, EvidenceSource};

use super::process_event::ProcessStartEvent;
use super::script_monitor::script_execution_indicator;
use super::security_tamper::{assess_security_tamper, is_security_sensitive_command_host};

pub fn analyze_process_start_event(event: &ProcessStartEvent) -> Result<Vec<Evidence>> {
    validate_process_start_event(event)?;

    let executable_name = event
        .executable_path
        .file_name()
        .and_then(|value| value.to_str());
    let mut evidence = Vec::new();
    let Some(executable_name) = executable_name else {
        evidence.push(Evidence {
            id: "process_executable_name_unavailable".to_string(),
            title: "Process behavior inspection limited".to_string(),
            detail: "The executable filename was not valid Unicode; file scanning continues but filename-based process behavior checks are unavailable.".to_string(),
            weight: 0,
            source: EvidenceSource::NativeBehavior,
        });
        return Ok(evidence);
    };

    if script_execution_indicator(executable_name) {
        evidence.push(Evidence {
            id: "script_host_process_observed".to_string(),
            title: "Script host process observed".to_string(),
            detail: "The process executable is a recognized script host. Script-host use alone is not malicious and adds no risk score.".to_string(),
            weight: 0,
            source: EvidenceSource::NativeBehavior,
        });
    }

    if let Some(command_line) = event.command_line.as_deref() {
        let assessment =
            assess_security_tamper(executable_name, command_line, event.command_line_truncated);
        if assessment.command_line_truncated && is_security_sensitive_command_host(executable_name)
        {
            evidence.push(Evidence {
                id: "process_command_line_inspection_limited".to_string(),
                title: "Process command-line inspection limited".to_string(),
                detail: "Only a bounded command-line head and tail were inspected; omitted middle arguments require review.".to_string(),
                weight: 0,
                source: EvidenceSource::NativeBehavior,
            });
        }
        if assessment.score > 0 {
            evidence.push(Evidence {
                id: "security_tamper_command_review".to_string(),
                title: "Security-tamper command review".to_string(),
                detail: format!(
                    "Observed {} distinct context-bound security-tamper command indicator(s). This is post-start review evidence; no process was stopped.",
                    assessment.distinct_indicator_count
                ),
                weight: i32::try_from(assessment.score).unwrap_or(i32::MAX),
                source: EvidenceSource::NativeBehavior,
            });
        }
    }

    Ok(evidence)
}

pub fn process_start_requires_native_review(event: &ProcessStartEvent) -> Result<bool> {
    validate_process_start_event(event)?;
    let Some(executable_name) = event
        .executable_path
        .file_name()
        .and_then(|value| value.to_str())
    else {
        return Ok(false);
    };
    Ok(event.command_line.is_some() && is_security_sensitive_command_host(executable_name))
}

fn validate_process_start_event(event: &ProcessStartEvent) -> Result<()> {
    if event.process_id == 0 {
        bail!("process-start behavior event requires a nonzero process id");
    }
    if event
        .command_line
        .as_deref()
        .is_some_and(|value| value.contains('\0'))
    {
        bail!("process-start command line contains an embedded NUL");
    }
    if event.command_line.is_none() && event.command_line_truncated {
        bail!("process-start command truncation flag requires command-line evidence");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::verdict::{RiskFusion, Verdict};

    use super::*;

    #[test]
    fn process_behavior_is_review_only_without_independent_file_evidence() {
        let event = ProcessStartEvent {
            process_id: 42,
            parent_process_id: Some(7),
            executable_path: PathBuf::from("powershell.exe"),
            command_line: Some(
                "powershell.exe Set-MpPreference; vssadmin.exe delete shadows; wbadmin.exe delete catalog; bcdedit.exe /set recoveryenabled no".to_string(),
            ),
            command_line_truncated: false,
        };
        let evidence = analyze_process_start_event(&event).unwrap();
        let verdict = RiskFusion::fuse(evidence, false, false);

        assert_eq!(verdict.verdict, Verdict::Suspicious);
        assert_eq!(verdict.risk_score, 75);
        assert!(verdict
            .evidence
            .iter()
            .any(|item| item.id == "security_tamper_command_review"));
    }

    #[test]
    fn process_behavior_reports_bounded_command_line_omission() {
        let mut command_line = "é".repeat(10_000);
        command_line.push_str(" vssadmin.exe delete shadows");
        let event = ProcessStartEvent {
            process_id: 44,
            parent_process_id: None,
            executable_path: PathBuf::from("powershell.exe"),
            command_line: Some(command_line),
            command_line_truncated: false,
        };

        let evidence = analyze_process_start_event(&event).unwrap();
        assert!(evidence
            .iter()
            .any(|item| item.id == "process_command_line_inspection_limited"));
        assert!(evidence
            .iter()
            .all(|item| !item.detail.contains("vssadmin.exe")));
    }

    #[test]
    fn process_behavior_rejects_invalid_event_identity_and_nul() {
        let zero_pid = ProcessStartEvent {
            process_id: 0,
            parent_process_id: None,
            executable_path: PathBuf::from("missing.exe"),
            command_line: None,
            command_line_truncated: false,
        };
        assert!(analyze_process_start_event(&zero_pid)
            .unwrap_err()
            .to_string()
            .contains("nonzero process id"));

        let nul = ProcessStartEvent {
            process_id: 1,
            parent_process_id: None,
            executable_path: PathBuf::from("powershell.exe"),
            command_line: Some("powershell.exe\0hidden".to_string()),
            command_line_truncated: false,
        };
        assert!(analyze_process_start_event(&nul)
            .unwrap_err()
            .to_string()
            .contains("embedded NUL"));

        let inconsistent = ProcessStartEvent {
            process_id: 2,
            parent_process_id: None,
            executable_path: PathBuf::from("powershell.exe"),
            command_line: None,
            command_line_truncated: true,
        };
        assert!(analyze_process_start_event(&inconsistent)
            .unwrap_err()
            .to_string()
            .contains("requires command-line evidence"));
    }

    #[test]
    fn process_behavior_review_candidate_is_bounded_to_relevant_commands() {
        let relevant = ProcessStartEvent {
            process_id: 3,
            parent_process_id: Some(1),
            executable_path: PathBuf::from("cmd.exe"),
            command_line: Some("cmd.exe /c echo benign-fixture".to_string()),
            command_line_truncated: false,
        };
        let unrelated = ProcessStartEvent {
            executable_path: PathBuf::from("notepad.exe"),
            ..relevant.clone()
        };

        assert!(process_start_requires_native_review(&relevant).unwrap());
        assert!(!process_start_requires_native_review(&unrelated).unwrap());
    }
}
