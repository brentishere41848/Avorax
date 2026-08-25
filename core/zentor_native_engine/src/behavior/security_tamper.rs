const MAX_PROCESS_COMMAND_LINE_SAMPLE_BYTES: usize = 16 * 1024;
const MAX_SECURITY_TAMPER_SCORE: u32 = 75;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityTamperAssessment {
    pub distinct_indicator_count: u8,
    pub score: u32,
    pub command_line_truncated: bool,
}

pub fn assess_security_tamper(
    executable_name: &str,
    command_line: &str,
) -> SecurityTamperAssessment {
    let (sample, command_line_truncated) = bounded_head_tail_sample(command_line);
    let command_host = is_command_host(executable_name);
    let mut count = 0_u8;

    if is_mp_preference_host(executable_name)
        && (contains_ascii_phrase(&sample, "set-mppreference")
            || contains_ascii_phrase(&sample, "disableantispyware"))
    {
        count = count.saturating_add(1);
    }
    if direct_or_hosted_utility_match(
        executable_name,
        command_host,
        &sample,
        "vssadmin.exe",
        &["delete", "shadows"],
    ) {
        count = count.saturating_add(1);
    }
    if direct_or_hosted_utility_match(
        executable_name,
        command_host,
        &sample,
        "wbadmin.exe",
        &["delete", "catalog"],
    ) {
        count = count.saturating_add(1);
    }
    if direct_or_hosted_utility_match(
        executable_name,
        command_host,
        &sample,
        "bcdedit.exe",
        &["recoveryenabled", "no"],
    ) {
        count = count.saturating_add(1);
    }

    SecurityTamperAssessment {
        distinct_indicator_count: count,
        score: u32::from(count)
            .saturating_mul(25)
            .min(MAX_SECURITY_TAMPER_SCORE),
        command_line_truncated,
    }
}

pub fn is_security_sensitive_command_host(executable_name: &str) -> bool {
    is_command_host(executable_name)
        || ["vssadmin.exe", "wbadmin.exe", "bcdedit.exe"]
            .iter()
            .any(|expected| executable_name.eq_ignore_ascii_case(expected))
}

fn is_command_host(executable_name: &str) -> bool {
    [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    ]
    .iter()
    .any(|expected| executable_name.eq_ignore_ascii_case(expected))
}

fn is_mp_preference_host(executable_name: &str) -> bool {
    ["powershell.exe", "pwsh.exe", "cmd.exe"]
        .iter()
        .any(|expected| executable_name.eq_ignore_ascii_case(expected))
}

fn direct_or_hosted_utility_match(
    executable_name: &str,
    command_host: bool,
    sample: &str,
    utility: &str,
    required_terms: &[&str],
) -> bool {
    let direct_utility = executable_name.eq_ignore_ascii_case(utility);
    let hosted_utility = command_host && contains_ascii_phrase(sample, utility);
    (direct_utility || hosted_utility)
        && required_terms
            .iter()
            .all(|term| contains_ascii_phrase(sample, term))
}

fn contains_ascii_phrase(text: &str, expected: &str) -> bool {
    text.as_bytes()
        .windows(expected.len())
        .enumerate()
        .any(|(index, window)| {
            if !window.eq_ignore_ascii_case(expected.as_bytes()) {
                return false;
            }
            let before_is_token = index > 0 && text.as_bytes()[index - 1].is_ascii_alphanumeric();
            let after_index = index + expected.len();
            let after_is_token =
                after_index < text.len() && text.as_bytes()[after_index].is_ascii_alphanumeric();
            !before_is_token && !after_is_token
        })
}

fn bounded_head_tail_sample(command_line: &str) -> (String, bool) {
    if command_line.len() <= MAX_PROCESS_COMMAND_LINE_SAMPLE_BYTES {
        return (command_line.to_string(), false);
    }

    let available = MAX_PROCESS_COMMAND_LINE_SAMPLE_BYTES - 1;
    let mut head_end = available / 2;
    while !command_line.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let tail_budget = available - head_end;
    let mut tail_start = command_line.len().saturating_sub(tail_budget);
    while !command_line.is_char_boundary(tail_start) {
        tail_start += 1;
    }

    let mut sample = String::with_capacity(MAX_PROCESS_COMMAND_LINE_SAMPLE_BYTES);
    sample.push_str(&command_line[..head_end]);
    sample.push('\0');
    sample.push_str(&command_line[tail_start..]);
    (sample, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_behavior_tamper_matching_is_contextual_and_distinct() {
        let direct = assess_security_tamper(
            "VSSADMIN.EXE",
            r#""C:\Windows\System32\vssadmin.exe" delete shadows /all"#,
        );
        let hosted = assess_security_tamper(
            "powershell.exe",
            "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference; vssadmin.exe delete shadows",
        );
        let quoted_by_benign = assess_security_tamper(
            "documentation-viewer.exe",
            "example: Set-MpPreference and vssadmin.exe delete shadows",
        );

        assert_eq!(direct.distinct_indicator_count, 1);
        assert_eq!(direct.score, 25);
        assert_eq!(hosted.distinct_indicator_count, 2);
        assert_eq!(hosted.score, 50);
        assert_eq!(quoted_by_benign.score, 0);
    }

    #[test]
    fn process_behavior_tamper_sample_is_utf8_safe_and_bounded() {
        let mut command = "é".repeat(MAX_PROCESS_COMMAND_LINE_SAMPLE_BYTES);
        command.push_str(" bcdedit.exe /set recoveryenabled no");
        let assessment = assess_security_tamper("cmd.exe", &command);

        assert!(assessment.command_line_truncated);
        assert_eq!(assessment.distinct_indicator_count, 1);
        assert_eq!(assessment.score, 25);
    }

    #[test]
    fn process_behavior_tamper_phrase_rejects_embedded_lookalikes() {
        let assessment = assess_security_tamper(
            "powershell.exe",
            "notset-mppreference and disableantispywarelookalike",
        );
        assert_eq!(assessment.score, 0);
    }
}
