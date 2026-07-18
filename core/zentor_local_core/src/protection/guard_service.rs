use serde::{Deserialize, Serialize};

#[cfg(windows)]
const GUARD_SERVICE_QUERY_NAMES: [&str; 2] = ["avorax_guard_service", "zentor_guard_service"];
#[cfg(not(windows))]
const NON_WINDOWS_GUARD_SERVICE_STATUS_UNSUPPORTED: &str =
    "Guard Service status is only available through Windows service control";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GuardMode {
    Off,
    MonitorOnly,
    #[default]
    BlockConfirmedThreats,
    Aggressive,
}

#[derive(Default)]
#[allow(dead_code)]
pub struct GuardService {
    mode: GuardMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardServiceStatusReport {
    pub status: &'static str,
    pub error: Option<String>,
}

impl GuardServiceStatusReport {
    fn status(status: &'static str) -> Self {
        Self {
            status,
            error: None,
        }
    }

    fn unknown(error: String) -> Self {
        Self {
            status: "unknown",
            error: Some(error),
        }
    }
}

impl GuardService {
    #[allow(dead_code)]
    pub fn status(&self) -> &'static str {
        match self.mode {
            GuardMode::Off => "off",
            GuardMode::MonitorOnly => "monitorOnly",
            GuardMode::BlockConfirmedThreats => "blockConfirmedThreats",
            GuardMode::Aggressive => "aggressive",
        }
    }

    #[allow(dead_code)]
    pub fn system_status() -> &'static str {
        Self::system_status_report().status
    }

    pub fn system_status_report() -> GuardServiceStatusReport {
        #[cfg(windows)]
        {
            use crate::windows_tools::WindowsServiceStatus;

            let mut query_errors = Vec::new();
            for service_name in GUARD_SERVICE_QUERY_NAMES {
                let status = match crate::windows_tools::query_windows_service_status(service_name)
                {
                    Ok(status) => status,
                    Err(error) => {
                        query_errors.push(format!(
                            "failed to query Guard Service {service_name}: {error:#}"
                        ));
                        continue;
                    }
                };
                match status {
                    WindowsServiceStatus::Missing => continue,
                    WindowsServiceStatus::Running => {
                        return GuardServiceStatusReport::status("running");
                    }
                    WindowsServiceStatus::Stopped => {
                        return GuardServiceStatusReport::status("stopped");
                    }
                    WindowsServiceStatus::Installed => {
                        return GuardServiceStatusReport::status("installed");
                    }
                }
            }
            if !query_errors.is_empty() {
                return GuardServiceStatusReport::unknown(query_errors.join("; "));
            }
            GuardServiceStatusReport::status("off")
        }
        #[cfg(not(windows))]
        {
            GuardServiceStatusReport::unknown(
                NON_WINDOWS_GUARD_SERVICE_STATUS_UNSUPPORTED.to_string(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    use super::*;

    #[test]
    fn guard_service_status_queries_scm_api_with_alias_fallback() {
        let source = include_str!("guard_service.rs");
        let start = source.find("pub fn system_status").unwrap();
        let end = source.find("#[cfg(test)]").unwrap();
        let status_source = &source[start..end];

        assert!(status_source.contains("GUARD_SERVICE_QUERY_NAMES"));
        assert!(status_source.contains("windows_tools::query_windows_service_status(service_name)"));
        assert!(status_source.contains("WindowsServiceStatus::Missing => continue"));
        assert!(status_source.contains("WindowsServiceStatus::Running"));
        assert!(status_source.contains("WindowsServiceStatus::Stopped"));
        assert!(status_source.contains("WindowsServiceStatus::Installed"));
        assert!(status_source.contains("query_errors.push"));
        assert!(status_source.contains("GuardServiceStatusReport::unknown"));
        assert!(status_source.contains("\"off\""));
    }

    #[test]
    fn guard_service_status_does_not_parse_localized_command_output() {
        let source = include_str!("guard_service.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(!production.contains("sc.exe"));
        assert!(!production.contains("Command::new"));
        assert!(!production.contains("output.stdout"));
        assert!(!production.contains("output.stderr"));
        assert!(!production.contains("String::from_utf8_lossy"));
        assert!(!production.contains("DOES NOT EXIST AS AN INSTALLED SERVICE"));
    }

    #[cfg(not(windows))]
    #[test]
    fn guard_service_status_is_unsupported_not_off_off_windows() {
        let report = GuardService::system_status_report();

        assert_eq!(report.status, "unknown");
        assert_eq!(
            report.error.as_deref(),
            Some(NON_WINDOWS_GUARD_SERVICE_STATUS_UNSUPPORTED)
        );
    }
}
