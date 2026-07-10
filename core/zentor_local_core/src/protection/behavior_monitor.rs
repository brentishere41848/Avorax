pub struct BehaviorMonitor;

const BEHAVIOR_MONITOR_STATUS: &str = "notActive";
const BEHAVIOR_MONITOR_STATUS_REASON: &str =
    "local behavior monitor has no active observation loop in this build";

impl BehaviorMonitor {
    pub fn status() -> &'static str {
        BEHAVIOR_MONITOR_STATUS
    }

    pub fn status_reason() -> &'static str {
        BEHAVIOR_MONITOR_STATUS_REASON
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavior_monitor_status_is_not_active_without_runtime_loop() {
        assert_eq!(BehaviorMonitor::status(), "notActive");
        assert_eq!(
            BehaviorMonitor::status_reason(),
            "local behavior monitor has no active observation loop in this build"
        );
    }
}
