pub mod browser_data_access;
pub mod credential_access_behavior;
pub mod behavior_score;
pub mod file_activity;
pub mod file_activity_window;
pub mod infostealer_behavior;
pub mod persistence_monitor;
pub mod persistence_behavior;
pub mod process_event;
pub mod ransomware_guard;
pub mod security_tamper;
pub mod script_monitor;
pub mod suspicious_child_processes;

pub use file_activity::FileActivityEvent;
pub use file_activity_window::RansomwareActivityWindow;
pub use process_event::ProcessStartEvent;
pub use ransomware_guard::{BehaviorDecision, RansomwareGuard};
