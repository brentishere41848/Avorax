use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProcessStartEvent {
    pub process_id: u32,
    pub parent_process_id: Option<u32>,
    pub executable_path: PathBuf,
    pub command_line: Option<String>,
}
