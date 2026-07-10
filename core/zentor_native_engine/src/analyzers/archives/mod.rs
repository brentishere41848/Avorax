pub mod zip;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveAnalysis {
    pub entry_count: u32,
    pub contains_executable: bool,
    pub suspicious_nested_name_count: u32,
    pub autorun_inf_entry_count: u32,
    pub autorun_inf_executable_command_count: u32,
    pub autorun_executable_entry_count: u32,
    pub shortcut_entry_count: u32,
    pub zip_slip_blocked: bool,
    pub limit_exceeded: bool,
    pub ooxml_vba_project_count: u32,
    pub ooxml_external_relationship_count: u32,
    pub ooxml_remote_executable_relationship_count: u32,
}
