use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FileActivityEvent {
    pub process_id: u32,
    pub process_path: PathBuf,
    pub affected_paths: Vec<PathBuf>,
    pub files_modified_count: u32,
    pub files_renamed_count: u32,
    pub entropy_increase_count: u32,
    pub ransom_note_created: bool,
    pub backup_tamper_attempt: bool,
}
