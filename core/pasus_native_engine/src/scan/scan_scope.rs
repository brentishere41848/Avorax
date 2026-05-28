use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanScope {
    pub roots: Vec<PathBuf>,
}
