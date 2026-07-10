#![allow(dead_code)]

use std::path::PathBuf;

use super::ScanKind;

#[derive(Debug, Clone)]
pub struct ScanScope {
    pub kind: ScanKind,
    pub roots: Vec<PathBuf>,
}
