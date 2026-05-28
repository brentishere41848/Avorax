pub mod archives;
pub mod elf;
pub mod entropy;
pub mod file_type;
pub mod macho;
pub mod pe;
pub mod scripts;
pub mod strings;

pub use entropy::{entropy, mean_entropy};
pub use file_type::{detect_file_type, FileType};
pub use strings::StringIndicators;

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysis {
    pub file_type: FileType,
    pub file_size: u64,
    pub entropy_mean: f64,
    pub entropy_max: f64,
    pub string_indicators: StringIndicators,
    pub pe: Option<pe::PeAnalysis>,
    pub script: Option<scripts::ScriptAnalysis>,
    pub archive: Option<archives::ArchiveAnalysis>,
}

pub fn analyze_path(path: &Path, bytes: &[u8]) -> Result<StaticAnalysis> {
    let file_type = detect_file_type(path, bytes);
    let chunks = bytes.chunks(4096).map(entropy).collect::<Vec<_>>();
    let entropy_mean = mean_entropy(&chunks);
    let entropy_max = chunks
        .iter()
        .copied()
        .fold(0.0_f64, |acc, value| acc.max(value));
    let string_indicators = strings::extract_indicators(bytes);
    let pe = if file_type == FileType::Pe {
        Some(pe::parse_pe(bytes))
    } else {
        None
    };
    let script = if matches!(
        file_type,
        FileType::PowerShell | FileType::JavaScript | FileType::Batch | FileType::Vbs
    ) {
        Some(scripts::analyze_script(file_type, bytes))
    } else {
        None
    };
    let archive = if file_type == FileType::Zip {
        Some(archives::zip::analyze_zip(bytes)?)
    } else {
        None
    };
    Ok(StaticAnalysis {
        file_type,
        file_size: bytes.len() as u64,
        entropy_mean,
        entropy_max,
        string_indicators,
        pe,
        script,
        archive,
    })
}
