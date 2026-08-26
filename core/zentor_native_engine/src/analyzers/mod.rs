pub mod archives;
pub mod elf;
pub mod entropy;
pub mod file_type;
pub mod macho;
pub mod pe;
pub mod scripts;
pub mod strings;

pub use entropy::{entropy, entropy_with_cancellation, mean_entropy};
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
    analyze_path_with_size(path, bytes, bytes.len() as u64)
}

pub fn analyze_path_with_size(
    path: &Path,
    bytes: &[u8],
    file_size_bytes: u64,
) -> Result<StaticAnalysis> {
    let mut never_cancel = || Ok(());
    analyze_path_with_size_and_cancellation(path, bytes, file_size_bytes, &mut never_cancel)
}

pub fn analyze_path_with_size_and_cancellation(
    path: &Path,
    bytes: &[u8],
    file_size_bytes: u64,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<StaticAnalysis> {
    cancellation_checkpoint()?;
    let file_type = detect_file_type(path, bytes);
    cancellation_checkpoint()?;
    let mut entropy_sum = 0.0_f64;
    let mut entropy_max = 0.0_f64;
    let mut entropy_chunk_count = 0usize;
    for chunk in bytes.chunks(4096) {
        cancellation_checkpoint()?;
        let value = entropy(chunk);
        entropy_sum += value;
        entropy_max = entropy_max.max(value);
        entropy_chunk_count += 1;
    }
    let entropy_mean = if entropy_chunk_count == 0 {
        0.0
    } else {
        entropy_sum / entropy_chunk_count as f64
    };
    cancellation_checkpoint()?;
    let string_indicators =
        strings::extract_indicators_with_cancellation(bytes, cancellation_checkpoint)?;
    cancellation_checkpoint()?;
    let pe = if file_type == FileType::Pe {
        Some(pe::parse_pe_with_cancellation(
            bytes,
            cancellation_checkpoint,
        )?)
    } else {
        None
    };
    cancellation_checkpoint()?;
    let script = if matches!(
        file_type,
        FileType::PowerShell | FileType::JavaScript | FileType::Batch | FileType::Vbs
    ) {
        Some(scripts::analyze_script_with_cancellation(
            file_type,
            bytes,
            cancellation_checkpoint,
        )?)
    } else {
        None
    };
    cancellation_checkpoint()?;
    let archive = if file_type == FileType::Zip {
        Some(archives::zip::analyze_zip_with_cancellation(
            bytes,
            cancellation_checkpoint,
        )?)
    } else {
        None
    };
    cancellation_checkpoint()?;
    Ok(StaticAnalysis {
        file_type,
        file_size: file_size_bytes.max(bytes.len() as u64),
        entropy_mean,
        entropy_max,
        string_indicators,
        pe,
        script,
        archive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_preserves_declared_file_size_for_sampled_content() {
        let analysis =
            analyze_path_with_size(Path::new("large-benign.bin"), b"sample", 128 * 1024 * 1024)
                .unwrap();

        assert_eq!(analysis.file_size, 128 * 1024 * 1024);
    }

    #[test]
    fn static_archive_cancellation_probe_failure_is_fail_visible() {
        let archive = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0safe.txt";
        let mut checkpoint = || anyhow::bail!("benign static analyzer probe failure");

        let error = analyze_path_with_size_and_cancellation(
            Path::new("benign.zip"),
            archive,
            archive.len() as u64,
            &mut checkpoint,
        )
        .expect_err("checkpoint failure must abort static archive analysis");

        assert!(error
            .to_string()
            .contains("benign static analyzer probe failure"));
    }

    #[test]
    fn non_archive_static_cancellation_interrupts_entropy_before_partial_analysis() {
        let bytes = vec![b'a'; 4096 * 8];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 5 {
                anyhow::bail!("benign non-archive entropy cancellation")
            }
            Ok(())
        };

        let error = analyze_path_with_size_and_cancellation(
            Path::new("benign.txt"),
            &bytes,
            bytes.len() as u64,
            &mut checkpoint,
        )
        .expect_err("non-archive entropy cancellation must abort analysis");

        assert!(error
            .to_string()
            .contains("benign non-archive entropy cancellation"));
        assert_eq!(checks, 5);
    }

    #[test]
    fn non_archive_static_cancellation_preserves_compatibility_wrapper() {
        let bytes = b"https://example.invalid/readme.txt powershell";
        let wrapped = analyze_path_with_size(Path::new("benign.txt"), bytes, bytes.len() as u64)
            .expect("compatibility analysis must pass");
        let mut never_cancel = || Ok(());
        let fallible = analyze_path_with_size_and_cancellation(
            Path::new("benign.txt"),
            bytes,
            bytes.len() as u64,
            &mut never_cancel,
        )
        .expect("fallible analysis must pass without cancellation");

        assert_eq!(wrapped.file_type, fallible.file_type);
        assert_eq!(wrapped.file_size, fallible.file_size);
        assert_eq!(wrapped.entropy_mean, fallible.entropy_mean);
        assert_eq!(wrapped.entropy_max, fallible.entropy_max);
        assert_eq!(
            wrapped.string_indicators.embedded_url_count,
            fallible.string_indicators.embedded_url_count
        );
        assert_eq!(wrapped.pe.is_some(), fallible.pe.is_some());
        assert_eq!(wrapped.script.is_some(), fallible.script.is_some());
        assert_eq!(wrapped.archive.is_some(), fallible.archive.is_some());
    }
}
