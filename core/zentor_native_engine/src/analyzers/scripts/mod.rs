pub mod batch;
pub mod javascript;
pub mod powershell;
pub mod vbs;

use serde::{Deserialize, Serialize};

use super::FileType;
use anyhow::{bail, Result};

use crate::signatures::text::ascii_lowercase_lossy_with_cancellation;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptAnalysis {
    pub encoded_command: bool,
    pub obfuscation_score: u32,
    pub downloader_patterns: u32,
    pub execution_patterns: u32,
    pub persistence_patterns: u32,
    pub security_tamper_indicators: u32,
}

pub fn analyze_script(file_type: FileType, bytes: &[u8]) -> Result<ScriptAnalysis> {
    let mut never_cancel = || Ok(());
    analyze_script_with_cancellation(file_type, bytes, &mut never_cancel)
}

pub fn analyze_script_with_cancellation(
    file_type: FileType,
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<ScriptAnalysis> {
    cancellation_checkpoint()?;
    let analysis = match file_type {
        FileType::PowerShell => {
            powershell::analyze_with_cancellation(bytes, cancellation_checkpoint)?
        }
        FileType::JavaScript => {
            javascript::analyze_with_cancellation(bytes, cancellation_checkpoint)?
        }
        FileType::Batch => batch::analyze_with_cancellation(bytes, cancellation_checkpoint)?,
        FileType::Vbs => vbs::analyze_with_cancellation(bytes, cancellation_checkpoint)?,
        _ => bail!("unsupported script analysis file type: {:?}", file_type),
    };
    cancellation_checkpoint()?;
    Ok(analysis)
}

pub(super) fn lowercase_script_text_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<String> {
    ascii_lowercase_lossy_with_cancellation(bytes, cancellation_checkpoint)
}

pub(super) fn count_terms_with_cancellation(
    text: &str,
    terms: &[&str],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    let mut total = 0u32;
    for term in terms {
        cancellation_checkpoint()?;
        total = total.saturating_add(text.matches(term).count() as u32);
    }
    cancellation_checkpoint()?;
    Ok(total)
}

pub(super) fn contains_any_with_cancellation(
    text: &str,
    terms: &[&str],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    for term in terms {
        cancellation_checkpoint()?;
        if text.contains(term) {
            return Ok(true);
        }
    }
    cancellation_checkpoint()?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_analysis_rejects_unsupported_file_types() {
        let error = analyze_script(FileType::Text, b"plain text")
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported script analysis file type"));
    }

    #[test]
    fn script_analysis_default_branch_is_not_silent() {
        let source = include_str!("mod.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains("pub fn analyze_script"));
        assert!(production.contains("-> Result<ScriptAnalysis>"));
        assert!(production.contains("unsupported script analysis file type"));
        let old_default = ["_ => ScriptAnalysis::", "default()"].concat();
        assert!(!production.contains(&old_default));
    }

    #[test]
    fn non_archive_static_cancellation_interrupts_script_substeps() {
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 5 {
                anyhow::bail!("benign script cancellation")
            }
            Ok(())
        };

        let error = analyze_script_with_cancellation(
            FileType::PowerShell,
            b"Write-Output 'benign'",
            &mut checkpoint,
        )
        .expect_err("script cancellation must abort analysis");

        assert!(error.to_string().contains("benign script cancellation"));
        assert_eq!(checks, 5);
    }

    #[test]
    fn static_text_normalization_interrupts_script_input_chunks_before_evidence() {
        let bytes =
            vec![b'A'; crate::signatures::text::TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign static script normalization cancellation")
            }
            Ok(())
        };

        let error = lowercase_script_text_with_cancellation(&bytes, &mut checkpoint)
            .expect_err("script normalization cancellation must abort before analysis");

        assert!(error
            .to_string()
            .contains("benign static script normalization cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn non_archive_static_cancellation_preserves_script_wrapper_results() {
        for (file_type, bytes) in [
            (FileType::PowerShell, b"Write-Output 'benign'".as_slice()),
            (FileType::JavaScript, b"console.log('benign')".as_slice()),
            (FileType::Batch, b"@echo benign".as_slice()),
            (FileType::Vbs, b"WScript.Echo \"benign\"".as_slice()),
        ] {
            let wrapped = analyze_script(file_type, bytes).expect("wrapper analysis must pass");
            let mut never_cancel = || Ok(());
            let fallible = analyze_script_with_cancellation(file_type, bytes, &mut never_cancel)
                .expect("fallible script analysis must pass without cancellation");

            assert_eq!(wrapped, fallible);
        }
    }
}
