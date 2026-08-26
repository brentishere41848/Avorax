use anyhow::Result;

use super::ScriptAnalysis;

pub fn analyze(bytes: &[u8]) -> ScriptAnalysis {
    let mut never_cancel = || Ok(());
    analyze_with_cancellation(bytes, &mut never_cancel)
        .expect("the infallible batch callback cannot fail")
}

pub fn analyze_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<ScriptAnalysis> {
    let text = super::lowercase_script_text_with_cancellation(bytes, cancellation_checkpoint)?;
    let obfuscation_score =
        super::count_terms_with_cancellation(&text, &["^"], cancellation_checkpoint)?;
    let downloader_patterns = super::count_terms_with_cancellation(
        &text,
        &["bitsadmin", "curl "],
        cancellation_checkpoint,
    )?;
    let execution_patterns = super::count_terms_with_cancellation(
        &text,
        &["start ", "powershell"],
        cancellation_checkpoint,
    )?;
    let persistence_patterns = super::count_terms_with_cancellation(
        &text,
        &["schtasks", "reg add"],
        cancellation_checkpoint,
    )?;
    let security_tamper_indicators =
        super::count_terms_with_cancellation(&text, &["vssadmin delete"], cancellation_checkpoint)?;
    Ok(ScriptAnalysis {
        encoded_command: false,
        obfuscation_score,
        downloader_patterns,
        execution_patterns,
        persistence_patterns,
        security_tamper_indicators,
    })
}
