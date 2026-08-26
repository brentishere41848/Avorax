use anyhow::Result;

use super::ScriptAnalysis;

pub fn analyze(bytes: &[u8]) -> ScriptAnalysis {
    let mut never_cancel = || Ok(());
    analyze_with_cancellation(bytes, &mut never_cancel)
        .expect("the infallible JavaScript callback cannot fail")
}

pub fn analyze_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<ScriptAnalysis> {
    let text = super::lowercase_script_text_with_cancellation(bytes, cancellation_checkpoint)?;
    let encoded_command = super::contains_any_with_cancellation(
        &text,
        &["atob(", "fromcharcode"],
        cancellation_checkpoint,
    )?;
    let obfuscation_score = super::count_terms_with_cancellation(
        &text,
        &["eval(", "fromcharcode"],
        cancellation_checkpoint,
    )?;
    let downloader_patterns = super::count_terms_with_cancellation(
        &text,
        &["xmlhttprequest", "fetch("],
        cancellation_checkpoint,
    )?;
    let execution_patterns = super::count_terms_with_cancellation(
        &text,
        &["wscript.shell", "child_process"],
        cancellation_checkpoint,
    )?;
    let persistence_patterns =
        super::count_terms_with_cancellation(&text, &["runonce"], cancellation_checkpoint)?;
    cancellation_checkpoint()?;
    Ok(ScriptAnalysis {
        encoded_command,
        obfuscation_score,
        downloader_patterns,
        execution_patterns,
        persistence_patterns,
        security_tamper_indicators: 0,
    })
}
