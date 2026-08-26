use anyhow::Result;

use super::ScriptAnalysis;

pub fn analyze(bytes: &[u8]) -> ScriptAnalysis {
    let mut never_cancel = || Ok(());
    analyze_with_cancellation(bytes, &mut never_cancel)
        .expect("the infallible PowerShell callback cannot fail")
}

pub fn analyze_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<ScriptAnalysis> {
    let text = super::lowercase_script_text_with_cancellation(bytes, cancellation_checkpoint)?;
    let encoded_command = super::contains_any_with_cancellation(
        &text,
        &["-enc", "-encodedcommand", "frombase64string"],
        cancellation_checkpoint,
    )?;
    let downloader_patterns = super::count_terms_with_cancellation(
        &text,
        &["downloadstring", "invoke-webrequest", "webclient", "curl "],
        cancellation_checkpoint,
    )?;
    let execution_patterns = super::count_terms_with_cancellation(
        &text,
        &["invoke-expression", "iex ", "start-process", "powershell -"],
        cancellation_checkpoint,
    )?;
    let persistence_patterns = super::count_terms_with_cancellation(
        &text,
        &["schtasks", "new-service", "currentversion\\run"],
        cancellation_checkpoint,
    )?;
    let security_tamper_indicators = super::count_terms_with_cancellation(
        &text,
        &["set-mppreference", "disableantispyware", "vssadmin delete"],
        cancellation_checkpoint,
    )?;
    let obfuscation_score = u32::from(encoded_command).saturating_add(
        super::count_terms_with_cancellation(&text, &["`", "$(", "^^"], cancellation_checkpoint)?,
    );
    Ok(ScriptAnalysis {
        encoded_command,
        obfuscation_score,
        downloader_patterns,
        execution_patterns,
        persistence_patterns,
        security_tamper_indicators,
    })
}
