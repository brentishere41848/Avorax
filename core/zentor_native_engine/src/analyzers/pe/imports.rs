use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::signatures::text::ascii_lowercase_lossy_with_cancellation;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportCategories {
    pub process_injection: u32,
    pub credential_access: u32,
    pub persistence: u32,
    pub network: u32,
    pub crypto: u32,
    pub process_manipulation: u32,
    pub service_control: u32,
    pub registry_autorun: u32,
    pub anti_debugging: u32,
}

pub fn categorize_imports(bytes: &[u8]) -> ImportCategories {
    let mut never_cancel = || Ok(());
    categorize_imports_with_cancellation(bytes, &mut never_cancel)
        .expect("the infallible PE-import callback cannot fail")
}

pub fn categorize_imports_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<ImportCategories> {
    cancellation_checkpoint()?;
    let text = ascii_lowercase_lossy_with_cancellation(bytes, cancellation_checkpoint)?;
    cancellation_checkpoint()?;
    Ok(ImportCategories {
        process_injection: count_import_terms(
            &text,
            &["virtualallocex", "writeprocessmemory", "createremotethread"],
            cancellation_checkpoint,
        )?,
        credential_access: count_import_terms(
            &text,
            &["credread", "lsaenumerate", "samiconnect"],
            cancellation_checkpoint,
        )?,
        persistence: count_import_terms(
            &text,
            &["regsetvalue", "createservice", "taskscheduler"],
            cancellation_checkpoint,
        )?,
        network: count_import_terms(
            &text,
            &["winhttp", "internetopen", "wsastartup", "connect"],
            cancellation_checkpoint,
        )?,
        crypto: count_import_terms(
            &text,
            &["cryptencrypt", "bcrypt", "cryptacquirecontext"],
            cancellation_checkpoint,
        )?,
        process_manipulation: count_import_terms(
            &text,
            &["openprocess", "terminateprocess", "createprocess"],
            cancellation_checkpoint,
        )?,
        service_control: count_import_terms(
            &text,
            &["openscmanager", "controlservice", "startservice"],
            cancellation_checkpoint,
        )?,
        registry_autorun: count_import_terms(
            &text,
            &["currentversion\\run", "runonce"],
            cancellation_checkpoint,
        )?,
        anti_debugging: count_import_terms(
            &text,
            &["isdebuggerpresent", "checkremotedebuggerpresent"],
            cancellation_checkpoint,
        )?,
    })
}

fn count_import_terms(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_archive_static_cancellation_interrupts_pe_import_terms() {
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 5 {
                anyhow::bail!("benign PE import cancellation")
            }
            Ok(())
        };

        let error =
            categorize_imports_with_cancellation(b"MZ ordinary benign bytes", &mut checkpoint)
                .expect_err("PE import cancellation must abort categorization");

        assert!(error.to_string().contains("benign PE import cancellation"));
        assert_eq!(checks, 5);
    }

    #[test]
    fn static_text_normalization_interrupts_pe_import_input_chunks_before_evidence() {
        let bytes =
            vec![b'A'; crate::signatures::text::TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 3 {
                anyhow::bail!("benign PE import normalization cancellation")
            }
            Ok(())
        };

        let error = categorize_imports_with_cancellation(&bytes, &mut checkpoint)
            .expect_err("PE import normalization cancellation must abort before categories");

        assert!(error
            .to_string()
            .contains("benign PE import normalization cancellation"));
        assert_eq!(checks, 3);
    }
}
