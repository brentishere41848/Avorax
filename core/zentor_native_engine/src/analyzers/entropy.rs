use anyhow::Result;

const ENTROPY_CANCELLATION_CHUNK_BYTES: usize = 64 * 1024;

pub fn entropy(bytes: &[u8]) -> f64 {
    let mut never_cancel = || Ok(());
    entropy_with_cancellation(bytes, &mut never_cancel)
        .expect("the infallible entropy callback cannot fail")
}

pub fn entropy_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<f64> {
    if bytes.is_empty() {
        cancellation_checkpoint()?;
        return Ok(0.0);
    }
    let mut counts = [0usize; 256];
    for chunk in bytes.chunks(ENTROPY_CANCELLATION_CHUNK_BYTES) {
        cancellation_checkpoint()?;
        for byte in chunk {
            counts[*byte as usize] += 1;
        }
    }
    let len = bytes.len() as f64;
    let value = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum();
    cancellation_checkpoint()?;
    Ok(value)
}

pub fn mean_entropy(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_archive_static_cancellation_interrupts_entropy_chunks() {
        let bytes = vec![b'a'; ENTROPY_CANCELLATION_CHUNK_BYTES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign entropy cancellation")
            }
            Ok(())
        };

        let error = entropy_with_cancellation(&bytes, &mut checkpoint)
            .expect_err("entropy traversal must propagate cancellation");

        assert!(error.to_string().contains("benign entropy cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn non_archive_static_cancellation_preserves_entropy_wrapper_result() {
        let bytes = b"ordinary benign entropy input";
        let wrapped = entropy(bytes);
        let mut never_cancel = || Ok(());
        let fallible = entropy_with_cancellation(bytes, &mut never_cancel)
            .expect("fallible entropy must pass without cancellation");

        assert_eq!(wrapped, fallible);
    }
}
