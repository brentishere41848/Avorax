use std::path::Path;

use anyhow::Context;
use tract_onnx::prelude::*;

use super::thresholds::{CATEGORY_LABELS, FEATURE_COUNT};

pub fn run_static_model(
    model_path: &Path,
    features: &[f32; FEATURE_COUNT],
) -> anyhow::Result<(f32, Vec<(String, f32)>)> {
    let model = tract_onnx::onnx()
        .model_for_path(model_path)?
        .with_input_fact(0, f32::fact([1, FEATURE_COUNT]).into())?
        .into_optimized()?
        .into_runnable()?;
    let input = tract_ndarray::Array2::from_shape_vec((1, FEATURE_COUNT), features.to_vec())?;
    let outputs = model.run(tvec!(input.into_tensor().into()))?;
    let probability = outputs
        .first()
        .context("ONNX model did not return malware probability output")?
        .to_array_view::<f32>()?
        .iter()
        .next()
        .copied()
        .context("ONNX malware probability output was empty")?;
    anyhow::ensure!(
        probability.is_finite() && (0.0..=1.0).contains(&probability),
        "ONNX malware probability output must be finite and between 0 and 1"
    );
    let category_values = outputs
        .get(1)
        .context("ONNX model did not return category score output")?
        .to_array_view::<f32>()?
        .iter()
        .copied()
        .collect::<Vec<_>>();
    anyhow::ensure!(
        category_values.len() >= CATEGORY_LABELS.len(),
        "ONNX category score output has {} value(s), expected at least {}",
        category_values.len(),
        CATEGORY_LABELS.len()
    );
    for (index, value) in category_values
        .iter()
        .take(CATEGORY_LABELS.len())
        .enumerate()
    {
        anyhow::ensure!(
            value.is_finite() && (0.0..=1.0).contains(value),
            "ONNX category score output at index {index} must be finite and between 0 and 1"
        );
    }
    let categories = CATEGORY_LABELS
        .iter()
        .enumerate()
        .map(|(index, label)| ((*label).to_string(), category_values[index]))
        .collect();
    Ok((probability, categories))
}

#[cfg(test)]
mod tests {
    #[test]
    fn onnx_runtime_does_not_default_missing_outputs_to_clean_scores() {
        let source = include_str!("onnx_runtime.rs");
        let production_source = source
            .split_once("#[cfg(test)]")
            .map(|(production, _)| production)
            .expect("test module marker");

        assert!(production_source.contains("ONNX model did not return malware probability output"));
        assert!(production_source.contains("ONNX malware probability output was empty"));
        assert!(production_source.contains("ONNX category score output has"));
        assert!(production_source.contains("must be finite and between 0 and 1"));
        assert!(production_source.contains(
            "ONNX category score output at index {index} must be finite and between 0 and 1"
        ));
        assert!(!production_source.contains(".unwrap_or(&0.0)"));
        assert!(!production_source.contains(".unwrap_or_default()"));
    }

    #[test]
    fn onnx_runtime_category_scores_stay_unit_bounded() {
        let source = include_str!("onnx_runtime.rs");
        let production_source = source
            .split_once("#[cfg(test)]")
            .map(|(production, _)| production)
            .expect("test module marker");

        assert!(production_source.contains("value.is_finite() && (0.0..=1.0).contains(value)"));
        assert!(production_source.contains(
            "ONNX category score output at index {index} must be finite and between 0 and 1"
        ));
    }
}
