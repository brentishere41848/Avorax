use std::path::Path;

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
    let probability = *outputs[0]
        .to_array_view::<f32>()?
        .iter()
        .next()
        .unwrap_or(&0.0);
    let category_values = outputs[1]
        .to_array_view::<f32>()?
        .iter()
        .copied()
        .collect::<Vec<_>>();
    let categories = CATEGORY_LABELS
        .iter()
        .enumerate()
        .map(|(index, label)| {
            (
                (*label).to_string(),
                category_values.get(index).copied().unwrap_or_default(),
            )
        })
        .collect();
    Ok((probability, categories))
}
