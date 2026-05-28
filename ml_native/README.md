# Pasus Native ML

Pasus Native ML uses feature vectors only. The production app does not train itself, does not download samples, does not execute suspicious files, and does not upload user files.

The checked-in model is a development `.pmodel` used to validate the pure Rust runtime path. It is marked `production_ready: false` and cannot auto-quarantine by itself.

## Workflow

1. Build safe static feature JSONL with `build_features.py`.
2. Train with developer-provided labeled feature data:
   `python train_native_model.py --input path/to/features.jsonl --output out/pasus_native_model.pmodel`
3. Evaluate:
   `python evaluate_native_model.py --model out/pasus_native_model.pmodel --fixtures fixtures/benign_features.jsonl`
4. Export only after false-positive gates pass:
   `python export_pmodel.py --model out/pasus_native_model.pmodel --assets ../../assets/pasus_native/ml`

No real malware samples are stored in this repository.
