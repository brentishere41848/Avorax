# Avorax Native ML

Avorax Native ML uses feature vectors only. The production app does not train itself, does not download samples, does not execute suspicious files, and does not upload user files.

The checked-in model is a development `.zmodel` used to validate the pure Rust runtime path. It is marked `production_ready: false` and cannot auto-quarantine by itself.

## Workflow

1. Build safe static feature JSONL with `build_features.py`.
2. Train with developer-provided labeled feature data:
   `python train_native_model.py --input path/to/features.jsonl --output out/zentor_native_model.zmodel`
3. Evaluate:
   `python evaluate_native_model.py --model out/zentor_native_model.zmodel --fixtures fixtures/benign_features.jsonl fixtures/suspicious_features.jsonl fixtures/test_threat_features.jsonl`
4. Export only after false-positive gates pass:
   `python export_zmodel.py --model out/zentor_native_model.zmodel --assets ../../assets/zentor_native/ml`

No real malware samples are stored in this repository.

`evaluate_native_model.py` validates the `.zmodel`, feature schema, and benign/positive fixture JSONL files before scoring. It rejects missing or malformed model fields, weights outside the schema, invalid fixture labels/features, non-finite metrics, and unordered thresholds. Sparse fixture rows may omit schema-valid zero-valued features, and the report records that convention explicitly.

`build_features.py` validates generated development rows against the native feature schema and evaluator row rules, requires positive and negative labels, rejects unsafe output targets, and writes JSONL atomically. `train_native_model.py` uses the same feature schema and fixture validation before producing a candidate `.zmodel`; it does not infer the model schema from the first row. `export_pmodel.py` validates model metadata before writing app assets and refuses `production_ready=false` exports unless `--allow-development` is explicitly supplied for a non-production build. Build, train, and export outputs use `native_ml_io.py` for checked non-linked output paths, exclusive UUID temp files, and atomic replacement.
