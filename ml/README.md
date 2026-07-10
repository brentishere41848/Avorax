# Avorax Offline Malware Model

Avorax uses a local ONNX model for static malware analysis. The production app must never fake AI detections. If `assets/models/zentor_static_malware_model.onnx` is missing, the AI engine reports `Model missing`.

The repository includes a development ONNX model so runtime loading, deterministic inference, and UI behavior are real. It is marked `production_ready=false` and must not auto-quarantine by itself.

The training workflow is offline and developer-controlled:

1. Export local `training_labels.jsonl` files from test machines.
2. Combine labeled static-feature datasets outside the production app.
3. Create a local Python environment and install the pinned tooling from `requirements.txt`.
4. Run `python build_features.py --input labels.jsonl --output build/features.jsonl` to bounded-read JSONL rows and validate every `extracted_features` object against `feature_schema.json`.
5. Run `python train_model.py --input build/features.jsonl --output build/model`. This script validates labels, feature schema ownership, minimum records, and class balance, then writes a development-only training summary. It does not fit or export a production classifier.
6. Evaluate precision, recall, false-positive rate, threshold ordering, validation sample count, and production-readiness metadata with `python evaluate_model.py --metadata path/to/model_metadata.json`.
7. Export a versioned ONNX model with explicit release evidence. `--production-ready` requires a dataset name, positive train/validation sample counts, and acceptable false-positive, precision, and recall metrics; otherwise the exporter refuses to mark metadata as production-ready.
8. Place the model in `assets/models/zentor_static_malware_model.onnx`.

The ML requirements are pinned and license-noted in `docs/dependency-license-inventory.md`. Do not replace them with unpinned packages or weekly/nightly packages in release branches.

Do not commit malware samples to this repository.

`evaluate_model.py` is a release metadata validator, not a malware test harness. It reads bounded regular JSON metadata, rejects missing or non-finite metrics, keeps `production_ready=false` as `development_blocked`, and only treats `--allow-development` as an explicit non-production override while preserving `ok: false` in the report.

`build_features.py` and `train_model.py` are offline development tools. They reject linked/reparse/non-regular inputs, oversized JSON/JSONL rows, unknown feature names, malformed feature values, unsupported labels, unsafe output targets, and empty datasets. `train_model.py` also requires positive and negative supervised labels before writing a development-only metadata summary. Static ML output helpers use exclusive UUID temp files, fsynced JSON/JSONL/ONNX-byte writes, and atomic replacement.
