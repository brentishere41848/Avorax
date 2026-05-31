# Avorax Offline Malware Model

Avorax uses a local ONNX model for static malware analysis. The production app must never fake AI detections. If `assets/models/zentor_static_malware_model.onnx` is missing, the AI engine reports `Model missing`.

The repository includes a development ONNX model so runtime loading, deterministic inference, and UI behavior are real. It is marked `production_ready=false` and must not auto-quarantine by itself.

The training workflow is offline and developer-controlled:

1. Export local `training_labels.jsonl` files from test machines.
2. Combine labeled static-feature datasets outside the production app.
3. Run `python train_model.py --input labels.jsonl --output build/model`.
4. Evaluate precision, recall, false-positive rate, and the confusion matrix.
5. Export a versioned ONNX model.
6. Place the model in `assets/models/zentor_static_malware_model.onnx`.

Do not commit malware samples to this repository.
