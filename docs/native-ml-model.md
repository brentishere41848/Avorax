# Avorax Native ML Model

ANE uses a Avorax-owned `.zmodel` format for local ML inference. The runtime is pure Rust and deterministic.

The checked-in model is:

- `assets/zentor_native/ml/zentor_native_model.zmodel`
- version `0.1.0-dev`
- `production_ready: false`

Development ML can participate in explanations and review verdicts, but it cannot auto-quarantine by itself. A production model requires real feature datasets, false-positive evaluation, metrics, metadata, and release-gate approval. No malware samples are stored in this repository.

Runtime `.zmodel` JSON is treated as an untrusted engine asset. The native model runner rejects model files larger than 256 KiB before JSON parsing.
