# AI Engine

Avorax local AI runs offline through the Rust local core and packaged ONNX assets.

Release gates:

- `assets/models/zentor_static_malware_model.onnx` must exist.
- `assets/models/zentor_static_malware_model.metadata.json` must exist.
- Metadata must parse and thresholds must exist.
- UI may say `Local AI Active` only when the model loads and inference self-test passes.

The current bundled model is marked `production_ready=false`. It proves runtime loading and deterministic inference, but it cannot auto-quarantine by itself and must be shown as a development model.

Training happens only through `ml/` scripts. The app does not retrain itself silently.
