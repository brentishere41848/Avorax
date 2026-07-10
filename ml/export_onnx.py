#!/usr/bin/env python3
"""Export the conservative Avorax static-feature model to ONNX."""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path

from static_ml_schema import checked_output_dir, write_bytes_atomic, write_json_atomic


@dataclass(frozen=True)
class ProductionEvidence:
    training_dataset_name: str
    training_sample_count: int
    validation_sample_count: int
    false_positive_rate: float
    precision: float
    recall: float


def finite_unit(value: float, name: str) -> float:
    if not math.isfinite(value) or value < 0.0 or value > 1.0:
        raise SystemExit(f"{name} must be a finite number between 0 and 1.")
    return value


def positive_int(value: int, name: str) -> int:
    if value <= 0:
        raise SystemExit(f"{name} must be a positive integer.")
    return value


def production_evidence_from_args(args: argparse.Namespace) -> ProductionEvidence | None:
    if not args.production_ready:
        return None

    missing = [
        name
        for name in (
            "training_dataset_name",
            "training_sample_count",
            "validation_sample_count",
            "false_positive_rate",
            "precision",
            "recall",
        )
        if getattr(args, name) is None
    ]
    if missing:
        raise SystemExit(
            "Production-ready export requires explicit evidence fields: "
            + ", ".join(missing)
        )

    dataset = args.training_dataset_name.strip()
    if not dataset:
        raise SystemExit("training-dataset-name must not be blank.")
    evidence = ProductionEvidence(
        training_dataset_name=dataset,
        training_sample_count=positive_int(
            args.training_sample_count, "training-sample-count"
        ),
        validation_sample_count=positive_int(
            args.validation_sample_count, "validation-sample-count"
        ),
        false_positive_rate=finite_unit(
            args.false_positive_rate, "false-positive-rate"
        ),
        precision=finite_unit(args.precision, "precision"),
        recall=finite_unit(args.recall, "recall"),
    )
    if evidence.false_positive_rate > args.max_fpr:
        raise SystemExit(
            f"false-positive-rate {evidence.false_positive_rate:.6f} exceeds {args.max_fpr:.6f}."
        )
    if evidence.precision < args.min_precision:
        raise SystemExit(
            f"precision {evidence.precision:.6f} is below {args.min_precision:.6f}."
        )
    if evidence.recall < args.min_recall:
        raise SystemExit(f"recall {evidence.recall:.6f} is below {args.min_recall:.6f}.")
    return evidence


def export(output_dir: Path, production_evidence: ProductionEvidence | None = None) -> None:
    import numpy as np
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    output_dir = checked_output_dir(output_dir)
    production_ready = production_evidence is not None
    feature_count = 18
    w_prob = np.array(
        [
            0.10,
            0.03,
            0.12,
            0.05,
            0.03,
            0.08,
            0.18,
            -0.08,
            -0.05,
            0.45,
            0.25,
            0.10,
            0.10,
            0.55,
            0.20,
            0.22,
            0.16,
            0.20,
        ],
        dtype=np.float32,
    ).reshape(feature_count, 1)
    b_prob = np.array([-1.55], dtype=np.float32)
    w_cat = np.zeros((feature_count, 9), dtype=np.float32)
    w_cat[:, 8] = 0.05
    w_cat[9, 0] = 0.8
    w_cat[13, 2] = 0.9
    w_cat[15, 2] = 0.5
    w_cat[14, 0] = 0.3
    w_cat[6, 7] = 0.4
    w_cat[17, 0] = 0.4
    b_cat = np.array(
        [0.05, -0.1, 0.0, -0.2, -0.25, -0.2, -0.2, 0.0, 0.1],
        dtype=np.float32,
    )

    graph = helper.make_graph(
        [
            helper.make_node("Gemm", ["features", "W_prob", "B_prob"], ["prob_logits"]),
            helper.make_node("Sigmoid", ["prob_logits"], ["malware_probability"]),
            helper.make_node("Gemm", ["features", "W_cat", "B_cat"], ["category_logits"]),
            helper.make_node("Softmax", ["category_logits"], ["category_scores"], axis=1),
        ],
        "zentor_static_malware_model",
        [helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, feature_count])],
        [
            helper.make_tensor_value_info("malware_probability", TensorProto.FLOAT, [1, 1]),
            helper.make_tensor_value_info("category_scores", TensorProto.FLOAT, [1, 9]),
        ],
        [
            numpy_helper.from_array(w_prob, "W_prob"),
            numpy_helper.from_array(b_prob, "B_prob"),
            numpy_helper.from_array(w_cat, "W_cat"),
            numpy_helper.from_array(b_cat, "B_cat"),
        ],
    )
    model = helper.make_model(
        graph,
        producer_name="avorax-export-onnx",
        opset_imports=[helper.make_operatorsetid("", 13)],
    )
    model.ir_version = 7
    onnx.checker.check_model(model)
    onnx_path = output_dir / "zentor_static_malware_model.onnx"
    write_bytes_atomic(onnx_path, model.SerializeToString())

    metadata = {
        "model_name": "zentor_static_malware_model",
        "model_version": "0.1.0-dev" if not production_ready else "1.0.0",
        "model_type": "static_feature_logistic_onnx",
        "feature_schema_version": "1.0.0",
        "trained_at": "2026-05-26T00:00:00Z",
        "production_ready": production_ready,
        "training_dataset_name": (
            "zentor-development-fixtures"
            if production_evidence is None
            else production_evidence.training_dataset_name
        ),
        "training_sample_count": (
            12 if production_evidence is None else production_evidence.training_sample_count
        ),
        "validation_sample_count": (
            6 if production_evidence is None else production_evidence.validation_sample_count
        ),
        "false_positive_rate": (
            None if production_evidence is None else production_evidence.false_positive_rate
        ),
        "precision": None if production_evidence is None else production_evidence.precision,
        "recall": None if production_evidence is None else production_evidence.recall,
        "thresholds": {
            "suspicious": 0.72,
            "probable_malware": 0.90,
            "confirmed_malware": 0.995,
        },
        "supported_categories": [
            "trojan",
            "ransomware",
            "spyware",
            "adware",
            "worm",
            "keylogger",
            "miner",
            "potentially_unwanted_app",
            "unknown",
        ],
        "limitations": (
            ["Development model; not trained on a production malware corpus."]
            if production_evidence is None
            else []
        ),
    }
    write_json_atomic(output_dir / "zentor_static_malware_model.metadata.json", metadata)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="assets/models")
    parser.add_argument("--production-ready", action="store_true")
    parser.add_argument("--training-dataset-name")
    parser.add_argument("--training-sample-count", type=int)
    parser.add_argument("--validation-sample-count", type=int)
    parser.add_argument("--false-positive-rate", type=float)
    parser.add_argument("--precision", type=float)
    parser.add_argument("--recall", type=float)
    parser.add_argument("--max-fpr", type=float, default=0.005)
    parser.add_argument("--min-precision", type=float, default=0.98)
    parser.add_argument("--min-recall", type=float, default=0.90)
    args = parser.parse_args()
    for name in ("max_fpr", "min_precision", "min_recall"):
        finite_unit(getattr(args, name), name.replace("_", "-"))
    production_evidence = production_evidence_from_args(args)
    export(Path(args.output_dir), production_evidence)


if __name__ == "__main__":
    main()
