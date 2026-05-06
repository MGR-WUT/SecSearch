from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def export_predictions_for_wildgraphbench(samples: list[dict[str, Any]], output_path: Path) -> None:
    """Write predictions in a simple JSONL format suitable for external benchmark tooling."""
    lines = []
    for sample in samples:
        lines.append(
            json.dumps(
                {
                    "id": sample.get("id"),
                    "question": sample.get("question"),
                    "prediction": sample.get("answer"),
                    "evidence_path": sample.get("evidence_path", []),
                    "citations": sample.get("citations", []),
                },
                ensure_ascii=True,
            )
        )
    output_path.write_text("\n".join(lines), encoding="utf-8")


def compare_with_sota(local_report_path: Path, sota_reference_path: Path) -> dict[str, Any]:
    """
    Compare local model metrics against larger SOTA model references.
    Expected reference file structure:
    {"models":[{"name":"...", "multi_hop_accuracy":0.0, "faithfulness_ragas":0.0}]}
    """
    local = json.loads(local_report_path.read_text(encoding="utf-8"))
    sota = json.loads(sota_reference_path.read_text(encoding="utf-8"))

    comparisons = []
    for model in sota.get("models", []):
        comparisons.append(
            {
                "model": model.get("name"),
                "multi_hop_gap": local.get("multi_hop_accuracy", 0.0) - model.get("multi_hop_accuracy", 0.0),
                "faithfulness_gap": local.get("faithfulness_ragas", 0.0) - model.get("faithfulness_ragas", 0.0),
            }
        )
    return {"local": local, "comparisons": comparisons}

