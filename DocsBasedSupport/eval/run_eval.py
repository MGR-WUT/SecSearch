from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any

from datasets import Dataset
from ragas import evaluate
from ragas.metrics import faithfulness

from app.pipeline.query_agent_v2 import GraphRAGV2Service


@dataclass
class EvalSample:
    question: str
    expected_entities: list[str]
    expected_answer_contains: list[str]


def _load_samples(path: Path) -> list[EvalSample]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [EvalSample(**item) for item in raw]


def _multi_hop_accuracy(samples: list[EvalSample], outputs: list[dict[str, Any]]) -> float:
    if not samples:
        return 0.0
    hits = 0
    for sample, output in zip(samples, outputs):
        edges = output.get("evidence_path", [])
        names = {edge["source"] for edge in edges} | {edge["target"] for edge in edges}
        if all(entity in names for entity in sample.expected_entities):
            hits += 1
    return hits / len(samples)


def _latency_stats(latencies: list[float], token_counts: list[int]) -> dict[str, float]:
    avg_latency = mean(latencies) if latencies else 0.0
    total_tokens = sum(token_counts)
    total_time = sum(latencies)
    tps = total_tokens / total_time if total_time else 0.0
    return {"avg_latency_seconds": avg_latency, "tokens_per_second_estimate": tps}


def _ragas_faithfulness(samples: list[EvalSample], outputs: list[dict[str, Any]]) -> float:
    dataset = Dataset.from_dict(
        {
            "question": [s.question for s in samples],
            "answer": [o["answer"] for o in outputs],
            "contexts": [[c["snippet"] or "" for c in o.get("citations", [])] for o in outputs],
            "ground_truth": [
                " ".join(sample.expected_answer_contains) if sample.expected_answer_contains else ""
                for sample in samples
            ],
        }
    )
    result = evaluate(dataset, metrics=[faithfulness])
    return float(result["faithfulness"])


def run(query_agent: GraphRAGV2Service, dataset_path: Path, output_path: Path) -> dict[str, Any]:
    samples = _load_samples(dataset_path)
    outputs: list[dict[str, Any]] = []
    latencies: list[float] = []
    token_counts: list[int] = []

    for sample in samples:
        start = time.perf_counter()
        response = query_agent.answer(sample.question)
        elapsed = time.perf_counter() - start
        latencies.append(elapsed)
        token_counts.append(len(response.answer.split()))
        outputs.append(response.model_dump())

    multihop = _multi_hop_accuracy(samples, outputs)

    faithfulness_score = _ragas_faithfulness(samples, outputs)

    report = {
        "multi_hop_accuracy": multihop,
        "faithfulness_ragas": faithfulness_score,
        "latency": _latency_stats(latencies, token_counts),
        "samples": outputs,
    }
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    raise SystemExit(
        "Instantiate GraphRAGV2Service from app context and call run(...) from a service-aware script. "
        "This CLI keeps eval utilities isolated from runtime dependency injection."
    )


if __name__ == "__main__":
    main()

