"""Score LLM-extracted CVE→actor EXPLOITS edges against CTI gold (non-circular)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from eval.AttackGraph.lib._run_utils import append_run_card, resolve_report_path, resolve_run_dir  # noqa: E402

DEFAULT_CORPUS_FILENAME = "cti_cve_actor_corpus.json"
DEFAULT_REPORT_FILENAME = "cti_cve_extraction_quality.json"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extraction-variant", required=True)
    parser.add_argument("--corpus-path", type=Path, default=None)
    parser.add_argument("--narrative-gold-only", action="store_true", default=True)
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _prf(predicted: set[tuple[str, str]], gold: set[tuple[str, str]]) -> dict[str, float | int]:
    if not gold and not predicted:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "support": 0}
    tp = len(predicted & gold)
    precision = tp / len(predicted) if predicted else 0.0
    recall = tp / len(gold) if gold else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "support": len(gold),
        "true_positives": tp,
        "false_positives": len(predicted - gold),
        "false_negatives": len(gold - predicted),
    }


def _gold_from_corpus(
    corpus_path: Path,
    *,
    narrative_only: bool,
) -> set[tuple[str, str]]:
    payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    pairs: set[tuple[str, str]] = set()
    for doc in payload.get("documents", []):
        actor_id = doc.get("actor_entity_id")
        if not actor_id:
            continue
        for edge in doc.get("gold_cves", []):
            if narrative_only and not edge.get("in_narrative"):
                continue
            cve_entity_id = edge.get("cve_entity_id")
            if cve_entity_id:
                pairs.add((str(actor_id), str(cve_entity_id)))
    return pairs


def _fetch_predicted(store: Neo4jStore, extraction_variant: str) -> set[tuple[str, str]]:
    rows = store.run_read(
        """
        MATCH (a:ThreatActor)-[r:EXPLOITS]->(c:CVE)
        WHERE r.extraction_variant = $variant
        RETURN a.entity_id AS actor_id, c.entity_id AS cve_id
        """,
        variant=extraction_variant,
    )
    return {
        (str(row["actor_id"]), str(row["cve_id"]))
        for row in rows
        if row.get("actor_id") and row.get("cve_id")
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    run_dir = resolve_run_dir(args.run_dir, default_hint="cti-cve-quality")
    corpus_path = args.corpus_path or (run_dir / DEFAULT_CORPUS_FILENAME)

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        gold_narrative = _gold_from_corpus(corpus_path, narrative_only=True)
        gold_all = _gold_from_corpus(corpus_path, narrative_only=False)
        predicted = _fetch_predicted(store, args.extraction_variant)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "extraction_variant": args.extraction_variant,
                "corpus_path": str(corpus_path),
                "narrative_gold_only_primary": bool(args.narrative_gold_only),
            },
            "counts": {
                "predicted_exploit_edges": len(predicted),
                "gold_pairs_all_structured": len(gold_all),
                "gold_pairs_in_narrative": len(gold_narrative),
            },
            "actor_cve_pairs_vs_narrative_gold": _prf(predicted, gold_narrative),
            "actor_cve_pairs_vs_all_structured_gold": _prf(predicted, gold_all),
        }
        report_path = resolve_report_path(None, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        append_run_card(
            run_dir,
            script="eval_cti_cve_extraction_quality.py",
            config=report["config"],
            output_files=[report_path],
        )
        print(json.dumps(report, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
