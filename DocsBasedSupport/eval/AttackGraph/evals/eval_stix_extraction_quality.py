"""Score LLM-extracted USES edges against deterministic STIX gold."""

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
from eval.AttackGraph.lib.graph_constants import (  # noqa: E402
    GRAPH_VARIANT_STIX,
    USES_EXTRACTED_REL,
    is_llm_extracted_variant,
)

DEFAULT_REPORT_FILENAME = "extraction_quality.json"
DEFAULT_CORPUS_FILENAME = "stix_actor_corpus.json"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph-variant", required=True, help="llm-extracted:<model> variant to score.")
    parser.add_argument("--corpus-path", type=Path, default=None)
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _prf(predicted: set[tuple[str, str]], gold: set[tuple[str, str]]) -> dict[str, float]:
    if not gold and not predicted:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "support": 0}
    tp = len(predicted & gold)
    fp = len(predicted - gold)
    fn = len(gold - predicted)
    precision = tp / len(predicted) if predicted else 0.0
    recall = tp / len(gold) if gold else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "support": len(gold),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
    }


def _gold_from_corpus(corpus_path: Path) -> set[tuple[str, str]]:
    payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    pairs: set[tuple[str, str]] = set()
    for doc in payload.get("documents", []):
        actor_id = doc.get("actor_entity_id")
        for pair in doc.get("gold_pairs", []):
            technique_id = pair.get("technique_id")
            if actor_id and technique_id:
                pairs.add((str(actor_id), str(technique_id)))
    return pairs


def _fetch_predicted(store: Neo4jStore, graph_variant: str) -> set[tuple[str, str]]:
    rows = store.run_read(
        f"""
        MATCH (a:ThreatActor)-[r:{USES_EXTRACTED_REL}]->(t:Technique)
        WHERE r.graph_variant = $variant
        RETURN a.entity_id AS actor_id, t.entity_id AS technique_id
        """,
        variant=graph_variant,
    )
    return {
        (str(row["actor_id"]), str(row["technique_id"]))
        for row in rows
        if row.get("actor_id") and row.get("technique_id")
    }


def _fetch_stix_gold(store: Neo4jStore) -> set[tuple[str, str]]:
    rows = store.run_read(
        """
        MATCH (a:ThreatActor)-[r:USES]->(t:Technique)
        WHERE r.graph_variant IS NULL OR r.graph_variant = $stix
        RETURN a.entity_id AS actor_id, t.entity_id AS technique_id
        """,
        stix=GRAPH_VARIANT_STIX,
    )
    return {
        (str(row["actor_id"]), str(row["technique_id"]))
        for row in rows
        if row.get("actor_id") and row.get("technique_id")
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    if not is_llm_extracted_variant(args.graph_variant):
        raise SystemExit("--graph-variant must start with llm-extracted:")

    run_dir = resolve_run_dir(args.run_dir, default_hint="stix-extraction-quality")
    corpus_path = args.corpus_path or (run_dir / DEFAULT_CORPUS_FILENAME)

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        predicted = _fetch_predicted(store, args.graph_variant)
        if corpus_path.exists():
            gold_full = _gold_from_corpus(corpus_path)
            actor_ids = {a for a, _ in gold_full}
            gold_corpus = gold_full
            gold_global = _fetch_stix_gold(store)
            gold_global_restricted = {(a, t) for a, t in gold_global if a in actor_ids}
        else:
            gold_corpus = _fetch_stix_gold(store)
            gold_global_restricted = gold_corpus
            logging.warning("Corpus not found at %s; using full STIX gold.", corpus_path)

        actors_pred = {a for a, _ in predicted}
        techniques_pred = {t for _, t in predicted}

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "graph_variant": args.graph_variant,
                "corpus_path": str(corpus_path) if corpus_path.exists() else None,
            },
            "counts": {
                "predicted_uses_edges": len(predicted),
                "predicted_actors": len(actors_pred),
                "predicted_techniques": len(techniques_pred),
                "gold_pairs_corpus": len(gold_corpus),
                "gold_pairs_stix_restricted": len(gold_global_restricted),
            },
            "actor_technique_pairs_vs_corpus_gold": _prf(predicted, gold_corpus),
            "actor_technique_pairs_vs_stix_gold": _prf(predicted, gold_global_restricted),
        }
        report_path = resolve_report_path(None, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        append_run_card(
            run_dir,
            script="eval_stix_extraction_quality.py",
            config=report["config"],
            output_files=[report_path],
        )
        print(json.dumps(report, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
