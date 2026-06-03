"""Build MISP+ETDA CVE→actor gold corpus (no graph writes)."""

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
from eval.AttackGraph.lib.cti_cve_sources import (  # noqa: E402
    build_actor_catalog,
    build_cti_cve_reports,
    reports_to_corpus_payload,
)

DEFAULT_CORPUS_FILENAME = "cti_cve_actor_corpus.json"
DEFAULT_SUMMARY_FILENAME = "cti_cve_corpus_summary.json"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--narrative-gold-only", action="store_true", help="Summarize narrative-only gold subset.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    run_dir = resolve_run_dir(args.run_dir, default_hint="cti-cve-corpus")

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        rows = store.run_read(
            """
            MATCH (a:ThreatActor)
            RETURN a.entity_id AS entity_id, a.name AS name, a.aliases AS aliases
            """
        )
        catalog = build_actor_catalog(rows)
        reports = build_cti_cve_reports(catalog)
        payload = reports_to_corpus_payload(reports)

        matched = sum(1 for d in payload["documents"] if d.get("matched_attack"))
        narrative_pairs = payload["num_gold_pairs_in_narrative"]
        summary = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "counts": {
                "num_actors": payload["num_actors"],
                "num_gold_pairs": payload["num_gold_pairs"],
                "num_gold_pairs_in_narrative": narrative_pairs,
                "num_distinct_cves": payload["num_distinct_cves"],
                "actors_matched_attack": matched,
                "actors_cti_only": payload["num_actors"] - matched,
            },
            "interpretation": (
                "Gold pairs come from structured CTI cards (MISP galaxy + ETDA). "
                "LLM extraction runs on narrative text only; scoring should use "
                "num_gold_pairs_in_narrative for a fair prose-recovery benchmark."
            ),
        }
        corpus_path = run_dir / DEFAULT_CORPUS_FILENAME
        corpus_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        summary_path = resolve_report_path(None, run_dir, DEFAULT_SUMMARY_FILENAME)
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        append_run_card(
            run_dir,
            script="build_cti_cve_corpus.py",
            config={"narrative_gold_only": bool(args.narrative_gold_only)},
            output_files=[corpus_path, summary_path],
        )
        print(json.dumps(summary, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
