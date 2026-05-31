"""CLI: run LLM-based description enrichment over the loaded ATT&CK subgraph.

Typical workflow:

  RUN_DIR=eval/AttackGraph/runs/2026-05-31_baseline
  RUN_DIR_ENRICHED=eval/AttackGraph/runs/2026-05-31_enriched_gemma3-4b

  # 1. baseline path report (in the baseline run folder)
  PYTHONPATH=. python eval/AttackGraph/eval_cve_apt.py --run-dir $RUN_DIR --variant baseline

  # 2. ask the LLM to extract any CVEs mentioned in entity descriptions
  PYTHONPATH=. python eval/AttackGraph/enrich_with_llm.py \\
      --labels ThreatActor Malware Tool Campaign --run-dir $RUN_DIR_ENRICHED

  # 3. recompute PageRank / Louvain over the now-enriched graph
  PYTHONPATH=. python eval/AttackGraph/load_attack.py --enrich --run-dir $RUN_DIR_ENRICHED

  # 4. enriched path report -- compare with step 1 in the thesis text
  PYTHONPATH=. python eval/AttackGraph/eval_cve_apt.py --run-dir $RUN_DIR_ENRICHED --variant enriched

The LLM model is taken from settings.yaml (``llm_extract_model`` by default).
Use ``--model`` to override on the CLI without touching the YAML.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.core.llm_factory import build_chat_llm  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from app.pipeline.attack_enrichment import AttackDescriptionEnricher  # noqa: E402
from eval.AttackGraph._run_utils import (  # noqa: E402
    append_run_card,
    resolve_report_path,
    resolve_run_dir,
)

DEFAULT_REPORT_FILENAME = "llm_enrichment.json"
DEFAULT_LABELS = ("ThreatActor", "Malware", "Tool", "Campaign")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--labels",
        nargs="+",
        default=list(DEFAULT_LABELS),
        help="ATT&CK labels to enrich (default: ThreatActor Malware Tool Campaign).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional cap on entities to send to the LLM (useful for smoke tests).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-enrich entities even if they already have llm_enriched_at set.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override llm_extract_model from settings.yaml.",
    )
    parser.add_argument(
        "--source-id",
        default="mitre-attack:enterprise",
        help="Source id used when creating new CVE nodes.",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help=(
            "Run directory for tracked outputs (defaults to "
            "eval/AttackGraph/runs/enrichment-<UTC timestamp>)."
        ),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=None,
        help="Explicit override for the report path. Wins over --run-dir.",
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _fetch_entities(
    store: Neo4jStore, labels: list[str], limit: int | None, force: bool
) -> list[dict[str, object]]:
    label_clause = " OR ".join(f"n:`{lbl}`" for lbl in labels)
    where_extra = "" if force else "AND n.llm_enriched_at IS NULL"
    limit_clause = f"LIMIT {int(limit)}" if limit else ""
    query = f"""
    MATCH (n:AttackEntity)
    WHERE ({label_clause})
      AND n.description IS NOT NULL AND trim(n.description) <> ''
      {where_extra}
    RETURN n.entity_id AS entity_id,
           n.name AS name,
           [lbl IN labels(n) WHERE lbl <> 'Entity' AND lbl <> 'AttackEntity'][0] AS primary_label,
           n.external_id AS external_id,
           n.description AS description,
           n.llm_enriched_at AS llm_enriched_at
    ORDER BY n.entity_id
    {limit_clause}
    """
    return store.run_read(query)


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    settings = get_settings()
    model_name = args.model or settings.llm_extract_model
    if not model_name:
        raise SystemExit(
            "No LLM model configured. Set llm_extract_model in settings.yaml or pass --model."
        )

    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        entities = _fetch_entities(store, args.labels, args.limit, args.force)
        logging.info(
            "Fetched %d AttackEntity nodes to enrich (labels=%s, force=%s, limit=%s).",
            len(entities),
            args.labels,
            args.force,
            args.limit,
        )
        if not entities:
            print(json.dumps({"processed": 0, "reason": "nothing-to-do"}, indent=2))
            return 0
        llm = build_chat_llm(
            provider=settings.llm_provider,
            model=model_name,
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
        )
        enricher = AttackDescriptionEnricher(
            graph_store=store,
            llm=llm,
            model_name=model_name,
            source_id=args.source_id,
            provider_tag=f"{settings.llm_provider}",
        )
        summary = enricher.enrich(entities, force=args.force)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "labels": args.labels,
                "limit": args.limit,
                "force": bool(args.force),
                "model": model_name,
                "provider": settings.llm_provider,
                "source_id": args.source_id,
            },
            "summary": summary.as_dict(),
            "per_entity": [
                {
                    "entity_id": r.entity_id,
                    "new_cve_nodes": r.new_cve_nodes,
                    "new_exploits_edges": r.new_exploits_edges,
                    "new_attribution_edges": r.new_attribution_edges,
                    "extracted_count": r.extracted_count,
                    "extracted_actor_count": r.extracted_actor_count,
                    "dropped_unquoted": r.dropped_unquoted,
                    "dropped_unmatched_actors": r.dropped_unmatched_actors,
                    "parse_failed": r.parse_failed,
                }
                for r in summary.per_entity
            ],
        }
        run_dir = resolve_run_dir(args.run_dir, default_hint="enrichment")
        report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logging.info("Wrote enrichment report -> %s", report_path)
        append_run_card(
            run_dir,
            script="enrich_with_llm.py",
            config={
                "labels": args.labels,
                "limit": args.limit,
                "force": bool(args.force),
                "provider": settings.llm_provider,
                "model": model_name,
                "source_id": args.source_id,
                "processed_entities": summary.processed_entities,
                "new_cve_nodes": summary.new_cve_nodes,
                "new_exploits_edges": summary.new_exploits_edges,
                "new_attribution_edges": summary.new_attribution_edges,
                "dropped_unquoted": summary.dropped_unquoted,
                "dropped_unmatched_actors": summary.dropped_unmatched_actors,
                "parse_failures": summary.parse_failures,
            },
            output_files=[report_path],
        )
        print(json.dumps(summary.as_dict(), indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
