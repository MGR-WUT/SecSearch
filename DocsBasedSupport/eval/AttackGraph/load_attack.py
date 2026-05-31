"""CLI: download and load MITRE ATT&CK Enterprise into the GraphoDynamo Neo4j.

Usage:

    PYTHONPATH=. python eval/AttackGraph/load_attack.py \\
        --bundle-path data/ontologies/mitre_attack/enterprise-attack.json \\
        --enrich --reset

If --bundle-path does not exist, the script downloads the official STIX 2.1
bundle from the MITRE ``cti`` repository and stores it at that path so
subsequent runs are offline. Defaults respect the local-only privacy posture
of GraphoDynamo (no remote LLM call is ever made; only a static GitHub
download).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import urllib.request
from pathlib import Path

# Allow `python eval/AttackGraph/load_attack.py` from the project root without
# requiring PYTHONPATH=. — convenient when invoking via cron/CI.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from app.pipeline.attack_loader import (  # noqa: E402
    ATTACK_SOURCE_ID,
    ATTACK_SOURCE_URI,
    STIX_TYPE_TO_LABEL,
    AttackLoader,
)
from eval.AttackGraph._run_utils import (  # noqa: E402
    append_run_card,
    resolve_report_path,
    resolve_run_dir,
)

DEFAULT_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_BUNDLE_PATH = (
    PROJECT_ROOT / "data" / "ontologies" / "mitre_attack" / "enterprise-attack.json"
)
DEFAULT_REPORT_FILENAME = "load_summary.json"

ATTACK_SUBGRAPH_LABELS = list({*STIX_TYPE_TO_LABEL.values(), "CVE"})
ATTACK_SUBGRAPH_RELATIONS = [
    "USES",
    "MITIGATES",
    "SUBTECHNIQUE_OF",
    "ATTRIBUTED_TO",
    "TARGETS",
    "EXPLOITS",
    "IN_TACTIC",
]


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--bundle-path",
        type=Path,
        default=DEFAULT_BUNDLE_PATH,
        help="Local path to the STIX 2.1 bundle. Downloaded on demand if missing.",
    )
    parser.add_argument(
        "--bundle-url",
        default=DEFAULT_BUNDLE_URL,
        help="URL to download the STIX 2.1 bundle from if --bundle-path is missing.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Detach-delete the existing MITRE ATT&CK Source subgraph before reloading.",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Run PageRank + Louvain over the ATT&CK subgraph after loading.",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help=(
            "Run directory for tracked outputs (defaults to "
            "eval/AttackGraph/runs/load-<UTC timestamp>). Pass the same value to "
            "all AttackGraph scripts to group them under one run."
        ),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=None,
        help="Explicit override for the report path. Wins over --run-dir.",
    )
    parser.add_argument(
        "--source-id",
        default=ATTACK_SOURCE_ID,
        help="Stable Source id to write into Neo4j; reset/re-load is keyed on this id.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def _ensure_bundle(bundle_path: Path, bundle_url: str) -> Path:
    if bundle_path.exists():
        return bundle_path
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    logging.info("Downloading STIX bundle from %s -> %s", bundle_url, bundle_path)
    with urllib.request.urlopen(bundle_url, timeout=120) as response:  # noqa: S310 - static GitHub URL
        bundle_path.write_bytes(response.read())
    return bundle_path


def _summary_after_load(store: Neo4jStore) -> dict[str, object]:
    """Snapshot per-label / per-relation counts directly from Neo4j after ingestion."""
    label_counts = store.run_read(
        """
        UNWIND $labels AS lbl
        CALL apoc.cypher.run('MATCH (n:`' + lbl + '`) RETURN count(n) AS c', {}) YIELD value
        RETURN lbl AS label, value.c AS count
        """,
        labels=ATTACK_SUBGRAPH_LABELS,
    )
    rel_counts = store.run_read(
        """
        UNWIND $types AS rt
        CALL apoc.cypher.run('MATCH ()-[r:`' + rt + '`]->() RETURN count(r) AS c', {}) YIELD value
        RETURN rt AS rel_type, value.c AS count
        """,
        types=ATTACK_SUBGRAPH_RELATIONS,
    )
    return {
        "labels": {row["label"]: int(row["count"] or 0) for row in label_counts},
        "relations": {row["rel_type"]: int(row["count"] or 0) for row in rel_counts},
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        store.ensure_schema()
        if args.reset:
            deleted = store.delete_by_source(args.source_id)
            logging.info("Reset existing ATT&CK subgraph: %s", deleted)

        bundle_path = _ensure_bundle(args.bundle_path, args.bundle_url)
        loader = AttackLoader(store, source_id=args.source_id)
        stats = loader.load_bundle(bundle_path, source_uri=ATTACK_SOURCE_URI)

        if args.enrich:
            logging.info("Projecting ATT&CK subgraph into GDS for PageRank + Louvain")
            store.enrich_subgraph(
                graph_name="attack_graph",
                node_labels=ATTACK_SUBGRAPH_LABELS,
                relationship_types=ATTACK_SUBGRAPH_RELATIONS,
                pagerank_property="pagerank",
                community_property="community",
            )

        post_summary = _summary_after_load(store)
        report = {
            "bundle_path": str(bundle_path),
            "source_id": args.source_id,
            "load_stats": stats.as_dict(),
            "post_load_counts": post_summary,
            "enriched": bool(args.enrich),
        }
        run_dir = resolve_run_dir(args.run_dir, default_hint="load")
        report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logging.info("Wrote load summary -> %s", report_path)
        append_run_card(
            run_dir,
            script="load_attack.py",
            config={
                "bundle_path": str(bundle_path),
                "source_id": args.source_id,
                "reset": bool(args.reset),
                "enrich": bool(args.enrich),
                "bundle_url": args.bundle_url,
            },
            output_files=[report_path],
        )
        print(json.dumps(report, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
