"""Qualitative community + centrality report for the loaded MITRE ATT&CK graph.

Run after ``load_attack.py --enrich`` so that the PageRank (``pagerank``) and
Louvain (``community``) properties are written on the attack subgraph. This
script does *no* mutation. It produces:

* Top-K nodes by PageRank globally and per label, with their stable ATT&CK ids.
* Louvain community summaries: size, dominant label distribution, top members
  by PageRank, and label-purity score (Gini impurity over labels). Communities
  with mixed labels indicate cross-label co-occurrence -- e.g. an actor
  clustered with the malware and techniques it relies on, which is exactly the
  analytical view the supervisor's feedback asks for.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from eval.AttackGraph._run_utils import (  # noqa: E402
    append_run_card,
    resolve_report_path,
    resolve_run_dir,
)

DEFAULT_REPORT_FILENAME = "community_report.json"

REPORT_LABELS = ["ThreatActor", "Technique", "Tactic", "Malware", "Tool", "Mitigation", "CVE", "Campaign"]


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--pagerank-property",
        default="pagerank",
        help="Node property where PageRank was written (default written by enrich_subgraph).",
    )
    parser.add_argument(
        "--community-property",
        default="community",
        help="Node property where Louvain community ID was written.",
    )
    parser.add_argument("--top-overall", type=int, default=30, help="Top-K nodes by PageRank globally.")
    parser.add_argument("--top-per-label", type=int, default=15, help="Top-K nodes by PageRank per label.")
    parser.add_argument("--top-communities", type=int, default=10, help="Top-K communities by node count.")
    parser.add_argument("--top-per-community", type=int, default=10, help="Top members per community by PageRank.")
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help=(
            "Run directory for tracked outputs (defaults to "
            "eval/AttackGraph/runs/community-<UTC timestamp>)."
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


def _gini_impurity(label_counts: Counter[str]) -> float:
    total = sum(label_counts.values())
    if total == 0:
        return 0.0
    return 1.0 - sum((count / total) ** 2 for count in label_counts.values())


def _primary_label(labels: list[str]) -> str:
    for candidate in REPORT_LABELS:
        if candidate in labels:
            return candidate
    return "Other"


def _top_pagerank_overall(store: Neo4jStore, pr_property: str, top_k: int) -> list[dict[str, object]]:
    rows = store.run_read(
        f"""
        MATCH (n:AttackEntity)
        WHERE n.{pr_property} IS NOT NULL
        RETURN n.entity_id AS entity_id, n.name AS name, labels(n) AS labels,
               n.{pr_property} AS pagerank, n.external_id AS external_id
        ORDER BY pagerank DESC
        LIMIT $top_k
        """,
        top_k=top_k,
    )
    return [
        {
            "entity_id": row["entity_id"],
            "name": row["name"],
            "label": _primary_label(list(row["labels"] or [])),
            "external_id": row["external_id"],
            "pagerank": float(row["pagerank"]),
        }
        for row in rows
    ]


def _top_pagerank_per_label(
    store: Neo4jStore, pr_property: str, top_k: int
) -> dict[str, list[dict[str, object]]]:
    by_label: dict[str, list[dict[str, object]]] = {}
    for label in REPORT_LABELS:
        rows = store.run_read(
            f"""
            MATCH (n:`{label}`)
            WHERE n.{pr_property} IS NOT NULL
            RETURN n.entity_id AS entity_id, n.name AS name,
                   n.external_id AS external_id, n.{pr_property} AS pagerank
            ORDER BY pagerank DESC
            LIMIT $top_k
            """,
            top_k=top_k,
        )
        if not rows:
            continue
        by_label[label] = [
            {
                "entity_id": row["entity_id"],
                "name": row["name"],
                "external_id": row["external_id"],
                "pagerank": float(row["pagerank"]),
            }
            for row in rows
        ]
    return by_label


def _community_summaries(
    store: Neo4jStore,
    pr_property: str,
    community_property: str,
    top_communities: int,
    top_per_community: int,
) -> dict[str, object]:
    sizes = store.run_read(
        f"""
        MATCH (n:AttackEntity)
        WHERE n.{community_property} IS NOT NULL
        RETURN n.{community_property} AS community_id, count(n) AS size
        ORDER BY size DESC
        LIMIT $top
        """,
        top=top_communities,
    )
    total_assigned = store.run_read(
        f"""
        MATCH (n:AttackEntity)
        WHERE n.{community_property} IS NOT NULL
        RETURN count(n) AS total
        """
    )
    total_communities = store.run_read(
        f"""
        MATCH (n:AttackEntity)
        WHERE n.{community_property} IS NOT NULL
        RETURN count(DISTINCT n.{community_property}) AS total
        """
    )
    summaries: list[dict[str, object]] = []
    for row in sizes:
        community_id = row["community_id"]
        size = int(row["size"])
        members = store.run_read(
            f"""
            MATCH (n:AttackEntity)
            WHERE n.{community_property} = $cid
            RETURN n.entity_id AS entity_id, n.name AS name, labels(n) AS labels,
                   n.external_id AS external_id,
                   coalesce(n.{pr_property}, 0.0) AS pagerank
            ORDER BY pagerank DESC
            """,
            cid=community_id,
        )
        label_counts: Counter[str] = Counter()
        for member in members:
            label_counts[_primary_label(list(member["labels"] or []))] += 1
        purity = _gini_impurity(label_counts)
        top_members = [
            {
                "entity_id": m["entity_id"],
                "name": m["name"],
                "label": _primary_label(list(m["labels"] or [])),
                "external_id": m["external_id"],
                "pagerank": float(m["pagerank"]),
            }
            for m in members[:top_per_community]
        ]
        summaries.append(
            {
                "community_id": community_id,
                "size": size,
                "label_distribution": dict(label_counts),
                "label_gini_impurity": purity,
                "top_members": top_members,
            }
        )
    return {
        "summaries": summaries,
        "total_assigned_nodes": int(total_assigned[0]["total"]) if total_assigned else 0,
        "total_communities": int(total_communities[0]["total"]) if total_communities else 0,
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
        # Sanity-check that PageRank/Louvain ran. If not, warn explicitly.
        sanity = store.run_read(
            f"""
            MATCH (n:AttackEntity)
            WHERE n.{args.pagerank_property} IS NOT NULL AND n.{args.community_property} IS NOT NULL
            RETURN count(n) AS enriched
            """
        )
        enriched_count = int(sanity[0]["enriched"]) if sanity else 0
        if enriched_count == 0:
            raise SystemExit(
                "No AttackEntity nodes have both pagerank and community properties. "
                "Re-run eval/AttackGraph/load_attack.py --enrich first."
            )

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "pagerank_property": args.pagerank_property,
                "community_property": args.community_property,
                "top_overall": args.top_overall,
                "top_per_label": args.top_per_label,
                "top_communities": args.top_communities,
                "top_per_community": args.top_per_community,
            },
            "enriched_node_count": enriched_count,
            "top_pagerank_overall": _top_pagerank_overall(
                store, args.pagerank_property, args.top_overall
            ),
            "top_pagerank_per_label": _top_pagerank_per_label(
                store, args.pagerank_property, args.top_per_label
            ),
            "communities": _community_summaries(
                store,
                pr_property=args.pagerank_property,
                community_property=args.community_property,
                top_communities=args.top_communities,
                top_per_community=args.top_per_community,
            ),
        }
        run_dir = resolve_run_dir(args.run_dir, default_hint="community")
        report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logging.info("Wrote community report -> %s", report_path)
        append_run_card(
            run_dir,
            script="community_report.py",
            config={
                "pagerank_property": args.pagerank_property,
                "community_property": args.community_property,
                "top_overall": args.top_overall,
                "top_per_label": args.top_per_label,
                "top_communities": args.top_communities,
                "top_per_community": args.top_per_community,
                "enriched_node_count": enriched_count,
                "total_communities": report["communities"]["total_communities"],
            },
            output_files=[report_path],
        )
        print(json.dumps(
            {
                "enriched_node_count": report["enriched_node_count"],
                "num_communities": report["communities"]["total_communities"],
                "top_overall_preview": report["top_pagerank_overall"][:10],
            },
            indent=2,
        ))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
