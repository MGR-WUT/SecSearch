"""CVE -> Threat Actor mapping report on the loaded MITRE ATT&CK graph.

Run after ``load_attack.py --enrich`` (and optionally after ``enrich_with_llm.py``)
so PageRank / Louvain have been written. The script answers a single question:

  "Given a CVE node, which threat actors does the graph link it to, and through
   which intermediate technique / malware / tool / campaign?"

For every CVE we enumerate evidence paths of length 2 or 3 of the form:

    (CVE) <-[:EXPLOITS]- (Technique|Malware|Tool) <-[:USES]- (ThreatActor)
    (CVE) <-[:EXPLOITS]- (Technique|Malware|Tool) <-[:USES]- (Software)
                                                  <-[:USES]- (ThreatActor)
    (CVE) <-[:EXPLOITS]- (Campaign) -[:ATTRIBUTED_TO]-> (ThreatActor)
    (CVE) <-[:EXPLOITS]- (Campaign) <-[:USES]- (Software)
                                                 -[:ATTRIBUTED_TO]-> (ThreatActor)
    (CVE) <-[:EXPLOITS]- (ThreatActor)

We rank candidate actors per CVE by

    score = path_count * (1 + actor.pagerank)

so that an actor that reaches the CVE through several distinct intermediaries
and is structurally central scores highest. Output combines:

  * a **qualitative** per-CVE top-K with full evidence paths -- useful for the
    thesis to show concrete reasoning chains;
  * an **aggregate** summary: coverage (% CVEs with >=1 actor link), average
    actors per CVE, evidence-path count distribution.

The report is fully driven by the existing labelled ATT&CK subgraph; the same
script can be re-run after LLM enrichment to demonstrate the lift from
description-based extraction.
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
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

DEFAULT_REPORT_BASENAME = "cve_apt_paths"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--top-actors", type=int, default=5, help="Top-K actors to keep per CVE.")
    parser.add_argument(
        "--max-paths-per-pair",
        type=int,
        default=10,
        help="Cap on evidence paths kept per (CVE, actor) pair in the qualitative report.",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=3,
        choices=[2, 3],
        help="Length of the longest evidence path: 2 = direct, 3 = through an extra USES hop.",
    )
    parser.add_argument(
        "--pagerank-property",
        default="pagerank",
        help="Node property holding actor PageRank (default written by load_attack --enrich).",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help=(
            "Run directory for tracked outputs (defaults to "
            "eval/AttackGraph/runs/cve-apt-<UTC timestamp>)."
        ),
    )
    parser.add_argument(
        "--variant",
        default=None,
        help=(
            "Optional variant label (e.g. baseline / enriched) appended to the report "
            "filename so multiple variants can co-exist in the same --run-dir."
        ),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=None,
        help="Explicit override for the report path. Wins over --run-dir / --variant.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def _fetch_cves(store: Neo4jStore) -> list[dict[str, object]]:
    return store.run_read(
        """
        MATCH (c:CVE)
        RETURN c.entity_id AS entity_id, c.name AS name, c.external_id AS external_id
        ORDER BY c.name
        """
    )


def _paths_for_cve(
    store: Neo4jStore, cve_entity_id: str, max_hops: int, pr_property: str
) -> list[dict[str, object]]:
    """Return every evidence path CVE <- ... <- ThreatActor up to ``max_hops`` long."""
    if max_hops == 2:
        query = f"""
        MATCH (cve:CVE {{entity_id: $cve_id}})
        CALL {{
            WITH cve
            MATCH (cve)<-[:EXPLOITS]-(mid)<-[:USES]-(actor:ThreatActor)
            RETURN actor, mid, null AS hop2, 'uses_direct' AS path_kind
            UNION
            WITH cve
            MATCH (cve)<-[:EXPLOITS]-(mid:Campaign)-[:ATTRIBUTED_TO]->(actor:ThreatActor)
            RETURN actor, mid, null AS hop2, 'campaign_attribution' AS path_kind
            UNION
            WITH cve
            MATCH (cve)<-[:EXPLOITS]-(actor:ThreatActor)
            RETURN actor, actor AS mid, null AS hop2, 'actor_direct_exploit' AS path_kind
        }}
        RETURN DISTINCT actor.entity_id AS actor_id,
               actor.name AS actor_name,
               coalesce(actor.{pr_property}, 0.0) AS actor_pagerank,
               labels(mid) AS mid_labels,
               mid.entity_id AS mid_id,
               mid.name AS mid_name,
               mid.external_id AS mid_external_id,
               null AS hop2_labels,
               null AS hop2_id,
               null AS hop2_name,
               null AS hop2_external_id,
               path_kind AS path_kind
        """
    else:
        query = f"""
        MATCH (cve:CVE {{entity_id: $cve_id}})
        CALL {{
            WITH cve
            MATCH (cve)<-[:EXPLOITS]-(mid)<-[:USES]-(actor:ThreatActor)
            RETURN actor, mid, null AS hop2, 'uses_direct' AS path_kind
            UNION
            WITH cve
            MATCH (cve)<-[:EXPLOITS]-(mid)<-[:USES]-(hop2)<-[:USES]-(actor:ThreatActor)
            WHERE hop2 <> mid AND NOT hop2:ThreatActor
            RETURN actor, mid, hop2, 'uses_indirect' AS path_kind
            UNION
            WITH cve
            MATCH (cve)<-[:EXPLOITS]-(mid:Campaign)-[:ATTRIBUTED_TO]->(actor:ThreatActor)
            RETURN actor, mid, null AS hop2, 'campaign_attribution' AS path_kind
            UNION
            WITH cve
            MATCH (cve)<-[:EXPLOITS]-(mid)<-[:USES]-(hop2:Campaign)-[:ATTRIBUTED_TO]->(actor:ThreatActor)
            WHERE hop2 <> mid
            RETURN actor, mid, hop2, 'campaign_uses_software' AS path_kind
            UNION
            WITH cve
            MATCH (cve)<-[:EXPLOITS]-(actor:ThreatActor)
            RETURN actor, actor AS mid, null AS hop2, 'actor_direct_exploit' AS path_kind
        }}
        RETURN DISTINCT actor.entity_id AS actor_id,
               actor.name AS actor_name,
               coalesce(actor.{pr_property}, 0.0) AS actor_pagerank,
               labels(mid) AS mid_labels,
               mid.entity_id AS mid_id,
               mid.name AS mid_name,
               mid.external_id AS mid_external_id,
               CASE WHEN hop2 IS NULL THEN null ELSE labels(hop2) END AS hop2_labels,
               CASE WHEN hop2 IS NULL THEN null ELSE hop2.entity_id END AS hop2_id,
               CASE WHEN hop2 IS NULL THEN null ELSE hop2.name END AS hop2_name,
               CASE WHEN hop2 IS NULL THEN null ELSE hop2.external_id END AS hop2_external_id,
               path_kind AS path_kind
        """
    return store.run_read(query, cve_id=cve_entity_id)


def _domain_label(labels: list[str] | None) -> str:
    if not labels:
        return "Entity"
    for preferred in ("Technique", "Malware", "Tool", "Campaign", "ThreatActor", "Tactic", "Mitigation", "CVE"):
        if preferred in labels:
            return preferred
    for label in labels:
        if label not in {"Entity", "AttackEntity"}:
            return label
    return labels[0]


def _summarize_cve(
    cve: dict[str, object],
    paths: list[dict[str, object]],
    top_actors: int,
    max_paths_per_pair: int,
) -> dict[str, object]:
    actors: dict[str, dict[str, object]] = {}
    for row in paths:
        actor_id = row["actor_id"]
        if actor_id is None:
            continue
        bucket = actors.setdefault(
            actor_id,
            {
                "actor_id": actor_id,
                "actor_name": row["actor_name"],
                "actor_pagerank": float(row["actor_pagerank"] or 0.0),
                "evidence_paths": [],
            },
        )
        path: dict[str, object] = {
            "path_kind": row.get("path_kind"),
            "mid_label": _domain_label(row.get("mid_labels")),
            "mid_id": row.get("mid_id"),
            "mid_name": row.get("mid_name"),
            "mid_external_id": row.get("mid_external_id"),
        }
        if row.get("hop2_id"):
            path["hop2_label"] = _domain_label(row.get("hop2_labels"))
            path["hop2_id"] = row.get("hop2_id")
            path["hop2_name"] = row.get("hop2_name")
            path["hop2_external_id"] = row.get("hop2_external_id")
        bucket["evidence_paths"].append(path)
    ranked: list[dict[str, object]] = []
    for actor in actors.values():
        path_count = len(actor["evidence_paths"])
        actor["path_count"] = path_count
        actor["score"] = round(path_count * (1.0 + float(actor["actor_pagerank"])), 6)
        actor["evidence_paths"] = actor["evidence_paths"][:max_paths_per_pair]
        ranked.append(actor)
    ranked.sort(key=lambda a: (float(a["score"]), int(a["path_count"])), reverse=True)
    return {
        "cve_id": cve.get("external_id") or cve.get("name"),
        "cve_entity_id": cve["entity_id"],
        "actor_link_count": len(ranked),
        "total_evidence_paths": sum(int(a["path_count"]) for a in ranked),
        "top_actors": ranked[:top_actors],
    }


def _aggregate(per_cve: list[dict[str, object]]) -> dict[str, object]:
    n_total = len(per_cve)
    if n_total == 0:
        return {"num_cves": 0, "num_cves_with_actor_link": 0}
    actor_counts = [int(c["actor_link_count"]) for c in per_cve]
    path_counts = [int(c["total_evidence_paths"]) for c in per_cve]
    linked = [c for c in actor_counts if c > 0]
    return {
        "num_cves": n_total,
        "num_cves_with_actor_link": len(linked),
        "coverage_fraction": round(len(linked) / n_total, 4),
        "actors_per_cve": {
            "mean": round(statistics.fmean(actor_counts), 3) if actor_counts else 0.0,
            "median": int(statistics.median(actor_counts)) if actor_counts else 0,
            "max": max(actor_counts) if actor_counts else 0,
        },
        "evidence_paths_per_cve": {
            "mean": round(statistics.fmean(path_counts), 3) if path_counts else 0.0,
            "median": int(statistics.median(path_counts)) if path_counts else 0,
            "max": max(path_counts) if path_counts else 0,
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    run_dir = resolve_run_dir(args.run_dir, default_hint="cve-apt")
    variant_suffix = f"_{args.variant.strip()}" if args.variant and args.variant.strip() else ""
    default_filename = f"{DEFAULT_REPORT_BASENAME}{variant_suffix}.json"
    report_path = resolve_report_path(args.report_path, run_dir, default_filename)

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        cves = _fetch_cves(store)
        logging.info("Found %d CVE nodes in the graph.", len(cves))
        if not cves:
            raise SystemExit("No CVE nodes found. Run eval/AttackGraph/load_attack.py --enrich first.")
        per_cve: list[dict[str, object]] = []
        for idx, cve in enumerate(cves, start=1):
            paths = _paths_for_cve(
                store,
                cve_entity_id=str(cve["entity_id"]),
                max_hops=args.max_hops,
                pr_property=args.pagerank_property,
            )
            per_cve.append(
                _summarize_cve(
                    cve=cve,
                    paths=paths,
                    top_actors=args.top_actors,
                    max_paths_per_pair=args.max_paths_per_pair,
                )
            )
            if idx % 10 == 0 or idx == len(cves):
                logging.info("Processed %d/%d CVEs.", idx, len(cves))

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "top_actors": args.top_actors,
                "max_paths_per_pair": args.max_paths_per_pair,
                "max_hops": args.max_hops,
                "pagerank_property": args.pagerank_property,
            },
            "aggregate": _aggregate(per_cve),
            "per_cve": per_cve,
        }
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logging.info("Wrote CVE -> APT report -> %s", report_path)
        append_run_card(
            run_dir,
            script="eval_cve_apt.py",
            config={
                "variant": args.variant or "(none)",
                "top_actors": args.top_actors,
                "max_paths_per_pair": args.max_paths_per_pair,
                "max_hops": args.max_hops,
                "pagerank_property": args.pagerank_property,
                "num_cves": report["aggregate"]["num_cves"],
                "num_cves_with_actor_link": report["aggregate"]["num_cves_with_actor_link"],
                "coverage_fraction": report["aggregate"].get("coverage_fraction"),
            },
            output_files=[report_path],
        )

        preview = {
            "aggregate": report["aggregate"],
            "top_examples": [
                {
                    "cve_id": entry["cve_id"],
                    "top_actors": [
                        {
                            "name": a["actor_name"],
                            "paths": a["path_count"],
                            "score": a["score"],
                        }
                        for a in entry["top_actors"]
                    ],
                }
                for entry in per_cve
                if entry["actor_link_count"] > 0
            ][:5],
        }
        print(json.dumps(preview, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
