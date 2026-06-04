"""Load the Center for Threat-Informed Defense ATT&CK -> CVE mappings into Neo4j.

This is the **gold source for Experiment B₂**: it maps every CVE to one or more
ATT&CK **technique IDs** taken from the CTID ``Att&ckToCveMappings.csv``. Each
mapping becomes a deterministic ``(Technique)-[:EXPLOITS]->(CVE)`` edge against
the techniques already loaded by ``load_attack.py``, and the CTID technique IDs
are stored on each CVE node (``mapped_technique_ids``) so the NVD corpus builder
(``build_nvd_cve_corpus.py``) can pair them with NVD prose for LLM scoring.

Usage::

    NEO4J_URI=bolt://localhost:7688 PYTHONPATH=. python \
        eval/AttackGraph/loaders/load_attack_to_cve.py \
        --enrich --reset --run-dir eval/AttackGraph/runs/cve-attack-map-all-v2-gpt-oss-20b

Run ``load_attack.py --enrich --reset`` against the same graph first so the
``Technique`` / ``ThreatActor`` nodes (and their PageRank) exist.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import re
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.graph.neo4j_store import GraphEntity, GraphRelation, Neo4jStore  # noqa: E402
from eval.AttackGraph.lib._run_utils import (  # noqa: E402
    append_run_card,
    resolve_report_path,
    resolve_run_dir,
)
from eval.AttackGraph.lib.graph_constants import (  # noqa: E402
    ATTACK_TO_CVE_SOURCE_ID,
    ATTACK_TO_CVE_SOURCE_URI,
    DEFAULT_ATTACK_TO_CVE_URL,
)

DEFAULT_REPORT_FILENAME = "attack_to_cve_load_summary.json"

# CVE node label set is included in the ATT&CK GDS projection so re-running
# PageRank/Louvain over the enlarged graph stays scoped to the same subgraph.
ATTACK_SUBGRAPH_LABELS = [
    "ThreatActor",
    "Technique",
    "Tactic",
    "Malware",
    "Tool",
    "Mitigation",
    "Campaign",
    "CVE",
]
ATTACK_SUBGRAPH_RELATIONS = [
    "USES",
    "MITIGATES",
    "SUBTECHNIQUE_OF",
    "ATTRIBUTED_TO",
    "TARGETS",
    "EXPLOITS",
    "IN_TACTIC",
]

# ATT&CK technique IDs: Txxxx with optional .yyy sub-technique. Word boundaries
# keep us from slicing typo'd IDs such as ``T11190`` into a bogus ``T1119``.
TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

TECHNIQUE_COLUMNS = (
    "Primary Impact",
    "Secondary Impact",
    "Exploitation Technique",
    "Uncategorized",
)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv-url", default=DEFAULT_ATTACK_TO_CVE_URL)
    parser.add_argument(
        "--csv-path",
        type=Path,
        default=None,
        help="Local CSV path. If given, --csv-url is ignored (offline / pinned snapshot).",
    )
    parser.add_argument(
        "--no-base-fallback",
        action="store_true",
        help="Do not fall back to the base technique when a sub-technique node is missing.",
    )
    parser.add_argument("--reset", action="store_true", help="Delete prior attack-to-cve subgraph.")
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Re-run PageRank + Louvain over the ATT&CK subgraph after loading.",
    )
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--report-path", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _read_csv_text(args: argparse.Namespace) -> tuple[str, str]:
    if args.csv_path is not None:
        text = Path(args.csv_path).expanduser().read_text(encoding="utf-8-sig")
        return text, str(args.csv_path)
    with urllib.request.urlopen(args.csv_url, timeout=120) as response:  # noqa: S310 - static GitHub URL
        text = response.read().decode("utf-8-sig")
    return text, args.csv_url


def _parse_mappings(csv_text: str) -> dict[str, set[str]]:
    """Return {CVE-ID -> set(technique external_id)} from the CTID CSV."""
    reader = csv.DictReader(io.StringIO(csv_text))
    mappings: dict[str, set[str]] = defaultdict(set)
    for row in reader:
        raw_cve = str(row.get("CVE ID") or "").strip()
        match = CVE_ID_PATTERN.fullmatch(raw_cve)
        if not match:
            continue
        cve_id = raw_cve.upper()
        for column in TECHNIQUE_COLUMNS:
            cell = row.get(column)
            if not cell:
                continue
            for tech_id in TECHNIQUE_ID_PATTERN.findall(cell):
                mappings[cve_id].add(tech_id.upper())
    return mappings


def _cve_entity_id(cve_id: str) -> str:
    return f"cve:{cve_id.strip().upper()}"


def _technique_index(store: Neo4jStore) -> dict[str, str]:
    """{technique external_id -> entity_id} for every loaded Technique node."""
    rows = store.run_read(
        """
        MATCH (t:Technique)
        WHERE t.external_id IS NOT NULL
        RETURN t.external_id AS external_id, t.entity_id AS entity_id
        """
    )
    return {str(r["external_id"]).upper(): str(r["entity_id"]) for r in rows}


def _resolve_technique(
    tech_id: str, index: dict[str, str], *, base_fallback: bool
) -> tuple[str | None, bool]:
    """Return (entity_id, used_base_fallback) for a technique external id."""
    entity_id = index.get(tech_id)
    if entity_id is not None:
        return entity_id, False
    if base_fallback and "." in tech_id:
        base = tech_id.split(".", 1)[0]
        entity_id = index.get(base)
        if entity_id is not None:
            return entity_id, True
    return None, False


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
        if args.reset:
            deleted = store.delete_by_source(ATTACK_TO_CVE_SOURCE_ID)
            logging.info("Reset attack-to-cve subgraph: %s", deleted)

        csv_text, csv_origin = _read_csv_text(args)
        mappings = _parse_mappings(csv_text)
        logging.info("Parsed %d CVEs with >=1 technique id from %s.", len(mappings), csv_origin)

        technique_index = _technique_index(store)
        logging.info("Loaded %d Technique nodes for external_id matching.", len(technique_index))
        if not technique_index:
            raise SystemExit(
                "No Technique nodes found. Run load_attack.py --enrich --reset on this graph first."
            )

        store.upsert_source(
            source_id=ATTACK_TO_CVE_SOURCE_ID,
            source_uri=ATTACK_TO_CVE_SOURCE_URI,
            source_type="attack-to-cve-csv",
            last_updated=datetime.now(timezone.utc).isoformat(),
            etag=None,
            content_hash=None,
        )

        now = datetime.now(timezone.utc).isoformat()
        cves_loaded = 0
        cves_with_edge = 0
        exploits_edges = 0
        base_fallback_edges = 0
        unmatched_techniques: set[str] = set()
        for cve_id, tech_ids in sorted(mappings.items()):
            description = (
                f"{cve_id} mapped to ATT&CK techniques "
                f"{', '.join(sorted(tech_ids))} by the Center for Threat-Informed "
                "Defense ATT&CK-to-CVE project."
            )
            store.upsert_entity(
                GraphEntity(
                    label="CVE",
                    entity_id=_cve_entity_id(cve_id),
                    name=cve_id,
                    properties={
                        "stix_type": "vulnerability",
                        "external_id": cve_id,
                        "domain": "attack-to-cve",
                        "source": "attack-to-cve",
                        "cve_source": "attack-to-cve",
                        "mapped_technique_ids": sorted(tech_ids),
                        "description": description[:8000],
                        "created_at": now,
                    },
                ),
                source_id=ATTACK_TO_CVE_SOURCE_ID,
                extra_labels=["CVE", "AttackEntity"],
            )
            cves_loaded += 1
            cve_has_edge = False
            for tech_id in sorted(tech_ids):
                entity_id, used_base = _resolve_technique(
                    tech_id, technique_index, base_fallback=not args.no_base_fallback
                )
                if entity_id is None:
                    unmatched_techniques.add(tech_id)
                    continue
                store.upsert_relation(
                    GraphRelation(
                        source_id=entity_id,
                        target_id=_cve_entity_id(cve_id),
                        relation_type="EXPLOITS",
                        properties={
                            "source": "attack-to-cve",
                            "mapped_technique_id": tech_id,
                            "base_technique_fallback": used_base,
                        },
                    )
                )
                exploits_edges += 1
                cve_has_edge = True
                if used_base:
                    base_fallback_edges += 1
            if cve_has_edge:
                cves_with_edge += 1

        if args.enrich:
            logging.info("Projecting ATT&CK subgraph into GDS for PageRank + Louvain")
            store.enrich_subgraph(
                graph_name="attack_graph",
                node_labels=ATTACK_SUBGRAPH_LABELS,
                relationship_types=ATTACK_SUBGRAPH_RELATIONS,
                pagerank_property="pagerank",
                community_property="community",
            )

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "csv_origin": csv_origin,
                "reset": bool(args.reset),
                "enrich": bool(args.enrich),
                "base_fallback": not args.no_base_fallback,
            },
            "num_cves_in_csv": len(mappings),
            "num_cves_loaded": cves_loaded,
            "num_cves_with_technique_edge": cves_with_edge,
            "num_exploits_edges": exploits_edges,
            "num_base_fallback_edges": base_fallback_edges,
            "num_unmatched_technique_ids": len(unmatched_techniques),
            "unmatched_technique_ids": sorted(unmatched_techniques),
        }
        run_dir = resolve_run_dir(args.run_dir, default_hint="attack-to-cve")
        report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        append_run_card(
            run_dir,
            script="load_attack_to_cve.py",
            config={
                "csv_origin": csv_origin,
                "reset": bool(args.reset),
                "enrich": bool(args.enrich),
                "base_fallback": not args.no_base_fallback,
                "num_cves_loaded": cves_loaded,
                "num_cves_with_technique_edge": cves_with_edge,
                "num_exploits_edges": exploits_edges,
                "num_base_fallback_edges": base_fallback_edges,
                "num_unmatched_technique_ids": len(unmatched_techniques),
            },
            output_files=[report_path],
        )
        print(json.dumps(report, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
