"""Upsert CTI ThreatActor + CVE nodes from cti_cve_actor_corpus.json (no gold EXPLOITS edges)."""

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
from app.graph.neo4j_store import GraphEntity, Neo4jStore  # noqa: E402
from eval.AttackGraph.lib._run_utils import append_run_card, resolve_report_path, resolve_run_dir  # noqa: E402
from eval.AttackGraph.lib.graph_constants import CTI_CVE_SOURCE_ID  # noqa: E402

DEFAULT_CORPUS_FILENAME = "cti_cve_actor_corpus.json"
DEFAULT_REPORT_FILENAME = "cti_actors_load_summary.json"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-path", type=Path, default=None)
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    run_dir = resolve_run_dir(args.run_dir, default_hint="cti-cve-load")
    corpus_path = args.corpus_path or (run_dir / DEFAULT_CORPUS_FILENAME)
    if not corpus_path.exists():
        raise SystemExit(f"Corpus not found: {corpus_path}. Run build_cti_cve_corpus.py first.")

    payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        now = datetime.now(timezone.utc).isoformat()
        store.upsert_source(
            source_id=CTI_CVE_SOURCE_ID,
            source_uri="misp-galaxy+etda",
            source_type="cti-cve-attribution",
            last_updated=now,
            etag=None,
            content_hash=None,
        )
        actors_loaded = 0
        cves_loaded = 0
        for doc in payload.get("documents", []):
            actor_id = doc.get("actor_entity_id")
            if not actor_id:
                continue
            if not doc.get("matched_attack"):
                store.upsert_entity(
                    GraphEntity(
                        label="ThreatActor",
                        entity_id=str(actor_id),
                        name=str(doc.get("actor_name") or actor_id),
                        properties={
                            "aliases": doc.get("aliases") or [],
                            "source": "cti-misp-etda",
                            "cve_source": None,
                            "description": (doc.get("text") or "")[:8000],
                            "created_at": now,
                        },
                    ),
                    source_id=CTI_CVE_SOURCE_ID,
                    extra_labels=["ThreatActor", "AttackEntity"],
                )
                actors_loaded += 1
            for edge in doc.get("gold_cves", []):
                cve_entity_id = edge.get("cve_entity_id")
                cve_id = edge.get("cve_id")
                if not cve_entity_id or not cve_id:
                    continue
                existing = store.run_read(
                    "MATCH (c:CVE {entity_id: $id}) RETURN count(c) AS n",
                    id=cve_entity_id,
                )
                if existing and int(existing[0]["n"]) > 0:
                    continue
                store.upsert_entity(
                    GraphEntity(
                        label="CVE",
                        entity_id=str(cve_entity_id),
                        name=str(cve_id),
                        properties={
                            "stix_type": "vulnerability",
                            "external_id": cve_id,
                            "cve_source": "cti-attributed",
                            "source": "cti-misp-etda",
                            "created_at": now,
                        },
                    ),
                    source_id=CTI_CVE_SOURCE_ID,
                    extra_labels=["CVE", "AttackEntity"],
                )
                cves_loaded += 1

        report = {
            "generated_at": now,
            "corpus_path": str(corpus_path),
            "new_cti_threat_actors": actors_loaded,
            "new_cti_cve_nodes": cves_loaded,
            "note": "Gold EXPLOITS edges are NOT written; gold lives in corpus JSON only.",
        }
        report_path = resolve_report_path(None, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        append_run_card(run_dir, script="load_cti_actors.py", config={}, output_files=[report_path])
        print(json.dumps(report, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
