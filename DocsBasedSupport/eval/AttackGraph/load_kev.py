"""Load CISA Known Exploited Vulnerabilities (KEV) catalog CVE nodes into Neo4j.

Usage::

    PYTHONPATH=. python eval/AttackGraph/load_kev.py --run-dir eval/AttackGraph/runs/kev-load
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.graph.neo4j_store import GraphEntity, Neo4jStore  # noqa: E402
from eval.AttackGraph._run_utils import append_run_card, resolve_report_path, resolve_run_dir  # noqa: E402
from eval.AttackGraph.graph_constants import DEFAULT_KEV_URL, KEV_SOURCE_ID, KEV_SOURCE_URI  # noqa: E402

DEFAULT_REPORT_FILENAME = "kev_load_summary.json"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kev-url", default=DEFAULT_KEV_URL)
    parser.add_argument("--sample", type=int, default=None, help="Optional random sample size.")
    parser.add_argument("--seed", type=int, default=20260603)
    parser.add_argument("--reset", action="store_true", help="Delete prior KEV source subgraph.")
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _fetch_kev(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def _cve_entity_id(cve_id: str) -> str:
    return f"cve:{cve_id.strip().upper()}"


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
            deleted = store.delete_by_source(KEV_SOURCE_ID)
            logging.info("Reset KEV subgraph: %s", deleted)

        payload = _fetch_kev(args.kev_url)
        vulnerabilities = list(payload.get("vulnerabilities") or [])
        if args.sample is not None and args.sample < len(vulnerabilities):
            rng = random.Random(args.seed)
            vulnerabilities = rng.sample(vulnerabilities, args.sample)

        store.upsert_source(
            source_id=KEV_SOURCE_ID,
            source_uri=KEV_SOURCE_URI,
            source_type="cisa-kev",
            last_updated=str(payload.get("dateReleased") or ""),
            etag=str(payload.get("catalogVersion") or ""),
            content_hash=None,
        )
        now = datetime.now(timezone.utc).isoformat()
        loaded = 0
        for row in vulnerabilities:
            cve_id = str(row.get("cveID") or "").strip().upper()
            if not cve_id:
                continue
            description_parts = [
                str(row.get("vulnerabilityName") or ""),
                str(row.get("shortDescription") or ""),
                str(row.get("notes") or ""),
            ]
            description = "\n\n".join(part for part in description_parts if part.strip())
            store.upsert_entity(
                GraphEntity(
                    label="CVE",
                    entity_id=_cve_entity_id(cve_id),
                    name=cve_id,
                    properties={
                        "stix_type": "vulnerability",
                        "external_id": cve_id,
                        "domain": "cisa-kev",
                        "source": "cisa-kev",
                        "cve_source": "cisa-kev",
                        "vendor_project": str(row.get("vendorProject") or ""),
                        "product": str(row.get("product") or ""),
                        "vulnerability_name": str(row.get("vulnerabilityName") or ""),
                        "short_description": str(row.get("shortDescription") or ""),
                        "required_action": str(row.get("requiredAction") or ""),
                        "date_added": str(row.get("dateAdded") or ""),
                        "due_date": str(row.get("dueDate") or ""),
                        "known_ransomware_campaign_use": str(
                            row.get("knownRansomwareCampaignUse") or ""
                        ),
                        "notes": str(row.get("notes") or ""),
                        "description": description[:8000],
                        "created_at": now,
                    },
                ),
                source_id=KEV_SOURCE_ID,
                extra_labels=["CVE", "AttackEntity"],
            )
            loaded += 1

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "kev_url": args.kev_url,
                "sample": args.sample,
                "seed": args.seed,
                "reset": bool(args.reset),
            },
            "catalog_version": payload.get("catalogVersion"),
            "date_released": payload.get("dateReleased"),
            "num_cves_loaded": loaded,
            "num_cves_in_feed": len(payload.get("vulnerabilities") or []),
        }
        run_dir = resolve_run_dir(args.run_dir, default_hint="kev-load")
        report_path = resolve_report_path(None, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        append_run_card(
            run_dir,
            script="load_kev.py",
            config=report["config"] | {"num_cves_loaded": loaded},
            output_files=[report_path],
        )
        print(json.dumps(report, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
