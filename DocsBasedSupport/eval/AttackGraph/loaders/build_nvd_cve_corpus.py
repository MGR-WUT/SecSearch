"""Build a CVE corpus pairing CTID ATT&CK-to-CVE *gold* technique mappings with
*real* NVD vulnerability descriptions.

This is the input for the at-scale LLM CVE->ATT&CK mapping experiment. The CTID
mapping (loaded by ``load_attack_to_cve.py``) is treated as the **gold standard**;
the NVD prose is the only thing the LLM will be allowed to read. Scoring the LLM
against CTID is therefore non-circular: the structured technique edges are never
shown to the model.

Sampling is deterministic (``--seed``) over the CVEs that have >=1 gold technique
mapping, so the corpus is reproducible.

Usage::

    NVD_API_KEY=... NEO4J_URI=bolt://localhost:7688 PYTHONPATH=. python \
        eval/AttackGraph/loaders/build_nvd_cve_corpus.py \
        --sample 200 --run-dir eval/AttackGraph/runs/cve-attack-map-gpt-oss-20b
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from eval.AttackGraph.lib._run_utils import (  # noqa: E402
    append_run_card,
    resolve_report_path,
    resolve_run_dir,
)

DEFAULT_REPORT_FILENAME = "nvd_cve_corpus.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sample", type=int, default=200, help="Number of CVEs to sample (0 = all).")
    parser.add_argument("--seed", type=int, default=20260604)
    parser.add_argument(
        "--cve-source",
        default="attack-to-cve",
        help="cve_source property to draw gold mappings from.",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.7,
        help="Seconds between NVD requests (0.7s ~= 43 req / 30s, safe with an API key).",
    )
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--report-path", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _fetch_gold(store: Neo4jStore, cve_source: str) -> list[dict[str, object]]:
    rows = store.run_read(
        """
        MATCH (c:CVE)
        WHERE c.cve_source = $cve_source AND c.mapped_technique_ids IS NOT NULL
        RETURN c.external_id AS cve_id, c.mapped_technique_ids AS gold_techniques
        ORDER BY c.external_id
        """,
        cve_source=cve_source,
    )
    out: list[dict[str, object]] = []
    for row in rows:
        gold = row.get("gold_techniques")
        if isinstance(gold, str):
            gold = [gold]
        gold_list = sorted({str(t).upper() for t in (gold or []) if str(t).strip()})
        if gold_list:
            out.append({"cve_id": str(row["cve_id"]).upper(), "gold_techniques": gold_list})
    return out


def _fetch_nvd_description(cve_id: str, api_key: str | None) -> str | None:
    url = f"{NVD_API_URL}?{urllib.parse.urlencode({'cveId': cve_id})}"
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310 - static NVD URL
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
        logging.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return None
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    descriptions = (((vulns[0] or {}).get("cve") or {}).get("descriptions")) or []
    for desc in descriptions:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            value = str(desc.get("value") or "").strip()
            if value:
                return value
    return None


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        logging.warning("NVD_API_KEY not set — falling back to unauthenticated rate limits.")

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        gold = _fetch_gold(store, args.cve_source)
        logging.info("Found %d CVEs with gold technique mappings (cve_source=%s).", len(gold), args.cve_source)
        if not gold:
            raise SystemExit(
                "No gold CVE mappings found. Run load_attack_to_cve.py on this graph first."
            )
        if args.sample and args.sample < len(gold):
            rng = random.Random(args.seed)
            gold = sorted(rng.sample(gold, args.sample), key=lambda r: str(r["cve_id"]))
            logging.info("Sampled %d CVEs (seed=%d).", len(gold), args.seed)
    finally:
        store.close()

    corpus: list[dict[str, object]] = []
    no_description = 0
    for idx, entry in enumerate(gold, start=1):
        cve_id = str(entry["cve_id"])
        description = _fetch_nvd_description(cve_id, api_key)
        if not description:
            no_description += 1
        corpus.append(
            {
                "cve_id": cve_id,
                "gold_techniques": entry["gold_techniques"],
                "nvd_description": description or "",
                "has_description": bool(description),
            }
        )
        if idx % 25 == 0 or idx == len(gold):
            logging.info("Fetched NVD descriptions %d/%d (missing=%d).", idx, len(gold), no_description)
        time.sleep(max(0.0, args.sleep))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "cve_source": args.cve_source,
            "sample": args.sample,
            "seed": args.seed,
            "nvd_api_key_used": bool(api_key),
        },
        "num_cves": len(corpus),
        "num_with_description": sum(1 for c in corpus if c["has_description"]),
        "num_missing_description": no_description,
        "corpus": corpus,
    }
    run_dir = resolve_run_dir(args.run_dir, default_hint="cve-attack-map")
    report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    append_run_card(
        run_dir,
        script="build_nvd_cve_corpus.py",
        config={
            "cve_source": args.cve_source,
            "sample": args.sample,
            "seed": args.seed,
            "nvd_api_key_used": bool(api_key),
            "num_cves": len(corpus),
            "num_with_description": report["num_with_description"],
            "num_missing_description": no_description,
        },
        output_files=[report_path],
    )
    print(
        json.dumps(
            {k: v for k, v in report.items() if k != "corpus"},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
