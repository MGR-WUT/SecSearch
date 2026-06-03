"""LLM-extract (ThreatActor)-[:EXPLOITS]->(CVE) from CTI actor documents."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.core.llm_factory import build_chat_llm  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from app.pipeline.attack_cti_cve_extractor import AttackCtiCveExtractor  # noqa: E402
from eval.AttackGraph.lib._run_utils import append_run_card, resolve_report_path, resolve_run_dir  # noqa: E402

DEFAULT_CORPUS_FILENAME = "cti_cve_actor_corpus.json"
DEFAULT_EXTRACTION_FILENAME = "cti_cve_extraction.json"


@dataclass
class _Report:
    actor_entity_id: str
    actor_name: str
    actor_external_id: str | None
    text: str


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--corpus-path", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    model_slug = args.model.replace(":", "-")
    run_dir = resolve_run_dir(args.run_dir, default_hint=f"cti-cve-llm-{model_slug}")
    corpus_path = args.corpus_path or (run_dir / DEFAULT_CORPUS_FILENAME)
    if not corpus_path.exists():
        raise SystemExit(f"Corpus not found: {corpus_path}")

    payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    documents = payload.get("documents", [])
    reports = [
        _Report(
            actor_entity_id=str(doc["actor_entity_id"]),
            actor_name=str(doc["actor_name"]),
            actor_external_id=doc.get("actor_external_id"),
            text=str(doc.get("text") or ""),
        )
        for doc in documents
        if doc.get("actor_entity_id") and doc.get("text")
    ]
    if args.limit:
        reports = reports[: args.limit]

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        llm = build_chat_llm(
            provider=settings.llm_provider,
            model=args.model,
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
        )
        extractor = AttackCtiCveExtractor(
            store,
            llm,
            model_name=args.model,
            provider_tag=settings.llm_provider,
        )
        deleted = 0
        if args.reset:
            deleted = extractor.clear_extracted_edges()
        summary = extractor.extract_reports(reports, progress_every=5)
        written = extractor.write_edges(summary)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "model": args.model,
                "extraction_variant": summary.extraction_variant,
                "corpus_path": str(corpus_path),
                "limit": args.limit,
                "reset": bool(args.reset),
                "prior_edges_deleted": deleted,
            },
            "summary": summary.as_dict(),
            "edges_written": written,
            "parse_failure_actors": [
                r.actor_name for r in summary.per_actor if r.parse_failed
            ],
            "next_commands": [
                f"PYTHONPATH=. python eval/AttackGraph/evals/eval_cti_cve_extraction_quality.py "
                f'--extraction-variant "{summary.extraction_variant}" --run-dir {run_dir}',
            ],
        }
        report_path = resolve_report_path(None, run_dir, DEFAULT_EXTRACTION_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        append_run_card(
            run_dir,
            script="extract_cti_cve_graph.py",
            config=report["config"],
            output_files=[report_path],
        )
        print(json.dumps(report, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
