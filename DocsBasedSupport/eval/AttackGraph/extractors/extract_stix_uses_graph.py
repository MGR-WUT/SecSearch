"""Extract (ThreatActor)-[:USES]->(Technique) from STIX prose via GraphoDynamo's LLM path.

Each MITRE group is turned into a synthetic CTI document (group description + per-edge
``uses`` relationship text from the STIX bundle). A local/cloud LLM re-extracts USES
edges; results are written as ``USES_EXTRACTED`` so deterministic STIX stays intact.

Usage::

    PYTHONPATH=. python eval/AttackGraph/loaders/load_attack.py --enrich --reset
    PYTHONPATH=. python eval/AttackGraph/extractors/extract_stix_uses_graph.py \\
        --model gemma3:4b --reset --run-dir eval/AttackGraph/runs/stix-llm-gemma3-4b
    PYTHONPATH=. python eval/AttackGraph/evals/eval_stix_extraction_quality.py \\
        --graph-variant llm-extracted:gemma3-4b --run-dir ...
    PYTHONPATH=. python eval/AttackGraph/evals/eval_link_prediction.py \\
        --graph-variant llm-extracted:gemma3-4b --run-dir ...
"""

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
from app.core.llm_factory import build_chat_llm  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from app.pipeline.attack_uses_extractor import AttackUsesExtractor  # noqa: E402
from app.pipeline.attack_graph_variants import build_llm_extracted_variant  # noqa: E402
from eval.AttackGraph.lib._run_utils import append_run_card, resolve_report_path, resolve_run_dir  # noqa: E402
from eval.AttackGraph.loaders.load_attack import DEFAULT_BUNDLE_PATH, DEFAULT_BUNDLE_URL, _ensure_bundle  # noqa: E402
from eval.AttackGraph.lib.stix_actor_reports import build_actor_reports, reports_to_corpus_payload  # noqa: E402
from eval.AttackGraph.lib.stix_document_structure import (  # noqa: E402
    apply_structure_profile,
    corpus_structure_summary,
    structure_profiles,
)

DEFAULT_CORPUS_FILENAME = "stix_actor_corpus.json"
DEFAULT_EXTRACTION_FILENAME = "stix_uses_extraction.json"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", required=True, help="LLM model id (e.g. gemma3:4b, gpt-oss:20b).")
    parser.add_argument("--bundle-path", type=Path, default=DEFAULT_BUNDLE_PATH)
    parser.add_argument("--limit", type=int, default=None, help="Cap number of actor reports processed.")
    parser.add_argument(
        "--structure-profile",
        default="structured",
        choices=structure_profiles(),
        help="Controlled lack-of-structure on input documents (structured=mild STIX layout).",
    )
    parser.add_argument("--structure-seed", type=int, default=20260603, help="RNG seed for severe shuffling.")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete prior USES_EXTRACTED for this run's graph_variant only.",
    )
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
    hint = f"stix-llm-{model_slug}"
    if args.structure_profile != "structured":
        hint = f"{hint}-struct-{args.structure_profile}"
    run_dir = resolve_run_dir(args.run_dir, default_hint=hint)
    run_dir.mkdir(parents=True, exist_ok=True)

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        bundle_path = _ensure_bundle(args.bundle_path, DEFAULT_BUNDLE_URL)

        reports = build_actor_reports(bundle_path)
        if args.limit:
            reports = reports[: args.limit]
        if not reports:
            raise SystemExit("No actor reports built from STIX bundle.")

        for report in reports:
            report.text = apply_structure_profile(
                report.text,
                args.structure_profile,
                seed=args.structure_seed,
                doc_key=report.actor_entity_id,
            )
        structure_metrics = corpus_structure_summary([r.text for r in reports])
        (run_dir / "structure_metrics.json").write_text(
            json.dumps(
                {
                    "structure_profile": args.structure_profile,
                    "structure_seed": args.structure_seed,
                    **structure_metrics,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        llm = build_chat_llm(
            provider=settings.llm_provider,
            model=args.model,
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
        )
        extractor = AttackUsesExtractor(
            store,
            llm,
            model_name=args.model,
            structure_profile=args.structure_profile,
        )

        deleted = 0
        if args.reset:
            deleted = extractor.clear_extracted_edges(graph_variant=extractor.graph_variant)
            logging.info(
                "Cleared %d prior USES_EXTRACTED edges for variant %s.",
                deleted,
                extractor.graph_variant,
            )

        summary = extractor.extract_reports(reports, progress_every=1)
        written = extractor.write_edges(summary)

        corpus_path = run_dir / DEFAULT_CORPUS_FILENAME
        corpus_payload = reports_to_corpus_payload(reports)
        corpus_payload["structure_profile"] = args.structure_profile
        corpus_payload["structure_metrics"] = structure_metrics
        corpus_path.write_text(json.dumps(corpus_payload, indent=2), encoding="utf-8")
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "model": args.model,
                "graph_variant": extractor.graph_variant,
                "structure_profile": args.structure_profile,
                "structure_seed": args.structure_seed,
                "structure_metrics": structure_metrics,
                "bundle_path": str(bundle_path),
                "limit": args.limit,
                "reset": bool(args.reset),
                "prior_edges_deleted": deleted,
            },
            "summary": summary.as_dict(),
            "parse_failure_actors": [
                r.actor_name for r in summary.per_actor if r.parse_failed
            ],
            "edges_written": written,
            "next_commands": [
                f"PYTHONPATH=. python eval/AttackGraph/evals/eval_stix_extraction_quality.py "
                f'--graph-variant "{summary.graph_variant}" --run-dir {run_dir}',
                f"PYTHONPATH=. python eval/AttackGraph/evals/eval_link_prediction.py "
                f'--graph-variant "{summary.graph_variant}" --run-dir {run_dir}',
            ],
        }
        report_path = resolve_report_path(None, run_dir, DEFAULT_EXTRACTION_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        append_run_card(
            run_dir,
            script="extract_stix_uses_graph.py",
            config=report["config"],
            output_files=[corpus_path, report_path],
        )
        print(json.dumps(report, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
