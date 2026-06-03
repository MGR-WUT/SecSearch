"""Aggregate structure-sweep metrics vs clean STIX link-prediction baseline."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RUNS = PROJECT_ROOT / "eval" / "AttackGraph" / "runs"
REPORTS = PROJECT_ROOT / "eval" / "AttackGraph" / "reports"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _neighbour_hits10(link_pred: dict) -> float | None:
    agg = link_pred.get("aggregated", {})
    neighbour = agg.get("neighbour", {})
    val = neighbour.get("hits@10")
    return float(val) if val is not None else None


def _extraction_f1(quality: dict) -> dict[str, float]:
    pairs = quality.get("actor_technique_pairs_vs_corpus_gold", {})
    return {
        "precision": float(pairs.get("precision", 0)),
        "recall": float(pairs.get("recall", 0)),
        "f1": float(pairs.get("f1", 0)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="gpt-oss:20b-cloud")
    parser.add_argument("--profiles", default="mild,moderate,severe")
    parser.add_argument(
        "--structured-run",
        type=Path,
        default=RUNS / "stix-llm-gpt-oss-20b-cloud",
        help="Run dir for structured (default STIX layout) LLM extraction.",
    )
    parser.add_argument(
        "--baseline-link-pred",
        type=Path,
        default=REPORTS / "link_prediction.json",
    )
    parser.add_argument("--out", type=Path, default=RUNS / "structure_sweep_summary.json")
    args = parser.parse_args(argv)

    baseline_lp = _load(args.baseline_link_pred) if args.baseline_link_pred.exists() else {}
    baseline_hits = _neighbour_hits10(baseline_lp)

    rows: list[dict] = []
    if args.structured_run.exists():
        q_path = args.structured_run / "extraction_quality.json"
        lp_path = args.structured_run / "link_prediction.json"
        ext_path = args.structured_run / "stix_uses_extraction.json"
        if q_path.exists() and lp_path.exists() and ext_path.exists():
            q = _load(q_path)
            lp = _load(lp_path)
            ext = _load(ext_path)
            struct_metrics = _load(args.structured_run / "structure_metrics.json") if (
                args.structured_run / "structure_metrics.json"
            ).exists() else {}
            rows.append(
                {
                    "profile": "structured",
                    "graph_variant": ext["config"].get("graph_variant"),
                    "lack_of_structure_score": struct_metrics.get("mean_lack_of_structure_score"),
                    "parse_failures": ext["summary"].get("parse_failures"),
                    "parse_recoveries": ext["summary"].get("parse_recoveries", 0),
                    "extraction": _extraction_f1(q),
                    "neighbour_hits10": _neighbour_hits10(lp),
                    "delta_hits10_vs_clean": (
                        (_neighbour_hits10(lp) - baseline_hits) if baseline_hits and _neighbour_hits10(lp) is not None else None
                    ),
                }
            )

    slug = args.model.replace(":", "-")
    for profile in [p.strip() for p in args.profiles.split(",") if p.strip()]:
        run_dir = RUNS / f"stix-llm-{slug}-struct-{profile}"
        q_path = run_dir / "extraction_quality.json"
        lp_path = run_dir / "link_prediction.json"
        ext_path = run_dir / "stix_uses_extraction.json"
        struct_path = run_dir / "structure_metrics.json"
        if not (q_path.exists() and lp_path.exists() and ext_path.exists()):
            print(f"skip {profile}: missing eval artefacts in {run_dir}", file=sys.stderr)
            continue
        q, lp, ext = _load(q_path), _load(lp_path), _load(ext_path)
        struct_metrics = _load(struct_path) if struct_path.exists() else {}
        hits = _neighbour_hits10(lp)
        rows.append(
            {
                "profile": profile,
                "graph_variant": ext["config"].get("graph_variant"),
                "lack_of_structure_score": struct_metrics.get("mean_lack_of_structure_score"),
                "parse_failures": ext["summary"].get("parse_failures"),
                "parse_recoveries": ext["summary"].get("parse_recoveries", 0),
                "extraction": _extraction_f1(q),
                "neighbour_hits10": hits,
                "delta_hits10_vs_clean": (hits - baseline_hits) if baseline_hits and hits is not None else None,
            }
        )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": args.model,
        "clean_stix_neighbour_hits10": baseline_hits,
        "rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Clean STIX neighbour Hits@10: {baseline_hits}")
    print(f"{'profile':<12} {'lack_struct':>12} {'P':>6} {'R':>6} {'F1':>6} {'Hits@10':>8} {'Δ clean':>8} {'parse_fail':>10}")
    for row in rows:
        ex = row["extraction"]
        print(
            f"{row['profile']:<12} "
            f"{(row.get('lack_of_structure_score') or 0):>12.4f} "
            f"{ex['precision']:>6.3f} "
            f"{ex['recall']:>6.3f} "
            f"{ex['f1']:>6.3f} "
            f"{(row.get('neighbour_hits10') or 0):>8.3f} "
            f"{(row.get('delta_hits10_vs_clean') or 0):>8.3f} "
            f"{row.get('parse_failures', 0):>10}"
        )
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
