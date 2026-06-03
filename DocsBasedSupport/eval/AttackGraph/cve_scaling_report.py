"""Bootstrap stability analysis for CVE-to-APT coverage at multiple sample sizes."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from eval.AttackGraph._run_utils import append_run_card, resolve_report_path, resolve_run_dir  # noqa: E402

DEFAULT_REPORT_FILENAME = "cve_scaling_report.json"
DEFAULT_SAMPLE_CSV = "cve_attribution_sample.csv"
DEFAULT_SAMPLE_SIZES = [33, 100, 200, 400, 800]


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--baseline-report",
        type=Path,
        required=True,
        help="Path to cve_apt_paths_baseline.json (or variant).",
    )
    parser.add_argument(
        "--enriched-report",
        type=Path,
        default=None,
        help="Optional enriched report for lift comparison.",
    )
    parser.add_argument(
        "--sample-sizes",
        type=int,
        nargs="+",
        default=DEFAULT_SAMPLE_SIZES,
    )
    parser.add_argument("--bootstrap-iters", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20260603)
    parser.add_argument(
        "--precision-sample-size",
        type=int,
        default=50,
        help="Number of attributed CVEs to export for manual precision review.",
    )
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _load_per_cve(path: Path) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return list(payload.get("per_cve") or [])


def _coverage_fraction(entries: list[dict[str, object]]) -> float:
    if not entries:
        return 0.0
    linked = sum(1 for e in entries if int(e.get("actor_link_count") or 0) > 0)
    return linked / len(entries)


def _bootstrap_coverage(
    entries: list[dict[str, object]],
    *,
    sample_size: int,
    iters: int,
    seed: int,
) -> dict[str, float]:
    if not entries:
        return {"mean": 0.0, "ci_low": 0.0, "ci_high": 0.0}
    rng = random.Random(seed)
    n = min(sample_size, len(entries))
    scores: list[float] = []
    for _ in range(iters):
        sample = rng.sample(entries, n) if n < len(entries) else list(entries)
        scores.append(_coverage_fraction(sample))
    scores.sort()
    mean = statistics.fmean(scores)
    low_idx = max(0, int(0.025 * len(scores)) - 1)
    high_idx = min(len(scores) - 1, int(0.975 * len(scores)))
    return {
        "mean": round(mean, 4),
        "ci_low": round(scores[low_idx], 4),
        "ci_high": round(scores[high_idx], 4),
    }


def _scaling_curve(entries: list[dict[str, object]], sample_sizes: list[int], seed: int) -> list[dict[str, object]]:
    curve: list[dict[str, object]] = []
    for size in sorted(set(sample_sizes)):
        effective = min(size, len(entries))
        curve.append(
            {
                "requested_n": size,
                "effective_n": effective,
                "bootstrap": _bootstrap_coverage(
                    entries, sample_size=effective, iters=50, seed=seed + size
                ),
            }
        )
    return curve


def _export_precision_sample(
    entries: list[dict[str, object]],
    path: Path,
    *,
    sample_size: int,
    seed: int,
) -> int:
    attributed = [e for e in entries if int(e.get("actor_link_count") or 0) > 0]
    if not attributed:
        return 0
    rng = random.Random(seed)
    sample = rng.sample(attributed, min(sample_size, len(attributed)))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "cve_id",
                "actor_link_count",
                "total_evidence_paths",
                "top_actor_name",
                "top_actor_paths",
                "manual_correct",
                "notes",
            ],
        )
        writer.writeheader()
        for entry in sample:
            top = (entry.get("top_actors") or [{}])[0]
            writer.writerow(
                {
                    "cve_id": entry.get("cve_id"),
                    "actor_link_count": entry.get("actor_link_count"),
                    "total_evidence_paths": entry.get("total_evidence_paths"),
                    "top_actor_name": top.get("actor_name"),
                    "top_actor_paths": top.get("path_count"),
                    "manual_correct": "",
                    "notes": "",
                }
            )
    return len(sample)


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    baseline_entries = _load_per_cve(args.baseline_report)
    enriched_entries = _load_per_cve(args.enriched_report) if args.enriched_report else None

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "baseline_report": str(args.baseline_report),
            "enriched_report": str(args.enriched_report) if args.enriched_report else None,
            "sample_sizes": args.sample_sizes,
            "bootstrap_iters": args.bootstrap_iters,
            "seed": args.seed,
        },
        "baseline": {
            "num_cves": len(baseline_entries),
            "full_coverage": round(_coverage_fraction(baseline_entries), 4),
            "scaling_curve": _scaling_curve(baseline_entries, args.sample_sizes, args.seed),
            "bootstrap_full": _bootstrap_coverage(
                baseline_entries,
                sample_size=len(baseline_entries),
                iters=args.bootstrap_iters,
                seed=args.seed,
            ),
        },
    }
    if enriched_entries is not None:
        report["enriched"] = {
            "num_cves": len(enriched_entries),
            "full_coverage": round(_coverage_fraction(enriched_entries), 4),
            "scaling_curve": _scaling_curve(enriched_entries, args.sample_sizes, args.seed + 1),
            "bootstrap_full": _bootstrap_coverage(
                enriched_entries,
                sample_size=len(enriched_entries),
                iters=args.bootstrap_iters,
                seed=args.seed + 1,
            ),
            "coverage_lift": round(
                _coverage_fraction(enriched_entries) - _coverage_fraction(baseline_entries),
                4,
            ),
        }

    run_dir = resolve_run_dir(args.run_dir, default_hint="cve-scaling")
    report_path = resolve_report_path(None, run_dir, DEFAULT_REPORT_FILENAME)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    sample_csv = run_dir / DEFAULT_SAMPLE_CSV
    exported = _export_precision_sample(
        enriched_entries or baseline_entries,
        sample_csv,
        sample_size=args.precision_sample_size,
        seed=args.seed,
    )
    append_run_card(
        run_dir,
        script="cve_scaling_report.py",
        config=report["config"],
        output_files=[report_path, sample_csv],
    )
    report["precision_sample_exported"] = exported
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
