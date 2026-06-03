"""Run mild / moderate / severe document-structure arms + downstream evals.

Structured (baseline) input is the default STIX report layout from ``stix_actor_reports``.
Each profile writes a separate ``graph_variant`` so clean STIX and other models stay intact.

Usage::

    cd DocsBasedSupport
    PYTHONPATH=. python eval/AttackGraph/evals/run_stix_structure_sweep.py \\
        --model gpt-oss:20b-cloud --profiles mild,moderate,severe
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROFILES = ("mild", "moderate", "severe")


def _run(cmd: list[str], *, cwd: Path) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default="gpt-oss:20b-cloud")
    parser.add_argument(
        "--profiles",
        default=",".join(DEFAULT_PROFILES),
        help="Comma-separated structure profiles (mild,moderate,severe).",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--skip-extract", action="store_true", help="Only run quality + link-pred evals.")
    parser.add_argument("--seed", type=int, default=20260603)
    args = parser.parse_args(argv)

    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    py = sys.executable
    runs_root = PROJECT_ROOT / "eval" / "AttackGraph" / "runs"

    for profile in profiles:
        slug = args.model.replace(":", "-")
        run_dir = runs_root / f"stix-llm-{slug}-struct-{profile}"
        run_dir.mkdir(parents=True, exist_ok=True)
        extract_cmd = [
            py,
            "eval/AttackGraph/extractors/extract_stix_uses_graph.py",
            "--model",
            args.model,
            "--structure-profile",
            profile,
            "--structure-seed",
            str(args.seed),
            "--reset",
            "--run-dir",
            str(run_dir),
        ]
        if args.limit:
            extract_cmd.extend(["--limit", str(args.limit)])
        if not args.skip_extract:
            _run(extract_cmd, cwd=PROJECT_ROOT)

        report = run_dir / "stix_uses_extraction.json"
        if not report.exists():
            raise SystemExit(f"Missing {report}; extraction did not complete.")
        import json

        variant = json.loads(report.read_text(encoding="utf-8"))["config"]["graph_variant"]
        _run(
            [
                py,
                "eval/AttackGraph/evals/eval_stix_extraction_quality.py",
                "--graph-variant",
                variant,
                "--run-dir",
                str(run_dir),
            ],
            cwd=PROJECT_ROOT,
        )
        _run(
            [
                py,
                "eval/AttackGraph/evals/eval_link_prediction.py",
                "--graph-variant",
                variant,
                "--run-dir",
                str(run_dir),
            ],
            cwd=PROJECT_ROOT,
        )

    summarize = [
        py,
        "eval/AttackGraph/evals/summarize_structure_sweep.py",
        "--model",
        args.model,
        "--profiles",
        args.profiles,
    ]
    _run(summarize, cwd=PROJECT_ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
