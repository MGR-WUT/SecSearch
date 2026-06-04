"""Summarize explicit IDs present in NVD descriptions for the CVE mapping corpus.

The B2 experiment asks an LLM to infer ATT&CK techniques from NVD prose. This
helper checks whether the prose literally contains ATT&CK technique IDs, so the
write-up can distinguish quote-like extraction from inference.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from eval.AttackGraph.lib._run_utils import append_run_card, resolve_report_path, resolve_run_dir

DEFAULT_CORPUS_FILENAME = "nvd_cve_corpus.json"
DEFAULT_REPORT_FILENAME = "nvd_explicit_id_summary.json"

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
CWE_ID_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-path", type=Path, default=None)
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--report-path", type=Path, default=None)
    return parser


def _ids(pattern: re.Pattern[str], text: str) -> list[str]:
    return sorted({match.group(0).upper() for match in pattern.finditer(text or "")})


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    run_dir = resolve_run_dir(args.run_dir, default_hint="cve-attack-map")
    corpus_path = args.corpus_path or (run_dir / DEFAULT_CORPUS_FILENAME)
    payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    rows = list(payload.get("corpus") or [])

    per_cve: list[dict[str, object]] = []
    for row in rows:
        description = str(row.get("nvd_description") or "")
        per_cve.append(
            {
                "cve_id": row.get("cve_id"),
                "explicit_attack_ids": _ids(ATTACK_ID_RE, description),
                "explicit_cwe_ids": _ids(CWE_ID_RE, description),
                "explicit_cve_ids": _ids(CVE_ID_RE, description),
            }
        )

    attack = [r for r in per_cve if r["explicit_attack_ids"]]
    cwe = [r for r in per_cve if r["explicit_cwe_ids"]]
    cve = [r for r in per_cve if r["explicit_cve_ids"]]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {"corpus_path": str(corpus_path), "num_cves": len(rows)},
        "summary": {
            "num_cves": len(rows),
            "descriptions_with_explicit_attack_ids": len(attack),
            "descriptions_without_explicit_attack_ids": len(rows) - len(attack),
            "descriptions_with_explicit_cwe_ids": len(cwe),
            "descriptions_with_explicit_cve_ids": len(cve),
        },
        "with_explicit_attack_ids": attack,
        "with_explicit_cwe_ids": cwe,
        "with_explicit_cve_ids": cve,
        "per_cve": per_cve,
    }
    report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    append_run_card(
        run_dir,
        script="summarize_nvd_explicit_ids.py",
        config=report["summary"],
        output_files=[report_path],
    )
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
