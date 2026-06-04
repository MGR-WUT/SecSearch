"""Score LLM CVE -> ATT&CK technique mapping against the CTID gold mapping, and
compare structured vs LLM CVE -> APT actor coverage.

Two questions:

1. **Mapping quality** — how well does the LLM reproduce the curated CTID
   CVE->technique mapping from raw NVD prose? (precision / recall / F1, micro+macro)
2. **Attribution coverage** — using only an actor-reachable technique set derived
   from the loaded ATT&CK graph, how many CVEs reach >=1 threat actor via the
   *structured/gold* technique mapping vs via the *LLM* technique mapping
   (+ any actor the LLM named directly)?

A technique is "actor-reachable" via the standard ATT&CK actor paths: used by an
actor directly, used by a software/campaign that is itself tied to an actor.

Usage::

    NEO4J_URI=bolt://localhost:7688 PYTHONPATH=. python \
        eval/AttackGraph/evals/eval_cve_attack_mapping.py \
        --run-dir eval/AttackGraph/runs/cve-attack-map-all-v2-gpt-oss-20b
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
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

DEFAULT_PREDICTIONS_FILENAME = "cve_attack_map_predictions.json"
DEFAULT_REPORT_FILENAME = "cve_attack_map_eval.json"


DEFAULT_TOP_KS = [1, 3, 5, 10]


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--predictions-path", type=Path, default=None)
    parser.add_argument("--top-ks", type=int, nargs="+", default=DEFAULT_TOP_KS)
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--report-path", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _actor_reachable_techniques(store: Neo4jStore) -> set[str]:
    """External IDs of techniques that reach >=1 ThreatActor via standard actor paths."""
    rows = store.run_read(
        """
        MATCH (t:Technique)
        WHERE t.external_id IS NOT NULL
          AND (
                EXISTS { (t)<-[:USES]-(:ThreatActor) }
             OR EXISTS { (t)<-[:USES]-(h)<-[:USES]-(:ThreatActor) WHERE NOT h:ThreatActor }
             OR EXISTS { (t)<-[:USES]-(:Campaign)-[:ATTRIBUTED_TO]->(:ThreatActor) }
          )
        RETURN DISTINCT toUpper(t.external_id) AS ext
        """
    )
    return {str(r["ext"]) for r in rows if r.get("ext")}


def _technique_external_ids(store: Neo4jStore) -> set[str]:
    rows = store.run_read(
        "MATCH (t:Technique) WHERE t.external_id IS NOT NULL RETURN toUpper(t.external_id) AS ext"
    )
    return {str(r["ext"]) for r in rows if r.get("ext")}


def _technique_actor_paths(store: Neo4jStore) -> dict[str, list[dict[str, object]]]:
    """{technique external_id -> [{actor_id, actor_name, paths, pagerank}, ...]}.

    Uses the standard ATT&CK actor paths, anchored at the technique (since
    attack-to-cve CVEs reach actors only through techniques):
    actor uses the technique directly, actor uses software/tool that uses the
    technique, or a campaign that uses the technique is attributed to the actor.
    ``paths`` counts the distinct evidence paths so the per-CVE actor score can
    reuse ``path_count * (1 + pagerank)``.
    """
    rows = store.run_read(
        """
        MATCH (t:Technique)
        WHERE t.external_id IS NOT NULL
        CALL {
            WITH t
            MATCH (t)<-[:USES]-(a:ThreatActor)
            RETURN a AS actor
            UNION
            WITH t
            MATCH (t)<-[:USES]-(h)<-[:USES]-(a:ThreatActor)
            WHERE NOT h:ThreatActor
            RETURN a AS actor
            UNION
            WITH t
            MATCH (t)<-[:USES]-(:Campaign)-[:ATTRIBUTED_TO]->(a:ThreatActor)
            RETURN a AS actor
        }
        RETURN toUpper(t.external_id) AS ext,
               actor.entity_id AS actor_id,
               actor.name AS actor_name,
               coalesce(actor.pagerank, 0.0) AS pagerank,
               count(*) AS paths
        """
    )
    index: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        ext = row.get("ext")
        actor_id = row.get("actor_id")
        if not ext or not actor_id:
            continue
        index.setdefault(str(ext), []).append(
            {
                "actor_id": str(actor_id),
                "actor_name": row.get("actor_name"),
                "pagerank": float(row.get("pagerank") or 0.0),
                "paths": int(row.get("paths") or 0),
            }
        )
    return index


def _parent(ext: str) -> str:
    """Roll a sub-technique to its parent: ``T1059.001`` -> ``T1059``."""
    return ext.split(".", 1)[0]


def _rollup_index(
    tech_actor_paths: dict[str, list[dict[str, object]]]
) -> dict[str, list[dict[str, object]]]:
    """Merge the per-technique actor index onto parent technique IDs, so a
    predicted parent (e.g. ``T1059``) still reaches actors that the graph only
    attaches to its sub-techniques (``T1059.001``)."""
    rolled: dict[str, list[dict[str, object]]] = {}
    for ext, hits in tech_actor_paths.items():
        rolled.setdefault(_parent(ext), []).extend(hits)
    return rolled


def _rank_actors(
    technique_ids: set[str], tech_actor_paths: dict[str, list[dict[str, object]]]
) -> list[str]:
    """Return actor_ids ranked by path_count * (1 + pagerank), highest first."""
    agg: dict[str, dict[str, float]] = {}
    for ext in technique_ids:
        for hit in tech_actor_paths.get(ext, []):
            actor_id = str(hit["actor_id"])
            bucket = agg.setdefault(actor_id, {"paths": 0.0, "pagerank": float(hit["pagerank"])})
            bucket["paths"] += float(hit["paths"])
    ranked = sorted(
        agg.items(),
        key=lambda kv: (kv[1]["paths"] * (1.0 + kv[1]["pagerank"]), kv[1]["paths"]),
        reverse=True,
    )
    return [actor_id for actor_id, _ in ranked]


def _safe_div(num: float, den: float) -> float:
    return round(num / den, 4) if den else 0.0


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    run_dir = resolve_run_dir(args.run_dir, default_hint="cve-attack-map")
    predictions_path = args.predictions_path or (run_dir / DEFAULT_PREDICTIONS_FILENAME)
    payload = json.loads(Path(predictions_path).read_text(encoding="utf-8"))
    predictions = list(payload.get("predictions") or [])
    logging.info("Loaded %d CVE predictions from %s.", len(predictions), predictions_path)

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        reachable = _actor_reachable_techniques(store)
        known = _technique_external_ids(store)
        tech_actor_paths = _technique_actor_paths(store)
        tech_actor_paths_parent = _rollup_index(tech_actor_paths)
        logging.info(
            "Actor-reachable techniques: %d / %d known (%d techniques carry actor paths).",
            len(reachable),
            len(known),
            len(tech_actor_paths),
        )
    finally:
        store.close()

    top_ks = sorted({k for k in args.top_ks if k > 0})
    micro_tp = micro_pred = micro_gold = 0
    per_cve_precision: list[float] = []
    per_cve_recall: list[float] = []
    per_cve_f1: list[float] = []
    # Parent-level (sub-technique rolled to parent) granularity-fair scoring.
    par_micro_tp = par_micro_pred = par_micro_gold = 0
    par_precision: list[float] = []
    par_recall: list[float] = []
    par_f1: list[float] = []
    covered_struct = covered_llm = covered_llm_actor_only = 0
    llm_nonempty = 0
    per_cve: list[dict[str, object]] = []
    # Top-K actor agreement: of the gold mapping's top-K actors, how many appear
    # in the LLM mapping's top-K? Only CVEs whose gold techniques reach >=1 actor.
    topk_hits: dict[int, list[float]] = {k: [] for k in top_ks}
    topk_hits_parent: dict[int, list[float]] = {k: [] for k in top_ks}
    top1_exact = 0
    top1_exact_parent = 0
    topk_eligible = 0
    topk_eligible_parent = 0
    gold_actor_counts: list[int] = []
    llm_actor_counts: list[int] = []

    for entry in predictions:
        # Restrict gold to techniques actually present in the loaded matrix so the
        # comparison is fair (CTID lists ICS/mobile/deprecated IDs with no node).
        gold = {t.upper() for t in (entry.get("gold_techniques") or [])} & known
        pred = {t.upper() for t in (entry.get("pred_techniques") or [])}
        actors = entry.get("pred_actors") or []

        tp = len(gold & pred)
        micro_tp += tp
        micro_pred += len(pred)
        micro_gold += len(gold)
        p = _safe_div(tp, len(pred))
        r = _safe_div(tp, len(gold))
        f1 = _safe_div(2 * p * r, (p + r)) if (p + r) else 0.0
        per_cve_precision.append(p)
        per_cve_recall.append(r)
        per_cve_f1.append(f1)
        if pred:
            llm_nonempty += 1

        gold_par = {_parent(t) for t in gold}
        pred_par = {_parent(t) for t in pred}
        tp_par = len(gold_par & pred_par)
        par_micro_tp += tp_par
        par_micro_pred += len(pred_par)
        par_micro_gold += len(gold_par)
        p_par = _safe_div(tp_par, len(pred_par))
        r_par = _safe_div(tp_par, len(gold_par))
        f1_par = _safe_div(2 * p_par * r_par, (p_par + r_par)) if (p_par + r_par) else 0.0
        par_precision.append(p_par)
        par_recall.append(r_par)
        par_f1.append(f1_par)

        struct_cov = bool(gold & reachable)
        llm_tech_cov = bool(pred & reachable)
        llm_cov = llm_tech_cov or bool(actors)
        if struct_cov:
            covered_struct += 1
        if llm_cov:
            covered_llm += 1
        if llm_cov and not llm_tech_cov and actors:
            covered_llm_actor_only += 1

        gold_ranked = _rank_actors(gold, tech_actor_paths)
        llm_ranked = _rank_actors(pred, tech_actor_paths)
        gold_actor_counts.append(len(gold_ranked))
        llm_actor_counts.append(len(llm_ranked))
        cve_topk: dict[str, float] = {}
        if gold_ranked:
            topk_eligible += 1
            if llm_ranked and llm_ranked[0] == gold_ranked[0]:
                top1_exact += 1
            for k in top_ks:
                gold_topk = gold_ranked[:k]
                llm_topk = set(llm_ranked[:k])
                hit = sum(1 for a in gold_topk if a in llm_topk) / len(gold_topk)
                topk_hits[k].append(hit)
                cve_topk[f"recall_at_{k}"] = round(hit, 4)

        gold_ranked_par = _rank_actors(gold_par, tech_actor_paths_parent)
        llm_ranked_par = _rank_actors(pred_par, tech_actor_paths_parent)
        if gold_ranked_par:
            topk_eligible_parent += 1
            if llm_ranked_par and llm_ranked_par[0] == gold_ranked_par[0]:
                top1_exact_parent += 1
            for k in top_ks:
                gold_topk_par = gold_ranked_par[:k]
                llm_topk_par = set(llm_ranked_par[:k])
                hit_par = sum(1 for a in gold_topk_par if a in llm_topk_par) / len(gold_topk_par)
                topk_hits_parent[k].append(hit_par)

        per_cve.append(
            {
                "cve_id": entry.get("cve_id"),
                "gold_in_matrix": sorted(gold),
                "pred": sorted(pred),
                "tp": tp,
                "precision": p,
                "recall": r,
                "f1": f1,
                "struct_covered": struct_cov,
                "llm_covered": llm_cov,
                "named_actors": [a.get("name") for a in actors],
                "gold_candidate_actors": len(gold_ranked),
                "llm_candidate_actors": len(llm_ranked),
                "topk_actor_recall": cve_topk,
            }
        )

    n = len(predictions)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "predictions_path": str(predictions_path),
            "num_cves": n,
        },
        "mapping_quality": {
            "micro_precision": _safe_div(micro_tp, micro_pred),
            "micro_recall": _safe_div(micro_tp, micro_gold),
            "micro_f1": _safe_div(
                2 * micro_tp, (micro_pred + micro_gold)
            ),
            "macro_precision": round(statistics.fmean(per_cve_precision), 4) if per_cve_precision else 0.0,
            "macro_recall": round(statistics.fmean(per_cve_recall), 4) if per_cve_recall else 0.0,
            "macro_f1": round(statistics.fmean(per_cve_f1), 4) if per_cve_f1 else 0.0,
            "cves_with_nonempty_prediction": llm_nonempty,
            "total_gold_pairs": micro_gold,
            "total_pred_pairs": micro_pred,
            "total_true_positives": micro_tp,
        },
        "mapping_quality_parent_level": {
            "note": (
                "Sub-techniques rolled to parent (T1059.001 -> T1059) before scoring; "
                "removes the granularity penalty when the LLM names the right family."
            ),
            "micro_precision": _safe_div(par_micro_tp, par_micro_pred),
            "micro_recall": _safe_div(par_micro_tp, par_micro_gold),
            "micro_f1": _safe_div(2 * par_micro_tp, (par_micro_pred + par_micro_gold)),
            "macro_precision": round(statistics.fmean(par_precision), 4) if par_precision else 0.0,
            "macro_recall": round(statistics.fmean(par_recall), 4) if par_recall else 0.0,
            "macro_f1": round(statistics.fmean(par_f1), 4) if par_f1 else 0.0,
            "total_gold_pairs": par_micro_gold,
            "total_pred_pairs": par_micro_pred,
            "total_true_positives": par_micro_tp,
        },
        "attribution_coverage": {
            "num_cves": n,
            "structured_gold_coverage": _safe_div(covered_struct, n),
            "structured_gold_covered": covered_struct,
            "llm_coverage": _safe_div(covered_llm, n),
            "llm_covered": covered_llm,
            "llm_covered_via_named_actor_only": covered_llm_actor_only,
            "coverage_gap": _safe_div(covered_struct - covered_llm, n),
        },
        "topk_actor_agreement": {
            "description": (
                "Of the gold mapping's top-K actors (ranked by path_count*(1+pagerank)), "
                "mean fraction also present in the LLM mapping's top-K. Sharper than "
                "binary reachability: measures whether the SAME actors are surfaced."
            ),
            "eligible_cves": topk_eligible,
            "top1_exact_match": _safe_div(top1_exact, topk_eligible),
            "mean_recall_at_k": {
                str(k): round(statistics.fmean(topk_hits[k]), 4) if topk_hits[k] else 0.0
                for k in top_ks
            },
            "mean_gold_candidate_actors": round(statistics.fmean(gold_actor_counts), 3)
            if gold_actor_counts
            else 0.0,
            "mean_llm_candidate_actors": round(statistics.fmean(llm_actor_counts), 3)
            if llm_actor_counts
            else 0.0,
            "parent_level": {
                "note": "Same metric with predicted/gold/graph techniques rolled to parent.",
                "eligible_cves": topk_eligible_parent,
                "top1_exact_match": _safe_div(top1_exact_parent, topk_eligible_parent),
                "mean_recall_at_k": {
                    str(k): round(statistics.fmean(topk_hits_parent[k]), 4)
                    if topk_hits_parent[k]
                    else 0.0
                    for k in top_ks
                },
            },
        },
        "per_cve": per_cve,
    }
    report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    append_run_card(
        run_dir,
        script="eval_cve_attack_mapping.py",
        config={
            "num_cves": n,
            **report["mapping_quality"],
            **{f"coverage_{k}": v for k, v in report["attribution_coverage"].items()},
        },
        output_files=[report_path],
    )
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "mapping_quality",
                    "mapping_quality_parent_level",
                    "attribution_coverage",
                    "topk_actor_agreement",
                )
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
