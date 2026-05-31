"""Link-prediction evaluation on the MITRE ATT&CK Enterprise graph.

Motivation
----------
Supervisor feedback: GraphoDynamo's WildGraphBench (general IT) numbers do not
demonstrate that the system can map *specialised* security relationships
(CVE -> APT, technique -> actor). This experiment loads MITRE ATT&CK into
Neo4j, hides a random sample of explicit ``(ThreatActor)-[:USES]->(Technique)``
edges, and asks: can PageRank + Louvain (the graph-analytics layer the thesis
claims is useful) **recover** the hidden edges from the remaining graph?

We compare four ranking strategies against the held-out edges:

1. ``random``   - baseline; random ordering of Technique candidates.
2. ``popularity`` - rank by global Technique PageRank computed on the train
   graph; ignores which actor is asking.
3. ``neighbour`` - collaborative-style: for each candidate Technique, count how
   many *other* actors share at least one Technique with the query actor and
   also use the candidate (2-hop co-use). Pure graph traversal, no PageRank.
4. ``neighbour_pagerank`` - same 2-hop neighbour count multiplied by the
   candidate's train-graph PageRank (graph structure + centrality).

The experiment is reproducible via a seeded random split and writes a single
report JSON. It assumes the ATT&CK bundle has already been loaded via
``eval/AttackGraph/load_attack.py``.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from eval.AttackGraph._run_utils import (  # noqa: E402
    append_run_card,
    resolve_report_path,
    resolve_run_dir,
)

DEFAULT_REPORT_FILENAME = "link_prediction.json"


@dataclass
class HeldOutEdge:
    actor_id: str
    actor_name: str
    technique_id: str
    technique_name: str


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=20260529)
    parser.add_argument(
        "--hold-out-fraction",
        type=float,
        default=0.2,
        help="Fraction of (Actor)-[:USES]->(Technique) edges to hide for evaluation.",
    )
    parser.add_argument(
        "--top-ks",
        type=int,
        nargs="+",
        default=[5, 10, 20, 50],
        help="K values to compute Precision@K / Recall@K / Hits@K.",
    )
    parser.add_argument(
        "--max-actors",
        type=int,
        default=None,
        help="Optional cap on evaluated actors (useful for smoke tests).",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help=(
            "Run directory for tracked outputs (defaults to "
            "eval/AttackGraph/runs/link-prediction-<UTC timestamp>)."
        ),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=None,
        help="Explicit override for the report path. Wins over --run-dir.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def _fetch_uses_edges(store: Neo4jStore) -> list[HeldOutEdge]:
    rows = store.run_read(
        """
        MATCH (a:ThreatActor)-[r:USES]->(t:Technique)
        RETURN a.entity_id AS actor_id, a.name AS actor_name,
               t.entity_id AS technique_id, t.name AS technique_name
        """
    )
    return [
        HeldOutEdge(
            actor_id=row["actor_id"],
            actor_name=row["actor_name"],
            technique_id=row["technique_id"],
            technique_name=row["technique_name"],
        )
        for row in rows
    ]


def _mark_held_out(store: Neo4jStore, edges: Iterable[HeldOutEdge]) -> int:
    pairs = [{"a": e.actor_id, "t": e.technique_id} for e in edges]
    if not pairs:
        return 0
    result = store.run_write(
        """
        UNWIND $pairs AS pair
        MATCH (a:ThreatActor {entity_id: pair.a})-[r:USES]->(t:Technique {entity_id: pair.t})
        SET r.held_out = true
        RETURN count(r) AS updated
        """,
        pairs=pairs,
    )
    return int(result[0]["updated"]) if result else 0


def _reset_held_out(store: Neo4jStore) -> int:
    result = store.run_write(
        """
        MATCH ()-[r {held_out: true}]->()
        SET r.held_out = false
        RETURN count(r) AS updated
        """
    )
    return int(result[0]["updated"]) if result else 0


def _project_train_graph(store: Neo4jStore) -> None:
    # Drop any leftover projection first so reruns are idempotent.
    store.run_write("CALL gds.graph.drop('attack_train', false) YIELD graphName RETURN graphName")
    store.run_write(
        """
        CALL gds.graph.project.cypher(
          'attack_train',
          'MATCH (n) WHERE n:ThreatActor OR n:Technique OR n:Tactic OR n:Malware OR n:Tool OR n:Mitigation OR n:CVE OR n:Campaign RETURN id(n) AS id, labels(n) AS labels',
          'MATCH (a:AttackEntity)-[r]->(b:AttackEntity)
           WHERE coalesce(r.held_out, false) = false
             AND type(r) IN ["USES", "MITIGATES", "SUBTECHNIQUE_OF", "ATTRIBUTED_TO", "TARGETS", "EXPLOITS", "IN_TACTIC"]
           RETURN id(a) AS source, id(b) AS target, type(r) AS type'
        ) YIELD graphName, nodeCount, relationshipCount
        RETURN graphName, nodeCount, relationshipCount
        """
    )
    store.run_write(
        "CALL gds.pageRank.write('attack_train', {writeProperty: 'pagerank_train'}) "
        "YIELD nodePropertiesWritten RETURN nodePropertiesWritten"
    )
    store.run_write(
        "CALL gds.louvain.write('attack_train', {writeProperty: 'community_train'}) "
        "YIELD communityCount RETURN communityCount"
    )
    store.run_write("CALL gds.graph.drop('attack_train') YIELD graphName RETURN graphName")


def _all_technique_candidates(store: Neo4jStore) -> list[dict[str, object]]:
    rows = store.run_read(
        """
        MATCH (t:Technique)
        RETURN t.entity_id AS technique_id,
               t.name AS technique_name,
               coalesce(t.pagerank_train, 0.0) AS pagerank_train,
               coalesce(t.community_train, -1) AS community_train
        """
    )
    return list(rows)


def _actor_known_techniques(
    store: Neo4jStore, actor_id: str
) -> set[str]:
    rows = store.run_read(
        """
        MATCH (a:ThreatActor {entity_id: $actor_id})-[r:USES]->(t:Technique)
        WHERE coalesce(r.held_out, false) = false
        RETURN t.entity_id AS technique_id
        """,
        actor_id=actor_id,
    )
    return {row["technique_id"] for row in rows}


def _neighbour_scores(store: Neo4jStore, actor_id: str) -> dict[str, int]:
    """For a query actor, count 2-hop co-use paths through other actors (train edges only)."""
    rows = store.run_read(
        """
        MATCH (a:ThreatActor {entity_id: $actor_id})-[r1:USES]->(t:Technique)
              <-[r2:USES]-(other:ThreatActor)-[r3:USES]->(candidate:Technique)
        WHERE coalesce(r1.held_out, false) = false
          AND coalesce(r2.held_out, false) = false
          AND coalesce(r3.held_out, false) = false
          AND other <> a
        RETURN candidate.entity_id AS technique_id, count(*) AS shared_path_count
        """,
        actor_id=actor_id,
    )
    return {row["technique_id"]: int(row["shared_path_count"]) for row in rows}


def _rank_random(candidates: list[dict[str, object]], rng: random.Random) -> list[str]:
    shuffled = list(candidates)
    rng.shuffle(shuffled)
    return [str(item["technique_id"]) for item in shuffled]


def _rank_popularity(candidates: list[dict[str, object]]) -> list[str]:
    return [
        str(item["technique_id"])
        for item in sorted(candidates, key=lambda c: float(c["pagerank_train"]), reverse=True)
    ]


def _rank_neighbour(
    candidates: list[dict[str, object]], scores: dict[str, int], rng: random.Random
) -> list[str]:
    # Stable tie-break: candidates not seen in the 2-hop walk get score 0, then a deterministic shuffle.
    perm = list(candidates)
    rng.shuffle(perm)
    perm.sort(key=lambda c: scores.get(str(c["technique_id"]), 0), reverse=True)
    return [str(item["technique_id"]) for item in perm]


def _rank_neighbour_pagerank(
    candidates: list[dict[str, object]], scores: dict[str, int]
) -> list[str]:
    def combined(item: dict[str, object]) -> float:
        tid = str(item["technique_id"])
        return scores.get(tid, 0) * float(item["pagerank_train"])

    return [
        str(item["technique_id"])
        for item in sorted(candidates, key=combined, reverse=True)
    ]


def _filter_unseen(ranking: list[str], known: set[str]) -> list[str]:
    return [tid for tid in ranking if tid not in known]


def _metrics_for_ranking(ranking: list[str], gold: set[str], top_ks: list[int]) -> dict[str, float]:
    if not gold:
        return {f"hits@{k}": 0.0 for k in top_ks} | {f"precision@{k}": 0.0 for k in top_ks} | {f"recall@{k}": 0.0 for k in top_ks} | {"mrr": 0.0}
    metrics: dict[str, float] = {}
    for k in top_ks:
        top_k = set(ranking[:k])
        hit = len(top_k & gold) > 0
        precision = len(top_k & gold) / k
        recall = len(top_k & gold) / len(gold)
        metrics[f"hits@{k}"] = float(hit)
        metrics[f"precision@{k}"] = float(precision)
        metrics[f"recall@{k}"] = float(recall)
    # MRR over the first hit.
    rr = 0.0
    for idx, tid in enumerate(ranking, start=1):
        if tid in gold:
            rr = 1.0 / idx
            break
    metrics["mrr"] = rr
    return metrics


def _aggregate_metrics(per_actor: list[dict[str, float]]) -> dict[str, float]:
    if not per_actor:
        return {}
    keys = sorted({k for d in per_actor for k in d.keys()})
    return {key: sum(d.get(key, 0.0) for d in per_actor) / len(per_actor) for key in keys}


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    rng = random.Random(args.seed)

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        # Always start from a clean held-out state so reruns reflect a fresh split.
        cleared = _reset_held_out(store)
        if cleared:
            logging.info("Cleared held_out flag on %d existing edges before split.", cleared)

        all_edges = _fetch_uses_edges(store)
        if not all_edges:
            raise SystemExit(
                "No (ThreatActor)-[:USES]->(Technique) edges found. Run "
                "eval/AttackGraph/load_attack.py first."
            )
        rng.shuffle(all_edges)
        held_out_count = max(1, int(len(all_edges) * args.hold_out_fraction))
        held_out = all_edges[:held_out_count]
        marked = _mark_held_out(store, held_out)
        logging.info(
            "Held out %d/%d USES edges (%.1f%%); marked in Neo4j: %d",
            len(held_out),
            len(all_edges),
            100.0 * len(held_out) / len(all_edges),
            marked,
        )

        _project_train_graph(store)

        candidates = _all_technique_candidates(store)
        logging.info("Scoring against %d candidate techniques.", len(candidates))

        # Group held-out edges by actor; each actor's gold set is the techniques we hid.
        actor_to_gold: dict[str, set[str]] = {}
        actor_names: dict[str, str] = {}
        for edge in held_out:
            actor_to_gold.setdefault(edge.actor_id, set()).add(edge.technique_id)
            actor_names[edge.actor_id] = edge.actor_name
        actors = sorted(actor_to_gold.keys())
        if args.max_actors is not None:
            actors = actors[: args.max_actors]
        logging.info("Evaluating %d actors with held-out techniques.", len(actors))

        strategies = ["random", "popularity", "neighbour", "neighbour_pagerank"]
        per_actor_metrics: dict[str, list[dict[str, float]]] = {s: [] for s in strategies}
        per_actor_details: list[dict[str, object]] = []

        for actor_id in actors:
            gold = actor_to_gold[actor_id]
            known = _actor_known_techniques(store, actor_id)
            neighbour_scores = _neighbour_scores(store, actor_id)

            rankings = {
                "random": _filter_unseen(_rank_random(candidates, rng), known),
                "popularity": _filter_unseen(_rank_popularity(candidates), known),
                "neighbour": _filter_unseen(_rank_neighbour(candidates, neighbour_scores, rng), known),
                "neighbour_pagerank": _filter_unseen(
                    _rank_neighbour_pagerank(candidates, neighbour_scores), known
                ),
            }
            metrics_per_strategy = {
                strategy: _metrics_for_ranking(rankings[strategy], gold, args.top_ks)
                for strategy in strategies
            }
            for strategy, metrics in metrics_per_strategy.items():
                per_actor_metrics[strategy].append(metrics)
            per_actor_details.append(
                {
                    "actor_id": actor_id,
                    "actor_name": actor_names[actor_id],
                    "held_out_count": len(gold),
                    "metrics": metrics_per_strategy,
                }
            )

        aggregated = {strategy: _aggregate_metrics(per_actor_metrics[strategy]) for strategy in strategies}

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "seed": args.seed,
                "hold_out_fraction": args.hold_out_fraction,
                "top_ks": args.top_ks,
                "max_actors": args.max_actors,
                "num_held_out_edges": len(held_out),
                "num_total_edges": len(all_edges),
                "num_evaluated_actors": len(actors),
                "num_candidates": len(candidates),
            },
            "aggregated": aggregated,
            "per_actor": per_actor_details,
        }
        run_dir = resolve_run_dir(args.run_dir, default_hint="link-prediction")
        report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logging.info("Wrote link-prediction report -> %s", report_path)
        append_run_card(
            run_dir,
            script="eval_link_prediction.py",
            config={
                "seed": args.seed,
                "hold_out_fraction": args.hold_out_fraction,
                "top_ks": args.top_ks,
                "max_actors": args.max_actors,
                "num_held_out_edges": len(held_out),
                "num_total_edges": len(all_edges),
                "num_evaluated_actors": len(actors),
                "num_candidates": len(candidates),
            },
            output_files=[report_path],
        )

        # Restore held_out flags so the graph is back to its loaded state.
        restored = _reset_held_out(store)
        logging.info("Restored %d held-out edges to full visibility.", restored)

        # Pretty-print the summary table to stdout for convenience.
        print(json.dumps({"aggregated": aggregated, "config": report["config"]}, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
