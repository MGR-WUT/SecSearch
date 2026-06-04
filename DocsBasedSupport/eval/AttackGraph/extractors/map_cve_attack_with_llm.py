"""LLM CVE -> ATT&CK technique/actor mapping from raw NVD descriptions.

The model reads ONLY the NVD vulnerability description and infers the ATT&CK
technique(s) the vulnerability enables (and any threat actor explicitly named).
This is an *inferential mapping* task, not quote-faithful extraction: NVD prose
rarely names a technique ID, so the no-hallucination guard is "the predicted
technique ID must exist in the ATT&CK matrix" (invalid IDs are dropped) rather
than "must be quoted verbatim".

Predictions are written to ``cve_attack_map_predictions.json`` and scored against
the CTID gold mapping by ``evals/eval_cve_attack_mapping.py``. This script does
NOT write into the shared graph, so the structured CTID baseline stays clean.

Usage::

    NEO4J_URI=bolt://localhost:7688 PYTHONPATH=. python \
        eval/AttackGraph/extractors/map_cve_attack_with_llm.py \
        --model gpt-oss:20b-cloud \
        --run-dir eval/AttackGraph/runs/cve-attack-map-gpt-oss-20b
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.core.llm_factory import build_chat_llm  # noqa: E402
from app.graph.neo4j_store import Neo4jStore  # noqa: E402
from app.pipeline.attack_graph_canonicalize import AttackGraphCanonicalizer  # noqa: E402
from eval.AttackGraph.lib._run_utils import (  # noqa: E402
    append_run_card,
    resolve_report_path,
    resolve_run_dir,
)

DEFAULT_CORPUS_FILENAME = "nvd_cve_corpus.json"
DEFAULT_REPORT_FILENAME = "cve_attack_map_predictions.json"

_MAP_PROMPT = """You are a MITRE ATT&CK analyst. Read ONLY the vulnerability description below
and infer which ATT&CK (Enterprise) techniques an attacker would use to exploit
or leverage this vulnerability, plus any threat actor/APT group explicitly named.

CVE: {cve_id}
Vulnerability description:
\"\"\"
{description}
\"\"\"

Rules:
- Output ATT&CK technique IDs in the form Txxxx or Txxxx.yyy (e.g. T1190, T1059.001).
- Map only techniques clearly implied by the described impact/behaviour.
- Do NOT invent technique IDs that are not real ATT&CK techniques.
- Only list a threat actor if the description explicitly names one; otherwise leave actors empty.
- If nothing can be confidently mapped, return empty lists.

Reply with strict JSON only, no markdown:
{{
  "techniques": [{{"technique_id": "T1190", "technique_name": "<name if known>"}}],
  "actors": [{{"name": "<actor name>"}}]
}}
"""


class ActorCanonicalizer:
    """Map LLM-named actors to loaded ThreatActor nodes by name / alias."""

    def __init__(self, store: Neo4jStore) -> None:
        self._index: dict[str, tuple[str, str]] = {}
        rows = store.run_read(
            """
            MATCH (a:ThreatActor)
            RETURN a.entity_id AS entity_id, a.name AS name,
                   a.external_id AS external_id, a.aliases AS aliases
            """
        )
        for row in rows:
            entity_id = row.get("entity_id")
            name = row.get("name")
            if not entity_id or not name:
                continue
            keys = [str(name)]
            aliases = row.get("aliases")
            if isinstance(aliases, str):
                try:
                    aliases = json.loads(aliases)
                except json.JSONDecodeError:
                    aliases = [aliases]
            if isinstance(aliases, list):
                keys.extend(str(a) for a in aliases if a)
            ext = row.get("external_id")
            if isinstance(ext, str) and ext.strip():
                keys.append(ext.strip())
            for key in keys:
                norm = key.strip().lower()
                if norm:
                    self._index.setdefault(norm, (str(entity_id), str(name)))

    def match(self, mention: str) -> tuple[str, str] | None:
        return self._index.get((mention or "").strip().lower())


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default=None, help="Override llm_extract_model from settings.yaml.")
    parser.add_argument("--corpus-path", type=Path, default=None, help="nvd_cve_corpus.json path.")
    parser.add_argument("--limit", type=int, default=None, help="Cap CVEs processed (smoke test).")
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--report-path", type=Path, default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _invoke_llm(llm, prompt: str) -> str:
    response = llm.invoke(prompt)
    if isinstance(response, str):
        return response
    content = getattr(response, "content", None)
    return content if isinstance(content, str) else str(response)


def _parse_json(raw: str) -> dict | None:
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    for candidate in (cleaned, re.sub(r",\s*([}\]])", r"\1", cleaned.replace("'", '"'))):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if match:
        try:
            parsed = json.loads(re.sub(r",\s*([}\]])", r"\1", match.group(0)))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    run_dir = resolve_run_dir(args.run_dir, default_hint="cve-attack-map")
    corpus_path = args.corpus_path or (run_dir / DEFAULT_CORPUS_FILENAME)
    corpus_payload = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    corpus = list(corpus_payload.get("corpus") or [])
    corpus = [c for c in corpus if c.get("has_description")]
    if args.limit:
        corpus = corpus[: args.limit]
    logging.info("Loaded %d CVEs with NVD descriptions from %s.", len(corpus), corpus_path)

    settings = get_settings()
    model_name = args.model or settings.llm_extract_model
    if not model_name:
        raise SystemExit("No LLM model configured. Set llm_extract_model or pass --model.")

    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    try:
        technique_canon = AttackGraphCanonicalizer(store)
        actor_canon = ActorCanonicalizer(store)
        llm = build_chat_llm(
            provider=settings.llm_provider,
            model=model_name,
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
        )

        predictions: list[dict[str, object]] = []
        parse_failures = 0
        total_raw_tech = 0
        total_valid_tech = 0
        total_invalid_tech = 0
        total_raw_actors = 0
        total_matched_actors = 0
        for idx, entry in enumerate(corpus, start=1):
            cve_id = str(entry["cve_id"])
            description = str(entry.get("nvd_description") or "")
            prompt = _MAP_PROMPT.format(cve_id=cve_id, description=description[:6000])
            parsed: dict | None = None
            try:
                parsed = _parse_json(_invoke_llm(llm, prompt))
            except Exception as exc:  # noqa: BLE001
                logging.warning("LLM failed for %s: %s", cve_id, exc)
            if parsed is None:
                parse_failures += 1
                parsed = {}

            raw_techs = parsed.get("techniques") if isinstance(parsed.get("techniques"), list) else []
            pred_ext: set[str] = set()
            invalid_ids: list[str] = []
            for item in raw_techs:
                if not isinstance(item, dict):
                    continue
                total_raw_tech += 1
                mention = str(item.get("technique_id") or "").strip()
                name = str(item.get("technique_name") or "").strip()
                entity_id, ext = technique_canon.canonicalize_technique(mention=mention, fallback_name=name)
                if entity_id and ext:
                    pred_ext.add(ext.upper())
                else:
                    invalid_ids.append(mention or name)
            total_valid_tech += len(pred_ext)
            total_invalid_tech += len(invalid_ids)

            raw_actors = parsed.get("actors") if isinstance(parsed.get("actors"), list) else []
            matched_actors: list[dict[str, str]] = []
            for item in raw_actors:
                name = ""
                if isinstance(item, dict):
                    name = str(item.get("name") or "").strip()
                elif isinstance(item, str):
                    name = item.strip()
                if not name:
                    continue
                total_raw_actors += 1
                hit = actor_canon.match(name)
                if hit:
                    matched_actors.append({"entity_id": hit[0], "name": hit[1], "mention": name})
            total_matched_actors += len(matched_actors)

            predictions.append(
                {
                    "cve_id": cve_id,
                    "gold_techniques": entry.get("gold_techniques") or [],
                    "pred_techniques": sorted(pred_ext),
                    "pred_invalid_technique_ids": invalid_ids,
                    "pred_actors": matched_actors,
                }
            )
            if idx % 10 == 0 or idx == len(corpus):
                logging.info(
                    "Mapped %d/%d CVEs (valid_tech=%d, invalid_tech=%d, actors=%d).",
                    idx,
                    len(corpus),
                    total_valid_tech,
                    total_invalid_tech,
                    total_matched_actors,
                )

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "config": {
                "model": model_name,
                "provider": settings.llm_provider,
                "corpus_path": str(corpus_path),
                "num_cves": len(corpus),
                "limit": args.limit,
            },
            "summary": {
                "processed": len(corpus),
                "parse_failures": parse_failures,
                "total_raw_techniques": total_raw_tech,
                "total_valid_techniques": total_valid_tech,
                "total_invalid_techniques": total_invalid_tech,
                "hallucinated_technique_rate": round(
                    total_invalid_tech / total_raw_tech, 4
                ) if total_raw_tech else 0.0,
                "total_raw_actors": total_raw_actors,
                "total_matched_actors": total_matched_actors,
            },
            "predictions": predictions,
        }
        report_path = resolve_report_path(args.report_path, run_dir, DEFAULT_REPORT_FILENAME)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        append_run_card(
            run_dir,
            script="map_cve_attack_with_llm.py",
            config={
                "model": model_name,
                "provider": settings.llm_provider,
                "num_cves": len(corpus),
                "limit": args.limit,
                **report["summary"],
            },
            output_files=[report_path],
        )
        print(json.dumps(report["summary"], indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
