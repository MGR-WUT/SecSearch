"""LLM extraction of (ThreatActor)-[:USES]->(Technique) from STIX-derived actor reports."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from app.graph.neo4j_store import GraphRelation, Neo4jStore
from app.pipeline.attack_graph_canonicalize import AttackGraphCanonicalizer, CanonicalUsesEdge
from app.pipeline.attack_graph_variants import USES_EXTRACTED_REL, build_llm_extracted_variant


class ActorReportLike(Protocol):
    actor_entity_id: str
    actor_name: str
    actor_external_id: str | None
    text: str

logger = logging.getLogger(__name__)

_USES_PROMPT = """You extract MITRE ATT&CK technique usage for ONE threat group from a CTI-style report.

Threat group (focal actor): {actor_name}
ATT&CK group ID: {actor_external_id}

Report text:
\"\"\"
{text}
\"\"\"

Rules:
- Return every technique this group is documented as USING in the report.
- Prefer MITRE technique IDs (e.g. T1566.001) when they appear in the text.
- Include a short verbatim quote (<=200 chars) from the report as evidence for each technique.
- Do NOT invent techniques not supported by the report text.
- Do NOT extract techniques used only by other actors or malware.

Reply with strict JSON only, no markdown:
{{
  "uses": [
    {{"technique_id": "T1234", "technique_name": "<name if known>", "quote": "<verbatim quote>"}}
  ]
}}
"""


@dataclass
class ActorExtractionResult:
    actor_entity_id: str
    actor_name: str
    extracted_raw: int = 0
    canonicalized: int = 0
    dropped_unquoted: int = 0
    dropped_unmatched: int = 0
    parse_failed: bool = False
    parse_recovered: bool = False
    recovery_method: str | None = None
    edges: list[CanonicalUsesEdge] = field(default_factory=list)


@dataclass
class UsesExtractionSummary:
    model: str
    graph_variant: str
    processed_actors: int = 0
    parse_failures: int = 0
    total_extracted_raw: int = 0
    total_canonicalized: int = 0
    total_dropped_unquoted: int = 0
    total_dropped_unmatched: int = 0
    parse_recoveries: int = 0
    per_actor: list[ActorExtractionResult] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "graph_variant": self.graph_variant,
            "processed_actors": self.processed_actors,
            "parse_failures": self.parse_failures,
            "parse_recoveries": self.parse_recoveries,
            "total_extracted_raw": self.total_extracted_raw,
            "total_canonicalized": self.total_canonicalized,
            "total_dropped_unquoted": self.total_dropped_unquoted,
            "total_dropped_unmatched": self.total_dropped_unmatched,
        }


class AttackUsesExtractor:
    """Run GraphoDynamo-style LLM extraction over STIX text; write USES_EXTRACTED edges."""

    def __init__(
        self,
        graph_store: Neo4jStore,
        llm: Any,
        *,
        model_name: str,
        provider_tag: str = "llm",
        graph_variant: str | None = None,
        structure_profile: str | None = None,
    ) -> None:
        self.graph_store = graph_store
        self.llm = llm
        self.model_name = model_name
        self.provider_tag = provider_tag
        self.source_label = f"{provider_tag}:{model_name}"
        self.graph_variant = graph_variant or build_llm_extracted_variant(
            model_name, structure_profile=structure_profile
        )
        self.canonicalizer = AttackGraphCanonicalizer(graph_store)

    def extract_reports(
        self,
        reports: list[ActorReportLike],
        *,
        progress_every: int = 10,
    ) -> UsesExtractionSummary:
        summary = UsesExtractionSummary(model=self.source_label, graph_variant=self.graph_variant)
        for idx, report in enumerate(reports, start=1):
            result = self._extract_one(report)
            summary.processed_actors += 1
            summary.total_extracted_raw += result.extracted_raw
            summary.total_canonicalized += result.canonicalized
            summary.total_dropped_unquoted += result.dropped_unquoted
            summary.total_dropped_unmatched += result.dropped_unmatched
            if result.parse_failed:
                summary.parse_failures += 1
            if result.parse_recovered:
                summary.parse_recoveries += 1
            summary.per_actor.append(result)
            if idx % progress_every == 0:
                logger.info(
                    "Extracted %d/%d actor reports (canonicalized=%d).",
                    idx,
                    len(reports),
                    summary.total_canonicalized,
                )
        return summary

    def write_edges(self, summary: UsesExtractionSummary) -> int:
        now = datetime.now(timezone.utc).isoformat()
        written = 0
        for actor_result in summary.per_actor:
            for edge in actor_result.edges:
                self.graph_store.upsert_relation(
                    GraphRelation(
                        source_id=edge.actor_entity_id,
                        target_id=edge.technique_entity_id,
                        relation_type=USES_EXTRACTED_REL,
                        properties={
                            "graph_variant": self.graph_variant,
                            "source": self.source_label,
                            "created_via": "stix-llm-uses-extraction",
                            "created_at": now,
                            "technique_external_id": edge.technique_external_id,
                            "context": edge.quote[:500],
                        },
                    )
                )
                written += 1
        return written

    def clear_extracted_edges(self, *, graph_variant: str | None = None) -> int:
        if graph_variant:
            result = self.graph_store.run_write(
                f"""
                MATCH ()-[r:{USES_EXTRACTED_REL}]->()
                WHERE r.graph_variant = $variant
                WITH collect(r) AS rels
                UNWIND rels AS rel
                DELETE rel
                RETURN size(rels) AS deleted
                """,
                variant=graph_variant,
            )
            return int(result[0]["deleted"]) if result else 0
        variant_prefix = "llm-extracted"
        result = self.graph_store.run_write(
            f"""
            MATCH ()-[r:{USES_EXTRACTED_REL}]->()
            WHERE r.graph_variant STARTS WITH $prefix
            WITH collect(r) AS rels
            UNWIND rels AS rel
            DELETE rel
            RETURN size(rels) AS deleted
            """,
            prefix=variant_prefix,
        )
        repair = self.graph_store.run_write(
            """
            MATCH ()-[r:USES]->()
            WHERE r.graph_variant STARTS WITH $prefix
            WITH collect(r) AS rels
            UNWIND rels AS rel
            DELETE rel
            RETURN size(rels) AS repaired
            """,
            prefix=variant_prefix,
        )
        deleted = int(result[0]["deleted"]) if result else 0
        deleted += int(repair[0]["repaired"]) if repair else 0
        return deleted

    def _extract_one(self, report: ActorReportLike) -> ActorExtractionResult:
        prompt = _USES_PROMPT.format(
            actor_name=report.actor_name,
            actor_external_id=report.actor_external_id or "(unknown)",
            text=report.text[:12_000],
        )
        result = ActorExtractionResult(
            actor_entity_id=report.actor_entity_id,
            actor_name=report.actor_name,
        )
        uses_items: list[Any] = []
        try:
            raw = self._invoke_llm(prompt)
            uses_items = self._parse_uses_items(raw)
            if not uses_items:
                raw_retry = self._invoke_llm(
                    prompt
                    + "\n\nIMPORTANT: Reply with ONLY a JSON object {\"uses\": [...]} — no markdown, no commentary."
                )
                uses_items = self._parse_uses_items(raw_retry)
                if uses_items:
                    result.parse_recovered = True
                    result.recovery_method = "retry_prompt"
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM failed for actor %s: %s", report.actor_name, exc)

        if not uses_items:
            uses_items = self._fallback_uses_from_text(report.text)
            if uses_items:
                result.parse_recovered = True
                result.recovery_method = "regex_technique_ids"
                logger.info("Recovered %s via regex fallback.", report.actor_name)

        if not uses_items:
            result.parse_failed = True
            logger.warning("Parse/extraction failed for actor %s.", report.actor_name)
            return result

        result.extracted_raw = len(uses_items)

        seen_pairs: set[tuple[str, str]] = set()
        haystack = report.text
        haystack_lower = haystack.lower()
        for item in uses_items:
            if not isinstance(item, dict):
                continue
            technique_id = str(item.get("technique_id") or "").strip()
            technique_name = str(item.get("technique_name") or "").strip()
            quote = str(item.get("quote") or "").strip()
            mention = technique_id or technique_name
            tech_id_in_text = bool(
                technique_id and technique_id.upper() in haystack.upper()
            )
            if not tech_id_in_text:
                if quote and quote not in haystack and quote.lower() not in haystack_lower:
                    result.dropped_unquoted += 1
                    continue
                if mention and mention.lower() not in haystack_lower:
                    result.dropped_unquoted += 1
                    continue

            tech_entity_id, tech_ext = self.canonicalizer.canonicalize_technique(
                mention=mention,
                fallback_name=technique_name,
            )
            if not tech_entity_id:
                result.dropped_unmatched += 1
                continue
            pair = (report.actor_entity_id, tech_entity_id)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            result.edges.append(
                CanonicalUsesEdge(
                    actor_entity_id=report.actor_entity_id,
                    technique_entity_id=tech_entity_id,
                    technique_external_id=tech_ext,
                    quote=quote,
                )
            )
        result.canonicalized = len(result.edges)
        return result

    def _invoke_llm(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        if isinstance(response, str):
            return response
        content = getattr(response, "content", None)
        if isinstance(content, str):
            return content
        return str(response)

    def _parse_uses_items(self, raw: str) -> list[Any]:
        parsed = self._parse_response(raw)
        if parsed is None:
            return []
        return self._coerce_uses_list(parsed)

    @staticmethod
    def _coerce_uses_list(parsed: dict[str, Any] | list[Any]) -> list[Any]:
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
        if isinstance(parsed, dict):
            for key in ("uses", "techniques", "relationships", "data"):
                val = parsed.get(key)
                if isinstance(val, list):
                    return [x for x in val if isinstance(x, dict)]
        return []

    @staticmethod
    def _fallback_uses_from_text(text: str) -> list[dict[str, str]]:
        """Last resort: emit one entry per ATT&CK technique id literally present in text."""
        seen: set[str] = set()
        items: list[dict[str, str]] = []
        for match in re.finditer(r"\b(T\d{4}(?:\.\d{3})?)\b", text, flags=re.IGNORECASE):
            tid = match.group(1).upper()
            if tid in seen:
                continue
            seen.add(tid)
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            items.append(
                {
                    "technique_id": tid,
                    "technique_name": "",
                    "quote": text[start:end].strip(),
                }
            )
        return items

    @staticmethod
    def _parse_response(raw: str) -> dict[str, Any] | list[Any] | None:
        cleaned = raw.strip()
        if not cleaned:
            return None
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()
        candidates = [cleaned, AttackUsesExtractor._repair_json(cleaned)]
        for candidate in candidates:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
        for pattern in (r"\{.*\}", r"\[.*\]"):
            match = re.search(pattern, cleaned, flags=re.DOTALL)
            if not match:
                continue
            fragment = AttackUsesExtractor._repair_json(match.group(0))
            try:
                return json.loads(fragment)
            except json.JSONDecodeError:
                continue
        return None

    @staticmethod
    def _repair_json(payload: str) -> str:
        payload = payload.replace("'", '"')
        payload = re.sub(r",\s*}", "}", payload)
        payload = re.sub(r",\s*]", "]", payload)
        return payload
