"""LLM extraction of (ThreatActor)-[:EXPLOITS]->(CVE) from CTI actor narrative documents."""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from app.graph.neo4j_store import GraphEntity, GraphRelation, Neo4jStore

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
ENRICHMENT_RELATION = "EXPLOITS"
CTI_CVE_CREATED_VIA = "llm-cti-cve-extraction"


class CtiActorReportLike(Protocol):
    actor_entity_id: str
    actor_name: str
    actor_external_id: str | None
    text: str


_CVE_PROMPT = """You extract CVE identifiers exploited by ONE threat group from a CTI report.

Threat group (focal actor): {actor_name}

Report text:
\"\"\"
{text}
\"\"\"

Rules:
- Return every CVE id (CVE-YYYY-NNNN) this group is documented as exploiting in the report.
- Include a short verbatim quote (<=200 chars) from the report as evidence for each CVE.
- Do NOT invent CVEs not supported by the report text.
- Do NOT extract CVEs only used by other actors.

Reply with strict JSON only, no markdown:
{{
  "cves": [
    {{"cve_id": "CVE-YYYY-NNNN", "quote": "<verbatim quote>"}}
  ]
}}
"""


@dataclass
class ActorCveExtractionResult:
    actor_entity_id: str
    actor_name: str
    extracted_raw: int = 0
    validated: int = 0
    dropped_unquoted: int = 0
    parse_failed: bool = False
    edges: list[tuple[str, str, str]] = field(default_factory=list)


@dataclass
class CveExtractionSummary:
    model: str
    extraction_variant: str
    processed_actors: int = 0
    parse_failures: int = 0
    total_extracted_raw: int = 0
    total_validated: int = 0
    total_dropped_unquoted: int = 0
    per_actor: list[ActorCveExtractionResult] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "extraction_variant": self.extraction_variant,
            "processed_actors": self.processed_actors,
            "parse_failures": self.parse_failures,
            "total_extracted_raw": self.total_extracted_raw,
            "total_validated": self.total_validated,
            "total_dropped_unquoted": self.total_dropped_unquoted,
        }


def build_cti_cve_extraction_variant(model: str) -> str:
    slug = model.replace(":", "-")
    return f"llm-cti-cve:{slug}"


class AttackCtiCveExtractor:
    """Extract CVE exploitation from CTI prose; write tagged EXPLOITS edges."""

    def __init__(
        self,
        graph_store: Neo4jStore,
        llm: Any,
        *,
        model_name: str,
        provider_tag: str = "llm",
        extraction_variant: str | None = None,
        source_id: str = "cti-cve-attribution:misp-etda",
    ) -> None:
        self.graph_store = graph_store
        self.llm = llm
        self.model_name = model_name
        self.provider_tag = provider_tag
        self.source_label = f"{provider_tag}:{model_name}"
        self.extraction_variant = extraction_variant or build_cti_cve_extraction_variant(model_name)
        self.source_id = source_id
        self._namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"cti-cve-extraction::{self.source_label}")

    def extract_reports(
        self,
        reports: list[CtiActorReportLike],
        *,
        progress_every: int = 10,
    ) -> CveExtractionSummary:
        summary = CveExtractionSummary(
            model=self.model_name,
            extraction_variant=self.extraction_variant,
        )
        for idx, report in enumerate(reports, start=1):
            result = self._extract_one(report)
            summary.processed_actors += 1
            summary.total_extracted_raw += result.extracted_raw
            summary.total_validated += result.validated
            summary.total_dropped_unquoted += result.dropped_unquoted
            if result.parse_failed:
                summary.parse_failures += 1
            summary.per_actor.append(result)
            if idx % progress_every == 0 or idx == len(reports):
                logger.info(
                    "Extracted %d/%d CTI actor reports (validated_cves=%d).",
                    idx,
                    len(reports),
                    summary.total_validated,
                )
        return summary

    def write_edges(self, summary: CveExtractionSummary) -> int:
        written = 0
        for result in summary.per_actor:
            for actor_id, cve_entity_id, context in result.edges:
                if self._write_exploit_edge(
                    actor_entity_id=actor_id,
                    cve_entity_id=cve_entity_id,
                    context=context,
                ):
                    written += 1
        return written

    def clear_extracted_edges(self) -> int:
        rows = self.graph_store.run_read(
            """
            MATCH ()-[r:EXPLOITS]->()
            WHERE r.extraction_variant = $variant
            RETURN count(r) AS n
            """,
            variant=self.extraction_variant,
        )
        prior = int(rows[0]["n"]) if rows else 0
        if prior:
            self.graph_store.run_write(
                """
                MATCH ()-[r:EXPLOITS]->()
                WHERE r.extraction_variant = $variant
                DELETE r
                """,
                variant=self.extraction_variant,
            )
        return prior

    def _extract_one(self, report: CtiActorReportLike) -> ActorCveExtractionResult:
        result = ActorCveExtractionResult(
            actor_entity_id=report.actor_entity_id,
            actor_name=report.actor_name,
        )
        prompt = _CVE_PROMPT.format(
            actor_name=report.actor_name,
            text=report.text[:6000],
        )
        try:
            raw = self._invoke_llm(prompt)
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM failed for %s: %s", report.actor_name, exc)
            result.parse_failed = True
            return result
        items = self._parse_response(raw)
        if items is None:
            result.parse_failed = True
            return result
        result.extracted_raw = len(items)
        validated = self._validate_cves(items, report.text)
        result.validated = len(validated)
        result.dropped_unquoted = max(0, result.extracted_raw - result.validated)
        for item in validated:
            result.edges.append(
                (report.actor_entity_id, item["cve_entity_id"], item["context"])
            )
        return result

    def _write_exploit_edge(
        self,
        *,
        actor_entity_id: str,
        cve_entity_id: str,
        context: str,
    ) -> bool:
        cve_id = cve_entity_id.split(":", 1)[-1]
        now = datetime.now(timezone.utc).isoformat()
        cve_check = self.graph_store.run_read(
            "MATCH (c:CVE {entity_id: $cve_id}) RETURN count(c) AS n",
            cve_id=cve_entity_id,
        )
        if not cve_check or int(cve_check[0]["n"]) == 0:
            self.graph_store.upsert_entity(
                GraphEntity(
                    label="CVE",
                    entity_id=cve_entity_id,
                    name=cve_id,
                    properties={
                        "stix_type": "vulnerability",
                        "external_id": cve_id,
                        "cve_source": "cti-attributed",
                        "source": self.source_label,
                        "created_via": CTI_CVE_CREATED_VIA,
                        "created_at": now,
                    },
                ),
                source_id=self.source_id,
                extra_labels=["CVE", "AttackEntity"],
            )
        edge_check = self.graph_store.run_read(
            """
            MATCH (a:AttackEntity {entity_id: $actor_id})-[r:EXPLOITS]->(c:CVE {entity_id: $cve_id})
            WHERE r.extraction_variant = $variant
            RETURN count(r) AS n
            """,
            actor_id=actor_entity_id,
            cve_id=cve_entity_id,
            variant=self.extraction_variant,
        )
        if edge_check and int(edge_check[0]["n"]) > 0:
            return False
        provenance_id = str(
            uuid.uuid5(self._namespace, f"{actor_entity_id}::EXPLOITS::{cve_entity_id}")
        )
        self.graph_store.upsert_relation(
            GraphRelation(
                source_id=actor_entity_id,
                target_id=cve_entity_id,
                relation_type=ENRICHMENT_RELATION,
                properties={
                    "source": self.source_label,
                    "extracted_from": actor_entity_id,
                    "context": context,
                    "llm_provenance_id": provenance_id,
                    "created_via": CTI_CVE_CREATED_VIA,
                    "extraction_variant": self.extraction_variant,
                    "created_at": now,
                },
            )
        )
        return True

    def _invoke_llm(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        if isinstance(response, str):
            return response
        content = getattr(response, "content", None)
        if isinstance(content, str):
            return content
        return str(response)

    @staticmethod
    def _coerce_items(parsed: Any) -> list[Any] | None:
        """Accept either a bare list or a dict like {"cves": [...]} from the LLM."""
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            for key in ("cves", "CVEs", "results", "items"):
                value = parsed.get(key)
                if isinstance(value, list):
                    return value
            return []
        return None

    @classmethod
    def _parse_response(cls, raw: str) -> list[Any] | None:
        cleaned = raw.strip().replace("```json", "").replace("```", "").strip()
        try:
            return cls._coerce_items(json.loads(cleaned))
        except json.JSONDecodeError:
            pass
        for pattern in (r"\{.*\}", r"\[.*\]"):
            match = re.search(pattern, cleaned, flags=re.DOTALL)
            if not match:
                continue
            try:
                return cls._coerce_items(json.loads(match.group(0)))
            except json.JSONDecodeError:
                continue
        return None

    @staticmethod
    def _validate_cves(items: Any, description: str) -> list[dict[str, str]]:
        if not isinstance(items, list):
            return []
        kept: list[dict[str, str]] = []
        seen: set[str] = set()
        haystack_upper = description.upper()
        for item in items:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve_id", "")).strip().upper()
            context = str(item.get("quote", "") or item.get("context", "")).strip()
            if not CVE_PATTERN.fullmatch(cve_id):
                continue
            if cve_id in seen:
                continue
            if cve_id not in haystack_upper:
                continue
            if context and context not in description and context.lower() not in description.lower():
                context = ""
            kept.append(
                {
                    "cve_id": cve_id,
                    "cve_entity_id": f"cve:{cve_id}",
                    "context": context[:500],
                }
            )
            seen.add(cve_id)
        return kept
