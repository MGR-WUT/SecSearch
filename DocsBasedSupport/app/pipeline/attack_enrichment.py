"""LLM-driven enrichment of the deterministic MITRE ATT&CK graph.

Why this exists
---------------
The deterministic STIX loader writes only what ATT&CK ships in
``external_references`` (about 33 CVEs in the Enterprise bundle). A lot of
additional CVE / actor cross-references are buried inside the *free-text
descriptions* of threat actors, malware, tools, and campaigns. This module
asks a configured LLM to **quote-extract** those references and writes them
back into Neo4j as new edges / nodes with explicit provenance, so the
analytical graph layer can take advantage of the extra coverage without the
ATT&CK ground truth being polluted.

Design constraints
------------------
* The prompt forbids fabrication and requires a verbatim quote from the
  description for every claim. Anything else is dropped at parse time.
* Every node / edge added by this module carries
  ``source='llm:<model>'``, ``extracted_from=<entity_id>``,
  ``context=<short quote>``, and ``llm_provenance_id=<uuid>`` so MITRE-derived
  data can always be distinguished from LLM-derived data downstream.
* Processed entities are marked with ``llm_enriched_at`` so reruns skip them
  unless ``force=True``.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from app.graph.neo4j_store import GraphEntity, GraphRelation, Neo4jStore

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
ENRICHMENT_RELATION = "EXPLOITS"


@dataclass
class EnrichmentResult:
    entity_id: str
    new_cve_nodes: int = 0
    new_exploits_edges: int = 0
    new_attribution_edges: int = 0
    skipped_no_description: bool = False
    parse_failed: bool = False
    extracted_count: int = 0
    extracted_actor_count: int = 0
    raw_response_chars: int = 0
    dropped_unquoted: int = 0
    dropped_unmatched_actors: int = 0


@dataclass
class EnrichmentSummary:
    model: str
    processed_entities: int = 0
    skipped_already_enriched: int = 0
    skipped_no_description: int = 0
    parse_failures: int = 0
    new_cve_nodes: int = 0
    new_exploits_edges: int = 0
    new_attribution_edges: int = 0
    dropped_unquoted: int = 0
    dropped_unmatched_actors: int = 0
    per_entity: list[EnrichmentResult] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "processed_entities": self.processed_entities,
            "skipped_already_enriched": self.skipped_already_enriched,
            "skipped_no_description": self.skipped_no_description,
            "parse_failures": self.parse_failures,
            "new_cve_nodes": self.new_cve_nodes,
            "new_exploits_edges": self.new_exploits_edges,
            "new_attribution_edges": self.new_attribution_edges,
            "dropped_unquoted": self.dropped_unquoted,
            "dropped_unmatched_actors": self.dropped_unmatched_actors,
        }


_PROMPT_TEMPLATE = """You extract structured cybersecurity references from a single MITRE ATT&CK description.

Entity name: {name}
Entity label: {label}
Entity external ID: {external_id}
Description:
\"\"\"
{description}
\"\"\"

Rules:
- Return ONLY CVE identifiers (format CVE-YYYY-NNNN) that appear LITERALLY in the description above.
- For every CVE include a short quote (<=200 chars) copied verbatim from the description as evidence.
- If the entity is a campaign, also return threat actor / group names that appear LITERALLY in the description.
- For every threat actor include a short quote (<=200 chars) copied verbatim from the description as evidence.
- DO NOT invent or infer CVEs. If the description does not mention any CVE, return an empty list.
- DO NOT include CVEs that are only implied; the exact CVE id must be substring of the description.
- DO NOT infer actor attribution; the actor/group name must appear explicitly as text.

Reply with strict JSON only, no markdown:
{{
  "cves": [
    {{"cve_id": "CVE-YYYY-NNNN", "context": "<short verbatim quote>"}}
  ],
  "threat_actors": [
    {{"name": "<actor/group name as written>", "context": "<short verbatim quote>"}}
  ]
}}
"""


LlmFn = Callable[[str], str]


class AttackDescriptionEnricher:
    """Enrich AttackEntity nodes by extracting CVE references from descriptions."""

    def __init__(
        self,
        graph_store: Neo4jStore,
        llm: Any,
        *,
        model_name: str,
        source_id: str = "mitre-attack:enterprise",
        provider_tag: str | None = None,
    ) -> None:
        self.graph_store = graph_store
        self.llm = llm
        self.model_name = model_name
        self.provider_tag = provider_tag or "llm"
        self.source_label = f"{self.provider_tag}:{model_name}"
        self.source_id = source_id
        # Used to seed a deterministic UUID-ish identifier per (entity, cve) pair.
        self._namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"attack-enrichment::{self.source_label}")
        self._actor_catalog: dict[str, str] | None = None

    def enrich(
        self,
        entities: Iterable[dict[str, Any]],
        *,
        force: bool = False,
        progress_every: int = 10,
    ) -> EnrichmentSummary:
        summary = EnrichmentSummary(model=self.source_label)
        for idx, entity in enumerate(entities, start=1):
            entity_id = str(entity["entity_id"])
            description = entity.get("description")
            if not entity.get("force_reenrich", force) and entity.get("llm_enriched_at"):
                summary.skipped_already_enriched += 1
                continue
            if not description or not str(description).strip():
                summary.skipped_no_description += 1
                self._mark_processed(entity_id, parsed=False, extracted=0)
                continue
            result = self._enrich_one(
                entity_id=entity_id,
                name=str(entity.get("name") or entity_id),
                label=str(entity.get("primary_label") or entity.get("label") or "AttackEntity"),
                external_id=str(entity.get("external_id") or ""),
                description=str(description),
            )
            summary.processed_entities += 1
            summary.new_cve_nodes += result.new_cve_nodes
            summary.new_exploits_edges += result.new_exploits_edges
            summary.new_attribution_edges += result.new_attribution_edges
            summary.dropped_unquoted += result.dropped_unquoted
            summary.dropped_unmatched_actors += result.dropped_unmatched_actors
            if result.parse_failed:
                summary.parse_failures += 1
            summary.per_entity.append(result)
            self._mark_processed(
                entity_id,
                parsed=not result.parse_failed,
                extracted=result.extracted_count,
            )
            if idx % progress_every == 0:
                logger.info(
                    "Enriched %d entities so far (new_cve_nodes=%d, new_exploits_edges=%d, new_attribution_edges=%d).",
                    idx,
                    summary.new_cve_nodes,
                    summary.new_exploits_edges,
                    summary.new_attribution_edges,
                )
        return summary

    def _enrich_one(
        self,
        *,
        entity_id: str,
        name: str,
        label: str,
        external_id: str,
        description: str,
    ) -> EnrichmentResult:
        prompt = _PROMPT_TEMPLATE.format(
            name=name,
            label=label,
            external_id=external_id or "(none)",
            description=description[:6000],
        )
        try:
            raw = self._invoke_llm(prompt)
        except Exception as exc:  # noqa: BLE001 -- never crash the enrichment loop on LLM errors
            logger.warning("LLM call failed for entity %s: %s", entity_id, exc)
            return EnrichmentResult(entity_id=entity_id, parse_failed=True)
        result = EnrichmentResult(entity_id=entity_id, raw_response_chars=len(raw))
        parsed = self._parse_response(raw)
        if parsed is None:
            result.parse_failed = True
            return result
        extracted_cves = self._validate_cves(parsed.get("cves") or [], description)
        extracted_actors = self._validate_actors(
            parsed.get("threat_actors") or [],
            description,
        )
        result.extracted_count = len(extracted_cves)
        result.extracted_actor_count = len(extracted_actors)
        result.dropped_unquoted = max(0, len(parsed.get("cves") or []) - len(extracted_cves))
        result.dropped_unmatched_actors = max(
            0,
            len(parsed.get("threat_actors") or []) - len(extracted_actors),
        )
        for cve in extracted_cves:
            created_cve, created_edge = self._write_cve_link(
                entity_id=entity_id,
                cve_id=cve["cve_id"],
                context=cve["context"],
            )
            if created_cve:
                result.new_cve_nodes += 1
            if created_edge:
                result.new_exploits_edges += 1
        if label == "Campaign":
            for actor in extracted_actors:
                created_attribution = self._write_attribution_link(
                    campaign_entity_id=entity_id,
                    actor_entity_id=actor["actor_entity_id"],
                    actor_name=actor["name"],
                    context=actor["context"],
                )
                if created_attribution:
                    result.new_attribution_edges += 1
        return result

    def _invoke_llm(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        if isinstance(response, str):
            return response
        content = getattr(response, "content", None)
        if isinstance(content, str):
            return content
        return str(response)

    @staticmethod
    def _parse_response(raw: str) -> dict[str, Any] | None:
        cleaned = raw.strip().replace("```json", "").replace("```", "").strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
            if not match:
                return None
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None

    @staticmethod
    def _validate_cves(items: Any, description: str) -> list[dict[str, str]]:
        """Drop entries whose CVE id or quoted context cannot be confirmed against the source text."""
        if not isinstance(items, list):
            return []
        kept: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        haystack_upper = description.upper()
        for item in items:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve_id", "")).strip().upper()
            context = str(item.get("context", "")).strip()
            if not CVE_PATTERN.fullmatch(cve_id):
                continue
            if cve_id in seen_ids:
                continue
            # Only accept CVEs that literally appear in the source description.
            if cve_id not in haystack_upper:
                continue
            # Accept context only if the quote is a substring of the description.
            if context and context not in description and context.lower() not in description.lower():
                context = ""
            kept.append({"cve_id": cve_id, "context": context[:500]})
            seen_ids.add(cve_id)
        return kept

    def _validate_actors(self, items: Any, description: str) -> list[dict[str, str]]:
        """Keep only actor names that are literal text and match an existing ThreatActor."""
        if not isinstance(items, list):
            return []
        catalog = self._get_actor_catalog()
        kept: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        description_lower = description.lower()
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            context = str(item.get("context", "")).strip()
            if not name or name.lower() not in description_lower:
                continue
            actor_entity_id = catalog.get(name.lower())
            if not actor_entity_id:
                continue
            if actor_entity_id in seen_ids:
                continue
            if context and context not in description and context.lower() not in description_lower:
                context = ""
            kept.append(
                {
                    "name": name,
                    "actor_entity_id": actor_entity_id,
                    "context": context[:500],
                }
            )
            seen_ids.add(actor_entity_id)
        return kept

    def _get_actor_catalog(self) -> dict[str, str]:
        if self._actor_catalog is not None:
            return self._actor_catalog
        rows = self.graph_store.run_read(
            """
            MATCH (a:ThreatActor)
            RETURN a.entity_id AS entity_id, a.name AS name, a.aliases AS aliases
            """
        )
        catalog: dict[str, str] = {}
        for row in rows:
            entity_id = row.get("entity_id")
            if not entity_id:
                continue
            names: list[str] = []
            if row.get("name"):
                names.append(str(row["name"]))
            aliases = row.get("aliases")
            if isinstance(aliases, list):
                names.extend(str(alias) for alias in aliases if alias)
            elif aliases:
                names.append(str(aliases))
            for name in names:
                catalog.setdefault(name.strip().lower(), str(entity_id))
        self._actor_catalog = catalog
        return catalog

    def _write_cve_link(self, *, entity_id: str, cve_id: str, context: str) -> tuple[bool, bool]:
        now = datetime.now(timezone.utc).isoformat()
        cve_entity_id = f"cve:{cve_id}"
        provenance_id = str(uuid.uuid5(self._namespace, f"{entity_id}::{cve_id}"))

        cve_check = self.graph_store.run_read(
            "MATCH (c:CVE {entity_id: $cve_id}) RETURN count(c) AS n",
            cve_id=cve_entity_id,
        )
        created_cve = bool(cve_check and int(cve_check[0]["n"]) == 0)
        if created_cve:
            self.graph_store.upsert_entity(
                GraphEntity(
                    label="CVE",
                    entity_id=cve_entity_id,
                    name=cve_id,
                    properties={
                        "stix_type": "vulnerability",
                        "external_id": cve_id,
                        "domain": "mitre-attack-enterprise",
                        "source": self.source_label,
                        "created_via": "llm-enrichment",
                        "created_at": now,
                    },
                ),
                source_id=self.source_id,
                extra_labels=["CVE", "AttackEntity"],
            )

        edge_check = self.graph_store.run_read(
            """
            MATCH (a:AttackEntity {entity_id: $entity_id})-[r:EXPLOITS]->(c:CVE {entity_id: $cve_id})
            RETURN count(r) AS n, collect(r.source) AS sources
            """,
            entity_id=entity_id,
            cve_id=cve_entity_id,
        )
        edge_already_exists = bool(edge_check and int(edge_check[0]["n"]) > 0)
        existing_sources: list[str] = []
        if edge_already_exists:
            existing_sources = [s for s in (edge_check[0]["sources"] or []) if s]
        created_edge = False
        if not edge_already_exists:
            self.graph_store.upsert_relation(
                GraphRelation(
                    source_id=entity_id,
                    target_id=cve_entity_id,
                    relation_type=ENRICHMENT_RELATION,
                    properties={
                        "source": self.source_label,
                        "extracted_from": entity_id,
                        "context": context,
                        "llm_provenance_id": provenance_id,
                        "created_via": "llm-enrichment",
                        "created_at": now,
                    },
                )
            )
            created_edge = True
        else:
            # Mark the existing edge as also corroborated by the LLM, without overwriting MITRE provenance.
            self.graph_store.run_write(
                """
                MATCH (a:AttackEntity {entity_id: $entity_id})-[r:EXPLOITS]->(c:CVE {entity_id: $cve_id})
                SET r.corroborated_by = coalesce(r.corroborated_by, [])
                  + CASE WHEN $tag IN coalesce(r.corroborated_by, []) THEN [] ELSE [$tag] END,
                  r.corroborated_at = $now
                RETURN count(r) AS n
                """,
                entity_id=entity_id,
                cve_id=cve_entity_id,
                tag=self.source_label,
                now=now,
            )
            logger.debug(
                "EXPLOITS edge %s -> %s already existed (sources=%s); corroborated by %s.",
                entity_id,
                cve_entity_id,
                existing_sources,
                self.source_label,
            )
        return created_cve, created_edge

    def _write_attribution_link(
        self,
        *,
        campaign_entity_id: str,
        actor_entity_id: str,
        actor_name: str,
        context: str,
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        provenance_id = str(uuid.uuid5(self._namespace, f"{campaign_entity_id}::ATTRIBUTED_TO::{actor_entity_id}"))
        edge_check = self.graph_store.run_read(
            """
            MATCH (c:Campaign {entity_id: $campaign_id})-[r:ATTRIBUTED_TO]->(a:ThreatActor {entity_id: $actor_id})
            RETURN count(r) AS n
            """,
            campaign_id=campaign_entity_id,
            actor_id=actor_entity_id,
        )
        edge_already_exists = bool(edge_check and int(edge_check[0]["n"]) > 0)
        if not edge_already_exists:
            self.graph_store.upsert_relation(
                GraphRelation(
                    source_id=campaign_entity_id,
                    target_id=actor_entity_id,
                    relation_type="ATTRIBUTED_TO",
                    properties={
                        "source": self.source_label,
                        "extracted_from": campaign_entity_id,
                        "actor_mention": actor_name,
                        "context": context,
                        "llm_provenance_id": provenance_id,
                        "created_via": "llm-enrichment",
                        "created_at": now,
                    },
                )
            )
            return True
        self.graph_store.run_write(
            """
            MATCH (c:Campaign {entity_id: $campaign_id})-[r:ATTRIBUTED_TO]->(a:ThreatActor {entity_id: $actor_id})
            SET r.corroborated_by = coalesce(r.corroborated_by, [])
              + CASE WHEN $tag IN coalesce(r.corroborated_by, []) THEN [] ELSE [$tag] END,
              r.corroborated_at = $now
            RETURN count(r) AS n
            """,
            campaign_id=campaign_entity_id,
            actor_id=actor_entity_id,
            tag=self.source_label,
            now=now,
        )
        return False

    def _mark_processed(self, entity_id: str, *, parsed: bool, extracted: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.graph_store.run_write(
            """
            MATCH (e:AttackEntity {entity_id: $entity_id})
            SET e.llm_enriched_at = $now,
                e.llm_enriched_model = $model,
                e.llm_enriched_parsed_ok = $parsed,
                e.llm_enriched_extracted_count = $extracted
            """,
            entity_id=entity_id,
            now=now,
            model=self.source_label,
            parsed=parsed,
            extracted=int(extracted),
        )
