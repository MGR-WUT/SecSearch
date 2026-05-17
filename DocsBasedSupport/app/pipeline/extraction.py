from __future__ import annotations

import json
import re
from typing import Any

from app.core.llm_factory import build_chat_llm
from app.graph.neo4j_store import GraphEntity, GraphRelation, Neo4jStore
from app.pipeline.ingestion import IngestedDocument

ALLOWED_REL_TYPES = {"MITIGATES", "AFFECTS", "DEPENDS_ON", "INTEGRATES_WITH"}


class ExtractionService:
    def __init__(
        self,
        graph_store: Neo4jStore,
        llm_provider: str,
        llm_base_url: str | None,
        llm_api_key: str | None,
        model: str,
    ) -> None:
        self.graph_store = graph_store
        self.llm = build_chat_llm(
            provider=llm_provider,
            model=model,
            base_url=llm_base_url,
            api_key=llm_api_key,
        )

    def extract_and_store(self, document: IngestedDocument) -> dict[str, Any]:
        extraction = self._extract_graph_elements(document.content)
        self.graph_store.upsert_source(
            source_id=document.source_id,
            source_uri=document.source_uri,
            source_type=document.source_type,
            last_updated=document.last_updated,
            etag=document.etag,
            content_hash=document.content_hash,
        )

        for entity in extraction["entities"]:
            entity_props = dict(entity.get("properties", {}))
            self.graph_store.upsert_entity(
                GraphEntity(
                    label=entity["label"],
                    entity_id=entity["id"],
                    name=entity["name"],
                    properties=entity_props,
                ),
                source_id=document.source_id,
            )

        for relation in extraction["relationships"]:
            rel_type = relation["type"].upper()
            if rel_type not in ALLOWED_REL_TYPES:
                continue
            self.graph_store.upsert_relation(
                GraphRelation(
                    source_id=relation["source_id"],
                    target_id=relation["target_id"],
                    relation_type=rel_type,
                    properties={"source_id": document.source_id, "current": True},
                )
            )

        return {
            "source_id": document.source_id,
            "entity_count": len(extraction["entities"]),
            "relation_count": len(extraction["relationships"]),
        }

    def _extract_graph_elements(self, text: str) -> dict[str, Any]:
        prompt = f"""
Extract technical cybersecurity entities and relationships from text.
Entity labels: API, ConfigOption, ErrorCode, Component, Policy, CVE, MitigationStep, Integration.
Relationship types: MITIGATES, AFFECTS, DEPENDS_ON, INTEGRATES_WITH.
Every entity must include:
- short_description: concise synthesis from mentions
- tags: list of keywords

Typed properties by label:
- API: signature, language_or_platform, stability_status, version_introduced, version_deprecated
- ConfigOption: default_value, allowed_values, constraints, data_type, effect
- ErrorCode: code, category, severity, typical_causes, recommended_action
- Component: layer, runtime_environment, supported_protocols, owner_team
- Policy/CVE/MitigationStep/Integration: include any known operational fields in properties
- properties must be a flat map of strings/lists (no nested JSON objects)

Return only JSON:
{{
  "entities":[{{"id":"...", "label":"...", "name":"...", "properties":{{"short_description":"...", "tags":[]}}}}],
  "relationships":[{{"source_id":"...", "target_id":"...", "type":"..."}}]
}}
Text:
{text[:15000]}
"""
        raw = self.llm.invoke(prompt).content.strip()
        cleaned = raw.replace("```json", "").replace("```", "").strip()
        data = self._safe_parse_json(cleaned)
        return self._normalize(data)

    @staticmethod
    def _safe_parse_json(payload: str) -> dict[str, Any]:
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            # Fallback recovery from malformed model output.
            match = re.search(r"\{.*\}", payload, flags=re.DOTALL)
            if not match:
                return {"entities": [], "relationships": []}
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return {"entities": [], "relationships": []}

    @staticmethod
    def _normalize(data: dict[str, Any]) -> dict[str, Any]:
        entities = data.get("entities", [])
        relationships = data.get("relationships", [])
        if not isinstance(entities, list):
            entities = []
        if not isinstance(relationships, list):
            relationships = []
        return {"entities": entities, "relationships": relationships}

