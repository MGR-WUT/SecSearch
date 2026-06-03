"""Canonicalize LLM-extracted ATT&CK mentions to Neo4j entity ids."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.graph.neo4j_store import Neo4jStore

_TECHNIQUE_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


@dataclass(frozen=True)
class CanonicalUsesEdge:
    actor_entity_id: str
    technique_entity_id: str
    technique_external_id: str | None
    quote: str


class AttackGraphCanonicalizer:
    """Map extracted technique ids/names to loaded ATT&CK Technique nodes."""

    def __init__(self, graph_store: Neo4jStore) -> None:
        self.graph_store = graph_store
        self._technique_by_external: dict[str, str] | None = None
        self._technique_by_name: dict[str, str] | None = None

    def canonicalize_technique(
        self,
        *,
        mention: str,
        fallback_name: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Return (entity_id, external_id) or (None, None) if unmatched."""
        catalog_ext, catalog_name = self._technique_catalogs()
        text = (mention or "").strip()
        if not text and fallback_name:
            text = fallback_name.strip()
        if not text:
            return None, None

        match = _TECHNIQUE_ID_RE.search(text)
        if match:
            ext = match.group(1).upper()
            entity_id = catalog_ext.get(ext)
            if entity_id:
                return entity_id, ext

        entity_id = catalog_name.get(text.lower())
        if entity_id:
            ext_row = self.graph_store.run_read(
                """
                MATCH (t:Technique {entity_id: $eid})
                RETURN t.external_id AS external_id
                LIMIT 1
                """,
                eid=entity_id,
            )
            ext = None
            if ext_row and ext_row[0].get("external_id"):
                ext = str(ext_row[0]["external_id"]).upper()
            return entity_id, ext

        return None, None

    def _technique_catalogs(self) -> tuple[dict[str, str], dict[str, str]]:
        if self._technique_by_external is not None and self._technique_by_name is not None:
            return self._technique_by_external, self._technique_by_name
        rows = self.graph_store.run_read(
            """
            MATCH (t:Technique)
            RETURN t.entity_id AS entity_id, t.name AS name, t.external_id AS external_id
            """
        )
        by_ext: dict[str, str] = {}
        by_name: dict[str, str] = {}
        for row in rows:
            entity_id = row.get("entity_id")
            if not entity_id:
                continue
            ext = row.get("external_id")
            if isinstance(ext, str) and ext.strip():
                by_ext.setdefault(ext.strip().upper(), str(entity_id))
            name = row.get("name")
            if name:
                by_name.setdefault(str(name).strip().lower(), str(entity_id))
        self._technique_by_external = by_ext
        self._technique_by_name = by_name
        return by_ext, by_name
