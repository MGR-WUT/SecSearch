"""Deterministic STIX 2.1 loader for MITRE ATT&CK Enterprise.

This loader intentionally avoids the LLM ExtractionService:

* MITRE ATT&CK ships as canonical structured STIX, so an LLM round-trip would
  only add noise. Bypassing it lets the thesis credit the *graph analytics*
  (PageRank, Louvain) for any signal we observe, rather than the extraction LLM.
* The same Neo4j ``Entity`` superclass is reused so the existing GraphRAG
  retrieval and graph maintenance code continue to work over the ATT&CK
  subgraph (we just add domain-specific labels like ``ThreatActor`` so we can
  write idiomatic Cypher in evaluation scripts).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.graph.neo4j_store import GraphEntity, GraphRelation, Neo4jStore

logger = logging.getLogger(__name__)

ATTACK_SOURCE_ID = "mitre-attack:enterprise"
ATTACK_SOURCE_URI = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"

# Map STIX object types to in-graph entity labels. Everything still gets the
# shared ``Entity`` label via Neo4jStore.upsert_entity so PageRank/Louvain
# projections do not need to know about the ATT&CK schema explicitly.
STIX_TYPE_TO_LABEL: dict[str, str] = {
    "intrusion-set": "ThreatActor",
    "attack-pattern": "Technique",
    "x-mitre-tactic": "Tactic",
    "malware": "Malware",
    "tool": "Tool",
    "course-of-action": "Mitigation",
    "campaign": "Campaign",
}

# STIX `relationship_type` strings we honour, mapped to Cypher edge types.
# ATT&CK only uses a small, well-defined set; anything else is ignored.
STIX_REL_TO_TYPE: dict[str, str] = {
    "uses": "USES",
    "mitigates": "MITIGATES",
    "subtechnique-of": "SUBTECHNIQUE_OF",
    "attributed-to": "ATTRIBUTED_TO",
    "targets": "TARGETS",
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class LoadStats:
    """Counters reported back so CLI/CI can show a one-line summary."""

    entities_by_label: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    relations_by_type: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    skipped_objects: int = 0
    skipped_relationships: int = 0
    cve_nodes: int = 0
    revoked_objects_skipped: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "entities_by_label": dict(self.entities_by_label),
            "relations_by_type": dict(self.relations_by_type),
            "total_entities": sum(self.entities_by_label.values()),
            "total_relations": sum(self.relations_by_type.values()),
            "skipped_objects": self.skipped_objects,
            "skipped_relationships": self.skipped_relationships,
            "cve_nodes": self.cve_nodes,
            "revoked_objects_skipped": self.revoked_objects_skipped,
        }


class AttackLoader:
    """Load a MITRE ATT&CK Enterprise STIX 2.1 bundle into Neo4j.

    The loader is idempotent: rerunning over the same Neo4j keeps a single
    Source node and re-MERGEs entities / relationships by stable IDs.
    """

    def __init__(self, graph_store: Neo4jStore, *, source_id: str = ATTACK_SOURCE_ID) -> None:
        self.graph_store = graph_store
        self.source_id = source_id

    def load_bundle(
        self,
        bundle: dict[str, Any] | str | Path,
        *,
        source_uri: str = ATTACK_SOURCE_URI,
    ) -> LoadStats:
        """Load a bundle from a parsed dict, a JSON string, or a path on disk."""

        if isinstance(bundle, (str, Path)):
            data = json.loads(Path(bundle).read_text(encoding="utf-8"))
        else:
            data = bundle

        if not isinstance(data, dict) or data.get("type") != "bundle":
            raise ValueError("Bundle must be a STIX 2.1 bundle object with type='bundle'.")
        objects = data.get("objects")
        if not isinstance(objects, list):
            raise ValueError("Bundle is missing the 'objects' array.")

        content_hash = hashlib.sha256(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        self.graph_store.upsert_source(
            source_id=self.source_id,
            source_uri=source_uri,
            source_type="stix-bundle",
            last_updated=datetime.now(timezone.utc).isoformat(),
            etag=None,
            content_hash=content_hash,
        )

        stats = LoadStats()
        cve_ids_seen: set[str] = set()

        # Pass 1: index domain objects by STIX id so we can resolve relationships
        # and skip revoked/deprecated entries deterministically.
        indexed_objects: dict[str, dict[str, Any]] = {}
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            stix_id = obj.get("id")
            stix_type = obj.get("type")
            if not isinstance(stix_id, str) or not isinstance(stix_type, str):
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                stats.revoked_objects_skipped += 1
                continue
            indexed_objects[stix_id] = obj

        # Pass 2: write domain entities (everything except relationships and CVEs derived from refs).
        for stix_id, obj in indexed_objects.items():
            stix_type = obj["type"]
            if stix_type == "relationship":
                # Relationships are handled in pass 3; do not count them as skipped entities.
                continue
            label = STIX_TYPE_TO_LABEL.get(stix_type)
            if label is None:
                # Many STIX types (identity, marking-definition, x-mitre-collection, ...) are
                # metadata that does not belong in the analytical graph.
                stats.skipped_objects += 1
                continue
            self._upsert_domain_entity(obj, label=label)
            stats.entities_by_label[label] += 1

            for cve_id in _collect_cve_ids(obj):
                if cve_id not in cve_ids_seen:
                    self._upsert_cve(cve_id)
                    cve_ids_seen.add(cve_id)
                    stats.cve_nodes += 1
                    stats.entities_by_label["CVE"] += 1
                # CVE edge: the STIX object that referenced the CVE is treated as the
                # exploit/usage carrier. This includes actors and campaigns because
                # some recent ATT&CK entries mention exploited CVEs only in actor /
                # campaign descriptions, not as technique or software references.
                if stix_type in {"attack-pattern", "malware", "tool", "intrusion-set", "campaign"}:
                    self.graph_store.upsert_relation(
                        GraphRelation(
                            source_id=_attack_id_to_entity_id(stix_id),
                            target_id=_cve_to_entity_id(cve_id),
                            relation_type="EXPLOITS",
                            properties={"source": "mitre-attack-external-reference"},
                        )
                    )
                    stats.relations_by_type["EXPLOITS"] += 1

            # Technique -> Tactic edges from kill_chain_phases (not a STIX relationship).
            if stix_type == "attack-pattern":
                for tactic_phase in _kill_chain_tactic_names(obj):
                    tactic_entity_id = self._lookup_tactic_entity_id(indexed_objects, tactic_phase)
                    if tactic_entity_id is None:
                        continue
                    self.graph_store.upsert_relation(
                        GraphRelation(
                            source_id=_attack_id_to_entity_id(stix_id),
                            target_id=tactic_entity_id,
                            relation_type="IN_TACTIC",
                            properties={"source": "mitre-attack-kill-chain"},
                        )
                    )
                    stats.relations_by_type["IN_TACTIC"] += 1

        # Pass 3: write explicit STIX relationships, resolved against the indexed objects.
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "relationship":
                continue
            if obj.get("revoked"):
                stats.skipped_relationships += 1
                continue
            rel_kind = obj.get("relationship_type")
            mapped_rel = STIX_REL_TO_TYPE.get(str(rel_kind))
            if mapped_rel is None:
                stats.skipped_relationships += 1
                continue
            src_ref = obj.get("source_ref")
            dst_ref = obj.get("target_ref")
            if (
                not isinstance(src_ref, str)
                or not isinstance(dst_ref, str)
                or src_ref not in indexed_objects
                or dst_ref not in indexed_objects
            ):
                stats.skipped_relationships += 1
                continue
            # Skip relationships whose endpoints are not in our analytical schema.
            src_label = STIX_TYPE_TO_LABEL.get(indexed_objects[src_ref]["type"])
            dst_label = STIX_TYPE_TO_LABEL.get(indexed_objects[dst_ref]["type"])
            if src_label is None or dst_label is None:
                stats.skipped_relationships += 1
                continue
            self.graph_store.upsert_relation(
                GraphRelation(
                    source_id=_attack_id_to_entity_id(src_ref),
                    target_id=_attack_id_to_entity_id(dst_ref),
                    relation_type=mapped_rel,
                    properties={
                        "stix_id": obj.get("id"),
                        "description": _truncate(obj.get("description"), 500),
                    },
                )
            )
            stats.relations_by_type[mapped_rel] += 1

        logger.info("ATT&CK load summary: %s", stats.as_dict())
        return stats

    # ----- helpers ----------------------------------------------------------------

    def _upsert_domain_entity(self, obj: dict[str, Any], *, label: str) -> None:
        stix_id = obj["id"]
        entity_id = _attack_id_to_entity_id(stix_id)
        name = obj.get("name") or stix_id
        external_id = _primary_attack_id(obj)
        aliases = obj.get("aliases") if isinstance(obj.get("aliases"), list) else None
        properties: dict[str, Any] = {
            "stix_type": obj.get("type"),
            "stix_id": stix_id,
            "external_id": external_id,
            "description": _truncate(obj.get("description"), 1200),
            "platforms": obj.get("x_mitre_platforms"),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique"),
            "aliases": aliases,
            "domain": "mitre-attack-enterprise",
        }
        self.graph_store.upsert_entity(
            GraphEntity(label=label, entity_id=entity_id, name=name, properties=properties),
            source_id=self.source_id,
            extra_labels=[label, "AttackEntity"],
        )

    def _upsert_cve(self, cve_id: str) -> None:
        cve_id = cve_id.upper()
        self.graph_store.upsert_entity(
            GraphEntity(
                label="CVE",
                entity_id=_cve_to_entity_id(cve_id),
                name=cve_id,
                properties={
                    "stix_type": "vulnerability",
                    "external_id": cve_id,
                    "domain": "mitre-attack-enterprise",
                },
            ),
            source_id=self.source_id,
            extra_labels=["CVE", "AttackEntity"],
        )

    @staticmethod
    def _lookup_tactic_entity_id(
        indexed_objects: dict[str, dict[str, Any]], tactic_phase_name: str
    ) -> str | None:
        # Kill-chain phases reference tactics by `x_mitre_shortname` (e.g. "initial-access").
        for stix_id, obj in indexed_objects.items():
            if obj.get("type") != "x-mitre-tactic":
                continue
            if obj.get("x_mitre_shortname") == tactic_phase_name:
                return _attack_id_to_entity_id(stix_id)
        return None


def _attack_id_to_entity_id(stix_id: str) -> str:
    return f"attack:{stix_id}"


def _cve_to_entity_id(cve_id: str) -> str:
    return f"cve:{cve_id.upper()}"


def _primary_attack_id(obj: dict[str, Any]) -> str | None:
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if isinstance(ext, str):
                return ext
    return None


def _kill_chain_tactic_names(obj: dict[str, Any]) -> list[str]:
    phases = obj.get("kill_chain_phases")
    if not isinstance(phases, list):
        return []
    names: list[str] = []
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        name = phase.get("phase_name")
        if isinstance(name, str):
            names.append(name)
    return names


def _collect_cve_ids(obj: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    refs = obj.get("external_references")
    if isinstance(refs, list):
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            if ref.get("source_name", "").lower() == "cve":
                ext = ref.get("external_id")
                if isinstance(ext, str) and CVE_PATTERN.fullmatch(ext.strip()):
                    found.add(ext.strip().upper())
            # Some references stash a CVE in the URL or description rather than external_id.
            for field_name in ("description", "url"):
                value = ref.get(field_name)
                if isinstance(value, str):
                    for match in CVE_PATTERN.findall(value):
                        found.add(match.upper())
    for field_name in ("description", "name"):
        value = obj.get(field_name)
        if isinstance(value, str):
            for match in CVE_PATTERN.findall(value):
                found.add(match.upper())
    return sorted(found)


def _truncate(value: Any, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
