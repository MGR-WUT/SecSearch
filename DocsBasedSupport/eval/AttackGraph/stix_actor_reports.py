"""Build per–threat-actor documents from the MITRE ATT&CK STIX bundle for LLM extraction.

Each document concatenates the group's description and the prose MITRE ships on
every ``uses`` relationship (ThreatActor → Technique). Gold ``USES`` pairs come
from the same STIX graph so extraction quality can be scored without AnnoCTR.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.pipeline.attack_loader import (
    STIX_REL_TO_TYPE,
    STIX_TYPE_TO_LABEL,
    _attack_id_to_entity_id,
    _primary_attack_id,
    _truncate,
)

logger = logging.getLogger(__name__)

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


@dataclass(frozen=True)
class GoldUsesEdge:
    technique_entity_id: str
    technique_external_id: str | None
    technique_name: str


@dataclass
class StixActorReport:
    actor_stix_id: str
    actor_entity_id: str
    actor_name: str
    actor_external_id: str | None
    text: str
    gold_edges: list[GoldUsesEdge] = field(default_factory=list)

    @property
    def gold_pairs(self) -> set[tuple[str, str]]:
        return {(self.actor_entity_id, edge.technique_entity_id) for edge in self.gold_edges}


def _index_objects(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for obj in bundle.get("objects", []):
        if isinstance(obj, dict) and isinstance(obj.get("id"), str):
            indexed[obj["id"]] = obj
    return indexed


def _technique_external_id(obj: dict[str, Any]) -> str | None:
    ext = _primary_attack_id(obj)
    if ext and _TECHNIQUE_ID_RE.fullmatch(ext):
        return ext.upper()
    return None


def build_actor_reports(
    bundle: dict[str, Any] | str | Path,
    *,
    min_gold_edges: int = 1,
    max_text_chars: int = 14_000,
) -> list[StixActorReport]:
    """Return one synthetic CTI document per intrusion-set with STIX gold USES edges."""
    if isinstance(bundle, (str, Path)):
        bundle = json.loads(Path(bundle).read_text(encoding="utf-8"))
    indexed = _index_objects(bundle)

    uses_rels: list[dict[str, Any]] = []
    for obj in indexed.values():
        if obj.get("type") != "relationship" or obj.get("revoked"):
            continue
        if obj.get("relationship_type") != "uses":
            continue
        src_ref = obj.get("source_ref")
        dst_ref = obj.get("target_ref")
        if not isinstance(src_ref, str) or not isinstance(dst_ref, str):
            continue
        src_obj = indexed.get(src_ref)
        dst_obj = indexed.get(dst_ref)
        if not src_obj or not dst_obj:
            continue
        if src_obj.get("type") != "intrusion-set" or dst_obj.get("type") != "attack-pattern":
            continue
        uses_rels.append(obj)

    by_actor: dict[str, list[dict[str, Any]]] = {}
    for rel in uses_rels:
        src_ref = str(rel["source_ref"])
        by_actor.setdefault(src_ref, []).append(rel)

    reports: list[StixActorReport] = []
    for actor_stix_id, rels in sorted(by_actor.items()):
        actor_obj = indexed.get(actor_stix_id)
        if not actor_obj or actor_obj.get("revoked"):
            continue
        actor_entity_id = _attack_id_to_entity_id(actor_stix_id)
        actor_name = str(actor_obj.get("name") or actor_stix_id)
        actor_external_id = _primary_attack_id(actor_obj)
        aliases = actor_obj.get("aliases")
        alias_str = ""
        if isinstance(aliases, list) and aliases:
            alias_str = ", ".join(str(a) for a in aliases if a)

        sections: list[str] = [
            f"# Threat group report: {actor_name}",
        ]
        if actor_external_id:
            sections.append(f"ATT&CK group ID: {actor_external_id}")
        if alias_str:
            sections.append(f"Aliases: {alias_str}")
        actor_desc = actor_obj.get("description")
        if actor_desc:
            sections.append("\n## Group overview\n" + str(actor_desc).strip())

        gold_edges: list[GoldUsesEdge] = []
        technique_blocks: list[str] = []
        for rel in rels:
            dst_ref = str(rel["target_ref"])
            tech_obj = indexed.get(dst_ref)
            if not tech_obj:
                continue
            tech_entity_id = _attack_id_to_entity_id(dst_ref)
            tech_name = str(tech_obj.get("name") or dst_ref)
            tech_ext = _technique_external_id(tech_obj)
            gold_edges.append(
                GoldUsesEdge(
                    technique_entity_id=tech_entity_id,
                    technique_external_id=tech_ext,
                    technique_name=tech_name,
                )
            )
            rel_desc = rel.get("description") or tech_obj.get("description") or ""
            header = f"### {tech_ext or tech_name} — {tech_name}"
            block = header
            if rel_desc:
                block += f"\n{str(rel_desc).strip()}"
            technique_blocks.append(block)

        if len(gold_edges) < min_gold_edges:
            continue

        sections.append("\n## Documented techniques used by this group")
        sections.extend(technique_blocks)
        text = "\n\n".join(sections)
        if len(text) > max_text_chars:
            text = text[:max_text_chars] + "\n\n[Document truncated for model context.]"

        reports.append(
            StixActorReport(
                actor_stix_id=actor_stix_id,
                actor_entity_id=actor_entity_id,
                actor_name=actor_name,
                actor_external_id=actor_external_id,
                text=text,
                gold_edges=gold_edges,
            )
        )

    logger.info("Built %d STIX actor reports (min_gold_edges=%d).", len(reports), min_gold_edges)
    return reports


def reports_to_corpus_payload(reports: list[StixActorReport]) -> dict[str, Any]:
    return {
        "documents": [
            {
                "actor_entity_id": r.actor_entity_id,
                "actor_name": r.actor_name,
                "actor_external_id": r.actor_external_id,
                "text_chars": len(r.text),
                "gold_uses_count": len(r.gold_edges),
                "gold_pairs": [
                    {"actor_id": r.actor_entity_id, "technique_id": e.technique_entity_id}
                    for e in r.gold_edges
                ],
            }
            for r in reports
        ],
        "total_gold_pairs": sum(len(r.gold_pairs) for r in reports),
    }
