"""Graph variant ids and parallel relationship types for ATT&CK experiments."""

from __future__ import annotations

import re

GRAPH_VARIANT_STIX = "mitre-stix"
GRAPH_VARIANT_LLM_PREFIX = "llm-extracted"
USES_EXTRACTED_REL = "USES_EXTRACTED"


def build_llm_extracted_variant(model: str, *, structure_profile: str | None = None) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", model.strip())
    base = f"{GRAPH_VARIANT_LLM_PREFIX}:{slug}"
    if structure_profile and structure_profile not in ("structured", "none"):
        prof = re.sub(r"[^a-zA-Z0-9._-]+", "-", structure_profile.strip().lower())
        return f"{base}:struct-{prof}"
    return base


def is_llm_extracted_variant(graph_variant: str | None) -> bool:
    return bool(graph_variant and graph_variant.startswith(GRAPH_VARIANT_LLM_PREFIX))


def actor_technique_uses_rel(graph_variant: str | None) -> str:
    return USES_EXTRACTED_REL if is_llm_extracted_variant(graph_variant) else "USES"
