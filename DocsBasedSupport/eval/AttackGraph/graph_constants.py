"""Shared graph-variant identifiers for AttackGraph experiments."""

from __future__ import annotations

from app.pipeline.attack_graph_variants import (  # noqa: F401
    GRAPH_VARIANT_LLM_PREFIX,
    GRAPH_VARIANT_STIX,
    USES_EXTRACTED_REL,
    actor_technique_uses_rel,
    build_llm_extracted_variant,
    is_llm_extracted_variant,
)

KEV_SOURCE_ID = "cisa-kev:catalog"
KEV_SOURCE_URI = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_KEV_URL = KEV_SOURCE_URI


def is_clean_stix_variant(graph_variant: str | None) -> bool:
    return graph_variant is None or graph_variant == GRAPH_VARIANT_STIX


def llm_source_tag(provider: str, model: str) -> str:
    import re

    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", model.strip())
    return f"{provider}:{slug}"
