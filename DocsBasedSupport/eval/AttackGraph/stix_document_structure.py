"""Controlled degradation of CTI document structure before LLM extraction.

Mirrors the old synthetic *edge* noise idea, but applies to the *input text*:
same STIX gold USES pairs, progressively less markdown/sectioning/ATT&CK id salience.
"""

from __future__ import annotations

import random
import re
from typing import Any

_STRUCTURE_PROFILES = ("structured", "mild", "moderate", "severe")
_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_HEADER_RE = re.compile(r"^#{1,6}\s+", re.MULTILINE)


def structure_profiles() -> tuple[str, ...]:
    return _STRUCTURE_PROFILES


def apply_structure_profile(
    text: str,
    profile: str,
    *,
    seed: int = 20260603,
    doc_key: str = "",
) -> str:
    """Return document text for the given structure profile."""
    if profile == "structured":
        return text
    if profile == "mild":
        return _mild(text)
    if profile == "moderate":
        return _moderate(text)
    if profile == "severe":
        doc_seed = (seed + hash(doc_key)) & 0xFFFFFFFF
        return _severe(text, seed=doc_seed)
    raise ValueError(f"Unknown structure profile {profile!r}; expected one of {_STRUCTURE_PROFILES}")


def estimate_lack_of_structure(text: str) -> dict[str, float]:
    """Heuristic metrics; higher ``lack_of_structure_score`` = less structure."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    n_lines = max(len(lines), 1)
    header_lines = sum(1 for ln in lines if ln.lstrip().startswith("#"))
    technique_ids = len(_TECHNIQUE_ID_RE.findall(text))
    words = max(len(text.split()), 1)
    paragraphs = [p for p in re.split(r"\n\s*\n", text) if p.strip()]
    avg_para_words = sum(len(p.split()) for p in paragraphs) / max(len(paragraphs), 1)

    header_ratio = header_lines / n_lines
    tid_density = technique_ids / words
    # Composite: low headers, low T-id density, long paragraphs => less structure
    lack = (
        0.35 * (1.0 - min(header_ratio * 8, 1.0))
        + 0.35 * (1.0 - min(tid_density * 120, 1.0))
        + 0.30 * min(avg_para_words / 80.0, 1.0)
    )
    return {
        "header_line_ratio": round(header_ratio, 4),
        "technique_id_per_100_words": round(100.0 * tid_density, 2),
        "avg_paragraph_words": round(avg_para_words, 1),
        "paragraph_count": float(len(paragraphs)),
        "lack_of_structure_score": round(lack, 4),
    }


def corpus_structure_summary(texts: list[str]) -> dict[str, Any]:
    per_doc = [estimate_lack_of_structure(t) for t in texts]
    if not per_doc:
        return {"documents": 0, "mean_lack_of_structure_score": 0.0}
    keys = [k for k in per_doc[0] if k != "lack_of_structure_score"]
    means = {k: round(sum(d[k] for d in per_doc) / len(per_doc), 4) for k in keys}
    means["mean_lack_of_structure_score"] = round(
        sum(d["lack_of_structure_score"] for d in per_doc) / len(per_doc), 4
    )
    means["documents"] = len(per_doc)
    return means


def _mild(text: str) -> str:
    """Flatten markdown headings; keep technique ids and section content."""
    out = _HEADER_RE.sub("", text)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


def _moderate(text: str) -> str:
    """Single narrative block: no headings, technique blocks run together."""
    chunks: list[str] = []
    for block in re.split(r"\n\s*\n", _mild(text)):
        line = " ".join(ln.strip() for ln in block.splitlines() if ln.strip())
        if line:
            chunks.append(line)
    return " ".join(chunks)


def _severe(text: str, *, seed: int) -> str:
    """Weak structure: narrative blob, shuffled sections, ATT&CK ids redacted in body."""
    rng = random.Random(seed)
    body = _moderate(text)
    # Split on technique section markers (### or inline T-id headers from mild)
    parts = re.split(r"(?=\bT\d{4}(?:\.\d{3})?\b)", body)
    intro = parts[0].strip() if parts else body
    technique_parts = [p.strip() for p in parts[1:] if p.strip()]
    rng.shuffle(technique_parts)
    merged = " ".join([intro, *technique_parts]).strip()
    merged = _TECHNIQUE_ID_RE.sub("[TECHNIQUE]", merged)
    merged = re.sub(r"\bATT&CK group ID:\s*\S+", "ATT&CK group ID: [REDACTED]", merged, flags=re.I)
    return merged
