from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from langchain_ollama import ChatOllama


class MitreMapper:
    def __init__(self, catalog_path: str, ollama_base_url: str, model: str) -> None:
        self.catalog_path = Path(catalog_path)
        with self.catalog_path.open("r", encoding="utf-8") as fh:
            self.catalog = json.load(fh)
        self.llm = ChatOllama(model=model, base_url=ollama_base_url, temperature=0)

    def map_item(self, text: str) -> dict[str, Any]:
        lowered = text.lower()
        for item in self.catalog:
            for keyword in item.get("keywords", []):
                if keyword.lower() in lowered:
                    return {
                        "framework": item["framework"],
                        "technique_id": item["technique_id"],
                        "technique_name": item["technique_name"],
                        "mapping_method": "catalog",
                        "confidence": 0.95,
                        "ontology_version": item.get("ontology_version", "unknown"),
                    }

        prompt = f"""
Map the following cybersecurity behavior to MITRE ATT&CK or D3FEND.
Return only JSON with keys: framework, technique_id, technique_name, confidence.
Text: {text}
"""
        response = self.llm.invoke(prompt).content.strip()
        parsed = self._parse_json(response)
        parsed["mapping_method"] = "llm_fallback"
        parsed["ontology_version"] = parsed.get("ontology_version", "unknown")
        return parsed

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        raw = raw.replace("```json", "").replace("```", "").strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {
                "framework": "UNKNOWN",
                "technique_id": "UNKNOWN",
                "technique_name": raw[:120],
                "confidence": 0.2,
            }
        return data

