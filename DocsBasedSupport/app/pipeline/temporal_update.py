from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.core.models import TemporalCheckResult
from app.graph.neo4j_store import Neo4jStore
from app.pipeline.extraction import ExtractionService
from app.pipeline.ingestion import IngestionService


class TemporalUpdateService:
    def __init__(
        self,
        graph_store: Neo4jStore,
        ingestion_service: IngestionService,
        extraction_service: ExtractionService,
        timeout_seconds: int = 20,
    ) -> None:
        self.graph_store = graph_store
        self.ingestion_service = ingestion_service
        self.extraction_service = extraction_service
        self.timeout_seconds = timeout_seconds

    def check_sources(self) -> list[TemporalCheckResult]:
        results: list[TemporalCheckResult] = []
        for source in self.graph_store.list_sources():
            if not source.get("source_uri", "").startswith("http"):
                continue
            try:
                with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
                    response = client.head(source["source_uri"])
                    remote_last_modified = response.headers.get("Last-Modified")
                    remote_etag = response.headers.get("ETag")
            except Exception as exc:
                results.append(
                    TemporalCheckResult(
                        source_id=source["source_id"],
                        source_url=source["source_uri"],
                        stale=False,
                        checked_at=datetime.now(timezone.utc),
                        reason=f"head_failed:{exc}",
                    )
                )
                continue

            stale = False
            reason = "up_to_date"
            if remote_etag and source.get("etag") and remote_etag != source["etag"]:
                stale = True
                reason = "etag_changed"
            elif remote_last_modified and source.get("last_updated") and remote_last_modified != source["last_updated"]:
                stale = True
                reason = "last_modified_changed"

            results.append(
                TemporalCheckResult(
                    source_id=source["source_id"],
                    source_url=source["source_uri"],
                    stale=stale,
                    checked_at=datetime.now(timezone.utc),
                    reason=reason,
                )
            )
        return results

    def run_update_cycle(self) -> dict[str, int]:
        checks = self.check_sources()
        stale_urls = [item.source_url for item in checks if item.stale]
        if not stale_urls:
            return {"checked": len(checks), "updated": 0}

        refreshed = self.ingestion_service.load_urls(stale_urls)
        for doc in refreshed:
            self.graph_store.mark_source_superseded(doc.source_id)
            self.extraction_service.extract_and_store(doc)

        return {"checked": len(checks), "updated": len(refreshed)}

