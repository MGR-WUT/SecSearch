from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException

from app.core.config import get_settings
from app.core.models import IngestRequest, QueryRequest, QueryResponse
from app.graph.neo4j_store import Neo4jStore
from app.pipeline.extraction import ExtractionService
from app.pipeline.ingestion import IngestionService
from app.pipeline.query_agent_v2 import GraphRAGV2Service
from app.pipeline.temporal_update import TemporalUpdateService

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("docs-graphrag")

scheduler = BackgroundScheduler()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    store.ensure_schema()
    app.state.graph_store = store
    app.state.ingestion_service = IngestionService(timeout_seconds=settings.temporal_http_timeout_seconds)
    app.state.extraction_service = ExtractionService(
        graph_store=store,
        llm_provider=settings.llm_provider,
        llm_base_url=settings.llm_base_url,
        llm_api_key=settings.llm_api_key,
        model=settings.llm_extract_model,
    )
    app.state.temporal_service = TemporalUpdateService(
        graph_store=store,
        ingestion_service=app.state.ingestion_service,
        extraction_service=app.state.extraction_service,
        timeout_seconds=settings.temporal_http_timeout_seconds,
    )
    app.state.query_agent_v2 = GraphRAGV2Service(
        graph_store=store,
        index_name=settings.graphrag_v2_index_name,
        embedding_dims=settings.graphrag_v2_embedding_dims,
        top_k=settings.graphrag_v2_top_k,
        llm_provider=settings.llm_provider,
        llm_base_url=settings.llm_base_url,
        llm_api_key=settings.llm_api_key,
        embed_model=settings.llm_embed_model,
        chat_model=settings.llm_chat_model,
    )
    scheduler.add_job(
        app.state.temporal_service.run_update_cycle,
        "interval",
        minutes=settings.temporal_refresh_minutes,
        id="temporal_refresh",
        replace_existing=True,
    )
    scheduler.start()
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)
        store.close()


app = FastAPI(title="Dynamic Local GraphRAG", lifespan=lifespan)


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok", "privacy": "local-only"}


@app.post("/ingest")
def ingest(payload: IngestRequest) -> dict[str, object]:
    docs = app.state.ingestion_service.load_pdfs(payload.pdf_paths) + app.state.ingestion_service.load_urls(payload.urls)
    results = []
    for doc in docs:
        extracted = app.state.extraction_service.extract_and_store(doc)
        extracted["v2_chunks_indexed"] = app.state.query_agent_v2.index_document_chunks(doc)
        results.append(extracted)
    return {"ingested": len(results), "details": results}


@app.post("/query_v2", response_model=QueryResponse)
def query_v2(payload: QueryRequest) -> QueryResponse:
    if not payload.question.strip():
        raise HTTPException(status_code=400, detail="Question must not be empty.")
    return app.state.query_agent_v2.answer(payload.question)


@app.post("/temporal/update")
def temporal_update() -> dict[str, int]:
    return app.state.temporal_service.run_update_cycle()

