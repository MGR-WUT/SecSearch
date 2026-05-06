# Dynamic Local GraphRAG for Cybersecurity Docs

This service builds and queries a local Neo4j knowledge graph from cybersecurity PDFs and vendor URLs.
It runs fully local with Ollama + Neo4j and exposes a FastAPI interface for ingestion, temporal refresh, and multi-hop QA.

## Privacy and safety guarantees

- Local-only by default: the app blocks non-local LLM endpoints unless explicitly enabled.
- No autonomous actions: responses are recommendation/hypothesis only.
- Evidence-first answering: answers are returned with graph path evidence and source citations.

## Stack

- FastAPI backend
- LangChain + `GraphCypherQAChain`
- Neo4j graph database
- Ollama local LLMs (`deepseek-r1:8b` / `gemma3:4b`)
- RAGAS-based faithfulness metric and WildGraphBench-compatible output adapter

## Quick start

1. Copy env file:
   - `cp .env.example .env`
2. Start Neo4j:
   - `docker compose up -d`
3. Install dependencies:
   - `pip install -r requirements.txt`
4. Run API:
   - `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`

## API endpoints

- `GET /` health + privacy mode
- `POST /ingest` with payload:
  - `pdf_paths`: local file paths
  - `urls`: vendor documentation URLs
- `POST /query` with payload:
  - `question`: user question
- `POST /query_v2` for Neo4j GraphRAG Python + vector retrieval (`nomic-embed-text`)
- `POST /query/compare` for side-by-side response comparison (`/query` vs `/query_v2`)
- `POST /temporal/update` to trigger stale-source refresh

## Temporal update loop

- Each source stores `last_updated`, `etag`, and `content_hash`.
- A scheduler periodically checks HTTP metadata.
- Stale sources are re-ingested and older graph state is marked superseded.

## Evaluation

Run baseline evaluation:

- `PYTHONPATH=. python scripts/run_evaluation.py`

Artifacts:

- `data/eval/report.json`: local multi-hop, faithfulness, and latency metrics
- `data/eval/sota_comparison.json`: gap vs larger SOTA references
- `data/eval/sample_multihop_dataset.json`: starter multi-hop dataset

WildGraphBench integration:

- Use `app/eval/wildgraphbench.py` to export predictions and compare with benchmark/SOTA outputs.

## GraphRAG v2 notes

- v2 uses `neo4j-graphrag-python` retriever flow with chunk embeddings stored on `Chunk.embedding`.
- Default embedding model is `nomic-embed-text` (configure in `settings.yaml`).
- Ensure vector dimensions in settings match the selected embedding model.
