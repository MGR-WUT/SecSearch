# Neo4j snapshot: WildGraphBench technology (gpt-oss:120b)

Offline copy of the `docsbasedsupport_neo4j_data` Docker volume from container `docs_support_neo4j` (Neo4j 5.22).

| Field | Value |
| --- | --- |
| Extract model | `gpt-oss:120b` (via API ingest) |
| Domain | WildGraphBench `technology` |
| Reference run | `eval/WildGraphBench/runs_technology/gpt-oss:120b_e2e/` |
| Nodes (at export) | 13,769 |
| Ingested pages | 432 (+ 9 failures) |
| Archive | `neo4j-data.tar.gz` |

## Restore into Docker

From `DocsBasedSupport/`:

```bash
docker compose down -v
docker volume create docsbasedsupport_neo4j_data
docker run --rm \
  -v docsbasedsupport_neo4j_data:/data \
  -v "$(pwd)/neo4j_snapshots/gpt-oss-120b-technology-wildgraphbench:/backup:ro" \
  alpine tar xzf /backup/neo4j-data.tar.gz -C /data
docker compose up -d
```

(`docker compose down -v && docker compose up -d` alone gives an empty DB — run the volume import between those steps as above.)

Bolt: `bolt://localhost:7687` — user `neo4j` / password `neo4j_password`.

## Rebuild graph with another extract model

Wipe Neo4j, start stack, run API, then ingest only (example: `gpt-oss:20b-cloud`):

```bash
docker compose down -v && docker compose up -d
```

```bash
# terminal 1
cd DocsBasedSupport && PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 8000
```

```bash
# terminal 2 — ingest all technology reference pages (~2.7h for 120b-scale runs)
cd DocsBasedSupport && PYTHONUNBUFFERED=1 PYTHONPATH=. python eval/wildgraphbench_run.py \
  --mode api \
  --api-base-url http://localhost:8000 \
  --wildgraphbench-root "$(pwd)/eval/WildGraphBenchDataset" \
  --domain technology \
  --max-questions 0 \
  --output-dir "eval/WildGraphBench/runs_technology/gpt-oss:20b-cloud_technology_ingest" \
  --llm-provider ollama \
  --llm-base-url http://localhost:11434 \
  --llm-extract-model gpt-oss:20b-cloud \
  --llm-chat-model gpt-oss:20b-cloud \
  --llm-embed-model nomic-embed-text \
  --request-timeout-seconds 1800
```

Use your real Ollama/cloud base URL and API key settings if not local. Default client timeout is 1800s (30 min) per `/ingest` call; raise further if needed. Omit `--max-questions 0` to run full QA after ingest.
