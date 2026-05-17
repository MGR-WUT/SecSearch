# Neo4j snapshot: WildGraphBench technology (gemma3:4b)

Offline copy of the `docsbasedsupport_neo4j_data` Docker volume (Neo4j 5.22).

| Field | Value |
| --- | --- |
| Extract model | `gemma3:4b` |
| Chat model (QA run) | `gemma3:4b` |
| Domain | WildGraphBench `technology` |
| Reference run | `eval/WildGraphBench/runs_technology/gemma3:4b_e2e/` |
| Nodes (at export) | 13,440 |
| Ingested pages | 439 (+ 2 failures) |
| Archive | `neo4j-data.tar.gz` (~191 MB) |

## Restore

From `DocsBasedSupport/`:

```bash
docker compose down -v
docker volume create docsbasedsupport_neo4j_data
docker run --rm \
  -v docsbasedsupport_neo4j_data:/data \
  -v "$(pwd)/neo4j_snapshots/gemma3-4b-technology-wildgraphbench:/backup:ro" \
  alpine tar xzf /backup/neo4j-data.tar.gz -C /data
docker compose up -d
```

Bolt: `bolt://localhost:7687` — user `neo4j` / password `neo4j_password`.
