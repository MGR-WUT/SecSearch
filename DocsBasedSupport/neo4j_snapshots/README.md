# Neo4j graph snapshots

Large `neo4j-data.tar.gz` files are gitignored. `SNAPSHOT.md` in each folder is tracked.

## Available snapshots

| Folder | Extract model | Domain | Nodes |
| --- | --- | --- | --- |
| `gpt-oss-120b-technology-wildgraphbench/` | `gpt-oss:120b` | technology | 13,769 |
| `gemma3-4b-technology-wildgraphbench/` | `gemma3:4b` | technology | 13,440 |

## Switch graphs

Stop ingest/QA and the API first, then from `DocsBasedSupport/`:

**Load gpt-oss:120b (original benchmark graph):**

```bash
docker compose down -v
docker volume create docsbasedsupport_neo4j_data
docker run --rm \
  -v docsbasedsupport_neo4j_data:/data \
  -v "$(pwd)/neo4j_snapshots/gpt-oss-120b-technology-wildgraphbench:/backup:ro" \
  alpine tar xzf /backup/neo4j-data.tar.gz -C /data
docker compose up -d
```

**Load gemma3:4b technology graph:**

```bash
docker compose down -v
docker volume create docsbasedsupport_neo4j_data
docker run --rm \
  -v docsbasedsupport_neo4j_data:/data \
  -v "$(pwd)/neo4j_snapshots/gemma3-4b-technology-wildgraphbench:/backup:ro" \
  alpine tar xzf /backup/neo4j-data.tar.gz -C /data
docker compose up -d
```

## Export current Docker volume

```bash
mkdir -p neo4j_snapshots/<name>
docker run --rm \
  -v docsbasedsupport_neo4j_data:/data:ro \
  -v "$(pwd)/neo4j_snapshots/<name>:/backup" \
  alpine tar czf /backup/neo4j-data.tar.gz -C /data .
```
