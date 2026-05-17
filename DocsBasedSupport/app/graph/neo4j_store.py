from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


def sanitize_neo4j_properties(props: dict[str, Any], *, prefix: str = "") -> dict[str, Any]:
    """Neo4j node properties must be primitives or arrays of primitives (no nested maps)."""
    sanitized: dict[str, Any] = {}
    for key, value in props.items():
        if value is None:
            continue
        key_str = str(key)
        full_key = f"{prefix}_{key_str}" if prefix else key_str
        if isinstance(value, dict):
            sanitized.update(sanitize_neo4j_properties(value, prefix=full_key))
            continue
        if isinstance(value, list):
            if value and all(isinstance(item, (str, int, float, bool)) for item in value):
                sanitized[full_key] = value
            else:
                sanitized[full_key] = json.dumps(value, ensure_ascii=True)
            continue
        if isinstance(value, (str, int, float, bool)):
            sanitized[full_key] = value
            continue
        sanitized[full_key] = str(value)
    return sanitized


@dataclass
class GraphEntity:
    label: str
    entity_id: str
    name: str
    properties: dict[str, Any]


@dataclass
class GraphRelation:
    source_id: str
    target_id: str
    relation_type: str
    properties: dict[str, Any]


class Neo4jStore:
    def __init__(self, uri: str, username: str, password: str, database: str) -> None:
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self.database = database

    def close(self) -> None:
        self.driver.close()

    def ensure_schema(self) -> None:
        statements = [
            "CREATE CONSTRAINT source_id_unique IF NOT EXISTS FOR (s:Source) REQUIRE s.source_id IS UNIQUE",
            "CREATE CONSTRAINT entity_id_unique IF NOT EXISTS FOR (e:Entity) REQUIRE e.entity_id IS UNIQUE",
            "CREATE INDEX source_current_idx IF NOT EXISTS FOR (s:Source) ON (s.current)",
            "CREATE CONSTRAINT chunk_id_unique IF NOT EXISTS FOR (c:Chunk) REQUIRE c.chunk_id IS UNIQUE",
        ]
        with self.driver.session(database=self.database) as session:
            for statement in statements:
                session.run(statement)

    def upsert_source(
        self,
        source_id: str,
        source_uri: str,
        source_type: str,
        last_updated: str | None,
        etag: str | None,
        content_hash: str | None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        query = """
        MERGE (s:Source {source_id: $source_id})
        ON CREATE SET s.created_at = $now
        SET
            s.source_uri = $source_uri,
            s.source_type = $source_type,
            s.last_updated = $last_updated,
            s.etag = $etag,
            s.content_hash = $content_hash,
            s.current = true,
            s.updated_at = $now
        """
        with self.driver.session(database=self.database) as session:
            session.run(
                query,
                source_id=source_id,
                source_uri=source_uri,
                source_type=source_type,
                last_updated=last_updated,
                etag=etag,
                content_hash=content_hash,
                now=now,
            )

    def upsert_entity(self, entity: GraphEntity, source_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        query = """
        MERGE (e:Entity {entity_id: $entity_id})
        ON CREATE SET e.created_at = $now
        SET e.label = $label, e.name = $name, e += $props, e.updated_at = $now
        WITH e
        MATCH (s:Source {source_id: $source_id})
        MERGE (s)-[:CONTAINS]->(e)
        """
        with self.driver.session(database=self.database) as session:
            session.run(
                query,
                entity_id=entity.entity_id,
                label=entity.label,
                name=entity.name,
                props=sanitize_neo4j_properties(entity.properties),
                source_id=source_id,
                now=now,
            )

    def upsert_relation(self, relation: GraphRelation) -> None:
        now = datetime.now(timezone.utc).isoformat()
        query = f"""
        MATCH (a:Entity {{entity_id: $source_id}})
        MATCH (b:Entity {{entity_id: $target_id}})
        MERGE (a)-[r:{relation.relation_type}]->(b)
        SET r += $props, r.updated_at = $now, r.current = true
        """
        with self.driver.session(database=self.database) as session:
            session.run(
                query,
                source_id=relation.source_id,
                target_id=relation.target_id,
                props=sanitize_neo4j_properties(relation.properties),
                now=now,
            )

    def mark_source_superseded(self, source_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        query = """
        MATCH (s:Source {source_id: $source_id})
        SET s.current = false, s.valid_to = $now
        WITH s
        MATCH (s)-[:CONTAINS]->(e:Entity)
        SET e.current = false, e.valid_to = $now
        """
        with self.driver.session(database=self.database) as session:
            session.run(query, source_id=source_id, now=now)

    def list_sources(self) -> list[dict[str, Any]]:
        query = """
        MATCH (s:Source)
        RETURN s.source_id AS source_id, s.source_uri AS source_uri, s.last_updated AS last_updated, s.etag AS etag, s.current AS current
        """
        with self.driver.session(database=self.database) as session:
            return [dict(record) for record in session.run(query)]

    def get_evidence_path(self, entity_a: str, entity_b: str, max_hops: int = 4) -> list[dict[str, str]]:
        query = """
        MATCH p = (a:Entity {name: $entity_a})-[*1..4]->(b:Entity {name: $entity_b})
        RETURN p
        LIMIT 1
        """
        with self.driver.session(database=self.database) as session:
            record = session.run(query, entity_a=entity_a, entity_b=entity_b, max_hops=max_hops).single()
            if record is None:
                return []
            path = record["p"]
            edges: list[dict[str, str]] = []
            for rel in path.relationships:
                edges.append(
                    {
                        "source": rel.start_node["name"],
                        "relationship": rel.type,
                        "target": rel.end_node["name"],
                    }
                )
            return edges

    def upsert_chunks(self, source_id: str, chunks: list[dict[str, str]]) -> None:
        query = """
        UNWIND $rows AS row
        MERGE (c:Chunk {chunk_id: row.chunk_id})
        SET c.text = row.text, c.source_id = $source_id
        WITH c
        MATCH (s:Source {source_id: $source_id})
        MERGE (s)-[:HAS_CHUNK]->(c)
        """
        with self.driver.session(database=self.database) as session:
            session.run(query, rows=chunks, source_id=source_id)

    def set_chunk_embeddings(self, chunk_rows: list[dict[str, Any]]) -> None:
        query = """
        UNWIND $rows AS row
        MATCH (c:Chunk {chunk_id: row.chunk_id})
        SET c.embedding = row.embedding
        """
        with self.driver.session(database=self.database) as session:
            session.run(query, rows=chunk_rows)

    def get_chunk_contexts(self, chunk_ids: list[str]) -> list[dict[str, str]]:
        if not chunk_ids:
            return []
        query = """
        UNWIND $chunk_ids AS chunk_id
        MATCH (c:Chunk {chunk_id: chunk_id})
        OPTIONAL MATCH (s:Source)-[:HAS_CHUNK]->(c)
        RETURN c.chunk_id AS chunk_id, c.text AS text, c.source_id AS source_id, s.source_uri AS source_uri
        """
        with self.driver.session(database=self.database) as session:
            return [dict(record) for record in session.run(query, chunk_ids=chunk_ids)]

    def enrich_graph_offline(self) -> None:
        statements = [
            "CALL gds.graph.project('rag_graph', ['Entity', 'Chunk'], '*')",
            "CALL gds.pageRank.write('rag_graph', {writeProperty: 'pagerank'})",
            "CALL gds.louvain.write('rag_graph', {writeProperty: 'community'})",
            "CALL gds.graph.drop('rag_graph')",
        ]
        with self.driver.session(database=self.database) as session:
            for statement in statements:
                session.run(statement)

    def resolve_duplicate_entities(self) -> int:
        find_query = """
        MATCH (e1:Entity), (e2:Entity)
        WHERE e1.name = e2.name AND e1.label = e2.label AND elementId(e1) < elementId(e2)
        RETURN elementId(e1) AS id1, elementId(e2) AS id2
        LIMIT 500
        """
        merge_query = """
        MATCH (e1:Entity) WHERE elementId(e1) = $id1
        MATCH (e2:Entity) WHERE elementId(e2) = $id2
        CALL apoc.refactor.mergeNodes([e1, e2], {properties: 'combine', mergeRels: true})
        YIELD node
        RETURN count(node) AS merged_count
        """
        merged_total = 0
        with self.driver.session(database=self.database) as session:
            pairs = [(record["id1"], record["id2"]) for record in session.run(find_query)]
            for id1, id2 in pairs:
                try:
                    record = session.run(merge_query, id1=id1, id2=id2).single()
                    if record is not None:
                        merged_total += int(record["merged_count"])
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Skipping duplicate merge for entities %s / %s: %s", id1, id2, exc)
        return merged_total

    def query_chunk_vector_index(
        self, index_name: str, query_embedding: list[float], top_k: int
    ) -> list[dict[str, Any]]:
        query = """
        CALL db.index.vector.queryNodes($index_name, $top_k, $embedding)
        YIELD node, score
        OPTIONAL MATCH (node)<-[:HAS_CHUNK]-(s:Source)-[:CONTAINS]->(e:Entity)
        RETURN
            node.chunk_id AS chunk_id,
            node.text AS text,
            node.source_id AS source_id,
            s.source_uri AS source_uri,
            score,
            coalesce(max(e.pagerank), 0) AS max_pagerank
        ORDER BY score DESC, max_pagerank DESC
        """
        with self.driver.session(database=self.database) as session:
            return [
                dict(record)
                for record in session.run(
                    query,
                    index_name=index_name,
                    top_k=top_k,
                    embedding=query_embedding,
                )
            ]

