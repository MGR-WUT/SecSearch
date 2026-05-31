from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


_LABEL_ALLOWED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REL_ALLOWED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _sanitize_labels(labels: list[str] | None) -> list[str]:
    """Only allow plain identifier characters to avoid Cypher injection via labels."""
    if not labels:
        return []
    sanitized: list[str] = []
    for label in labels:
        label_str = str(label)
        if _LABEL_ALLOWED.match(label_str):
            sanitized.append(label_str)
    return sanitized


def _sanitize_relation_type(rel_type: str) -> str:
    if not _REL_ALLOWED.match(rel_type):
        raise ValueError(f"Invalid relation type {rel_type!r}; must match {_REL_ALLOWED.pattern}.")
    return rel_type


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

    def upsert_entity(
        self,
        entity: GraphEntity,
        source_id: str,
        extra_labels: list[str] | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        # Build a SET clause for extra labels (e.g. ThreatActor, Technique) so callers
        # like the MITRE ATT&CK loader can write Cypher in idiomatic STIX terms while
        # still keeping :Entity for the existing GDS projection / GraphRAG retrieval.
        sanitized_extra_labels = _sanitize_labels(extra_labels)
        extra_labels_clause = (
            f", e:{':'.join(sanitized_extra_labels)}" if sanitized_extra_labels else ""
        )
        query = f"""
        MERGE (e:Entity {{entity_id: $entity_id}})
        ON CREATE SET e.created_at = $now
        SET e.label = $label, e.name = $name, e += $props, e.updated_at = $now{extra_labels_clause}
        WITH e
        MATCH (s:Source {{source_id: $source_id}})
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
        rel_type = _sanitize_relation_type(relation.relation_type)
        query = f"""
        MATCH (a:Entity {{entity_id: $source_id}})
        MATCH (b:Entity {{entity_id: $target_id}})
        MERGE (a)-[r:{rel_type}]->(b)
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

    def enrich_subgraph(
        self,
        *,
        graph_name: str,
        node_labels: list[str],
        relationship_types: list[str] | str = "*",
        pagerank_property: str = "pagerank",
        community_property: str = "community",
    ) -> None:
        """Project a labelled subgraph into GDS, run PageRank + Louvain, then drop it.

        Used by the MITRE ATT&CK experiment so analytics can be scoped to e.g.
        [ThreatActor, Technique, Tactic, Malware, Tool, Mitigation, CVE]
        independently from the GraphRAG chunk / general Entity graph.
        """
        sanitized_labels = _sanitize_labels(node_labels)
        if not sanitized_labels:
            raise ValueError("node_labels must contain at least one valid label identifier.")
        label_clause = "[" + ", ".join(f"'{lab}'" for lab in sanitized_labels) + "]"
        pr_property = _sanitize_relation_type(pagerank_property)
        cm_property = _sanitize_relation_type(community_property)
        with self.driver.session(database=self.database) as session:
            if isinstance(relationship_types, list):
                requested_rels = [_sanitize_relation_type(rt) for rt in relationship_types]
                existing_rels = {
                    record["relationshipType"]
                    for record in session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType")
                }
                sanitized_rels = [rt for rt in requested_rels if rt in existing_rels]
                missing_rels = sorted(set(requested_rels) - set(sanitized_rels))
                if missing_rels:
                    logger.info(
                        "Skipping relationship types not present in Neo4j for GDS projection %s: %s",
                        graph_name,
                        ", ".join(missing_rels),
                    )
                if not sanitized_rels:
                    raise ValueError(
                        "None of the requested relationship types exist in Neo4j; "
                        f"requested={requested_rels}"
                    )
                rel_clause = "[" + ", ".join(f"'{rt}'" for rt in sanitized_rels) + "]"
            elif relationship_types == "*":
                rel_clause = "'*'"
            else:
                raise ValueError("relationship_types must be a list of identifiers or the string '*'.")

            statements = [
                f"CALL gds.graph.drop('{graph_name}', false)",
                f"CALL gds.graph.project('{graph_name}', {label_clause}, {rel_clause})",
                f"CALL gds.pageRank.write('{graph_name}', {{writeProperty: '{pr_property}'}})",
                f"CALL gds.louvain.write('{graph_name}', {{writeProperty: '{cm_property}'}})",
                f"CALL gds.graph.drop('{graph_name}')",
            ]
            for statement in statements:
                session.run(statement)

    def delete_by_source(self, source_id: str) -> dict[str, int]:
        """Detach-delete every Entity and Chunk attached to a given Source, plus the Source.

        Required for re-runnable experiments — the ATT&CK loader uses a stable
        source_id so callers can rebuild from scratch without leaking stale nodes.
        """
        delete_entities = """
        MATCH (s:Source {source_id: $source_id})-[:CONTAINS]->(e:Entity)
        DETACH DELETE e
        RETURN count(e) AS deleted_entities
        """
        delete_chunks = """
        MATCH (s:Source {source_id: $source_id})-[:HAS_CHUNK]->(c:Chunk)
        DETACH DELETE c
        RETURN count(c) AS deleted_chunks
        """
        delete_source = """
        MATCH (s:Source {source_id: $source_id})
        DETACH DELETE s
        RETURN count(s) AS deleted_sources
        """
        with self.driver.session(database=self.database) as session:
            deleted_entities = session.run(delete_entities, source_id=source_id).single()["deleted_entities"]
            deleted_chunks = session.run(delete_chunks, source_id=source_id).single()["deleted_chunks"]
            deleted_sources = session.run(delete_source, source_id=source_id).single()["deleted_sources"]
        return {
            "deleted_entities": int(deleted_entities or 0),
            "deleted_chunks": int(deleted_chunks or 0),
            "deleted_sources": int(deleted_sources or 0),
        }

    def run_read(self, query: str, **params: Any) -> list[dict[str, Any]]:
        """Generic read helper used by evaluation scripts; keep callers thin."""
        with self.driver.session(database=self.database) as session:
            return [dict(record) for record in session.run(query, **params)]

    def run_write(self, query: str, **params: Any) -> list[dict[str, Any]]:
        with self.driver.session(database=self.database) as session:
            return [dict(record) for record in session.run(query, **params)]

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

