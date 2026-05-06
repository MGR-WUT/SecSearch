from __future__ import annotations

from typing import Any

try:
    from langchain_neo4j import GraphCypherQAChain
except ImportError:
    from langchain_community.chains.graph_qa.cypher import GraphCypherQAChain
from langchain_neo4j import Neo4jGraph
from langchain_ollama import ChatOllama

from app.core.models import ClaimCitation, EvidenceEdge, QueryResponse
from app.graph.neo4j_store import Neo4jStore


class QueryAgent:
    def __init__(
        self,
        graph_store: Neo4jStore,
        neo4j_uri: str,
        neo4j_username: str,
        neo4j_password: str,
        neo4j_database: str,
        ollama_base_url: str,
        model: str,
    ) -> None:
        self.graph_store = graph_store
        llm = ChatOllama(model=model, base_url=ollama_base_url, temperature=0)
        graph = Neo4jGraph(
            url=neo4j_uri,
            username=neo4j_username,
            password=neo4j_password,
            database=neo4j_database,
        )
        self.chain = GraphCypherQAChain.from_llm(
            llm=llm,
            graph=graph,
            verbose=False,
            allow_dangerous_requests=True,
            return_intermediate_steps=True,
        )

    def answer(self, question: str) -> QueryResponse:
        result: dict[str, Any] = self.chain.invoke({"query": question})
        answer = result.get("result", "").strip()
        steps = result.get("intermediate_steps", [])
        evidence_path = self._build_evidence(steps)
        citations = self._build_citations(steps, question, answer)

        if not evidence_path:
            answer = (
                "Insufficient grounded graph evidence was found for a reliable conclusion. "
                "Please ingest additional vendor documentation and retry."
            )
        else:
            answer = f"{answer}\n\nRecommendation: Validate this hypothesis with a human analyst before remediation."

        return QueryResponse(answer=answer, evidence_path=evidence_path, citations=citations)

    @staticmethod
    def _build_evidence(steps: list[dict[str, Any]]) -> list[EvidenceEdge]:
        edges: list[EvidenceEdge] = []
        for step in steps:
            context_rows = step.get("context")
            if not isinstance(context_rows, list):
                continue
            for row in context_rows:
                if not isinstance(row, dict):
                    continue
                src = row.get("source_name") or row.get("source") or row.get("a.name")
                rel = QueryAgent._normalize_relationship(row.get("relationship") or row.get("r.type"))
                dst = row.get("target_name") or row.get("target") or row.get("b.name")
                if src and dst:
                    edges.append(EvidenceEdge(source=str(src), relationship=str(rel), target=str(dst)))
        return edges

    @staticmethod
    def _build_citations(steps: list[dict[str, Any]], question: str, answer: str) -> list[ClaimCitation]:
        citations: list[ClaimCitation] = []
        edge_index = 0
        for step in steps:
            context_rows = step.get("context")
            if not isinstance(context_rows, list):
                continue
            for row in context_rows:
                if not isinstance(row, dict):
                    continue
                source_id = row.get("source_id")
                source_uri = row.get("source_uri")
                if source_id and source_uri:
                    quote = row.get("quote") or row.get("excerpt") or row.get("text")
                    citations.append(
                        ClaimCitation(
                            claim=question,
                            source_id=str(source_id),
                            source_location=str(source_uri),
                            evidence_edge_index=edge_index,
                            quote=str(quote)[:320] if quote else None,
                            snippet=str(answer[:180]),
                        )
                    )
                edge_index += 1
        return citations[:10]

    @staticmethod
    def _normalize_relationship(raw: Any) -> str:
        allowed = {"MITIGATES", "AFFECTS", "DEPENDS_ON", "INTEGRATES_WITH"}
        if not raw:
            return "AFFECTS"
        candidate = str(raw).upper()
        return candidate if candidate in allowed else "AFFECTS"

