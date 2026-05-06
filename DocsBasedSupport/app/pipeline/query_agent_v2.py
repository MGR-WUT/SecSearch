from __future__ import annotations

import hashlib
import re
from typing import Any

from langchain_ollama import ChatOllama, OllamaEmbeddings
from neo4j_graphrag.generation import GraphRAG
from neo4j_graphrag.indexes import create_vector_index
from neo4j_graphrag.llm import OllamaLLM
from neo4j_graphrag.retrievers import VectorRetriever

from app.core.models import ClaimCitation, EvidenceEdge, QueryResponse
from app.graph.neo4j_store import Neo4jStore
from app.pipeline.ingestion import IngestedDocument


class GraphRAGV2Service:
    def __init__(
        self,
        graph_store: Neo4jStore,
        index_name: str,
        embedding_dims: int,
        top_k: int,
        ollama_base_url: str,
        embed_model: str,
        chat_model: str,
    ) -> None:
        self.graph_store = graph_store
        self.index_name = index_name
        self.embedding_dims = embedding_dims
        self.top_k = top_k
        self.embedder = OllamaEmbeddings(model=embed_model, base_url=ollama_base_url)
        self.fallback_chat = ChatOllama(model=chat_model, base_url=ollama_base_url, temperature=0)
        self._ensure_vector_index()
        self.retriever = VectorRetriever(self.graph_store.driver, self.index_name, self.embedder)
        self.rag = GraphRAG(
            retriever=self.retriever,
            llm=OllamaLLM(model_name=chat_model, model_params={"temperature": 0}),
        )

    def _ensure_vector_index(self) -> None:
        create_vector_index(
            self.graph_store.driver,
            self.index_name,
            label="Chunk",
            embedding_property="embedding",
            dimensions=self.embedding_dims,
            similarity_fn="cosine",
        )

    def index_document_chunks(self, document: IngestedDocument, chunk_size: int = 1200, overlap: int = 150) -> int:
        chunks = self._split_text(document.content, chunk_size=chunk_size, overlap=overlap)
        rows = []
        for idx, chunk_text in enumerate(chunks):
            chunk_id = self._chunk_id(document.source_id, idx, chunk_text)
            rows.append({"chunk_id": chunk_id, "text": chunk_text})
        self.graph_store.upsert_chunks(document.source_id, rows)

        embeddings = self.embedder.embed_documents([row["text"] for row in rows]) if rows else []
        embedding_rows = [
            {"chunk_id": row["chunk_id"], "embedding": embedding}
            for row, embedding in zip(rows, embeddings)
        ]
        if embedding_rows:
            self.graph_store.set_chunk_embeddings(embedding_rows)
        return len(rows)

    def answer(self, question: str) -> QueryResponse:
        search_result = self.rag.search(query_text=question, retriever_config={"top_k": self.top_k})
        raw_answer = getattr(search_result, "answer", "").strip()
        retrieval_items = self._retrieve_context(question, search_result, raw_answer)

        if not raw_answer:
            raw_answer = self._fallback_answer(question, retrieval_items)

        evidence_path = [
            EvidenceEdge(
                source=f"Chunk:{item.get('chunk_id', 'unknown')}",
                relationship="DEPENDS_ON",
                target=f"Source:{item.get('source_id', 'unknown')}",
            )
            for item in retrieval_items
        ]
        citations = [
            ClaimCitation(
                claim=question,
                source_id=item.get("source_id", "unknown"),
                source_location=item.get("source_uri", ""),
                evidence_edge_index=idx,
                quote=item.get("text", "")[:320],
                snippet=item.get("text", "")[:180],
            )
            for idx, item in enumerate(retrieval_items)
        ]
        if not evidence_path:
            raw_answer = (
                "GraphRAG v2 did not return grounded retrieval context. "
                "Ingest additional data and verify vector indexing."
            )
        else:
            raw_answer = f"{raw_answer}\n\nRecommendation: Validate this hypothesis with a human analyst before remediation."
        return QueryResponse(answer=raw_answer, evidence_path=evidence_path, citations=citations)

    def _retrieve_context(
        self, question: str, search_result: Any, answer_text: str
    ) -> list[dict[str, str]]:
        retrieval_items = self._extract_retrieval_items(search_result)
        if retrieval_items:
            return retrieval_items

        query_embedding = self.embedder.embed_query(question)
        vector_hits = self.graph_store.query_chunk_vector_index(
            index_name=self.index_name,
            query_embedding=query_embedding,
            top_k=self.top_k,
        )
        if vector_hits:
            return [
                {
                    "chunk_id": str(hit.get("chunk_id", "")),
                    "source_id": str(hit.get("source_id", "")),
                    "source_uri": str(hit.get("source_uri", "")),
                    "text": str(hit.get("text", "")),
                }
                for hit in vector_hits
            ]

        return self._extract_cited_chunks_from_answer(answer_text)

    def _extract_retrieval_items(self, search_result: Any) -> list[dict[str, str]]:
        contexts: list[dict[str, str]] = []
        records = getattr(search_result, "retriever_result", None)
        items = getattr(records, "items", []) if records is not None else []
        for item in items:
            content = getattr(item, "content", None)
            metadata = getattr(item, "metadata", {}) or {}
            text = ""
            if isinstance(content, str):
                text = content
            elif isinstance(content, dict):
                text = str(content.get("text", ""))
            contexts.append(
                {
                    "chunk_id": str(metadata.get("chunk_id", "")),
                    "source_id": str(metadata.get("source_id", "")),
                    "source_uri": str(metadata.get("source_uri", "")),
                    "text": text,
                }
            )
        return contexts

    def _fallback_answer(self, question: str, retrieval_items: list[dict[str, str]]) -> str:
        context = "\n\n".join(item.get("text", "") for item in retrieval_items[: self.top_k])
        prompt = (
            "Answer based only on the retrieved context.\n"
            "If context is insufficient, say so.\n\n"
            f"Question: {question}\n\nContext:\n{context}"
        )
        return self.fallback_chat.invoke(prompt).content.strip()

    def _extract_cited_chunks_from_answer(self, answer: str) -> list[dict[str, str]]:
        chunk_ids = list(dict.fromkeys(re.findall(r"\[([^\[\]]+:chunk:\d+:[a-f0-9]+)\]", answer)))
        contexts = self.graph_store.get_chunk_contexts(chunk_ids)
        return [
            {
                "chunk_id": str(ctx.get("chunk_id", "")),
                "source_id": str(ctx.get("source_id", "")),
                "source_uri": str(ctx.get("source_uri", "")),
                "text": str(ctx.get("text", "")),
            }
            for ctx in contexts
        ]

    @staticmethod
    def _split_text(text: str, chunk_size: int, overlap: int) -> list[str]:
        text = text.strip()
        if not text:
            return []
        chunks: list[str] = []
        start = 0
        while start < len(text):
            end = min(start + chunk_size, len(text))
            chunks.append(text[start:end])
            if end == len(text):
                break
            start = max(0, end - overlap)
        return chunks

    @staticmethod
    def _chunk_id(source_id: str, idx: int, text: str) -> str:
        digest = hashlib.sha256(f"{source_id}:{idx}:{text[:80]}".encode("utf-8")).hexdigest()[:12]
        return f"{source_id}:chunk:{idx}:{digest}"

