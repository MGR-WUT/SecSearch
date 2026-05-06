from __future__ import annotations

import argparse
from pathlib import Path

from app.core.config import get_settings
from app.graph.neo4j_store import Neo4jStore
from app.pipeline.query_agent_v2 import GraphRAGV2Service
from eval.run_eval import run


def main() -> None:
    parser = argparse.ArgumentParser(description="Run evaluation on a real benchmark dataset.")
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to a benchmark JSON dataset used for evaluation.",
    )
    parser.add_argument(
        "--output",
        default="eval/benchmarkName/report.json",
        help="Path where the evaluation report JSON will be written.",
    )
    args = parser.parse_args()

    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    agent = GraphRAGV2Service(
        graph_store=store,
        llm_provider=settings.llm_provider,
        llm_base_url=settings.llm_base_url,
        llm_api_key=settings.llm_api_key,
        embed_model=settings.llm_embed_model,
        chat_model=settings.llm_chat_model,
        index_name=settings.graphrag_v2_index_name,
        embedding_dims=settings.graphrag_v2_embedding_dims,
        top_k=settings.graphrag_v2_top_k,
    )
    dataset_path = Path(args.dataset)
    report_path = Path(args.output)
    report = run(agent, dataset_path, report_path)
    print(f"Evaluation complete: {report['multi_hop_accuracy']:.2%} multi-hop accuracy")
    print(f"Report written to: {report_path}")
    store.close()


if __name__ == "__main__":
    main()

