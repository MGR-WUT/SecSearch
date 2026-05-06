from __future__ import annotations

from pathlib import Path

from app.core.config import get_settings
from app.eval.run_eval import run
from app.eval.wildgraphbench import compare_with_sota
from app.graph.neo4j_store import Neo4jStore
from app.pipeline.query_agent import QueryAgent


def main() -> None:
    settings = get_settings()
    store = Neo4jStore(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )
    agent = QueryAgent(
        graph_store=store,
        neo4j_uri=settings.neo4j_uri,
        neo4j_username=settings.neo4j_username,
        neo4j_password=settings.neo4j_password,
        neo4j_database=settings.neo4j_database,
        ollama_base_url=settings.ollama_base_url,
        model=settings.ollama_chat_model,
    )
    report_path = Path("data/eval/report.json")
    report = run(agent, Path("data/eval/sample_multihop_dataset.json"), report_path)
    comparison = compare_with_sota(report_path, Path("data/eval/sota_reference.json"))
    Path("data/eval/sota_comparison.json").write_text(__import__("json").dumps(comparison, indent=2), encoding="utf-8")
    print(f"Evaluation complete: {report['multi_hop_accuracy']:.2%} multi-hop accuracy")
    store.close()


if __name__ == "__main__":
    main()

