# SecSearch

Research codebase for **security-oriented LLM workflows**: (1) safer **code generation** with static analysis and iterative refinement, and (2) **document-grounded GraphRAG** over cybersecurity knowledge with benchmarked QA.

The repository is organized as two mostly independent projects. Each has its own dependencies, configuration, and documentation.

---

## What this repository contains

| Directory | Project | Role |
| :--- | :--- | :--- |
| [`CodeGeneration/`](./CodeGeneration/) | **CodeGuard** + **PurpleLlama** | Secure code generation pipeline (FastAPI service), CyberSecEval4-style evaluation, and extensions to Meta’s PurpleLlama benchmark harness (Ollama + CodeGuard as “LLMs under test”). |
| [`DocsBasedSupport/`](./DocsBasedSupport/) | **GraphoDynamo** | Neo4j-backed ingestion and **GraphRAG v2** QA over cybersecurity PDFs and URLs; WildGraphBench end-to-end runs and official scores. |

---

## Where to find results

### Code generation (CyberSecEval4, Python subset)

- **Aggregated metrics (BLEU, vulnerable %, pass rate):**
  - [`CodeGeneration/CodeGuard/Eval/CyberSecEval4/`](./CodeGeneration/CodeGuard/Eval/CyberSecEval4/) — primary location referenced in the CodeGeneration docs (`*_stat.json`, model response JSON).
  - [`CodeGeneration/CodeGuard/eval/CyberSecEval4/`](./CodeGeneration/CodeGuard/eval/CyberSecEval4/) — additional or newer run artifacts (same benchmark; lowercase `eval` may appear alongside `Eval` depending on export path).
- **PurpleLlama dataset copies / stats used by the benchmark runner:**
  - [`CodeGeneration/PurpleLlama/CybersecurityBenchmarks/datasets/`](./CodeGeneration/PurpleLlama/CybersecurityBenchmarks/datasets/) — e.g. `*_stat*.json`, filtered Python instruct/autocomplete data per the CodeGeneration README.

Tables and interpretation of instruct vs autocomplete runs are in [`CodeGeneration/README.md`](./CodeGeneration/README.md).

### Documentation GraphRAG (WildGraphBench — technology domain)

- **Run folders (predictions, runtime reports, official scorer output):**
  - [`DocsBasedSupport/eval/WildGraphBench/runs_technology/`](./DocsBasedSupport/eval/WildGraphBench/runs_technology/) — e.g. `gpt-oss:120b_e2e_grag_enrichment/official_scores/report2.json`, `predictions_technology.jsonl`, `report_technology.json`.
- **How runs are structured and scored:** [`DocsBasedSupport/eval/README.md`](./DocsBasedSupport/eval/README.md).

Leaderboard-style numbers and caveats (QA vs summary metrics) are documented in [`DocsBasedSupport/README.md`](./DocsBasedSupport/README.md).

---

## Implementation (short)

**CodeGuard** ([`CodeGeneration/CodeGuard/`](./CodeGeneration/CodeGuard/)): A `CodeGuard` class orchestrates **generate → Bandit (SAST) → optional LLM audit → refine** in a bounded loop (`source.py`, `agents.py`, `static_analysis.py`). A **FastAPI** app exposes `POST /run` for tasks and optional config overrides (`api/main.py`). Models are pluggable (e.g. Ollama, cloud endpoints) via `config.yml`.

**GraphoDynamo** ([`DocsBasedSupport/app/`](./DocsBasedSupport/app/)): **FastAPI** + **Neo4j** — hybrid **LLM graph extraction** and **chunk vector indexing** on ingest; **`/query_v2`** performs GraphRAG-style retrieval and answer synthesis. Optional **GDS** enrichment (PageRank, Louvain) and temporal refresh are described in the DocsBasedSupport README.

**PurpleLlama fork** ([`CodeGeneration/PurpleLlama/`](./CodeGeneration/PurpleLlama/)): Benchmark code extended with **Ollama** and **CodeGuard** backends so the same CyberSecEval4 flows can score baselines vs the secured pipeline.

---

## What has been achieved so far

- **Secure code generation:** On the **Python** CyberSecEval4 **instruct** and **autocomplete** tasks, **CodeGuard + gemma3:4b** substantially **reduces vulnerable suggestions** and **raises pass rate** versus strong baselines, at the cost of lower BLEU (security-oriented rewrites). Additional baselines and **CodeGuard-wrapped larger models** appear in the rolling `*_stat.json` files under `CodeGuard/Eval` and `CodeGuard/eval`. See [`CodeGeneration/README.md`](./CodeGeneration/README.md) for the full comparison tables and methodology.
- **Cybersecurity GraphRAG:** On **WildGraphBench (technology)**, the documented **GraphoDynamo** configuration with **`gpt-oss:120b`** extraction, end-to-end answering, and **graph enrichment** reaches the **best reported Ave. Acc.** in the project’s comparison table (**~62.9%** weighted mean of single- and multi-fact QA), with strong **multi-fact** accuracy; summary-style items remain a known limitation under strict scoring. Details and paths to `report2.json` are in [`DocsBasedSupport/README.md`](./DocsBasedSupport/README.md).

---

## Quick links

| Topic | Document |
| :--- | :--- |
| CodeGuard API, architecture, benchmarks, PurpleLlama changes | [`CodeGeneration/README.md`](./CodeGeneration/README.md) |
| GraphoDynamo setup, API, pipeline, WildGraphBench results | [`DocsBasedSupport/README.md`](./DocsBasedSupport/README.md) |
| Evaluation artifact layout and reproducible run logging | [`DocsBasedSupport/eval/README.md`](./DocsBasedSupport/eval/README.md) |
