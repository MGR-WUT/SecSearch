# MITRE ATT&CK experiments for GraphoDynamo — Setup

WildGraphBench evaluates GraphoDynamo on general IT reference text. It does not
exercise **security-specific** relationships (CVEs, techniques, malware, campaigns,
threat actors) or whether **PageRank** and **Louvain** help analysts navigate a
security knowledge graph. This folder holds complementary evaluations on the MITRE
ATT&CK Enterprise STIX 2.1 bundle and independent CTI sources.

This file covers **setup, data, and layout only**. Experiment methodology and
measured results live in [`EXPERIMENTS.md`](./EXPERIMENTS.md).

| Experiment | Question |
| :--- | :--- |
| **A** — LLM extraction + link prediction | When actor→technique edges come from **LLM extraction** on CTI-style text (not deterministic STIX), does graph-based link prediction still beat trivial baselines? |
| **B₂** — NVD → ATT&CK mapping (inferential) | Can the LLM reproduce CTID expert CVE→technique mappings from **NVD prose only**, and how far does that support CVE→actor reachability vs structured gold? |

Both experiments share the same Neo4j ATT&CK subgraph loaded by
`loaders/load_attack.py`. Experiment A never overwrites deterministic `USES` edges;
it writes parallel `USES_EXTRACTED` relationships tagged by `graph_variant`. B₂ adds
the CTID ATT&CK-to-CVE mappings (`loaders/load_attack_to_cve.py`) as gold for scoring.

---

## Prerequisites

Neo4j 5 with APOC + GDS (project `docker-compose.yml`).

```bash
cd DocsBasedSupport
docker compose up -d
pip install -r requirements.txt
```

## Data and schema

| Source | Path / note |
| :--- | :--- |
| [MITRE ATT&CK Enterprise STIX 2.1](https://github.com/mitre/cti) | `data/ontologies/mitre_attack/enterprise-attack.json` (downloaded on first run, git-ignored) |
| [CTID ATT&CK-to-CVE mappings](https://github.com/center-for-threat-informed-defense/attack_to_cve) | fetched at run time by `loaders/load_attack_to_cve.py` (Experiment B₂ gold source) |
| [NVD CVE descriptions](https://nvd.nist.gov/) | fetched at run time by `loaders/build_nvd_cve_corpus.py` (`NVD_API_KEY`) |

Nodes: `:Entity` + ATT&CK labels (`ThreatActor`, `Technique`, `Malware`, `Tool`,
`Campaign`, `Mitigation`, `Tactic`, `CVE`). Core edges: `USES`, `MITIGATES`,
`SUBTECHNIQUE_OF`, `ATTRIBUTED_TO`, `TARGETS`, `EXPLOITS`, `IN_TACTIC`.

## Run folders

Scripts accept `--run-dir eval/AttackGraph/runs/<name>/`. Each run appends a
timestamped section to `RUN.md` with parameters and outputs.

**Load ATT&CK (required before any experiment):**

```bash
PYTHONPATH=. python eval/AttackGraph/loaders/load_attack.py --enrich --reset \
    --run-dir eval/AttackGraph/runs/baseline
```

**Clean STIX link-prediction baseline** (deterministic `USES`, no LLM — reference
for Experiment A):

```bash
PYTHONPATH=. python eval/AttackGraph/evals/eval_link_prediction.py \
    --run-dir eval/AttackGraph/runs/baseline
# Canonical copy: eval/AttackGraph/reports/link_prediction.json
```

## CLI knobs (shared)

* `evals/eval_link_prediction.py`: `--seed`, `--hold-out-fraction`, `--top-ks`,
  `--max-actors`, `--graph-variant` (LLM arms only).
* `extractors/extract_stix_uses_graph.py`: `--model`, `--structure-profile`,
  `--limit`, `--reset`.

---

## Directory layout

Python files are grouped by function:

| Folder | Purpose | Files |
| :--- | :--- | :--- |
| `lib/` | Shared helpers + importable libraries (no standalone graph writes) | `_run_utils.py`, `graph_constants.py`, `stix_actor_reports.py`, `stix_document_structure.py` |
| `loaders/` | Ingest data / build corpora | `load_attack.py`, `load_attack_to_cve.py`, `build_nvd_cve_corpus.py` |
| `extractors/` | LLM extraction / enrichment → edges | `extract_stix_uses_graph.py`, `map_cve_attack_with_llm.py` |
| `evals/` | Scoring, reports, sweep drivers | `eval_link_prediction.py`, `eval_stix_extraction_quality.py`, `run_stix_structure_sweep.py`, `summarize_structure_sweep.py`, `plot_structure_sweep.py`, `eval_cve_attack_mapping.py`, `summarize_nvd_explicit_ids.py` |
| `runs/`, `reports/` | Per-run artefacts and canonical report copies | — |

Invoke scripts from the `DocsBasedSupport` root with `PYTHONPATH=.`, e.g.
`PYTHONPATH=. python eval/AttackGraph/<folder>/<script>.py …`.

### Script index by experiment

| Script | Experiment |
| :--- | :--- |
| `loaders/load_attack.py` | A, B₂ (shared ATT&CK load) |
| `extractors/extract_stix_uses_graph.py` | A |
| `evals/eval_stix_extraction_quality.py` | A |
| `evals/eval_link_prediction.py` | A (baseline + LLM variants) |
| `lib/stix_actor_reports.py`, `lib/stix_document_structure.py` | A |
| `evals/run_stix_structure_sweep.py`, `evals/summarize_structure_sweep.py`, `evals/plot_structure_sweep.py` | A |
| `loaders/load_attack_to_cve.py` | B₂ (CTID gold source) |
| `loaders/build_nvd_cve_corpus.py`, `extractors/map_cve_attack_with_llm.py`, `evals/eval_cve_attack_mapping.py`, `evals/summarize_nvd_explicit_ids.py` | B₂ (NVD inferential mapping) |
