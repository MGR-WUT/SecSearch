# MITRE ATT&CK experiments for GraphoDynamo

## Motivation

WildGraphBench evaluates GraphoDynamo on general IT reference text. It does not
exercise **security-specific** relationships (CVEs, techniques, malware, campaigns,
threat actors) or whether **PageRank** and **Louvain** help analysts navigate a
security knowledge graph.

This folder holds two complementary evaluations on the MITRE ATT&CK Enterprise
STIX 2.1 bundle:

| Experiment | Question |
| :--- | :--- |
| **A** — LLM extraction + link prediction | When actor→technique edges come from **LLM extraction** on CTI-style text (not deterministic STIX), does graph-based link prediction still beat trivial baselines? |
| **B** — CVE → APT at scale *(pending)* | On a **much larger CVE universe** (CISA KEV), does bounded LLM enrichment improve attribution coverage and stay stable at scale? |

Both use the same Neo4j ATT&CK subgraph loaded by `load_attack.py`. Experiment A
never overwrites deterministic `USES` edges; it writes parallel `USES_EXTRACTED`
relationships tagged by `graph_variant`.

---

## Setup

### Prerequisites

Neo4j 5 with APOC + GDS (project `docker-compose.yml`).

```bash
cd DocsBasedSupport
docker compose up -d
pip install -r requirements.txt
```

### Data and schema

| Source | Path / note |
| :--- | :--- |
| [MITRE ATT&CK Enterprise STIX 2.1](https://github.com/mitre/cti) | `data/ontologies/mitre_attack/enterprise-attack.json` (downloaded on first run, git-ignored) |

Nodes: `:Entity` + ATT&CK labels (`ThreatActor`, `Technique`, `Malware`, `Tool`,
`Campaign`, `Mitigation`, `Tactic`, `CVE`). Core edges: `USES`, `MITIGATES`,
`SUBTECHNIQUE_OF`, `ATTRIBUTED_TO`, `TARGETS`, `EXPLOITS`, `IN_TACTIC`.

### Run folders

Scripts accept `--run-dir eval/AttackGraph/runs/<name>/`. Each run appends a
timestamped section to `RUN.md` with parameters and outputs.

**Load ATT&CK (required before A or B):**

```bash
PYTHONPATH=. python eval/AttackGraph/load_attack.py --enrich --reset \
    --run-dir eval/AttackGraph/runs/baseline
```

**Clean STIX link-prediction baseline** (deterministic `USES`, no LLM — reference
for Experiment A):

```bash
PYTHONPATH=. python eval/AttackGraph/eval_link_prediction.py \
    --run-dir eval/AttackGraph/runs/baseline
# Canonical copy: eval/AttackGraph/reports/link_prediction.json
```

Optional diagnostics on the same graph: `community_report.py`, `eval_cve_apt.py`
(`--cve-source mitre-attack`) — not part of the thesis claims for A/B.

### CLI knobs (shared)

* `eval_link_prediction.py`: `--seed`, `--hold-out-fraction`, `--top-ks`,
  `--max-actors`, `--graph-variant` (LLM arms only).
* `extract_stix_uses_graph.py`: `--model`, `--structure-profile`, `--limit`, `--reset`.

---

## Experiment A: LLM extraction on STIX text

**Problem.** A held-out link-prediction score on the **deterministic** STIX graph
(e.g. neighbour Hits@10 ≈ 72%) does not test GraphoDynamo’s **LLM extraction**
path. We need **real extraction noise**: rebuild `(ThreatActor)-[:USES]->(Technique)`
from prose, then re-run the same link-prediction protocol.

### Methodology

1. **Gold** — STIX `USES` pairs per intrusion-set (`stix_actor_reports.py`).
2. **Documents** — Group description + MITRE prose on each `uses` relationship.
3. **Extraction** — `extract_stix_uses_graph.py` → `USES_EXTRACTED` with
   `graph_variant=llm-extracted:<model>`; deterministic `USES` unchanged.
4. **Structure sweep (optional)** — `--structure-profile {structured,mild,moderate,severe}`
   via `stix_document_structure.py`; variants
   `llm-extracted:<model>:struct-<profile>` + `structure_metrics.json`.
5. **Quality** — `eval_stix_extraction_quality.py`: P/R/F1 vs STIX gold.
6. **Link prediction** — `eval_link_prediction.py --graph-variant …`; non-USES
   structure remains deterministic STIX.

| Arm | `--graph-variant` | USES layer |
| :--- | :--- | :--- |
| Clean baseline | *(omit)* | STIX `USES` |
| LLM-extracted | `llm-extracted:<model>` | `USES_EXTRACTED` for that model / profile |

### Commands

```bash
cd DocsBasedSupport
RUN=eval/AttackGraph/runs/stix-llm-gpt-oss-20b-cloud
MODEL=gpt-oss:20b-cloud

PYTHONPATH=. python eval/AttackGraph/load_attack.py --enrich --reset

PYTHONPATH=. python eval/AttackGraph/extract_stix_uses_graph.py \
    --model $MODEL --reset --run-dir $RUN

PYTHONPATH=. python eval/AttackGraph/eval_stix_extraction_quality.py \
    --graph-variant llm-extracted:gpt-oss-20b-cloud --run-dir $RUN

PYTHONPATH=. python eval/AttackGraph/eval_link_prediction.py \
    --graph-variant llm-extracted:gpt-oss-20b-cloud --run-dir $RUN
```

Smoke: add `--limit N` to extraction. Compare LLM runs to clean STIX via
`reports/link_prediction.json` or `runs/baseline/link_prediction.json`.

**Structure sweep (mild / moderate / severe):**

```bash
PYTHONPATH=. python eval/AttackGraph/run_stix_structure_sweep.py \
    --model gpt-oss:20b-cloud --profiles mild,moderate,severe
```

Summary table: `runs/structure_sweep_summary.json` (neighbour Hits@10 vs clean STIX).

**Parser robustness:** list or `{"uses":[...]}` JSON, trailing-comma repair, retry
prompt, regex fallback for `Txxxx` in text (`parse_failure_actors` in
`stix_uses_extraction.json`). Re-extract after parser updates to refresh failure counts.

### Artefacts (Experiment A)

| File | Purpose |
| :--- | :--- |
| `stix_actor_corpus.json` | Gold pairs + document stats |
| `structure_metrics.json` | Lack-of-structure heuristics per profile |
| `stix_uses_extraction.json` | Extraction summary + next steps |
| `extraction_quality.json` | P/R/F1 vs STIX gold |
| `link_prediction.json` | Hits@K / MRR |

### Results (measured)

Run `runs/stix-llm-gpt-oss-20b-cloud` — model `gpt-oss:20b-cloud`, 170 actor
documents, link-pred seed 20260529, hold-out 20%.

**Extraction vs STIX gold:**

| Metric | Value |
| :--- | ---: |
| Gold USES pairs | 4,546 |
| Extracted edges | 2,693 |
| Pair precision | **1.00** |
| Pair recall | **0.592** |
| Pair F1 | **0.744** |
| Parse failures (first run) | 12 / 170 |

Noise is **recall-dominated** (sparser graph, no contradicting pairs after validation).

**Link prediction — neighbour Hits@10:**

| Strategy | Clean STIX | LLM-extracted | Δ |
| :--- | ---: | ---: | ---: |
| random | 6.7% | 2.6% | −4.1 pp |
| popularity | 46.7% | 42.1% | −4.6 pp |
| **neighbour** | **72.0%** | **61.4%** | **−10.6 pp** |
| neighbour × PageRank | 58.0% | 52.6% | −5.4 pp |

MRR (neighbour): 0.407 → 0.339. `neighbour` still beats `popularity` on the extracted graph.

Structure-sweep rows (mild / moderate / severe) — *pending full run*.

### Claims and scope (Experiment A)

**Support.** LLM-rebuilt actor→technique graphs retain useful structure for link
prediction (neighbour Hits@10 ≈ 61% vs 72% clean) with **100% pair precision /
~59% recall** under quote + canonicalization guards.

**Caveats.** Input is **MITRE STIX-shaped prose**, not arbitrary vendor PDFs or
tickets. Precision is pipeline-dependent. Single model, single pass. Structure
sweep and additional models optional.

---

## Experiment B: CVE → APT at scale (CISA KEV)

*Status: **not yet run** — section reserved for results and commands.*

**Goal.** The ATT&CK graph contains only ~33 CVEs with actor linkage; reviewers
rightly question generalisation from that denominator. Experiment B evaluates
**coverage and enrichment lift** on the full
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(~1,600 CVEs), with the MITRE 33-CVE case as an optional
`--cve-source mitre-attack` baseline.

**Planned pipeline**

1. `load_attack.py` — ATT&CK subgraph (path traversal + actor catalogs).
2. `load_kev.py` — ingest KEV CVE nodes.
3. `eval_cve_apt.py --cve-source cisa-kev --variant baseline` — graph paths only.
4. `enrich_with_llm.py` on KEV descriptions — bounded reverse attribution.
5. `eval_cve_apt.py --variant enriched` — post-enrichment coverage.
6. `cve_scaling_report.py` — bootstrap stability + precision sample export.

**Planned LLM variants:** `gpt-oss:20b`, `gemma3:4b` (separate run dirs per model).

**Expected artefacts**

| File | Purpose |
| :--- | :--- |
| `kev_load_summary.json` | Feed version + CVE count |
| `cve_apt_paths_baseline.json` | Coverage without LLM |
| `cve_apt_paths_enriched.json` | Coverage after enrichment |
| `cve_scaling_report.json` | Bootstrap CI at subsample sizes |
| `cve_attribution_sample.csv` | Manual precision spot-check sample |

**Interpretation (when run).** KEV coverage will likely be **lower** than the
curated ATT&CK 33-CVE figure; the valid claim is **marginal lift** and **stability**
of enrichment at scale, not parity with small-corpus headline percentages.

Commands and measured results will be added here after the run completes.

---

## Script index

| Script | Experiment |
| :--- | :--- |
| `load_attack.py` | A, B |
| `extract_stix_uses_graph.py` | A |
| `eval_stix_extraction_quality.py` | A |
| `eval_link_prediction.py` | A (baseline + LLM variants) |
| `stix_actor_reports.py`, `stix_document_structure.py` | A |
| `run_stix_structure_sweep.py`, `summarize_structure_sweep.py` | A |
| `load_kev.py`, `enrich_with_llm.py`, `eval_cve_apt.py`, `cve_scaling_report.py` | B |
| `community_report.py` | Optional / legacy diagnostic |
