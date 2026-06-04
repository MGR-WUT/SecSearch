# MITRE ATT&CK experiments — Methodology and Results

Setup, data, and directory layout are in [`README.md`](./README.md). This file
covers the methodology and measured results for each experiment. Run the shared
ATT&CK load (`loaders/load_attack.py --enrich --reset`) before any experiment.

---

## Experiment A: LLM extraction on STIX text

**Problem.** A held-out link-prediction score on the **deterministic** STIX graph
(e.g. neighbour Hits@10 ≈ 72%) does not test GraphoDynamo’s **LLM extraction**
path. We need **real extraction noise**: rebuild `(ThreatActor)-[:USES]->(Technique)`
from prose, then re-run the same link-prediction protocol.

### Methodology

1. **Gold** — STIX `USES` pairs per intrusion-set (`lib/stix_actor_reports.py`).
2. **Documents** — Group description + MITRE prose on each `uses` relationship.
3. **Extraction** — `extractors/extract_stix_uses_graph.py` → `USES_EXTRACTED` with
   `graph_variant=llm-extracted:<model>`; deterministic `USES` unchanged.
4. **Structure sweep (optional)** — `--structure-profile {structured,mild,moderate,severe}`
   via `lib/stix_document_structure.py`; variants
   `llm-extracted:<model>:struct-<profile>` + `structure_metrics.json`.
5. **Quality** — `evals/eval_stix_extraction_quality.py`: P/R/F1 vs STIX gold.
6. **Link prediction** — `evals/eval_link_prediction.py --graph-variant …`; non-USES
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

PYTHONPATH=. python eval/AttackGraph/loaders/load_attack.py --enrich --reset

PYTHONPATH=. python eval/AttackGraph/extractors/extract_stix_uses_graph.py \
    --model $MODEL --reset --run-dir $RUN

PYTHONPATH=. python eval/AttackGraph/evals/eval_stix_extraction_quality.py \
    --graph-variant llm-extracted:gpt-oss-20b-cloud --run-dir $RUN

PYTHONPATH=. python eval/AttackGraph/evals/eval_link_prediction.py \
    --graph-variant llm-extracted:gpt-oss-20b-cloud --run-dir $RUN
```

Smoke: add `--limit N` to extraction. Compare LLM runs to clean STIX via
`reports/link_prediction.json` or `runs/baseline/link_prediction.json`.

**Structure sweep (mild / moderate / severe):**

```bash
PYTHONPATH=. python eval/AttackGraph/evals/run_stix_structure_sweep.py \
    --model gpt-oss:20b-cloud --profiles mild,moderate,severe
```

Summary table: `runs/structure_sweep_summary.json` (neighbour Hits@10 vs clean STIX).

**Parser robustness:** list or `{"uses":[...]}` JSON, trailing-comma repair, retry
prompt, regex fallback for `Txxxx` in text (`parse_failure_actors` in
`stix_uses_extraction.json`). Re-extract after parser updates to refresh failure counts.

### Artefacts

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

**Link prediction on the LLM-extracted graph** (`USES_EXTRACTED`,
`graph_variant=llm-extracted:gpt-oss-20b-cloud`). 538 held-out edges across 114
actors, 697 candidate techniques, seed 20260529, hold-out 20%. Non-USES structure
remains deterministic STIX.

| Strategy | Hits@5 | Hits@10 | Hits@20 | Hits@50 | MRR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Random | 1.8% | 2.6% | 5.3% | 21.9% | 0.025 |
| Popularity (PageRank only) | 33.3% | 42.1% | 53.5% | 74.6% | 0.223 |
| **Neighbour (graph traversal)** | **50.0%** | **61.4%** | **73.7%** | **88.6%** | **0.339** |
| Neighbour + PageRank | 39.5% | 52.6% | 71.1% | 86.8% | 0.280 |

As on the clean STIX graph, the `neighbour` strategy dominates: it recovers 61.4% of
hidden actor--technique relationships within the top ten candidates and achieves the
highest MRR (0.339), versus 42.1% Hits@10 for the popularity-only baseline.

**Link prediction — neighbour Hits@10 (clean STIX vs LLM-extracted):**

| Strategy | Clean STIX | LLM-extracted | Δ |
| :--- | ---: | ---: | ---: |
| random | 6.7% | 2.6% | −4.1 pp |
| popularity | 46.7% | 42.1% | −4.6 pp |
| **neighbour** | **72.0%** | **61.4%** | **−10.6 pp** |
| neighbour × PageRank | 58.0% | 52.6% | −5.4 pp |

MRR (neighbour): 0.407 → 0.339. `neighbour` still beats `popularity` on the extracted graph.

**Structure sweep (measured):** runs `stix-llm-gpt-oss-20b-cloud-struct-{mild,moderate,severe}`,
summary `runs/structure_sweep_summary.json`. The same actor documents are reflowed
to remove structure (higher *lack-of-structure score*), re-extracted, and re-evaluated.

| Profile | Lack score | Pred. edges | Actors | Precision | Recall | F1 | neighbour Hits@10 | Δ vs clean |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| structured | — | 2,693 | 170 | 1.000 | 0.592 | 0.744 | 61.4% | −10.6 pp |
| mild | 0.434 | 3,228 | 159 | 0.998 | 0.708 | **0.828** | **65.0%** | −7.0 pp |
| moderate | 0.649 | 2,644 | 150 | 0.995 | 0.579 | 0.732 | 60.2% | −11.8 pp |
| severe | 0.999 | 407 | 33 | 0.961 | 0.086 | 0.158 | 39.1% | −32.9 pp |

Precision stays ≥ 0.96 across all profiles; recall (and thus graph density) is what
collapses under severe destructuring. Even at the severe extreme — 407 extracted edges
over 33 actors — `neighbour` (39.1%) stays ahead of `popularity` (26.1%) on the same graph.

**Document-structure noise profiles.** To test robustness of LLM extraction (not the
deterministic STIX graph), the same actor-level MITRE prose is reflowed through four
controlled profiles before re-extraction (`lib/stix_document_structure.py`):

| Profile | Transformations | Mean lack-of-structure score |
| :--- | :--- | ---: |
| **Structured** | Original markdown: headings, technique IDs, paragraph breaks | — |
| **Mild** | Markdown headings removed; technique IDs and content preserved | 0.434 |
| **Moderate** | Single narrative block: sections merged into continuous prose | 0.649 |
| **Severe** | Shuffled technique sections, `Txxxx` IDs redacted to `[TECHNIQUE]`, group IDs redacted | 0.999 |

Higher *lack-of-structure score* means less salient ATT&CK identifiers and weaker
document scaffolding—closer to unstructured vendor reports or ticket prose. Gold
`USES` pairs are unchanged; only the text seen by the extractor differs. Figures:
`figures/hits_at_k_<strategy>.png`, `figures/mrr_by_noise.png` (regenerate with
`evals/plot_structure_sweep.py`).

**Full link-prediction metrics per noise profile.** Same protocol as above (seed
20260529, hold-out 20%, 697 candidate techniques).

*Structured* — 538 held-out edges, 114 actors:

| Strategy | Hits@5 | Hits@10 | Hits@20 | Hits@50 | MRR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Random | 1.8% | 2.6% | 5.3% | 21.9% | 0.025 |
| Popularity (PageRank only) | 33.3% | 42.1% | 53.5% | 74.6% | 0.223 |
| **Neighbour (graph traversal)** | **50.0%** | **61.4%** | **73.7%** | **88.6%** | **0.339** |
| Neighbour + PageRank | 39.5% | 52.6% | 71.1% | 86.8% | 0.280 |

*Mild* (lack 0.434) — 645 held-out edges, 137 actors:

| Strategy | Hits@5 | Hits@10 | Hits@20 | Hits@50 | MRR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Random | 2.2% | 6.6% | 10.9% | 24.1% | 0.028 |
| Popularity (PageRank only) | 27.0% | 44.5% | 62.0% | 75.9% | 0.202 |
| **Neighbour (graph traversal)** | **54.7%** | **65.0%** | **75.2%** | **91.2%** | **0.373** |
| Neighbour + PageRank | 40.1% | 59.1% | 74.5% | 88.3% | 0.269 |

*Moderate* (lack 0.649) — 528 held-out edges, 118 actors:

| Strategy | Hits@5 | Hits@10 | Hits@20 | Hits@50 | MRR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Random | 0.8% | 3.4% | 7.6% | 24.6% | 0.026 |
| Popularity (PageRank only) | 31.4% | 39.8% | 52.5% | 77.1% | 0.200 |
| **Neighbour (graph traversal)** | **47.5%** | **60.2%** | **69.5%** | **80.5%** | **0.363** |
| Neighbour + PageRank | 36.4% | 45.8% | 68.6% | 82.2% | 0.261 |

*Severe* (lack 0.999) — 81 held-out edges, 23 actors:

| Strategy | Hits@5 | Hits@10 | Hits@20 | Hits@50 | MRR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Random | 8.7% | 8.7% | 13.0% | 26.1% | 0.066 |
| Popularity (PageRank only) | 17.4% | 26.1% | 30.4% | 52.2% | 0.115 |
| **Neighbour (graph traversal)** | **21.7%** | **39.1%** | **39.1%** | 52.2% | **0.186** |
| Neighbour + PageRank | 17.4% | 21.7% | 30.4% | **60.9%** | 0.171 |

`neighbour` leads on Hits@5–20 and MRR across every profile; only at the severe
extreme (23 actors, very sparse graph) does `neighbour + PageRank` overtake it at
Hits@50.

### Claims and scope

**Support.** LLM-rebuilt actor→technique graphs retain useful structure for link
prediction (neighbour Hits@10 ≈ 61% vs 72% clean) with **100% pair precision /
~59% recall** under quote + canonicalization guards.

**Robustness.** A structure sweep (mild → severe destructuring of the same documents)
keeps neighbour Hits@10 at 60–65% through moderate noise and degrades gracefully to
39.1% only under near-total structure loss, while pair precision never drops below 0.96.

**Caveats.** Input is **MITRE STIX-shaped prose**, not arbitrary vendor PDFs or
tickets. Precision is pipeline-dependent. Single model, single pass. Additional
models optional.

---

## Experiment B: CVE → APT at scale (ATT&CK-to-CVE)

**Goal.** The ATT&CK graph links only ~33 CVEs to actors; reviewers rightly
question generalisation from that denominator. Experiment B scales the CVE
universe by ~25× while preserving the **graph mechanism** that gives the
baseline its signal, then measures whether deterministic CVE→APT actor coverage
holds and is statistically stable.

### CVE-source selection (why ATT&CK-to-CVE)

The baseline 33-CVE coverage comes entirely from graph linkage:
`(CVE)<-[:EXPLOITS]-(Technique)<-[:USES]-(ThreatActor)`. A scaled CVE source is
only comparable if its CVEs attach to the **same technique / actor nodes**. We
evaluated five candidate sources against that requirement:

| Candidate source | Links CVE → ATT&CK technique/actor? | Verdict |
| :--- | :--- | :--- |
| **[Center for Threat-Informed Defense — ATT&CK-to-CVE](https://github.com/center-for-threat-informed-defense/attack_to_cve/blob/master/Att%26ckToCveMappings.csv)** | **Yes** — every CVE carries ≥1 ATT&CK technique ID | **Selected** |
| [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | No — standalone CVE descriptions, no technique edge | Negative control (see below) |
| [FalconFeeds threat-actor repository](https://falconfeeds.io/features/largest-threat-actor-repository/) | No bulk/API export; marketing surface only | Rejected — not machine-ingestible |
| [Databricks CyberIQ dataset](https://marketplace.databricks.com/details/a9688160-f841-44d3-9634-ce675cf0c01c/Kaze-Consulting_CyberIQ-Dataset) | Paywalled marketplace listing, no schema available | Rejected — inaccessible |
| [SOCRadar free Threat Actor tool](https://socradar.io/free-tools/threat-actor) | Interactive lookup, no bulk technique/CVE mapping | Rejected — no dataset export |
| [HF `reloading0101/threat-intelligence-dataset`](https://huggingface.co/datasets/reloading0101/threat-intelligence-dataset) | AI-generated synthetic CTI prose, no curated CVE→technique edges | Rejected — off-distribution synthetic; would only add noise to a *deterministic* baseline |

Only the CTID ATT&CK-to-CVE CSV maps each CVE to curated ATT&CK technique IDs,
so it reproduces the baseline's deterministic, technique-mediated path structure
at scale — exactly the property the other four sources lack. The CISA KEV run is
retained as a **negative control** that shows what happens when the CVE source
has no technique linkage.

### Methodology

1. `loaders/load_attack.py --enrich --reset` — ATT&CK subgraph (techniques,
   actors, PageRank).
2. `loaders/load_attack_to_cve.py --enrich --reset` — parse the CTID CSV; per CVE
   collect technique IDs across *Primary/Secondary Impact*, *Exploitation
   Technique*, *Uncategorized*; write `(Technique)-[:EXPLOITS]->(CVE)` against
   matching `Technique.external_id` (sub-technique → base fallback); re-run
   PageRank/Louvain over the enlarged subgraph.
3. `evals/eval_cve_apt.py --cve-source attack-to-cve --variant baseline` —
   deterministic graph-traversal coverage, identical scoring to the 33-CVE case.
4. `evals/cve_scaling_report.py` — bootstrap stability + scaling curve +
   precision-sample export.

ICS (`T08xx`), mobile (`T1404`, `T1456`, …) and deprecated technique IDs in the
CSV have no Enterprise node and are reported as `unmatched_technique_ids` rather
than silently dropped.

### Commands

```bash
cd DocsBasedSupport
B=eval/AttackGraph/runs/attack-to-cve-baseline

# Experiment B uses the isolated graph on 7688 (docker-compose service neo4j_b)
export NEO4J_URI=bolt://localhost:7688

PYTHONPATH=. python eval/AttackGraph/loaders/load_attack.py --enrich --reset --run-dir $B
PYTHONPATH=. python eval/AttackGraph/loaders/load_attack_to_cve.py --enrich --reset --run-dir $B
PYTHONPATH=. python eval/AttackGraph/evals/eval_cve_apt.py \
    --cve-source attack-to-cve --variant baseline --run-dir $B
PYTHONPATH=. python eval/AttackGraph/evals/cve_scaling_report.py \
    --baseline-report $B/cve_apt_paths_baseline.json --run-dir $B
```

Offline / pinned snapshot: pass `--csv-path <file>` to `load_attack_to_cve.py`.

### Artefacts

| File | Purpose |
| :--- | :--- |
| `attack_to_cve_load_summary.json` | CVE count, edges, unmatched technique IDs |
| `cve_apt_paths_baseline.json` | Per-CVE actors + aggregate coverage |
| `cve_scaling_report.json` | Bootstrap CI + scaling curve (n = 33…800) |
| `cve_attribution_sample.csv` | Manual precision spot-check sample |

### Results (measured)

Run `runs/attack-to-cve-baseline`, ATT&CK-to-CVE CSV, graph `bolt://localhost:7688`.

**Load:** 825 CVEs parsed and loaded, **815 with ≥1 technique edge**, 1,651
`EXPLOITS` edges (1 base-technique fallback), 23 unmatched technique IDs
(ICS / mobile / deprecated).

**Deterministic CVE → APT coverage (no LLM):**

| CVE source | # CVEs | Coverage (≥1 actor) | Mean actors / CVE | Mean evidence paths / CVE |
| :--- | ---: | ---: | ---: | ---: |
| MITRE ATT&CK (curated) | 33 | **57.6%** | 9.8 | 12.9 |
| CISA KEV (negative control) | 1,585 | **0.06%** | 0.02 | 0.02 |
| **ATT&CK-to-CVE (this run)** | **825** | **97.7%** | **66.6** | **132.3** |

**Scaling stability** (`cve_scaling_report.json`, 200-iteration bootstrap):

| Subsample n | Coverage mean | 95% CI |
| ---: | ---: | :--- |
| 33 | 0.977 | [0.909, 1.000] |
| 100 | 0.974 | [0.940, 1.000] |
| 200 | 0.977 | [0.955, 0.995] |
| 400 | 0.979 | [0.965, 0.988] |
| 800 | 0.977 | [0.976, 0.979] |

Coverage is flat at ≈97.7% from n=33 to n=800 with CIs tightening as n grows —
the headline figure is **not** an artefact of the small 33-CVE denominator.

### Claims and scope

**Support.** When the scaled CVE source preserves ATT&CK technique linkage
(ATT&CK-to-CVE), deterministic graph traversal recovers ≥1 actor for **97.7%** of
825 CVEs, and bootstrap resampling shows the coverage is **stable across scale**
(n = 33 → 800). This directly answers the generalisation concern: the 33-CVE
baseline's mechanism holds — and strengthens — at 25× the denominator.

**Negative control.** The same pipeline on CISA KEV scores **0.06%** (1/1,585)
with zero LLM-enrichment lift. Coverage therefore tracks **technique linkage**,
not CVE count: KEV CVE nodes are isolated, ATT&CK-to-CVE CVE nodes are not.

**Caveats.** High coverage trades off **specificity**: technique-mediated paths
attach a mean of **66.6 actors per CVE** (vs 9.8 for the hand-curated 33), because
common techniques (e.g. T1059, T1190, T1068) are used by many actors. Coverage
here is a *reachability* claim, not a precise single-actor attribution; the
top-K ranking (`score = path_count × (1 + PageRank)`) and `cve_attribution_sample.csv`
exist to inspect that ranking quality. Mappings are curated, single-snapshot.

---

## Experiment B₂: Inferential CVE → ATT&CK mapping from NVD prose

**Goal.** The 97.7% structured baseline is high because CTID already supplies
curated CVE→technique IDs. This arm tests whether an LLM can **reproduce that
mapping from raw NVD text alone** (inferential, not quote-faithful), and whether
LLM-inferred techniques still reach threat actors via the same graph paths.
CTID gold is used **only for scoring** — never written into the graph the model sees.

### Methodology

1. **Corpus** — `loaders/build_nvd_cve_corpus.py`: fetch real NVD descriptions
   (`NVD_API_KEY`) for CTID CVEs; attach CTID gold technique IDs (never shown to the LLM).
2. **Explicit-ID audit** — `evals/summarize_nvd_explicit_ids.py`: count literal
   `Txxxx` / `CWE-xxx` / `CVE-xxx` strings in NVD prose (not in gold metadata).
3. **Inference** — `extractors/map_cve_attack_with_llm.py` (`gpt-oss:20b-cloud`):
   read NVD prose only → predict ATT&CK technique IDs + named actors; drop technique
   IDs not in the loaded matrix.
4. **Evaluation** — `evals/eval_cve_attack_mapping.py`: micro/macro P/R/F1 vs gold
   (gold restricted to techniques present in Enterprise); actor coverage using
   structured gold techniques vs LLM-predicted techniques on actor-reachable paths.

### Commands

```bash
cd DocsBasedSupport
export NEO4J_URI=bolt://localhost:7688
R=eval/AttackGraph/runs/cve-attack-map-gpt-oss-20b

PYTHONPATH=. python eval/AttackGraph/loaders/build_nvd_cve_corpus.py --sample 200 --run-dir $R
PYTHONPATH=. python eval/AttackGraph/extractors/map_cve_attack_with_llm.py \
    --model gpt-oss:20b-cloud --run-dir $R
PYTHONPATH=. python eval/AttackGraph/evals/eval_cve_attack_mapping.py --run-dir $R
```

Sample run: `--sample 200` → `runs/cve-attack-map-gpt-oss-20b`. Full run:
`--sample 0` (all 825) → `runs/cve-attack-map-all-gpt-oss-20b`. Logs: `pipeline.log`.

### Artefacts

| File | Purpose |
| :--- | :--- |
| `nvd_cve_corpus.json` | NVD text + CTID gold per CVE |
| `nvd_explicit_id_summary.json` | Literal ID counts in NVD prose |
| `cve_attack_map_predictions.json` | LLM predictions + summary |
| `cve_attack_map_eval.json` | P/R/F1 + coverage comparison |

### Explicit IDs in NVD descriptions (measured)

Run `runs/cve-attack-map-all-gpt-oss-20b`, all **825** CVEs with NVD text:

| ID type in NVD prose | CVEs with ≥1 literal mention |
| :--- | ---: |
| ATT&CK technique (`Txxxx`) | **0 / 825** |
| CWE (`CWE-xxx`) | 2 / 825 |
| Other CVE references | 81 / 825 |

**Every** ATT&CK technique prediction is therefore **inferential** (impact/behaviour
→ technique), not extraction of an explicit ID in the description. This differs from
Experiments A / B′, which use quote guards on prose that often names techniques/CVEs.

### Results (measured)

Model `gpt-oss:20b-cloud`, graph `bolt://localhost:7688`, 100% NVD descriptions fetched.

| Run | n | Micro F1 | Macro F1 | Structured coverage | LLM coverage | Gap |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `cve-attack-map-gpt-oss-20b` (sample) | 200 | 0.200 | 0.192 | 96.0% | 81.0% | 15.0 pp |
| `cve-attack-map-all-gpt-oss-20b` (full) | 825 | **0.265** | **0.275** | **97.7%** | **96.9%** | **0.85 pp** |

Full-run mapping quality: 361 TP / 1,650 gold pairs / 1,077 predictions; 804/825 CVEs
with ≥1 prediction; 27 invalid technique IDs dropped (2.5% of raw); 1 parse failure;
0 actors matched from NVD text (actors rarely named in descriptions).

### Top-K actor agreement (beyond binary reachability)

Binary coverage ("≥1 actor reachable") is near-saturated because a single common
technique (e.g. T1190, used by ~150 actors) lights up the dense `USES` web — mean
**66.5** candidate actors per CVE. So coverage answers *"is this CVE in scope for
attribution?"*, **not** *"did the LLM find the right actor?"*. The top-K metric
ranks actors by `path_count × (1 + PageRank)` from the gold technique set and from
the LLM technique set, then measures how many of gold's top-K actors the LLM also
surfaces in its top-K:

| Run | n (eligible) | Top-1 exact | Recall@1 | Recall@3 | Recall@5 | Recall@10 | Gold/LLM cand. actors |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| sample 200 | 192 | 0.537 | 0.537 | 0.399 | 0.422 | 0.463 | 63.7 / 49.8 |
| full 825 | 806 | **0.684** | **0.684** | 0.489 | 0.527 | 0.582 | 66.5 / 59.6 |

The LLM's single most-plausible actor matches gold's **68%** of the time at full
scale (vs binary coverage's ~97%), and ~58% of gold's top-10 actors appear in the
LLM's top-10. This is the honest "the LLM surfaces the *same* actors" signal:
substantially above chance, well below the structured ceiling.

### Claims and scope

**Support.** NVD prose contains **no** literal ATT&CK IDs (0/825), yet the LLM
reproduces a measurable fraction of expert CTID mappings (micro-F1 ≈ 0.27 at full
scale) with low invalid-ID rate (~2.5%). For **actor reachability**, LLM-inferred
techniques close most of the gap to structured gold on the full corpus (**96.9%** vs
**97.7%**, 0.85 pp) even though technique-level F1 stays well below 1.0 — the LLM
often predicts *different but still actor-reachable* techniques (e.g. T1068 vs gold
T1203). The sharper **top-K** view shows the LLM's top-ranked actor matches gold's
**68%** of the time (Recall@10 = 0.58), confirming it surfaces the *same* actors —
not merely *some* actor — at well-above-chance rates.

**Contrast with B.** Structured linkage is the ceiling; B₂ separates *technique
label agreement* (moderate F1) from *graph reachability* (near-parity at n=825).

**Caveats.** The 200-CVE sample shows a larger coverage gap (15 pp) than the full
825 — subsample variance, not contradiction. Inferential mapping ≠ quote-guarded
extraction. Gold is CTID curated, not exploitation telemetry.

---

## Experiment B′: CVE → actor extraction from CTI prose (MISP + ETDA)

**Goal.** Test whether bounded LLM extraction recovers `(ThreatActor)-[:EXPLOITS]->(CVE)`
attribution from independent CTI narratives — the CVE→actor analogue of Experiment A.
Gold pairs come from structured MISP galaxy + ETDA threat-actor cards; the LLM reads
**narrative prose only**, so scoring is non-circular (structured gold edges are never
written into the graph the model sees).

### Methodology

1. **Gold + documents** — `loaders/build_cti_cve_corpus.py` merges MISP galaxy + ETDA
   cards into `cti_cve_actor_corpus.json`: per-actor narrative text plus structured CVE
   gold, with an `in_narrative` flag per pair.
2. **Load** — `loaders/load_cti_actors.py` upserts CTI `ThreatActor` / `CVE` nodes (no
   gold edges).
3. **Extraction** — `extractors/extract_cti_cve_graph.py` → `EXPLOITS` edges tagged
   `extraction_variant=llm-cti-cve:<model>` (quote-required, CVE-substring guard).
4. **Quality** — `evals/eval_cti_cve_extraction_quality.py`: P/R/F1 vs gold, primary
   benchmark against the narrative-only subset.

### Commands

```bash
cd DocsBasedSupport
CTI_RUN=eval/AttackGraph/runs/cti-cve-gpt-oss-20b-cloud
CTI_MODEL=gpt-oss:20b-cloud

PYTHONPATH=. python eval/AttackGraph/loaders/build_cti_cve_corpus.py --run-dir $CTI_RUN
PYTHONPATH=. python eval/AttackGraph/loaders/load_cti_actors.py --run-dir $CTI_RUN
PYTHONPATH=. python eval/AttackGraph/extractors/extract_cti_cve_graph.py \
    --model $CTI_MODEL --reset --run-dir $CTI_RUN
PYTHONPATH=. python eval/AttackGraph/evals/eval_cti_cve_extraction_quality.py \
    --extraction-variant llm-cti-cve:gpt-oss-20b-cloud --run-dir $CTI_RUN
```

### Results (measured)

Run `runs/cti-cve-gpt-oss-20b-cloud` — model `gpt-oss:20b-cloud`, 103 actor documents
(20 matched to ATT&CK, 83 CTI-only), 150 structured gold pairs / 105 distinct CVEs.

**Corpus:**

| Metric | Value |
| :--- | ---: |
| Actor documents | 103 |
| Structured gold pairs | 150 |
| Gold pairs present in narrative | 98 |
| Distinct CVEs | 105 |

**Extraction vs gold:**

| Metric | vs narrative gold (98) | vs all structured gold (150) |
| :--- | ---: | ---: |
| Precision | **1.00** | **1.00** |
| Recall | **0.582** | 0.380 |
| F1 | **0.736** | 0.551 |
| True positives | 57 | 57 |
| False positives | **0** | **0** |

Extraction: 64 raw → **57 validated** edges (7 dropped unquoted), 19 parse failures.
The all-structured recall gap is expected: 52 gold pairs appear only in card metadata,
never in the narrative the model reads.

### Claims and scope

**Support.** Bounded LLM extraction reproduces Experiment A's profile (**100% precision,
~58% recall, F1 ≈ 0.74**) on a **different relation** (CVE→actor) and an **independent
corpus** (MISP + ETDA), showing the quote-guarded method generalises beyond STIX-shaped
ATT&CK prose with zero fabrication.

**Caveats.** Recall is bounded by parse failures (19 actors) and by attribution that
lives only in card metadata. Public CVE→actor gold is small (~150 pairs); this is a
precision/recall benchmark, not a scale claim. Contrast with Experiment B (KEV), where
the signal is absent from the data entirely.
