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

## Experiment B₂: Inferential CVE → ATT&CK mapping from NVD prose

**Goal.** The CTID ATT&CK-to-CVE source supplies curated CVE→technique IDs, and a
deterministic graph traversal over those edges reaches ≥1 actor for **97.7%** of the
825 CVEs (the *structured* reference computed by the eval). This arm tests whether an
LLM can **reproduce that CVE→technique mapping from raw NVD text alone** (inferential,
not quote-faithful), and whether LLM-inferred techniques still reach threat actors via
the same graph paths. CTID gold is used **only for scoring** — never written into the
graph the model sees.

### Methodology

1. **Graph + gold** — `loaders/load_attack.py --enrich --reset` then
   `loaders/load_attack_to_cve.py --enrich --reset`: load the ATT&CK subgraph
   (techniques, actors, PageRank) and the CTID ATT&CK-to-CVE mappings, which store
   each CVE's gold technique IDs on its node (`mapped_technique_ids`). The CTID
   technique→CVE edges supply the gold; they are not shown to the LLM.
2. **Corpus** — `loaders/build_nvd_cve_corpus.py --sample 0`: fetch real NVD
   descriptions (`NVD_API_KEY`) for all CTID CVEs; attach the gold technique IDs.
3. **Explicit-ID audit** — `evals/summarize_nvd_explicit_ids.py`: count literal
   `Txxxx` / `CWE-xxx` / `CVE-xxx` strings in NVD prose (not in gold metadata).
4. **Inference** — `extractors/map_cve_attack_with_llm.py` (`gpt-oss:20b-cloud`):
   read NVD prose only → predict ATT&CK technique IDs + named actors; drop technique
   IDs not in the loaded matrix. The prompt uses few-shot exploitation-chain examples
   and asks for up to 5 techniques ordered most-likely-first.
5. **Evaluation** — `evals/eval_cve_attack_mapping.py`: micro/macro P/R/F1 vs gold
   (gold restricted to techniques present in Enterprise); actor coverage using
   structured gold techniques vs LLM-predicted techniques on actor-reachable paths;
   top-K actor agreement.

### Commands

```bash
cd DocsBasedSupport
export NEO4J_URI=bolt://localhost:7688
R=eval/AttackGraph/runs/cve-attack-map-all-v2-gpt-oss-20b

PYTHONPATH=. python eval/AttackGraph/loaders/load_attack.py --enrich --reset
PYTHONPATH=. python eval/AttackGraph/loaders/load_attack_to_cve.py --enrich --reset
PYTHONPATH=. python eval/AttackGraph/loaders/build_nvd_cve_corpus.py --sample 0 --run-dir $R
PYTHONPATH=. python eval/AttackGraph/evals/summarize_nvd_explicit_ids.py --run-dir $R
PYTHONPATH=. python eval/AttackGraph/extractors/map_cve_attack_with_llm.py \
    --model gpt-oss:20b-cloud --run-dir $R
PYTHONPATH=. python eval/AttackGraph/evals/eval_cve_attack_mapping.py --run-dir $R
```

Full run only: `--sample 0` (all 825 CVEs) → `runs/cve-attack-map-all-v2-gpt-oss-20b`.

### Artefacts

| File | Purpose |
| :--- | :--- |
| `nvd_cve_corpus.json` | NVD text + CTID gold per CVE |
| `nvd_explicit_id_summary.json` | Literal ID counts in NVD prose |
| `cve_attack_map_predictions.json` | LLM predictions + summary |
| `cve_attack_map_eval.json` | P/R/F1 + coverage comparison |

### Explicit IDs in NVD descriptions (measured)

Run `runs/cve-attack-map-all-v2-gpt-oss-20b`, all **825** CVEs with NVD text:

| ID type in NVD prose | CVEs with ≥1 literal mention |
| :--- | ---: |
| ATT&CK technique (`Txxxx`) | **0 / 825** |
| CWE (`CWE-xxx`) | 2 / 825 |
| Other CVE references | 81 / 825 |

**Every** ATT&CK technique prediction is therefore **inferential** (impact/behaviour
→ technique), not extraction of an explicit ID in the description. This differs from
Experiment A, which uses quote guards on prose that often names techniques.

### Results (measured)

Model `gpt-oss:20b-cloud`, graph `bolt://localhost:7688`, all **825** CVEs, 100% NVD
descriptions fetched. Run `runs/cve-attack-map-all-v2-gpt-oss-20b`.

| n | Micro F1 | Macro F1 | Structured coverage | LLM coverage | Gap |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 825 | **0.277** | **0.290** | **97.7%** | **99.5%** | **−1.8 pp** |

**Parent-level scoring (granularity-fair).** CTID gold carries 334 sub-technique IDs
(`T1059.001`); exact match penalises the LLM for naming the right *family* but the
wrong granularity. Rolling both sides to the parent technique (`T1059.001` → `T1059`)
before scoring:

| Scoring (full 825) | Micro-P | Micro-R | Micro-F1 | Macro-F1 |
| :--- | ---: | ---: | ---: | ---: |
| Exact | 0.254 | 0.306 | 0.277 | 0.290 |
| **Parent-level** | 0.309 | **0.371** | **0.337** | **0.348** |

Mapping quality: 504 TP / 1,650 gold pairs / 1,987 predictions (~2.4 techniques/CVE);
821/825 CVEs with ≥1 prediction; 21 invalid technique IDs dropped (~1.1% of raw); 1
parse failure; 0 actors matched from NVD text (actors rarely named in descriptions).

### Primary-actor recovery (Hits@K + MRR)

Binary coverage ("≥1 actor reachable") is near-saturated because a single common
technique (e.g. T1190, used by ~150 actors) lights up the dense `USES` web — mean
**66.5** candidate actors per CVE. So coverage answers *"is this CVE in scope for
attribution?"*, **not** *"did the LLM find the right actor?"*. To answer the second
question with the same vocabulary and baselines as Experiment A, the curated
mapping's top-ranked actor is the **primary** actor (the target). The full actor
universe (174 ATT&CK ThreatActors) is then ordered by each ranking strategy, and we
measure how often the primary actor lands within the model's top-K (Hits@K) plus the
mean reciprocal rank (MRR). Strategies match Experiment A: *random*, *popularity*
(PageRank only), *neighbour* (evidence-path count from the LLM-predicted techniques),
and *neighbour × PageRank*:

Run `cve-attack-map-all-v2-gpt-oss-20b`, 806 attributable CVEs, 174-actor universe, seed 20260604:

| Strategy | Hits@1 | Hits@5 | Hits@10 | Hits@20 | Hits@50 | MRR |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Random | 0.6% | 3.1% | 5.5% | 10.9% | 29.7% | 0.033 |
| Popularity (PageRank only) | 1.0% | 76.6% | 84.0% | 97.3% | 97.6% | 0.407 |
| Neighbour (graph traversal) | 5.5% | 27.3% | 43.4% | 67.6% | 90.8% | 0.171 |
| **Neighbour × PageRank** | **70.5%** | **81.9%** | **88.2%** | **90.9%** | **95.9%** | **0.756** |

Read plainly: combining graph-traversal evidence with PageRank, the curated mapping's
single most-relevant actor is the model's own top pick **71%** of the time (Hits@1),
sits in its top 5 in **82%**, and top 10 in **88%** (MRR 0.756 ⇒ typically rank 1–2).
As in Experiment A, `neighbour × PageRank` dominates at the precise top ranks where it
matters: *popularity* alone reaches the right actor *somewhere* in the top 5–20 (it
ranks globally prominent actors highly) but pins it at rank 1 only **1%** of the time,
and *random* is at the ~1/174 floor.

*Graph-isolation check.* The eval reads actor paths + PageRank from the live graph.
Recomputing against a freshly **wiped + pure-ATT&CK** graph (`MATCH (n) DETACH DELETE n`
→ `load_attack --enrich`, 174 actors / 33 CVEs, pristine PageRank) leaves the figures
unchanged: any extra loaded CVE/actor sources add no
`(Technique)<-[:USES]-(ThreatActor)` edges, so they never enter the rankings. The
numbers are graph-contamination-free.

### Claims and scope

**Support.** NVD prose contains **no** literal ATT&CK IDs (0/825), yet the LLM
reproduces a measurable fraction of expert CTID mappings (micro-F1 **0.277**,
parent-level **0.337**) with low invalid-ID rate (~1.1%). For **actor reachability**,
LLM-inferred techniques **match** structured gold coverage on the full corpus
(**99.5%** vs **97.7%**). The sharper **primary-actor** view shows the correct top
actor is the model's own top pick **71%** of the time and within its top 5 in **82%**
(MRR 0.76) — it surfaces the *same* actors, not merely *some* actor.

**Structured reference.** The deterministic CTID traversal (97.7% coverage) is the
ceiling; B₂ separates *technique label agreement* (moderate F1) from *actor recovery*
(coverage at parity with the structured reference; primary-actor Hits@5 = 0.82, below
a perfect oracle but well above chance).

**Caveats.** Inferential mapping ≠ quote-guarded extraction. Gold is CTID curated,
not exploitation telemetry. Single model, single pass.
