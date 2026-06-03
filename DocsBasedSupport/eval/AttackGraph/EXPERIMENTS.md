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

**Link prediction — neighbour Hits@10:**

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

## Experiment B: CVE → APT at scale (CISA KEV)

*Status: **not yet run** — section reserved for results and commands.*

**Goal.** The ATT&CK graph contains only ~33 CVEs with actor linkage; reviewers
rightly question generalisation from that denominator. Experiment B evaluates
**coverage and enrichment lift** on the full
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(~1,600 CVEs), with the MITRE 33-CVE case as an optional
`--cve-source mitre-attack` baseline.

**Planned pipeline**

1. `loaders/load_attack.py` — ATT&CK subgraph (path traversal + actor catalogs).
2. `loaders/load_kev.py` — ingest KEV CVE nodes.
3. `evals/eval_cve_apt.py --cve-source cisa-kev --variant baseline` — graph paths only.
4. `extractors/enrich_with_llm.py` on KEV descriptions — bounded reverse attribution.
5. `evals/eval_cve_apt.py --variant enriched` — post-enrichment coverage.
6. `evals/cve_scaling_report.py` — bootstrap stability + precision sample export.

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
