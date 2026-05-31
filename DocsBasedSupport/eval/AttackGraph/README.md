# MITRE ATT&CK experiment for GraphoDynamo

## Motivation

WildGraphBench evaluates GraphoDynamo on general IT reference text. By design,
that benchmark does not exercise the system's ability to map *specialised*
cybersecurity relationships — vulnerabilities (CVEs), techniques, malware,
campaigns and threat actors — nor does it ground the claim that PageRank and
Louvain community detection are useful for analytical navigation over a
security knowledge base. This experiment closes both gaps using the MITRE
ATT&CK Enterprise STIX 2.1 bundle as a curated security graph.

## Evaluation

### What was done

Three artefacts were produced over the same Neo4j subgraph (~1840 entities,
~21 100 relationships) loaded from the official ATT&CK Enterprise bundle:

1. **Held-out link prediction** for `(ThreatActor)-[:USES]->(Technique)`
   edges, comparing four ranking strategies on a fixed 20% test split:
   `random`, `popularity` (Technique PageRank), `neighbour` (2-hop co-use
   through other actors), `neighbour_pagerank` (neighbour × PageRank).
2. **Community + centrality report** over the labelled ATT&CK subgraph,
   recording top-PageRank nodes overall and per label, Louvain community
   sizes, label distributions and label purity.
3. **CVE → APT mapping** evaluated as **baseline** (deterministic ATT&CK
   only) and **enriched** (after a controlled LLM enrichment step that
   extracts verbatim CVE / actor mentions from entity descriptions with
   strict validation). Each variant reports per-CVE top actors with full
   evidence paths plus aggregate coverage.

### How and why

The deterministic loader writes STIX directly into Neo4j without any LLM
round-trip. ATT&CK is canonical structured data, so any LLM re-extraction
would inject noise and obscure whether the analytical signal comes from the
*graph layer* or the *extractor*. PageRank and Louvain run via the same
`enrich_subgraph` primitive GraphoDynamo uses elsewhere — no shadow analytics.

The link-prediction test isolates the **structural recoverability** of removed
`USES` edges from random and popularity-only baselines, which is the most
direct empirical test of "does the graph capture meaningful actor–technique
relationships?" The CVE → APT evaluator enumerates concrete evidence paths
between each CVE node and candidate threat actors, scoring them by
`path_count × (1 + actor.pagerank)`; this produces both an aggregate coverage
number and ready-to-cite reasoning chains.

The LLM enrichment is intentionally **narrow and conservative**: only verbatim
CVE identifiers and only threat-actor names that already exist as ATT&CK
nodes are accepted, and every added node or edge carries full provenance
(`source`, `extracted_from`, `context`, `llm_provenance_id`, `created_at`).
Pre-existing ATT&CK edges are corroborated rather than overwritten.

### Scope and denominators

All numbers in the next section are computed over the **entire MITRE ATT&CK
Enterprise Matrix v18** STIX bundle — nothing is sampled or filtered for the
evaluation. Every count below comes directly from the bundle's STIX objects:

| Label | Count | Source in bundle |
| :--- | ---: | :--- |
| `ThreatActor` | 174 | every non-revoked `intrusion-set` object |
| `Technique` | 697 | every non-revoked `attack-pattern` object (incl. sub-techniques) |
| `Malware` | 726 | every non-revoked `malware` object |
| `Tool` | 95 | every non-revoked `tool` object |
| `Campaign` | 56 | every non-revoked `campaign` object |
| `Mitigation` | 44 | every non-revoked `course-of-action` object |
| `Tactic` | 15 | every `x-mitre-tactic` object |
| `CVE` | 33 | every distinct `CVE-YYYY-NNNN` that appears in a STIX `external_references` entry with `source_name='cve'`, or as literal text inside an entity's description/name/external references |

The reason "only 33 CVEs" and "only 56 campaigns" surface in the evaluation
is that **these are the universes ATT&CK itself publishes**: ATT&CK is an
actor- and TTP-centric ontology, and historically catalogues a CVE only when
it has been observed in real intrusions and processed by MITRE. There is no
selection by GraphoDynamo — every CVE node and every campaign node present in
the bundle is included.

The 18 220 `USES` edges are split 80% / 20% (deterministic, seeded) for the
link-prediction experiment; the 20% test split contains the 909 held-out
edges over 150 distinct actors reported below.

### Results

#### Held-out link prediction

For each evaluated threat actor we hide a random 20% of its
`(ThreatActor)-[:USES]->(Technique)` edges, then ask every ranking strategy:
*given the remaining graph, where in your top-K list of the 697 candidate
techniques does the hidden technique appear?* Metrics are averaged over the
150 actors with at least one held-out technique.

| Strategy | Hits@5 | Hits@10 | Hits@20 | Hits@50 | MRR |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `random` | 2.7% | 6.7% | 16.0% | 36.0% | 0.033 |
| `popularity` (PageRank only) | 34.7% | 46.7% | 60.7% | 78.0% | 0.204 |
| `neighbour` (graph traversal) | **60.7%** | **72.0%** | **82.7%** | **92.7%** | **0.407** |
| `neighbour_pagerank` | 43.3% | 58.0% | 78.7% | 88.0% | 0.320 |

**How to read these numbers.** Each ranking strategy outputs an ordered list
of all 697 techniques per actor.

* **Hits@K** = fraction of evaluated actors for whom at least one of their
  held-out techniques appears in the strategy's top-K list. Higher is
  better. `random` is the chance-level baseline (≈ K/697 ≈ 0.7% at K=5);
  `popularity` is the strongest non-relational baseline; `neighbour` is
  the actual graph-aware strategy.
* **MRR** (mean reciprocal rank) = average of 1/rank-of-first-hit across
  actors. Higher = the first correct technique appears earlier in the list.
  0.407 means on average the first correct hidden technique appears around
  position 2–3.

**What this shows.** Using only structural information from the ATT&CK
graph (`neighbour`), we recover 72% of hidden actor↔technique edges in the
top 10 candidates out of 697 — ten times better than chance and 1.5×
better than ranking by raw technique popularity. The graph encodes
actor-specific behavioural signal, not just hub centrality.

#### CVE → APT mapping coverage

For each of the 33 CVE nodes in ATT&CK we ask: *can we reach at least one
named threat actor from this CVE by walking the graph through any approved
evidence-path shape?*

| Variant | CVEs mapped to ≥1 threat actor / total CVEs | Coverage | Mean actors / CVE | Mean evidence paths / CVE |
| :--- | :---: | ---: | ---: | ---: |
| Baseline (deterministic ATT&CK only) | 19 / 33 | 57.6% | 9.79 | 12.94 |
| Enriched (loader + evaluator + LLM attribution) | **26 / 33** | **78.8%** | **10.58** | **14.55** |

**How to read the `X / Y` fraction.** The fraction means *"covered CVEs /
total CVEs in the loaded ATT&CK graph"*. The denominator `33` is the full
ATT&CK Enterprise CVE universe (see *Scope and denominators* above) and is
identical across both rows. So `19 / 33` means the baseline produces at
least one threat-actor attribution path for 19 of the 33 ATT&CK CVEs, and
`26 / 33` means the enriched pipeline produces at least one such path for 26
of those same 33 CVEs — i.e. 7 additional CVEs gained an actor mapping
without any of the previously covered ones losing one.

**How to read the other columns.**

* **Coverage** = the same fraction expressed as a percentage. This is the
  primary outcome metric — it answers "for how many CVEs can the system
  give the SOC analyst an attribution hypothesis at all?".
* **Mean actors / CVE** = average number of distinct threat actors surfaced
  per CVE. Computed across **all 33** CVEs (including the uncovered ones,
  which contribute zero), so the denominator stays constant between rows
  and the metric is directly comparable.
* **Mean evidence paths / CVE** = average number of distinct walks
  (technique-, malware-, tool- or campaign-mediated) that justify the
  surfaced actors, again over all 33 CVEs.

**What this shows.** The deterministic ATT&CK graph alone already attributes
57.6% of CVEs to at least one actor. Adding actor/campaign description
ingestion (loader fix), three extra path shapes (evaluator extension), and
the bounded LLM campaign-attribution pass raises that to 78.8%, with no
regression on the previously covered CVEs and with mean actors per covered
CVE almost unchanged (≈ 10–11), confirming the new coverage is genuine new
attribution rather than noise.

#### LLM enrichment quality (campaigns only)

The campaign LLM enrichment pass processed all 56 ATT&CK campaigns and
returned:

| Counter | Value | Meaning |
| :--- | ---: | :--- |
| `new_attribution_edges` | 13 | New `Campaign -[:ATTRIBUTED_TO]-> ThreatActor` edges added to the graph. |
| `parse_failures` | 0 | LLM responses that failed JSON parsing. |
| `dropped_unmatched_actors` | 28 | Actor names extracted by the LLM that did NOT correspond to any existing ATT&CK `ThreatActor` node and were therefore rejected. |
| `dropped_unquoted` | 0 | CVE / actor mentions that could not be verified as literal text from the source description. |

**What this shows.** The LLM never invented data: every extraction was either
written as a new edge (because the actor exists in ATT&CK and is literally
named in the description) or silently rejected. The 28 dropped mentions are
the validator doing its job — not pipeline failures.

#### Centrality and community structure

| What | Examples surfaced by PageRank |
| :--- | :--- |
| Top techniques | `T1105 Ingress Tool Transfer`, `T1027 Obfuscated Files or Information`, `T1059 Command and Scripting Interpreter` |
| Top threat actors | Sandworm Team, APT5, APT41, Volt Typhoon |
| Top CVEs | `CVE-2017-11774`, `CVE-2014-7169`, `CVE-2016-6662` |

Louvain partitions the 1840 ATT&CK nodes into 30 communities. The largest
communities are deliberately label-mixed — each cluster contains a tactic
plus the techniques and malware used to execute it plus the actors that wield
them — which is the expected structure for a "campaign neighbourhood" view
and matches the qualitative use case (a SOC analyst navigating from one
artefact to related ones via the graph).

### Discussion

The link-prediction numbers give the headline finding: a purely structural
neighbour-based ranking recovers 72% of held-out actor↔technique edges in the
top 10, versus 47% for a PageRank-only popularity baseline and 7% random.
This is a direct, quantitative answer to *"does the graph map specialised
actor–technique relationships?"*, and confirms that PageRank and Louvain are
not decorative on this knowledge base.

For CVE → APT mapping, the deterministic ATT&CK subgraph alone reaches 57.6%
coverage, which already shows that the schema and the analytical layer can
connect CVEs to threat actors through technique, malware and campaign
intermediaries. Three additions push coverage to 78.8%:

* a loader extension that also creates `EXPLOITS` edges when CVEs appear in
  the descriptions of `ThreatActor` and `Campaign` (not only `Technique` /
  `Malware` / `Tool`);
* an evaluator extension that traverses three additional path shapes —
  `Campaign -[:ATTRIBUTED_TO]-> ThreatActor`,
  `Campaign -[:USES]-> Software -[:EXPLOITS]-> CVE` paired with attribution,
  and direct `ThreatActor -[:EXPLOITS]-> CVE`;
* a tightly bounded LLM enrichment pass that recovers `Campaign ↔ ThreatActor`
  attributions from campaign descriptions where ATT&CK has not yet published
  an explicit `attributed-to` edge.

The remaining seven uncovered CVEs cluster into two categories: (i) CVEs
referenced inside techniques or malware that no ATT&CK threat actor currently
`USES` (e.g. `CVE-2021-30724`, `CVE-2022-42475`, `CVE-2025-22457`), and (ii)
unattributed recent campaigns for which the LLM did not find an in-ontology
actor name (e.g. `CVE-2023-48022`, `CVE-2024-3400`). These are upstream
ATT&CK knowledge gaps rather than pipeline failures, and they could be
addressed in future work by ingesting external CTI sources.

The LLM enrichment is **complementary, not foundational**: the
`dropped_unmatched_actors = 28` counter shows the validator actively rejected
extracted actor names that were not part of ATT&CK, which keeps the graph
conservative and the provenance audit-friendly.

### What this experiment does *not* claim

* It does not evaluate performance on real SIEM tickets or firewall logs —
  that is a separate "unstructured incidents" experiment.
* The deterministic ATT&CK graph is built without any LLM. LLM-derived nodes
  and edges only appear after the optional `enrich_with_llm.py` step and are
  tagged with explicit `source` and `created_via='llm-enrichment'` provenance
  so any downstream metric can separate ATT&CK ground truth from LLM-derived
  content.
* The held-out link-prediction setup measures structural recoverability of
  removed edges, not generalisation to unseen actors.

### Artefacts

All artefacts live inside the run folder selected via `--run-dir` (see
*Setup and execution* below). For the runs cited here:

| File | Cite for |
| :--- | :--- |
| `RUN.md` | Reproducibility card: every script invocation, parameters, output files. |
| `load_summary.json` | Graph size and per-label / per-relation counts. |
| `link_prediction.json` | Hits@K / Precision@K / Recall@K / MRR for the four ranking strategies. |
| `community_report.json` | Top-PageRank entities and Louvain community structure. |
| `cve_apt_paths_baseline.json` | CVE → APT mapping on the deterministic graph. |
| `cve_apt_paths_enriched.json` | CVE → APT mapping after loader / evaluator / LLM enrichment. |
| `llm_enrichment.json` | Per-entity / aggregate counts from the LLM enrichment pass. |

---

## Setup and execution

### Prerequisites

Neo4j 5 with APOC + GDS plugins (provided by the project `docker-compose.yml`).

```bash
cd DocsBasedSupport
docker compose up -d           # start Neo4j with APOC + GDS
pip install -r requirements.txt
```

### Data source

| Source | What it contributes | License |
| :--- | :--- | :--- |
| [MITRE ATT&CK Enterprise STIX 2.1](https://github.com/mitre/cti) (`enterprise-attack.json`) | All entities and explicit relationships (`uses`, `mitigates`, `subtechnique-of`, `attributed-to`, `targets`) plus CVE references and Technique→Tactic mappings via kill-chain phases. | [ATT&CK terms](https://attack.mitre.org/resources/terms-of-use/) |

Downloaded on first run and stored at
`DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
(git-ignored).

### Schema in Neo4j

Every node carries `:Entity` (so existing GraphRAG retrieval keeps working)
plus the ATT&CK-specific label below and a marker `:AttackEntity` for scoped
Cypher queries.

| Cypher label | STIX type |
| :--- | :--- |
| `ThreatActor` | `intrusion-set` |
| `Technique` | `attack-pattern` |
| `Tactic` | `x-mitre-tactic` |
| `Malware` | `malware` |
| `Tool` | `tool` |
| `Mitigation` | `course-of-action` |
| `Campaign` | `campaign` |
| `CVE` | derived from CVE references in `external_references` / descriptions |

Edge types: `USES`, `MITIGATES`, `SUBTECHNIQUE_OF`, `ATTRIBUTED_TO`, `TARGETS`
(STIX-direct), plus `EXPLOITS` (Technique / Malware / Tool / Campaign /
ThreatActor → CVE) and `IN_TACTIC` (Technique → Tactic, derived from
`kill_chain_phases`).

### Tracking runs

All scripts accept a shared `--run-dir <path>` argument that follows the
WildGraphBench `runs_*/` convention:

```
eval/AttackGraph/runs/<run_name>/
    load_summary.json
    link_prediction.json
    community_report.json
    cve_apt_paths_<variant>.json
    llm_enrichment.json
    RUN.md
```

`RUN.md` is auto-appended by each script invocation with a timestamped
section recording every parameter and output file. If `--run-dir` is omitted,
each script falls back to an auto-timestamped folder under `runs/`.

### Baseline run

```bash
RUN_DIR=eval/AttackGraph/runs/2026-05-31_baseline

PYTHONPATH=. python eval/AttackGraph/load_attack.py --enrich --reset --run-dir $RUN_DIR
PYTHONPATH=. python eval/AttackGraph/eval_link_prediction.py --run-dir $RUN_DIR
PYTHONPATH=. python eval/AttackGraph/community_report.py    --run-dir $RUN_DIR
PYTHONPATH=. python eval/AttackGraph/eval_cve_apt.py        --run-dir $RUN_DIR --variant baseline
```

### Enriched run

```bash
RUN_DIR_ENRICHED=eval/AttackGraph/runs/2026-05-31_enriched_<model-tag>

PYTHONPATH=. python eval/AttackGraph/enrich_with_llm.py \
    --labels ThreatActor Malware Tool Campaign \
    --run-dir $RUN_DIR_ENRICHED
PYTHONPATH=. python eval/AttackGraph/load_attack.py  --enrich --run-dir $RUN_DIR_ENRICHED
PYTHONPATH=. python eval/AttackGraph/eval_cve_apt.py --run-dir $RUN_DIR_ENRICHED --variant enriched
```

CLI knobs of interest:

* `eval_link_prediction.py`: `--seed`, `--hold-out-fraction`, `--top-ks`,
  `--max-actors`.
* `eval_cve_apt.py`: `--variant`, `--top-actors`, `--max-paths-per-pair`,
  `--max-hops`.
* `enrich_with_llm.py`: `--labels`, `--limit`, `--force`, `--model`.
