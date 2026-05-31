# MITRE ATT&CK experiment for GraphoDynamo

## Why this exists

It has been acknowledged that two aspects of the broader evaluation deserve
dedicated empirical support, which this experiment provides:

1. **Specialised security relationships.** WildGraphBench covers general IT
   reference text, so by itself it does not exercise GraphoDynamo's ability
   to map relationships between vulnerabilities, techniques, and threat
   actors.
2. **Analytical use of PageRank and Louvain.** These graph-analytics
   primitives are widely cited as useful for SOC-style navigation; this
   experiment grounds that claim on a curated security knowledge base.

This experiment loads the **MITRE ATT&CK Enterprise** STIX 2.1 bundle into the
existing Neo4j and uses the *same* PageRank + Louvain pipeline GraphoDynamo
already runs (`enrich_graph_offline` / `enrich_subgraph`) to:

* Build a labelled knowledge graph over
  `ThreatActor / Technique / Tactic / Malware / Tool / Mitigation / CVE / Campaign`.
* Recover hidden `Actor -[:USES]-> Technique` edges (held-out link prediction)
  to give a **quantitative** answer to "does the graph map specialised
  relationships?"
* Summarise Louvain communities and PageRank centrality to give a
  **qualitative** picture of *which* actors / techniques / CVEs cluster
  together.

The loader is **deterministic** (no LLM round-trip). MITRE ATT&CK is already
canonical structured data; using an LLM to re-extract it would only add noise
and would attribute any improvement to the extractor rather than to the
analytical graph layer.

## Data sources

| Source | What it contributes | License |
| :--- | :--- | :--- |
| [MITRE ATT&CK Enterprise STIX 2.1](https://github.com/mitre/cti) (`enterprise-attack.json`) | All entities and explicit relationships (`uses`, `mitigates`, `subtechnique-of`, `attributed-to`, `targets`) plus CVE references and Technique→Tactic mappings via kill-chain phases. | [ATT&CK terms](https://attack.mitre.org/resources/terms-of-use/) |

The bundle is downloaded on first run and stored at
`DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`. It is
git-ignored.

## Schema in Neo4j

Every node still carries the shared `:Entity` label (so the existing GraphRAG
retrieval keeps working) plus the ATT&CK-specific labels below and a marker
`:AttackEntity` for scoped Cypher queries.

| Cypher label | STIX type | Notes |
| :--- | :--- | :--- |
| `ThreatActor` | `intrusion-set` | APT-style groups (e.g. APT29, FIN7). |
| `Technique` | `attack-pattern` | Includes sub-techniques; `is_subtechnique` property. |
| `Tactic` | `x-mitre-tactic` | Initial Access, Execution, ... |
| `Malware`  | `malware`        | |
| `Tool`     | `tool`           | |
| `Mitigation` | `course-of-action` | |
| `Campaign` | `campaign`        | |
| `CVE`      | (derived) | Created from CVE references on techniques, malware, tools. |

Edge types:

| Edge | Where it comes from |
| :--- | :--- |
| `USES` | STIX `uses` (actor→technique, actor→software, software→technique). |
| `MITIGATES` | STIX `mitigates`. |
| `SUBTECHNIQUE_OF` | STIX `subtechnique-of`. |
| `ATTRIBUTED_TO` | STIX `attributed-to` (campaign→actor). |
| `TARGETS` | STIX `targets`. |
| `EXPLOITS` | Technique/Malware/Tool → CVE (from `external_references[source_name='cve']`). |
| `IN_TACTIC` | Technique → Tactic (from `kill_chain_phases`). |

## Running the experiment

Prereqs: Neo4j 5 with APOC + GDS plugins. This is exactly the
`docker-compose.yml` already in `DocsBasedSupport/`.

```bash
cd DocsBasedSupport
docker compose up -d           # start Neo4j with APOC + GDS
pip install -r requirements.txt
```

### Tracking runs

Every script supports a shared `--run-dir <path>` argument that mirrors the
WildGraphBench `runs_*/` convention. Outputs go into

```
eval/AttackGraph/runs/<run_name>/
    load_summary.json
    link_prediction.json
    community_report.json
    cve_apt_paths_<variant>.json
    llm_enrichment.json
    RUN.md
```

`RUN.md` is auto-appended by each script invocation with a timestamped section
recording every parameter and output file, so a run folder is a self-contained
record of one experiment. If `--run-dir` is omitted the script falls back to an
auto-timestamped folder under `runs/`, e.g.
`runs/load-20260531-094512Z/`. A run name typically follows
`<date>_<config-label>` -- e.g. `runs/2026-05-31_baseline/` and
`runs/2026-05-31_enriched_gemma3-4b/`.

The legacy `eval/AttackGraph/reports/` directory is retained for historical
scratch outputs but new work should write to `runs/`.

### Step 1 - load + enrich

```bash
RUN_DIR=eval/AttackGraph/runs/2026-05-31_baseline
PYTHONPATH=. python eval/AttackGraph/load_attack.py --enrich --reset --run-dir $RUN_DIR
```

What this does:

1. Downloads the ATT&CK bundle on first run (no auth, single GitHub URL).
2. Detach-deletes any existing `mitre-attack:enterprise` source (idempotent).
3. Writes nodes/edges via `Neo4jStore` (same primitives as `/ingest`).
4. Runs PageRank and Louvain over the labelled ATT&CK subgraph only.
5. Writes a JSON summary to `eval/AttackGraph/reports/load_summary.json`.

### Step 2 - held-out link prediction

```bash
PYTHONPATH=. python eval/AttackGraph/eval_link_prediction.py --run-dir $RUN_DIR
```

What this does:

1. Hides a random 20% of `(ThreatActor)-[:USES]->(Technique)` edges via a
   `held_out=true` flag (no data loss; flags are restored at the end).
2. Re-runs PageRank + Louvain on the **train graph** only (via a Cypher GDS
   projection that filters out held-out edges); writes `pagerank_train` and
   `community_train` properties to nodes.
3. For every actor with at least one held-out technique, ranks all techniques
   under four strategies and records Precision@K / Recall@K / Hits@K / MRR:
   - `random` baseline
   - `popularity` (rank by global Technique PageRank, ignores the actor)
   - `neighbour` (2-hop co-use through other actors, pure graph traversal)
   - `neighbour_pagerank` (neighbour count × candidate PageRank)
4. Writes `eval/AttackGraph/reports/link_prediction.json`.

CLI knobs:

```bash
--seed 20260529              # deterministic split
--hold-out-fraction 0.2      # change to 0.1 / 0.3 for ablations
--top-ks 5 10 20 50          # K values to compute metrics at
--max-actors 50              # smoke-test sample size
```

The "neighbour" strategies probe the central analytical question motivating
this experiment: *does the ATT&CK-derived graph map relationships between
actors and techniques well enough that the graph alone can predict missing
edges?*

### Step 3 - community + centrality report

```bash
PYTHONPATH=. python eval/AttackGraph/community_report.py --run-dir $RUN_DIR
```

What this does (read-only):

* Top-K PageRank nodes overall and per label.
* Per-community size, label distribution, label Gini impurity, top members by
  PageRank.
* Output: `$RUN_DIR/community_report.json`.

Use the per-label PageRank list and the per-community top members for the
qualitative paragraphs in the thesis ("which APTs / techniques / CVEs surface
as central?", "do communities cluster meaningfully?").

### Step 4 - CVE -> APT mapping report (baseline)

```bash
PYTHONPATH=. python eval/AttackGraph/eval_cve_apt.py --run-dir $RUN_DIR --variant baseline
```

What this does (read-only):

* For every `CVE` node, enumerates evidence paths of the form
  `(CVE) <-[:EXPLOITS]- (Technique|Malware|Tool) <-[:USES]- (ThreatActor)`,
  optionally a longer 3-hop variant that goes through one extra `USES` step,
  and campaign-attribution paths of the form
  `(CVE) <-[:EXPLOITS]- (Campaign) -[:ATTRIBUTED_TO]-> (ThreatActor)`.
* Scores each candidate actor by `path_count * (1 + actor.pagerank)`, keeping
  the top-K actors per CVE plus their evidence paths.
* Aggregates: coverage (% CVEs with >=1 actor link), mean / median / max
  actors per CVE, mean / median / max evidence paths per CVE.
* Output: `$RUN_DIR/cve_apt_paths_baseline.json`.

Use this for the thesis's CVE-to-APT narrative -- the per-CVE evidence paths
double as ready-to-quote reasoning chains.

### Step 5 (optional) - LLM-driven enrichment

The deterministic loader writes only the CVEs ATT&CK exposes in
`external_references` (about 33 in the current Enterprise bundle). A lot of
extra CVE / actor cross-references are buried inside free-text descriptions of
threat actors, malware, tools, and campaigns. The enrichment pipeline asks the
configured LLM (`llm_extract_model` in `settings.yaml`) to *quote-extract*
those references and writes them back as new nodes / edges with full
provenance.

```bash
# pick a new run folder for the enriched experiment so before/after stays separable
RUN_DIR_ENRICHED=eval/AttackGraph/runs/2026-05-31_enriched_gemma3-4b

PYTHONPATH=. python eval/AttackGraph/enrich_with_llm.py \
    --labels ThreatActor Malware Tool Campaign \
    --run-dir $RUN_DIR_ENRICHED
# refresh PageRank / Louvain over the now-enriched graph (logs into the same run folder)
PYTHONPATH=. python eval/AttackGraph/load_attack.py --enrich --run-dir $RUN_DIR_ENRICHED
# enriched CVE -> APT report next to the baseline numbers
PYTHONPATH=. python eval/AttackGraph/eval_cve_apt.py --run-dir $RUN_DIR_ENRICHED --variant enriched
# optional: rerun link prediction / community report inside the enriched run folder
PYTHONPATH=. python eval/AttackGraph/eval_link_prediction.py --run-dir $RUN_DIR_ENRICHED
PYTHONPATH=. python eval/AttackGraph/community_report.py --run-dir $RUN_DIR_ENRICHED
```

Design choices:

* **No hallucination.** The validator drops any CVE whose identifier is not a
  literal substring of the source description. Quotes that are not verbatim are
  removed before write.
* **Full provenance.** Every node and edge added by this module carries
  `source='<provider>:<model>'`, `extracted_from=<entity_id>`,
  `context=<verbatim quote>`, `llm_provenance_id=<uuid>`, and `created_at`. A
  pre-existing MITRE `EXPLOITS` edge is *not* duplicated; it is annotated with
  `corroborated_by=['<provider>:<model>']` so MITRE ground truth stays intact.
* **Idempotent.** Processed entities are flagged with `llm_enriched_at`; reruns
  skip them unless `--force` is passed.
* Output: `eval/AttackGraph/reports/llm_enrichment.json` (per-entity counts
  and aggregate summary).

CLI knobs:

```bash
--labels ThreatActor Malware Tool Campaign   # which AttackEntity labels to enrich
--limit 50                                   # smoke-test sample size
--force                                       # re-enrich already-processed entities
--model gpt-oss:20b                           # override settings.yaml llm_extract_model
```

The `baseline` vs `enriched` CVE -> APT reports give a defensible
before/after table: more CVE nodes, more `EXPLOITS` edges, higher actor-link
coverage, longer / richer evidence chains.

## Outputs to cite in the thesis

After running steps 1-3, the following artefacts are written and can be cited
directly:

All paths below are inside the chosen `runs/<run_name>/` folder (the baseline
example used `2026-05-31_baseline/`, the enriched example used
`2026-05-31_enriched_gemma3-4b/`).

| File | What to cite it for |
| :--- | :--- |
| `RUN.md` | Reproducibility card: every script invocation with timestamp, parameters, and output files. |
| `load_summary.json` | Graph size, entity / relationship counts. |
| `link_prediction.json` | Quantitative evidence that PageRank/Louvain map actor-technique relationships better than random and better than a popularity-only baseline. |
| `community_report.json` | Qualitative discussion of central CVEs / APTs / techniques and how Louvain communities cluster the threat landscape. |
| `cve_apt_paths_baseline.json` | CVE -> APT mapping report on the deterministic ATT&CK graph: per-CVE top actors with evidence paths and aggregate coverage. |
| `cve_apt_paths_enriched.json` | Same report after LLM enrichment of entity descriptions, for the before/after comparison. |
| `llm_enrichment.json` | Summary of the LLM enrichment pass: new CVE nodes, new `EXPLOITS` edges, dropped (unquoted) candidates, parse failures. |

## What this experiment does *not* claim

* It does not claim performance on **real SIEM tickets or firewall logs** —
  that is the separate "unstructured incidents" experiment.
* The deterministic ATT&CK graph loaded by `load_attack.py` is built *without*
  any LLM. LLM-derived nodes / edges only appear after the optional
  `enrich_with_llm.py` step and are tagged with explicit `source` and
  `created_via='llm-enrichment'` provenance, so any downstream metric can
  separate ATT&CK ground truth from LLM-contributed content.
* The held-out link-prediction setup measures **structural recoverability** of
  removed edges, not generalisation to unseen actors. This is consistent with
  the analytical framing it was acknowledged this work should evaluate —
  namely, that PageRank and Louvain Community Detection can correctly map
  relationships between vulnerabilities and threat actors for analytical
  purposes.
