# AttackGraph run: `stix-llm-gpt-oss-20b-cloud`

This folder collects the outputs of one experiment over the MITRE ATT&CK
knowledge graph. Each section below records a script that was run into
this folder, including parameters and the files it produced. The folder
is self-contained: copy / archive / commit it to keep the experiment
reproducible.


## extract_stix_uses_graph.py
- `timestamp_utc`: `2026-06-03T14:29:25+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `graph_variant`: `llm-extracted:gpt-oss-20b-cloud`
- `limit`: `null`
- `model`: `gpt-oss:20b-cloud`
- `prior_edges_deleted`: `0`
- `reset`: `true`
- `outputs`: `stix_actor_corpus.json`, `stix_uses_extraction.json`

## eval_stix_extraction_quality.py
- `timestamp_utc`: `2026-06-03T14:29:51+00:00`
- `corpus_path`: `eval/AttackGraph/runs/stix-llm-gpt-oss-20b-cloud/stix_actor_corpus.json`
- `graph_variant`: `llm-extracted:gpt-oss-20b-cloud`
- `outputs`: `extraction_quality.json`

## eval_link_prediction.py
- `timestamp_utc`: `2026-06-03T14:29:54+00:00`
- `graph_variant`: `llm-extracted:gpt-oss-20b-cloud`
- `hold_out_fraction`: `0.2`
- `max_actors`: `null`
- `num_candidates`: `697`
- `num_evaluated_actors`: `114`
- `num_held_out_edges`: `538`
- `num_total_edges`: `2693`
- `seed`: `20260529`
- `top_ks`: `5, 10, 20, 50`
- `outputs`: `link_prediction.json`
