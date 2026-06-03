# AttackGraph run: `stix-llm-gemma3-4b-smoke2`

This folder collects the outputs of one experiment over the MITRE ATT&CK
knowledge graph. Each section below records a script that was run into
this folder, including parameters and the files it produced. The folder
is self-contained: copy / archive / commit it to keep the experiment
reproducible.


## extract_stix_uses_graph.py
- `timestamp_utc`: `2026-06-03T13:53:27+00:00`
- `bundle_path`: `/Users/bkosinski/Desktop/STUDIA/MGR/SecSearch/DocsBasedSupport/data/ontologies/mitre_attack/enterprise-attack.json`
- `graph_variant`: `llm-extracted:gemma3-4b`
- `limit`: `2`
- `model`: `gemma3:4b`
- `prior_edges_deleted`: `14`
- `reset`: `true`
- `outputs`: `stix_actor_corpus.json`, `stix_uses_extraction.json`

## eval_stix_extraction_quality.py
- `timestamp_utc`: `2026-06-03T13:55:00+00:00`
- `corpus_path`: `eval/AttackGraph/runs/stix-llm-gemma3-4b-smoke2/stix_actor_corpus.json`
- `graph_variant`: `llm-extracted:gemma3-4b`
- `outputs`: `extraction_quality.json`

## eval_link_prediction.py
- `timestamp_utc`: `2026-06-03T13:55:01+00:00`
- `graph_variant`: `llm-extracted:gemma3-4b`
- `hold_out_fraction`: `0.2`
- `max_actors`: `null`
- `num_candidates`: `697`
- `num_evaluated_actors`: `2`
- `num_held_out_edges`: `11`
- `num_total_edges`: `58`
- `seed`: `20260529`
- `top_ks`: `5, 10, 20, 50`
- `outputs`: `link_prediction.json`
